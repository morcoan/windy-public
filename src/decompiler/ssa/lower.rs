//! Lowering: per-instruction P-code -> a flat, location-resolved op stream.
//!
//! This is the bridge from Phase 1's per-instruction `PcodeOp` lists to the
//! side-layer SSA input. For each instruction we:
//!
//! 1. Normalize `Register`-space varnodes to their 8-byte container
//!    (`Location::Register { base_offset }`), applying the x86-64 zero-extension
//!    rule for sub-register writes (see [`register_container_base`]).
//! 2. Resolve `Load`/`Store` pointer expressions to a `Location::StackSlot`
//!    (when the base is RSP/RBP ± const) or to the single `Location::RawRam`
//!    token (everything else).
//!
//! ## Design notes
//!
//! * **Unique temporaries are instruction-scoped SSA locations.** SLEIGH
//!   reuses `Unique`-space offsets for each decoded instruction, so lowering
//!   records `(instruction_va, offset, size)` rather than a function-global
//!   temporary. This keeps intra-instruction dataflow (for example a temporary
//!   address feeding a later operation) without allowing accidental aliases
//!   between instructions.
//! * **Sub-register writes (size 1/2 — AL/AX/AH).** `register_container_base`
//!   maps any sub-register offset that falls within 8 bytes of a GPR container
//!   base onto that base (so AL/AX/EAX/RAX all land in `Register { base_offset: 0 }`,
//!   and AH at offset `1` also lands in RAX's container since `1 - 0 < 8`). A
//!   write of any size therefore *defines the whole container* — the conservative
//!   "whole container redefined" fall-back called out in the Phase 2 plan. This
//!   is sound (all reaching reads merge to this def); it loses intra-container
//!   byte/word precision, which only matters for rare 8/16-bit GPR code that
//!   compiler x86-64 output almost never emits. The x86-64 32-bit zero-extension
//!   rule (a 32-bit write defines the entire 64-bit container) is the same
//!   container-def behavior, so no special-casing is needed.

use std::collections::HashMap;

use pcode_ir::{AddressSpaceId, get_output, visit_reads};
use rsleigh_api::{PcodeOp, Varnode};

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::Function;
use crate::decompiler::ssa::{CallAbiInputs, FlatOp, Location};

/// x86-64 GPR container bases: RAX..RDI at `0x00..0x38`, R8..R15 at `0x80..0xB8`.
/// Each is the base offset of an 8-byte register container.
const REG_BASES: &[u64] = &[
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8,
];

/// RSP / RBP container bases (frame-pointer registers).
const RSP_OFFSET: u64 = 0x20;
const RBP_OFFSET: u64 = 0x28;

/// Human-readable name for a SLEIGH register-container base offset.
///
/// Maps the 16 x86-64 GPR containers (`0x00`→`rax` … `0xb8`→`r15`). Unknown
/// bases fall back to `r{offset:x}` (e.g. flags / segment slots).
pub fn reg_name(base_offset: u64) -> String {
    match base_offset {
        0x00 => "rax".to_string(),
        0x08 => "rcx".to_string(),
        0x10 => "rdx".to_string(),
        0x18 => "rbx".to_string(),
        0x20 => "rsp".to_string(),
        0x28 => "rbp".to_string(),
        0x30 => "rsi".to_string(),
        0x38 => "rdi".to_string(),
        0x80 => "r8".to_string(),
        0x88 => "r9".to_string(),
        0x90 => "r10".to_string(),
        0x98 => "r11".to_string(),
        0xa0 => "r12".to_string(),
        0xa8 => "r13".to_string(),
        0xb0 => "r14".to_string(),
        0xb8 => "r15".to_string(),
        other => format!("r{other:x}"),
    }
}

/// Map a register varnode offset to its 8-byte container base.
///
/// If `offset` is within 8 bytes of a known GPR base, returns that base (so
/// EAX/AX/AL/RAX all collapse to `0`, AH at offset `1` also collapses to `0`,
/// and R8D/R8W/R8B all collapse to `0x80`). Offsets that fall in the gap
/// between containers (flags, segment registers, &c.) are treated as their own
/// opaque container, per the "reject out-of-table offsets" rule.
pub fn register_container_base(offset: u64) -> u64 {
    let mut best: Option<u64> = None;
    for &b in REG_BASES {
        if b <= offset {
            best = Some(b);
        } else {
            break;
        }
    }
    if let Some(b) = best
        && offset - b < 8
    {
        return b;
    }
    offset
}

/// Whether a container base is a frame-pointer register (RSP or RBP).
fn is_frame_ptr(base_offset: u64) -> bool {
    base_offset == RSP_OFFSET || base_offset == RBP_OFFSET
}

/// Turn a value-carrying P-code varnode into an SSA storage location.
///
/// Constants are values rather than storage and RAM is handled by the
/// load/store memory resolver, so only registers and instruction-scoped Unique
/// temporaries belong in generic def/use chains here.
fn value_location(vn: Varnode, instruction_va: u64) -> Option<Location> {
    match vn.space {
        AddressSpaceId::Register => Some(Location::Register {
            base_offset: register_container_base(vn.offset),
        }),
        AddressSpaceId::Unique => Some(Location::Unique {
            instruction_va,
            offset: vn.offset,
            size: vn.size,
        }),
        AddressSpaceId::Ram | AddressSpaceId::Const => None,
    }
}

/// Append a generic value use when its storage is represented by the SSA
/// side-layer. Duplicates are retained because P-code operands are ordered and
/// may legitimately read the same storage twice.
fn push_value_use(uses: &mut Vec<Location>, vn: Varnode, instruction_va: u64) {
    if let Some(location) = value_location(vn, instruction_va) {
        uses.push(location);
    }
}

/// Resolve a pointer varnode to a memory `Location` (stack slot or raw RAM).
///
/// `defs` maps each `Unique` output varnode of the *current instruction* to the
/// op that produced it, so we can look through `IntAdd`/`Copy` addressing
/// expressions.
fn resolve_ptr(ptr: Varnode, defs: &HashMap<Varnode, PcodeOp>) -> Location {
    if ptr.space == AddressSpaceId::Register {
        let base = register_container_base(ptr.offset);
        if is_frame_ptr(base) {
            return Location::StackSlot {
                base_reg: ptr.offset,
                disp: 0,
            };
        }
        return Location::RawRam;
    }

    if ptr.space == AddressSpaceId::Unique {
        if let Some(op) = defs.get(&ptr) {
            match op {
                PcodeOp::IntAdd { left, right, .. } => {
                    let (base_vn, disp) = if right.space == AddressSpaceId::Const {
                        (*left, right.offset as i64)
                    } else if left.space == AddressSpaceId::Const {
                        (*right, left.offset as i64)
                    } else {
                        return Location::RawRam;
                    };
                    match resolve_base_register(base_vn, defs) {
                        Some(reg_off) if is_frame_ptr(register_container_base(reg_off)) => {
                            Location::StackSlot {
                                base_reg: reg_off,
                                disp,
                            }
                        }
                        _ => Location::RawRam,
                    }
                }
                PcodeOp::Copy { input, .. } => {
                    if input.space == AddressSpaceId::Register
                        && is_frame_ptr(register_container_base(input.offset))
                    {
                        return Location::StackSlot {
                            base_reg: input.offset,
                            disp: 0,
                        };
                    }
                    Location::RawRam
                }
                _ => Location::RawRam,
            }
        } else {
            Location::RawRam
        }
    } else {
        Location::RawRam
    }
}

/// Peel `Copy` chains to find the underlying register offset used as a pointer base.
fn resolve_base_register(vn: Varnode, defs: &HashMap<Varnode, PcodeOp>) -> Option<u64> {
    if vn.space == AddressSpaceId::Register {
        return Some(vn.offset);
    }
    if vn.space == AddressSpaceId::Unique
        && let Some(PcodeOp::Copy { input, .. }) = defs.get(&vn)
    {
        return resolve_base_register(*input, defs);
    }
    None
}

/// Resolve the def + uses of a single (already namespaced) P-code op.
///
/// `call_abi_inputs` comes from a separately resolved call contract.  It is
/// appended only to `Call` / `CallInd` operations so the frozen P-code stays
/// unchanged while the SSA liveness graph retains the ABI values consumed by a
/// known call.
fn resolve_op(
    op: &PcodeOp,
    instruction_va: u64,
    defs: &HashMap<Varnode, PcodeOp>,
    call_abi_inputs: &[Location],
) -> (Option<Location>, Vec<Location>) {
    let (def, mut uses) = match op {
        PcodeOp::Store { ptr, val, .. } => {
            let def = Some(resolve_ptr(*ptr, defs));
            let mut uses = Vec::new();
            // The stored *value* is a use; the pointer is resolved purely to
            // determine the written slot. Preserve the historical value-first
            // ordering, then retain an instruction-scoped Unique pointer if
            // one exists so temporary address expressions have def/use edges.
            push_value_use(&mut uses, *val, instruction_va);
            if ptr.space == AddressSpaceId::Unique {
                push_value_use(&mut uses, *ptr, instruction_va);
            }
            (def, uses)
        }
        PcodeOp::Load { ptr, out, .. } => {
            let slot = resolve_ptr(*ptr, defs);
            // Keep the memory token first: existing pointer/type consumers use
            // `uses[0]` for this location. A Unique pointer follows it so a
            // temporary address can still be traced by generic SSA users.
            let mut uses = vec![slot];
            if ptr.space == AddressSpaceId::Unique {
                push_value_use(&mut uses, *ptr, instruction_va);
            }
            let def = value_location(*out, instruction_va);
            (def, uses)
        }
        _ => {
            let def = get_output(op).and_then(|out| value_location(out, instruction_va));
            let mut uses = Vec::new();
            visit_reads(op, &mut |v| {
                push_value_use(&mut uses, *v, instruction_va);
            });
            (def, uses)
        }
    };

    if matches!(op, PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) {
        for input in call_abi_inputs {
            if !uses.contains(input) {
                uses.push(input.clone());
            }
        }
    }

    (def, uses)
}

/// Flatten a function's P-code into a per-block [`FlatOp`] stream with def/use
/// locations resolved, including ABI inputs from resolved calls. Block order
/// and intra-block instruction order follow `func.blocks` + the code index.
pub fn lower_function_with_call_abi_inputs(
    func: &Function,
    pcode: &HashMap<u64, Vec<PcodeOp>>,
    code_index: &CodeIndex,
    call_abi_inputs: &CallAbiInputs,
) -> Vec<Vec<FlatOp>> {
    let mut blocks_flat = Vec::with_capacity(func.blocks.len());

    for block in &func.blocks {
        let mut flat: Vec<FlatOp> = Vec::new();
        let mut va = block.entry_va;
        loop {
            if let Some(ops) = pcode.get(&va) {
                // Intra-instruction def map for pointer resolution.
                let mut defs: HashMap<Varnode, PcodeOp> = HashMap::new();
                for op in ops {
                    if let Some(out) = get_output(op) {
                        defs.insert(out, op.clone());
                    }
                }
                for op in ops {
                    let op = op.clone();
                    let inputs = if matches!(&op, PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) {
                        call_abi_inputs
                            .get(&va)
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                    } else {
                        &[]
                    };
                    let (def, uses) = resolve_op(&op, va, &defs, inputs);
                    flat.push(FlatOp { va, op, def, uses });
                }
            }
            if va == block.exit_va {
                break;
            }
            match code_index.at_va(va) {
                Some(dec) => va = dec.next_ip(),
                None => break,
            }
        }
        blocks_flat.push(flat);
    }

    blocks_flat
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSN_A: u64 = 0x1400_0010;
    const INSN_B: u64 = 0x1400_0014;

    #[test]
    fn unique_value_locations_are_scoped_by_instruction() {
        let temp = Varnode::unique(0x40, 8);
        assert_eq!(
            value_location(temp, INSN_A),
            Some(Location::Unique {
                instruction_va: INSN_A,
                offset: 0x40,
                size: 8,
            })
        );
        assert_ne!(value_location(temp, INSN_A), value_location(temp, INSN_B));
    }

    #[test]
    fn generic_ops_track_unique_defs_and_uses() {
        let temp = Varnode::unique(0x40, 8);
        let producer = PcodeOp::IntAdd {
            out: temp,
            left: Varnode::register(0x08, 8),
            right: Varnode::constant(1, 8),
        };
        let (def, uses) = resolve_op(&producer, INSN_A, &HashMap::new(), &[]);
        assert_eq!(
            def,
            Some(Location::Unique {
                instruction_va: INSN_A,
                offset: 0x40,
                size: 8,
            })
        );
        assert_eq!(
            uses,
            vec![Location::Register { base_offset: 0x08 }],
            "ordinary register use remains available beside the Unique def"
        );

        let consumer = PcodeOp::Copy {
            out: Varnode::register(0x00, 8),
            input: temp,
        };
        let (def, uses) = resolve_op(&consumer, INSN_A, &HashMap::new(), &[]);
        assert_eq!(def, Some(Location::Register { base_offset: 0x00 }));
        assert_eq!(
            uses,
            vec![Location::Unique {
                instruction_va: INSN_A,
                offset: 0x40,
                size: 8,
            }]
        );
    }

    #[test]
    fn load_keeps_memory_token_before_unique_pointer_use() {
        let ptr = Varnode::unique(0x80, 8);
        let load = PcodeOp::Load {
            space: AddressSpaceId::Ram,
            ptr,
            out: Varnode::register(0x00, 8),
        };
        let (_, uses) = resolve_op(&load, INSN_A, &HashMap::new(), &[]);
        assert_eq!(uses.first(), Some(&Location::RawRam));
        assert_eq!(
            uses.get(1),
            Some(&Location::Unique {
                instruction_va: INSN_A,
                offset: 0x80,
                size: 8,
            })
        );
    }
}
