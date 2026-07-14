//! P-code lifter â€” Phase 0 of WindyDec.
//!
//! This module wraps the vendored [`rsleigh_api`] SLEIGH decoder and lifts
//! x86-64 machine code into Ghidra-style P-code. The SLEIGH specification for
//! x86-64 ships *inside* the `rsleigh-api` crate (generated sub-crate
//! `rsleigh-gen-x86`), so there is no external process and no `.sla` file to
//! compile â€” Windy links a single self-contained binary that owns its lifter.
//!
//! P-code vocabulary mirrors Ghidra's [`pcoderef`] exactly (op names such as
//! `IntAdd`, `Store`, `Load`, `Copy`, `CBranch`). Downstream phases â€” SSA
//! construction (Phase 2), TRex type recovery (Phase 4), DREAM structuring
//! (Phase 5) â€” all consume this standard IR.
//!
//! [`rsleigh_api`]: https://crates.io/crates/rsleigh-api
//! [`pcoderef`]: https://ghidra.re/courses/languages/html/pcoderef.html

use std::collections::HashMap;

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::Function;

// Re-export the full P-code IR surface so downstream phases (SSA, type
// recovery, structuring) import everything from `crate::decompiler::pcode`.
pub use rsleigh_api::*;
#[allow(dead_code)] // re-export alias for downstream pcode consumers
pub type PcodeInstruction = rsleigh_api::Instruction;

/// Size of the stack given to the SLEIGH decode thread.
///
/// The vendored SLEIGH decoder recurses deeply while lifting x86 instructions,
/// so the default libtest worker stack (2 MiB) â€” and the default tokio worker
/// stack â€” overflows even for trivial instructions. We give the decode its own
/// 128 MiB stack so both `cargo test` and the async MCP path lift without
/// `RUST_MIN_STACK` gymnastics.
pub const DECODE_STACK_SIZE: usize = 128 * 1024 * 1024;

/// Lifts x86-64 machine code to P-code via the SLEIGH decoder.
///
/// The decoder keeps internal decode state, so lifting methods take `&mut self`.
/// A single `SleighLifter` is reused for the whole image; wrap in a `Mutex` if
/// concurrent lifting is needed.
pub struct SleighLifter {
    decoder: Decoder,
}

/// A single lifted machine instruction: where it lives, how big it is, its
/// human-readable disassembly, and the P-code operations that implement it.
#[derive(Clone, Debug)]
pub struct LiftedInstr {
    /// Virtual address of the instruction.
    #[allow(dead_code)] // retained for region lifters / diagnostics
    pub va: u64,
    /// Encoded length in bytes.
    #[allow(dead_code)] // retained for region lifters / diagnostics
    pub len: u64,
    /// Human-readable disassembly (e.g. `"MOV RAX,RBX"`).
    #[allow(dead_code)] // retained for region lifters / diagnostics
    pub disasm: String,
    /// P-code operations (peephole-optimized), in execution order.
    pub ops: Vec<PcodeOp>,
}

impl Default for SleighLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl SleighLifter {
    /// Create a lifter for the x86-64 architecture.
    pub fn new() -> Self {
        Self {
            decoder: Decoder::new(Architecture::X86_64),
        }
    }

    /// Lift exactly one instruction given its raw bytes and virtual address.
    ///
    /// `bytes` should start at the instruction boundary (a sub-slice of the
    /// code region is fine); the decoder reads only what it needs.
    pub fn lift_one(&mut self, bytes: &[u8], va: u64) -> Result<LiftedInstr, DecodeError> {
        let inst = self.decoder.decode(bytes, va)?;
        Ok(LiftedInstr {
            va,
            len: inst.len,
            disasm: inst.disassembly.clone(),
            ops: inst.ops.clone(),
        })
    }

    /// Create a lifter for the given bitness (64 -> `X86_64`, otherwise
    /// `X86_32`). `sample.exe` and the analysis pipeline use 64.
    pub fn for_bitness(bitness: u32) -> Self {
        let arch = if bitness == 64 {
            Architecture::X86_64
        } else {
            Architecture::X86_32
        };
        Self {
            decoder: Decoder::new(arch),
        }
    }

    /// Lift a contiguous code region, decoding instruction-by-instruction until
    /// `bytes` is exhausted.
    ///
    /// Best-effort: if a byte sequence cannot be decoded (e.g. embedded data or
    /// alignment padding inside `.text`), the lifter skips a single byte and
    /// resumes, so a partially-decodable section still yields everything around
    /// it. Use [`SleighLifter::lift_one`] when you need strict, all-or-nothing
    /// lifting.
    #[allow(dead_code)] // whole-section lift path for offline tooling
    pub fn lift_region(&mut self, bytes: &[u8], base_va: u64) -> Vec<LiftedInstr> {
        let mut out = Vec::new();
        let mut off = 0usize;
        let mut va = base_va;
        while off < bytes.len() {
            match self.decoder.decode(&bytes[off..], va) {
                Ok(inst) => {
                    let len = inst.len as usize;
                    if len == 0 {
                        // Defensive: never spin on a zero-length decode.
                        off += 1;
                        va += 1;
                        continue;
                    }
                    let lifted = LiftedInstr {
                        va,
                        len: inst.len,
                        disasm: inst.disassembly.clone(),
                        ops: inst.ops.clone(),
                    };
                    out.push(lifted);
                    off += len;
                    va += inst.len;
                }
                Err(_) => {
                    // Undecodable byte: skip it and try the next boundary.
                    off += 1;
                    va += 1;
                }
            }
        }
        out
    }
}

/// Collect the `(va, bytes)` pairs for every instruction in `func`, in
/// basic-block order, by walking each block's linear instruction stream via the
/// code index.
fn collect_function_instructions(func: &Function, code_index: &CodeIndex) -> Vec<(u64, Vec<u8>)> {
    let mut instrs = Vec::new();
    for block in &func.blocks {
        let mut va = block.entry_va;
        while let Some(dec) = code_index.at_va(va) {
            instrs.push((va, dec.bytes_slice().to_vec()));
            if va == block.exit_va {
                break;
            }
            va = dec.next_ip();
        }
    }
    instrs
}

/// Lift every instruction in `func` to P-code on the caller's stack.
///
/// Returns a vector of `(va, ops)` in basic-block order; NOP/fence
/// instructions legitimately yield empty op lists (handled by the caller using
/// disassembly text). A single fresh [`SleighLifter`] is created per call.
///
/// This is the lazy, per-function lift: it touches only the bytes of the
/// function, not the whole image. Prefer [`lift_function_blocking`] when called
/// from an async worker (e.g. an MCP tool) whose default stack is too small for
/// the SLEIGH decoder's recursion.
#[allow(dead_code)] // non-blocking twin of lift_function_blocking
pub fn lift_function(
    func: &Function,
    code_index: &CodeIndex,
    bitness: u32,
) -> Vec<(u64, Vec<PcodeOp>)> {
    let mut lifter = SleighLifter::for_bitness(bitness);
    collect_function_instructions(func, code_index)
        .into_iter()
        .filter_map(|(va, bytes)| {
            lifter
                .lift_one(&bytes, va)
                .ok()
                .map(|lifted| (va, lifted.ops))
        })
        .collect()
}

/// Lift every instruction in `func` to P-code on a dedicated â‰¥128 MiB stack.
///
/// Same result as [`lift_function`] but runs the SLEIGH decode off the calling
/// thread, so it is safe to call from the default tokio worker stack (the MCP
/// async path) and from `cargo test` workers without `RUST_MIN_STACK` set.
pub fn lift_function_blocking(
    func: &Function,
    code_index: &CodeIndex,
    bitness: u32,
) -> HashMap<u64, Vec<PcodeOp>> {
    // Gather the (va, bytes) pairs on the caller's stack â€” cheap, since each
    // instruction is at most 16 bytes. The code index itself is not moved into
    // the worker thread.
    let instrs = collect_function_instructions(func, code_index);

    let handle = std::thread::Builder::new()
        .stack_size(DECODE_STACK_SIZE)
        .name("windy-pcode".to_string())
        .spawn(move || {
            let mut lifter = SleighLifter::for_bitness(bitness);
            let mut map: HashMap<u64, Vec<PcodeOp>> = HashMap::with_capacity(instrs.len());
            for (va, bytes) in &instrs {
                if let Ok(lifted) = lifter.lift_one(bytes, *va) {
                    map.insert(*va, lifted.ops);
                }
            }
            map
        })
        .expect("spawn pcode decode thread");
    handle.join().expect("pcode decode thread panicked")
}

/// Locate the `.text` section of a PE file in memory-mapped bytes.
///
/// Returns `(image_base, virtual_address, raw_offset, raw_size)`. Pure
/// byte-parsing so it works on the raw `LoadedPe::image` mmap without pulling in
/// the full PE analysis stack.
#[allow(dead_code)] // PE section locator used by offline pcode tests/tools
pub fn locate_text_section(bytes: &[u8]) -> Option<(u64, u64, usize, usize)> {
    if bytes.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 4 + 20 > bytes.len() {
        return None;
    }
    // "PE\0\0"
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_header_size = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().ok()?) as usize;
    let machine = u16::from_le_bytes(bytes[coff..coff + 2].try_into().ok()?);
    let is_pe32plus = machine == 0x8664;
    let opt_off = coff + 20;
    if opt_off + (if is_pe32plus { 0x18 } else { 0x10 }) + 4 > bytes.len() {
        return None;
    }
    let image_base = if is_pe32plus {
        u64::from_le_bytes(bytes[opt_off + 0x18..opt_off + 0x20].try_into().ok()?)
    } else {
        u32::from_le_bytes(bytes[opt_off + 0x10..opt_off + 0x14].try_into().ok()?) as u64
    };
    let section_table_off = opt_off + opt_header_size;
    let section_entry = 40usize;
    for i in 0..num_sections {
        let sh = section_table_off + i * section_entry;
        if sh + section_entry > bytes.len() {
            break;
        }
        let name = &bytes[sh..sh + 8];
        if name.starts_with(b".text") {
            let virtual_address =
                u32::from_le_bytes(bytes[sh + 12..sh + 16].try_into().ok()?) as u64;
            let raw_offset = u32::from_le_bytes(bytes[sh + 20..sh + 24].try_into().ok()?) as usize;
            let raw_size = u32::from_le_bytes(bytes[sh + 16..sh + 20].try_into().ok()?) as usize;
            return Some((image_base, virtual_address, raw_offset, raw_size));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `f` on a thread with a large stack.
    ///
    /// The vendored SLEIGH decoder recurses deeply while lifting x86
    /// instructions, so the default libtest worker stack (2 MiB) overflows even
    /// for trivial instructions. We give the decode its own 128 MiB stack so
    /// `cargo test` passes without requiring `RUST_MIN_STACK` to be set.
    fn with_big_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(128 * 1024 * 1024)
            .spawn(f)
            .expect("spawn decode thread")
            .join()
            .expect("decode thread panicked");
    }

    /// `mov [rsp+0x10], edx` (Intel) â€” the Phase 0 verification gate instruction.
    ///
    /// Lifting this must produce a `Store` whose pointer is computed by an
    /// `IntAdd` of the stack pointer and the displacement `0x10`, exactly as
    /// Ghidra's P-code models a memory write through a based+displaced address.
    const MOV_RSP_DISP_EDX: &[u8] = &[0x89, 0x54, 0x24, 0x10];

    /// `add eax, edx` â€” the heart of `add(int a, int b)`.
    const ADD_EAX_EDX: &[u8] = &[0x03, 0xc2];

    /// `mov eax, ecx`.
    const MOV_EAX_ECX: &[u8] = &[0x8b, 0xc1];

    /// `ret`.
    const RET: &[u8] = &[0xc3];

    #[test]
    fn test_pcode_lift_add() {
        with_big_stack(|| {
            let mut lifter = SleighLifter::new();

            // --- `add eax, edx` -> INT_ADD ---
            let add = lifter.lift_one(ADD_EAX_EDX, 0x1000).expect("lift add");
            assert_eq!(add.len, 2);
            let int_add = add
                .ops
                .iter()
                .find(|op| matches!(op, PcodeOp::IntAdd { .. }))
                .expect("add eax,edx must emit IntAdd");
            // IntAdd(out, left, right): out <- left + right
            if let PcodeOp::IntAdd { out, left, right } = int_add {
                // The two inputs are distinct varnodes (eax, edx) feeding one output.
                assert_ne!(left, right, "IntAdd operands should differ");
                assert_eq!(out.size, 4, "32-bit add");
                let _ = (left, right);
            }

            // --- `mov eax, ecx` -> COPY ---
            let mov = lifter.lift_one(MOV_EAX_ECX, 0x1002).expect("lift mov");
            assert!(
                mov.ops.iter().any(|op| matches!(op, PcodeOp::Copy { .. })),
                "mov should emit a Copy"
            );

            // --- `ret` -> RETURN ---
            let ret = lifter.lift_one(RET, 0x1004).expect("lift ret");
            assert!(
                ret.ops
                    .iter()
                    .any(|op| matches!(op, PcodeOp::Return { .. })),
                "ret should emit Return"
            );

            // --- `mov [rsp+0x10], edx` -> STORE + INT_ADD (the gate instruction) ---
            let store = lifter
                .lift_one(MOV_RSP_DISP_EDX, 0x1010)
                .expect("lift store");
            let store_op = store
                .ops
                .iter()
                .find(|op| matches!(op, PcodeOp::Store { .. }))
                .expect("store must emit a Store op");
            let int_add_op = store
                .ops
                .iter()
                .find(|op| matches!(op, PcodeOp::IntAdd { .. }))
                .expect("store through [rsp+0x10] must compute the address with IntAdd");

            // The Store's pointer must be exactly the IntAdd's output varnode â€” i.e.
            // the effective address rsp + 0x10 is materialized once and reused.
            let (store_ptr, add_out) = match (store_op, int_add_op) {
                (PcodeOp::Store { ptr, .. }, PcodeOp::IntAdd { out, .. }) => (ptr, out),
                _ => unreachable!("variant matched above"),
            };
            assert_eq!(
                store_ptr, add_out,
                "Store pointer must equal the IntAdd output (effective address)"
            );

            // The IntAdd right-hand side must be the displacement constant 0x10.
            if let PcodeOp::IntAdd { left, right, .. } = int_add_op {
                // One operand is the stack pointer, the other the 0x10 displacement.
                let disp = if left.offset == 0x10 {
                    left.offset
                } else {
                    right.offset
                };
                assert_eq!(disp, 0x10, "displacement should be 0x10");
            }
        });
    }

    #[test]
    fn test_pcode_lift_control_flow() {
        with_big_stack(|| {
            let mut lifter = SleighLifter::new();
            // `cmp ecx, edx` (39 d1) then `jg` (7f xx) â€” used by max3 decision tree.
            let cmp = lifter.lift_one(&[0x39, 0xd1], 0x2000).expect("lift cmp");
            assert!(
                cmp.ops.iter().any(|op| matches!(
                    op,
                    PcodeOp::IntSub { .. }
                        | PcodeOp::IntLess { .. }
                        | PcodeOp::IntSLess { .. }
                        | PcodeOp::IntEq { .. }
                        | PcodeOp::IntNotEq { .. }
                )),
                "cmp should emit an integer comparison op"
            );

            // `jmp rel32` (e9 xx xx xx xx)
            let jmp = lifter
                .lift_one(&[0xe9, 0x00, 0x00, 0x00, 0x00], 0x2002)
                .expect("lift jmp");
            assert!(
                jmp.ops
                    .iter()
                    .any(|op| matches!(op, PcodeOp::Branch { .. })),
                "jmp should emit Branch"
            );
        });
    }

    #[test]
    fn test_pcode_lift_sample_exe() {
        with_big_stack(|| {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.exe");
            let bytes = std::fs::read(path).expect("read sample.exe");
            let (image_base, va, raw_off, raw_size) =
                locate_text_section(&bytes).expect("find .text section");
            let text = &bytes[raw_off..raw_off + raw_size];
            let base_va = image_base + va;

            // 1) Lift the whole .text with the SLEIGH lifter.
            let mut lifter = SleighLifter::new();
            let lifted = lifter.lift_region(text, base_va);
            assert!(
                !lifted.is_empty(),
                "sample.exe .text must lift to at least one instruction"
            );
            // A handful of x86 instructions are true no-ops in P-code: NOP and the
            // memory-barrier fences (LFENCE/SFENCE/MFENCE). Ghidra/rsleigh emit zero
            // ops for these because they have no modeled data-flow effect. Any other
            // instruction with no P-code op list is a lifter bug.
            let is_pcode_noop = |d: &str| {
                d.starts_with("NOP")
                    || d.starts_with("LFENCE")
                    || d.starts_with("SFENCE")
                    || d.starts_with("MFENCE")
                    || d.starts_with("PAUSE")
            };
            let non_noop_empty: Vec<_> = lifted
                .iter()
                .filter(|i| i.ops.is_empty() && !is_pcode_noop(&i.disasm))
                .map(|i| (i.va, i.disasm.clone(), i.len))
                .collect();
            if !non_noop_empty.is_empty() {
                eprintln!(
                    "non-noop instructions with no P-code ops: {:#?}",
                    non_noop_empty
                );
            }
            assert!(
                non_noop_empty.is_empty(),
                "only P-code no-ops (NOP/LFENCE/SFENCE/MFENCE/PAUSE) may have empty op lists ({} bad)",
                non_noop_empty.len()
            );

            // 2) Independent cross-check: decode the SAME bytes with iced-x86 and
            //    confirm the two decoders agree on every instruction boundary. This
            //    stands in for the Ghidra P-code cross-check (byte-accurate decoding
            //    is a prerequisite for correct P-code semantics).
            let iced_instrs: Vec<(u64, usize)> = crate::disasm::decode_range(64, text, base_va)
                .map(|i| (i.ip(), i.len()))
                .collect();
            assert!(!iced_instrs.is_empty(), "iced must also decode .text");

            // Compare boundary-by-boundary up to the shorter of the two; real, clean
            // compiler output should agree across the entire code region.
            let common = lifted.len().min(iced_instrs.len());
            let mut mismatches = 0usize;
            for i in 0..common {
                if lifted[i].len as usize != iced_instrs[i].1 {
                    mismatches += 1;
                }
            }
            assert!(
                mismatches == 0,
                "SLEIGH and iced agree on instruction boundaries for {common} instrs (mismatches: {mismatches})"
            );
            // The decoders should cover essentially the same number of instructions.
            assert!(
                (lifted.len() as i64 - iced_instrs.len() as i64).abs() <= 2,
                "lifted {} vs iced {} instructions",
                lifted.len(),
                iced_instrs.len()
            );
        });
    }
}
