//! Side-layer points-to map over optimized SSA (Phase 7 C).
//!
//! `Location::RawRam` stays a single opaque SSA token. This map resolves Load
//! and Store pointer operands to concrete targets (globals, IAT slots, stack
//! refs, params, or heap-unknown) without mutating the SSA enum.

use std::collections::HashMap;

use iced_x86::Register;
use pcode_ir::AddressSpaceId;
use rsleigh_api::PcodeOp;
use serde::Serialize;

use crate::decompiler::ssa::lower::register_container_base;
use crate::decompiler::ssa::{Location, SsaFunction, SsaOp, SsaOpKind, SsaVar};
use crate::loader::address_space::AddressSpace;
use crate::project::symbols::SymbolTable;

/// Classification of a resolved pointer target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum PointsToKind {
    Global,
    IATSlot,
    StackRef,
    HeapUnknown,
    ParamPtr,
}

/// One resolved pointer target for a Load/Store operand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PointsToEntry {
    pub kind: PointsToKind,
    pub va: Option<u64>,
    pub symbol: Option<String>,
    /// Frame-relative displacement when `kind == StackRef`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_disp: Option<i64>,
}

/// Side-map: `(instruction_va, operand_index) → resolved target`.
/// Operand index 0 is the pointer operand of Load/Store.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PointsToMap {
    pub entries: HashMap<(u64, u32), PointsToEntry>,
}

impl PointsToMap {
    pub fn get(&self, va: u64, op_index: u32) -> Option<&PointsToEntry> {
        self.entries.get(&(va, op_index))
    }

    pub fn by_instruction(&self, va: u64) -> Option<&PointsToEntry> {
        self.get(va, 0)
    }

    /// All distinct global VAs resolved in this function.
    #[cfg(test)]
    pub fn global_vas(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .entries
            .values()
            .filter(|e| matches!(e.kind, PointsToKind::Global | PointsToKind::IATSlot))
            .filter_map(|e| e.va)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    pub fn to_json(&self) -> serde_json::Value {
        let arr: Vec<_> = self
            .entries
            .iter()
            .map(|((insn, idx), e)| {
                serde_json::json!({
                    "instruction_va": format!("{insn:#x}"),
                    "operand_index": idx,
                    "kind": format!("{:?}", e.kind),
                    "va": e.va.map(|v| format!("{v:#x}")),
                    "symbol": e.symbol,
                    "stack_disp": e.stack_disp,
                })
            })
            .collect();
        serde_json::json!({ "entries": arr, "count": arr.len() })
    }
}

/// Context required to resolve pointer targets.
pub struct PointsToCtx<'a> {
    pub address_space: &'a AddressSpace,
    pub symbols: &'a SymbolTable,
    /// Optional: instruction VA → iced memory target (from project layer).
    pub insn_global: &'a HashMap<u64, u64>,
    /// Optional: is this VA an import/IAT slot?
    pub is_iat: &'a dyn Fn(u64) -> bool,
}

/// Build a points-to map for `ssa` after SSA construction.
pub fn compute_points_to(ssa: &SsaFunction, ctx: &PointsToCtx<'_>) -> PointsToMap {
    let mut map = PointsToMap::default();

    // def SsaVar → defining op (for backward tracing).
    let mut def_op: HashMap<SsaVar, &SsaOp> = HashMap::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            if let Some(d) = &op.def {
                def_op.insert(d.clone(), op);
            }
        }
    }

    for block in &ssa.blocks {
        for op in &block.ops {
            let SsaOpKind::Pcode(pcode) = &op.kind else {
                continue;
            };
            let ptr_vn = match pcode {
                PcodeOp::Load { ptr, .. } | PcodeOp::Store { ptr, .. } => *ptr,
                _ => continue,
            };
            // Stack-slot uses already resolved by lower.rs.
            if let Some(u) = op.uses.first()
                && let Location::StackSlot { disp, .. } = u.location
            {
                map.entries.insert(
                    (op.va, 0),
                    PointsToEntry {
                        kind: PointsToKind::StackRef,
                        va: None,
                        symbol: None,
                        stack_disp: Some(disp),
                    },
                );
                continue;
            }

            // Prefer project-layer RIP-relative resolution.
            if let Some(&gva) = ctx.insn_global.get(&op.va) {
                let is_iat = (ctx.is_iat)(gva);
                let sym = ctx.symbols.name(gva).map(str::to_string);
                map.entries.insert(
                    (op.va, 0),
                    PointsToEntry {
                        kind: if is_iat {
                            PointsToKind::IATSlot
                        } else {
                            PointsToKind::Global
                        },
                        va: Some(gva),
                        symbol: sym,
                        stack_disp: None,
                    },
                );
                continue;
            }

            // Trace the pointer varnode / register use.
            let entry = resolve_pointer(ptr_vn, op, &def_op, ctx);
            map.entries.insert((op.va, 0), entry);
        }
    }
    map
}

fn resolve_pointer(
    ptr: rsleigh_api::Varnode,
    op: &SsaOp,
    def_op: &HashMap<SsaVar, &SsaOp>,
    ctx: &PointsToCtx<'_>,
) -> PointsToEntry {
    // Const / Ram space → direct address.
    if ptr.space == AddressSpaceId::Const || ptr.space == AddressSpaceId::Ram {
        let va = ptr.offset;
        if va != 0 && ctx.address_space.is_data_va(va) {
            let is_iat = (ctx.is_iat)(va);
            return PointsToEntry {
                kind: if is_iat {
                    PointsToKind::IATSlot
                } else {
                    PointsToKind::Global
                },
                va: Some(va),
                symbol: ctx.symbols.name(va).map(str::to_string),
                stack_disp: None,
            };
        }
        return PointsToEntry {
            kind: PointsToKind::HeapUnknown,
            va: if va != 0 { Some(va) } else { None },
            symbol: None,
            stack_disp: None,
        };
    }

    // Find the use matching the pointer — register by container, Unique by
    // exact instruction-scoped identity (never first-register guesswork).
    let use_sv = if ptr.space == AddressSpaceId::Register {
        let base = register_container_base(ptr.offset);
        op.uses.iter().find(
            |u| matches!(u.location, Location::Register { base_offset } if base_offset == base),
        )
    } else if ptr.space == AddressSpaceId::Unique {
        op.uses.iter().find(|u| {
            matches!(
                &u.location,
                Location::Unique {
                    instruction_va,
                    offset,
                    size
                } if *instruction_va == op.va && *offset == ptr.offset && *size == ptr.size
            )
        })
    } else {
        None
    };

    let Some(sv) = use_sv else {
        return PointsToEntry {
            kind: PointsToKind::HeapUnknown,
            va: None,
            symbol: None,
            stack_disp: None,
        };
    };

    // Live-in param (no defining op, version 1).
    if sv.version == 1
        && !def_op.contains_key(sv)
        && let Location::Register { base_offset } = sv.location
        && is_param_reg(base_offset)
    {
        return PointsToEntry {
            kind: PointsToKind::ParamPtr,
            va: None,
            symbol: Some(format!("param_{}", reg_label(base_offset))),
            stack_disp: None,
        };
    }

    // Trace reaching defs through Copy / IntAdd chains (bounded).
    let mut current = sv.clone();
    for _ in 0..16 {
        let Some(definer) = def_op.get(&current) else {
            break;
        };
        match &definer.kind {
            SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => {
                if input.space == AddressSpaceId::Const {
                    let va = input.offset;
                    if va != 0 && ctx.address_space.is_data_va(va) {
                        return PointsToEntry {
                            kind: if (ctx.is_iat)(va) {
                                PointsToKind::IATSlot
                            } else {
                                PointsToKind::Global
                            },
                            va: Some(va),
                            symbol: ctx.symbols.name(va).map(str::to_string),
                            stack_disp: None,
                        };
                    }
                    return PointsToEntry {
                        kind: PointsToKind::HeapUnknown,
                        va: Some(va),
                        symbol: None,
                        stack_disp: None,
                    };
                }
                if input.space == AddressSpaceId::Register {
                    let base = register_container_base(input.offset);
                    if let Some(u) = definer.uses.iter().find(|u| {
                        matches!(u.location, Location::Register { base_offset } if base_offset == base)
                    }) {
                        current = u.clone();
                        continue;
                    }
                }
                // Copy of unique / other — try first use.
                if let Some(u) = definer.uses.first() {
                    current = u.clone();
                    continue;
                }
                break;
            }
            SsaOpKind::Pcode(PcodeOp::IntAdd { left, right, .. }) => {
                // Prefer const + register form (LEA-style).
                let (base_vn, _disp) = if right.space == AddressSpaceId::Const {
                    (*left, right.offset as i64)
                } else if left.space == AddressSpaceId::Const {
                    (*right, left.offset as i64)
                } else {
                    // Both non-const: follow left use.
                    if let Some(u) = definer.uses.first() {
                        current = u.clone();
                        continue;
                    }
                    break;
                };
                if base_vn.space == AddressSpaceId::Register {
                    let base = register_container_base(base_vn.offset);
                    // RIP is not a SLEIGH register we track as param; LEA [rip+disp]
                    // is usually resolved via insn_global already.
                    if is_frame_ptr(base) {
                        return PointsToEntry {
                            kind: PointsToKind::StackRef,
                            va: None,
                            symbol: None,
                            stack_disp: Some(_disp),
                        };
                    }
                    if let Some(u) = definer.uses.iter().find(|u| {
                        matches!(u.location, Location::Register { base_offset } if base_offset == base)
                    }) {
                        current = u.clone();
                        continue;
                    }
                }
                if let Some(u) = definer.uses.first() {
                    current = u.clone();
                    continue;
                }
                break;
            }
            SsaOpKind::Pcode(PcodeOp::Load { .. }) => {
                // Pointer loaded from memory — if that load has a global target
                // via insn_global, this is a pointer through a global.
                if let Some(&gva) = ctx.insn_global.get(&definer.va) {
                    return PointsToEntry {
                        kind: PointsToKind::HeapUnknown,
                        va: Some(gva),
                        symbol: ctx.symbols.name(gva).map(|n| format!("*{}", n)),
                        stack_disp: None,
                    };
                }
                break;
            }
            _ => break,
        }
    }

    // If we ended on a param live-in.
    if current.version == 1
        && !def_op.contains_key(&current)
        && let Location::Register { base_offset } = current.location
        && is_param_reg(base_offset)
    {
        return PointsToEntry {
            kind: PointsToKind::ParamPtr,
            va: None,
            symbol: Some(format!("param_{}", reg_label(base_offset))),
            stack_disp: None,
        };
    }

    PointsToEntry {
        kind: PointsToKind::HeapUnknown,
        va: None,
        symbol: None,
        stack_disp: None,
    }
}

fn is_frame_ptr(base_offset: u64) -> bool {
    base_offset == 0x20 || base_offset == 0x28 // RSP / RBP
}

fn is_param_reg(base_offset: u64) -> bool {
    matches!(base_offset, 0x08 | 0x10 | 0x80 | 0x88) // RCX RDX R8 R9
}

fn reg_label(base_offset: u64) -> &'static str {
    match base_offset {
        0x08 => "rcx",
        0x10 => "rdx",
        0x80 => "r8",
        0x88 => "r9",
        _ => "reg",
    }
}

/// Resolve RIP-relative target from an iced instruction (re-export helper shape).
#[allow(dead_code)]
pub fn iced_rip_target(instr: &iced_x86::Instruction, bitness: u32) -> Option<u64> {
    if bitness != 64 {
        return None;
    }
    if instr.memory_base() != Register::RIP || instr.memory_index() != Register::None {
        return None;
    }
    let disp = instr.memory_displacement64() as i32 as i64;
    Some(instr.next_ip().wrapping_add(disp as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use crate::loader::address_space::AddressSpace;
    use crate::project::symbols::{SymbolKind, SymbolTable};
    use rsleigh_api::Varnode;

    fn empty_space() -> AddressSpace {
        AddressSpace::new(0x140000000, &[])
    }

    #[test]
    fn stack_ref_from_stack_slot_use() {
        let op = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x28, 8),
            }),
            def: Some(SsaVar {
                location: Location::Register { base_offset: 0x00 },
                version: 2,
            }),
            uses: vec![SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x28,
                    disp: -0x10,
                },
                version: 1,
            }],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![op],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x140000000,
        };
        let space = empty_space();
        let symbols = SymbolTable::default();
        let insn_global = HashMap::new();
        let is_iat = |_va: u64| false;
        let ctx = PointsToCtx {
            address_space: &space,
            symbols: &symbols,
            insn_global: &insn_global,
            is_iat: &is_iat,
        };
        let map = compute_points_to(&ssa, &ctx);
        let e = map.by_instruction(0x1000).expect("entry");
        assert_eq!(e.kind, PointsToKind::StackRef);
        assert_eq!(e.stack_disp, Some(-0x10));
    }

    #[test]
    fn two_globals_via_insn_map() {
        let load1 = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x08, 8),
            }),
            def: Some(SsaVar {
                location: Location::RawRam,
                version: 1,
            }),
            uses: vec![SsaVar {
                location: Location::Register { base_offset: 0x08 },
                version: 1,
            }],
        };
        let load2 = SsaOp {
            va: 0x1010,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x08, 8),
            }),
            def: Some(SsaVar {
                location: Location::RawRam,
                version: 2,
            }),
            uses: vec![SsaVar {
                location: Location::Register { base_offset: 0x08 },
                version: 1,
            }],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![load1, load2],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x140000000,
        };
        let space = empty_space();
        let mut symbols = SymbolTable::default();
        symbols.insert(0x140001000, "g_count", SymbolKind::Data);
        symbols.insert(0x140005000, "g_total", SymbolKind::Data);
        let mut insn_global = HashMap::new();
        insn_global.insert(0x1000, 0x140001000);
        insn_global.insert(0x1010, 0x140005000);
        let is_iat = |_va: u64| false;
        let ctx = PointsToCtx {
            address_space: &space,
            symbols: &symbols,
            insn_global: &insn_global,
            is_iat: &is_iat,
        };
        let map = compute_points_to(&ssa, &ctx);
        let vas = map.global_vas();
        assert_eq!(vas.len(), 2);
        assert!(vas.contains(&0x140001000));
        assert!(vas.contains(&0x140005000));
        assert_eq!(
            map.by_instruction(0x1000).and_then(|e| e.symbol.as_deref()),
            Some("g_count")
        );
        assert_eq!(
            map.by_instruction(0x1010).and_then(|e| e.symbol.as_deref()),
            Some("g_total")
        );
    }
}
