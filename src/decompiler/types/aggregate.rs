//! Stack aggregate (struct) inference over recovered stack locals (Phase 7 B).
//!
//! After type recovery, contiguous stack slots that share a base register are
//! grouped into a synthetic `CompositeType` so the LLM sees fields of one
//! struct rather than independent `local_0` / `local_4` / `local_8` slots.

use std::collections::BTreeMap;

use crate::decompiler::ssa::{Location, SsaFunction};
use crate::decompiler::types::recover::{StackLocalType, TyGuess};
use crate::project::types::{CompositeKind, CompositeType, DataType, Field};

/// Maximum gap (bytes) between consecutive field ends and next starts that
/// still counts as contiguous. Gaps larger than this split the group.
const MAX_GAP: i64 = 4;

/// Infer struct aggregates from recovered stack locals + SSA stack-slot bases.
///
/// Groups by `base_reg`, sorts by displacement, and emits one composite per
/// contiguous run of ≥2 typed locals.
pub fn infer_aggregates(
    ssa: &SsaFunction,
    locals: &[StackLocalType],
    function_va: u64,
) -> Vec<CompositeType> {
    if locals.len() < 2 {
        return Vec::new();
    }

    // Map disp → base_reg (first seen) from SSA StackSlot locations.
    let mut offset_base: BTreeMap<i64, u64> = BTreeMap::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            for loc in op
                .def
                .iter()
                .map(|d| &d.location)
                .chain(op.uses.iter().map(|u| &u.location))
            {
                if let Location::StackSlot { base_reg, disp } = loc {
                    offset_base.entry(*disp).or_insert(*base_reg);
                }
            }
        }
    }

    // Group typed locals by base_reg.
    let mut by_base: BTreeMap<u64, Vec<&StackLocalType>> = BTreeMap::new();
    for local in locals {
        if matches!(local.ty, TyGuess::Unknown) {
            continue;
        }
        // Prefer negative offsets (true locals); skip pure args (positive).
        if local.offset > 0 {
            continue;
        }
        let base = offset_base.get(&local.offset).copied().unwrap_or(0x28);
        by_base.entry(base).or_default().push(local);
    }

    let mut out = Vec::new();
    for (base_reg, mut group) in by_base {
        group.sort_by_key(|l| l.offset);
        // Walk contiguous runs.
        let mut run_start = 0usize;
        while run_start < group.len() {
            let mut run_end = run_start + 1;
            while run_end < group.len() {
                let prev = group[run_end - 1];
                let cur = group[run_end];
                let prev_size = ty_byte_size(&prev.ty) as i64;
                let prev_end = prev.offset + prev_size;
                let gap = cur.offset - prev_end;
                if gap > MAX_GAP {
                    break;
                }
                run_end += 1;
            }
            if run_end - run_start >= 2 {
                let run = &group[run_start..run_end];
                let name = format!("__ws_{function_va:x}_{base_reg:x}");
                let base_off = run[0].offset;
                let mut fields = Vec::new();
                let mut max_end = 0u64;
                for (i, local) in run.iter().enumerate() {
                    let rel = (local.offset - base_off) as u64;
                    let size = ty_byte_size(&local.ty);
                    max_end = max_end.max(rel + size as u64);
                    fields.push(Field {
                        name: format!("field_{i}"),
                        ty: local.ty.to_data_type(64),
                        offset: rel,
                        bit_offset: None,
                    });
                }
                out.push(CompositeType {
                    kind: CompositeKind::Struct,
                    name,
                    size: max_end,
                    align: 4,
                    fields,
                    variants: Vec::new(),
                });
            }
            run_start = run_end;
        }
    }
    out
}

fn ty_byte_size(ty: &TyGuess) -> u32 {
    match ty {
        TyGuess::Unknown => 8,
        TyGuess::Int(b) | TyGuess::Uint(b) => (*b as u32) / 8,
        TyGuess::Bool => 1,
        TyGuess::Float => 4,
        TyGuess::Double => 8,
        TyGuess::Ptr(_) => 8,
    }
}

/// Map each aggregate to the absolute base offset of its first field.
pub fn aggregate_base_offsets(
    locals: &[StackLocalType],
    aggregates: &[CompositeType],
) -> Vec<(i64, String)> {
    let mut out = Vec::new();
    for agg in aggregates {
        if let Some(b) = match_run_base(locals, agg) {
            out.push((b, agg.name.clone()));
        }
    }
    out
}

fn match_run_base(locals: &[StackLocalType], agg: &CompositeType) -> Option<i64> {
    let mut typed: Vec<&StackLocalType> = locals
        .iter()
        .filter(|l| !matches!(l.ty, TyGuess::Unknown) && l.offset <= 0)
        .collect();
    typed.sort_by_key(|l| l.offset);
    if typed.len() < agg.fields.len() {
        return None;
    }
    'outer: for start in 0..=typed.len() - agg.fields.len() {
        let base = typed[start].offset;
        for (i, f) in agg.fields.iter().enumerate() {
            let local = typed[start + i];
            if (local.offset - base) as u64 != f.offset {
                continue 'outer;
            }
            // Loose type match: bit widths.
            let local_dt = local.ty.to_data_type(64);
            if std::mem::discriminant(&local_dt) != std::mem::discriminant(&f.ty)
                && !matches!(
                    (&local_dt, &f.ty),
                    (DataType::Int(_), DataType::Uint(_)) | (DataType::Uint(_), DataType::Int(_))
                )
            {
                // still accept if both are integers of same size
                match (&local_dt, &f.ty) {
                    (DataType::Int(a), DataType::Int(b))
                    | (DataType::Uint(a), DataType::Uint(b))
                    | (DataType::Int(a), DataType::Uint(b))
                    | (DataType::Uint(a), DataType::Int(b))
                        if a == b => {}
                    _ if local_dt == f.ty => {}
                    _ => continue 'outer,
                }
            }
        }
        return Some(base);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};
    use pcode_ir::AddressSpaceId;
    use rsleigh_api::{PcodeOp, Varnode};

    fn stack_var(base_reg: u64, disp: i64, version: u32) -> SsaVar {
        SsaVar {
            location: Location::StackSlot { base_reg, disp },
            version,
        }
    }

    #[test]
    fn three_contiguous_uint32_become_one_struct() {
        let locals = vec![
            StackLocalType {
                offset: -0x10,
                ty: TyGuess::Uint(32),
                old_ty: TyGuess::Unknown,
            },
            StackLocalType {
                offset: -0xc,
                ty: TyGuess::Uint(32),
                old_ty: TyGuess::Unknown,
            },
            StackLocalType {
                offset: -0x8,
                ty: TyGuess::Uint(32),
                old_ty: TyGuess::Unknown,
            },
        ];
        // Synthetic SSA with stack slots at those offsets.
        let ops = vec![
            SsaOp {
                va: 0x1000,
                kind: SsaOpKind::Pcode(PcodeOp::Store {
                    space: AddressSpaceId::Ram,
                    ptr: Varnode::register(0x28, 8),
                    val: Varnode::register(0x00, 4),
                }),
                def: Some(stack_var(0x28, -0x10, 1)),
                uses: vec![],
            },
            SsaOp {
                va: 0x1004,
                kind: SsaOpKind::Pcode(PcodeOp::Store {
                    space: AddressSpaceId::Ram,
                    ptr: Varnode::register(0x28, 8),
                    val: Varnode::register(0x00, 4),
                }),
                def: Some(stack_var(0x28, -0xc, 1)),
                uses: vec![],
            },
            SsaOp {
                va: 0x1008,
                kind: SsaOpKind::Pcode(PcodeOp::Store {
                    space: AddressSpaceId::Ram,
                    ptr: Varnode::register(0x28, 8),
                    val: Varnode::register(0x00, 4),
                }),
                def: Some(stack_var(0x28, -0x8, 1)),
                uses: vec![],
            },
        ];
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops,
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x140000000,
        };
        let aggs = infer_aggregates(&ssa, &locals, 0x1000);
        assert_eq!(aggs.len(), 1, "expected one struct: {aggs:?}");
        assert_eq!(aggs[0].fields.len(), 3);
        assert_eq!(aggs[0].kind, CompositeKind::Struct);
        assert!(aggs[0].name.starts_with("__ws_1000_"));
        assert_eq!(aggs[0].fields[0].offset, 0);
        assert_eq!(aggs[0].fields[1].offset, 4);
        assert_eq!(aggs[0].fields[2].offset, 8);
    }

    #[test]
    fn gapped_locals_do_not_merge() {
        let locals = vec![
            StackLocalType {
                offset: -0x20,
                ty: TyGuess::Uint(32),
                old_ty: TyGuess::Unknown,
            },
            StackLocalType {
                offset: -0x8,
                ty: TyGuess::Uint(32),
                old_ty: TyGuess::Unknown,
            },
        ];
        let ssa = SsaFunction {
            entry_va: 0x2000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x2000,
                ops: vec![],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0,
        };
        let aggs = infer_aggregates(&ssa, &locals, 0x2000);
        assert!(aggs.is_empty(), "gap too large: {aggs:?}");
    }
}
