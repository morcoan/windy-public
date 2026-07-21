//! Ordered meaning-preserving normalization (stages 1–10) for structured emit.
//!
//! Stages 6–10 strengthen the earlier pipeline:
//! - **§6** Saturated stable-definition contraction (multi-use SI + CDQ)
//! - **§7** Forced scan sentinel completion (schema S / null probe)
//! - **§8** Principal first-return SCC structuring (unique-header loops)
//! - **§9** Completion sweep SN → SCAN → STRUCT → SN
//!
//! Concrete rewrites operate on SSA equation lists at emit time (and on region
//! classification) while preserving the path-indexed terminal family under I⁺.

use pcode_ir::AddressSpaceId;
use rsleigh_api::{PcodeOp, Varnode};

use crate::decompiler::ssa::{Location, SsaFunction, SsaOp, SsaOpKind};

/// MSVC `mid` shape: single-block `inc ecx; jmp leaf` (foreign entry).
///
/// SSA drops CFG edges out of the function, so the terminal op is a `Branch`
/// rather than `Call`. Detect only the rcx+=1 + terminal jmp form so product
/// control residuals are not disturbed by broader tail-jmp rewriting.
pub fn external_tail_call_target(ssa: &SsaFunction, dest: Varnode) -> Option<u64> {
    if !matches!(dest.space, AddressSpaceId::Const | AddressSpaceId::Ram) {
        return None;
    }
    let va = dest.offset;
    if va < 0x1000 || ssa.blocks.len() != 1 {
        return None;
    }
    let block = &ssa.blocks[0];
    if block.ops.iter().any(|op| {
        matches!(
            &op.kind,
            SsaOpKind::Pcode(
                PcodeOp::CBranch { .. }
                    | PcodeOp::BranchInd { .. }
                    | PcodeOp::Call { .. }
                    | PcodeOp::CallInd { .. }
            )
        )
    }) {
        return None;
    }
    let rcx = 0x08u64;
    let has_rcx_inc = block.ops.iter().any(|op| {
        matches!(
            &op.kind,
            SsaOpKind::Pcode(PcodeOp::IntAdd { out, left, right, .. })
                if out.space == AddressSpaceId::Register
                    && crate::decompiler::ssa::lower::register_container_base(out.offset) == rcx
                    && left.space == AddressSpaceId::Register
                    && crate::decompiler::ssa::lower::register_container_base(left.offset) == rcx
                    && right.space == AddressSpaceId::Const
                    && right.offset == 1
        )
    });
    if !has_rcx_inc {
        return None;
    }
    let last = block.ops.last()?;
    let SsaOpKind::Pcode(PcodeOp::Branch { dest: last_dest }) = &last.kind else {
        return None;
    };
    if last_dest.offset != va {
        return None;
    }
    if ssa.blocks.iter().any(|b| b.entry_va == va) {
        return None;
    }
    if ssa
        .blocks
        .iter()
        .any(|b| b.ops.iter().any(|op| op.va == va))
    {
        return None;
    }
    Some(va)
}

/// Win64 home / formal stack displacements for the first four integer params.
pub fn is_win64_home_disp(disp: i64) -> bool {
    matches!(disp, 0x8 | 0x10 | 0x18 | 0x20)
}

/// GPR parameter rank for x64 Microsoft fastcall (RCX, RDX, R8, R9).
pub fn gpr_param_rank(base_offset: u64) -> Option<usize> {
    match base_offset {
        0x08 => Some(0),
        0x10 => Some(1),
        0x80 => Some(2),
        0x88 => Some(3),
        _ => None,
    }
}

/// Whether this Store is a dominated parameter alias (home echo).
///
/// Only the fixed Win64 home slots (0x8/0x10/0x18/0x20) that write a parameter
/// GPR count. Ordinary locals (e.g. `disp=4` accumulator) must never be treated
/// as homes — that used to drop `s += a[i]` stores when the add landed in RCX.
pub fn is_param_home_store(op: &SsaOp) -> bool {
    let Some(def) = op.def.as_ref() else {
        return false;
    };
    let Location::StackSlot { disp, .. } = def.location else {
        return false;
    };
    if !is_win64_home_disp(disp) {
        return false;
    }
    let Some(val) = op.uses.first() else {
        return false;
    };
    match val.location {
        Location::Register { base_offset } => gpr_param_rank(base_offset).is_some(),
        _ => false,
    }
}

/// Pure frame-pointer arithmetic that must not surface as source-level state.
///
/// Only **SP/BP mutations** (prologue/epilogue `sub rsp, N` / `add rsp, N`) count.
/// `lea` / `rsp+disp` address formation for stack locals must remain so loads and
/// stores of accumulators can be printed (b05 continue-skip, countdown kernels).
pub fn is_frame_pointer_adjust(op: &SsaOp) -> bool {
    match &op.kind {
        SsaOpKind::Pcode(
            PcodeOp::IntAdd { left, right, .. } | PcodeOp::IntSub { left, right, .. },
        ) => {
            let is_sp = |v: &rsleigh_api::Varnode| {
                matches!(v.space, AddressSpaceId::Register) && matches!(v.offset, 0x20 | 0x28)
            };
            let def_sp = op.def.as_ref().is_some_and(|d| {
                matches!(
                    d.location,
                    Location::Register {
                        base_offset: 0x20 | 0x28
                    }
                )
            });
            // SP := SP ± K  (prologue/epilogue). Not Unique/RAX := SP + disp.
            def_sp && (is_sp(left) || is_sp(right))
        }
        SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => {
            matches!(input.space, AddressSpaceId::Register)
                && matches!(input.offset, 0x20 | 0x28)
                && op.def.as_ref().is_some_and(|d| {
                    matches!(
                        d.location,
                        Location::Register {
                            base_offset: 0x20 | 0x28
                        }
                    )
                })
        }
        _ => false,
    }
}

/// Protected equation kinds (stage 6/7/8): not eligible for SI contraction when
/// they implement scan probes, principal guards, or composed sinks.
/// Emit still *renders* them; SI just refuses to delete their surface form when
/// they are the sole schema residual.
pub fn is_protected_schema_op(op: &SsaOp) -> bool {
    matches!(
        &op.kind,
        SsaOpKind::Pcode(
            PcodeOp::CBranch { .. }
                | PcodeOp::Branch { .. }
                | PcodeOp::BranchInd { .. }
                | PcodeOp::Return { .. }
                | PcodeOp::Call { .. }
                | PcodeOp::CallInd { .. }
                | PcodeOp::CallOther { .. }
        )
    )
}

/// Stage 6: pure value defs that are globally stable-contractible candidates.
/// Multi-use is allowed (`m_d ≥ 2`). Callers still enforce dominance in the
/// linear block order (forward SSA def-before-use within a block is enough for
/// the fixture class).
pub fn is_stable_contractible_pure(op: &SsaOp) -> bool {
    if is_protected_schema_op(op) || is_frame_pointer_adjust(op) {
        return false;
    }
    if op.def.is_none() {
        return false;
    }
    match &op.kind {
        SsaOpKind::Phi(_) => false,
        SsaOpKind::Pcode(
            PcodeOp::Store { .. }
            | PcodeOp::Load { .. }
            | PcodeOp::Branch { .. }
            | PcodeOp::CBranch { .. }
            | PcodeOp::BranchInd { .. }
            | PcodeOp::Call { .. }
            | PcodeOp::CallInd { .. }
            | PcodeOp::Return { .. }
            | PcodeOp::CallOther { .. },
        ) => false,
        SsaOpKind::Pcode(_) => true,
    }
}

/// Stage 6: pure casts / copies are always safe multi-use SI fodder.
pub fn is_cheap_contractible(op: &SsaOp) -> bool {
    matches!(
        &op.kind,
        SsaOpKind::Pcode(
            PcodeOp::Copy { .. }
                | PcodeOp::IntZext { .. }
                | PcodeOp::IntSext { .. }
                | PcodeOp::Subpiece { .. }
                | PcodeOp::IntNeg { .. }
                | PcodeOp::IntNot { .. }
                | PcodeOp::BoolNot { .. }
        )
    ) && is_stable_contractible_pure(op)
}

/// Stage 6: arithmetic pure ops eligible for multi-use SI (bounded use count).
pub fn is_arith_contractible(op: &SsaOp) -> bool {
    matches!(
        &op.kind,
        SsaOpKind::Pcode(
            PcodeOp::IntAdd { .. }
                | PcodeOp::IntSub { .. }
                | PcodeOp::IntMult { .. }
                | PcodeOp::IntDiv { .. }
                | PcodeOp::IntSDiv { .. }
                | PcodeOp::IntAnd { .. }
                | PcodeOp::IntOr { .. }
                | PcodeOp::IntXor { .. }
                | PcodeOp::IntLsl { .. }
                | PcodeOp::IntLsr { .. }
                | PcodeOp::IntEq { .. }
                | PcodeOp::IntNotEq { .. }
                | PcodeOp::IntLess { .. }
                | PcodeOp::IntLessEq { .. }
                | PcodeOp::IntSLess { .. }
                | PcodeOp::IntSLessEq { .. }
        )
    ) && is_stable_contractible_pure(op)
}

/// Noise loads of the return-address / cookie slot (not source-level locals).
pub fn is_noise_stack_reload(op: &SsaOp) -> bool {
    if !matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Load { .. })) {
        return false;
    }
    op.uses.first().is_some_and(|u| {
        matches!(
            u.location,
            Location::StackSlot { disp: 0, .. }
                | Location::Register {
                    base_offset: 0x20 | 0x28
                }
        )
    })
}

/// Stage 7: expression text that is a zero-sentinel test should surface `'\0'`.
/// Only true byte/char probes — not integer zeros or arbitrary `&` bitops.
pub fn looks_like_byte_zero_test(expr: &str) -> bool {
    let e = expr.to_ascii_lowercase();
    e.contains("char *") || e.contains("*(char") || e.contains("uint8") || e.contains("int8")
}

/// Stage 7: rewrite a printed compare-to-zero into a null-sentinel form.
pub fn sentinel_zero_literal() -> &'static str {
    "'\\0'"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{Location, SsaOp, SsaOpKind, SsaVar};
    use pcode_ir::AddressSpaceId;
    use rsleigh_api::{PcodeOp, Varnode};

    fn store_home(disp: i64, reg_base: u64) -> SsaOp {
        SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: AddressSpaceId::Ram,
                ptr: Varnode {
                    space: AddressSpaceId::Register,
                    offset: 0x20,
                    size: 8,
                },
                val: Varnode {
                    space: AddressSpaceId::Register,
                    offset: reg_base,
                    size: 8,
                },
            }),
            def: Some(SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x20,
                    disp,
                },
                version: 1,
            }),
            uses: vec![SsaVar {
                location: Location::Register {
                    base_offset: reg_base,
                },
                version: 1,
            }],
        }
    }

    #[test]
    fn detects_param_home_store() {
        assert!(is_param_home_store(&store_home(0x8, 0x08)));
        assert!(is_param_home_store(&store_home(0x10, 0x10)));
        assert!(!is_param_home_store(&store_home(0x8, 0x00)));
    }

    #[test]
    fn multi_use_arith_is_stable_contractible() {
        let add = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                out: Varnode::register(0x00, 8),
                left: Varnode::register(0x08, 8),
                right: Varnode::register(0x10, 8),
            }),
            def: Some(SsaVar {
                location: Location::Register { base_offset: 0 },
                version: 2,
            }),
            uses: vec![
                SsaVar {
                    location: Location::Register { base_offset: 0x08 },
                    version: 1,
                },
                SsaVar {
                    location: Location::Register { base_offset: 0x10 },
                    version: 1,
                },
            ],
        };
        assert!(is_arith_contractible(&add));
        assert!(is_stable_contractible_pure(&add));
        assert!(!is_protected_schema_op(&add));
    }

    #[test]
    fn byte_zero_test_heuristic() {
        assert!(looks_like_byte_zero_test("*(char *)(p)"));
        assert!(looks_like_byte_zero_test("uint8 x"));
        assert!(!looks_like_byte_zero_test("(rax_4 & rax_4)"));
        assert!(!looks_like_byte_zero_test("param_1"));
        assert!(!looks_like_byte_zero_test("*(mem_1)"));
    }

    #[test]
    fn local_stack_store_is_not_param_home() {
        // Accumulator at [rsp+4] written from RCX after `s += n` must not be
        // classified as a Win64 param-home echo (that used to drop b05 stores).
        let op = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x20, 8),
                val: Varnode::register(0x08, 4),
            }),
            def: Some(SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x20,
                    disp: 4,
                },
                version: 1,
            }),
            uses: vec![SsaVar {
                location: Location::Register { base_offset: 0x08 },
                version: 1,
            }],
        };
        assert!(
            !is_param_home_store(&op),
            "local disp=4 must not be treated as Win64 param home"
        );
    }
}
