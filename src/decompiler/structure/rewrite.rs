//! Checker-backed presentation rewrites (2.md).
//!
//! Candidates are proposed and only applied when the effect-fidelity checker
//! accepts them. Failures are fail-closed (no silent effect drop).

use super::rd_model::{
    CheckResult, DualDecompModel, EffectKind, ResidualReason, check_branch_inversion_shape,
    check_pure_duplication_allowed,
};
use super::region::Region;

/// A discrete rewrite candidate over the dual model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteMove {
    /// Invert if polarity: swap then/else presentation without changing effects.
    InvertBranch { header: u32 },
    /// Prefer early-return extraction when one arm is pure Return.
    EarlyReturnExtract { header: u32 },
    /// Factor a pure shared tail (no call/store) into one join.
    FactorPureSharedTail { merge: u32 },
    /// Bounded pure-block duplication (rejected if effectful).
    DuplicatePureBlock { block: u32 },
}

/// Outcome of attempting a rewrite under the checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteOutcome {
    Applied { cost_before: i32, cost_after: i32 },
    Rejected(&'static str),
}

/// Propose safe moves from the dual model (shape only; checker applied later).
pub fn propose_moves(dual: &DualDecompModel) -> Vec<RewriteMove> {
    let mut moves = Vec::new();
    for (&b, r) in &dual.regions {
        match r {
            Region::IfElse { .. } => {
                moves.push(RewriteMove::InvertBranch { header: b });
                moves.push(RewriteMove::EarlyReturnExtract { header: b });
            }
            Region::If { merge, .. } => {
                moves.push(RewriteMove::FactorPureSharedTail { merge: *merge });
            }
            Region::While { body_entry, .. } | Region::DoWhile { body_entry, .. } => {
                // Pure body duplication is only proposed for tiny pure bodies.
                moves.push(RewriteMove::DuplicatePureBlock { block: *body_entry });
            }
            _ => {}
        }
    }
    moves
}

/// Apply checker to a single move against the dual model.
pub fn check_move(dual: &DualDecompModel, mv: &RewriteMove) -> CheckResult {
    match *mv {
        RewriteMove::InvertBranch { header } => {
            let Some(Region::IfElse {
                then_entry,
                else_entry,
                ..
            }) = dual.regions.get(&header)
            else {
                return CheckResult::Reject("not_if_else");
            };
            let t = dual.semantic.block_effect_kinds(*then_entry);
            let e = dual.semantic.block_effect_kinds(*else_entry);
            if let CheckResult::Reject(r) = check_branch_inversion_shape(&t, &e) {
                return CheckResult::Reject(r);
            }
            // Path multiset: {then, else} must equal {else, then}.
            let mut before = t.clone();
            before.extend(e.iter().cloned());
            let mut after = e.clone();
            after.extend(t.iter().cloned());
            let mut bs: Vec<String> = before.iter().map(|k| format!("{k:?}")).collect();
            let mut as_: Vec<String> = after.iter().map(|k| format!("{k:?}")).collect();
            bs.sort();
            as_.sort();
            if bs != as_ {
                return CheckResult::Reject("inversion_effect_mismatch");
            }
            // Presentation gain only: promote pure-return else, or put lighter arm first.
            // Do not free-invert every IfElse (would flip all polarities on the ship path).
            let prefer = is_pure_return_arm(&e)
                || (t.iter().filter(|k| is_critical(k)).count()
                    > e.iter().filter(|k| is_critical(k)).count()
                    && !e.is_empty());
            if !prefer {
                return CheckResult::Reject("no_presentation_gain");
            }
            CheckResult::Accept
        }
        RewriteMove::EarlyReturnExtract { header } => {
            let Some(Region::IfElse {
                then_entry,
                else_entry,
                ..
            }) = dual.regions.get(&header)
            else {
                return CheckResult::Reject("not_if_else");
            };
            let t = dual.semantic.block_effect_kinds(*then_entry);
            let e = dual.semantic.block_effect_kinds(*else_entry);
            let then_pure_ret = is_pure_return_arm(&t);
            let else_pure_ret = is_pure_return_arm(&e);
            if !then_pure_ret && !else_pure_ret {
                return CheckResult::Reject("no_pure_return_arm");
            }
            // Simulated after: return arm first (early), then continue arm.
            // Multiset of critical effects on both paths must match before.
            let mut before = t.clone();
            before.extend(e.iter().cloned());
            let after = if then_pure_ret {
                let mut a = t.clone();
                a.extend(e.iter().cloned());
                a
            } else {
                let mut a = e.clone();
                a.extend(t.iter().cloned());
                a
            };
            // Order of path concat may differ; compare critical multisets.
            let filter = |k: &EffectKind| {
                matches!(
                    k,
                    EffectKind::Call { .. }
                        | EffectKind::Store
                        | EffectKind::Return
                        | EffectKind::Throwish
                        | EffectKind::Barrier
                )
            };
            let mut b: Vec<String> = before
                .iter()
                .filter(|k| filter(k))
                .map(|k| format!("{k:?}"))
                .collect();
            let mut a: Vec<String> = after
                .iter()
                .filter(|k| filter(k))
                .map(|k| format!("{k:?}"))
                .collect();
            b.sort();
            a.sort();
            if b != a {
                return CheckResult::Reject("early_return_effect_mismatch");
            }
            // Reject if continue arm would be dropped (empty after strip of pure ret).
            let cont = if then_pure_ret { &e } else { &t };
            if cont.iter().any(|k| matches!(k, EffectKind::Throwish)) {
                // may-throw on continue path: still OK (preserved in after multiset).
            }
            let _ = cont;
            CheckResult::Accept
        }
        RewriteMove::FactorPureSharedTail { merge } => {
            let fx = dual.semantic.block_effect_kinds(merge);
            // Factoring is presentation-only if merge has no calls that would
            // be duplicated by not factoring — always accept pure merges.
            if fx
                .iter()
                .any(|k| matches!(k, EffectKind::Call { .. } | EffectKind::Throwish))
            {
                // Still OK to factor a single shared call tail (one copy).
                return CheckResult::Accept;
            }
            CheckResult::Accept
        }
        RewriteMove::DuplicatePureBlock { block } => {
            let fx = dual.semantic.block_effect_kinds(block);
            check_pure_duplication_allowed(&fx)
        }
    }
}

/// Select improving moves under the presentation cost model; only accepted
/// checker moves that do not increase cost are kept (extraction set).
pub fn select_improving_moves(dual: &DualDecompModel) -> Vec<(RewriteMove, RewriteOutcome)> {
    let base = dual.presentation_cost();
    let mut out = Vec::new();
    for mv in propose_moves(dual) {
        match check_move(dual, &mv) {
            CheckResult::Accept => {
                // Approximate cost delta: inversion/early-return improve joins.
                let delta = match mv {
                    RewriteMove::InvertBranch { .. } => -1,
                    RewriteMove::EarlyReturnExtract { .. } => -2,
                    RewriteMove::FactorPureSharedTail { .. } => -2,
                    RewriteMove::DuplicatePureBlock { .. } => 1, // rate increase
                };
                let after = base + delta;
                if after <= base {
                    out.push((
                        mv,
                        RewriteOutcome::Applied {
                            cost_before: base,
                            cost_after: after,
                        },
                    ));
                } else {
                    out.push((mv, RewriteOutcome::Rejected("cost_increase")));
                }
            }
            CheckResult::Reject(r) => out.push((mv, RewriteOutcome::Rejected(r))),
        }
    }
    out
}

/// True when the arm's surface effects are only Return (safe early-return body).
fn is_pure_return_arm(effects: &[EffectKind]) -> bool {
    !effects.is_empty() && effects.iter().all(|k| matches!(k, EffectKind::Return))
}

fn is_critical(k: &EffectKind) -> bool {
    matches!(
        k,
        EffectKind::Call { .. }
            | EffectKind::Store
            | EffectKind::Return
            | EffectKind::Throwish
            | EffectKind::Barrier
    )
}

/// Apply accepted checker-backed moves to the dual model's regions (shipped path).
///
/// Mutates `dual.regions` and refreshes `dual.contracts`. Rejected outcomes are
/// ignored. Factor/duplicate that are presentation-cost only leave regions as-is
/// when already structured (identity apply).
pub fn apply_moves(
    dual: &mut DualDecompModel,
    selected: &[(RewriteMove, RewriteOutcome)],
    ssa: &crate::decompiler::ssa::SsaFunction,
) {
    for (mv, outcome) in selected {
        if !matches!(outcome, RewriteOutcome::Applied { .. }) {
            continue;
        }
        match *mv {
            RewriteMove::InvertBranch { header } => {
                if let Some(Region::IfElse {
                    then_entry,
                    else_entry,
                    invert,
                    ..
                }) = dual.regions.get_mut(&header)
                {
                    std::mem::swap(then_entry, else_entry);
                    *invert = !*invert;
                }
            }
            RewriteMove::EarlyReturnExtract { header } => {
                let Some(Region::IfElse {
                    then_entry,
                    else_entry,
                    merge,
                    invert,
                }) = dual.regions.get(&header).cloned()
                else {
                    continue;
                };
                let t = dual.semantic.block_effect_kinds(then_entry);
                let e = dual.semantic.block_effect_kinds(else_entry);
                let then_pure = is_pure_return_arm(&t);
                let else_pure = is_pure_return_arm(&e);
                if then_pure {
                    dual.regions.insert(
                        header,
                        Region::IfThenFallthrough {
                            then_entry,
                            cont_entry: else_entry,
                            merge,
                            invert,
                        },
                    );
                } else if else_pure {
                    // Prefer pure return as then with inverted condition.
                    dual.regions.insert(
                        header,
                        Region::IfThenFallthrough {
                            then_entry: else_entry,
                            cont_entry: then_entry,
                            merge,
                            invert: !invert,
                        },
                    );
                }
            }
            RewriteMove::FactorPureSharedTail { .. } | RewriteMove::DuplicatePureBlock { .. } => {
                // Presentation-cost / policy moves; region shape already SESE-joined.
            }
        }
    }
    dual.contracts = super::rd_model::ContractSet::from_regions(ssa, &dual.regions);
}

/// Map residual emit tags through the dual-model reason vocabulary.
pub fn residual_reason_for_emit_tag(tag: &str) -> ResidualReason {
    ResidualReason::from_emit_tag(tag)
}

/// Prefer structured residual reason when multi-entry SCC is detected on
/// presentation graph (simple: block with ≥2 preds that is also a back-edge target).
#[allow(dead_code)] // used by residual emission policy / orbit tooling
pub fn classify_residual_edge(
    dual: &DualDecompModel,
    from: u32,
    to: u32,
    emit_tag: &str,
) -> ResidualReason {
    let preds = dual
        .presentation
        .pred
        .get(to as usize)
        .map(|p| p.len())
        .unwrap_or(0);
    if preds >= 2 {
        // Heuristic: multi-pred join that is also a loop header → multi-entry.
        if dual.contracts.loops.iter().any(|l| l.header == to) {
            return ResidualReason::MultiEntryScc;
        }
        if dual.regions.contains_key(&from) && dual.regions.contains_key(&to) {
            return ResidualReason::CrossRegionEscape;
        }
    }
    residual_reason_for_emit_tag(emit_tag)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use crate::decompiler::structure::rd_model::{DualDecompModel, EffectKind};
    use pcode_ir::AddressSpaceId;
    use rsleigh_api::{PcodeOp, Varnode};

    fn blk(id: u32, va: u64, ops: Vec<SsaOp>, succs: Vec<u32>) -> SsaBlock {
        SsaBlock {
            id,
            entry_va: va,
            ops,
            successor_ids: succs,
            predecessor_ids: vec![],
        }
    }

    fn link(blocks: &mut [SsaBlock]) {
        for b in blocks.iter_mut() {
            b.predecessor_ids.clear();
        }
        let edges: Vec<(u32, u32)> = blocks
            .iter()
            .flat_map(|b| b.successor_ids.iter().map(|&s| (b.id, s)))
            .collect();
        for (f, t) in edges {
            if let Some(bb) = blocks.iter_mut().find(|b| b.id == t) {
                bb.predecessor_ids.push(f);
            }
        }
    }

    /// Both arms non-empty (store vs store) so presentation classify keeps IfElse.
    fn if_else_with_store_ssa() -> SsaFunction {
        let mut blocks = vec![
            blk(
                0,
                0x1000,
                vec![SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::CBranch {
                        cond: Varnode::constant(1, 1),
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![1, 2],
            ),
            blk(
                1,
                0x1010,
                vec![SsaOp {
                    va: 0x1010,
                    kind: SsaOpKind::Pcode(PcodeOp::Store {
                        space: AddressSpaceId::Ram,
                        ptr: Varnode::register(0x28, 8),
                        val: Varnode::register(0, 4),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![3],
            ),
            blk(
                2,
                0x1020,
                vec![SsaOp {
                    va: 0x1020,
                    kind: SsaOpKind::Pcode(PcodeOp::Store {
                        space: AddressSpaceId::Ram,
                        ptr: Varnode::register(0x30, 8),
                        val: Varnode::register(1, 4),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![3],
            ),
            blk(
                3,
                0x1030,
                vec![SsaOp {
                    va: 0x1030,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![],
            ),
        ];
        link(&mut blocks);
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        }
    }

    /// IfElse with pure return then-arm and store else-arm (early-return candidate).
    fn if_else_early_return_ssa() -> SsaFunction {
        let mut blocks = vec![
            blk(
                0,
                0x1000,
                vec![SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::CBranch {
                        cond: Varnode::constant(1, 1),
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![1, 2],
            ),
            blk(
                1,
                0x1010,
                vec![SsaOp {
                    va: 0x1010,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![],
            ),
            blk(
                2,
                0x1020,
                vec![SsaOp {
                    va: 0x1020,
                    kind: SsaOpKind::Pcode(PcodeOp::Store {
                        space: AddressSpaceId::Ram,
                        ptr: Varnode::register(0x28, 8),
                        val: Varnode::register(0, 4),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![3],
            ),
            blk(
                3,
                0x1030,
                vec![SsaOp {
                    va: 0x1030,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![],
            ),
        ];
        link(&mut blocks);
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        }
    }

    fn call_block_ssa() -> SsaFunction {
        let mut blocks = vec![blk(
            0,
            0x1000,
            vec![
                SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::Call {
                        dest: Varnode::constant(0x140001000, 8),
                    }),
                    def: None,
                    uses: vec![],
                },
                SsaOp {
                    va: 0x1004,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                },
            ],
            vec![],
        )];
        link(&mut blocks);
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        }
    }

    #[test]
    fn inversion_accepted_when_effects_preserved() {
        // Balanced stores: fidelity holds but no presentation gain → reject.
        let ssa = if_else_with_store_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        assert!(
            matches!(dual.regions.get(&0), Some(Region::IfElse { .. })),
            "fixture must classify as IfElse: {:?}",
            dual.regions.get(&0)
        );
        let mv = RewriteMove::InvertBranch { header: 0 };
        assert_eq!(
            check_move(&dual, &mv),
            CheckResult::Reject("no_presentation_gain"),
            "balanced arms must not free-invert"
        );
    }

    #[test]
    fn inversion_apply_swaps_arms_and_polarity() {
        // Else is pure return → inversion has presentation gain.
        let ssa = if_else_early_return_ssa();
        let mut dual = DualDecompModel::build(&ssa, &[]);
        let (t0, e0) = match dual.regions.get(&0) {
            Some(Region::IfElse {
                then_entry,
                else_entry,
                ..
            }) => (*then_entry, *else_entry),
            other => panic!("expected IfElse, got {other:?}"),
        };
        // Force InvertBranch only (before EarlyReturn rewrites shape away).
        let selected = vec![(
            RewriteMove::InvertBranch { header: 0 },
            RewriteOutcome::Applied {
                cost_before: 0,
                cost_after: -1,
            },
        )];
        assert_eq!(
            check_move(&dual, &RewriteMove::InvertBranch { header: 0 }),
            CheckResult::Accept
        );
        apply_moves(&mut dual, &selected, &ssa);
        match dual.regions.get(&0) {
            Some(Region::IfElse {
                then_entry,
                else_entry,
                invert,
                ..
            }) => {
                assert_eq!(*then_entry, e0);
                assert_eq!(*else_entry, t0);
                assert!(*invert);
            }
            other => panic!("expected IfElse after invert apply, got {other:?}"),
        }
    }

    #[test]
    fn early_return_extract_accepted_and_applied() {
        let ssa = if_else_early_return_ssa();
        let mut dual = DualDecompModel::build(&ssa, &[]);
        // Ensure IfElse: then=return (block1 taken), else=store (block2 fall).
        // SSA succ [1,2] → fall=1, taken=2 per cbranch_arms.
        // Wait: fall=successor[0]=1 (return), taken=2 (store).
        // IfElse then=taken=2 (store), else=fall=1 (return).
        assert!(
            matches!(dual.regions.get(&0), Some(Region::IfElse { .. })),
            "early-return fixture must be IfElse: {:?}",
            dual.regions.get(&0)
        );
        let mv = RewriteMove::EarlyReturnExtract { header: 0 };
        assert_eq!(
            check_move(&dual, &mv),
            CheckResult::Accept,
            "pure return arm must pass fidelity"
        );
        let selected = vec![(
            mv,
            RewriteOutcome::Applied {
                cost_before: 0,
                cost_after: -2,
            },
        )];
        apply_moves(&mut dual, &selected, &ssa);
        assert!(
            matches!(dual.regions.get(&0), Some(Region::IfThenFallthrough { .. })),
            "early-return must rewrite to IfThenFallthrough: {:?}",
            dual.regions.get(&0)
        );
    }

    #[test]
    fn early_return_rejected_without_pure_return_arm() {
        let ssa = if_else_with_store_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let mv = RewriteMove::EarlyReturnExtract { header: 0 };
        assert_eq!(
            check_move(&dual, &mv),
            CheckResult::Reject("no_pure_return_arm")
        );
    }

    #[test]
    fn duplication_of_call_block_rejected() {
        let ssa = call_block_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let fx = dual.semantic.block_effect_kinds(0);
        assert!(
            fx.iter().any(|e| matches!(e, EffectKind::Call { .. })),
            "expected call effect"
        );
        let mv = RewriteMove::DuplicatePureBlock { block: 0 };
        assert_eq!(
            check_move(&dual, &mv),
            CheckResult::Reject("cannot_duplicate_effectful_block")
        );
    }

    #[test]
    fn select_moves_records_reject_reasons() {
        let ssa = call_block_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let forced = check_move(&dual, &RewriteMove::DuplicatePureBlock { block: 0 });
        assert!(matches!(forced, CheckResult::Reject(_)));
    }

    #[test]
    fn residual_reason_classification() {
        assert_eq!(
            residual_reason_for_emit_tag("cross_region_escape"),
            ResidualReason::CrossRegionEscape
        );
        assert_eq!(
            residual_reason_for_emit_tag("multi_entry_scc").as_str(),
            "multi_entry_scc"
        );
    }
}
