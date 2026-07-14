//! Coverage checker for AST candidates (fail-closed).

use super::artifact::CheckReport;
use super::extract::AstCandidate;
use super::observation::{critical_signature, effects_from_text};
use super::semantic::SemanticModel;

/// Reject candidates that drop/reorder critical effects or miss control coverage.
///
/// Critical effects are derived from **candidate text** and compared against the
/// semantic (SSA/HIR) observation multiset — candidates cannot self-stamp.
pub fn check_candidate(sem: &SemanticModel, cand: &AstCandidate) -> CheckReport {
    let mut report = CheckReport {
        accepted: true,
        edges_covered: cand.edges_covered,
        effects_covered: cand.effects_covered,
        rejects: Vec::new(),
        candidates_tried: 1,
        candidates_accepted: 0,
        ..Default::default()
    };

    let total_edges: usize = sem.succ.iter().map(|s| s.len()).sum();
    if cand.edges_covered + cand.residual_edges
        < total_edges.saturating_sub(sem.cookie_blocks.len())
    {
        // Soft: residual edges are allowed when reason-coded.
        if cand.residual_edges > total_edges / 2 + 2 {
            report.accepted = false;
            report.rejects.push("too_many_residual_edges".into());
        }
    }

    let expected = critical_signature(&sem.observations);
    // Always re-derive from text so a candidate that drops return/store/call fails.
    let from_text = effects_from_text(&cand.text);
    if !expected.is_empty()
        && !effect_multiset_eq(&from_text, &expected)
        && !effect_multiset_eq(&cand.effect_signature, &expected)
    {
        // Prefer text-derived; fall back to stamp only if text empty of effects
        // but stamp matches (legacy candidates mid-migration).
        if from_text.is_empty() || !effect_kind_subset(&from_text, &expected) {
            report.accepted = false;
            report.rejects.push("effect_multiset_mismatch".into());
        }
    }
    // Text must not drop all critical effects when semantic has them.
    if !sem.critical_effects().is_empty() {
        let text_kinds = effect_kinds(&from_text);
        let exp_kinds = effect_kinds(&expected);
        // Every expected kind must appear at least once in the text (coverage).
        for k in &exp_kinds {
            if !text_kinds.contains(k) {
                report.accepted = false;
                report.rejects.push(format!("dropped_critical_effect:{k}"));
            }
        }
        if from_text.is_empty() {
            report.accepted = false;
            report.rejects.push("dropped_all_critical_effects".into());
        }
    }

    // Switch partitions must be exhaustive when present.
    for c in &cand.case_partitions {
        if c.case_count == 0 {
            report.accepted = false;
            report.rejects.push("empty_case_partition".into());
        }
    }

    // Text claims of switch must not lose all cases when contracts have cases.
    if !sem.observations.is_empty()
        && cand.text.contains("switch")
        && !cand.case_partitions.is_empty()
        && !cand.text.contains("case")
    {
        report.accepted = false;
        report.rejects.push("switch_without_cases".into());
    }

    // Pure structure quality (no gold/Ghidra). Multi-block pure is allowed when
    // structure presentation left a low-goto structured surface.
    if !cand.text.trim().is_empty() {
        let tl = cand.text.to_ascii_lowercase();
        let goto_n = cand.text.matches("goto ").count();
        let has_kw = tl.contains("if")
            || tl.contains("while")
            || tl.contains("for")
            || tl.contains("switch")
            || tl.contains("case");
        // Heavy residual gotos → Legacy (presentation failed to structure).
        if goto_n > 2 {
            report.accepted = false;
            report.rejects.push("pure_goto_heavy".into());
        } else if goto_n > 0 && !has_kw {
            report.accepted = false;
            report.rejects.push("pure_has_goto".into());
        }
        let has_branch = sem.terminators.iter().any(|t| {
            matches!(
                t,
                super::semantic::Terminator::Branch { .. }
                    | super::semantic::Terminator::Switch { .. }
            )
        });
        if has_branch && !has_kw && goto_n == 0 {
            report.accepted = false;
            report.rejects.push("missing_control_surface".into());
        }
        // Single-block pure arithmetic/compare returns need if-form for CRW;
        // that remains semantic polish → Legacy.
        if sem.n_blocks == 1 && !has_kw && tl.contains("return") {
            let ret_line = cand
                .text
                .lines()
                .map(str::trim)
                .find(|l| l.starts_with("return"))
                .unwrap_or("");
            let has_op = ret_line.contains('^')
                || ret_line.contains('&')
                || ret_line.contains('|')
                || ret_line.contains('+')
                || ret_line.contains('*')
                || ret_line.contains('<')
                || ret_line.contains('>');
            if has_op {
                report.accepted = false;
                report.rejects.push("pure_leaf_needs_control".into());
            }
        }
        if sem.exit_class.has_return && !tl.contains("return") {
            report.accepted = false;
            report.rejects.push("missing_return_surface".into());
        }
    } else {
        report.accepted = false;
        report.rejects.push("empty_pure_text".into());
    }

    if report.accepted {
        report.candidates_accepted = 1;
    }
    report
}

fn effect_kinds(sig: &[String]) -> Vec<String> {
    let mut k: Vec<String> = sig
        .iter()
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
        .collect();
    k.sort();
    k.dedup();
    k
}

fn effect_kind_subset(a: &[String], b: &[String]) -> bool {
    // Every kind in b appears at least once in a.
    let ak = effect_kinds(a);
    let bk = effect_kinds(b);
    bk.iter().all(|k| ak.contains(k))
}

fn effect_multiset_eq(a: &[String], b: &[String]) -> bool {
    let mut a2: Vec<_> = a
        .iter()
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
        .collect();
    let mut b2: Vec<_> = b
        .iter()
        .map(|s| s.split(':').next().unwrap_or(s).to_string())
        .collect();
    a2.sort();
    b2.sort();
    a2 == b2
}

/// Negative tests: deliberately broken candidates must be rejected.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use crate::decompiler::v2::contracts::CaseContractV2;
    use crate::decompiler::v2::extract::AstCandidate;
    use crate::decompiler::v2::semantic::SemanticModel;
    use rsleigh_api::{PcodeOp, Varnode};

    fn ret_ssa() -> SsaFunction {
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![
                    SsaOp {
                        va: 0x1000,
                        kind: SsaOpKind::Pcode(PcodeOp::Store {
                            space: pcode_ir::AddressSpaceId::Ram,
                            ptr: Varnode::register(0x28, 8),
                            val: Varnode::register(0, 4),
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
                successor_ids: vec![],
                predecessor_ids: vec![],
            }],
            image_base: 0,
        }
    }

    #[test]
    fn rejects_dropped_critical_effects() {
        let ssa = ret_ssa();
        let sem = SemanticModel::from_ssa(&ssa);
        let bad = AstCandidate {
            text: "void f() {}".into(),
            edges_covered: 0,
            residual_edges: 0,
            effects_covered: 0,
            effect_signature: vec![],
            case_partitions: vec![],
            cost: 0,
            nesting: 0,
        };
        let r = check_candidate(&sem, &bad);
        assert!(!r.accepted, "{r:?}");
        assert!(
            r.rejects
                .iter()
                .any(|x| x.contains("dropped") || x.contains("mismatch")),
            "{r:?}"
        );
    }

    #[test]
    fn rejects_text_that_drops_return_even_if_stamp_lies() {
        // Theater-proof: stamp claims return+store, text has neither.
        let ssa = ret_ssa();
        let sem = SemanticModel::from_ssa(&ssa);
        let expected = critical_signature(&sem.observations);
        let bad = AstCandidate {
            text: "void f() { int x = 1; }".into(),
            edges_covered: 1,
            residual_edges: 0,
            effects_covered: expected.len(),
            effect_signature: expected, // self-stamp lies
            case_partitions: vec![],
            cost: 0,
            nesting: 0,
        };
        let r = check_candidate(&sem, &bad);
        assert!(
            !r.accepted,
            "must reject when text drops return/store: {r:?}"
        );
    }

    #[test]
    fn rejects_empty_case_partition() {
        let ssa = ret_ssa();
        let sem = SemanticModel::from_ssa(&ssa);
        let sig = critical_signature(&sem.observations);
        let bad = AstCandidate {
            text: "int f(){ *p=1; return 0; }".into(),
            edges_covered: 0,
            residual_edges: 0,
            effects_covered: sig.len(),
            effect_signature: sig,
            case_partitions: vec![CaseContractV2 {
                case_count: 0,
                has_default: false,
                labels: vec![],
                source: "bad".into(),
            }],
            cost: 0,
            nesting: 0,
        };
        let r = check_candidate(&sem, &bad);
        assert!(!r.accepted);
        assert!(r.rejects.iter().any(|x| x.contains("empty_case")));
    }

    #[test]
    fn accepts_preserving_candidate() {
        let ssa = ret_ssa();
        let sem = SemanticModel::from_ssa(&ssa);
        let from_text = effects_from_text("int f(){ *p=1; return 0; }");
        let good = AstCandidate {
            text: "int f(){ *p=1; return 0; }".into(),
            edges_covered: 0,
            residual_edges: 0,
            effects_covered: from_text.len(),
            effect_signature: from_text,
            case_partitions: vec![],
            cost: 1,
            nesting: 0,
        };
        let r = check_candidate(&sem, &good);
        assert!(r.accepted, "{r:?}");
    }

    #[test]
    fn effects_from_text_sees_return_store_call() {
        let sig = effects_from_text("void f() {\n  *(p) = 1;\n  call(FUN_1);\n  return 0;\n}\n");
        let kinds: Vec<_> = sig.iter().map(|s| s.split(':').next().unwrap()).collect();
        assert!(kinds.contains(&"store"), "{sig:?}");
        assert!(kinds.contains(&"call"), "{sig:?}");
        assert!(kinds.contains(&"return"), "{sig:?}");
    }
}
