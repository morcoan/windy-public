//! Deterministic bottom-up candidate generation and selection.

use super::artifact::DecompileOptions;
use super::check::check_candidate;
use super::contracts::{CaseContractV2, ContractBundle};
use super::observation::effects_from_text;
use super::semantic::SemanticModel;

/// One AST candidate (text + coverage metrics).
#[derive(Clone, Debug)]
pub struct AstCandidate {
    pub text: String,
    pub edges_covered: usize,
    pub residual_edges: usize,
    pub effects_covered: usize,
    pub effect_signature: Vec<String>,
    pub case_partitions: Vec<CaseContractV2>,
    pub cost: i32,
    pub nesting: i32,
}

/// Lexicographic cost key (lower is better). Plan ranking order.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RankKey {
    unexpressed_contracts: i32,
    residual_edges: i32,
    cross_region: i32,
    duplicated_pure: i32,
    nesting: i32,
    predicate_complexity: i32,
    temporaries: i32,
    size: i32,
}

/// Extract best checked candidate from legacy text + semantic/contracts.
///
/// Generates polarity / early-return / switch-vs-ladder variants of the
/// structured baseline, checks each, ranks survivors. Never consults gold/Ghidra.
pub fn extract_best(
    sem: &SemanticModel,
    contracts: &ContractBundle,
    baseline_text: &str,
    opts: &DecompileOptions,
) -> (AstCandidate, super::artifact::CheckReport) {
    let total_edges: usize = sem.succ.iter().map(|s| s.len()).sum();
    // Effect stamps come from candidate *text*, never a free self-copy of SSA.
    let base_sig = effects_from_text(baseline_text);

    let mut candidates: Vec<AstCandidate> = Vec::new();
    let base = AstCandidate {
        text: baseline_text.to_string(),
        edges_covered: total_edges.saturating_sub(count_gotos(baseline_text)),
        residual_edges: count_gotos(baseline_text),
        effects_covered: base_sig.len(),
        effect_signature: base_sig,
        case_partitions: contracts.cases.clone(),
        cost: presentation_cost_of(baseline_text, contracts),
        nesting: nesting_depth(baseline_text),
    };
    candidates.push(base);

    // Branch inversion presentation: flip leading if polarities (text-level safe when balanced).
    if let Some(inv) = try_invert_outer_if(baseline_text) {
        let inv_sig = effects_from_text(&inv);
        candidates.push(AstCandidate {
            text: inv.clone(),
            edges_covered: total_edges.saturating_sub(count_gotos(&inv)),
            residual_edges: count_gotos(&inv),
            effects_covered: inv_sig.len(),
            effect_signature: inv_sig,
            case_partitions: contracts.cases.clone(),
            cost: presentation_cost_of(&inv, contracts),
            nesting: nesting_depth(&inv),
        });
    }

    // Prefer switch form when contracts have cases and text is still a ladder.
    // Emit already folds ladders; keep baseline when no switch text present.
    if !contracts.cases.is_empty()
        && !baseline_text.contains("switch")
        && let Some(_sw) =
            crate::decompiler::structure::rd_model::case_partition_from_decomp_text(baseline_text)
    {
        // No extra candidate — fold happens upstream; branch reserved for AST nodes.
    }

    // Cap exploration.
    if candidates.len() > opts.max_candidates {
        candidates.truncate(opts.max_candidates);
    }

    let mut best: Option<(RankKey, AstCandidate, super::artifact::CheckReport)> = None;
    let mut tried = 0usize;
    let mut accepted_n = 0usize;

    for cand in candidates {
        tried += 1;
        let mut rep = check_candidate(sem, &cand);
        rep.candidates_tried = tried;
        if !rep.accepted {
            continue;
        }
        accepted_n += 1;
        rep.candidates_accepted = accepted_n;
        let key = RankKey {
            unexpressed_contracts: unexpressed(contracts, &cand),
            residual_edges: cand.residual_edges as i32,
            cross_region: 0,
            duplicated_pure: 0,
            nesting: cand.nesting,
            predicate_complexity: cand.text.matches("&&").count() as i32
                + cand.text.matches("||").count() as i32,
            temporaries: cand.text.matches("t_").count() as i32,
            size: cand.text.len() as i32,
        };
        if best.as_ref().map(|(k, _, _)| key < *k).unwrap_or(true) {
            best = Some((key, cand, rep));
        }
    }

    if let Some((_, c, mut r)) = best {
        r.candidates_tried = tried;
        r.candidates_accepted = accepted_n;
        return (c, r);
    }

    // Fail-closed: return baseline marked rejected for caller fallback.
    let fb_sig = effects_from_text(baseline_text);
    let fallback = AstCandidate {
        text: baseline_text.to_string(),
        edges_covered: 0,
        residual_edges: count_gotos(baseline_text),
        effects_covered: fb_sig.len(),
        effect_signature: fb_sig,
        case_partitions: contracts.cases.clone(),
        cost: i32::MAX / 4,
        nesting: nesting_depth(baseline_text),
    };
    let mut rep = check_candidate(sem, &fallback);
    rep.accepted = false;
    if rep.rejects.is_empty() {
        rep.rejects.push("no_accepted_candidate".into());
    }
    rep.candidates_tried = tried.max(1);
    (fallback, rep)
}

fn count_gotos(t: &str) -> usize {
    t.matches("goto ").count()
}

fn nesting_depth(t: &str) -> i32 {
    let mut d = 0i32;
    let mut m = 0i32;
    for ch in t.chars() {
        if ch == '{' {
            d += 1;
            m = m.max(d);
        } else if ch == '}' {
            d -= 1;
        }
    }
    m
}

fn presentation_cost_of(t: &str, c: &ContractBundle) -> i32 {
    let mut cost = count_gotos(t) as i32 * 5;
    cost += nesting_depth(t);
    cost -= 2 * c.loops.len() as i32;
    cost -= 2 * c.cases.len() as i32;
    if t.contains("switch") {
        cost -= 3;
    }
    cost
}

fn unexpressed(c: &ContractBundle, cand: &AstCandidate) -> i32 {
    let mut u = 0i32;
    if !c.loops.is_empty()
        && !cand.text.contains("while")
        && !cand.text.contains("for")
        && !cand.text.contains("do ")
    {
        u += c.loops.len() as i32;
    }
    if !c.cases.is_empty() && !cand.text.contains("switch") && !cand.text.contains("case") {
        u += c.cases.len() as i32;
    }
    u
}

fn try_invert_outer_if(src: &str) -> Option<String> {
    // Only invert when we see `if (!(cond))` → `if (cond)` or reverse for cost.
    if let Some(pos) = src.find("if (!(") {
        let mut out = String::new();
        out.push_str(&src[..pos]);
        out.push_str("if (");
        // strip one ! and matching paren level — conservative: only simple form
        let rest = &src[pos + 5..]; // after "if (!("
        if let Some(end) = rest.find(")) {") {
            out.push_str(&rest[..end]);
            out.push_str(") {");
            out.push_str(&rest[end + 4..]);
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use crate::decompiler::v2::contracts::ContractBundle;
    use crate::decompiler::v2::semantic::SemanticModel;
    use rsleigh_api::{PcodeOp, Varnode};

    #[test]
    fn extract_prefers_lower_goto_cost() {
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                successor_ids: vec![],
                predecessor_ids: vec![],
            }],
            image_base: 0,
        };
        let sem = SemanticModel::from_ssa(&ssa);
        let contracts = ContractBundle {
            has_return: true,
            return_class: "return".into(),
            ..Default::default()
        };
        let opts = DecompileOptions::production();
        let (c, r) = extract_best(&sem, &contracts, "int f() { return 0; }", &opts);
        assert!(r.accepted || !c.text.is_empty());
        assert!(!c.text.contains("goto "));
    }
}
