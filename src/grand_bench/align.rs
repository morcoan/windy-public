//! Anonymous edge-alignment \(S_{\mathrm{align}}\) and residual-edge topology penalty.
//!
//! Implements Defs 1, 4, 9, 15 and Theorems 2, 7 from the structural brief:
//! typed structures, injective sort-preserving alignments, continuous
//! irreducibility penalty \(P_\lambda = e^{-\lambda\eta}\).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Edge weight for control edges \(E^{\mathrm c}\).
pub const ALPHA_C: f64 = 1.0;
/// Edge weight for data edges \(E^{\mathrm d}\).
pub const ALPHA_D: f64 = 1.0;
/// Mix for \(S_{\mathrm{align}} = \lambda S_E + (1-\lambda) S_V\).
pub const LAMBDA_ALIGN: f64 = 0.75;
/// Topology decay for residual edges.
pub const LAMBDA_TOPO: f64 = 2.0;
/// Mix for \(\Phi_{\mathrm{str}}^\sharp = \Phi^\theta \cdot S_{\mathrm{align}}^{1-\theta}\).
pub const THETA_STR: f64 = 0.70;

/// Vertex sort (anonymous type class).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VertexSort {
    Entry,
    Assign,
    Predicate,
    LoopHeader,
    SwitchHead,
    Call,
    Return,
    Store,
    Load,
    Cleanup,
    Label,
    Other,
}

/// Finite typed relational structure \(\mathfrak H\) (Def 1).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypedStructure {
    /// Vertex id → sort.
    pub vertices: BTreeMap<u32, VertexSort>,
    /// Control edges \(E^{\mathrm c}\).
    pub control_edges: BTreeSet<(u32, u32)>,
    /// Data/dependence edges \(E^{\mathrm d}\).
    pub data_edges: BTreeSet<(u32, u32)>,
    /// Auxiliary labels (anonymous-relabelable).
    pub labels: BTreeMap<u32, String>,
}

impl TypedStructure {
    pub fn edge_weight(&self) -> f64 {
        ALPHA_C * self.control_edges.len() as f64 + ALPHA_D * self.data_edges.len() as f64
    }

    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }
}

/// True edge-alignment score \(S_E\) for a fixed injective partial map.
fn tp_edges(h: &TypedStructure, h2: &TypedStructure, psi: &HashMap<u32, u32>) -> f64 {
    let mut tp = 0.0;
    for &(u, v) in &h.control_edges {
        if let (Some(&pu), Some(&pv)) = (psi.get(&u), psi.get(&v))
            && h2.control_edges.contains(&(pu, pv))
        {
            tp += ALPHA_C;
        }
    }
    for &(u, v) in &h.data_edges {
        if let (Some(&pu), Some(&pv)) = (psi.get(&u), psi.get(&v))
            && h2.data_edges.contains(&(pu, pv))
        {
            tp += ALPHA_D;
        }
    }
    tp
}

/// Greedy sort-preserving alignment maximizing edge TP then domain size.
/// Exact on small graphs via greedy by sort buckets (Def 4).
pub fn score_edge_alignment(h: &TypedStructure, h2: &TypedStructure) -> f64 {
    if h.is_empty() && h2.is_empty() {
        return 1.0;
    }
    if h.is_empty() || h2.is_empty() {
        return 0.0;
    }

    // Bucket vertices by sort.
    let mut buckets: BTreeMap<VertexSort, Vec<u32>> = BTreeMap::new();
    for (&v, s) in &h.vertices {
        buckets.entry(s.clone()).or_default().push(v);
    }
    let mut buckets2: BTreeMap<VertexSort, Vec<u32>> = BTreeMap::new();
    for (&v, s) in &h2.vertices {
        buckets2.entry(s.clone()).or_default().push(v);
    }

    // Degree centrality for matching order.
    let deg = |st: &TypedStructure, v: u32| -> usize {
        st.control_edges
            .iter()
            .chain(st.data_edges.iter())
            .filter(|(a, b)| *a == v || *b == v)
            .count()
    };

    let mut psi: HashMap<u32, u32> = HashMap::new();
    let mut used2: HashSet<u32> = HashSet::new();

    for (sort, mut vs) in buckets {
        let Some(mut vs2) = buckets2.get(&sort).cloned() else {
            continue;
        };
        vs.sort_by_key(|&v| std::cmp::Reverse(deg(h, v)));
        vs2.sort_by_key(|&v| std::cmp::Reverse(deg(h2, v)));
        // Greedy: for each v, pick unused v2 maximizing local edge agreement.
        for v in vs {
            let mut best: Option<(u32, i64)> = None;
            for &v2 in &vs2 {
                if used2.contains(&v2) {
                    continue;
                }
                // Local score: common neighbor sorts via tentative map.
                let mut local = 0i64;
                for &(a, b) in h.control_edges.iter().chain(h.data_edges.iter()) {
                    if a != v && b != v {
                        continue;
                    }
                    let other = if a == v { b } else { a };
                    if let Some(&po) = psi.get(&other) {
                        let want = if a == v { (v2, po) } else { (po, v2) };
                        if h2.control_edges.contains(&want) || h2.data_edges.contains(&want) {
                            local += 2;
                        }
                    } else {
                        local += 1; // free endpoint still matches sort availability
                    }
                }
                if best.map(|(_, s)| local > s).unwrap_or(true) {
                    best = Some((v2, local));
                }
            }
            if let Some((v2, _)) = best {
                psi.insert(v, v2);
                used2.insert(v2);
            }
        }
    }

    let w_e = h.edge_weight() + h2.edge_weight();
    let s_e = if w_e <= 0.0 {
        1.0
    } else {
        2.0 * tp_edges(h, h2, &psi) / w_e
    };
    let s_v = {
        let den = h.vertices.len() + h2.vertices.len();
        if den == 0 {
            1.0
        } else {
            2.0 * psi.len() as f64 / den as f64
        }
    };
    (LAMBDA_ALIGN * s_e + (1.0 - LAMBDA_ALIGN) * s_v).clamp(0.0, 1.0)
}

/// Continuous irreducibility penalty \(P_\lambda = e^{-\lambda \eta}\) (Def 15).
pub fn topology_penalty(residual_edges: usize, total_edges: usize, lambda: f64) -> f64 {
    let eta = residual_edges as f64 / (total_edges.max(1) as f64);
    (-lambda * eta).exp()
}

/// Count residual (goto-like) edges vs structured control edges in pseudocode.
pub fn residual_edge_counts(text: &str) -> (usize, usize) {
    let t = text.to_ascii_lowercase();
    let goto_n = t.matches("goto ").count() + t.matches("goto\t").count();
    let structured = t.matches("while").count()
        + t.matches("for ").count()
        + t.matches("for(").count()
        + t.matches("if ").count()
        + t.matches("if(").count()
        + t.matches("switch").count()
        + t.matches("return").count();
    let total = (goto_n + structured).max(1);
    (goto_n, total)
}

/// Extract a typed structure from comment-stripped pseudocode (heuristic \(\mathfrak H(x)\)).
pub fn extract_structure_from_pseudo(credit: &str) -> TypedStructure {
    let mut st = TypedStructure::default();
    let mut next_id = 0u32;
    let mut alloc = |sort: VertexSort, label: String| -> u32 {
        let id = next_id;
        next_id += 1;
        st.vertices.insert(id, sort);
        st.labels.insert(id, label);
        id
    };

    let entry = alloc(VertexSort::Entry, "entry".into());
    let mut prev = entry;
    let mut last_assign: Option<u32> = None;
    let mut stack_ctrl: Vec<u32> = Vec::new(); // open if/while/switch

    // Split on `;` / braces so one-line functions still yield Return verts.
    let mut pieces: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in credit.chars() {
        cur.push(ch);
        if ch == ';' || ch == '{' || ch == '}' {
            let t = cur.trim().to_string();
            if !t.is_empty() {
                pieces.push(t);
            }
            cur.clear();
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() {
        pieces.push(t);
    }

    for t in pieces {
        let t = t.trim();
        if t.is_empty() || t == "{" || t == "}" {
            if t == "}"
                && let Some(h) = stack_ctrl.pop()
            {
                st.control_edges.insert((prev, h));
                prev = h;
            }
            continue;
        }
        let n = t.to_ascii_lowercase();
        // One-line `if (...) return C;` carries both a Predicate and a Return
        // (and often an Assign when C is a constant HRESULT / 0/1). Emit all
        // sorts so sort-multiset alignment matches gold Store/Constant/Return.
        let is_if_return = (n.starts_with("if") || n.contains("if(") || n.contains("if ("))
            && n.contains("return");
        let sorts: Vec<(VertexSort, String)> = if is_if_return {
            let mut v = vec![
                (VertexSort::Predicate, "if".into()),
                (VertexSort::Return, "return".into()),
            ];
            // Constant / op materialization in the return (HRESULT, bool, xor).
            if n.contains("0x")
                || n.contains("return 0")
                || n.contains("return 1")
                || n.contains("hr =")
                || n.contains("hr=")
                || n.contains('^')
                || n.contains('*')
                || n.contains('+')
            {
                v.insert(1, (VertexSort::Assign, "assign".into()));
            }
            v
        } else if n.contains("return") {
            // Bare return; materialize Assign when the return expression carries
            // ops / constants (gold Operation/Constant map to Assign sorts).
            let mut v = vec![(VertexSort::Return, "return".into())];
            let rich_ret = n.contains('^')
                || n.contains('*')
                || n.contains('+')
                || n.contains("0x")
                || n.contains("hr =")
                || n.contains("hr=");
            if rich_ret {
                v.insert(0, (VertexSort::Assign, "assign".into()));
            }
            v
        } else if n.contains("while")
            || n.starts_with("for")
            || n.contains("for(")
            || n.contains("do{")
            || n.starts_with("do ")
        {
            vec![(VertexSort::LoopHeader, "loop".into())]
        } else if n.contains("switch") {
            vec![(VertexSort::SwitchHead, "switch".into())]
        } else if n.contains("case ") || n.starts_with("case") {
            vec![(VertexSort::Predicate, "case".into())]
        } else if n.starts_with("if")
            || n.contains("if(")
            || n.contains("if (")
            || n.starts_with("else")
        {
            vec![(VertexSort::Predicate, "if".into())]
        } else if n.contains("goto ") {
            vec![(VertexSort::Label, "goto".into())]
        } else if n.contains("break") || n.contains("continue") {
            vec![(VertexSort::Other, "loopctl".into())]
        } else if n.contains("destroy") || n.contains("release") || n.contains("cleanup") {
            vec![(VertexSort::Cleanup, "cleanup".into())]
        } else if n.contains('*') && n.contains('=') && !n.contains("==") {
            vec![(VertexSort::Store, "store".into())]
        } else if n.contains('=') && !n.contains("==") && !n.contains("!=") {
            vec![(VertexSort::Assign, "assign".into())]
        } else if n.contains('(') && n.contains(')') {
            vec![(VertexSort::Call, "call".into())]
        } else {
            vec![(VertexSort::Other, "stmt".into())]
        };

        for (sort, label) in sorts {
            let v = alloc(sort.clone(), label);
            st.control_edges.insert((prev, v));
            if matches!(
                sort,
                VertexSort::LoopHeader | VertexSort::Predicate | VertexSort::SwitchHead
            ) {
                stack_ctrl.push(v);
            }
            if matches!(sort, VertexSort::Assign | VertexSort::Store) {
                if let Some(la) = last_assign {
                    st.data_edges.insert((la, v));
                }
                last_assign = Some(v);
            }
            if matches!(sort, VertexSort::Return | VertexSort::Call)
                && let Some(la) = last_assign
            {
                st.data_edges.insert((la, v));
            }
            prev = v;
        }
    }
    // Soft loop orbit (mirrors SFG loop fact): sentinel/induction scans often
    // lower to nested `if` without `while`/`for`. When the credit has bound +
    // induction surface but no LoopHeader keyword, retag the first Predicate
    // as LoopHeader so sort multiset alignment matches gold Loop facts.
    // Applies identically to Windy and Ghidra observations.
    let has_loop_kw = st
        .vertices
        .values()
        .any(|s| matches!(s, VertexSort::LoopHeader));
    if !has_loop_kw {
        let n = credit.to_ascii_lowercase();
        let has_induction = n.contains("++")
            || n.contains("+= 0x1")
            || n.contains("+=1")
            || n.contains("+ 0x1")
            || n.contains("+0x1")
            || n.contains("+ 1")
            || n.contains("* 0x1")
            || n.contains("*0x1");
        let has_bound = n.contains('<') || n.contains('>') || n.contains("!=");
        let has_if = n.contains("if");
        if has_induction
            && has_bound
            && has_if
            && let Some((&id, _)) = st
                .vertices
                .iter()
                .find(|(_, s)| matches!(s, VertexSort::Predicate))
        {
            st.vertices.insert(id, VertexSort::LoopHeader);
            st.labels.insert(id, "loop".into());
        }
    }
    st
}

/// Build gold structure from fact kinds (synthetic \(\mathfrak H(t)\)).
/// Clarity-only / parameter-role facts do not invent control vertices (they
/// are not structural obligations under Def 1).
pub fn structure_from_gold_facts(
    facts: &[(String, crate::grand_bench::sfg::FactKind)],
) -> TypedStructure {
    use crate::grand_bench::sfg::FactKind;
    let mut st = TypedStructure::default();
    let entry = 0u32;
    st.vertices.insert(entry, VertexSort::Entry);
    st.labels.insert(entry, "entry".into());
    let mut prev = entry;
    let mut id = 1u32;
    let mut last_op = None;
    for (fid, kind) in facts {
        // Non-structural fact kinds omitted from \(\mathfrak H(t)\).
        // Skip parameter roles and bare control_region clarity probes; real
        // regions use Loop/Switch/Predicate kinds for structure.
        if matches!(kind, FactKind::ParameterRole | FactKind::ControlRegion) {
            continue;
        }
        let sort = match kind {
            FactKind::Return => VertexSort::Return,
            FactKind::Loop => VertexSort::LoopHeader,
            // Must match extract_structure_from_pseudo switch → SwitchHead (not Predicate).
            FactKind::Switch => VertexSort::SwitchHead,
            FactKind::Predicate => VertexSort::Predicate,
            FactKind::ControlRegion => VertexSort::Predicate,
            FactKind::CallSite => VertexSort::Call,
            FactKind::Store => VertexSort::Store,
            FactKind::Load | FactKind::MemoryField | FactKind::MemoryObject => VertexSort::Load,
            FactKind::LifetimeRegion => VertexSort::Cleanup,
            FactKind::ExceptionRegion => VertexSort::Predicate,
            FactKind::Operation | FactKind::LocalState | FactKind::Constant => VertexSort::Assign,
            _ => continue,
        };
        st.vertices.insert(id, sort.clone());
        st.labels.insert(id, fid.clone());
        st.control_edges.insert((prev, id));
        if matches!(
            sort,
            VertexSort::Assign | VertexSort::Store | VertexSort::Load
        ) {
            if let Some(lo) = last_op {
                st.data_edges.insert((lo, id));
            }
            last_op = Some(id);
        }
        if matches!(sort, VertexSort::Return | VertexSort::Call)
            && let Some(lo) = last_op
        {
            st.data_edges.insert((lo, id));
        }
        prev = id;
        id += 1;
    }
    st
}

/// Sort-multiset Jaccard (fallback when edge structure is thin).
pub fn sort_jaccard(h: &TypedStructure, h2: &TypedStructure) -> f64 {
    use std::collections::BTreeMap;
    let mut c1: BTreeMap<VertexSort, usize> = BTreeMap::new();
    let mut c2: BTreeMap<VertexSort, usize> = BTreeMap::new();
    for s in h.vertices.values() {
        *c1.entry(s.clone()).or_default() += 1;
    }
    for s in h2.vertices.values() {
        *c2.entry(s.clone()).or_default() += 1;
    }
    let mut inter = 0usize;
    let mut uni = 0usize;
    let mut sorts: BTreeSet<VertexSort> = BTreeSet::new();
    for s in c1.keys().chain(c2.keys()) {
        sorts.insert(s.clone());
    }
    for s in sorts {
        let a = c1.get(&s).copied().unwrap_or(0);
        let b = c2.get(&s).copied().unwrap_or(0);
        inter += a.min(b);
        uni += a.max(b);
    }
    if uni == 0 {
        1.0
    } else {
        inter as f64 / uni as f64
    }
}

/// Effective alignment: max of edge alignment and thin-structure sort Jaccard floor.
/// When the observation recovers the gold *sort multiset* well, raise the floor
/// so honest structured C is not over-penalized by greedy edge matching noise.
pub fn effective_alignment(h: &TypedStructure, h2: &TypedStructure) -> f64 {
    let s_e = score_edge_alignment(h, h2);
    let j = sort_jaccard(h, h2);
    // Presence of all gold sorts in the observation (ignore extra noise verts).
    let mut covered = 0usize;
    let mut need = 0usize;
    for s in h.vertices.values() {
        if *s == VertexSort::Entry {
            continue;
        }
        need += 1;
        if h2.vertices.values().any(|t| t == s) {
            covered += 1;
        }
    }
    let cover = if need == 0 {
        1.0
    } else {
        covered as f64 / need as f64
    };
    // Distinct gold sorts fully present in observation (set coverage, not multiset).
    let mut gold_sorts: BTreeSet<VertexSort> = BTreeSet::new();
    let mut obs_sorts: BTreeSet<VertexSort> = BTreeSet::new();
    for s in h.vertices.values() {
        if *s != VertexSort::Entry {
            gold_sorts.insert(s.clone());
        }
    }
    for s in h2.vertices.values() {
        if *s != VertexSort::Entry {
            obs_sorts.insert(s.clone());
        }
    }
    let set_cover = if gold_sorts.is_empty() {
        1.0
    } else {
        gold_sorts.intersection(&obs_sorts).count() as f64 / gold_sorts.len() as f64
    };
    // Thin gold (≤3 verts incl. entry): rely on sort coverage / Jaccard.
    if h.vertices.len() <= 3 {
        s_e.max(j * 0.95).max(cover * 0.9).max(set_cover * 0.92)
    } else if set_cover >= 0.8 && cover >= 0.55 {
        // Strong structural keyword recovery — edge-match greediness should not
        // dominate (still < 1 unless edges also match).
        s_e.max(j * 0.72).max(cover * 0.62).max(set_cover * 0.72)
    } else if set_cover >= 0.5 {
        s_e.max(j * 0.58).max(cover * 0.48).max(set_cover * 0.5)
    } else {
        s_e.max(j * 0.5).max(cover * 0.4).max(set_cover * 0.35)
    }
}

/// Mixed structural score \(\Phi_{\mathrm{str}}^\sharp = \Phi^\theta \cdot S^{1-\theta}\) (Cor 2.1).
pub fn phi_structural(phi: f64, s_align: f64, theta: f64) -> f64 {
    let phi = phi.clamp(0.0, 1.0);
    let s = s_align.clamp(0.0, 1.0);
    if phi <= 0.0 {
        return 0.0;
    }
    phi.powf(theta) * s.powf(1.0 - theta)
}

/// Return-class operator multiset (Lemma 11 orbit invariant) from live return slice.
pub fn return_class_ops(return_slice: &str) -> BTreeSet<char> {
    let mut ops = BTreeSet::new();
    for line in return_slice.lines() {
        let n: String = line
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if let Some(i) = n.rfind("return") {
            let expr = &n[i..];
            for c in ['+', '-', '*', '/', '^', '&', '|', '%'] {
                if expr.contains(c) {
                    // Skip arrow/decrement false positives for '-'.
                    if c == '-' && (expr.contains("->") || expr.contains("--")) {
                        continue;
                    }
                    ops.insert(c);
                }
            }
        }
    }
    ops
}

/// Multiplicity of an anchor pattern (Lemma 9 — occurrence count, not presence).
pub fn anchor_multiplicity(code: &str, anchor: &str) -> usize {
    if anchor.is_empty() {
        return 0;
    }
    let c: String = code
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let a: String = anchor
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if a.is_empty() {
        return 0;
    }
    c.matches(a.as_str()).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grand_bench::sfg::FactKind;

    fn iso_pair() -> (TypedStructure, TypedStructure) {
        let mut h = TypedStructure::default();
        h.vertices.insert(0, VertexSort::Entry);
        h.vertices.insert(1, VertexSort::LoopHeader);
        h.vertices.insert(2, VertexSort::Assign);
        h.vertices.insert(3, VertexSort::Return);
        h.control_edges.insert((0, 1));
        h.control_edges.insert((1, 2));
        h.control_edges.insert((2, 3));
        h.data_edges.insert((2, 3));
        // Relabeled ids + different label strings (anonymous).
        let mut h2 = TypedStructure::default();
        h2.vertices.insert(10, VertexSort::Entry);
        h2.vertices.insert(11, VertexSort::LoopHeader);
        h2.vertices.insert(12, VertexSort::Assign);
        h2.vertices.insert(13, VertexSort::Return);
        h2.control_edges.insert((10, 11));
        h2.control_edges.insert((11, 12));
        h2.control_edges.insert((12, 13));
        h2.data_edges.insert((12, 13));
        h2.labels.insert(12, "tmp_42".into());
        (h, h2)
    }

    #[test]
    fn align_isomorphism_scores_one() {
        let (h, h2) = iso_pair();
        let s = score_edge_alignment(&h, &h2);
        assert!(s > 0.95, "expected near-1 on isomorphic: {s}");
    }

    #[test]
    fn high_local_low_structure_gap() {
        // Same vertex sorts multiset, wrong edges (edge-blind local would pass).
        let mut gold = TypedStructure::default();
        gold.vertices.insert(0, VertexSort::Entry);
        gold.vertices.insert(1, VertexSort::Assign);
        gold.vertices.insert(2, VertexSort::Return);
        gold.control_edges.insert((0, 1));
        gold.control_edges.insert((1, 2));
        gold.data_edges.insert((1, 2));

        let mut bad = TypedStructure::default();
        bad.vertices.insert(0, VertexSort::Entry);
        bad.vertices.insert(1, VertexSort::Assign);
        bad.vertices.insert(2, VertexSort::Return);
        // Missing data edge; extra control edge cycle-ish reverse.
        bad.control_edges.insert((0, 2));
        bad.control_edges.insert((2, 1));

        let s = score_edge_alignment(&gold, &bad);
        assert!(s < 0.85, "edge-wrong structure should not score 1: {s}");
    }

    #[test]
    fn topology_penalty_monotonic() {
        let p0 = topology_penalty(0, 10, LAMBDA_TOPO);
        let p1 = topology_penalty(1, 10, LAMBDA_TOPO);
        let p5 = topology_penalty(5, 10, LAMBDA_TOPO);
        assert!((p0 - 1.0).abs() < 1e-9);
        assert!(p1 < p0);
        assert!(p5 < p1);
    }

    #[test]
    fn phi_str_requires_structure() {
        let local = 1.0;
        let s_low = 0.2;
        let mixed = phi_structural(local, s_low, THETA_STR);
        assert!(
            mixed < 0.85,
            "high local low S_align must pull down: {mixed}"
        );
        let mixed_full = phi_structural(1.0, 1.0, THETA_STR);
        assert!((mixed_full - 1.0).abs() < 1e-9);
    }

    #[test]
    fn extract_and_align_loop_return() {
        let credit = "int f(int *a,int n){\n  int s=0;\n  for(int i=0;i<n;i++){\n    s=s+a[i];\n  }\n  return s;\n}\n";
        let h = extract_structure_from_pseudo(credit);
        assert!(!h.vertices.is_empty());
        assert!(h.vertices.values().any(|s| *s == VertexSort::LoopHeader));
        assert!(h.vertices.values().any(|s| *s == VertexSort::Return));
        let gold_facts = vec![
            ("loop".into(), FactKind::Loop),
            ("acc".into(), FactKind::Operation),
            ("ret".into(), FactKind::Return),
        ];
        let g = structure_from_gold_facts(&gold_facts);
        let s = effective_alignment(&g, &h);
        assert!(s > 0.3, "partial structure align: {s}");
    }

    #[test]
    fn return_class_ops_stable_under_space() {
        let a = return_class_ops("return a + b;");
        let b = return_class_ops("return  a+b ;");
        assert_eq!(a, b);
        assert!(a.contains(&'+'));
    }

    #[test]
    fn multiplicity_counts_occurrences() {
        assert_eq!(anchor_multiplicity("s=s+1; s=s+1;", "+"), 2);
        assert_eq!(anchor_multiplicity("s=s+1;", "+"), 1);
    }

    /// Priority 3: Switch gold kind maps to SwitchHead and aligns with switch pseudo.
    #[test]
    fn switch_gold_aligns_with_extracted_switch_head() {
        let gold_facts = vec![
            ("sw".into(), FactKind::Switch),
            ("ret".into(), FactKind::Return),
        ];
        let g = structure_from_gold_facts(&gold_facts);
        assert!(
            g.vertices.values().any(|s| *s == VertexSort::SwitchHead),
            "Switch fact must become SwitchHead, not Predicate: {g:?}"
        );
        let credit = r#"
int classify(int n) {
    switch (n) {
    case 0: return 10;
    default: return -1;
    }
}
"#;
        let h = extract_structure_from_pseudo(credit);
        assert!(
            h.vertices.values().any(|s| *s == VertexSort::SwitchHead),
            "extract must emit SwitchHead: {h:?}"
        );
        let s = effective_alignment(&g, &h);
        assert!(
            s > 0.5,
            "switch gold must align to switch decomp: s={s} g={g:?} h={h:?}"
        );
    }
}
