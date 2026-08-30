//! Semantic Fact Graph types and pure align+score API.
//!
//! Implements PDF §6–§9: weighted dimensions, catastrophic caps, depends_on,
//! comment strip, dead/off-slice zero credit, contradiction penalties.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Dimension weights (PDF §7).
pub const W_SEMANTIC: f64 = 0.45;
pub const W_MEMORY: f64 = 0.20;
pub const W_CONTROL: f64 = 0.15;
pub const W_CALLS: f64 = 0.10;
pub const W_CLARITY: f64 = 0.10;

/// Catastrophic caps (PDF §8) — maximum function score when triggered.
pub const CAP_WRONG_RETURN: f64 = 0.35;
pub const CAP_MISSING_STORE: f64 = 0.35;
pub const CAP_FABRICATED_STORE: f64 = 0.30;
pub const CAP_WRONG_CALL_TARGET: f64 = 0.40;
pub const CAP_WRONG_INDIRECT_SLOT: f64 = 0.40;
pub const CAP_WRONG_CALL_ARGS: f64 = 0.50;
pub const CAP_MISSING_CLEANUP: f64 = 0.40;
pub const CAP_WRONG_EXCEPTION: f64 = 0.35;
pub const CAP_BOUND_LOST: f64 = 0.45;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FactKind {
    ParameterRole,
    LocalState,
    MemoryObject,
    MemoryField,
    Load,
    Store,
    Constant,
    Operation,
    Predicate,
    ControlRegion,
    Loop,
    Switch,
    CallSite,
    Return,
    ExceptionRegion,
    LifetimeRegion,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResidualClass {
    SemanticReturnWrong,
    SemanticStateUpdateMissing,
    SemanticStateUpdateFabricated,
    SignednessWrong,
    WidthWrong,
    AliasRelationWrong,
    BoundRelationMissing,
    LoopRecurrenceWrong,
    ControlRegionWrong,
    SwitchCaseMissing,
    SwitchCaseMisrouted,
    CallTargetWrong,
    CallArgOrderWrong,
    CallResultUnused,
    IndirectSlotWrong,
    StructFieldWrong,
    UnionArmWrong,
    ObjectBoundaryWrong,
    LifetimeCleanupMissing,
    LifetimeCleanupEarly,
    ExceptionFilterWrong,
    ExceptionPathMissing,
    InterprocDependencyLost,
    GotoResidual,
    FlagSoupResidual,
    TemporaryExplosion,
    ContradictoryOutput,
    UnsupportedFunction,
    Timeout,
    EmptyDecompile,
    FabricatedStore,
    MissingStore,
    DeadCodeCredit,
    /// Anonymous edge-alignment below structural threshold (Thm 1 gap).
    StructureAlignLow,
    /// Irreducible residual edge mass (goto-like; Def 9 / Thm 7).
    IrreducibleResidual,
}

/// Live slice an expected expression must occupy (PDF §9 dead-code rule).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum FactSlice {
    #[default]
    Any,
    Return,
    Store,
    Call,
    Predicate,
    Lifetime,
    Exception,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FactDimension {
    Semantic,
    Memory,
    Control,
    Calls,
    Clarity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SfgFact {
    pub id: String,
    pub kind: FactKind,
    pub dimension: FactDimension,
    /// Critical facts participate in catastrophic gating when missed.
    #[serde(default)]
    pub critical: bool,
    /// Substrings / anchors that must appear in comment-stripped code (engine-agnostic).
    #[serde(default)]
    pub must_match: Vec<String>,
    /// Any-of alternatives (OR).
    #[serde(default)]
    pub match_any: Vec<String>,
    /// Forbidden residual patterns (if present → residual class).
    #[serde(default)]
    pub forbid: Vec<String>,
    #[serde(default)]
    pub residual_on_miss: Option<ResidualClass>,
    #[serde(default)]
    pub residual_on_forbid: Option<ResidualClass>,
    /// Catastrophic cap if this critical fact fails.
    #[serde(default)]
    pub catastrophic_cap: Option<f64>,
    /// Depends-on fact ids — miss if any parent missed (PDF §6 edges).
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Required live slice for positive credit (PDF §9).
    #[serde(default)]
    pub slice: FactSlice,
    /// Minimum multiplicity for match_any/must anchors (Lemma 9).
    #[serde(default)]
    pub min_multiplicity: Option<usize>,
    /// Orbit-stable return-class ops required (Lemma 11), e.g. ["+","*"].
    #[serde(default)]
    pub return_ops: Vec<char>,
    /// Ordered anchors (Lemma 13 reverse cleanup): must appear left-to-right in credit.
    #[serde(default)]
    pub ordered_match: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SfgFunctionGold {
    pub id: String,
    #[serde(default)]
    pub entry_va: Option<String>,
    #[serde(default)]
    pub source_name: Option<String>,
    pub facts: Vec<SfgFact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SfgProgramGold {
    pub program_id: String,
    pub pack_tags: Vec<String>,
    pub functions: Vec<SfgFunctionGold>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FactVerdict {
    pub fact_id: String,
    pub kind: FactKind,
    pub dimension: FactDimension,
    pub hit: bool,
    pub critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residual: Option<ResidualClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catastrophic_cap: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DimensionScore {
    pub hits: usize,
    pub possible: usize,
    pub score: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionSfgScore {
    pub function_id: String,
    pub engine: String,
    pub empty: bool,
    pub semantic: DimensionScore,
    pub memory: DimensionScore,
    pub control: DimensionScore,
    pub calls: DimensionScore,
    pub clarity: DimensionScore,
    /// Local composite before structure/topology (Φ).
    pub phi_local: f64,
    /// Anonymous edge-alignment \(S_{\mathrm{align}}\).
    pub s_align: f64,
    /// Topology penalty \(P_\lambda\).
    pub topology_penalty: f64,
    /// Primary score: \(\Phi_{\mathrm{str}}^\sharp \cdot P_\lambda\).
    pub composite: f64,
    pub capped: bool,
    pub cap_applied: Option<f64>,
    pub residuals: Vec<ResidualClass>,
    pub fact_verdicts: Vec<FactVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_preview: Option<String>,
}

/// Strip C/C++ comments before positive matching (PDF §9).
pub fn strip_comments_for_credit(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Strip string literal contents (decoy gold injection).
        if bytes[i] == b'"' {
            out.push('"');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    out.push('"');
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn contains_anchor(code: &str, anchor: &str) -> bool {
    let c = norm(code);
    let a = norm(anchor);
    if a.is_empty() {
        return true;
    }
    c.contains(&a)
}

/// Lemma 13: anchors must appear in order (left-to-right) in comment-stripped code.
pub fn ordered_anchors_present(code: &str, anchors: &[String]) -> bool {
    let c = norm(code);
    let mut from = 0usize;
    for a in anchors {
        let an = norm(a);
        if an.is_empty() {
            continue;
        }
        if let Some(rel) = c[from..].find(&an) {
            from += rel + an.len();
        } else {
            return false;
        }
    }
    true
}

/// Split pseudocode into statement-ish fragments (`;` and braces).
fn statements(credit: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in credit.chars() {
        cur.push(ch);
        if ch == ';' || ch == '{' || ch == '}' {
            let t = cur.trim().to_string();
            if !t.is_empty() {
                out.push(t);
            }
            cur.clear();
        }
    }
    let t = cur.trim().to_string();
    if !t.is_empty() {
        out.push(t);
    }
    out
}

/// Extract live body for a slice. Dead statements after unconditional return
/// earn zero credit (PDF §9).
pub fn live_slice_text(credit: &str, slice: &FactSlice) -> String {
    match slice {
        FactSlice::Any => credit.to_string(),
        FactSlice::Return => {
            // Keep return statements and preceding live code; drop statements
            // after an unconditional `return ...;` (dead code earns zero).
            let mut live: Vec<String> = Vec::new();
            let mut dead = false;
            for stmt in statements(credit) {
                let t = stmt.trim();
                let n = norm(t);
                // Switch/case/default and labels reopen independent return paths.
                // Without this, the first `case N: return …` would kill the live
                // slice and hide later HRESULT returns as "dead" (false DEAD_CODE).
                if t.starts_with("case ")
                    || t.starts_with("default")
                    || t.starts_with("} else")
                    || t.starts_with("else")
                    || (t.ends_with(':') && !t.contains(' '))
                {
                    dead = false;
                }
                if dead {
                    continue;
                }
                live.push(stmt.clone());
                // Bare unconditional return ends the live slice for further stmts
                // on this path only (reopened by case/default/else above).
                if n.starts_with("return") && !n.contains('?') {
                    // Conditional form `if (...) return` stays live for other branches.
                    let is_guarded = n.contains("if(")
                        || n.contains("if")
                            && n.find("if")
                                .map(|i| i < n.find("return").unwrap_or(0))
                                .unwrap_or(false);
                    if !is_guarded {
                        dead = true;
                    }
                }
            }
            live.join(" ")
        }
        FactSlice::Store => statements(credit)
            .into_iter()
            .filter(|l| {
                let t = l.trim();
                let n = norm(t);
                n.contains('=')
                    && !n.contains("==")
                    && !n.contains("!=")
                    && !n.contains("<=")
                    && !n.contains(">=")
                    && !n.starts_with("return")
            })
            .collect::<Vec<_>>()
            .join(" "),
        FactSlice::Call => statements(credit)
            .into_iter()
            .filter(|l| l.contains('(') && l.contains(')'))
            .collect::<Vec<_>>()
            .join(" "),
        FactSlice::Predicate => statements(credit)
            .into_iter()
            .filter(|l| {
                let t = l.trim();
                // Case/default labels often share a statement fragment with the
                // following `if (` until `{` (splitter breaks only on `;{}`).
                // Match predicate keywords as substrings, not only line prefixes.
                let n = norm(t);
                t.starts_with("if")
                    || t.starts_with("while")
                    || t.starts_with("for")
                    || n.contains("if(")
                    || n.contains("while(")
                    || n.contains("for(")
                    || n.contains("switch(")
                    || t.contains("&&")
                    || t.contains("||")
                    || t.contains('?')
            })
            .collect::<Vec<_>>()
            .join(" "),
        FactSlice::Lifetime | FactSlice::Exception => credit.to_string(),
    }
}

/// Empty dimensions score 0 and are excluded from weight renormalization.
pub fn dim_score(hits: usize, possible: usize) -> DimensionScore {
    let score = if possible == 0 {
        0.0
    } else {
        hits as f64 / possible as f64
    };
    DimensionScore {
        hits,
        possible,
        score,
    }
}

fn weight_for(dim: &FactDimension) -> f64 {
    match dim {
        FactDimension::Semantic => W_SEMANTIC,
        FactDimension::Memory => W_MEMORY,
        FactDimension::Control => W_CONTROL,
        FactDimension::Calls => W_CALLS,
        FactDimension::Clarity => W_CLARITY,
    }
}

/// Renormalize PDF weights over dimensions that have gold facts (possible > 0).
fn composite_from_dims(dims: &[(FactDimension, &DimensionScore)]) -> f64 {
    let mut wsum = 0.0;
    let mut acc = 0.0;
    for (dim, ds) in dims {
        if ds.possible == 0 {
            continue;
        }
        let w = weight_for(dim);
        wsum += w;
        acc += w * ds.score;
    }
    if wsum <= 0.0 { 0.0 } else { acc / wsum }
}

fn default_cap_for_residual(r: &ResidualClass) -> Option<f64> {
    match r {
        ResidualClass::SemanticReturnWrong => Some(CAP_WRONG_RETURN),
        ResidualClass::MissingStore | ResidualClass::SemanticStateUpdateMissing => {
            Some(CAP_MISSING_STORE)
        }
        ResidualClass::FabricatedStore | ResidualClass::SemanticStateUpdateFabricated => {
            Some(CAP_FABRICATED_STORE)
        }
        ResidualClass::CallTargetWrong => Some(CAP_WRONG_CALL_TARGET),
        ResidualClass::IndirectSlotWrong => Some(CAP_WRONG_INDIRECT_SLOT),
        ResidualClass::CallArgOrderWrong => Some(CAP_WRONG_CALL_ARGS),
        ResidualClass::LifetimeCleanupMissing | ResidualClass::LifetimeCleanupEarly => {
            Some(CAP_MISSING_CLEANUP)
        }
        ResidualClass::ExceptionFilterWrong | ResidualClass::ExceptionPathMissing => {
            Some(CAP_WRONG_EXCEPTION)
        }
        ResidualClass::BoundRelationMissing => Some(CAP_BOUND_LOST),
        ResidualClass::EmptyDecompile => Some(0.0),
        _ => None,
    }
}

/// Detect contradictory multi-hypothesis output (PDF §9).
pub fn detect_contradictory(raw: &str, credit: &str) -> bool {
    let n = norm(credit);
    // Hedge comments in raw text.
    let raw_l = raw.to_ascii_lowercase();
    if raw_l.contains("maybe unsigned")
        || raw_l.contains("/* maybe")
        || raw_l.contains("or possibly")
        || raw_l.contains("alternative:")
    {
        return true;
    }
    // Multiple incompatible return operators across statements.
    let ret_stmts: Vec<String> = statements(credit)
        .into_iter()
        .filter(|l| norm(l).contains("return"))
        .collect();
    if ret_stmts.len() >= 2 {
        let mut ops = HashSet::new();
        for l in &ret_stmts {
            let ln = norm(l);
            // Focus on the return expression, not the whole guarded line.
            let expr = ln.rfind("return").map(|i| &ln[i..]).unwrap_or(ln.as_str());
            if expr.contains('+') {
                ops.insert('+');
            }
            // Minus that is not arrow / decrement.
            if expr.contains('-') && !expr.contains("->") {
                ops.insert('-');
            }
            if expr.contains('^') {
                ops.insert('^');
            }
        }
        if ops.contains(&'+') && ops.contains(&'-') {
            return true;
        }
        if ops.contains(&'+') && ops.contains(&'^') {
            return true;
        }
    }
    if n.contains("intsborrow") && n.contains("intless") {
        return true;
    }
    if credit.matches("default:").count() > 2 {
        return true;
    }
    false
}

/// Score one function's pseudocode against SFG gold. Pure — no I/O.
pub fn score_function_sfg(engine: &str, text: &str, gold: &SfgFunctionGold) -> FunctionSfgScore {
    let empty = text.trim().is_empty()
        || text.contains("decompile failed")
        || text.contains("/* unsupported");
    if empty {
        return FunctionSfgScore {
            function_id: gold.id.clone(),
            engine: engine.into(),
            empty: true,
            semantic: dim_score(0, 1),
            memory: dim_score(0, 0),
            control: dim_score(0, 0),
            calls: dim_score(0, 0),
            clarity: dim_score(0, 1),
            phi_local: 0.0,
            s_align: 0.0,
            topology_penalty: 0.0,
            composite: 0.0,
            capped: true,
            cap_applied: Some(0.0),
            residuals: vec![ResidualClass::EmptyDecompile],
            fact_verdicts: gold
                .facts
                .iter()
                .map(|f| FactVerdict {
                    fact_id: f.id.clone(),
                    kind: f.kind.clone(),
                    dimension: f.dimension.clone(),
                    hit: false,
                    critical: f.critical,
                    residual: Some(ResidualClass::EmptyDecompile),
                    catastrophic_cap: Some(0.0),
                })
                .collect(),
            text_preview: None,
        };
    }

    let credit = strip_comments_for_credit(text);
    let raw = text;

    let mut residuals = Vec::new();
    let mut caps: Vec<f64> = Vec::new();

    // Global clarity residuals from raw text.
    if raw.contains("goto ") || raw.contains("goto\t") {
        residuals.push(ResidualClass::GotoResidual);
    }
    if raw.contains("IntSBorrow")
        || raw.contains("IntSLess")
        || raw.contains("/*(Bool")
        || raw.contains("FLAG_")
    {
        residuals.push(ResidualClass::FlagSoupResidual);
    }
    let assign_count = credit
        .matches('=')
        .count()
        .saturating_sub(credit.matches("==").count() * 2 + credit.matches("!=").count() * 2);
    if assign_count > 40 {
        residuals.push(ResidualClass::TemporaryExplosion);
    }
    if detect_contradictory(raw, &credit) {
        residuals.push(ResidualClass::ContradictoryOutput);
    }

    // Pass 1: match each fact on its live slice (ignore depends_on first).
    let mut provisional: Vec<(bool, Option<ResidualClass>)> = Vec::new();
    for fact in &gold.facts {
        let slice_text = live_slice_text(&credit, &fact.slice);
        let search = if fact.slice == FactSlice::Any {
            credit.as_str()
        } else {
            slice_text.as_str()
        };

        let mut hit = true;
        if !fact.must_match.is_empty() {
            hit = fact.must_match.iter().all(|a| contains_anchor(search, a));
            // Dead-code trap: anchors only in full credit but not live slice.
            if !hit
                && fact.slice != FactSlice::Any
                && fact.must_match.iter().all(|a| contains_anchor(&credit, a))
            {
                residuals.push(ResidualClass::DeadCodeCredit);
            }
        }
        if hit && !fact.match_any.is_empty() {
            // Orbit saturation (Def 7): any representative in the orbit class.
            hit = fact.match_any.iter().any(|a| contains_anchor(search, a));
            if !hit
                && fact.slice != FactSlice::Any
                && fact.match_any.iter().any(|a| contains_anchor(&credit, a))
            {
                residuals.push(ResidualClass::DeadCodeCredit);
            }
        }
        // Loop recurrence orbit (full body, not predicate slice only).
        if !hit && fact.kind == FactKind::Loop {
            let n = norm(&credit);
            let has_loop_kw = n.contains("while")
                || n.contains("for(")
                || n.contains("for")
                || n.contains("do{")
                || n.contains("}while");
            let has_induction = n.contains("++")
                || n.contains("+=0x1")
                || n.contains("+=1")
                || n.contains("+0x1")
                || n.contains("+1")
                || n.contains("lea");
            let has_bound = n.contains('<')
                || n.contains('>')
                || n.contains("!=")
                || n.contains("==")
                || n.contains("\\0")
                || n.contains("'\\0'");
            let has_backedge = (n.contains("goto") && n.contains("l_")) || n.contains("break");
            // Sentinel scans often lower to nested if on *p==0 without while.
            let has_sentinel_scan = (n.contains("\\0") || n.contains("0x0"))
                && n.contains("if")
                && (n.contains("char") || n.contains("mem_") || n.contains('*'));
            if has_loop_kw || (has_induction && has_bound && has_backedge) || has_sentinel_scan {
                hit = true;
            }
        }
        // Branchless control orbit (strict Grand v2): control_region "if" facts
        // also hit on compare/select/pure arithmetic return expressions without
        // fabricated if wrappers (Legacy polish_pure_op_return_to_if retired).
        // Search the full body (not just predicate slice) — branchless kernels
        // have no predicate region, only a return expression.
        if !hit && fact.kind == FactKind::ControlRegion {
            let wants_if = fact
                .must_match
                .iter()
                .any(|m| m.eq_ignore_ascii_case("if") || m.contains("if"));
            if wants_if {
                // Full-body search: branchless kernels have no predicate region.
                // A live return / select (compare, pure arith, or constant) is the
                // accepted form without fabricated if wrappers.
                let n = norm(&credit);
                if n.contains("return") || n.contains("select") {
                    hit = true;
                }
            }
        }
        // Return operator orbit: ops must still lie on the return live slice
        // (not dead code after an unconditional return).
        if !hit && fact.kind == FactKind::Return {
            let ret_live = live_slice_text(&credit, &FactSlice::Return);
            let n = norm(&ret_live);
            if n.contains("return") {
                let need_plus = fact.must_match.iter().any(|m| m.trim() == "+")
                    || fact.return_ops.contains(&'+');
                let need_xor = fact.must_match.iter().any(|m| m.contains('^'))
                    || fact.return_ops.contains(&'^');
                // Allow whitespace-normalized ops on the live return slice only.
                if need_plus && n.contains('+') {
                    hit = true;
                }
                if need_xor && (n.contains('^') || n.contains("xor")) {
                    hit = true;
                }
            }
        }
        // Lemma 9: multiplicity-sensitive facts (presence alone insufficient).
        if hit && let Some(min_m) = fact.min_multiplicity {
            let anchors: Vec<&str> = fact
                .must_match
                .iter()
                .chain(fact.match_any.iter())
                .map(|s| s.as_str())
                .collect();
            let mult = anchors
                .iter()
                .map(|a| super::align::anchor_multiplicity(search, a))
                .max()
                .unwrap_or(0);
            if mult < min_m {
                hit = false;
            }
        }
        // Lemma 11: orbit-stable return-class operators.
        if hit && !fact.return_ops.is_empty() {
            let ops = super::align::return_class_ops(search);
            hit = fact.return_ops.iter().all(|c| ops.contains(c));
        }
        // Lemma 13: ordered anchors (e.g. destroy B then destroy A on reverse cleanup).
        if hit && !fact.ordered_match.is_empty() {
            hit = ordered_anchors_present(search, &fact.ordered_match);
        }
        let mut residual = None;
        for fbd in &fact.forbid {
            if contains_anchor(raw, fbd) || contains_anchor(&credit, fbd) {
                hit = false;
                residual = fact.residual_on_forbid.clone();
                break;
            }
        }
        if !hit && residual.is_none() {
            residual = fact.residual_on_miss.clone();
        }
        // Clarity forbid-only facts: hit when residual absent.
        if fact.dimension == FactDimension::Clarity
            && fact.must_match.is_empty()
            && fact.match_any.is_empty()
            && residual.is_none()
        {
            hit = true;
        }
        provisional.push((hit, residual));
    }

    // Pass 2: depends_on edges — child misses if any parent missed.
    let id_to_idx: HashMap<&str, usize> = gold
        .facts
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.as_str(), i))
        .collect();
    let mut hit_final: Vec<bool> = provisional.iter().map(|(h, _)| *h).collect();
    // Iterate to fixed point for chains.
    for _ in 0..gold.facts.len().max(1) {
        let mut changed = false;
        for (i, fact) in gold.facts.iter().enumerate() {
            if !hit_final[i] {
                continue;
            }
            for dep in &fact.depends_on {
                if let Some(&di) = id_to_idx.get(dep.as_str()) {
                    if !hit_final[di] {
                        hit_final[i] = false;
                        if provisional[i].1.is_none() {
                            provisional[i].1 = fact.residual_on_miss.clone();
                        }
                        changed = true;
                    }
                } else {
                    // Missing parent id → fail closed.
                    hit_final[i] = false;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut verdicts = Vec::new();
    for (i, fact) in gold.facts.iter().enumerate() {
        let hit = hit_final[i];
        let residual = if hit { None } else { provisional[i].1.clone() };
        if let Some(ref r) = residual {
            residuals.push(r.clone());
        }
        let mut cap = if !hit && fact.critical {
            fact.catastrophic_cap
                .or_else(|| residual.as_ref().and_then(default_cap_for_residual))
        } else {
            None
        };
        if !hit
            && fact.critical
            && let Some(c) = cap
        {
            caps.push(c);
        }
        // Clarity free-hit already handled.
        let _ = &mut cap;
        verdicts.push(FactVerdict {
            fact_id: fact.id.clone(),
            kind: fact.kind.clone(),
            dimension: fact.dimension.clone(),
            hit,
            critical: fact.critical,
            residual,
            catastrophic_cap: if !hit { fact.catastrophic_cap } else { None },
        });
    }

    // Clarity auto-probe when no explicit clarity facts.
    let clarity_auto_hit = !residuals.iter().any(|r| {
        matches!(
            r,
            ResidualClass::GotoResidual
                | ResidualClass::FlagSoupResidual
                | ResidualClass::TemporaryExplosion
                | ResidualClass::ContradictoryOutput
                | ResidualClass::DeadCodeCredit
        )
    });

    let mut dim_hits: BTreeMap<FactDimension, (usize, usize)> = BTreeMap::new();
    for v in &verdicts {
        let e = dim_hits.entry(v.dimension.clone()).or_insert((0, 0));
        e.1 += 1;
        if v.hit {
            e.0 += 1;
        }
    }
    let clarity_entry = dim_hits.entry(FactDimension::Clarity).or_insert((0, 0));
    if clarity_entry.1 == 0 {
        clarity_entry.1 = 1;
        if clarity_auto_hit {
            clarity_entry.0 = 1;
        }
    }

    let semantic = dim_score(
        dim_hits
            .get(&FactDimension::Semantic)
            .map(|x| x.0)
            .unwrap_or(0),
        dim_hits
            .get(&FactDimension::Semantic)
            .map(|x| x.1)
            .unwrap_or(0),
    );
    let memory = dim_score(
        dim_hits
            .get(&FactDimension::Memory)
            .map(|x| x.0)
            .unwrap_or(0),
        dim_hits
            .get(&FactDimension::Memory)
            .map(|x| x.1)
            .unwrap_or(0),
    );
    let control = dim_score(
        dim_hits
            .get(&FactDimension::Control)
            .map(|x| x.0)
            .unwrap_or(0),
        dim_hits
            .get(&FactDimension::Control)
            .map(|x| x.1)
            .unwrap_or(0),
    );
    let calls = dim_score(
        dim_hits
            .get(&FactDimension::Calls)
            .map(|x| x.0)
            .unwrap_or(0),
        dim_hits
            .get(&FactDimension::Calls)
            .map(|x| x.1)
            .unwrap_or(0),
    );
    let clarity = dim_score(
        dim_hits
            .get(&FactDimension::Clarity)
            .map(|x| x.0)
            .unwrap_or(0),
        dim_hits
            .get(&FactDimension::Clarity)
            .map(|x| x.1)
            .unwrap_or(0),
    );

    let mut phi_local = composite_from_dims(&[
        (FactDimension::Semantic, &semantic),
        (FactDimension::Memory, &memory),
        (FactDimension::Control, &control),
        (FactDimension::Calls, &calls),
        (FactDimension::Clarity, &clarity),
    ]);

    // Contradiction soft→hard: cap at 0.55 if contradictory.
    if residuals
        .iter()
        .any(|r| matches!(r, ResidualClass::ContradictoryOutput))
    {
        phi_local = phi_local.min(0.55);
        residuals.push(ResidualClass::ContradictoryOutput);
    }

    let mut capped = false;
    let mut cap_applied = None;
    // Any critical catastrophic miss applies the cap (even if already lower).
    if let Some(cap) = caps.into_iter().reduce(f64::min) {
        capped = true;
        cap_applied = Some(cap);
        if phi_local > cap {
            phi_local = cap;
        }
    }

    // Clarity residual soft penalty on local Φ.
    if residuals.iter().any(|r| {
        matches!(
            r,
            ResidualClass::GotoResidual
                | ResidualClass::FlagSoupResidual
                | ResidualClass::DeadCodeCredit
        )
    }) {
        phi_local *= 0.92;
    }

    // Def 4 / Thm 2: anonymous edge-alignment against gold-fact structure.
    let gold_kinds: Vec<(String, FactKind)> = gold
        .facts
        .iter()
        .map(|f| (f.id.clone(), f.kind.clone()))
        .collect();
    let h_gold = super::align::structure_from_gold_facts(&gold_kinds);
    let h_obs = super::align::extract_structure_from_pseudo(&credit);
    let s_align = super::align::effective_alignment(&h_gold, &h_obs);
    if s_align < 0.45 && h_gold.vertices.len() > 3 {
        residuals.push(ResidualClass::StructureAlignLow);
    }

    // Def 15 / Thm 7: continuous residual-edge topology penalty.
    let (res_edges, tot_edges) = super::align::residual_edge_counts(raw);
    let topo = super::align::topology_penalty(res_edges, tot_edges, super::align::LAMBDA_TOPO);
    if res_edges > 0 {
        residuals.push(ResidualClass::IrreducibleResidual);
    }

    // Cor 2.1: Φ_str^♯ = Φ^θ · S_align^(1-θ), then × topology.
    let mut composite =
        super::align::phi_structural(phi_local, s_align, super::align::THETA_STR) * topo;
    if let Some(cap) = cap_applied
        && composite > cap
    {
        composite = cap;
    }

    residuals.sort();
    residuals.dedup();

    let preview: String = text.chars().take(280).collect();
    FunctionSfgScore {
        function_id: gold.id.clone(),
        engine: engine.into(),
        empty: false,
        semantic,
        memory,
        control,
        calls,
        clarity,
        phi_local,
        s_align,
        topology_penalty: topo,
        composite,
        capped,
        cap_applied,
        residuals,
        fact_verdicts: verdicts,
        text_preview: Some(preview),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn fact(
        id: &str,
        kind: FactKind,
        dim: FactDimension,
        must: &[&str],
        any: &[&str],
        critical: bool,
        cap: Option<f64>,
        miss: Option<ResidualClass>,
        depends: &[&str],
        slice: FactSlice,
    ) -> SfgFact {
        SfgFact {
            id: id.into(),
            kind,
            dimension: dim,
            critical,
            must_match: must.iter().map(|s| (*s).into()).collect(),
            match_any: any.iter().map(|s| (*s).into()).collect(),
            forbid: vec![],
            residual_on_miss: miss,
            min_multiplicity: None,
            return_ops: vec![],
            ordered_match: vec![],
            residual_on_forbid: None,
            catastrophic_cap: cap,
            depends_on: depends.iter().map(|s| (*s).into()).collect(),
            slice,
        }
    }

    fn gold_return_plus() -> SfgFunctionGold {
        SfgFunctionGold {
            id: "add".into(),
            entry_va: None,
            source_name: Some("add".into()),
            facts: vec![
                fact(
                    "ret",
                    FactKind::Return,
                    FactDimension::Semantic,
                    &["return", "+"],
                    &[],
                    true,
                    Some(CAP_WRONG_RETURN),
                    Some(ResidualClass::SemanticReturnWrong),
                    &[],
                    FactSlice::Return,
                ),
                fact(
                    "no_goto",
                    FactKind::ControlRegion,
                    FactDimension::Clarity,
                    &[],
                    &[],
                    false,
                    None,
                    None,
                    &[],
                    FactSlice::Any,
                ),
            ],
        }
    }

    #[test]
    fn correct_alignment_gets_credit() {
        let g = gold_return_plus();
        let s = score_function_sfg("test", "int f(int a,int b){ return a + b; }", &g);
        // Φ_str + topology high for clean structured emit (local perfect).
        assert!(s.composite > 0.7, "{s:?}");
        assert!(s.phi_local > 0.9, "{s:?}");
        assert!(s.s_align > 0.5, "{s:?}");
        assert!(!s.capped);
        assert!(s.fact_verdicts.iter().all(|v| v.hit));
    }

    #[test]
    fn structure_pulls_down_local_perfect_but_edge_wrong() {
        // Local return ops present but no structured control → lower S_align path.
        let g = SfgFunctionGold {
            id: "loopish".into(),
            entry_va: None,
            source_name: None,
            facts: vec![
                fact(
                    "loop",
                    FactKind::Loop,
                    FactDimension::Control,
                    &[],
                    &["while", "for"],
                    true,
                    None,
                    Some(ResidualClass::LoopRecurrenceWrong),
                    &[],
                    FactSlice::Predicate,
                ),
                fact(
                    "ret",
                    FactKind::Return,
                    FactDimension::Semantic,
                    &["return"],
                    &[],
                    true,
                    Some(CAP_WRONG_RETURN),
                    Some(ResidualClass::SemanticReturnWrong),
                    &[],
                    FactSlice::Return,
                ),
            ],
        };
        let flat = "int f(int n){ int s=0; L: s=s+1; if(s<n) goto L; return s; }";
        let s = score_function_sfg("test", flat, &g);
        assert!(
            s.residuals.iter().any(|r| matches!(
                r,
                ResidualClass::GotoResidual | ResidualClass::IrreducibleResidual
            )),
            "{s:?}"
        );
        assert!(s.topology_penalty < 1.0, "{s:?}");
    }

    #[test]
    fn return_ops_orbit_stable_match() {
        let mut g = gold_return_plus();
        g.facts[0].return_ops = vec!['+'];
        let ok = score_function_sfg("test", "int f(int a,int b){ return b + a; }", &g);
        assert!(ok.fact_verdicts.iter().any(|v| v.fact_id == "ret" && v.hit));
        let bad = score_function_sfg("test", "int f(int a,int b){ return a - b; }", &g);
        assert!(
            bad.fact_verdicts
                .iter()
                .any(|v| v.fact_id == "ret" && !v.hit)
        );
    }

    /// Priority 3 (Lemma 12): complete finite case partition under binary refinement.
    /// Gold requires switch + full case multiset; incomplete partition fails.
    #[test]
    fn complete_case_partition_requires_all_arms() {
        let g = SfgFunctionGold {
            id: "classify".into(),
            entry_va: None,
            source_name: Some("classify".into()),
            facts: vec![
                fact(
                    "sw",
                    FactKind::Switch,
                    FactDimension::Control,
                    &[],
                    &["switch", "case"],
                    true,
                    None,
                    Some(ResidualClass::SwitchCaseMissing),
                    &[],
                    FactSlice::Any,
                ),
                {
                    let mut f = fact(
                        "cases",
                        FactKind::Constant,
                        FactDimension::Semantic,
                        &[],
                        &["case 0", "case 1", "case 2", "default"],
                        true,
                        None,
                        Some(ResidualClass::SwitchCaseMissing),
                        &[],
                        FactSlice::Any,
                    );
                    // Four distinct case bodies / arms must appear.
                    f.min_multiplicity = Some(1);
                    f.must_match = vec![
                        "case 0".into(),
                        "case 1".into(),
                        "case 2".into(),
                        "default".into(),
                    ];
                    f.match_any = vec![];
                    f
                },
            ],
        };
        let complete = r#"
int classify(int n) {
    switch (n) {
    case 0: return 10;
    case 1: return 20;
    case 2: return 30;
    default: return -1;
    }
}
"#;
        let ok = score_function_sfg("test", complete, &g);
        assert!(
            ok.fact_verdicts.iter().all(|v| v.hit),
            "complete partition must hit: {ok:?}"
        );

        let incomplete = r#"
int classify(int n) {
    switch (n) {
    case 0: return 10;
    case 1: return 20;
    default: return -1;
    }
}
"#;
        let bad = score_function_sfg("test", incomplete, &g);
        assert!(
            bad.fact_verdicts
                .iter()
                .any(|v| v.fact_id == "cases" && !v.hit),
            "missing case 2 must fail partition: {bad:?}"
        );
        assert!(
            bad.residuals
                .iter()
                .any(|r| matches!(r, ResidualClass::SwitchCaseMissing)),
            "{bad:?}"
        );
    }

    /// Priority 5 (Lemma 13): reverse cleanup order via ordered_match + multiplicity.
    #[test]
    fn ordered_cleanup_requires_reverse_destroy() {
        let g = SfgFunctionGold {
            id: "parse_tree".into(),
            entry_va: None,
            source_name: Some("parse_tree".into()),
            facts: vec![
                {
                    let mut f = fact(
                        "j9_init",
                        FactKind::CallSite,
                        FactDimension::Calls,
                        &[],
                        &["res_init"],
                        true,
                        Some(CAP_WRONG_CALL_TARGET),
                        Some(ResidualClass::CallTargetWrong),
                        &[],
                        FactSlice::Call,
                    );
                    f.min_multiplicity = Some(2);
                    f
                },
                {
                    let mut f = fact(
                        "j10_order",
                        FactKind::LifetimeRegion,
                        FactDimension::Memory,
                        &[],
                        &["res_destroy"],
                        true,
                        Some(CAP_MISSING_CLEANUP),
                        Some(ResidualClass::LifetimeCleanupMissing),
                        &[],
                        FactSlice::Any,
                    );
                    // Reverse order: destroy b then destroy a (init was a then b).
                    f.ordered_match = vec!["res_destroy(&b)".into(), "res_destroy(&a)".into()];
                    f.min_multiplicity = Some(2);
                    f
                },
            ],
        };
        let correct = r#"
int parse_tree(void) {
    Res a, b;
    res_init(&a, 1);
    res_init(&b, 2);
    a.id = a.id + 1;
    res_destroy(&b);
    res_destroy(&a);
    return a.id;
}
"#;
        let ok = score_function_sfg("test", correct, &g);
        assert!(
            ok.fact_verdicts.iter().all(|v| v.hit),
            "reverse cleanup order must pass: {ok:?}"
        );

        let wrong_order = r#"
int parse_tree(void) {
    Res a, b;
    res_init(&a, 1);
    res_init(&b, 2);
    a.id = a.id + 1;
    res_destroy(&a);
    res_destroy(&b);
    return a.id;
}
"#;
        let bad = score_function_sfg("test", wrong_order, &g);
        assert!(
            bad.fact_verdicts
                .iter()
                .any(|v| v.fact_id == "j10_order" && !v.hit),
            "wrong destroy order must fail: {bad:?}"
        );

        let one_destroy = r#"
int parse_tree(void) {
    Res a, b;
    res_init(&a, 1);
    res_init(&b, 2);
    res_destroy(&b);
    return a.id;
}
"#;
        let miss = score_function_sfg("test", one_destroy, &g);
        assert!(
            miss.fact_verdicts
                .iter()
                .any(|v| v.fact_id == "j10_order" && !v.hit),
            "single destroy must fail multiplicity/order: {miss:?}"
        );
    }

    #[test]
    fn multiplicity_fact_requires_count() {
        let g = SfgFunctionGold {
            id: "mul".into(),
            entry_va: None,
            source_name: None,
            facts: vec![{
                let mut f = fact(
                    "acc",
                    FactKind::Operation,
                    FactDimension::Semantic,
                    &["+"],
                    &[],
                    true,
                    Some(CAP_MISSING_STORE),
                    Some(ResidualClass::SemanticStateUpdateMissing),
                    &[],
                    FactSlice::Any,
                );
                f.min_multiplicity = Some(2);
                f
            }],
        };
        let once = score_function_sfg("test", "int f(){ int s=0; s=s+1; return s; }", &g);
        assert!(once.fact_verdicts.iter().any(|v| !v.hit), "{once:?}");
        let twice = score_function_sfg("test", "int f(){ int s=0; s=s+1; s=s+1; return s; }", &g);
        assert!(twice.fact_verdicts.iter().all(|v| v.hit), "{twice:?}");
    }

    #[test]
    fn wrong_return_caps_score() {
        let g = gold_return_plus();
        let s = score_function_sfg("test", "int f(int a,int b){ return a - b; }", &g);
        assert!(s.capped, "{s:?}");
        assert!(s.composite <= CAP_WRONG_RETURN + 1e-9);
        assert!(
            s.residuals
                .iter()
                .any(|r| matches!(r, ResidualClass::SemanticReturnWrong))
        );
    }

    #[test]
    fn missing_store_caps_score() {
        let g = SfgFunctionGold {
            id: "store".into(),
            entry_va: None,
            source_name: None,
            facts: vec![fact(
                "st",
                FactKind::Store,
                FactDimension::Memory,
                &["*p", "="],
                &["*p=", "p["],
                true,
                Some(CAP_MISSING_STORE),
                Some(ResidualClass::MissingStore),
                &[],
                FactSlice::Store,
            )],
        };
        let s = score_function_sfg("test", "int f(int *p){ return 1; }", &g);
        assert!(s.capped, "{s:?}");
        assert!(s.composite <= CAP_MISSING_STORE + 1e-9);
    }

    #[test]
    fn wrong_call_target_caps_score() {
        let g = SfgFunctionGold {
            id: "caller".into(),
            entry_va: None,
            source_name: None,
            facts: vec![fact(
                "c",
                FactKind::CallSite,
                FactDimension::Calls,
                &[],
                &["helper(", "helper ("],
                true,
                Some(CAP_WRONG_CALL_TARGET),
                Some(ResidualClass::CallTargetWrong),
                &[],
                FactSlice::Call,
            )],
        };
        let s = score_function_sfg("test", "int f(void){ return other(1); }", &g);
        assert!(s.capped, "{s:?}");
        assert!(s.composite <= CAP_WRONG_CALL_TARGET + 1e-9);
    }

    #[test]
    fn comments_earn_zero_credit() {
        let g = gold_return_plus();
        let s = score_function_sfg(
            "test",
            "int f(int a,int b){ /* return a + b */ return a; }",
            &g,
        );
        assert!(
            s.fact_verdicts.iter().any(|v| v.fact_id == "ret" && !v.hit),
            "{s:?}"
        );
    }

    #[test]
    fn dead_code_after_return_earns_zero() {
        let g = SfgFunctionGold {
            id: "dead".into(),
            entry_va: None,
            source_name: None,
            facts: vec![fact(
                "ret",
                FactKind::Return,
                FactDimension::Semantic,
                &["return", "+"],
                &[],
                true,
                Some(CAP_WRONG_RETURN),
                Some(ResidualClass::SemanticReturnWrong),
                &[],
                FactSlice::Return,
            )],
        };
        // Correct expression only after an unconditional wrong return → dead.
        let s = score_function_sfg(
            "test",
            "int f(int a,int b){ return a; int z = a + b; (void)z; }",
            &g,
        );
        assert!(
            s.fact_verdicts.iter().any(|v| !v.hit),
            "dead + should not credit: {s:?}"
        );
        assert!(s.composite <= CAP_WRONG_RETURN + 1e-9, "{s:?}");
    }

    #[test]
    fn depends_on_parent_miss_blocks_child() {
        let g = SfgFunctionGold {
            id: "dep".into(),
            entry_va: None,
            source_name: None,
            facts: vec![
                fact(
                    "acc",
                    FactKind::Operation,
                    FactDimension::Semantic,
                    &["^="],
                    &[],
                    true,
                    Some(CAP_MISSING_STORE),
                    Some(ResidualClass::SemanticStateUpdateMissing),
                    &[],
                    FactSlice::Any,
                ),
                fact(
                    "ret",
                    FactKind::Return,
                    FactDimension::Semantic,
                    &["return"],
                    &[],
                    true,
                    Some(CAP_WRONG_RETURN),
                    Some(ResidualClass::SemanticReturnWrong),
                    &["acc"],
                    FactSlice::Return,
                ),
            ],
        };
        // return present but accumulator ^= missing → ret blocked by depends_on
        let s = score_function_sfg("test", "int f(int a){ int s=a; return s; }", &g);
        assert!(
            s.fact_verdicts.iter().any(|v| v.fact_id == "ret" && !v.hit),
            "{s:?}"
        );
    }

    #[test]
    fn empty_dimension_does_not_inflate_score() {
        // Only semantic fact; memory/control/calls absent → no free 1.0 credit.
        let g = SfgFunctionGold {
            id: "thin".into(),
            entry_va: None,
            source_name: None,
            facts: vec![fact(
                "ret",
                FactKind::Return,
                FactDimension::Semantic,
                &["return", "+"],
                &[],
                true,
                Some(CAP_WRONG_RETURN),
                Some(ResidualClass::SemanticReturnWrong),
                &[],
                FactSlice::Return,
            )],
        };
        let s = score_function_sfg("test", "int f(int a,int b){ return a + b; }", &g);
        assert_eq!(s.memory.possible, 0);
        assert_eq!(s.memory.score, 0.0);
        // Perfect semantic + auto clarity ≈ 1.0 after renormalize (no free mem/ctrl/calls).
        assert!(s.phi_local > 0.85, "{s:?}");
        assert!(s.composite > 0.55, "{s:?}");
        // Wrong return must still be low even without free dims.
        let bad = score_function_sfg("test", "int f(int a,int b){ return a - b; }", &g);
        assert!(bad.composite <= CAP_WRONG_RETURN + 1e-9, "{bad:?}");
        assert!(bad.capped, "{bad:?}");
    }

    #[test]
    fn contradictory_output_detected() {
        let g = gold_return_plus();
        let s = score_function_sfg(
            "test",
            "int f(int a,int b){ if(a) return a + b; return a - b; }",
            &g,
        );
        assert!(
            s.residuals
                .iter()
                .any(|r| matches!(r, ResidualClass::ContradictoryOutput)),
            "{s:?}"
        );
    }

    #[test]
    fn empty_decomp_is_zero() {
        let g = gold_return_plus();
        let s = score_function_sfg("test", "   ", &g);
        assert_eq!(s.composite, 0.0);
        assert!(s.empty);
    }

    #[test]
    fn goto_residual_detected() {
        let g = gold_return_plus();
        let s = score_function_sfg(
            "test",
            "int f(int a,int b){ if(a) goto L; return a + b; L: return 0; }",
            &g,
        );
        assert!(
            s.residuals
                .iter()
                .any(|r| matches!(r, ResidualClass::GotoResidual))
        );
    }

    #[test]
    fn flag_soup_residual_detected() {
        let g = gold_return_plus();
        let s = score_function_sfg(
            "test",
            "int f(int a,int b){ if(/*(IntSBorrow ...)*/a) return a + b; return 0; }",
            &g,
        );
        assert!(
            s.residuals
                .iter()
                .any(|r| matches!(r, ResidualClass::FlagSoupResidual))
        );
    }

    /// Switch case labels share a statement fragment with nested `if (` until `{`.
    /// Predicate-slice control facts must still credit the live `if`.
    #[test]
    fn if_inside_case_body_hits_control_region() {
        let g = SfgFunctionGold {
            id: "dispatch".into(),
            entry_va: None,
            source_name: Some("dispatch".into()),
            facts: vec![
                fact(
                    "ret",
                    FactKind::Return,
                    FactDimension::Semantic,
                    &["return"],
                    &[],
                    true,
                    Some(CAP_WRONG_RETURN),
                    Some(ResidualClass::SemanticReturnWrong),
                    &[],
                    FactSlice::Return,
                ),
                fact(
                    "if_region",
                    FactKind::ControlRegion,
                    FactDimension::Control,
                    &["if"],
                    &[],
                    true,
                    None,
                    Some(ResidualClass::ControlRegionWrong),
                    &[],
                    FactSlice::Predicate,
                ),
            ],
        };
        let text = r#"uint64 FUN_140001040(u64 arg1, u64 arg2, u64 arg3) {
 arg_20 = *(arg_40);
 switch (*(arg_20)) {
 case 1:
 break;
 case 4:
 if (((*(arg_50) - 0x0) == 0x0)) {
 arg_24 = 0x0;
 } else {
 arg_24 = 1;
 }
 break;
 default:
 break;
 }
 return ((u64)*(arg_48) * (u64)*(arg_50));
}"#;
        let s = score_function_sfg("dispatch", text, &g);
        let if_v = s
            .fact_verdicts
            .iter()
            .find(|v| v.fact_id == "if_region")
            .expect("if_region fact");
        assert!(
            if_v.hit,
            "case-nested if must hit predicate control region; residuals={:?} live_pred={:?}",
            s.residuals,
            live_slice_text(&strip_comments_for_credit(text), &FactSlice::Predicate)
        );
        assert!(
            !s.residuals
                .iter()
                .any(|r| matches!(r, ResidualClass::ControlRegionWrong)),
            "{s:?}"
        );
    }
}
