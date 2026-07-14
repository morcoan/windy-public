//! Offline source region/effect graphs + symmetric graph scoring for strict Grand v2.
//!
//! Gold is generated from Grand `.c` sources via the evaluator frontend and checked
//! into `eval/grand/graph_gold/`. Runtime scoring parses decomp text through the
//! **same** frontend and compares graph identities — never lexical `must_match`.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::evaluator::{ExtractedGraph, ReturnClass, extract_graph_from_text, parse_all_functions};
use super::sfg::{
    FactDimension, FactKind, FactVerdict, FunctionSfgScore, ResidualClass, dim_score,
};

/// Checked-in program graph gold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceProgramGraph {
    pub program_id: String,
    #[serde(default)]
    pub source: String,
    pub functions: Vec<SourceFunctionGraph>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceFunctionGraph {
    pub id: String,
    #[serde(default)]
    pub source_name: Option<String>,
    /// Structural regions expected (expr_return does **not** require `if`).
    #[serde(default)]
    pub regions: Vec<RegionKind>,
    /// Critical / non-critical effects.
    pub effects: Vec<GraphEffect>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// Branchless or structured return expression (compare/select/binop ok).
    ExprReturn,
    If,
    Loop,
    Switch,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GraphEffect {
    Return {
        #[serde(default)]
        class: Option<ReturnClass>,
        #[serde(default)]
        ops: Vec<String>,
        #[serde(default)]
        critical: bool,
    },
    Store {
        #[serde(default)]
        critical: bool,
    },
    Call {
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        critical: bool,
    },
    SwitchPartition {
        #[serde(default)]
        cases: Vec<i64>,
        #[serde(default)]
        critical: bool,
    },
    Loop {
        #[serde(default)]
        critical: bool,
    },
}

impl GraphEffect {
    fn critical(&self) -> bool {
        match self {
            GraphEffect::Return { critical, .. }
            | GraphEffect::Store { critical }
            | GraphEffect::Call { critical, .. }
            | GraphEffect::SwitchPartition { critical, .. }
            | GraphEffect::Loop { critical } => *critical,
        }
    }

    fn id_tag(&self) -> String {
        match self {
            GraphEffect::Return { class, ops, .. } => {
                format!("ret:{:?}:{}", class, ops.join(""))
            }
            GraphEffect::Store { .. } => "store".into(),
            GraphEffect::Call { target, .. } => {
                format!("call:{}", target.as_deref().unwrap_or("*"))
            }
            GraphEffect::SwitchPartition { cases, .. } => {
                format!("switch:{}", cases.len())
            }
            GraphEffect::Loop { .. } => "loop".into(),
        }
    }
}

/// Load `eval/grand/graph_gold/{program_id}.json` if present.
pub fn load_program_graph_gold(path: &Path) -> Option<SourceProgramGraph> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn graph_gold_path(repo: &Path, program_id: &str) -> PathBuf {
    repo.join("eval/grand/graph_gold")
        .join(format!("{program_id}.json"))
}

/// Build a [`SourceFunctionGraph`] from evaluator extract of source or decomp text.
pub fn graph_from_extracted(
    id: &str,
    source_name: Option<&str>,
    g: &ExtractedGraph,
) -> SourceFunctionGraph {
    let mut regions = Vec::new();
    if g.has_return {
        regions.push(RegionKind::ExprReturn);
    }
    if g.has_if {
        regions.push(RegionKind::If);
    }
    if g.has_loop {
        regions.push(RegionKind::Loop);
    }
    if g.has_switch {
        regions.push(RegionKind::Switch);
    }
    let mut effects = Vec::new();
    if g.has_return {
        let class = g
            .return_classes
            .first()
            .cloned()
            .or(Some(ReturnClass::Other));
        // Critical identity is return class (compare/binop/const), not lexical ops.
        // Specific ops are a soft non-critical effect (orbit-stable any-of).
        effects.push(GraphEffect::Return {
            class: class.clone(),
            ops: vec![],
            critical: true,
        });
        if !g.return_ops.is_empty() {
            effects.push(GraphEffect::Return {
                class: None,
                ops: g.return_ops.clone(),
                critical: false,
            });
        }
    }
    if g.store_count > 0 {
        effects.push(GraphEffect::Store { critical: false });
    }
    for t in &g.call_targets {
        if t == "main" {
            continue;
        }
        effects.push(GraphEffect::Call {
            target: Some(t.clone()),
            critical: false,
        });
    }
    if g.has_switch {
        effects.push(GraphEffect::SwitchPartition {
            cases: g.switch_case_values.clone(),
            // Case partition residual is scored, but not catastrophic by default
            // (decomp switches often use different value encoding).
            critical: false,
        });
    }
    if g.has_loop {
        effects.push(GraphEffect::Loop { critical: false });
    }
    SourceFunctionGraph {
        id: id.into(),
        source_name: source_name.map(|s| s.into()),
        regions,
        effects,
    }
}

/// Offline: parse Grand C sources into a program graph gold document.
#[allow(dead_code)] // used by offline generator tests + tooling
pub fn generate_graph_from_c_source(program_id: &str, source: &str) -> SourceProgramGraph {
    let fns = parse_all_functions(source);
    let mut functions = Vec::new();
    for pf in fns {
        if pf.name == "main" {
            continue;
        }
        // Reconstruct a minimal function text for extract.
        let body: String = pf
            .body
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let text = format!("int {}(void) {{ {} }}", pf.name, body);
        let g = extract_graph_from_text(&text);
        functions.push(graph_from_extracted(&pf.name, Some(&pf.name), &g));
    }
    SourceProgramGraph {
        program_id: program_id.into(),
        source: String::new(),
        functions,
    }
}

fn effect_hit(effect: &GraphEffect, got: &ExtractedGraph) -> bool {
    match effect {
        GraphEffect::Return { class, ops, .. } => {
            if !got.has_return {
                return false;
            }
            // Required operators: any-of overlap when specified (orbit-stable).
            let ops_ok =
                ops.is_empty() || ops.iter().any(|o| got.return_ops.iter().any(|g| g == o));
            if !ops_ok {
                return false;
            }
            let Some(want) = class else {
                return true;
            };
            match want {
                ReturnClass::Compare => {
                    got.branchless_compare_return
                        || got.return_classes.contains(&ReturnClass::Compare)
                        || got.return_ops.iter().any(|o| {
                            matches!(o.as_str(), "<" | ">" | "<=" | ">=" | "==" | "!=" | "?")
                        })
                }
                ReturnClass::BinOp => {
                    got.return_classes.contains(&ReturnClass::BinOp)
                        || got.return_ops.iter().any(|o| {
                            matches!(
                                o.as_str(),
                                "+" | "-" | "*" | "/" | "%" | "^" | "&" | "|" | "<<" | ">>"
                            )
                        })
                }
                ReturnClass::Const => {
                    // Multi-exit switches often lower as binop/name; presence of
                    // return is enough for class Const identity.
                    got.has_return
                }
                ReturnClass::Other | ReturnClass::Name | ReturnClass::Load | ReturnClass::Call => {
                    true // presence of return + ops_ok is enough
                }
            }
        }
        GraphEffect::Store { .. } => got.store_count > 0,
        GraphEffect::Call { target, .. } => {
            if got.call_targets.is_empty() {
                return false;
            }
            match target {
                None => true,
                Some(t) => got
                    .call_targets
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(t) || c.contains(t)),
            }
        }
        GraphEffect::SwitchPartition { cases, .. } => {
            if !got.has_switch {
                return false;
            }
            // Partition: every gold case value appears, or at least same count.
            if cases.is_empty() {
                return true;
            }
            let covered = cases
                .iter()
                .filter(|c| got.switch_case_values.contains(c))
                .count();
            covered * 2 >= cases.len() // ≥50% case coverage
        }
        GraphEffect::Loop { .. } => got.has_loop,
    }
}

fn region_hit(region: &RegionKind, got: &ExtractedGraph) -> bool {
    match region {
        RegionKind::ExprReturn => got.has_return,
        // If gold asks for If, branchless compare return also satisfies control.
        RegionKind::If => got.has_if || got.branchless_compare_return,
        RegionKind::Loop => got.has_loop,
        RegionKind::Switch => got.has_switch,
    }
}

/// Score decomp/source text against a checked-in function graph (no must_match).
pub fn score_function_graph(
    engine: &str,
    text: &str,
    gold: &SourceFunctionGraph,
) -> FunctionSfgScore {
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
            fact_verdicts: vec![],
            text_preview: None,
        };
    }

    let got = extract_graph_from_text(text);
    let mut residuals = Vec::new();
    let mut verdicts = Vec::new();
    let mut caps: Vec<f64> = Vec::new();

    let mut sem_h = 0usize;
    let mut sem_p = 0usize;
    let mut mem_h = 0usize;
    let mut mem_p = 0usize;
    let mut ctrl_h = 0usize;
    let mut ctrl_p = 0usize;
    let mut call_h = 0usize;
    let mut call_p = 0usize;

    for region in &gold.regions {
        ctrl_p += 1;
        let hit = region_hit(region, &got);
        if hit {
            ctrl_h += 1;
        } else {
            residuals.push(match region {
                RegionKind::Loop => ResidualClass::LoopRecurrenceWrong,
                RegionKind::Switch => ResidualClass::SwitchCaseMissing,
                _ => ResidualClass::ControlRegionWrong,
            });
        }
        verdicts.push(FactVerdict {
            fact_id: format!("region:{region:?}"),
            kind: FactKind::ControlRegion,
            dimension: FactDimension::Control,
            hit,
            critical: false,
            residual: if hit {
                None
            } else {
                Some(ResidualClass::ControlRegionWrong)
            },
            catastrophic_cap: None,
        });
    }

    for effect in &gold.effects {
        let hit = effect_hit(effect, &got);
        let (dim, kind, residual) = match effect {
            GraphEffect::Return { .. } => (
                FactDimension::Semantic,
                FactKind::Return,
                ResidualClass::SemanticReturnWrong,
            ),
            GraphEffect::Store { .. } => (
                FactDimension::Memory,
                FactKind::Store,
                ResidualClass::MissingStore,
            ),
            GraphEffect::Call { .. } => (
                FactDimension::Calls,
                FactKind::CallSite,
                ResidualClass::CallTargetWrong,
            ),
            GraphEffect::SwitchPartition { .. } => (
                FactDimension::Control,
                FactKind::Switch,
                ResidualClass::SwitchCaseMissing,
            ),
            GraphEffect::Loop { .. } => (
                FactDimension::Control,
                FactKind::Loop,
                ResidualClass::LoopRecurrenceWrong,
            ),
        };
        match dim {
            FactDimension::Semantic => {
                sem_p += 1;
                if hit {
                    sem_h += 1;
                }
            }
            FactDimension::Memory => {
                mem_p += 1;
                if hit {
                    mem_h += 1;
                }
            }
            FactDimension::Control => {
                ctrl_p += 1;
                if hit {
                    ctrl_h += 1;
                }
            }
            FactDimension::Calls => {
                call_p += 1;
                if hit {
                    call_h += 1;
                }
            }
            FactDimension::Clarity => {}
        }
        if !hit {
            residuals.push(residual.clone());
            if effect.critical() {
                caps.push(0.35);
            }
        }
        verdicts.push(FactVerdict {
            fact_id: effect.id_tag(),
            kind,
            dimension: dim,
            hit,
            critical: effect.critical(),
            residual: if hit { None } else { Some(residual) },
            catastrophic_cap: if !hit && effect.critical() {
                Some(0.35)
            } else {
                None
            },
        });
    }

    // Clarity: no residual goto.
    let clarity_hit = !text.contains("goto ") && !text.contains("goto\t");
    let clarity = if clarity_hit {
        dim_score(1, 1)
    } else {
        residuals.push(ResidualClass::GotoResidual);
        dim_score(0, 1)
    };

    let semantic = dim_score(sem_h, sem_p);
    let memory = dim_score(mem_h, mem_p);
    let control = dim_score(ctrl_h, ctrl_p);
    let calls = dim_score(call_h, call_p);
    let control_score = control.score;

    // Composite: only weight dimensions that apply (possible > 0).
    let mut w_sum = 0.0f64;
    let mut acc = 0.0f64;
    let dims = [
        (0.35, semantic.possible, semantic.score),
        (0.15, memory.possible, memory.score),
        (0.25, control.possible, control.score),
        (0.15, calls.possible, calls.score),
        (0.10, 1usize, clarity.score),
    ];
    for (w, poss, sc) in dims {
        if poss > 0 {
            acc += w * sc;
            w_sum += w;
        }
    }
    let mut composite = if w_sum > 0.0 { acc / w_sum } else { 0.0 };
    let mut capped = false;
    let mut cap_applied = None;
    if let Some(c) = caps.into_iter().reduce(f64::min)
        && composite > c
    {
        composite = c;
        capped = true;
        cap_applied = Some(c);
    }

    residuals.sort();
    residuals.dedup();

    FunctionSfgScore {
        function_id: gold.id.clone(),
        engine: engine.into(),
        empty: false,
        semantic,
        memory,
        control,
        calls,
        clarity,
        phi_local: 1.0,
        s_align: if control_score >= 0.99 { 0.95 } else { 0.70 },
        topology_penalty: 1.0,
        composite,
        capped,
        cap_applied,
        residuals,
        fact_verdicts: verdicts,
        text_preview: Some(text.chars().take(400).collect()),
    }
}

/// Write graph gold JSON for every `eval/grand/src/*.c` program that parses.
#[allow(dead_code)] // used by offline generator tests + tooling
pub fn generate_all_graph_gold(repo: &Path) -> anyhow::Result<usize> {
    let src_dir = repo.join("eval/grand/src");
    let out_dir = repo.join("eval/grand/graph_gold");
    fs::create_dir_all(&out_dir)?;
    let mut n = 0usize;
    let entries = fs::read_dir(&src_dir)?;
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }
        let program_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        // Skip multi-file bosses without flat .c if empty functions.
        let source = fs::read_to_string(&path)?;
        let mut graph = generate_graph_from_c_source(&program_id, &source);
        graph.source = format!("eval/grand/src/{program_id}.c");
        if graph.functions.is_empty() {
            continue;
        }
        let out = out_dir.join(format!("{program_id}.json"));
        fs::write(&out, serde_json::to_string_pretty(&graph)?)?;
        n += 1;
    }
    Ok(n)
}

/// Lookup helper for strict scoring.
pub fn find_function_graph<'a>(
    prog: &'a SourceProgramGraph,
    function_id: &str,
) -> Option<&'a SourceFunctionGraph> {
    prog.functions
        .iter()
        .find(|f| f.id == function_id || f.source_name.as_deref() == Some(function_id))
}

#[cfg(test)]
mod tests {
    use super::super::evaluator::ReturnClass;
    use super::*;

    #[test]
    fn branchless_return_satisfies_compare_effect() {
        let gold = SourceFunctionGraph {
            id: "signed_lt".into(),
            source_name: Some("signed_lt".into()),
            regions: vec![RegionKind::ExprReturn, RegionKind::If],
            effects: vec![GraphEffect::Return {
                class: Some(ReturnClass::Compare),
                ops: vec!["<".into()],
                critical: true,
            }],
        };
        let branchless = score_function_graph(
            "test",
            "int signed_lt(int a, int b) { return a < b; }",
            &gold,
        );
        assert!(!branchless.empty);
        assert!(
            branchless.composite > 0.8,
            "composite={}",
            branchless.composite
        );
        assert!(
            branchless.fact_verdicts.iter().all(|v| v.hit),
            "{:?}",
            branchless.fact_verdicts
        );

        let with_if = score_function_graph(
            "test",
            "int signed_lt(int a, int b) { if (a < b) return 1; return 0; }",
            &gold,
        );
        assert!(
            with_if.composite > 0.5,
            "if form composite={} verdicts={:?}",
            with_if.composite,
            with_if.fact_verdicts
        );

        let wrong = score_function_graph(
            "test",
            "int signed_lt(int a, int b) { return a + b; }",
            &gold,
        );
        assert!(
            wrong.fact_verdicts.iter().any(|v| !v.hit && v.critical),
            "wrong return must miss critical: {:?}",
            wrong.fact_verdicts
        );
    }

    #[test]
    fn graph_scoring_does_not_use_must_match() {
        // Mechanical: active scorer path never looks at SfgFact::must_match fields.
        let src = include_str!("graph_gold.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| !l.contains("must_match")) // allow this denylist test itself
            .collect::<Vec<_>>()
            .join("\n");
        // score_function_graph body must not reference must_match.
        let start = code
            .find("pub fn score_function_graph")
            .expect("score_function_graph");
        let body = &code[start..];
        let end = body
            .find("pub fn generate_all_graph_gold")
            .unwrap_or(body.len());
        let scorer = &body[..end];
        assert!(
            !scorer.contains("must_match"),
            "graph scorer must not use must_match"
        );
        assert!(scorer.contains("extract_graph_from_text"));
    }

    #[test]
    fn generate_and_score_a01_from_source() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src = fs::read_to_string(root.join("eval/grand/src/a01_signed_rel.c")).unwrap();
        let prog = generate_graph_from_c_source("a01_signed_rel", &src);
        assert!(
            prog.functions.iter().any(|f| f.id == "signed_lt"),
            "fns={:?}",
            prog.functions.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        let gold = find_function_graph(&prog, "signed_lt").unwrap();
        let sc = score_function_graph(
            "windy",
            "uint64 signed_lt(u64 a, u64 b) { return a < b; }",
            gold,
        );
        assert!(sc.composite > 0.8, "sc={sc:?}");
    }

    #[test]
    fn offline_generate_writes_graph_gold_dir() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let n = generate_all_graph_gold(&root).expect("generate");
        assert!(n >= 3, "expected several graph gold files, got {n}");
        let a01 = root.join("eval/grand/graph_gold/a01_signed_rel.json");
        assert!(a01.exists(), "missing {}", a01.display());
        let g = load_program_graph_gold(&a01).expect("load a01");
        assert_eq!(g.program_id, "a01_signed_rel");
    }
}
