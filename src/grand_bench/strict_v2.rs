//! Strict Grand v2: exact-VA, no gold-aware picking, four lanes, engine share over presents.
//!
//! Forbidden on this path: gold-aware candidate ranking, shell hard-reject VA
//! selection, and text-search VA recovery helpers (see unit audit).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use super::graph_gold::{
    SourceProgramGraph, find_function_graph, graph_gold_path, load_program_graph_gold,
    score_function_graph,
};
use super::sfg::{SfgFunctionGold, score_function_sfg};
use super::suite::{
    ExactFunctionPair, FunctionPair, FunctionPresence, GrandReportV2, ManifestFunction,
    OmittedFunction, aggregate_engine, load_manifest, load_program_gold, verify_file_sha256,
};
use crate::decompiler::v2::{DecompileEngine, DecompileOptions};
use crate::project::Project;
use anyhow::Context;

/// Score Windy/Ghidra text: prefer offline source graph gold when present
/// (symmetric evaluator frontend). Fall back to lexical SFG only when no graph.
pub(crate) fn score_lane(
    engine: &str,
    text: &str,
    gf: &SfgFunctionGold,
    graph_prog: Option<&SourceProgramGraph>,
) -> super::sfg::FunctionSfgScore {
    if let Some(prog) = graph_prog {
        let fg = find_function_graph(prog, &gf.id).or_else(|| {
            gf.source_name
                .as_deref()
                .and_then(|n| find_function_graph(prog, n))
        });
        if let Some(fg) = fg {
            return score_function_graph(engine, text, fg);
        }
    }
    score_function_sfg(engine, text, gf)
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraEntry {
    entry_va: u64,
    #[serde(default)]
    pseudocode: String,
    #[serde(default)]
    name: String,
}

fn load_ghidra_full(path: &Path) -> anyhow::Result<HashMap<u64, (String, String)>> {
    let bytes = fs::read(path).with_context(|| format!("read Ghidra export {}", path.display()))?;
    let entries = serde_json::from_slice::<Vec<GhidraEntry>>(&bytes)
        .with_context(|| format!("parse Ghidra export {}", path.display()))?;
    let mut map = HashMap::new();
    for e in entries {
        map.insert(e.entry_va, (e.pseudocode, e.name));
    }
    anyhow::ensure!(!map.is_empty(), "empty Ghidra export {}", path.display());
    Ok(map)
}

fn resolve_repo_path(repo: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() { pb } else { repo.join(p) }
}

fn parse_va(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod graph_scoring_integration {
    use super::score_lane;
    use crate::decompiler::v2::{DecompileEngine, DecompileOptions};
    use crate::grand_bench::graph_gold::{
        find_function_graph, generate_graph_from_c_source, load_program_graph_gold,
    };
    use crate::grand_bench::sfg::SfgFunctionGold;
    use crate::project::Project;
    use std::path::PathBuf;

    #[test]
    fn strict_score_lane_uses_graph_gold_not_must_match() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src = std::fs::read_to_string(root.join("eval/grand/src/a01_signed_rel.c")).unwrap();
        let prog = generate_graph_from_c_source("a01_signed_rel", &src);
        // Lexical gold still has must_match "if" historically — graph path must
        // still credit branchless return.
        let gf = SfgFunctionGold {
            id: "signed_lt".into(),
            entry_va: None,
            source_name: Some("signed_lt".into()),
            facts: vec![], // empty lexical facts — graph is authority
        };
        let text = "uint64 signed_lt(u64 a, u64 b) { return a < b; }";
        let sc = score_lane("windy_pure_v2", text, &gf, Some(&prog));
        assert!(!sc.empty);
        assert!(
            sc.composite > 0.8,
            "graph lane must score branchless high: {sc:?}"
        );
        // Ensure graph function was found
        assert!(find_function_graph(&prog, "signed_lt").is_some());
        // Checked-in file path exists after offline generate test
        let path = root.join("eval/grand/graph_gold/a01_signed_rel.json");
        if path.exists() {
            let loaded = load_program_graph_gold(&path).expect("load");
            let sc2 = score_lane("windy_pure_v2", text, &gf, Some(&loaded));
            assert!(sc2.composite > 0.8, "{sc2:?}");
        }
    }

    #[test]
    fn linker_entry_hint_recovers_optimized_leaf_for_pure_v2() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pe = root.join("eval/grand/bin/P2/a05_bitops.exe");
        assert!(pe.is_file(), "authored scorecard fixture is missing");
        let state =
            std::env::temp_dir().join(format!("windy-linker-hint-test-{}", uuid::Uuid::new_v4()));

        let project = Project::open_with_data_dir_and_entry_hints(&pe, &state, &[0x1400_01000])
            .expect("open scorecard fixture with exact linker boundary");
        assert!(
            project.function_at(0x1400_01000).is_some(),
            "trusted linker entry must become a function boundary"
        );
        let artifact = project
            .function_decompile_artifact(0x1400_01000, DecompileOptions::pure_no_fallback())
            .expect("hinted leaf must produce a decompile artifact");
        assert_eq!(artifact.engine, DecompileEngine::V2);
        assert!(artifact.fallback_reason.is_none());
        assert!(!artifact.text.trim().is_empty());

        drop(project);
        let _ = std::fs::remove_dir_all(state);
    }
}

/// Resolve function VAs without gold-aware picking.
///
/// Prefer manifest `function_map` entry_va. Else match gold `source_name`/`id` to
/// (1) PE function symbols, then (2) Ghidra export names at fixed VAs. Ambiguous
/// or missing → Missing. Never ranks decompile text against gold.
pub fn resolve_function_map_strict(
    project: &Project,
    gold_fns: &[SfgFunctionGold],
    manifest_map: &[ManifestFunction],
    ghidra_name_to_va: &HashMap<String, Vec<u64>>,
) -> (Vec<ManifestFunction>, HashMap<String, u64>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut out = Vec::new();
    let mut id_to_va: HashMap<String, u64> = HashMap::new();

    if !manifest_map.is_empty() {
        for m in manifest_map {
            if let Some(ref va_s) = m.entry_va
                && let Some(va) = parse_va(va_s)
            {
                id_to_va.insert(m.function_id.clone(), va);
            } else if matches!(m.status, FunctionPresence::Present) {
                warnings.push(format!(
                    "unresolved present identity: {} (no entry_va)",
                    m.function_id
                ));
            }
            out.push(m.clone());
        }
        return (out, id_to_va, warnings);
    }

    // PE function symbols (no decompile).
    let mut pe_name_to_vas: HashMap<String, Vec<u64>> = HashMap::new();
    for f in project.functions().iter() {
        let n = f.name(&project.symbols);
        pe_name_to_vas
            .entry(n.to_ascii_lowercase())
            .or_default()
            .push(f.entry_va);
    }

    for gf in gold_fns {
        let gold_name = gf
            .source_name
            .as_deref()
            .unwrap_or(gf.id.as_str())
            .to_ascii_lowercase();
        let mut vas = pe_name_to_vas.get(&gold_name).cloned().unwrap_or_default();
        if vas.is_empty() {
            vas = ghidra_name_to_va
                .get(&gold_name)
                .cloned()
                .unwrap_or_default();
        }
        // Also try gold id as name.
        if vas.is_empty() {
            let idn = gf.id.to_ascii_lowercase();
            vas = pe_name_to_vas
                .get(&idn)
                .cloned()
                .or_else(|| ghidra_name_to_va.get(&idn).cloned())
                .unwrap_or_default();
        }
        vas.sort_unstable();
        vas.dedup();
        // Prefer VA that exists in PE function table when multiple Ghidra hits.
        if vas.len() > 1 {
            let pe_vas: Vec<u64> = vas
                .iter()
                .copied()
                .filter(|va| project.function_at(*va).is_some())
                .collect();
            if pe_vas.len() == 1 {
                vas = pe_vas;
            }
        }
        if vas.len() == 1 && project.function_at(vas[0]).is_some() {
            let va = vas[0];
            id_to_va.insert(gf.id.clone(), va);
            out.push(ManifestFunction {
                function_id: gf.id.clone(),
                source_name: gf.source_name.clone().unwrap_or_else(|| gf.id.clone()),
                status: FunctionPresence::Present,
                entry_va: Some(format!("{va:#x}")),
                folded_to: None,
            });
        } else if vas.is_empty() {
            warnings.push(format!("missing identity for gold {}", gf.id));
            out.push(ManifestFunction {
                function_id: gf.id.clone(),
                source_name: gf.source_name.clone().unwrap_or_else(|| gf.id.clone()),
                status: FunctionPresence::Missing,
                entry_va: None,
                folded_to: None,
            });
        } else {
            warnings.push(format!(
                "ambiguous identity for gold {} ({} VAs)",
                gf.id,
                vas.len()
            ));
            out.push(ManifestFunction {
                function_id: gf.id.clone(),
                source_name: gf.source_name.clone().unwrap_or_else(|| gf.id.clone()),
                status: FunctionPresence::Missing,
                entry_va: None,
                folded_to: None,
            });
        }
    }

    (out, id_to_va, warnings)
}

/// Decompile lanes for four-lane reporting.
#[derive(Clone, Copy, Debug)]
pub enum ScoreLane {
    /// Frozen Legacy only.
    Legacy,
    /// Pure V2, no fallback.
    PureV2,
    /// Product mode (V2 with structured fallback allowed).
    Product,
}

fn decompile_lane(project: &Project, va: u64, lane: ScoreLane) -> (String, String, Option<String>) {
    let opts = match lane {
        ScoreLane::Legacy => DecompileOptions::legacy_only(),
        ScoreLane::PureV2 => DecompileOptions::pure_no_fallback(),
        ScoreLane::Product => DecompileOptions::production(),
    };
    match project.function_decompile_artifact(va, opts) {
        Some(art) => {
            let eng = match art.engine {
                DecompileEngine::V2 => "V2",
                DecompileEngine::Legacy => "Legacy",
            };
            let key = match &art.fallback_reason {
                Some(r) => format!("{eng}:{r}"),
                None => eng.to_string(),
            };
            (art.text, key, art.fallback_reason)
        }
        None => (String::new(), "missing".into(), Some("no_artifact".into())),
    }
}

/// Four-lane exact-address report.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FourLaneReport {
    pub suite: String,
    pub pure_v2: super::suite::EngineAggregate,
    pub product: super::suite::EngineAggregate,
    pub legacy: super::suite::EngineAggregate,
    pub ghidra: super::suite::EngineAggregate,
    pub engine_share_present: BTreeMap<String, usize>,
    pub pure_v2_share: f64,
    pub pure_fallback_count: usize,
    pub functions_scored: usize,
    pub identity_warnings: Vec<String>,
    pub omitted_functions: Vec<OmittedFunction>,
}

/// Run strict pure no-fallback Grand v2 (primary victory lane).
pub fn run_grand_score_v2_strict(
    repo: &Path,
    manifest_path: &Path,
) -> anyhow::Result<(GrandReportV2, FourLaneReport)> {
    let manifest = load_manifest(manifest_path)?;
    let mut pairs_pure: Vec<ExactFunctionPair> = Vec::new();
    let mut pairs_product: Vec<FunctionPair> = Vec::new();
    let mut pairs_legacy: Vec<FunctionPair> = Vec::new();
    let mut omitted: Vec<OmittedFunction> = Vec::new();
    let mut stage_hist: BTreeMap<String, usize> = BTreeMap::new();
    let mut engine_share: BTreeMap<String, usize> = BTreeMap::new();
    let mut pure_fallback = 0usize;
    let mut all_warnings = Vec::new();
    // Keep scorecard reads isolated from the operator's real Windy state.
    // This directory is under ignored build output and the scorecard performs
    // no mutations, so reruns are deterministic without touching ~/.windy.
    let benchmark_data_dir = repo.join("target").join("grand-score-state");

    for bin in &manifest.binaries {
        let pe = resolve_repo_path(repo, &bin.pe_path);
        verify_file_sha256(&pe, &bin.sha256, "Grand PE")?;
        let gold_path = resolve_repo_path(repo, &bin.gold_path);
        let gold = load_program_gold(&gold_path)
            .with_context(|| format!("load source gold {}", gold_path.display()))?;
        // Offline source region/effect graphs (evaluator-only); preferred scorer.
        let graph_prog = load_program_graph_gold(&graph_gold_path(repo, &bin.program_id));
        // Linker-derived identities embedded in the manifest are authoritative.
        // An explicit WINDY_IDENTITY_DIR remains available for older manifests
        // and controlled experiments, but an ambient generated map must never
        // override release provenance.
        let frozen = if bin.function_map.is_empty() {
            std::env::var("WINDY_IDENTITY_DIR").ok().and_then(|base| {
                let path =
                    PathBuf::from(base).join(format!("{}_{}.json", bin.program_id, bin.profile));
                super::identity_bootstrap::load_identity_map(&path)
            })
        } else {
            None
        };
        let manifest_slice = frozen.as_deref().unwrap_or(&bin.function_map);
        let mut entry_hints = manifest_slice
            .iter()
            .filter(|function| matches!(&function.status, FunctionPresence::Present))
            .filter_map(|function| function.entry_va.as_deref().and_then(parse_va))
            .collect::<Vec<_>>();
        entry_hints.sort_unstable();
        entry_hints.dedup();

        // Ghidra receives the same linker boundaries during export. Seed Windy
        // with those exact VAs as well so this measures decompiler quality, not
        // asymmetric function-discovery luck.
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &benchmark_data_dir, &entry_hints)
                .with_context(|| format!("open Grand PE {}", pe.display()))?;
        let ghidra_full = if let Some(export) = &bin.ghidra_export {
            let path = resolve_repo_path(repo, export);
            if let Some(expected) = &bin.ghidra_sha256 {
                verify_file_sha256(&path, expected, "Ghidra export")?;
            }
            load_ghidra_full(&path)?
        } else {
            HashMap::new()
        };
        let ghidra_export_present = !ghidra_full.is_empty();
        let mut ghidra_name_to_va: HashMap<String, Vec<u64>> = HashMap::new();
        for (va, (_text, name)) in &ghidra_full {
            if name.is_empty() {
                continue;
            }
            ghidra_name_to_va
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(*va);
        }

        let (fmap, id_to_va, warns) = resolve_function_map_strict(
            &project,
            &gold.functions,
            manifest_slice,
            &ghidra_name_to_va,
        );
        all_warnings.extend(warns);

        for gf in &gold.functions {
            let mf = fmap.iter().find(|m| m.function_id == gf.id);
            let status = mf
                .map(|m| m.status.clone())
                .unwrap_or(FunctionPresence::Missing);
            match status {
                FunctionPresence::Present => {
                    let Some(va) = id_to_va
                        .get(&gf.id)
                        .copied()
                        .or_else(|| mf.and_then(|m| m.entry_va.as_deref()).and_then(parse_va))
                    else {
                        omitted.push(OmittedFunction {
                            program_id: bin.program_id.clone(),
                            profile: bin.profile.clone(),
                            function_id: gf.id.clone(),
                            source_name: gf.source_name.clone().unwrap_or_else(|| gf.id.clone()),
                            status: FunctionPresence::Missing,
                            folded_to: None,
                        });
                        continue;
                    };

                    let (pure_text, pure_eng, pure_fb) =
                        decompile_lane(&project, va, ScoreLane::PureV2);
                    let (prod_text, _prod_eng, _) =
                        decompile_lane(&project, va, ScoreLane::Product);
                    let (leg_text, _leg_eng, _) = decompile_lane(&project, va, ScoreLane::Legacy);

                    *engine_share.entry(pure_eng.clone()).or_default() += 1;
                    if pure_fb.is_some() {
                        pure_fallback += 1;
                    }

                    let ghidra_text = ghidra_full
                        .get(&va)
                        .map(|(t, _)| t.clone())
                        .unwrap_or_default();

                    let windy_pure =
                        score_lane("windy_pure_v2", &pure_text, gf, graph_prog.as_ref());
                    let windy_prod =
                        score_lane("windy_product", &prod_text, gf, graph_prog.as_ref());
                    let windy_leg = score_lane("windy_legacy", &leg_text, gf, graph_prog.as_ref());
                    let ghidra = score_lane("ghidra", &ghidra_text, gf, graph_prog.as_ref());

                    let w_stage: Option<String> = if windy_pure.empty {
                        Some("EmptyDecompile".into())
                    } else {
                        None
                    };
                    if let Some(ref s) = w_stage {
                        *stage_hist.entry(s.clone()).or_default() += 1;
                    }

                    pairs_pure.push(ExactFunctionPair {
                        scored: FunctionPair {
                            program_id: bin.program_id.clone(),
                            profile: bin.profile.clone(),
                            function_id: gf.id.clone(),
                            pack_tags: bin.pack_tags.clone(),
                            kind: bin.kind.clone(),
                            windy: windy_pure,
                            ghidra: ghidra.clone(),
                            ghidra_export_present,
                        },
                        entry_va: format!("{va:#x}"),
                        windy_failure_stage: w_stage,
                        ghidra_failure_stage: if ghidra.empty {
                            Some("EmptyDecompile".into())
                        } else {
                            None
                        },
                    });
                    pairs_product.push(FunctionPair {
                        program_id: bin.program_id.clone(),
                        profile: bin.profile.clone(),
                        function_id: gf.id.clone(),
                        pack_tags: bin.pack_tags.clone(),
                        kind: bin.kind.clone(),
                        windy: windy_prod,
                        ghidra: ghidra.clone(),
                        ghidra_export_present,
                    });
                    pairs_legacy.push(FunctionPair {
                        program_id: bin.program_id.clone(),
                        profile: bin.profile.clone(),
                        function_id: gf.id.clone(),
                        pack_tags: bin.pack_tags.clone(),
                        kind: bin.kind.clone(),
                        windy: windy_leg,
                        ghidra,
                        ghidra_export_present,
                    });
                }
                FunctionPresence::Folded
                | FunctionPresence::InlinedOnly
                | FunctionPresence::Missing => {
                    omitted.push(OmittedFunction {
                        program_id: bin.program_id.clone(),
                        profile: bin.profile.clone(),
                        function_id: gf.id.clone(),
                        source_name: gf.source_name.clone().unwrap_or_else(|| gf.id.clone()),
                        status,
                        folded_to: mf.and_then(|m| m.folded_to.clone()),
                    });
                }
            }
        }
    }

    let rows_pure: Vec<(FunctionPair, bool)> = pairs_pure
        .iter()
        .map(|p| (p.scored.clone(), true))
        .collect();
    let rows_prod: Vec<(FunctionPair, bool)> =
        pairs_product.iter().map(|p| (p.clone(), true)).collect();
    let rows_leg: Vec<(FunctionPair, bool)> =
        pairs_legacy.iter().map(|p| (p.clone(), true)).collect();

    let pure_agg = aggregate_engine("windy_pure_v2", &rows_pure);
    let prod_agg = aggregate_engine("windy_product", &rows_prod);
    let leg_agg = aggregate_engine("windy_legacy", &rows_leg);
    let ghidra_agg = aggregate_engine("ghidra", &rows_pure);

    let scored = pairs_pure.len();
    let v2_only = engine_share.get("V2").copied().unwrap_or(0);
    let pure_share = if scored == 0 {
        0.0
    } else {
        v2_only as f64 / scored as f64
    };

    let four = FourLaneReport {
        suite: "windy_grand_strict_v2_four_lanes".into(),
        pure_v2: pure_agg.clone(),
        product: prod_agg,
        legacy: leg_agg,
        ghidra: ghidra_agg.clone(),
        engine_share_present: engine_share,
        pure_v2_share: pure_share,
        pure_fallback_count: pure_fallback,
        functions_scored: scored,
        identity_warnings: all_warnings,
        omitted_functions: omitted.clone(),
    };

    let report = GrandReportV2 {
        suite: "windy_grand_decompilation_benchmark_v2_strict".into(),
        windy: pure_agg,
        ghidra: ghidra_agg,
        per_function: pairs_pure,
        omitted_functions: omitted,
        failure_stage_histogram: stage_hist,
    };

    Ok((report, four))
}

/// Static audit: this module must not call gold-aware picker APIs.
#[cfg(test)]
mod tests {
    #[test]
    fn strict_v2_source_forbids_picker_apis() {
        let src = include_str!("strict_v2.rs");
        // Strip comments so the audit list itself is not a false positive.
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // Build forbidden identifiers without embedding them as contiguous literals
        // in this test body (self-check would otherwise match the asserts).
        let forbid = [
            ["pick", "_score("].concat(),
            ["hard", "_reject("].concat(),
            ["find_windy", "_text("].concat(),
            ["use super::", "run::"].concat(),
            ["use super::", "kernel_gate::"].concat(),
        ];
        for f in &forbid {
            assert!(!code.contains(f), "strict path must not reference {f}");
        }
    }
}
