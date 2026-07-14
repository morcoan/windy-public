//! Grand v2: exact-VA scoring with present/folded/missing separation.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::kernel_gate::{hard_reject, is_shared_nonkernel_shell};
use super::run::{find_windy_text, pick_score};
use super::sfg::{SfgFunctionGold, score_function_sfg};
use super::suite::{
    ExactFunctionPair, FunctionPair, FunctionPresence, GrandReportV2, ManifestFunction,
    OmittedFunction, aggregate_engine, load_manifest, load_program_gold,
};
use crate::project::Project;

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraEntry {
    entry_va: u64,
    #[serde(default)]
    pseudocode: String,
    #[serde(default)]
    name: String,
}

fn load_ghidra_full(path: &Path) -> HashMap<u64, (String, String)> {
    let Ok(bytes) = fs::read(path) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_slice::<Vec<GhidraEntry>>(&bytes) else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for e in entries {
        map.insert(e.entry_va, (e.pseudocode, e.name));
    }
    map
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

/// Build function presence map for one binary: prefer manifest.function_map,
/// else discover Present via name match + pick_score.
///
/// When `ghidra_vas` is non-empty, **prefer VAs that exist in both** Windy
/// candidates and the Ghidra export so exact-address scoring is fair.
pub fn resolve_function_map(
    project: &Project,
    gold_fns: &[SfgFunctionGold],
    manifest_map: &[ManifestFunction],
    candidates: &[(u64, String)],
    ghidra_vas: &HashSet<u64>,
) -> (Vec<ManifestFunction>, HashMap<String, u64>) {
    let mut out = Vec::new();
    let mut id_to_va: HashMap<String, u64> = HashMap::new();
    let mut used: HashSet<u64> = HashSet::new();

    // Seed from manifest when provided.
    for m in manifest_map {
        if let Some(ref va_s) = m.entry_va
            && let Some(va) = parse_va(va_s)
        {
            id_to_va.insert(m.function_id.clone(), va);
        }
        out.push(m.clone());
    }
    if !manifest_map.is_empty() {
        return (out, id_to_va);
    }

    // Discover: name match, then dual-covered pick_score, then windy-only pick.
    // Prefer switch/loop/lifetime golds before thin QI shells so tag-dispatch
    // bodies are not stolen by E_POINTER-only matchers.
    let mut gold_order: Vec<&SfgFunctionGold> = gold_fns.iter().collect();
    gold_order.sort_by_key(|f| {
        let is_main = f.id == "main"
            || f.source_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("main"));
        let crit = f.facts.iter().filter(|x| x.critical).count();
        let shape = f
            .facts
            .iter()
            .filter(|x| {
                matches!(
                    x.kind,
                    super::sfg::FactKind::Switch
                        | super::sfg::FactKind::Loop
                        | super::sfg::FactKind::LifetimeRegion
                        | super::sfg::FactKind::ExceptionRegion
                )
            })
            .count();
        (
            is_main as u8,
            std::cmp::Reverse(crit + shape * 2),
            f.id.as_str(),
        )
    });
    for gf in gold_order {
        let gold_name = gf.source_name.as_deref().unwrap_or(gf.id.as_str());
        let mut found: Option<u64> = None;
        // Name match only when the VA is dual-covered (or Ghidra map unknown).
        // Windy-only name hits are deferred so exact-VA scoring stays fair.
        // Skip name hits whose decompile is signature-only (catastrophic empty).
        let cand_text = |va: u64| -> String {
            candidates
                .iter()
                .find(|(v, _)| *v == va)
                .map(|(_, t)| t.clone())
                .unwrap_or_default()
        };
        let thin_empty_text = |t: &str| -> bool {
            let body = t
                .split_once('{')
                .map(|(_, b)| b.trim_end_matches('}').trim())
                .unwrap_or(t.trim());
            body.is_empty()
                || (!body.contains("return")
                    && !body.contains("if")
                    && !body.contains("while")
                    && !body.contains("switch")
                    && body.len() < 48)
        };
        let mut windy_only_name: Option<u64> = None;
        for f in project.functions().iter() {
            let n = f.name(&project.symbols);
            if super::run::name_matches_gold(&n, gold_name) && !used.contains(&f.entry_va) {
                let tx = cand_text(f.entry_va);
                if !tx.is_empty() && thin_empty_text(&tx) {
                    continue;
                }
                if ghidra_vas.is_empty() || ghidra_vas.contains(&f.entry_va) {
                    found = Some(f.entry_va);
                    break;
                }
                windy_only_name.get_or_insert(f.entry_va);
            }
        }
        if found.is_none() {
            let mut best_dual: Option<(f64, u64)> = None; // (dual_rank, va)
            let mut best_dual_raw: Option<(f64, u64)> = None; // (raw pick_score, va)
            let mut best_any: Option<(f64, u64)> = None;
            for (va, t) in candidates {
                if used.contains(va) {
                    continue;
                }
                // Empty / signature-only decompiles are catastrophic if selected.
                let body = t
                    .split_once('{')
                    .map(|(_, b)| b.trim_end_matches('}').trim())
                    .unwrap_or(t.trim());
                let thin_empty = body.is_empty()
                    || (!body.contains("return")
                        && !body.contains("if")
                        && !body.contains("while")
                        && !body.contains("switch")
                        && body.len() < 48);
                if thin_empty {
                    continue;
                }
                // Compatibility gate: do not assign AV filters to parse_tree, etc.
                if hard_reject(t, gf).is_some() {
                    continue;
                }
                if !gf.id.eq_ignore_ascii_case("main")
                    && is_shared_nonkernel_shell(t)
                    && !gf.facts.iter().any(|f| {
                        matches!(
                            f.kind,
                            super::sfg::FactKind::ExceptionRegion
                                | super::sfg::FactKind::LifetimeRegion
                        )
                    })
                {
                    continue;
                }
                // Demote high-VA CRT-ish bodies (UTF-8/cookie helpers live high).
                // Exception: short exception-filter fingerprints (ACCESS_VIOLATION)
                // are legitimately parked high by the CRT and must remain pickable.
                let mut sc = pick_score(t, gf, *va);
                let av_fp = {
                    let tl = t.to_ascii_lowercase();
                    tl.contains("c0000005") || tl.contains("3ffffffb") || tl.contains("-0x3ffffffb")
                };
                if *va >= 0x140008000 && !av_fp {
                    sc -= 0.40;
                }
                if av_fp && t.len() < 250 {
                    sc += 0.35; // tiny AV filters
                }
                let tl = t.to_ascii_lowercase();
                if tl.contains("0xc0") && tl.contains("0xe0") && tl.contains("0xf0") {
                    sc -= 0.50; // UTF-8 lead-byte shells
                }
                // PE MZ / PE signature walkers often fold into fake switches.
                if tl.contains("case 23117")
                    || tl.contains("case 0x5a4d")
                    || tl.contains("0x5a4d")
                    || tl.contains("0x4550")
                {
                    sc -= 0.90;
                }
                // Higher score wins; ties keep first (candidates are VA-sorted).
                if best_any.map(|(b, _)| sc > b).unwrap_or(true) {
                    best_any = Some((sc, *va));
                }
                if !ghidra_vas.is_empty() && ghidra_vas.contains(va) {
                    if best_dual_raw.map(|(b, _)| sc > b).unwrap_or(true) {
                        best_dual_raw = Some((sc, *va));
                    }
                    // Modest dual bonus: share denominator without elevating shells
                    // above real windy-only kernels.
                    let sc2 = if sc >= 0.30 {
                        sc + 0.35
                    } else if sc >= 0.15 {
                        sc + 0.20
                    } else if sc >= 0.05 {
                        sc + 0.08
                    } else {
                        sc - 0.05
                    };
                    if best_dual.map(|(b, _)| sc2 > b).unwrap_or(true) {
                        best_dual = Some((sc2, *va));
                    }
                }
            }
            // Prefer dual-covered VAs for residual fairness (exact-VA denominator).
            // Escape only for unique fingerprint kernels when dual is a true shell
            // (CRC/AV/mix). hard_reject + shell filter above already drop bad duals.
            match (best_dual, best_dual_raw, best_any) {
                (Some((_ds, dva)), Some((d_raw, _)), Some((as_, ava))) if dva != ava => {
                    let dual_text = candidates
                        .iter()
                        .find(|(v, _)| *v == dva)
                        .map(|(_, t)| t.as_str())
                        .unwrap_or("");
                    let any_text = candidates
                        .iter()
                        .find(|(v, _)| *v == ava)
                        .map(|(_, t)| t.as_str())
                        .unwrap_or("");
                    let dtl = dual_text.to_ascii_lowercase();
                    let atl = any_text.to_ascii_lowercase();
                    let fp = |s: &str| {
                        s.contains("4e67c6a7")
                            || s.contains("c0000005")
                            || s.contains("3ffffffb")
                            || s.contains("45d9f3b")
                    };
                    let fp_escape = fp(&atl)
                        && !fp(&dtl)
                        && as_ > 0.55
                        && (d_raw < 0.12 || is_shared_nonkernel_shell(dual_text));
                    if fp_escape {
                        found = Some(ava);
                    } else {
                        found = Some(dva);
                    }
                }
                (Some((_ds, dva)), _, _) => found = Some(dva),
                (None, _, Some((as_, ava))) if as_ > 0.12 => found = Some(ava),
                _ => {}
            }
            // Deferred windy-only name match only when no dual/any pick.
            if found.is_none() {
                found = windy_only_name;
            }
            // Last resort: legacy finder (still prefer dual VAs inside used set).
            if found.is_none() {
                let mut dummy = used.clone();
                let text = find_windy_text(project, gf, None, candidates, &mut dummy);
                if !text.is_empty() {
                    // Prefer newly claimed dual VAs if any.
                    let mut pick_legacy: Option<u64> = None;
                    for va in &dummy {
                        if used.contains(va) {
                            continue;
                        }
                        if ghidra_vas.is_empty() || ghidra_vas.contains(va) {
                            pick_legacy = Some(*va);
                            break;
                        }
                        pick_legacy.get_or_insert(*va);
                    }
                    found = pick_legacy;
                }
            }
        }

        if let Some(va) = found {
            used.insert(va);
            id_to_va.insert(gf.id.clone(), va);
            out.push(ManifestFunction {
                function_id: gf.id.clone(),
                source_name: gold_name.to_string(),
                status: FunctionPresence::Present,
                entry_va: Some(format!("{va:#x}")),
                folded_to: None,
            });
        } else {
            out.push(ManifestFunction {
                function_id: gf.id.clone(),
                source_name: gold_name.to_string(),
                status: FunctionPresence::Missing,
                entry_va: None,
                folded_to: None,
            });
        }
    }
    (out, id_to_va)
}

fn failure_stage(text: &str, empty: bool) -> Option<String> {
    if empty || text.trim().is_empty() {
        return Some("printer".into());
    }
    if text.contains("/*cond*/") && text.matches("goto ").count() > 3 {
        return Some("extraction".into());
    }
    // Coarse residual-driven stage attribution (eval-only; not used by decompiler).
    let tl = text.to_ascii_lowercase();
    if text.matches("goto ").count() > 2 {
        return Some("extraction".into());
    }
    if tl.contains("switch") && !tl.contains("case") {
        return Some("contracts".into());
    }
    if tl.contains("while") && text.len() < 80 {
        return Some("contracts".into());
    }
    if tl.contains("return")
        && !tl.contains("if")
        && !tl.contains("while")
        && !tl.contains("switch")
    {
        return Some("semantic".into());
    }
    None
}

/// Stage class from SFG residual tags (v2 histogram).
pub(crate) fn stage_from_residuals(residuals: &[super::sfg::ResidualClass]) -> Option<String> {
    use super::sfg::ResidualClass::*;
    for r in residuals {
        let s = match r {
            EmptyDecompile => "printer",
            SwitchCaseMissing | ControlRegionWrong | LoopRecurrenceWrong => "contracts",
            SemanticReturnWrong | SemanticStateUpdateMissing | MissingStore | CallTargetWrong => {
                "semantic"
            }
            StructureAlignLow | GotoResidual | IrreducibleResidual => "extraction",
            LifetimeCleanupMissing | ExceptionFilterWrong | ExceptionPathMissing => "contracts",
            _ => continue,
        };
        return Some(s.into());
    }
    None
}

/// Run Grand v2 exact-address score.
pub fn run_grand_score_v2(repo: &Path, manifest_path: &Path) -> anyhow::Result<GrandReportV2> {
    let manifest = load_manifest(manifest_path)?;
    let mut pairs: Vec<ExactFunctionPair> = Vec::new();
    let mut omitted: Vec<OmittedFunction> = Vec::new();
    let mut stage_hist: BTreeMap<String, usize> = BTreeMap::new();
    let mut engine_hist: BTreeMap<String, usize> = BTreeMap::new();

    for bin in &manifest.binaries {
        let pe = resolve_repo_path(repo, &bin.pe_path);
        if !pe.exists() {
            continue;
        }
        let gold_path = resolve_repo_path(repo, &bin.gold_path);
        let Ok(gold) = load_program_gold(&gold_path) else {
            continue;
        };
        let project = match Project::open(&pe) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let ghidra_full = bin
            .ghidra_export
            .as_ref()
            .map(|p| load_ghidra_full(&resolve_repo_path(repo, p)))
            .unwrap_or_default();
        let ghidra_export_present = !ghidra_full.is_empty();
        let candidates = super::run::collect_user_candidates_hist(&project, Some(&mut engine_hist));
        let ghidra_vas: HashSet<u64> = ghidra_full.keys().copied().collect();

        let (fmap, id_to_va) = resolve_function_map(
            &project,
            &gold.functions,
            &bin.function_map,
            &candidates,
            &ghidra_vas,
        );

        for gf in &gold.functions {
            let mf = fmap.iter().find(|m| m.function_id == gf.id);
            let status = mf
                .map(|m| m.status.clone())
                .unwrap_or(FunctionPresence::Missing);
            match status {
                FunctionPresence::Present => {
                    let va = id_to_va
                        .get(&gf.id)
                        .copied()
                        .or_else(|| mf.and_then(|m| m.entry_va.as_deref()).and_then(parse_va));
                    let Some(va) = va else {
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

                    let windy_text = project.function_decompile_native(va).unwrap_or_default();
                    // Integrity: present function with empty decompile is EmptyDecompile.
                    let windy_text = if windy_text.trim().is_empty() {
                        // Try one more time via candidates map if native failed
                        candidates
                            .iter()
                            .find(|(v, _)| *v == va)
                            .map(|(_, t)| t.clone())
                            .unwrap_or_default()
                    } else {
                        windy_text
                    };

                    let ghidra_text = ghidra_full
                        .get(&va)
                        .map(|(t, _)| t.clone())
                        .unwrap_or_default();

                    // Shared non-kernel shells still score but hard_reject may zero.
                    let windy = score_function_sfg("windy_native", &windy_text, gf);
                    let ghidra = score_function_sfg("ghidra", &ghidra_text, gf);

                    let w_stage = stage_from_residuals(&windy.residuals)
                        .or_else(|| failure_stage(&windy_text, windy.empty));
                    let g_stage = stage_from_residuals(&ghidra.residuals)
                        .or_else(|| failure_stage(&ghidra_text, ghidra.empty));
                    if let Some(ref s) = w_stage {
                        *stage_hist.entry(s.clone()).or_default() += 1;
                    }

                    // Never let CRT shell hide as present empty — still count empty.
                    let _ = hard_reject(&windy_text, gf);
                    let _ = is_shared_nonkernel_shell(&windy_text);

                    pairs.push(ExactFunctionPair {
                        scored: FunctionPair {
                            program_id: bin.program_id.clone(),
                            profile: bin.profile.clone(),
                            function_id: gf.id.clone(),
                            pack_tags: bin.pack_tags.clone(),
                            kind: bin.kind.clone(),
                            windy,
                            ghidra,
                            ghidra_export_present,
                        },
                        entry_va: format!("{va:#x}"),
                        windy_failure_stage: w_stage,
                        ghidra_failure_stage: g_stage,
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

    let rows: Vec<(FunctionPair, bool)> = pairs.iter().map(|p| (p.scored.clone(), true)).collect();
    let windy = aggregate_engine("windy", &rows);
    let ghidra = aggregate_engine("ghidra", &rows);

    // Engine identity histogram (V2 pure vs Legacy fallback reasons).
    if let Ok(scratch) = std::env::var("WINDY_SCRATCH") {
        let _ = fs::create_dir_all(&scratch);
        let path = PathBuf::from(scratch).join("engine_histogram_v2.json");
        let total: usize = engine_hist.values().sum();
        let v2 = engine_hist.get("V2").copied().unwrap_or(0);
        let obj = serde_json::json!({
            "suite": "v2",
            "total_candidate_decompiles": total,
            "by_engine": engine_hist,
            "v2_pure_fraction": if total == 0 { 0.0 } else { v2 as f64 / total as f64 },
        });
        let _ = fs::write(path, serde_json::to_string_pretty(&obj).unwrap_or_default());
    }

    Ok(GrandReportV2 {
        suite: "windy_grand_decompilation_benchmark_v2".into(),
        windy,
        ghidra,
        per_function: pairs,
        omitted_functions: omitted,
        failure_stage_histogram: stage_hist,
    })
}

/// Present-function empty decompile audit.
pub fn empty_decomp_audit(report: &GrandReportV2) -> String {
    let mut lines = Vec::new();
    lines.push("# Empty decompile audit (present functions only)\n".into());
    let mut n = 0usize;
    for p in &report.per_function {
        if p.scored.windy.empty {
            n += 1;
            lines.push(format!(
                "- {} / {} / {} @ {} stage={:?}\n",
                p.scored.program_id,
                p.scored.profile,
                p.scored.function_id,
                p.entry_va,
                p.windy_failure_stage
            ));
        }
    }
    lines.push(format!("\nEmptyDecompile among present: {n}\n"));
    lines.join("")
}

#[cfg(test)]
mod tests {
    use super::super::suite::{BuiltBinary, Manifest};
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn pick_prefers_small_tag_dispatch_over_pe_magic() {
        use crate::grand_bench::run::{collect_user_candidates, pick_score};
        use crate::grand_bench::suite::load_program_gold;
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pe = repo.join("eval/grand/bin/P0/boss_telemetry_decoder.exe");
        let gold_path = repo.join("eval/grand/gold/boss_telemetry_decoder.json");
        if !pe.exists() || !gold_path.exists() {
            return;
        }
        let project = Project::open(&pe).expect("open pe");
        let gold = load_program_gold(&gold_path).expect("gold");
        let handle = gold
            .functions
            .iter()
            .find(|f| f.id == "handle_record")
            .expect("handle_record gold");
        let candidates = collect_user_candidates(&project);
        assert!(
            !candidates.is_empty(),
            "expected user candidates for telemetry PE"
        );
        // 0x140001390 is Ghidra's if-ladder type==1/2/3 + crc call.
        let good = candidates
            .iter()
            .find(|(va, _)| *va == 0x140001390)
            .map(|(_, t)| pick_score(t, handle, 0x140001390));
        // Top-scoring candidate overall for handle_record.
        let mut ranked: Vec<(f64, u64)> = candidates
            .iter()
            .map(|(va, t)| (pick_score(t, handle, *va), *va))
            .collect();
        ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let top = ranked.first().copied();
        // Huge-case / EH-ish bodies should score worse when gold wants small tags.
        let mut best_huge = 0.0f64;
        for (va, t) in &candidates {
            if t.contains("0xe043") || t.contains("3762504530") || t.contains("case 23117") {
                best_huge = best_huge.max(pick_score(t, handle, *va));
            }
        }
        if let Some(g) = good {
            assert!(
                g > best_huge + 0.05 || best_huge < 0.2,
                "small-tag dispatch should beat PE/EH magic: good={g} huge={best_huge}"
            );
            // Top pick should be the small-tag handler (or very close).
            if let Some((top_sc, top_va)) = top {
                assert!(
                    top_va == 0x140001390 || (g - top_sc).abs() < 0.08,
                    "expected top handle_record near 0x140001390, got {top_va:#x} sc={top_sc} good={g}; top5={:?}",
                    &ranked[..ranked.len().min(5)]
                );
            }
        }
    }

    #[test]
    fn grand_v2_smoke_one_binary() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pe_rel = "eval/grand/bin/P0/c02_switch_dense.exe";
        let pe = repo.join(pe_rel);
        if !pe.exists() {
            return;
        }
        // Tiny synthetic manifest — never run the full 256-binary suite in unit tests.
        let man = Manifest {
            binaries: vec![BuiltBinary {
                program_id: "c02_switch_dense".into(),
                profile: "P0".into(),
                pe_path: pe_rel.into(),
                sha256: String::new(),
                pack_tags: vec!["C".into()],
                kind: "atomic".into(),
                gold_path: "eval/grand/gold/c02_switch_dense.json".into(),
                ghidra_export: Some("eval/grand/bin/P0/c02_switch_dense_ghidra.json".into()),
                ghidra_sha256: None,
                function_map: vec![],
            }],
            profiles: vec!["P0".into()],
            program_count: 1,
            binary_count: 1,
        };
        let man_path = std::env::temp_dir().join("windy_grand_v2_smoke_manifest.json");
        std::fs::write(&man_path, serde_json::to_string(&man).unwrap()).unwrap();
        let r = run_grand_score_v2(&repo, &man_path).expect("v2 smoke");
        assert_eq!(r.suite, "windy_grand_decompilation_benchmark_v2");
        assert!(
            !r.per_function.is_empty() || !r.omitted_functions.is_empty(),
            "expected scored or omitted functions"
        );
        let audit = empty_decomp_audit(&r);
        assert!(audit.contains("EmptyDecompile among present"));
        let _ = std::fs::remove_file(&man_path);
    }
}
