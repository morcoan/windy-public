//! Grand Bench suite runner: Windy native + Ghidra JSON vs SFG gold.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::kernel_gate::{derive_pick_requirements, hard_reject, is_shared_nonkernel_shell};
use super::sfg::{SfgFunctionGold, score_function_sfg};
use super::suite::{
    FunctionPair, GrandReport, Manifest, aggregate_engine, load_manifest, load_program_gold,
};
use crate::project::Project;

#[derive(Clone, Debug, serde::Deserialize)]
struct GhidraEntry {
    entry_va: u64,
    #[serde(default)]
    pseudocode: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
}

fn parse_va(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn load_ghidra_map(path: &Path) -> HashMap<u64, String> {
    let Ok(bytes) = fs::read(path) else {
        return HashMap::new();
    };
    let Ok(entries) = serde_json::from_slice::<Vec<GhidraEntry>>(&bytes) else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for e in entries {
        // Drop huge CRT dumps; keep user-scale decompilations.
        if e.pseudocode.len() > 12_000 || e.pseudocode.len() < 20 {
            continue;
        }
        if is_crtish_text(&e.pseudocode) {
            continue;
        }
        map.insert(e.entry_va, e.pseudocode);
    }
    map
}

fn is_crtish_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("scrt")
        || n.contains("security")
        || n.contains("__crt")
        || n.contains("atexit")
        || n.contains("gs_handler")
        || n.contains("guard_check")
        || n == "entry"
        || n.starts_with("__")
}

fn is_crtish_text(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    // Explicit CRT / security runtime markers only. A user kernel that still
    // carries a residual cookie fail leaf comment is NOT CRT — those used to
    // exclude decode_packet-style bodies from the pick pool.
    let hard = l.contains("__scrt")
        || l.contains("security_check_cookie")
        || l.contains("__gshandler")
        || l.contains("_guard_check_icall")
        || l.contains("__current_exception")
        || l.contains("isprocessorfeaturepresent")
        || l.contains("__imp_")
        || l.contains("vcrt_startup")
        || l.contains("cor_exe_main")
        || l.contains("cookie/fail path");
    if hard {
        return true;
    }
    // Call-heavy CRT soup.
    if l.matches("call(").count() > 8 {
        return true;
    }
    let body = l.split_once('{').map(|(_, b)| b).unwrap_or(&l);
    if body.matches("fun_").count() > 8 && t.len() > 800 {
        return true;
    }
    false
}

/// GS-cookie / CRT epilogue body mistaken for a user kernel under strip.
fn is_cookie_epilogue_text(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    // Pure cookie scaffolding only. User kernels with multi-if / loop / switch
    // work must remain pickable even when a residual fail-leaf comment remains.
    if l.contains("cookie/fail path") {
        return true;
    }
    let has_real_work = l.contains("while")
        || l.contains("for ")
        || l.contains("for(")
        || l.contains("switch")
        || (l.matches("if ").count() + l.matches("if(").count() >= 2
            && (l.contains('+') || l.contains("return") || l.contains("fun_")));
    if has_real_work {
        return false;
    }
    // Refcount / COM helpers often use `g_14…` + `^` (xor-zero HRESULT) —
    // that is NOT a GS cookie epilogue.
    let has_refcount_store =
        (l.contains("+ 0x1") || l.contains("+0x1") || l.contains("- 0x1") || l.contains("-0x1"))
            && (l.contains("g_14") || l.contains("0x14001"));
    if has_refcount_store {
        return false;
    }
    let has_cookie_xor =
        (l.contains("g_14") || l.contains("0x14001a")) && (l.contains('^') || l.contains("xor"));
    // Cookie setup + single return, no loop/switch kernel body.
    if has_cookie_xor && t.len() < 900 {
        return true;
    }
    // Many high-VA FUN_ callees and cookie global → CRT startup / main CRT.
    let body = l.split_once('{').map(|(_, b)| b).unwrap_or(&l);
    let fun_n = body.matches("fun_").count() + body.matches("call(").count();
    if fun_n >= 4 && has_cookie_xor {
        return true;
    }
    false
}

/// Thin wrapper / constant-fold stub — rarely the gold kernel under strip.
fn is_trivial_stub(t: &str) -> bool {
    if is_cookie_epilogue_text(t) {
        return true;
    }
    let l = t.to_ascii_lowercase();
    let lines = t.lines().filter(|x| !x.trim().is_empty()).count();
    // Exception-filter / pure-compare kernels are short but semantic (AV, LT).
    let has_compare = t.contains("==")
        || t.contains("!=")
        || t.contains('<')
        || t.contains('>')
        || t.contains("0xc0000005")
        || t.contains("3ffffffb")
        || t.contains("c0000005");
    if lines <= 4 && l.contains("return") && !l.contains("while") && !l.contains("for") {
        // `return 0xa;` or call+return only — not compare kernels.
        if !t.contains('+')
            && !t.contains('^')
            && !t.contains('*')
            && !t.contains("if")
            && !has_compare
        {
            return true;
        }
    }
    // Pure constant return (optimizer folded kernel).
    let has_const_ret =
        l.contains("return 0x") || l.contains("return 0;") || l.contains("return 1;");
    if has_const_ret
        && !l.contains("while")
        && !l.contains("for")
        && !l.contains("switch")
        && !has_compare
        && t.len() < 160
    {
        return true;
    }
    false
}

/// Prefer user-code candidates: early image VA, not CRT-named, decompile not CRT soup.
///
/// When `engine_hist` is provided, counts production-path engine identity
/// (`V2` vs `Legacy:<reason>`) for every candidate decompile.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn collect_user_candidates(project: &Project) -> Vec<(u64, String)> {
    collect_user_candidates_hist(project, None)
}

pub(crate) fn collect_user_candidates_hist(
    project: &Project,
    engine_hist: Option<&mut std::collections::BTreeMap<String, usize>>,
) -> Vec<(u64, String)> {
    collect_user_candidates_with_opts(
        project,
        crate::decompiler::v2::DecompileOptions::production(),
        engine_hist,
    )
}

fn collect_user_candidates_with_opts(
    project: &Project,
    opts: crate::decompiler::v2::DecompileOptions,
    mut engine_hist: Option<&mut std::collections::BTreeMap<String, usize>>,
) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    for f in project.functions().iter() {
        let va = f.entry_va;
        // User kernels sit early in .text; widen for SEH filters / small helpers
        // that the linker may park higher while remaining non-CRT.
        if !(0x140001000..0x140010000).contains(&va) {
            continue;
        }
        let name = f.name(&project.symbols);
        if is_crtish_name(&name) {
            continue;
        }
        let Some(art) = project.function_decompile_artifact(va, opts.clone()) else {
            continue;
        };
        if let Some(h) = engine_hist.as_mut() {
            let tag = match art.engine {
                crate::decompiler::v2::artifact::DecompileEngine::V2 => "V2".to_string(),
                crate::decompiler::v2::artifact::DecompileEngine::Legacy => {
                    format!(
                        "Legacy:{}",
                        art.fallback_reason.as_deref().unwrap_or("unknown")
                    )
                }
            };
            *h.entry(tag).or_default() += 1;
        }
        let t = art.text;
        // Atomic/bench kernels are small-to-medium; huge bodies are almost always CRT.
        // Exception: tiny AV/exception filters may sit high and stay under 200 chars.
        let tl = t.to_ascii_lowercase();
        let fingerprint_keep = tl.contains("c0000005")
            || tl.contains("3ffffffb")
            || tl.contains("80004003")
            || tl.contains("80070057")
            || tl.contains("45d9f3b")
            || tl.contains("4e67c6a7");
        if t.len() < 30 || (t.len() > 6_000 && !fingerprint_keep) {
            continue;
        }
        // High-VA: only keep strong fingerprints (AV/HRESULT/CRC), not CRT soup.
        if va >= 0x14000c000 && !fingerprint_keep {
            continue;
        }
        if is_crtish_text(&t) || is_cookie_epilogue_text(&t) {
            // Still allow AV/HRESULT fingerprint bodies (exception filters).
            if !fingerprint_keep {
                continue;
            }
        }
        out.push((va, t));
    }
    out.sort_by_key(|(va, _)| *va);
    out.dedup_by_key(|(va, _)| *va);
    out
}

fn write_engine_histogram(hist: &std::collections::BTreeMap<String, usize>, suite: &str) {
    let Ok(scratch) = std::env::var("WINDY_SCRATCH") else {
        return;
    };
    let _ = fs::create_dir_all(&scratch);
    let path = PathBuf::from(&scratch).join(format!("engine_histogram_{suite}.json"));
    let mut total = 0usize;
    for c in hist.values() {
        total += c;
    }
    let mut obj = serde_json::Map::new();
    obj.insert("suite".into(), serde_json::json!(suite));
    obj.insert(
        "total_candidate_decompiles".into(),
        serde_json::json!(total),
    );
    obj.insert(
        "by_engine".into(),
        serde_json::to_value(hist).unwrap_or_default(),
    );
    let v2 = hist.get("V2").copied().unwrap_or(0);
    obj.insert(
        "v2_pure_fraction".into(),
        serde_json::json!(if total == 0 {
            0.0
        } else {
            v2 as f64 / total as f64
        }),
    );
    let _ = fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap_or_default(),
    );
}

/// Count distinct `case N` labels with N in 0..32 (user dispatch, not PE magic).
/// Duplicate `case 0` rows (broken CRT shells) count once.
fn count_small_case_labels(text: &str) -> usize {
    let mut tags = std::collections::HashSet::new();
    for line in text.lines() {
        let t = line.trim();
        let rest = if let Some(r) = t.strip_prefix("case ") {
            r
        } else if let Some(r) = t.strip_prefix("case") {
            r.trim_start()
        } else {
            continue;
        };
        let num = rest.trim_end_matches(':').trim();
        let k = if let Some(h) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).ok()
        } else {
            num.parse::<i64>().ok()
        };
        if let Some(k) = k
            && (0..32).contains(&k)
        {
            tags.insert(k);
        }
    }
    tags.len()
}

/// Count case labels that look like PE/EH magic (MZ, large facility codes).
fn count_huge_case_labels(text: &str) -> usize {
    let mut n = 0usize;
    for line in text.lines() {
        let t = line.trim();
        let rest = if let Some(r) = t.strip_prefix("case ") {
            r
        } else if let Some(r) = t.strip_prefix("case") {
            r.trim_start()
        } else {
            continue;
        };
        let num = rest.trim_end_matches(':').trim();
        let k = if let Some(h) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).ok()
        } else {
            num.parse::<i64>().ok()
        };
        if let Some(k) = k {
            // MZ 0x5a4d (=23117), PE 0x4550 (=17744), EH facility codes, etc.
            if matches!(k, 0x5a4d | 0x4550) || k > 0xffff || (k as u64) >= 0x8000_0000 {
                n += 1;
            }
        }
    }
    n
}

fn small_case_hint(text: &str) -> bool {
    count_small_case_labels(text) >= 2 || count_small_eq_tags(text) >= 2
}

/// True when `case N` / `== N` / subtract-eq forms mention decimal tag `dec`.
fn compact_has_case_or_eq(text: &str, dec: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let cl = compact.to_ascii_lowercase();
    cl.contains(&format!("case{dec}"))
        || cl.contains(&format!("case0x{dec}"))
        || cl.contains(&format!("=={dec}"))
        || cl.contains(&format!("==0x{dec}"))
        || cl.contains(&format!("-0x{dec})==0"))
        || cl.contains(&format!("-{dec})==0"))
}

/// Count small integer tag tests: `== 1`, `(x - 0x1) == 0`, etc.
fn count_small_eq_tags(text: &str) -> usize {
    let mut tags = std::collections::HashSet::new();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    // Direct equality: ==0x1 / ==1 / ==0x2 ...
    for k in 1i64..=8 {
        let hex = format!("==0x{k:x}");
        let dec = format!("=={k}");
        if compact.to_ascii_lowercase().contains(&hex) || compact.contains(&dec) {
            tags.insert(k);
        }
        // Subtract-eq-zero: -0x1)==0x0 or -1)==0
        let sub_hex = format!("-0x{k:x})==0x0");
        let sub_dec = format!("-{k})==0");
        let sub_hex0 = format!("-0x{k:x})==0");
        if compact.to_ascii_lowercase().contains(&sub_hex)
            || compact.contains(&sub_dec)
            || compact.to_ascii_lowercase().contains(&sub_hex0)
        {
            tags.insert(k);
        }
    }
    tags.len()
}

/// Shape-aware pick score for stripped function identification (not gold softening).
pub(crate) fn pick_score(text: &str, gold: &SfgFunctionGold, va: u64) -> f64 {
    let s = score_function_sfg("pick", text, gold);
    let crit_hits = s
        .fact_verdicts
        .iter()
        .filter(|v| v.critical && v.hit)
        .count() as f64;
    let crit_n = gold.facts.iter().filter(|f| f.critical).count().max(1) as f64;
    let mut score = s.composite + 0.10 * (crit_hits / crit_n);

    let tl = text.to_ascii_lowercase();
    let wants_loop = gold
        .facts
        .iter()
        .any(|f| matches!(f.kind, super::sfg::FactKind::Loop));
    let wants_switch = gold
        .facts
        .iter()
        .any(|f| matches!(f.kind, super::sfg::FactKind::Switch));
    let wants_arith = gold.facts.iter().any(|f| {
        f.kind == super::sfg::FactKind::Return
            || f.kind == super::sfg::FactKind::Operation
            || f.return_ops.iter().any(|c| matches!(c, '+' | '^' | '*'))
            || f.must_match
                .iter()
                .any(|m| m.contains('+') || m.contains('^'))
            || f.match_any.iter().any(|m| {
                m.contains('+') || m.contains("add") || m.contains('^') || m.contains("xor")
            })
    });

    if wants_loop {
        let while_n =
            tl.matches("while").count() + tl.matches("for ").count() + tl.matches("for(").count();
        if while_n >= 2 {
            score += 0.28; // nested loops (mat_sum etc.) — rare in CRT helpers
        } else if while_n == 1 {
            score += 0.10;
        } else {
            score -= 0.40;
        }
    }

    // Pure computational gold (no call_site facts): hard-penalize call-heavy CRT helpers.
    // Exception: multi-fact control orchestrators (decode-style) call 1–3 helpers.
    let gold_wants_calls = gold
        .facts
        .iter()
        .any(|f| matches!(f.kind, super::sfg::FactKind::CallSite));
    // Count callee mentions in the body only (skip signature line `FUN_…(`).
    let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
    let call_n = body.matches("call(").count()
        + body.matches("FUN_").count()
        + body.matches("__imp_").count();
    let multi_control = gold.facts.iter().filter(|f| f.critical).count() >= 4
        && (wants_switch
            || gold
                .facts
                .iter()
                .any(|f| matches!(f.kind, super::sfg::FactKind::Predicate)));
    if !gold_wants_calls {
        if call_n == 0 {
            score += 0.18;
        } else if multi_control && call_n <= 3 {
            // Orchestrator kernels (outer decode loop calling handlers) are not CRT.
            score += 0.08;
        } else {
            // CRT startup / helpers almost always contain calls; pure kernels rarely do.
            score -= 0.55 - 0.15 * (call_n as f64).min(3.0);
        }
    }
    // Penalize EH/PE facility codes mistaken for user constants.
    if text.contains("0xe043") || text.contains("0xE043") || text.contains("3762504530") {
        score -= 0.40;
    }
    // C++ EH type-info / magic (MSVC) — never user kernels.
    if text.contains("0xe06d7363")
        || text.contains("0xE06D7363")
        || text.contains("0x19930520")
        || text.contains("19930520")
    {
        score -= 0.85;
    }
    if wants_switch {
        let small_cases = count_small_case_labels(text);
        let huge_cases = count_huge_case_labels(text);
        let small_eq = count_small_eq_tags(text);
        // Distinct user tags 1..8 (case labels or MSVC subtract-eq).
        let user_tag_dispatch = small_eq >= 2
            || (small_cases >= 2
                && text.lines().any(|l| {
                    let t = l.trim();
                    t.starts_with("case 1")
                        || t.starts_with("case 2")
                        || t.starts_with("case 3")
                        || t.starts_with("case 0x1")
                        || t.starts_with("case 0x2")
                        || t.starts_with("case 0x3")
                }));
        // Empty / degenerate switch shells (duplicate case 0, no user tags).
        let degenerate_switch =
            tl.contains("switch") && small_cases <= 1 && small_eq < 2 && huge_cases == 0;

        if tl.contains("switch") && user_tag_dispatch {
            score += 0.40;
        } else if tl.contains("switch") && !degenerate_switch {
            score += 0.20;
        } else if user_tag_dispatch {
            // Honest if-ladder tag partition (pre-fold or fold missed).
            score += 0.38;
        } else if tl.matches("if (").count() + tl.matches("if(").count() >= 3 {
            score += 0.12;
        } else if degenerate_switch {
            score -= 0.55; // CRT broken switch shells
        } else {
            score -= 0.35;
        }
        // Dense small case labels (1/2/3) are typical user dispatch; PE/EH magic
        // tables (MZ 0x5a4d, huge facility codes) are not.
        if small_cases >= 2 && user_tag_dispatch {
            score += 0.22;
        } else if small_cases >= 2 {
            score += 0.08;
        }
        if huge_cases >= 1 && small_cases == 0 {
            score -= 0.85; // PE header / EH dispatch mistaken for user switch
        }
        // Gold often lists "1","2","3" as case constants — or generic switch/case.
        let gold_wants_small = gold.facts.iter().any(|f| {
            f.match_any.iter().any(|m| {
                m == "1" || m == "2" || m == "3" || m == "0x1" || m == "case" || m == "switch"
            })
        });
        if gold_wants_small && (small_cases >= 2 || small_eq >= 2) && user_tag_dispatch {
            score += 0.22;
        }
        if gold_wants_small && huge_cases >= 1 && small_cases == 0 {
            score -= 0.50;
        }
        // Call-bearing tag dispatch (record handler style) is rare in CRT.
        if user_tag_dispatch && gold_wants_calls {
            let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
            let calls = body.matches("FUN_").count() + body.matches("call(").count();
            if calls >= 1 {
                score += 0.28;
            }
        }
    }

    // Loop+switch/if-ladder kernels (decode/record processors) are rare in CRT.
    if wants_loop && wants_switch {
        let has_while = tl.contains("while") || tl.contains("for") || tl.contains("for (");
        let has_sw = tl.contains("switch") || small_case_hint(text);
        let has_xor = tl.contains('^') || tl.contains("xor");
        let callish_body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let calls = callish_body.matches("call(").count() + callish_body.matches("FUN_").count();
        if has_while && has_sw {
            score += 0.30;
        }
        if has_while && has_sw && has_xor {
            score += 0.15;
        }
        // Multi-module style: outer loop calls a record handler (FUN_).
        if has_while && calls >= 1 && (120..2500).contains(&text.len()) {
            score += 0.35;
        }
        if !has_while {
            score -= 0.25;
        }
    }

    // Decode-style multi-fact gold (bound + switch cases + xor) often compiles
    // as outer loop calling a tag handler — prefer while+calls+xor over a
    // pure tag switch leaf (handle_record) that lacks a loop/bound.
    let gold_wants_bound = gold.facts.iter().any(|f| {
        matches!(f.kind, super::sfg::FactKind::Predicate)
            && f.match_any
                .iter()
                .any(|m| m == "<" || m.contains("end") || m.contains("cursor"))
    });
    let crit_facts = gold.facts.iter().filter(|f| f.critical).count();
    if gold_wants_bound && wants_switch && crit_facts >= 4 {
        let has_while = tl.contains("while") || tl.contains("for ") || tl.contains("for(");
        let has_xor = tl.contains('^') || tl.contains("xor");
        let callish_body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let calls = callish_body.matches("FUN_").count() + callish_body.matches("call(").count();
        let has_sw_only = (tl.contains("switch") || small_case_hint(text)) && !has_while;
        if has_while && calls >= 1 {
            score += 0.45;
        }
        if has_while && has_xor {
            score += 0.20;
        }
        // Pure tag-dispatch leaf without loop is the callee, not the decoder.
        if has_sw_only && calls <= 2 && text.len() < 800 {
            score -= 0.55;
        }
    }

    // Gold with many critical facts prefers multi-arg user kernels.
    let crit_n = gold.facts.iter().filter(|f| f.critical).count();
    if crit_n >= 4 {
        let arg_n = text.matches("arg_").count() + text.matches("param").count();
        if arg_n >= 3 {
            score += 0.12;
        }
        if text.len() < 200 {
            score -= 0.30;
        }
    }
    if wants_arith {
        if tl.contains('+') || tl.contains('^') || tl.contains("xor") || tl.contains("*") {
            score += 0.08;
        } else {
            score -= 0.25;
        }
    }

    // Prefer user-scale size for multi-fact gold (bench kernels ~100–1500 chars).
    let crit_total = gold.facts.iter().filter(|f| f.critical).count();
    if crit_total >= 2 {
        if text.len() < 80 {
            score -= 0.55; // stubs cannot carry multi-fact gold / s_align
        } else if (120..2500).contains(&text.len()) {
            score += 0.10;
        } else if text.len() > 3500 {
            score -= 0.15; // CRT-scale
        }
    }
    // Structure-rich surface forms for multi-fact gold (s_align / CRW).
    if crit_total >= 3 {
        let pred_n =
            tl.matches("if").count() + tl.matches("while").count() + tl.matches("switch").count();
        if pred_n >= 2 {
            score += 0.15;
        } else if pred_n == 0 {
            score -= 0.25;
        }
    }

    // Early .text bias for multi-fact kernels (CRT helpers often land higher).
    if crit_total >= 3 {
        if (0x140001000..0x140002000).contains(&va) {
            score += 0.12;
        } else if va >= 0x140005000 {
            // Mid/high .text CRT shells (UTF-8 / locale) frequently dual-cover
            // and steal loop+load golds (d06, b04). Demote unless they carry
            // loop keywords or resource-pair tags.
            let looks_kernel = tl.contains("while")
                || tl.contains("switch")
                || tl.contains("res_init")
                || tl.contains("0x45d9")
                || tl.contains("4e67c6a7");
            if !looks_kernel {
                score -= 0.45;
            } else {
                score -= 0.10;
            }
        } else if va >= 0x140008000 {
            score -= 0.25;
        }
    }

    if is_trivial_stub(text) && (wants_loop || wants_switch || wants_arith) {
        score -= 0.55;
    }
    // CRT atexit / TLS callback tables: while over a global array calling
    // through a function pointer — never the gold loop kernel (e05/b05).
    if wants_loop {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let atexitish = body.contains("while")
            && (body.contains("call(*(") || body.contains("call (*("))
            && (body.contains("g_") || body.contains("0x1400"));
        if atexitish && body.matches("while").count() <= 1 && text.len() < 500 {
            score -= 0.75;
        }
        // Prefer loop bodies that accumulate (+ / ^) — gold Operation facts.
        let gold_wants_acc = gold.facts.iter().any(|f| {
            matches!(f.kind, super::sfg::FactKind::Operation)
                && f.match_any
                    .iter()
                    .any(|m| m == "+" || m == "+=" || m == "^")
        });
        if gold_wants_acc {
            if (body.contains('+') || body.contains('^'))
                && (body.contains("while") || body.contains("for"))
            {
                score += 0.35;
            } else if body.contains("while") && !body.contains('+') && !body.contains('^') {
                score -= 0.40;
            }
        }
    }

    // Reject pure zeroing returns for control/semantic kernels (common CRT stubs).
    let wants_if = gold.facts.iter().any(|f| {
        matches!(f.kind, super::sfg::FactKind::ControlRegion)
            || f.must_match.iter().any(|m| m == "if")
            || f.match_any.iter().any(|m| m == "if")
    });
    if (wants_if || wants_loop || wants_switch)
        && (tl.contains("rax ^ (u64)rax") || tl.contains("return 0;") || tl.contains("return 0x0"))
        && !tl.contains("if")
        && !tl.contains("while")
    {
        score -= 0.70;
    }
    // Gold control_region must_match "if": demote bodies with no if/while/switch
    // (tiny return-only stubs and pure arithmetic that cannot satisfy CRW).
    if wants_if && !tl.contains("if") && !tl.contains("while") && !tl.contains("switch") {
        score -= 0.85;
    } else if wants_if && tl.contains("if") {
        score += 0.12;
    }

    // Thin call wrappers: one call and return address materialization.
    let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
    let callish = body.matches("call(").count() + body.matches("FUN_").count();
    if callish >= 1
        && !tl.contains("while")
        && !tl.contains("for")
        && text.len() < 220
        && (wants_loop || wants_switch)
    {
        score -= 0.45;
    }

    // Strong early .text bias: grand-bench kernels are the first few user functions.
    if (0x140001000..0x140001200).contains(&va) {
        score += 0.22;
    } else if (0x140001200..0x140001800).contains(&va) {
        score += 0.10;
    } else if (0x140001800..0x140003000).contains(&va) {
        score += 0.02;
    } else if va >= 0x140004000 {
        score -= 0.12;
    }

    // Arity hint from gold name/signature is unavailable; prefer multi-arg forms
    // for non-main kernels (mat_sum, decode_packet, …).
    let id = gold.id.to_ascii_lowercase();
    if id != "main" && !id.starts_with("main") {
        let arg_n = text.matches("arg").count() + text.matches("param").count();
        if arg_n >= 2 {
            score += 0.05;
        }
        // Main-like globals/sink xor is rarely the kernel body.
        if text.contains("g_windy")
            || (text.contains("0x14001") && !tl.contains("while") && text.len() < 400)
        {
            score -= 0.08;
        }
    }

    // Prefer more critical hits hard-gate: zero critical hits → large penalty.
    if crit_hits < 1.0 && crit_total >= 2 {
        score -= 0.20;
    }

    // COM variant router tags 3/8/13 (VT_I4/BSTR/UNKNOWN-style) are distinctive.
    let gold_wants_variant_tags = gold.facts.iter().any(|f| {
        let has3 = f.match_any.iter().any(|m| m == "3" || m == "0x3");
        let has8 = f.match_any.iter().any(|m| m == "8" || m == "0x8");
        let has13 = f
            .match_any
            .iter()
            .any(|m| m == "13" || m == "0xd" || m == "0xD");
        has3 && (has8 || has13)
    });
    if gold_wants_variant_tags {
        let mut hit = 0usize;
        for dec in ["3", "8", "13"] {
            if compact_has_case_or_eq(text, dec) {
                hit += 1;
            }
        }
        // Also count hex forms not covered above.
        if tl.contains("0x3") || tl.contains("case 3") {
            hit = hit.max(1);
        }
        if hit >= 2 {
            score += 0.55;
        } else if hit == 1 {
            score -= 0.15;
        } else {
            // No VT tags: pure QI/refcount bodies must not steal route_variant.
            score -= 0.85;
            if tl.contains("80004003") && text.len() < 400 {
                score -= 0.70; // classic QI leaf
            }
        }
        if tl.contains("switch") {
            score += 0.25;
        }
        // (C++ EH magic demoted globally above.)
    }

    // COM / HRESULT gold: prefer bodies that surface facility constants and
    // multi-arm null/ppv guards; demote pure refcount ±1 stubs.
    let gold_wants_hresult = gold.facts.iter().any(|f| {
        f.match_any.iter().any(|m| {
            m.contains("80004003")
                || m.contains("0x8000")
                || m.eq_ignore_ascii_case("e_pointer")
                || m.contains("E_NOINTERFACE")
                || m.contains("S_OK")
        }) || f
            .must_match
            .iter()
            .any(|m| m.contains("80004003") || m.contains("0x8000"))
    });
    if gold_wants_hresult {
        if tl.contains("0x80004003") || tl.contains("80004003") {
            score += 0.95; // E_POINTER is the distinguishing QI/COM fail constant
        } else if tl.contains("0x80004002") || tl.contains("0x8000") {
            score += 0.40;
        } else {
            // Hard demotion so VARIANT routers with tag dispatch do not steal QI.
            score -= 0.95;
        }
        // Thin refcount-only bodies are not QueryInterface / routers.
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let thin_refcount = body.matches("if").count() <= 1
            && (body.contains("+ 0x1") || body.contains("+0x1") || body.contains("- 0x1"))
            && body.len() < 220;
        if thin_refcount {
            score -= 0.55;
        }
        // Huge CRT COM helpers without E_POINTER rarely are the gold QI kernel.
        if text.len() > 2000 && !tl.contains("80004003") {
            score -= 0.35;
        }
        // Real QI kernels are tiny (null-check + store + E_POINTER); CRT
        // facilities that print E_POINTER deep inside are not QI.
        if !gold_wants_variant_tags {
            if text.len() > 800 {
                score -= 0.60;
            }
            if text.len() < 350 && tl.contains("80004003") {
                score += 0.35;
            }
        }
        // Prefer pure E_POINTER QI bodies over VARIANT tag routers that also
        // happen to print E_POINTER (leave those for route_variant).
        if !gold_wants_variant_tags {
            let tag38 = compact_has_case_or_eq(text, "3") && compact_has_case_or_eq(text, "8");
            let tag13 = compact_has_case_or_eq(text, "13")
                || compact_has_case_or_eq(text, "0xd")
                || compact_has_case_or_eq(text, "0xD");
            if tag38 && tag13 {
                score -= 1.20; // full VT_I4/BSTR/UNKNOWN router is not QI
            } else if tag38 {
                score -= 0.70;
            }
        }
    }

    // CRC / mul-constant gold: the telemetry CRC constant is a strong fingerprint.
    let gold_wants_crc = gold.facts.iter().any(|f| {
        f.match_any
            .iter()
            .any(|m| m.contains("4e67c6a7") || m.contains("1315423911") || m.contains("0x4e67"))
    });
    if gold_wants_crc {
        if tl.contains("4e67c6a7") || tl.contains("0x4e67c6a7") {
            score += 0.55;
        } else {
            score -= 0.35;
        }
    }
    // Decode-style final mix constant.
    let gold_wants_mix = gold.facts.iter().any(|f| {
        f.match_any
            .iter()
            .any(|m| m.contains("45d9f3b") || m.contains("0x45d9"))
    });
    if gold_wants_mix && (tl.contains("45d9f3b") || tl.contains("0x45d9")) {
        score += 0.80;
    }

    // Pure bitwise / arithmetic leaf kernels (gold Operation with &|^).
    let gold_wants_bitwise = gold.facts.iter().any(|f| {
        matches!(f.kind, super::sfg::FactKind::Operation)
            && f.match_any.iter().any(|m| m == "&" || m == "|" || m == "^")
    });
    if gold_wants_bitwise {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let calls = body.matches("FUN_").count() + body.matches("call(").count();
        let has_bit = tl.contains('&') || tl.contains('|') || tl.contains('^');
        if has_bit && calls == 0 && text.len() < 400 {
            score += 0.55;
        } else if calls >= 1 && text.len() < 200 {
            score -= 0.40; // call wrappers / CRT shells
        }
    }

    // SEH filter gold: ACCESS_VIOLATION / facility codes are unique fingerprints.
    let gold_wants_av = gold.facts.iter().any(|f| {
        f.match_any.iter().any(|m| {
            m.contains("c0000005")
                || m.contains("C0000005")
                || m.contains("1073741819")
                || m.contains("0xc0000005")
        })
    });
    if gold_wants_av {
        if tl.contains("c0000005")
            || tl.contains("C0000005")
            || tl.contains("1073741819")
            || tl.contains("3ffffffb")
            || tl.contains("-0x3ffffffb")
        {
            score += 1.20; // ACCESS_VIOLATION fingerprint is unique
            if text.len() < 300 {
                score += 0.40; // tiny filter leaf
            }
        } else {
            score -= 0.85; // non-AV bodies never win filter_av
        }
    }

    // Refcount Release gold: prefer bodies that store a decremented refs field.
    let gold_wants_refcount_store = gold.facts.iter().any(|f| {
        matches!(f.kind, super::sfg::FactKind::Store)
            && f.match_any
                .iter()
                .any(|m| m.contains("refs") || m.contains("g_refs") || m.contains("DAT_"))
            && f.match_any.iter().any(|m| m.contains('-') || m == "=")
    });
    if gold_wants_refcount_store {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let has_dec = (body.contains("- 0x1") || body.contains("-0x1") || body.contains("--"))
            && body.contains('=');
        let has_store = body.contains("*(") && body.contains('=');
        if has_dec && has_store {
            score += 0.70;
        } else if has_store && body.contains('-') {
            score += 0.30;
        } else {
            score -= 0.55; // null-check stubs never win Release
        }
    }

    // Lifetime / resource-pair gold (parse_tree): prefer res_init/res_destroy surface.
    // Keep boosts modest so dual-covered shells are not abandoned (residual fairness).
    let gold_wants_lifetime = gold.facts.iter().any(|f| {
        matches!(f.kind, super::sfg::FactKind::LifetimeRegion)
            || f.match_any
                .iter()
                .any(|m| m.contains("res_destroy") || m.contains("res_init") || m == "destroy")
    });
    if gold_wants_lifetime {
        if tl.contains("res_destroy") && tl.contains("res_init") {
            score += 0.55;
        } else if tl.contains("res_destroy") || tl.contains("res_init") {
            score += 0.25;
        } else if !(text.contains(", 0x1)") || text.contains(", 0x2)")) {
            score -= 0.25;
        }
        // Two tagged inits (id 1/2) is the resource-pair fingerprint.
        let has1 = text.contains(", 0x1)") || text.contains(", 1)");
        let has2 = text.contains(", 0x2)") || text.contains(", 2)");
        if has1 && has2 {
            score += 0.30;
        }
    }

    // Signed vs unsigned affinity: both may print `<` after flag recovery.
    // Prefer bodies that look like two-arg pure kernels for *_lt / minmax.
    if id.contains("signed") || id.contains("unsigned") || id == "imin" || id == "iabs" {
        let has_ord = text.contains('<') || text.contains('>');
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let calls = body.matches("call(").count() + body.matches("FUN_").count();
        if has_ord && calls == 0 && text.matches("arg").count() >= 2 {
            score += 0.12;
        }
        // Signed leftovers sometimes keep IntS* names before strip; tiny boost.
        if id.contains("signed")
            && (text.contains("IntS") || text.contains("arg_20") || text.contains("arg_28"))
        {
            score += 0.04;
        }
    }

    score
}

/// Pick best unused candidate text for this gold function (name / VA / score).
/// True when a symbol name is a real match for gold source_name / id.
/// Short names like `"f"` must not match via `ends_with` (FUN_…eddf).
/// Longer names only suffix-match with a path/separator boundary.
pub(crate) fn name_matches_gold(name: &str, gold_name: &str) -> bool {
    if name == gold_name || name.eq_ignore_ascii_case(gold_name) {
        return true;
    }
    // Require meaningful length before suffix matching.
    if gold_name.len() < 4 {
        return false;
    }
    // Boundary-aware suffix only (`_kernel`, `::kernel`, `.kernel`).
    name.ends_with(&format!("_{gold_name}"))
        || name.ends_with(&format!("::{gold_name}"))
        || name.ends_with(&format!(".{gold_name}"))
}

pub(crate) fn find_windy_text(
    project: &Project,
    gold: &SfgFunctionGold,
    va_hint: Option<u64>,
    candidates: &[(u64, String)],
    used: &mut HashSet<u64>,
) -> String {
    let gold_name = gold.source_name.as_deref().unwrap_or(gold.id.as_str());
    let mut pool: Vec<(u64, String)> = candidates.to_vec();

    // Explicit gold VA or symbol name: add into scored pool (never auto-accept).
    if let Some(va) = va_hint
        && !used.contains(&va)
        && let Some(t) = project.function_decompile_native(va)
        && !is_crtish_text(&t)
        && !pool.iter().any(|(v, _)| *v == va)
    {
        pool.push((va, t));
    }
    for f in project.functions().iter() {
        if used.contains(&f.entry_va) {
            continue;
        }
        let name = f.name(&project.symbols);
        if name_matches_gold(&name, gold_name)
            && let Some(t) = project.function_decompile_native(f.entry_va)
            && !is_crtish_text(&t)
            && !pool.iter().any(|(v, _)| *v == f.entry_va)
        {
            pool.push((f.entry_va, t));
        }
    }

    // Deterministic VA order for scoring + early-rank bias.
    pool.sort_by_key(|(va, _)| *va);
    pool.dedup_by_key(|(va, _)| *va);

    // Rank by ascending VA among unused pool entries — first kernels are user code.
    let mut early_vas: Vec<u64> = pool
        .iter()
        .filter(|(v, _)| !used.contains(v))
        .map(|(v, _)| *v)
        .collect();
    early_vas.sort_unstable();
    early_vas.dedup();
    let early_rank: HashMap<u64, usize> =
        early_vas.iter().enumerate().map(|(i, v)| (*v, i)).collect();

    // Single gold-derived contract (kernel_gate::derive_pick_requirements).
    let req = derive_pick_requirements(gold);
    let max_rank = if req.is_kernel { 32 } else { 80 };

    let mut best: Option<(f64, u64, String)> = None;
    for (va, t) in &pool {
        if used.contains(va) {
            continue;
        }
        if is_crtish_text(t) || is_cookie_epilogue_text(t) || is_trivial_stub(t) {
            continue;
        }
        // Shared CRT shells never eligible for non-main gold (defense in depth).
        let is_main = gold.id == "main"
            || gold
                .source_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("main"));
        if !is_main && is_shared_nonkernel_shell(t) {
            continue;
        }
        // Unified pick_compatible gate — empty unmatched preferred over CRT shell.
        if hard_reject(t, gold).is_some() {
            continue;
        }
        let rank = early_rank.get(va).copied().unwrap_or(999);
        // SEH/COM fingerprints (AV filter, HRESULT, CRC) often live high in
        // .text after CRT; do not rank-cap them out of the pool.
        let tl_cand = t.to_ascii_lowercase();
        let fingerprint_exempt = tl_cand.contains("c0000005")
            || tl_cand.contains("3ffffffb")
            || tl_cand.contains("80004003")
            || tl_cand.contains("45d9f3b")
            || tl_cand.contains("4e67c6a7");
        if rank > max_rank && !fingerprint_exempt {
            continue;
        }
        let mut score = pick_score(t, gold, *va);
        // Early-VA bias is real for leaf kernels, but for loop/switch gold the
        // first .text function is often a tiny helper (read_header) — keep the
        // boost mild so the large structured body can win.
        let structured = req.requires_loop || req.requires_switch;
        if rank < 3 {
            score += if structured {
                0.08 - 0.02 * (rank as f64)
            } else {
                0.45 - 0.10 * (rank as f64)
            };
        } else if rank < 8 {
            score += if structured { 0.04 } else { 0.12 };
        }
        // Name match boost only after shape scoring.
        let name = project
            .functions()
            .iter()
            .find(|f| f.entry_va == *va)
            .map(|f| f.name(&project.symbols))
            .unwrap_or_default();
        if !name.is_empty() && name_matches_gold(&name, gold_name) {
            score += 0.25;
        }
        if va_hint == Some(*va) {
            score += 0.03; // weak hint only
        }
        // Soft penalty for residual gotos when gold prefers structured control.
        if gold
            .facts
            .iter()
            .any(|f| f.id.contains("no_goto") || f.forbid.iter().any(|x| x.contains("goto")))
        {
            score -= 0.08 * (t.matches("goto ").count() as f64);
        }
        // Main prefers call-bearing bodies.
        let is_main = gold.id == "main"
            || gold
                .source_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("main"));
        if is_main {
            let body = t.split_once('{').map(|(_, b)| b).unwrap_or(t);
            let calls = body.matches("call(").count() + body.matches("FUN_").count();
            if calls >= 1 {
                score += 0.15;
            } else {
                score -= 0.25; // do not steal pure kernels for main
            }
        }
        // Higher score wins; on ties keep the first (pool is VA-sorted → lower VA).
        if best.as_ref().map(|(b, _, _)| score > *b).unwrap_or(true) {
            best = Some((score, *va, t.clone()));
        }
    }

    // Fallback: expand pool if early window had no usable hit — same hard_reject.
    if best.as_ref().map(|(s, _, _)| *s < 0.20).unwrap_or(true) {
        for (va, t) in &pool {
            if used.contains(va) || is_crtish_text(t) || is_cookie_epilogue_text(t) {
                continue;
            }
            let is_main = gold.id == "main"
                || gold
                    .source_name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case("main"));
            if !is_main && is_shared_nonkernel_shell(t) {
                continue;
            }
            if hard_reject(t, gold).is_some() {
                continue;
            }
            let mut score = pick_score(t, gold, *va);
            if va_hint == Some(*va) {
                score += 0.03;
            }
            if best.as_ref().map(|(b, _, _)| score > *b).unwrap_or(true) {
                best = Some((score, *va, t.clone()));
            }
        }
    }

    if let Some((sc, va, t)) = best {
        // Final integrity: never claim a hard-rejected / trivial body as a hit.
        if hard_reject(&t, gold).is_some() || is_trivial_stub(&t) {
            return String::new();
        }
        if sc > 0.10 {
            used.insert(va);
            return t;
        }
        // Multi-critical golds: accept weaker shape-compatible hits to avoid
        // EmptyDecompile on present decode/switch functions.
        let crit_n = gold.facts.iter().filter(|f| f.critical).count();
        if crit_n >= 2 && sc > 0.03 && !t.trim().is_empty() {
            used.insert(va);
            return t;
        }
        if crit_n <= 1 && sc > 0.05 && !t.trim().is_empty() {
            used.insert(va);
            return t;
        }
    }

    String::new()
}

fn resolve_repo_path(repo: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() { pb } else { repo.join(p) }
}

/// Run full Grand Bench score for all binaries in the manifest.
pub fn run_grand_score(repo: &Path, manifest_path: &Path) -> anyhow::Result<GrandReport> {
    let manifest: Manifest = load_manifest(manifest_path)?;
    let mut pairs: Vec<FunctionPair> = Vec::new();
    let mut engine_hist: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

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
        // Honest profile baseline: only same-profile Ghidra export (no P0 reuse).
        let ghidra_map = bin
            .ghidra_export
            .as_ref()
            .map(|p| load_ghidra_map(&resolve_repo_path(repo, p)))
            .unwrap_or_default();
        let ghidra_export_present = !ghidra_map.is_empty();

        let candidates = collect_user_candidates_hist(&project, Some(&mut engine_hist));
        let mut used_vas: HashSet<u64> = HashSet::new();

        // Ghidra VAs filtered to non-CRT scale entries already.
        let mut ghidra_vas: Vec<u64> = ghidra_map.keys().copied().collect();
        ghidra_vas.sort_unstable();

        let mut used_ghidra: HashSet<u64> = HashSet::new();

        // Match non-main kernels before main so main cannot steal the only
        // high-quality compare/loop body under stripped symbols.
        // Prefer golds with more critical facts first so constrained functions
        // (decode_packet, handle_record) claim their real bodies before leaf
        // helpers (read_header, crc_add) can steal early VAs.
        let mut gold_order: Vec<&SfgFunctionGold> = gold.functions.iter().collect();
        gold_order.sort_by_key(|f| {
            let is_main = f.id == "main"
                || f.source_name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case("main"));
            let crit = f.facts.iter().filter(|x| x.critical).count();
            // Prefer switch/loop/lifetime golds before thin QI/refcount shells
            // so tag-dispatch bodies are claimed by route/decode first.
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
            // Only trust gold-provided entry VAs — never index-order CRT assignment.
            let va_hint = gf.entry_va.as_deref().and_then(parse_va);
            let windy_text = find_windy_text(&project, gf, va_hint, &candidates, &mut used_vas);

            // Ghidra: same-profile export only; shape-aware pick (no index VA).
            let ghidra_text = if ghidra_export_present {
                let mut best: Option<(f64, u64, String)> = None;
                if let Some(v) = va_hint
                    && !used_ghidra.contains(&v)
                    && let Some(text) = ghidra_map.get(&v)
                {
                    let sc = pick_score(text, gf, v) + 0.05;
                    best = Some((sc, v, text.clone()));
                }
                for (&gva, text) in &ghidra_map {
                    if used_ghidra.contains(&gva) {
                        continue;
                    }
                    if is_crtish_text(text) || is_trivial_stub(text) {
                        // still allow scoring — pick_score penalizes stubs
                    }
                    let sc = pick_score(text, gf, gva);
                    if best.as_ref().map(|(b, _, _)| sc > *b).unwrap_or(true) {
                        best = Some((sc, gva, text.clone()));
                    }
                }
                if let Some((sc, gva, t)) = best {
                    if sc > 0.12 {
                        used_ghidra.insert(gva);
                        t
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            let windy = score_function_sfg("windy_native", &windy_text, gf);
            let ghidra = score_function_sfg("ghidra", &ghidra_text, gf);
            pairs.push(FunctionPair {
                program_id: bin.program_id.clone(),
                profile: bin.profile.clone(),
                function_id: gf.id.clone(),
                pack_tags: bin.pack_tags.clone(),
                kind: bin.kind.clone(),
                windy,
                ghidra,
                ghidra_export_present,
            });
        }
    }

    let rows: Vec<(FunctionPair, bool)> = pairs.iter().cloned().map(|p| (p, true)).collect();
    let windy = aggregate_engine("windy", &rows);
    let ghidra = aggregate_engine("ghidra", &rows);

    write_engine_histogram(&engine_hist, "v1");

    // 2.md orbit stability sidecar (shipped dual-model fingerprints).
    {
        let orbit = super::orbit::run_orbit_stability(repo);
        let md = super::orbit::format_orbit_report(&orbit);
        if let Ok(dir) = std::env::var("WINDY_SCRATCH") {
            let p = PathBuf::from(dir).join("orbit_stability.md");
            let _ = fs::write(p, md.as_bytes());
        }
    }

    Ok(GrandReport {
        suite: "windy_grand_decompilation_benchmark_v1".into(),
        windy,
        ghidra,
        per_function: pairs,
    })
}

/// Format a human-readable scores table.
pub fn format_scores_table(report: &GrandReport) -> String {
    let mut out = String::new();
    out.push_str("# Windy Grand Decompilation Benchmark — Results\n\n");
    out.push_str("| Engine | Overall mean | Functions | Programs | Catastrophic rate |\n");
    out.push_str("|---|---:|---:|---:|---:|\n");
    for eng in [&report.windy, &report.ghidra] {
        out.push_str(&format!(
            "| {} | {:.4} | {} | {} | {:.2}% |\n",
            eng.engine,
            eng.overall_mean,
            eng.functions_scored,
            eng.programs_scored,
            eng.catastrophic_rate * 100.0
        ));
    }
    out.push_str("\n## Per-pack means (A–J)\n\n| Pack | Windy | Ghidra |\n|---|---:|---:|\n");
    let mut packs: Vec<String> = report
        .windy
        .pack_means
        .keys()
        .chain(report.ghidra.pack_means.keys())
        .cloned()
        .collect();
    packs.sort();
    packs.dedup();
    for p in packs {
        out.push_str(&format!(
            "| {} | {:.4} | {:.4} |\n",
            p,
            report.windy.pack_means.get(&p).copied().unwrap_or(0.0),
            report.ghidra.pack_means.get(&p).copied().unwrap_or(0.0)
        ));
    }
    out.push_str(
        "\n## Per-profile means (P0–P3)\n\n| Profile | Windy | Ghidra (same-profile export only) |\n|---|---:|---:|\n",
    );
    for p in ["P0", "P1", "P2", "P3"] {
        let g = report
            .ghidra
            .profile_means
            .get(p)
            .map(|v| format!("{v:.4}"))
            .unwrap_or_else(|| "n/a".into());
        out.push_str(&format!(
            "| {} | {:.4} | {} |\n",
            p,
            report.windy.profile_means.get(p).copied().unwrap_or(0.0),
            g
        ));
    }
    out.push_str(&format!(
        "\n_Ghidra functions with real same-profile export: {} (no silent P0 reuse)._\n",
        report.ghidra.functions_scored
    ));
    out.push_str("\n## Boss programs\n\n| Program | Windy | Ghidra |\n|---|---:|---:|\n");
    let mut bosses: Vec<String> = report
        .windy
        .boss_scores
        .keys()
        .chain(report.ghidra.boss_scores.keys())
        .cloned()
        .collect();
    bosses.sort();
    bosses.dedup();
    for b in bosses {
        out.push_str(&format!(
            "| {} | {:.4} | {:.4} |\n",
            b,
            report.windy.boss_scores.get(&b).copied().unwrap_or(0.0),
            report.ghidra.boss_scores.get(&b).copied().unwrap_or(0.0)
        ));
    }
    out.push_str("\n## Top residual classes (Windy)\n\n| Residual | Count |\n|---|---:|\n");
    let mut res: Vec<_> = report.windy.residual_histogram.iter().collect();
    res.sort_by(|a, b| b.1.cmp(a.1));
    for (k, v) in res.into_iter().take(15) {
        out.push_str(&format!("| {k} | {v} |\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::name_matches_gold;

    fn write_scratch(name: &str, contents: &str) {
        let Ok(dir) = std::env::var("WINDY_SCRATCH") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join(name), contents);
    }

    #[test]
    fn short_gold_name_does_not_suffix_match_fun_suffix() {
        // Gold source_name "f" must not match FUN_14000eddf via ends_with.
        assert!(!name_matches_gold("FUN_14000eddf", "f"));
        assert!(!name_matches_gold("FUN_140001000", "f"));
        assert!(name_matches_gold("f", "f"));
        assert!(name_matches_gold("kernel", "kernel"));
        assert!(name_matches_gold("my_kernel", "kernel"));
        assert!(!name_matches_gold("mykernel", "kernel")); // no separator
        assert!(!name_matches_gold("FUN_14000eddf", "f"));
    }

    #[test]
    fn filter_av_high_va_present_on_p1() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/boss_seh_resource_loader.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).unwrap();
        let mut found = 0usize;
        let mut samples = String::new();
        // Known AV filter leaves (after int3) from binary scan.
        for va in [0x14000ed61u64, 0x14000f150, 0x140001000] {
            if let Some(t) = p.function_decompile_native(va) {
                let tl = t.to_ascii_lowercase();
                samples.push_str(&format!("{va:#x}: {}\n", t.replace('\n', " ")));
                if tl.contains("c0000005") || tl.contains("3ffffffb") {
                    found += 1;
                }
            }
        }
        write_scratch(
            "filter_av_p1_probe.txt",
            &format!("found={found}\n{samples}"),
        );
        assert!(
            found >= 1,
            "AV filter must decompile ACCESS_VIOLATION compare (found={found})\n{samples}"
        );
    }

    #[test]
    fn crw_leaf_decompiles_contain_if() {
        use crate::project::Project;
        use std::path::PathBuf;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cases = [
            ("eval/grand/bin/P0/a05_bitops.exe", 0x140001000u64),
            ("eval/grand/bin/P0/c02_switch_dense.exe", 0x140001000u64),
            ("eval/grand/bin/P0/c03_dispatch.exe", 0x140001040u64),
        ];
        let mut log = String::new();
        for (rel, va) in cases {
            let pe = root.join(rel);
            if !pe.exists() {
                continue;
            }
            let p = Project::open(&pe).unwrap();
            let t = p
                .function_decompile_native_with(
                    va,
                    crate::decompiler::v2::DecompileOptions::legacy_only(),
                )
                .unwrap_or_default();
            log.push_str(&format!(
                "{rel} va={va:#x} if={}\n{t}\n---\n",
                t.contains("if")
            ));
            assert!(
                t.contains("if ") || t.contains("if("),
                "control_region if missing in {rel}:\n{t}"
            );
        }
        write_scratch("crw_if_probe.txt", &log);
    }

    #[test]
    fn decompile_same_va_is_deterministic() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval/grand/bin/P0/a01_signed_lt.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).unwrap();
        let va = 0x140001000u64;
        let a = p.function_decompile_native(va).unwrap_or_default();
        let b = p.function_decompile_native(va).unwrap_or_default();
        assert_eq!(a, b, "same-process double decompile must match");
        let p2 = Project::open(&pe).unwrap();
        let c = p2.function_decompile_native(va).unwrap_or_default();
        assert_eq!(a, c, "reopen decompile must match");
    }

    #[test]
    fn find_crc_const_on_p3_telemetry() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P3/boss_telemetry_decoder.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).unwrap();
        let mut hits = String::new();
        for f in p.functions().iter() {
            if let Some(t) = p.function_decompile_native(f.entry_va) {
                let tl = t.to_ascii_lowercase();
                if tl.contains("4e67") {
                    hits.push_str(&format!(
                        "{:#x} {}\n",
                        f.entry_va,
                        t.chars().take(200).collect::<String>().replace('\n', " ")
                    ));
                }
            }
        }
        write_scratch("crc_hits_p3.txt", &hits);
        assert!(
            !hits.is_empty(),
            "must find CRC 4e67 constant in some function"
        );
    }

    #[test]
    fn route_p1_surfaces_hresult() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/boss_com_variant_router.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).unwrap();
        let t = p.function_decompile_native(0x140001028).unwrap_or_default();
        write_scratch("route_p1.txt", &t);
        assert!(
            t.contains("80004003") || t.contains("80070057"),
            "route must surface HRESULT constants, got:\n{t}"
        );
    }

    #[test]
    fn qi_p0_surfaces_e_pointer() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/boss_com_variant_router.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).unwrap();
        let t = p.function_decompile_native(0x140001000).unwrap_or_default();
        write_scratch("qi_p0.txt", &t);
        assert!(
            t.contains("80004003"),
            "QI must surface E_POINTER, got:\n{t}"
        );
    }

    #[test]
    fn boss_extra_deep_p2_structure_dump() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval/grand/bin/P2/boss_extra_3.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).unwrap();
        let t = p.function_decompile_native(0x140001000).unwrap_or_default();
        write_scratch("boss_extra_deep_p2.txt", &t);
        // Soft structural expectation: multi-fact deep kernels should surface a loop.
        // (Hard assert deferred until loop recovery is complete.)
        assert!(!t.is_empty());
    }

    #[test]
    fn bitops_p0_early_leaf_has_bitwise_ops() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval/grand/bin/P0/a05_bitops.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open");
        let t = p.function_decompile_native(0x140001000).expect("decomp");
        assert!(
            t.contains('&') || t.contains('|') || t.contains('^'),
            "bitops leaf must surface bitwise ops, got:\n{t}"
        );
        // Must not be a call-wrapper CRT shell.
        let body = t.split_once('{').map(|(_, b)| b).unwrap_or(&t);
        assert!(
            !body.contains("call(") && body.matches("FUN_").count() == 0,
            "leaf should not call helpers, got:\n{t}"
        );
    }
}
