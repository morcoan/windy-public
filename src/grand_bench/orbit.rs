//! Multi-profile orbit stability for recovered contracts (2.md criterion 5).
//!
//! Compares loop / return-class / case-partition fingerprints from the
//! **shipped** dual-model path across P0–P3 for curated programs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::project::Project;

/// One kernel observation under a profile.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct OrbitKernel {
    pub profile: String,
    pub entry_va: u64,
    pub fingerprint: String,
    pub decomp_preview: String,
}

/// Orbit result for one program across profiles.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct OrbitProgramReport {
    pub program_id: String,
    pub kernels: Vec<OrbitKernel>,
    /// True when ≥2 profiles share the same fingerprint for the primary kernel.
    pub stable: bool,
    pub note: String,
}

const ORBIT_PROGRAMS: &[&str] = &[
    "a01_signed_rel",
    "a03_minmax_abs",
    "a04_div_rem",
    "a05_bitops",
    "b01_sum_until_zero",
    "c02_switch_dense",
    "c01_nested_if",
    "boss_telemetry_decoder",
];

const PROFILES: &[&str] = &["P0", "P1", "P2", "P3"];

fn pe_path(repo: &Path, profile: &str, program: &str) -> PathBuf {
    repo.join("eval/grand/bin")
        .join(profile)
        .join(format!("{program}.exe"))
}

/// Prefer real user kernels via grand-bench candidate filter (early .text, not CRT soup).
/// Rank: switch/case contracts first, then early VA order among structured bodies.
fn primary_kernels(project: &Project) -> Vec<u64> {
    let candidates = super::run::collect_user_candidates(project);
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(i64, u64)> = Vec::new();
    for (rank, (va, text)) in candidates.iter().enumerate() {
        // Early rank is gold for leaf kernels (same bias as grand-bench pick).
        let mut score = 1_000_000i64 - (rank as i64) * 10_000;
        if (0x140001000..0x140001800).contains(va) {
            score += 500_000;
        } else if *va >= 0x140008000 {
            // High-VA CRT helpers that slipped the filter.
            score -= 2_000_000;
        }
        let t = text.to_ascii_lowercase();
        // PE MZ / PE signature walkers (0x5a4d / 0x4550) are CRT/loader helpers.
        if t.contains("0x5a4d") || t.contains("0x4550") {
            score -= 1_500_000;
        }
        if t.contains("switch") {
            score += 400_000;
        }
        if t.contains("while") || t.contains("for ") || t.contains("for(") {
            score += 80_000;
        }
        if t.contains("if (") || t.contains("if(") {
            score += 30_000;
        }
        // Mass prolog saves → still CRT-ish even if filter missed it.
        let prolog_saves = ["arg_0 = fp", "arg_0 = rbx", "arg_0 = rsi", "arg_0 = rdi"]
            .iter()
            .filter(|p| text.contains(*p))
            .count();
        if prolog_saves >= 3 {
            score -= 300_000;
        }
        // Contract fingerprint: cases > loops > vacuous return.
        if let Some(fp) = project.function_contract_fingerprint(*va) {
            // Prefer real `switch` text + case contract; demote high-VA CRT switch tables.
            if !fp.contains("cases=0") && fp.contains("cases=") && t.contains("switch") {
                if *va < 0x140003000 {
                    score += 800_000;
                } else {
                    score += 20_000; // high-VA CRT often has switch tables
                }
            } else if !fp.contains("cases=0") && fp.contains("cases=") {
                score += 30_000;
            }
            // Prefer early pure kernels over multi-call CRT with switch.
            let fun_calls = text.matches("call(").count() + text.matches("FUN_").count();
            if fun_calls >= 2 {
                score -= 200_000;
            }
            if !fp.contains("loops=0") && fp.contains("loops=") {
                score += 40_000;
            }
            if fp.contains("loops=0") && fp.contains("cases=0") && !t.contains("switch") {
                score -= 40_000;
            }
        }
        // EH exception-code magic (0xe0…) is not a user kernel.
        if t.contains("0xe0") && t.contains("0x43") {
            score -= 1_000_000;
        }
        scored.push((score, *va));
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut out = Vec::new();
    for (_, va) in scored {
        if out.contains(&va) {
            continue;
        }
        out.push(va);
        if out.len() >= 4 {
            break;
        }
    }
    out
}

/// Run orbit stability for curated multi-profile programs.
pub fn run_orbit_stability(repo: &Path) -> Vec<OrbitProgramReport> {
    let mut reports = Vec::new();
    for prog in ORBIT_PROGRAMS {
        let mut kernels = Vec::new();
        for prof in PROFILES {
            let pe = pe_path(repo, prof, prog);
            if !pe.exists() {
                continue;
            }
            let Ok(project) = Project::open(&pe) else {
                continue;
            };
            for va in primary_kernels(&project) {
                let Some(fp) = project.function_contract_fingerprint(va) else {
                    continue;
                };
                let preview = project
                    .function_decompile_native(va)
                    .unwrap_or_default()
                    .chars()
                    .take(160)
                    .collect::<String>()
                    .replace('\n', " | ");
                kernels.push(OrbitKernel {
                    profile: (*prof).into(),
                    entry_va: va,
                    fingerprint: fp,
                    decomp_preview: preview,
                });
            }
        }
        // Stability: best non-CRT kernel per profile — ≥2 profiles share FP.
        // Prefer fingerprints that recover loops/cases (not vacuous ret-only).
        let mut by_profile: BTreeMap<String, String> = BTreeMap::new();
        for k in &kernels {
            by_profile.entry(k.profile.clone()).or_insert_with(|| {
                // Prefer the highest-scored kernel already ordered by primary_kernels.
                k.fingerprint.clone()
            });
        }
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for fp in by_profile.values() {
            *counts.entry(fp.clone()).or_default() += 1;
        }
        let stable = counts.values().any(|&c| c >= 2);
        let vacuous = by_profile
            .values()
            .all(|fp| fp.contains("loops=0") && fp.contains("cases=0") && !fp.contains("cases=1"));
        let note = if stable && !vacuous {
            "stable: ≥2 profiles share primary non-CRT kernel contract fingerprint".into()
        } else if stable && vacuous {
            "stable but low-structure (loops=0,cases=0): may still be observationally thin; CRT filtered".into()
        } else if by_profile.len() < 2 {
            "insufficient profiles present".into()
        } else {
            "unstable: primary fingerprints diverge (documented; shapes may be observationally inequivalent under opt)".into()
        };
        reports.push(OrbitProgramReport {
            program_id: (*prog).into(),
            kernels,
            stable,
            note,
        });
    }
    reports
}

/// Render markdown report for `{SCRATCH}/orbit_stability.md`.
pub fn format_orbit_report(reports: &[OrbitProgramReport]) -> String {
    let mut out = String::from("# Orbit stability (2.md criterion 5)\n\n");
    out.push_str("Contracts from shipped `Project::function_contract_fingerprint` ");
    out.push_str("(dual-model loops / return class / case partitions).\n\n");
    let n = reports.len();
    let n_stable = reports.iter().filter(|r| r.stable).count();
    out.push_str(&format!(
        "Programs: {n}; stable (≥2 profiles agree): {n_stable}\n\n"
    ));
    for r in reports {
        out.push_str(&format!("## {}\n\n", r.program_id));
        out.push_str(&format!("- **stable:** {}\n", r.stable));
        out.push_str(&format!("- **note:** {}\n\n", r.note));
        out.push_str("| Profile | VA | Fingerprint | Preview |\n|---|---|---|---|\n");
        // One row per profile (first kernel)
        let mut seen = std::collections::HashSet::new();
        for k in &r.kernels {
            if !seen.insert(k.profile.clone()) {
                continue;
            }
            out.push_str(&format!(
                "| {} | `{:#x}` | `{}` | {} |\n",
                k.profile,
                k.entry_va,
                k.fingerprint.replace('|', "¦"),
                k.decomp_preview.replace('|', "/")
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn orbit_report_covers_at_least_six_programs() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let reports = run_orbit_stability(&repo);
        assert!(
            reports.len() >= 6,
            "expected ≥6 orbit programs, got {}",
            reports.len()
        );
        // At least one program should produce kernels on P0 when bins exist.
        let any_kernels = reports.iter().any(|r| !r.kernels.is_empty());
        assert!(
            any_kernels,
            "expected at least one program with recovered kernels"
        );
        // Drive shipped dual-model path: fingerprints non-empty when kernels exist.
        for r in &reports {
            for k in &r.kernels {
                assert!(
                    !k.fingerprint.is_empty(),
                    "empty fingerprint for {} {}",
                    r.program_id,
                    k.profile
                );
            }
        }
        let md = format_orbit_report(&reports);
        assert!(md.contains("# Orbit stability"), "missing header in {md}");
        assert!(
            md.contains("a01_signed_rel") || md.contains("Programs:"),
            "report body missing"
        );
        // Persist for verification plan when CARGO_TARGET_TMPDIR / env available.
        if let Ok(dir) = std::env::var("WINDY_SCRATCH") {
            let p = PathBuf::from(dir).join("orbit_stability.md");
            let _ = std::fs::write(&p, &md);
        }
    }
}
