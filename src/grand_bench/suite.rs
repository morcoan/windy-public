//! Suite inventory, profiles, and aggregation helpers.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::sfg::{FunctionSfgScore, ResidualClass, SfgProgramGold};

/// Compiler profiles (PDF §2).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Profile {
    P0,
    P1,
    P2,
    P3,
}

impl Profile {
    #[allow(dead_code)]
    pub fn all() -> &'static [Profile] {
        &[Profile::P0, Profile::P1, Profile::P2, Profile::P3]
    }
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::P0 => "P0",
            Profile::P1 => "P1",
            Profile::P2 => "P2",
            Profile::P3 => "P3",
        }
    }
    #[allow(dead_code)]
    pub fn cl_flags(self) -> &'static [&'static str] {
        match self {
            Profile::P0 => &["/Od", "/Ob0"],
            Profile::P1 => &["/O1"],
            Profile::P2 => &["/O2", "/Ob2"],
            Profile::P3 => &["/O2", "/GL"],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InventoryProgram {
    pub program_id: String,
    pub kind: String,
    pub pack_tags: Vec<String>,
    pub language: String,
    pub source: String,
    pub gold: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inventory {
    pub programs: Vec<InventoryProgram>,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuiltBinary {
    // Serialize: Grand v2 smoke tests write mini-manifests.
    pub program_id: String,
    pub profile: String,
    pub pe_path: String,
    pub sha256: String,
    pub pack_tags: Vec<String>,
    pub kind: String,
    pub gold_path: String,
    pub ghidra_export: Option<String>,
    /// SHA-256 of the pruned same-profile Ghidra export, when present.
    #[serde(default)]
    pub ghidra_sha256: Option<String>,
    /// Exact source-function identities captured from the linker MAP for this
    /// concrete profile build. Grand v1 ignores this field; Grand v2 uses it
    /// to keep function discovery separate from decompiler quality.
    #[serde(default)]
    pub function_map: Vec<ManifestFunction>,
}

/// Link-time status of one source function in one concrete profile binary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FunctionPresence {
    // Clone required for Grand v2 resolve/omit paths.
    Present,
    Folded,
    InlinedOnly,
    Missing,
}

/// Exact source identity for Grand v2. `entry_va` is present only when the
/// linker emitted a callable body; folded/inlined/missing functions remain in
/// the manifest as explicit non-scored observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestFunction {
    pub function_id: String,
    pub source_name: String,
    pub status: FunctionPresence,
    #[serde(default)]
    pub entry_va: Option<String>,
    #[serde(default)]
    pub folded_to: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub binaries: Vec<BuiltBinary>,
    pub profiles: Vec<String>,
    pub program_count: usize,
    pub binary_count: usize,
}

// Manifest already Serialize+Deserialize for mini-manifest unit tests.

#[derive(Clone, Debug, Serialize)]
pub struct EngineAggregate {
    // Clone used by grand-bench CLI v2 table adapter.
    pub engine: String,
    pub overall_mean: f64,
    pub functions_scored: usize,
    pub programs_scored: usize,
    pub pack_means: BTreeMap<String, f64>,
    pub profile_means: BTreeMap<String, f64>,
    pub boss_scores: BTreeMap<String, f64>,
    pub catastrophic_rate: f64,
    pub residual_histogram: BTreeMap<String, usize>,
    pub empty_decomp_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct GrandReport {
    pub suite: String,
    pub windy: EngineAggregate,
    pub ghidra: EngineAggregate,
    pub per_function: Vec<FunctionPair>,
}

/// Exact-address Grand v2 report. Scored functions use the same VA and
/// denominator for both engines; source functions without a callable body are
/// recorded in `omitted_functions` instead of becoming empty decompiles.
#[derive(Clone, Debug, Serialize)]
pub struct GrandReportV2 {
    pub suite: String,
    pub windy: EngineAggregate,
    pub ghidra: EngineAggregate,
    pub per_function: Vec<ExactFunctionPair>,
    pub omitted_functions: Vec<OmittedFunction>,
    pub failure_stage_histogram: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExactFunctionPair {
    #[serde(flatten)]
    pub scored: FunctionPair,
    pub entry_va: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windy_failure_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ghidra_failure_stage: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OmittedFunction {
    pub program_id: String,
    pub profile: String,
    pub function_id: String,
    pub source_name: String,
    pub status: FunctionPresence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folded_to: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionPair {
    // Clone: Grand v2 table adapter / aggregation rows.
    pub program_id: String,
    pub profile: String,
    pub function_id: String,
    pub pack_tags: Vec<String>,
    pub kind: String,
    pub windy: FunctionSfgScore,
    pub ghidra: FunctionSfgScore,
    /// True only when a real same-profile Ghidra export existed (no P0 reuse).
    #[serde(default)]
    pub ghidra_export_present: bool,
}

#[allow(dead_code)]
pub fn load_inventory(path: &Path) -> anyhow::Result<Inventory> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn load_program_gold(path: &Path) -> anyhow::Result<SfgProgramGold> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn load_manifest(path: &Path) -> anyhow::Result<Manifest> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

/// Verify a pinned fixture or comparison export before it enters a score.
pub fn verify_file_sha256(path: &Path, expected: &str, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(path.is_file(), "missing {label}: {}", path.display());
    if expected.is_empty() {
        // Synthetic unit manifests predate pinned hashes.
        return Ok(());
    }
    let actual = crate::project::persistence::hash_file(path)?;
    anyhow::ensure!(
        actual.eq_ignore_ascii_case(expected),
        "{label} SHA-256 mismatch for {}: expected {expected}, got {actual}",
        path.display()
    );
    Ok(())
}

#[allow(dead_code)]
pub fn default_grand_root(repo: &Path) -> PathBuf {
    repo.join("eval/grand")
}

pub fn aggregate_engine(engine: &str, rows: &[(FunctionPair, bool)]) -> EngineAggregate {
    // rows: (pair, unused). Ghidra aggregates only when same-profile export present.
    let mut scores: Vec<f64> = Vec::new();
    let mut pack_acc: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut prof_acc: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut boss_acc: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut residual_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut catastrophic = 0usize;
    let mut empty = 0usize;
    let mut programs = std::collections::BTreeSet::new();

    for (pair, _) in rows {
        let is_windy = engine == "windy" || engine.starts_with("windy_");
        if !is_windy && !pair.ghidra_export_present {
            continue;
        }
        let s = if is_windy { &pair.windy } else { &pair.ghidra };
        scores.push(s.composite);
        programs.insert(pair.program_id.clone());
        if s.capped || s.empty {
            catastrophic += 1;
        }
        if s.empty {
            empty += 1;
        }
        for tag in &pair.pack_tags {
            pack_acc.entry(tag.clone()).or_default().push(s.composite);
        }
        prof_acc
            .entry(pair.profile.clone())
            .or_default()
            .push(s.composite);
        if pair.kind == "boss" {
            boss_acc
                .entry(pair.program_id.clone())
                .or_default()
                .push(s.composite);
        }
        for r in &s.residuals {
            *residual_histogram.entry(format!("{r:?}")).or_default() += 1;
        }
    }

    let mean = |v: &[f64]| {
        if v.is_empty() {
            0.0
        } else {
            v.iter().sum::<f64>() / v.len() as f64
        }
    };

    EngineAggregate {
        engine: engine.into(),
        overall_mean: mean(&scores),
        functions_scored: scores.len(),
        programs_scored: programs.len(),
        pack_means: pack_acc.into_iter().map(|(k, v)| (k, mean(&v))).collect(),
        profile_means: prof_acc.into_iter().map(|(k, v)| (k, mean(&v))).collect(),
        boss_scores: boss_acc.into_iter().map(|(k, v)| (k, mean(&v))).collect(),
        catastrophic_rate: if scores.is_empty() {
            0.0
        } else {
            catastrophic as f64 / scores.len() as f64
        },
        residual_histogram,
        empty_decomp_count: empty,
    }
}

#[allow(dead_code)]
pub fn residual_label(r: &ResidualClass) -> String {
    format!("{r:?}")
}
