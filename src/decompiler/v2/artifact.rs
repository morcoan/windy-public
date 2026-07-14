//! Canonical decompile product surface (WindyDec v2 / v2.1).

use serde::{Deserialize, Serialize};

use super::ast::TypedAst;
use super::contracts::ContractBundle;

/// Explicit decompile mode (v2.1). Old booleans remain as deprecated compat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DecompileMode {
    /// Frozen Legacy structure + polish path.
    Legacy,
    /// Run pure V2 extraction for diagnostics; returned text stays Legacy.
    ShadowV2,
    /// Pure V2 authority path (fallback policy via `allow_legacy_fallback`).
    #[default]
    V2,
}

/// Which engine produced the artifact text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompileEngine {
    /// Checked v2 extraction + pure AST printer.
    V2,
    /// Legacy structure emit (Phase 5.1 + dual-model rewrites).
    Legacy,
}

/// Pipeline stage associated with a structured failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    Discovery,
    Lift,
    Hir,
    Contracts,
    Extract,
    Checker,
    Printer,
}

/// Options for v2 decompilation.
#[derive(Clone, Debug)]
pub struct DecompileOptions {
    /// Explicit mode (preferred).
    pub mode: DecompileMode,
    /// Prefer v2; fall back to legacy on HIR/checker failure (default true for product).
    /// Deprecated in favor of `mode`; still honored for one release.
    pub allow_legacy_fallback: bool,
    /// Record shadow comparison without changing returned text.
    /// Deprecated in favor of `mode == ShadowV2`.
    pub shadow_only: bool,
    /// Max AST candidates explored per function (plan default 2048).
    pub max_candidates: usize,
    /// Keep best N per region (plan default 8).
    pub beam_width: usize,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self::production()
    }
}

impl DecompileOptions {
    /// Product default: checked V2 output with an explicit Legacy fallback.
    ///
    /// Victory measurement remains [`Self::pure_no_fallback`], which never
    /// permits the fallback and is therefore suitable for strict scorecards.
    pub fn production() -> Self {
        Self {
            mode: DecompileMode::V2,
            allow_legacy_fallback: true,
            shadow_only: false,
            max_candidates: 2048,
            beam_width: 8,
        }
    }

    /// Pure no-fallback lane for strict Grand v2 victory measurement.
    pub fn pure_no_fallback() -> Self {
        Self {
            mode: DecompileMode::V2,
            allow_legacy_fallback: false,
            shadow_only: false,
            max_candidates: 2048,
            beam_width: 8,
        }
    }

    /// Frozen Legacy-only mode.
    pub fn legacy_only() -> Self {
        Self {
            mode: DecompileMode::Legacy,
            allow_legacy_fallback: true,
            shadow_only: false,
            max_candidates: 2048,
            beam_width: 8,
        }
    }

    /// Shadow: compute V2 diagnostics, ship Legacy text.
    pub fn shadow_v2() -> Self {
        Self {
            mode: DecompileMode::ShadowV2,
            allow_legacy_fallback: true,
            shadow_only: true,
            max_candidates: 2048,
            beam_width: 8,
        }
    }

    /// Effective mode after deprecated boolean reconciliation.
    pub fn effective_mode(&self) -> DecompileMode {
        if self.shadow_only {
            return DecompileMode::ShadowV2;
        }
        self.mode
    }
}

/// Checker outcome for one extracted AST.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckReport {
    pub accepted: bool,
    pub edges_covered: usize,
    pub effects_covered: usize,
    pub rejects: Vec<String>,
    pub candidates_tried: usize,
    pub candidates_accepted: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<FailureStage>,
    #[serde(default)]
    pub hit_candidate_cap: bool,
}

/// Optional Legacy-vs-pure delta for shadow diagnostics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyDelta {
    pub pure_text_len: usize,
    pub legacy_text_len: usize,
    pub texts_equal: bool,
    pub pure_engine_would_be: String,
}

/// Single canonical decompile result (additive fields for v2.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecompileArtifact {
    pub text: String,
    /// Compact AST summary (region topology + statement counts).
    pub ast_summary: String,
    /// Serializable typed AST when pure path produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_ast: Option<TypedAst>,
    pub contracts: ContractBundle,
    pub check_report: CheckReport,
    pub presentation_cost: i32,
    pub diagnostics: Vec<String>,
    pub engine: DecompileEngine,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Topology/value fingerprint (not raw block IDs).
    pub contract_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_delta: Option<LegacyDelta>,
    #[serde(default)]
    pub hit_candidate_cap: bool,
}

impl DecompileArtifact {
    pub fn empty_present(reason: &str) -> Self {
        Self {
            text: String::new(),
            ast_summary: String::new(),
            typed_ast: None,
            contracts: ContractBundle::default(),
            check_report: CheckReport {
                accepted: false,
                rejects: vec![reason.into()],
                failure_stage: Some(FailureStage::Extract),
                ..Default::default()
            },
            presentation_cost: i32::MAX,
            diagnostics: vec![reason.into()],
            engine: DecompileEngine::Legacy,
            fallback_reason: Some(reason.into()),
            contract_fingerprint: String::new(),
            legacy_delta: None,
            hit_candidate_cap: false,
        }
    }
}
