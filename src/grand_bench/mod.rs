//! Windy Grand Decompilation Benchmark — Semantic Fact Graph (SFG) scoring.
//!
//! Implements the score model from *Windy Grand Decompilation Benchmark.pdf*:
//! weighted dimensions, catastrophic caps, residual classes, comment strip,
//! plus structural alignment \(S_{\mathrm{align}}\) and topology penalty.

pub mod align;
pub mod evaluator;
pub mod graph_gold;
pub mod identity_bootstrap;
pub mod kernel_gate;
pub mod orbit;
pub mod run;
pub mod sfg;
pub mod strict_v2;
pub mod suite;
pub mod v2;

pub use run::{format_scores_table, run_grand_score};
#[allow(unused_imports)]
pub use strict_v2::{FourLaneReport, run_grand_score_v2_strict};
pub use v2::{empty_decomp_audit, run_grand_score_v2};
