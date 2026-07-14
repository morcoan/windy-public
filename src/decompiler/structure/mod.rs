//! Native pseudo-C structuring over optimized SSA (Phase 5.1 full DREAM).
//!
//! 2.md dual-object path: semantic effects (`rd_model`) + presentation CFG
//! (`cfg_norm` / `PresentationGraph`) + checker-backed rewrites (`rewrite`).

pub mod cfg_norm;
pub mod emit;
pub mod pdom;
pub mod presentation;
pub mod rd_model;
pub mod region;
pub mod rewrite;

#[allow(unused_imports)] // public pure API still exported for Legacy/tests
pub use emit::decompile_structured_pure;
#[allow(unused_imports)] // public for tests / tooling
pub use emit::legacy_polish_pipeline;
#[allow(unused_imports)] // public region-tree emit for pure V2 (no presentation polish)
pub use emit::structure_emit_core;
pub use emit::{NameCtx, decompile};
#[allow(unused_imports)] // public API for agents/tests
pub use presentation::{PresentationTier, apply_presentation};
pub use rd_model::DualDecompModel;
pub use region::SwitchInfo;
