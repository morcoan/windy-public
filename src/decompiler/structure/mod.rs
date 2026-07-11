//! Native pseudo-C structuring over optimized SSA (Phase 5.1 full DREAM).

pub mod emit;
pub mod pdom;
pub mod region;

pub use emit::{NameCtx, decompile};
pub use region::SwitchInfo;
