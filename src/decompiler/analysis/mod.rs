//! Decompiler-side analysis passes that sit on top of optimized SSA
//! without mutating frozen P-code / Location enums (Phase 7).

pub mod points_to;

pub use points_to::{PointsToCtx, PointsToMap, compute_points_to};
