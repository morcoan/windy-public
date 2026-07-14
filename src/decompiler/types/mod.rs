//! Type recovery over optimized SSA (Phase 4 + 4.1 + Phase 7 A/B).

pub mod aggregate;
pub mod recover;
#[allow(dead_code)] // consumed by the project-level signature persistence bridge
pub mod signature;
pub use recover::{
    CallConstraint, TyGuess, TypeRecoveryReport, data_type_to_ty_guess, recover_types,
};
