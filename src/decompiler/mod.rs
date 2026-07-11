//! External decompiler model integration.

pub mod analysis;
pub mod client;
#[allow(dead_code)] // semantic HIR is additive until the call-lifting pass consumes it
pub mod hir;
pub mod pcode;
pub mod ssa;
pub mod structure;
pub mod types;
