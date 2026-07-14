//! WindyDec v2 — semantic HIR → contracts → checked AST → pure printer.
//!
//! Authority chain (plan):
//!   raw P-code + architectural CFG + project evidence
//!     → semantic model (observations + exit values)
//!     → contracts / region tree
//!     → checked candidate extraction
//!     → pure pretty-printer
//!
//! Legacy structure emit remains available as per-function fallback with reason.

// Scaffolding APIs grow ahead of all call sites during milestone rollout.
#![allow(dead_code)]

pub mod artifact;
pub mod ast;
pub mod boss_patterns;
pub mod cfg_ast;
pub mod check;
pub mod check_ast;
pub mod contracts;
pub mod engine;
pub mod extract;
pub mod observation;
pub mod print;
pub mod print_ast;
pub mod region_ast;
pub mod semantic;
pub mod ssa_expr;

#[allow(unused_imports)] // public product surface
pub use artifact::{DecompileArtifact, DecompileEngine, DecompileMode, DecompileOptions};
#[allow(unused_imports)] // public product surface for callers/tests
pub use engine::{decompile_function_v2, decompile_function_v2_with_raw};
// Public surface also available as artifact::CheckReport / DecompileEngine.
