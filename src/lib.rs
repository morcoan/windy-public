//! Windy library core — the headless analysis substrate behind the MCP host.
//!
//! Product interaction is deliberately MCP-only. Evaluation clients live in
//! workspace crates and connect through the same public protocol as agents.

pub mod analysis;
pub mod build_info;
pub mod cross_project;
pub mod decomp_scorecard;
pub mod decompiler;
pub mod disasm;
pub mod eval_metrics;
pub mod grand_bench;
pub mod ir;
pub mod llm;
pub mod loader;
pub mod mcp;
pub mod project;
pub mod project_manager;
