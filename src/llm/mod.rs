#![allow(dead_code)] // LLM seam; actively used in Phase 7

use crate::project::Project;

/// Supported LLM providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    OpenAI,
    AnthropicClaude,
    GoogleGemini,
    OllamaLocal,
}

/// Provider-agnostic LLM interface.
///
/// Implemented as a stub seam in Phase 0/1; real request logic is added when
/// we reach the LLM phase.
pub trait LlmProvider: Send + Sync {
    fn explain(&self, project: &Project, function_va: u64) -> Result<String, String>;
    fn suggest_renames(
        &self,
        project: &Project,
        function_va: u64,
    ) -> Result<Vec<(u64, String)>, String>;
}

pub struct StubProvider;

impl LlmProvider for StubProvider {
    fn explain(&self, _project: &Project, _function_va: u64) -> Result<String, String> {
        Err("LLM integration not implemented yet".to_string())
    }

    fn suggest_renames(
        &self,
        _project: &Project,
        _function_va: u64,
    ) -> Result<Vec<(u64, String)>, String> {
        Err("LLM integration not implemented yet".to_string())
    }
}
