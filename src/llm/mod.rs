use crate::project::Project;

pub mod query;
pub mod verify;

/// Supported LLM providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Used by future LLM integration callers
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
#[allow(dead_code)] // Used by future LLM integration callers
pub trait LlmProvider: Send + Sync {
    fn explain(&self, project: &Project, function_va: u64) -> Result<String, String>;
    fn suggest_renames(
        &self,
        project: &Project,
        function_va: u64,
    ) -> Result<Vec<(u64, String)>, String>;
}

#[allow(dead_code)] // Used by future LLM integration callers
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
