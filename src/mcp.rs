//! MCP server exposing windy projects to external agents.
//!
//! The server is token-efficient: tools return bounded JSON summaries by default,
//! and agents must explicitly ask for full function exports or compact agent text.

use std:: net::SocketAddr;
use std::sync::Arc;

use axum::{Router, extract::State, response::IntoResponse, routing::post};
use http_body_util::BodyExt;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ErrorCode, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::json;
use uuid::Uuid;

use crate::decompiler::client::{DecompilerCacheKey, DecompilerClient};
use crate::project::comments::CommentScope;
use crate::project::op::Op;
use crate::project::symbols::SymbolKind;
use crate::project::types::{DataType, FunctionSignature};
use crate::project::workspace::WorkspaceId;
use crate::project_manager::{ProjectId, ProjectManager};

/// Data exposed to MCP clients.
#[derive(Clone)]
pub struct WindyMcp {
    manager: Arc<ProjectManager>,
    decompiler: Arc<DecompilerClient>,
}

impl WindyMcp {
    pub fn new(manager: Arc<ProjectManager>, decompiler: Arc<DecompilerClient>) -> Self {
        Self {
            manager,
            decompiler,
        }
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct OpenProjectParams {
    path: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListFunctionsParams {
    project_id: String,
    #[serde(default)]
    pattern: String,
    /// Skip this many matching functions (pagination cursor).
    #[serde(default)]
    offset: usize,
    /// Max results to return (default 32, hard cap 128).
    #[serde(default = "default_list_limit")]
    limit: usize,
}

fn default_list_limit() -> usize {
    32
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ProjectOnlyParams {
    project_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListStringsParams {
    project_id: String,
    #[serde(default = "default_min_len")]
    min_len: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_list_limit")]
    limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ReadVaParams {
    project_id: String,
    va: String,
    /// Bytes to read (default 64, hard cap 512).
    #[serde(default = "default_read_len")]
    len: usize,
}

fn default_read_len() -> usize {
    64
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EvidenceParams {
    project_id: String,
    va: String,
    /// Cap per list section (default 32, max 64).
    #[serde(default = "default_list_limit")]
    max_items: usize,
    /// Include truncated agent_text (default false).
    #[serde(default)]
    include_agent_text: bool,
    /// Max instructions when include_agent_text is true (default 64).
    #[serde(default = "default_agent_insns")]
    max_agent_instructions: usize,
}

fn default_agent_insns() -> usize {
    64
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct VerifyClaimsParams {
    project_id: String,
    claims: Vec<crate::llm::verify::Claim>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SetFunctionMemoryParams {
    project_id: String,
    va: String,
    /// Merge into existing card when true (default true).
    #[serde(default = "default_true")]
    merge: bool,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    key_apis: Vec<String>,
    #[serde(default)]
    key_strings: Vec<String>,
    #[serde(default)]
    purity: Option<String>,
    /// 0–100; 0 means leave existing on merge.
    #[serde(default)]
    confidence: u8,
    /// Auto-fill empty key_apis/key_strings from evidence (default true).
    #[serde(default = "default_true")]
    auto_seed: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListMemoryParams {
    project_id: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_list_limit")]
    limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CrossSimilarParams {
    workspace_id: String,
    /// Optional: rank only against this project+va.
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    va: String,
    #[serde(default = "default_list_limit")]
    limit: usize,
    /// Minimum Jaccard on API sets (default 0.25).
    #[serde(default = "default_jaccard")]
    min_jaccard: f64,
}

fn default_jaccard() -> f64 {
    0.25
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FunctionParams {
    project_id: String,
    va: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct RenameSymbolParams {
    project_id: String,
    va: String,
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SetCommentParams {
    project_id: String,
    va: String,
    text: String,
    #[serde(default = "default_address_scope")]
    scope: String,
}

fn default_address_scope() -> String {
    "address".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ApplyRenameBatchParams {
    project_id: String,
    function_va: String,
    #[serde(default)]
    dry_run: bool,
    renames: Vec<ComponentRename>,
    /// Optional evidence strings / cites for the claim-first write path (soft v1).
    #[serde(default)]
    evidence: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ComponentRename {
    /// One of: function | address_comment | function_comment | arg | local | address
    target: String,
    /// For target=arg: parameter index (0-based).
    #[serde(default)]
    index: Option<usize>,
    /// For target=local: signed stack offset, e.g. "-0x10" or "-16".
    #[serde(default)]
    stack_offset: Option<String>,
    /// For target=address: VA to rename or comment.
    #[serde(default)]
    va: Option<String>,
    new_name: String,
    /// Optional type to apply with the rename (arg/local/address globals).
    #[serde(default)]
    data_type: Option<DataType>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct UndoLastParams {
    project_id: String,
    #[serde(default = "default_client_id")]
    client_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DecompileFunctionParams {
    project_id: String,
    va: String,
    /// Optional seed pseudo-code for the model to refine (Ghidra, prior output, etc.).
    #[serde(default)]
    refine: Option<String>,
    /// Optional token budget for the returned text (~4 tokens per line).
    #[serde(default)]
    max_tokens: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AgentTextParams {
    project_id: String,
    va: String,
    /// Cap body instructions; emit a summary when truncated.
    #[serde(default)]
    max_instructions: Option<usize>,
    /// Strip cookie/prologue/epilogue noise (default true).
    #[serde(default = "default_true")]
    strip_noise: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DataflowParams {
    project_id: String,
    va: String,
    /// Max defs across all blocks (default 128).
    #[serde(default)]
    max_defs: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListApiSignaturesParams {
    /// DLL basename, e.g. "kernel32" or "ntdll". Empty lists all loaded DLLs.
    #[serde(default)]
    dll: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ContextParams {
    project_id: String,
    va: String,
    /// Optional token budget for the agent-text body.
    #[serde(default)]
    max_tokens: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CreateWorkspaceParams {
    #[serde(default)]
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WorkspaceParams {
    workspace_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AddFilesToWorkspaceParams {
    workspace_id: String,
    paths: Vec<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AddProjectToWorkspaceParams {
    workspace_id: String,
    project_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct RemoveFromWorkspaceParams {
    workspace_id: String,
    path: String,
}

fn default_client_id() -> String {
    "mcp".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SearchParams {
    project_id: String,
    query: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FunctionsNamedParams {
    project_id: String,
    pattern: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct StringsInFunctionParams {
    project_id: String,
    va: String,
    #[serde(default = "default_min_len")]
    min_len: usize,
}

fn default_min_len() -> usize {
    4
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct RetypeGlobalParams {
    project_id: String,
    va: String,
    data_type: DataType,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SetFunctionSignatureParams {
    project_id: String,
    va: String,
    signature: FunctionSignature,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SetFocusParams {
    project_id: String,
    va: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SsaSuggestion {
    va: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ApplySsaSuggestionsParams {
    project_id: String,
    function_va: String,
    suggestions: Vec<SsaSuggestion>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ApplyTypeRecoveryParams {
    project_id: String,
    function_va: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListVtableSignaturesParams {
    /// Interface name (e.g. IUnknown). Empty returns all loaded interfaces.
    #[serde(default)]
    interface: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CrossProjectParams {
    workspace_id: String,
    #[serde(default)]
    project_id: String,
}

#[tool_router]
impl WindyMcp {
    #[tool(description = "List all currently open projects with their ids, paths, function count and instruction count")]
    async fn list_projects(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let projects = self.manager.list();
        let arr: Vec<_> = projects
            .into_iter()
            .map(|(id, path, fns, insns)| {
                json!({
                    "project_id": id.to_string(),
                    "path": path.to_string_lossy(),
                    "functions": fns,
                    "instructions": insns,
                })
            })
            .collect();
        Ok(success_json(&arr))
    }

    #[tool(description = "Open a PE file (exe/dll/sys) and return the new project_id")]
    async fn open_project(
        &self,
        Parameters(params): Parameters<OpenProjectParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = self
            .manager
            .open(params.path)
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({ "project_id": id.to_string() })))
    }

    #[tool(description = "List functions in a project. Optional pattern filters names. Use offset+limit for pagination (default limit 32, max 128).")]
    async fn list_functions(
        &self,
        Parameters(params): Parameters<ListFunctionsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let needle = params.pattern.to_ascii_lowercase();
        let limit = params.limit.clamp(1, 128);
        let matched: Vec<_> = project
            .functions()
            .iter()
            .filter(|f| {
                let name = f.name(&project.symbols);
                needle.is_empty() || name.to_ascii_lowercase().contains(&needle)
            })
            .collect();
        let total = matched.len();
        let fns: Vec<_> = matched
            .into_iter()
            .skip(params.offset)
            .take(limit)
            .map(|f| {
                json!({
                    "va": format!("{:#x}", f.entry_va),
                    "name": f.name(&project.symbols),
                    "size": f.size(),
                    "blocks": f.blocks.len(),
                })
            })
            .collect();
        let next_offset = params.offset.saturating_add(fns.len());
        Ok(success_json(&json!({
            "functions": fns,
            "total": total,
            "offset": params.offset,
            "limit": limit,
            "next_offset": if next_offset < total { Some(next_offset) } else { None::<usize> },
            "truncated": next_offset < total,
        })))
    }

    #[tool(description = "List functions whose names contain a substring pattern.")]
    async fn functions_named(
        &self,
        Parameters(params): Parameters<FunctionsNamedParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let named = crate::llm::query::functions_named(&project, &params.pattern);
        let arr: Vec<_> = named
            .into_iter()
            .map(|(va, name)| json!({ "va": format!("{va:#x}"), "name": name }))
            .collect();
        Ok(success_json(&json!({ "functions": arr })))
    }

    #[tool(description = "Get a compact function summary card (name, blocks, instructions, callers, callees).")]
    async fn get_function_summary(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let summary = crate::llm::query::function_summary(&project, va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&summary))
    }

    #[tool(description = "One-shot evidence pack for a function: summary, apis, strings, call_sites, points_to, constants, entities, callers/callees. Prefer this before agent_text. Optional include_agent_text.")]
    async fn get_function_evidence(
        &self,
        Parameters(params): Parameters<EvidenceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let pack = crate::llm::query::function_evidence(
            &project,
            va,
            crate::llm::query::EvidenceOpts {
                max_items: params.max_items.clamp(1, 64),
                include_agent_text: params.include_agent_text,
                max_agent_instructions: params.max_agent_instructions.max(1),
            },
        )
        .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&pack))
    }

    #[tool(description = "Statically verify structured claims about a function. Claim kinds: calls_api (api), has_string (string), local_name (stack_offset+name), local_type (stack_offset+data_type|type_str), param_count (count), signature_arity (optional count). Returns supported|contradicted|unknown + evidence.")]
    async fn verify_claims(
        &self,
        Parameters(params): Parameters<VerifyClaimsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        if params.claims.is_empty() {
            return Err(invalid_params("claims must be non-empty"));
        }
        if params.claims.len() > 32 {
            return Err(invalid_params("at most 32 claims per call"));
        }
        let results = crate::llm::verify::verify_claims_logged(
            &project,
            &params.claims,
            Some(self.manager.home_dir()),
        );
        Ok(success_json(&json!({
            "results": results,
            "checker_ver": crate::llm::verify::CLAIM_CHECKER_VERSION,
            "contract": { "name": "claim_registry", "version": 1 },
        })))
    }

    #[tool(description = "Auto consistency report for a function (pass/warn/unknown checks): signature present, stack locals vs frame, import SigDB coverage, SSA simplify stats, call graph. Run after rename batches.")]
    async fn get_function_consistency(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let report = crate::llm::verify::function_consistency(&project, va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&report))
    }

    #[tool(description = "Read durable agent memory card for a function (purpose, tags, key_apis/strings). Survives IDB reload. Distinct from get_function_summary structural stats.")]
    async fn get_function_memory(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        match project.function_memory.get(&va) {
            Some(card) => Ok(success_json(&card.to_json())),
            None => Ok(success_json(&json!({
                "va": format!("{va:#x}"),
                "memory": null,
            }))),
        }
    }

    #[tool(description = "Write durable agent memory for a function. Prefer merge=true. Empty key_apis/key_strings auto-seed from evidence when auto_seed=true. Call after solid renames so future sessions skip rediscovery.")]
    async fn set_function_memory(
        &self,
        Parameters(params): Parameters<SetFunctionMemoryParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let va = parse_va(&params.va)?;
        let project = get_project(&self.manager, id)?;
        if project.function_at(va).is_none() {
            return Err(invalid_params("function not found"));
        }

        let mut card = if params.merge {
            project
                .function_memory
                .get(&va)
                .cloned()
                .unwrap_or_default()
        } else {
            crate::project::memory::FunctionMemoryCard::default()
        };
        card.va = va;
        if let Some(p) = params.purpose {
            card.purpose = Some(p);
        }
        if !params.tags.is_empty() {
            card.tags = params.tags;
        }
        if !params.key_apis.is_empty() {
            card.key_apis = params.key_apis;
        }
        if !params.key_strings.is_empty() {
            card.key_strings = params.key_strings;
        }
        if let Some(p) = params.purity {
            card.purity = Some(p);
        }
        if params.confidence > 0 {
            card.confidence = params.confidence.min(100);
        }

        if params.auto_seed && (card.key_apis.is_empty() || card.key_strings.is_empty()) {
            let apis = crate::llm::query::apis_called(&project, va);
            let strings = crate::llm::query::strings_in_function(&project, va, 4);
            if card.key_apis.is_empty() {
                card.key_apis = apis.into_iter().take(16).collect();
            }
            if card.key_strings.is_empty() {
                card.key_strings = strings
                    .into_iter()
                    .take(16)
                    .map(|s| s.value)
                    .collect();
            }
        }

        let op = Op::SetFunctionMemory {
            va,
            card: card.clone(),
            old: None,
        };
        let applied = self
            .manager
            .apply_op(id, "mcp", op)
            .await
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({
            "memory": card.to_json(),
            "op": applied,
        })))
    }

    #[tool(description = "List durable function memory cards in a project (paginated).")]
    async fn list_function_memory(
        &self,
        Parameters(params): Parameters<ListMemoryParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let limit = params.limit.clamp(1, 128);
        let mut cards: Vec<_> = project.function_memory.values().collect();
        cards.sort_by_key(|c| c.va);
        let total = cards.len();
        let page: Vec<_> = cards
            .into_iter()
            .skip(params.offset)
            .take(limit)
            .map(|c| c.to_json())
            .collect();
        let next = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "memory": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
        })))
    }

    #[tool(description = "Find similar functions across workspace members using API-set Jaccard + size/shape (not name-only). Pass optional project_id+va to query one function; else samples.")]
    async fn get_cross_project_similar(
        &self,
        Parameters(params): Parameters<CrossSimilarParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ws = parse_workspace_id(&params.workspace_id)?;
        let members = self
            .manager
            .workspace_projects(ws)
            .ok_or_else(|| invalid_params("workspace not found or empty"))?;
        let fps = crate::cross_project::build_fingerprints(&members);
        let query = if !params.project_id.is_empty() && !params.va.is_empty() {
            Some((parse_project_id(&params.project_id)?, parse_va(&params.va)?))
        } else {
            None
        };
        let pairs = crate::cross_project::find_similar(
            &fps,
            query,
            params.min_jaccard.clamp(0.0, 1.0),
            params.limit,
        );
        Ok(success_json(&json!({
            "pairs": pairs,
            "fingerprint_count": fps.len(),
        })))
    }

    #[tool(description = "Get the token-efficient annotated agent text for a function. Optional max_instructions truncates large bodies; strip_noise (default true) drops cookie/prologue noise.")]
    async fn get_function_agent_text(
        &self,
        Parameters(params): Parameters<AgentTextParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let text = project
            .function_agent_text_opts(
                va,
                crate::ir::agent_text::AgentTextOpts {
                    strip_noise: params.strip_noise,
                    max_instructions: params.max_instructions,
                },
            )
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(description = "Get the full structured JSON export for a function.")]
    async fn get_function_json(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let export = project
            .function_export(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&export))
    }

    #[tool(description = "Search the whole project for symbols, instructions, and strings containing a substring. Returns at most 32 hits.")]
    async fn search_summary(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let hits = crate::llm::query::search_summary(&project, &params.query);
        Ok(success_json(&json!({ "hits": hits })))
    }

    #[tool(description = "List printable strings referenced by a function's code.")]
    async fn strings_in_function(
        &self,
        Parameters(params): Parameters<StringsInFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let strings = crate::llm::query::strings_in_function(&project, va, params.min_len);
        let arr: Vec<_> = strings
            .into_iter()
            .map(|s| {
                json!({
                    "va": format!("{:#x}", s.va),
                    "value": s.value,
                    "encoding": s.encoding,
                })
            })
            .collect();
        Ok(success_json(&arr))
    }

    #[tool(description = "List imported APIs called from a function.")]
    async fn apis_called(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let apis = crate::llm::query::apis_called(&project, va);
        Ok(success_json(&apis))
    }

    #[tool(description = "List callers of a function together with the recovered parameter list.")]
    async fn callers_with_args(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let callers = crate::llm::query::callers_with_args(&project, va);
        Ok(success_json(&callers))
    }

    #[tool(description = "List functions that directly call a given function.")]
    async fn function_callers(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let callers = crate::llm::query::function_callers(&project, va);
        let arr: Vec<_> = callers
            .into_iter()
            .map(|(va, name)| json!({ "va": format!("{va:#x}"), "name": name }))
            .collect();
        Ok(success_json(&arr))
    }

    #[tool(description = "List functions / locations directly called from a function.")]
    async fn function_callees(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let callees = crate::llm::query::function_callees(&project, va);
        let arr: Vec<_> = callees
            .into_iter()
            .map(|(va, name)| json!({ "va": format!("{va:#x}"), "name": name }))
            .collect();
        Ok(success_json(&arr))
    }

    #[tool(description = "List xrefs to a virtual address with resolved names and xref kinds.")]
    async fn xrefs_to(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let xrefs = crate::llm::query::xrefs_to_named(&project, va);
        let arr: Vec<_> = xrefs
            .into_iter()
            .map(|(va, name, kind)| json!({ "va": format!("{va:#x}"), "name": name, "kind": kind }))
            .collect();
        Ok(success_json(&arr))
    }

    #[tool(description = "Get the optimized SSA summary for a function: op counts before/after copy+constant propagation, trivial-phi collapse, and conservative DCE.")]
    async fn get_function_ssa_optimized(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let summary = crate::llm::query::function_ssa_optimized_summary(&project, va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&summary))
    }

    #[tool(description = "Get SSA-derived suggestion comments (constants proven by simplification) ready to feed back into apply_ssa_suggestions.")]
    async fn get_function_ssa_suggestions(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let suggestions = project
            .function_ssa_suggestions(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        let arr: Vec<_> = suggestions
            .into_iter()
            .map(|(va, comment)| json!({ "va": format!("{va:#x}"), "comment": comment }))
            .collect();
        Ok(success_json(&arr))
    }

    #[tool(description = "Preview recovered types for a function over its optimized SSA: stack-local types and the refined return type. Read-only.")]
    async fn get_function_types(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let report = project
            .function_types_recovered(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&report))
    }

    #[tool(description = "Apply recovered types to a function: stack-local types + refined return signature, persisted as a single reversible Op::Batch.")]
    async fn apply_type_recovery(
        &self,
        Parameters(params): Parameters<ApplyTypeRecoveryParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let function_va = parse_va(&params.function_va)?;
        let project = get_project(&self.manager, id)?;
        let report = project
            .function_types_recovered(function_va)
            .ok_or_else(|| invalid_params("function not found"))?;
        let op = project.type_recovery_ops(&report);
        let applied = self
            .manager
            .apply_op(id, "mcp", op)
            .await
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({
            "applied": report.locals.iter().filter(|l| !matches!(l.ty, crate::decompiler::types::TyGuess::Unknown)).count(),
            "report": report,
            "op": applied,
        })))
    }

    #[tool(description = "Get context text (signature header, block labels, type annotations, and xrefs) for a function. Optional max_tokens bounds the agent-text body.")]
    async fn get_function_context(
        &self,
        Parameters(params): Parameters<ContextParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let text = project
            .function_context_text_bounded(va, params.max_tokens)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(description = "Compact SSA def-use dataflow JSON for a function (no assembly). Token-dense; optional max_defs (default 128) truncates large functions.")]
    async fn get_function_dataflow(
        &self,
        Parameters(params): Parameters<DataflowParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let value = project
            .function_dataflow_json(va, params.max_defs)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&value))
    }

    #[tool(description = "List call sites inside a function with traced argument sources (constant/global/local/param) and Win32 param names when known.")]
    async fn get_call_sites(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let value = project
            .call_sites_with_args(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&value))
    }

    #[tool(description = "Structured decompilation export: signature, variable table, blocks with region kinds, control-flow summary, and def_types. Machine-parseable alternative to free-form C.")]
    async fn get_function_decompilation_structured(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let value = project
            .function_decompile_structured(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&value))
    }

    #[tool(description = "List Win32 API signatures known to the SigDB. Pass dll (e.g. kernel32, ntdll) to list APIs for that DLL; empty dll returns the list of loaded DLLs.")]
    async fn list_api_signatures(
        &self,
        Parameters(params): Parameters<ListApiSignaturesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // SigDB is project-independent for bundled defaults; use first open
        // project if any, else load bundled-only.
        let db_owned;
        let db = if let Some((_, path, _, _)) = self.manager.list().into_iter().next() {
            // Prefer a live project's DB (includes user overlays).
            // list() returns (id, path, fns, insns) — re-open is heavy; load once.
            let _ = path;
            db_owned = crate::analysis::win32_sigs::SigDB::load();
            &db_owned
        } else {
            db_owned = crate::analysis::win32_sigs::SigDB::load();
            &db_owned
        };
        if params.dll.is_empty() {
            return Ok(success_json(&json!({
                "dlls": db.dlls(),
                "total_signatures": db.len(),
            })));
        }
        let sigs: Vec<_> = db
            .signatures_for_dll(&params.dll)
            .into_iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "params": s.params.iter().map(|(n, t)| json!([n, format!("{t:?}")])).collect::<Vec<_>>(),
                    "ret": format!("{:?}", s.ret),
                    "calling_conv": s.calling_conv,
                })
            })
            .collect();
        Ok(success_json(&json!({
            "dll": params.dll,
            "signatures": sigs,
            "count": sigs.len(),
        })))
    }

    #[tool(description = "Decompile a function to C-like pseudocode using the external GCLSD model. Optional refine text seeds refinement. Falls back to the native structurer (Phase 5) if the model service is unreachable.")]
    async fn decompile_function(
        &self,
        Parameters(params): Parameters<DecompileFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let mut input = project
            .function_gclsd_input(va)
            .ok_or_else(|| invalid_params("function not found or could not be exported"))?;
        // Auto-seed refine with native decompilation when the client did not
        // supply one (keeps GCLSD refinement grounded in structured output).
        input.refine = params
            .refine
            .or_else(|| project.function_decompile_native(va));
        let key = DecompilerCacheKey {
            image_sha256: project.image_sha256.clone(),
            va,
            op_seq: project.op_seq,
        };
        match self.decompiler.decompile(key, &input).await {
            Ok(output) => {
                let mut code = output.pseudocode;
                if let Some(budget) = params.max_tokens {
                    code = truncate_text_tokens(&code, budget);
                }
                Ok(success_json(&json!({ "pseudocode": code, "source": "gclsd" })))
            }
            Err(_e) => {
                // Graceful fallback: synthesize pseudo-C natively when the
                // GCLSD HTTP service is unavailable.
                let native = project
                    .function_decompile_native_bounded(va, params.max_tokens)
                    .ok_or_else(|| invalid_params("function not found"))?;
                Ok(success_json(&json!({ "pseudocode": native, "source": "native" })))
            }
        }
    }

    #[tool(description = "Decompile a function to C-like pseudocode using the native SSA structurer (no external model). Always native. Optional max_tokens truncates with a summary line.")]
    async fn decompile_function_native(
        &self,
        Parameters(params): Parameters<DecompileFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let pseudocode = project
            .function_decompile_native_bounded(va, params.max_tokens)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&json!({
            "pseudocode": pseudocode,
            "source": "native",
            "truncated": params.max_tokens.is_some() && pseudocode.contains("truncated"),
        })))
    }

    #[tool(description = "Rename a symbol at a virtual address.")]
    async fn rename_symbol(
        &self,
        Parameters(params): Parameters<RenameSymbolParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let va = parse_va(&params.va)?;
        let op = Op::RenameSymbol {
            va,
            name: params.name,
            kind: SymbolKind::User,
            old_name: None,
            old_kind: None,
        };
        apply_and_report(&self.manager, id, op, "mcp").await
    }

    #[tool(description = "Set a comment at a virtual address. scope is 'address' or 'function'.")]
    async fn set_comment(
        &self,
        Parameters(params): Parameters<SetCommentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let va = parse_va(&params.va)?;
        let scope = parse_scope(&params.scope)?;
        let op = Op::SetComment {
            va,
            scope,
            text: params.text,
            old_text: None,
        };
        apply_and_report(&self.manager, id, op, "mcp").await
    }

    #[tool(description = "Retype a global variable at a virtual address with a DataType (e.g. {\"Uint\":[32]} or {\"Ptr\":[{\"Int\":[8]}]}).")]
    async fn retype_global(
        &self,
        Parameters(params): Parameters<RetypeGlobalParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let va = parse_va(&params.va)?;
        let op = Op::SetGlobalType {
            va,
            ty: params.data_type,
            old_ty: None,
        };
        apply_and_report(&self.manager, id, op, "mcp").await
    }

    #[tool(description = "Override the recovered signature of a function at a virtual address.")]
    async fn set_function_signature(
        &self,
        Parameters(params): Parameters<SetFunctionSignatureParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let va = parse_va(&params.va)?;
        let op = Op::SetFunctionSignature {
            va,
            signature: params.signature,
            old_signature: None,
        };
        apply_and_report(&self.manager, id, op, "mcp").await
    }

    #[tool(description = "Set the focused function for a project to the function starting at a virtual address.")]
    async fn set_focus(
        &self,
        Parameters(params): Parameters<SetFocusParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let va = parse_va(&params.va)?;
        let op = Op::SetFocus {
            va,
            old_focus: None,
        };
        apply_and_report(&self.manager, id, op, "mcp").await
    }

    #[tool(description = "Apply SSA-derived renames and comments as a single reversible batch. Each suggestion maps a defining VA to an optional name and/or comment.")]
    async fn apply_ssa_suggestions(
        &self,
        Parameters(params): Parameters<ApplySsaSuggestionsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let _function_va = parse_va(&params.function_va)?;
        let mut ops = Vec::new();
        let mut preview = Vec::new();
        for s in params.suggestions {
            let va = parse_va(&s.va)?;
            if let Some(name) = s.name {
                ops.push(Op::RenameSymbol {
                    va,
                    name: name.clone(),
                    kind: SymbolKind::User,
                    old_name: None,
                    old_kind: None,
                });
                preview.push(json!({ "va": format!("{:#x}", va), "rename": name }));
            }
            if let Some(comment) = s.comment {
                ops.push(Op::SetComment {
                    va,
                    scope: CommentScope::Address,
                    text: comment.clone(),
                    old_text: None,
                });
                preview.push(json!({ "va": format!("{:#x}", va), "comment": comment }));
            }
        }
        let op = Op::Batch { ops };
        let applied = self
            .manager
            .apply_op(id, "mcp", op)
            .await
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({ "applied": preview.len(), "preview": preview, "op": applied })))
    }

    #[tool(description = "List rename/retype targets for a function: function id, args (arg:N), stack locals (local:-0x..). Call before apply_rename_batch.")]
    async fn get_function_entities(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let entities = project
            .function_entities(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&entities))
    }

    #[tool(description = "Apply structured renames/retypes to a function. Targets: function, arg (index), local (stack_offset like -0x10), address (va), address_comment, function_comment. Optional data_type on arg/local/address. Optional evidence[] cites for claim-first soft write path. Set dry_run to preview.")]
    async fn apply_rename_batch(
        &self,
        Parameters(params): Parameters<ApplyRenameBatchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let function_va = parse_va(&params.function_va)?;
        let mut ops = Vec::new();
        let mut preview = Vec::new();
        let evidence = params.evidence.clone();

        for r in params.renames {
            match r.target.as_str() {
                "function" => {
                    ops.push(Op::RenameSymbol {
                        va: function_va,
                        name: r.new_name.clone(),
                        kind: SymbolKind::User,
                        old_name: None,
                        old_kind: None,
                    });
                    preview.push(json!({
                        "target": "function",
                        "va": format!("{function_va:#x}"),
                        "new_name": r.new_name
                    }));
                }
                "address" => {
                    let va = parse_va(r.va.as_deref().unwrap_or("0"))?;
                    if va == 0 {
                        return Err(invalid_params("address target requires va"));
                    }
                    ops.push(Op::RenameSymbol {
                        va,
                        name: r.new_name.clone(),
                        kind: SymbolKind::User,
                        old_name: None,
                        old_kind: None,
                    });
                    if let Some(ty) = r.data_type.clone() {
                        ops.push(Op::SetGlobalType {
                            va,
                            ty: ty.clone(),
                            old_ty: None,
                        });
                        preview.push(json!({
                            "target": "address",
                            "va": format!("{va:#x}"),
                            "new_name": r.new_name,
                            "data_type": ty,
                        }));
                    } else {
                        preview.push(json!({
                            "target": "address",
                            "va": format!("{va:#x}"),
                            "new_name": r.new_name
                        }));
                    }
                }
                "address_comment" => {
                    let va = r
                        .va
                        .as_deref()
                        .map(parse_va)
                        .transpose()?
                        .unwrap_or(function_va);
                    ops.push(Op::SetComment {
                        va,
                        scope: CommentScope::Address,
                        text: r.new_name.clone(),
                        old_text: None,
                    });
                    preview.push(json!({
                        "target": "address_comment",
                        "va": format!("{va:#x}"),
                        "text": r.new_name
                    }));
                }
                "function_comment" => {
                    ops.push(Op::SetComment {
                        va: function_va,
                        scope: CommentScope::Function,
                        text: r.new_name.clone(),
                        old_text: None,
                    });
                    preview.push(json!({
                        "target": "function_comment",
                        "va": format!("{function_va:#x}"),
                        "text": r.new_name
                    }));
                }
                "arg" => {
                    let idx = r.index.unwrap_or(0);
                    if let Some(ty) = r.data_type.clone() {
                        // Name + type: single signature write so the batch cannot
                        // clobber names with a stale SetFunctionSignature.
                        let project = get_project(&self.manager, id)?;
                        let mut sig = project
                            .function_signatures
                            .get(&function_va)
                            .cloned()
                            .unwrap_or_else(|| FunctionSignature {
                                name: project
                                    .symbols
                                    .name(function_va)
                                    .unwrap_or("sub")
                                    .to_string(),
                                params: Vec::new(),
                                ret: DataType::Unknown(0),
                                calling_conv: None,
                            });
                        while sig.params.len() <= idx {
                            let i = sig.params.len();
                            sig.params
                                .push((format!("arg{i}"), DataType::Unknown(0)));
                        }
                        sig.params[idx] = (r.new_name.clone(), ty.clone());
                        ops.push(Op::SetFunctionSignature {
                            va: function_va,
                            signature: sig,
                            old_signature: None,
                        });
                        preview.push(json!({
                            "target": "arg",
                            "index": idx,
                            "new_name": r.new_name,
                            "data_type": ty,
                        }));
                    } else {
                        ops.push(Op::SetParamName {
                            function_va,
                            index: idx,
                            name: r.new_name.clone(),
                            old_name: None,
                        });
                        preview.push(json!({
                            "target": "arg",
                            "index": idx,
                            "new_name": r.new_name
                        }));
                    }
                }
                "local" => {
                    let off_str = r
                        .stack_offset
                        .as_deref()
                        .ok_or_else(|| invalid_params("local target requires stack_offset"))?;
                    let offset = parse_i64_offset(off_str)?;
                    ops.push(Op::SetStackLocalName {
                        function_va,
                        offset,
                        name: r.new_name.clone(),
                        old_name: None,
                    });
                    let mut card = json!({
                        "target": "local",
                        "stack_offset": off_str,
                        "offset": offset,
                        "new_name": r.new_name
                    });
                    if let Some(ty) = r.data_type.clone() {
                        ops.push(Op::SetStackLocalType {
                            function_va,
                            offset,
                            ty: ty.clone(),
                            old_ty: None,
                        });
                        card.as_object_mut()
                            .unwrap()
                            .insert("data_type".into(), serde_json::to_value(&ty).unwrap_or_default());
                    }
                    preview.push(card);
                }
                other => return Err(invalid_params(format!("unknown rename target: {other}"))),
            }
        }

        if params.dry_run {
            return Ok(success_json(&json!({
                "dry_run": true,
                "preview": preview,
                "evidence": evidence,
            })));
        }

        let op = Op::Batch { ops };
        let applied = self
            .manager
            .apply_op(id, "mcp", op)
            .await
            .map_err(|e| invalid_params(e.to_string()))?;
        // Soft claim-first path: record evidence cites alongside the op summary.
        if !evidence.is_empty() {
            tracing::info!(
                target: "windy::claims",
                function_va = format!("{function_va:#x}"),
                evidence = ?evidence,
                "apply_rename_batch with evidence cites"
            );
        }
        Ok(success_json(&json!({
            "applied": preview.len(),
            "preview": preview,
            "evidence": evidence,
            "op": applied,
        })))
    }

    #[tool(description = "Undo the last MCP operation for a project.")]
    async fn undo_last(
        &self,
        Parameters(params): Parameters<UndoLastParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let undone = self
            .manager
            .undo_last(id, &params.client_id)
            .await
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({ "undone": undone })))
    }

    #[tool(description = "Redo the last undone MCP operation for a project.")]
    async fn redo_last(
        &self,
        Parameters(params): Parameters<UndoLastParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let redone = self
            .manager
            .redo_last(id, &params.client_id)
            .await
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({ "redone": redone })))
    }

    #[tool(description = "Create a workspace for grouping related PE files.")]
    async fn create_workspace(
        &self,
        Parameters(params): Parameters<CreateWorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let name = if params.name.is_empty() {
            None
        } else {
            Some(params.name)
        };
        let id = self
            .manager
            .create_workspace(name)
            .map_err(|e| internal_error(e.to_string()))?;
        Ok(success_json(&json!({ "workspace_id": id.to_string() })))
    }

    #[tool(description = "Add PE files to a workspace. Each path is opened and the result is reported per file.")]
    async fn add_files_to_workspace(
        &self,
        Parameters(params): Parameters<AddFilesToWorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let results = self
            .manager
            .add_files_to_workspace(id, params.paths)
            .map_err(|e| invalid_params(e.to_string()))?;
        let arr: Vec<_> = results
            .into_iter()
            .map(|(path, res)| match res {
                Ok(project_id) => json!({
                    "path": path.to_string_lossy(),
                    "project_id": project_id.to_string(),
                    "error": serde_json::Value::Null,
                }),
                Err(e) => json!({
                    "path": path.to_string_lossy(),
                    "project_id": serde_json::Value::Null,
                    "error": e.to_string(),
                }),
            })
            .collect();
        Ok(success_json(&json!({ "results": arr })))
    }

    #[tool(description = "Add an already-open project to a workspace.")]
    async fn add_project_to_workspace(
        &self,
        Parameters(params): Parameters<AddProjectToWorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let workspace_id = parse_workspace_id(&params.workspace_id)?;
        let project_id = parse_project_id(&params.project_id)?;
        self.manager
            .add_project_to_workspace(workspace_id, project_id)
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({ "added": true })))
    }

    #[tool(description = "List all persisted workspaces.")]
    async fn list_workspaces(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let workspaces = self.manager.list_workspaces();
        Ok(success_json(&workspaces))
    }

    #[tool(description = "Get a workspace with its member list.")]
    async fn get_workspace(
        &self,
        Parameters(params): Parameters<WorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let ws = self
            .manager
            .get_workspace(id)
            .ok_or_else(|| invalid_params("workspace not found"))?;
        Ok(success_json(&ws))
    }

    #[tool(description = "Reopen every member of a workspace. Returns fresh project IDs per file.")]
    async fn open_workspace(
        &self,
        Parameters(params): Parameters<WorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_workspace_id(&params.workspace_id)?;
        let results = self
            .manager
            .open_workspace(id)
            .map_err(|e| invalid_params(e.to_string()))?;
        let arr: Vec<_> = results
            .into_iter()
            .map(|(path, res)| match res {
                Ok(project_id) => json!({
                    "path": path.to_string_lossy(),
                    "project_id": project_id.to_string(),
                    "error": serde_json::Value::Null,
                }),
                Err(e) => json!({
                    "path": path.to_string_lossy(),
                    "project_id": serde_json::Value::Null,
                    "error": e.to_string(),
                }),
            })
            .collect();
        Ok(success_json(&json!({ "results": arr })))
    }

    #[tool(description = "Remove a member path from a workspace.")]
    async fn remove_from_workspace(
        &self,
        Parameters(params): Parameters<RemoveFromWorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_workspace_id(&params.workspace_id)?;
        self.manager
            .remove_from_workspace(id, &params.path)
            .map_err(|e| invalid_params(e.to_string()))?;
        Ok(success_json(&json!({ "removed": true })))
    }

    // ── Phase 7 MCP tools ────────────────────────────────────────────────

    #[tool(description = "Get the points-to map for a function: each Load/Store resolved to Global/IATSlot/StackRef/ParamPtr/HeapUnknown.")]
    async fn get_function_points_to(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let value = project
            .function_points_to_json(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&value))
    }

    #[tool(description = "List COM/interface vtable signatures. Pass interface (e.g. IUnknown) for methods; empty returns loaded interface names.")]
    async fn list_vtable_signatures(
        &self,
        Parameters(params): Parameters<ListVtableSignaturesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let db = crate::analysis::vtable_sigs::VtableDB::load();
        if params.interface.is_empty() {
            return Ok(success_json(&json!({
                "interfaces": db.interfaces(),
                "total_methods": db.len(),
            })));
        }
        let Some(iface) = db.lookup(&params.interface) else {
            return Ok(success_json(&json!({
                "interface": params.interface,
                "methods": [],
                "error": "interface not found",
            })));
        };
        let methods: Vec<_> = iface
            .methods
            .iter()
            .map(|m| {
                json!({
                    "offset": m.offset,
                    "name": m.name,
                    "params": m.signature.params.iter().map(|(n, t)| json!([n, format!("{t:?}")])).collect::<Vec<_>>(),
                    "ret": format!("{:?}", m.signature.ret),
                })
            })
            .collect();
        Ok(success_json(&json!({
            "interface": iface.name,
            "methods": methods,
            "count": methods.len(),
        })))
    }

    #[tool(description = "List resolved COM/vtable calls inside a function (this->Method with param types when known).")]
    async fn get_vtable_calls(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let value = project
            .function_vtable_calls(va)
            .ok_or_else(|| invalid_params("function not found"))?;
        Ok(success_json(&value))
    }

    #[tool(description = "What does this binary import from other workspace members? Pass workspace_id and project_id.")]
    async fn get_cross_project_calls(
        &self,
        Parameters(params): Parameters<CrossProjectParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ws = parse_workspace_id(&params.workspace_id)?;
        let index = self
            .manager
            .cross_project_index(ws)
            .ok_or_else(|| invalid_params("workspace not found or no index"))?;
        if params.project_id.is_empty() {
            return Ok(success_json(&index.to_json()));
        }
        let pid = parse_project_id(&params.project_id)?;
        let imports: Vec<_> = index
            .imports_of(pid)
            .into_iter()
            .map(|c| {
                json!({
                    "importer": c.importer.to_string(),
                    "importer_va": format!("{:#x}", c.importer_va),
                    "exporter": c.exporter.to_string(),
                    "exporter_va": format!("{:#x}", c.exporter_va),
                    "api_name": c.api_name,
                })
            })
            .collect();
        Ok(success_json(&json!({ "imports": imports, "count": imports.len() })))
    }

    #[tool(description = "What does each workspace member export? Returns api_name → exporter list for the workspace.")]
    async fn get_cross_project_exports(
        &self,
        Parameters(params): Parameters<WorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ws = parse_workspace_id(&params.workspace_id)?;
        let index = self
            .manager
            .cross_project_index(ws)
            .ok_or_else(|| invalid_params("workspace not found or no index"))?;
        let exports: Vec<_> = index
            .by_api_name
            .iter()
            .map(|(name, list)| {
                json!({
                    "api_name": name,
                    "exporters": list.iter().map(|(pid, va)| json!({
                        "project_id": pid.to_string(),
                        "va": format!("{va:#x}"),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok(success_json(&json!({ "exports": exports, "count": exports.len() })))
    }

    #[tool(description = "High-level cross-binary call graph JSON for a workspace (import→export edges).")]
    async fn get_cross_project_dataflow(
        &self,
        Parameters(params): Parameters<WorkspaceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ws = parse_workspace_id(&params.workspace_id)?;
        let index = self
            .manager
            .cross_project_index(ws)
            .ok_or_else(|| invalid_params("workspace not found or no index"))?;
        Ok(success_json(&index.to_json()))
    }

    #[tool(description = "List PE imports (DLL + API names). Paginated with offset/limit (default 32, max 128).")]
    async fn list_imports(
        &self,
        Parameters(params): Parameters<ListStringsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let limit = params.limit.clamp(1, 128);
        let mut items = Vec::new();
        if let Some(imports) = &project.pe.triage.imports {
            for entry in imports {
                for api in &entry.functions {
                    items.push(json!({
                        "dll": entry.dll,
                        "name": api.name,
                    }));
                }
            }
        }
        if items.is_empty() {
            for (va, sym) in project.symbols.iter() {
                if let Some(api) = sym.name.strip_prefix("__imp_") {
                    items.push(json!({
                        "dll": null,
                        "name": api,
                        "iat_va": format!("{va:#x}"),
                    }));
                }
            }
        }
        let total = items.len();
        let page: Vec<_> = items
            .into_iter()
            .skip(params.offset)
            .take(limit)
            .collect();
        let next = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "imports": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
        })))
    }

    #[tool(description = "List PE exports (name + VA when available). Paginated (offset/limit, max 128).")]
    async fn list_exports(
        &self,
        Parameters(params): Parameters<ListStringsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let limit = params.limit.clamp(1, 128);
        let mut items = Vec::new();
        if let Ok(val) = serde_json::to_value(&project.pe.triage.exports) {
            match val {
                serde_json::Value::Array(arr) => items.extend(arr),
                serde_json::Value::Null => {}
                other => items.push(other),
            }
        }
        if items.is_empty() {
            for (va, sym) in project.symbols.iter() {
                if sym.kind == SymbolKind::Export {
                    items.push(json!({
                        "name": sym.name,
                        "va": format!("{va:#x}"),
                    }));
                }
            }
        }
        let total = items.len();
        let page: Vec<_> = items
            .into_iter()
            .skip(params.offset)
            .take(limit)
            .collect();
        let next = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "exports": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
        })))
    }

    #[tool(description = "List PE sections (name, VA, size, characteristics).")]
    async fn list_sections(
        &self,
        Parameters(params): Parameters<ProjectOnlyParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let sections = project.pe.triage.sections.as_deref().unwrap_or_default();
        let arr: Vec<_> = sections
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "virtual_address": s.virtual_address,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "characteristics": s.characteristics,
                })
            })
            .collect();
        Ok(success_json(&json!({ "sections": arr, "count": arr.len() })))
    }

    #[tool(description = "List printable strings from the PE triage table. min_len filters length; offset/limit paginate (max 128).")]
    async fn list_strings(
        &self,
        Parameters(params): Parameters<ListStringsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let limit = params.limit.clamp(1, 128);
        let min_len = params.min_len.max(1);
        let mut items = Vec::new();
        if let Some(strings) = &project.pe.triage.strings {
            for s in strings {
                if s.value.len() < min_len {
                    continue;
                }
                items.push(json!({
                    "offset": s.offset,
                    "encoding": s.encoding,
                    "value": s.value,
                }));
            }
        }
        let total = items.len();
        let page: Vec<_> = items
            .into_iter()
            .skip(params.offset)
            .take(limit)
            .collect();
        let next = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "strings": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
        })))
    }

    #[tool(description = "Read up to len bytes at a VA as hex (default 64, hard cap 512). Prefer evidence tools first; use only when needed.")]
    async fn read_va(
        &self,
        Parameters(params): Parameters<ReadVaParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let len = params.len.clamp(1, 512);
        let bytes = project
            .address_space
            .slice_for_va(&project.pe.image, va, len)
            .ok_or_else(|| invalid_params("VA not mapped or out of range"))?;
        let hex: String = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(success_json(&json!({
            "va": format!("{va:#x}"),
            "len": bytes.len(),
            "hex": hex,
            "cite": { "kind": "data", "va": format!("{va:#x}") },
        })))
    }

    #[tool(description = "Bounded fragment excerpt at a VA (alias of read_va with cite). Cap 512 bytes. Prefer get_function_evidence first.")]
    async fn get_fragment(
        &self,
        Parameters(params): Parameters<ReadVaParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.read_va(Parameters(params)).await
    }

    #[tool(description = "List symbol rename lineage (old→new) for a project. Pass va to filter one address; use va=0 or omit via 0x0 for all.")]
    async fn get_alias_history(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let filter_va = parse_va(&params.va).unwrap_or(0);
        let filter = if filter_va == 0 { None } else { Some(filter_va) };
        let events: Vec<_> = project
            .alias_history
            .iter()
            .filter(|e| filter.is_none_or(|va| e.va == va))
            .rev()
            .take(64)
            .map(|e| {
                json!({
                    "va": format!("{:#x}", e.va),
                    "old_name": e.old_name,
                    "new_name": e.new_name,
                    "source": e.source,
                    "seq": e.seq,
                })
            })
            .collect();
        Ok(success_json(&json!({ "aliases": events, "count": events.len() })))
    }
}

#[tool_handler]
impl ServerHandler for WindyMcp {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.protocol_version = rmcp::model::ProtocolVersion::V_2024_11_05;
        info.server_info = rmcp::model::Implementation::from_build_env();
        info.instructions = Some(
            "Windy is a pure MCP reverse-engineering substrate for external agents \
             (OpenCode, Claude, Cursor, etc.). Windy does not plan — you do. \
             Ladder: open_project → list_functions/list_imports/list_strings/search_summary → \
             get_function_evidence (prefer; includes memory if set) → apply_rename_batch → \
             verify_claims / get_function_consistency → set_function_memory (purpose/tags) → \
             re-read evidence. Multi-DLL: get_cross_project_similar. Prefer evidence over decompile."
                .to_string(),
        );
        info
    }
}

fn success_json(value: &impl serde::Serialize) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string(value).unwrap_or_default(),
    )])
}

fn get_project(manager: &ProjectManager, id: ProjectId) -> Result<Arc<crate::project::Project>, rmcp::ErrorData> {
    manager
        .get(id)
        .ok_or_else(|| invalid_params("project not found"))
}

async fn apply_and_report(
    manager: &ProjectManager,
    id: ProjectId,
    op: Op,
    client_id: &str,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let applied = manager
        .apply_op(id, client_id, op)
        .await
        .map_err(|e| invalid_params(e.to_string()))?;
    Ok(success_json(&json!({ "applied": applied })))
}

fn truncate_text_tokens(text: &str, max_tokens: usize) -> String {
    let max_lines = max_tokens / 4;
    if max_lines == 0 {
        return "// truncated\n".to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= max_lines {
        return text.to_string();
    }
    let mut out = lines[..max_lines].join("\n");
    out.push_str(&format!(
        "\n// ... {} more lines truncated. Call get_function_dataflow for full SSA.\n",
        lines.len() - max_lines
    ));
    out
}

fn invalid_params(message: impl Into<String>) -> rmcp::ErrorData {
    rmcp::ErrorData::new(ErrorCode::INVALID_PARAMS, message.into(), None)
}

fn internal_error(message: impl Into<String>) -> rmcp::ErrorData {
    rmcp::ErrorData::new(ErrorCode::INTERNAL_ERROR, message.into(), None)
}

fn parse_project_id(s: &str) -> Result<ProjectId, rmcp::ErrorData> {
    Uuid::parse_str(s).map_err(|e| invalid_params(format!("bad project_id: {e}")))
}

fn parse_workspace_id(s: &str) -> Result<WorkspaceId, rmcp::ErrorData> {
    Uuid::parse_str(s).map_err(|e| invalid_params(format!("bad workspace_id: {e}")))
}

fn parse_va(s: &str) -> Result<u64, rmcp::ErrorData> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        s.parse()
    }
    .map_err(|e| invalid_params(format!("bad va: {e}")))
}

fn parse_i64_offset(s: &str) -> Result<i64, rmcp::ErrorData> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        i64::from_str_radix(hex, 16)
            .map(|v| -v)
            .map_err(|e| invalid_params(format!("bad stack_offset: {e}")))
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|e| invalid_params(format!("bad stack_offset: {e}")))
    } else {
        s.parse::<i64>()
            .map_err(|e| invalid_params(format!("bad stack_offset: {e}")))
    }
}

fn parse_scope(s: &str) -> Result<CommentScope, rmcp::ErrorData> {
    match s {
        "address" => Ok(CommentScope::Address),
        "function" => Ok(CommentScope::Function),
        other => Err(invalid_params(format!("bad scope: {other}"))),
    }
}

type McpService = StreamableHttpService<WindyMcp, LocalSessionManager>;

async fn mcp_http_handler(
    State(service): State<Arc<McpService>>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let response = service.handle(req).await;
    let (parts, body) = response.into_parts();
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            axum::response::Response::from_parts(parts, axum::body::Body::from(bytes))
        }
        Err(e) => axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from(format!("body read error: {e}")))
            .unwrap(),
    }
}

/// Start the streamable-HTTP MCP server on `bind`.  Returns the bound port.
pub async fn serve_http(
    manager: Arc<ProjectManager>,
    decompiler: Arc<DecompilerClient>,
    bind: SocketAddr,
) -> anyhow::Result<u16> {
    let session_manager = Arc::new(LocalSessionManager::default());
    let service = Arc::new(StreamableHttpService::new(
        move || {
            Ok(WindyMcp::new(
                manager.clone(),
                decompiler.clone(),
            ))
        },
        session_manager,
        StreamableHttpServerConfig::default(),
    ));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/mcp", post(mcp_http_handler))
        .with_state(service);

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("MCP HTTP server error: {e}");
        }
    });

    Ok(port)
}
