//! MCP server exposing windy projects to external agents.
//!
//! The server is token-efficient: tools return bounded JSON summaries by default,
//! and agents must explicitly ask for full function exports or compact agent text.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use http_body_util::BodyExt;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ErrorCode, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde_json::json;
use uuid::Uuid;

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
}

impl WindyMcp {
    pub fn new(manager: Arc<ProjectManager>) -> Self {
        Self { manager }
    }

    fn decompile_native_result(
        &self,
        params: DecompileFunctionParams,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = match Uuid::parse_str(&params.project_id) {
            Ok(id) => id,
            Err(error) => {
                return Ok(tool_error_json(
                    "INVALID_PROJECT_ID",
                    format!("bad project_id: {error}"),
                    json!({ "project_id": params.project_id }),
                    false,
                ));
            }
        };
        let Some(project) = self.manager.get(id) else {
            return Ok(tool_error_json(
                "PROJECT_NOT_FOUND",
                "project not found",
                json!({ "project_id": id.to_string() }),
                false,
            ));
        };
        let va = match parse_va(&params.va) {
            Ok(va) => va,
            Err(_) => {
                return Ok(tool_error_json(
                    "INVALID_VA",
                    "va must be hexadecimal (0x...) or decimal",
                    json!({ "va": params.va }),
                    false,
                ));
            }
        };
        let options = match params.policy {
            DecompilePolicy::Product => crate::decompiler::v2::DecompileOptions::production(),
            DecompilePolicy::PureV2 => crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            DecompilePolicy::Legacy => crate::decompiler::v2::DecompileOptions::legacy_only(),
        };
        let Some(artifact) = project.function_decompile_artifact(va, options) else {
            return Ok(tool_error_json(
                "FUNCTION_NOT_FOUND",
                "function not found or native decompilation failed",
                json!({ "project_id": id.to_string(), "va": format!("{va:#x}") }),
                false,
            ));
        };

        let rejected_v2 = artifact.engine == crate::decompiler::v2::DecompileEngine::V2
            && !artifact.check_report.accepted;
        let omitted = artifact.text.trim().is_empty()
            || matches!(params.policy, DecompilePolicy::PureV2) && rejected_v2
            || matches!(params.policy, DecompilePolicy::Product) && rejected_v2;
        let (pseudocode, truncated) = if omitted {
            (None, false)
        } else if let Some(max_tokens) = params.max_tokens {
            let (text, truncated) = truncate_text_tokens_with_flag(&artifact.text, max_tokens);
            (Some(text), truncated)
        } else {
            (Some(artifact.text.clone()), false)
        };

        let mut output = json!({
            "project_id": id.to_string(),
            "va": format!("{va:#x}"),
            "status": if omitted { "omitted" } else { "ok" },
            "pseudocode": pseudocode,
            "source": "native",
            "engine": artifact.engine,
            "policy": params.policy,
            "truncated": truncated,
            "check_report": artifact.check_report,
            "contract_fingerprint": artifact.contract_fingerprint,
        });
        if let Some(reason) = artifact.fallback_reason {
            output
                .as_object_mut()
                .expect("decompile result is an object")
                .insert("fallback_reason".to_string(), json!(reason));
        }
        Ok(success_json(&output))
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

#[derive(
    Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
enum DecompilePolicy {
    #[default]
    Product,
    PureV2,
    Legacy,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DecompileFunctionParams {
    project_id: String,
    va: String,
    /// Optional token budget for the returned text (~4 tokens per line).
    #[serde(default)]
    max_tokens: Option<usize>,
    /// product (default), pure_v2 (no fallback), or legacy.
    #[serde(default)]
    policy: DecompilePolicy,
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
    #[tool(
        description = "List all currently open projects with their ids, paths, function count and instruction count"
    )]
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

    #[tool(
        description = "List functions in a project. Optional pattern filters names. Use offset+limit for pagination (default limit 32, max 128)."
    )]
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

    #[tool(
        description = "Get a compact function summary card (name, blocks, instructions, callers, callees)."
    )]
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

    #[tool(
        description = "One-shot evidence pack for a function: summary, apis, strings, call_sites, points_to, constants, entities, callers/callees. Prefer this before agent_text. Optional include_agent_text."
    )]
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

    #[tool(
        description = "Statically verify structured claims about a function. Claim kinds: calls_api (api), has_string (string), local_name (stack_offset+name), local_type (stack_offset+data_type|type_str), param_count (count), signature_arity (optional count). Returns supported|contradicted|unknown + evidence."
    )]
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
        )
        .map_err(|error| internal_error(format!("append claim journal: {error}")))?;
        Ok(success_json(&json!({
            "results": results,
            "checker_ver": crate::llm::verify::CLAIM_CHECKER_VERSION,
            "contract": { "name": "claim_registry", "version": 1 },
        })))
    }

    #[tool(
        description = "Auto consistency report for a function (pass/warn/unknown checks): signature present, stack locals vs frame, import SigDB coverage, SSA simplify stats, call graph. Run after rename batches."
    )]
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

    #[tool(
        description = "Read durable agent memory card for a function (purpose, tags, key_apis/strings). Survives IDB reload. Distinct from get_function_summary structural stats."
    )]
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

    #[tool(
        description = "Write durable agent memory for a function. Prefer merge=true. Empty key_apis/key_strings auto-seed from evidence when auto_seed=true. Call after solid renames so future sessions skip rediscovery."
    )]
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
                card.key_strings = strings.into_iter().take(16).map(|s| s.value).collect();
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

    #[tool(
        description = "Find similar functions across workspace members using API-set Jaccard + size/shape (not name-only). Pass optional project_id+va to query one function; else samples."
    )]
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

    #[tool(
        description = "Get the token-efficient annotated agent text for a function. Optional max_instructions truncates large bodies; strip_noise (default true) drops cookie/prologue noise."
    )]
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

    #[tool(
        description = "Search the whole project for symbols, instructions, and strings containing a substring. Returns at most 32 hits."
    )]
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

    #[tool(
        description = "Get the optimized SSA summary for a function: op counts before/after copy+constant propagation, trivial-phi collapse, and conservative DCE."
    )]
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

    #[tool(
        description = "Get SSA-derived suggestion comments (constants proven by simplification) ready to feed back into apply_ssa_suggestions."
    )]
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

    #[tool(
        description = "Preview recovered types for a function over its optimized SSA: stack-local types and the refined return type. Read-only."
    )]
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

    #[tool(
        description = "Apply recovered types to a function: stack-local types + refined return signature, persisted as a single reversible Op::Batch."
    )]
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

    #[tool(
        description = "Get context text (signature header, block labels, type annotations, and xrefs) for a function. Optional max_tokens bounds the agent-text body."
    )]
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

    #[tool(
        description = "Compact SSA def-use dataflow JSON for a function (no assembly). Token-dense; optional max_defs (default 128) truncates large functions."
    )]
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

    #[tool(
        description = "List call sites inside a function with traced argument sources (constant/global/local/param) and Win32 param names when known."
    )]
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

    #[tool(
        description = "Structured decompilation export: signature, variable table, blocks with region kinds, control-flow summary, and def_types. Machine-parseable alternative to free-form C."
    )]
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

    #[tool(
        description = "List Win32 API signatures known to the SigDB. Pass dll (e.g. kernel32, ntdll) to list APIs for that DLL; empty dll returns the list of loaded DLLs."
    )]
    async fn list_api_signatures(
        &self,
        Parameters(params): Parameters<ListApiSignaturesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let db = crate::analysis::win32_sigs::SigDB::load_from(self.manager.home_dir());
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

    #[tool(
        description = "Decompile with Windy's native checked pipeline. policy=product uses V2 with explicit Legacy fallback; pure_v2 never falls back; legacy is for comparison. Returns engine/checker metadata."
    )]
    async fn decompile_function(
        &self,
        Parameters(params): Parameters<DecompileFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.decompile_native_result(params)
    }

    #[tool(
        description = "Deprecated v0.1 alias of decompile_function. Uses the same native policy and structured result; prefer decompile_function."
    )]
    async fn decompile_function_native(
        &self,
        Parameters(params): Parameters<DecompileFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.decompile_native_result(params)
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

    #[tool(
        description = "Retype a global variable at a virtual address with a DataType (e.g. {\"Uint\":[32]} or {\"Ptr\":[{\"Int\":[8]}]})."
    )]
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

    #[tool(
        description = "Set the focused function for a project to the function starting at a virtual address."
    )]
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

    #[tool(
        description = "Apply SSA-derived renames and comments as a single reversible batch. Each suggestion maps a defining VA to an optional name and/or comment."
    )]
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
        Ok(success_json(
            &json!({ "applied": preview.len(), "preview": preview, "op": applied }),
        ))
    }

    #[tool(
        description = "List rename/retype targets for a function: function id, args (arg:N), stack locals (local:-0x..). Call before apply_rename_batch."
    )]
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

    #[tool(
        description = "Apply structured renames/retypes to a function. Targets: function, arg (index), local (stack_offset like -0x10), address (va), address_comment, function_comment. Optional data_type on arg/local/address. Optional evidence[] cites for claim-first soft write path. Set dry_run to preview."
    )]
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
                    let va =
                        r.va.as_deref()
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
                            sig.params.push((format!("arg{i}"), DataType::Unknown(0)));
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
                        card.as_object_mut().unwrap().insert(
                            "data_type".into(),
                            serde_json::to_value(&ty).unwrap_or_default(),
                        );
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

    #[tool(
        description = "Add PE files to a workspace. Each path is opened and the result is reported per file."
    )]
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

    #[tool(
        description = "Get the points-to map for a function: each Load/Store resolved to Global/IATSlot/StackRef/ParamPtr/HeapUnknown."
    )]
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

    #[tool(
        description = "List COM/interface vtable signatures. Pass interface (e.g. IUnknown) for methods; empty returns loaded interface names."
    )]
    async fn list_vtable_signatures(
        &self,
        Parameters(params): Parameters<ListVtableSignaturesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let db = crate::analysis::vtable_sigs::VtableDB::load_from(self.manager.home_dir());
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

    #[tool(
        description = "List resolved COM/vtable calls inside a function (this->Method with param types when known)."
    )]
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

    #[tool(
        description = "What does this binary import from other workspace members? Pass workspace_id and project_id."
    )]
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
        Ok(success_json(
            &json!({ "imports": imports, "count": imports.len() }),
        ))
    }

    #[tool(
        description = "What does each workspace member export? Returns api_name → exporter list for the workspace."
    )]
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
        Ok(success_json(
            &json!({ "exports": exports, "count": exports.len() }),
        ))
    }

    #[tool(
        description = "High-level cross-binary call graph JSON for a workspace (import→export edges)."
    )]
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

    #[tool(
        description = "List PE imports (DLL + API names). Paginated with offset/limit (default 32, max 128)."
    )]
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
        let page: Vec<_> = items.into_iter().skip(params.offset).take(limit).collect();
        let next = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "imports": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
        })))
    }

    #[tool(
        description = "List PE exports (name + VA when available). Paginated (offset/limit, max 128)."
    )]
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
        let page: Vec<_> = items.into_iter().skip(params.offset).take(limit).collect();
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
        Ok(success_json(
            &json!({ "sections": arr, "count": arr.len() }),
        ))
    }

    #[tool(
        description = "List printable strings from the PE triage table. min_len filters length; offset/limit paginate (max 128)."
    )]
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
        let page: Vec<_> = items.into_iter().skip(params.offset).take(limit).collect();
        let next = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "strings": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
        })))
    }

    #[tool(
        description = "Read up to len bytes at a VA as hex (default 64, hard cap 512). Prefer evidence tools first; use only when needed."
    )]
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

    #[tool(
        description = "Bounded fragment excerpt at a VA (alias of read_va with cite). Cap 512 bytes. Prefer get_function_evidence first."
    )]
    async fn get_fragment(
        &self,
        Parameters(params): Parameters<ReadVaParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.read_va(Parameters(params)).await
    }

    #[tool(
        description = "List symbol rename lineage (old→new) for a project. Pass va to filter one address; use va=0 or omit via 0x0 for all."
    )]
    async fn get_alias_history(
        &self,
        Parameters(params): Parameters<FunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let filter_va = parse_va(&params.va).unwrap_or(0);
        let filter = if filter_va == 0 {
            None
        } else {
            Some(filter_va)
        };
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
        Ok(success_json(
            &json!({ "aliases": events, "count": events.len() }),
        ))
    }
}

#[tool_handler]
impl ServerHandler for WindyMcp {
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let tool_context =
            rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        match Self::tool_router().call(tool_context).await {
            Ok(result) => Ok(result),
            Err(error) => {
                let message = error.message.into_owned();
                let code = if message.to_ascii_lowercase().contains("not found") {
                    "NOT_FOUND"
                } else if error.code == ErrorCode::INVALID_PARAMS {
                    "INVALID_ARGUMENT"
                } else if error.code == ErrorCode::RESOURCE_NOT_FOUND {
                    "NOT_FOUND"
                } else {
                    "TOOL_EXECUTION_FAILED"
                };
                Ok(tool_error_json(
                    code,
                    message,
                    json!({ "rpc_code": error.code.0, "data": error.data }),
                    error.code == ErrorCode::INTERNAL_ERROR,
                ))
            }
        }
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListToolsResult {
            tools: Self::tool_router()
                .list_all()
                .into_iter()
                .map(annotate_tool)
                .collect(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        Self::tool_router().get(name).cloned().map(annotate_tool)
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.protocol_version = rmcp::model::ProtocolVersion::LATEST;
        info.server_info = rmcp::model::Implementation::new("windy", env!("CARGO_PKG_VERSION"))
            .with_title("Windy")
            .with_description(
                "Static Windows PE reverse-engineering workbench and pure MCP substrate",
            );
        info.instructions = Some(
            "Windy is a local, static PE analysis substrate; the MCP client owns planning. \
             Recommended ladder: list_projects/open_project; triage with imports, exports, strings, \
             sections, and search_summary; inspect list_functions; prefer get_function_evidence; \
             write back with apply_rename_batch; check verify_claims/get_function_consistency; \
             persist conclusions with set_function_memory; then re-read evidence. Use \
             get_cross_project_similar for multi-binary workspaces."
                .to_string(),
        );
        info
    }
}

fn annotate_tool(mut tool: rmcp::model::Tool) -> rmcp::model::Tool {
    let name = tool.name.as_ref();
    let stateful = matches!(
        name,
        "open_project"
            | "verify_claims"
            | "set_function_memory"
            | "apply_type_recovery"
            | "rename_symbol"
            | "set_comment"
            | "retype_global"
            | "set_function_signature"
            | "set_focus"
            | "apply_ssa_suggestions"
            | "apply_rename_batch"
            | "undo_last"
            | "redo_last"
            | "create_workspace"
            | "add_files_to_workspace"
            | "add_project_to_workspace"
            | "open_workspace"
            | "remove_from_workspace"
    );
    let destructive = matches!(name, "remove_from_workspace");
    tool.annotations = Some(
        rmcp::model::ToolAnnotations::with_title(tool_title(name))
            .read_only(!stateful)
            .destructive(destructive)
            .idempotent(!stateful)
            .open_world(false),
    );
    tool
}

fn tool_title(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + chars.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn success_json(value: &impl serde::Serialize) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(value) => CallToolResult::structured(value),
        Err(error) => tool_error_json("SERIALIZATION_ERROR", error.to_string(), json!({}), false),
    }
}

fn tool_error_json(
    code: &str,
    message: impl Into<String>,
    details: serde_json::Value,
    retryable: bool,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "error": {
            "code": code,
            "message": message.into(),
            "details": details,
            "retryable": retryable,
        }
    }))
}

fn get_project(
    manager: &ProjectManager,
    id: ProjectId,
) -> Result<Arc<crate::project::Project>, rmcp::ErrorData> {
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

fn truncate_text_tokens_with_flag(text: &str, max_tokens: usize) -> (String, bool) {
    let max_lines = max_tokens / 4;
    if max_lines == 0 {
        return ("// truncated\n".to_string(), true);
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= max_lines {
        return (text.to_string(), false);
    }
    let mut out = lines[..max_lines].join("\n");
    out.push_str(&format!(
        "\n// ... {} more lines truncated. Call get_function_dataflow for full SSA.\n",
        lines.len() - max_lines
    ));
    (out, true)
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

async fn enforce_loopback_origin(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(origin) = req.headers().get(axum::http::header::ORIGIN)
        && !origin.to_str().ok().is_some_and(origin_is_loopback)
    {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("forbidden Origin"))
            .unwrap();
    }
    next.run(req).await
}

fn origin_is_loopback(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<axum::http::Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let host = authority.host().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "name": "windy",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": rmcp::model::ProtocolVersion::LATEST.as_str(),
    }))
}

/// Handle for a running local MCP server.
pub struct McpServerHandle {
    port: u16,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    finished: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl McpServerHandle {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Stop accepting requests and wait briefly for graceful completion.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(finished) = self.finished.take() {
            tokio::time::timeout(std::time::Duration::from_secs(5), finished)
                .await
                .map_err(|_| anyhow::anyhow!("timed out waiting for MCP server shutdown"))?
                .map_err(|_| anyhow::anyhow!("MCP server shutdown task was cancelled"))?;
        }
        Ok(())
    }
}

impl Drop for McpServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Start the streamable-HTTP MCP server on `bind`.
pub async fn serve_http(
    manager: Arc<ProjectManager>,
    bind: SocketAddr,
) -> anyhow::Result<McpServerHandle> {
    anyhow::ensure!(
        bind.ip().is_loopback(),
        "Windy v0.1 MCP is local-only; refusing non-loopback bind {}",
        bind.ip()
    );
    let session_manager = Arc::new(LocalSessionManager::default());
    let service = Arc::new(StreamableHttpService::new(
        move || Ok(WindyMcp::new(manager.clone())),
        session_manager,
        StreamableHttpServerConfig::default(),
    ));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route("/mcp", post(mcp_http_handler))
        .route("/healthz", get(healthz))
        .with_state(service)
        .layer(axum::middleware::from_fn(enforce_loopback_origin));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
        {
            tracing::error!("MCP HTTP server error: {e}");
        }
        let _ = finished_tx.send(());
    });

    Ok(McpServerHandle {
        port,
        shutdown: Some(shutdown_tx),
        finished: Some(finished_rx),
    })
}

#[cfg(test)]
mod http_tests {
    use super::*;

    struct TestClient {
        endpoint: String,
        session: String,
        next_id: u64,
    }

    impl TestClient {
        fn initialize(endpoint: String) -> Self {
            let response = post_json(
                &endpoint,
                None,
                None,
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": { "name": "windy-http-test", "version": "0.1.0" }
                    }
                }),
            );
            let session = response
                .header("Mcp-Session-Id")
                .expect("initialize session header")
                .to_string();
            let body = response_json(response);
            assert_eq!(body["result"]["serverInfo"]["name"], "windy");
            assert_eq!(
                body["result"]["serverInfo"]["version"],
                env!("CARGO_PKG_VERSION")
            );
            assert_eq!(body["result"]["protocolVersion"], "2025-11-25");

            let _ = post_json(
                &endpoint,
                Some(&session),
                None,
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                }),
            );
            Self {
                endpoint,
                session,
                next_id: 2,
            }
        }

        fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
            let id = self.next_id;
            self.next_id += 1;
            response_json(post_json(
                &self.endpoint,
                Some(&self.session),
                None,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": method,
                    "params": params,
                }),
            ))
        }

        fn call(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
            self.request(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
        }
    }

    fn post_json(
        endpoint: &str,
        session: Option<&str>,
        origin: Option<&str>,
        body: &serde_json::Value,
    ) -> ureq::Response {
        let mut request = ureq::post(endpoint)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("MCP-Protocol-Version", "2025-11-25");
        if let Some(session) = session {
            request = request.set("Mcp-Session-Id", session);
        }
        if let Some(origin) = origin {
            request = request.set("Origin", origin);
        }
        request
            .send_string(&body.to_string())
            .expect("MCP HTTP request")
    }

    fn response_json(response: ureq::Response) -> serde_json::Value {
        let text = response.into_string().expect("read MCP response");
        if text.trim_start().starts_with("data:") || text.contains("\ndata:") {
            let data = text
                .lines()
                .filter_map(|line| line.strip_prefix("data:").map(str::trim))
                .find(|data| !data.is_empty())
                .expect("SSE data line");
            serde_json::from_str(data).expect("parse MCP SSE JSON")
        } else {
            serde_json::from_str(&text).expect("parse MCP JSON")
        }
    }

    fn structured(result: &serde_json::Value) -> &serde_json::Value {
        let call = &result["result"];
        let structured = &call["structuredContent"];
        let legacy_text = call["content"][0]["text"]
            .as_str()
            .expect("legacy text content");
        let legacy_json: serde_json::Value =
            serde_json::from_str(legacy_text).expect("legacy JSON content");
        assert_eq!(
            &legacy_json, structured,
            "legacy and structured JSON differ"
        );
        structured
    }

    #[test]
    fn streamable_http_release_contract_and_persistence() {
        let fixture =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("gclsd/bench/sample.exe");
        assert!(fixture.exists(), "sample.exe fixture is required");
        let home = std::env::temp_dir().join(format!(
            "windy-mcp-e2e-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let manager = Arc::new(ProjectManager::with_home_dir(&home).expect("test manager"));
        assert!(
            manager
                .runtime()
                .block_on(serve_http(manager.clone(), "0.0.0.0:0".parse().unwrap()))
                .is_err()
        );

        let mut server = manager
            .runtime()
            .block_on(serve_http(manager.clone(), "127.0.0.1:0".parse().unwrap()))
            .expect("start MCP server");
        let endpoint = format!("http://127.0.0.1:{}/mcp", server.port());
        let base = endpoint.trim_end_matches("/mcp");

        let health: serde_json::Value = serde_json::from_str(
            &ureq::get(&format!("{base}/healthz"))
                .call()
                .expect("healthz")
                .into_string()
                .expect("health body"),
        )
        .expect("health JSON");
        assert_eq!(health["name"], "windy");
        assert_eq!(health["status"], "ok");
        assert_eq!(health["protocol"], "2025-11-25");

        let bad_health_origin = ureq::get(&format!("{base}/healthz"))
            .set("Origin", "https://attacker.example")
            .call()
            .expect_err("non-loopback health Origin must fail");
        if let Some(resp) = bad_health_origin.into_response() {
            assert_eq!(resp.status(), 403);
        }
        assert_eq!(
            ureq::get(&format!("{base}/healthz"))
                .set("Origin", "http://localhost:3000")
                .call()
                .expect("loopback health Origin")
                .status(),
            200
        );

        for method in ["GET", "DELETE"] {
            let error = ureq::request(method, &endpoint)
                .call()
                .expect_err("unsupported MCP method must fail");
            if let Some(resp) = error.into_response() {
                assert_eq!(resp.status(), 405);
            }
        }

        let bad_origin = ureq::post(&endpoint)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("Origin", "https://attacker.example")
            .send_string(
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": { "name": "bad-origin", "version": "1" }
                    }
                })
                .to_string(),
            )
            .expect_err("non-loopback Origin must fail");
        if let Some(resp) = bad_origin.into_response() {
            assert_eq!(resp.status(), 403);
        }

        let loopback_origin = post_json(
            &endpoint,
            None,
            Some("http://localhost:3000"),
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "loopback-origin", "version": "1" }
                }
            }),
        );
        assert_eq!(
            response_json(loopback_origin)["result"]["serverInfo"]["name"],
            "windy"
        );

        let mut client = TestClient::initialize(endpoint.clone());
        let listed = client.request("tools/list", json!({}));
        let tools = listed["result"]["tools"].as_array().expect("tools array");
        assert!(tools.len() >= 60, "expected the complete MCP surface");
        assert!(tools.iter().all(|tool| !tool["annotations"].is_null()));
        let tool = |name: &str| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing tool {name}"))
        };
        assert_eq!(
            tool("get_function_evidence")["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(tool("verify_claims")["annotations"]["readOnlyHint"], false);
        assert_eq!(
            tool("remove_from_workspace")["annotations"]["destructiveHint"],
            true
        );
        assert!(
            tool("decompile_function")["inputSchema"]["properties"]
                .get("policy")
                .is_some()
        );
        assert!(
            tool("decompile_function")["inputSchema"]["properties"]
                .get("refine")
                .is_none()
        );

        let self_correcting = client.call("list_functions", json!({ "project_id": "not-a-uuid" }));
        assert_eq!(self_correcting["result"]["isError"], true);
        assert_eq!(
            structured(&self_correcting)["error"]["code"],
            "INVALID_ARGUMENT"
        );

        let opened = client.call("open_project", json!({ "path": fixture.to_string_lossy() }));
        let project_id = structured(&opened)["project_id"]
            .as_str()
            .expect("project id")
            .to_string();
        let imports = client.call("list_imports", json!({ "project_id": project_id }));
        assert!(structured(&imports)["total"].as_u64().is_some());
        let functions = client.call(
            "list_functions",
            json!({ "project_id": project_id, "limit": 32 }),
        );
        let va = structured(&functions)["functions"][0]["va"]
            .as_str()
            .expect("function VA")
            .to_string();
        let evidence = client.call(
            "get_function_evidence",
            json!({ "project_id": project_id, "va": va }),
        );
        assert_eq!(evidence["result"]["isError"], false);
        let _ = structured(&evidence);

        for policy in ["product", "pure_v2", "legacy"] {
            let decompiled = client.call(
                "decompile_function",
                json!({ "project_id": project_id, "va": va, "policy": policy }),
            );
            assert_eq!(decompiled["result"]["isError"], false, "policy={policy}");
            let output = structured(&decompiled);
            assert_eq!(output["project_id"], project_id);
            assert_eq!(output["policy"], policy);
            assert!(matches!(output["status"].as_str(), Some("ok" | "omitted")));
            assert!(output.get("check_report").is_some());
            assert!(output.get("contract_fingerprint").is_some());
        }

        let memory_args = json!({
            "project_id": project_id,
            "va": va,
            "purpose": "MCP persistence smoke marker",
            "tags": ["release-smoke"],
            "confidence": 88,
            "auto_seed": false
        });
        let memory = client.call("set_function_memory", memory_args.clone());
        assert_eq!(memory["result"]["isError"], false, "{memory:#}");
        assert_eq!(
            structured(&memory)["memory"]["purpose"],
            "MCP persistence smoke marker"
        );
        let undo = client.call(
            "undo_last",
            json!({ "project_id": project_id, "client_id": "mcp" }),
        );
        assert_eq!(undo["result"]["isError"], false);
        let after_undo = client.call(
            "get_function_memory",
            json!({ "project_id": project_id, "va": va }),
        );
        assert!(structured(&after_undo)["memory"].is_null());
        let restored = client.call("set_function_memory", memory_args);
        assert_eq!(restored["result"]["isError"], false);

        let claims = client.call(
            "verify_claims",
            json!({
                "project_id": project_id,
                "claims": [{ "kind": "param_count", "function_va": va, "count": 0 }]
            }),
        );
        assert_eq!(claims["result"]["isError"], false);
        assert_eq!(structured(&claims)["results"].as_array().unwrap().len(), 1);
        assert!(
            std::fs::read_dir(home.join("projects"))
                .expect("projects state dir")
                .flatten()
                .any(|entry| entry.path().to_string_lossy().ends_with(".claims.jsonl"))
        );

        manager
            .runtime()
            .block_on(server.shutdown())
            .expect("graceful shutdown");
        drop(client);
        drop(manager);

        let manager = Arc::new(ProjectManager::with_home_dir(&home).expect("restarted manager"));
        let mut server = manager
            .runtime()
            .block_on(serve_http(manager.clone(), "127.0.0.1:0".parse().unwrap()))
            .expect("restart MCP server");
        let mut client = TestClient::initialize(format!("http://127.0.0.1:{}/mcp", server.port()));
        let reopened = client.call("open_project", json!({ "path": fixture.to_string_lossy() }));
        let reopened_id = structured(&reopened)["project_id"]
            .as_str()
            .expect("reopened project id");
        let persisted = client.call(
            "get_function_memory",
            json!({ "project_id": reopened_id, "va": va }),
        );
        assert_eq!(
            structured(&persisted)["purpose"],
            "MCP persistence smoke marker"
        );

        manager
            .runtime()
            .block_on(server.shutdown())
            .expect("second graceful shutdown");
        drop(client);
        drop(manager);
        let _ = std::fs::remove_dir_all(home);
    }
}
