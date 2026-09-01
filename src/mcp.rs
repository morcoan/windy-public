//! MCP server exposing windy projects to external agents.
//!
//! The server is token-efficient: tools return bounded JSON summaries by default,
//! and agents must explicitly ask for full function exports or compact agent text.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use http_body_util::BodyExt;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, ErrorCode, ProgressNotificationParam, ServerCapabilities, ServerInfo,
};
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

mod v3;

const DEFAULT_INLINE_BYTES: usize = 2048;
const MAX_INLINE_BYTES: usize = 8192;
const ARTIFACT_TTL: Duration = Duration::from_secs(15 * 60);
const INVESTIGATION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_EDIT_RESULTS: usize = 1_024;
const MAX_OPEN_JOBS: usize = 256;
const MAX_INVESTIGATIONS: usize = 256;

static HTTP_REQUESTS: AtomicU64 = AtomicU64::new(0);
static HTTP_RESPONSE_BYTES: AtomicU64 = AtomicU64::new(0);
static HTTP_ERRORS: AtomicU64 = AtomicU64::new(0);
static HTTP_LATENCY_MICROS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RuntimeMetrics {
    pub requests: u64,
    pub response_bytes: u64,
    pub errors: u64,
    pub average_latency_micros: u64,
    pub rss_bytes: Option<u64>,
}

pub fn runtime_metrics() -> RuntimeMetrics {
    let requests = HTTP_REQUESTS.load(Ordering::Relaxed);
    RuntimeMetrics {
        requests,
        response_bytes: HTTP_RESPONSE_BYTES.load(Ordering::Relaxed),
        errors: HTTP_ERRORS.load(Ordering::Relaxed),
        average_latency_micros: HTTP_LATENCY_MICROS.load(Ordering::Relaxed) / requests.max(1),
        rss_bytes: current_process_rss_bytes(),
    }
}

#[derive(Clone)]
struct StoredArtifact {
    body: Arc<str>,
    created: Instant,
}

#[derive(Clone)]
enum OpenJobState {
    Running {
        stage: String,
        progress: f32,
    },
    CatalogReady {
        catalog: CatalogSnapshot,
    },
    SketchReady {
        catalog: CatalogSnapshot,
        sketch: Arc<crate::analysis::sketch::SketchImage>,
    },
    Ready {
        target_id: ProjectId,
    },
    Failed {
        error: String,
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CatalogImport {
    dll: String,
    name: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CatalogSnapshot {
    elapsed_ms: u128,
    image_sha256: String,
    bytes: u64,
    bitness: u32,
    sections: usize,
    imports: usize,
    #[serde(default)]
    import_items: Vec<CatalogImport>,
    exports: usize,
    strings: usize,
    security_markers: Vec<String>,
    #[serde(default)]
    cache_hit: bool,
}

#[derive(Clone)]
struct OpenJob {
    id: String,
    path: String,
    started: Instant,
    state: OpenJobState,
}

#[derive(Clone)]
struct Investigation {
    id: String,
    intent: String,
    question: String,
    budget: String,
    target_id: Option<ProjectId>,
    open_job_id: Option<String>,
    created: Instant,
}

#[derive(Clone)]
struct ActionTicket {
    id: String,
    investigation_id: String,
    label: String,
    capability: String,
    arguments: serde_json::Map<String, serde_json::Value>,
    expected_revision: Option<u64>,
    created: Instant,
}

#[derive(Clone)]
struct ChangeProposal {
    id: String,
    investigation_id: String,
    target_id: ProjectId,
    expected_revision: u64,
    capability: String,
    arguments: serde_json::Map<String, serde_json::Value>,
    created: Instant,
}

enum StepPlan {
    Immediate(CallToolResult),
    Execute(ActionTicket),
}

#[derive(Clone)]
enum DeepJobState {
    Running,
    Ready(Arc<crate::analysis::compact_index::CompactIndex>),
    Failed(String),
}

#[derive(Default)]
struct McpShared {
    artifacts: Mutex<HashMap<String, StoredArtifact>>,
    edit_results: Mutex<HashMap<String, CallToolResult>>,
    open_jobs: Mutex<HashMap<String, OpenJob>>,
    investigations: Mutex<HashMap<String, Investigation>>,
    actions: Mutex<HashMap<String, ActionTicket>>,
    proposals: Mutex<HashMap<String, ChangeProposal>>,
    deep_jobs: Mutex<HashMap<String, DeepJobState>>,
}

/// Data exposed to MCP clients.
#[derive(Clone)]
pub struct WindyMcp {
    manager: Arc<ProjectManager>,
    shared: Arc<McpShared>,
}

fn is_single_missing_ascii_char(requested: &str, candidate: &str) -> bool {
    if !requested.is_ascii() || !candidate.is_ascii() || candidate.len() != requested.len() + 1 {
        return false;
    }
    let requested = requested.to_ascii_lowercase();
    let candidate = candidate.to_ascii_lowercase();
    (0..candidate.len()).any(|skip| {
        candidate.as_bytes()[..skip] == requested.as_bytes()[..skip]
            && candidate.as_bytes()[skip + 1..] == requested.as_bytes()[skip..]
    })
}

/// Repair only the narrow, mechanically safe case where a weak tool caller
/// omitted one ASCII character from a filename and exactly one sibling file
/// matches.  Ambiguous or broader typos remain errors rather than silently
/// selecting a different analysis target.
fn repair_unique_missing_path_char(path: &std::path::Path) -> Option<std::path::PathBuf> {
    if path.exists() {
        return None;
    }
    let parent = path.parent()?;
    let requested = path.file_name()?.to_str()?;
    let mut matched = None;
    for entry in std::fs::read_dir(parent).ok()?.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let candidate = entry.file_name();
        let Some(candidate) = candidate.to_str() else {
            continue;
        };
        if !is_single_missing_ascii_char(requested, candidate) {
            continue;
        }
        if matched.is_some() {
            return None;
        }
        matched = Some(entry.path());
    }
    matched
}

impl WindyMcp {
    pub fn new(manager: Arc<ProjectManager>) -> Self {
        Self {
            manager,
            shared: Arc::new(McpShared::default()),
        }
    }

    fn with_shared(manager: Arc<ProjectManager>, shared: Arc<McpShared>) -> Self {
        Self { manager, shared }
    }

    async fn decompile_native_result(
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

        // Complexity guardrail: refuse whole-function C emit for oversized
        // functions with structured alternatives instead of hanging/crashing
        // (transcript: 1,183-instruction CreateMove killed the server).
        let effective_cap = params
            .max_instructions
            .unwrap_or(DEFAULT_MAX_DECOMPILE_INSTRUCTIONS);
        let instructions = project.function_at(va).map(|f| {
            f.blocks
                .iter()
                .map(|block| block.instr_count)
                .sum::<usize>()
        });
        if let Some(instructions) = instructions
            && instructions > effective_cap
        {
            let guidance = vec![
                "get_function_evidence: one-shot pack (summary, entities, APIs, strings, call sites) — the fast path for big functions.".to_string(),
                "get_function_decompilation_structured: signature + blocks + control-flow regions, no C emit.".to_string(),
                format!("get_function_agent_text with max_instructions={effective_cap}: token-bounded body (current fn has {instructions} instructions)."),
                format!("decompile_function with max_instructions={instructions}: force the full C emit despite the default {effective_cap}-instruction cap (pair with deadline_ms to bound the wait)."),
            ];
            return Ok(success_json(&json!({
                "project_id": id.to_string(),
                "va": format!("{va:#x}"),
                "status": "too_complex",
                "instructions": instructions,
                "max_instructions": effective_cap,
                "policy": params.policy,
                "guidance": guidance,
                "message": format!(
                    "Function has {instructions} instructions (cap {effective_cap}). Use get_function_evidence / get_function_decompilation_structured, or raise max_instructions to force the full decompile."
                ),
            })));
        }

        let deadline_ms = params.deadline_ms.unwrap_or(DEFAULT_DECOMPILE_DEADLINE_MS);
        let deadline = Duration::from_millis(deadline_ms.clamp(1, 120_000));
        let guarded = self
            .manager
            .decompile_artifact_guarded(id, va, options, Some(deadline))
            .await;
        let artifact = match guarded {
            crate::project_manager::DecompileOutcome::Ready(artifact) => artifact,
            crate::project_manager::DecompileOutcome::StillRunning => {
                let guidance = vec![
                    "Retry the identical call: the background decompile is cached when done and the retry returns instantly.",
                    "get_function_evidence: one-shot pack while the full decompile finishes.",
                    "get_function_decompilation_structured: signature + blocks, no C emit.",
                    "Raise deadline_ms for a longer synchronous wait.",
                ];
                return Ok(success_json(&json!({
                    "project_id": id.to_string(),
                    "va": format!("{va:#x}"),
                    "status": "pending",
                    "deadline_ms": deadline_ms,
                    "policy": params.policy,
                    "guidance": guidance,
                    "message": format!(
                        "Decompilation did not finish within {deadline_ms}ms and continues in the background. The finished artifact is cached; an identical retry returns instantly."
                    ),
                })));
            }
            crate::project_manager::DecompileOutcome::NotFound => {
                return Ok(tool_error_json(
                    "FUNCTION_NOT_FOUND",
                    "function not found or native decompilation failed",
                    json!({ "project_id": id.to_string(), "va": format!("{va:#x}") }),
                    false,
                ));
            }
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
        if let Some(reason) = artifact.fallback_reason.clone() {
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
struct ListDumpModulesParams {
    project_id: String,
    #[serde(default)]
    pattern: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_list_limit")]
    limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListDumpThreadsParams {
    project_id: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_list_limit")]
    limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ListMemoryRegionsParams {
    project_id: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_list_limit")]
    limit: usize,
    /// If set, return only the region containing this VA.
    #[serde(default)]
    contains_va: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetThreadStackParams {
    project_id: String,
    /// OS thread id; omit for exception thread / first with IP.
    #[serde(default)]
    thread_id: Option<u32>,
    #[serde(default)]
    max_frames: Option<usize>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct OpenDumpModuleParams {
    /// Dump session project_id from open_project on a .dmp.
    project_id: String,
    /// Module name, substring, or 0x base. Empty = primary module.
    #[serde(default)]
    module: String,
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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ReadPointersParams {
    project_id: String,
    va: String,
    /// Number of pointer slots (default 16, max 256).
    #[serde(default = "default_pointer_count")]
    count: usize,
    /// Byte stride between slots (default: pointer size).
    #[serde(default)]
    stride: Option<u64>,
}

fn default_pointer_count() -> usize {
    16
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FieldLayoutParam {
    name: String,
    /// Byte offset within the node/struct.
    offset: u64,
    /// ptr | u32 | u64 | i32 | i64 | string | bytes
    #[serde(default = "default_field_kind")]
    kind: String,
    /// Optional size for kind=bytes (max 64).
    #[serde(default)]
    size: Option<usize>,
}

fn default_field_kind() -> String {
    "ptr".into()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WalkListParams {
    project_id: String,
    head_va: String,
    /// Offset of the next-pointer field within each node.
    next_offset: u64,
    /// Max nodes to visit (default 32, max 128).
    #[serde(default = "default_walk_nodes")]
    max_nodes: usize,
    /// Optional field layout decoded per node.
    #[serde(default)]
    fields: Vec<FieldLayoutParam>,
}

fn default_walk_nodes() -> usize {
    32
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ReadStructArrayParams {
    project_id: String,
    va: String,
    /// Byte size of one element.
    stride: u64,
    /// Number of elements (default 8, max 64).
    #[serde(default = "default_struct_count")]
    count: usize,
    fields: Vec<FieldLayoutParam>,
}

fn default_struct_count() -> usize {
    8
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DescribeAddressParams {
    project_id: String,
    va: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct TriageParams {
    project_id: String,
    /// Max ranked functions (default 32, max 64).
    #[serde(default = "default_list_limit")]
    limit: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct TraceValueParams {
    project_id: String,
    /// Function entry VA where the site is observed.
    va: String,
    /// Register, stack offset (e.g. -0x10), or operand/site label.
    site: String,
    /// backward (default) or forward.
    #[serde(default = "default_trace_direction")]
    direction: String,
    /// Max call-graph hops (default 4, max 8).
    #[serde(default)]
    depth: Option<usize>,
}

fn default_trace_direction() -> String {
    "backward".into()
}

fn field_specs_from_params(
    fields: &[FieldLayoutParam],
) -> Vec<crate::analysis::mem_walk::FieldSpec> {
    fields
        .iter()
        .map(|f| crate::analysis::mem_walk::FieldSpec {
            name: f.name.clone(),
            offset: f.offset,
            kind: f.kind.clone(),
            size: f.size,
        })
        .collect()
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
    /// Work cap in instructions. Above the cap the tool returns a structured
    /// `too_complex` status with lighter-weight alternatives instead of a
    /// long synchronous decompile (default 1000).
    #[serde(default)]
    max_instructions: Option<usize>,
    /// Hard synchronous wait in milliseconds (default 30000, max 120000).
    /// On overrun the decompile continues in the background and the finished
    /// artifact is cached, so an identical retry returns instantly.
    #[serde(default)]
    deadline_ms: Option<u64>,
}

/// Default `max_instructions` cap for whole-function C decompilation.
const DEFAULT_MAX_DECOMPILE_INSTRUCTIONS: usize = 1000;
/// Default `deadline_ms` for a synchronous decompile wait.
const DEFAULT_DECOMPILE_DEADLINE_MS: u64 = 30_000;

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
    /// Skip this many matching results.
    #[serde(default)]
    offset: usize,
    /// Results to return (default 32, hard cap 128).
    #[serde(default = "default_list_limit")]
    limit: usize,
    /// Search only cheap symbol and extracted-string tables.
    #[serde(default)]
    fast_only: bool,
    /// Hard deadline for broad instruction search (default 30 seconds, max 120).
    #[serde(default = "default_search_timeout_secs")]
    timeout_secs: u64,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct BelSearchParams {
    project_id: String,
    query: String,
    /// auto | exact | prefix | substring | numeric | regex | token |
    /// relationship | motif | ontology | multi_evidence
    #[serde(default)]
    mode: crate::analysis::bel::SearchMode,
    /// Additional independent clauses for multi_evidence mode.
    #[serde(default)]
    evidence: Vec<String>,
    /// Minimum independent clauses required for multi-evidence results.
    #[serde(default)]
    quorum: Option<u8>,
    /// Exact relationship expansion depth, capped by BEL configuration.
    #[serde(default = "default_relationship_depth")]
    relationship_depth: u8,
    /// Optional entity-kind filter.
    #[serde(default)]
    kinds: Vec<crate::analysis::bel::EntityKind>,
    #[serde(default = "default_list_limit")]
    limit: usize,
    /// Opaque stable cursor returned by the previous page.
    #[serde(default)]
    cursor: Option<String>,
    /// Hard cooperative deadline in milliseconds (default 30s, max 120s).
    #[serde(default = "default_bel_deadline_ms")]
    deadline_ms: u64,
}

fn default_relationship_depth() -> u8 {
    1
}

fn default_bel_deadline_ms() -> u64 {
    30_000
}

fn default_search_timeout_secs() -> u64 {
    30
}

const LARGE_PE_FILE_BYTES: usize = 128 * 1024 * 1024;
const LARGE_PE_FUNCTIONS: usize = 100_000;
const LARGE_PE_INSTRUCTIONS: usize = 2_000_000;

#[derive(Clone, Debug, serde::Serialize)]
struct ProjectScale {
    category: &'static str,
    is_large: bool,
    file_bytes: usize,
    functions: usize,
    instructions: usize,
    notice: Option<String>,
}

fn project_scale(project: &crate::project::Project) -> ProjectScale {
    let file_bytes = project.pe.image.len();
    let functions = project.functions().len();
    let instructions = project.analysis.code_index.len();
    let is_large = file_bytes >= LARGE_PE_FILE_BYTES
        || functions >= LARGE_PE_FUNCTIONS
        || instructions >= LARGE_PE_INSTRUCTIONS;
    ProjectScale {
        category: if is_large { "large" } else { "standard" },
        is_large,
        file_bytes,
        functions,
        instructions,
        notice: is_large.then(|| {
            format!(
                "Large PE detected ({functions} functions, {instructions} instructions, {} MiB). Prefer targeted queries; broad instruction searches have a 30s default timeout.",
                file_bytes / (1024 * 1024)
            )
        }),
    }
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
        description = "Cheap liveness and workload status: idle/busy operation, elapsed time, open projects, search-index readiness, and recently used project reopen hints."
    )]
    async fn get_server_status(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(success_json(&server_status_json(&self.manager)))
    }

    #[tool(
        description = "List all currently open projects and dump sessions with ids, paths, kind, function/instruction counts"
    )]
    async fn list_projects(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let projects = self.manager.list();
        let arr: Vec<_> = projects
            .into_iter()
            .map(|(id, path, fns, insns)| {
                let kind = if self.manager.is_dump_session(id) {
                    "dump_session".to_string()
                } else if let Some(p) = self.manager.get(id) {
                    p.kind_label().to_string()
                } else {
                    "pe".to_string()
                };
                let mut obj = json!({
                    "project_id": id.to_string(),
                    "path": path.to_string_lossy(),
                    "kind": kind,
                    "functions": fns,
                    "instructions": insns,
                });
                if let Some(p) = self.manager.get(id) {
                    if let Some(o) = &p.dump_origin {
                        obj["dump_session_id"] = json!(o.dump_session_id.to_string());
                        obj["module_name"] = json!(o.module_name);
                        obj["module_base"] = json!(format!("{:#x}", o.module_base));
                    }
                }
                obj
            })
            .collect();
        let mut result = success_json(&arr);
        if arr.is_empty() {
            let recent = self.manager.recent_projects(1);
            let message = recent.first().map_or_else(
                || {
                    "Server is up, but nothing is open. Call open_project with an absolute PE or .dmp path, or start Windy with --open."
                        .to_string()
                },
                |entry| {
                    format!(
                        "Server is up, but nothing is open. Last used: {}. Reopen it with open_project.",
                        entry.path.display()
                    )
                },
            );
            result.content = vec![Content::text(message)];
        }
        Ok(result)
    }

    #[tool(
        description = "Open a PE (exe/dll/sys) or user-mode Windows minidump (.dmp). Dumps return kind=dump_session; use get_dump_triage / list_dump_modules next. PE returns kind=pe."
    )]
    async fn open_project(
        &self,
        Parameters(params): Parameters<OpenProjectParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let started = Instant::now();
        // Offload the full parse + discovery + indexing onto the blocking
        // pool with a visible operation, so `get_server_status` reports
        // progress and every other tool stays responsive while opening.
        let manager = self.manager.clone();
        let path = std::path::PathBuf::from(params.path);
        let operation = manager.begin_operation_shared(format!("opening {}", path.display()));
        let progress = {
            let operation = operation.clone();
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            crate::project::open_progress(move |stage: crate::project::OpenStage| {
                operation.update(format!(
                    "opening {file_name}: {} ({:.0}%)",
                    stage.label(),
                    stage.fraction() * 100.0
                ));
            })
        };
        let handle = manager.runtime().handle().clone();
        let id = handle
            .spawn_blocking(move || manager.open_with_progress(&path, Some(progress)))
            .await
            .map_err(|error| invalid_params(format!("open task failed: {error}")))?
            .map_err(|error| invalid_params(error.to_string()))?;
        drop(operation);

        if let Some(session) = self.manager.get_dump(id) {
            let dump = &session.dump;
            let primary = dump.primary_module();
            let notice = if dump.identity.file_len >= 1024 * 1024 * 1024 {
                Some(format!(
                    "Large dump ({:.2} GiB). Use get_dump_triage then open_dump_module; do not BEL the whole process.",
                    dump.identity.file_len as f64 / (1024.0 * 1024.0 * 1024.0)
                ))
            } else {
                None
            };
            return Ok(success_json(&json!({
                "project_id": id.to_string(),
                "kind": "dump_session",
                "path": session.path,
                "elapsed_ms": started.elapsed().as_millis(),
                "workspace_id": session.workspace_id.map(|w| w.to_string()),
                "system": dump.system,
                "exception": dump.exception,
                "module_count": dump.modules.len(),
                "thread_count": dump.threads.len(),
                "memory_regions": dump.memory_map.region_count(),
                "memory_bytes": dump.memory_map.total_bytes(),
                "primary_module": primary.map(|m| json!({
                    "name": m.name,
                    "base": format!("{:#x}", m.base),
                    "size": m.size,
                    "presence": m.presence,
                    "has_pe_headers": m.has_pe_headers,
                })),
                "warnings": dump.open_warnings(),
                "next": [
                    "get_dump_triage",
                    "list_dump_modules",
                    "list_dump_threads",
                    "get_thread_stack",
                    "list_memory_regions",
                    "open_dump_module",
                    "get_function_evidence (on module project_id)"
                ],
                "message": notice.unwrap_or_else(|| format!(
                    "Opened dump session {} ({} modules, {} threads).",
                    session.path.display(),
                    dump.modules.len(),
                    dump.threads.len()
                )),
            })));
        }

        let project = get_project(&self.manager, id)?;
        let scale = project_scale(&project);
        let pdb = if project.pdb_info.loaded {
            json!({
                "status": "loaded",
                "source": project.pdb_info.source,
                "message": "PDB loaded.",
            })
        } else {
            json!({
                "status": "unavailable",
                "source": null,
                "message": "No PDB (normal for private or game binaries). Continuing without symbols.",
            })
        };
        Ok(success_json(&json!({
            "project_id": id.to_string(),
            "kind": "pe",
            "path": project.pe.path,
            "elapsed_ms": started.elapsed().as_millis(),
            "scale": scale,
            "pdb": pdb,
            "message": scale.notice.clone().unwrap_or_else(|| format!(
                "Opened {} in {:.2}s.",
                project.pe.path.display(),
                started.elapsed().as_secs_f64()
            )),
        })))
    }

    #[tool(
        description = "Dump-session triage: exception (if any), primary/faulting module, module/thread counts, memory coverage, top threads with IP/SP. Prefer this after open_project on a .dmp."
    )]
    async fn get_dump_triage(
        &self,
        Parameters(params): Parameters<ProjectOnlyParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let session = get_dump_session(&self.manager, id)?;
        let dump = &session.dump;
        let primary = dump.primary_module();
        let top_threads: Vec<_> = dump
            .threads
            .iter()
            .filter(|t| t.is_exception_thread || t.instruction_pointer.is_some())
            .take(16)
            .map(|t| {
                let module = t
                    .instruction_pointer
                    .and_then(|ip| dump.module_at(ip))
                    .map(|m| m.name.clone());
                json!({
                    "thread_id": t.thread_id,
                    "ip": t.instruction_pointer.map(|v| format!("{v:#x}")),
                    "sp": t.stack_pointer.map(|v| format!("{v:#x}")),
                    "fp": t.frame_pointer.map(|v| format!("{v:#x}")),
                    "module": module,
                    "is_exception_thread": t.is_exception_thread,
                })
            })
            .collect();
        Ok(success_json(&json!({
            "project_id": id.to_string(),
            "kind": "dump_session",
            "path": session.path,
            "system": dump.system,
            "exception": dump.exception,
            "primary_module": primary.map(|m| json!({
                "name": m.name,
                "base": format!("{:#x}", m.base),
                "size": m.size,
                "presence": m.presence,
                "has_pe_headers": m.has_pe_headers,
                "is_main": m.is_main,
                "is_exception_module": m.is_exception_module,
                "path": m.path,
            })),
            "module_count": dump.modules.len(),
            "thread_count": dump.threads.len(),
            "memory": {
                "region_count": dump.memory_map.region_count(),
                "total_bytes": dump.memory_map.total_bytes(),
                "source": dump.memory_map.source_label(),
            },
            "top_threads": top_threads,
            "warnings": dump.open_warnings(),
            "inventory": dump.inventory,
        })))
    }

    #[tool(
        description = "List modules in a dump session. Paginate with offset+limit (default 32, max 128). Optional pattern filters name/path."
    )]
    async fn list_dump_modules(
        &self,
        Parameters(params): Parameters<ListDumpModulesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let session = get_dump_session(&self.manager, id)?;
        let dump = &session.dump;
        let needle = params.pattern.to_ascii_lowercase();
        let limit = params.limit.clamp(1, 128);
        let mut filtered: Vec<_> = dump
            .modules
            .iter()
            .filter(|m| {
                needle.is_empty()
                    || m.name.to_ascii_lowercase().contains(&needle)
                    || m.path.to_ascii_lowercase().contains(&needle)
            })
            .collect();
        // Exception/main modules first for agent convenience.
        filtered.sort_by_key(|m| {
            (
                !m.is_exception_module,
                !m.is_main,
                m.name.to_ascii_lowercase(),
            )
        });
        let total = filtered.len();
        let page: Vec<_> = filtered
            .into_iter()
            .skip(params.offset)
            .take(limit)
            .map(|m| {
                json!({
                    "index": m.index,
                    "name": m.name,
                    "path": m.path,
                    "base": format!("{:#x}", m.base),
                    "size": m.size,
                    "presence": m.presence,
                    "has_pe_headers": m.has_pe_headers,
                    "is_main": m.is_main,
                    "is_exception_module": m.is_exception_module,
                    "timestamp": m.timestamp,
                    "checksum": m.checksum,
                })
            })
            .collect();
        let next_offset = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "project_id": id.to_string(),
            "total": total,
            "offset": params.offset,
            "next_offset": next_offset,
            "has_more": next_offset < total,
            "modules": page,
        })))
    }

    #[tool(
        description = "List threads in a dump session. Paginate with offset+limit (default 32, max 128)."
    )]
    async fn list_dump_threads(
        &self,
        Parameters(params): Parameters<ListDumpThreadsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let session = get_dump_session(&self.manager, id)?;
        let dump = &session.dump;
        let limit = params.limit.clamp(1, 128);
        let total = dump.threads.len();
        let page: Vec<_> = dump
            .threads
            .iter()
            .skip(params.offset)
            .take(limit)
            .map(|t| {
                let module = t
                    .instruction_pointer
                    .and_then(|ip| dump.module_at(ip))
                    .map(|m| m.name.clone());
                json!({
                    "thread_id": t.thread_id,
                    "ip": t.instruction_pointer.map(|v| format!("{v:#x}")),
                    "sp": t.stack_pointer.map(|v| format!("{v:#x}")),
                    "fp": t.frame_pointer.map(|v| format!("{v:#x}")),
                    "teb": format!("{:#x}", t.teb),
                    "module": module,
                    "stack_start": t.stack_start.map(|v| format!("{v:#x}")),
                    "stack_size": t.stack_size,
                    "is_exception_thread": t.is_exception_thread,
                })
            })
            .collect();
        let next_offset = params.offset.saturating_add(page.len());
        Ok(success_json(&json!({
            "project_id": id.to_string(),
            "total": total,
            "offset": params.offset,
            "next_offset": next_offset,
            "has_more": next_offset < total,
            "threads": page,
        })))
    }

    #[tool(
        description = "List sparse process memory regions in a dump session. Paginate with offset+limit (default 32, max 128). Optional contains_va filters to the region covering that address."
    )]
    async fn list_memory_regions(
        &self,
        Parameters(params): Parameters<ListMemoryRegionsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let session = get_dump_session(&self.manager, id)?;
        let dump = &session.dump;
        let limit = params.limit.clamp(1, 128);
        if let Some(va_s) = &params.contains_va {
            let va = parse_va(va_s)?;
            let page = dump
                .memory_map
                .regions_page(0, dump.memory_map.region_count());
            let hit: Vec<_> = page
                .into_iter()
                .filter(|r| va >= r.va_start && va < r.va_start.saturating_add(r.size))
                .map(|r| {
                    json!({
                        "va_start": format!("{:#x}", r.va_start),
                        "size": r.size,
                        "va_end": format!("{:#x}", r.va_start.saturating_add(r.size)),
                    })
                })
                .collect();
            return Ok(success_json(&json!({
                "project_id": id.to_string(),
                "contains_va": format!("{va:#x}"),
                "total": hit.len(),
                "regions": hit,
                "source": dump.memory_map.source_label(),
            })));
        }
        let total = dump.memory_map.region_count();
        let page = dump.memory_map.regions_page(params.offset, limit);
        let regions: Vec<_> = page
            .into_iter()
            .map(|r| {
                json!({
                    "va_start": format!("{:#x}", r.va_start),
                    "size": r.size,
                    "va_end": format!("{:#x}", r.va_start.saturating_add(r.size)),
                })
            })
            .collect();
        let next_offset = params.offset.saturating_add(regions.len());
        Ok(success_json(&json!({
            "project_id": id.to_string(),
            "total": total,
            "offset": params.offset,
            "next_offset": next_offset,
            "has_more": next_offset < total,
            "total_bytes": dump.memory_map.total_bytes(),
            "source": dump.memory_map.source_label(),
            "regions": regions,
        })))
    }

    #[tool(
        description = "Describe a dump session: stream inventory, OS/arch, size, warnings. Use after open_project on a .dmp."
    )]
    async fn describe_dump(
        &self,
        Parameters(params): Parameters<ProjectOnlyParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let session = get_dump_session(&self.manager, id)?;
        Ok(success_json(&session.dump.summary_json()))
    }

    #[tool(
        description = "Stackwalk a dump-session thread (frame-pointer chain, else RSP scan). Omit thread_id for exception thread or first with IP. Hang dumps without Exception stream still walk. max_frames default 32, max 256."
    )]
    async fn get_thread_stack(
        &self,
        Parameters(params): Parameters<GetThreadStackParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let session = get_dump_session(&self.manager, id)?;
        let max_frames = params.max_frames.unwrap_or(32);
        let stack = session.dump.walk_thread_stack(params.thread_id, max_frames);
        Ok(success_json(&json!({
            "project_id": id.to_string(),
            "kind": "dump_session",
            "stack": stack,
        })))
    }

    #[tool(
        description = "Lazy-open a dump module as a PE-style project (functions, evidence, decompile, BEL). module: name substring, exact name, or 0x base. Returns module project_id (kind=dump_module). Same MCP tools as PE thereafter."
    )]
    async fn open_dump_module(
        &self,
        Parameters(params): Parameters<OpenDumpModuleParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let dump_id = parse_project_id(&params.project_id)?;
        let started = Instant::now();
        let module_spec = if params.module.trim().is_empty() {
            // Default to primary module name.
            let session = get_dump_session(&self.manager, dump_id)?;
            session
                .dump
                .primary_module()
                .map(|m| m.name.clone())
                .unwrap_or_default()
        } else {
            params.module.clone()
        };
        let module_id = self
            .manager
            .open_dump_module(dump_id, &module_spec)
            .map_err(|e| invalid_params(e.to_string()))?;
        let project = get_project(&self.manager, module_id)?;
        let origin = project.dump_origin.as_ref();
        Ok(success_json(&json!({
            "project_id": module_id.to_string(),
            "kind": "dump_module",
            "dump_session_id": dump_id.to_string(),
            "module_name": origin.map(|o| o.module_name.clone()),
            "module_base": origin.map(|o| format!("{:#x}", o.module_base)),
            "path": project.pe.path,
            "functions": project.functions().len(),
            "instructions": project.analysis.code_index.len(),
            "bitness": project.bitness,
            "elapsed_ms": started.elapsed().as_millis(),
            "next": [
                "get_triage",
                "list_functions",
                "get_function_evidence",
                "get_function_agent_text / decompile_function_native"
            ],
            "message": format!(
                "Opened dump module {} ({} functions, {} instructions) in {:.2}s.",
                origin.map(|o| o.module_name.as_str()).unwrap_or("?"),
                project.functions().len(),
                project.analysis.code_index.len(),
                started.elapsed().as_secs_f64()
            ),
        })))
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
        let mut total = 0usize;
        let mut fns = Vec::with_capacity(limit);
        for function in project.functions().iter() {
            let name = function.name(&project.symbols);
            if !needle.is_empty()
                && !crate::analysis::search::contains_ascii_case_insensitive(&name, &needle)
            {
                continue;
            }
            if total >= params.offset && fns.len() < limit {
                fns.push(json!({
                    "va": format!("{:#x}", function.entry_va),
                    "name": name,
                    "size": function.size(),
                    "blocks": function.blocks.len(),
                }));
            }
            total += 1;
        }
        let next_offset = params.offset.saturating_add(fns.len());
        let rows: Vec<String> = fns
            .iter()
            .map(|f| {
                format!(
                    "{} {} (size={} blocks={})",
                    f["va"].as_str().unwrap_or("?"),
                    f["name"].as_str().unwrap_or("?"),
                    f["size"].as_u64().unwrap_or(0),
                    f["blocks"].as_u64().unwrap_or(0)
                )
            })
            .collect();
        let truncated = next_offset < total;
        let message = if truncated {
            format!(
                "Showing {} of {total} function(s); continue at offset {next_offset}.",
                fns.len()
            )
        } else {
            format!("Found {total} function(s).")
        };
        Ok(success_json_with_rows(
            &json!({
                "functions": fns,
                "total": total,
                "offset": params.offset,
                "limit": limit,
                "next_offset": if truncated { Some(next_offset) } else { None::<usize> },
                "truncated": truncated,
            }),
            message,
            &rows,
        ))
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
        let rows: Vec<String> = arr
            .iter()
            .map(|f| {
                format!(
                    "{} {}",
                    f["va"].as_str().unwrap_or("?"),
                    f["name"].as_str().unwrap_or("?")
                )
            })
            .collect();
        let message = format!("{} function(s) match \"{}\".", arr.len(), params.pattern);
        Ok(success_json_with_rows(
            &json!({ "functions": arr }),
            message,
            &rows,
        ))
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
        let mut pack = crate::llm::query::function_evidence(
            &project,
            va,
            crate::llm::query::EvidenceOpts {
                max_items: params.max_items.clamp(1, 64),
                include_agent_text: params.include_agent_text,
                max_agent_instructions: params.max_agent_instructions.max(1),
            },
        )
        .ok_or_else(|| invalid_params("function not found"))?;
        if let Some(object) = pack.as_object_mut() {
            object.insert("project_id".to_string(), json!(id.to_string()));
            object.insert("va".to_string(), json!(format!("{va:#x}")));
            object.insert("contract".to_string(), json!("evidence_card_v2"));
        }
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
        let supported = results
            .iter()
            .filter(|result| result.verdict == crate::llm::verify::ClaimVerdict::Supported)
            .count();
        let contradicted = results
            .iter()
            .filter(|result| result.verdict == crate::llm::verify::ClaimVerdict::Contradicted)
            .count();
        let unknown = results.len().saturating_sub(supported + contradicted);
        Ok(success_json_with_message(
            &json!({
                "results": results,
                "summary": {
                    "supported": supported,
                    "contradicted": contradicted,
                    "unknown": unknown,
                },
                "checker_ver": crate::llm::verify::CLAIM_CHECKER_VERSION,
                "contract": { "name": "claim_registry", "version": 1 },
            }),
            format!(
                "Verification: {supported} supported, {contradicted} contradicted, {unknown} unknown."
            ),
        ))
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
        let reread_matches = self
            .manager
            .get(id)
            .is_some_and(|project| op_visible(&project, &applied));
        Ok(success_json_with_message(
            &json!({
                "memory": card.to_json(),
                "op": applied,
                "saved": true,
                "reread_matches": reread_matches,
            }),
            if reread_matches {
                "Saved. Re-read matches the memory write."
            } else {
                "Saved, but the immediate re-read did not match; inspect get_function_memory."
            },
        ))
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
        description = "Binary Evidence Lattice search. Exact deterministic modes: exact, prefix, substring, numeric, regex, token, relationship, motif, ontology, and multi_evidence. Returns provenance, stable cursors, exact/lower-bound totals, hard deadline status, and refinement guidance."
    )]
    async fn search_bel(
        &self,
        Parameters(params): Parameters<BelSearchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let deadline_ms = params.deadline_ms.clamp(1, 120_000);
        let deadline = Instant::now() + Duration::from_millis(deadline_ms);
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let progress = |status: crate::analysis::bel::BelBuildProgress| {
            if status.completed == 0 || status.completed == status.total {
                tracing::info!(
                    "BEL {}: {}/{}",
                    status.stage,
                    status.completed,
                    status.total
                );
            }
        };
        let control = crate::analysis::bel::BelBuildControl {
            cancel: &cancel,
            deadline: Some(deadline),
            progress: Some(&progress),
        };
        let index = match crate::analysis::bel::get_or_build(
            &project,
            crate::analysis::bel::BelConfig::default(),
            &control,
        ) {
            Ok(index) => index,
            Err(crate::analysis::bel::BelBuildError::Deadline) => {
                let shared_build_continues = project.analysis.bel.is_building();
                let refinement = if shared_build_continues {
                    "The wait reached its deadline before the shared lifecycle build completed. No query started; the single-flight build is still running. Watch get_server_status for bel_ready, then retry."
                } else {
                    "BEL construction reached the hard deadline. The partial index was discarded and no work from this request continues. Retry with a larger deadline."
                };
                let value = json!({
                    "hits": [],
                    "total": 0,
                    "total_kind": "lower_bound",
                    "next_cursor": null,
                    "truncated": true,
                    "elapsed_ms": deadline_ms,
                    "timeout_or_partial": true,
                    "refinement_suggestion": refinement,
                    "estimated_candidates": null,
                    "strategy": if shared_build_continues { "single_flight_wait" } else { "cooperative_index_build" },
                    "bel_building": shared_build_continues,
                });
                return Ok(success_json_with_message(
                    &value,
                    if shared_build_continues {
                        format!(
                            "Waited {deadline_ms}ms for the shared BEL build. It is still indexing; no query started."
                        )
                    } else {
                        format!(
                            "BEL index construction stopped at the {deadline_ms}ms deadline; no work from this request remains."
                        )
                    },
                ));
            }
            Err(error) => {
                return Ok(tool_error_json(
                    "BEL_BUILD_FAILED",
                    error.to_string(),
                    json!({ "project_id": params.project_id }),
                    matches!(error, crate::analysis::bel::BelBuildError::Cancelled),
                ));
            }
        };
        let overlay = index.overlay(&project);
        let query = crate::analysis::bel::Query {
            text: params.query,
            mode: params.mode,
            evidence: params.evidence,
            quorum: params.quorum,
            relationship_depth: params.relationship_depth,
            kinds: params.kinds,
        };
        match crate::analysis::bel::search(
            &index,
            &overlay,
            &query,
            params.limit,
            params.cursor.as_deref(),
            deadline,
        ) {
            Ok(result) => {
                let message = if result.timeout_or_partial {
                    format!(
                        "BEL returned {} verified hit(s) before the deadline; total is a lower bound. No query work continues.",
                        result.hits.len()
                    )
                } else if result.truncated {
                    format!(
                        "BEL found {} exact match(es); {} shown. Continue with next_cursor.",
                        result.total,
                        result.hits.len()
                    )
                } else {
                    format!("BEL found {} exact match(es).", result.total)
                };
                let rows: Vec<String> = result.hits.iter().map(bel_hit_row).collect();
                Ok(success_json_with_rows(&result, message, &rows))
            }
            Err(error) => Ok(tool_error_json(
                "INVALID_BEL_QUERY",
                error.to_string(),
                json!({ "query": query.text, "mode": query.mode }),
                false,
            )),
        }
    }

    #[tool(
        description = "Compatibility search over BEL. Paginated with offset/limit, exact/lower-bound totals, fast_only guardrails, and hard timeout messaging. Prefer search_bel for stable cursors and provenance."
    )]
    async fn search_summary(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let query = params.query.trim();
        if query.is_empty() {
            return Err(invalid_params("query must not be empty"));
        }
        let large = project_scale(&project).is_large;
        let broad_large_query = large && query.chars().count() < 3 && !params.fast_only;
        let fast_only = params.fast_only || broad_large_query;
        let timeout_secs = params.timeout_secs.clamp(1, 120);
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        if params.offset >= 512 {
            return Ok(tool_error_json(
                "USE_STABLE_CURSOR",
                "Offsets above 511 are intentionally disabled. Use search_bel and its stable next_cursor for deep pagination.",
                json!({ "offset": params.offset }),
                false,
            ));
        }
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let control = crate::analysis::bel::BelBuildControl {
            cancel: &cancel,
            deadline: Some(deadline),
            progress: None,
        };
        let index = match crate::analysis::bel::get_or_build(
            &project,
            crate::analysis::bel::BelConfig::default(),
            &control,
        ) {
            Ok(index) => index,
            Err(crate::analysis::bel::BelBuildError::Deadline) => {
                return Ok(tool_error_json(
                    "SEARCH_TIMEOUT",
                    format!(
                        "BEL index construction timed out after {timeout_secs}s on this PE. No query work continues. Wait for get_server_status to report bel_ready or retry with search_bel and a larger deadline."
                    ),
                    json!({
                        "query": query,
                        "timeout_secs": timeout_secs,
                        "partial_hits": [],
                        "project_scale": project_scale(&project),
                    }),
                    true,
                ));
            }
            Err(error) => {
                return Ok(tool_error_json(
                    "BEL_BUILD_FAILED",
                    error.to_string(),
                    json!({ "query": query }),
                    false,
                ));
            }
        };
        let overlay = index.overlay(&project);
        let kinds = if fast_only {
            vec![
                crate::analysis::bel::EntityKind::Symbol,
                crate::analysis::bel::EntityKind::String,
                crate::analysis::bel::EntityKind::Import,
                crate::analysis::bel::EntityKind::Export,
            ]
        } else {
            Vec::new()
        };
        let mut bel_query = crate::analysis::bel::Query::auto(query);
        bel_query.mode = crate::analysis::bel::SearchMode::Substring;
        bel_query.kinds = kinds;
        let requested = params
            .offset
            .saturating_add(params.limit.clamp(1, 128))
            .min(512);
        let result = match crate::analysis::bel::search(
            &index, &overlay, &bel_query, requested, None, deadline,
        ) {
            Ok(result) => result,
            Err(error) => {
                return Ok(tool_error_json(
                    "INVALID_BEL_QUERY",
                    error.to_string(),
                    json!({ "query": query }),
                    false,
                ));
            }
        };
        let hits: Vec<_> = result
            .hits
            .iter()
            .skip(params.offset)
            .take(params.limit.clamp(1, 128))
            .map(|hit| {
                let location = hit
                    .va
                    .map(|va| format!("{va:#x}"))
                    .or_else(|| hit.file_offset.map(|offset| format!("file+{offset:#x}")))
                    .unwrap_or_else(|| "n/a".to_string());
                format!("{:?} {location}: {}", hit.kind, hit.display)
            })
            .collect();
        let shown = hits.len();
        let next_offset = params.offset.saturating_add(shown);
        let truncated = result.truncated || next_offset < result.total as usize;
        let warning = broad_large_query.then_some(
            "Large PE + query shorter than 3 characters: BEL safety mode searched only symbols/strings. Refine the query for instruction evidence.",
        );
        let message = if result.timeout_or_partial {
            format!(
                "Showing {shown} verified matches; total is a lower bound because the hard deadline or safety cardinality was reached."
            )
        } else if truncated {
            format!(
                "Showing {shown} of {} matches. Continue at offset {next_offset}, refine, or switch to search_bel cursors.",
                result.total
            )
        } else {
            format!("Found {} match(es).", result.total)
        };
        Ok(success_json_with_rows(
            &json!({
                "hits": hits,
                "total": result.total,
                "total_kind": result.total_kind,
                "offset": params.offset,
                "limit": params.limit.clamp(1, 128),
                "next_offset": truncated.then_some(next_offset),
                "truncated": truncated,
                "timed_out": result.timeout_or_partial,
                "fast_path": fast_only,
                "instruction_index_ready": true,
                "bel_strategy": result.strategy,
                "warning": warning,
                "message": message,
            }),
            message,
            &hits,
        ))
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
        let rows: Vec<String> = arr
            .iter()
            .map(|c| {
                format!(
                    "{} {}",
                    c["va"].as_str().unwrap_or("?"),
                    c["name"].as_str().unwrap_or("?")
                )
            })
            .collect();
        let message = format!("{} caller(s) of {va:#x}.", arr.len());
        Ok(success_json_with_rows(&arr, message, &rows))
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
        let rows: Vec<String> = arr
            .iter()
            .map(|c| {
                format!(
                    "{} {}",
                    c["va"].as_str().unwrap_or("?"),
                    c["name"].as_str().unwrap_or("?")
                )
            })
            .collect();
        let message = format!("{} callee(s) of {va:#x}.", arr.len());
        Ok(success_json_with_rows(&arr, message, &rows))
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
        let rows: Vec<String> = arr
            .iter()
            .map(|x| {
                format!(
                    "{} {} ({})",
                    x["va"].as_str().unwrap_or("?"),
                    x["name"].as_str().unwrap_or("?"),
                    x["kind"].as_str().unwrap_or("?")
                )
            })
            .collect();
        let message = format!("{} xref(s) to {va:#x}.", arr.len());
        Ok(success_json_with_rows(&arr, message, &rows))
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
        description = "Decompile with Windy's native checked pipeline. policy=product uses V2 with explicit Legacy fallback; pure_v2 never falls back; legacy is for comparison. max_instructions caps work (default 1000; raise to force large functions); deadline_ms bounds the synchronous wait (default 30000, max 120000) and overruns finish in the background, cached. Returns engine/checker metadata."
    )]
    async fn decompile_function(
        &self,
        Parameters(params): Parameters<DecompileFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.decompile_native_result(params).await
    }

    #[tool(
        description = "Deprecated v0.1 alias of decompile_function. Uses the same native policy and structured result; prefer decompile_function."
    )]
    async fn decompile_function_native(
        &self,
        Parameters(params): Parameters<DecompileFunctionParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.decompile_native_result(params).await
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
        let reread_matches = self
            .manager
            .get(id)
            .is_some_and(|project| op_visible(&project, &applied));
        Ok(success_json_with_message(
            &json!({
                "applied": preview.len(),
                "preview": preview,
                "op": applied,
                "saved": true,
                "reread_matches": reread_matches,
            }),
            if reread_matches {
                "Saved. Re-read matches the applied SSA suggestions."
            } else {
                "Saved, but the immediate re-read did not match; inspect function evidence."
            },
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
        let reread_matches = self
            .manager
            .get(id)
            .is_some_and(|project| op_visible(&project, &applied));
        Ok(success_json_with_message(
            &json!({
                "applied": preview.len(),
                "preview": preview,
                "evidence": evidence,
                "op": applied,
                "saved": true,
                "reread_matches": reread_matches,
            }),
            if reread_matches {
                "Saved. Re-read matches the rename/type batch."
            } else {
                "Saved, but the immediate re-read did not match; inspect get_function_evidence."
            },
        ))
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
        let strings = project.pe.triage.strings.as_deref().unwrap_or_default();
        let total = strings
            .iter()
            .filter(|string| string.value.len() >= min_len)
            .count();
        let page: Vec<_> = strings
            .iter()
            .filter(|string| string.value.len() >= min_len)
            .skip(params.offset)
            .take(limit)
            .map(|string| {
                json!({
                    "offset": string.offset,
                    "encoding": string.encoding,
                    "value": string.value,
                })
            })
            .collect();
        let page_len = page.len();
        let next = params.offset.saturating_add(page_len);
        let truncated = next < total;
        Ok(success_json(&json!({
            "strings": page,
            "total": total,
            "offset": params.offset,
            "next_offset": if next < total { Some(next) } else { None::<usize> },
            "truncated": truncated,
            "message": if truncated {
                format!("Showing {page_len} of {total} strings. Continue at offset {next} or raise min_len.")
            } else {
                format!("Showing all {total} matching strings.")
            },
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
        description = "Read N machine pointers at a VA (resolved: function/import/string). Prefer over read_va for tables/lists. count max 256; optional stride."
    )]
    async fn read_pointers(
        &self,
        Parameters(params): Parameters<ReadPointersParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        Ok(success_json(&crate::analysis::mem_walk::read_pointers(
            &project,
            va,
            params.count,
            params.stride,
        )))
    }

    #[tool(
        description = "Walk a singly-linked list from head_va following next_offset. Decodes optional fields per node; resolves pointers to functions/strings. Cycle-safe, node-capped."
    )]
    async fn walk_list(
        &self,
        Parameters(params): Parameters<WalkListParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let head_va = parse_va(&params.head_va)?;
        let fields = field_specs_from_params(&params.fields);
        Ok(success_json(&crate::analysis::mem_walk::walk_list(
            &project,
            head_va,
            params.next_offset,
            params.max_nodes,
            &fields,
        )))
    }

    #[tool(
        description = "Decode a struct array at va with explicit field layout (name/offset/kind). Resolves ptr/string fields. Element-count capped (max 64)."
    )]
    async fn read_struct_array(
        &self,
        Parameters(params): Parameters<ReadStructArrayParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        let fields = field_specs_from_params(&params.fields);
        Ok(success_json(&crate::analysis::mem_walk::read_struct_array(
            &project,
            va,
            params.stride,
            params.count,
            &fields,
        )))
    }

    #[tool(
        description = "Classify a VA: section, symbol, function, string, or as_pointer target. Prefer before dumping hex."
    )]
    async fn describe_address(
        &self,
        Parameters(params): Parameters<DescribeAddressParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        Ok(success_json(&crate::analysis::mem_walk::describe_address(
            &project, va,
        )))
    }

    #[tool(
        description = "First-minute triage: rank interesting functions by export/entry, call degree, imports, strings, size, BEL ontology/motifs. Deterministic fixed-point scores."
    )]
    async fn get_triage(
        &self,
        Parameters(params): Parameters<TriageParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        Ok(success_json(&crate::llm::triage::get_triage(
            &project,
            params.limit,
        )))
    }

    #[tool(
        description = "Interprocedural value provenance. site=reg/stack_offset/label; direction=backward|forward. Reports died reason (depth_cap|inlined|indirect|cycle|origin) instead of guessing."
    )]
    async fn trace_value(
        &self,
        Parameters(params): Parameters<TraceValueParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let id = parse_project_id(&params.project_id)?;
        let project = get_project(&self.manager, id)?;
        let va = parse_va(&params.va)?;
        Ok(success_json(&crate::llm::provenance::trace_value(
            &project,
            va,
            &params.site,
            &params.direction,
            params.depth,
        )))
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
        mut request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let tool_name = request.name.to_string();
        let started = Instant::now();
        let max_output_bytes = request
            .arguments
            .as_ref()
            .and_then(|arguments| {
                arguments.get("max_output_bytes").or_else(|| {
                    (tool_name == "evidence_read")
                        .then(|| arguments.get("max_bytes"))
                        .flatten()
                })
            })
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(DEFAULT_INLINE_BYTES)
            .clamp(512, MAX_INLINE_BYTES);
        let public_tool = v3::is_public(&tool_name);
        if !public_tool && !cfg!(test) {
            return Ok(self.normalize_v3_result(
                &tool_name,
                tool_error_json(
                    "UNKNOWN_TOOL",
                    format!("{tool_name} is not part of the Windy v0.3 public surface"),
                    json!({"repair":[{"tool":"investigation_start","intent":"capability","question":format!("perform {tool_name}")}]}),
                    false,
                ),
                max_output_bytes,
            ));
        }

        let original_arguments = request.arguments.clone().unwrap_or_default();
        if !public_tool {
            // Internal parity tests can still exercise the private operator
            // implementations directly. They are never advertised or
            // callable in a non-test server.
            request.arguments = Some(original_arguments);
            let tool_context =
                rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
            let result = route_result(Self::tool_router().call(tool_context).await);
            return Ok(self.normalize_v3_result(&tool_name, result, usize::MAX));
        }
        let repair_arguments = original_arguments.clone();
        let dispatch = if public_tool {
            v3::dispatch(&tool_name, original_arguments)
        } else {
            Err(format!("legacy tool {tool_name} is private"))
        };
        let dispatch = match dispatch {
            Ok(dispatch) => dispatch,
            Err(message) => {
                return Ok(self.normalize_v3_result(
                    &tool_name,
                    tool_error_json(
                        "INVALID_ARGUMENT",
                        message,
                        public_call_repair(&tool_name, &repair_arguments),
                        false,
                    ),
                    max_output_bytes,
                ));
            }
        };
        let track = tool_name != "windy_status";
        let _operation = track.then(|| {
            self.manager
                .begin_operation(format!("MCP tool {tool_name}"))
        });
        let progress_token = context.meta.get_progress_token();
        let progress_peer = context.peer.clone();
        if let Some(token) = progress_token.clone() {
            let _ = progress_peer
                .notify_progress(
                    ProgressNotificationParam::new(token, 0.0)
                        .with_message(format!("Started {tool_name}")),
                )
                .await;
        }
        if track {
            tracing::info!("Started MCP tool {tool_name}");
        }
        let heartbeat = track.then(|| {
            let peer = progress_peer.clone();
            let name = tool_name.clone();
            let token = progress_token.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let elapsed = started.elapsed().as_secs_f64();
                    let message = format!("Still working on {name} ({elapsed:.0}s)...");
                    tracing::info!("{message}");
                    if let Some(token) = token.clone()
                        && peer
                            .notify_progress(
                                ProgressNotificationParam::new(token, elapsed)
                                    .with_message(message),
                            )
                            .await
                            .is_err()
                    {
                        return;
                    }
                }
            })
        });
        let mut commit_cache_key = None;
        let result = match dispatch {
            v3::Dispatch::Status { id } => self.status_v3(id.as_deref()),
            v3::Dispatch::Start {
                path,
                target_id,
                intent,
                question,
                budget,
            } => self.start_investigation(path, target_id, intent, question, budget),
            v3::Dispatch::Step {
                investigation_id,
                action_id,
                inputs,
            } => {
                match self
                    .prepare_step(investigation_id.as_deref(), &action_id, inputs)
                    .await
                {
                    StepPlan::Immediate(result) => result,
                    StepPlan::Execute(ticket) => {
                        request.name = ticket.capability.into();
                        request.arguments = Some(ticket.arguments);
                        let tool_context = rmcp::handler::server::tool::ToolCallContext::new(
                            self, request, context,
                        );
                        let mut result = route_result(Self::tool_router().call(tool_context).await);
                        if let Some(value) = result.structured_content.as_mut()
                            && let Some(object) = value.as_object_mut()
                        {
                            object
                                .insert("investigation_id".into(), json!(ticket.investigation_id));
                            object.insert("action_id".into(), json!(action_id));
                        }
                        result
                    }
                }
            }
            v3::Dispatch::Read {
                investigation_id,
                cursor,
                max_bytes,
            } => {
                if !self
                    .shared
                    .investigations
                    .lock()
                    .unwrap()
                    .contains_key(&investigation_id)
                {
                    tool_error_json(
                        "INVESTIGATION_NOT_FOUND",
                        "investigation is missing or expired",
                        json!({}),
                        false,
                    )
                } else {
                    let (artifact_id, offset) = parse_artifact_cursor(&cursor);
                    self.read_artifact(artifact_id, offset, max_bytes)
                }
            }
            v3::Dispatch::Commit {
                proposal_id,
                expected_revision,
                idempotency_key,
            } => match self.commit_change(&proposal_id, expected_revision, &idempotency_key) {
                Err(result) => result,
                Ok(proposal) => {
                    let cache_key = format!("v3:{}:{idempotency_key}", proposal.target_id);
                    let reopen_path = self
                        .manager
                        .get(proposal.target_id)
                        .map(|project| project.pe.path.to_string_lossy().to_string());
                    let function_va = proposal
                        .arguments
                        .get("function_va")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let persisted_edit = proposal
                        .arguments
                        .get("renames")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|renames| renames.first())
                        .and_then(|rename| {
                            Some((
                                rename.get("target")?.as_str()?.to_owned(),
                                rename.get("new_name")?.as_str()?.to_owned(),
                            ))
                        });
                    request.name = proposal.capability.into();
                    request.arguments = Some(proposal.arguments);
                    let tool_context =
                        rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
                    let mut result = route_result(Self::tool_router().call(tool_context).await);
                    if let Some(value) = result.structured_content.as_mut()
                        && let Some(object) = value.as_object_mut()
                    {
                        object.insert("proposal_id".into(), json!(proposal.id));
                        object.insert("investigation_id".into(), json!(proposal.investigation_id));
                        object.insert("idempotency_key".into(), json!(idempotency_key));
                        if let (Some(path), Some(va), Some((target, value))) =
                            (reopen_path, function_va, persisted_edit)
                        {
                            let (purpose, question) = if target == "function_comment" {
                                (
                                    "after close, reopen and verify the persisted comment",
                                    format!(
                                        "Verify the function comment '{}' at {va} persists after reopen. Return exactly PERSISTED or NOT_PERSISTED.",
                                        value.replace(['\'', '"'], "")
                                    ),
                                )
                            } else {
                                (
                                    "after close, reopen and verify the persisted symbol",
                                    format!(
                                        "Verify the renamed symbol {value} at {va} persists after reopen. Return exactly PERSISTED or NOT_PERSISTED."
                                    ),
                                )
                            };
                            object.insert(
                                "next_actions".into(),
                                json!([
                                    {
                                        "purpose":"flush and close the edited target",
                                        "execute":{"tool":"target_close","arguments":{"target_id":proposal.target_id}}
                                    },
                                    {
                                        "purpose":purpose,
                                        "execute":{"tool":"investigation_start","arguments":{
                                            "path":path,"intent":"verify","budget":"tiny",
                                            "question":question
                                        }}
                                    }
                                ]),
                            );
                        }
                    }
                    commit_cache_key = Some(cache_key);
                    result
                }
            },
            v3::Dispatch::Close { target_id } => {
                let parsed_target = Uuid::parse_str(&target_id).ok();
                let job = {
                    let mut jobs = self.shared.open_jobs.lock().unwrap();
                    let matching_job_id = jobs.iter().find_map(|(job_id, job)| match job.state {
                        OpenJobState::Ready { target_id: ready }
                            if parsed_target == Some(ready) =>
                        {
                            Some(job_id.clone())
                        }
                        _ => None,
                    });
                    jobs.remove(&target_id)
                        .or_else(|| matching_job_id.and_then(|job_id| jobs.remove(&job_id)))
                };
                self.shared.deep_jobs.lock().unwrap().remove(
                    job.as_ref()
                        .map(|value| value.id.as_str())
                        .unwrap_or(&target_id),
                );
                let ready_target = job.as_ref().and_then(|job| match job.state {
                    OpenJobState::Ready { target_id } => Some(target_id),
                    _ => None,
                });
                if let Some(id) = ready_target {
                    match self.manager.close(id) {
                        Ok(closed) => success_json(&json!({
                            "target_id":closed.id,"kind":closed.kind,"path":closed.path,
                            "child_projects_closed":closed.child_projects,
                        })),
                        Err(error) => tool_error_json(
                            "TARGET_CLOSE_FAILED",
                            error.to_string(),
                            json!({"target_id":id}),
                            true,
                        ),
                    }
                } else if job.is_some() {
                    success_json(&json!({"target_id":target_id,"kind":"catalog","closed":true}))
                } else {
                    match parse_project_id(&target_id).and_then(|id| {
                        self.manager
                            .close(id)
                            .map_err(|error| invalid_params(error.to_string()))
                    }) {
                        Ok(closed) => success_json(&json!({
                            "target_id":closed.id,"kind":closed.kind,"path":closed.path,
                            "child_projects_closed":closed.child_projects,
                        })),
                        Err(error) => mcp_error_result(error),
                    }
                }
            }
        };
        if let Some(heartbeat) = heartbeat {
            heartbeat.abort();
        }
        let elapsed = started.elapsed().as_secs_f64();
        if track {
            tracing::info!("Finished MCP tool {tool_name} in {elapsed:.2}s");
        }
        if let Some(token) = progress_token {
            let _ = progress_peer
                .notify_progress(
                    ProgressNotificationParam::new(token, elapsed + 1.0)
                        .with_message(format!("Finished {tool_name} in {elapsed:.2}s")),
                )
                .await;
        }
        if let Some(key) = commit_cache_key
            && result.is_error != Some(true)
        {
            let mut results = self.shared.edit_results.lock().unwrap();
            if results.len() >= MAX_EDIT_RESULTS
                && let Some(oldest) = results.keys().next().cloned()
            {
                results.remove(&oldest);
            }
            results.insert(key, result.clone());
        }
        Ok(self.normalize_v3_result(&tool_name, result, max_output_bytes))
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListToolsResult {
            tools: v3::tools(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        v3::tool(name)
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.protocol_version = rmcp::model::ProtocolVersion::LATEST;
        info.server_info = rmcp::model::Implementation::new(
            crate::build_info::PRODUCT_ID,
            crate::build_info::VERSION,
        )
        .with_title(crate::build_info::PRODUCT_TITLE)
        .with_description(crate::build_info::DESCRIPTION);
        info.instructions = Some(
            "Windy v0.3 is a local static Evidence Query VM. Start one bounded investigation \
             with an intent and question, then execute only server-issued action IDs. Evidence \
             is proof-carrying and budgeted; read larger immutable results only through returned \
             cursors. Commit only server-issued proposals with revision and idempotency checks."
                .to_string(),
        );
        info
    }
}

impl WindyMcp {
    fn start_open_job(&self, path: String) -> CallToolResult {
        let supplied = std::path::PathBuf::from(&path);
        let normalized = if supplied.is_absolute() {
            supplied
        } else {
            let Ok(current_dir) = std::env::current_dir() else {
                return tool_error_json(
                    "INVALID_ARGUMENT",
                    "relative target path could not be resolved",
                    json!({ "path": path, "repair":[{"field":"path","requirement":"absolute or relative to server working directory"}] }),
                    false,
                );
            };
            current_dir.join(supplied)
        };
        let normalized = repair_unique_missing_path_char(&normalized).unwrap_or(normalized);
        let path = normalized.to_string_lossy().into_owned();
        {
            let mut jobs = self.shared.open_jobs.lock().unwrap();
            prune_open_jobs(&mut jobs);
            if let Some(existing) = jobs.values().find(|job| {
                job.path.eq_ignore_ascii_case(&path)
                    && !matches!(job.state, OpenJobState::Failed { .. })
            }) {
                return success_json(&open_job_json(existing));
            }
        }

        let id = Uuid::new_v4().to_string();
        let job = OpenJob {
            id: id.clone(),
            path: path.clone(),
            started: Instant::now(),
            state: OpenJobState::Running {
                stage: "queued".to_string(),
                progress: 0.0,
            },
        };
        let mut jobs = self.shared.open_jobs.lock().unwrap();
        if jobs.len() >= MAX_OPEN_JOBS
            && let Some(oldest) = jobs
                .iter()
                .filter(|(_, job)| !matches!(job.state, OpenJobState::Running { .. }))
                .min_by_key(|(_, job)| job.started)
                .map(|(id, _)| id.clone())
        {
            jobs.remove(&oldest);
        }
        jobs.insert(id.clone(), job.clone());
        drop(jobs);

        let shared = self.shared.clone();
        let cache_root = self.manager.home_dir().to_path_buf();
        let job_id = id.clone();
        let task_path = std::path::PathBuf::from(path);
        self.manager.runtime().handle().spawn(async move {
            let outcome =
                tokio::task::spawn_blocking(move || build_catalog_cached(&task_path, &cache_root))
                    .await;
            let state = match outcome {
                Ok(Ok(catalog)) => OpenJobState::CatalogReady { catalog },
                Ok(Err(error)) => OpenJobState::Failed {
                    error: sanitize_untrusted_text(&error.to_string(), 512),
                },
                Err(error) => OpenJobState::Failed {
                    error: format!("catalog worker failed: {error}"),
                },
            };
            if let Some(job) = shared.open_jobs.lock().unwrap().get_mut(&job_id) {
                job.state = state;
            }
        });

        // A bounded foreground join removes a mechanical poll for tiny files
        // while preserving the sub-second handle contract for large images.
        let join_deadline = Instant::now() + Duration::from_millis(75);
        while Instant::now() < join_deadline {
            let ready = self
                .shared
                .open_jobs
                .lock()
                .unwrap()
                .get(&id)
                .is_some_and(|value| !matches!(value.state, OpenJobState::Running { .. }));
            if ready {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        success_json(&open_job_json(&job))
    }

    fn promote_analysis(&self, job_id: &str) {
        let path = {
            let mut jobs = self.shared.open_jobs.lock().unwrap();
            let Some(job) = jobs.get_mut(job_id) else {
                return;
            };
            if !matches!(
                job.state,
                OpenJobState::CatalogReady { .. } | OpenJobState::SketchReady { .. }
            ) {
                return;
            }
            job.state = OpenJobState::Running {
                stage: "sketch queued".to_string(),
                progress: 0.25,
            };
            job.path.clone()
        };
        let manager = self.manager.clone();
        let shared = self.shared.clone();
        let job_id = job_id.to_string();
        let task_path = std::path::PathBuf::from(path);
        self.manager.runtime().handle().spawn(async move {
            let operation =
                manager.begin_operation_shared(format!("analyzing {}", task_path.display()));
            let progress_shared = shared.clone();
            let progress_job_id = job_id.clone();
            let progress_operation = operation.clone();
            let progress = crate::project::open_progress(move |stage| {
                progress_operation.update(format!("analysis: {}", stage.label()));
                if let Some(job) = progress_shared
                    .open_jobs
                    .lock()
                    .unwrap()
                    .get_mut(&progress_job_id)
                {
                    job.state = OpenJobState::Running {
                        stage: stage.label().to_string(),
                        progress: 0.25 + stage.fraction() * 0.75,
                    };
                }
            });
            let open_manager = manager.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                open_manager.open_with_progress(&task_path, Some(progress))
            })
            .await;
            let state = match outcome {
                Ok(Ok(target_id)) => OpenJobState::Ready { target_id },
                Ok(Err(error)) => OpenJobState::Failed {
                    error: sanitize_untrusted_text(&error.to_string(), 512),
                },
                Err(error) => OpenJobState::Failed {
                    error: format!("analysis worker failed: {error}"),
                },
            };
            if let Some(job) = shared.open_jobs.lock().unwrap().get_mut(&job_id) {
                job.state = state;
            }
            drop(operation);
        });
    }

    fn promote_sketch(&self, job_id: &str) {
        let (path, catalog) = {
            let mut jobs = self.shared.open_jobs.lock().unwrap();
            let Some(job) = jobs.get_mut(job_id) else {
                return;
            };
            let OpenJobState::CatalogReady { catalog } = &job.state else {
                return;
            };
            let catalog = catalog.clone();
            job.state = OpenJobState::Running {
                stage: "building compact function sketches".to_string(),
                progress: 0.5,
            };
            (job.path.clone(), catalog)
        };
        let shared = self.shared.clone();
        let cache_root = self.manager.home_dir().to_path_buf();
        let image_sha256 = catalog.image_sha256.clone();
        let bitness = catalog.bitness;
        let job_id = job_id.to_string();
        self.manager.runtime().handle().spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                crate::analysis::sketch::load_or_build_cached(
                    std::path::Path::new(&path),
                    &cache_root,
                    &image_sha256,
                    bitness,
                )
            })
            .await;
            let state = match outcome {
                Ok(Ok(sketch)) => OpenJobState::SketchReady {
                    catalog,
                    sketch: Arc::new(sketch),
                },
                Ok(Err(error)) => OpenJobState::Failed {
                    error: sanitize_untrusted_text(&error.to_string(), 512),
                },
                Err(error) => OpenJobState::Failed {
                    error: format!("sketch worker failed: {error}"),
                },
            };
            if let Some(job) = shared.open_jobs.lock().unwrap().get_mut(&job_id) {
                job.state = state;
            }
        });
    }

    fn start_investigation(
        &self,
        path: Option<String>,
        target_id: Option<String>,
        intent: String,
        question: String,
        budget: String,
    ) -> CallToolResult {
        let (intent, question) = canonical_investigation_input(&intent, &question);
        let id = Uuid::new_v4().to_string();
        let mut target = None;
        let mut open_job_id = None;
        if let Some(target_id) = target_id {
            let parsed = match parse_project_id(&target_id) {
                Ok(parsed) => parsed,
                Err(error) => return mcp_error_result(error),
            };
            if self.manager.get(parsed).is_some() {
                target = Some(parsed);
            } else if self
                .shared
                .open_jobs
                .lock()
                .unwrap()
                .contains_key(&target_id)
            {
                open_job_id = Some(target_id);
            } else {
                return tool_error_json(
                    "TARGET_NOT_FOUND",
                    "target is not open",
                    json!({ "repair": [{"tool":"investigation_start","replace":"target_id","with":"path"}] }),
                    false,
                );
            }
        } else if let Some(path) = path {
            let opened = self.start_open_job(path);
            if opened.is_error == Some(true) {
                return opened;
            }
            open_job_id = opened
                .structured_content
                .as_ref()
                .and_then(|value| value.get("job_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
        let investigation = Investigation {
            id: id.clone(),
            intent,
            question,
            budget,
            target_id: target,
            open_job_id,
            created: Instant::now(),
        };
        {
            let mut investigations = self.shared.investigations.lock().unwrap();
            prune_investigations(&mut investigations);
            if investigations.len() >= MAX_INVESTIGATIONS
                && let Some(oldest) = investigations
                    .iter()
                    .min_by_key(|(_, value)| value.created)
                    .map(|(key, _)| key.clone())
            {
                investigations.remove(&oldest);
            }
            investigations.insert(id.clone(), investigation.clone());
        }
        if investigation.target_id.is_some() {
            self.run_investigation(&investigation)
        } else {
            let action = self.bind_action(
                &investigation,
                "continue when target is ready",
                "__poll_open",
                serde_json::Map::new(),
                None,
            );
            success_json(&json!({
                "state":"pending",
                "investigation_id":id,
                "intent":investigation.intent,
                "job_id":investigation.open_job_id,
                "completeness_reason":"target opening",
                "evidence_delta":[],
                "next_actions":[action_json(&action, false)],
            }))
        }
    }

    fn run_investigation(&self, investigation: &Investigation) -> CallToolResult {
        let Some(target_id) = investigation.target_id else {
            return tool_error_json(
                "TARGET_PENDING",
                "target has not finished opening",
                json!({"investigation_id": investigation.id}),
                true,
            );
        };
        let Some(project) = self.manager.get(target_id) else {
            return tool_error_json(
                "TARGET_NOT_FOUND",
                "target was closed",
                json!({"target_id":target_id,"repair":[{"tool":"investigation_start","replace":"target_id","with":"path"}]}),
                false,
            );
        };
        let revision = project.op_seq;
        if investigation.intent == "verify"
            && is_persistence_query(&investigation.question)
            && let Some(va) = first_hex_address(&investigation.question)
            && investigation
                .question
                .to_ascii_lowercase()
                .contains("comment")
            && let Some(expected_comment) = expected_persisted_comment(&investigation.question)
        {
            let actual_comment = project
                .comments
                .get(va, CommentScope::Function)
                .map(str::to_owned);
            let persisted = actual_comment.as_deref() == Some(expected_comment.as_str());
            return success_json(&json!({
                "state":"complete",
                "investigation_id":investigation.id,
                "target_id":target_id,
                "revision":revision,
                "evidence_delta":[{
                    "id":format!("comment:{va:#x}"),
                    "kind":"persisted_comment",
                    "address":format!("{va:#x}"),
                    "expected":sanitize_untrusted_text(&expected_comment, 256),
                    "actual":actual_comment.as_deref().map(|value| sanitize_untrusted_text(value, 256)),
                }],
                "verdict":if persisted { "supported" } else { "contradicted" },
                "answer":if persisted { "PERSISTED" } else { "NOT_PERSISTED" },
                "uncertainty":"none",
                "next_actions":[],
            }));
        }
        if investigation.intent == "verify"
            && is_persistence_query(&investigation.question)
            && let Some(va) = first_hex_address(&investigation.question)
            && let Some(expected_name) = expected_persisted_symbol(&investigation.question)
        {
            let actual_name = project.symbols.name(va).map(str::to_owned);
            let persisted = actual_name.as_deref() == Some(expected_name.as_str());
            return success_json(&json!({
                "state":"complete",
                "investigation_id":investigation.id,
                "target_id":target_id,
                "revision":revision,
                "evidence_delta":[{
                    "id":format!("symbol:{va:#x}"),
                    "kind":"persisted_symbol",
                    "address":format!("{va:#x}"),
                    "expected":sanitize_untrusted_text(&expected_name, 256),
                    "actual":actual_name.as_deref().map(|value| sanitize_untrusted_text(value, 256)),
                }],
                "verdict":if persisted { "supported" } else { "contradicted" },
                "answer":if persisted { "PERSISTED" } else { "NOT_PERSISTED" },
                "uncertainty":"none",
                "next_actions":[],
            }));
        }
        let rank_limit = if investigation.budget == "tiny" { 2 } else { 3 };
        let ranked = crate::analysis::sketch::rank(&project, &investigation.question, rank_limit);
        let ranked_delta: Vec<_> = ranked.iter().map(sketch_delta).collect();
        let mut actions = Vec::new();
        for candidate in ranked.iter().take(3) {
            let mut arguments = serde_json::Map::new();
            arguments.insert("project_id".into(), json!(target_id.to_string()));
            arguments.insert("va".into(), json!(candidate.va));
            arguments.insert("max_items".into(), json!(8));
            arguments.insert("include_agent_text".into(), json!(false));
            let ticket = self.bind_action(
                investigation,
                &format!("verify candidate {}", candidate.va),
                "get_function_evidence",
                arguments,
                Some(revision),
            );
            actions.push(action_json(&ticket, true));
        }

        if investigation.intent == "edit" {
            if let Some((va, target, value)) = parse_edit_request(&investigation.question) {
                if crate::analysis::sketch::at_va(&project, va).is_none() {
                    return tool_error_json(
                        "FUNCTION_NOT_FOUND",
                        "the requested edit address is not a function entry",
                        json!({"address":format!("{va:#x}"),"repair":[{"intent":"locate","question":"locate the function before editing"}]}),
                        false,
                    );
                }
                let proposal_id = Uuid::new_v4().to_string();
                let mut arguments = serde_json::Map::new();
                arguments.insert("project_id".into(), json!(target_id.to_string()));
                arguments.insert("function_va".into(), json!(format!("{va:#x}")));
                arguments.insert("dry_run".into(), json!(false));
                arguments.insert(
                    "renames".into(),
                    json!([{
                        "target":target,
                        "new_name":sanitize_untrusted_text(&value, 256),
                    }]),
                );
                arguments.insert(
                    "evidence".into(),
                    json!([format!("investigation:{}", investigation.id)]),
                );
                let proposal = ChangeProposal {
                    id: proposal_id.clone(),
                    investigation_id: investigation.id.clone(),
                    target_id,
                    expected_revision: revision,
                    capability: "apply_rename_batch".into(),
                    arguments,
                    created: Instant::now(),
                };
                self.shared
                    .proposals
                    .lock()
                    .unwrap()
                    .insert(proposal_id.clone(), proposal);
                return success_json(&json!({
                    "state":"partial",
                    "investigation_id":investigation.id,
                    "target_id":target_id,
                    "revision":revision,
                    "evidence_delta":[{"id":format!("fn:{va:#x}"),"kind":"function_entry","address":format!("{va:#x}")}],
                    "proposal":{"proposal_id":proposal_id,"expected_revision":revision,"operation":target},
                    "next_actions":[{
                        "purpose":"commit the verified proposal",
                        "execute":{"tool":"change_commit","arguments":{
                            "proposal_id":proposal_id,
                            "expected_revision":revision,
                            "idempotency_key":format!("{}-commit", investigation.id),
                        }}
                    }],
                    "uncertainty":"change is proposed but not committed",
                }));
            }
            return tool_error_json(
                "UNBOUND_EDIT",
                "state a function address and either a new name or function comment",
                json!({"repair":[{"question":"rename function 0x... to NAME"},{"question":"attach the function comment 'TEXT' to 0x..."}]}),
                false,
            );
        }

        let intent = investigation.intent.as_str();
        let known_address = first_hex_address(&investigation.question);
        if intent == "verify" {
            let direct_call_claim = investigation
                .question
                .to_ascii_lowercase()
                .contains("directly call");
            if let Some(va) = known_address
                && let Some(sketch) = crate::analysis::sketch::at_va(&project, va)
            {
                let verdict = if direct_call_claim && sketch.direct_calls.is_empty() {
                    "contradicted"
                } else {
                    "unknown"
                };
                return success_json(&json!({
                    "state":"complete",
                    "investigation_id":investigation.id,
                    "target_id":target_id,
                    "revision":revision,
                    "evidence_delta":[sketch_fact_delta(sketch, 0, Vec::new())],
                    "verdict":verdict,
                    "answer":verdict.to_ascii_uppercase(),
                    "uncertainty":if verdict == "unknown" { "sketch cannot prove the requested semantics" } else { "none" },
                    "next_actions":[],
                }));
            }
        }

        if let Some(best) = ranked.first() {
            let has_semantic_proof = best
                .evidence
                .iter()
                .any(|value| value.starts_with("motif:") || value == "constraint:exact_address");
            let is_unique = ranked.get(1).is_none_or(|second| best.score > second.score);
            if has_semantic_proof && is_unique {
                return success_json(&json!({
                    "state":"complete",
                    "investigation_id":investigation.id,
                    "intent":investigation.intent,
                    "target_id":target_id,
                    "revision":revision,
                    "stage":"function",
                    "answer":{"address":best.va,"semantic_tags":sketch_semantic_tags(&best.sketch)},
                    "evidence_delta":[sketch_delta(best)],
                    "omitted":ranked.len().saturating_sub(1),
                    "completeness_reason":"unique candidate verified by intersecting structural constraints",
                    "uncertainty":"none",
                    "next_actions":[],
                }));
            }
        }

        if matches!(intent, "capability" | "dump") {
            let result = self.search_capabilities(&investigation.question, 3);
            let mut capability_actions = Vec::new();
            if capability_ids(&result).contains(&"list_imports") {
                let mut arguments = serde_json::Map::new();
                arguments.insert("project_id".into(), json!(target_id.to_string()));
                arguments.insert("offset".into(), json!(0));
                arguments.insert("limit".into(), json!(32));
                let ticket = self.bind_action(
                    investigation,
                    "list PE imports",
                    "list_imports",
                    arguments,
                    Some(revision),
                );
                capability_actions.push(action_json(&ticket, true));
            }
            return success_json(&json!({
                "state":"partial",
                "investigation_id":investigation.id,
                "target_id":target_id,
                "revision":revision,
                "evidence_delta":result.structured_content,
                "next_actions":capability_actions,
                "uncertainty":if capability_actions.is_empty() { "matching capability requires inputs or a deeper target stage" } else { "execute the bound action ticket to obtain evidence" },
            }));
        }

        let state = if ranked.is_empty() {
            "complete"
        } else {
            "partial"
        };
        success_json(&json!({
            "state":state,
            "investigation_id":investigation.id,
            "intent":investigation.intent,
            "budget":investigation.budget,
            "target_id":target_id,
            "revision":revision,
            "evidence_delta":ranked_delta,
            "omitted":0,
            "uncertainty":if actions.is_empty() { "no matching sketch; unsupported rather than guessed" } else { "candidates require verification" },
            "next_actions":actions,
        }))
    }

    fn run_sketch_investigation(
        &self,
        investigation: &Investigation,
        target_handle: &str,
        path: &str,
        sketch_image: &crate::analysis::sketch::SketchImage,
    ) -> CallToolResult {
        let rank_limit = if investigation.budget == "tiny" { 2 } else { 3 };
        let ranked = crate::analysis::sketch::rank_sketches(
            &sketch_image.sketches,
            &investigation.question,
            rank_limit,
        );
        let ranked_delta: Vec<_> = ranked.iter().map(sketch_delta).collect();
        let lower_question = investigation.question.to_ascii_lowercase();
        if investigation.intent == "capability"
            && lower_question.contains("deep")
            && lower_question.contains("index")
        {
            let mut arguments = serde_json::Map::new();
            arguments.insert("target_handle".into(), json!(target_handle));
            let action = self.bind_action(
                investigation,
                "build or load the compact partitioned deep index",
                "__build_deep_index",
                arguments,
                None,
            );
            return success_json(&json!({
                "state":"partial",
                "investigation_id":investigation.id,
                "target_id":target_handle,
                "stage":"sketch",
                "evidence_delta":[{"id":format!("capability:{target_handle}:deep"),"kind":"capability","record_bytes":8,"partition":"section"}],
                "uncertainty":"deep index is not built until its action is executed",
                "next_actions":[action_json(&action, true)],
            }));
        }
        if investigation.intent == "capability" {
            return self.run_compact_capability_investigation(investigation, target_handle);
        }
        if investigation.intent == "verify"
            && let Some(va) = first_hex_address(&investigation.question)
            && let Some(sketch) = sketch_image.sketches.iter().find(|value| value.va == va)
        {
            let direct_call_claim = investigation
                .question
                .to_ascii_lowercase()
                .contains("directly call");
            let verdict = if direct_call_claim && sketch.direct_calls.is_empty() {
                "contradicted"
            } else {
                "unknown"
            };
            return success_json(&json!({
                "state":"complete",
                "investigation_id":investigation.id,
                "target_id":target_handle,
                "stage":"sketch",
                "evidence_delta":[sketch_fact_delta(sketch, 0, vec!["authoritative function range".to_string()])],
                "verdict":verdict,
                "answer":verdict.to_ascii_uppercase(),
                "uncertainty":if verdict == "unknown" { "function sketch cannot prove the requested semantics" } else { "none" },
                "next_actions":[],
            }));
        }
        if let Some(best) = ranked.first() {
            let has_semantic_proof = best
                .evidence
                .iter()
                .any(|value| value.starts_with("motif:") || value == "constraint:exact_address");
            let is_unique = ranked.get(1).is_none_or(|second| best.score > second.score);
            if has_semantic_proof && is_unique {
                let tags = sketch_semantic_tags(&best.sketch);
                return success_json(&json!({
                    "state":"complete",
                    "investigation_id":investigation.id,
                    "intent":investigation.intent,
                    "target_id":target_handle,
                    "revision":0,
                    "stage":"sketch",
                    "answer":{"address":best.va,"semantic_tags":tags},
                    "evidence_delta":[sketch_delta(best)],
                    "omitted":ranked.len().saturating_sub(1),
                    "completeness_reason":"unique candidate verified by intersecting structural constraints",
                    "uncertainty":"none",
                    "next_actions":[],
                }));
            }
        }
        let mut actions = Vec::new();
        for candidate in ranked.iter().take(2) {
            let mut arguments = serde_json::Map::new();
            arguments.insert("path".into(), json!(path));
            arguments.insert("target_handle".into(), json!(target_handle));
            arguments.insert("va".into(), json!(candidate.va));
            let ticket = self.bind_action(
                investigation,
                &format!("inspect bounded function window {}", candidate.va),
                "__inspect_window",
                arguments,
                None,
            );
            actions.push(action_json(&ticket, true));
        }
        success_json(&json!({
            "state":if ranked.is_empty() { "complete" } else { "partial" },
            "investigation_id":investigation.id,
            "intent":investigation.intent,
            "target_id":target_handle,
            "revision":0,
            "stage":"sketch",
            "sketch_metrics":{"functions":sketch_image.sketches.len(),"decoded":sketch_image.decoded_instructions,"elapsed_ms":sketch_image.elapsed_ms},
            "evidence_delta":ranked_delta,
            "omitted":0,
            "uncertainty":if actions.is_empty() { "no matching sketch; unsupported rather than guessed" } else { "ranked structural evidence; inspect only if more proof is required" },
            "next_actions":actions,
        }))
    }

    fn run_compact_capability_investigation(
        &self,
        investigation: &Investigation,
        target_handle: &str,
    ) -> CallToolResult {
        let result = self.search_capabilities(&investigation.question, 3);
        let mut actions = Vec::new();
        if capability_ids(&result).contains(&"list_imports") {
            let mut arguments = serde_json::Map::new();
            arguments.insert("target_handle".into(), json!(target_handle));
            arguments.insert("offset".into(), json!(0));
            arguments.insert("limit".into(), json!(32));
            let ticket = self.bind_action(
                investigation,
                "list PE imports from the compact catalog",
                "__catalog_list_imports",
                arguments,
                None,
            );
            actions.push(action_json(&ticket, true));
        }
        success_json(&json!({
            "state":"partial",
            "investigation_id":investigation.id,
            "target_id":target_handle,
            "revision":0,
            "stage":"catalog",
            "evidence_delta":result.structured_content,
            "next_actions":actions,
            "uncertainty":if actions.is_empty() { "matching capability requires inputs or a deeper target stage" } else { "execute the bound action ticket to obtain evidence" },
        }))
    }

    fn bind_action(
        &self,
        investigation: &Investigation,
        label: &str,
        capability: &str,
        arguments: serde_json::Map<String, serde_json::Value>,
        expected_revision: Option<u64>,
    ) -> ActionTicket {
        let ticket = ActionTicket {
            id: Uuid::new_v4().to_string(),
            investigation_id: investigation.id.clone(),
            label: label.to_string(),
            capability: capability.to_string(),
            arguments,
            expected_revision,
            created: Instant::now(),
        };
        self.shared
            .actions
            .lock()
            .unwrap()
            .insert(ticket.id.clone(), ticket.clone());
        ticket
    }

    async fn prepare_step(
        &self,
        _investigation_id: Option<&str>,
        action_id: &str,
        inputs: serde_json::Map<String, serde_json::Value>,
    ) -> StepPlan {
        let ticket = self.shared.actions.lock().unwrap().get(action_id).cloned();
        let Some(mut ticket) = ticket else {
            return StepPlan::Immediate(tool_error_json(
                "ACTION_NOT_FOUND",
                "action is missing or expired",
                json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                false,
            ));
        };
        let investigation_id = ticket.investigation_id.clone();
        if ticket.created.elapsed() > INVESTIGATION_TTL {
            return StepPlan::Immediate(tool_error_json(
                "ACTION_EXPIRED",
                "action expired",
                json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                true,
            ));
        }
        if ticket.capability == "__poll_open" {
            let investigation = self
                .shared
                .investigations
                .lock()
                .unwrap()
                .get(&investigation_id)
                .cloned();
            let Some(mut investigation) = investigation else {
                return StepPlan::Immediate(tool_error_json(
                    "INVESTIGATION_NOT_FOUND",
                    "investigation is missing or expired",
                    json!({}),
                    false,
                ));
            };
            let job_id = investigation.open_job_id.clone().unwrap_or_default();
            let mut job = self.shared.open_jobs.lock().unwrap().get(&job_id).cloned();
            // A continuation is a request to make foreground progress, not a
            // status poll. Give the promoted job its normal foreground window
            // before charging the model another action/call cycle.
            let foreground_deadline = Instant::now() + Duration::from_secs(2);
            while matches!(
                job.as_ref().map(|value| &value.state),
                Some(OpenJobState::Running { .. })
            ) && Instant::now() < foreground_deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
                job = self.shared.open_jobs.lock().unwrap().get(&job_id).cloned();
            }
            let job_path = job.as_ref().map(|job| job.path.clone()).unwrap_or_default();
            return match job.map(|job| job.state) {
                Some(OpenJobState::SketchReady { sketch, .. }) => {
                    if investigation_requires_full_project(&investigation) {
                        self.promote_analysis(&job_id);
                        StepPlan::Immediate(success_json(&json!({
                            "state":"pending",
                            "investigation_id":investigation_id,
                            "target_id":job_id,
                            "stage":"function",
                            "completeness_reason":"mutable or specialized work promoted a full project",
                            "evidence_delta":[],
                            "next_actions":[action_json(&ticket, false)],
                        })))
                    } else {
                        StepPlan::Immediate(self.run_sketch_investigation(
                            &investigation,
                            &job_id,
                            &job_path,
                            sketch.as_ref(),
                        ))
                    }
                }
                Some(OpenJobState::Ready { target_id }) => {
                    investigation.target_id = Some(target_id);
                    self.shared
                        .investigations
                        .lock()
                        .unwrap()
                        .insert(investigation_id.to_string(), investigation.clone());
                    StepPlan::Immediate(self.run_investigation(&investigation))
                }
                Some(OpenJobState::CatalogReady { catalog }) => {
                    let lower_question = investigation.question.to_ascii_lowercase();
                    if investigation.intent == "capability"
                        && !(lower_question.contains("deep") && lower_question.contains("index"))
                    {
                        return StepPlan::Immediate(
                            self.run_compact_capability_investigation(&investigation, &job_id),
                        );
                    }
                    let crypto_query = ["aes", "gcm", "encrypt", "cryptographic"]
                        .iter()
                        .any(|term| investigation.question.to_ascii_lowercase().contains(term));
                    if investigation.intent == "verify"
                        && crypto_query
                        && catalog.security_markers.is_empty()
                    {
                        StepPlan::Immediate(success_json(&json!({
                            "state":"complete",
                            "investigation_id":investigation_id,
                            "target_id":job_id,
                            "stage":"catalog",
                            "evidence_delta":[{"id":format!("catalog:{job_id}"),"kind":"catalog","facts":catalog}],
                            "verdict":"unknown",
                            "answer":"UNKNOWN",
                            "uncertainty":"catalog has no AES/GCM imports or strings; custom cryptography was not inferred",
                            "next_actions":[],
                        })))
                    } else {
                        let requires_full_project =
                            investigation_requires_full_project(&investigation);
                        if requires_full_project {
                            self.promote_analysis(&job_id);
                        } else {
                            self.promote_sketch(&job_id);
                        }
                        let deadline = Instant::now() + Duration::from_secs(2);
                        loop {
                            let state = self
                                .shared
                                .open_jobs
                                .lock()
                                .unwrap()
                                .get(&job_id)
                                .map(|job| job.state.clone());
                            match state {
                                Some(OpenJobState::SketchReady { sketch, .. }) => {
                                    break StepPlan::Immediate(self.run_sketch_investigation(
                                        &investigation,
                                        &job_id,
                                        &job_path,
                                        sketch.as_ref(),
                                    ));
                                }
                                Some(OpenJobState::Ready { target_id }) => {
                                    investigation.target_id = Some(target_id);
                                    self.shared.investigations.lock().unwrap().insert(
                                        investigation_id.to_string(),
                                        investigation.clone(),
                                    );
                                    break StepPlan::Immediate(
                                        self.run_investigation(&investigation),
                                    );
                                }
                                Some(OpenJobState::Failed { error }) => {
                                    break StepPlan::Immediate(tool_error_json(
                                        "TARGET_OPEN_FAILED",
                                        error,
                                        json!({"job_id":job_id}),
                                        false,
                                    ));
                                }
                                _ if Instant::now() >= deadline => {
                                    break StepPlan::Immediate(success_json(&json!({
                                        "state":"pending",
                                        "investigation_id":investigation_id,
                                        "target_id":job_id,
                                        "stage":"sketch",
                                        "evidence_delta":[{"id":format!("catalog:{job_id}"),"kind":"catalog","facts":catalog}],
                                        "completeness_reason":"function sketch continues in a foreground-priority job",
                                        "next_actions":[action_json(&ticket, false)],
                                    })));
                                }
                                _ => tokio::time::sleep(Duration::from_millis(10)).await,
                            }
                        }
                    }
                }
                Some(OpenJobState::Failed { error }) => StepPlan::Immediate(tool_error_json(
                    "TARGET_OPEN_FAILED",
                    error,
                    json!({"job_id":job_id}),
                    false,
                )),
                Some(OpenJobState::Running { stage, progress }) => {
                    StepPlan::Immediate(success_json(&json!({
                        "state":"pending",
                        "investigation_id":investigation_id,
                        "job_id":job_id,
                        "stage":stage,
                        "progress":progress,
                        "evidence_delta":[],
                        "next_actions":[action_json(&ticket, false)],
                    })))
                }
                None => StepPlan::Immediate(tool_error_json(
                    "JOB_NOT_FOUND",
                    "target-open job is missing",
                    json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                    true,
                )),
            };
        }
        if ticket.capability == "__build_deep_index" {
            let target_handle = ticket
                .arguments
                .get("target_handle")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let existing = self
                .shared
                .deep_jobs
                .lock()
                .unwrap()
                .get(&target_handle)
                .cloned();
            if existing.is_none() {
                let source = self
                    .shared
                    .open_jobs
                    .lock()
                    .unwrap()
                    .get(&target_handle)
                    .and_then(|job| match &job.state {
                        OpenJobState::SketchReady { catalog, .. } => {
                            Some((job.path.clone(), catalog.clone()))
                        }
                        _ => None,
                    });
                let Some((path, catalog)) = source else {
                    return StepPlan::Immediate(tool_error_json(
                        "TARGET_NOT_READY",
                        "deep indexing requires a ready compact sketch target",
                        json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                        true,
                    ));
                };
                self.shared
                    .deep_jobs
                    .lock()
                    .unwrap()
                    .insert(target_handle.clone(), DeepJobState::Running);
                let shared = self.shared.clone();
                let cache_root = self.manager.home_dir().to_path_buf();
                let deep_handle = target_handle.clone();
                self.manager.runtime().handle().spawn(async move {
                    let outcome = tokio::task::spawn_blocking(move || {
                        crate::analysis::compact_index::load_or_build_cached(
                            std::path::Path::new(&path),
                            &cache_root,
                            &catalog.image_sha256,
                            catalog.bitness,
                        )
                    })
                    .await;
                    let state = match outcome {
                        Ok(Ok(index)) => DeepJobState::Ready(Arc::new(index)),
                        Ok(Err(error)) => {
                            DeepJobState::Failed(sanitize_untrusted_text(&error.to_string(), 512))
                        }
                        Err(error) => DeepJobState::Failed(format!("deep worker failed: {error}")),
                    };
                    shared.deep_jobs.lock().unwrap().insert(deep_handle, state);
                });
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let state = self
                    .shared
                    .deep_jobs
                    .lock()
                    .unwrap()
                    .get(&target_handle)
                    .cloned();
                match state {
                    Some(DeepJobState::Ready(index)) => {
                        return StepPlan::Immediate(success_json(&json!({
                            "state":"complete",
                            "investigation_id":investigation_id,
                            "target_id":target_handle,
                            "stage":"deep",
                            "evidence_delta":[{
                                "id":format!("deep:{target_handle}"),"kind":"compact_instruction_index",
                                "instructions":index.instructions,"sections":index.sections.len(),
                                "record_bytes":std::mem::size_of::<crate::analysis::compact_index::InstrMeta>(),
                                "retained_bytes":index.instructions * std::mem::size_of::<crate::analysis::compact_index::InstrMeta>(),
                                "elapsed_ms":index.elapsed_ms,"cache_hit":index.cache_hit,
                            }],
                            "uncertainty":"none","next_actions":[],
                        })));
                    }
                    Some(DeepJobState::Failed(error)) => {
                        return StepPlan::Immediate(tool_error_json(
                            "DEEP_INDEX_FAILED",
                            error,
                            json!({"target_id":target_handle}),
                            true,
                        ));
                    }
                    _ if Instant::now() >= deadline => {
                        return StepPlan::Immediate(success_json(&json!({
                            "state":"pending","investigation_id":investigation_id,
                            "target_id":target_handle,"stage":"deep",
                            "completeness_reason":"compact deep index is still building",
                            "evidence_delta":[],"next_actions":[action_json(&ticket, false)],
                        })));
                    }
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
        if ticket.capability == "__catalog_list_imports" {
            let target_handle = ticket
                .arguments
                .get("target_handle")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let offset = inputs
                .get("offset")
                .or_else(|| ticket.arguments.get("offset"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or_default();
            let limit = inputs
                .get("limit")
                .or_else(|| ticket.arguments.get("limit"))
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(32)
                .clamp(1, 128);
            let catalog = self
                .shared
                .open_jobs
                .lock()
                .unwrap()
                .get(target_handle)
                .and_then(|job| match &job.state {
                    OpenJobState::CatalogReady { catalog }
                    | OpenJobState::SketchReady { catalog, .. } => Some(catalog.clone()),
                    _ => None,
                });
            let Some(catalog) = catalog else {
                return StepPlan::Immediate(tool_error_json(
                    "CATALOG_NOT_READY",
                    "compact import catalog is missing or expired",
                    json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                    true,
                ));
            };
            let page: Vec<_> = catalog
                .import_items
                .iter()
                .skip(offset)
                .take(limit)
                .map(|item| json!({"dll":item.dll,"name":item.name}))
                .collect();
            let next = offset.saturating_add(page.len());
            return StepPlan::Immediate(success_json(&json!({
                "state":"complete",
                "investigation_id":investigation_id,
                "target_id":target_handle,
                "stage":"catalog",
                "imports":page,
                "total":catalog.import_items.len(),
                "offset":offset,
                "next_offset":if next < catalog.import_items.len() { Some(next) } else { None::<usize> },
                "evidence_delta":[{"id":format!("imports:{target_handle}:{offset}"),"kind":"pe_imports","count":page.len()}],
                "uncertainty":"none",
                "next_actions":[],
            })));
        }
        if ticket.capability == "__inspect_window" {
            let target_handle = ticket
                .arguments
                .get("target_handle")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let va = ticket
                .arguments
                .get("va")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| parse_va(value).ok());
            let state = self
                .shared
                .open_jobs
                .lock()
                .unwrap()
                .get(target_handle)
                .map(|job| job.state.clone());
            if let (Some(va), Some(OpenJobState::SketchReady { sketch, .. })) = (va, state)
                && let Some(fact) = sketch.sketches.iter().find(|value| value.va == va)
            {
                return StepPlan::Immediate(success_json(&json!({
                    "state":"complete",
                    "investigation_id":investigation_id,
                    "target_id":target_handle,
                    "stage":"function",
                    "evidence_delta":[sketch_fact_delta(fact, 0, vec!["bounded function window".to_string()])],
                    "uncertainty":"instruction window was summarized into typed structural facts",
                    "next_actions":[],
                })));
            }
            return StepPlan::Immediate(tool_error_json(
                "WINDOW_NOT_READY",
                "bounded function window is missing or expired",
                json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                true,
            ));
        }
        for (key, value) in inputs {
            ticket.arguments.insert(key, value);
        }
        if let Some(expected_revision) = ticket.expected_revision
            && let Some(project_id) = ticket
                .arguments
                .get("project_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
            && self.manager.get(project_id).map(|project| project.op_seq) != Some(expected_revision)
        {
            return StepPlan::Immediate(tool_error_json(
                "REVISION_CONFLICT",
                "target changed after this action was issued",
                json!({"repair":[{"tool":"investigation_start","reuse_question":true}]}),
                true,
            ));
        }
        StepPlan::Execute(ticket)
    }

    fn commit_change(
        &self,
        proposal_id: &str,
        expected_revision: u64,
        idempotency_key: &str,
    ) -> Result<ChangeProposal, CallToolResult> {
        if !(8..=128).contains(&idempotency_key.len()) {
            return Err(tool_error_json(
                "INVALID_ARGUMENT",
                "idempotency_key must contain 8..128 bytes",
                json!({"repair":[{"field":"idempotency_key","example":"case-0001-edit"}]}),
                false,
            ));
        }
        let proposal = self
            .shared
            .proposals
            .lock()
            .unwrap()
            .get(proposal_id)
            .cloned()
            .ok_or_else(|| {
                tool_error_json(
                    "PROPOSAL_NOT_FOUND",
                    "proposal is missing or expired",
                    json!({"repair":[{"intent":"edit","reuse_question":true}]}),
                    false,
                )
            })?;
        if proposal.created.elapsed() > INVESTIGATION_TTL {
            return Err(tool_error_json(
                "PROPOSAL_EXPIRED",
                "proposal expired",
                json!({"repair":[{"intent":"edit","reuse_question":true}]}),
                true,
            ));
        }
        let cache_key = format!("v3:{}:{idempotency_key}", proposal.target_id);
        if let Some(cached) = self
            .shared
            .edit_results
            .lock()
            .unwrap()
            .get(&cache_key)
            .cloned()
        {
            return Err(cached);
        }
        let current = self
            .manager
            .get(proposal.target_id)
            .map(|project| project.op_seq);
        if expected_revision != proposal.expected_revision || current != Some(expected_revision) {
            return Err(tool_error_json(
                "REVISION_CONFLICT",
                "proposal revision does not match the current target",
                json!({"expected_revision":proposal.expected_revision,"current_revision":current}),
                true,
            ));
        }
        Ok(proposal)
    }

    fn status_result(&self, job_id: Option<&str>) -> CallToolResult {
        let mut value = server_status_json(&self.manager);
        let mut jobs = self.shared.open_jobs.lock().unwrap();
        prune_open_jobs(&mut jobs);
        if let Some(job_id) = job_id {
            let Some(job) = jobs.get(job_id) else {
                return tool_error_json(
                    "JOB_NOT_FOUND",
                    "open job not found",
                    json!({ "job_id": job_id }),
                    false,
                );
            };
            value["job"] = open_job_json(job);
        } else {
            value["jobs"] = serde_json::Value::Array(jobs.values().map(open_job_json).collect());
        }
        success_json(&value)
    }

    fn status_v3(&self, id: Option<&str>) -> CallToolResult {
        let mut value = server_status_json(&self.manager);
        value["protocol"] = json!("windy-eqvm-v3");
        value["public_tools"] = json!(v3::PUBLIC_TOOL_NAMES);
        let Some(id) = id else {
            value["investigations"] = json!(self.shared.investigations.lock().unwrap().len());
            value["actions"] = json!(self.shared.actions.lock().unwrap().len());
            return success_json(&value);
        };
        if let Some(investigation) = self.shared.investigations.lock().unwrap().get(id).cloned() {
            value["investigation"] = json!({
                "investigation_id":investigation.id,
                "intent":investigation.intent,
                "budget":investigation.budget,
                "target_id":investigation.target_id,
                "job_id":investigation.open_job_id,
                "age_ms":investigation.created.elapsed().as_millis(),
            });
            return success_json(&value);
        }
        if let Some(action) = self.shared.actions.lock().unwrap().get(id).cloned() {
            value["action"] = action_json(&action, true);
            return success_json(&value);
        }
        if self.shared.open_jobs.lock().unwrap().contains_key(id) {
            return self.status_result(Some(id));
        }
        if let Ok(project_id) = Uuid::parse_str(id)
            && let Some(project) = self.manager.get(project_id)
        {
            value["target"] = json!({
                "target_id":project_id,
                "revision":project.op_seq,
                "sha256":project.image_sha256,
                "bitness":project.bitness,
                "functions":project.functions().len(),
            });
            return success_json(&value);
        }
        tool_error_json(
            "ID_NOT_FOUND",
            "no target, job, investigation, or action has this id",
            json!({"id":id}),
            false,
        )
    }

    fn search_capabilities(&self, query: &str, limit: usize) -> CallToolResult {
        let query = query.trim().to_ascii_lowercase();
        let terms: Vec<_> = query
            .split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|term| term.len() >= 2)
            .collect();
        let mut ranked = Vec::new();
        for tool in Self::tool_router().list_all() {
            let name = tool.name.to_string();
            let description = tool.description.as_deref().unwrap_or_default();
            let haystack =
                format!("{} {}", name.replace('_', " "), description).to_ascii_lowercase();
            let mut score = usize::from(!query.is_empty() && haystack.contains(&query)) * 100;
            score += terms
                .iter()
                .map(|term| {
                    usize::from(name.contains(term)) * 20 + usize::from(haystack.contains(term)) * 5
                })
                .sum::<usize>();
            if score == 0 {
                continue;
            }
            let required = tool
                .input_schema
                .get("required")
                .cloned()
                .unwrap_or_else(|| json!([]));
            let arguments = capability_argument_summary(&tool.input_schema);
            ranked.push((
                score,
                json!({
                    "capability_id": name,
                    "description": sanitize_untrusted_text(description, 240),
                    "required": required,
                    "arguments": arguments,
                }),
            ));
        }
        ranked.sort_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| {
                left.1["capability_id"]
                    .as_str()
                    .cmp(&right.1["capability_id"].as_str())
            })
        });
        let total = ranked.len();
        let capabilities: Vec<_> = ranked
            .into_iter()
            .take(limit)
            .map(|(_, value)| value)
            .collect();
        success_json(&json!({
            "query": query,
            "count": capabilities.len(),
            "total_matches": total,
            "capabilities": capabilities,
        }))
    }

    fn read_artifact(&self, artifact_id: &str, offset: usize, max_bytes: usize) -> CallToolResult {
        let mut artifacts = self.shared.artifacts.lock().unwrap();
        artifacts.retain(|_, artifact| artifact.created.elapsed() <= ARTIFACT_TTL);
        let Some(artifact) = artifacts.get(artifact_id) else {
            return tool_error_json(
                "ARTIFACT_NOT_FOUND",
                "artifact is missing or expired",
                json!({ "artifact_id": artifact_id }),
                false,
            );
        };
        let body = artifact.body.as_ref();
        let mut start = offset.min(body.len());
        while start < body.len() && !body.is_char_boundary(start) {
            start += 1;
        }
        let mut end = start.saturating_add(max_bytes).min(body.len());
        while end > start && !body.is_char_boundary(end) {
            end -= 1;
        }
        success_json(&json!({
            "artifact_id": artifact_id,
            "offset": start,
            "next_cursor": (end < body.len()).then(|| format!("{artifact_id}:{end}")),
            "total_bytes": body.len(),
            "complete": end == body.len(),
            "chunk": &body[start..end],
        }))
    }

    fn normalize_v3_result(
        &self,
        tool_name: &str,
        mut result: CallToolResult,
        max_output_bytes: usize,
    ) -> CallToolResult {
        let is_error = result.is_error == Some(true);
        let data = result
            .structured_content
            .take()
            .unwrap_or_else(|| json!({}));
        let data_state = data
            .get("status")
            .or_else(|| data.get("state"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let pending = data_state == "pending";
        let data_failed = data_state == "error";
        let target_id = data
            .get("project_id")
            .or_else(|| data.get("target_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let revision = target_id
            .as_deref()
            .and_then(|id| Uuid::parse_str(id).ok())
            .and_then(|id| self.manager.get(id))
            .map(|project| project.op_seq);
        let state = if is_error || data_failed {
            "error"
        } else if pending {
            "pending"
        } else {
            "complete"
        };
        let mut envelope = json!({
            "v": 3,
            "tool": tool_name,
            "state": state,
            "completeness": if pending { "pending" } else if is_error || data_failed { "unknown" } else { "complete" },
            "target_id": target_id,
            "revision": revision,
            "data": data,
        });
        let encoded = serde_json::to_string(&envelope).unwrap_or_default();
        let artifact_id = if encoded.len() > max_output_bytes {
            let artifact_id = Uuid::new_v4().to_string();
            let mut artifacts = self.shared.artifacts.lock().unwrap();
            artifacts.retain(|_, artifact| artifact.created.elapsed() <= ARTIFACT_TTL);
            artifacts.insert(
                artifact_id.clone(),
                StoredArtifact {
                    body: Arc::from(encoded.as_str()),
                    created: Instant::now(),
                },
            );
            let preview = compact_preview(&envelope, 0);
            envelope = json!({
                "v": 3,
                "tool": tool_name,
                "state": state,
                "completeness": "partial",
                "target_id": target_id,
                "revision": revision,
                "data": preview,
                "artifact": {
                    "artifact_id": artifact_id,
                    "cursor": format!("{artifact_id}:0"),
                    "total_bytes": encoded.len(),
                    "expires_after_seconds": ARTIFACT_TTL.as_secs(),
                },
            });
            if serde_json::to_vec(&envelope).map_or(usize::MAX, |bytes| bytes.len())
                > max_output_bytes
            {
                envelope["data"] = json!({
                    "message": "result exceeded the inline budget; read the artifact deliberately"
                });
            }
            Some(artifact_id)
        } else {
            None
        };
        let summary = artifact_id.map_or_else(
            || format!("{tool_name}: {state}"),
            |id| format!("{tool_name}: partial; full result in artifact {id}"),
        );
        result.structured_content = Some(envelope);
        result.content = vec![Content::text(summary)];
        result
    }
}

fn route_result(result: Result<CallToolResult, rmcp::ErrorData>) -> CallToolResult {
    match result {
        Ok(result) => result,
        Err(error) => mcp_error_result(error),
    }
}

fn open_job_json(job: &OpenJob) -> serde_json::Value {
    let (state, stage, progress, target_id, error) = match &job.state {
        OpenJobState::Running { stage, progress } => {
            ("pending", Some(stage.as_str()), Some(*progress), None, None)
        }
        OpenJobState::CatalogReady { .. } => (
            "partial",
            Some("catalog ready"),
            Some(0.25),
            Some(job.id.clone()),
            None,
        ),
        OpenJobState::SketchReady { .. } => (
            "partial",
            Some("sketch ready"),
            Some(0.75),
            Some(job.id.clone()),
            None,
        ),
        OpenJobState::Ready { target_id } => (
            "complete",
            Some("done"),
            Some(1.0),
            Some(target_id.to_string()),
            None,
        ),
        OpenJobState::Failed { error } => ("error", None, None, None, Some(error.as_str())),
    };
    json!({
        "job_id": job.id,
        "path": sanitize_untrusted_text(&job.path, 512),
        "state": state,
        "stage": stage,
        "progress": progress,
        "target_id": target_id,
        "error": error,
        "elapsed_ms": job.started.elapsed().as_millis(),
        "catalog":match &job.state {
            OpenJobState::CatalogReady { catalog } | OpenJobState::SketchReady { catalog, .. } => Some(catalog),
            _ => None,
        },
        "sketch":match &job.state {
            OpenJobState::SketchReady { sketch, .. } => Some(json!({
                "functions":sketch.sketches.len(),"decoded":sketch.decoded_instructions,
                "elapsed_ms":sketch.elapsed_ms,"cache_hit":sketch.cache_hit
            })),
            _ => None,
        },
    })
}

fn build_catalog_cached(
    path: &std::path::Path,
    cache_root: &std::path::Path,
) -> anyhow::Result<CatalogSnapshot> {
    let started = Instant::now();
    let image_sha256 = crate::analysis::structural_cache::hash_path_memoized(path, cache_root)?;
    let bitness = crate::analysis::structural_cache::pe_bitness(path)?;
    let abi = format!("v3-catalog-2-{bitness}-default");
    let cache_path = crate::analysis::structural_cache::partition_path(
        cache_root,
        "catalog",
        &image_sha256,
        &abi,
    );
    if let Some(mut cached) = crate::analysis::structural_cache::load::<CatalogSnapshot>(
        &cache_path,
        &abi,
        &image_sha256,
    )? {
        cached.elapsed_ms = started.elapsed().as_millis();
        cached.cache_hit = true;
        return Ok(cached);
    }
    let mut built = build_catalog(path, image_sha256)?;
    crate::analysis::structural_cache::store(&cache_path, &abi, &built.image_sha256, &built)?;
    let _ = crate::analysis::structural_cache::prune_lru(
        &cache_root.join("structural"),
        crate::analysis::structural_cache::DEFAULT_MAX_BYTES,
    );
    built.cache_hit = false;
    Ok(built)
}

fn build_catalog(path: &std::path::Path, image_sha256: String) -> anyhow::Result<CatalogSnapshot> {
    let started = Instant::now();
    let pe = crate::loader::pe::LoadedPe::open_catalog(path)?;
    let import_items: Vec<_> = pe
        .triage
        .imports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .flat_map(|entry| {
            entry.functions.iter().map(|function| CatalogImport {
                dll: entry.dll.clone(),
                name: function.name.clone(),
            })
        })
        .collect();
    let imports = import_items.len();
    let exports = serde_json::to_value(&pe.triage.exports)
        .ok()
        .map(|value| {
            value
                .as_array()
                .map_or(usize::from(!value.is_null()), Vec::len)
        })
        .unwrap_or_default();
    let strings = pe.triage.strings.as_deref().unwrap_or_default();
    let mut security_markers = Vec::new();
    if let Some(entries) = &pe.triage.imports {
        for entry in entries {
            for function in &entry.functions {
                let lower = function.name.to_ascii_lowercase();
                if ["aes", "gcm", "bcrypt", "cryptencrypt"]
                    .iter()
                    .any(|marker| lower.contains(marker))
                {
                    security_markers.push(format!(
                        "import:{}",
                        sanitize_untrusted_text(&function.name, 96)
                    ));
                }
            }
        }
    }
    for string in strings {
        let lower = string.value.to_ascii_lowercase();
        if ["aes", "gcm", "encrypt"]
            .iter()
            .any(|marker| lower.contains(marker))
        {
            security_markers.push(format!("string@{}", string.offset));
        }
        if security_markers.len() >= 16 {
            break;
        }
    }
    security_markers.sort();
    security_markers.dedup();
    let magic = pe
        .triage
        .optional_header
        .as_ref()
        .map(|header| header.magic.as_str())
        .unwrap_or("PE32");
    Ok(CatalogSnapshot {
        elapsed_ms: started.elapsed().as_millis(),
        image_sha256,
        bytes: std::fs::metadata(path)?.len(),
        bitness: if magic.contains('+') { 64 } else { 32 },
        sections: pe.triage.sections.as_deref().unwrap_or_default().len(),
        imports,
        import_items,
        exports,
        strings: strings.len(),
        security_markers,
        cache_hit: false,
    })
}

fn prune_open_jobs(jobs: &mut HashMap<String, OpenJob>) {
    jobs.retain(|_, job| {
        matches!(job.state, OpenJobState::Running { .. }) || job.started.elapsed() <= ARTIFACT_TTL
    });
}

fn prune_investigations(investigations: &mut HashMap<String, Investigation>) {
    investigations.retain(|_, value| value.created.elapsed() <= INVESTIGATION_TTL);
}

fn action_json(action: &ActionTicket, _bound: bool) -> serde_json::Value {
    json!({
        "purpose":action.label,
        "execute":{
            "tool":"investigation_step",
            "arguments":{"action_id":action.id}
        }
    })
}

fn sketch_delta(candidate: &crate::analysis::sketch::RankedSketch) -> serde_json::Value {
    sketch_fact_delta(
        &candidate.sketch,
        candidate.score,
        candidate.evidence.clone(),
    )
}

fn sketch_semantic_tags(sketch: &crate::analysis::sketch::FunctionSketch) -> Vec<&'static str> {
    if sketch
        .motifs
        .iter()
        .any(|motif| motif == "arithmetic_dispatch")
    {
        vec!["ADD", "SUBTRACT", "MULTIPLY"]
    } else if sketch
        .motifs
        .iter()
        .any(|motif| motif == "xor_multiply_hash")
    {
        vec!["BYTE", "XOR", "MULTIPLY"]
    } else {
        Vec::new()
    }
}

fn sketch_fact_delta(
    sketch: &crate::analysis::sketch::FunctionSketch,
    score: u32,
    support: Vec<String>,
) -> serde_json::Value {
    json!({
        "id":format!("sketch:{:#x}", sketch.va),
        "kind":"function_sketch",
        "address":format!("{:#x}", sketch.va),
        "score":score,
        "support":support,
        "facts":{
            "size":sketch.size,
            "blocks":sketch.blocks,
            "loops":sketch.loops,
            "calls":sketch.direct_calls.iter().take(6).map(|value|format!("{value:#x}")).collect::<Vec<_>>(),
            "byte_memory":sketch.byte_memory_ops,
            "memory":sketch.memory_ops,
            "add":sketch.adds,
            "subtract":sketch.subtracts,
            "multiply":sketch.multiplies,
            "xor":sketch.xors,
            "zero_tests":sketch.zero_tests,
            "motifs":sketch.motifs,
        }
    })
}

fn public_call_repair(
    tool: &str,
    supplied: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    match tool {
        "investigation_start" => json!({
            "supplied_fields":supplied.keys().collect::<Vec<_>>(),
            "repair":[{
                "tool":"investigation_start",
                "arguments":{
                    "path":supplied.get("path").or_else(|| supplied.get("target_path")).cloned().unwrap_or_else(|| json!("<absolute target path>")),
                    "intent":"locate",
                    "question":"<the complete investigation question>",
                    "budget":"tiny"
                },
                "allowed_intents":v3::INTENTS,
            }]
        }),
        "investigation_step" => json!({"repair":[{
            "tool":"investigation_step",
            "arguments":{"action_id":"<returned action_id>"}
        }]}),
        "evidence_read" => json!({"repair":[{
            "tool":"evidence_read",
            "arguments":{"investigation_id":"<returned investigation_id>","cursor":"<returned artifact.cursor>"},
            "note":"action_id values execute with investigation_step; evidence_read accepts only artifact cursors"
        }]}),
        _ => json!({"repair":[{"tool":tool,"use_advertised_schema":true}]}),
    }
}

fn parse_artifact_cursor(cursor: &str) -> (&str, usize) {
    cursor
        .rsplit_once(':')
        .and_then(|(id, offset)| offset.parse::<usize>().ok().map(|offset| (id, offset)))
        .unwrap_or((cursor, 0))
}

fn first_hex_address(value: &str) -> Option<u64> {
    value
        .split(|character: char| !(character.is_ascii_hexdigit() || matches!(character, 'x' | 'X')))
        .find_map(|token| {
            let token = token.trim();
            let digits = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))?;
            (!digits.is_empty())
                .then(|| u64::from_str_radix(digits, 16).ok())
                .flatten()
        })
}

fn is_persistence_query(question: &str) -> bool {
    let lower = question.to_ascii_lowercase();
    lower.contains("persist") || lower.contains("reopen") || lower.contains("renamed")
}

fn canonical_intent(intent: &str, question: &str) -> String {
    let requested = intent.to_ascii_lowercase();
    let lexical = format!("{intent} {question}").to_ascii_lowercase();
    let canonical = if requested.contains("edit")
        || requested.contains("rename")
        || requested.contains("comment")
    {
        "edit"
    } else if requested.contains("verify") {
        "verify"
    } else if lexical.contains("rename")
        || lexical.contains("comment")
        || lexical.contains("durable edit")
    {
        "edit"
    } else if lexical.contains("verify")
        || lexical.contains("contradicted")
        || lexical.contains("direct call edge")
    {
        "verify"
    } else if lexical.contains("dump") {
        "dump"
    } else if lexical.contains("capability") || lexical.contains("deep index") {
        "capability"
    } else if lexical.contains("compare") || lexical.contains("similar") {
        "compare"
    } else if lexical.contains("trace")
        || lexical.contains("caller")
        || lexical.contains("pipeline")
        || lexical.contains("provenance")
    {
        "trace"
    } else if lexical.contains("read data")
        || lexical.contains("pointer")
        || lexical.contains("structure")
    {
        "read_data"
    } else if lexical.contains("explain")
        || lexical.contains("summarize")
        || lexical.contains("operations")
    {
        "explain"
    } else {
        "locate"
    };
    canonical.to_string()
}

fn canonical_investigation_input(intent: &str, question: &str) -> (String, String) {
    let supplied_intent = intent.trim();
    let canonical = canonical_intent(supplied_intent, question);
    // Weak callers often place the full natural-language task in `intent` and
    // a generic request such as "return the VA" in `question`. Keep the typed
    // canonical intent for dispatch, but retain those lexical constraints for
    // sketch ranking and claim verification.
    let compiled_question = if canonical == "edit" {
        let question_binding = parse_edit_request(question);
        let intent_binding = parse_edit_request(supplied_intent);
        let binding_specificity = |binding: &(u64, &'static str, String)| {
            let (_, target, value) = binding;
            usize::from(*target == "function" && value.contains('_')) * 4
                + usize::from(value.len() >= 8) * 2
                + usize::from(*target == "function_comment" && value.contains(' ')) * 4
        };
        match (question_binding.as_ref(), intent_binding.as_ref()) {
            (Some(question_value), Some(intent_value))
                if binding_specificity(intent_value) > binding_specificity(question_value) =>
            {
                supplied_intent.to_string()
            }
            (Some(_), _) => question.to_string(),
            (None, Some(_)) => supplied_intent.to_string(),
            (None, None) => question.to_string(),
        }
    } else if supplied_intent.is_empty() || supplied_intent.eq_ignore_ascii_case(&canonical) {
        question.to_string()
    } else {
        format!("{supplied_intent}. {question}")
    };
    (canonical, compiled_question)
}

fn investigation_requires_full_project(investigation: &Investigation) -> bool {
    investigation.intent == "edit"
        || investigation.intent == "dump"
        || (investigation.intent == "verify" && is_persistence_query(&investigation.question))
}

fn capability_ids(result: &CallToolResult) -> Vec<&str> {
    result
        .structured_content
        .as_ref()
        .and_then(|value| value.get("capabilities"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.get("capability_id"))
        .filter_map(serde_json::Value::as_str)
        .collect()
}

fn expected_persisted_symbol(question: &str) -> Option<String> {
    let lower = question.to_ascii_lowercase();
    if let Some(index) = lower.rfind(" to ") {
        let value = question[index + 4..]
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .find(|token| !token.is_empty())?;
        return Some(value.to_string());
    }
    question
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .find(|token| {
            token.contains('_')
                && !token.starts_with("0x")
                && !matches!(
                    token.to_ascii_lowercase().as_str(),
                    "function_name" | "target_id" | "investigation_id"
                )
        })
        .map(str::to_string)
}

fn expected_persisted_comment(question: &str) -> Option<String> {
    let lower = question.to_ascii_lowercase();
    let index = lower.find("comment")?;
    quoted_value(question).or_else(|| {
        let tail = question[index + "comment".len()..].trim();
        let tail_lower = tail.to_ascii_lowercase();
        let end = [" to 0x", " at 0x", " on 0x", " for 0x"]
            .iter()
            .filter_map(|marker| tail_lower.find(marker))
            .min()
            .unwrap_or(tail.len());
        let value = tail[..end]
            .trim_matches(|character: char| {
                character.is_whitespace() || matches!(character, ':' | '-' | '\'' | '"')
            })
            .to_string();
        (!value.is_empty()).then_some(value)
    })
}

fn parse_edit_request(question: &str) -> Option<(u64, &'static str, String)> {
    let va = first_hex_address(question)?;
    let lower = question.to_ascii_lowercase();
    if lower.contains("comment") {
        let value = expected_persisted_comment(question)?;
        return Some((va, "function_comment", value));
    }
    let marker = " to ";
    let index = lower.rfind(marker)?;
    let name = question[index + marker.len()..]
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .find(|token| !token.is_empty())?
        .to_string();
    let generic_verb = matches!(
        name.to_ascii_lowercase().as_str(),
        "rename" | "edit" | "change" | "comment" | "perform" | "apply"
    );
    (!name.is_empty() && !generic_verb).then_some((va, "function", name))
}

fn quoted_value(value: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let start = value.find(quote)?;
        let remainder = &value[start + quote.len_utf8()..];
        if let Some(end) = remainder.find(quote) {
            return Some(remainder[..end].to_string());
        }
    }
    None
}

fn capability_argument_summary(
    schema: &serde_json::Map<String, serde_json::Value>,
) -> Vec<serde_json::Value> {
    let required: std::collections::HashSet<_> = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .map(|(name, property)| {
            json!({
                "name": name,
                "required": required.contains(name.as_str()),
                "type": property.get("type").cloned().unwrap_or_else(|| json!("any")),
                "description": property
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .map(|text| sanitize_untrusted_text(text, 120)),
            })
        })
        .collect()
}

fn mcp_error_result(error: rmcp::ErrorData) -> CallToolResult {
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
    tool_error_json(
        code,
        message,
        json!({ "rpc_code": error.code.0, "data": error.data }),
        error.code == ErrorCode::INTERNAL_ERROR,
    )
}

fn compact_preview(value: &serde_json::Value, depth: usize) -> serde_json::Value {
    if depth >= 4 {
        return match value {
            serde_json::Value::Array(values) => json!({ "items": values.len() }),
            serde_json::Value::Object(values) => json!({ "fields": values.len() }),
            serde_json::Value::String(text) => json!(sanitize_untrusted_text(text, 256)),
            other => other.clone(),
        };
    }
    match value {
        serde_json::Value::Array(values) => {
            let items: Vec<_> = values
                .iter()
                .take(2)
                .map(|value| compact_preview(value, depth + 1))
                .collect();
            if values.len() > items.len() {
                json!({ "items": items, "omitted": values.len() - items.len() })
            } else {
                json!(items)
            }
        }
        serde_json::Value::Object(values) => {
            let mut out = serde_json::Map::new();
            for (key, value) in values.iter().take(20) {
                out.insert(key.clone(), compact_preview(value, depth + 1));
            }
            if values.len() > out.len() {
                out.insert(
                    "omitted_fields".to_string(),
                    json!(values.len() - out.len()),
                );
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::String(text) => json!(sanitize_untrusted_text(text, 512)),
        other => other.clone(),
    }
}

fn sanitize_untrusted_text(text: &str, max_chars: usize) -> String {
    let mut clean = String::with_capacity(text.len().min(max_chars));
    for character in text
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
    {
        clean.push(character);
    }
    if text
        .chars()
        .filter(|character| !character.is_control())
        .count()
        > max_chars
    {
        clean.push('\u{2026}');
    }
    clean
}

fn success_json(value: &impl serde::Serialize) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(value) => CallToolResult::structured(value),
        Err(error) => tool_error_json("SERIALIZATION_ERROR", error.to_string(), json!({}), false),
    }
}

fn success_json_with_message(
    value: &impl serde::Serialize,
    message: impl Into<String>,
) -> CallToolResult {
    let mut result = success_json(value);
    if result.is_error != Some(true) {
        result.content = vec![Content::text(message.into())];
    }
    result
}

/// Max rows embedded in the human-readable text of a tool result. The
/// structured payload still carries the full page; this cap keeps the text
/// token-bounded for text-first MCP clients.
const TEXT_ROWS_MAX: usize = 40;
/// Per-row width cap before truncation with an ellipsis.
const TEXT_ROW_MAX_CHARS: usize = 120;

/// Same as [`success_json_with_message`] but appends a token-bounded row
/// block to the human-readable text. Text-first clients (which strip
/// `structuredContent`) get VA-anchored rows instead of only a count.
fn success_json_with_rows(
    value: &impl serde::Serialize,
    message: impl Into<String>,
    rows: &[String],
) -> CallToolResult {
    let mut result = success_json(value);
    if result.is_error != Some(true) {
        result.content = vec![Content::text(message_with_rows(message, rows))];
    }
    result
}

fn message_with_rows(message: impl Into<String>, rows: &[String]) -> String {
    let mut out = message.into();
    if !rows.is_empty() {
        out.push('\n');
        for row in rows.iter().take(TEXT_ROWS_MAX) {
            out.push_str("  ");
            out.push_str(&clamp_text_row(row));
            out.push('\n');
        }
        let hidden = rows.len().saturating_sub(TEXT_ROWS_MAX);
        if hidden > 0 {
            out.push_str(&format!(
                "  \u{2026} {hidden} more row(s); page with next_cursor/offset\n"
            ));
        }
        while out.ends_with('\n') {
            out.pop();
        }
    }
    out
}

fn clamp_text_row(row: &str) -> String {
    let row = row.replace(['\n', '\r'], " ");
    if row.chars().count() <= TEXT_ROW_MAX_CHARS {
        row
    } else {
        let mut clamped: String = row.chars().take(TEXT_ROW_MAX_CHARS - 1).collect();
        clamped.push('\u{2026}');
        clamped
    }
}

/// Compact one-line rendering of a BEL hit for the human-readable text of
/// `search_bel`. VA-anchored so text-first clients can proceed to
/// `get_function_evidence` / `decompile_function` without re-searching.
fn bel_hit_row(hit: &crate::analysis::bel::Hit) -> String {
    let location = hit
        .va
        .map(|va| format!("{va:#x}"))
        .or_else(|| hit.function_va.map(|va| format!("fn={va:#x}")))
        .or_else(|| hit.file_offset.map(|offset| format!("file+{offset:#x}")))
        .unwrap_or_else(|| "n/a".to_string());
    let kind = format!("{:?}", hit.kind).to_ascii_lowercase();
    format!(
        "{location} {kind} \"{}\" score={:.2} ({})",
        hit.display, hit.score, hit.strategy
    )
}

fn op_visible(project: &crate::project::Project, op: &Op) -> bool {
    match op {
        Op::RenameSymbol { va, name, .. } => project.symbols.name(*va) == Some(name.as_str()),
        Op::SetComment {
            va, scope, text, ..
        } => project.comments.get(*va, *scope) == Some(text.as_str()),
        Op::SetFocus { va, .. } => project.focus == Some(*va),
        Op::SetGlobalType { va, ty, .. } => project.typed_globals.get(va) == Some(ty),
        Op::SetFunctionSignature { va, signature, .. } => {
            project.function_signatures.get(va) == Some(signature)
        }
        Op::SetStackLocalType {
            function_va,
            offset,
            ty,
            ..
        } => project
            .function_frames
            .get(function_va)
            .is_some_and(|frame| {
                frame
                    .locals
                    .iter()
                    .chain(&frame.args)
                    .any(|variable| variable.offset == *offset && variable.ty == *ty)
            }),
        Op::SetStackLocalName {
            function_va,
            offset,
            name,
            ..
        } => project
            .function_frames
            .get(function_va)
            .is_some_and(|frame| {
                frame.locals.iter().chain(&frame.args).any(|variable| {
                    variable.offset == *offset && variable.name.as_deref() == Some(name)
                })
            }),
        Op::SetParamName {
            function_va,
            index,
            name,
            ..
        } => project
            .function_signatures
            .get(function_va)
            .and_then(|signature| signature.params.get(*index))
            .is_some_and(|(saved_name, _)| saved_name == name),
        Op::SetFunctionMemory { va, card, .. } => project
            .function_memory
            .get(va)
            .is_some_and(|saved| memory_content_matches(saved, card)),
        Op::Batch { ops } => ops.iter().all(|child| op_visible(project, child)),
    }
}

fn memory_content_matches(
    saved: &crate::project::memory::FunctionMemoryCard,
    expected: &crate::project::memory::FunctionMemoryCard,
) -> bool {
    saved.va == expected.va
        && saved.purpose == expected.purpose
        && saved.tags == expected.tags
        && saved.key_apis == expected.key_apis
        && saved.key_strings == expected.key_strings
        && saved.purity == expected.purity
        && saved.confidence == expected.confidence
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
    if manager.is_dump_session(id) {
        return Err(invalid_params(
            "project_id is a dump_session. Use get_dump_triage / list_dump_modules / list_dump_threads, \
             or open_dump_module for PE-style RE (module projects).",
        ));
    }
    manager
        .get(id)
        .ok_or_else(|| invalid_params("project not found"))
}

fn get_dump_session(
    manager: &ProjectManager,
    id: ProjectId,
) -> Result<Arc<crate::project_manager::DumpSessionHandle>, rmcp::ErrorData> {
    manager.get_dump(id).ok_or_else(|| {
        if manager.get(id).is_some() {
            invalid_params(
                "project_id is a PE project, not a dump_session. Open a .dmp with open_project first.",
            )
        } else {
            invalid_params("dump session not found")
        }
    })
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
    let reread_matches = manager
        .get(id)
        .is_some_and(|project| op_visible(&project, &applied));
    Ok(success_json_with_message(
        &json!({
            "applied": applied,
            "saved": true,
            "reread_matches": reread_matches,
        }),
        if reread_matches {
            "Saved. Re-read matches the write."
        } else {
            "Saved, but the immediate re-read did not match; inspect the project state."
        },
    ))
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

#[derive(Clone)]
struct McpHttpState {
    service: Arc<McpService>,
    manager: Arc<ProjectManager>,
}

async fn mcp_http_handler(
    State(state): State<McpHttpState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let started = Instant::now();
    let response = state.service.handle(req).await;
    let (parts, body) = response.into_parts();
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            HTTP_REQUESTS.fetch_add(1, Ordering::Relaxed);
            HTTP_RESPONSE_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            HTTP_LATENCY_MICROS.fetch_add(
                started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );
            if parts.status.is_server_error() || parts.status.is_client_error() {
                HTTP_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
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

#[cfg(windows)]
fn current_process_rss_bytes() -> Option<u64> {
    use std::ffi::c_void;

    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
    }

    let mut counters = ProcessMemoryCounters {
        cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };
    // SAFETY: Windows owns the pseudo-handle and the output buffer has the
    // exact size reported through `cb` for the duration of the call.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &raw mut counters, counters.cb) };
    (ok != 0).then_some(counters.working_set_size as u64)
}

#[cfg(not(windows))]
fn current_process_rss_bytes() -> Option<u64> {
    None
}

fn server_status_json(manager: &ProjectManager) -> serde_json::Value {
    let activity = manager.server_activity();
    let projects: Vec<_> = manager
        .list()
        .into_iter()
        .map(|(id, path, functions, instructions)| {
            let project = manager.get(id);
            let search_index_ready = project
                .as_ref()
                .is_some_and(|project| project.analysis.bel.get().is_some());
            let bel_building = project
                .as_ref()
                .is_some_and(|project| project.analysis.bel.is_building());
            let bel_stats = project
                .as_ref()
                .and_then(|project| project.analysis.bel.get())
                .map(|index| index.stats.clone());
            json!({
                "project_id": id,
                "path": path,
                "functions": functions,
                "instructions": instructions,
                "bel_ready": search_index_ready,
                "bel_building": bel_building,
                "bel_stats": bel_stats,
            })
        })
        .collect();
    let message = if activity.busy {
        format!(
            "Windy is busy: {} ({:.1}s elapsed).",
            activity.operation.as_deref().unwrap_or("working"),
            activity.elapsed_secs.unwrap_or_default()
        )
    } else if projects.is_empty() {
        "Windy is idle. No targets are open; call target_open with an absolute path.".to_string()
    } else {
        format!("Windy is idle with {} open project(s).", projects.len())
    };
    json!({
        "name": crate::build_info::PRODUCT_ID,
        "version": crate::build_info::VERSION,
        "channel": crate::build_info::CHANNEL,
        "state": activity.state,
        "busy": activity.busy,
        "active_operations": activity.active_operations,
        "operation": activity.operation,
        "elapsed_secs": activity.elapsed_secs,
        "projects_open": projects.len(),
        "projects": projects,
        "runtime": runtime_metrics(),
        "message": message,
    })
}

async fn healthz(State(state): State<McpHttpState>) -> Json<serde_json::Value> {
    let server = server_status_json(&state.manager);
    Json(json!({
        "status": "ok",
        "name": crate::build_info::PRODUCT_ID,
        "version": crate::build_info::VERSION,
        "channel": crate::build_info::CHANNEL,
        "protocol": rmcp::model::ProtocolVersion::LATEST.as_str(),
        "state": server["state"],
        "busy": server["busy"],
        "operation": server["operation"],
        "elapsed_secs": server["elapsed_secs"],
        "projects_open": server["projects_open"],
        "message": server["message"],
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
        "Windy MCP is local-only; refusing non-loopback bind {}",
        bind.ip()
    );
    let session_manager = Arc::new(LocalSessionManager::default());
    let service_manager = manager.clone();
    let shared = Arc::new(McpShared::default());
    let service = Arc::new(StreamableHttpService::new(
        move || {
            Ok(WindyMcp::with_shared(
                service_manager.clone(),
                shared.clone(),
            ))
        },
        session_manager,
        StreamableHttpServerConfig::default(),
    ));

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let port = listener.local_addr()?.port();
    let state = McpHttpState { service, manager };
    let app = Router::new()
        .route("/mcp", post(mcp_http_handler))
        .route("/healthz", get(healthz))
        .with_state(state)
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

    #[test]
    fn target_path_repair_accepts_only_one_missing_ascii_character() {
        assert!(is_single_missing_ascii_char(
            "-c-p0-0f6cd8a45ffa.exe",
            "t-c-p0-0f6cd8a45ffa.exe"
        ));
        assert!(is_single_missing_ascii_char("ample.exe", "sample.exe"));
        assert!(!is_single_missing_ascii_char("sample.exe", "simple.exe"));
        assert!(!is_single_missing_ascii_char("mple.exe", "sample.exe.bak"));
    }

    #[test]
    fn edit_and_persistence_questions_bind_one_symbol() {
        let question = "Rename function 0x140001000 to list_value_sum using a verified change, close and reopen, then return PERSISTED";
        let (va, target, value) = parse_edit_request(question).expect("edit binding");
        assert_eq!(va, 0x140001000);
        assert_eq!(target, "function");
        assert_eq!(value, "list_value_sum");
        assert!(is_persistence_query(question));
        assert_eq!(
            expected_persisted_symbol(question).as_deref(),
            Some("list_value_sum")
        );

        let comment = "Attach the function comment 'validated dispatch root' to 0x140001020, close and reopen, then return PERSISTED";
        let (va, target, value) = parse_edit_request(comment).expect("comment binding");
        assert_eq!(va, 0x140001020);
        assert_eq!(target, "function_comment");
        assert_eq!(value, "validated dispatch root");
        assert_eq!(
            quoted_value(comment).as_deref(),
            Some("validated dispatch root")
        );

        let unquoted = "Attach the function comment bounded integer clamp to 0x140001060 and verify persistence after close and reopen";
        let (_, target, value) = parse_edit_request(unquoted).expect("unquoted comment binding");
        assert_eq!(target, "function_comment");
        assert_eq!(value, "bounded integer clamp");
        assert_eq!(
            expected_persisted_comment(
                "Verify the function comment bounded integer clamp at 0x140001060 persists after reopen."
            )
            .as_deref(),
            Some("bounded integer clamp")
        );
        assert_eq!(
            canonical_intent("verify direct call edge", "Does 0x140001020 call the sink?"),
            "verify"
        );
        assert_eq!(
            canonical_intent(
                "verify",
                "Verify the renamed symbol list_value_sum persists after reopen"
            ),
            "verify"
        );
        assert_eq!(
            canonical_intent("Identify a function", "summarize its supported operations"),
            "explain"
        );
        let (intent, compiled) = canonical_investigation_input(
            "Identify the function traversing a linked list via next pointers",
            "Return one hex VA or UNKNOWN.",
        );
        assert_eq!(intent, "read_data");
        assert!(compiled.contains("linked list via next pointers"));
        assert!(compiled.contains("Return one hex VA"));

        let edit_question = "Rename function 0x140001020 to list_value_sum and verify persistence";
        let (intent, compiled) = canonical_investigation_input(
            "Rename function with a verified revision-checked change",
            edit_question,
        );
        assert_eq!(intent, "edit");
        assert_eq!(compiled, edit_question);
        assert_eq!(
            parse_edit_request(&compiled).map(|(_, _, value)| value),
            Some("list_value_sum".to_string())
        );
        let intent_only_edit =
            "Rename function 0x140001020 to list_value_sum and verify persistence";
        let (_, compiled) = canonical_investigation_input(
            intent_only_edit,
            "Provide the ticket needed to inspect and rename function 0x140001020 with a revision-checked commit.",
        );
        assert_eq!(compiled, intent_only_edit);
        assert_eq!(
            parse_edit_request(&compiled).map(|(_, _, value)| value),
            Some("list_value_sum".to_string())
        );
    }

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
            assert_eq!(
                body["result"]["serverInfo"]["name"],
                crate::build_info::PRODUCT_ID
            );
            assert_eq!(
                body["result"]["serverInfo"]["version"],
                crate::build_info::VERSION
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
        let summary = call["content"][0]["text"]
            .as_str()
            .expect("one-line summary content");
        assert!(!summary.trim().is_empty());
        if let Ok(text) = serde_json::from_str::<serde_json::Value>(summary) {
            assert_ne!(
                text, *structured,
                "v2 must not duplicate structured JSON into text content"
            );
        }
        assert_eq!(structured["v"], 3);
        &structured["data"]
    }

    #[test]
    fn streamable_http_release_contract_and_persistence() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/fixtures/pe/sample.exe");
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
        assert_eq!(health["name"], crate::build_info::PRODUCT_ID);
        assert_eq!(health["channel"], crate::build_info::CHANNEL);
        assert_eq!(health["status"], "ok");
        assert_eq!(health["protocol"], "2025-11-25");
        assert_eq!(health["state"], "idle");
        assert_eq!(health["projects_open"], 0);

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
            crate::build_info::PRODUCT_ID
        );

        let mut client = TestClient::initialize(endpoint.clone());
        let initial_status = client.call("get_server_status", json!({}));
        assert_eq!(structured(&initial_status)["state"], "idle");
        assert_eq!(structured(&initial_status)["projects_open"], 0);
        let empty_projects = client.call("list_projects", json!({}));
        assert_eq!(structured(&empty_projects), &json!([]));
        assert_eq!(
            empty_projects["result"]["content"][0]["text"],
            "list_projects: complete"
        );

        let listed = client.request("tools/list", json!({}));
        let tools = listed["result"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 6, "expected the compact MCP v0.3 surface");
        assert!(
            serde_json::to_vec(tools).unwrap().len() <= 4 * 1024,
            "tools/list schema budget exceeded"
        );
        assert!(tools.iter().all(|tool| !tool["annotations"].is_null()));
        let tool = |name: &str| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("missing tool {name}"))
        };
        assert_eq!(
            tool("investigation_start")["annotations"]["readOnlyHint"],
            true
        );
        assert_eq!(tool("change_commit")["annotations"]["readOnlyHint"], false);
        assert!(
            tool("investigation_start")["inputSchema"]["properties"]
                .get("question")
                .is_some()
        );

        let self_correcting = client.call("list_functions", json!({ "project_id": "not-a-uuid" }));
        assert_eq!(self_correcting["result"]["isError"], true);
        assert_eq!(
            structured(&self_correcting)["error"]["code"],
            "INVALID_ARGUMENT"
        );

        let opened = client.call("open_project", json!({ "path": fixture.to_string_lossy() }));
        let opened_payload = structured(&opened);
        assert!(opened_payload["elapsed_ms"].as_u64().is_some());
        assert!(opened_payload["scale"]["category"].as_str().is_some());
        assert!(opened_payload["pdb"]["message"].as_str().is_some());
        let project_id = opened_payload["project_id"]
            .as_str()
            .expect("project id")
            .to_string();
        let open_status = client.call("get_server_status", json!({}));
        assert_eq!(structured(&open_status)["projects_open"], 1);

        let search = client.call(
            "search_summary",
            json!({
                "project_id": project_id,
                "query": "_",
                "limit": 1,
                "fast_only": true
            }),
        );
        let search_payload = structured(&search);
        assert!(search_payload["total"].as_u64().is_some());
        assert!(search_payload["message"].as_str().is_some());
        assert!(
            search_payload["hits"]
                .as_array()
                .is_some_and(|hits| hits.len() <= 1)
        );

        let bel = client.call(
            "search_bel",
            json!({
                "project_id": project_id,
                "query": "mov",
                "mode": "token",
                "limit": 2
            }),
        );
        let bel_payload = structured(&bel);
        assert!(bel_payload["total"].as_u64().is_some());
        assert!(matches!(
            bel_payload["total_kind"].as_str(),
            Some("exact" | "lower_bound")
        ));
        assert!(
            bel_payload["hits"]
                .as_array()
                .is_some_and(|hits| { hits.iter().all(|hit| hit["provenance"].is_array()) })
        );
        if let Some(cursor) = bel_payload["next_cursor"].as_str() {
            let second = client.call(
                "search_bel",
                json!({
                    "project_id": project_id,
                    "query": "mov",
                    "mode": "token",
                    "limit": 2,
                    "cursor": cursor,
                }),
            );
            let second_payload = structured(&second);
            let first_ids: std::collections::HashSet<_> = bel_payload["hits"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|hit| hit["entity_id"].as_u64())
                .collect();
            assert!(
                second_payload["hits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|hit| {
                        hit["entity_id"]
                            .as_u64()
                            .is_none_or(|id| !first_ids.contains(&id))
                    })
            );
        }
        let indexed_status = client.call("get_server_status", json!({}));
        let indexed_status = structured(&indexed_status);
        assert_eq!(indexed_status["projects"][0]["bel_ready"], true);
        assert!(
            indexed_status["projects"][0]["bel_stats"]["entities"]
                .as_u64()
                .is_some()
        );

        let strings = client.call(
            "list_strings",
            json!({ "project_id": project_id, "limit": 1 }),
        );
        let strings_payload = structured(&strings);
        assert!(strings_payload["total"].as_u64().is_some());
        assert!(strings_payload["truncated"].as_bool().is_some());
        assert!(strings_payload["message"].as_str().is_some());
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

        // Complexity guardrail: a tiny max_instructions cap must return the
        // structured too_complex status with guidance instead of hanging.
        let too_complex = client.call(
            "decompile_function",
            json!({ "project_id": project_id, "va": va, "max_instructions": 0 }),
        );
        assert_eq!(too_complex["result"]["isError"], false);
        let cap_output = structured(&too_complex);
        assert_eq!(cap_output["status"], "too_complex");
        assert!(
            cap_output["guidance"]
                .as_array()
                .is_some_and(|g| g.len() >= 3),
            "too_complex must carry lighter-weight alternatives"
        );
        // The same function still decompiles with an explicit higher cap.
        let uncapped = client.call(
            "decompile_function",
            json!({ "project_id": project_id, "va": va, "max_instructions": 1_000_000 }),
        );
        let uncapped_output = structured(&uncapped);
        assert!(
            matches!(
                uncapped_output["status"].as_str(),
                Some("ok" | "omitted" | "pending")
            ),
            "raising the cap must restore full decompilation"
        );

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

    #[test]
    fn v3_public_surface_opens_investigates_edits_and_closes() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/fixtures/pe/sample.exe");
        let home = std::env::temp_dir().join(format!(
            "windy-mcp-v3-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let manager = Arc::new(ProjectManager::with_home_dir(&home).expect("test manager"));
        let mut server = manager
            .runtime()
            .block_on(serve_http(manager.clone(), "127.0.0.1:0".parse().unwrap()))
            .expect("start MCP server");
        let mut client = TestClient::initialize(format!("http://127.0.0.1:{}/mcp", server.port()));

        let started = Instant::now();
        let opened = client.call(
            "investigation_start",
            json!({
                "path": fixture,
                "intent":"locate",
                "question":"locate a NUL-terminated byte-counting loop",
                "budget":"tiny"
            }),
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        let opened = structured(&opened);
        let action_id = opened["next_actions"][0]["execute"]["arguments"]["action_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut target_handle = None;
        for _ in 0..200 {
            let step = client.call("investigation_step", json!({ "action_id":action_id }));
            assert_ne!(step["result"]["isError"], true, "{step:#}");
            let data = structured(&step);
            if data["stage"] == "sketch" && data["state"] != "pending" {
                target_handle = data["target_id"].as_str().map(str::to_owned);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let target_handle = target_handle.expect("sketch target completed");
        assert!(
            manager.list().is_empty(),
            "sketch stage must not build a Project"
        );

        let capability = client.call(
            "investigation_start",
            json!({
                "target_id":target_handle,
                "intent":"capability",
                "question":"perform list_imports",
                "budget":"tiny"
            }),
        );
        let capability_data = structured(&capability);
        let capability_poll =
            capability_data["next_actions"][0]["execute"]["arguments"]["action_id"]
                .as_str()
                .expect("capability continuation")
                .to_string();
        let discovered = client.call("investigation_step", json!({"action_id":capability_poll}));
        let discovered_data = structured(&discovered);
        assert_eq!(discovered_data["stage"], "catalog", "{discovered:#}");
        let import_action = discovered_data["next_actions"][0]["execute"]["arguments"]["action_id"]
            .as_str()
            .expect("bound list_imports action")
            .to_string();
        let imported = client.call(
            "investigation_step",
            json!({"action_id":import_action,"inputs":{"limit":1}}),
        );
        let imported_data = structured(&imported);
        assert_eq!(imported_data["state"], "complete", "{imported:#}");
        assert_eq!(imported_data["stage"], "catalog", "{imported:#}");
        assert!(imported_data["imports"].is_array(), "{imported:#}");
        assert!(imported_data["total"].as_u64().is_some(), "{imported:#}");
        assert!(
            manager.list().is_empty(),
            "catalog capability must not promote a full Project"
        );

        let pe = crate::loader::pe::LoadedPe::open_catalog(&fixture).unwrap();
        let optional = pe.triage.optional_header.as_ref().unwrap();
        let va = format!(
            "{:#x}",
            optional.image_base + optional.address_of_entry_point
        );

        let edit = client.call(
            "investigation_start",
            json!({
                "target_id":target_handle,
                "intent":"edit",
                "question":format!("attach the function comment 'v3 smoke marker' to {va}"),
                "budget":"tiny"
            }),
        );
        let edit_data = structured(&edit);
        let edit_investigation = edit_data["investigation_id"].as_str().unwrap().to_string();
        let edit_action = edit_data["next_actions"][0]["execute"]["arguments"]["action_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut proposal_value = None;
        for _ in 0..200 {
            let step = client.call(
                "investigation_step",
                json!({
                    "investigation_id":edit_investigation,
                    "action_id":edit_action
                }),
            );
            assert_ne!(step["result"]["isError"], true, "{step:#}");
            let data = structured(&step);
            if data["proposal"].is_object() {
                proposal_value = Some(data["proposal"].clone());
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let proposal = proposal_value.expect("edit proposal after full-project promotion");
        let proposal_id = proposal["proposal_id"].as_str().unwrap().to_string();
        let revision = proposal["expected_revision"].as_u64().unwrap();
        assert_eq!(proposal["expected_revision"], revision);
        let edit_args = json!({
            "proposal_id":proposal_id,
            "expected_revision":revision,
            "idempotency_key":"v3-smoke-edit-0001"
        });
        let edited = client.call("change_commit", edit_args.clone());
        assert_eq!(edited["result"]["isError"], false, "{edited:#}");
        let replayed = client.call("change_commit", edit_args);
        assert_eq!(replayed["result"]["isError"], false, "{replayed:#}");

        let closed = client.call("target_close", json!({ "target_id": target_handle }));
        assert_eq!(closed["result"]["isError"], false, "{closed:#}");
        assert!(manager.list().is_empty());

        manager
            .runtime()
            .block_on(server.shutdown())
            .expect("graceful shutdown");
        drop(client);
        drop(manager);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn search_rows_embedded_in_text_content() {
        // Text-first clients strip structuredContent; the human text must
        // carry VA-anchored rows, not just a count.
        let rows: Vec<String> = (0..50)
            .map(|i| format!("0x1800{i:x} instruction \"mov eax,{i}\" score=1.00 (exact)"))
            .collect();
        let text = message_with_rows("BEL found 50 exact match(es).", &rows);
        assert!(text.starts_with("BEL found 50 exact match(es)."));
        assert!(text.contains("0x18000"), "first row VA must appear");
        assert!(text.contains("mov eax,0"), "row payload must appear");
        assert!(
            text.contains("10 more row(s)"),
            "overflow trailer must appear"
        );
        assert_eq!(text.lines().count(), 1 + TEXT_ROWS_MAX + 1);

        let long = "x".repeat(500);
        let clamped = clamp_text_row(&long);
        assert!(clamped.chars().count() <= TEXT_ROW_MAX_CHARS);
        assert!(clamped.ends_with('\u{2026}'));

        // Hit rows anchor on va with kind + display + strategy.
        let hit = crate::analysis::bel::Hit {
            entity_id: 0,
            kind: crate::analysis::bel::EntityKind::Instruction,
            display: "movsd xmm0,[r9+430h]".into(),
            va: Some(0x1816_3f1a7),
            file_offset: None,
            function_va: Some(0x1816_3f1a0),
            provenance: Vec::new(),
            score: 1.0,
            reason: String::new(),
            strategy: "exact".into(),
        };
        let row = bel_hit_row(&hit);
        assert!(row.contains("0x18163f1a7"));
        assert!(row.contains("instruction"));
        assert!(row.contains("movsd xmm0,[r9+430h]"));
        assert!(row.contains("exact"));

        // Fallback: no va, no function_va -> file offset form.
        let file_hit = crate::analysis::bel::Hit {
            va: None,
            file_offset: Some(0x1234),
            function_va: None,
            ..hit.clone()
        };
        assert!(bel_hit_row(&file_hit).contains("file+0x1234"));
    }
}
