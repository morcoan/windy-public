//! Agent-loop benchmark harness (outside the windy binary).
//!
//! Arms:
//! - A: windy-evidence (MCP tools: get_function_evidence, search_bel, get_triage, …)
//! - B: python-tools (bash + scratch dir with pefile/capstone; no Windy)
//! - C: windy-dump (agent_text + read_va only)
//!
//! Token accounting sums input_tokens + cache_creation_input_tokens +
//! cache_read_input_tokens (Anthropic usage fields). Never report
//! input_tokens alone.
//!
//! Default mode is offline **scoring-wiring** only (synthetic answers, no
//! binary analysis). It is not a benchmark result — write fixtures under
//! `eval/agent-bench/fixtures/`, never under `docs/benchmarks/`.
//! Pass `--live` with ANTHROPIC_API_KEY and a built `windy` binary for a
//! real model loop; live reports may land in `docs/benchmarks/`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Shared abstention vocabulary for scoring success **and** abstention rate.
/// Keep `score_answer` and `is_abstain` on this single list.
const ABSTAIN_MARKERS: &[&str] = &[
    "refuse",
    "unknown",
    "inlined",
    "missing",
    "not present",
    "eliminated",
];

const MAX_SHELL_OUTPUT: usize = 32 * 1024;
const SHELL_TIMEOUT_SECS: u64 = 45;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Arm {
    /// Windy evidence tools.
    A,
    /// Python pefile/capstone baseline.
    B,
    /// Windy dump-only tools.
    C,
}

#[derive(Parser, Debug)]
#[command(name = "agent-bench")]
#[command(about = "Windy agent-loop harness: evidence vs python baseline")]
struct Cli {
    /// Repo root (contains eval/grand and target/).
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Path to windy.exe (default: target/release/windy.exe or target/debug/windy.exe).
    #[arg(long)]
    windy: Option<PathBuf>,
    /// Arms to run.
    #[arg(long, value_enum, default_values_t = vec![Arm::A, Arm::B])]
    arm: Vec<Arm>,
    /// Max tasks (after filtering).
    #[arg(long, default_value_t = 12)]
    limit: usize,
    /// Profiles to include (P0 P1 …).
    #[arg(long, default_values_t = ["P0".to_string(), "P1".to_string()])]
    profile: Vec<String>,
    /// Task families: locate, abstain, enumerate, triage, provenance.
    #[arg(long, default_values_t = ["locate".to_string(), "abstain".to_string()])]
    family: Vec<String>,
    /// Live Anthropic loop (requires ANTHROPIC_API_KEY).
    #[arg(long, default_value_t = false)]
    live: bool,
    /// Model id for live runs.
    #[arg(long, default_value = "claude-opus-4-20250514")]
    model: String,
    /// Write machine-readable report JSON here.
    /// Offline wiring: prefer `eval/agent-bench/fixtures/wiring-check-*.json`.
    /// Live results: prefer `docs/benchmarks/agent-loop-v1-report.json`.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Also write markdown summary here.
    #[arg(long)]
    markdown: Option<PathBuf>,
    /// MCP bind host:port base (port auto-bumped per task).
    #[arg(long, default_value = "127.0.0.1:18765")]
    mcp_bind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct IdentityEntry {
    function_id: String,
    source_name: String,
    status: String,
    entry_va: Option<String>,
    #[allow(dead_code)]
    folded_to: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Task {
    id: String,
    family: String,
    program_id: String,
    profile: String,
    pe_path: PathBuf,
    question: String,
    /// Gold answer (VA hex, or "refuse", or free text).
    gold: String,
    source_name: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct TokenUsage {
    input_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
    output_tokens: u64,
}

impl TokenUsage {
    fn total_prompt(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.cache_creation_input_tokens)
            .saturating_add(self.cache_read_input_tokens)
    }

    fn add_assign(&mut self, other: &TokenUsage) {
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.cache_creation_input_tokens = self
            .cache_creation_input_tokens
            .saturating_add(other.cache_creation_input_tokens);
        self.cache_read_input_tokens = self
            .cache_read_input_tokens
            .saturating_add(other.cache_read_input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
    }
}

#[derive(Clone, Debug, Serialize)]
struct TaskResult {
    task_id: String,
    arm: String,
    success: bool,
    abstained: bool,
    answer: String,
    gold: String,
    tool_calls: usize,
    tokens: TokenUsage,
    wall_ms: u128,
    mode: String,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ArmSummary {
    arm: String,
    tasks: usize,
    successes: usize,
    abstentions: usize,
    abstention_correct: usize,
    total_tool_calls: usize,
    tokens: TokenUsage,
    wall_ms: u128,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    harness: String,
    /// Explicit: offline wiring is synthetic; only live reports are evidence.
    synthetic: bool,
    commit: Option<String>,
    model: Option<String>,
    live: bool,
    arms: Vec<ArmSummary>,
    results: Vec<TaskResult>,
    corpus: Value,
}

/// How tool_use blocks are executed.
enum ToolBackend {
    Mcp {
        endpoint: String,
    },
    /// Arm B: shell + files confined to `scratch`.
    PythonScratch {
        scratch: PathBuf,
        pe_path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = cli.root.canonicalize().unwrap_or(cli.root.clone());
    let tasks = load_tasks(&root, &cli.profile, &cli.family, cli.limit)?;
    if tasks.is_empty() {
        bail!(
            "no tasks matched filters (profiles={:?} families={:?})",
            cli.profile,
            cli.family
        );
    }

    if !cli.live {
        eprintln!(
            "agent-bench: offline wiring-check mode (synthetic answers). \
             Not a benchmark result. Use --live for A-vs-B measurement."
        );
    }

    let windy = resolve_windy(&root, cli.windy.as_deref())?;
    let mut results = Vec::new();

    for arm in &cli.arm {
        for task in &tasks {
            let result = if cli.live {
                run_live_task(&cli, &root, &windy, *arm, task)
            } else {
                run_offline_task(*arm, task)
            };
            results.push(result);
        }
    }

    let report = build_report(&cli, &root, &tasks, results);
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &cli.output {
        warn_if_synthetic_in_benchmarks(&report, path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &json)?;
        eprintln!("wrote {}", path.display());
    }
    println!("{json}");

    if let Some(path) = &cli.markdown {
        warn_if_synthetic_in_benchmarks(&report, path);
        let md = render_markdown(&report);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, md)?;
        eprintln!("wrote {}", path.display());
    }

    // Non-zero exit if offline oracle for arm A fails on locate (sanity).
    let a_fails = report
        .results
        .iter()
        .filter(|r| r.arm == "A" && r.mode == "offline_wiring" && !r.success)
        .count();
    if a_fails > 0 && !cli.live {
        eprintln!(
            "warning: {a_fails} offline arm-A wiring failures (unexpected for locate/abstain)"
        );
    }
    Ok(())
}

fn warn_if_synthetic_in_benchmarks(report: &Report, path: &Path) {
    let p = path.to_string_lossy().replace('\\', "/");
    if report.synthetic && p.contains("docs/benchmarks") {
        eprintln!(
            "warning: writing synthetic wiring-check report under docs/benchmarks/ ({}). \
             Prefer eval/agent-bench/fixtures/wiring-check-*. Leave docs/benchmarks/ for live runs only.",
            path.display()
        );
    }
}

fn resolve_windy(root: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    for rel in [
        "target/release/windy.exe",
        "target/debug/windy.exe",
        "target/release/windy",
        "target/debug/windy",
    ] {
        let p = root.join(rel);
        if p.exists() {
            return Ok(p);
        }
    }
    Ok(root.join("target/debug/windy.exe"))
}

fn load_tasks(
    root: &Path,
    profiles: &[String],
    families: &[String],
    limit: usize,
) -> Result<Vec<Task>> {
    let id_dir = root.join("eval/grand/identity_maps");
    let bin_root = root.join("eval/grand/bin");
    if !id_dir.is_dir() {
        bail!("missing {}", id_dir.display());
    }

    let mut tasks = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&id_dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        let stem = name.trim_end_matches(".json");
        let Some((program_id, profile)) = stem.rsplit_once('_') else {
            continue;
        };
        if !profiles.iter().any(|p| p.eq_ignore_ascii_case(profile)) {
            continue;
        }
        let pe_path = bin_root.join(profile).join(format!("{program_id}.exe"));
        if !pe_path.exists() {
            continue;
        }
        let raw = fs::read_to_string(entry.path())?;
        let map: Vec<IdentityEntry> = serde_json::from_str(&raw)
            .with_context(|| format!("parse {}", entry.path().display()))?;

        for row in map {
            if families.iter().any(|f| f == "locate")
                && row.status == "present"
                && let Some(va) = row.entry_va.clone()
            {
                tasks.push(Task {
                    id: format!("locate:{program_id}:{profile}:{}", row.function_id),
                    family: "locate".into(),
                    program_id: program_id.into(),
                    profile: profile.into(),
                    pe_path: pe_path.clone(),
                    question: format!(
                        "Which VA implements source function `{}` in this binary? Answer with a single hex VA or refuse.",
                        row.source_name
                    ),
                    gold: va,
                    source_name: Some(row.source_name.clone()),
                });
            }
            if families.iter().any(|f| f == "abstain")
                && (row.status == "inlined-only" || row.status == "missing")
            {
                tasks.push(Task {
                    id: format!("abstain:{program_id}:{profile}:{}", row.function_id),
                    family: "abstain".into(),
                    program_id: program_id.into(),
                    profile: profile.into(),
                    pe_path: pe_path.clone(),
                    question: format!(
                        "Which VA implements source function `{}`? If it was inlined/eliminated, refuse.",
                        row.source_name
                    ),
                    gold: "refuse".into(),
                    source_name: Some(row.source_name.clone()),
                });
            }
        }
    }

    tasks.sort_by(|a, b| a.id.cmp(&b.id));
    tasks.truncate(limit);
    Ok(tasks)
}

/// Offline **wiring** oracle: proves scorer + report shape only.
/// Arm A returns gold; B/C return wrong answers by construction.
/// Do not publish these numbers as benchmark results.
fn run_offline_task(arm: Arm, task: &Task) -> TaskResult {
    let started = Instant::now();
    let answer = match (arm, task.family.as_str()) {
        (Arm::A, "locate") => task.gold.clone(),
        (Arm::A, "abstain") => "refuse".into(),
        (Arm::A, _) => task.gold.clone(),
        (Arm::B | Arm::C, "abstain") => "0x140001000".into(),
        (Arm::B | Arm::C, _) => "0x0".into(),
    };
    let success = score_answer(task, &answer);
    TaskResult {
        task_id: task.id.clone(),
        arm: arm_name(arm).into(),
        success,
        abstained: is_abstain(&answer),
        answer,
        gold: task.gold.clone(),
        tool_calls: match arm {
            Arm::A => 3,
            Arm::B => 5,
            Arm::C => 2,
        },
        tokens: TokenUsage {
            // Distinct shapes only — not measured cost.
            input_tokens: match arm {
                Arm::A => 1200,
                Arm::B => 2400,
                Arm::C => 4000,
            },
            cache_creation_input_tokens: 500,
            cache_read_input_tokens: match arm {
                Arm::A => 800,
                Arm::B => 0,
                Arm::C => 200,
            },
            output_tokens: 80,
        },
        wall_ms: started.elapsed().as_millis(),
        mode: "offline_wiring".into(),
        error: None,
    }
}

fn score_answer(task: &Task, answer: &str) -> bool {
    let a = answer.trim().to_ascii_lowercase();
    let g = task.gold.trim().to_ascii_lowercase();
    if g == "refuse" {
        return is_abstain(&a);
    }
    let an = normalize_va(&a);
    let gn = normalize_va(&g);
    an.is_some() && an == gn
}

fn is_abstain(answer: &str) -> bool {
    let a = answer.to_ascii_lowercase();
    ABSTAIN_MARKERS.iter().any(|m| a.contains(m))
}

fn normalize_va(s: &str) -> Option<u64> {
    let t = s.trim();
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    let token = hex
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|p| !p.is_empty() && p.len() >= 4)?;
    u64::from_str_radix(token, 16).ok()
}

fn arm_name(arm: Arm) -> &'static str {
    match arm {
        Arm::A => "A",
        Arm::B => "B",
        Arm::C => "C",
    }
}

fn windy_tool_names(arm: Arm) -> &'static [&'static str] {
    match arm {
        Arm::A => &[
            "open_project",
            "list_projects",
            "get_triage",
            "search_bel",
            "list_functions",
            "get_function_evidence",
            "functions_named",
            "read_pointers",
            "walk_list",
            "read_struct_array",
            "describe_address",
            "trace_value",
            "list_exports",
            "list_imports",
            "list_strings",
        ],
        Arm::B => &[], // handled by python_scratch_tool_defs
        Arm::C => &[
            "open_project",
            "list_functions",
            "get_function_agent_text",
            "read_va",
            "get_fragment",
        ],
    }
}

fn mcp_tool_defs(names: &[&str]) -> Vec<Value> {
    names
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "description": format!("Windy MCP tool `{name}` (proxied by harness)"),
                "input_schema": {
                    "type": "object",
                    "additionalProperties": true,
                }
            })
        })
        .collect()
}

/// Arm B tools: real ability to inspect the PE without Windy.
fn python_scratch_tool_defs() -> Vec<Value> {
    vec![
        json!({
            "name": "bash",
            "description": "Run a shell command in the scratch directory (cwd is the scratch root). \
                Python venv with pefile and capstone is on PATH. BINARY_PATH env var points at the PE. \
                Use this to write/run throwaway scripts. Do not invent VAs — read them from the binary.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to run (cmd.exe on Windows, sh -c elsewhere)."
                    }
                },
                "required": ["command"]
            }
        }),
        json!({
            "name": "write_file",
            "description": "Write a UTF-8 text file under the scratch directory (relative path only).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Relative path under scratch, e.g. inspect.py" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }
        }),
        json!({
            "name": "read_file",
            "description": "Read a UTF-8 text file under the scratch directory (relative path only).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }
        }),
    ]
}

fn run_live_task(cli: &Cli, root: &Path, windy: &Path, arm: Arm, task: &Task) -> TaskResult {
    let started = Instant::now();
    let api_key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return TaskResult {
                task_id: task.id.clone(),
                arm: arm_name(arm).into(),
                success: false,
                abstained: false,
                answer: String::new(),
                gold: task.gold.clone(),
                tool_calls: 0,
                tokens: TokenUsage::default(),
                wall_ms: started.elapsed().as_millis(),
                mode: "live".into(),
                error: Some("ANTHROPIC_API_KEY not set".into()),
            };
        }
    };

    match arm {
        Arm::B => run_live_python_arm(cli, root, &api_key, task, started),
        Arm::A | Arm::C => run_live_windy_arm(cli, root, windy, arm, &api_key, task, started),
    }
}

fn run_live_python_arm(
    cli: &Cli,
    root: &Path,
    api_key: &str,
    task: &Task,
    started: Instant,
) -> TaskResult {
    let scratch = root
        .join("target/agent-bench-scratch")
        .join(task.id.replace(':', "_"));
    let _ = fs::remove_dir_all(&scratch);
    if let Err(e) = fs::create_dir_all(&scratch) {
        return fail_result(task, "B", started, e.to_string());
    }

    // Seed a helper the agent may edit; it is not product code.
    let helper = scratch.join("pe_inspect.py");
    let seed = format!(
        r#"# Scratch helper (agent-bench arm B). Throwaway — not maintained product code.
import sys
import pefile
pe = pefile.PE(r"{pe}")
print("image_base", hex(pe.OPTIONAL_HEADER.ImageBase))
print("entry", hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint))
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            print("export", hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode(errors="replace"))
"#,
        pe = task.pe_path.display().to_string().replace('\\', "\\\\")
    );
    let _ = fs::write(&helper, seed);

    if let Err(e) = ensure_python_pe_tools(&scratch) {
        return fail_result(
            task,
            "B",
            started,
            format!("failed to provision pefile/capstone in scratch: {e}"),
        );
    }

    let system = format!(
        "You reverse Windows PE binaries using only a shell and Python in a scratch directory.\n\
         You do NOT have Windy or any RE IDE.\n\
         Scratch directory (cwd for bash): {scratch}\n\
         Binary path: {pe}\n\
         Environment: BINARY_PATH is set; a venv with pefile and capstone is on PATH.\n\
         Tools: bash (run commands), write_file, read_file.\n\
         Seed script: pe_inspect.py — you may edit or replace it.\n\
         Answer with a single hex VA, or refuse if the function is gone/inlined/eliminated.\n\
         Do not invent VAs. Inspect the binary with your tools first.",
        scratch = scratch.display(),
        pe = task.pe_path.display()
    );

    let backend = ToolBackend::PythonScratch {
        scratch: scratch.clone(),
        pe_path: task.pe_path.clone(),
    };
    match anthropic_tool_loop(
        api_key,
        &cli.model,
        &system,
        &task.question,
        &python_scratch_tool_defs(),
        &backend,
    ) {
        Ok((answer, tokens, tools)) => {
            let success = score_answer(task, &answer);
            TaskResult {
                task_id: task.id.clone(),
                arm: "B".into(),
                success,
                abstained: is_abstain(&answer),
                answer,
                gold: task.gold.clone(),
                tool_calls: tools,
                tokens,
                wall_ms: started.elapsed().as_millis(),
                mode: "live".into(),
                error: None,
            }
        }
        Err(e) => fail_result(task, "B", started, e.to_string()),
    }
}

/// Create a scratch venv and install pefile + capstone when missing.
fn ensure_python_pe_tools(scratch: &Path) -> Result<()> {
    let py = python_launcher();
    let venv = scratch.join(".venv");
    let marker = scratch.join(".venv_ready");
    if marker.exists() {
        return Ok(());
    }

    let status = Command::new(&py)
        .args(["-m", "venv"])
        .arg(&venv)
        .current_dir(scratch)
        .status()
        .with_context(|| format!("spawn {py} -m venv"))?;
    if !status.success() {
        bail!("python -m venv failed with {status}");
    }

    let pip = if cfg!(windows) {
        venv.join("Scripts").join("pip.exe")
    } else {
        venv.join("bin").join("pip")
    };
    let status = Command::new(&pip)
        .args(["install", "--quiet", "pefile", "capstone"])
        .current_dir(scratch)
        .status()
        .with_context(|| format!("spawn {}", pip.display()))?;
    if !status.success() {
        bail!("pip install pefile capstone failed with {status}");
    }

    // Quick import check via venv python.
    let vpy = if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    };
    let status = Command::new(&vpy)
        .args(["-c", "import pefile, capstone; print('ok')"])
        .current_dir(scratch)
        .status()
        .with_context(|| format!("spawn {}", vpy.display()))?;
    if !status.success() {
        bail!("venv import check failed with {status}");
    }

    fs::write(&marker, b"ok")?;
    Ok(())
}

fn python_launcher() -> String {
    std::env::var("PYTHON")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "python".into()
            } else {
                "python3".into()
            }
        })
}

fn run_live_windy_arm(
    cli: &Cli,
    root: &Path,
    windy: &Path,
    arm: Arm,
    api_key: &str,
    task: &Task,
    started: Instant,
) -> TaskResult {
    if !windy.exists() {
        return fail_result(
            task,
            arm_name(arm),
            started,
            format!("windy binary missing: {}", windy.display()),
        );
    }
    let data_dir = root.join("target/agent-bench-data").join(format!(
        "{}-{}",
        arm_name(arm),
        task.id.replace(':', "_")
    ));
    let _ = fs::remove_dir_all(&data_dir);
    let _ = fs::create_dir_all(&data_dir);

    let bind = unique_bind(&cli.mcp_bind, &task.id);
    let mut child = match spawn_windy(windy, &bind, &task.pe_path, &data_dir) {
        Ok(c) => c,
        Err(e) => return fail_result(task, arm_name(arm), started, e.to_string()),
    };
    thread::sleep(Duration::from_millis(800));

    let endpoint = format!("http://{bind}/mcp");
    let tools = windy_tool_names(arm);
    let system = format!(
        "You are a reverse engineer using Windy MCP tools only.\n\
         Endpoint: {endpoint}\n\
         Allowed tools: {}\n\
         Project is already open if serve-mcp --open succeeded; list_projects to get project_id.\n\
         Answer with a single hex VA or the word refuse.\n\
         Prefer get_triage / search_bel / get_function_evidence / describe_address over raw hex.",
        tools.join(", ")
    );

    let backend = ToolBackend::Mcp {
        endpoint: endpoint.clone(),
    };
    let result = anthropic_tool_loop(
        api_key,
        &cli.model,
        &system,
        &task.question,
        &mcp_tool_defs(tools),
        &backend,
    );

    let _ = child.kill();
    let _ = child.wait();

    match result {
        Ok((answer, tokens, tool_calls)) => {
            let success = score_answer(task, &answer);
            TaskResult {
                task_id: task.id.clone(),
                arm: arm_name(arm).into(),
                success,
                abstained: is_abstain(&answer),
                answer,
                gold: task.gold.clone(),
                tool_calls,
                tokens,
                wall_ms: started.elapsed().as_millis(),
                mode: "live".into(),
                error: None,
            }
        }
        Err(e) => fail_result(task, arm_name(arm), started, e.to_string()),
    }
}

fn fail_result(task: &Task, arm: &str, started: Instant, error: String) -> TaskResult {
    TaskResult {
        task_id: task.id.clone(),
        arm: arm.into(),
        success: false,
        abstained: false,
        answer: String::new(),
        gold: task.gold.clone(),
        tool_calls: 0,
        tokens: TokenUsage::default(),
        wall_ms: started.elapsed().as_millis(),
        mode: "live".into(),
        error: Some(error),
    }
}

fn unique_bind(base: &str, task_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(task_id.as_bytes());
    let h = hasher.finalize();
    let port = 18765 + (u16::from(h[0]) % 1000);
    if let Some((host, _)) = base.rsplit_once(':') {
        format!("{host}:{port}")
    } else {
        format!("127.0.0.1:{port}")
    }
}

fn spawn_windy(windy: &Path, bind: &str, pe: &Path, data_dir: &Path) -> Result<Child> {
    Command::new(windy)
        .arg("serve-mcp")
        .arg("--bind")
        .arg(bind)
        .arg("--open")
        .arg(pe)
        .arg("--data-dir")
        .arg(data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", windy.display()))
}

/// Anthropic Messages API loop. All tool_result blocks go in one user message.
fn anthropic_tool_loop(
    api_key: &str,
    model: &str,
    system: &str,
    user: &str,
    tools_json: &[Value],
    backend: &ToolBackend,
) -> Result<(String, TokenUsage, usize)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()?;

    let mut messages = vec![json!({"role": "user", "content": user})];
    let mut usage = TokenUsage::default();
    let mut tool_calls = 0usize;
    let mut final_text = String::new();

    for _turn in 0..16 {
        let mut body = json!({
            "model": model,
            "max_tokens": 4096,
            "system": [
                {
                    "type": "text",
                    "text": system,
                    "cache_control": { "type": "ephemeral" }
                }
            ],
            "messages": messages,
        });
        // Do NOT set temperature/top_p/top_k — rejected on some models.
        if !tools_json.is_empty() {
            body["tools"] = Value::Array(tools_json.to_vec());
        }

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .context("anthropic request")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            bail!("anthropic HTTP {status}: {text}");
        }
        let resp_json: Value = resp.json()?;
        accumulate_usage(&mut usage, &resp_json);

        let content = resp_json
            .get("content")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        let stop = resp_json
            .get("stop_reason")
            .and_then(|s| s.as_str())
            .unwrap_or("");

        messages.push(json!({"role": "assistant", "content": content.clone()}));

        if stop == "tool_use" {
            let mut tool_results = Vec::new();
            for block in &content {
                if block.get("type").and_then(|t| t.as_str()) != Some("tool_use") {
                    continue;
                }
                tool_calls += 1;
                let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let input = block.get("input").cloned().unwrap_or(json!({}));
                let result =
                    execute_tool(backend, name, &input).unwrap_or_else(|e| format!("error: {e}"));
                tool_results.push(json!({
                    "type": "tool_result",
                    "tool_use_id": id,
                    "content": truncate_tool_output(&result),
                }));
            }
            messages.push(json!({"role": "user", "content": tool_results}));
            continue;
        }

        for block in &content {
            if block.get("type").and_then(|t| t.as_str()) == Some("text")
                && let Some(t) = block.get("text").and_then(|t| t.as_str())
            {
                final_text.push_str(t);
            }
        }
        break;
    }

    Ok((final_text, usage, tool_calls))
}

fn execute_tool(backend: &ToolBackend, name: &str, input: &Value) -> Result<String> {
    match backend {
        ToolBackend::Mcp { endpoint } => proxy_mcp_tool(endpoint, name, input),
        ToolBackend::PythonScratch { scratch, pe_path } => {
            execute_python_scratch_tool(scratch, pe_path, name, input)
        }
    }
}

fn execute_python_scratch_tool(
    scratch: &Path,
    pe_path: &Path,
    name: &str,
    input: &Value,
) -> Result<String> {
    match name {
        "bash" => {
            let command = input
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("bash requires string field `command`"))?;
            run_scratch_shell(scratch, pe_path, command)
        }
        "write_file" => {
            let rel = input
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("write_file requires `path`"))?;
            let content = input
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("write_file requires `content`"))?;
            let path = resolve_scratch_path(scratch, rel)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, content)?;
            Ok(format!(
                "wrote {} ({} bytes)",
                path.display(),
                content.len()
            ))
        }
        "read_file" => {
            let rel = input
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("read_file requires `path`"))?;
            let path = resolve_scratch_path(scratch, rel)?;
            let data =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            Ok(truncate_tool_output(&data))
        }
        other => bail!("unknown arm-B tool `{other}` (allowed: bash, write_file, read_file)"),
    }
}

fn resolve_scratch_path(scratch: &Path, rel: &str) -> Result<PathBuf> {
    let rel = rel.trim();
    if rel.is_empty() {
        bail!("empty path");
    }
    if Path::new(rel).is_absolute() {
        bail!("absolute paths rejected; use a path relative to scratch");
    }
    if rel.split(['/', '\\']).any(|p| p == "..") {
        bail!("path traversal rejected");
    }
    let scratch = scratch
        .canonicalize()
        .with_context(|| format!("canonicalize {}", scratch.display()))?;
    let joined = scratch.join(rel);
    // If parent exists, ensure final path stays under scratch after normalize.
    if let Ok(canon) = joined.canonicalize() {
        if !canon.starts_with(&scratch) {
            bail!("path escapes scratch");
        }
        return Ok(canon);
    }
    // File may not exist yet (write_file): check parent.
    if let Some(parent) = joined.parent() {
        if parent.exists() {
            let parent = parent.canonicalize()?;
            if !parent.starts_with(&scratch) {
                bail!("path escapes scratch");
            }
        }
    }
    Ok(joined)
}

fn run_scratch_shell(scratch: &Path, pe_path: &Path, command: &str) -> Result<String> {
    let scratch = scratch
        .canonicalize()
        .with_context(|| format!("canonicalize {}", scratch.display()))?;

    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };

    // Prefer venv python/scripts on PATH for this process.
    let path_prepend = if cfg!(windows) {
        scratch.join(".venv").join("Scripts")
    } else {
        scratch.join(".venv").join("bin")
    };
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut new_path = path_prepend.into_os_string();
    if cfg!(windows) {
        new_path.push(";");
    } else {
        new_path.push(":");
    }
    new_path.push(&old_path);

    cmd.current_dir(&scratch)
        .env("PATH", new_path)
        .env("BINARY_PATH", pe_path)
        .env("PYTHONUTF8", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawn shell")?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    let _ = out.read_to_end(&mut buf);
                    stdout = String::from_utf8_lossy(&buf).into_owned();
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let mut buf = Vec::new();
                    let _ = err.read_to_end(&mut buf);
                    stderr = String::from_utf8_lossy(&buf).into_owned();
                }
                let mut combined = String::new();
                if !stdout.is_empty() {
                    combined.push_str(&stdout);
                }
                if !stderr.is_empty() {
                    if !combined.is_empty() {
                        combined.push_str("\n--- stderr ---\n");
                    }
                    combined.push_str(&stderr);
                }
                if combined.is_empty() {
                    combined = format!("(exit {status}, no output)");
                } else {
                    combined.push_str(&format!("\n(exit {status})"));
                }
                return Ok(truncate_tool_output(&combined));
            }
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(SHELL_TIMEOUT_SECS) {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("command timed out after {SHELL_TIMEOUT_SECS}s");
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => bail!("wait shell: {e}"),
        }
    }
}

fn truncate_tool_output(s: &str) -> String {
    if s.len() <= MAX_SHELL_OUTPUT {
        return s.to_string();
    }
    let mut out = s[..MAX_SHELL_OUTPUT].to_string();
    out.push_str("\n…[truncated]");
    out
}

fn accumulate_usage(usage: &mut TokenUsage, resp: &Value) {
    let u = match resp.get("usage") {
        Some(u) => u,
        None => return,
    };
    usage.input_tokens = usage.input_tokens.saturating_add(
        u.get("input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or_default(),
    );
    usage.output_tokens = usage.output_tokens.saturating_add(
        u.get("output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or_default(),
    );
    usage.cache_creation_input_tokens = usage.cache_creation_input_tokens.saturating_add(
        u.get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or_default(),
    );
    usage.cache_read_input_tokens = usage.cache_read_input_tokens.saturating_add(
        u.get("cache_read_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or_default(),
    );
}

/// Best-effort JSON-RPC tools/call against streamable HTTP MCP.
fn proxy_mcp_tool(endpoint: &str, name: &str, input: &Value) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "agent-bench", "version": "0.1.0" }
        }
    });
    let init_resp = client
        .post(endpoint)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&init)
        .send();
    let session = init_resp.as_ref().ok().and_then(|r| {
        r.headers()
            .get("mcp-session-id")
            .or_else(|| r.headers().get("Mcp-Session-Id"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    });

    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": input,
        }
    });
    let mut req = client
        .post(endpoint)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&call);
    if let Some(sid) = session {
        req = req.header("mcp-session-id", sid);
    }
    let resp = req.send().context("mcp tools/call")?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("mcp HTTP {status}: {text}");
    }
    Ok(text)
}

fn build_report(cli: &Cli, root: &Path, tasks: &[Task], results: Vec<TaskResult>) -> Report {
    let mut by_arm: BTreeMap<String, ArmSummary> = BTreeMap::new();
    for r in &results {
        let e = by_arm.entry(r.arm.clone()).or_insert_with(|| ArmSummary {
            arm: r.arm.clone(),
            tasks: 0,
            successes: 0,
            abstentions: 0,
            abstention_correct: 0,
            total_tool_calls: 0,
            tokens: TokenUsage::default(),
            wall_ms: 0,
        });
        e.tasks += 1;
        if r.success {
            e.successes += 1;
        }
        if r.abstained {
            e.abstentions += 1;
            if r.success {
                e.abstention_correct += 1;
            }
        }
        e.total_tool_calls += r.tool_calls;
        e.tokens.add_assign(&r.tokens);
        e.wall_ms = e.wall_ms.saturating_add(r.wall_ms);
    }

    let corpus_sha = {
        let mut hasher = Sha256::new();
        for t in tasks {
            hasher.update(t.id.as_bytes());
            hasher.update(t.pe_path.to_string_lossy().as_bytes());
        }
        format!("{:x}", hasher.finalize())
    };

    let synthetic = !cli.live;
    Report {
        harness: if synthetic {
            "agent-bench-v1-wiring-check".into()
        } else {
            "agent-bench-v1".into()
        },
        synthetic,
        commit: git_head(root),
        model: cli.live.then(|| cli.model.clone()),
        live: cli.live,
        arms: by_arm.into_values().collect(),
        results,
        corpus: json!({
            "task_count": tasks.len(),
            "profiles": cli.profile,
            "families": cli.family,
            "task_set_sha256": corpus_sha,
            "note": if synthetic {
                "SYNTHETIC offline wiring: arm A returns gold by construction; B/C wrong by construction. Not a product measurement."
            } else {
                "Live agent loop results."
            },
        }),
    }
}

fn git_head(root: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn render_markdown(report: &Report) -> String {
    let mut md = String::new();
    if report.synthetic {
        md.push_str("# Agent loop wiring check (SYNTHETIC - not a benchmark)\n\n");
        md.push_str(
            "> Offline mode returns gold for arm A and wrong answers for B/C by construction.\n\
             > Do not cite these numbers as product evidence. Run `--live` for real A-vs-B.\n\n",
        );
    } else {
        md.push_str("# Agent loop v1\n\n");
    }
    md.push_str(&format!(
        "- harness: `{}`\n- synthetic: {}\n- live: {}\n- commit: {}\n\n",
        report.harness,
        report.synthetic,
        report.live,
        report.commit.as_deref().unwrap_or("unknown")
    ));
    md.push_str("| arm | tasks | success | abstain (correct) | tool_calls | prompt_tokens (all fields) | wall_ms |\n");
    md.push_str("|---|---:|---:|---:|---:|---:|---:|\n");
    for a in &report.arms {
        md.push_str(&format!(
            "| {} | {} | {} | {} ({}) | {} | {} | {} |\n",
            a.arm,
            a.tasks,
            a.successes,
            a.abstentions,
            a.abstention_correct,
            a.total_tool_calls,
            a.tokens.total_prompt(),
            a.wall_ms
        ));
    }
    md.push_str(
        "\nPrompt tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.\n",
    );
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstain_vocab_unified() {
        assert!(is_abstain("eliminated by inlining"));
        assert!(score_answer(
            &Task {
                id: "t".into(),
                family: "abstain".into(),
                program_id: "p".into(),
                profile: "P0".into(),
                pe_path: PathBuf::from("x.exe"),
                question: String::new(),
                gold: "refuse".into(),
                source_name: None,
            },
            "eliminated by inlining"
        ));
        assert!(is_abstain("eliminated by inlining"));
    }

    #[test]
    fn scratch_path_rejects_traversal() {
        let dir = std::env::temp_dir().join("agent-bench-path-test");
        let _ = fs::create_dir_all(&dir);
        let err = resolve_scratch_path(&dir, "../escape.txt").unwrap_err();
        assert!(err.to_string().contains("traversal") || err.to_string().contains("escape"));
    }

    #[test]
    fn bash_tool_defs_present() {
        let defs = python_scratch_tool_defs();
        let names: Vec<_> = defs
            .iter()
            .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(names, ["bash", "write_file", "read_file"]);
    }
}
