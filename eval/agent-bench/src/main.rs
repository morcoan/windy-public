//! Agent-loop benchmark harness (outside the windy binary).
//!
//! Arms:
//! - A: windy-evidence (MCP v2: target_triage, evidence_search, function_inspect, …)
//! - B: python-tools (bash + scratch dir with pefile/capstone; no Windy)
//! - C: windy-dump (agent_text + read_va only)
//!
//! Token accounting sums input_tokens + cache_creation_input_tokens +
//! cache_read_input_tokens (Anthropic usage fields). Never report
//! input_tokens alone.
//!
//! Default mode is offline **scoring-wiring** only (synthetic answers, no
//! binary analysis). It is not a benchmark result â€” write fixtures under
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
    /// Profiles to include (P0 P1 â€¦).
    #[arg(long, default_values_t = ["P0".to_string(), "P1".to_string()])]
    profile: Vec<String>,
    /// Task families: locate, abstain, enumerate, triage, provenance.
    #[arg(long, default_values_t = ["locate".to_string(), "abstain".to_string()])]
    family: Vec<String>,
    /// Live Anthropic loop (requires ANTHROPIC_API_KEY). Paid tokens.
    #[arg(long, default_value_t = false)]
    live: bool,
    /// Free local tool agents: arm A = Windy MCP evidence ladder, arm B = python+pefile.
    /// No Anthropic. Preferred for P0/P1 CI / free subagent orchestration.
    #[arg(long, default_value_t = false)]
    local: bool,
    /// Interleave locate/abstain instead of sort-all-abstain-first.
    #[arg(long, default_value_t = false)]
    balanced: bool,
    /// Ingest per-task result JSON written by external agents (one file per
    /// task/arm). Used for subagent runs where the model is driven outside this
    /// process; each file must report the tools it actually called.
    #[arg(long)]
    sidecar: Option<PathBuf>,
    /// Model id for live runs.
    #[arg(long, default_value = "claude-opus-5")]
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

// `IdentityEntry` (the eval/grand/identity_maps row type) is deliberately gone:
// 442/480 of its entries contradict the linker map for the same binary, and it
// disagrees with itself about whether `function_id` or `source_name` holds the
// real C symbol. Nothing should read it until it is regenerated.

/// Usual first-function VA of an `/Od` MSVC x64 image — the answer a model
/// produces from layout priors alone, with no analysis. Scored as a baseline so
/// a lucky guess can never be mistaken for capability.
#[derive(Debug, Deserialize)]
struct BenchManifest {
    binaries: Vec<BenchBinary>,
}

#[derive(Debug, Deserialize)]
struct BenchBinary {
    program_id: String,
    profile: String,
    pe_path: PathBuf,
    #[serde(default)]
    function_map: Vec<BenchFunction>,
}

#[derive(Debug, Deserialize)]
struct BenchFunction {
    source_name: String,
    status: String,
    #[serde(default)]
    entry_va: Option<String>,
}

const DEFAULT_VA_GUESS: &str = "0x140001000";

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    family: String,
    success: bool,
    abstained: bool,
    answer: String,
    gold: String,
    /// `None` = not instrumented. Never emit 0 for "we didn't measure" — a zero
    /// that looks like a measurement is what made the first Grok report unreadable.
    tool_calls: Option<usize>,
    tools_used: Vec<String>,
    tokens: Option<TokenUsage>,
    wall_ms: Option<u128>,
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
    /// Per-family accuracy. Never average these into one headline: with a 50/50
    /// locate/abstain split, "always refuse" scores 50% while locating nothing.
    families: BTreeMap<String, FamilyStat>,
    /// How many of `tasks` carried real telemetry.
    instrumented_tasks: usize,
    total_tool_calls: Option<usize>,
    tokens: Option<TokenUsage>,
    wall_ms: Option<u128>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct FamilyStat {
    n: usize,
    successes: usize,
}

/// Trivial constant policies scored on the same task set. An arm that does not
/// beat both of these has demonstrated no capability, whatever its total says.
#[derive(Clone, Debug, Serialize)]
struct Baselines {
    always_refuse: BTreeMap<String, FamilyStat>,
    always_default_va: BTreeMap<String, FamilyStat>,
    note: String,
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
    baselines: Baselines,
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
    if cli.live && cli.local {
        bail!("pass only one of --live or --local");
    }

    let tasks = load_tasks(
        &root,
        &cli.profile,
        &cli.family,
        cli.limit,
        cli.balanced || cli.local,
    )?;
    if tasks.is_empty() {
        bail!(
            "no tasks matched filters (profiles={:?} families={:?})",
            cli.profile,
            cli.family
        );
    }

    if cli.local {
        eprintln!(
            "agent-bench: free --local mode (Windy MCP ladder vs python/pefile). No Anthropic."
        );
    } else if !cli.live {
        eprintln!(
            "agent-bench: offline wiring-check mode (synthetic answers). \
             Not a benchmark result. Use --local (free) or --live (paid Anthropic)."
        );
    }

    let windy = resolve_windy(&root, cli.windy.as_deref())?;
    let mut results = Vec::new();

    for arm in &cli.arm {
        for task in &tasks {
            let result = if let Some(dir) = &cli.sidecar {
                run_sidecar_task(dir, *arm, task)
            } else if cli.live {
                run_live_task(&cli, &root, &windy, *arm, task)
            } else if cli.local {
                run_local_task(&root, &windy, *arm, task)
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
    // Prefer newest among debug/release so a stale release binary does not hide
    // a freshly built debug with agent-query.
    let candidates = [
        root.join("target/debug/windy.exe"),
        root.join("target/release/windy.exe"),
        root.join("target/debug/windy"),
        root.join("target/release/windy"),
    ];
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for p in candidates {
        if !p.exists() {
            continue;
        }
        let modified = fs::metadata(&p)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &best {
            None => best = Some((modified, p)),
            Some((t, _)) if modified > *t => best = Some((modified, p)),
            _ => {}
        }
    }
    Ok(best
        .map(|(_, p)| p)
        .unwrap_or_else(|| root.join("target/debug/windy.exe")))
}

/// Copy a PE on its own into a staging directory, leaving every sibling behind.
///
/// This is load-bearing, not hygiene. `src/project/mod.rs` calls
/// `apply_adjacent_msvc_map_names`, so opening `bin/P0/x.exe` lets Windy lift
/// real function names straight out of `bin/P0/x.map` — the same linker-derived
/// identities frozen in the tracked manifest. Measured directly: with the `.map` present,
/// `functions_named "main"` returns `0x140001080`; with the PE staged alone, it
/// returns nothing. Benchmarking symbol recovery against a directory that also
/// contains the answer key measures the directory, not the substrate.
///
/// Staging is deliberately applied to every arm so the two see identical inputs.
fn stage_pe(pe: &Path, stage_root: &Path, program_id: &str, profile: &str) -> Result<PathBuf> {
    let dir = stage_root.join(format!("{program_id}_{profile}"));
    if dir.exists() {
        fs::remove_dir_all(&dir)
            .with_context(|| format!("clear stale stage dir {}", dir.display()))?;
    }
    fs::create_dir_all(&dir).with_context(|| format!("create stage dir {}", dir.display()))?;
    let dest = dir.join(
        pe.file_name()
            .ok_or_else(|| anyhow::anyhow!("PE has no file name: {}", pe.display()))?,
    );
    fs::copy(pe, &dest).with_context(|| format!("stage {} -> {}", pe.display(), dest.display()))?;
    Ok(dest)
}

fn load_tasks(
    root: &Path,
    profiles: &[String],
    families: &[String],
    limit: usize,
    balanced: bool,
) -> Result<Vec<Task>> {
    let manifest_path = root.join("eval/grand/manifest.json");
    let manifest_text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read benchmark manifest {}", manifest_path.display()))?;
    let manifest: BenchManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("parse benchmark manifest {}", manifest_path.display()))?;

    for bin in &manifest.binaries {
        for function in &bin.function_map {
            if !matches!(
                function.status.as_str(),
                "present" | "folded" | "inlined_only" | "missing"
            ) {
                bail!(
                    "unknown manifest status {:?} for {} {} {}",
                    function.status,
                    bin.program_id,
                    bin.profile,
                    function.source_name
                );
            }
        }
    }

    // The tracked manifest freezes linker-derived source identity for every
    // concrete binary. It is the clean-checkout truth source; adjacent map
    // files are deliberately ignored because they are not shipped publicly and
    // would leak the answer key to Windy's symbol loader.
    let p0_by_program: BTreeMap<String, &BenchBinary> = manifest
        .binaries
        .iter()
        .filter(|bin| bin.profile == "P0")
        .map(|bin| (bin.program_id.clone(), bin))
        .collect();
    if p0_by_program.is_empty() {
        bail!("manifest has no P0 source rosters");
    }

    let mut foreign_names: Vec<String> = p0_by_program
        .values()
        .filter_map(|bin| {
            bin.function_map
                .iter()
                .map(|function| function.source_name.as_str())
                .find(|name| *name != "main" && name.len() > 4 && !name.starts_with('_'))
                .map(str::to_owned)
        })
        .collect();
    foreign_names.sort();
    foreign_names.dedup();

    let stage_root = root.join("target/agent-bench-stage");
    let mut tasks = Vec::new();
    for (program_id, p0) in p0_by_program {
        let roster: BTreeMap<String, &BenchFunction> = p0
            .function_map
            .iter()
            .map(|function| (function.source_name.clone(), function))
            .collect();
        if roster.is_empty() {
            continue;
        }

        for profile in profiles {
            let Some(bin) = manifest
                .binaries
                .iter()
                .find(|bin| bin.program_id == program_id && bin.profile == *profile)
            else {
                continue;
            };
            let source_pe = root.join(&bin.pe_path);
            if !source_pe.is_file() {
                eprintln!(
                    "warning: manifest binary is missing for {program_id} {profile}: {}",
                    source_pe.display()
                );
                continue;
            }
            let pe_path = stage_pe(&source_pe, &stage_root, &program_id, profile)?;
            let truth: BTreeMap<&str, &BenchFunction> = bin
                .function_map
                .iter()
                .map(|function| (function.source_name.as_str(), function))
                .collect();

            for name in roster.keys() {
                match truth.get(name.as_str()).copied() {
                    Some(function) if function.status == "present" => {
                        if !families.iter().any(|family| family == "locate") {
                            continue;
                        }
                        let va = function.entry_va.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "present function has no entry_va: {program_id} {profile} {name}"
                            )
                        })?;
                        let normalized = u64::from_str_radix(va.trim_start_matches("0x"), 16)
                            .with_context(|| {
                                format!("invalid entry_va {va:?} for {program_id} {profile} {name}")
                            })?;
                        tasks.push(Task {
                            id: format!("locate:{program_id}:{profile}:{name}"),
                            family: "locate".into(),
                            program_id: program_id.clone(),
                            profile: profile.clone(),
                            pe_path: pe_path.clone(),
                            question: format!(
                                "Which VA implements source function `{name}` in this binary? \
                                 Answer with a single hex VA, or refuse if it is not present."
                            ),
                            gold: format!("{normalized:#x}"),
                            source_name: Some(name.clone()),
                        });
                    }
                    Some(_) | None if families.iter().any(|family| family == "abstain") => {
                        tasks.push(Task {
                            id: format!("abstain:{program_id}:{profile}:{name}"),
                            family: "abstain".into(),
                            program_id: program_id.clone(),
                            profile: profile.clone(),
                            pe_path: pe_path.clone(),
                            question: format!(
                                "Which VA implements source function `{name}` in this binary? \
                                 Answer with a single hex VA, or refuse if it is not present."
                            ),
                            gold: "refuse".into(),
                            source_name: Some(name.clone()),
                        });
                    }
                    _ => {}
                }
            }

            // Optimizer-elided functions are rare in P0/P1. Add one real name
            // borrowed from another program so a balanced run can still test
            // honest refusal without inventing a fake symbol.
            let pick = {
                let mut hash = Sha256::new();
                hash.update(program_id.as_bytes());
                hash.update(profile.as_bytes());
                let digest = hash.finalize();
                usize::from(digest[0]) | (usize::from(digest[1]) << 8)
            };
            if families.iter().any(|family| family == "abstain")
                && let Some(foreign) = (0..foreign_names.len())
                    .map(|index| &foreign_names[(pick + index) % foreign_names.len()])
                    .find(|name| !roster.contains_key(name.as_str()))
            {
                tasks.push(Task {
                    id: format!("abstain:{program_id}:{profile}:{foreign}"),
                    family: "abstain".into(),
                    program_id: program_id.clone(),
                    profile: profile.clone(),
                    pe_path: pe_path.clone(),
                    question: format!(
                        "Which VA implements source function `{foreign}` in this binary? \
                         Answer with a single hex VA, or refuse if it is not present."
                    ),
                    gold: "refuse".into(),
                    source_name: Some(foreign.clone()),
                });
            }
        }
    }

    select_tasks(tasks, limit, balanced)
}

fn select_tasks(mut tasks: Vec<Task>, limit: usize, balanced: bool) -> Result<Vec<Task>> {
    if balanced {
        // Interleave locate and abstain so limit=12 exercises both skills.
        let mut locate: Vec<_> = tasks
            .iter()
            .filter(|task| task.family == "locate")
            .cloned()
            .collect();
        let mut abstain: Vec<_> = tasks
            .iter()
            .filter(|task| task.family == "abstain")
            .cloned()
            .collect();
        let mut out = Vec::new();
        let half = limit.div_ceil(2);
        locate.truncate(half.min(locate.len()));
        abstain.truncate(limit.saturating_sub(locate.len()).min(abstain.len()));
        let mut index = 0;
        while out.len() < limit && (index < locate.len() || index < abstain.len()) {
            if index < locate.len() {
                out.push(locate[index].clone());
            }
            if out.len() < limit && index < abstain.len() {
                out.push(abstain[index].clone());
            }
            index += 1;
        }
        if out.len() < limit {
            let selected: std::collections::BTreeSet<_> =
                out.iter().map(|task| task.id.clone()).collect();
            out.extend(
                tasks
                    .iter()
                    .filter(|task| !selected.contains(&task.id))
                    .take(limit - out.len())
                    .cloned(),
            );
        }
        return Ok(out);
    }
    tasks.truncate(limit);
    Ok(tasks)
}

/// Free local tool agents (no LLM / no Anthropic).
/// Arm A: multi-step Windy MCP evidence ladder (triage → BEL → named → evidence).
/// Arm B: python + pefile in scratch (baseline).
/// Arm C: refuse unless name is literally an export-like hit via agent-query dump-style:
/// uses agent-query then only accepts exact name match without fuzzy refuse heuristics beyond empty.
fn run_local_task(root: &Path, windy: &Path, arm: Arm, task: &Task) -> TaskResult {
    let started = Instant::now();
    let source = task.source_name.clone().unwrap_or_else(|| "unknown".into());
    let (answer, tool_calls, tools_used, error) = match arm {
        Arm::A => match local_arm_a_windy_ladder(root, windy, &task.pe_path, &source, &task.id) {
            Ok((ans, n, tools)) => (ans, n, tools, None),
            Err(e) => (String::new(), 0, Vec::new(), Some(e.to_string())),
        },
        Arm::B => match local_arm_b_python(root, &task.pe_path, &source) {
            Ok((ans, n)) => (ans, n, vec!["bash".into(), "write_file".into()], None),
            Err(e) => (String::new(), 0, Vec::new(), Some(e.to_string())),
        },
        Arm::C => match local_arm_c_dump(windy, &task.pe_path, &source) {
            Ok((ans, n)) => (ans, n, vec!["agent-query".into()], None),
            Err(e) => (String::new(), 0, Vec::new(), Some(e.to_string())),
        },
    };
    let success = if error.is_some() {
        false
    } else {
        score_answer(task, &answer)
    };
    TaskResult {
        task_id: task.id.clone(),
        arm: arm_name(arm).into(),
        family: task.family.clone(),
        success,
        abstained: is_abstain(&answer),
        answer,
        gold: task.gold.clone(),
        tool_calls: Some(tool_calls),
        tools_used,
        tokens: None, // free path: no model tokens to report
        wall_ms: Some(started.elapsed().as_millis()),
        mode: "local_tools".into(),
        error,
    }
}

/// Deterministic Arm A policy: exercise the real product MCP ladder over HTTP.
///
/// Order mirrors AGENTS.md: target_open → target_triage → evidence_search →
/// a discovered name capability → function_inspect (when a candidate exists).
fn local_arm_a_windy_ladder(
    root: &Path,
    windy: &Path,
    pe: &Path,
    source: &str,
    task_id: &str,
) -> Result<(String, usize, Vec<String>)> {
    if !windy.exists() {
        bail!("windy binary missing: {}", windy.display());
    }

    let data_dir = root
        .join("target/agent-bench-data")
        .join(format!("local-A-{}", task_id.replace(':', "_")));
    let _ = fs::remove_dir_all(&data_dir);
    fs::create_dir_all(&data_dir)?;

    // Ephemeral free port — never hash-collide with a leftover serve-mcp.
    let bind = free_local_bind("127.0.0.1")?;
    let mut child = spawn_windy(windy, &bind, &data_dir)?;
    let endpoint = format!("http://{bind}/mcp");

    let outcome = (|| -> Result<(String, usize, Vec<String>)> {
        // Allow serve-mcp to bind, then open exclusively through MCP.
        wait_for_mcp_ready(&endpoint, Duration::from_secs(45))?;

        let mut session = McpSession::connect(&endpoint)?;
        let mut tools_used = Vec::new();
        let mut name_hits: Vec<Value> = Vec::new();

        // 1) Open, then wait for the catalog job to yield the target id.
        let opened = session.call("target_open", &json!({ "path": pe }))?;
        tools_used.push("target_open".into());
        let job_id = opened
            .get("job_id")
            .and_then(Value::as_str)
            .context("target_open returned no job_id")?;
        let deadline = Instant::now() + Duration::from_secs(90);
        let project_id = loop {
            let status = session.call("server_status", &json!({ "job_id": job_id }))?;
            let job = status.get("job").context("server_status returned no job")?;
            match job.get("state").and_then(Value::as_str) {
                Some("complete") => {
                    break job
                        .get("target_id")
                        .and_then(Value::as_str)
                        .context("completed open job returned no target_id")?
                        .to_string();
                }
                Some("error") => bail!("target_open failed: {}", job["error"]),
                _ if Instant::now() >= deadline => bail!("target_open timed out"),
                _ => thread::sleep(Duration::from_millis(100)),
            }
        };

        // 2) First-minute triage ranking.
        let triage = session.call(
            "target_triage",
            &json!({ "target_id": project_id, "limit": 32 }),
        )?;
        tools_used.push("target_triage".into());
        collect_named_hits(&triage, &mut name_hits);

        // 3) BEL name/token search (product ranked search surface).
        let bel = session.call(
            "evidence_search",
            &json!({
                "target_id": project_id,
                "query": source,
                "mode": "substring",
                "limit": 32,
                "deadline_ms": 60_000u64,
            }),
        )?;
        tools_used.push("evidence_search".into());
        collect_bel_hits(&bel, source, &mut name_hits);

        // 4) Compatibility name list (same core as MCP functions_named).
        let named = session.call(
            "capability_execute",
            &json!({
                "capability_id": "functions_named",
                "arguments": { "target_id": project_id, "pattern": source }
            }),
        )?;
        tools_used.push("capability_execute:functions_named".into());
        collect_named_hits(&named, &mut name_hits);

        // 5) Evidence pack on the best current candidate (confirms the ladder step).
        let provisional = pick_name_match(&name_hits, source);
        if let Some(va) = provisional.as_ref() {
            let evidence = session.call(
                "function_inspect",
                &json!({
                    "target_id": project_id,
                    "va": va,
                    "max_items": 16,
                    "include_agent_text": false,
                }),
            )?;
            tools_used.push("function_inspect".into());
            // Fold evidence summary name back into the candidate pool.
            if let Some(summary) = evidence
                .pointer("/summary")
                .or_else(|| evidence.get("summary"))
            {
                let mut one = Vec::new();
                if let Some(obj) = summary.as_object() {
                    let n = obj
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let v = obj
                        .get("va")
                        .map(|x| match x {
                            Value::String(s) => s.clone(),
                            Value::Number(num) => format!("{:#x}", num.as_u64().unwrap_or(0)),
                            _ => String::new(),
                        })
                        .unwrap_or_default();
                    if !v.is_empty() {
                        one.push(json!({ "va": v, "name": n }));
                    }
                }
                collect_named_hits(&Value::Array(one), &mut name_hits);
            }
        }

        let answer = pick_name_match(&name_hits, source).unwrap_or_else(|| "refuse".into());
        let n = tools_used.len();
        Ok((answer, n, tools_used))
    })();

    // Best-effort teardown (Windows may keep the port until wait).
    let _ = child.kill();
    let _ = child.wait();
    outcome
}

/// Bind `host:0` to reserve an unused loopback port for a fresh serve-mcp.
fn free_local_bind(host: &str) -> Result<String> {
    let listener = std::net::TcpListener::bind(format!("{host}:0"))
        .with_context(|| format!("bind free port on {host}"))?;
    let port = listener
        .local_addr()
        .context("local_addr for free port")?
        .port();
    drop(listener);
    Ok(format!("{host}:{port}"))
}

/// Blocking MCP client that reuses one session for the multi-tool ladder.
struct McpSession {
    client: reqwest::blocking::Client,
    endpoint: String,
    session_id: Option<String>,
    next_id: u64,
}

impl McpSession {
    fn connect(endpoint: &str) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(90))
            .build()?;
        let mut s = Self {
            client,
            endpoint: endpoint.to_string(),
            session_id: None,
            next_id: 1,
        };
        let init = json!({
            "jsonrpc": "2.0",
            "id": s.alloc_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "agent-bench-local-a", "version": "0.1.0" }
            }
        });
        let resp = s
            .client
            .post(&s.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .json(&init)
            .send()
            .context("mcp initialize")?;
        s.session_id = resp
            .headers()
            .get("mcp-session-id")
            .or_else(|| resp.headers().get("Mcp-Session-Id"))
            .and_then(|v| v.to_str().ok())
            .map(|x| x.to_string());
        let _ = resp.text();

        // Required by streamable HTTP MCP after initialize.
        let mut note = s
            .client
            .post(&s.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }));
        if let Some(sid) = &s.session_id {
            note = note.header("mcp-session-id", sid);
        }
        let _ = note.send();
        Ok(s)
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn call(&mut self, name: &str, arguments: &Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": self.alloc_id(),
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        let mut req = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .json(&body);
        if let Some(sid) = &self.session_id {
            req = req.header("mcp-session-id", sid);
        }
        let resp = req
            .send()
            .with_context(|| format!("mcp tools/call {name}"))?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!("mcp HTTP {status} for {name}: {text}");
        }
        parse_mcp_tool_payload(&text)
            .with_context(|| format!("parse mcp payload for {name}: {text}"))
    }
}

fn wait_for_mcp_ready(endpoint: &str, budget: Duration) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let started = Instant::now();
    let mut last_err = String::from("not attempted");
    while started.elapsed() < budget {
        match client
            .post(endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "agent-bench-ready", "version": "0.1.0" }
                }
            }))
            .send()
        {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => last_err = format!("HTTP {}", r.status()),
            Err(e) => last_err = e.to_string(),
        }
        thread::sleep(Duration::from_millis(250));
    }
    bail!("MCP not ready at {endpoint} within {budget:?}: {last_err}")
}

/// Extract structured tool result from streamable-HTTP MCP (JSON or SSE).
fn parse_mcp_tool_payload(raw: &str) -> Result<Value> {
    let json_text = if raw.contains("data:") {
        raw.lines()
            .filter_map(|line| {
                let t = line.trim();
                t.strip_prefix("data:")
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && s.starts_with('{'))
            })
            .next_back()
            .unwrap_or(raw)
            .to_string()
    } else {
        raw.trim().to_string()
    };
    let envelope: Value = serde_json::from_str(&json_text).context("envelope json")?;
    if let Some(err) = envelope.get("error") {
        bail!("mcp error: {err}");
    }
    let result = envelope.get("result").cloned().unwrap_or(envelope);
    if result.get("isError").and_then(|v| v.as_bool()) == Some(true) {
        bail!("tool isError: {result}");
    }
    if let Some(sc) = result.get("structuredContent") {
        return Ok(sc.get("data").cloned().unwrap_or_else(|| sc.clone()));
    }
    // Fall back to first text content block (may itself be JSON).
    if let Some(arr) = result.get("content").and_then(|c| c.as_array()) {
        for block in arr {
            if block.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                    if let Ok(v) = serde_json::from_str::<Value>(t) {
                        return Ok(v);
                    }
                    return Ok(json!({ "text": t }));
                }
            }
        }
    }
    Ok(result)
}

/// Pull `{va,name}` pairs from triage / functions_named shaped payloads.
fn collect_named_hits(payload: &Value, out: &mut Vec<Value>) {
    let arrays = [
        payload.as_array(),
        payload.get("functions").and_then(|v| v.as_array()),
        payload.get("hits").and_then(|v| v.as_array()),
        payload.get("items").and_then(|v| v.as_array()),
        payload.get("ranked").and_then(|v| v.as_array()),
        payload.get("results").and_then(|v| v.as_array()),
    ];
    for arr in arrays.into_iter().flatten() {
        for item in arr {
            let name = item
                .get("name")
                .or_else(|| item.get("function_name"))
                .or_else(|| item.get("label"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let va = item
                .get("va")
                .or_else(|| item.get("entry_va"))
                .or_else(|| item.get("address"))
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => format!("{:#x}", n.as_u64().unwrap_or(0)),
                    _ => String::new(),
                })
                .unwrap_or_default();
            if !va.is_empty() {
                out.push(json!({ "va": va, "name": name }));
            }
        }
    }
}

/// BEL hits may nest entity metadata; keep only name-bearing function-like rows.
fn collect_bel_hits(payload: &Value, source: &str, out: &mut Vec<Value>) {
    let needle = source.to_ascii_lowercase();
    let hits = payload
        .get("hits")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default();
    for hit in hits {
        // Prefer direct fields, then entity sub-object.
        let entity = hit.get("entity").cloned().unwrap_or(hit.clone());
        let name = entity
            .get("name")
            .or_else(|| hit.get("name"))
            .or_else(|| hit.get("label"))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let va = entity
            .get("va")
            .or_else(|| hit.get("va"))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => format!("{:#x}", n.as_u64().unwrap_or(0)),
                _ => String::new(),
            })
            .unwrap_or_default();
        if va.is_empty() || name.is_empty() {
            continue;
        }
        // Only keep hits whose entity name actually relates to the source symbol.
        // Never treat empty-name hits as matches (`needle.contains("")` is true).
        let name_l = name.to_ascii_lowercase();
        if name_l == needle
            || name_l.ends_with(&format!("::{needle}"))
            || name_l.ends_with(&needle)
            || name_l.contains(&needle)
        {
            out.push(json!({ "va": va, "name": name }));
        }
    }
}

/// Prefer exact (case-insensitive) name, else unique substring hit, else refuse.
fn pick_name_match(matches: &[Value], source: &str) -> Option<String> {
    let src = source.to_ascii_lowercase();
    let mut exact = Vec::new();
    let mut fuzzy = Vec::new();
    for m in matches {
        let name = m
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let va = m.get("va").and_then(|v| v.as_str()).unwrap_or("");
        if va.is_empty() {
            continue;
        }
        if name == src || name.ends_with(&format!("::{src}")) || name.ends_with(&src) {
            exact.push(va.to_string());
        } else if name.contains(&src) {
            fuzzy.push(va.to_string());
        }
    }
    if exact.len() == 1 {
        return Some(exact[0].clone());
    }
    if exact.is_empty() && fuzzy.len() == 1 {
        return Some(fuzzy[0].clone());
    }
    if exact.len() > 1 {
        // Stable: pick lowest VA.
        exact.sort();
        return Some(exact[0].clone());
    }
    None
}

fn local_arm_b_python(root: &Path, pe: &Path, source: &str) -> Result<(String, usize)> {
    let scratch = root.join("target/agent-bench-scratch").join("local_b");
    fs::create_dir_all(&scratch)?;
    ensure_python_pe_tools(&scratch)?;
    let script = scratch.join("locate_symbol.py");
    // Throwaway baseline: exports + entry only (honest pefile without Windy analysis).
    let code = r#"
import json, sys
import pefile
pe_path, needle = sys.argv[1], sys.argv[2].lower()
pe = pefile.PE(pe_path)
base = pe.OPTIONAL_HEADER.ImageBase
hits = []
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        name = exp.name.decode(errors="replace")
        if needle in name.lower():
            hits.append(hex(base + exp.address))
entry = hex(base + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
# Confabulation risk: if no export hit, some agents return entry â€” we mirror weak baseline.
if len(hits) == 1:
    print(hits[0])
elif len(hits) > 1:
    print(sorted(hits)[0])
elif needle in ("main", "wmain", "winmain", "wwinmain"):
    print(entry)
else:
    print("refuse")
"#;
    fs::write(&script, code)?;
    let vpy = venv_python(&scratch.join(".venv"));
    let out = Command::new(&vpy)
        .arg(&script)
        .arg(pe)
        .arg(source)
        .current_dir(&scratch)
        .output()
        .with_context(|| format!("spawn {}", vpy.display()))?;
    if !out.status.success() {
        bail!(
            "pefile script failed: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let answer = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((answer, 2))
}

fn local_arm_c_dump(windy: &Path, pe: &Path, source: &str) -> Result<(String, usize)> {
    // Dump-style: same query, but only accept exact name match (no fuzzy).
    if !windy.exists() {
        bail!("windy binary missing: {}", windy.display());
    }
    let out = Command::new(windy)
        .arg("agent-query")
        .arg("--pe")
        .arg(pe)
        .arg("--functions-named")
        .arg(source)
        .env("RUST_LOG", "error")
        .output()
        .with_context(|| format!("spawn {}", windy.display()))?;
    if !out.status.success() {
        bail!("agent-query failed");
    }
    let v: Value = parse_json_stdout(&out.stdout)?;
    let matches = v
        .get("matches")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    let src = source.to_ascii_lowercase();
    for m in &matches {
        let name = m
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name == src {
            if let Some(va) = m.get("va").and_then(|v| v.as_str()) {
                return Ok((va.to_string(), 1));
            }
        }
    }
    Ok(("refuse".into(), 1))
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
        family: task.family.clone(),
        success,
        abstained: is_abstain(&answer),
        answer,
        gold: task.gold.clone(),
        // This path exercises scoring/reporting wiring only. It has no agent and
        // therefore no cost to report — emitting invented counts here is exactly
        // how a fixture gets mistaken for a measurement.
        tool_calls: None,
        tools_used: Vec::new(),
        tokens: None,
        wall_ms: Some(started.elapsed().as_millis()),
        mode: "offline_wiring".into(),
        error: None,
    }
}

/// Sidecar filename for a task/arm pair. Task ids contain `:` which is illegal
/// in Windows filenames, so they are flattened.
fn sidecar_name(arm: Arm, task_id: &str) -> String {
    format!(
        "{}__{}.json",
        arm_name(arm),
        task_id.replace([':', '/'], "_")
    )
}

/// Read one externally-produced task result. A missing or malformed sidecar is
/// recorded as an error with no telemetry — never as a scored zero.
fn run_sidecar_task(dir: &Path, arm: Arm, task: &Task) -> TaskResult {
    let path = dir.join(sidecar_name(arm, &task.id));
    let base = |error: Option<String>| TaskResult {
        task_id: task.id.clone(),
        arm: arm_name(arm).into(),
        family: task.family.clone(),
        success: false,
        abstained: false,
        answer: String::new(),
        gold: task.gold.clone(),
        tool_calls: None,
        tools_used: Vec::new(),
        tokens: None,
        wall_ms: None,
        mode: "sidecar".into(),
        error,
    };

    let raw = match fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => return base(Some(format!("sidecar missing {}: {e}", path.display()))),
    };
    let v: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => return base(Some(format!("sidecar parse {}: {e}", path.display()))),
    };
    let Some(answer) = v.get("answer").and_then(|a| a.as_str()) else {
        return base(Some(format!("sidecar {} has no `answer`", path.display())));
    };

    let tools_used: Vec<String> = v
        .get("tools_used")
        .and_then(|t| t.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // An agent that reported no tool list is unverified, not zero-tool.
    let tool_calls = v
        .get("tool_calls")
        .and_then(|t| t.as_u64())
        .map(|n| n as usize)
        .or(if tools_used.is_empty() {
            None
        } else {
            Some(tools_used.len())
        });

    TaskResult {
        task_id: task.id.clone(),
        arm: arm_name(arm).into(),
        family: task.family.clone(),
        success: score_answer(task, answer),
        abstained: is_abstain(answer),
        answer: answer.to_string(),
        gold: task.gold.clone(),
        tool_calls,
        tools_used,
        tokens: None,
        wall_ms: v.get("wall_ms").and_then(|w| w.as_u64()).map(u128::from),
        mode: "sidecar".into(),
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
            "server_status",
            "target_open",
            "target_triage",
            "evidence_search",
            "function_inspect",
            "data_read",
            "claim_verify",
            "artifact_read",
            "capability_search",
            "capability_execute",
        ],
        Arm::B => &[], // handled by python_scratch_tool_defs
        Arm::C => &[
            "server_status",
            "target_open",
            "function_inspect",
            "data_read",
            "artifact_read",
            "capability_search",
            "capability_execute",
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
                Use this to write/run throwaway scripts. Do not invent VAs â€” read them from the binary.",
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
                family: task.family.clone(),
                success: false,
                abstained: false,
                answer: String::new(),
                gold: task.gold.clone(),
                tool_calls: None,
                tools_used: Vec::new(),
                tokens: None,
                wall_ms: Some(started.elapsed().as_millis()),
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
        r#"# Scratch helper (agent-bench arm B). Throwaway â€” not maintained product code.
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
         Seed script: pe_inspect.py â€” you may edit or replace it.\n\
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
                family: task.family.clone(),
                success,
                abstained: is_abstain(&answer),
                answer,
                gold: task.gold.clone(),
                tool_calls: Some(tools),
                tools_used: Vec::new(),
                tokens: Some(tokens),
                wall_ms: Some(started.elapsed().as_millis()),
                mode: "live".into(),
                error: None,
            }
        }
        Err(e) => fail_result(task, "B", started, e.to_string()),
    }
}

/// Create a scratch venv and install pefile + capstone when missing.
fn ensure_python_pe_tools(scratch: &Path) -> Result<()> {
    let venv = scratch.join(".venv");
    let marker = scratch.join(".venv_ready");
    let vpy_existing = venv_python(&venv);
    if vpy_existing.is_file() {
        // Reuse existing venv; ensure deps present.
        let check = Command::new(&vpy_existing)
            .args(["-c", "import pefile, capstone"])
            .status();
        if matches!(check, Ok(s) if s.success()) {
            let _ = fs::write(&marker, b"ok");
            return Ok(());
        }
    }
    if venv.exists() {
        let _ = fs::remove_dir_all(&venv);
    }

    // Each attempt is (program, prefix_args before -m venv).
    let attempts: Vec<(String, Vec<&str>)> = {
        let mut v = Vec::new();
        if let Ok(p) = std::env::var("PYTHON") {
            if !p.is_empty() {
                v.push((p, vec![]));
            }
        }
        // Absolute Windows installs (PATH is often empty/minimal under cargo).
        let mut abs = Vec::new();
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            for ver in [
                "Python314",
                "Python313",
                "Python312",
                "Python311",
                "Python310",
            ] {
                abs.push(
                    local_app
                        .join("Programs")
                        .join("Python")
                        .join(ver)
                        .join("python.exe"),
                );
            }
        }
        if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            abs.push(home.join(r"AppData\Local\Programs\Python\Python312\python.exe"));
            abs.push(home.join(r"AppData\Local\Programs\Python\Python311\python.exe"));
        }
        abs.push(PathBuf::from(r"C:\Python312\python.exe"));
        for c in abs {
            if c.is_file() {
                v.push((c.display().to_string(), vec![]));
            }
        }
        if cfg!(windows) {
            v.push(("py".into(), vec!["-3"]));
            v.push(("python".into(), vec![]));
            v.push(("python3".into(), vec![]));
        } else {
            v.push(("python3".into(), vec![]));
            v.push(("python".into(), vec![]));
        }
        v
    };

    let mut last_err = String::from("no python launcher tried");
    let mut created = false;
    for (prog, prefix) in &attempts {
        let mut cmd = Command::new(prog);
        for a in prefix {
            cmd.arg(a);
        }
        let status = cmd
            .args(["-m", "venv"])
            .arg(&venv)
            .current_dir(scratch)
            .status();
        match status {
            Ok(s) if s.success() => {
                created = true;
                break;
            }
            Ok(s) => last_err = format!("{prog} {:?} -m venv -> {s}", prefix),
            Err(e) => last_err = format!("{prog} {:?} -m venv: {e}", prefix),
        }
    }
    if !created {
        bail!("python venv creation failed: {last_err}");
    }

    let vpy = venv_python(&venv);
    let status = Command::new(&vpy)
        .args(["-m", "pip", "install", "--quiet", "pefile", "capstone"])
        .current_dir(scratch)
        .status()
        .with_context(|| format!("spawn {} -m pip", vpy.display()))?;
    if !status.success() {
        bail!("pip install pefile capstone failed with {status}");
    }

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

fn venv_python(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    }
}

/// Extract JSON object from stdout that may include log noise.
fn parse_json_stdout(stdout: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(stdout);
    if let Ok(v) = serde_json::from_str::<Value>(text.trim()) {
        return Ok(v);
    }
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            if end > start {
                return serde_json::from_str(&text[start..=end])
                    .context("parse JSON object from stdout");
            }
        }
    }
    bail!(
        "no JSON object in stdout: {}",
        text.chars().take(200).collect::<String>()
    );
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
    let mut child = match spawn_windy(windy, &bind, &data_dir) {
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
         Open the absolute binary path with target_open and poll server_status for target_id.\n\
         Answer with a single hex VA or the word refuse.\n\
         Prefer target_triage / evidence_search / function_inspect / data_read over raw bytes.",
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
                family: task.family.clone(),
                success,
                abstained: is_abstain(&answer),
                answer,
                gold: task.gold.clone(),
                tool_calls: Some(tool_calls),
                tools_used: Vec::new(),
                tokens: Some(tokens),
                wall_ms: Some(started.elapsed().as_millis()),
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
        family: task.family.clone(),
        success: false,
        abstained: false,
        answer: String::new(),
        gold: task.gold.clone(),
        tool_calls: None,
        tools_used: Vec::new(),
        tokens: None,
        wall_ms: Some(started.elapsed().as_millis()),
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

fn spawn_windy(windy: &Path, bind: &str, data_dir: &Path) -> Result<Child> {
    Command::new(windy)
        .arg("serve-mcp")
        .arg("--bind")
        .arg(bind)
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
        // Do NOT set temperature/top_p/top_k â€” rejected on some models.
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
    out.push_str("\nâ€¦[truncated]");
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
            families: BTreeMap::new(),
            instrumented_tasks: 0,
            total_tool_calls: None,
            tokens: None,
            wall_ms: None,
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
        let fam = e.families.entry(r.family.clone()).or_default();
        fam.n += 1;
        if r.success {
            fam.successes += 1;
        }
        // "Instrumented" means we captured what the agent actually *did* — a
        // wall-clock timer the harness kept for itself proves nothing about
        // whether any tool was reached.
        if r.tool_calls.is_some() {
            e.instrumented_tasks += 1;
        }
        if let Some(tc) = r.tool_calls {
            *e.total_tool_calls.get_or_insert(0) += tc;
        }
        if let Some(tok) = &r.tokens {
            e.tokens
                .get_or_insert_with(TokenUsage::default)
                .add_assign(tok);
        }
        if let Some(ms) = r.wall_ms {
            let slot = e.wall_ms.get_or_insert(0);
            *slot = slot.saturating_add(ms);
        }
    }

    // Null policies over the same task set.
    let mut always_refuse: BTreeMap<String, FamilyStat> = BTreeMap::new();
    let mut always_default_va: BTreeMap<String, FamilyStat> = BTreeMap::new();
    for t in tasks {
        let r = always_refuse.entry(t.family.clone()).or_default();
        r.n += 1;
        if score_answer(t, "refuse") {
            r.successes += 1;
        }
        let g = always_default_va.entry(t.family.clone()).or_default();
        g.n += 1;
        if score_answer(t, DEFAULT_VA_GUESS) {
            g.successes += 1;
        }
    }
    let baselines = Baselines {
        always_refuse,
        always_default_va,
        note: format!(
            "Constant policies on this task set. `always_refuse` answers \"refuse\" \
             everywhere; `always_default_va` answers {DEFAULT_VA_GUESS} (the usual \
             first-function VA of an /Od MSVC x64 image). An arm that does not beat \
             both per family has shown no capability."
        ),
    };

    let corpus_sha = {
        let mut hasher = Sha256::new();
        for t in tasks {
            hasher.update(t.id.as_bytes());
            hasher.update(t.pe_path.to_string_lossy().as_bytes());
        }
        format!("{:x}", hasher.finalize())
    };

    let synthetic = !cli.live && !cli.local;
    Report {
        harness: if cli.local {
            "agent-bench-v1-local-tools".into()
        } else if synthetic {
            "agent-bench-v1-wiring-check".into()
        } else {
            "agent-bench-v1".into()
        },
        synthetic,
        commit: git_head(root),
        model: cli.live.then(|| cli.model.clone()),
        live: cli.live,
        arms: by_arm.into_values().collect(),
        baselines,
        results,
        corpus: json!({
            "task_count": tasks.len(),
            "profiles": cli.profile,
            "families": cli.family,
            "task_set_sha256": corpus_sha,
            "mode": if cli.local {
                "local_tools"
            } else if cli.live {
                "live_anthropic"
            } else {
                "offline_wiring"
            },
            "note": if cli.local {
                "Free local tools: arm A Windy MCP ladder (triage/search_bel/functions_named/evidence); arm B python+pefile. No model tokens."
            } else if synthetic {
                "SYNTHETIC offline wiring: arm A returns gold by construction; B/C wrong by construction. Not a product measurement."
            } else {
                "Live Anthropic agent loop results."
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
             > Do not cite these numbers as product evidence. Run `--local` (free) or `--live` (paid).\n\n",
        );
    } else if report.harness.contains("local") {
        md.push_str("# Agent loop v1 (local tools — free, no Anthropic)\n\n");
        md.push_str(
            "> Arm A: Windy MCP evidence ladder (`list_projects` → `get_triage` → `search_bel` → `functions_named` → `get_function_evidence`). Arm B: python + pefile. Zero model tokens.\n\n",
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
    // Per-family accuracy is the result. A single blended number is not reported
    // on purpose: on a 50/50 split "always refuse" scores 50% and locates nothing.
    let families: Vec<String> = {
        let mut f: Vec<String> = report
            .arms
            .iter()
            .flat_map(|a| a.families.keys().cloned())
            .collect();
        f.sort();
        f.dedup();
        f
    };

    md.push_str("## Accuracy by family\n\n");
    md.push_str("| arm |");
    for fam in &families {
        md.push_str(&format!(" {fam} |"));
    }
    md.push_str("\n|---|");
    for _ in &families {
        md.push_str("---:|");
    }
    md.push('\n');

    let row = |label: &str, get: &dyn Fn(&str) -> Option<FamilyStat>| -> String {
        let mut s = format!("| {label} |");
        for fam in &families {
            match get(fam) {
                Some(st) => s.push_str(&format!(" {}/{} |", st.successes, st.n)),
                None => s.push_str(" - |"),
            }
        }
        s.push('\n');
        s
    };

    for a in &report.arms {
        md.push_str(&row(&a.arm, &|fam| a.families.get(fam).cloned()));
    }
    md.push_str(&row("_always_refuse_", &|fam| {
        report.baselines.always_refuse.get(fam).cloned()
    }));
    md.push_str(&row("_always_default_va_", &|fam| {
        report.baselines.always_default_va.get(fam).cloned()
    }));
    md.push_str(&format!("\n{}\n\n", report.baselines.note));

    md.push_str("## Cost and instrumentation\n\n");
    md.push_str(
        "| arm | tasks | instrumented | tool_calls | prompt_tokens (all fields) | wall_ms |\n",
    );
    md.push_str("|---|---:|---:|---:|---:|---:|\n");
    for a in &report.arms {
        let fmt_opt = |v: Option<String>| v.unwrap_or_else(|| "not measured".into());
        md.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} | {} |\n",
            a.arm,
            a.tasks,
            a.instrumented_tasks,
            a.tasks,
            fmt_opt(a.total_tool_calls.map(|v| v.to_string())),
            fmt_opt(a.tokens.as_ref().map(|t| t.total_prompt().to_string())),
            fmt_opt(a.wall_ms.map(|v| v.to_string())),
        ));
    }
    md.push_str(
        "\nPrompt tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.\n\
         `not measured` means the runner captured no telemetry — it is not zero.\n",
    );
    for a in &report.arms {
        if a.instrumented_tasks < a.tasks {
            md.push_str(&format!(
                "\n> Arm {}: only {}/{} tasks carried telemetry. Tool-use claims for this arm are unverified.\n",
                a.arm, a.instrumented_tasks, a.tasks
            ));
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(family: &str, gold: &str) -> Task {
        Task {
            id: format!("{family}:p:P0:f"),
            family: family.into(),
            program_id: "p".into(),
            profile: "P0".into(),
            pe_path: PathBuf::from("x.exe"),
            question: String::new(),
            gold: gold.into(),
            source_name: None,
        }
    }

    /// The failure that made the first Grok report unreadable: an arm with no
    /// telemetry must surface as "not measured", never as a zero that reads
    /// like a measured value.
    #[test]
    fn missing_telemetry_is_never_zero() {
        let dir = std::env::temp_dir().join("agent-bench-sidecar-test");
        let _ = fs::create_dir_all(&dir);
        let task = t("locate", "0x140001000");
        // No sidecar written for this task.
        let r = run_sidecar_task(&dir, Arm::A, &task);
        assert!(r.tool_calls.is_none(), "absent telemetry must stay None");
        assert!(r.tokens.is_none());
        assert!(
            r.error.is_some(),
            "a missing sidecar is an error, not a 0/1"
        );
        assert!(!r.success);
    }

    /// A sidecar that reports an answer but no tool list is unverified, not
    /// zero-tool — we cannot tell whether it used the substrate.
    #[test]
    fn sidecar_without_tool_list_is_unverified() {
        let dir = std::env::temp_dir().join("agent-bench-sidecar-test2");
        let _ = fs::create_dir_all(&dir);
        let task = t("locate", "0x140001000");
        fs::write(
            dir.join(sidecar_name(Arm::A, &task.id)),
            r#"{"answer":"0x140001000"}"#,
        )
        .unwrap();
        let r = run_sidecar_task(&dir, Arm::A, &task);
        assert!(r.success, "answer still scores");
        assert!(r.tool_calls.is_none(), "no tool list => unverified, not 0");
    }

    /// Windy lifts function names from an adjacent MSVC `.map`
    /// (`src/project/mod.rs` -> `apply_adjacent_msvc_map_names`), which is the
    /// same file this harness scores against. Staged PEs must therefore be
    /// alone in their directory, or arm A reads the answer key through its
    /// tools and a 6/6 means nothing.
    #[test]
    fn staged_pe_has_no_sibling_answer_key() {
        let root =
            std::env::temp_dir().join(format!("agent-bench-stage-test-{}", uuid::Uuid::new_v4()));
        let src_dir = root.join("source");
        fs::create_dir_all(&src_dir).expect("source dir");
        let pe = src_dir.join("fixture.exe");
        fs::write(&pe, b"tracked PE bytes").expect("PE");
        for extension in ["map", "pdb", "obj", "json"] {
            fs::write(
                src_dir.join(format!("fixture.{extension}")),
                b"private answer key",
            )
            .expect("sibling answer key");
        }

        let stage = root.join("stage");
        let staged = stage_pe(&pe, &stage, "fixture", "P0").expect("stage");
        assert!(staged.exists());
        let dir = staged.parent().expect("staged parent");
        let mut entries = 0;
        for e in fs::read_dir(dir).expect("read stage dir") {
            entries += 1;
            let p = e.expect("entry").path();
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            assert!(
                !matches!(ext, "map" | "pdb" | "obj" | "json"),
                "staged dir leaks {}",
                p.display()
            );
        }
        assert_eq!(entries, 1, "only the staged PE is visible to either arm");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn manifest_tasks_work_without_linker_maps_and_balance_refusals() {
        let root = std::env::temp_dir().join(format!(
            "agent-bench-manifest-test-{}",
            uuid::Uuid::new_v4()
        ));
        let grand = root.join("eval/grand");
        for profile in ["P0", "P1"] {
            let bin_dir = grand.join("bin").join(profile);
            fs::create_dir_all(&bin_dir).expect("bin dir");
            for program in ["alpha", "beta", "gamma"] {
                fs::write(bin_dir.join(format!("{program}.exe")), b"PE").expect("PE");
            }
        }

        let function = |name: &str, status: &str, entry: Option<&str>| {
            json!({
                "source_name": name,
                "status": status,
                "entry_va": entry
            })
        };
        let binary = |program: &str, profile: &str, functions: Vec<Value>| {
            json!({
                "program_id": program,
                "profile": profile,
                "pe_path": format!("eval/grand/bin/{profile}/{program}.exe"),
                "function_map": functions
            })
        };
        let manifest = json!({
            "binaries": [
                binary("alpha", "P0", vec![
                    function("main", "present", Some("0x140001000")),
                    function("alpha_helper", "present", Some("0x140001040"))
                ]),
                binary("alpha", "P1", vec![
                    function("main", "present", Some("0x140001000")),
                    function("alpha_helper", "inlined_only", None)
                ]),
                binary("beta", "P0", vec![
                    function("main", "present", Some("0x140001000")),
                    function("beta_helper", "present", Some("0x140001040"))
                ]),
                binary("beta", "P1", vec![
                    function("main", "present", Some("0x140001000")),
                    function("beta_helper", "present", Some("0x140001040"))
                ]),
                binary("gamma", "P0", vec![
                    function("main", "present", Some("0x140001000")),
                    function("gamma_helper", "present", Some("0x140001040"))
                ]),
                binary("gamma", "P1", vec![
                    function("main", "present", Some("0x140001000")),
                    function("gamma_helper", "present", Some("0x140001040"))
                ])
            ]
        });
        fs::write(
            grand.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest json"),
        )
        .expect("manifest");

        let tasks = load_tasks(
            &root,
            &["P0".into(), "P1".into()],
            &["locate".into(), "abstain".into()],
            12,
            true,
        )
        .expect("load clean-checkout tasks");
        assert_eq!(tasks.len(), 12);
        assert_eq!(
            tasks.iter().filter(|task| task.family == "locate").count(),
            6
        );
        assert_eq!(
            tasks.iter().filter(|task| task.family == "abstain").count(),
            6
        );
        assert!(
            tasks
                .iter()
                .any(|task| task.id == "abstain:alpha:P1:alpha_helper"),
            "manifest inlining must become a refusal task"
        );
        for task in &tasks {
            let entries = fs::read_dir(task.pe_path.parent().expect("stage parent"))
                .expect("stage dir")
                .count();
            assert_eq!(entries, 1, "staged task leaked an answer-key sibling");
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn committed_balanced_fixture_matches_manifest_loader() {
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let tasks = load_tasks(
            &repo,
            &["P0".into(), "P1".into()],
            &["locate".into(), "abstain".into()],
            12,
            true,
        )
        .expect("manifest task set");
        let fixture_path = repo.join("eval/agent-bench/fixtures/p0p1_tasks_12.json");
        let fixture: Value =
            serde_json::from_slice(&fs::read(&fixture_path).expect("committed task fixture"))
                .expect("fixture JSON");
        let rows = fixture["tasks"].as_array().expect("fixture tasks");
        assert_eq!(rows.len(), tasks.len());
        for (row, task) in rows.iter().zip(tasks.iter()) {
            assert_eq!(row["id"].as_str(), Some(task.id.as_str()));
            assert_eq!(row["family"].as_str(), Some(task.family.as_str()));
            assert_eq!(row["gold"].as_str(), Some(task.gold.as_str()));
            assert_eq!(row["program"].as_str(), Some(task.program_id.as_str()));
            assert_eq!(row["profile"].as_str(), Some(task.profile.as_str()));
            assert_eq!(
                row["source"].as_str(),
                task.source_name.as_deref(),
                "source mismatch for {}",
                task.id
            );
            let expected_pe = format!("eval/grand/bin/{}/{}.exe", task.profile, task.program_id);
            assert_eq!(
                row["pe"].as_str(),
                Some(expected_pe.as_str()),
                "fixture PE path mismatch for {}",
                task.id
            );
        }
    }

    /// Guards the conclusion the first Grok run got wrong: on a 50/50 split the
    /// constant refuser scores 50% overall while locating nothing, so the
    /// baselines must be reported per family.
    #[test]
    fn always_refuse_ties_half_on_balanced_split() {
        let tasks = [
            t("locate", "0x140001000"),
            t("locate", "0x140002000"),
            t("abstain", "refuse"),
            t("abstain", "refuse"),
        ];
        let refused: usize = tasks.iter().filter(|x| score_answer(x, "refuse")).count();
        assert_eq!(refused, 2, "always-refuse gets exactly the abstain half");
        let located: usize = tasks
            .iter()
            .filter(|x| x.family == "locate" && score_answer(x, "refuse"))
            .count();
        assert_eq!(located, 0, "and locates nothing");
    }

    /// Exact name must beat a longer substring hit (the product failure mode
    /// where `mainCRTStartup` steals `main` under unranked substring search).
    #[test]
    fn pick_name_match_prefers_exact_over_substring() {
        let matches = vec![
            json!({"va": "0x14000132c", "name": "mainCRTStartup"}),
            json!({"va": "0x140001080", "name": "main"}),
            json!({"va": "0x14000dead", "name": "domain"}),
        ];
        let got = pick_name_match(&matches, "main").expect("exact hit");
        assert_eq!(got.to_ascii_lowercase(), "0x140001080");
    }

    #[test]
    fn pick_name_match_refuses_ambiguous_fuzzy() {
        // Contains-only (not exact, not ends_with) — two hits must refuse.
        let matches = vec![
            json!({"va": "0x140001000", "name": "bar_foo"}),
            json!({"va": "0x140002000", "name": "xbarx"}),
        ];
        assert!(pick_name_match(&matches, "bar").is_none());
    }

    #[test]
    fn collect_named_hits_from_functions_array() {
        let payload = json!({
            "functions": [
                {"va": "0x140001000", "name": "main"},
                {"va": 5368713472u64, "name": "other"}
            ]
        });
        let mut out = Vec::new();
        collect_named_hits(&payload, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["name"], "main");
    }

    #[test]
    fn parse_mcp_tool_payload_sse_structured() {
        let raw = "data: \nid: 0/0\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"server_status: complete\"}],\"structuredContent\":{\"v\":\"2\",\"data\":[{\"project_id\":\"abc\",\"path\":\"x.exe\"}]},\"isError\":false}}\nid: 1/0\n";
        let v = parse_mcp_tool_payload(raw).expect("parse");
        assert_eq!(v[0]["project_id"], "abc");
    }

    #[test]
    fn local_arm_a_source_mentions_mcp_ladder_not_single_query() {
        // Structural guard: local Arm A must call the MCP v2 ladder.
        let src = include_str!("main.rs");
        assert!(
            src.contains("local_arm_a_windy_ladder"),
            "local Arm A entry point missing"
        );
        assert!(
            src.contains("target_triage")
                && src.contains("evidence_search")
                && src.contains("function_inspect"),
            "MCP ladder tools missing from harness source"
        );
        // The Arm A local policy body must not be a single agent-query shell-out.
        // Arm C may still use agent-query; ensure ladder is the A path.
        let a_fn = src
            .split("fn local_arm_a_windy_ladder")
            .nth(1)
            .and_then(|s| s.split("fn local_arm_b_python").next())
            .expect("A ladder fn body");
        assert!(
            !a_fn.contains("agent-query"),
            "Arm A ladder must not shell out to agent-query"
        );
        assert!(a_fn.contains("McpSession") || a_fn.contains("session.call"));
    }

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
