use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// The rest of the crate lives in src/lib.rs (the `windy` library) so that
// evaluation binaries can link the analysis core directly. These imports
// keep the `crate::<module>` paths used throughout the bin-side code resolving
// unchanged.
use windy::{analysis, build_info, loader, mcp, project, project_manager};

#[derive(Parser)]
#[command(name = build_info::PRODUCT_ID)]
#[command(about = "Agent-first static analysis MCP server")]
#[command(version = build_info::VERSION)]
struct Cli {
    /// Windy state directory (overrides WINDY_HOME and %USERPROFILE%\.windy).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run headless MCP HTTP server for external agents (OpenCode, Claude, Cursor, …).
    #[command(visible_alias = "agent")]
    ServeMcp {
        /// Bind address (default 127.0.0.1:8765).
        #[arg(long, default_value = "127.0.0.1:8765")]
        bind: String,
        /// Optional endpoint text file (defaults to <data-dir>/agent-endpoint.txt).
        #[arg(long, value_name = "FILE")]
        endpoint_file: Option<PathBuf>,
    },
    /// Check the standalone runtime, storage, bundled databases, and MCP endpoint.
    Doctor {
        /// Optional PE to parse as part of diagnostics.
        #[arg(long)]
        open: Option<PathBuf>,
        /// Optional running MCP URL to probe.
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Reproducibility and decompiler quality benchmarks.
    Bench {
        #[command(subcommand)]
        command: BenchCommands,
    },
    /// Inspect a user-mode Windows minidump (.dmp) without full project open.
    DumpInfo {
        /// Path to an MDMP crash dump.
        path: PathBuf,
        /// Print full module list (default: summary + primary only).
        #[arg(long)]
        modules: bool,
        /// Print thread list.
        #[arg(long)]
        threads: bool,
        /// Compute full content SHA-256 (slow on multi-GB dumps).
        #[arg(long)]
        hash: bool,
        /// Emit JSON instead of human text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum BenchCommands {
    /// Build the compact partitioned deep instruction index.
    CompactIndex {
        /// Path to PE.
        #[arg(long)]
        pe: PathBuf,
    },
    /// Stream compact function sketches without retaining full instructions.
    Sketch {
        /// Path to PE.
        #[arg(long)]
        pe: PathBuf,
        /// Semantic queries to rank (repeat --query).
        #[arg(long)]
        query: Vec<String>,
        /// Ranked functions per query.
        #[arg(long, default_value_t = 3)]
        limit: usize,
    },
    /// Build and benchmark the Binary Evidence Lattice with oracle checksums.
    Bel {
        /// Path to PE.
        #[arg(long)]
        pe: PathBuf,
        /// Warm iterations per representative query.
        #[arg(long, default_value_t = 20)]
        iterations: usize,
        /// Optional literal substring queries (repeat --query). Defaults are
        /// derived deterministically from the PE.
        #[arg(long)]
        query: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let data_dir = if let Some(path) = cli.data_dir {
        crate::project::persistence::set_process_windy_home(path.clone())?;
        path
    } else {
        crate::project::persistence::windy_home_dir()
    };

    match cli.command {
        Some(Commands::ServeMcp {
            bind,
            endpoint_file,
        }) => run_serve_mcp(bind, endpoint_file, data_dir),
        Some(Commands::Doctor { open, endpoint }) => run_doctor(data_dir, open, endpoint),
        Some(Commands::Bench { command }) => match command {
            BenchCommands::CompactIndex { pe } => run_compact_index_bench(pe),
            BenchCommands::Sketch { pe, query, limit } => run_sketch_bench(pe, query, limit),
            BenchCommands::Bel {
                pe,
                iterations,
                query,
            } => run_bel_bench(pe, iterations, query),
        },
        Some(Commands::DumpInfo {
            path,
            modules,
            threads,
            hash,
            json,
        }) => run_dump_info(path, modules, threads, hash, json),
        None => run_serve_mcp("127.0.0.1:8765".to_string(), None, data_dir),
    }
}

fn run_compact_index_bench(pe: PathBuf) -> anyhow::Result<()> {
    let index = analysis::compact_index::build_from_path(&pe)
        .with_context(|| format!("build compact instruction index for {}", pe.display()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "path":pe,
            "elapsed_ms":index.elapsed_ms,
            "instructions":index.instructions,
            "sections":index.sections.len(),
            "retained_bytes_estimate":index.instructions * std::mem::size_of::<analysis::compact_index::InstrMeta>(),
            "record_bytes":std::mem::size_of::<analysis::compact_index::InstrMeta>(),
        }))?
    );
    Ok(())
}

fn run_sketch_bench(pe: PathBuf, queries: Vec<String>, limit: usize) -> anyhow::Result<()> {
    let sketch = analysis::sketch::build_from_path(&pe)
        .with_context(|| format!("build compact sketches for {}", pe.display()))?;
    let queries = if queries.is_empty() {
        vec![
            "NUL terminated byte string length".to_string(),
            "linked list next pointer accumulator".to_string(),
            "arithmetic dispatcher add subtract multiply".to_string(),
        ]
    } else {
        queries
    };
    let ranked: Vec<_> = queries
        .iter()
        .map(|query| {
            serde_json::json!({
                "query":query,
                "matches":analysis::sketch::rank_sketches(&sketch.sketches, query, limit),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "path":pe,
            "elapsed_ms":sketch.elapsed_ms,
            "decoded_instructions":sketch.decoded_instructions,
            "functions":sketch.sketches.len(),
            "retained_bytes_estimate":sketch.sketches.len() * std::mem::size_of::<analysis::sketch::FunctionSketch>(),
            "queries":ranked,
        }))?
    );
    Ok(())
}

fn run_dump_info(
    path: PathBuf,
    show_modules: bool,
    show_threads: bool,
    do_hash: bool,
    as_json: bool,
) -> anyhow::Result<()> {
    use crate::loader::dump::LoadedDump;

    let mut dump =
        LoadedDump::open(&path).with_context(|| format!("open dump {}", path.display()))?;
    if do_hash {
        dump.ensure_content_hash()?;
    }

    if as_json {
        let mut value = dump.summary_json();
        if show_modules {
            value["modules"] = serde_json::json!(
                dump.modules
                    .iter()
                    .map(|m| serde_json::json!({
                        "index": m.index,
                        "name": m.name,
                        "base": format!("{:#x}", m.base),
                        "size": m.size,
                        "presence": m.presence,
                        "has_pe_headers": m.has_pe_headers,
                        "is_main": m.is_main,
                        "is_exception_module": m.is_exception_module,
                        "path": m.path,
                    }))
                    .collect::<Vec<_>>()
            );
        }
        if show_threads {
            value["threads"] = serde_json::json!(
                dump.threads
                    .iter()
                    .map(|t| serde_json::json!({
                        "thread_id": t.thread_id,
                        "ip": t.instruction_pointer.map(|v| format!("{v:#x}")),
                        "sp": t.stack_pointer.map(|v| format!("{v:#x}")),
                        "fp": t.frame_pointer.map(|v| format!("{v:#x}")),
                        "teb": format!("{:#x}", t.teb),
                        "is_exception_thread": t.is_exception_thread,
                    }))
                    .collect::<Vec<_>>()
            );
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }

    println!("Dump: {}", dump.path.display());
    println!(
        "  size: {:.2} GiB  key: {}",
        dump.identity.file_len as f64 / (1024.0 * 1024.0 * 1024.0),
        dump.identity
            .content_hash
            .as_deref()
            .unwrap_or(&dump.identity.session_key)
    );
    println!(
        "  system: {} {}  cpu: {} ({}-bit)  cpus: {}",
        dump.system.os,
        dump.system.os_version,
        dump.system.cpu,
        dump.system.bitness,
        dump.system.cpu_count
    );
    println!(
        "  memory: {} regions, {:.2} GiB mapped ({})",
        dump.memory_map.region_count(),
        dump.memory_map.total_bytes() as f64 / (1024.0 * 1024.0 * 1024.0),
        dump.memory_map.source_label()
    );
    println!(
        "  modules: {}  threads: {}",
        dump.modules.len(),
        dump.threads.len()
    );
    if let Some(exc) = &dump.exception {
        println!(
            "  exception: thread={} code={:#x} addr={:#x} reason={}",
            exc.thread_id, exc.exception_code, exc.exception_address, exc.crash_reason
        );
        if let Some(ip) = exc.crashing_instruction_address {
            println!("    crashing_ip: {ip:#x}");
        }
    } else {
        println!("  exception: (none)");
    }
    if let Some(m) = dump.primary_module() {
        println!(
            "  primary: {} @ {:#x} size={:#x} presence={:.0}% pe_headers={}",
            m.name,
            m.base,
            m.size,
            m.presence * 100.0,
            m.has_pe_headers
        );
    }
    for w in dump.open_warnings() {
        println!("  warning: {w}");
    }
    if show_modules {
        println!("modules:");
        for m in &dump.modules {
            println!(
                "  [{:>3}] {:#014x} {:>10}  {:>5.1}%  {}{}",
                m.index,
                m.base,
                m.size,
                m.presence * 100.0,
                m.name,
                if m.is_exception_module {
                    "  [exception]"
                } else if m.is_main {
                    "  [main]"
                } else {
                    ""
                }
            );
        }
    }
    if show_threads {
        println!("threads:");
        for t in &dump.threads {
            println!(
                "  tid={:<6} ip={} sp={} teb={:#x}{}",
                t.thread_id,
                t.instruction_pointer
                    .map(|v| format!("{v:#x}"))
                    .unwrap_or_else(|| "-".into()),
                t.stack_pointer
                    .map(|v| format!("{v:#x}"))
                    .unwrap_or_else(|| "-".into()),
                t.teb,
                if t.is_exception_thread {
                    "  [exception]"
                } else {
                    ""
                }
            );
        }
    }
    Ok(())
}

fn run_bel_bench(pe: PathBuf, iterations: usize, queries: Vec<String>) -> anyhow::Result<()> {
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    let opened_at = Instant::now();
    let project = crate::project::Project::open(&pe)
        .with_context(|| format!("open BEL benchmark PE {}", pe.display()))?;
    let open_ms = opened_at.elapsed().as_millis();
    let cancel = AtomicBool::new(false);
    let progress = |status: crate::analysis::bel::BelBuildProgress| {
        if status.completed == 0 || status.completed == status.total {
            eprintln!(
                "BEL {}: {}/{}",
                status.stage, status.completed, status.total
            );
        }
    };
    let control = crate::analysis::bel::BelBuildControl {
        cancel: &cancel,
        deadline: None,
        progress: Some(&progress),
    };
    let built_at = Instant::now();
    let index = crate::analysis::bel::BelIndex::build(
        &project,
        crate::analysis::bel::BelConfig::default(),
        &control,
    )?;
    let build_ms = built_at.elapsed().as_millis();
    let overlay = index.overlay(&project);

    let mut cases: Vec<(String, crate::analysis::bel::Query, bool)> = queries
        .into_iter()
        .map(|text| {
            (
                format!("substring:{text}"),
                crate::analysis::bel::Query {
                    text,
                    mode: crate::analysis::bel::SearchMode::Substring,
                    evidence: Vec::new(),
                    quorum: None,
                    relationship_depth: 1,
                    kinds: Vec::new(),
                },
                true,
            )
        })
        .collect();
    if cases.is_empty() {
        if let Some(entity) = index.entities.iter().find(|entity| {
            matches!(
                entity.kind,
                crate::analysis::bel::EntityKind::Import
                    | crate::analysis::bel::EntityKind::Export
                    | crate::analysis::bel::EntityKind::String
                    | crate::analysis::bel::EntityKind::Symbol
            ) && entity.display.len() >= 6
        }) {
            for (label, mode) in [
                ("exact", crate::analysis::bel::SearchMode::Exact),
                (
                    "selective_substring",
                    crate::analysis::bel::SearchMode::Substring,
                ),
                ("regex_literal", crate::analysis::bel::SearchMode::Regex),
            ] {
                let text = if mode == crate::analysis::bel::SearchMode::Regex {
                    regex::escape(entity.display.as_ref())
                } else {
                    entity.display.to_string()
                };
                cases.push((
                    label.to_string(),
                    crate::analysis::bel::Query {
                        text,
                        mode,
                        evidence: Vec::new(),
                        quorum: None,
                        relationship_depth: 1,
                        kinds: Vec::new(),
                    },
                    true,
                ));
            }
            cases.push((
                "relationship".to_string(),
                crate::analysis::bel::Query {
                    text: entity.display.to_string(),
                    mode: crate::analysis::bel::SearchMode::Relationship,
                    evidence: Vec::new(),
                    quorum: None,
                    relationship_depth: 1,
                    kinds: Vec::new(),
                },
                false,
            ));
            if let Some(va) = entity.va {
                cases.push((
                    "numeric".to_string(),
                    crate::analysis::bel::Query {
                        text: format!("{va:#x}"),
                        mode: crate::analysis::bel::SearchMode::Numeric,
                        evidence: Vec::new(),
                        quorum: None,
                        relationship_depth: 1,
                        kinds: Vec::new(),
                    },
                    true,
                ));
            }
        }
        cases.push((
            "token:mov".to_string(),
            crate::analysis::bel::Query {
                text: "mov".to_string(),
                mode: crate::analysis::bel::SearchMode::Token,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            true,
        ));
    }

    let iterations = iterations.clamp(1, 10_000);
    let mut reports = Vec::new();
    for (label, query, oracle_compatible) in cases {
        let warm = crate::analysis::bel::search(
            &index,
            &overlay,
            &query,
            512,
            None,
            Instant::now() + Duration::from_secs(60),
        )?;
        let mut optimized_ids: Vec<_> = warm.hits.iter().map(|hit| hit.entity_id).collect();
        let mut page_cursor = oracle_compatible
            .then(|| warm.next_cursor.clone())
            .flatten();
        let mut paginated_exact = warm.total_kind == crate::analysis::bel::TotalKind::Exact;
        for _ in 0..10_000 {
            let Some(cursor) = page_cursor.take() else {
                break;
            };
            if optimized_ids.len() >= 100_000 {
                page_cursor = Some(cursor);
                break;
            }
            let page = crate::analysis::bel::search(
                &index,
                &overlay,
                &query,
                512,
                Some(&cursor),
                Instant::now() + Duration::from_secs(60),
            )?;
            paginated_exact &= page.total_kind == crate::analysis::bel::TotalKind::Exact
                && page.total == warm.total;
            optimized_ids.extend(page.hits.iter().map(|hit| hit.entity_id));
            page_cursor = page.next_cursor;
        }
        let correctness = if oracle_compatible
            && paginated_exact
            && page_cursor.is_none()
            && optimized_ids.len() as u64 == warm.total
            && warm.total <= 100_000
        {
            let mut oracle = crate::analysis::bel::query::linear_oracle_ids(
                &index,
                &overlay,
                query.mode,
                &query.text,
            )?;
            oracle.sort_unstable();
            let mut optimized = optimized_ids.clone();
            optimized.sort_unstable();
            serde_json::json!({
                "checked": true,
                "equal": optimized == oracle,
                "optimized_checksum": bel_id_checksum(&optimized),
                "oracle_checksum": bel_id_checksum(&oracle),
            })
        } else {
            serde_json::json!({
                "checked": false,
                "reason": "mode is structural, partial, or exceeds the 100k oracle cap",
            })
        };
        let mut samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = crate::analysis::bel::search(
                &index,
                &overlay,
                &query,
                32,
                None,
                Instant::now() + Duration::from_secs(60),
            )?;
            samples.push(start.elapsed().as_micros() as u64);
        }
        samples.sort_unstable();
        reports.push(serde_json::json!({
            "name": label,
            "mode": query.mode,
            "query": query.text,
            "strategy": warm.strategy,
            "total": warm.total,
            "total_kind": warm.total_kind,
            "p50_us": percentile(&samples, 50),
            "p95_us": percentile(&samples, 95),
            "p99_us": percentile(&samples, 99),
            "correctness": correctness,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "engine": "binary_evidence_lattice",
            "pe": pe,
            "open_ms": open_ms,
            "build_ms": build_ms,
            "iterations": iterations,
            "stats": index.stats,
            "queries": reports,
        }))?
    );
    Ok(())
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let index = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted.get(index).copied().unwrap_or_default()
}

fn bel_id_checksum(ids: &[crate::analysis::bel::EntityId]) -> String {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(ids));
    for id in ids {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    format!("{:016x}", crate::analysis::bel::stable_u64_hash(&bytes))
}

#[cfg(any())]
fn run_grand_bench(
    manifest: Option<PathBuf>,
    output: Option<PathBuf>,
    table: bool,
    suite: String,
) -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = manifest.unwrap_or_else(|| root.join("eval/grand/manifest.json"));
    if suite.eq_ignore_ascii_case("v2-strict") || suite.eq_ignore_ascii_case("v2-pure") {
        let (report, four) =
            crate::grand_bench::run_grand_score_v2_strict(&root, &manifest_path)
                .with_context(|| format!("grand-bench v2-strict {}", manifest_path.display()))?;
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(out) = output {
            std::fs::write(&out, &json)?;
            eprintln!("Wrote strict pure-v2 report to {}", out.display());
            if let Ok(dir) = std::env::var("WINDY_SCRATCH") {
                let d = std::path::Path::new(&dir);
                let audit = crate::grand_bench::empty_decomp_audit(&report);
                let _ = std::fs::write(d.join("empty_decomp_audit.txt"), audit);
                let _ = std::fs::write(
                    d.join("grand_v2_four_lanes.json"),
                    serde_json::to_string_pretty(&four).unwrap_or_default(),
                );
                let share = serde_json::json!({
                    "suite": "v2_strict",
                    "functions_scored": four.functions_scored,
                    "by_engine": four.engine_share_present,
                    "v2_pure_fraction": four.pure_v2_share,
                    "pure_fallback_count": four.pure_fallback_count,
                });
                let _ = std::fs::write(
                    d.join("engine_share_v2.json"),
                    serde_json::to_string_pretty(&share).unwrap_or_default(),
                );
            }
        }
        if table {
            let adapted = crate::grand_bench::suite::GrandReport {
                suite: report.suite.clone(),
                windy: report.windy.clone(),
                ghidra: report.ghidra.clone(),
                per_function: report
                    .per_function
                    .iter()
                    .map(|p| p.scored.clone())
                    .collect(),
            };
            println!("{}", crate::grand_bench::format_scores_table(&adapted));
            println!(
                "\n_pure_v2_share={:.4} fallbacks={} omitted={}_",
                four.pure_v2_share,
                four.pure_fallback_count,
                report.omitted_functions.len()
            );
        } else {
            println!("{json}");
        }
        return Ok(());
    }
    if suite.eq_ignore_ascii_case("v2") || suite.eq_ignore_ascii_case("v2-picker") {
        // Historical diagnostic path (may use dual-VA picker); not the victory lane.
        let report = crate::grand_bench::run_grand_score_v2(&root, &manifest_path)
            .with_context(|| format!("grand-bench v2-picker {}", manifest_path.display()))?;
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(out) = output {
            std::fs::write(&out, &json)?;
            eprintln!("Wrote grand bench v2-picker report to {}", out.display());
            if let Ok(dir) = std::env::var("WINDY_SCRATCH") {
                let audit = crate::grand_bench::empty_decomp_audit(&report);
                let _ = std::fs::write(
                    std::path::Path::new(&dir).join("empty_decomp_audit.txt"),
                    audit,
                );
            }
        }
        if table {
            let adapted = crate::grand_bench::suite::GrandReport {
                suite: report.suite.clone(),
                windy: report.windy.clone(),
                ghidra: report.ghidra.clone(),
                per_function: report
                    .per_function
                    .iter()
                    .map(|p| p.scored.clone())
                    .collect(),
            };
            println!("{}", crate::grand_bench::format_scores_table(&adapted));
            println!(
                "\n_Omitted (folded/inlined/missing): {}_",
                report.omitted_functions.len()
            );
        } else {
            println!("{json}");
        }
        return Ok(());
    }
    let report = crate::grand_bench::run_grand_score(&root, &manifest_path)
        .with_context(|| format!("grand-bench {}", manifest_path.display()))?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(out) = output {
        std::fs::write(&out, &json)?;
        eprintln!("Wrote grand bench report to {}", out.display());
    }
    if table {
        println!("{}", crate::grand_bench::format_scores_table(&report));
    } else {
        println!("{json}");
    }
    Ok(())
}

#[cfg(any())]
fn run_decomp_scorecard(gold: Option<PathBuf>, output: Option<PathBuf>) -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let gold_path = gold.unwrap_or_else(|| crate::decomp_scorecard::default_gold_path(&root));
    let report = crate::decomp_scorecard::run_scorecard(&root, &gold_path)
        .with_context(|| format!("scorecard {}", gold_path.display()))?;
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(out) = output {
        std::fs::write(&out, &json)?;
        eprintln!("Wrote scorecard to {}", out.display());
    }
    println!("{json}");
    Ok(())
}

#[cfg(any())]
fn run_eval_agent_loop(pe: PathBuf, limit: usize) -> anyhow::Result<()> {
    let project =
        crate::project::Project::open(&pe).with_context(|| format!("open PE {}", pe.display()))?;
    let smoke = crate::eval_metrics::run_evidence_smoke(&project, limit);
    let out = serde_json::json!({
        "pe": pe.display().to_string(),
        "evidence_smoke": smoke,
        "note": "Full agent-loop benchmark is eval/agent-bench (workspace crate). This CLI path only smokes evidence cards.",
        "north_star": "agent_task_success_and_tokens (see docs/benchmarks/agent-loop-v1.md)",
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Token-free locate helper for `agent-bench --local` (arm A substrate, no LLM).
#[cfg(any())]
fn run_agent_query(
    pe: PathBuf,
    functions_named: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    let project =
        crate::project::Project::open(&pe).with_context(|| format!("open PE {}", pe.display()))?;
    let limit = limit.clamp(1, 128);
    let mut matches = Vec::new();
    if let Some(pattern) = functions_named.as_deref() {
        let needle = pattern.to_ascii_lowercase();
        for (va, name) in crate::llm::query::functions_named(&project, pattern) {
            matches.push(serde_json::json!({
                "va": format!("{va:#x}"),
                "name": name,
            }));
            if matches.len() >= limit {
                break;
            }
        }
        // functions_named already caps; if empty, scan full table for exact-ish hits.
        if matches.is_empty() {
            for f in project.functions().iter() {
                let name = f.name(&project.symbols);
                if name.to_ascii_lowercase().contains(&needle) {
                    matches.push(serde_json::json!({
                        "va": format!("{:#x}", f.entry_va),
                        "name": name,
                    }));
                    if matches.len() >= limit {
                        break;
                    }
                }
            }
        }
    }
    let out = serde_json::json!({
        "pe": pe.display().to_string(),
        "query": { "functions_named": functions_named },
        "matches": matches,
        "count": matches.len(),
        "entry_focus": project.focus.map(|va| format!("{va:#x}")),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_serve_mcp(
    bind: String,
    endpoint_file: Option<PathBuf>,
    data_dir: PathBuf,
) -> anyhow::Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parse bind address {bind}"))?;
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "Windy is local-only; --bind must use 127.0.0.1 or ::1 (got {})",
            addr.ip()
        );
    }
    let manager = Arc::new(crate::project_manager::ProjectManager::with_home_dir(
        &data_dir,
    )?);
    let mut server = match manager.start_http_server(addr) {
        Ok(server) => server,
        Err(error) => return Err(friendly_bind_error(addr, error)),
    };
    let port = server.port();
    let host = match addr.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    let endpoint = format!("http://{host}:{port}/mcp");
    let endpoint_file = endpoint_file.unwrap_or_else(|| data_dir.join("agent-endpoint.txt"));
    if let Some(parent) = endpoint_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create endpoint file directory {}", parent.display()))?;
    }
    std::fs::write(&endpoint_file, format!("{endpoint}\n"))
        .with_context(|| format!("write endpoint file {}", endpoint_file.display()))?;
    eprintln!(
        "{} {} — agent-first MCP",
        build_info::PRODUCT_TITLE,
        build_info::VERSION
    );
    eprintln!("endpoint: {endpoint}");
    eprintln!("state: {}", data_dir.display());
    eprintln!("targets are opened and closed by MCP agents; Ctrl+C stops the host");
    run_status_display(&manager, &endpoint)?;
    eprintln!("Shutting down.");
    manager
        .runtime()
        .block_on(server.shutdown())
        .context("shut down MCP HTTP server")?;
    Ok(())
}

fn run_status_display(
    manager: &Arc<crate::project_manager::ProjectManager>,
    endpoint: &str,
) -> anyhow::Result<()> {
    use std::io::IsTerminal;

    let interactive = std::io::stderr().is_terminal();
    manager.runtime().block_on(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut previous = String::new();
        loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal.context("wait for Ctrl+C")?;
                    break;
                }
                _ = interval.tick(), if interactive => {
                    let activity = manager.server_activity();
                    let metrics = crate::mcp::runtime_metrics();
                    let line = format!(
                        "endpoint={endpoint}  state={}  stage={}  clients=n/a  targets={}  jobs={}  cache=n/a  req={}  latency={}us  wire={}KiB  errors={}  rss={}MiB",
                        activity.state,
                        activity.operation.as_deref().unwrap_or("idle"),
                        manager.list().len(),
                        activity.active_operations,
                        metrics.requests,
                        metrics.average_latency_micros,
                        metrics.response_bytes / 1024,
                        metrics.errors,
                        metrics.rss_bytes.unwrap_or_default() / (1024 * 1024),
                    );
                    if line != previous {
                        eprint!("\r\x1b[2K{line}");
                        let _ = std::io::stderr().flush();
                        previous = line;
                    }
                }
            }
        }
        if interactive && !previous.is_empty() {
            eprintln!();
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn friendly_bind_error(addr: SocketAddr, error: anyhow::Error) -> anyhow::Error {
    let endpoint = format!("http://{}:{}/mcp", addr.ip(), addr.port());
    let pid = port_owner_pid(addr.port())
        .map(|pid| format!(" (PID {pid})"))
        .unwrap_or_default();
    anyhow::anyhow!(
        "Port {} is already in use by another process{pid}. If it is Windy, attach to {endpoint}; otherwise stop that process or choose --bind 127.0.0.1:<port>. Details: {error}",
        addr.port()
    )
}

fn port_owner_pid(port: u16) -> Option<u32> {
    if !cfg!(windows) {
        return None;
    }
    let output = std::process::Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 || !fields[3].eq_ignore_ascii_case("LISTENING") {
            return None;
        }
        let local_port = fields[1].rsplit(':').next()?.parse::<u16>().ok()?;
        (local_port == port)
            .then(|| fields[4].parse::<u32>().ok())
            .flatten()
    })
}

fn run_doctor(
    data_dir: PathBuf,
    open: Option<PathBuf>,
    endpoint: Option<String>,
) -> anyhow::Result<()> {
    println!(
        "{} {} doctor ({})",
        build_info::PRODUCT_TITLE,
        build_info::VERSION,
        build_info::CHANNEL
    );
    println!(
        "  platform: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("  data_dir: {}", data_dir.display());

    let projects_dir = data_dir.join("projects");
    std::fs::create_dir_all(&projects_dir).context("create Windy data directory")?;
    let probe = projects_dir.join(format!(".doctor-{}.tmp", std::process::id()));
    std::fs::write(&probe, b"windy-doctor").context("write Windy data directory")?;
    std::fs::remove_file(&probe).context("remove Windy doctor probe")?;
    println!("  storage: ok");

    let signatures = crate::analysis::win32_sigs::SigDB::load_from(&data_dir);
    let vtables = crate::analysis::vtable_sigs::VtableDB::load_from(&data_dir);
    println!(
        "  bundled databases: ok ({} API signatures, {} vtable methods)",
        signatures.len(),
        vtables.len()
    );

    if let Some(path) = open {
        let project = crate::project::Project::open_with_data_dir(&path, &data_dir)
            .with_context(|| format!("parse PE {}", path.display()))?;
        println!(
            "  PE: ok ({} functions, {} indexed instructions)",
            project.functions().len(),
            project.analysis.code_index.len()
        );
    }

    if let Some(endpoint) = endpoint {
        probe_mcp_endpoint(&endpoint)?;
    } else {
        match std::net::TcpListener::bind("127.0.0.1:8765") {
            Ok(listener) => {
                drop(listener);
                println!("  127.0.0.1:8765: available");
            }
            Err(_) => {
                if let Err(error) = probe_mcp_endpoint("http://127.0.0.1:8765/mcp") {
                    return Err(friendly_bind_error(
                        "127.0.0.1:8765".parse().unwrap(),
                        error,
                    ));
                }
            }
        }
    }

    println!("Doctor: all checks passed");
    Ok(())
}

fn probe_mcp_endpoint(endpoint: &str) -> anyhow::Result<()> {
    let endpoint = endpoint.trim_end_matches('/');
    let health = endpoint.strip_suffix("/mcp").map_or_else(
        || format!("{endpoint}/healthz"),
        |base| format!("{base}/healthz"),
    );
    let health_response = ureq::get(&health)
        .timeout(std::time::Duration::from_secs(5))
        .call()
        .map_err(|error| friendly_endpoint_error(endpoint, &health, error))?;
    let health_json: serde_json::Value = serde_json::from_str(
        &health_response
            .into_string()
            .context("read health response")?,
    )
    .context("parse health response")?;
    anyhow::ensure!(
        health_json["status"] == "ok",
        "Windy health status is not ok"
    );

    let request =
        |body: serde_json::Value, session: Option<&str>| -> anyhow::Result<ureq::Response> {
            let mut request = ureq::post(endpoint)
                .set("Content-Type", "application/json")
                .set("Accept", "application/json, text/event-stream")
                .set("MCP-Protocol-Version", "2025-11-25");
            if let Some(session) = session {
                request = request.set("Mcp-Session-Id", session);
            }
            Ok(request.send_string(&body.to_string())?)
        };

    let initialized = request(
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "windy-doctor", "version": build_info::VERSION }
            }
        }),
        None,
    )
    .with_context(|| format!("initialize {endpoint}"))?;
    let session = initialized
        .header("Mcp-Session-Id")
        .map(str::to_owned)
        .context("MCP initialize response did not include Mcp-Session-Id")?;
    let initialized_json = parse_mcp_response(initialized, "initialize")?;
    anyhow::ensure!(
        initialized_json["result"]["serverInfo"]["name"] == build_info::PRODUCT_ID,
        "endpoint is not a Windy MCP server"
    );

    let _ = request(
        serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        Some(&session),
    );
    let listed = request(
        serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
        Some(&session),
    )
    .with_context(|| format!("tools/list {endpoint}"))?;
    let listed_json = parse_mcp_response(listed, "tools/list")?;
    let count = listed_json["result"]["tools"]
        .as_array()
        .map(Vec::len)
        .context("tools/list response has no tools array")?;
    println!(
        "  MCP: ok ({count} tools at {endpoint}; state={}, projects={})",
        health_json["state"].as_str().unwrap_or("unknown"),
        health_json["projects_open"].as_u64().unwrap_or_default()
    );
    if health_json["projects_open"].as_u64() == Some(0) {
        println!("  hint: server is up without a target; the MCP agent should call target_open.");
    }
    Ok(())
}

fn friendly_endpoint_error(endpoint: &str, health: &str, error: ureq::Error) -> anyhow::Error {
    let default_endpoint = "http://127.0.0.1:8765/mcp";
    let default_is_running = endpoint != default_endpoint
        && ureq::get("http://127.0.0.1:8765/healthz")
            .timeout(std::time::Duration::from_secs(2))
            .call()
            .is_ok();
    if default_is_running {
        anyhow::anyhow!(
            "Nothing usable answered at {endpoint}. Windy Agent is running at {default_endpoint}; update the client URL and refresh its MCP session. ({error})"
        )
    } else {
        anyhow::anyhow!(
            "Nothing usable is listening at {health}. Start it with: windy serve-mcp. The default agent URL is {default_endpoint}. ({error})"
        )
    }
}

fn parse_mcp_response(
    response: ureq::Response,
    operation: &str,
) -> anyhow::Result<serde_json::Value> {
    let text = response
        .into_string()
        .with_context(|| format!("read {operation} response"))?;
    let payload = if text.trim_start().starts_with("data:") || text.contains("\ndata:") {
        text.lines()
            .filter_map(|line| line.strip_prefix("data:").map(str::trim))
            .find(|data| !data.is_empty())
            .with_context(|| format!("{operation} SSE response contained no data"))?
    } else {
        text.trim()
    };
    serde_json::from_str(payload).with_context(|| format!("parse {operation} response"))
}

#[cfg(any())]
fn run_emit_contract(output: Option<PathBuf>) -> anyhow::Result<()> {
    let schema = schemars::schema_for!(crate::ir::gclsd::GclsdInput);
    let json = serde_json::to_string_pretty(&schema)?;

    match output {
        Some(out_path) => {
            std::fs::write(&out_path, json)?;
            eprintln!("Wrote GCLSD input contract to {}", out_path.display());
        }
        None => {
            std::io::stdout().write_all(json.as_bytes())?;
        }
    }
    Ok(())
}

#[cfg(any())]
fn run_export_gclsd(
    path: PathBuf,
    output: Option<PathBuf>,
    min_insns: usize,
) -> anyhow::Result<()> {
    let project = crate::project::Project::open(&path)
        .with_context(|| format!("open PE {}", path.display()))?;

    let writer: Box<dyn Write> = match output {
        Some(out_path) => Box::new(std::fs::File::create(&out_path)?),
        None => Box::new(std::io::stdout()),
    };
    let mut writer = BufWriter::new(writer);

    let mut exported = 0usize;
    for input in crate::ir::gclsd::export_project_gclsd(&project, min_insns) {
        serde_json::to_writer(&mut writer, &input)?;
        writer.write_all(b"\n")?;
        exported += 1;
    }
    writer.flush()?;

    eprintln!("Exported {exported} function(s) from {}", path.display());
    Ok(())
}
