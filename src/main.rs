#[cfg(feature = "gclsd-archive")]
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use eframe::NativeOptions;
use egui::ViewportBuilder;
use tracing_subscriber::EnvFilter;

mod analysis;
mod app;
mod cross_project;
mod decomp_scorecard;
mod decompiler;
mod disasm;
mod eval_metrics;
mod grand_bench;
mod ir;
mod llm;
mod loader;
mod mcp;
mod project;
mod project_manager;
mod ui;

#[derive(Parser)]
#[command(name = "windy")]
#[command(about = "Windy reverse-engineering workbench")]
#[command(version)]
struct Cli {
    /// Optional PE to open directly in the GUI.
    #[arg(value_name = "PE")]
    path: Option<PathBuf>,

    /// Windy state directory (overrides WINDY_HOME and %USERPROFILE%\.windy).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run headless MCP HTTP server for external agents (OpenCode, Claude, Cursor, …).
    ServeMcp {
        /// Bind address (default 127.0.0.1:8765).
        #[arg(long, default_value = "127.0.0.1:8765")]
        bind: String,
        /// Optional PE path to open on startup.
        #[arg(long)]
        open: Option<PathBuf>,
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
    #[cfg(feature = "gclsd-archive")]
    /// Export every function of a PE as GCLSD (asm + CFG) JSONL for model training.
    ExportGclsd {
        /// Path to the PE file (.exe/.dll/.sys).
        path: PathBuf,
        /// Output JSONL file (defaults to stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Minimum instruction count for a function to be exported.
        #[arg(long, default_value_t = 1)]
        min_insns: usize,
    },
    #[cfg(feature = "gclsd-archive")]
    /// Emit the JSON Schema for the external GCLSD model input contract.
    EmitContract {
        /// Output JSON file (defaults to stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    #[command(hide = true)]
    /// Compatibility alias for `bench agent-loop`.
    EvalAgentLoop {
        /// Path to PE.
        #[arg(long)]
        pe: PathBuf,
        /// Max functions to sample (largest first).
        #[arg(long, default_value_t = 16)]
        limit: usize,
    },
    #[command(hide = true)]
    /// Compatibility alias for `bench scorecard`.
    DecompScorecard {
        /// Gold JSON path (default: eval/gold/sample_source_gold.json under CWD/manifest).
        #[arg(long)]
        gold: Option<PathBuf>,
        /// Optional output JSON path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    #[command(hide = true)]
    /// Compatibility alias for `bench grand`.
    GrandBench {
        /// Manifest JSON (default: eval/grand/manifest.json).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Optional JSON report output path.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Also print human-readable markdown table to stdout (default true).
        #[arg(long, default_value_t = true)]
        table: bool,
        /// Suite: `v1` (frozen picker SFG) or `v2` (exact-VA present-function scoring).
        #[arg(long, default_value = "v1")]
        suite: String,
    },
}

#[derive(Subcommand)]
enum BenchCommands {
    /// Compare evidence-first agent queries with whole-function dumps.
    AgentLoop {
        /// Path to PE.
        #[arg(long)]
        pe: PathBuf,
        /// Max functions to sample (largest first).
        #[arg(long, default_value_t = 16)]
        limit: usize,
    },
    /// Grade native decompilation against source gold and a Ghidra export.
    Scorecard {
        /// Gold JSON path (defaults to the authored sample fixture).
        #[arg(long)]
        gold: Option<PathBuf>,
        /// Optional output JSON path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run the Windy Grand Decompilation Benchmark suite.
    Grand {
        /// Manifest JSON (default: eval/grand/manifest.json).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Optional JSON report output path.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Also print the human-readable score table.
        #[arg(long, default_value_t = true)]
        table: bool,
        /// Suite: v1, v2, or v2-strict.
        #[arg(long, default_value = "v1")]
        suite: String,
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
        Some(Commands::ServeMcp { bind, open }) => run_serve_mcp(bind, open, data_dir),
        Some(Commands::Doctor { open, endpoint }) => run_doctor(data_dir, open, endpoint),
        Some(Commands::Bench { command }) => match command {
            BenchCommands::AgentLoop { pe, limit } => run_eval_agent_loop(pe, limit),
            BenchCommands::Scorecard { gold, output } => run_decomp_scorecard(gold, output),
            BenchCommands::Grand {
                manifest,
                output,
                table,
                suite,
            } => run_grand_bench(manifest, output, table, suite),
        },
        #[cfg(feature = "gclsd-archive")]
        Some(Commands::ExportGclsd {
            path,
            output,
            min_insns,
        }) => run_export_gclsd(path, output, min_insns),
        #[cfg(feature = "gclsd-archive")]
        Some(Commands::EmitContract { output }) => run_emit_contract(output),
        Some(Commands::EvalAgentLoop { pe, limit }) => run_eval_agent_loop(pe, limit),
        Some(Commands::DecompScorecard { gold, output }) => run_decomp_scorecard(gold, output),
        Some(Commands::GrandBench {
            manifest,
            output,
            table,
            suite,
        }) => run_grand_bench(manifest, output, table, suite),
        None => run_gui(data_dir, cli.path),
    }
}

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

fn run_eval_agent_loop(pe: PathBuf, limit: usize) -> anyhow::Result<()> {
    let project =
        crate::project::Project::open(&pe).with_context(|| format!("open PE {}", pe.display()))?;
    let (evidence, dump) = crate::eval_metrics::run_agent_loop_eval(&project, limit);
    let out = serde_json::json!({
        "pe": pe.display().to_string(),
        "evidence": evidence,
        "dump": dump,
        "north_star": "verified_facts_per_1k_tokens",
        "winner": if evidence.verified_facts_per_1k_tokens >= dump.verified_facts_per_1k_tokens {
            "evidence"
        } else {
            "dump"
        },
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_serve_mcp(bind: String, open: Option<PathBuf>, data_dir: PathBuf) -> anyhow::Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parse bind address {bind}"))?;
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "Windy v0.1 is local-only; --bind must use 127.0.0.1 or ::1 (got {})",
            addr.ip()
        );
    }
    let manager = Arc::new(crate::project_manager::ProjectManager::with_home_dir(
        &data_dir,
    )?);
    if let Some(path) = open {
        let id = manager
            .open(&path)
            .with_context(|| format!("open PE {}", path.display()))?;
        eprintln!("Opened {} as project_id={}", path.display(), id);
    }
    let mut server = manager
        .start_http_server(addr)
        .context("start MCP HTTP server")?;
    let port = server.port();
    let host = match addr.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    eprintln!("Windy MCP listening on http://{host}:{port}/mcp");
    eprintln!("State directory: {}", data_dir.display());
    eprintln!("Pure MCP mode - external agents plan; Windy answers and commits.");
    eprintln!("Ctrl+C to stop.");
    // Multi-threaded runtime keeps the server alive; block until interrupt.
    manager.runtime().block_on(async {
        tokio::signal::ctrl_c().await.context("wait for Ctrl+C")?;
        Ok::<(), anyhow::Error>(())
    })?;
    eprintln!("Shutting down.");
    manager
        .runtime()
        .block_on(server.shutdown())
        .context("shut down MCP HTTP server")?;
    Ok(())
}

fn run_doctor(
    data_dir: PathBuf,
    open: Option<PathBuf>,
    endpoint: Option<String>,
) -> anyhow::Result<()> {
    println!("Windy {} doctor", env!("CARGO_PKG_VERSION"));
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
            Err(_) => probe_mcp_endpoint("http://127.0.0.1:8765/mcp")?,
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
        .call()
        .with_context(|| format!("GET {health}"))?;
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
                "clientInfo": { "name": "windy-doctor", "version": env!("CARGO_PKG_VERSION") }
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
        initialized_json["result"]["serverInfo"]["name"] == "windy",
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
    println!("  MCP: ok ({count} tools at {endpoint})");
    Ok(())
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

fn run_gui(data_dir: PathBuf, initial_path: Option<PathBuf>) -> anyhow::Result<()> {
    let options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1280.0, 900.0])
            .with_title("Windy"),
        ..Default::default()
    };

    eframe::run_native(
        "Windy",
        options,
        Box::new(move |cc| {
            Ok(Box::new(app::App::new(
                cc,
                data_dir.clone(),
                initial_path.clone(),
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;
    Ok(())
}

#[cfg(feature = "gclsd-archive")]
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

#[cfg(feature = "gclsd-archive")]
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
