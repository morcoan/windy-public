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
mod decompiler;
mod disasm;
mod decomp_scorecard;
mod eval_metrics;
mod ir;
mod loader;
mod llm;
mod mcp;
mod project;
mod project_manager;
mod ui;

#[derive(Parser)]
#[command(name = "windy")]
#[command(about = "Windy reverse-engineering workbench")]
struct Cli {
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
    /// Emit the JSON Schema for the external GCLSD model input contract.
    EmitContract {
        /// Output JSON file (defaults to stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run scripted agent-loop eval (evidence vs dump) on a PE; print JSON metrics.
    EvalAgentLoop {
        /// Path to PE.
        pe: PathBuf,
        /// Max functions to sample (largest first).
        #[arg(long, default_value_t = 16)]
        limit: usize,
    },
    /// Grade Windy native decompile vs Ghidra export against source gold JSON.
    DecompScorecard {
        /// Gold JSON path (default: eval/gold/sample_source_gold.json under CWD/manifest).
        #[arg(long)]
        gold: Option<PathBuf>,
        /// Optional output JSON path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::ServeMcp { bind, open }) => run_serve_mcp(bind, open),
        Some(Commands::ExportGclsd {
            path,
            output,
            min_insns,
        }) => run_export_gclsd(path, output, min_insns),
        Some(Commands::EmitContract { output }) => run_emit_contract(output),
        Some(Commands::EvalAgentLoop { pe, limit }) => run_eval_agent_loop(pe, limit),
        Some(Commands::DecompScorecard { gold, output }) => run_decomp_scorecard(gold, output),
        None => run_gui(),
    }
}

fn run_decomp_scorecard(
    gold: Option<PathBuf>,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
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
    let project = crate::project::Project::open(&pe)
        .with_context(|| format!("open PE {}", pe.display()))?;
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

fn run_serve_mcp(bind: String, open: Option<PathBuf>) -> anyhow::Result<()> {
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("parse bind address {bind}"))?;
    let manager = Arc::new(crate::project_manager::ProjectManager::new()?);
    if let Some(path) = open {
        let id = manager
            .open(&path)
            .with_context(|| format!("open PE {}", path.display()))?;
        eprintln!(
            "Opened {} as project_id={}",
            path.display(),
            id
        );
    }
    let decompiler = Arc::new(
        crate::decompiler::client::DecompilerClient::from_env()
            .context("init decompiler client")?,
    );
    let port = manager
        .start_http_server(decompiler, addr)
        .context("start MCP HTTP server")?;
    let host = match addr.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    eprintln!("Windy MCP listening on http://{host}:{port}/mcp");
    eprintln!("Pure MCP mode — external agents plan; windy answers and commits.");
    eprintln!("Ctrl+C to stop.");
    // Multi-threaded runtime keeps the server alive; block until interrupt.
    manager.runtime().block_on(async {
        tokio::signal::ctrl_c()
            .await
            .context("wait for Ctrl+C")?;
        Ok::<(), anyhow::Error>(())
    })?;
    eprintln!("Shutting down.");
    Ok(())
}

fn run_gui() -> anyhow::Result<()> {
    let options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1280.0, 900.0])
            .with_title("Windy"),
        ..Default::default()
    };

    eframe::run_native(
        "Windy",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;
    Ok(())
}

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
