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
        None => run_gui(data_dir, cli.path),
    }
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
