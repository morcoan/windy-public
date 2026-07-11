use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use eframe::{CreationContext, Frame};
use egui::{Context, Ui};
use egui_dock::{DockArea, Style};
use tracing::{error, info};

use crate::decompiler::client::{DecompilerCacheKey, DecompilerClient};
use crate::disasm::{Disassembler, Syntax};
use crate::project::op::Op;
use crate::project::workspace::{WorkspaceId, WorkspaceSummary};
use crate::project::Project;
use crate::project_manager::{ProjectId, ProjectManager};
use crate::ui::view::View;
use crate::ui::{empty_tree, project_tree, WindyTabViewer};

pub struct App {
    manager: Arc<ProjectManager>,
    decompiler: Arc<DecompilerClient>,
    project: Option<Arc<Project>>,
    active_id: Option<ProjectId>,
    activity_filter: Option<ProjectId>,
    dock_state: egui_dock::DockState<View>,
    console: Vec<String>,
    cursor_va: u64,
    goto_input: String,
    disassembler: Disassembler,
    decompiler_cache: HashMap<DecompilerCacheKey, String>,
    decompiler_tx: mpsc::Sender<(DecompilerCacheKey, Result<String, String>)>,
    decompiler_rx: mpsc::Receiver<(DecompilerCacheKey, Result<String, String>)>,
}

impl App {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        let manager = Arc::new(ProjectManager::new().expect("tokio runtime required"));
        // The HTTP decompiler (legacy GCLSD model) is optional: Windy runs fully
        // standalone off its native P-code decompiler. If the endpoint can't be
        // constructed we fall back to the default and keep going.
        let decompiler = Arc::new(
            DecompilerClient::from_env().unwrap_or_else(|e| {
                tracing::warn!("HTTP decompiler unavailable ({e}); using native P-code decompiler");
                DecompilerClient::new(crate::decompiler::client::DEFAULT_ENDPOINT)
                    .expect("reqwest client build failed")
            }),
        );
        let mcp_port = manager
            .start_http_server(decompiler.clone(), "127.0.0.1:0".parse().unwrap())
            .expect("MCP server required");
        let (decompiler_tx, decompiler_rx) = mpsc::channel();
        let mut console = vec!["Windy ready. Use File → Open to load a PE.".to_string()];
        console.push(format!("MCP server listening on http://127.0.0.1:{mcp_port}/mcp"));
        console.push(format!(
            "Decompiler endpoint: {}",
            decompiler.endpoint()
        ));
        Self {
            manager,
            decompiler,
            project: None,
            active_id: None,
            activity_filter: None,
            dock_state: empty_tree(),
            console,
            cursor_va: 0,
            goto_input: String::new(),
            disassembler: Disassembler::new(Syntax::Intel, HashMap::new()),
            decompiler_cache: HashMap::new(),
            decompiler_tx,
            decompiler_rx,
        }
    }

    fn push_console(&mut self, msg: impl Into<String>) {
        let line = msg.into();
        info!("{}", line);
        self.console.push(line);
    }

    fn start_open(&mut self, path: PathBuf) {
        self.push_console(format!("Loading {} ...", path.display()));
        match self.manager.open(&path) {
            Ok(id) => {
                let project = self.manager.get(id).expect("project just opened");
                self.push_console(format!(
                    "Loaded {} ({})",
                    project.pe.path.display(),
                    human_bytes(project.pe.image.len())
                ));
                self.push_console(format!(
                    "  {} functions, {} instructions indexed",
                    project.functions().len(),
                    project.analysis.code_index.len()
                ));
                if let Some(w) = &project.pe.parse_warning {
                    self.push_console(format!("Parse warning: {}", w));
                }

                self.cursor_va = project.focus.unwrap_or(0);
                self.disassembler =
                    Disassembler::new_from_symbol_table(Syntax::Intel, &project.symbols);
                self.project = Some(project);
                self.active_id = Some(id);
                self.dock_state = project_tree();
            }
            Err(e) => {
                error!("load failed: {}", e);
                self.push_console(format!("Failed to load: {}", e));
            }
        }
    }

    fn main_menu(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open…").clicked() {
                    ui.close();
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("PE files", &["exe", "dll", "sys"])
                        .add_filter("All files", &["*"])
                        .pick_file()
                    {
                        self.start_open(path);
                    }
                }

                if ui
                    .add_enabled(self.has_project(), egui::Button::new("Export function JSON"))
                    .clicked()
                {
                    ui.close();
                    self.export_function_json();
                }

                if ui.button("Exit").clicked() {
                    ui.close();
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            if ui
                .add_enabled(self.has_project(), egui::Button::new("Undo"))
                .clicked()
            {
                ui.close();
                self.undo_last();
            }

            ui.separator();
            ui.label("Goto VA:");
            ui.add(egui::TextEdit::singleline(&mut self.goto_input).desired_width(120.0));
            if ui.button("Go").clicked()
                && let Some(va) = self.parse_goto_va()
            {
                self.goto(va);
                self.goto_input.clear();
            }
        });
    }

    fn has_project(&self) -> bool {
        self.project.is_some()
    }

    fn parse_goto_va(&self) -> Option<u64> {
        let s = self.goto_input.trim();
        if s.is_empty() {
            return None;
        }
        if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(rest, 16).ok()
        } else {
            u64::from_str_radix(s, 16).ok().or_else(|| s.parse::<u64>().ok())
        }
    }

    fn goto(&mut self, va: u64) {
        self.cursor_va = va;
        if let Some(id) = self.active_id {
            if let Err(e) = self
                .manager
                .apply_op_sync(id, "ui", Op::SetFocus { va, old_focus: None })
            {
                error!("focus op failed: {}", e);
            } else {
                self.project = self.manager.get(id);
            }
        }
        self.push_console(format!("Cursor: {:#x}", va));
    }

    fn export_function_json(&mut self) {
        let Some(project) = &self.project else { return };
        let Some(focus) = project.focus else {
            self.push_console("No function focused".to_string());
            return;
        };
        let Some(export) = project.function_export(focus) else {
            self.push_console("Failed to export focused function".to_string());
            return;
        };

        let default_name = format!("{}.json", export.name);
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name(&default_name)
            .save_file()
        else {
            return;
        };

        match serde_json::to_string_pretty(&export) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(()) => self.push_console(format!("Exported {}", path.display())),
                Err(e) => self.push_console(format!("Failed to write JSON: {}", e)),
            },
            Err(e) => self.push_console(format!("JSON serialization error: {}", e)),
        }
    }

    fn undo_last(&mut self) {
        let Some(id) = self.active_id else { return };
        match self.manager.undo_last_sync(id, "ui") {
            Ok(op) => {
                self.project = self.manager.get(id);
                self.push_console(format!("Undid: {}", op.summary()));
            }
            Err(e) => self.push_console(format!("Undo failed: {}", e)),
        }
    }

    fn switch_project(&mut self, id: ProjectId) {
        let Some(project) = self.manager.get(id) else { return };
        self.cursor_va = project.focus.unwrap_or(0);
        self.disassembler =
            Disassembler::new_from_symbol_table(Syntax::Intel, &project.symbols);
        self.project = Some(project);
        self.active_id = Some(id);
        self.dock_state = project_tree();
        self.push_console(format!("Switched to project {id}"));
    }

    /// Drain completed async decompile tasks into the cache.
    fn drain_decompiler_channel(&mut self) {
        while let Ok((key, result)) = self.decompiler_rx.try_recv() {
            match result {
                Ok(text) => {
                    self.decompiler_cache.insert(key, text);
                }
                Err(e) => {
                    self.push_console(format!("Decompile error: {e}"));
                }
            }
        }
    }

    fn render_project_sidebar(&mut self, ui: &mut Ui) {
        egui::Panel::left("windy_sidebar")
            .default_size(220.0)
            .resizable(true)
            .show(ui, |ui| {
                ui.heading("Projects");
                ui.separator();

                let workspaces = self.manager.list_workspaces();
                let projects = self.manager.list();

                if projects.is_empty() && workspaces.is_empty() {
                    ui.label("No project loaded. Use File → Open.");
                }

                egui::ScrollArea::vertical().show(ui, |ui| {
                    // Group currently open projects by workspace membership (matched by
                    // SHA256 + path). Workspaces list their members even if the PE is
                    // not currently open, but the sidebar only displays open projects.
                    let mut grouped: HashMap<WorkspaceId, Vec<_>> = HashMap::default();
                    let mut ungrouped = Vec::new();

                    for (project_id, path, fn_count, insn_count) in &projects {
                        let mut assigned = None;
                        for ws in &workspaces {
                            let Some(full) = self.manager.get_workspace(ws.id) else {
                                continue;
                            };
                            let Some(project) = self.manager.get(*project_id) else {
                                continue;
                            };
                            if full.members.iter().any(|m| {
                                m.sha256 == project.image_sha256 && m.path == project.pe.path
                            }) {
                                assigned = Some(ws.id);
                                break;
                            }
                        }
                        if let Some(ws_id) = assigned {
                            grouped
                                .entry(ws_id)
                                .or_default()
                                .push((*project_id, path.clone(), *fn_count, *insn_count));
                        } else {
                            ungrouped.push((*project_id, path.clone(), *fn_count, *insn_count));
                        }
                    }

                    for ws in &workspaces {
                        let member_count = grouped.get(&ws.id).map(|v| v.len()).unwrap_or(0);
                        let title = ws_summary_title(ws, member_count);
                        egui::CollapsingHeader::new(title)
                            .default_open(false)
                            .show(ui, |ui| {
                                if member_count == 0 {
                                    ui.label("No open members.");
                                }
                                for (id, path, fn_count, insn_count) in
                                    grouped.get(&ws.id).into_iter().flatten()
                                {
                                    self.render_project_item(ui, *id, path, *fn_count, *insn_count);
                                }
                            });
                    }

                    if !ungrouped.is_empty() {
                        if !workspaces.is_empty() {
                            ui.separator();
                            ui.label(egui::RichText::new("Ungrouped Projects").strong());
                        }
                        for (id, path, fn_count, insn_count) in ungrouped {
                            self.render_project_item(ui, id, &path, fn_count, insn_count);
                        }
                    }
                });
            });
    }

    fn render_project_item(
        &mut self,
        ui: &mut Ui,
        id: ProjectId,
        path: &std::path::Path,
        fn_count: usize,
        insn_count: usize,
    ) {
        let is_active = self.active_id == Some(id);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_else(|| path.to_string_lossy());
        let label = format!("{name}\n{fn_count} funcs · {insn_count} insns");
        if ui.selectable_label(is_active, label).clicked() {
            self.switch_project(id);
        }
    }

    fn render_activity_panel(&mut self, ui: &mut Ui) {
        egui::Panel::right("windy_activity")
            .default_size(260.0)
            .resizable(true)
            .show(ui, |ui| {
                ui.heading("Activity");
                ui.separator();

                let projects = self.manager.list();
                let filter_label = self
                    .activity_filter
                    .and_then(|id| projects.iter().find(|(pid, _, _, _)| *pid == id))
                    .map(|(_, path, _, _)| {
                        path.file_name()
                            .map(|n| n.to_string_lossy())
                            .unwrap_or_else(|| path.to_string_lossy())
                            .to_string()
                    })
                    .unwrap_or_else(|| "All projects".to_string());

                ui.horizontal(|ui| {
                    ui.label("Show:");
                    egui::ComboBox::from_id_salt("activity_filter")
                        .selected_text(filter_label)
                        .width(140.0)
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_label(self.activity_filter.is_none(), "All projects")
                                .clicked()
                            {
                                self.activity_filter = None;
                            }
                            for (id, path, _, _) in &projects {
                                let name = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy())
                                    .unwrap_or_else(|| path.to_string_lossy());
                                let selected = self.activity_filter == Some(*id);
                                if ui.selectable_label(selected, name).clicked() {
                                    self.activity_filter = Some(*id);
                                }
                            }
                        });
                });
                ui.separator();

                let events = self
                    .manager
                    .recent_activity_filtered(50, self.activity_filter);
                if events.is_empty() {
                    ui.label("No activity yet.");
                }
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for event in events {
                            let elapsed = SystemTime::now()
                                .duration_since(event.timestamp)
                                .unwrap_or_default();
                            let ago = elapsed.as_secs();
                            let client = if event.client_id.len() > 8 {
                                &event.client_id[..8]
                            } else {
                                &event.client_id
                            };
                            let pid = event.project_id.to_string();
                            let pid_short = if pid.len() > 8 {
                                pid[..8].to_string()
                            } else {
                                pid.clone()
                            };
                            let epoch_secs = event
                                .timestamp
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                .to_string();
                            ui.horizontal(|ui| {
                                ui.monospace(format!("{ago:3}s")).on_hover_text(epoch_secs);
                                ui.label(format!("[{pid_short}]")).on_hover_text(pid);
                                ui.label(format!("[{client}]"));
                                ui.label(&event.op_summary);
                            });
                        }
                    });
            });
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &Context, _frame: &mut Frame) {
        // Keep the UI ticking so agent-driven mutations appear in the activity feed
        // and async decompile results are drained into the cache.
        self.drain_decompiler_channel();
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut Frame) {
        self.main_menu(ui);
        ui.separator();

        // Pull the latest snapshot from the MCP-backed project manager.
        if let Some(id) = self.active_id {
            self.project = self.manager.get(id);
        }

        self.render_project_sidebar(ui);
        self.render_activity_panel(ui);

        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(ui.style()))
            .show(ui, |ui| {
                let mut viewer = WindyTabViewer {
                    project: &self.project,
                    console: &mut self.console,
                    cursor: &mut self.cursor_va,
                    disassembler: &self.disassembler,
                    decompiler_cache: &mut self.decompiler_cache,
                    decompiler_tx: self.decompiler_tx.clone(),
                    manager: self.manager.clone(),
                    decompiler: self.decompiler.clone(),
                };
                DockArea::new(&mut self.dock_state)
                    .style(Style::from_egui(ui.style().as_ref()))
                    .show_inside(ui, &mut viewer);
            });
    }
}

fn human_bytes(n: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = n as f64;
    let mut unit = UNITS[0];
    for &u in UNITS.iter().take(4) {
        unit = u;
        if size < 1024.0 {
            break;
        }
        size /= 1024.0;
    }
    format!("{:.2} {}", size, unit)
}

fn ws_summary_title(ws: &WorkspaceSummary, open_members: usize) -> String {
    let name = ws
        .name
        .clone()
        .unwrap_or_else(|| format!("Workspace {}", &ws.id.to_string()[..8]));
    format!("{name} ({open_members}/{})", ws.member_count)
}
