use std::collections::HashMap;
use std::path::PathBuf;

use eframe::{CreationContext, Frame};
use egui::{Context, Ui};
use egui_dock::{DockArea, Style};
use tracing::{error, info};

use crate::disasm::{Disassembler, Syntax};
use crate::project::Project;
use crate::ui::view::View;
use crate::ui::{empty_tree, project_tree, WindyTabViewer};

pub struct App {
    project: Option<Project>,
    dock_state: egui_dock::DockState<View>,
    console: Vec<String>,
    cursor_va: u64,
    goto_input: String,
    disassembler: Disassembler,
}

impl App {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        Self {
            project: None,
            dock_state: empty_tree(),
            console: vec!["Windy ready. Use File → Open to load a PE.".to_string()],
            cursor_va: 0,
            goto_input: String::new(),
            disassembler: Disassembler::new(Syntax::Intel, HashMap::new()),
        }
    }

    fn push_console(&mut self, msg: impl Into<String>) {
        let line = msg.into();
        info!("{}", line);
        self.console.push(line);
    }

    fn start_open(&mut self, path: PathBuf) {
        self.push_console(format!("Loading {} ...", path.display()));
        match Project::open(&path) {
            Ok(project) => {
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

            ui.menu_button("Edit", |ui| {
                if ui
                    .add_enabled(self.can_undo(), egui::Button::new("Undo"))
                    .clicked()
                {
                    ui.close();
                    self.undo();
                }
                if ui
                    .add_enabled(self.can_redo(), egui::Button::new("Redo"))
                    .clicked()
                {
                    ui.close();
                    self.redo();
                }
            });

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

    fn can_undo(&self) -> bool {
        self.project.as_ref().is_some_and(Project::can_undo)
    }

    fn can_redo(&self) -> bool {
        self.project.as_ref().is_some_and(Project::can_redo)
    }

    fn undo(&mut self) {
        if let Some(project) = &mut self.project {
            project.undo();
            self.disassembler.set_names(&project.symbols);
            self.push_console("Undid last action".to_string());
        }
    }

    fn redo(&mut self) {
        if let Some(project) = &mut self.project {
            project.redo();
            self.disassembler.set_names(&project.symbols);
            self.push_console("Redid last action".to_string());
        }
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
        if let Some(project) = &mut self.project {
            project.set_focus(va);
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
}

impl eframe::App for App {
    fn logic(&mut self, _ctx: &Context, _frame: &mut Frame) {}

    fn ui(&mut self, ui: &mut Ui, _frame: &mut Frame) {
        self.main_menu(ui);
        ui.separator();

        let mut viewer = WindyTabViewer {
            project: &mut self.project,
            console: &mut self.console,
            cursor: &mut self.cursor_va,
            disassembler: &self.disassembler,
        };

        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(ui.style()))
            .show(ui, |ui| {
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
