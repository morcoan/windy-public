use std::path::PathBuf;

use eframe::{CreationContext, Frame};
use egui::{Context, Ui};
use egui_dock::{DockArea, Style};
use tracing::{error, info};

use crate::project::Project;
use crate::ui::view::View;
use crate::ui::{empty_tree, project_tree, WindyTabViewer};

pub struct App {
    project: Option<Project>,
    dock_state: egui_dock::DockState<View>,
    console: Vec<String>,
}

impl App {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        Self {
            project: None,
            dock_state: empty_tree(),
            console: vec!["Windy ready. Use File → Open to load a PE.".to_string()],
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
                if let Some(w) = &project.pe.parse_warning {
                    self.push_console(format!("Parse warning: {}", w));
                }
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
                if ui.button("Exit").clicked() {
                    ui.close();
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
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
