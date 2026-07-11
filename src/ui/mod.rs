use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;

use egui::{Ui, WidgetText};
use egui_dock::{DockState, TabViewer};

use crate::decompiler::client::{DecompilerCacheKey, DecompilerClient};
use crate::disasm::Disassembler;
use crate::project::Project;
use crate::project_manager::ProjectManager;
use crate::ui::triage_panels::render_view;
use crate::ui::view::View;

pub mod disasm_view;
pub mod function_tree;
pub mod hex_view;
pub mod triage_panels;
pub mod view;
pub mod xrefs_view;

/// Mutable view state borrowed from the application. Holding references to
/// individual fields lets `DockArea` keep the `dock_state` borrow separate.
pub struct WindyTabViewer<'a> {
    pub project: &'a Option<Arc<Project>>,
    pub console: &'a mut [String],
    pub cursor: &'a mut u64,
    pub disassembler: &'a Disassembler,
    pub decompiler_cache: &'a mut HashMap<DecompilerCacheKey, String>,
    pub decompiler_tx: mpsc::Sender<(DecompilerCacheKey, Result<String, String>)>,
    pub manager: Arc<ProjectManager>,
    pub decompiler: Arc<DecompilerClient>,
}

impl<'a> WindyTabViewer<'a> {
    /// Render the decompiled pseudo-code panel for the function at `va`.
    pub fn render_decompiled_view(&mut self, ui: &mut Ui, project: &Project, va: u64) {
        self.poll_decompiler_results();

        let key = DecompilerCacheKey {
            image_sha256: project.image_sha256.clone(),
            va,
            op_seq: project.op_seq,
        };

        if let Some(text) = self.decompiler_cache.get(&key) {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(30)
                        .lock_focus(true)
                        .desired_width(f32::INFINITY),
                );
            });
        } else {
            ui.label("Decompiling...");
            self.request_decompilation(project, va);
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
        }
    }

    fn poll_decompiler_results(&mut self) {
        // The receiver lives on the App; the viewer only owns the sender.
        // This method intentionally no-ops here because results are drained
        // into the cache by App::logic each frame.
    }

    fn request_decompilation(&mut self, project: &Project, va: u64) {
        let Some(input) = project.function_gclsd_input(va) else { return };
        let key = DecompilerCacheKey {
            image_sha256: project.image_sha256.clone(),
            va,
            op_seq: project.op_seq,
        };
        if self.decompiler_cache.contains_key(&key) {
            return;
        }
        let tx = self.decompiler_tx.clone();
        let client = self.decompiler.clone();
        let manager = self.manager.clone();
        manager.runtime().spawn(async move {
            let result = client
                .decompile(key.clone(), &input)
                .await
                .map(|o| o.pseudocode)
                .map_err(|e| e.to_string());
            let _ = tx.send((key, result));
        });
    }
}

impl<'a> TabViewer for WindyTabViewer<'a> {
    type Tab = View;

    fn title(&mut self, tab: &mut Self::Tab) -> WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Self::Tab) {
        render_view(ui, tab, self);
    }

    fn scroll_bars(&self, _tab: &Self::Tab) -> [bool; 2] {
        [false, false] // each panel manages its own ScrollArea for better control
    }
}

/// Initial tree layout when a project is first loaded.
pub fn project_tree() -> DockState<View> {
    DockState::new(vec![
        View::FunctionTree,
        View::Disassembly,
        View::Decompiled,
        View::Hex,
        View::Xrefs,
        View::ProjectStatus,
        View::Headers,
        View::Sections,
        View::Imports,
        View::Exports,
        View::Strings,
        View::RichHeader,
        View::Authenticode,
        View::OverlayAnomalies,
        View::Console,
    ])
}

/// Tree layout when no project is loaded yet.
pub fn empty_tree() -> DockState<View> {
    DockState::new(vec![View::Console])
}
