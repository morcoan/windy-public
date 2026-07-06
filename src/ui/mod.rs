use egui::{Ui, WidgetText};
use egui_dock::{DockState, TabViewer};

use crate::disasm::Disassembler;
use crate::project::Project;
use crate::ui::triage_panels::render_view;
use crate::ui::view::View;

pub mod disasm_view;
pub mod function_tree;
pub mod hex_view;
pub mod triage_panels;
pub mod view;
pub mod xrefs_view;

/// A tab viewer needs to hold mutable borrows of whatever the views need.
pub struct WindyTabViewer<'a> {
    pub project: &'a mut Option<Project>,
    pub console: &'a mut [String],
    pub cursor: &'a mut u64,
    pub disassembler: &'a Disassembler,
}

impl<'a> TabViewer for WindyTabViewer<'a> {
    type Tab = View;

    fn title(&mut self, tab: &mut Self::Tab) -> WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Self::Tab) {
        match self.project {
            Some(project) => render_view(
                ui,
                tab,
                project,
                self.console,
                self.cursor,
                self.disassembler,
            ),
            None => {
                ui.centered_and_justified(|ui| {
                    ui.label("No PE loaded. Use File → Open to get started.");
                });
            }
        }
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
        View::Hex,
        View::Xrefs,
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
