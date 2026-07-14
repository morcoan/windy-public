use egui::{ScrollArea, Ui};

use crate::project::Project;

pub fn show(ui: &mut Ui, project: &Project, cursor: &mut u64) {
    ui.heading("Functions");

    let functions: Vec<_> = project
        .functions()
        .iter()
        .map(|f| (f.entry_va, f.name(&project.symbols)))
        .collect();

    ScrollArea::vertical().show(ui, |ui| {
        for (va, name) in functions {
            let label = format!("{:#010x}  {}", va, name);
            if ui.selectable_label(false, label).clicked() {
                *cursor = va;
            }
        }
    });
}
