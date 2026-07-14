use egui::{ScrollArea, Ui};

use crate::project::Project;

pub fn show(ui: &mut Ui, project: &Project, cursor: u64) {
    ui.heading(format!("Xrefs to {:#x}", cursor));

    let xrefs = project.xrefs_to(cursor);
    if xrefs.is_empty() {
        ui.label("No cross-references.");
        return;
    }

    ScrollArea::vertical().show(ui, |ui| {
        for xref in xrefs {
            ui.horizontal(|ui| {
                ui.monospace(format!("{:016x}", xref.from_va));
                ui.label("→");
                ui.monospace(format!("{:016x}", xref.to_va));
                ui.label(format!("{:?}", xref.kind));
            });
        }
    });
}
