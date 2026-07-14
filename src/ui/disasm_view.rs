use egui::{RichText, ScrollArea, Ui};

use crate::disasm::Disassembler;
use crate::project::Project;
use crate::project::comments::CommentScope;

const WINDOW_SIZE: usize = 250;

pub fn show(ui: &mut Ui, project: &Project, cursor: u64, disassembler: &Disassembler) {
    ui.heading(format!("Disassembly @ {:#x}", cursor));

    if project.analysis.code_index.is_empty() {
        ui.label("No executable code indexed.");
        return;
    }

    ScrollArea::vertical().show(ui, |ui| {
        let window = project.analysis.code_index.window(cursor, WINDOW_SIZE);
        for dec in window {
            let formatted = disassembler.format(&dec.instr);
            ui.horizontal(|ui| {
                ui.monospace(format!("{:016x}", dec.ip));
                ui.monospace(crate::ui::hex_view::bytes_to_compact_hex(dec.bytes_slice()));
                ui.label(formatted);
                if let Some(comment) = project.comments.get(dec.ip, CommentScope::Address) {
                    ui.label(RichText::new(comment).italics());
                }
            });
        }
    });
}
