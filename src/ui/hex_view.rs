use egui::{ScrollArea, Ui};

use crate::project::Project;

const BYTES_PER_ROW: usize = 16;
const CHUNK_SIZE: usize = 4096;

pub fn show(ui: &mut Ui, project: &Project, cursor: u64) {
    ui.heading(format!("Hex @ {:#x}", cursor));

    let bytes = match project
        .address_space
        .slice_for_va(&project.pe.image, cursor, CHUNK_SIZE)
    {
        Some(b) => b,
        None => {
            ui.label("No mapped bytes at cursor.");
            return;
        }
    };

    ScrollArea::vertical().show(ui, |ui| {
        for (row, chunk) in bytes.chunks(BYTES_PER_ROW).enumerate() {
            let va = cursor.wrapping_add((row * BYTES_PER_ROW) as u64);
            let mut hex = String::with_capacity(BYTES_PER_ROW * 3);
            let mut ascii = String::with_capacity(BYTES_PER_ROW);
            for b in chunk {
                hex.push_str(&format!("{:02x} ", b));
                ascii.push(if b.is_ascii_graphic() { *b as char } else { '.' });
            }
            ui.monospace(format!("{:016x}  {:48}  {}", va, hex, ascii));
        }
    });
}

/// Short one-line hex for disassembly listing (no spaces between bytes).
pub fn bytes_to_compact_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
