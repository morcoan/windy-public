use egui::{RichText, ScrollArea, Separator, Ui};
use egui_extras::{Column, TableBuilder};

use crate::project::Project;
use crate::ui::view::View;
use crate::ui::{disasm_view, function_tree, hex_view, xrefs_view};
use crate::ui::WindyTabViewer;

pub fn render_view(ui: &mut Ui, view: &View, viewer: &mut WindyTabViewer<'_>) {
    match viewer.project {
        Some(project) => render_view_for_project(ui, view, viewer, project),
        None => {
            ui.centered_and_justified(|ui| {
                ui.label("No PE loaded. Use File → Open to get started.");
            });
        }
    }
}

fn render_view_for_project(
    ui: &mut Ui,
    view: &View,
    viewer: &mut WindyTabViewer<'_>,
    project: &Project,
) {
    match view {
        // Phase 1 triage panels
        View::Headers => headers_panel(ui, project),
        View::Sections => sections_panel(ui, project),
        View::Imports => imports_panel(ui, project),
        View::Exports => exports_panel(ui, project),
        View::Strings => strings_panel(ui, project),
        View::RichHeader => rich_header_panel(ui, project),
        View::Authenticode => authenticode_panel(ui, project),
        View::OverlayAnomalies => overlay_anomalies_panel(ui, project),
        View::Console => console_panel(ui, viewer.console),

        // Platform-phase code browser panels
        View::FunctionTree => function_tree::show(ui, project, viewer.cursor),
        View::Disassembly => disasm_view::show(ui, project, *viewer.cursor, viewer.disassembler),
        View::Decompiled => viewer.render_decompiled_view(ui, project, *viewer.cursor),
        View::Hex => hex_view::show(ui, project, *viewer.cursor),
        View::Xrefs => xrefs_view::show(ui, project, *viewer.cursor),
        View::ProjectStatus => project_status_panel(ui, project),
    }
}

// ---------------------------------------------------------------------------
// Generic JSON rendering fallbacks. These avoid needing exact petriage field
// knowledge for every sub-struct while still producing useful output.
// ---------------------------------------------------------------------------

fn render_json_value(ui: &mut Ui, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => {
            ui.label(RichText::new("none").italics().weak());
        }
        serde_json::Value::Bool(b) => {
            ui.label(b.to_string());
        }
        serde_json::Value::Number(n) => {
            ui.label(n.to_string());
        }
        serde_json::Value::String(s) => {
            ui.label(s);
        }
        serde_json::Value::Array(arr) => render_json_array(ui, arr),
        serde_json::Value::Object(map) => render_json_object(ui, map),
    }
}

fn render_json_object(ui: &mut Ui, map: &serde_json::Map<String, serde_json::Value>) {
    TableBuilder::new(ui)
        .column(Column::auto().at_least(120.0))
        .column(Column::remainder())
        .striped(true)
        .vertical_scroll_offset(0.0)
        .body(|mut body| {
            for (key, value) in map {
                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        ui.label(RichText::new(key).monospace());
                    });
                    row.col(|ui| {
                        if value.is_object() || value.is_array() {
                            ui.collapsing("+", |ui| render_json_value(ui, value));
                        } else {
                            render_json_value(ui, value);
                        }
                    });
                });
            }
        });
}

fn render_json_array(ui: &mut Ui, arr: &[serde_json::Value]) {
    if arr.is_empty() {
        ui.label("(empty)");
        return;
    }

    // If all entries are objects, render as a table; otherwise as a list.
    if arr.iter().all(|v| v.is_object()) {
        let mut keys: Vec<String> = Vec::new();
        for value in arr {
            if let serde_json::Value::Object(map) = value {
                for k in map.keys() {
                    if !keys.contains(k) {
                        keys.push(k.clone());
                    }
                }
            }
        }

        let rows = arr.len();
        TableBuilder::new(ui)
            .columns(Column::auto(), keys.len())
            .striped(true)
            .vertical_scroll_offset(0.0)
            .header(20.0, |mut header| {
                for key in &keys {
                    header.col(|ui| {
                        ui.heading(key);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, rows, |mut row| {
                    let idx = row.index();
                    let value = &arr[idx];
                    let map = value.as_object().unwrap();
                    for key in &keys {
                    row.col(|ui| {
                        let v = map.get(key).unwrap_or(&serde_json::Value::Null);
                        ui.label(value_summary(v));
                    });
                    }
                });
            });
    } else {
        ScrollArea::vertical().show(ui, |ui| {
            for value in arr {
                render_json_value(ui, value);
            }
        });
    }
}

fn value_summary(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "-".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => format!("[{} items]", arr.len()),
        serde_json::Value::Object(map) => format!("{{{} fields}}", map.len()),
    }
}

fn section_heading(ui: &mut Ui, title: &str) {
    ui.heading(title);
    ui.add(Separator::default().spacing(4.0));
}

// ---------------------------------------------------------------------------
// Panels
// ---------------------------------------------------------------------------

fn headers_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "PE Headers");
    ScrollArea::vertical().show(ui, |ui| {
        for (label, value) in [
            ("File", &serde_json::to_value(&project.pe.triage.file_info).unwrap_or_default()),
            ("DOS Header", &serde_json::to_value(&project.pe.triage.dos_header).unwrap_or_default()),
            ("COFF Header", &serde_json::to_value(&project.pe.triage.coff_header).unwrap_or_default()),
            ("Optional Header", &serde_json::to_value(&project.pe.triage.optional_header).unwrap_or_default()),
        ] {
            ui.collapsing(label, |ui| render_json_value(ui, value));
        }
    });
}

fn sections_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Sections");

    let Some(sections) = &project.pe.triage.sections else {
        ui.label("No section information available.");
        return;
    };

    ScrollArea::both().auto_shrink([false; 2]).show(ui, |ui| {
        TableBuilder::new(ui)
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::remainder().at_least(200.0))
            .striped(true)
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.heading("Name");
                });
                header.col(|ui| {
                    ui.heading("Virtual Address");
                });
                header.col(|ui| {
                    ui.heading("Virtual Size");
                });
                header.col(|ui| {
                    ui.heading("Raw Address");
                });
                header.col(|ui| {
                    ui.heading("Raw Size");
                });
                header.col(|ui| {
                    ui.heading("Entropy");
                });
                header.col(|ui| {
                    ui.heading("Characteristics");
                });
            })
            .body(|body| {
                body.rows(20.0, sections.len(), |mut row| {
                    let s = &sections[row.index()];
                    row.col(|ui| {
                        ui.monospace(&s.name);
                    });
                    row.col(|ui| {
                        ui.label(format!("{:#010x}", s.virtual_address));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:#x}", s.virtual_size));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:#010x}", s.raw_address));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:#x}", s.raw_size));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:.3}", s.entropy));
                    });
                    row.col(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            for c in &s.characteristics_str {
                                ui.label(c);
                            }
                        });
                    });
                });
            });
    });
}

fn imports_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Imports");

    let Some(imports) = &project.pe.triage.imports else {
        ui.label("No imports.");
        return;
    };

    ScrollArea::vertical().show(ui, |ui| {
        for entry in imports {
            ui.collapsing(format!("{} ({} funcs)", entry.dll, entry.functions.len()), |ui| {
                for func in &entry.functions {
                    let risk = func
                        .risk
                        .as_ref()
                        .map(|r| format!(" [{}: {}]", r.category, r.severity))
                        .unwrap_or_default();
                    ui.label(format!("{}{}", func.name, risk));
                }
            });
        }
    });
}

fn exports_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Exports");
    ScrollArea::both().auto_shrink([false; 2]).show(ui, |ui| {
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.export_directory).unwrap_or_default(),
        );
        ui.separator();
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.exports).unwrap_or_default(),
        );
    });
}

fn strings_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Strings");

    let Some(strings) = &project.pe.triage.strings else {
        ui.label("No strings extracted.");
        return;
    };

    ScrollArea::vertical().show(ui, |ui| {
        for s in strings {
            ui.horizontal(|ui| {
                ui.monospace(format!("{:#010x}", s.offset));
                ui.monospace(&s.encoding);
                ui.label(&s.value);
            });
        }
    });
}

fn rich_header_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Rich Header");
    ScrollArea::vertical().show(ui, |ui| {
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.rich_header).unwrap_or_default(),
        );
    });
}

fn authenticode_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Authenticode");
    ScrollArea::vertical().show(ui, |ui| {
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.authenticode).unwrap_or_default(),
        );
    });
}

fn console_panel(ui: &mut Ui, console: &mut [String]) {
    section_heading(ui, "Console");
    ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
        for line in console.iter().rev().take(250) {
            ui.label(line);
        }
    });
}

fn overlay_anomalies_panel(ui: &mut Ui, project: &Project) {
    section_heading(ui, "Overlay & Anomalies");
    ScrollArea::vertical().show(ui, |ui| {
        ui.label("Overlay");
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.overlay).unwrap_or_default(),
        );
        ui.separator();
        ui.label("Suspicious Summary");
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.suspicious_summary).unwrap_or_default(),
        );
        ui.separator();
        ui.label("OPSEC");
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.opsec).unwrap_or_default(),
        );
        ui.separator();
        ui.label("Anomalies");
        render_json_value(
            ui,
            &serde_json::to_value(&project.pe.triage.anomalies).unwrap_or_default(),
        );
    });
}

fn project_status_panel(ui: &mut Ui, project: &Project) {
    ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Project Status");
        ui.separator();

        ui.label(format!("Image: {}", project.pe.path.display()));
        ui.label(format!("SHA256: {}", project.image_sha256));
        ui.label(format!(
            "IDB: {}",
            crate::project::persistence::idb_path(&project.image_sha256).display()
        ));

        ui.separator();
        ui.heading("Analysis");
        ui.label(format!("Functions: {}", project.analysis.functions.len()));
        ui.label(format!("Instructions: {}", project.analysis.code_index.len()));
        ui.label(format!("Symbols: {}", project.symbols.iter().count()));
        ui.label(format!("Stack frames: {}", project.function_frames.len()));
        ui.label(format!(
            "Types: {}",
            project.types.iter_composites().count() + project.types.iter_signatures().count()
        ));

        ui.separator();
        ui.heading("PDB");
        if let Some(err) = &project.pdb_info.error {
            ui.label(format!("PDB error: {err}"));
        } else if project.pdb_info.loaded {
            if let Some(src) = &project.pdb_info.source {
                ui.label(format!("PDB loaded: {}", src.display()));
            } else {
                ui.label("PDB loaded from embedded/bundled symbols");
            }
            ui.label(format!("PDB symbols: {}", project.pdb_info.symbols.len()));
            ui.label(format!("PDB frames: {}", project.pdb_info.frames.len()));
        } else {
            ui.label("No PDB available for this image.");
        }
    });
}
