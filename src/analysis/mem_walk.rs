//! Structured bulk memory reads for agents.
//!
//! Python agents win with `struct.unpack` walks; Windy wins by *resolving*
//! each slot (function / import / string / pointer target) instead of returning
//! raw hex. Bounds are element/node counts with cycle detection — not a byte dump.

use serde::Serialize;
use serde_json::{Value, json};

use crate::analysis::indirect::read_pointer_at;
use crate::llm::query::try_read_string_at_va;
use crate::project::Project;
use crate::project::symbols::SymbolKind;

/// Hard caps (token budgets, not PE size).
pub const MAX_POINTER_COUNT: usize = 256;
pub const MAX_WALK_NODES: usize = 128;
pub const MAX_STRUCT_ARRAY: usize = 64;
pub const MAX_FIELDS_PER_NODE: usize = 16;

/// One resolved pointer slot.
#[derive(Clone, Debug, Serialize)]
pub struct ResolvedPointer {
    pub slot_va: String,
    pub value: String,
    pub resolved: Value,
}

/// Field layout for [`walk_list`] / [`read_struct_array`].
#[derive(Clone, Debug)]
pub struct FieldSpec {
    pub name: String,
    pub offset: u64,
    /// `ptr` | `u32` | `u64` | `i32` | `i64` | `string` | `bytes`
    pub kind: String,
    pub size: Option<usize>,
}

/// Promote a raw pointer value through Windy's analysis layer.
pub fn resolve_value(project: &Project, va: u64) -> Value {
    if va == 0 {
        return json!({ "kind": "null" });
    }
    let mut out = json!({
        "kind": "pointer",
        "va": format!("{va:#x}"),
    });
    let map = out.as_object_mut().expect("object");

    if let Some(name) = project.symbols.name(va) {
        let kind = project
            .symbols
            .get(va)
            .map(|s| format!("{:?}", s.kind).to_ascii_lowercase())
            .unwrap_or_else(|| "symbol".into());
        map.insert("symbol".into(), json!(name));
        map.insert("symbol_kind".into(), json!(kind));
        if name.starts_with("__imp_") {
            map.insert(
                "import".into(),
                json!(name.strip_prefix("__imp_").unwrap_or(name)),
            );
            map.insert("kind".into(), json!("import"));
        }
    }

    if let Some(func) = project.function_at(va) {
        map.insert("kind".into(), json!("function"));
        map.insert("function".into(), json!(func.name(&project.symbols)));
        map.insert("entry_va".into(), json!(format!("{:#x}", func.entry_va)));
        map.insert("size".into(), json!(func.size()));
    } else if project.address_space.is_executable_va(va) {
        map.insert("kind".into(), json!("code"));
    }

    if let Some(sref) = try_read_string_at_va(&project.pe.image, &project.address_space, va, 2) {
        // Prefer string label when the VA is not a known function/import.
        if map.get("kind").and_then(|k| k.as_str()) == Some("pointer")
            || map.get("kind").and_then(|k| k.as_str()) == Some("code")
                && !map.contains_key("function")
        {
            map.insert("kind".into(), json!("string"));
        }
        map.insert(
            "string".into(),
            json!({
                "value": sref.value,
                "encoding": sref.encoding,
            }),
        );
    }

    if let Some(section) = section_name_at(project, va) {
        map.insert("section".into(), json!(section));
    }

    // One-level target peek for data pointers that look like tables.
    if map.get("kind").and_then(|k| k.as_str()) == Some("pointer") {
        let ptr_size = (project.bitness / 8) as usize;
        let inner = read_pointer_at(&project.address_space, &project.pe.image, va, ptr_size);
        if inner != 0 && project.address_space.is_valid_va(inner) {
            map.insert("points_to".into(), resolve_value_shallow(project, inner));
        }
    }

    out
}

fn resolve_value_shallow(project: &Project, va: u64) -> Value {
    if va == 0 {
        return json!({ "kind": "null" });
    }
    let mut map = serde_json::Map::new();
    map.insert("va".into(), json!(format!("{va:#x}")));
    if let Some(name) = project.symbols.name(va) {
        map.insert("symbol".into(), json!(name));
        if name.starts_with("__imp_") {
            map.insert("kind".into(), json!("import"));
            map.insert(
                "import".into(),
                json!(name.strip_prefix("__imp_").unwrap_or(name)),
            );
            return Value::Object(map);
        }
    }
    if let Some(func) = project.function_at(va) {
        map.insert("kind".into(), json!("function"));
        map.insert("function".into(), json!(func.name(&project.symbols)));
        return Value::Object(map);
    }
    if let Some(sref) = try_read_string_at_va(&project.pe.image, &project.address_space, va, 2) {
        map.insert("kind".into(), json!("string"));
        map.insert("string".into(), json!(sref.value));
        return Value::Object(map);
    }
    map.insert("kind".into(), json!("pointer"));
    Value::Object(map)
}

fn section_name_at(project: &Project, va: u64) -> Option<String> {
    let section = project.address_space.section_at_va(va)?;
    let rva = va.saturating_sub(project.address_space.image_base) as u32;
    // Match triage section metadata by RVA when names are available.
    if let Some(triage) = project.pe.triage.sections.as_ref() {
        for s in triage.iter() {
            let start = s.virtual_address;
            let end = start.saturating_add(s.virtual_size.max(1));
            if rva >= start && rva < end {
                return Some(s.name.clone());
            }
        }
    }
    Some(format!("sect_{:x}", section.vaddr))
}

/// Read `count` pointers starting at `va` with optional `stride` (default: ptr size).
pub fn read_pointers(project: &Project, va: u64, count: usize, stride: Option<u64>) -> Value {
    let count = count.clamp(1, MAX_POINTER_COUNT);
    let ptr_size = (project.bitness / 8) as usize;
    let stride = stride.unwrap_or(ptr_size as u64).max(1);
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let slot = va.saturating_add(i as u64 * stride);
        if !project.address_space.is_valid_va(slot) {
            break;
        }
        let value = read_pointer_at(&project.address_space, &project.pe.image, slot, ptr_size);
        entries.push(ResolvedPointer {
            slot_va: format!("{slot:#x}"),
            value: format!("{value:#x}"),
            resolved: if value != 0 && project.address_space.is_valid_va(value) {
                resolve_value(project, value)
            } else if value == 0 {
                json!({ "kind": "null" })
            } else {
                json!({ "kind": "unmapped", "va": format!("{value:#x}") })
            },
        });
    }
    json!({
        "va": format!("{va:#x}"),
        "count": entries.len(),
        "stride": stride,
        "ptr_size": ptr_size,
        "entries": entries,
        "cite": { "kind": "data", "va": format!("{va:#x}") },
    })
}

/// Walk a singly-linked list: `head_va` → node, `next` at `next_offset`.
pub fn walk_list(
    project: &Project,
    head_va: u64,
    next_offset: u64,
    max_nodes: usize,
    fields: &[FieldSpec],
) -> Value {
    let max_nodes = max_nodes.clamp(1, MAX_WALK_NODES);
    let ptr_size = (project.bitness / 8) as usize;
    let mut nodes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut cur = head_va;
    let mut died = None::<&'static str>;

    for _ in 0..max_nodes {
        if cur == 0 {
            died = Some("null");
            break;
        }
        if !project.address_space.is_valid_va(cur) {
            died = Some("unmapped");
            break;
        }
        if !seen.insert(cur) {
            died = Some("cycle");
            break;
        }

        let mut node = json!({
            "va": format!("{cur:#x}"),
            "fields": {},
        });
        let field_map = node
            .get_mut("fields")
            .and_then(|v| v.as_object_mut())
            .expect("fields object");

        for field in fields.iter().take(MAX_FIELDS_PER_NODE) {
            let fva = cur.saturating_add(field.offset);
            field_map.insert(
                field.name.clone(),
                decode_field(project, fva, &field.kind, field.size, ptr_size),
            );
        }

        // Always surface next pointer for transparency.
        let next_va = cur.saturating_add(next_offset);
        let next = read_pointer_at(&project.address_space, &project.pe.image, next_va, ptr_size);
        node.as_object_mut()
            .expect("node")
            .insert("next".into(), json!(format!("{next:#x}")));
        nodes.push(node);
        cur = next;
    }

    if died.is_none() && cur != 0 && nodes.len() >= max_nodes {
        died = Some("node_cap");
    }

    json!({
        "head_va": format!("{head_va:#x}"),
        "next_offset": next_offset,
        "nodes": nodes,
        "count": nodes.len(),
        "died": died,
        "cite": { "kind": "data", "va": format!("{head_va:#x}") },
    })
}

/// Decode an array of structs with an explicit field layout.
pub fn read_struct_array(
    project: &Project,
    va: u64,
    stride: u64,
    count: usize,
    fields: &[FieldSpec],
) -> Value {
    let count = count.clamp(1, MAX_STRUCT_ARRAY);
    let stride = stride.max(1);
    let ptr_size = (project.bitness / 8) as usize;
    let mut items = Vec::with_capacity(count);

    for i in 0..count {
        let base = va.saturating_add(i as u64 * stride);
        if !project.address_space.is_valid_va(base) {
            break;
        }
        let mut fields_json = serde_json::Map::new();
        for field in fields.iter().take(MAX_FIELDS_PER_NODE) {
            let fva = base.saturating_add(field.offset);
            fields_json.insert(
                field.name.clone(),
                decode_field(project, fva, &field.kind, field.size, ptr_size),
            );
        }
        items.push(json!({
            "index": i,
            "va": format!("{base:#x}"),
            "fields": fields_json,
        }));
    }

    json!({
        "va": format!("{va:#x}"),
        "stride": stride,
        "count": items.len(),
        "items": items,
        "cite": { "kind": "data", "va": format!("{va:#x}") },
    })
}

fn decode_field(
    project: &Project,
    va: u64,
    kind: &str,
    size: Option<usize>,
    ptr_size: usize,
) -> Value {
    if !project.address_space.is_valid_va(va) {
        return json!({ "error": "unmapped", "va": format!("{va:#x}") });
    }
    match kind {
        "ptr" | "pointer" => {
            let value = read_pointer_at(&project.address_space, &project.pe.image, va, ptr_size);
            json!({
                "raw": format!("{value:#x}"),
                "resolved": if value != 0 && project.address_space.is_valid_va(value) {
                    resolve_value(project, value)
                } else if value == 0 {
                    json!({ "kind": "null" })
                } else {
                    json!({ "kind": "unmapped", "va": format!("{value:#x}") })
                },
            })
        }
        "string" => {
            // Treat field as pointer-to-string first; fall back to inline.
            let value = read_pointer_at(&project.address_space, &project.pe.image, va, ptr_size);
            if value != 0
                && let Some(sref) =
                    try_read_string_at_va(&project.pe.image, &project.address_space, value, 1)
            {
                return json!({
                    "ptr": format!("{value:#x}"),
                    "value": sref.value,
                    "encoding": sref.encoding,
                });
            }
            if let Some(sref) =
                try_read_string_at_va(&project.pe.image, &project.address_space, va, 1)
            {
                return json!({
                    "inline": true,
                    "value": sref.value,
                    "encoding": sref.encoding,
                });
            }
            json!({ "raw_ptr": format!("{value:#x}"), "string": null })
        }
        "u32" => {
            let bytes = project
                .address_space
                .slice_for_va(&project.pe.image, va, 4)
                .unwrap_or_default();
            let v = if bytes.len() >= 4 {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            } else {
                0
            };
            json!(v)
        }
        "u64" => {
            let bytes = project
                .address_space
                .slice_for_va(&project.pe.image, va, 8)
                .unwrap_or_default();
            let v = if bytes.len() >= 8 {
                u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            } else {
                0
            };
            json!(format!("{v:#x}"))
        }
        "i32" => {
            let bytes = project
                .address_space
                .slice_for_va(&project.pe.image, va, 4)
                .unwrap_or_default();
            let v = if bytes.len() >= 4 {
                i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            } else {
                0
            };
            json!(v)
        }
        "i64" => {
            let bytes = project
                .address_space
                .slice_for_va(&project.pe.image, va, 8)
                .unwrap_or_default();
            let v = if bytes.len() >= 8 {
                i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            } else {
                0
            };
            json!(v)
        }
        "bytes" => {
            let len = size.unwrap_or(8).clamp(1, 64);
            let bytes = project
                .address_space
                .slice_for_va(&project.pe.image, va, len)
                .unwrap_or_default();
            let hex: String = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            json!({ "len": bytes.len(), "hex": hex })
        }
        other => json!({ "error": format!("unknown field kind '{other}'") }),
    }
}

/// Classify a VA: section, symbol, function, string, or pointer target.
pub fn describe_address(project: &Project, va: u64) -> Value {
    let mut out = json!({
        "va": format!("{va:#x}"),
        "mapped": project.address_space.is_valid_va(va),
        "executable": project.address_space.is_executable_va(va),
    });
    let map = out.as_object_mut().expect("object");

    if let Some(section) = section_name_at(project, va) {
        map.insert("section".into(), json!(section));
    }
    if let Some(name) = project.symbols.name(va) {
        map.insert("symbol".into(), json!(name));
        if let Some(sym) = project.symbols.get(va) {
            map.insert(
                "symbol_kind".into(),
                json!(format!("{:?}", sym.kind).to_ascii_lowercase()),
            );
            if sym.kind == SymbolKind::Import || name.starts_with("__imp_") {
                map.insert(
                    "import".into(),
                    json!(name.strip_prefix("__imp_").unwrap_or(name)),
                );
            }
        }
    }
    if let Some(func) = project.function_at(va) {
        map.insert(
            "function".into(),
            json!({
                "name": func.name(&project.symbols),
                "entry_va": format!("{:#x}", func.entry_va),
                "size": func.size(),
            }),
        );
    } else if let Some(func) = containing_function(project, va) {
        map.insert(
            "containing_function".into(),
            json!({
                "name": func.name(&project.symbols),
                "entry_va": format!("{:#x}", func.entry_va),
                "offset": va.saturating_sub(func.entry_va),
            }),
        );
    }
    if let Some(sref) = try_read_string_at_va(&project.pe.image, &project.address_space, va, 2) {
        map.insert(
            "string".into(),
            json!({ "value": sref.value, "encoding": sref.encoding }),
        );
    }

    let ptr_size = (project.bitness / 8) as usize;
    if project.address_space.is_valid_va(va) && !project.address_space.is_executable_va(va) {
        let value = read_pointer_at(&project.address_space, &project.pe.image, va, ptr_size);
        if value != 0 && project.address_space.is_valid_va(value) {
            map.insert(
                "as_pointer".into(),
                json!({
                    "value": format!("{value:#x}"),
                    "resolved": resolve_value_shallow(project, value),
                }),
            );
        }
    }

    map.insert(
        "cite".into(),
        json!({ "kind": "address", "va": format!("{va:#x}") }),
    );
    out
}

fn containing_function(
    project: &Project,
    va: u64,
) -> Option<&crate::analysis::functions::Function> {
    project.analysis.functions.iter().find(|f| {
        f.entry_va <= va && va <= f.blocks.last().map(|b| b.exit_va).unwrap_or(f.entry_va)
    })
}

#[cfg(test)]
mod tests {
    use crate::analysis::indirect::read_pointer;
    use crate::loader::address_space::{AddressSpace, Section};

    #[test]
    fn read_pointer_at_slot() {
        let mut image = vec![0u8; 0x100];
        image[0x10..0x18].copy_from_slice(&0xABCD_EF01_2345_6789u64.to_le_bytes());
        let space = AddressSpace {
            image_base: 0x1000,
            sections: vec![Section {
                vaddr: 0,
                vsize: 0x100,
                raw_addr: 0,
                raw_size: 0x100,
                characteristics: 0x4000_0000,
            }],
        };
        let p = read_pointer(&space, &image, 0x1010, 8);
        assert_eq!(p, 0xABCD_EF01_2345_6789);
    }

    #[test]
    fn cycle_detection_on_self_loop() {
        let mut image = vec![0u8; 0x100];
        image[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        let space = AddressSpace {
            image_base: 0x1000,
            sections: vec![Section {
                vaddr: 0,
                vsize: 0x100,
                raw_addr: 0,
                raw_size: 0x100,
                characteristics: 0x4000_0000,
            }],
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut cur = 0x1000u64;
        let mut died = None;
        for _ in 0..8 {
            if !seen.insert(cur) {
                died = Some("cycle");
                break;
            }
            cur = read_pointer(&space, &image, cur, 8);
        }
        assert_eq!(died, Some("cycle"));
    }
}
