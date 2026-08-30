//! Compact, agent-first MCP v2 surface.
//!
//! The analysis backend still has many focused operations, but only this
//! small stable set is advertised. Rare operations are retrieved through the
//! capability registry and invoked with `capability_execute`.

use std::sync::Arc;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde_json::{Value, json};

pub const PUBLIC_TOOL_NAMES: [&str; 12] = [
    "server_status",
    "target_open",
    "target_close",
    "target_triage",
    "evidence_search",
    "function_inspect",
    "data_read",
    "claim_verify",
    "project_edit",
    "artifact_read",
    "capability_search",
    "capability_execute",
];

pub enum Dispatch {
    Status {
        job_id: Option<String>,
    },
    Open {
        path: String,
    },
    Legacy {
        name: String,
        arguments: JsonObject,
    },
    Close {
        target_id: String,
    },
    ArtifactRead {
        artifact_id: String,
        offset: usize,
        max_bytes: usize,
    },
    CapabilitySearch {
        query: String,
        limit: usize,
    },
    CapabilityExecute {
        capability_id: String,
        arguments: JsonObject,
    },
}

pub fn is_public(name: &str) -> bool {
    PUBLIC_TOOL_NAMES.contains(&name)
}

pub fn tools() -> Vec<Tool> {
    PUBLIC_TOOL_NAMES.into_iter().filter_map(tool).collect()
}

pub fn tool(name: &str) -> Option<Tool> {
    let (description, schema, mutable) = match name {
        "server_status" => (
            "Read server, target, job, cache, memory, and request statistics.",
            object_schema(
                json!({"job_id":{"type":"string", "description":"Optional open-job id"}}),
                &[],
            ),
            false,
        ),
        "target_open" => (
            "Open a PE or user-mode minidump analysis target. Targets are never opened implicitly.",
            object_schema(
                json!({
                    "path": {"type":"string", "description":"Absolute .exe/.dll/.sys/.dmp path"}
                }),
                &["path"],
            ),
            true,
        ),
        "target_close" => (
            "Flush annotations and close one PE, dump, module, or workspace target.",
            target_schema(),
            true,
        ),
        "target_triage" => (
            "Return the highest-value first-minute functions and evidence for a target.",
            object_schema(
                json!({
                    "target_id": string_prop("Open target id"),
                    "limit": {"type":"integer", "minimum":1, "maximum":64, "default":8}
                }),
                &["target_id"],
            ),
            false,
        ),
        "evidence_search" => (
            "Search symbols, strings, APIs, relationships, motifs, and ontology evidence.",
            object_schema(
                json!({
                    "target_id": string_prop("Open target id"),
                    "query": {"type":"string"},
                    "mode": {"type":"string", "enum":["auto","exact","prefix","substring","numeric","regex","token","relationship","motif","ontology","multi_evidence"], "default":"auto"},
                    "evidence": {"type":"array", "items":{"type":"string"}, "maxItems":8},
                    "quorum": {"type":["integer","null"], "minimum":1, "maximum":8},
                    "relationship_depth": {"type":"integer", "minimum":0, "maximum":4, "default":1},
                    "kinds": {"type":"array", "items":{"type":"string"}, "maxItems":8},
                    "limit": {"type":"integer", "minimum":1, "maximum":64, "default":8},
                    "cursor": {"type":["string","null"]},
                    "deadline_ms": {"type":"integer", "minimum":1, "maximum":120000, "default":2000}
                }),
                &["target_id", "query"],
            ),
            false,
        ),
        "function_inspect" => (
            "Return a budgeted Evidence Card v2 for one function; request expanded text explicitly.",
            object_schema(
                json!({
                    "target_id": string_prop("Open target id"),
                    "va": string_prop("Function VA as 0x..."),
                    "max_items": {"type":"integer", "minimum":1, "maximum":64, "default":8},
                    "include_agent_text": {"type":"boolean", "default":false},
                    "max_agent_instructions": {"type":"integer", "minimum":1, "maximum":4096, "default":64},
                    "max_output_bytes": {"type":"integer", "minimum":512, "maximum":65536, "default":4096}
                }),
                &["target_id", "va"],
            ),
            false,
        ),
        "data_read" => (
            "Read resolved addresses, bounded bytes, pointers, structures, arrays, or linked lists.",
            object_schema(
                json!({
                    "target_id": string_prop("Open target id"),
                    "operation": {"type":"string", "enum":["describe","bytes","pointers","struct_array","list"]},
                    "va": string_prop("Address as 0x..."),
                    "head_va": string_prop("List head as 0x..."),
                    "len": {"type":"integer", "minimum":1, "maximum":512},
                    "count": {"type":"integer", "minimum":1, "maximum":256},
                    "stride": {"type":"integer", "minimum":1},
                    "next_offset": {"type":"integer", "minimum":0},
                    "max_nodes": {"type":"integer", "minimum":1, "maximum":128},
                    "fields": {"type":"array", "items":{"type":"object"}, "maxItems":32}
                }),
                &["target_id", "operation"],
            ),
            false,
        ),
        "claim_verify" => (
            "Check machine-verifiable claims against static evidence and report unknown honestly.",
            object_schema(
                json!({
                    "target_id": string_prop("Open target id"),
                    "claims": {"type":"array", "items":{"type":"object"}, "minItems":1, "maxItems":64}
                }),
                &["target_id", "claims"],
            ),
            false,
        ),
        "project_edit" => (
            "Apply an idempotent, revision-checked batch of names, types, comments, or memory edits.",
            object_schema(
                json!({
                    "target_id": string_prop("Open target id"),
                    "function_va": string_prop("Owning function VA as 0x..."),
                    "idempotency_key": {"type":"string", "minLength":8, "maxLength":128},
                    "expected_revision": {"type":"integer", "minimum":0},
                    "dry_run": {"type":"boolean", "default":false},
                    "renames": {"type":"array", "items":{"type":"object"}, "minItems":1, "maxItems":128},
                    "evidence": {"type":"array", "items":{"type":"string"}, "maxItems":32}
                }),
                &[
                    "target_id",
                    "function_va",
                    "idempotency_key",
                    "expected_revision",
                    "renames",
                ],
            ),
            true,
        ),
        "artifact_read" => (
            "Read one bounded page from an immutable oversized result artifact.",
            object_schema(
                json!({
                    "artifact_id": {"type":"string"},
                    "offset": {"type":"integer", "minimum":0, "default":0},
                    "max_bytes": {"type":"integer", "minimum":512, "maximum":65536, "default":4096}
                }),
                &["artifact_id"],
            ),
            false,
        ),
        "capability_search" => (
            "Retrieve the most relevant specialized analysis operations without advertising every schema.",
            object_schema(
                json!({
                    "query": {"type":"string"},
                    "limit": {"type":"integer", "minimum":1, "maximum":8, "default":5}
                }),
                &["query"],
            ),
            false,
        ),
        "capability_execute" => (
            "Execute one specialized operation returned by capability_search with server-side schema validation.",
            object_schema(
                json!({
                    "capability_id": {"type":"string"},
                    "arguments": {"type":"object"},
                    "max_output_bytes": {"type":"integer", "minimum":512, "maximum":65536, "default":4096}
                }),
                &["capability_id", "arguments"],
            ),
            true,
        ),
        _ => return None,
    };
    let annotations = ToolAnnotations::with_title(title(name))
        .read_only(!mutable)
        .destructive(false)
        .idempotent(!mutable || name == "project_edit")
        .open_world(false);
    Some(Tool::new(name.to_string(), description, schema).with_annotations(annotations))
}

pub fn dispatch(name: &str, mut arguments: JsonObject) -> Result<Dispatch, String> {
    let target_id = || {
        arguments
            .get("target_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "target_id is required".to_string())
    };
    match name {
        "server_status" => Ok(Dispatch::Status {
            job_id: arguments
                .get("job_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }),
        "target_open" => Ok(Dispatch::Open {
            path: required_string(&arguments, "path")?,
        }),
        "target_close" => Ok(Dispatch::Close {
            target_id: target_id()?,
        }),
        "target_triage" => {
            rename_target(&mut arguments)?;
            arguments.entry("limit").or_insert(json!(8));
            Ok(legacy("get_triage", arguments))
        }
        "evidence_search" => {
            rename_target(&mut arguments)?;
            arguments.entry("limit").or_insert(json!(8));
            arguments.entry("deadline_ms").or_insert(json!(2000));
            Ok(legacy("search_bel", arguments))
        }
        "function_inspect" => {
            rename_target(&mut arguments)?;
            arguments.remove("max_output_bytes");
            arguments.entry("max_items").or_insert(json!(8));
            Ok(legacy("get_function_evidence", arguments))
        }
        "data_read" => dispatch_data_read(arguments),
        "claim_verify" => {
            rename_target(&mut arguments)?;
            Ok(legacy("verify_claims", arguments))
        }
        "project_edit" => {
            rename_target(&mut arguments)?;
            arguments.remove("idempotency_key");
            arguments.remove("expected_revision");
            Ok(legacy("apply_rename_batch", arguments))
        }
        "artifact_read" => Ok(Dispatch::ArtifactRead {
            artifact_id: required_string(&arguments, "artifact_id")?,
            offset: optional_usize(&arguments, "offset", 0),
            max_bytes: optional_usize(&arguments, "max_bytes", 4096).clamp(512, 65_536),
        }),
        "capability_search" => Ok(Dispatch::CapabilitySearch {
            query: required_string(&arguments, "query")?,
            limit: optional_usize(&arguments, "limit", 5).clamp(1, 8),
        }),
        "capability_execute" => {
            let capability_id = required_string(&arguments, "capability_id")?;
            let mut nested = arguments
                .remove("arguments")
                .and_then(|value| value.as_object().cloned())
                .ok_or_else(|| "arguments must be an object".to_string())?;
            if nested.contains_key("target_id") && !nested.contains_key("project_id") {
                rename_target(&mut nested)?;
            }
            Ok(Dispatch::CapabilityExecute {
                capability_id,
                arguments: nested,
            })
        }
        _ => Err(format!("unknown MCP v2 tool: {name}")),
    }
}

fn dispatch_data_read(mut arguments: JsonObject) -> Result<Dispatch, String> {
    let operation = required_string(&arguments, "operation")?;
    arguments.remove("operation");
    rename_target(&mut arguments)?;
    let name = match operation.as_str() {
        "describe" => "describe_address",
        "bytes" => "read_va",
        "pointers" => "read_pointers",
        "struct_array" => "read_struct_array",
        "list" => {
            if !arguments.contains_key("head_va") {
                return Err("head_va is required for list".to_string());
            }
            "walk_list"
        }
        _ => return Err(format!("unsupported data_read operation: {operation}")),
    };
    Ok(legacy(name, arguments))
}

fn legacy(name: &str, arguments: JsonObject) -> Dispatch {
    Dispatch::Legacy {
        name: name.to_string(),
        arguments,
    }
}

fn rename_target(arguments: &mut JsonObject) -> Result<(), String> {
    let target = arguments
        .remove("target_id")
        .ok_or_else(|| "target_id is required".to_string())?;
    arguments.insert("project_id".to_string(), target);
    Ok(())
}

fn required_string(arguments: &JsonObject, key: &str) -> Result<String, String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} is required"))
}

fn optional_usize(arguments: &JsonObject, key: &str, default: usize) -> usize {
    arguments
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
}

fn target_schema() -> Arc<JsonObject> {
    object_schema(
        json!({"target_id": string_prop("Open target id")}),
        &["target_id"],
    )
}

fn string_prop(description: &str) -> Value {
    json!({"type":"string", "description":description})
}

fn object_schema(properties: Value, required: &[&str]) -> Arc<JsonObject> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    });
    Arc::new(schema.as_object().cloned().expect("schema object"))
}

fn title(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + chars.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_surface_has_exactly_twelve_tools_and_stays_small() {
        let tools = tools();
        assert_eq!(tools.len(), 12);
        let encoded = serde_json::to_vec(&tools).unwrap();
        assert!(
            encoded.len() <= 12 * 1024,
            "v2 tool surface is {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn direct_legacy_names_are_not_public() {
        assert!(!is_public("open_project"));
        assert!(is_public("target_open"));
    }
}
