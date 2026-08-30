//! Windy MCP v0.3: six-tool Evidence Query VM surface.
//!
//! The model expresses intent once. Windy binds target state and specialized
//! operations into opaque action tickets, so weak agents do not repeatedly
//! reconstruct nested schemas.

use std::sync::Arc;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde_json::{Value, json};

pub const PUBLIC_TOOL_NAMES: [&str; 6] = [
    "windy_status",
    "investigation_start",
    "investigation_step",
    "evidence_read",
    "change_commit",
    "target_close",
];

pub const INTENTS: [&str; 9] = [
    "locate",
    "explain",
    "trace",
    "verify",
    "read_data",
    "compare",
    "edit",
    "capability",
    "dump",
];

#[derive(Debug)]
pub enum Dispatch {
    Status {
        id: Option<String>,
    },
    Start {
        path: Option<String>,
        target_id: Option<String>,
        intent: String,
        question: String,
        budget: String,
    },
    Step {
        investigation_id: Option<String>,
        action_id: String,
        inputs: JsonObject,
    },
    Read {
        investigation_id: String,
        cursor: String,
        max_bytes: usize,
    },
    Commit {
        proposal_id: String,
        expected_revision: u64,
        idempotency_key: String,
    },
    Close {
        target_id: String,
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
        "windy_status" => (
            "Inspect Windy or one job, target, investigation, or action.",
            object_schema(
                json!({"id":{"type":"string","description":"Optional returned id"}}),
                &[],
            ),
            false,
        ),
        "investigation_start" => (
            "Start a bounded static investigation from a path or open target. Returns evidence and executable next actions.",
            object_schema(
                json!({
                    "path":{"type":"string","description":"Absolute PE or dump path; use path or target_id"},
                    "target_id":{"type":"string","description":"Open target id; use path or target_id"},
                    "intent":{"type":"string","enum":INTENTS},
                    "question":{"type":"string","minLength":1,"maxLength":2048},
                    "budget":{"type":"string","enum":["tiny","normal","deep"],"default":"tiny"}
                }),
                &["intent", "question"],
            ),
            false,
        ),
        "investigation_step" => (
            "Execute one opaque action_id returned by the investigation. Common actions require no inputs.",
            object_schema(
                json!({
                    "investigation_id":{"type":"string","description":"Optional diagnostic scope; action_id is authoritative"},
                    "action_id":{"type":"string"},
                    "inputs":{"type":"object","default":{}}
                }),
                &["action_id"],
            ),
            false,
        ),
        "evidence_read" => (
            "Read the next bounded evidence or artifact delta using a returned cursor.",
            object_schema(
                json!({
                    "investigation_id":{"type":"string"},
                    "cursor":{"type":"string"},
                    "max_bytes":{"type":"integer","minimum":256,"maximum":8192,"default":2048}
                }),
                &["investigation_id", "cursor"],
            ),
            false,
        ),
        "change_commit" => (
            "Commit a verified server-issued change proposal with optimistic revision and idempotency protection.",
            object_schema(
                json!({
                    "proposal_id":{"type":"string"},
                    "expected_revision":{"type":"integer","minimum":0},
                    "idempotency_key":{"type":"string","minLength":8,"maxLength":128}
                }),
                &["proposal_id", "expected_revision", "idempotency_key"],
            ),
            true,
        ),
        "target_close" => (
            "Flush annotations and close one target.",
            object_schema(json!({"target_id":{"type":"string"}}), &["target_id"]),
            true,
        ),
        _ => return None,
    };
    let annotations = ToolAnnotations::with_title(title(name))
        .read_only(!mutable)
        .destructive(false)
        .idempotent(!mutable || name == "change_commit")
        .open_world(false);
    Some(Tool::new(name.to_string(), description, schema).with_annotations(annotations))
}

pub fn dispatch(name: &str, mut arguments: JsonObject) -> Result<Dispatch, String> {
    match name {
        "windy_status" => Ok(Dispatch::Status {
            id: arguments
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }),
        "investigation_start" => {
            let path = optional_string(&arguments, "path")
                .or_else(|| optional_string(&arguments, "target_path"));
            let target_id = optional_string(&arguments, "target_id");
            if path.is_some() == target_id.is_some() {
                return Err("provide exactly one of path or target_id".to_string());
            }
            let raw_intent = optional_string(&arguments, "intent");
            let question = optional_string(&arguments, "question")
                .or_else(|| optional_string(&arguments, "task"))
                .or_else(|| {
                    raw_intent
                        .as_ref()
                        .filter(|value| !INTENTS.contains(&value.as_str()))
                        .cloned()
                })
                .ok_or_else(|| "question is required".to_string())?;
            // Preserve descriptive intent text until the query compiler sees
            // it. `start_investigation` canonicalizes the dispatch intent
            // while retaining useful lexical constraints for sketch ranking.
            let intent = raw_intent.unwrap_or_else(|| infer_intent(&question).to_string());
            if question.len() > 2048 {
                return Err("question exceeds 2048 bytes".to_string());
            }
            let budget = optional_string(&arguments, "budget").unwrap_or_else(|| "tiny".into());
            if !matches!(budget.as_str(), "tiny" | "normal" | "deep") {
                return Err("budget must be tiny, normal, or deep".to_string());
            }
            Ok(Dispatch::Start {
                path,
                target_id,
                intent,
                question,
                budget,
            })
        }
        "investigation_step" => Ok(Dispatch::Step {
            investigation_id: optional_string(&arguments, "investigation_id"),
            action_id: required_string(&arguments, "action_id")?,
            inputs: arguments
                .remove("inputs")
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default(),
        }),
        "evidence_read" => Ok(Dispatch::Read {
            investigation_id: required_string(&arguments, "investigation_id")?,
            cursor: required_string(&arguments, "cursor")?,
            max_bytes: arguments
                .get("max_bytes")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(2048)
                .clamp(256, 8192),
        }),
        "change_commit" => Ok(Dispatch::Commit {
            proposal_id: required_string(&arguments, "proposal_id")?,
            expected_revision: arguments
                .get("expected_revision")
                .and_then(Value::as_u64)
                .ok_or_else(|| "expected_revision is required".to_string())?,
            idempotency_key: required_string(&arguments, "idempotency_key")?,
        }),
        "target_close" => Ok(Dispatch::Close {
            target_id: required_string(&arguments, "target_id")?,
        }),
        _ => Err(format!("unknown MCP v0.3 tool: {name}")),
    }
}

fn infer_intent(question: &str) -> &'static str {
    let question = question.to_ascii_lowercase();
    if question.contains("rename") || question.contains("comment") || question.contains("edit") {
        "edit"
    } else if question.contains("verify")
        || question.contains("claim")
        || question.contains("present")
        || question.contains("absent")
        || question.contains("aes")
    {
        "verify"
    } else if question.contains("linked list")
        || question.contains("pointer")
        || question.contains("struct")
        || question.contains("array")
    {
        "read_data"
    } else if question.contains("explain")
        || question.contains("summarize")
        || question.contains("supported operations")
    {
        "explain"
    } else if question.contains("trace") || question.contains("provenance") {
        "trace"
    } else if question.contains("compare") || question.contains("similar") {
        "compare"
    } else {
        "locate"
    }
}

fn optional_string(arguments: &JsonObject, key: &str) -> Option<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn required_string(arguments: &JsonObject, key: &str) -> Result<String, String> {
    optional_string(arguments, key).ok_or_else(|| format!("{key} is required"))
}

fn object_schema(properties: Value, required: &[&str]) -> Arc<JsonObject> {
    let schema = json!({
        "type":"object",
        "additionalProperties":false,
        "properties":properties,
        "required":required,
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
    fn surface_is_six_tools_and_under_four_kib() {
        let tools = tools();
        assert_eq!(tools.len(), 6);
        assert!(serde_json::to_vec(&tools).unwrap().len() <= 4096);
    }

    #[test]
    fn start_requires_exactly_one_target_source() {
        let args = json!({"intent":"locate","question":"x"})
            .as_object()
            .unwrap()
            .clone();
        assert!(dispatch("investigation_start", args).is_err());
        let args = json!({"path":"C:\\x.exe","target_id":"x","intent":"locate","question":"x"})
            .as_object()
            .unwrap()
            .clone();
        assert!(dispatch("investigation_start", args).is_err());
    }

    #[test]
    fn repairs_common_binding_errors_and_compiles_intent() {
        let args = json!({
            "target_path":"C:\\x.exe",
            "intent":"Find the AES routine or abstain"
        })
        .as_object()
        .unwrap()
        .clone();
        let Dispatch::Start {
            path,
            intent,
            question,
            ..
        } = dispatch("investigation_start", args).unwrap()
        else {
            panic!("start dispatch");
        };
        assert_eq!(path.as_deref(), Some("C:\\x.exe"));
        assert_eq!(intent, "Find the AES routine or abstain");
        assert!(question.contains("AES"));
    }
}
