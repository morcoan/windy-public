//! Interprocedural value provenance (bounded).
//!
//! Walks callers / callees using existing call-site and points-to machinery.
//! Always reports where the chain died rather than guessing through inlining.

use serde::Serialize;
use serde_json::{Value, json};

use crate::analysis::functions::EdgeKind;
use crate::analysis::xrefs::XrefKind;
use crate::project::Project;

const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 48;

#[derive(Clone, Debug, Serialize)]
struct TraceNode {
    function_va: String,
    function_name: String,
    kind: String,
    detail: String,
    confidence: String,
}

/// Trace a value at a site backward (to origin) or forward (to sinks).
///
/// `site` is one of:
/// - register name (`rcx`, `rdx`, …)
/// - stack offset (`-0x10`, `0x20`)
/// - operand string (best-effort match against call-site args)
/// - absolute VA (treated as global / constant source)
pub fn trace_value(
    project: &Project,
    function_va: u64,
    site: &str,
    direction: &str,
    depth: Option<usize>,
) -> Value {
    let depth = depth.unwrap_or(4).clamp(1, MAX_DEPTH);
    let direction = direction.to_ascii_lowercase();
    let backward = direction != "forward";

    let Some(func) = project.function_at(function_va) else {
        return json!({
            "error": "function_not_found",
            "va": format!("{function_va:#x}"),
        });
    };

    let mut nodes = Vec::new();
    let mut died = None::<String>;
    let mut confidence = "exact".to_string();
    let mut visited = std::collections::BTreeSet::new();

    nodes.push(TraceNode {
        function_va: format!("{function_va:#x}"),
        function_name: func.name(&project.symbols),
        kind: "seed".into(),
        detail: format!(
            "site={site} direction={}",
            if backward { "backward" } else { "forward" }
        ),
        confidence: "exact".into(),
    });
    visited.insert(function_va);

    // Local: classify site inside seed function.
    if let Some(local) = classify_local_site(project, function_va, site) {
        nodes.push(local);
    }

    if backward {
        let mut frontier = vec![function_va];
        for d in 0..depth {
            if nodes.len() >= MAX_NODES {
                died = Some("node_cap".into());
                break;
            }
            let mut next_frontier = Vec::new();
            for cur in frontier {
                let callers: Vec<(u64, u64)> = project
                    .xrefs_to(cur)
                    .iter()
                    .filter(|x| x.kind == XrefKind::Call)
                    .filter_map(|x| {
                        let caller_entry = project
                            .analysis
                            .functions
                            .iter()
                            .find(|f| {
                                f.entry_va <= x.from_va
                                    && x.from_va
                                        <= f.blocks.last().map(|b| b.exit_va).unwrap_or(f.entry_va)
                            })
                            .map(|f| f.entry_va)?;
                        Some((caller_entry, x.from_va))
                    })
                    .collect();

                if callers.is_empty() {
                    // Indirect or unknown.
                    if project.xrefs_to(cur).iter().any(|x| {
                        matches!(
                            x.kind,
                            XrefKind::DataRead | XrefKind::DataWrite | XrefKind::Indirect
                        )
                    }) {
                        confidence = "may".into();
                        nodes.push(TraceNode {
                            function_va: format!("{cur:#x}"),
                            function_name: name_of(project, cur),
                            kind: "data_xref".into(),
                            detail: "value may arrive via data reference".into(),
                            confidence: "may".into(),
                        });
                    }
                    continue;
                }

                for (caller_entry, call_site_va) in callers {
                    if !visited.insert(caller_entry) {
                        died = Some("recursion".into());
                        continue;
                    }
                    if project.function_at(caller_entry).is_none() {
                        confidence = "may".into();
                        nodes.push(TraceNode {
                            function_va: format!("{caller_entry:#x}"),
                            function_name: name_of(project, caller_entry),
                            kind: "missing_function".into(),
                            detail: format!(
                                "caller site {call_site_va:#x} — function boundary missing (inlined?)"
                            ),
                            confidence: "may".into(),
                        });
                        died = Some("inlined".into());
                        continue;
                    }

                    let arg_detail = describe_call_args(project, caller_entry, cur);
                    nodes.push(TraceNode {
                        function_va: format!("{caller_entry:#x}"),
                        function_name: name_of(project, caller_entry),
                        kind: "caller".into(),
                        detail: format!("depth={} call_site={call_site_va:#x} {arg_detail}", d + 1),
                        confidence: confidence.clone(),
                    });
                    next_frontier.push(caller_entry);
                    if nodes.len() >= MAX_NODES {
                        break;
                    }
                }
            }
            if next_frontier.is_empty() {
                if died.is_none() {
                    died = Some("origin".into());
                }
                break;
            }
            frontier = next_frontier;
            if d + 1 >= depth {
                died = Some("depth_cap".into());
            }
        }
    } else {
        // Forward: follow call callees and flag known sinks.
        let sinks = [
            "memcpy",
            "memmove",
            "strcpy",
            "strncpy",
            "CreateFileW",
            "CreateFileA",
            "WriteFile",
            "ReadFile",
            "send",
            "recv",
            "WSASend",
            "WSARecv",
            "InternetOpenUrlW",
            "WinHttpSendRequest",
            "RegSetValueExW",
            "ShellExecuteW",
        ];
        let mut frontier = vec![function_va];
        for d in 0..depth {
            if nodes.len() >= MAX_NODES {
                died = Some("node_cap".into());
                break;
            }
            let mut next_frontier = Vec::new();
            for cur in frontier {
                let Some(f) = project.function_at(cur) else {
                    died = Some("inlined".into());
                    continue;
                };
                let mut saw_indirect = false;
                for block in &f.blocks {
                    for edge in &block.successors {
                        if edge.kind != EdgeKind::Call {
                            if edge.kind == EdgeKind::Indirect {
                                saw_indirect = true;
                            }
                            continue;
                        }
                        if edge.target == 0 {
                            saw_indirect = true;
                            continue;
                        }
                        let callee = edge.target;
                        let cname = name_of(project, callee);
                        let is_sink = sinks.iter().any(|s| {
                            cname.eq_ignore_ascii_case(s)
                                || cname
                                    .strip_prefix("__imp_")
                                    .is_some_and(|n| n.eq_ignore_ascii_case(s))
                        });
                        if !visited.insert(callee) {
                            continue;
                        }
                        nodes.push(TraceNode {
                            function_va: format!("{callee:#x}"),
                            function_name: cname.clone(),
                            kind: if is_sink {
                                "sink".into()
                            } else {
                                "callee".into()
                            },
                            detail: format!("depth={}", d + 1),
                            confidence: confidence.clone(),
                        });
                        if is_sink {
                            continue;
                        }
                        if project.function_at(callee).is_some() {
                            next_frontier.push(callee);
                        } else {
                            // Import or unresolved.
                            confidence = "may".into();
                        }
                        if nodes.len() >= MAX_NODES {
                            break;
                        }
                    }
                }
                if saw_indirect {
                    confidence = "may".into();
                    nodes.push(TraceNode {
                        function_va: format!("{cur:#x}"),
                        function_name: name_of(project, cur),
                        kind: "indirect".into(),
                        detail: "indirect call/jump; chain may continue outside recovered CFG"
                            .into(),
                        confidence: "may".into(),
                    });
                    if died.is_none() {
                        died = Some("indirect".into());
                    }
                }
            }
            if next_frontier.is_empty() {
                if died.is_none() {
                    died = Some("sink_or_leaf".into());
                }
                break;
            }
            frontier = next_frontier;
            if d + 1 >= depth {
                died = Some("depth_cap".into());
            }
        }
    }

    json!({
        "function_va": format!("{function_va:#x}"),
        "site": site,
        "direction": if backward { "backward" } else { "forward" },
        "depth_limit": depth,
        "nodes": nodes,
        "count": nodes.len(),
        "confidence": confidence,
        "died": died,
        "cite": {
            "kind": "provenance",
            "va": format!("{function_va:#x}"),
            "site": site,
        },
    })
}

fn name_of(project: &Project, va: u64) -> String {
    project
        .symbols
        .name(va)
        .map(|s| s.to_string())
        .or_else(|| project.function_at(va).map(|f| f.name(&project.symbols)))
        .unwrap_or_else(|| format!("FUN_{va:08x}"))
}

fn classify_local_site(project: &Project, function_va: u64, site: &str) -> Option<TraceNode> {
    let site_l = site.trim().to_ascii_lowercase();
    // Absolute VA?
    if let Ok(va) = parse_hex_or_dec(site) {
        return Some(TraceNode {
            function_va: format!("{function_va:#x}"),
            function_name: name_of(project, function_va),
            kind: "global_or_const".into(),
            detail: format!("literal/global site {va:#x}"),
            confidence: "exact".into(),
        });
    }

    // Stack offset?
    if site_l.starts_with('-')
        || site_l.starts_with("0x")
        || site_l.chars().all(|c| c.is_ascii_digit())
    {
        if let Ok(off) = parse_i64_offset(site) {
            let local_name = project.function_frames.get(&function_va).and_then(|frame| {
                frame
                    .locals
                    .iter()
                    .chain(frame.args.iter())
                    .find(|v| v.offset == off)
                    .and_then(|v| v.name.clone())
            });
            return Some(TraceNode {
                function_va: format!("{function_va:#x}"),
                function_name: name_of(project, function_va),
                kind: "stack".into(),
                detail: format!(
                    "stack_offset={off}{}",
                    local_name.map(|n| format!(" name={n}")).unwrap_or_default()
                ),
                confidence: "exact".into(),
            });
        }
    }

    // Register / operand string — check call sites for matching arg labels.
    if let Some(sites) = project.call_sites_with_args(function_va) {
        let text = sites.to_string().to_ascii_lowercase();
        if text.contains(&site_l) {
            return Some(TraceNode {
                function_va: format!("{function_va:#x}"),
                function_name: name_of(project, function_va),
                kind: "call_site_match".into(),
                detail: format!("site `{site}` appears in call-site argument recovery"),
                confidence: "may".into(),
            });
        }
    }

    // Points-to map mention.
    if let Some(pt) = project.function_points_to_json(function_va) {
        let text = pt.to_string().to_ascii_lowercase();
        if text.contains(&site_l) {
            return Some(TraceNode {
                function_va: format!("{function_va:#x}"),
                function_name: name_of(project, function_va),
                kind: "points_to".into(),
                detail: format!("site `{site}` appears in points-to summary"),
                confidence: "may".into(),
            });
        }
    }

    Some(TraceNode {
        function_va: format!("{function_va:#x}"),
        function_name: name_of(project, function_va),
        kind: "unclassified_site".into(),
        detail: format!("no local classification for `{site}`; tracing call graph only"),
        confidence: "may".into(),
    })
}

fn describe_call_args(project: &Project, caller_va: u64, callee_va: u64) -> String {
    let Some(sites) = project.call_sites_with_args(caller_va) else {
        return "args=unknown".into();
    };
    let callee_hex = format!("{callee_va:#x}");
    let callee_name = name_of(project, callee_va);
    if let Some(arr) = sites.get("sites").and_then(|v| v.as_array()) {
        for site in arr {
            let dest = site
                .get("callee")
                .or_else(|| site.get("callee_va"))
                .or_else(|| site.get("target"))
                .map(|v| v.to_string())
                .unwrap_or_default();
            if dest.contains(&callee_hex) || dest.contains(&callee_name) {
                if let Some(args) = site.get("args") {
                    return format!("args={args}");
                }
            }
        }
    }
    // Fallback: dump truncated JSON.
    let s = sites.to_string();
    if s.len() > 180 {
        format!("call_sites~={}", &s[..180])
    } else {
        format!("call_sites={s}")
    }
}

fn parse_hex_or_dec(s: &str) -> Result<u64, ()> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        t.parse::<u64>().map_err(|_| ())
    }
}

fn parse_i64_offset(s: &str) -> Result<i64, ()> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("-0x").or_else(|| t.strip_prefix("-0X")) {
        let v = i64::from_str_radix(hex, 16).map_err(|_| ())?;
        Ok(-v)
    } else if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        t.parse::<i64>().map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_offsets() {
        assert_eq!(parse_i64_offset("-0x10").unwrap(), -0x10);
        assert_eq!(parse_i64_offset("-16").unwrap(), -16);
        assert_eq!(parse_hex_or_dec("0x140001000").unwrap(), 0x140001000);
    }
}
