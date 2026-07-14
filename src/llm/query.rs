//! Token-efficient, tool-like queries an LLM can issue against a Project. All
//! methods return compact text or JSON; they never dump the whole image.
// Individual pub items used only by MCP/external agents are allowed below.

use std::collections::HashSet;

use iced_x86::{FlowControl, Instruction, InstructionInfoFactory, Register};
use serde::Serialize;

use crate::analysis::functions::Function;
use crate::analysis::search::SearchHit;
use crate::analysis::xrefs::XrefKind;
use crate::ir::export::FunctionExport;
use crate::project::Project;
use crate::project::symbols::SymbolTable;

/// Compact function summary for LLM consumption. Much smaller than a full
/// [`FunctionExport`] while still providing everything needed to decide whether
/// to ask for the full decompilation.
#[derive(Serialize, Debug, Clone)]
pub struct FunctionSummary {
    pub name: String,
    pub va: u64,
    pub size: u64,
    pub blocks: usize,
    pub instructions: usize,
    pub has_pdb_frame: bool,
    pub callers: Vec<String>,
    pub callees: Vec<String>,
}

/// Max results returned by listing queries to keep token usage bounded.
const MAX_LIST: usize = 32;

/// Summarize a function at a given VA.
pub fn function_summary(project: &Project, va: u64) -> Option<FunctionSummary> {
    let func = project.function_at(va)?;
    let names = &project.symbols;
    Some(FunctionSummary {
        name: func.name(names),
        va: func.entry_va,
        size: func.size(),
        blocks: func.blocks.len(),
        instructions: func.blocks.iter().map(|block| block.instr_count).sum(),
        has_pdb_frame: func.stack_frame.is_some(),
        callers: caller_names(project, func, names),
        callees: callee_names(project, func, names),
    })
}

/// Compact report of the optimized SSA: op counts before/after and the
/// simplification breakdown. Read-only, token-bounded.
#[derive(Serialize, Debug, Clone)]
pub struct SsaOptimizedSummary {
    pub va: u64,
    pub op_count_before: usize,
    pub op_count_after: usize,
    pub copies_propagated: usize,
    pub constants_propagated: usize,
    pub phis_collapsed: usize,
    pub dead_ops_removed: usize,
    pub constants: Vec<SsaConstantCard>,
    pub suggestions: Vec<SsaSuggestionCard>,
}

#[derive(Serialize, Debug, Clone)]
pub struct SsaConstantCard {
    pub va: String,
    pub value: String,
    pub size: u32,
}

#[derive(Serialize, Debug, Clone)]
pub struct SsaSuggestionCard {
    pub va: String,
    pub comment: String,
}

/// Summary of `function_ssa_optimized` for agents.
pub fn function_ssa_optimized_summary(project: &Project, va: u64) -> Option<SsaOptimizedSummary> {
    let (_, analysis) = project.function_ssa_optimized(va)?;
    let suggestions = project.function_ssa_suggestions(va).unwrap_or_default();
    Some(SsaOptimizedSummary {
        va,
        op_count_before: analysis.op_count_before,
        op_count_after: analysis.op_count_after,
        copies_propagated: analysis.copies_propagated,
        constants_propagated: analysis.constants_propagated,
        phis_collapsed: analysis.phis_collapsed,
        dead_ops_removed: analysis.dead_ops_removed,
        constants: analysis
            .constants
            .iter()
            .filter(|c| c.va != 0)
            .map(|c| SsaConstantCard {
                va: format!("{:#x}", c.va),
                value: format!("0x{:x}", c.value),
                size: c.size,
            })
            .collect(),
        suggestions: suggestions
            .iter()
            .map(|(va, comment)| SsaSuggestionCard {
                va: format!("{:#x}", va),
                comment: comment.clone(),
            })
            .collect(),
    })
}

/// Full decompilation-style text for a single function (token-heavier).
#[allow(dead_code)] // MCP/agent query seam
pub fn function_decompile_text(project: &Project, va: u64) -> Option<String> {
    project.function_llm_text(va)
}

/// JSON export of a single function.
#[allow(dead_code)] // MCP/agent query seam
pub fn function_json(project: &Project, va: u64) -> Option<FunctionExport> {
    project.function_export(va)
}

/// One string literal recovered from a data VA (ASCII or UTF-16LE).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StringRef {
    pub va: u64,
    pub value: String,
    /// `"ascii"` or `"utf16"`.
    pub encoding: String,
}

/// Context: strings referenced by this function's code (e.g. `lea rdx,[rip+str]`).
/// Tries ASCII C strings first, then UTF-16LE wide strings at each data VA.
pub fn strings_in_function(project: &Project, va: u64, min_len: usize) -> Vec<StringRef> {
    let func = match project.function_at(va) {
        Some(f) => f,
        None => return Vec::new(),
    };
    let mut info_factory = InstructionInfoFactory::new();
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for block in &func.blocks {
        let mut cur = block.entry_va;
        while let Some(dec) = project.analysis.code_index.at_va(cur) {
            let info = info_factory.info(&dec.instr);
            for um in info.used_memory() {
                let target = memory_target_va(&dec.instr, um.base(), um.index(), um.displacement());
                if target == 0 || !project.address_space.is_data_va(target) {
                    continue;
                }
                if !seen.insert(target) {
                    continue;
                }
                if let Some(sref) = try_read_string_at_va(
                    &project.pe.image,
                    &project.address_space,
                    target,
                    min_len,
                ) {
                    out.push(sref);
                    if out.len() >= MAX_LIST {
                        return out;
                    }
                }
            }
            // Also treat large immediates as possible string pointers (LEA/mov abs).
            use iced_x86::OpKind;
            for i in 0..dec.instr.op_count() {
                let imm = match dec.instr.op_kind(i) {
                    OpKind::Immediate64 => dec.instr.immediate(i),
                    OpKind::Immediate32to64 => dec.instr.immediate(i),
                    OpKind::Immediate32 if project.bitness == 32 => dec.instr.immediate(i),
                    _ => continue,
                };
                if imm == 0 || !project.address_space.is_data_va(imm) || !seen.insert(imm) {
                    continue;
                }
                if let Some(sref) =
                    try_read_string_at_va(&project.pe.image, &project.address_space, imm, min_len)
                {
                    out.push(sref);
                    if out.len() >= MAX_LIST {
                        return out;
                    }
                }
            }
            if cur == block.exit_va {
                break;
            }
            cur = dec.next_ip();
        }
    }
    out
}

/// Try ASCII then UTF-16LE at `va`. Public for call-site value resolution.
pub fn try_read_string_at_va(
    image: &[u8],
    address_space: &crate::loader::address_space::AddressSpace,
    va: u64,
    min_len: usize,
) -> Option<StringRef> {
    if let Some(s) = read_printable_asciiz(image, address_space, va, 256, min_len) {
        return Some(StringRef {
            va,
            value: s,
            encoding: "ascii".into(),
        });
    }
    if let Some(s) = read_printable_utf16le(image, address_space, va, 256, min_len) {
        return Some(StringRef {
            va,
            value: s,
            encoding: "utf16".into(),
        });
    }
    None
}

/// Context: imported DLL APIs called from this function.
pub fn apis_called(project: &Project, va: u64) -> Vec<String> {
    let Some(func) = project.function_at(va) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // Direct CFG call edges retain imported thunk names when available.
    for (_, name) in function_callees(project, va) {
        if let Some(api) = name.strip_prefix("__imp_")
            && !out.iter().any(|seen| seen == api)
        {
            out.push(api.to_string());
        }
    }

    // PE64 normally calls imports through RIP-relative IAT slots. Those calls
    // are intentionally represented as indirect CFG edges, so relying only on
    // function_callees silently drops APIs that call-site evidence can see.
    for block in &func.blocks {
        for decoded in project
            .analysis
            .code_index
            .window(block.entry_va, block.instr_count)
            .iter()
            .take(block.instr_count)
        {
            let Some(api) =
                imported_api_for_instruction(&decoded.instr, project.bitness, &project.symbols)
            else {
                continue;
            };
            if !out.iter().any(|seen| seen == &api) {
                out.push(api);
                if out.len() == MAX_LIST {
                    return out;
                }
            }
        }
    }
    out
}

fn imported_api_for_instruction(
    instruction: &Instruction,
    bitness: u32,
    symbols: &SymbolTable,
) -> Option<String> {
    if instruction.flow_control() != FlowControl::IndirectCall {
        return None;
    }
    let slot_va = crate::analysis::indirect::rip_relative_target_va(instruction, bitness)?;
    symbols
        .name(slot_va)?
        .strip_prefix("__imp_")
        .map(str::to_string)
}

/// Context: callers of `va` together with the expected parameter list of `va`.
pub fn callers_with_args(project: &Project, va: u64) -> Vec<CallerContext> {
    let target_sig = project.function_at(va).and_then(|f| {
        f.signature.clone().or_else(|| {
            crate::analysis::signatures::recover_signature_with_db(
                f,
                &project.analysis.code_index,
                project.bitness,
                &f.name(&project.symbols),
                Some(&project.sig_db),
            )
        })
    });
    project
        .xrefs_to(va)
        .iter()
        .filter(|x| x.kind == XrefKind::Call)
        .take(MAX_LIST)
        .map(|x| CallerContext {
            from_va: x.from_va,
            caller: containing_function_name(project, x.from_va),
            args: target_sig
                .as_ref()
                .map(|s| {
                    s.params
                        .iter()
                        .map(|(n, t)| format!("{n}: {}", types_render_from(project, t)))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

#[derive(Serialize, Debug, Clone)]
pub struct CallerContext {
    pub from_va: u64,
    pub caller: String,
    pub args: Vec<String>,
}

/// List functions whose name contains `pattern`.
pub fn functions_named(project: &Project, pattern: &str) -> Vec<(u64, String)> {
    let needle = pattern.to_ascii_lowercase();
    project
        .analysis
        .functions
        .iter()
        .filter_map(|f| {
            let name = f.name(&project.symbols);
            if name.to_ascii_lowercase().contains(&needle) {
                Some((f.entry_va, name))
            } else {
                None
            }
        })
        .take(MAX_LIST)
        .collect()
}

/// Functions that directly call `va`.
pub fn function_callers(project: &Project, va: u64) -> Vec<(u64, String)> {
    project
        .xrefs_to(va)
        .iter()
        .filter(|x| x.kind == XrefKind::Call)
        .map(|x| (x.from_va, containing_function_name(project, x.from_va)))
        .take(MAX_LIST)
        .collect()
}

/// Functions / locations directly called from `va`.
pub fn function_callees(project: &Project, va: u64) -> Vec<(u64, String)> {
    let func = match project.function_at(va) {
        Some(f) => f,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for block in &func.blocks {
        for edge in &block.successors {
            if edge.kind == crate::analysis::functions::EdgeKind::Call && edge.target != 0 {
                out.push((edge.target, symbol_or_hex(&project.symbols, edge.target)));
            }
        }
    }
    out.dedup_by(|a, b| a.0 == b.0);
    out.truncate(MAX_LIST);
    out
}

/// All xrefs to a VA, with resolved names.
pub fn xrefs_to_named(project: &Project, va: u64) -> Vec<(u64, String, String)> {
    project
        .xrefs_to(va)
        .iter()
        .map(|x| {
            (
                x.from_va,
                symbol_or_hex(&project.symbols, x.from_va),
                format!("{:?}", x.kind),
            )
        })
        .take(MAX_LIST)
        .collect()
}

/// Global search wrapper that returns a concise text summary.
pub fn search_summary(project: &Project, query: &str) -> Vec<String> {
    if query.is_empty() {
        return Vec::new();
    }

    // Most agent triage searches target a symbol or extracted string. Resolve
    // those indexed sources first and avoid formatting every instruction in a
    // million-instruction image merely to duplicate the same named hit.
    if !query.starts_with('/') && parse_search_number(query).is_none() {
        let needle = query.to_ascii_lowercase();
        let mut fast = Vec::new();
        for (va, symbol) in project.symbols.iter() {
            if symbol.name.to_ascii_lowercase().contains(&needle) {
                fast.push(format!("sym {va:#x}: {}", symbol.name));
                if fast.len() == MAX_LIST {
                    return fast;
                }
            }
        }
        for string in project.pe.triage.strings.as_deref().unwrap_or_default() {
            if string.value.to_ascii_lowercase().contains(&needle) {
                fast.push(format!("str @{:x}: {}", string.offset, string.value));
                if fast.len() == MAX_LIST {
                    return fast;
                }
            }
        }
        if !fast.is_empty() {
            return fast;
        }
    }

    project
        .search(query)
        .into_iter()
        .take(MAX_LIST)
        .map(|hit| match hit {
            SearchHit::Instruction { va, text } => format!("insn {va:#x}: {text}"),
            SearchHit::Symbol { va, name } => format!("sym {va:#x}: {name}"),
            SearchHit::String { offset, value } => format!("str @{offset:#x}: {value}"),
        })
        .collect()
}

fn parse_search_number(query: &str) -> Option<u64> {
    if let Some(hex) = query
        .strip_prefix("0x")
        .or_else(|| query.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        query.parse().ok()
    }
}

/// Options for [`function_evidence`].
#[derive(Clone, Debug)]
pub struct EvidenceOpts {
    /// Cap per list section (default [`MAX_LIST`]).
    pub max_items: usize,
    /// When true, include truncated agent_text body.
    pub include_agent_text: bool,
    /// Max instructions for optional agent_text (default 64).
    pub max_agent_instructions: usize,
}

impl Default for EvidenceOpts {
    fn default() -> Self {
        Self {
            max_items: MAX_LIST,
            include_agent_text: false,
            max_agent_instructions: 64,
        }
    }
}

/// Build a citation object (`docs/contracts/evidence_card_v1.md`).
pub fn cite(kind: &str, va: u64, note: Option<&str>) -> serde_json::Value {
    let mut o = serde_json::json!({
        "kind": kind,
        "va": format!("{va:#x}"),
    });
    if let Some(n) = note {
        o.as_object_mut()
            .unwrap()
            .insert("note".into(), serde_json::Value::String(n.to_string()));
    }
    o
}

/// One-shot evidence pack for a function (Evidence Card v1).
///
/// Prefer this over fetching many tools before deciding to rename.
/// Every list field carries a `cite` locator when a VA exists.
pub fn function_evidence(
    project: &Project,
    va: u64,
    opts: EvidenceOpts,
) -> Option<serde_json::Value> {
    let summary = function_summary(project, va)?;
    let max = opts.max_items.clamp(1, 64);

    // Prefer call-site VAs for API cites when available.
    let mut call_sites = project
        .call_sites_with_args(va)
        .unwrap_or(serde_json::json!([]));
    if let Some(arr) = call_sites.as_array_mut() {
        arr.truncate(max);
        for site in arr.iter_mut() {
            if let Some(obj) = site.as_object_mut() {
                let call_va = obj
                    .get("call_va")
                    .and_then(|v| v.as_str())
                    .and_then(parse_va_opt)
                    .unwrap_or(va);
                obj.entry("cite")
                    .or_insert_with(|| cite("call", call_va, None));
            }
        }
    }

    let apis: Vec<_> = apis_called(project, va)
        .into_iter()
        .take(max)
        .map(|name| {
            let site_va = call_sites
                .as_array()
                .and_then(|arr| {
                    arr.iter().find_map(|s| {
                        let callee = s.get("callee").and_then(|v| v.as_str()).unwrap_or("");
                        if callee == name || callee.ends_with(&name) {
                            s.get("call_va")
                                .and_then(|v| v.as_str())
                                .and_then(parse_va_opt)
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(va);
            serde_json::json!({
                "name": name,
                "cite": cite("call", site_va, Some("api")),
            })
        })
        .collect();

    let strings: Vec<_> = strings_in_function(project, va, 4)
        .into_iter()
        .take(max)
        .map(|s| {
            serde_json::json!({
                "va": format!("{:#x}", s.va),
                "value": s.value,
                "encoding": s.encoding,
                "cite": cite("data", s.va, Some("string")),
            })
        })
        .collect();

    let callers: Vec<_> = function_callers(project, va)
        .into_iter()
        .take(max)
        .map(|(cva, name)| {
            serde_json::json!({
                "va": format!("{cva:#x}"),
                "name": name,
                "cite": cite("call", cva, Some("caller")),
            })
        })
        .collect();

    let callees: Vec<_> = function_callees(project, va)
        .into_iter()
        .take(max)
        .map(|(cva, name)| {
            serde_json::json!({
                "va": format!("{cva:#x}"),
                "name": name,
                "cite": cite("symbol", cva, Some("callee")),
            })
        })
        .collect();

    let mut points_to = serde_json::json!({ "entries": [], "count": 0 });
    if let Some(map) = project.function_points_to_map(va) {
        let mut entries: Vec<_> = map
            .entries
            .iter()
            .map(|((insn, idx), e)| {
                serde_json::json!({
                    "instruction_va": format!("{insn:#x}"),
                    "operand_index": idx,
                    "kind": format!("{:?}", e.kind),
                    "va": e.va.map(|v| format!("{v:#x}")),
                    "symbol": e.symbol,
                    "stack_disp": e.stack_disp,
                    "cite": cite("insn", *insn, Some("points_to")),
                })
            })
            .collect();
        let total = entries.len();
        entries.truncate(max);
        points_to =
            serde_json::json!({ "entries": entries, "count": total, "truncated": total > max });
    }

    let mut constants = Vec::new();
    if let Some(ssa_sum) = function_ssa_optimized_summary(project, va) {
        constants = ssa_sum
            .constants
            .into_iter()
            .take(max)
            .map(|c| {
                let cva = parse_va_opt(&c.va).unwrap_or(0);
                serde_json::json!({
                    "va": c.va,
                    "value": c.value,
                    "size": c.size,
                    "cite": cite("insn", cva, Some("const")),
                })
            })
            .collect();
    }

    let entities = project.function_entities(va);
    let memory = project
        .function_memory
        .get(&va)
        .map(|c| c.to_json())
        .unwrap_or(serde_json::Value::Null);

    let (open_questions, resolve_hint) =
        evidence_open_questions(project, va, &entities, &memory, &callees, &apis);

    let mut out = serde_json::json!({
        "contract": { "name": "evidence_card", "version": 1 },
        "summary": summary,
        "apis": apis,
        "strings": strings,
        "call_sites": call_sites,
        "points_to": points_to,
        "constants": constants,
        "entities": entities,
        "callers": callers,
        "callees": callees,
        "memory": memory,
        "open_questions": open_questions,
        "resolve_hint": resolve_hint,
    });

    if opts.include_agent_text
        && let Some(text) = project.function_agent_text_opts(
            va,
            crate::ir::agent_text::AgentTextOpts {
                strip_noise: true,
                max_instructions: Some(opts.max_agent_instructions),
            },
        )
    {
        out.as_object_mut()
            .unwrap()
            .insert("agent_text".into(), serde_json::Value::String(text));
    }

    Some(out)
}

fn parse_va_opt(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn evidence_open_questions(
    project: &Project,
    va: u64,
    entities: &Option<serde_json::Value>,
    memory: &serde_json::Value,
    callees: &[serde_json::Value],
    apis: &[serde_json::Value],
) -> (Vec<String>, String) {
    let mut q = Vec::new();
    let mut hints = Vec::new();

    if let Some(ent) = entities
        && let Some(locals) = ent.get("locals").and_then(|v| v.as_array())
    {
        let unknown = locals
            .iter()
            .filter(|l| {
                l.get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t.contains("unknown") || t == "Unknown")
            })
            .count();
        if unknown > 0 {
            q.push(format!("{unknown} stack local(s) still Unknown-typed"));
            hints.push("apply_type_recovery");
            hints.push("get_function_dataflow");
        }
    }

    let unknown_callees = callees
        .iter()
        .filter(|c| {
            c.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.starts_with("sub_") || n.starts_with("FUN_") || n == "unknown")
        })
        .count();
    if unknown_callees > 0 {
        q.push(format!(
            "{unknown_callees} callee(s) still generic FUN_*/sub_* / unknown"
        ));
        hints.push("get_function_callees");
    }

    let has_purpose = memory
        .get("purpose")
        .and_then(|p| p.as_str())
        .is_some_and(|s| !s.is_empty());
    if !has_purpose && !apis.is_empty() {
        q.push("no function_memory.purpose yet despite import APIs".into());
        hints.push("set_function_memory");
    }

    if !project.function_memory.contains_key(&va) && apis.is_empty() && unknown_callees == 0 {
        // leaf-ish with no memory — still useful to note
        if q.is_empty() {
            q.push("no durable memory card; consider summarizing after renames".into());
            hints.push("set_function_memory");
        }
    }

    if q.is_empty() {
        q.push("no major gaps detected; verify claims before large rename batches".into());
        hints.push("verify_claims");
    }

    hints.dedup();
    let resolve_hint = if hints.is_empty() {
        "get_function_agent_text".into()
    } else {
        hints.join(" → ")
    };
    (q, resolve_hint)
}

fn caller_names(project: &Project, func: &Function, symbols: &SymbolTable) -> Vec<String> {
    project
        .xrefs_to(func.entry_va)
        .iter()
        .filter(|x| {
            matches!(
                x.kind,
                XrefKind::Call | XrefKind::JumpUnconditional | XrefKind::JumpTaken
            )
        })
        .map(|x| symbol_or_hex(symbols, x.from_va))
        .take(MAX_LIST)
        .collect()
}

fn callee_names(project: &Project, func: &Function, symbols: &SymbolTable) -> Vec<String> {
    project
        .xrefs_index()
        .from(func.entry_va)
        .iter()
        .filter(|x| matches!(x.kind, XrefKind::Call))
        .map(|x| symbol_or_hex(symbols, x.to_va))
        .take(MAX_LIST)
        .collect()
}

fn containing_function_name(project: &Project, va: u64) -> String {
    // Fallback to the function that owns the block containing this VA.
    for f in project.analysis.functions.iter() {
        if f.entry_va <= va && va <= f.blocks.last().map(|b| b.exit_va).unwrap_or(f.entry_va) {
            return f.name(&project.symbols);
        }
    }
    symbol_or_hex(&project.symbols, va)
}

fn symbol_or_hex(symbols: &SymbolTable, va: u64) -> String {
    symbols
        .name(va)
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| format!("FUN_{va:08x}"))
}

/// Resolve a memory operand's effective address based on the instruction and
/// the used-memory description.  Only constant (RIP-relative or absolute)
/// targets can be resolved statically.
pub(crate) fn memory_target_va(
    instr: &Instruction,
    base: Register,
    index: Register,
    disp: u64,
) -> u64 {
    let is_rip = base == Register::RIP || base == Register::EIP;
    let is_absolute = base == Register::None && index == Register::None;
    if is_rip {
        instr.next_ip().wrapping_add(disp)
    } else if is_absolute {
        disp
    } else {
        0
    }
}

fn read_printable_asciiz(
    image: &[u8],
    address_space: &crate::loader::address_space::AddressSpace,
    va: u64,
    max_len: usize,
    min_len: usize,
) -> Option<String> {
    let bytes = address_space.slice_for_va(image, va, max_len)?;
    let mut run = String::new();
    for &b in bytes {
        if b == 0 {
            break;
        }
        if b.is_ascii_graphic() || b.is_ascii_whitespace() {
            run.push(b as char);
        } else {
            break;
        }
    }
    if run.len() < min_len { None } else { Some(run) }
}

/// Read a UTF-16LE NUL-terminated printable string (max `max_chars` code units).
pub fn read_printable_utf16le(
    image: &[u8],
    address_space: &crate::loader::address_space::AddressSpace,
    va: u64,
    max_chars: usize,
    min_len: usize,
) -> Option<String> {
    let byte_len = max_chars.saturating_mul(2).saturating_add(2);
    let bytes = address_space.slice_for_va(image, va, byte_len)?;
    if bytes.len() < 2 {
        return None;
    }
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if u == 0 {
            break;
        }
        // Reject non-printable / non-BMP for agent-safe strings.
        if u < 0x20 && u != 0x09 && u != 0x0a && u != 0x0d {
            return None;
        }
        if (0x7f..0xa0).contains(&u) {
            return None;
        }
        units.push(u);
        i += 2;
        if units.len() >= max_chars {
            break;
        }
    }
    if units.len() < min_len {
        return None;
    }
    let s = String::from_utf16(&units).ok()?;
    // Prefer real wide strings: if all code units are ASCII and the buffer
    // also looks like a short ASCII C string at the same VA, still accept
    // UTF-16 when every other byte is 0 (classic LE wide pattern).
    if !s
        .chars()
        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    {
        return None;
    }
    Some(s)
}

fn types_render_from(project: &Project, ty: &crate::project::types::DataType) -> String {
    project.types.render(ty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::Project;

    #[test]
    fn query_module_exists() {
        assert!(true);
    }

    #[test]
    fn function_evidence_pack_on_sample() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample");
        let va = project.focus.expect("focus");
        let pack = function_evidence(&project, va, EvidenceOpts::default()).expect("evidence");
        assert!(pack.get("summary").is_some());
        assert!(pack.get("entities").is_some());
        assert!(pack.get("apis").is_some());
        assert!(pack.get("call_sites").is_some());
        // Second call should hit SSA cache path (same process).
        let pack2 = function_evidence(&project, va, EvidenceOpts::default()).expect("evidence2");
        assert_eq!(
            pack["summary"]["va"], pack2["summary"]["va"],
            "stable evidence across cache hits"
        );
    }

    #[test]
    fn imported_api_recovers_rip_relative_iat_call() {
        use iced_x86::{Decoder, DecoderOptions};

        // call qword ptr [rip+0] at 0x1000 addresses the slot at next_ip=0x1006.
        let mut decoder =
            Decoder::with_ip(64, &[0xff, 0x15, 0, 0, 0, 0], 0x1000, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let mut symbols = SymbolTable::default();
        symbols.insert(
            0x1006,
            "__imp_DogfoodImportedApi",
            crate::project::symbols::SymbolKind::Import,
        );

        assert_eq!(
            imported_api_for_instruction(&instruction, 64, &symbols).as_deref(),
            Some("DogfoodImportedApi")
        );
    }

    #[test]
    fn search_summary_prefers_indexed_import_symbol_hits() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/complex.exe");
        let project = Project::open(path).expect("open complex fixture");
        let api = project
            .symbols
            .iter()
            .find_map(|(_, symbol)| symbol.name.strip_prefix("__imp_").map(str::to_string))
            .expect("fixture must contain an import symbol");
        let hits = search_summary(&project, &api);
        assert!(
            hits.iter()
                .any(|hit| hit.contains("sym ") && hit.contains(&api)),
            "indexed import symbol should satisfy summary search without a full disassembly scan"
        );
    }

    #[test]
    fn utf16le_reader_synthetic() {
        use crate::loader::address_space::{AddressSpace, Section};
        // "Hi\0" as UTF-16LE
        let mut image = vec![0u8; 0x1000];
        let wide: &[u16] = &[0x0048, 0x0069, 0x0000];
        for (i, u) in wide.iter().enumerate() {
            let b = u.to_le_bytes();
            image[0x100 + i * 2] = b[0];
            image[0x100 + i * 2 + 1] = b[1];
        }
        let space = AddressSpace {
            image_base: 0,
            sections: vec![Section {
                vaddr: 0,
                vsize: 0x1000,
                raw_addr: 0,
                raw_size: 0x1000,
                characteristics: 0x4000_0040, // initialized data, not execute
            }],
        };
        let s = read_printable_utf16le(&image, &space, 0x100, 32, 2).expect("utf16");
        assert_eq!(s, "Hi");
        let sref = try_read_string_at_va(&image, &space, 0x100, 2).expect("string ref");
        // Prefer ascii if both work; at 0x100 pure wide "H\0i\0" is utf16-only.
        assert_eq!(sref.encoding, "utf16");
        assert_eq!(sref.value, "Hi");
    }
}
