//! Compact, token-efficient agent export with type annotations.
//!
//! While `to_llm_text` is frozen for LLM4Deparse compatibility, `to_agent_text`
//! is the interface used by the reasoning agent: it keeps type annotations,
//! uses block labels, and summarizes cross-references in header comments.

use std::collections::HashSet;

use crate::ir::export::{FunctionExport, InstrClass};

/// Options for [`to_agent_text_opts`].
///
/// Defaults: `strip_noise = false` (bit-stable with historical agent text),
/// `max_instructions = None` (unbounded). Bounded MCP paths set both explicitly.
#[derive(Clone, Debug, Default)]
pub struct AgentTextOpts {
    /// Strip security-cookie / prologue / epilogue noise.
    pub strip_noise: bool,
    /// Cap the number of body instructions; emit a summary line when truncated.
    pub max_instructions: Option<usize>,
}

/// Render a function export as compact annotated text for an LLM agent.
///
/// Format:
/// ```text
/// fn name(arg0: int32, arg1: uint64*) -> int32  // __fastcall entry:0x140001000
/// // in: [0x140000800, 0x140000900] out: [0x140002000]
/// block_0x140001000:
///   mov rax, [g_count:uint32]
///   call [__imp_CreateFileW:HANDLE(*)(PCWSTR,DWORD,DWORD,...)]
///   ret
/// ```
#[allow(dead_code)] // stable API; opts path is the primary caller
pub fn to_agent_text(export: &FunctionExport) -> String {
    to_agent_text_opts(export, &AgentTextOpts::default())
}

/// Like [`to_agent_text`] with noise stripping and instruction budget.
pub fn to_agent_text_opts(export: &FunctionExport, opts: &AgentTextOpts) -> String {
    let mut out = String::new();

    // Function header line.
    let params = export
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = if p.name.is_empty() {
                format!("arg{i}")
            } else {
                p.name.clone()
            };
            let ty = p.type_guess.as_deref().unwrap_or("unknown");
            format!("{name}: {ty}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let ret = export.return_type.as_deref().unwrap_or("unknown");
    let cc = export.calling_conv.as_deref().unwrap_or("unknown_cc");
    out.push_str(&format!(
        "fn {}({}) -> {}  // {} entry:{:#x}\n",
        export.name, params, ret, cc, export.entry_va
    ));

    // Cross-reference summary.
    if !export.xrefs_in.is_empty() || !export.xrefs_out.is_empty() {
        out.push_str("// in: [");
        out.push_str(
            &export
                .xrefs_in
                .iter()
                .map(|va| format!("{va:#x}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("] out: [");
        out.push_str(
            &export
                .xrefs_out
                .iter()
                .map(|va| format!("{va:#x}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("]\n");
    }

    // Block entry set.
    let block_entries: HashSet<u64> = export.blocks.iter().map(|b| b.entry_va).collect();

    // Noise stats for summary comments.
    let mut stripped_cookie = 0usize;
    let mut stripped_prologue = 0usize;
    let mut stripped_epilogue = 0usize;
    let mut prologue_frame_hint: Option<u64> = None;

    // Pre-scan prologue for local frame size (sub rsp, N).
    if opts.strip_noise {
        for instr in &export.instructions {
            if instr.class != InstrClass::Prologue {
                continue;
            }
            if instr.mnemonic == "sub"
                && (instr.operands_str.starts_with("rsp") || instr.operands_str.starts_with("esp"))
            {
                // "rsp, 0x40" or "rsp, 40h"
                if let Some(imm) = instr.operands_str.split(',').nth(1) {
                    let imm = imm.trim().trim_end_matches('h');
                    if let Some(hex) = imm.strip_prefix("0x").or_else(|| imm.strip_prefix("0X")) {
                        prologue_frame_hint = u64::from_str_radix(hex, 16).ok();
                    } else {
                        prologue_frame_hint = imm.parse().ok();
                    }
                }
            }
        }
    }

    let mut emitted = 0usize;
    let mut omitted = 0usize;
    let mut emitted_return = false;
    let mut last_return: Option<String> = None;
    let mut prologue_comment_emitted = false;
    let mut seh_comment_emitted = false;

    for instr in &export.instructions {
        // SEH / GS handler recognition: annotate once when seen.
        if opts.strip_noise {
            let ops = instr
                .operands_annotated
                .as_deref()
                .unwrap_or(instr.operands_str.as_str());
            if !seh_comment_emitted
                && (ops.contains("__C_specific_handler")
                    || ops.contains("__GSHandlerCheck")
                    || ops.contains("GSHandlerCheck"))
            {
                out.push_str("  // exception handler setup (deferred)\n");
                seh_comment_emitted = true;
                continue;
            }
        }

        if opts.strip_noise {
            match instr.class {
                InstrClass::Cookie => {
                    stripped_cookie += 1;
                    continue;
                }
                InstrClass::Prologue => {
                    stripped_prologue += 1;
                    if !prologue_comment_emitted {
                        if let Some(n) = prologue_frame_hint {
                            out.push_str(&format!("  // prologue: {n} bytes local frame\n"));
                        } else {
                            out.push_str("  // prologue\n");
                        }
                        prologue_comment_emitted = true;
                    }
                    continue;
                }
                InstrClass::Epilogue if instr.mnemonic != "ret" && !instr.mnemonic.starts_with("ret") =>
                {
                    stripped_epilogue += 1;
                    continue;
                }
                _ => {}
            }
        }

        // Format the instruction line.
        let ops = instr
            .operands_annotated
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(Some(instr.operands_str.as_str()))
            .unwrap_or("");
        let line = if ops.is_empty() {
            format!("  {}\n", instr.mnemonic)
        } else {
            format!("  {} {}\n", instr.mnemonic, ops)
        };

        let is_return = instr.class == InstrClass::Return
            || instr.mnemonic == "ret"
            || instr.mnemonic.starts_with("ret");
        if is_return {
            last_return = Some(line.clone());
        }

        // Budget: leave room for the final return.
        if let Some(max) = opts.max_instructions
            && emitted >= max
            && !is_return
        {
            omitted += 1;
            continue;
        }

        if block_entries.contains(&instr.ip) {
            out.push_str(&format!("block_{:#x}:\n", instr.ip));
        }
        out.push_str(&line);
        if let Some(c) = &instr.comment {
            out.push_str(&format!("  // {c}\n"));
        }
        emitted += 1;
        if is_return {
            emitted_return = true;
        }
    }

    let _ = stripped_cookie;

    if omitted > 0 {
        out.push_str(&format!(
            "// ... {omitted} more instructions truncated. Call get_function_dataflow for full SSA.\n"
        ));
        // Always emit the final return if present and not yet emitted.
        if !emitted_return
            && let Some(ret_line) = last_return
        {
            out.push_str(&ret_line);
        }
    }

    let _ = (stripped_epilogue, stripped_prologue);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::export::{BlockExport, FunctionExport, InstrClass, InstrExport, Param};

    fn instr(ip: u64, mnemonic: &str, ops: &str) -> InstrExport {
        InstrExport {
            ip,
            bytes_hex: String::new(),
            mnemonic: mnemonic.to_string(),
            operands_str: ops.to_string(),
            operands_annotated: Some(ops.to_string()),
            flow: "Next".to_string(),
            class: InstrClass::Logic,
            reads: Vec::new(),
            writes: Vec::new(),
            mem_refs: Vec::new(),
            comment: None,
            pcode_ops: Vec::new(),
        }
    }

    #[test]
    fn agent_text_includes_header_and_blocks() {
        let export = FunctionExport {
            name: "test_fn".to_string(),
            entry_va: 0x1000,
            calling_conv: Some("__fastcall".to_string()),
            params: vec![
                Param {
                    name: "a".to_string(),
                    type_guess: Some("int32".to_string()),
                    reg: Some("rcx".to_string()),
                },
                Param {
                    name: "b".to_string(),
                    type_guess: Some("uint64*".to_string()),
                    reg: Some("rdx".to_string()),
                },
            ],
            return_type: Some("int32".to_string()),
            blocks: vec![BlockExport {
                entry_va: 0x1000,
                successor_vas: vec![],
            }],
            instructions: vec![
                instr(0x1000, "mov", "eax, ecx"),
                instr(0x1002, "ret", ""),
            ],
            xrefs_in: vec![0x500],
            xrefs_out: vec![],
        };
        let text = to_agent_text(&export);
        assert!(text.contains("fn test_fn(a: int32, b: uint64*) -> int32"));
        assert!(text.contains("__fastcall"));
        assert!(text.contains("block_0x1000:"));
        assert!(text.contains("in: [0x500]"));
    }

    #[test]
    fn prefer_operands_annotated() {
        let mut i = instr(0x1000, "mov", "eax, ecx");
        i.operands_annotated = Some("eax, [g:uint32]".to_string());
        let export = FunctionExport {
            name: "x".to_string(),
            entry_va: 0x1000,
            calling_conv: None,
            params: vec![],
            return_type: None,
            blocks: vec![BlockExport {
                entry_va: 0x1000,
                successor_vas: vec![],
            }],
            instructions: vec![i],
            xrefs_in: vec![],
            xrefs_out: vec![],
        };
        assert!(to_agent_text(&export).contains("eax, [g:uint32]"));
    }

    #[test]
    fn strip_noise_omits_cookie_and_prologue() {
        let mut cookie = instr(0x1000, "xor", "rax, rsp");
        cookie.class = InstrClass::Cookie;
        let mut prol = instr(0x1001, "push", "rbp");
        prol.class = InstrClass::Prologue;
        let mut prol2 = instr(0x1002, "sub", "rsp, 0x20");
        prol2.class = InstrClass::Prologue;
        let logic = instr(0x1005, "mov", "eax, ecx");
        let mut ret = instr(0x1007, "ret", "");
        ret.class = InstrClass::Return;
        ret.flow = "Return".to_string();

        let export = FunctionExport {
            name: "f".to_string(),
            entry_va: 0x1000,
            calling_conv: None,
            params: vec![],
            return_type: Some("int32".to_string()),
            blocks: vec![BlockExport {
                entry_va: 0x1000,
                successor_vas: vec![],
            }],
            instructions: vec![cookie, prol, prol2, logic, ret],
            xrefs_in: vec![],
            xrefs_out: vec![],
        };
        let text = to_agent_text_opts(
            &export,
            &AgentTextOpts {
                strip_noise: true,
                max_instructions: None,
            },
        );
        assert!(!text.contains("xor rax, rsp"), "cookie should be stripped: {text}");
        assert!(!text.contains("push rbp"), "prologue should be stripped: {text}");
        assert!(text.contains("prologue"), "should include prologue summary: {text}");
        assert!(text.contains("mov eax, ecx"));
        assert!(text.contains("ret"));
    }

    #[test]
    fn max_instructions_truncates_with_summary() {
        let mut instrs = Vec::new();
        for i in 0..20 {
            instrs.push(instr(0x1000 + i, "nop", ""));
        }
        let mut ret = instr(0x2000, "ret", "");
        ret.class = InstrClass::Return;
        instrs.push(ret);
        let export = FunctionExport {
            name: "big".to_string(),
            entry_va: 0x1000,
            calling_conv: None,
            params: vec![],
            return_type: None,
            blocks: vec![BlockExport {
                entry_va: 0x1000,
                successor_vas: vec![],
            }],
            instructions: instrs,
            xrefs_in: vec![],
            xrefs_out: vec![],
        };
        let text = to_agent_text_opts(
            &export,
            &AgentTextOpts {
                strip_noise: false,
                max_instructions: Some(5),
            },
        );
        assert!(text.contains("truncated"), "expected truncation summary: {text}");
        assert!(text.contains("ret"), "final ret should be preserved: {text}");
    }
}
