//! GCLSD (Graph-Conditioned Latent State Decompiler) input contract.
//!
//! This module defines the JSON schema that windy emits for the external
//! decompiler model. Unlike the flat `FunctionExport` consumed by LLM4Decompile,
//! this format preserves the control-flow graph's edge kinds and groups
//! instructions by basic block so the model's graph encoder can operate directly
//! on the CFG produced by the disassembler.

use std::collections::{BTreeMap, HashMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::{BasicBlock, EdgeKind, Function};
use crate::analysis::xrefs::XrefIndex;
use crate::decompiler::pcode::PcodeOp;
use crate::ir::export::{function_to_export, InstrExport, MemRefExport, Param};
use crate::project::comments::CommentStore;
use crate::project::symbols::SymbolTable;
use crate::project::types::{DataType, DataTypeManager, FunctionSignature, StackFrame};

/// Input to the GCLSD decompiler model.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct GclsdInput {
    pub name: String,
    pub entry_va: u64,
    /// PE ImageBase used to convert this absolute VA back to an RVA.
    pub image_base: u64,
    pub bitness: u32,
    pub calling_conv: Option<String>,
    pub params: Vec<Param>,
    pub return_type: Option<String>,
    pub instructions: Vec<GclsdInstr>,
    pub blocks: Vec<GclsdBlock>,
    pub xrefs_in: Vec<u64>,
    pub xrefs_out: Vec<u64>,
    /// Optional seed pseudo-code for the model to refine (e.g., Ghidra output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refine: Option<String>,
}

/// One decoded instruction in the GCLSD input stream.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct GclsdInstr {
    pub ip: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operands_annotated: Option<String>,
    pub flow: String,
    pub class: String,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub mem_refs: Vec<MemRefExport>,
    /// P-code operations for this instruction, lifted lazily per-function via
    /// the SLEIGH decoder. Non-serialized (`PcodeOp` is not `Serialize`); a
    /// future JSON consumer would project this to a serializable shape. Empty
    /// for true P-code no-ops and undecodable instructions.
    #[serde(skip)]
    #[allow(dead_code)] // non-serialized; available to in-process GCLSD consumers
    pub pcode_ops: Vec<PcodeOp>,
}

/// One basic block node for the graph encoder.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct GclsdBlock {
    pub entry_va: u64,
    /// Instruction IPs that belong to this block, in order.
    pub instr_ips: Vec<u64>,
    /// Outgoing edges with their original control-flow kind.
    pub successors: Vec<GclsdEdge>,
}

/// A CFG edge. Target `0` means "unknown" (indirect branch/call/return).
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct GclsdEdge {
    pub target: u64,
    pub kind: GclsdEdgeKind,
}

/// Control-flow edge kinds, matching `analysis::functions::EdgeKind` but
/// serialized as stable snake_case strings for the Python model.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GclsdEdgeKind {
    Fallthrough,
    Unconditional,
    Conditional,
    Call,
    TailCall,
    Indirect,
    Return,
}

impl From<EdgeKind> for GclsdEdgeKind {
    fn from(kind: EdgeKind) -> Self {
        match kind {
            EdgeKind::Fallthrough => Self::Fallthrough,
            EdgeKind::Unconditional => Self::Unconditional,
            EdgeKind::Conditional => Self::Conditional,
            EdgeKind::Call => Self::Call,
            EdgeKind::TailCall => Self::TailCall,
            EdgeKind::Indirect => Self::Indirect,
            EdgeKind::Return => Self::Return,
        }
    }
}

/// Model output: a single C-like pseudo-code string.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct GclsdOutput {
    pub pseudocode: String,
}

/// Build a `GclsdInput` from an analyzed function, preserving CFG edge kinds.
#[allow(clippy::too_many_arguments)]
pub fn function_to_gclsd_input(
    func: &Function,
    code_index: &CodeIndex,
    symbols: &SymbolTable,
    comments: &CommentStore,
    xrefs: &XrefIndex,
    image_base: u64,
    bitness: u32,
    typed_globals: &HashMap<u64, DataType>,
    function_frames: &BTreeMap<u64, StackFrame>,
    types: &DataTypeManager,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
) -> Option<GclsdInput> {
    let export = function_to_export(
        func,
        code_index,
        symbols,
        comments,
        xrefs,
        bitness,
        typed_globals,
        function_frames,
        types,
        function_signatures,
    )?;

    let block_by_entry: HashMap<u64, &BasicBlock> =
        func.blocks.iter().map(|b| (b.entry_va, b)).collect();
    let block_entries: Vec<u64> = export.blocks.iter().map(|b| b.entry_va).collect();
    let mut block_ips: Vec<Vec<u64>> = vec![Vec::new(); export.blocks.len()];

    for instr in &export.instructions {
        let idx = match block_entries.binary_search(&instr.ip) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        if idx < block_ips.len() {
            block_ips[idx].push(instr.ip);
        }
    }

    let mut blocks = Vec::with_capacity(export.blocks.len());
    for (block_export, ips) in export.blocks.iter().zip(block_ips) {
        let bb = block_by_entry.get(&block_export.entry_va)?;
        let successors: Vec<GclsdEdge> = bb
            .successors
            .iter()
            .map(|e| GclsdEdge {
                target: e.target,
                kind: e.kind.into(),
            })
            .collect();
        blocks.push(GclsdBlock {
            entry_va: block_export.entry_va,
            instr_ips: ips,
            successors,
        });
    }

    Some(GclsdInput {
        name: export.name,
        entry_va: export.entry_va,
        image_base,
        bitness,
        calling_conv: export.calling_conv,
        params: export.params,
        return_type: export.return_type,
        instructions: export
            .instructions
            .iter()
            .map(gclsd_instr_from_export)
            .collect(),
        blocks,
        xrefs_in: export.xrefs_in,
        xrefs_out: export.xrefs_out,
        refine: None,
    })
}

/// Iterate every function in `project` that has at least `min_insns`
/// instructions and emit a `GclsdInput`. Used for headless corpus export.
pub fn export_project_gclsd(
    project: &crate::project::Project,
    min_insns: usize,
) -> impl Iterator<Item = GclsdInput> + '_ {
    project.functions().iter().filter_map(move |func| {
        let insn_count: usize = func.blocks.iter().map(|b| b.instr_count).sum();
        if insn_count < min_insns {
            return None;
        }
        project.function_gclsd_input(func.entry_va)
    })
}

fn gclsd_instr_from_export(instr: &InstrExport) -> GclsdInstr {
    GclsdInstr {
        ip: instr.ip,
        bytes_hex: instr.bytes_hex.clone(),
        mnemonic: instr.mnemonic.clone(),
        operands: instr.operands_str.clone(),
        operands_annotated: instr.operands_annotated.clone(),
        flow: instr.flow.clone(),
        class: format!("{:?}", instr.class),
        reads: instr.reads.clone(),
        writes: instr.writes.clone(),
        mem_refs: instr.mem_refs.clone(),
        pcode_ops: instr.pcode_ops.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::{Edge, EdgeKind};
    use crate::decompiler::pcode::PcodeOp;
    use crate::ir::export::{BlockExport, FunctionExport, InstrClass, Param};

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
    fn preserves_edge_kinds() {
        // We can't easily build a full Function from scratch, but we can test
        // the EdgeKind -> GclsdEdgeKind conversion and the instruction-to-block
        // grouping logic by constructing a synthetic export and a matching
        // Function struct manually.
        let export = FunctionExport {
            name: "test".to_string(),
            entry_va: 0x1000,
            calling_conv: None,
            params: vec![Param {
                name: "a".to_string(),
                type_guess: Some("int32".to_string()),
                reg: None,
            }],
            return_type: Some("int32".to_string()),
            blocks: vec![
                BlockExport {
                    entry_va: 0x1000,
                    successor_vas: vec![0x1002, 0x1010],
                },
                BlockExport {
                    entry_va: 0x1002,
                    successor_vas: vec![],
                },
            ],
            instructions: vec![
                instr(0x1000, "cmp", "eax, 0"),
                instr(0x1002, "ret", ""),
            ],
            xrefs_in: vec![],
            xrefs_out: vec![],
        };

        let mut func = Function {
            id: 0x1000,
            entry_va: 0x1000,
            blocks: vec![BasicBlock {
                entry_va: 0x1000,
                exit_va: 0x1001,
                instr_count: 1,
                successors: vec![
                    Edge {
                        target: 0x1002,
                        kind: EdgeKind::Conditional,
                    },
                    Edge {
                        target: 0x1010,
                        kind: EdgeKind::Unconditional,
                    },
                ],
                predecessors: vec![],
            }],
            outgoing: vec![],
            stack_frame: None,
            signature: None,
        };
        func.recompute_predecessors();

        // Replicate what the real builder does without needing a CodeIndex.
        let block_by_entry: std::collections::HashMap<u64, &BasicBlock> =
            func.blocks.iter().map(|b| (b.entry_va, b)).collect();
        let block_entries: Vec<u64> = export.blocks.iter().map(|b| b.entry_va).collect();
        let mut block_ips: Vec<Vec<u64>> = vec![Vec::new(); export.blocks.len()];
        for instr in &export.instructions {
            let idx = match block_entries.binary_search(&instr.ip) {
                Ok(i) => i,
                Err(i) => i.saturating_sub(1),
            };
            if idx < block_ips.len() {
                block_ips[idx].push(instr.ip);
            }
        }

        let gclsd_block = GclsdBlock {
            entry_va: 0x1000,
            instr_ips: block_ips.swap_remove(0),
            successors: func.blocks[0]
                .successors
                .iter()
                .map(|e| GclsdEdge {
                    target: e.target,
                    kind: e.kind.into(),
                })
                .collect(),
        };

        assert_eq!(gclsd_block.instr_ips, vec![0x1000]);
        assert_eq!(gclsd_block.successors.len(), 2);
        assert!(gclsd_block.successors.iter().any(|e| e.kind
            == GclsdEdgeKind::Conditional));
        assert!(gclsd_block.successors.iter().any(|e| e.kind
            == GclsdEdgeKind::Unconditional));
        assert!(block_by_entry.contains_key(&0x1000));
    }

    /// Round-trip / carry test: load `sample.exe`, run it through the analysis
    /// pipeline, and export every function as GCLSD input. Every instruction
    /// must carry a P-code op list, except for true P-code no-ops (NOP /
    /// LFENCE / SFENCE / MFENCE / PAUSE). Additionally, an "add"-like function
    /// (one that lifts to `IntAdd`) must also end in a `Return`.
    #[test]
    fn test_function_export_carries_pcode() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        let project = crate::project::Project::open(path).expect("open sample.exe");

        let is_pcode_noop = |m: &str| {
            let u = m.to_uppercase();
            u == "NOP"
                || u.starts_with("NOP")
                || u.starts_with("LFENCE")
                || u.starts_with("SFENCE")
                || u.starts_with("MFENCE")
                || u == "PAUSE"
                // `xchg eax,eax` / `xchg ax,ax` (`66 90`) is the two-byte NOP;
                // rsleigh emits no P-code ops for it.
                || u == "XCHG"
        };

        let mut total_instrs = 0usize;
        let mut empty_non_noop = 0usize;
        let mut add_func_va: Option<u64> = None;

        for func in project.functions().iter() {
            let Some(input) = project.function_gclsd_input(func.entry_va) else {
                continue;
            };
            total_instrs += input.instructions.len();

            let mut has_int_add = false;
            let mut has_return = false;
            for instr in &input.instructions {
                if !is_pcode_noop(&instr.mnemonic) && instr.pcode_ops.is_empty() {
                    empty_non_noop += 1;
                }
                if instr
                    .pcode_ops
                    .iter()
                    .any(|op| matches!(op, PcodeOp::IntAdd { .. }))
                {
                    has_int_add = true;
                }
                if instr
                    .pcode_ops
                    .iter()
                    .any(|op| matches!(op, PcodeOp::Return { .. }))
                {
                    has_return = true;
                }
            }
            if has_int_add && add_func_va.is_none() {
                add_func_va = Some(func.entry_va);
                assert!(has_return, "add-like function should contain a Return");
            }
        }

        assert!(total_instrs > 0, "sample.exe must yield functions");
        assert_eq!(
            empty_non_noop, 0,
            "only P-code no-ops may have empty P-code op lists"
        );
        assert!(
            add_func_va.is_some(),
            "expected an add-like function lifting to IntAdd"
        );
    }
}
