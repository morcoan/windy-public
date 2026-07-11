
use std::collections::HashSet;

use iced_x86::{Formatter as _, InstructionInfoFactory, IntelFormatter, OpAccess};
use serde::Serialize;

use std::collections::{BTreeMap, HashMap};

use schemars::JsonSchema;

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::{BasicBlock, Function};
use crate::analysis::signatures::recover_signature_with_db;
use crate::analysis::win32_sigs::SigDB;
use crate::analysis::xrefs::XrefIndex;
use crate::decompiler::pcode::PcodeOp;
use crate::disasm::TableResolver;
use crate::ir::annotate::annotate_operands_with_db;
use crate::project::comments::{CommentScope, CommentStore};
use crate::project::symbols::SymbolTable;
use crate::project::types::{DataType, DataTypeManager, FunctionSignature, StackFrame};

#[derive(Serialize, Debug, Clone, JsonSchema)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub type_guess: Option<String>,
    pub reg: Option<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstrClass {
    Prologue,
    Epilogue,
    Spill,
    Cookie,
    Call,
    Branch,
    Return,
    Logic,
}

#[derive(Serialize, Debug, Clone, JsonSchema)]
pub struct MemRefExport {
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u32,
    pub displacement: u64,
    pub size: String,
    pub access: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct InstrExport {
    pub ip: u64,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands_str: String,
    /// Type-annotated operand string for agent exports (LLM4Decompile uses
    /// `operands_str` unchanged).
    pub operands_annotated: Option<String>,
    pub flow: String,
    pub class: InstrClass,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub mem_refs: Vec<MemRefExport>,
    pub comment: Option<String>,
    /// P-code operations for this instruction, lifted lazily per-function via
    /// the SLEIGH decoder. Non-serialized: `PcodeOp` is not `Serialize`, and
    /// consumers (SSA / type recovery / structuring) read it in Rust. Empty for
    /// true P-code no-ops (NOP/LFENCE/SFENCE/MFENCE/PAUSE) and any instruction
    /// the decoder could not lift.
    #[serde(skip)]
    pub pcode_ops: Vec<PcodeOp>,
}

#[derive(Serialize, Debug, Clone)]
pub struct BlockExport {
    pub entry_va: u64,
    pub successor_vas: Vec<u64>,
}

#[derive(Serialize, Debug, Clone)]
pub struct FunctionExport {
    pub name: String,
    pub entry_va: u64,
    pub calling_conv: Option<String>,
    pub params: Vec<Param>,
    pub return_type: Option<String>,
    pub blocks: Vec<BlockExport>,
    pub instructions: Vec<InstrExport>,
    pub xrefs_in: Vec<u64>,
    pub xrefs_out: Vec<u64>,
}

impl FunctionExport {
    /// Return a copy containing only instructions whose IP falls in the closed
    /// range `[start_ip, end_ip]`. Block metadata is restricted to the blocks
    /// whose entry falls in the same range; cross-reference lists are preserved.
    #[allow(dead_code)] // pagination seam for token-bounded exports
    pub fn ip_window(&self, start_ip: u64, end_ip: u64) -> Self {
        let new_blocks: Vec<BlockExport> = self
            .blocks
            .iter()
            .filter(|b| b.entry_va >= start_ip && b.entry_va <= end_ip)
            .cloned()
            .collect();
        let new_instrs: Vec<InstrExport> = self
            .instructions
            .iter()
            .filter(|i| i.ip >= start_ip && i.ip <= end_ip)
            .cloned()
            .collect();
        let mut clone = self.clone();
        clone.blocks = new_blocks;
        clone.instructions = new_instrs;
        clone
    }
}

/// Render a function to the exact text format LLM4Decompile-End consumes:
/// `<name>:\n<mnemonic operands>\n...`.
#[allow(dead_code)] // frozen LLM4Decompile format; called via Project::function_llm_text
pub fn to_llm_text(export: &FunctionExport) -> String {
    let mut out = format!("<{}>:\n", export.name);
    for instr in &export.instructions {
        if instr.operands_str.is_empty() {
            out.push_str(&format!("{}\n", instr.mnemonic));
        } else {
            out.push_str(&format!("{} {}\n", instr.mnemonic, instr.operands_str));
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub fn function_to_export(
    func: &Function,
    code_index: &CodeIndex,
    symbols: &SymbolTable,
    comments: &CommentStore,
    xrefs: &XrefIndex,
    bitness: u32,
    typed_globals: &HashMap<u64, DataType>,
    function_frames: &BTreeMap<u64, StackFrame>,
    types: &DataTypeManager,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
) -> Option<FunctionExport> {
    function_to_export_with_db(
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
        None,
    )
}

/// Like [`function_to_export`], but consults the Win32 SigDB for IAT/API names.
#[allow(clippy::too_many_arguments)]
pub fn function_to_export_with_db(
    func: &Function,
    code_index: &CodeIndex,
    symbols: &SymbolTable,
    comments: &CommentStore,
    xrefs: &XrefIndex,
    bitness: u32,
    typed_globals: &HashMap<u64, DataType>,
    function_frames: &BTreeMap<u64, StackFrame>,
    types: &DataTypeManager,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
    sig_db: Option<&SigDB>,
) -> Option<FunctionExport> {
    let names = symbols.to_resolver_map();
    let name = func.name(symbols);
    let signature = func
        .signature
        .clone()
        .or_else(|| recover_signature_with_db(func, code_index, bitness, &name, sig_db));
    let (calling_conv, params, return_type) = signature
        .map(|s| {
            let params = s
                .params
                .into_iter()
                .map(|(n, t)| Param {
                    name: n,
                    type_guess: Some(types.render(&t)),
                    reg: None,
                })
                .collect();
            (s.calling_conv, params, Some(types.render(&s.ret)))
        })
        .unwrap_or((None, Vec::new(), None));

    let mut builder = FunctionExportBuilder {
        code_index,
        symbols,
        comments,
        xrefs,
        names,
        bitness,
        typed_globals,
        function_frames,
        types,
        function_signatures,
        sig_db,
        pcode_ops: crate::decompiler::pcode::lift_function_blocking(
            func,
            code_index,
            bitness,
        ),
        export: FunctionExport {
            name,
            entry_va: func.entry_va,
            calling_conv,
            params,
            return_type,
            blocks: Vec::new(),
            instructions: Vec::new(),
            xrefs_in: xrefs.to(func.entry_va).iter().map(|x| x.from_va).collect(),
            xrefs_out: Vec::new(),
        },
    };

    let mut seen_vas = HashSet::new();
    for block in &func.blocks {
        builder.export.blocks.push(BlockExport {
            entry_va: block.entry_va,
            successor_vas: block
                .successors
                .iter()
                .map(|e| e.target)
                .filter(|t| *t != 0)
                .collect(),
        });
        builder.collect_block_instructions(block, &mut seen_vas);
    }
    builder.export.xrefs_out = seen_vas
        .iter()
        .flat_map(|va| xrefs.from(*va).iter().map(|x| x.to_va))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    builder.export.xrefs_out.sort_unstable();

    classify_instructions(&mut builder.export.instructions, builder.export.entry_va);

    Some(builder.export)
}

fn classify_instructions(instrs: &mut [InstrExport], entry_va: u64) {
    const PROLOGUE_WINDOW: usize = 12;
    const EPILOGUE_WINDOW: usize = 8;

    let len = instrs.len();
    for (idx, instr) in instrs.iter_mut().enumerate() {
        instr.class = classify_one(instr, entry_va, idx, len, PROLOGUE_WINDOW, EPILOGUE_WINDOW);
    }

    // Security-cookie pair: `mov rax,[rip+...]` followed by `xor rax,rsp`.
    for i in 0..len.min(PROLOGUE_WINDOW) {
        if !is_cookie_xor(&instrs[i]) {
            continue;
        }
        for j in (0..i).rev() {
            if instrs[j].writes.iter().any(|w| w == "RAX")
                && instrs[j].mnemonic == "mov"
                && instrs[j].mem_refs.iter().any(|m| m.access == "Read")
            {
                instrs[j].class = InstrClass::Cookie;
                break;
            }
        }
        instrs[i].class = InstrClass::Cookie;
    }
}

fn classify_one(
    instr: &InstrExport,
    entry_va: u64,
    idx: usize,
    len: usize,
    prologue_window: usize,
    epilogue_window: usize,
) -> InstrClass {
    let flow = instr.flow.as_str();
    if flow == "Call" {
        return InstrClass::Call;
    }
    if matches!(flow, "UnconditionalBranch" | "ConditionalBranch" | "IndirectBranch") {
        return InstrClass::Branch;
    }
    if flow == "Return" {
        return InstrClass::Return;
    }

    let in_prologue_window = idx < prologue_window
        && instr.ip.saturating_sub(entry_va) < 0x40;
    let in_epilogue_window = idx + epilogue_window >= len;

    if in_prologue_window && is_prologue(instr) {
        return InstrClass::Prologue;
    }
    if in_prologue_window && is_spill(instr) {
        return InstrClass::Spill;
    }
    if in_epilogue_window && is_epilogue(instr) {
        return InstrClass::Epilogue;
    }

    InstrClass::Logic
}

fn is_prologue(instr: &InstrExport) -> bool {
    let op = &instr.operands_str;
    match instr.mnemonic.as_str() {
        "push" => op.contains("rbp") || op.contains("ebp"),
        "mov" => op.contains("rbp, rsp") || op.contains("ebp, esp"),
        "sub" => op.starts_with("rsp") || op.starts_with("esp"),
        "lea" => op.starts_with("rsp") || op.starts_with("esp"),
        "and" => (op.starts_with("rsp") || op.starts_with("esp")) && op.contains('-'),
        _ => false,
    }
}

fn is_spill(instr: &InstrExport) -> bool {
    if instr.mnemonic != "mov" {
        return false;
    }
    let op = &instr.operands_str;
    op.contains("[rbp-") || op.contains("[rsp+") || op.contains("[rsp-")
}

fn is_epilogue(instr: &InstrExport) -> bool {
    match instr.mnemonic.as_str() {
        "ret" | "rep" | "retfq" | "retf" => true,
        "add" => instr.operands_str.starts_with("rsp") || instr.operands_str.starts_with("esp"),
        "pop" => {
            let op = &instr.operands_str;
            op.contains("rbp") || op.contains("ebp")
        }
        "lea" => {
            let op = &instr.operands_str;
            (op.starts_with("rsp") || op.starts_with("esp")) && op.contains('+')
        }
        _ => false,
    }
}

fn is_cookie_xor(instr: &InstrExport) -> bool {
    instr.mnemonic == "xor"
        && (instr.operands_str == "rax, rsp"
            || instr.operands_str == "rsp, rax"
            || instr.operands_str == "eax, esp"
            || instr.operands_str == "esp, eax")
}

struct FunctionExportBuilder<'a> {
    code_index: &'a CodeIndex,
    symbols: &'a SymbolTable,
    comments: &'a CommentStore,
    #[allow(dead_code)] // retained for future xref-enriched export
    xrefs: &'a XrefIndex,
    names: std::collections::HashMap<u64, String>,
    #[allow(dead_code)] // bitness for type size projection
    bitness: u32,
    typed_globals: &'a HashMap<u64, DataType>,
    function_frames: &'a BTreeMap<u64, StackFrame>,
    types: &'a DataTypeManager,
    function_signatures: &'a BTreeMap<u64, FunctionSignature>,
    sig_db: Option<&'a SigDB>,
    pcode_ops: std::collections::HashMap<u64, Vec<PcodeOp>>,
    export: FunctionExport,
}

impl<'a> FunctionExportBuilder<'a> {
    fn collect_block_instructions(&mut self, block: &BasicBlock, seen_vas: &mut HashSet<u64>) {
        let mut va = block.entry_va;
        let mut info_factory = InstructionInfoFactory::new();

        while let Some(dec) = self.code_index.at_va(va) {
            seen_vas.insert(va);
            let instr = &dec.instr;

            let mut output = String::new();
            let resolver: Option<Box<dyn iced_x86::SymbolResolver>> =
                Some(Box::new(TableResolver::from_map(&self.names)));
            let mut formatter = IntelFormatter::with_options(resolver, None);
            formatter.format(instr, &mut output);

            // Split the formatted line into mnemonic and operands for JSON.
            let (mnemonic, operands_str) = if let Some(pos) = output.find(' ') {
                let (m, o) = output.split_at(pos);
                (m.to_string(), o[1..].to_string())
            } else {
                (output, String::new())
            };

            // Type-aware agent annotation (globals / IAT / stack locals).
            let frame = self.function_frames.get(&self.export.entry_va);
            let annotated_output = annotate_operands_with_db(
                instr,
                self.symbols,
                self.typed_globals,
                self.types,
                self.function_signatures,
                frame,
                self.sig_db,
            );
            let operands_annotated = if let Some(pos) = annotated_output.find(' ') {
                annotated_output[pos + 1..].to_string()
            } else {
                String::new()
            };

            let ii = info_factory.info(instr);
            let reads: Vec<String> = ii
                .used_registers()
                .iter()
                .filter(|ur| is_read(ur.access()))
                .map(|ur| format!("{:?}", ur.register()))
                .collect();
            let writes: Vec<String> = ii
                .used_registers()
                .iter()
                .filter(|ur| is_write(ur.access()))
                .map(|ur| format!("{:?}", ur.register()))
                .collect();
            let mem_refs: Vec<MemRefExport> = ii
                .used_memory()
                .iter()
                .map(|um| MemRefExport {
                    base: reg_name(um.base()),
                    index: reg_name(um.index()),
                    scale: um.scale(),
                    displacement: um.displacement(),
                    size: format!("{:?}", um.memory_size()),
                    access: format!("{:?}", um.access()),
                })
                .collect();

            self.export.instructions.push(InstrExport {
                ip: dec.ip,
                bytes_hex: bytes_to_hex(dec.bytes_slice()),
                mnemonic,
                operands_str,
                operands_annotated: Some(operands_annotated),
                flow: format!("{:?}", instr.flow_control()),
                class: InstrClass::Logic,
                reads,
                writes,
                mem_refs,
                comment: self.comments.get(dec.ip, CommentScope::Address).map(String::from),
                pcode_ops: self.pcode_ops.get(&dec.ip).cloned().unwrap_or_default(),
            });

            if va == block.exit_va {
                break;
            }
            va = dec.next_ip();
        }
    }
}

fn reg_name(reg: iced_x86::Register) -> Option<String> {
    if reg == iced_x86::Register::None {
        None
    } else {
        Some(format!("{:?}", reg))
    }
}

fn is_read(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn is_write(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}
