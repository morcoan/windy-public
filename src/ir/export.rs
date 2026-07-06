#![allow(dead_code)] // export API; actively used once LLM layer is wired

use std::collections::HashSet;

use iced_x86::{Formatter as _, InstructionInfoFactory, IntelFormatter, OpAccess};
use serde::Serialize;

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::{BasicBlock, Function};
use crate::analysis::xrefs::XrefIndex;
use crate::project::comments::{CommentScope, CommentStore};
use crate::project::symbols::SymbolTable;

#[derive(Serialize, Debug, Clone)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub type_guess: Option<String>,
    pub reg: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
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
    pub flow: String,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub mem_refs: Vec<MemRefExport>,
    pub comment: Option<String>,
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
    pub blocks: Vec<BlockExport>,
    pub instructions: Vec<InstrExport>,
    pub xrefs_in: Vec<u64>,
    pub xrefs_out: Vec<u64>,
}

/// Render a function to the exact text format LLM4Decompile-End consumes:
/// `<name>:\n<mnemonic operands>\n...`.
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

pub fn function_to_export(
    func: &Function,
    code_index: &CodeIndex,
    symbols: &SymbolTable,
    comments: &CommentStore,
    xrefs: &XrefIndex,
) -> Option<FunctionExport> {
    let mut builder = FunctionExportBuilder {
        code_index,
        symbols,
        comments,
        xrefs,
        export: FunctionExport {
            name: func.name(symbols),
            entry_va: func.entry_va,
            calling_conv: None,
            params: Vec::new(),
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

    Some(builder.export)
}

struct FunctionExportBuilder<'a> {
    code_index: &'a CodeIndex,
    symbols: &'a SymbolTable,
    comments: &'a CommentStore,
    xrefs: &'a XrefIndex,
    export: FunctionExport,
}

impl<'a> FunctionExportBuilder<'a> {
    fn collect_block_instructions(&mut self, block: &BasicBlock, seen_vas: &mut HashSet<u64>) {
        let mut va = block.entry_va;
        let mut info_factory = InstructionInfoFactory::new();

        while let Some(dec) = self.code_index.at_va(va) {
            seen_vas.insert(va);
            let instr = &dec.instr;

            let mut mnemonic = String::new();
            let mut operands_str = String::new();
            let mut formatter = IntelFormatter::new();
            formatter.format_mnemonic(instr, &mut mnemonic);
            formatter.format_all_operands(instr, &mut operands_str);

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
                flow: format!("{:?}", instr.flow_control()),
                reads,
                writes,
                mem_refs,
                comment: self.comments.get(dec.ip, CommentScope::Address).map(String::from),
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
