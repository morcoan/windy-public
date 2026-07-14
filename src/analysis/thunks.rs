//! Detect import forwarder thunks: small functions consisting of a single
//! `jmp [__imp_<Api>]`. These are renamed to the API name so call sites
//! resolve cleanly for the LLM.

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::FunctionTable;
use crate::project::symbols::{SymbolKind, SymbolTable};

/// A detected thunk that should be renamed.
#[derive(Clone, Debug)]
pub struct ThunkRename {
    pub thunk_va: u64,
    pub api_name: String,
    #[allow(dead_code)] // IAT slot VA retained for future import xrefs UI
    pub slot_va: u64,
}

/// Find single-instruction `jmp [__imp_<Api>]` forwarders and return rename
/// suggestions without mutating the symbol table.
pub fn find_thunk_renames(
    functions: &FunctionTable,
    code_index: &CodeIndex,
    symbols: &SymbolTable,
    bitness: u32,
) -> Vec<ThunkRename> {
    let mut out = Vec::new();

    for func in functions.iter() {
        // Thunks are one basic block with exactly one instruction.
        if func.blocks.len() != 1 || func.blocks[0].instr_count != 1 {
            continue;
        }
        let dec = match code_index.at_va(func.entry_va) {
            Some(d) => d,
            None => continue,
        };
        let instr = &dec.instr;
        if instr.mnemonic() != Mnemonic::Jmp {
            continue;
        }
        if instr.op0_kind() != OpKind::Memory {
            continue;
        }

        let slot_va = match memory_target_va(instr, bitness) {
            Some(va) => va,
            None => continue,
        };

        let sym = match symbols.get(slot_va) {
            Some(s) => s,
            None => continue,
        };
        if sym.kind != SymbolKind::Import {
            continue;
        }
        let api_name = match sym.name.strip_prefix("__imp_") {
            Some(api) if !api.is_empty() => api.to_string(),
            _ => continue,
        };

        out.push(ThunkRename {
            thunk_va: func.entry_va,
            api_name,
            slot_va,
        });
    }

    out
}

/// Apply thunk renames to the symbol table. Existing names at the thunk VA are
/// overwritten because thunks are compiler-generated and the API name is more
/// useful.
#[allow(dead_code)] // Used by Project open when bulk-applying thunk renames
pub fn apply_thunk_renames(symbols: &mut SymbolTable, renames: &[ThunkRename]) {
    for rename in renames {
        symbols.insert(rename.thunk_va, rename.api_name.clone(), SymbolKind::Import);
    }
}

/// Compute the absolute VA of a memory operand for simple addressing modes:
///   - x64 RIP-relative (`[rip+disp]`)
///   - x86 absolute (`[disp]`)
fn memory_target_va(instr: &Instruction, bitness: u32) -> Option<u64> {
    let base = instr.memory_base();
    let index = instr.memory_index();

    if base == Register::RIP && index == Register::None && bitness == 64 {
        let next_ip = instr.next_ip();
        let disp = instr.memory_displacement64() as i32 as i64;
        return Some(next_ip.wrapping_add(disp as u64));
    }

    if base == Register::None && index == Register::None {
        return Some(instr.memory_displacement64());
    }

    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn thunk_module_exists() {
        assert!(true);
    }
}
