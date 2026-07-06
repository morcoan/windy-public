use crate::analysis::code_index::{CodeIndex};
use crate::analysis::functions::{discover_functions, FunctionTable};
use crate::analysis::xrefs::{XrefIndex};
use crate::loader::address_space::AddressSpace;
use crate::project::symbols::{SymbolKind, SymbolTable};

pub mod code_index;
pub mod functions;
pub mod xrefs;

/// Cached analysis artifacts for a loaded image.
pub struct Analysis {
    /// Decoded executable-section cache.
    pub code_index: CodeIndex,
    /// Discovered functions with basic-block CFG.
    pub functions: FunctionTable,
    /// Cross-reference index.
    pub xrefs: XrefIndex,
}

impl Analysis {
    pub fn build(
        image: &[u8],
        address_space: &AddressSpace,
        bitness: u32,
        entry_va: u64,
        symbols: &SymbolTable,
    ) -> Self {
        let code_index = CodeIndex::build(image, address_space, bitness);

        // Seed functions: entry point + every exported address.
        let mut seeds: Vec<u64> = vec![entry_va];
        for (addr, sym) in symbols.iter() {
            if sym.kind == SymbolKind::Export {
                seeds.push(addr);
            }
        }
        seeds.sort_unstable();
        seeds.dedup();

        let functions = discover_functions(&code_index, address_space, &seeds);
        let xrefs = XrefIndex::build(&code_index);

        Self {
            code_index,
            functions,
            xrefs,
        }
    }
}
