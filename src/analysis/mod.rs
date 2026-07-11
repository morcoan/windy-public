use crate::analysis::code_index::{CodeIndex};
use crate::analysis::functions::{discover_functions, FunctionTable};
use crate::analysis::xrefs::{XrefIndex};
use crate::loader::address_space::AddressSpace;
use crate::project::symbols::{SymbolKind, SymbolTable};

pub mod code_index;
pub mod functions;
pub mod indirect;
pub mod search;
pub mod signatures;
pub mod stack_frame;
pub mod thunks;
pub mod unwind;
pub mod vtable_sigs;
pub mod win32_sigs;
pub mod xrefs;

/// Cached analysis artifacts for a loaded image.
#[derive(Clone, Debug)]
pub struct Analysis {
    /// Decoded executable-section cache.
    pub code_index: CodeIndex,
    /// Authoritative AMD64 runtime-function ranges recovered from the PE
    /// exception directory (`.pdata`) when the image provides them.  These
    /// seed function discovery and remain available to later unwind/frame/EH
    /// analysis; absence or malformed metadata never prevents basic analysis.
    pub runtime_functions: unwind::RuntimeFunctionTable,
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

        // On native x64 Windows binaries, `.pdata` is a much stronger source
        // of function starts than recursive descent alone.  Keep parsing
        // conservative: malformed or unavailable metadata simply contributes
        // no seeds and the existing discovery path remains intact.
        let runtime_functions = if bitness == 64 {
            unwind::parse_runtime_functions(image, address_space).unwrap_or_default()
        } else {
            unwind::RuntimeFunctionTable::default()
        };

        // Seed functions: entry point + exports/PDB symbols + authoritative
        // x64 runtime-function entries.  Direct-call discovery then expands
        // beyond these roots as before.
        let mut seeds: Vec<u64> = vec![entry_va];
        for (addr, sym) in symbols.iter() {
            if sym.kind == SymbolKind::Export || sym.kind == SymbolKind::Function {
                seeds.push(addr);
            }
        }
        seeds.extend(runtime_functions.entry_points());
        seeds.sort_unstable();
        seeds.dedup();

        let functions = discover_functions(&code_index, address_space, &seeds);
        let xrefs = XrefIndex::build(&code_index, address_space, bitness);

        Self {
            code_index,
            runtime_functions,
            functions,
            xrefs,
        }
    }
}
