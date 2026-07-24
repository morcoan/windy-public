use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::{
    FunctionTable, discover_functions, discover_functions_with_entry_hints,
};
use crate::analysis::xrefs::XrefIndex;
use crate::loader::address_space::AddressSpace;
use crate::project::symbols::{SymbolKind, SymbolTable};
use std::sync::{Arc, OnceLock};

pub mod bel;
pub mod code_index;
pub mod functions;
pub mod indirect;
pub mod mem_walk;
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
    /// Lazily formatted instruction text used by whole-image searches. Shared
    /// across project snapshots so renames/comments do not discard the cache.
    pub instruction_search: Arc<OnceLock<search::InstructionSearchIndex>>,
    /// Sorted immediate-value postings for exact numeric/VA searches.
    pub immediate_search: Arc<OnceLock<search::ImmediateSearchIndex>>,
    /// Immutable Binary Evidence Lattice, built cooperatively after project
    /// open and shared across copy-on-write annotation snapshots.
    pub bel: Arc<bel::BelIndexCell>,
}

impl Analysis {
    pub fn build(
        image: &[u8],
        address_space: &AddressSpace,
        bitness: u32,
        entry_va: u64,
        symbols: &SymbolTable,
    ) -> Self {
        Self::build_with_entry_hints(image, address_space, bitness, entry_va, symbols, &[])
    }

    /// Build analysis while treating caller-supplied addresses as trusted
    /// function boundaries. This is intended for authoritative metadata such
    /// as linker maps used by exact-address evaluations; ordinary product
    /// opens continue to use [`Self::build`] and PE/PDB-derived seeds only.
    pub fn build_with_entry_hints(
        image: &[u8],
        address_space: &AddressSpace,
        bitness: u32,
        entry_va: u64,
        symbols: &SymbolTable,
        entry_hints: &[u64],
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
        seeds.extend(entry_hints.iter().copied());
        seeds.sort_unstable();
        seeds.dedup();

        // Function discovery and xref indexing only read the decoded cache, so
        // run them together on large images instead of serially walking the
        // entire instruction set twice.
        let (functions, xrefs) = std::thread::scope(|scope| {
            let xref_task = scope.spawn(|| XrefIndex::build(&code_index, address_space, bitness));
            let functions = if entry_hints.is_empty() {
                discover_functions(&code_index, address_space, &seeds)
            } else {
                discover_functions_with_entry_hints(&code_index, address_space, &seeds, entry_hints)
            };
            let xrefs = xref_task.join().expect("xref indexing thread panicked");
            (functions, xrefs)
        });

        Self {
            code_index,
            runtime_functions,
            functions,
            xrefs,
            instruction_search: Arc::new(OnceLock::new()),
            immediate_search: Arc::new(OnceLock::new()),
            bel: Arc::new(bel::BelIndexCell::default()),
        }
    }
}
