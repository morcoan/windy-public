use std::path::Path;

use anyhow::Result;

use crate::loader::pe::LoadedPe;

pub mod command;
pub mod symbols;
pub mod types;

use command::CommandStack;
use symbols::{SymbolKind, SymbolTable};
use types::DataTypeManager;

#[allow(dead_code)] // symbols/types/commands are the decompiler/LLM seams
pub struct Project {
    /// The loaded PE image and surface analysis.
    pub pe: LoadedPe,
    /// User-defined and auto-discovered symbols.
    pub symbols: SymbolTable,
    /// Project-wide data types (seam for decompiler/LLM phases).
    pub types: DataTypeManager,
    /// Undo/redo stack.
    pub commands: CommandStack,
}

impl Project {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let pe = LoadedPe::open(path)?;
        let mut symbols = SymbolTable::default();

        SeedSymbolTable::from_triage(&pe, &mut symbols);

        Ok(Self {
            pe,
            symbols,
            types: DataTypeManager::default(),
            commands: CommandStack::default(),
        })
    }
}

struct SeedSymbolTable;

impl SeedSymbolTable {
    fn from_triage(pe: &LoadedPe, symbols: &mut SymbolTable) {
        if let Some(imports) = &pe.triage.imports {
            for entry in imports {
                let dll = &entry.dll;
                for func in &entry.functions {
                    // Imports don't have a load-time VA here, so skip for now.
                    let _ = (dll, func);
                }
            }
        }

        if let Some(exports) = &pe.triage.exports {
            let base = pe
                .triage
                .optional_header
                .as_ref()
                .map(|h| h.image_base)
                .unwrap_or_default();
            for exp in exports {
                let va = base.saturating_add(exp.rva as u64);
                symbols.insert(va, &exp.name, SymbolKind::Export);
            }
        }
    }
}
