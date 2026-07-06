#![allow(dead_code)] // most public methods are the programmatic LLM/UI surface; not all callers exist yet

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;

use crate::analysis::Analysis;
use crate::analysis::functions::{Function, FunctionTable};
use crate::analysis::xrefs::{Xref, XrefIndex};
use crate::ir::export::{function_to_export, to_llm_text, FunctionExport};
use crate::loader::pe::LoadedPe;
use crate::loader::AddressSpace;

pub mod command;
pub mod comments;
pub mod symbols;
pub mod types;

use command::{BatchRename, CommandStack, SetComment, SetName};
use comments::{CommentScope, CommentStore};
use symbols::{SymbolKind, SymbolTable};
use types::DataTypeManager;

#[allow(dead_code)] // symbols/types/commands are the decompiler/LLM seams
pub struct Project {
    /// The loaded PE image and surface analysis.
    pub pe: LoadedPe,
    /// Memory layout / VA↔offset translations.
    pub address_space: AddressSpace,
    /// Cached analysis: decoded code, functions, CFG, xrefs.
    pub analysis: Analysis,
    /// User-defined and auto-discovered symbols.
    pub symbols: SymbolTable,
    /// Per-address and per-function comments.
    pub comments: CommentStore,
    /// Project-wide data types (seam for decompiler/LLM phases).
    pub types: DataTypeManager,
    /// Undo/redo stack.
    pub commands: CommandStack,
    /// Current function cursor for LLM/function-scope UI operations.
    pub focus: Option<u64>,
}

impl Project {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let pe = LoadedPe::open(path)?;
        let mut symbols = SymbolTable::default();
        SeedSymbolTable::from_triage(&pe, &mut symbols);

        let optional = pe.triage.optional_header.as_ref();
        let sections = pe.triage.sections.as_deref().unwrap_or_default();
        let image_base = optional.map(|h| h.image_base).unwrap_or_default();
        let entry_rva = optional.map(|h| h.address_of_entry_point).unwrap_or_default();
        let entry_va = image_base.saturating_add(entry_rva);
        let address_space = AddressSpace::new(image_base, sections);
        let magic = optional.map(|h| h.magic.as_str()).unwrap_or("PE32");
        let bitness = address_space.bitness(magic);
        let analysis = Analysis::build(&pe.image, &address_space, bitness, entry_va, &symbols);

        // Auto-name discovered functions if they don't already have a symbol.
        for func in analysis.functions.iter() {
            if symbols.get(func.entry_va).is_none() {
                symbols.insert(
                    func.entry_va,
                    format!("sub_{:08x}", func.entry_va),
                    SymbolKind::Function,
                );
            }
        }

        Ok(Self {
            pe,
            address_space,
            analysis,
            symbols,
            comments: CommentStore::default(),
            types: DataTypeManager::default(),
            commands: CommandStack::default(),
            focus: Some(entry_va),
        })
    }

    /// LLM/programmatic read API ------------------------------------------------
    pub fn functions(&self) -> &FunctionTable {
        &self.analysis.functions
    }

    pub fn function_at(&self, va: u64) -> Option<&Function> {
        self.analysis.functions.get(va)
    }

    pub fn focused_function(&self) -> Option<&Function> {
        self.focus.and_then(|va| self.function_at(va))
    }

    pub fn xrefs_to(&self, va: u64) -> &[Xref] {
        self.analysis.xrefs.to(va)
    }

    pub fn xrefs_index(&self) -> &XrefIndex {
        &self.analysis.xrefs
    }

    pub fn function_export(&self, va: u64) -> Option<FunctionExport> {
        let func = self.function_at(va)?;
        function_to_export(
            func,
            &self.analysis.code_index,
            &self.symbols,
            &self.comments,
            &self.analysis.xrefs,
        )
    }

    pub fn function_llm_text(&self, va: u64) -> Option<String> {
        self.function_export(va).map(|e| to_llm_text(&e))
    }

    /// LLM/programmatic mutation API (all routed through CommandStack so an
    /// operator can Ctrl-Z any LLM action).
    pub fn rename(&mut self, va: u64, name: impl Into<String>) {
        let cmd = Box::new(SetName::new(va, name, SymbolKind::User));
        self.execute_command(cmd);
    }

    pub fn set_comment(&mut self, va: u64, text: impl Into<String>) {
        let cmd = Box::new(SetComment::new(va, text, CommentScope::Address));
        self.execute_command(cmd);
    }

    pub fn apply_rename_batch(&mut self, map: HashMap<String, String>) {
        let focus = match self.focus {
            Some(va) => va,
            None => return,
        };

        let mut commands: Vec<Box<dyn command::Command>> = Vec::new();
        for (key, value) in map {
            if key == "__function__" {
                commands.push(Box::new(SetName::new(focus, value, SymbolKind::User)));
            } else {
                // Without a decompiler variable model, we cannot map placeholder IDs
                // like v1/v2 to concrete addresses. Preserve the suggestion as a
                // function-scope comment so the operator can review it.
                commands.push(Box::new(SetComment::new(
                    focus,
                    format!("{key}: {value}"),
                    CommentScope::Function,
                )));
            }
        }

        if commands.is_empty() {
            return;
        }
        self.execute_command(Box::new(BatchRename::new(commands)));
    }

    pub fn set_focus(&mut self, va: u64) {
        if self.function_at(va).is_some() {
            self.focus = Some(va);
        }
    }

    pub fn undo(&mut self) {
        let mut commands = std::mem::take(&mut self.commands);
        commands.undo(self);
        self.commands = commands;
    }

    pub fn redo(&mut self) {
        let mut commands = std::mem::take(&mut self.commands);
        commands.redo(self);
        self.commands = commands;
    }

    pub fn can_undo(&self) -> bool {
        self.commands.can_undo()
    }

    pub fn can_redo(&self) -> bool {
        self.commands.can_redo()
    }

    fn execute_command(&mut self, cmd: Box<dyn command::Command>) {
        let mut commands = std::mem::take(&mut self.commands);
        commands.execute(self, cmd);
        self.commands = commands;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_notepad_functions_and_export() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }

        let project = Project::open(path).expect("should load notepad.exe");
        assert!(!project.functions().is_empty(), "should discover functions");

        let entry = project.focus.expect("should have entry focus");
        assert!(
            project.function_at(entry).is_some(),
            "entry point should be a discovered function"
        );

        let export = project
            .function_export(entry)
            .expect("should export entry function");
        assert!(!export.instructions.is_empty(), "export should have instructions");
        assert!(!export.blocks.is_empty(), "export should have blocks");

        let text = project.function_llm_text(entry).expect("llm text");
        assert!(text.starts_with('<') && text.contains('>'));
        assert!(text.contains('\n'));
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
