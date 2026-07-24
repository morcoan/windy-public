use std::collections::HashMap;
use std::sync::Arc;

use iced_x86::{
    Decoder, DecoderOptions, Formatter as _, Instruction, IntelFormatter, MasmFormatter,
    NasmFormatter, SymbolResolver, SymbolResult,
};

use crate::project::symbols::SymbolTable;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Syntax {
    #[default]
    Intel,
    #[allow(dead_code)] // selectable disassembly syntax
    Nasm,
    #[allow(dead_code)] // selectable disassembly syntax
    Masm,
}

impl Syntax {
    fn format_instruction_shared(
        &self,
        instr: &Instruction,
        names: Arc<HashMap<u64, String>>,
    ) -> String {
        let mut output = String::new();
        let resolver: Option<Box<dyn SymbolResolver>> =
            Some(Box::new(TableResolver::from_shared(names)));
        match self {
            Syntax::Intel => {
                IntelFormatter::with_options(resolver, None).format(instr, &mut output);
            }
            Syntax::Nasm => {
                NasmFormatter::with_options(resolver, None).format(instr, &mut output);
            }
            Syntax::Masm => {
                MasmFormatter::with_options(resolver, None).format(instr, &mut output);
            }
        }
        output
    }
}

/// Owns the symbol-name map so it can satisfy iced's `'static` formatter resolver.
pub struct TableResolver {
    names: Arc<HashMap<u64, String>>,
}

impl TableResolver {
    pub fn from_map(names: &HashMap<u64, String>) -> Self {
        Self {
            names: Arc::new(names.clone()),
        }
    }

    pub fn from_shared(names: Arc<HashMap<u64, String>>) -> Self {
        Self { names }
    }

    #[allow(dead_code)] // alternate constructor for TableResolver
    pub fn from_symbol_table(table: &SymbolTable) -> Self {
        Self {
            names: Arc::new(table.to_resolver_map()),
        }
    }
}

impl SymbolResolver for TableResolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        self.names
            .get(&address)
            .map(|name| SymbolResult::with_str(address, name.as_str()))
    }
}

/// Stable disassembler instance. Rebuild it when the symbol table changes so
/// newly renamed symbols appear in the listing.
pub struct Disassembler {
    syntax: Syntax,
    names: Arc<HashMap<u64, String>>,
}

impl Disassembler {
    pub fn new(syntax: Syntax, names: HashMap<u64, String>) -> Self {
        Self {
            syntax,
            names: Arc::new(names),
        }
    }

    pub fn new_from_symbol_table(syntax: Syntax, table: &SymbolTable) -> Self {
        Self::new(syntax, table.to_resolver_map())
    }

    pub fn format(&self, instr: &Instruction) -> String {
        self.syntax
            .format_instruction_shared(instr, self.names.clone())
    }

    #[allow(dead_code)] // rebuild resolver after symbol renames
    pub fn set_names(&mut self, table: &SymbolTable) {
        self.names = Arc::new(table.to_resolver_map());
    }
}

#[allow(dead_code)] // range decoder used by pcode tests / offline tooling
pub fn decode_range(
    bitness: u32,
    bytes: &[u8],
    start_ip: u64,
) -> impl Iterator<Item = Instruction> + '_ {
    let mut decoder = Decoder::with_ip(bitness, bytes, start_ip, DecoderOptions::NONE);
    std::iter::from_fn(move || {
        if decoder.can_decode() {
            Some(decoder.decode())
        } else {
            None
        }
    })
}
