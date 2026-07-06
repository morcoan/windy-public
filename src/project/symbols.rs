#![allow(dead_code)] // Symbol table seam; actively used in Phase 2+

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolKind {
    Import,
    Export,
    Function,
    Data,
    User,
}

#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
}

#[derive(Default)]
pub struct SymbolTable {
    by_addr: HashMap<u64, Symbol>,
}

impl SymbolTable {
    pub fn insert(&mut self, addr: u64, name: impl Into<String>, kind: SymbolKind) {
        self.by_addr.insert(
            addr,
            Symbol {
                name: name.into(),
                kind,
            },
        );
    }

    pub fn get(&self, addr: u64) -> Option<&Symbol> {
        self.by_addr.get(&addr)
    }

    pub fn name(&self, addr: u64) -> Option<&str> {
        self.get(addr).map(|s| s.name.as_str())
    }

    pub fn remove(&mut self, addr: u64) {
        self.by_addr.remove(&addr);
    }
}
