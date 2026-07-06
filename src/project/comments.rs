#![allow(dead_code)] // Comment store; actively used in Phase 3

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommentScope {
    Address,
    Function,
}

/// User-defined and LLM-generated comments keyed by address or function.
#[derive(Default)]
pub struct CommentStore {
    by_addr: BTreeMap<u64, String>,
    by_function: BTreeMap<u64, String>,
}

impl CommentStore {
    pub fn get(&self, va: u64, scope: CommentScope) -> Option<&str> {
        let map = match scope {
            CommentScope::Address => &self.by_addr,
            CommentScope::Function => &self.by_function,
        };
        map.get(&va).map(String::as_str)
    }

    pub fn set(&mut self, va: u64, scope: CommentScope, text: impl Into<String>) {
        let map = match scope {
            CommentScope::Address => &mut self.by_addr,
            CommentScope::Function => &mut self.by_function,
        };
        map.insert(va, text.into());
    }

    pub fn remove(&mut self, va: u64, scope: CommentScope) {
        let map = match scope {
            CommentScope::Address => &mut self.by_addr,
            CommentScope::Function => &mut self.by_function,
        };
        map.remove(&va);
    }
}
