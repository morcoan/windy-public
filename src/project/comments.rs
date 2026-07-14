use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommentScope {
    Address,
    Function,
}

/// User-defined and LLM-generated comments keyed by address or function.
#[derive(Default, Clone)]
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

    pub fn addr_entries(&self) -> Vec<(u64, String)> {
        self.by_addr.iter().map(|(&k, v)| (k, v.clone())).collect()
    }

    pub fn function_entries(&self) -> Vec<(u64, String)> {
        self.by_function
            .iter()
            .map(|(&k, v)| (k, v.clone()))
            .collect()
    }

    pub fn set(&mut self, va: u64, scope: CommentScope, text: impl Into<String>) {
        let map = match scope {
            CommentScope::Address => &mut self.by_addr,
            CommentScope::Function => &mut self.by_function,
        };
        map.insert(va, text.into());
    }

    #[allow(dead_code)] // used by UI command undo path
    pub fn remove(&mut self, va: u64, scope: CommentScope) {
        let map = match scope {
            CommentScope::Address => &mut self.by_addr,
            CommentScope::Function => &mut self.by_function,
        };
        map.remove(&va);
    }
}
