#![allow(dead_code)] // XrefKind variants reserved for future data-xref pass

use std::collections::BTreeMap;

use iced_x86::FlowControl;

use crate::analysis::code_index::CodeIndex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    JumpUnconditional,
    JumpTaken,
    DataRead,
    DataWrite,
    Indirect,
}

#[derive(Clone, Debug)]
pub struct Xref {
    pub from_va: u64,
    pub to_va: u64,
    pub kind: XrefKind,
}

/// Cross-reference look-up tables: code and data references between VAs.
#[derive(Default)]
pub struct XrefIndex {
    /// References *to* a given VA.
    pub to: BTreeMap<u64, Vec<Xref>>,
    /// References *from* a given VA.
    pub from: BTreeMap<u64, Vec<Xref>>,
}

impl XrefIndex {
    pub fn build(code_index: &CodeIndex) -> Self {
        let mut to: BTreeMap<u64, Vec<Xref>> = BTreeMap::new();
        let mut from: BTreeMap<u64, Vec<Xref>> = BTreeMap::new();

        for dec in code_index.iter() {
            let target = match dec.instr.flow_control() {
                FlowControl::Call => Some((dec.instr.near_branch_target(), XrefKind::Call)),
                FlowControl::UnconditionalBranch => {
                    Some((dec.instr.near_branch_target(), XrefKind::JumpUnconditional))
                }
                FlowControl::ConditionalBranch => {
                    Some((dec.instr.near_branch_target(), XrefKind::JumpTaken))
                }
                _ => None,
            };

            if let Some((to_va, kind)) = target {
                if to_va == 0 {
                    continue;
                }
                let xref = Xref {
                    from_va: dec.ip,
                    to_va,
                    kind,
                };
                to.entry(to_va).or_default().push(xref.clone());
                from.entry(dec.ip).or_default().push(xref);
            }
        }

        Self { to, from }
    }

    pub fn to(&self, va: u64) -> &[Xref] {
        self.to.get(&va).map(Vec::as_slice).unwrap_or_default()
    }

    pub fn from(&self, va: u64) -> &[Xref] {
        self.from.get(&va).map(Vec::as_slice).unwrap_or_default()
    }
}
