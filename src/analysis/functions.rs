#![allow(dead_code)] // core CFG/function API surface; callers grow in later UI/LLM phases

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::FlowControl;

use crate::analysis::code_index::{CodeIndex, DecodedInstr};
use crate::loader::address_space::AddressSpace;

pub type FunctionId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeKind {
    Fallthrough,
    Unconditional,
    Conditional,
    Call,
    TailCall,
    Indirect,
    Return,
}

#[derive(Clone, Debug)]
pub struct Edge {
    pub target: u64,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub entry_va: u64,
    pub exit_va: u64,
    pub instr_count: usize,
    pub successors: Vec<Edge>,
    pub predecessors: Vec<Edge>,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub id: FunctionId,
    pub entry_va: u64,
    pub blocks: Vec<BasicBlock>,
    /// VAs of direct call/jump targets out of this function (includes unresolved).
    pub outgoing: Vec<u64>,
}

impl Function {
    pub fn name(&self, symbols: &crate::project::symbols::SymbolTable) -> String {
        symbols
            .name(self.entry_va)
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| format!("sub_{:08x}", self.entry_va))
    }

    pub fn size(&self) -> u64 {
        self.blocks
            .last()
            .map(|b| b.exit_va.saturating_sub(self.entry_va) + self.block_last_len(b))
            .unwrap_or(0)
    }

    fn block_last_len(&self, block: &BasicBlock) -> u64 {
        // Approximate: use block length / instr_count; good enough for UI sizing.
        if block.instr_count == 0 {
            0
        } else {
            (block.exit_va - block.entry_va + 1) / block.instr_count as u64
        }
    }

    /// All instruction VAs in this function, in order (blocks are sorted by entry_va).
    pub fn instruction_vas(&self) -> Vec<u64> {
        self.blocks.iter().map(|b| b.entry_va).collect()
    }
}

pub struct FunctionTable {
    by_entry: BTreeMap<FunctionId, Function>,
}

impl Default for FunctionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionTable {
    pub fn new() -> Self {
        Self {
            by_entry: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, function: Function) {
        self.by_entry.insert(function.entry_va, function);
    }

    pub fn get(&self, va: u64) -> Option<&Function> {
        self.by_entry.get(&va)
    }

    pub fn get_mut(&mut self, va: u64) -> Option<&mut Function> {
        self.by_entry.get_mut(&va)
    }

    pub fn contains(&self, va: u64) -> bool {
        self.by_entry.contains_key(&va)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.by_entry.values()
    }

    pub fn len(&self) -> usize {
        self.by_entry.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_entry.is_empty()
    }

    pub fn block_at_va(&self, va: u64) -> Option<(FunctionId, &BasicBlock)> {
        for func in self.by_entry.values() {
            if let Some(block) = func.blocks.iter().find(|b| b.entry_va == va) {
                return Some((func.entry_va, block));
            }
        }
        None
    }
}

/// Discover functions via recursive descent from seeds and their direct callees.
pub fn discover_functions(
    code_index: &CodeIndex,
    address_space: &AddressSpace,
    seeds: &[u64],
) -> FunctionTable {
    let mut discovery = Discovery {
        code_index,
        address_space,
        function_entries: seeds.iter().copied().collect(),
        block_owners: BTreeMap::new(),
        functions: BTreeMap::new(),
    };
    discovery.run(seeds);
    FunctionTable {
        by_entry: discovery.functions,
    }
}

struct Discovery<'a> {
    code_index: &'a CodeIndex,
    address_space: &'a AddressSpace,
    function_entries: BTreeSet<u64>,
    block_owners: BTreeMap<u64, FunctionId>,
    functions: BTreeMap<FunctionId, Function>,
}

impl<'a> Discovery<'a> {
    fn run(&mut self, seeds: &[u64]) {
        let mut worklist: VecDeque<u64> = seeds.iter().copied().collect();
        while let Some(entry) = worklist.pop_front() {
            if self.functions.contains_key(&entry) {
                continue;
            }
            if !self.address_space.is_executable_va(entry) {
                continue;
            }
            self.discover_function(entry, &mut worklist);
        }
    }

    fn discover_function(&mut self, entry: u64, function_worklist: &mut VecDeque<u64>) {
        // Claim the entry block for this function if it isn't already owned.
        if let Some(owner) = self.block_owners.get(&entry).copied() {
            if owner != entry {
                // Seed landed in another function; ignore.
                return;
            }
        } else {
            self.block_owners.insert(entry, entry);
        }

        let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
        let mut block_queue: VecDeque<u64> = VecDeque::new();
        block_queue.push_back(entry);

        while let Some(start) = block_queue.pop_front() {
            if blocks.contains_key(&start) {
                continue;
            }
            if let Some(owner) = self.block_owners.get(&start).copied() {
                if owner != entry {
                    continue; // block belongs to another function
                }
            } else {
                self.block_owners.insert(start, entry);
            }

            self.decode_block(start, entry, &mut blocks, &mut block_queue, function_worklist);
        }

        let mut function = Function {
            id: entry,
            entry_va: entry,
            blocks: blocks.into_values().collect(),
            outgoing: Vec::new(),
        };
        // The BTreeMap iteration is sorted by entry_va, so blocks are in address order.
        Self::compute_predecessors(&mut function);
        self.functions.insert(entry, function);
    }

    fn decode_block(
        &mut self,
        start: u64,
        function_entry: u64,
        blocks: &mut BTreeMap<u64, BasicBlock>,
        block_queue: &mut VecDeque<u64>,
        function_worklist: &mut VecDeque<u64>,
    ) {
        let mut instrs: Vec<&DecodedInstr> = Vec::new();
        let mut successors: Vec<Edge> = Vec::new();
        let mut va = start;
        let mut exit_va = start;

        while let Some(dec) = self.code_index.at_va(va) {
            // If we crossed into another function's territory, stop this block.
            if self.is_owned_by_other(va, function_entry) {
                break;
            }

            // If we landed on a block start of another part of the same function while
            // walking, close the current block with a fallthrough edge.
            if va != start && blocks.contains_key(&va) {
                successors.push(Edge {
                    target: va,
                    kind: EdgeKind::Fallthrough,
                });
                break;
            }

            exit_va = va;
            instrs.push(dec);

            match dec.instr.flow_control() {
                FlowControl::Next => {
                    va = dec.next_ip();
                }
                FlowControl::UnconditionalBranch => {
                    let target = dec.instr.near_branch_target();
                    if self.is_executable_target(target) {
                        if self.is_function_entry(target) && target != function_entry {
                            successors.push(Edge {
                                target,
                                kind: EdgeKind::TailCall,
                            });
                        } else {
                            self.claim_or_queue_block(target, function_entry, block_queue);
                            successors.push(Edge {
                                target,
                                kind: EdgeKind::Unconditional,
                            });
                        }
                    }
                    break;
                }
                FlowControl::ConditionalBranch => {
                    let next_ip = dec.next_ip();
                    let target = dec.instr.near_branch_target();
                    if self.is_executable_target(next_ip) {
                        self.claim_or_queue_block(next_ip, function_entry, block_queue);
                        successors.push(Edge {
                            target: next_ip,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                    if self.is_executable_target(target) {
                        self.claim_or_queue_block(target, function_entry, block_queue);
                        successors.push(Edge {
                            target,
                            kind: EdgeKind::Conditional,
                        });
                    }
                    break;
                }
                FlowControl::Call => {
                    let next_ip = dec.next_ip();
                    let target = dec.instr.near_branch_target();
                    if self.is_executable_target(next_ip) {
                        self.claim_or_queue_block(next_ip, function_entry, block_queue);
                        successors.push(Edge {
                            target: next_ip,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                    if self.is_executable_target(target) {
                        if self.function_entries.insert(target) {
                            function_worklist.push_back(target);
                        }
                        successors.push(Edge {
                            target,
                            kind: EdgeKind::Call,
                        });
                    }
                    break;
                }
                FlowControl::IndirectBranch => {
                    successors.push(Edge {
                        target: 0,
                        kind: EdgeKind::Indirect,
                    });
                    break;
                }
                FlowControl::IndirectCall => {
                    let next_ip = dec.next_ip();
                    if self.is_executable_target(next_ip) {
                        self.claim_or_queue_block(next_ip, function_entry, block_queue);
                        successors.push(Edge {
                            target: next_ip,
                            kind: EdgeKind::Fallthrough,
                        });
                    }
                    successors.push(Edge {
                        target: 0,
                        kind: EdgeKind::Indirect,
                    });
                    break;
                }
                FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => {
                    successors.push(Edge {
                        target: 0,
                        kind: EdgeKind::Return,
                    });
                    break;
                }
                FlowControl::XbeginXabortXend => {
                    // End the block; no simple successor.
                    break;
                }
            }
        }

        blocks.insert(
            start,
            BasicBlock {
                entry_va: start,
                exit_va,
                instr_count: instrs.len(),
                successors,
                predecessors: Vec::new(),
            },
        );
    }

    fn is_owned_by_other(&self, va: u64, function_entry: FunctionId) -> bool {
        self.block_owners
            .get(&va)
            .map(|owner| *owner != function_entry)
            .unwrap_or(false)
    }

    fn is_function_entry(&self, va: u64) -> bool {
        self.function_entries.contains(&va)
    }

    fn is_executable_target(&self, va: u64) -> bool {
        va != 0 && self.address_space.is_executable_va(va)
    }

    fn claim_or_queue_block(
        &mut self,
        va: u64,
        function_entry: FunctionId,
        block_queue: &mut VecDeque<u64>,
    ) {
        if self.block_owners.get(&va).copied() != Some(function_entry)
            && !self.block_owners.contains_key(&va)
        {
            self.block_owners.insert(va, function_entry);
            block_queue.push_back(va);
        }
    }

    fn compute_predecessors(function: &mut Function) {
        let block_starts: Vec<u64> = function.blocks.iter().map(|b| b.entry_va).collect();
        for start in &block_starts {
            let succs = {
                let block = function
                    .blocks
                    .iter()
                    .find(|b| b.entry_va == *start)
                    .expect("block exists");
                block.successors.clone()
            };
            for edge in succs {
                if edge.target == 0 {
                    continue;
                }
                let pred = Edge {
                    target: *start,
                    kind: edge.kind,
                };
                if let Some(target_block) = function.blocks.iter_mut().find(|b| b.entry_va == edge.target) {
                    target_block.predecessors.push(pred);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table() {
        let table = FunctionTable::new();
        assert!(table.is_empty());
    }
}
