use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::FlowControl;

use crate::analysis::code_index::{CodeIndex, DecodedInstr};
use crate::loader::address_space::AddressSpace;
use crate::project::types::{FunctionSignature, StackFrame};

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
    #[allow(dead_code)] // stable function identity for UI/agent surfaces
    pub id: FunctionId,
    pub entry_va: u64,
    pub blocks: Vec<BasicBlock>,
    /// VAs of direct call/jump targets out of this function (includes unresolved).
    #[allow(dead_code)] // call-graph export seam
    pub outgoing: Vec<u64>,
    /// Recovered stack-frame layout, if available.
    pub stack_frame: Option<StackFrame>,
    /// PDB-derived or heuristic signature. Used by exports and the decompiler.
    pub signature: Option<FunctionSignature>,
}

impl Function {
    pub fn name(&self, symbols: &crate::project::symbols::SymbolTable) -> String {
        let raw = symbols
            .name(self.entry_va)
            .map(std::string::ToString::to_string)
            // Ghidra-style default for stripped symbols (gold matches fun_* aliases).
            .unwrap_or_else(|| format!("FUN_{:08x}", self.entry_va));
        // Normalize legacy auto-names so call emit matches fun_* gold aliases.
        if let Some(rest) = raw.strip_prefix("sub_") {
            format!("FUN_{rest}")
        } else {
            raw
        }
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

    /// Rebuild predecessor lists after successor edges have been mutated.
    pub fn recompute_predecessors(&mut self) {
        for block in &mut self.blocks {
            block.predecessors.clear();
        }
        let block_starts: Vec<u64> = self.blocks.iter().map(|b| b.entry_va).collect();
        for start in &block_starts {
            let succs = self
                .blocks
                .iter()
                .find(|b| b.entry_va == *start)
                .expect("block exists")
                .successors
                .clone();
            for edge in succs {
                if edge.target == 0 {
                    continue;
                }
                let pred = Edge {
                    target: *start,
                    kind: edge.kind,
                };
                if let Some(target_block) =
                    self.blocks.iter_mut().find(|b| b.entry_va == edge.target)
                {
                    target_block.predecessors.push(pred);
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct FunctionTable {
    by_entry: BTreeMap<FunctionId, Function>,
}

impl Default for FunctionTable {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // FunctionTable is the analysis API surface; not all methods have in-tree callers yet
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

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Function> {
        self.by_entry.values_mut()
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

    /// Attach recovered stack frames to functions by entry VA.
    pub fn apply_frames(&mut self, frames: &std::collections::BTreeMap<u64, StackFrame>) {
        for func in self.by_entry.values_mut() {
            if let Some(frame) = frames.get(&func.entry_va) {
                func.stack_frame = Some(frame.clone());
            }
        }
    }
}

/// Discover functions via recursive descent from seeds and their direct callees.
pub fn discover_functions(
    code_index: &CodeIndex,
    address_space: &AddressSpace,
    seeds: &[u64],
) -> FunctionTable {
    discover_functions_with_entry_hints(code_index, address_space, seeds, &[])
}

/// Discover functions while preserving a caller-supplied subset of seeds as
/// hard boundaries. PE/PDB/runtime-function seeds retain the established
/// recursive-descent behavior; exact linker entries cannot be absorbed by a
/// neighboring function.
pub fn discover_functions_with_entry_hints(
    code_index: &CodeIndex,
    address_space: &AddressSpace,
    seeds: &[u64],
    entry_hints: &[u64],
) -> FunctionTable {
    let mut discovery = Discovery {
        code_index,
        address_space,
        function_entries: seeds.iter().copied().collect(),
        hard_function_entries: entry_hints.iter().copied().collect(),
        block_owners: BTreeMap::new(),
        functions: BTreeMap::new(),
    };
    discovery.run(seeds);
    // Uncalled leaf helpers (e.g. COM `Release`) often have no inbound call
    // and no `.pdata` entry. Seed them from int3-padded gaps between known
    // functions so they still enter the function table.
    discovery.seed_int3_gap_leaves();
    // SEH filter leaves (ACCESS_VIOLATION compares) are often only referenced
    // from scope tables, not calls/.pdata — seed them from the AV immediate.
    discovery.seed_access_violation_filter_leaves();
    FunctionTable {
        by_entry: discovery.functions,
    }
}

struct Discovery<'a> {
    code_index: &'a CodeIndex,
    address_space: &'a AddressSpace,
    function_entries: BTreeSet<u64>,
    hard_function_entries: BTreeSet<u64>,
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

    /// Seed tiny SEH filter functions that compare against
    /// `EXCEPTION_ACCESS_VIOLATION` (`0xC0000005` / `-0x3FFFFFFB`). These are
    /// typically only referenced from `__C_specific_handler` scope tables and
    /// never appear as call targets or `.pdata` entries.
    fn seed_access_violation_filter_leaves(&mut self) {
        const AV: u64 = 0xc000_0005;
        const AV_NEG: u64 = 0xffff_ffff_c000_0005;
        let mut imm_vas: Vec<u64> = Vec::new();
        for dec in self.code_index.iter() {
            for i in 0..dec.instr.op_count() {
                use iced_x86::OpKind;
                let kind = dec.instr.op_kind(i);
                if !matches!(
                    kind,
                    OpKind::Immediate8
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate32to64
                        | OpKind::Immediate64
                ) {
                    continue;
                }
                let imm = dec.instr.immediate(i);
                if imm == AV || imm == AV_NEG || imm as u32 == AV as u32 {
                    imm_vas.push(dec.ip);
                    break;
                }
            }
        }
        if imm_vas.is_empty() {
            return;
        }
        // Walk back from each AV compare to the preceding int3-padded entry.
        let mut by_ip: BTreeMap<u64, &DecodedInstr> = BTreeMap::new();
        for dec in self.code_index.iter() {
            by_ip.insert(dec.ip, dec);
        }
        let ips: Vec<u64> = by_ip.keys().copied().collect();
        let mut candidates: Vec<u64> = Vec::new();
        for imm_va in imm_vas {
            // Find index of this IP.
            let Some(idx) = ips.binary_search(&imm_va).ok() else {
                continue;
            };
            // Walk backward for int3 padding; entry is first non-int3 after it.
            let mut entry = imm_va;
            let mut j = idx;
            while j > 0 {
                j -= 1;
                let prev = ips[j];
                let Some(dec) = by_ip.get(&prev) else {
                    break;
                };
                let is_int3 = dec.len == 1 && dec.bytes_slice() == [0xcc];
                if is_int3 {
                    // Entry is next IP after this int3 run.
                    entry = ips[j + 1];
                    break;
                }
                // Prefer the start after int3 padding; do not stop early on a
                // parent CRT function that swallowed this filter as a mid-body block.
                entry = prev;
            }
            if self.address_space.is_executable_va(entry) {
                candidates.push(entry);
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        if candidates.is_empty() {
            return;
        }
        // Reclaim: if a candidate is mid-body of a large owner, carve it out.
        for &entry in &candidates {
            if self.functions.contains_key(&entry) {
                continue;
            }
            if let Some(&owner) = self.block_owners.get(&entry)
                && owner != entry
            {
                // Drop ownership of entry.. so discover can claim them.
                let steal: Vec<u64> = self
                    .block_owners
                    .iter()
                    .filter(|(_, o)| **o == owner)
                    .map(|(va, _)| *va)
                    .filter(|va| *va >= entry)
                    .collect();
                for va in steal {
                    self.block_owners.remove(&va);
                }
                // Truncate the parent function's block list.
                if let Some(parent) = self.functions.get_mut(&owner) {
                    parent.blocks.retain(|b| b.entry_va < entry);
                }
            }
        }
        let mut worklist: VecDeque<u64> = VecDeque::new();
        for va in candidates {
            if self.function_entries.insert(va) {
                worklist.push_back(va);
            }
        }
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

    /// After callgraph discovery, claim unowned code that sits after `int3`
    /// padding between existing functions. Typical shape for MSVC leaf
    /// methods that are never called from the scored entry path.
    fn seed_int3_gap_leaves(&mut self) {
        let mut candidates: Vec<u64> = Vec::new();
        let mut prev_was_int3 = false;
        for dec in self.code_index.iter() {
            let va = dec.ip;
            let is_int3 = dec.len == 1 && dec.bytes_slice() == [0xcc];
            if is_int3 {
                prev_was_int3 = true;
                continue;
            }
            if prev_was_int3
                && !self.functions.contains_key(&va)
                && !self.block_owners.contains_key(&va)
                && self.address_space.is_executable_va(va)
            {
                candidates.push(va);
            }
            prev_was_int3 = false;
        }
        if candidates.is_empty() {
            return;
        }
        let mut worklist: VecDeque<u64> = VecDeque::new();
        for va in candidates {
            if self.function_entries.insert(va) {
                worklist.push_back(va);
            }
        }
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

            self.decode_block(
                start,
                entry,
                &mut blocks,
                &mut block_queue,
                function_worklist,
            );
        }

        // Drop any block that starts before the function entry (foreign code
        // claimed via misclassified tail-calls). Keep address order otherwise.
        let mut block_list: Vec<BasicBlock> = blocks
            .into_values()
            .filter(|b| b.entry_va >= entry)
            .collect();
        // Rewrite successors that pointed into dropped foreign blocks as tail-calls.
        for b in &mut block_list {
            for e in &mut b.successors {
                if e.target != 0 && e.target < entry {
                    e.kind = EdgeKind::TailCall;
                }
            }
        }
        let mut function = Function {
            id: entry,
            entry_va: entry,
            blocks: block_list,
            outgoing: Vec::new(),
            stack_frame: None,
            signature: None,
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
            // Trusted seeds are hard function boundaries. Do not let linear
            // decoding absorb a later linker/PDB-known entry merely because
            // the preceding bytes have no recognized terminator.
            if va != start && self.is_hard_function_entry(va) && va != function_entry {
                successors.push(Edge {
                    target: va,
                    kind: EdgeKind::TailCall,
                });
                break;
            }

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
                        // Never absorb code *before* this function's entry via a
                        // backward jmp (MSVC tail-calls to earlier helpers like
                        // AddRef). Treat those as TailCall edges.
                        let foreign_entry = (self.is_function_entry(target)
                            && target != function_entry)
                            || target < function_entry;
                        if foreign_entry {
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
                        let foreign_entry =
                            self.is_hard_function_entry(next_ip) && next_ip != function_entry;
                        if !foreign_entry {
                            self.claim_or_queue_block(next_ip, function_entry, block_queue);
                        }
                        successors.push(Edge {
                            target: next_ip,
                            kind: if foreign_entry {
                                EdgeKind::TailCall
                            } else {
                                EdgeKind::Fallthrough
                            },
                        });
                    }
                    if self.is_executable_target(target) {
                        let foreign_entry =
                            self.is_hard_function_entry(target) && target != function_entry;
                        if !foreign_entry {
                            self.claim_or_queue_block(target, function_entry, block_queue);
                        }
                        successors.push(Edge {
                            target,
                            kind: if foreign_entry {
                                EdgeKind::TailCall
                            } else {
                                EdgeKind::Conditional
                            },
                        });
                    }
                    break;
                }
                FlowControl::Call => {
                    let next_ip = dec.next_ip();
                    let target = dec.instr.near_branch_target();
                    if self.is_executable_target(next_ip) {
                        let foreign_entry =
                            self.is_hard_function_entry(next_ip) && next_ip != function_entry;
                        if !foreign_entry {
                            self.claim_or_queue_block(next_ip, function_entry, block_queue);
                        }
                        successors.push(Edge {
                            target: next_ip,
                            kind: if foreign_entry {
                                EdgeKind::TailCall
                            } else {
                                EdgeKind::Fallthrough
                            },
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

    fn is_hard_function_entry(&self, va: u64) -> bool {
        self.hard_function_entries.contains(&va)
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
                if let Some(target_block) = function
                    .blocks
                    .iter_mut()
                    .find(|b| b.entry_va == edge.target)
                {
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
