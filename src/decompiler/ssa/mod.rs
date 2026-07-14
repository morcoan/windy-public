//! Function-level SSA over per-instruction P-code â€” Phase 2 of WindyDec.
//!
//! This module builds a correct, function-level SSA IR from the per-instruction
//! P-code delivered by Phase 1 (the `crate::decompiler::pcode` lifter). It models
//! register containers (Ghidra-style) and stack-RAM slots, exposing phi nodes at
//! iterated dominance frontiers and renaming every register/stack-slot use to its
//! reaching definition.
//!
//! Design note: [`PcodeOp`] is a *closed* enum from `pcode_ir` with no phi variant.
//! SSA therefore lives in a side-layer of def/use chains plus [`PhiNode`]s keyed by
//! [`SsaVar`] (location + version). The lifted `PcodeOp`s are carried unchanged, so
//! p-code semantics stay verifiable and Phase 1 stays frozen.
//!
//! The locked contract keeps the `PcodeOp` enum untouched. To carry the renamed
//! def/use chains without mutating that enum, each [`SsaOp`] additionally holds its
//! resolved `def` and `uses` (as versioned [`SsaVar`]s); phis carry their own in
//! [`PhiNode`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::Function;
use crate::decompiler::pcode::{PcodeOp, lift_function_blocking};
use crate::project::types::StackFrame;

pub mod cfg;
pub mod lower;
pub mod phi;
pub mod rename;
pub mod simplify;

pub use simplify::{SsaAnalysis, simplify};

/// A storage location tracked by the SSA builder.
///
/// Registers are normalized to their 8-byte container base (x86-64 offsets
/// `0x00..0x38` = RAX..RDI, `0x80..0xB8` = R8..R15). Stack accesses resolved to a
/// `<frame_ptr_reg> Â± const` pattern become [`Location::StackSlot`]; everything
/// else (heap, RIP-relative globals, unresolved addressing) collapses to the
/// single [`Location::RawRam`] token. P-code `Unique` temporaries are scoped by
/// their originating instruction VA, so equal SLEIGH offsets from two decoded
/// instructions can never alias.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Location {
    /// A register container, e.g. EAX/AX/AL/RAX all live in `Register { base_offset: 0 }`.
    Register { base_offset: u64 },
    /// A stack slot keyed by its frame-pointer register and displacement.
    StackSlot { base_reg: u64, disp: i64 },
    /// A P-code temporary whose identity is local to one machine instruction.
    ///
    /// SLEIGH reuses Unique-space offsets while lifting different instructions,
    /// so the raw `(offset, size)` pair is not a function-global variable.
    /// These locations deliberately do not receive entry seeds or phi nodes.
    Unique {
        instruction_va: u64,
        offset: u64,
        size: u32,
    },
    /// Unresolved RAM â€” tracked as one opaque memory token (alias analysis deferred).
    RawRam,
}

impl Location {
    /// Whether this location is an instruction-local P-code temporary.
    ///
    /// Unique values may participate in intra-instruction def/use chains, but
    /// are never live-in values and never cross a CFG edge.
    pub fn is_instruction_scoped(&self) -> bool {
        matches!(self, Self::Unique { .. })
    }
}

/// A versioned storage location. The side-layer SSA currency.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub location: Location,
    pub version: u32,
}

/// A phi node: one merged definition for a location at a CFG merge, with one
/// argument slot per predecessor. `None` in `args` means the location is
/// undefined along that predecessor path.
#[derive(Clone, Debug)]
pub struct PhiNode {
    pub out: SsaVar,
    pub args: Vec<Option<SsaVar>>,
}

/// The kind of an [`SsaOp`]: either a (carried, unmodified) P-code op or a phi.
#[derive(Clone, Debug)]
pub enum SsaOpKind {
    Phi(PhiNode),
    Pcode(PcodeOp),
}

/// A single SSA operation: a phi or a lifted P-code op, tagged with its
/// originating instruction VA (`0` for phis). `def`/`uses` carry the renamed
/// def/use chains for this op (versions assigned by the Cytron renamer; `0`
/// means "uninitialized / undefined on entry").
#[derive(Clone, Debug)]
pub struct SsaOp {
    pub va: u64,
    pub kind: SsaOpKind,
    pub def: Option<SsaVar>,
    pub uses: Vec<SsaVar>,
}

/// A basic block in the SSA function: phis first, then P-code ops in order.
#[derive(Clone, Debug)]
pub struct SsaBlock {
    pub id: u32,
    pub entry_va: u64,
    pub ops: Vec<SsaOp>,
    pub predecessor_ids: Vec<u32>,
    pub successor_ids: Vec<u32>,
}

/// A function in SSA form: blocks in CFG order (block `id` == position in `blocks`).
#[derive(Clone, Debug)]
pub struct SsaFunction {
    pub entry_va: u64,
    pub bitness: u32,
    pub blocks: Vec<SsaBlock>,
    pub image_base: u64,
}

/// Resolve the SSA value reaching one architectural register at a return block.
///
/// Register aliases have already been normalized to their container
/// `base_offset`, so asking for offset zero covers RAX, EAX, AX, and AL. The
/// resolver first trusts an explicit use on the `Return`, then a definition in
/// the return block (including a phi), and finally walks CFG predecessors. A
/// predecessor merge is accepted only when every incoming path resolves to the
/// same SSA value; a proper SSA phi in the return block is handled by the local
/// definition case. Cycles and incomplete predecessor information fail closed.
pub fn reaching_register_at_return(
    ssa: &SsaFunction,
    block_id: u32,
    base_offset: u64,
) -> Option<SsaVar> {
    let return_block = ssa.blocks.iter().find(|block| block.id == block_id)?;
    return_block
        .ops
        .iter()
        .any(|op| matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
        .then_some(())?;

    fn resolve(
        ssa: &SsaFunction,
        block_id: u32,
        base_offset: u64,
        memo: &mut HashMap<u32, Option<SsaVar>>,
        visiting: &mut HashSet<u32>,
    ) -> Option<SsaVar> {
        if let Some(cached) = memo.get(&block_id) {
            return cached.clone();
        }
        if !visiting.insert(block_id) {
            return None;
        }

        let resolved = ssa
            .blocks
            .iter()
            .find(|block| block.id == block_id)
            .and_then(|block| {
                let return_index = block
                    .ops
                    .iter()
                    .position(|op| matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })));
                let end = return_index.unwrap_or(block.ops.len());

                let explicit_return_use = return_index.and_then(|index| {
                    block.ops[index]
                        .uses
                        .iter()
                        .find(|var| {
                            matches!(
                                var.location,
                                Location::Register { base_offset: offset } if offset == base_offset
                            )
                        })
                        .cloned()
                });
                let local_definition = block.ops[..end]
                    .iter()
                    .rev()
                    .filter_map(|op| op.def.as_ref())
                    .find(|var| {
                        matches!(
                            var.location,
                            Location::Register { base_offset: offset } if offset == base_offset
                        )
                    })
                    .cloned();

                explicit_return_use.or(local_definition).or_else(|| {
                    let mut common: Option<SsaVar> = None;
                    for predecessor_id in &block.predecessor_ids {
                        let incoming = resolve(ssa, *predecessor_id, base_offset, memo, visiting)?;
                        if let Some(existing) = &common {
                            if existing != &incoming {
                                return None;
                            }
                        } else {
                            common = Some(incoming);
                        }
                    }
                    common
                })
            });

        visiting.remove(&block_id);
        memo.insert(block_id, resolved.clone());
        resolved
    }

    resolve(
        ssa,
        block_id,
        base_offset,
        &mut HashMap::new(),
        &mut HashSet::new(),
    )
}

/// A flat, location-resolved P-code op produced by
/// [`lower::lower_function_with_call_abi_inputs`].
///
/// `def`/`uses` carry only *locations* (versions are assigned later by the
/// Cytron renamer). Constant operands are intentionally excluded; Unique-space
/// operands carry an instruction-scoped [`Location::Unique`] identity.
pub struct FlatOp {
    pub va: u64,
    pub op: PcodeOp,
    pub def: Option<Location>,
    pub uses: Vec<Location>,
}

/// Per-instruction ABI input locations that must be treated as true call uses
/// while building SSA.
///
/// Raw SLEIGH `Call` P-code contains a destination but not the Windows calling
/// convention's register inputs.  A project-level resolver supplies this
/// sidecar only for a known, supported call contract.  It is deliberately
/// separate from the frozen P-code enum: lowering appends these locations to
/// the call's SSA use chain so DCE preserves their value definitions.
pub type CallAbiInputs = BTreeMap<u64, Vec<Location>>;

/// Build the SSA form of `func`.
///
/// Performs no SLEIGH decoding itself: P-code is obtained via
/// [`lift_function_blocking`] (which already runs the decoder on a â‰¥128 MiB
/// stack). The dominator/phi/rename passes are stack-light, so this call is safe
/// from any caller thread.
pub fn build_ssa_with_call_abi_inputs(
    func: &Function,
    code_index: &CodeIndex,
    function_frames: &BTreeMap<u64, StackFrame>,
    bitness: u32,
    image_base: u64,
    call_abi_inputs: &CallAbiInputs,
) -> SsaFunction {
    // Stack-frame names are applied at emit time via `NameCtx` (see
    // `function_decompile_native`); the frames table is accepted so callers can
    // share the same signature as other analysis entry points.
    let _function_frames = function_frames;

    // 1) Lift P-code once, keyed by instruction VA.
    let pcode = lift_function_blocking(func, code_index, bitness);

    // 2) Flatten + resolve def/use locations per block.
    let block_flat =
        lower::lower_function_with_call_abi_inputs(func, &pcode, code_index, call_abi_inputs);

    // 3) CFG adjacency (block index == position in func.blocks).
    let n = func.blocks.len();
    let index_of = block_index_map(func);
    // Entry may not be blocks[0] when blocks are address-sorted and a
    // lower-VA tail-call target was (historically) absorbed â€” prefer the
    // true function entry VA.
    let entry_idx = index_of.get(&func.entry_va).copied().unwrap_or(0);
    let mut succ: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut pred: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, block) in func.blocks.iter().enumerate() {
        for e in &block.successors {
            if e.target == 0 {
                continue;
            }
            // Skip edges into blocks outside this function's block list
            // (true tail-calls / external targets).
            if let Some(&j) = index_of.get(&e.target) {
                let j = j as u32;
                if !succ[i].contains(&j) {
                    succ[i].push(j);
                }
            }
        }
        for e in &block.predecessors {
            if e.target == 0 {
                continue;
            }
            if let Some(&j) = index_of.get(&e.target) {
                let j = j as u32;
                if !pred[i].contains(&j) {
                    pred[i].push(j);
                }
            }
        }
    }

    // 4) Dominators + dominance frontier (rooted at real entry).
    let idom = cfg::build_idom(&succ, &pred, entry_idx as u32);
    let df = cfg::dominance_frontier(&succ, &pred, &idom);

    // 5) Collect the blocks that define each location, then place phis at the
    //    iterated dominance frontier of each.
    let def_blocks = collect_def_blocks(&block_flat, n);
    let phi_locs = phi::place_phis(&def_blocks, &df);

    // 6) Cytron renaming -> final per-block op streams.
    let (phis, pcode_ops) = rename::rename(&block_flat, &phi_locs, &succ, &pred, &idom);

    // 7) Assemble the SSA function.
    let mut blocks = Vec::with_capacity(n);
    for (i, block) in func.blocks.iter().enumerate() {
        let mut ops = Vec::with_capacity(phis[i].len() + pcode_ops[i].len());
        for p in &phis[i] {
            ops.push(SsaOp {
                va: 0,
                kind: SsaOpKind::Phi(p.clone()),
                def: Some(p.out.clone()),
                uses: Vec::new(),
            });
        }
        ops.extend(pcode_ops[i].iter().cloned());
        blocks.push(SsaBlock {
            id: i as u32,
            entry_va: block.entry_va,
            ops,
            predecessor_ids: pred[i].clone(),
            successor_ids: succ[i].clone(),
        });
    }

    SsaFunction {
        entry_va: func.entry_va,
        bitness,
        blocks,
        image_base,
    }
}

/// Map each block entry VA to its position index in `func.blocks`.
fn block_index_map(func: &Function) -> HashMap<u64, usize> {
    func.blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.entry_va, i))
        .collect()
}

/// For every location, the set of block indices that define it.
fn collect_def_blocks(block_flat: &[Vec<FlatOp>], n: usize) -> BTreeMap<Location, BTreeSet<u32>> {
    let mut def_blocks: BTreeMap<Location, BTreeSet<u32>> = BTreeMap::new();
    for (i, flat) in block_flat.iter().enumerate().take(n) {
        for op in flat {
            if let Some(loc) = &op.def {
                // P-code Unique-space varnodes are defined and consumed inside
                // one decoded instruction. They must never acquire a CFG phi,
                // even if a malformed lift happened to reuse their raw offset.
                if !loc.is_instruction_scoped() {
                    def_blocks.entry(loc.clone()).or_default().insert(i as u32);
                }
            }
        }
    }
    def_blocks
}

/// Verify the post-rename invariant: every tracked Register use resolves to a
/// defined version (never the `0` placeholder, which means "uninitialized").
///
/// Returns `true` iff no `SsaOp` carries a Register-location use with version `0`.
#[cfg(test)]
pub fn verify_no_uninitialized_register_uses(ssa: &SsaFunction) -> bool {
    for block in &ssa.blocks {
        for op in &block.ops {
            if let SsaOpKind::Pcode(_) = &op.kind {
                for u in &op.uses {
                    if let Location::Register { .. } = u.location
                        && u.version == 0
                    {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// All locations appearing anywhere in `ssa` (helper for tests/debug).
#[cfg(test)]
#[allow(dead_code)]
pub fn all_locations(ssa: &SsaFunction) -> HashSet<Location> {
    let mut out = HashSet::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            match &op.kind {
                SsaOpKind::Phi(p) => {
                    out.insert(p.out.location.clone());
                    for v in p.args.iter().flatten() {
                        out.insert(v.location.clone());
                    }
                }
                SsaOpKind::Pcode(_) => {
                    if let Some(d) = &op.def {
                        out.insert(d.location.clone());
                    }
                    for u in &op.uses {
                        out.insert(u.location.clone());
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pcode::PcodeOp;
    use crate::project::Project;

    fn open_sample() -> Project {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.exe");
        Project::open(path).expect("open sample.exe")
    }

    /// A function containing an `IntAdd` â€” the "add" / arithmetic function.
    fn find_intadd_function(p: &Project) -> Option<u64> {
        for f in p.functions().iter() {
            if let Some(ssa) = p.function_ssa(f.entry_va) {
                if ssa.blocks.iter().any(|b| {
                    b.ops
                        .iter()
                        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::IntAdd { .. })))
                }) {
                    return Some(f.entry_va);
                }
            }
        }
        None
    }

    #[test]
    fn test_ssa_add_function_unrenamed_uses_zero() {
        let p = open_sample();
        let add_va = find_intadd_function(&p).expect("sample.exe must contain an IntAdd function");
        let ssa = p.function_ssa(add_va).unwrap();

        // The Return op must read at least one register (the return value) and
        // every such register use must resolve to a defined SSA version (never
        // the uninitialized `0` sentinel â€” i.e. no un-renamed reads).
        let mut saw_return = false;
        for b in &ssa.blocks {
            for o in &b.ops {
                if let SsaOpKind::Pcode(PcodeOp::Return { .. }) = &o.kind {
                    saw_return = true;
                    let reg_uses: Vec<&SsaVar> = o
                        .uses
                        .iter()
                        .filter(|u| matches!(u.location, Location::Register { .. }))
                        .collect();
                    assert!(
                        !reg_uses.is_empty(),
                        "Return op should read at least one register (the return value)"
                    );
                    for u in reg_uses {
                        assert_ne!(
                            u.version, 0,
                            "Return register use must be renamed to a defined def, not the uninitialized sentinel"
                        );
                    }
                }
            }
        }
        assert!(saw_return, "add function must contain a Return op");
    }

    #[test]
    fn test_ssa_diamond_has_phi() {
        let p = open_sample();
        let mut found = false;
        for f in p.functions().iter() {
            let ssa = match p.function_ssa(f.entry_va) {
                Some(s) => s,
                None => continue,
            };
            // Require a conditional branch (the diamond's decision).
            let has_cbranch = ssa.blocks.iter().any(|b| {
                b.ops
                    .iter()
                    .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::CBranch { .. })))
            });
            if !has_cbranch {
                continue;
            }
            // A merge block (>= 2 predecessors) must carry a phi for a register,
            // with one arg slot per predecessor.
            for b in &ssa.blocks {
                if b.predecessor_ids.len() < 2 {
                    continue;
                }
                for o in &b.ops {
                    if let SsaOpKind::Phi(phi) = &o.kind {
                        if let Location::Register { .. } = phi.out.location {
                            if phi.args.len() == b.predecessor_ids.len() {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                if found {
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(
            found,
            "expected a CFG join (diamond) with a register phi merging the compared register"
        );
    }

    #[test]
    fn test_ssa_stack_slot_resolves() {
        let p = open_sample();
        let mut saw_slot = false;
        for f in p.functions().iter() {
            let ssa = match p.function_ssa(f.entry_va) {
                Some(s) => s,
                None => continue,
            };
            for b in &ssa.blocks {
                for o in &b.ops {
                    match &o.kind {
                        SsaOpKind::Pcode(PcodeOp::Store { .. }) => {
                            if let Some(SsaVar {
                                location: Location::StackSlot { .. },
                                ..
                            }) = &o.def
                            {
                                saw_slot = true;
                            }
                        }
                        SsaOpKind::Pcode(PcodeOp::Load { .. }) => {
                            if o.uses
                                .iter()
                                .any(|u| matches!(u.location, Location::StackSlot { .. }))
                            {
                                saw_slot = true;
                            }
                        }
                        _ => {}
                    }
                    if saw_slot {
                        break;
                    }
                }
                if saw_slot {
                    break;
                }
            }
            if saw_slot {
                break;
            }
        }
        assert!(
            saw_slot,
            "expected at least one Store/Load to resolve to a Location::StackSlot (prologue spill)"
        );
    }

    #[test]
    fn test_ssa_all_register_uses_renamed() {
        let p = open_sample();
        for f in p.functions().iter() {
            let ssa = match p.function_ssa(f.entry_va) {
                Some(s) => s,
                None => continue,
            };
            assert!(
                verify_no_uninitialized_register_uses(&ssa),
                "function {:#x} has an un-renamed (version 0) register use",
                f.entry_va
            );
        }
    }

    #[test]
    fn test_ssa_optimized_op_count_non_increasing() {
        let p = open_sample();
        let mut simplified_any = false;
        for f in p.functions().iter() {
            let raw = match p.function_ssa(f.entry_va) {
                Some(s) => s,
                None => continue,
            };
            let (opt, analysis) = p.function_ssa_optimized(f.entry_va).unwrap();
            assert!(
                analysis.op_count_after <= analysis.op_count_before,
                "function {:#x}: op count increased ({} -> {})",
                f.entry_va,
                analysis.op_count_before,
                analysis.op_count_after
            );
            // The raw SSA must still satisfy the Phase-2 invariant (untouched).
            assert!(
                verify_no_uninitialized_register_uses(&raw),
                "raw SSA invariant broken for {:#x}",
                f.entry_va
            );
            // The optimized SSA must preserve the invariant.
            assert!(
                verify_no_uninitialized_register_uses(&opt),
                "optimized SSA has an un-renamed (version 0) register use for {:#x}",
                f.entry_va
            );
            if analysis.op_count_after < analysis.op_count_before {
                simplified_any = true;
            }
        }
        // At least one function in sample.exe should reduce under optimization
        // (dead copies / trivial phis are common in compiler output).
        assert!(
            simplified_any,
            "expected at least one function to shrink under SSA simplification"
        );
    }

    #[test]
    fn test_ssa_suggestions_capture_constants() {
        let p = open_sample();
        // Aggregate constants across all functions; compiler output virtually
        // always materializes at least one immediate into a register.
        let mut total_constants = 0usize;
        let mut total_suggestions = 0usize;
        for f in p.functions().iter() {
            if let Some((_, analysis)) = p.function_ssa_optimized(f.entry_va) {
                total_constants += analysis.constants.len();
            }
            if let Some(sug) = p.function_ssa_suggestions(f.entry_va) {
                total_suggestions += sug.len();
            }
        }
        assert!(
            total_constants > 0,
            "expected at least one constant def across sample.exe"
        );
        assert_eq!(
            total_constants, total_suggestions,
            "every non-phi constant def must yield a suggestion"
        );
    }

    #[test]
    fn unique_defs_are_not_phi_candidates() {
        let unique = Location::Unique {
            instruction_va: 0x1400_0010,
            offset: 0x40,
            size: 8,
        };
        let flat = vec![vec![FlatOp {
            va: 0x1400_0010,
            op: PcodeOp::Copy {
                out: crate::decompiler::pcode::Varnode::unique(0x40, 8),
                input: crate::decompiler::pcode::Varnode::constant(1, 8),
            },
            def: Some(unique.clone()),
            uses: Vec::new(),
        }]];

        let defs = collect_def_blocks(&flat, 1);
        assert!(
            !defs.contains_key(&unique),
            "instruction-scoped Unique values must not enter phi placement"
        );
    }
}
