//! Semantic model from raw P-code ops + architectural CFG (v2 authority path).
//!
//! Built from the **unoptimized** SSA form (raw lifted P-code with CFG edges).
//! Surface-critical observations skip param-home / frame noise so they match
//! what a pure structure emitter can express — unknown alias never deletes
//! critical call/return/store effects that survive normalize filters.

use std::collections::{BTreeMap, BTreeSet};

use rsleigh_api::PcodeOp;

use crate::decompiler::ssa::{SsaFunction, SsaOp, SsaOpKind};
use crate::decompiler::structure::cfg_norm::resolve_jump_target;
use crate::decompiler::structure::pdom::adj_from_ssa;

use super::observation::{Observation, ObservationId, ObservationKind};

/// Architectural terminator for one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminator {
    Jump {
        target: u32,
    },
    Branch {
        cond_hint: String,
        false_target: u32,
        true_target: u32,
    },
    Switch {
        targets: Vec<u32>,
    },
    Return,
    TailCall {
        target_hint: Option<u64>,
    },
    Unreachable,
}

/// Exit value story for return blocks (coarse class, not richest-expr hunt).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitValueClass {
    pub class_tag: String,
    pub has_return: bool,
}

/// Semantic function model for checked extraction.
#[derive(Clone, Debug)]
pub struct SemanticModel {
    pub n_blocks: usize,
    pub entry: u32,
    pub succ: Vec<Vec<u32>>,
    pub pred: Vec<Vec<u32>>,
    pub terminators: Vec<Terminator>,
    pub observations: Vec<Observation>,
    pub by_block: BTreeMap<u32, Vec<ObservationId>>,
    pub cookie_blocks: BTreeSet<u32>,
    pub exception_blocks: BTreeSet<u32>,
    pub exit_class: ExitValueClass,
}

impl SemanticModel {
    /// Build from **raw** lifted P-code SSA (prefer over optimized for HIR).
    ///
    /// Architectural terminators use real CFG edges (jump-only chains collapsed
    /// for presentation). Surface observations skip prologue/param-home noise.
    pub fn from_raw_pcode(ssa: &SsaFunction) -> Self {
        Self::build(ssa, /*architectural_cfg*/ true)
    }

    /// Compatibility alias — same surface filtering; prefer [`from_raw_pcode`].
    pub fn from_ssa(ssa: &SsaFunction) -> Self {
        Self::from_raw_pcode(ssa)
    }

    fn build(ssa: &SsaFunction, architectural_cfg: bool) -> Self {
        let n = ssa.blocks.len();
        let (raw_succ, _raw_pred) = adj_from_ssa(ssa);
        // Architectural CFG: keep decoded edges; collapse jump-only for presentation.
        let mut succ: Vec<Vec<u32>> = Vec::with_capacity(n);
        for raw in &raw_succ {
            let mut ss: Vec<u32> = if architectural_cfg {
                raw.iter()
                    .map(|&s| resolve_jump_target(ssa, s, 16))
                    .collect()
            } else {
                raw.clone()
            };
            ss.sort_unstable();
            ss.dedup();
            succ.push(ss);
        }
        let mut pred = vec![Vec::new(); n];
        for (i, ss) in succ.iter().enumerate() {
            for &s in ss {
                if (s as usize) < n {
                    pred[s as usize].push(i as u32);
                }
            }
        }
        for p in &mut pred {
            p.sort_unstable();
            p.dedup();
        }

        let mut observations = Vec::new();
        let mut by_block: BTreeMap<u32, Vec<ObservationId>> = BTreeMap::new();
        let mut cookie_blocks = BTreeSet::new();
        let mut exception_blocks = BTreeSet::new();
        let mut terminators = Vec::with_capacity(n);
        let mut return_ops: Vec<String> = Vec::new();
        let mut has_return = false;
        let mut next_id = 0u32;

        for (i, block) in ssa.blocks.iter().enumerate() {
            let bid = i as u32;
            let mut ord = 0u32;
            let mut ids = Vec::new();
            for op in &block.ops {
                if is_nonsurface_op(op) {
                    continue;
                }
                let kind = match &op.kind {
                    SsaOpKind::Pcode(PcodeOp::Call { dest, .. }) => {
                        let th = if dest.space == pcode_ir::AddressSpaceId::Const
                            || dest.space == pcode_ir::AddressSpaceId::Ram
                        {
                            Some(dest.offset)
                        } else {
                            None
                        };
                        Some(ObservationKind::Call {
                            target_hint: th,
                            arg_count: 0,
                        })
                    }
                    SsaOpKind::Pcode(PcodeOp::CallInd { .. }) => Some(ObservationKind::Call {
                        target_hint: None,
                        arg_count: 0,
                    }),
                    SsaOpKind::Pcode(PcodeOp::Store { .. }) => {
                        // Surface store (param-home / noise already filtered).
                        Some(ObservationKind::Store { is_stack: false })
                    }
                    SsaOpKind::Pcode(PcodeOp::Load { .. }) => {
                        Some(ObservationKind::Load { is_stack: false })
                    }
                    SsaOpKind::Pcode(PcodeOp::Return { .. }) => {
                        has_return = true;
                        Some(ObservationKind::Return)
                    }
                    SsaOpKind::Pcode(PcodeOp::IntXor { .. }) => {
                        return_ops.push("xor".into());
                        None
                    }
                    SsaOpKind::Pcode(PcodeOp::IntAdd { .. } | PcodeOp::IntSub { .. }) => {
                        return_ops.push("arith".into());
                        None
                    }
                    SsaOpKind::Pcode(PcodeOp::IntSLess { .. } | PcodeOp::IntLess { .. }) => {
                        return_ops.push("cmp".into());
                        None
                    }
                    _ => None,
                };
                if let Some(kind) = kind {
                    let id = ObservationId::new(next_id);
                    next_id += 1;
                    observations.push(Observation {
                        id,
                        block: bid,
                        kind,
                        va: if op.va != 0 { Some(op.va) } else { None },
                        ordinal: ord,
                    });
                    ids.push(id);
                    ord += 1;
                }
            }
            if !ids.is_empty() {
                by_block.insert(bid, ids);
            }

            // Cookie / EH overlay heuristics with provenance tags (metadata preferred later).
            if is_cookie_like(block) {
                cookie_blocks.insert(bid);
            }
            if is_exception_like(block) {
                exception_blocks.insert(bid);
            }

            terminators.push(classify_terminator(ssa, bid, &succ[i]));
        }

        let class_tag = if return_ops.iter().any(|t| t == "xor") {
            "xor".into()
        } else if return_ops.iter().any(|t| t == "cmp") {
            "arg_select".into()
        } else if return_ops.iter().any(|t| t == "arith") {
            "arith".into()
        } else if has_return {
            "return".into()
        } else {
            "none".into()
        };

        Self {
            n_blocks: n,
            entry: 0,
            succ,
            pred,
            terminators,
            observations,
            by_block,
            cookie_blocks,
            exception_blocks,
            exit_class: ExitValueClass {
                class_tag,
                has_return,
            },
        }
    }

    pub fn block_observations(&self, b: u32) -> Vec<&Observation> {
        self.by_block
            .get(&b)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.observations.iter().find(|o| o.id == *id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn critical_effects(&self) -> Vec<&Observation> {
        self.observations
            .iter()
            .filter(|o| {
                matches!(
                    o.kind,
                    ObservationKind::Call { .. }
                        | ObservationKind::Store { .. }
                        | ObservationKind::Return
                        | ObservationKind::ExceptionalExit
                        | ObservationKind::Barrier
                        | ObservationKind::Cleanup
                )
            })
            .collect()
    }
}

/// Ops that never surface as critical effects in pure structure emit.
fn is_nonsurface_op(op: &SsaOp) -> bool {
    crate::decompiler::normalize::is_frame_pointer_adjust(op)
        || crate::decompiler::normalize::is_param_home_store(op)
        || crate::decompiler::normalize::is_noise_stack_reload(op)
        || matches!(&op.kind, SsaOpKind::Phi(_))
}

fn classify_terminator(ssa: &SsaFunction, bid: u32, succ: &[u32]) -> Terminator {
    let block = &ssa.blocks[bid as usize];
    let has_ret = block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })));
    if has_ret {
        return Terminator::Return;
    }
    let has_bind = block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::BranchInd { .. })));
    if has_bind && succ.len() >= 2 {
        return Terminator::Switch {
            targets: succ.to_vec(),
        };
    }
    let has_cbr = block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::CBranch { .. })));
    if has_cbr && succ.len() >= 2 {
        return Terminator::Branch {
            cond_hint: "cond".into(),
            false_target: succ[0],
            true_target: succ[1],
        };
    }
    if succ.len() == 1 {
        return Terminator::Jump { target: succ[0] };
    }
    if succ.is_empty() {
        return Terminator::Unreachable;
    }
    Terminator::Switch {
        targets: succ.to_vec(),
    }
}

fn is_cookie_like(block: &crate::decompiler::ssa::SsaBlock) -> bool {
    let mut xor = false;
    let mut load = false;
    let mut calls = 0usize;
    for op in &block.ops {
        match &op.kind {
            SsaOpKind::Pcode(PcodeOp::IntXor { .. }) => xor = true,
            SsaOpKind::Pcode(PcodeOp::Load { .. }) => load = true,
            SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) => calls += 1,
            _ => {}
        }
    }
    calls == 0 && xor && load && block.ops.len() <= 12
}

fn is_exception_like(block: &crate::decompiler::ssa::SsaBlock) -> bool {
    let bind = block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::BranchInd { .. })));
    bind && block.successor_ids.len() >= 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use rsleigh_api::{PcodeOp, Varnode};

    fn blk(id: u32, ops: Vec<SsaOp>, succs: Vec<u32>) -> SsaBlock {
        SsaBlock {
            id,
            entry_va: 0x1000 + id as u64 * 0x10,
            ops,
            successor_ids: succs,
            predecessor_ids: vec![],
        }
    }

    #[test]
    fn semantic_model_tracks_return_and_store() {
        let mut blocks = vec![
            blk(
                0,
                vec![SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::CBranch {
                        cond: Varnode::constant(1, 1),
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![1, 2],
            ),
            blk(
                1,
                vec![SsaOp {
                    va: 0x1010,
                    kind: SsaOpKind::Pcode(PcodeOp::Store {
                        space: pcode_ir::AddressSpaceId::Ram,
                        ptr: Varnode::register(0x28, 8),
                        val: Varnode::register(0, 4),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![3],
            ),
            blk(2, vec![], vec![3]),
            blk(
                3,
                vec![SsaOp {
                    va: 0x1030,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                vec![],
            ),
        ];
        // link preds
        for b in blocks.iter_mut() {
            b.predecessor_ids.clear();
        }
        let edges: Vec<(u32, u32)> = blocks
            .iter()
            .flat_map(|b| b.successor_ids.iter().map(|&s| (b.id, s)))
            .collect();
        for (f, t) in edges {
            if let Some(bb) = blocks.iter_mut().find(|b| b.id == t) {
                bb.predecessor_ids.push(f);
            }
        }
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        };
        let m = SemanticModel::from_ssa(&ssa);
        assert!(m.exit_class.has_return);
        assert!(
            m.critical_effects()
                .iter()
                .any(|o| matches!(o.kind, ObservationKind::Store { .. }))
        );
        assert!(matches!(m.terminators[0], Terminator::Branch { .. }));
        assert!(matches!(m.terminators[3], Terminator::Return));
    }
}
