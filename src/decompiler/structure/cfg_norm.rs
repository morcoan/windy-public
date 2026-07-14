//! Presentation-CFG normalization before structuring (1.txt workstream 1).
//!
//! Collapses jump-only / empty forwarding blocks so the structurer sees a
//! shorter presentation graph without changing the underlying SSA ops used for
//! side-effect emission. Exceptional edges are not modeled here (overlay later).

use std::collections::HashMap;

use rsleigh_api::PcodeOp;

use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOpKind};

/// True when a block has no surface side effects (only terminators / phis / noise).
pub fn is_forwarding_block(block: &SsaBlock) -> bool {
    !block.ops.iter().any(|op| {
        !matches!(
            &op.kind,
            SsaOpKind::Phi(_)
                | SsaOpKind::Pcode(
                    PcodeOp::Branch { .. }
                        | PcodeOp::CBranch { .. }
                        | PcodeOp::BranchInd { .. }
                        | PcodeOp::Return { .. }
                )
        ) && !crate::decompiler::normalize::is_frame_pointer_adjust(op)
            && !crate::decompiler::normalize::is_param_home_store(op)
            && !crate::decompiler::normalize::is_noise_stack_reload(op)
    })
}

/// Unconditional jump-only: single successor, no CBranch/Return/Call/Store surface.
pub fn is_jump_only(block: &SsaBlock) -> bool {
    if block.successor_ids.len() != 1 {
        return false;
    }
    if block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
    {
        return false;
    }
    if block.ops.iter().any(|o| {
        matches!(
            &o.kind,
            SsaOpKind::Pcode(
                PcodeOp::CBranch { .. }
                    | PcodeOp::BranchInd { .. }
                    | PcodeOp::Call { .. }
                    | PcodeOp::CallInd { .. }
                    | PcodeOp::Store { .. }
            )
        )
    }) {
        return false;
    }
    is_forwarding_block(block)
}

/// Follow jump-only chains to a non-forwarding presentation target (bounded).
pub fn resolve_jump_target(ssa: &SsaFunction, mut b: u32, limit: usize) -> u32 {
    for _ in 0..limit {
        if b as usize >= ssa.blocks.len() {
            return b;
        }
        let block = &ssa.blocks[b as usize];
        if !is_jump_only(block) {
            return b;
        }
        let Some(&next) = block.successor_ids.first() else {
            return b;
        };
        if next == b {
            return b;
        }
        b = next;
    }
    b
}

/// Map each block id → presentation successor list with jump-only edges collapsed.
#[allow(dead_code)] // used by DualDecompModel / presentation graph builders
pub fn presentation_successors(ssa: &SsaFunction) -> Vec<Vec<u32>> {
    let n = ssa.blocks.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let block = &ssa.blocks[i];
        let mut succs: Vec<u32> = block
            .successor_ids
            .iter()
            .map(|&s| resolve_jump_target(ssa, s, 16))
            .collect();
        succs.sort_unstable();
        succs.dedup();
        out.push(succs);
    }
    out
}

/// Collapse map: original block → canonical presentation block (self if non-forwarding).
#[allow(dead_code)]
pub fn presentation_canon(ssa: &SsaFunction) -> HashMap<u32, u32> {
    let mut m = HashMap::new();
    for i in 0..ssa.blocks.len() as u32 {
        m.insert(i, resolve_jump_target(ssa, i, 16));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};
    use rsleigh_api::{PcodeOp, Varnode};

    fn empty_jump(id: u32, va: u64, to: u32) -> SsaBlock {
        SsaBlock {
            id,
            entry_va: va,
            ops: vec![SsaOp {
                va,
                kind: SsaOpKind::Pcode(PcodeOp::Branch {
                    dest: Varnode::constant(0, 8),
                }),
                def: None,
                uses: vec![],
            }],
            predecessor_ids: vec![],
            successor_ids: vec![to],
        }
    }

    #[test]
    fn jump_only_chain_resolves() {
        // 0 -> 1 (jump) -> 2 (return)
        let b0 = empty_jump(0, 0x1000, 1);
        let b1 = empty_jump(1, 0x1010, 2);
        let b2 = SsaBlock {
            id: 2,
            entry_va: 0x1020,
            ops: vec![SsaOp {
                va: 0x1020,
                kind: SsaOpKind::Pcode(PcodeOp::Return {
                    dest: Varnode::register(0, 8),
                }),
                def: None,
                uses: vec![SsaVar {
                    location: Location::Register { base_offset: 0 },
                    version: 1,
                }],
            }],
            predecessor_ids: vec![1],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1, b2],
            image_base: 0,
        };
        assert!(is_jump_only(&ssa.blocks[0]));
        assert!(is_jump_only(&ssa.blocks[1]));
        assert!(!is_jump_only(&ssa.blocks[2]));
        assert_eq!(resolve_jump_target(&ssa, 0, 16), 2);
        assert_eq!(resolve_jump_target(&ssa, 1, 16), 2);
    }
}
