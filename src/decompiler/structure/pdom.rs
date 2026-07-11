//! Post-dominator tree over SSA block adjacency — Phase 5.1 S1.
//!
//! Builds the immediate post-dominator map by reversing the CFG, attaching a
//! virtual exit node to every exit block, and reusing Cooper-Harvey-Kennedy
//! [`crate::decompiler::ssa::cfg::build_idom`].

use crate::decompiler::ssa::SsaFunction;
use crate::decompiler::ssa::cfg::build_idom;

/// Index of the virtual exit node appended to the adjacency lists.
/// Equal to `ssa.blocks.len()` (one past the last real block).
pub fn virtual_exit(n_blocks: usize) -> u32 {
    n_blocks as u32
}

/// Immediate post-dominator of every block, plus the virtual exit.
///
/// - `ipdom[b]` for real block `b` is the immediate post-dominator.
/// - `ipdom[virtual_exit] = Some(virtual_exit)`.
/// - Unreachable-from-exit blocks may be `None` (rare after virtual-exit glue).
pub fn build_ipdom(succ: &[Vec<u32>], pred: &[Vec<u32>]) -> Vec<Option<u32>> {
    let n = succ.len();
    debug_assert_eq!(n, pred.len());
    let ve = virtual_exit(n);

    // Forward CFG extended with virtual exit: every real exit → ve.
    let mut fwd_succ: Vec<Vec<u32>> = succ.to_vec();
    let mut fwd_pred: Vec<Vec<u32>> = pred.to_vec();
    fwd_succ.push(Vec::new()); // ve has no successors
    fwd_pred.push(Vec::new()); // ve's predecessors filled below
    for (i, s) in fwd_succ.iter_mut().enumerate().take(n) {
        if s.is_empty() {
            s.push(ve);
            fwd_pred[ve as usize].push(i as u32);
        }
    }

    // Post-dominators = dominators on the reversed CFG, entry = virtual exit.
    // rev_succ[b] = predecessors of b in the forward graph.
    // rev_pred[b] = successors of b in the forward graph.
    let rev_succ = fwd_pred;
    let rev_pred = fwd_succ;
    build_idom(&rev_succ, &rev_pred, ve)
}

/// Children of each node in the post-dominator tree (`pdt_children[p]` lists
/// nodes whose immediate post-dominator is `p`).
pub fn pdt_children(ipdom: &[Option<u32>]) -> Vec<Vec<u32>> {
    let n = ipdom.len();
    let mut children: Vec<Vec<u32>> = vec![Vec::new(); n];
    for (i, &p) in ipdom.iter().enumerate() {
        if let Some(parent) = p
            && parent != i as u32
        {
            children[parent as usize].push(i as u32);
        }
    }
    children
}

/// Extract successor / predecessor adjacency from an [`SsaFunction`].
pub fn adj_from_ssa(ssa: &SsaFunction) -> (Vec<Vec<u32>>, Vec<Vec<u32>>) {
    let succ: Vec<Vec<u32>> = ssa.blocks.iter().map(|b| b.successor_ids.clone()).collect();
    let pred: Vec<Vec<u32>> = ssa
        .blocks
        .iter()
        .map(|b| b.predecessor_ids.clone())
        .collect();
    (succ, pred)
}

/// Full post-dominator analysis: `(ipdom, pdt_children, virtual_exit)`.
pub fn analyze(ssa: &SsaFunction) -> (Vec<Option<u32>>, Vec<Vec<u32>>, u32) {
    let (succ, pred) = adj_from_ssa(ssa);
    let ipdom = build_ipdom(&succ, &pred);
    let children = pdt_children(&ipdom);
    let ve = virtual_exit(ssa.blocks.len());
    (ipdom, children, ve)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Diamond: 0 → {1,2} → 3 → ∅. Virtual exit = 4.
    fn diamond() -> (Vec<Vec<u32>>, Vec<Vec<u32>>) {
        let succ = vec![
            vec![1, 2], // 0 branch
            vec![3],    // 1 then
            vec![3],    // 2 else
            vec![],     // 3 join
        ];
        let pred = vec![vec![], vec![0], vec![0], vec![1, 2]];
        (succ, pred)
    }

    #[test]
    fn diamond_post_dominators() {
        let (succ, pred) = diamond();
        let ipdom = build_ipdom(&succ, &pred);
        let ve = virtual_exit(4);

        // Virtual exit post-dominates itself.
        assert_eq!(ipdom[ve as usize], Some(ve));
        // Join's ipdom is the virtual exit.
        assert_eq!(ipdom[3], Some(ve), "join ipdom should be virtual exit");
        // Then / else are immediately post-dominated by the join.
        assert_eq!(ipdom[1], Some(3), "then → join");
        assert_eq!(ipdom[2], Some(3), "else → join");
        // Branch is immediately post-dominated by the join (both arms meet there).
        assert_eq!(ipdom[0], Some(3), "branch ipdom should be join");
    }

    #[test]
    fn diamond_pdt_children() {
        let (succ, pred) = diamond();
        let ipdom = build_ipdom(&succ, &pred);
        let children = pdt_children(&ipdom);
        let ve = virtual_exit(4) as usize;

        // Join is a child of the virtual exit.
        assert!(children[ve].contains(&3));
        // Then and else (and branch) hang under the join.
        assert!(children[3].contains(&1));
        assert!(children[3].contains(&2));
        assert!(children[3].contains(&0));
    }
}
