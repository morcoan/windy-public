//! Dominator tree + dominance frontier over the existing CFG adjacency lists.
//!
//! A from-scratch implementation of Cooper, Harvey & Kennedy, "A Simple, Fast
//! Dominance Algorithm" (2001). No graph crate: it rolls directly over the
//! `successors`/`predecessors` index adjacency produced by the caller, matching
//! the codebase's no-petgraph idiom.

use std::collections::BTreeSet;

/// Reverse-postorder numbering via iterative DFS from `entry`.
///
/// Returns a `(postorder, rpo)` pair where `postorder[b]` is the postorder index
/// of block `b` (0 = last finished) and `rpo` is the reverse-postorder list of
/// block indices reachable from `entry`.
fn reverse_postorder(succ: &[Vec<u32>], entry: u32) -> (Vec<usize>, Vec<u32>) {
    let n = succ.len();
    let mut postorder = vec![usize::MAX; n];
    let mut order: Vec<u32> = Vec::new();
    let mut visited = vec![false; n];

    // Iterative DFS to avoid deep recursion on large CFGs. We keep a per-node
    // successor cursor on the stack and mutate it in place via `last_mut`.
    let mut stack: Vec<(u32, usize)> = vec![(entry, 0)];
    while let Some(top) = stack.last_mut() {
        let node = top.0;
        let next = &mut top.1;
        if !visited[node as usize] {
            visited[node as usize] = true;
        }
        let succs = &succ[node as usize];
        if *next < succs.len() {
            let s = succs[*next];
            *next += 1;
            if !visited[s as usize] {
                stack.push((s, 0));
            }
        } else {
            // All successors visited — finish this node.
            postorder[node as usize] = order.len();
            order.push(node);
            stack.pop();
        }
    }

    // `order` is in postorder; reverse it for RPO.
    order.reverse();
    (postorder, order)
}

/// Immediate dominator of every block (Cooper-Harvey-Kennedy).
///
/// `idom[entry] = Some(entry)`; unreachable blocks get `None`. Node indices are
/// block positions in the caller's block list.
pub fn build_idom(succ: &[Vec<u32>], pred: &[Vec<u32>], entry: u32) -> Vec<Option<u32>> {
    let n = succ.len();
    let (postorder, rpo) = reverse_postorder(succ, entry);

    let intersect = |mut a: u32, mut b: u32, idom: &[Option<u32>]| -> u32 {
        while a != b {
            // Walk the node with the smaller postorder number up the dom tree
            // (smaller postorder == further from entry).
            while postorder[a as usize] < postorder[b as usize] {
                a = idom[a as usize].unwrap_or(a);
            }
            while postorder[b as usize] < postorder[a as usize] {
                b = idom[b as usize].unwrap_or(b);
            }
        }
        a
    };

    let mut idom: Vec<Option<u32>> = vec![None; n];
    idom[entry as usize] = Some(entry);

    let mut changed = true;
    while changed {
        changed = false;
        // Process nodes in reverse postorder (skipping the entry).
        for &node in &rpo {
            if node == entry {
                continue;
            }
            let preds = &pred[node as usize];
            if preds.is_empty() {
                continue;
            }
            // Start from a predecessor that already has an idom.
            let mut new_idom: Option<u32> = None;
            for &p in preds {
                if idom[p as usize].is_some() {
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => intersect(p, cur, &idom),
                    });
                }
            }
            if let Some(ni) = new_idom
                && idom[node as usize] != Some(ni)
            {
                idom[node as usize] = Some(ni);
                changed = true;
            }
        }
    }

    idom
}

/// Dominance frontier of every block (standard two-pass formulation).
///
/// Returns `df[b]` = the set of blocks that `b` dominates the *frontier* of.
pub fn dominance_frontier(
    succ: &[Vec<u32>],
    pred: &[Vec<u32>],
    idom: &[Option<u32>],
) -> Vec<BTreeSet<u32>> {
    let n = succ.len();
    let mut df: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); n];

    for b in 0..n as u32 {
        let preds = &pred[b as usize];
        if preds.len() >= 2 {
            for &p in preds {
                let mut runner = p;
                while Some(runner) != idom[b as usize] {
                    df[runner as usize].insert(b);
                    runner = match idom[runner as usize] {
                        Some(r) => r,
                        None => break,
                    };
                }
            }
        }
    }

    df
}

/// Iterated dominance frontier of a seed set of blocks.
///
/// Repeatedly adds the DF of every newly-added block until fixpoint. The seed
/// blocks themselves are *not* included — phi nodes are placed at the frontier
/// *beyond* the defining blocks (a def block already has an explicit definition).
pub fn iterated_df(df: &[BTreeSet<u32>], seed: &BTreeSet<u32>) -> BTreeSet<u32> {
    let mut worklist: Vec<u32> = seed.iter().copied().collect();
    let mut result: BTreeSet<u32> = BTreeSet::new();
    while let Some(b) = worklist.pop() {
        for &y in &df[b as usize] {
            if result.insert(y) {
                worklist.push(y);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a tiny synthetic CFG: entry -> {B, C}; B -> D; C -> D.
    // Block ids: 0 = entry, 1 = B, 2 = C, 3 = D (the join).
    fn diamond() -> (Vec<Vec<u32>>, Vec<Vec<u32>>, u32) {
        let succ = vec![
            vec![1, 2], // 0 entry
            vec![3],    // 1 B
            vec![3],    // 2 C
            vec![],     // 3 D
        ];
        let pred = vec![
            vec![],     // 0
            vec![0],    // 1
            vec![0],    // 2
            vec![1, 2], // 3
        ];
        (succ, pred, 0)
    }

    #[test]
    fn dominator_diamond() {
        let (succ, pred, entry) = diamond();
        let idom = build_idom(&succ, &pred, entry);
        // Entry dominates itself.
        assert_eq!(idom[0], Some(0));
        // B and C are dominated by entry.
        assert_eq!(idom[1], Some(0));
        assert_eq!(idom[2], Some(0));
        // The join D is dominated by entry (the only common dominator).
        assert_eq!(idom[3], Some(0), "join must be dominated by entry");

        let df = dominance_frontier(&succ, &pred, &idom);
        // The join D appears in the DF of both B and C (the predecessors with a
        // second incoming edge). D's own DF is empty.
        assert!(df[1].contains(&3), "DF(B) should contain the join D");
        assert!(df[2].contains(&3), "DF(C) should contain the join D");
        assert!(!df[3].contains(&3), "DF(D) should be empty");

        // Iterated DF of {B, C} == {D} -> that is where a phi for a variable
        // defined in B and C must be placed.
        let mut seed = BTreeSet::new();
        seed.insert(1u32);
        seed.insert(2u32);
        let idf = iterated_df(&df, &seed);
        assert_eq!(idf, BTreeSet::from([3u32]));
    }
}
