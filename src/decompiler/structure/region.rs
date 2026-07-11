//! Reachability + region classification for structured C emission — Phase 5.1 S2.
//!
//! Classifies CBranch / BranchInd / loop headers into If / IfElse / While /
//! DoWhile / Switch regions using the post-dominator tree and forward dominators.

use std::collections::{HashMap, HashSet};

use rsleigh_api::PcodeOp;

use crate::decompiler::ssa::cfg::build_idom;
use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOpKind};

use super::pdom::{adj_from_ssa, build_ipdom, virtual_exit};

/// Structured region rooted at a control-flow block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Region {
    /// Two-way branch with non-empty then and else arms meeting at `merge`.
    IfElse {
        then_entry: u32,
        else_entry: u32,
        merge: u32,
    },
    /// One-way branch; `invert` means emit `if (!cond)` when the non-empty arm
    /// is the fallthrough (cond-false) path.
    If {
        body_entry: u32,
        merge: u32,
        invert: bool,
    },
    /// Top-tested loop. `body_entry` is the in-loop successor; `exit` is the
    /// out-of-loop successor. Condition lives in the header block.
    While { body_entry: u32, exit: u32 },
    /// Bottom-tested loop. Body starts at `body_entry`; condition is in
    /// `cond_block` (often a self-loop single block where body_entry == cond_block).
    DoWhile {
        body_entry: u32,
        cond_block: u32,
        exit: u32,
    },
    /// Multi-way BranchInd with resolved case values.
    Switch { cases: Vec<(i64, u32)>, merge: u32 },
    /// Block ends in a Return.
    Return,
}

/// Resolved switch table for one BranchInd block (filled by the project layer).
#[derive(Clone, Debug, Default)]
pub struct SwitchInfo {
    /// Entry VA of the SSA block that ends in BranchInd.
    pub branch_va: u64,
    /// `(case_value, target_block_id)` ordered by table index.
    pub cases: Vec<(i64, u32)>,
}

/// Blocks reachable from `start` without entering `stop` (stop itself excluded).
pub fn reach(start: u32, stop: u32, succ: &[Vec<u32>]) -> HashSet<u32> {
    let n = succ.len();
    if start as usize >= n || start == stop {
        return HashSet::new();
    }
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(b) = stack.pop() {
        if b == stop || b as usize >= n {
            continue;
        }
        if !seen.insert(b) {
            continue;
        }
        for &s in &succ[b as usize] {
            if s != stop {
                stack.push(s);
            }
        }
    }
    seen
}

/// Whether `a` dominates `b` in the forward dominator tree (`idom`).
pub fn dominates(a: u32, b: u32, idom: &[Option<u32>]) -> bool {
    if a == b {
        return true;
    }
    let mut cur = b;
    let limit = idom.len() + 1;
    for _ in 0..limit {
        match idom.get(cur as usize).and_then(|x| *x) {
            Some(p) if p == cur => return false, // hit entry without seeing a
            Some(p) => {
                if p == a {
                    return true;
                }
                cur = p;
            }
            None => return false,
        }
    }
    false
}

/// Forward edge `from → to` is a back edge when `to` dominates `from`.
pub fn is_back_edge(from: u32, to: u32, idom: &[Option<u32>]) -> bool {
    dominates(to, from, idom)
}

fn is_cbranch(block: &SsaBlock) -> bool {
    block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::CBranch { .. })))
}

fn is_branch_ind(block: &SsaBlock) -> bool {
    block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::BranchInd { .. })))
}

fn is_return(block: &SsaBlock) -> bool {
    block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
}

/// CBranch successor convention from the CFG builder:
/// `successor_ids[0]` = fallthrough (cond false), `successor_ids[1]` = taken (cond true).
/// Returns `(fallthrough, taken)` when both exist.
fn cbranch_arms(block: &SsaBlock) -> Option<(u32, u32)> {
    if !is_cbranch(block) {
        return None;
    }
    let s = &block.successor_ids;
    if s.len() >= 2 {
        Some((s[0], s[1]))
    } else if s.len() == 1 {
        // Degenerate: only one arm recorded.
        Some((s[0], s[0]))
    } else {
        None
    }
}

/// Classify structured regions for `ssa`. `switches` supplies case values for
/// BranchInd blocks (empty → still classify as Switch with block-index cases).
pub fn classify(ssa: &SsaFunction, switches: &[SwitchInfo]) -> HashMap<u32, Region> {
    let n = ssa.blocks.len();
    if n == 0 {
        return HashMap::new();
    }
    let (succ, pred) = adj_from_ssa(ssa);
    let ipdom = build_ipdom(&succ, &pred);
    let idom = build_idom(&succ, &pred, 0);
    let ve = virtual_exit(n);

    // Map branch_va → switch cases for quick lookup.
    let switch_by_va: HashMap<u64, &SwitchInfo> =
        switches.iter().map(|s| (s.branch_va, s)).collect();

    // Loop headers: targets of back edges.
    let mut back_edge_preds: HashMap<u32, Vec<u32>> = HashMap::new();
    for b in 0..n as u32 {
        for &s in &succ[b as usize] {
            if is_back_edge(b, s, &idom) {
                back_edge_preds.entry(s).or_default().push(b);
            }
        }
    }

    let mut regions: HashMap<u32, Region> = HashMap::new();

    // --- Returns ---
    for (i, block) in ssa.blocks.iter().enumerate() {
        if is_return(block) {
            regions.insert(i as u32, Region::Return);
        }
    }

    // --- Switches (BranchInd with ≥2 successors preferred; >2 ideal) ---
    for (i, block) in ssa.blocks.iter().enumerate() {
        if !is_branch_ind(block) {
            continue;
        }
        let succs = &block.successor_ids;
        if succs.len() < 2 {
            continue;
        }
        let merge = ipdom
            .get(i)
            .and_then(|x| *x)
            .filter(|&m| m != ve)
            .unwrap_or(ve);

        let cases = if let Some(info) = switch_by_va.get(&block.entry_va) {
            info.cases.clone()
        } else {
            // Fallback: table index = successor order.
            succs
                .iter()
                .enumerate()
                .map(|(k, &t)| (k as i64, t))
                .collect()
        };
        regions.insert(i as u32, Region::Switch { cases, merge });
    }

    // --- Loops (While / DoWhile) before plain if, so headers win ---
    for (&header, latches) in &back_edge_preds {
        let hblock = &ssa.blocks[header as usize];

        // Self-loop do-while: header CBranch with a successor edge to itself.
        if is_cbranch(hblock)
            && let Some((fall, taken)) = cbranch_arms(hblock)
        {
            let self_loop = fall == header || taken == header;
            if self_loop {
                let exit = if fall == header { taken } else { fall };
                regions.insert(
                    header,
                    Region::DoWhile {
                        body_entry: header,
                        cond_block: header,
                        exit,
                    },
                );
                continue;
            }
        }

        // While: header is CBranch; one arm stays in-loop, one exits.
        if is_cbranch(hblock)
            && let Some((fall, taken)) = cbranch_arms(hblock)
        {
            let fall_in = is_in_loop(fall, header, &succ, &idom);
            let taken_in = is_in_loop(taken, header, &succ, &idom);
            if fall_in != taken_in {
                let (body, exit) = if taken_in {
                    (taken, fall)
                } else {
                    (fall, taken)
                };
                regions.insert(
                    header,
                    Region::While {
                        body_entry: body,
                        exit,
                    },
                );
                continue;
            }
        }

        // Do-while: latch is CBranch with back edge to header; header is body entry.
        for &latch in latches {
            if latch == header {
                continue;
            }
            let lblock = &ssa.blocks[latch as usize];
            if !is_cbranch(lblock) {
                continue;
            }
            if let Some((fall, taken)) = cbranch_arms(lblock) {
                let back = if fall == header {
                    fall
                } else if taken == header {
                    taken
                } else {
                    continue;
                };
                let _ = back;
                let exit = if fall == header { taken } else { fall };
                // Root the region at the body entry (header). Cond at latch.
                regions.insert(
                    header,
                    Region::DoWhile {
                        body_entry: header,
                        cond_block: latch,
                        exit,
                    },
                );
                break;
            }
        }
    }

    // --- If / IfElse for remaining CBranches ---
    for (i, block) in ssa.blocks.iter().enumerate() {
        let bi = i as u32;
        if regions.contains_key(&bi) {
            continue;
        }
        if !is_cbranch(block) {
            continue;
        }
        let Some((fall, taken)) = cbranch_arms(block) else {
            continue;
        };

        // Merge = immediate post-dominator of the branch (real block or ve).
        let merge = ipdom.get(i).and_then(|x| *x).unwrap_or(ve);

        // If an arm *is* the merge, that arm is empty.
        let then_reach = if taken == merge {
            HashSet::new()
        } else {
            reach(taken, merge, &succ)
        };
        let else_reach = if fall == merge {
            HashSet::new()
        } else {
            reach(fall, merge, &succ)
        };

        let then_empty = then_reach.is_empty();
        let else_empty = else_reach.is_empty();

        match (then_empty, else_empty) {
            (false, false) => {
                regions.insert(
                    bi,
                    Region::IfElse {
                        then_entry: taken,
                        else_entry: fall,
                        merge,
                    },
                );
            }
            (false, true) => {
                // Only taken (cond-true) arm has body.
                regions.insert(
                    bi,
                    Region::If {
                        body_entry: taken,
                        merge,
                        invert: false,
                    },
                );
            }
            (true, false) => {
                // Only fallthrough (cond-false) arm has body → if (!cond).
                regions.insert(
                    bi,
                    Region::If {
                        body_entry: fall,
                        merge,
                        invert: true,
                    },
                );
            }
            (true, true) => {
                // Both empty (branch directly to merge both ways) — skip.
            }
        }
    }

    // Short-circuit &&/|| merge (S5): fold adjacent CBranches sharing a false
    // (or true) target into a single logical region. Best-effort; failures
    // leave nested ifs (always correct).
    apply_short_circuit(ssa, &succ, &mut regions);

    regions
}

/// A successor is "in the loop" of `header` if it is the header itself or
/// `header` dominates it (natural-loop members are dominated by the header).
fn is_in_loop(succ: u32, header: u32, _succ_adj: &[Vec<u32>], idom: &[Option<u32>]) -> bool {
    succ == header || dominates(header, succ, idom)
}

/// Best-effort short-circuit detection (S5).
///
/// AND pattern: B1 fallthrough → B2, and B1.taken == B2.taken (shared false).
/// Then rewrite B1 as `If`/`IfElse` with a synthetic combined condition marker
/// stored by overwriting B1's region; B2 is left alone but the emitter checks
/// for the `&&` annotation via [`ShortCircuit`].
///
/// We store short-circuit metadata in a parallel map returned separately would
/// be cleaner, but to keep the API as `HashMap<u32, Region>` we encode AND/OR
/// by adjusting the If body to skip B2 and letting the emitter consult
/// [`detect_short_circuit`] at emit time instead.
fn apply_short_circuit(
    _ssa: &SsaFunction,
    _succ: &[Vec<u32>],
    _regions: &mut HashMap<u32, Region>,
) {
    // Pattern matching is applied at emit time via `detect_short_circuit` so
    // we never risk incorrect region rewrites. This hook is intentionally a
    // no-op placeholder for future region-level merging.
}

/// Detect `cond1 && cond2` or `cond1 || cond2` spanning two CBranch blocks.
///
/// Returns `Some((op, second_block, shared_target, true_target))` where `op` is
/// `"&&"` or `"||"`. Self-loops and same-block pairs are rejected.
pub fn detect_short_circuit(
    b1: &SsaBlock,
    ssa: &SsaFunction,
) -> Option<(&'static str, u32, u32, u32)> {
    let (f1, t1) = cbranch_arms(b1)?;
    let b1_id = b1.id;

    // AND: fallthrough is another CBranch B2; both share the same taken target.
    if f1 != b1_id && (f1 as usize) < ssa.blocks.len() {
        let b2 = &ssa.blocks[f1 as usize];
        if is_cbranch(b2)
            && let Some((f2, t2)) = cbranch_arms(b2)
            && t1 == t2
            && f1 != t1
            && f2 != b1_id
        {
            // Shared false (taken) target → if (c1 && c2) then fallthrough-of-b2.
            return Some(("&&", f1, t1, f2));
        }
    }
    // OR: taken of B1 is a *different* CBranch B2; both share fallthrough.
    if t1 != b1_id && (t1 as usize) < ssa.blocks.len() {
        let b2t = &ssa.blocks[t1 as usize];
        if is_cbranch(b2t)
            && let Some((f2, t2)) = cbranch_arms(b2t)
            && f1 == f2
            && t1 != f1
            && t2 != b1_id
        {
            // Shared fallthrough and B1.taken = B2 → if (c1 || c2).
            return Some(("||", t1, f1, t2));
        }
    }
    None
}

/// Public re-export of arm order helper for the emitter.
pub fn cbranch_fall_taken(block: &SsaBlock) -> Option<(u32, u32)> {
    cbranch_arms(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{Location, SsaOp, SsaVar};
    use pcode_ir::Varnode;

    fn reg(offset: u64, version: u32) -> SsaVar {
        SsaVar {
            location: Location::Register {
                base_offset: offset,
            },
            version,
        }
    }

    fn empty_block(id: u32, entry_va: u64, preds: Vec<u32>, succs: Vec<u32>) -> SsaBlock {
        SsaBlock {
            id,
            entry_va,
            ops: vec![],
            predecessor_ids: preds,
            successor_ids: succs,
        }
    }

    fn cbranch_block(id: u32, entry_va: u64, preds: Vec<u32>, succs: Vec<u32>) -> SsaBlock {
        let op = SsaOp {
            va: entry_va,
            kind: SsaOpKind::Pcode(PcodeOp::CBranch {
                dest: Varnode::constant(0, 8),
                cond: Varnode::register(0x00, 1),
            }),
            def: None,
            uses: vec![reg(0x00, 1)],
        };
        SsaBlock {
            id,
            entry_va,
            ops: vec![op],
            predecessor_ids: preds,
            successor_ids: succs,
        }
    }

    /// Diamond: 0 cbranch → then(1)/else(2) → join(3 return).
    fn diamond_ssa() -> SsaFunction {
        let b0 = cbranch_block(0, 0x1000, vec![], vec![2, 1]); // fall=else(2), taken=then(1)
        let b1 = empty_block(1, 0x1010, vec![0], vec![3]);
        let b2 = empty_block(2, 0x1020, vec![0], vec![3]);
        let mut b3 = empty_block(3, 0x1030, vec![1, 2], vec![]);
        b3.ops.push(SsaOp {
            va: 0x1030,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 1)],
        });
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1, b2, b3],
            image_base: 0,
        }
    }

    /// Self-loop: 0 cbranch → fall=exit(1), taken=self(0).
    fn self_loop_ssa() -> SsaFunction {
        let b0 = cbranch_block(0, 0x1000, vec![0], vec![1, 0]); // fall=exit, taken=self
        let mut b1 = empty_block(1, 0x1100, vec![0], vec![]);
        b1.ops.push(SsaOp {
            va: 0x1100,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![],
        });
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1],
            image_base: 0,
        }
    }

    /// If-then only: 0 cbranch → fall=merge(2), taken=body(1) → merge(2).
    fn if_then_ssa() -> SsaFunction {
        let b0 = cbranch_block(0, 0x1000, vec![], vec![2, 1]); // fall=merge, taken=body
        let b1 = empty_block(1, 0x1010, vec![0], vec![2]);
        let mut b2 = empty_block(2, 0x1020, vec![0, 1], vec![]);
        b2.ops.push(SsaOp {
            va: 0x1020,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![],
        });
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1, b2],
            image_base: 0,
        }
    }

    #[test]
    fn diamond_classifies_as_if_else() {
        let ssa = diamond_ssa();
        let regions = classify(&ssa, &[]);
        match regions.get(&0) {
            Some(Region::IfElse {
                then_entry,
                else_entry,
                merge,
            }) => {
                assert_eq!(*then_entry, 1);
                assert_eq!(*else_entry, 2);
                assert_eq!(*merge, 3);
            }
            other => panic!("expected IfElse, got {other:?}"),
        }
    }

    #[test]
    fn self_loop_classifies_as_while_or_do_while() {
        let ssa = self_loop_ssa();
        let regions = classify(&ssa, &[]);
        match regions.get(&0) {
            Some(Region::DoWhile { exit, .. }) | Some(Region::While { exit, .. }) => {
                assert_eq!(*exit, 1);
            }
            other => panic!("expected While/DoWhile, got {other:?}"),
        }
    }

    #[test]
    fn one_dead_arm_classifies_as_if() {
        let ssa = if_then_ssa();
        let regions = classify(&ssa, &[]);
        match regions.get(&0) {
            Some(Region::If {
                body_entry,
                merge,
                invert,
            }) => {
                assert_eq!(*body_entry, 1);
                assert_eq!(*merge, 2);
                assert!(!*invert);
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn reach_excludes_stop() {
        let succ = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let r = reach(1, 3, &succ);
        assert!(r.contains(&1));
        assert!(!r.contains(&3));
        assert!(!r.contains(&2));
    }
}
