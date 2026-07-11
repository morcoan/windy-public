//! Cytron-style SSA renaming (Cytron, Ferrante, Rosen, Wegman, Zadeck, 1991).
//!
//! Walks the dominator tree in preorder, maintaining a per-location stack of
//! current versions. Uses are rewritten to the version on top of their location's
//! stack; defs (including phi outputs) push a fresh version.
//!
//! Live-in values (function parameters and other registers read before any
//! in-function definition) are seeded as entry-block versions so that every
//! register use resolves to a real definition rather than the uninitialized `0`
//! sentinel. Instruction-scoped [`Location::Unique`] values are deliberately
//! excluded: they only have meaning within the decoded instruction that defines
//! them, and an unmatched use remains genuinely undefined. Versions start at
//! `1`; `0` is reserved for "genuinely undefined".

use std::collections::{BTreeSet, HashMap};

use crate::decompiler::ssa::{FlatOp, Location, PhiNode, SsaOp, SsaOpKind, SsaVar};

/// Assign the next version for `loc` (>= 1; `0` is the uninitialized sentinel).
fn new_version(next_ver: &mut HashMap<Location, u32>, loc: &Location) -> u32 {
    let v = next_ver.entry(loc.clone()).or_insert(1);
    let cur = *v;
    *v += 1;
    cur
}

/// Top of the version stack for `loc`, or `0` if never defined.
fn top(current_def: &HashMap<Location, Vec<u32>>, loc: &Location) -> u32 {
    current_def
        .get(loc)
        .and_then(|s| s.last().copied())
        .unwrap_or(0)
}

/// Run the renamer over the whole function.
///
/// Returns `(phis, pcode_ops)`: per-block phi nodes (with `out` versions and
/// filled `args`) and per-block renamed P-code [`SsaOp`]s (with versioned
/// `def`/`uses`). Block `id` == position in the input vectors.
pub fn rename(
    block_flat: &[Vec<FlatOp>],
    phi_locs: &[Vec<Location>],
    succ: &[Vec<u32>],
    pred: &[Vec<u32>],
    idom: &[Option<u32>],
) -> (Vec<Vec<PhiNode>>, Vec<Vec<SsaOp>>) {
    let n = block_flat.len();

    // Pre-allocate phi nodes (out version filled during rename; args sized to
    // the block's predecessor count).
    let mut phis: Vec<Vec<PhiNode>> = Vec::with_capacity(n);
    for (i, locs) in phi_locs.iter().enumerate() {
        let pc = pred[i].len();
        let mut v = Vec::with_capacity(locs.len());
        for loc in locs {
            v.push(PhiNode {
                out: SsaVar {
                    location: loc.clone(),
                    version: 0,
                },
                args: vec![None; pc],
            });
        }
        phis.push(v);
    }

    let mut pcode_ops: Vec<Vec<SsaOp>> = vec![Vec::new(); n];
    let mut current_def: HashMap<Location, Vec<u32>> = HashMap::new();
    let mut next_ver: HashMap<Location, u32> = HashMap::new();

    // Seed entry-block (= block 0) versions for every function-scoped location
    // that appears anywhere, so live-in/parameter reads resolve instead of
    // staying at 0. Unique values are local to one instruction and must never
    // be treated as function entry values.
    let mut all_locs: BTreeSet<Location> = BTreeSet::new();
    for flat in block_flat {
        for op in flat {
            if let Some(d) = &op.def
                && !d.is_instruction_scoped()
            {
                all_locs.insert(d.clone());
            }
            for u in &op.uses {
                if !u.is_instruction_scoped() {
                    all_locs.insert(u.clone());
                }
            }
        }
    }
    for loc in &all_locs {
        let v = new_version(&mut next_ver, loc);
        current_def.entry(loc.clone()).or_default().push(v);
    }

    // Dominator-tree children for preorder traversal.
    let mut dom_children: Vec<Vec<u32>> = vec![Vec::new(); n];
    for i in 0..n {
        if let Some(Some(p)) = idom.get(i)
            && *p != i as u32
        {
            dom_children[*p as usize].push(i as u32);
        }
    }

    rename_block(
        0,
        block_flat,
        phi_locs,
        succ,
        pred,
        &dom_children,
        &mut current_def,
        &mut next_ver,
        &mut phis,
        &mut pcode_ops,
    );

    (phis, pcode_ops)
}

#[allow(clippy::too_many_arguments)]
fn rename_block(
    block: u32,
    block_flat: &[Vec<FlatOp>],
    phi_locs: &[Vec<Location>],
    succ: &[Vec<u32>],
    pred: &[Vec<u32>],
    dom_children: &[Vec<u32>],
    current_def: &mut HashMap<Location, Vec<u32>>,
    next_ver: &mut HashMap<Location, u32>,
    phis: &mut [Vec<PhiNode>],
    pcode_ops: &mut [Vec<SsaOp>],
) {
    let bi = block as usize;
    let mut pushed: Vec<Location> = Vec::new();

    // 1) Phi outputs are definitions at this block's head.
    for (idx, loc) in phi_locs[bi].iter().enumerate() {
        let v = new_version(next_ver, loc);
        current_def.entry(loc.clone()).or_default().push(v);
        pushed.push(loc.clone());
        phis[bi][idx].out.version = v;
    }

    // 2) Rename the P-code ops.
    for flat in &block_flat[bi] {
        let mut uses = Vec::with_capacity(flat.uses.len());
        for u in &flat.uses {
            let ver = top(current_def, u);
            uses.push(SsaVar {
                location: u.clone(),
                version: ver,
            });
        }
        let def = match &flat.def {
            Some(loc) => {
                let v = new_version(next_ver, loc);
                current_def.entry(loc.clone()).or_default().push(v);
                pushed.push(loc.clone());
                Some(SsaVar {
                    location: loc.clone(),
                    version: v,
                })
            }
            None => None,
        };
        pcode_ops[bi].push(SsaOp {
            va: flat.va,
            kind: SsaOpKind::Pcode(flat.op.clone()),
            def,
            uses,
        });
    }

    // 3) Fill predecessor slots of successor phi nodes with this block's reaching
    //    definitions.
    for &s in &succ[bi] {
        let si = s as usize;
        let pred_slot = pred[si].iter().position(|&p| p == block).unwrap_or(0);
        for phi in &mut phis[si] {
            let ver = top(current_def, &phi.out.location);
            phi.args[pred_slot] = Some(SsaVar {
                location: phi.out.location.clone(),
                version: ver,
            });
        }
    }

    // 4) Recurse into dominator-tree children in preorder.
    for &c in &dom_children[bi] {
        rename_block(
            c,
            block_flat,
            phi_locs,
            succ,
            pred,
            dom_children,
            current_def,
            next_ver,
            phis,
            pcode_ops,
        );
    }

    // 5) Pop the versions defined in this block (entry-seeded versions are never
    //    pushed here, so they persist as live-in for the whole function).
    for loc in &pushed {
        if let Some(stack) = current_def.get_mut(loc) {
            stack.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcode_ir::Varnode;
    use rsleigh_api::PcodeOp;

    #[test]
    fn unique_values_are_renamed_only_from_intra_instruction_defs() {
        let instruction_va = 0x1400_0010;
        let temporary = Location::Unique {
            instruction_va,
            offset: 0x40,
            size: 8,
        };
        let flat = vec![vec![
            FlatOp {
                va: instruction_va,
                op: PcodeOp::Copy {
                    out: Varnode::unique(0x40, 8),
                    input: Varnode::register(0x08, 8),
                },
                def: Some(temporary.clone()),
                uses: vec![Location::Register { base_offset: 0x08 }],
            },
            FlatOp {
                va: instruction_va,
                op: PcodeOp::Copy {
                    out: Varnode::register(0x00, 8),
                    input: Varnode::unique(0x40, 8),
                },
                def: Some(Location::Register { base_offset: 0x00 }),
                uses: vec![temporary.clone()],
            },
        ]];

        let (phis, renamed) = rename(&flat, &[vec![]], &[vec![]], &[vec![]], &[None]);
        assert!(phis[0].is_empty());
        assert_eq!(
            renamed[0][0].def,
            Some(SsaVar {
                location: temporary.clone(),
                version: 1,
            }),
            "Unique def must start at version 1, not an entry-seeded version"
        );
        assert_eq!(
            renamed[0][1].uses,
            vec![SsaVar {
                location: temporary,
                version: 1,
            }],
            "same-instruction consumer must resolve to the Unique producer"
        );
    }
}
