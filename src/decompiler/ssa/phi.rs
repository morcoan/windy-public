//! Phi placement at iterated dominance frontiers (Cytron et al., 1991).
//!
//! For every location, the blocks that define it form a seed set. A phi for that
//! location is required at every block in the iterated dominance frontier (IDF)
//! of the seed. We collect, per block, the set of locations that need a phi at
//! its head.

use std::collections::{BTreeMap, BTreeSet};

use crate::decompiler::ssa::Location;
use crate::decompiler::ssa::cfg::iterated_df;

/// Compute, for each block, the ordered list of locations that need a phi node
/// at that block's head.
///
/// `def_blocks` maps each location to the set of block indices that define it.
/// `df` is the per-block dominance frontier computed by `cfg`.
pub fn place_phis(
    def_blocks: &BTreeMap<Location, BTreeSet<u32>>,
    df: &[BTreeSet<u32>],
) -> Vec<Vec<Location>> {
    let n = df.len();
    let mut phi_locs: Vec<Vec<Location>> = vec![Vec::new(); n];

    for (loc, blocks) in def_blocks {
        // A single-definition location never needs a phi (a use is always
        // dominated by its definition, so there is no merge ambiguity).
        if blocks.len() < 2 {
            continue;
        }
        let idf = iterated_df(df, blocks);
        for b in idf {
            if b as usize >= n {
                continue;
            }
            if !phi_locs[b as usize].contains(loc) {
                phi_locs[b as usize].push(loc.clone());
            }
        }
    }

    phi_locs
}
