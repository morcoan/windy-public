//! Loop / case / return contracts with topology-stable fingerprints.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::decompiler::ssa::SsaFunction;
use crate::decompiler::structure::region::{Region, SwitchInfo, classify_with_adj};

use super::semantic::{SemanticModel, Terminator};

/// Loop recurrence contract (header topology, not raw block IDs in fingerprint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopContractV2 {
    pub kind: String,
    pub body_depth: u32,
    pub multi_exit: bool,
}

/// Case partition contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseContractV2 {
    pub case_count: usize,
    pub has_default: bool,
    /// Sorted case labels when known.
    pub labels: Vec<i64>,
    pub source: String,
}

/// One architectural return block and its independently recovered value class.
/// Block IDs are retained for checker correlation but omitted from the stable
/// aggregate fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnExitContract {
    pub block_id: u32,
    pub value_class: String,
}

/// Bundle of validated contracts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractBundle {
    pub loops: Vec<LoopContractV2>,
    pub cases: Vec<CaseContractV2>,
    pub return_class: String,
    pub has_return: bool,
    #[serde(default)]
    pub return_exits: Vec<ReturnExitContract>,
}

impl ContractBundle {
    /// Topology/value fingerprint (no raw block IDs).
    pub fn fingerprint(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("loops={}", self.loops.len()));
        for l in &self.loops {
            parts.push(format!(
                "L:{}:d{}:m{}",
                l.kind, l.body_depth, l.multi_exit as u8
            ));
        }
        parts.push(format!("ret:{}", self.return_class));
        parts.push(format!("cases={}", self.cases.len()));
        for c in &self.cases {
            parts.push(format!(
                "C:{}:def{}:{:?}",
                c.case_count, c.has_default as u8, c.labels
            ));
        }
        parts.join("|")
    }

    /// Recover contracts from semantic model + structured regions.
    pub fn from_semantic(ssa: &SsaFunction, sem: &SemanticModel, switches: &[SwitchInfo]) -> Self {
        let regions = classify_with_adj(ssa, switches, &sem.succ, &sem.pred, true);
        let mut loops = Vec::new();
        let mut cases = Vec::new();

        for r in regions.values() {
            match r {
                Region::While { .. } => loops.push(LoopContractV2 {
                    kind: "while".into(),
                    body_depth: 1,
                    multi_exit: false,
                }),
                Region::DoWhile { .. } => loops.push(LoopContractV2 {
                    kind: "do_while".into(),
                    body_depth: 1,
                    multi_exit: false,
                }),
                Region::Switch { cases: cs, .. } => {
                    let mut labels: Vec<i64> = cs.iter().map(|(v, _)| *v).collect();
                    labels.sort_unstable();
                    cases.push(CaseContractV2 {
                        case_count: labels.len(),
                        has_default: false,
                        labels,
                        source: "branch_ind".into(),
                    });
                }
                _ => {}
            }
        }

        // Terminators: multiway Switch without region.
        if cases.is_empty() {
            for t in &sem.terminators {
                if let Terminator::Switch { targets } = t
                    && targets.len() >= 2
                {
                    let labels: Vec<i64> = (0..targets.len() as i64).collect();
                    cases.push(CaseContractV2 {
                        case_count: targets.len(),
                        has_default: false,
                        labels,
                        source: "terminator".into(),
                    });
                }
            }
        }

        // Eq-ladder constants from dual-model recovery path.
        if cases.is_empty()
            && let Some(part) =
                crate::decompiler::structure::rd_model::ContractSet::from_regions(ssa, &regions)
                    .cases
                    .into_iter()
                    .next()
        {
            cases.push(CaseContractV2 {
                case_count: part.case_values.len(),
                has_default: false,
                labels: part.case_values,
                source: "eq_ladder".into(),
            });
        }

        let env = crate::decompiler::v2::ssa_expr::build_expr_map(ssa);
        let return_exits = ssa
            .blocks
            .iter()
            .filter(|block| {
                block.ops.iter().any(|op| {
                    matches!(
                        &op.kind,
                        crate::decompiler::ssa::SsaOpKind::Pcode(
                            rsleigh_api::PcodeOp::Return { .. }
                        )
                    )
                })
            })
            .map(|block| ReturnExitContract {
                block_id: block.id,
                value_class: crate::decompiler::v2::ssa_expr::return_expr_of_exit(
                    ssa, block.id, &env,
                )
                .as_ref()
                .map(crate::decompiler::v2::ssa_expr::expr_class_tag)
                .unwrap_or_else(|| "unknown".into()),
            })
            .collect();

        Self {
            loops,
            cases,
            return_class: sem.exit_class.class_tag.clone(),
            has_return: sem.exit_class.has_return,
            return_exits,
        }
    }

    /// Canonicalize labels for cross-profile compare (drop block topology).
    pub fn orbit_key(&self) -> String {
        let mut loops: Vec<_> = self.loops.iter().map(|l| l.kind.as_str()).collect();
        loops.sort_unstable();
        let mut case_counts: Vec<_> = self.cases.iter().map(|c| c.case_count).collect();
        case_counts.sort_unstable();
        format!("L:{:?}|R:{}|C:{:?}", loops, self.return_class, case_counts)
    }
}

/// Control-dependence predicate map (block → simplified cond tags).
#[derive(Clone, Debug, Default)]
pub struct ControlDependence {
    pub predicates: BTreeMap<u32, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use crate::decompiler::v2::semantic::SemanticModel;
    use rsleigh_api::{PcodeOp, Varnode};

    #[test]
    fn fingerprint_omits_raw_block_ids() {
        let c = ContractBundle {
            loops: vec![LoopContractV2 {
                kind: "while".into(),
                body_depth: 1,
                multi_exit: false,
            }],
            cases: vec![CaseContractV2 {
                case_count: 3,
                has_default: true,
                labels: vec![0, 1, 2],
                source: "t".into(),
            }],
            return_class: "arith".into(),
            has_return: true,
            return_exits: vec![],
        };
        let fp = c.fingerprint();
        assert!(!fp.contains("block"), "{fp}");
        assert!(fp.contains("loops=1"), "{fp}");
        assert!(fp.contains("cases=1"), "{fp}");
        assert!(fp.contains("[0, 1, 2]"), "{fp}");
    }

    #[test]
    fn contracts_from_self_loop() {
        let mut blocks = vec![
            SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::CBranch {
                        cond: Varnode::constant(1, 1),
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                successor_ids: vec![1, 0],
                predecessor_ids: vec![0],
            },
            SsaBlock {
                id: 1,
                entry_va: 0x1010,
                ops: vec![SsaOp {
                    va: 0x1010,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                successor_ids: vec![],
                predecessor_ids: vec![0],
            },
        ];
        // fix preds
        blocks[0].predecessor_ids = vec![0];
        blocks[1].predecessor_ids = vec![0];
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        };
        let sem = SemanticModel::from_ssa(&ssa);
        let c = ContractBundle::from_semantic(&ssa, &sem, &[]);
        assert!(!c.loops.is_empty() || c.has_return, "{c:?}");
        let k1 = c.orbit_key();
        let k2 = c.orbit_key();
        assert_eq!(k1, k2);
    }
}
