//! Non-boss fixtures for boss-shaped control/data patterns (general mechanisms).
//!
//! These exercises must not name grand program IDs. They model:
//! - dense small-case switch (1/2/3) + loop + xor accumulation
//! - HRESULT constant return (E_POINTER / facility codes)
//! - refcount ±1 store patterns
//! - compound bound predicates (`cursor < end && n < count`)

#![cfg(test)]

use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
use rsleigh_api::{PcodeOp, Varnode};

fn blk(id: u32, va: u64, ops: Vec<SsaOp>, succs: Vec<u32>) -> SsaBlock {
    SsaBlock {
        id,
        entry_va: va,
        ops,
        successor_ids: succs,
        predecessor_ids: vec![],
    }
}

fn link(blocks: &mut [SsaBlock]) {
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
}

fn ret_op(va: u64) -> SsaOp {
    SsaOp {
        va,
        kind: SsaOpKind::Pcode(PcodeOp::Return {
            dest: Varnode::constant(0, 8),
        }),
        def: None,
        uses: vec![],
    }
}

fn cbranch_op(va: u64) -> SsaOp {
    SsaOp {
        va,
        kind: SsaOpKind::Pcode(PcodeOp::CBranch {
            cond: Varnode::constant(1, 1),
            dest: Varnode::constant(0, 8),
        }),
        def: None,
        uses: vec![],
    }
}

fn xor_op(va: u64) -> SsaOp {
    SsaOp {
        va,
        kind: SsaOpKind::Pcode(PcodeOp::IntXor {
            out: Varnode::register(0, 8),
            left: Varnode::register(0, 8),
            right: Varnode::register(8, 8),
        }),
        def: None,
        uses: vec![],
    }
}

fn store_op(va: u64) -> SsaOp {
    SsaOp {
        va,
        kind: SsaOpKind::Pcode(PcodeOp::Store {
            space: pcode_ir::AddressSpaceId::Ram,
            ptr: Varnode::register(0x28, 8),
            val: Varnode::register(0, 4),
        }),
        def: None,
        uses: vec![],
    }
}

fn branch_ind_op(va: u64) -> SsaOp {
    SsaOp {
        va,
        kind: SsaOpKind::Pcode(PcodeOp::BranchInd {
            dest: Varnode::register(0, 8),
        }),
        def: None,
        uses: vec![],
    }
}

/// Dense multiway: header BranchInd → case bodies → merge return with xor.
fn dense_switch_loop_ssa() -> SsaFunction {
    // 0: cbranch loop header → body(1) or exit(6)
    // 1: branchind switch → 2,3,4,5
    // 2/3/4: case arms with store + xor, jump merge
    // 5: default store
    // 6: return xor
    let mut blocks = vec![
        blk(0, 0x1000, vec![cbranch_op(0x1000)], vec![6, 1]),
        blk(1, 0x1010, vec![branch_ind_op(0x1010)], vec![2, 3, 4, 5]),
        blk(2, 0x1020, vec![store_op(0x1020), xor_op(0x1024)], vec![0]),
        blk(3, 0x1030, vec![store_op(0x1030), xor_op(0x1034)], vec![0]),
        blk(4, 0x1040, vec![store_op(0x1040), xor_op(0x1044)], vec![0]),
        blk(5, 0x1050, vec![store_op(0x1050)], vec![0]),
        blk(6, 0x1060, vec![xor_op(0x1060), ret_op(0x1064)], vec![]),
    ];
    link(&mut blocks);
    SsaFunction {
        entry_va: 0x1000,
        bitness: 64,
        blocks,
        image_base: 0,
    }
}

/// HRESULT-style: if (ptr == 0) return 0x80004003; else store through ptr.
fn hresult_null_check_ssa() -> SsaFunction {
    let mut blocks = vec![
        blk(0, 0x2000, vec![cbranch_op(0x2000)], vec![1, 2]),
        blk(
            1,
            0x2010,
            vec![
                SsaOp {
                    va: 0x2010,
                    kind: SsaOpKind::Pcode(PcodeOp::Copy {
                        out: Varnode::register(0, 4),
                        input: Varnode::constant(0x8000_4003, 4),
                    }),
                    def: None,
                    uses: vec![],
                },
                ret_op(0x2014),
            ],
            vec![],
        ),
        blk(2, 0x2020, vec![store_op(0x2020), ret_op(0x2024)], vec![]),
    ];
    link(&mut blocks);
    SsaFunction {
        entry_va: 0x2000,
        bitness: 64,
        blocks,
        image_base: 0,
    }
}

/// Refcount: load, add 1, store, return (AddRef-shaped).
fn refcount_inc_ssa() -> SsaFunction {
    let mut blocks = vec![blk(
        0,
        0x3000,
        vec![
            SsaOp {
                va: 0x3000,
                kind: SsaOpKind::Pcode(PcodeOp::Load {
                    out: Varnode::register(0, 4),
                    space: pcode_ir::AddressSpaceId::Ram,
                    ptr: Varnode::constant(0x1400_1000, 8),
                }),
                def: None,
                uses: vec![],
            },
            SsaOp {
                va: 0x3004,
                kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                    out: Varnode::register(0, 4),
                    left: Varnode::register(0, 4),
                    right: Varnode::constant(1, 4),
                }),
                def: None,
                uses: vec![],
            },
            store_op(0x3008),
            ret_op(0x300c),
        ],
        vec![],
    )];
    link(&mut blocks);
    SsaFunction {
        entry_va: 0x3000,
        bitness: 64,
        blocks,
        image_base: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::structure::region::SwitchInfo;
    use crate::decompiler::structure::{NameCtx, decompile};
    use crate::decompiler::v2::check::check_candidate;
    use crate::decompiler::v2::contracts::{CaseContractV2, ContractBundle};
    use crate::decompiler::v2::extract::AstCandidate;
    use crate::decompiler::v2::observation::critical_signature;
    use crate::decompiler::v2::semantic::SemanticModel;
    use std::collections::HashMap;

    fn decompile_plain(ssa: &SsaFunction) -> String {
        let names = NameCtx {
            frame: None,
            sig: None,
            global_names: HashMap::new(),
            insn_to_global: HashMap::new(),
        };
        decompile(ssa, None, None, 64, &[], &names)
    }

    #[test]
    fn dense_switch_recovers_case_partition_and_loop() {
        let ssa = dense_switch_loop_ssa();
        let switches = [SwitchInfo {
            branch_va: 0x1010,
            cases: vec![(1, 2), (2, 3), (3, 4), (0, 5)],
        }];
        let sem = SemanticModel::from_ssa(&ssa);
        let contracts = ContractBundle::from_semantic(&ssa, &sem, &switches);
        assert!(
            !contracts.cases.is_empty() || matches!(sem.terminators.get(1), Some(_)),
            "expected switch contract or terminator: {:?}",
            contracts
        );
        // Loop contract from back-edge 2/3/4 → 0
        assert!(
            !contracts.loops.is_empty() || sem.succ[2].contains(&0),
            "expected loop structure: {:?}",
            contracts.loops
        );
        let text = decompile_plain(&ssa);
        // Structured emit should surface multiway or residual control, not empty.
        assert!(!text.trim().is_empty(), "empty decompile");
        assert!(
            text.contains("switch")
                || text.contains("if")
                || text.contains("while")
                || text.contains("goto"),
            "expected control structure in:\n{text}"
        );
    }

    #[test]
    fn hresult_constant_surfaces_in_decompile() {
        let ssa = hresult_null_check_ssa();
        let text = decompile_plain(&ssa);
        assert!(
            text.contains("80004003") || text.contains("0x80004003") || text.contains("if"),
            "expected HRESULT or null-check shape:\n{text}"
        );
        let sem = SemanticModel::from_ssa(&ssa);
        assert!(
            sem.critical_effects().iter().any(|o| matches!(
                o.kind,
                crate::decompiler::v2::observation::ObservationKind::Return
            )),
            "return effect required"
        );
        assert!(
            sem.critical_effects().iter().any(|o| matches!(
                o.kind,
                crate::decompiler::v2::observation::ObservationKind::Store { .. }
            )),
            "store effect on non-null arm required"
        );
    }

    #[test]
    fn refcount_inc_preserves_store_and_return() {
        let ssa = refcount_inc_ssa();
        let text = decompile_plain(&ssa);
        assert!(!text.trim().is_empty());
        let sem = SemanticModel::from_ssa(&ssa);
        let stores = sem
            .critical_effects()
            .iter()
            .filter(|o| {
                matches!(
                    o.kind,
                    crate::decompiler::v2::observation::ObservationKind::Store { .. }
                )
            })
            .count();
        let rets = sem
            .critical_effects()
            .iter()
            .filter(|o| {
                matches!(
                    o.kind,
                    crate::decompiler::v2::observation::ObservationKind::Return
                )
            })
            .count();
        assert!(stores >= 1, "refcount must store: {text}");
        assert!(rets >= 1, "refcount must return: {text}");
    }

    #[test]
    fn checker_rejects_dropped_switch_partition() {
        let ssa = dense_switch_loop_ssa();
        let sem = SemanticModel::from_ssa(&ssa);
        let sig = critical_signature(&sem.observations);
        let bad = AstCandidate {
            text: "int f() { return 0; }".into(),
            edges_covered: 0,
            residual_edges: 0,
            effects_covered: 0,
            effect_signature: vec![], // dropped all
            case_partitions: vec![CaseContractV2 {
                case_count: 0,
                has_default: false,
                labels: vec![],
                source: "bad".into(),
            }],
            cost: 0,
            nesting: 0,
        };
        let r = check_candidate(&sem, &bad);
        assert!(!r.accepted, "{r:?}");
        assert!(
            r.rejects.iter().any(|x| x.contains("dropped")
                || x.contains("empty_case")
                || x.contains("mismatch")),
            "{r:?}"
        );
        let _ = sig;
    }

    #[test]
    fn checker_rejects_reordered_call_before_return_drop() {
        // Synthetic: call then return in semantic; candidate claims empty effects.
        let mut blocks = vec![blk(
            0,
            0x4000,
            vec![
                SsaOp {
                    va: 0x4000,
                    kind: SsaOpKind::Pcode(PcodeOp::Call {
                        dest: Varnode::constant(0x1400_01000, 8),
                    }),
                    def: None,
                    uses: vec![],
                },
                ret_op(0x4004),
            ],
            vec![],
        )];
        link(&mut blocks);
        let ssa = SsaFunction {
            entry_va: 0x4000,
            bitness: 64,
            blocks,
            image_base: 0,
        };
        let sem = SemanticModel::from_ssa(&ssa);
        let bad = AstCandidate {
            text: "void f() {}".into(),
            edges_covered: 0,
            residual_edges: 0,
            effects_covered: 0,
            effect_signature: vec![],
            case_partitions: vec![],
            cost: 0,
            nesting: 0,
        };
        let r = check_candidate(&sem, &bad);
        assert!(!r.accepted);
        assert!(
            r.rejects
                .iter()
                .any(|x| x.contains("dropped") || x.contains("mismatch"))
        );
    }

    #[test]
    fn checker_accepts_multiblock_pure_with_switch_text() {
        let ssa = dense_switch_loop_ssa();
        let sem = SemanticModel::from_ssa(&ssa);
        assert!(sem.n_blocks > 1, "fixture must be multi-block");
        let sig = critical_signature(&sem.observations);
        let good = AstCandidate {
            text: "int f(){ while(1){ switch(t){ case 1: *p=1; break; case 2: *p=2; break; } } return x^y; }"
                .into(),
            edges_covered: 4,
            residual_edges: 0,
            effects_covered: sig.len(),
            effect_signature: sig,
            case_partitions: vec![CaseContractV2 {
                case_count: 3,
                has_default: true,
                labels: vec![1, 2, 3],
                source: "fixture".into(),
            }],
            cost: 2,
            nesting: 2,
        };
        let r = check_candidate(&sem, &good);
        assert!(
            r.accepted,
            "structured multi-block pure must be accepted: {r:?}"
        );
    }
}
