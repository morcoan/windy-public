//! SSA simplification — a side-layer optimization pass over a frozen [`SsaFunction`].
//!
//! **Design contract (locked):** this pass never mutates the carried `PcodeOp`s.
//! It only drops whole [`SsaOp`]s and re-points `def`/`uses` [`SsaVar`] versions
//! (plus phi `args`) via union-find alias resolution. The raw SSA produced by
//! Phase 2's `build_ssa` is left untouched; [`super::SsaFunction`] is consumed by
//! value and a *pruned clone* is returned alongside an [`SsaAnalysis`] side-structure.
//!
//! The pass performs four conservative transformations:
//!
//! 1. **Copy propagation.** A `Copy { out: B, input: A }` where `A` is a tracked
//!    register makes `B` an alias of `A`'s reaching definition. All uses of `B`
//!    are re-pointed to `A` and the copy op is dead (removed by DCE). Cycles are
//!    guarded by `union`'s same-root check.
//! 2. **Constant propagation.** A `Copy { out: B, input: const }` records `B` as a
//!    constant. Constants are tracked so trivial phis can collapse and dead
//!    pure-constant results are eliminated by DCE. Because `PcodeOp`s are frozen
//!    we cannot physically inline a constant into a later op's operand, so a
//!    *used* constant-copy stays (it is still materialized into a register); only
//!    dead ones are removed.
//! 3. **Trivial-phi collapse.** A phi whose every defined argument resolves to the
//!    same representative (a single `SsaVar`) is aliased to that representative and
//!    dropped. A phi whose every argument is the same constant records the constant
//!    value (the phi itself is kept, since the frozen op still reads a register).
//!    Phis are iterated to a fixpoint to catch cascading collapses.
//! 4. **Conservative DCE.** Only *pure value-def ops* with zero live uses are
//!    removed. Store/Load/Branch/CBranch/BranchInd/Return/Call/CallInd/CallOther are
//!    treated as side effects and never removed. This includes instruction-scoped
//!    Unique temporaries, whose copy chains can be collapsed like register chains.

use std::collections::{HashMap, HashSet};

use pcode_ir::AddressSpaceId;
use rsleigh_api::PcodeOp;

use super::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};

/// A definition resolved to a concrete constant during simplification. `va` is
/// the defining op's instruction VA (0 for phis).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaConstant {
    pub va: u64,
    pub value: u64,
    pub size: u32,
}

/// A copy/alias collapsed during simplification. `def_va` defines an SSA value
/// as a copy of the alias chain rooted at `target_va`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaCopy {
    pub def_va: u64,
    pub target_va: u64,
}

/// Side-structure describing what the simplification pass achieved. Returned
/// alongside the pruned [`SsaFunction`] so callers (and agents) can report the
/// effect without re-scanning the IR.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SsaAnalysis {
    /// Total SSA ops before simplification (sum across all blocks).
    pub op_count_before: usize,
    /// Total SSA ops after simplification.
    pub op_count_after: usize,
    /// Number of `Copy` ops collapsed into an aliased SSA value (and dropped).
    pub copies_propagated: usize,
    /// Number of SSA definitions resolved to a constant value.
    pub constants_propagated: usize,
    /// Number of trivial phis collapsed (aliased and dropped).
    pub phis_collapsed: usize,
    /// Number of *other* dead pure value-def ops removed by DCE.
    pub dead_ops_removed: usize,
    /// Definitions proven constant (defining VA + value). Feed for the
    /// `apply_ssa_suggestions` bridge: each becomes a `= 0xV (uintN)` comment.
    pub constants: Vec<SsaConstant>,
    /// Alias chains collapsed by copy propagation.
    pub copies: Vec<SsaCopy>,
}

/// A resolved phi argument: either an aliased variable or a concrete constant.
#[derive(Clone, PartialEq, Eq)]
enum Resolved {
    Var(SsaVar),
    Const((u64, u32)),
}

/// Union-find root lookup with path compression.
fn find(parent: &mut HashMap<SsaVar, SsaVar>, v: SsaVar) -> SsaVar {
    match parent.get(&v).cloned() {
        Some(next) if next != v => {
            let root = find(parent, next);
            parent.insert(v, root.clone());
            root
        }
        _ => v,
    }
}

/// Resolve a `SsaVar` to its canonical representative, falling back to a tracked
/// constant value if the representative is known constant.
fn resolve_var(
    parent: &mut HashMap<SsaVar, SsaVar>,
    const_val: &HashMap<SsaVar, (u64, u32)>,
    v: SsaVar,
) -> Resolved {
    let f = find(parent, v.clone());
    if let Some(c) = const_val.get(&f).or_else(|| const_val.get(&v)) {
        return Resolved::Const(*c);
    }
    Resolved::Var(f)
}

/// Whether an SSA op is a side effect and therefore never removable.
fn is_side_effect(op: &SsaOp) -> bool {
    match &op.kind {
        SsaOpKind::Phi(_) => false,
        SsaOpKind::Pcode(p) => matches!(
            p,
            PcodeOp::Store { .. }
                | PcodeOp::Load { .. }
                | PcodeOp::Branch { .. }
                | PcodeOp::CBranch { .. }
                | PcodeOp::BranchInd { .. }
                | PcodeOp::Call { .. }
                | PcodeOp::CallInd { .. }
                | PcodeOp::Return { .. }
                | PcodeOp::CallOther { .. }
        ),
    }
}

/// Simplify `ssa`, returning a pruned clone plus an [`SsaAnalysis`] report.
///
/// The raw `ssa` is never mutated.
pub fn simplify(ssa: &SsaFunction) -> (SsaFunction, SsaAnalysis) {
    let mut analysis = SsaAnalysis::default();
    let op_count_before: usize = ssa.blocks.iter().map(|b| b.ops.len()).sum();
    analysis.op_count_before = op_count_before;

    // Flatten all ops, remembering each op's original block for reassembly.
    let mut work: Vec<SsaOp> = Vec::new();
    let mut block_of: Vec<u32> = Vec::new();
    for (bi, block) in ssa.blocks.iter().enumerate() {
        for op in &block.ops {
            work.push(op.clone());
            block_of.push(bi as u32);
        }
    }

    // Each SsaVar is defined exactly once; map it to its defining op index.
    let mut def_to_idx: HashMap<SsaVar, usize> = HashMap::new();
    for (i, op) in work.iter().enumerate() {
        if let Some(d) = &op.def {
            def_to_idx.insert(d.clone(), i);
        }
    }

    let mut parent: HashMap<SsaVar, SsaVar> = HashMap::new();
    let mut const_val: HashMap<SsaVar, (u64, u32)> = HashMap::new();

    // --- Pass 1: copy + constant analysis (forward over the flat op stream). ---
    for op in &work {
        if let SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) = &op.kind
            && let Some(def) = &op.def
        {
            match input.space {
                AddressSpaceId::Const => {
                    const_val.insert(def.clone(), (input.offset, input.size));
                    analysis.constants_propagated += 1;
                    analysis.constants.push(SsaConstant {
                        va: op.va,
                        value: input.offset,
                        size: input.size,
                    });
                }
                _ => {
                    // A Copy has one input. If lowering represented that input
                    // as storage, it is this op's reaching definition whether it
                    // came from a register or an instruction-scoped Unique
                    // temporary. Constants were handled above; unsupported
                    // input spaces have no SSA use and naturally do not alias.
                    if let Some(target) = op.uses.first() {
                        let rd = find(&mut parent, def.clone());
                        let rt = find(&mut parent, target.clone());
                        if rd != rt {
                            parent.insert(rd, rt);
                            analysis.copies_propagated += 1;
                            let target_va = def_to_idx
                                .get(target)
                                .and_then(|&i| work.get(i).map(|o| o.va))
                                .unwrap_or(0);
                            analysis.copies.push(SsaCopy {
                                def_va: op.va,
                                target_va,
                            });
                        }
                    }
                }
            }
        }

        // Stage 1 (parameter-home echo) is applied at *emit* time (suppress
        // home Stores; name stack slots). Aliasing them in the SSA union-find
        // was observed to drop live arithmetic feeding the ABI return (RAX).
    }

    // --- Pass 2: trivial-phi collapse (fixpoint over phis). ---
    let mut changed = true;
    let mut guard = 0;
    while changed && guard <= work.len() {
        changed = false;
        guard += 1;
        for op in &work {
            let phi = match &op.kind {
                SsaOpKind::Phi(phi) => phi,
                _ => continue,
            };
            if phi.args.is_empty() {
                continue;
            }
            let mut resolved: Option<Resolved> = None;
            let mut all_same = true;
            for arg in &phi.args {
                match arg {
                    Some(v) => {
                        let rv = resolve_var(&mut parent, &const_val, v.clone());
                        match &resolved {
                            Some(r) if *r == rv => {}
                            Some(_) => {
                                all_same = false;
                                break;
                            }
                            None => resolved = Some(rv),
                        }
                    }
                    None => {
                        // Undefined along this predecessor: not trivial.
                        all_same = false;
                        break;
                    }
                }
            }
            if let Some(r) = resolved
                && all_same
            {
                match r {
                    Resolved::Var(t) => {
                        let rd = find(&mut parent, phi.out.clone());
                        let rt = find(&mut parent, t.clone());
                        if rd != rt {
                            parent.insert(rd, rt);
                            analysis.phis_collapsed += 1;
                            changed = true;
                        }
                    }
                    Resolved::Const(c) => {
                        // Constant trivial phi: record value; the op stays
                        // because we cannot edit the frozen P-code operand.
                        const_val.insert(phi.out.clone(), c);
                    }
                }
            }
        }
    }

    // --- Pass 3: re-point every use / phi arg to its alias root. ---
    for op in &mut work {
        for u in op.uses.iter_mut() {
            *u = find(&mut parent, u.clone());
        }
        if let SsaOpKind::Phi(phi) = &mut op.kind {
            for v in phi.args.iter_mut().filter_map(Option::as_mut) {
                *v = find(&mut parent, v.clone());
            }
        }
    }

    // --- Pass 4: conservative dead-code elimination. ---
    let mut live: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = Vec::new();
    for (i, op) in work.iter().enumerate() {
        if is_side_effect(op) && live.insert(i) {
            stack.push(i);
        }
    }
    // ABI live-outs: integer return value is in RAX (SLEIGH offset 0). Return's
    // p-code only lists the return *address*, so without this seed, IntAdd/Copy
    // into EAX/RAX look dead and are wrongly DCE'd (breaks `return a + b`).
    //
    // Seed every RAX def. When a RAX def was copy-propagated to a non-RAX root
    // (e.g. `sete cl; mov eax,ecx` aliases RAX→ECX→ZF), also seed the root so
    // flag/cmp producers stay live. Previously aliased RAX defs were skipped
    // entirely, which deleted SEH filter cmp/sete chains.
    let has_return = work
        .iter()
        .any(|op| matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })));
    if has_return {
        for (i, op) in work.iter().enumerate() {
            if let Some(def) = &op.def
                && matches!(def.location, Location::Register { base_offset: 0 })
            {
                // Always keep the RAX materialization for emit's ABI return scan.
                if live.insert(i) {
                    stack.push(i);
                }
                let root = find(&mut parent, def.clone());
                if root != *def
                    && !matches!(root.location, Location::Register { base_offset: 0 })
                    && let Some(&di) = def_to_idx.get(&root)
                    && live.insert(di)
                {
                    stack.push(di);
                }
            }
        }
    }
    while let Some(i) = stack.pop() {
        let op = &work[i];
        for u in &op.uses {
            if let Some(&di) = def_to_idx.get(u)
                && live.insert(di)
            {
                stack.push(di);
            }
        }
        if let SsaOpKind::Phi(phi) = &op.kind {
            for v in phi.args.iter().flatten() {
                if let Some(&di) = def_to_idx.get(v)
                    && live.insert(di)
                {
                    stack.push(di);
                }
            }
        }
    }

    // A pure op whose def (after re-pointing) is among its own re-pointed uses is
    // a degenerate self-cycle (e.g. `B = B`); it contributes nothing and is dead.
    // Exception: `Copy` across registers (e.g. `mov eax, ecx` after `add ecx,eax`)
    // becomes `RAX_n → ECX_m` under union-find; treating that as a self-cycle
    // drops the ABI materialization into RAX and kills the visible return value.
    for (i, op) in work.iter().enumerate() {
        if is_side_effect(op) {
            continue;
        }
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Copy { .. })) {
            continue;
        }
        if let Some(def) = &op.def {
            let d = find(&mut parent, def.clone());
            let self_ref = op.uses.contains(&d)
                || matches!(&op.kind, SsaOpKind::Phi(phi) if phi.args.iter().flatten().any(|a| *a == d));
            if self_ref {
                live.remove(&i);
            }
        }
    }

    // --- Reassemble blocks in original order, keeping only live ops. ---
    let mut out_blocks: Vec<SsaBlock> = Vec::with_capacity(ssa.blocks.len());
    for (bi, block) in ssa.blocks.iter().enumerate() {
        let mut ops: Vec<SsaOp> = Vec::new();
        for (i, op) in work.iter().enumerate() {
            if block_of[i] == bi as u32 && live.contains(&i) {
                ops.push(op.clone());
            }
        }
        out_blocks.push(SsaBlock {
            id: bi as u32,
            entry_va: block.entry_va,
            ops,
            predecessor_ids: block.predecessor_ids.clone(),
            successor_ids: block.successor_ids.clone(),
        });
    }

    let op_count_after: usize = out_blocks.iter().map(|b| b.ops.len()).sum();
    analysis.op_count_after = op_count_after;
    // Removed ops = alias copies + collapsed phis + other dead pure ops.
    let removed = op_count_before.saturating_sub(op_count_after);
    analysis.dead_ops_removed = removed
        .saturating_sub(analysis.copies_propagated)
        .saturating_sub(analysis.phis_collapsed);

    let out = SsaFunction {
        entry_va: ssa.entry_va,
        bitness: ssa.bitness,
        blocks: out_blocks,
        image_base: ssa.image_base,
    };
    (out, analysis)
}

/// Helper used by tests: build a single-block SSA function from raw ops.
#[cfg(test)]
pub(crate) fn build_test_ssa(ops: Vec<SsaOp>) -> SsaFunction {
    let block = SsaBlock {
        id: 0,
        entry_va: 0x1000,
        ops,
        predecessor_ids: vec![],
        successor_ids: vec![],
    };
    SsaFunction {
        entry_va: 0x1000,
        bitness: 64,
        blocks: vec![block],
        image_base: 0x140000000,
    }
}

#[cfg(test)]
use rsleigh_api::Varnode;

#[cfg(test)]
use super::PhiNode;

/// Helper used by tests: construct a `Copy` SSA op whose def is the register at
/// `out_offset` with `out_version`, sourcing `input`.
#[cfg(test)]
pub(crate) fn copy_op(out_offset: u64, out_version: u32, input: Varnode) -> SsaOp {
    let uses = if input.space == AddressSpaceId::Register {
        vec![SsaVar {
            location: Location::Register {
                base_offset: input.offset,
            },
            // Use version 1 to mirror a renamed reaching def.
            version: 1,
        }]
    } else {
        vec![]
    };
    SsaOp {
        va: 0x1000,
        kind: SsaOpKind::Pcode(PcodeOp::Copy {
            out: Varnode::register(out_offset, 8),
            input,
        }),
        def: Some(SsaVar {
            location: Location::Register {
                base_offset: out_offset,
            },
            version: out_version,
        }),
        uses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::verify_no_uninitialized_register_uses;

    fn reg(offset: u64, version: u32) -> SsaVar {
        SsaVar {
            location: Location::Register {
                base_offset: offset,
            },
            version,
        }
    }

    #[test]
    fn copy_chain_collapses() {
        // B = A;  C = B;   (both plain register copies)
        let b_def = reg(0x08, 2);
        let c_def = reg(0x10, 3);
        let ops = vec![
            copy_op(0x08, 2, Varnode::register(0x00, 8)),
            copy_op(0x10, 3, Varnode::register(0x08, 8)),
        ];
        let _ = (b_def, c_def);
        let ssa = build_test_ssa(ops);
        let (opt, analysis) = simplify(&ssa);
        // The two copy ops are aliases and become dead (nothing uses C).
        assert_eq!(analysis.op_count_before, 2);
        assert_eq!(
            analysis.op_count_after, 0,
            "copy chain must be fully removed"
        );
        assert_eq!(analysis.copies_propagated, 2);
        assert!(verify_no_uninitialized_register_uses(&opt));
    }

    #[test]
    fn const_reaches_live_use() {
        // B = const 5;  a live Return reads B, so the const copy survives.
        let b_def = reg(0x08, 2);
        let const_copy = copy_op(0x08, 2, Varnode::constant(5, 4));

        let ret = SsaOp {
            va: 0x1004,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x08, 8),
            }),
            def: None,
            uses: vec![b_def.clone()],
        };
        let ssa = build_test_ssa(vec![const_copy, ret]);
        let (opt, analysis) = simplify(&ssa);
        assert_eq!(
            analysis.op_count_after, 2,
            "const copy feeding Return stays"
        );
        assert_eq!(analysis.constants_propagated, 1);
        assert!(verify_no_uninitialized_register_uses(&opt));
    }

    #[test]
    fn trivial_phi_collapses() {
        // P = phi(A, A, A); live use of P via Return -> phi collapsed, Return kept.
        let a = reg(0x00, 1);
        let p_def = reg(0x18, 4);
        let phi = SsaOp {
            va: 0,
            kind: SsaOpKind::Phi(PhiNode {
                out: p_def.clone(),
                args: vec![Some(a.clone()), Some(a.clone()), Some(a.clone())],
            }),
            def: Some(p_def.clone()),
            uses: vec![],
        };
        let ret = SsaOp {
            va: 0x1004,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x18, 8),
            }),
            def: None,
            uses: vec![p_def.clone()],
        };
        let ssa = build_test_ssa(vec![phi, ret]);
        let (opt, analysis) = simplify(&ssa);
        assert_eq!(analysis.phis_collapsed, 1, "trivial phi must collapse");
        assert_eq!(analysis.op_count_after, 1, "only the Return should remain");
        assert!(verify_no_uninitialized_register_uses(&opt));
    }

    #[test]
    fn side_effect_op_kept() {
        // A store is always kept even if its value register is uninteresting.
        let store = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x20, 8),
                val: Varnode::register(0x00, 4),
            }),
            def: Some(SsaVar {
                location: Location::RawRam,
                version: 1,
            }),
            uses: vec![reg(0x00, 1), reg(0x20, 1)],
        };
        let ssa = build_test_ssa(vec![store]);
        let (opt, analysis) = simplify(&ssa);
        assert_eq!(analysis.op_count_after, 1, "store must be kept");
        assert!(verify_no_uninitialized_register_uses(&opt));
    }

    #[test]
    fn op_count_never_increases() {
        let add = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                out: Varnode::register(0x00, 4),
                left: Varnode::register(0x08, 4),
                right: Varnode::register(0x10, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1), reg(0x10, 1)],
        };
        let ret = SsaOp {
            va: 0x1004,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let ssa = build_test_ssa(vec![add, ret]);
        let (opt, analysis) = simplify(&ssa);
        assert!(analysis.op_count_after <= analysis.op_count_before);
        assert_eq!(analysis.op_count_after, 2);
        assert!(verify_no_uninitialized_register_uses(&opt));
    }

    #[test]
    fn copy_propagation_follows_instruction_scoped_unique_chain() {
        let instruction_va = 0x1400_0010;
        let t0 = SsaVar {
            location: Location::Unique {
                instruction_va,
                offset: 0x40,
                size: 8,
            },
            version: 1,
        };
        let t1 = SsaVar {
            location: Location::Unique {
                instruction_va,
                offset: 0x48,
                size: 8,
            },
            version: 1,
        };
        let rax = reg(0x00, 2);
        let rcx = reg(0x08, 1);

        // t0 = rcx; t1 = t0; rax = t1; return rax. The frozen P-code is
        // retained, but the SSA use chain should collapse through both Unique
        // locations back to the live-in RCX definition.
        let copies = vec![
            SsaOp {
                va: instruction_va,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    out: Varnode::unique(0x40, 8),
                    input: Varnode::register(0x08, 8),
                }),
                def: Some(t0.clone()),
                uses: vec![rcx.clone()],
            },
            SsaOp {
                va: instruction_va,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    out: Varnode::unique(0x48, 8),
                    input: Varnode::unique(0x40, 8),
                }),
                def: Some(t1.clone()),
                uses: vec![t0],
            },
            SsaOp {
                va: instruction_va,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    out: Varnode::register(0x00, 8),
                    input: Varnode::unique(0x48, 8),
                }),
                def: Some(rax.clone()),
                uses: vec![t1],
            },
            SsaOp {
                va: instruction_va,
                kind: SsaOpKind::Pcode(PcodeOp::Return {
                    dest: Varnode::register(0x00, 8),
                }),
                def: None,
                uses: vec![rax],
            },
        ];

        let (optimized, analysis) = simplify(&build_test_ssa(copies));
        assert_eq!(analysis.copies_propagated, 3);
        // Last RAX materialization stays live (ABI return); Unique chain may fold.
        assert!(
            analysis.op_count_after >= 1 && analysis.op_count_after <= 3,
            "copies collapse toward return, got {}",
            analysis.op_count_after
        );
        let has_return = optimized.blocks[0]
            .ops
            .iter()
            .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })));
        assert!(has_return, "return must remain");
        let _ = rcx;
    }

    #[test]
    fn sete_cmp_chain_survives_dce_as_return() {
        // Model: cmp eax, imm → ZF; sete al → RAX; return.
        // Previously DCE dropped ZF when RAX was aliased to the flag.
        let eax_in = reg(0x00, 1);
        let zf = SsaVar {
            location: Location::Register { base_offset: 518 },
            version: 2,
        };
        let rax_out = reg(0x00, 2);
        let tmp = SsaVar {
            location: Location::Unique {
                instruction_va: 0x1000,
                offset: 0x99,
                size: 4,
            },
            version: 1,
        };
        let ops = vec![
            SsaOp {
                va: 0x1000,
                kind: SsaOpKind::Pcode(PcodeOp::IntSub {
                    out: Varnode::unique(0x99, 4),
                    left: Varnode::register(0x00, 4),
                    right: Varnode::constant(0xc000_0005, 4),
                }),
                def: Some(tmp.clone()),
                uses: vec![eax_in.clone()],
            },
            SsaOp {
                va: 0x1000,
                kind: SsaOpKind::Pcode(PcodeOp::IntEq {
                    out: Varnode::register(518, 1),
                    left: Varnode::unique(0x99, 4),
                    right: Varnode::constant(0, 4),
                }),
                def: Some(zf.clone()),
                uses: vec![tmp],
            },
            SsaOp {
                va: 0x1004,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    out: Varnode::register(0x00, 1),
                    input: Varnode::register(518, 1),
                }),
                def: Some(rax_out.clone()),
                uses: vec![zf],
            },
            SsaOp {
                va: 0x1005,
                kind: SsaOpKind::Pcode(PcodeOp::Return {
                    dest: Varnode::register(648, 8),
                }),
                def: None,
                uses: vec![],
            },
        ];
        let (optimized, _) = simplify(&build_test_ssa(ops));
        let kinds: Vec<&str> = optimized.blocks[0]
            .ops
            .iter()
            .map(|o| match &o.kind {
                SsaOpKind::Pcode(PcodeOp::IntSub { .. }) => "sub",
                SsaOpKind::Pcode(PcodeOp::IntEq { .. }) => "eq",
                SsaOpKind::Pcode(PcodeOp::Copy { .. }) => "copy",
                SsaOpKind::Pcode(PcodeOp::Return { .. }) => "ret",
                _ => "other",
            })
            .collect();
        assert!(
            kinds.contains(&"sub") && kinds.contains(&"eq"),
            "cmp/sete chain must remain live for return, got {kinds:?}"
        );
        assert!(kinds.contains(&"ret"));
    }
}
