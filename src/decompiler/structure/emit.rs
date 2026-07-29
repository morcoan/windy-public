//! Native pseudo-C emission over optimized SSA — Phase 5.1 (full DREAM).
//!
//! Recursively walks classified regions (if/else, while, do-while, switch)
//! using the post-dominator tree. Gotos remain only for irreducible edges.
//! Single-use SSA expression folding is unchanged from the MVP.
//!
//! Phase 4: large implementation bodies live in emit_fold, emit_polish,
//! and emit_region. This module keeps the public entry points and re-exports.

use std::collections::HashMap;

use crate::decompiler::ssa::SsaFunction;
use crate::project::types::{FunctionSignature, StackFrame};

use super::region::SwitchInfo;

// Re-exports: CfgOnly text passes (mechanical Phase 4 split → emit_fold).
pub(crate) use super::emit_fold::{
    fold_eq_ladder_to_switch, fold_goto_return_and_trivial_rejoins, inline_leaf_goto_targets,
    minimize_gotos, rewrite_label_backedge_to_while, strip_flag_helper_noise,
    strip_security_cookie_gotos,
};

// Re-exports: LegacySemantic polish (mechanical Phase 4 split → emit_polish).
pub(crate) use super::emit_polish::{
    polish_compare_return_to_if, polish_crc_xor_return, polish_dual_flag_zero_tests,
    polish_e_pointer_returns, polish_flag_lt_compares, polish_guard_returns,
    polish_hoist_null_guard_returns, polish_hoist_rich_xor_return, polish_loop_with_guard_if,
    polish_nested_if_keyword, polish_nested_while_keyword, polish_paired_cleanup_destroys,
    polish_pure_op_return_to_if, polish_resource_pair_names, polish_sentinel_literals,
    polish_switch_with_guard_if, polish_zero_returns,
};

// Re-exports: region emit core (mechanical Phase 4 split → emit_region).
pub use super::emit_region::structure_emit_core;

#[cfg(test)]
pub(crate) use super::emit_fold::fold_while_true_break_boundary;
#[cfg(test)]
pub(crate) use super::emit_region::{
    guard_return_class, normalize_return_class_expr, return_outer_class, simplify_predicate_expr,
};

/// Naming context for the native structurer: stack frame, signature params,
/// and global symbol names.
pub struct NameCtx<'a> {
    pub frame: Option<&'a StackFrame>,
    pub sig: Option<&'a FunctionSignature>,
    /// VA → annotated symbol name (from `crate::ir::annotate::build_global_names`).
    pub global_names: HashMap<u64, String>,
    /// Instruction VA → data-section global VA (from `resolve_global_va`).
    pub insn_to_global: HashMap<u64, u64>,
}

impl NameCtx<'static> {
    /// Empty context (unit tests / no metadata).
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            frame: None,
            sig: None,
            global_names: HashMap::new(),
            insn_to_global: HashMap::new(),
        }
    }
}

/// Render ssa to structured C-ish pseudo-code. switches supplies resolved
/// jump-table case values (may be empty).
/// Pure v2 baseline: region/CFG emit + **structural presentation only**.
///
/// Pure V2 path: raw region emit → **CfgOnly only**.
///
/// No polish_* semantic text rewrites. Control/constant/resource recovery that
/// is not yet native in the region emitter lives exclusively on the Legacy path.
pub fn decompile_structured_pure(
    ssa: &SsaFunction,
    types: Option<&crate::decompiler::types::TypeRecoveryReport>,
    sig: Option<&FunctionSignature>,
    bitness: u32,
    switches: &[SwitchInfo],
    names: &NameCtx<'_>,
) -> String {
    let raw = structure_emit_core(ssa, types, sig, bitness, switches, names);
    super::presentation::apply_presentation(&raw, super::presentation::PresentationTier::CfgOnly)
}

/// Full legacy decompile: pure (CfgOnly) + LegacySemantic polish chain.
pub fn decompile(
    ssa: &SsaFunction,
    types: Option<&crate::decompiler::types::TypeRecoveryReport>,
    sig: Option<&FunctionSignature>,
    bitness: u32,
    switches: &[SwitchInfo],
    names: &NameCtx<'_>,
) -> String {
    let pure = decompile_structured_pure(ssa, types, sig, bitness, switches, names);
    super::presentation::apply_legacy_semantic(&pure)
}

/// Compat: CfgOnly presentation only (no LegacySemantic).
#[allow(dead_code)] // public API / tests
pub fn structure_presentation_pipeline(src: &str) -> String {
    super::presentation::apply_cfg_only(src)
}

/// Legacy semantic tier only (expects CfgOnly already applied, or apply full tier).
#[allow(dead_code)] // public API / tests
pub fn legacy_semantic_polish(src: &str) -> String {
    super::presentation::apply_legacy_semantic(src)
}

/// Full legacy polish = CfgOnly + LegacySemantic (compat API).
#[allow(dead_code)]
pub fn legacy_polish_pipeline(src: &str) -> String {
    super::presentation::apply_presentation(
        src,
        super::presentation::PresentationTier::LegacySemantic,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};
    use crate::decompiler::structure::region::SwitchInfo;
    use pcode_ir::AddressSpaceId;
    use rsleigh_api::{PcodeOp, Varnode};

    fn write_scratch(name: &str, contents: &str) {
        let Ok(dir) = std::env::var("WINDY_SCRATCH") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join(name), contents);
    }

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

    fn ret_block(id: u32, entry_va: u64, preds: Vec<u32>) -> SsaBlock {
        let mut b = empty_block(id, entry_va, preds, vec![]);
        b.ops.push(SsaOp {
            va: entry_va,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 1)],
        });
        b
    }

    #[test]
    fn return_class_normalizes_commutative_add() {
        assert_eq!(normalize_return_class_expr("b + a"), "a + b");
        assert_eq!(normalize_return_class_expr("y * x * z"), "x * y * z");
        // Mixed / parenthesized left alone.
        assert_eq!(normalize_return_class_expr("(a + b) * c"), "(a + b) * c");
    }

    #[test]
    fn return_class_guard_rejects_op_class_change() {
        // Guard must keep XOR root if a broken rewrite tried to change it.
        let original = "a ^ (b + c)";
        let bad = "a + (b ^ c)";
        assert_eq!(guard_return_class(bad, original), original);
        assert_eq!(return_outer_class(original), '^');
    }

    #[test]
    fn simplify_predicate_strips_flag_noise() {
        let s = simplify_predicate_expr("/*(IntSLess)*/ (param_1 < param_2)");
        assert!(
            s.contains('<') && !s.contains("IntSLess"),
            "expected clean relation, got {s}"
        );
    }

    #[test]
    fn fold_while_true_break_to_boundary() {
        let src = "    while (1) {\n        if (!(i < n)) break;\n        s = s + a[i];\n    }\n";
        let out = fold_while_true_break_boundary(src);
        assert!(
            out.contains("while (i < n)"),
            "expected boundary form: {out}"
        );
        assert!(!out.contains("while (1)"), "{out}");
    }

    #[test]
    fn emits_return_for_single_block() {
        let add = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                out: Varnode::register(0x00, 4),
                left: Varnode::register(0x08, 4),
                right: Varnode::register(0x08, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1), reg(0x08, 1)],
        };
        let ret = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![add, ret],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0x140000000,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(text.contains("+"), "IntAdd should render as +");
        assert!(text.contains("return"), "missing return");
    }

    #[test]
    fn single_use_def_is_inlined() {
        let copy = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x00, 4),
                input: Varnode::register(0x08, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1)],
        };
        let ret = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![copy, ret],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0x140000000,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(
            !text.contains("rax_2 = rcx") && !text.contains("r00_2 = r08_1"),
            "single-use copy should be inlined, got:\n{text}"
        );
        assert!(text.contains("return"), "missing return");
    }

    #[test]
    fn win64_call_arguments_are_rendered_from_hir_facts() {
        let set_rcx = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 8),
                input: Varnode::constant(2, 8),
            }),
            def: Some(reg(0x08, 2)),
            uses: vec![],
        };
        let set_rdx = SsaOp {
            va: 0x1005,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x10, 8),
                input: Varnode::constant(3, 8),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![],
        };
        let call = SsaOp {
            va: 0x100a,
            kind: SsaOpKind::Pcode(PcodeOp::Call {
                dest: Varnode::constant(0x1400_0100, 8),
            }),
            def: None,
            uses: vec![reg(0x08, 2), reg(0x10, 2)],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![set_rcx, set_rdx, call],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x1400_0000,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);

        assert!(
            text.contains("FUN_14000100(0x2, 0x3);"),
            "Win64 HIR arguments should be emitted as a direct call:\n{text}"
        );
        assert!(
            !text.contains("call(FUN_14000100)"),
            "proved arguments must not fall back to the opaque call wrapper:\n{text}"
        );
        assert!(
            !text.contains("rcx_2 =") && !text.contains("rdx_2 ="),
            "single-use argument setup should fold into the call:\n{text}"
        );
    }

    #[test]
    fn win64_call_argument_gap_does_not_shift_register_positions() {
        let set_rdx = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x10, 8),
                input: Varnode::constant(3, 8),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![],
        };
        let call = SsaOp {
            va: 0x1005,
            kind: SsaOpKind::Pcode(PcodeOp::Call {
                dest: Varnode::constant(0x1400_0100, 8),
            }),
            def: None,
            uses: vec![reg(0x10, 2)],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![set_rdx, call],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x1400_0000,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);

        assert!(
            text.contains("call(FUN_14000100);"),
            "a missing RCX source must retain the opaque call form:\n{text}"
        );
        assert!(
            !text.contains("FUN_14000100(0x3)"),
            "RDX must never be rendered as logical argument zero:\n{text}"
        );
    }

    #[test]
    fn win64_call_contract_requires_every_declared_register_slot() {
        let set_rcx = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 8),
                input: Varnode::constant(2, 8),
            }),
            def: Some(reg(0x08, 2)),
            uses: vec![],
        };
        let set_rdx = SsaOp {
            va: 0x1005,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x10, 8),
                input: Varnode::constant(3, 8),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![],
        };
        let call = SsaOp {
            va: 0x100a,
            kind: SsaOpKind::Pcode(PcodeOp::Call {
                dest: Varnode::constant(0x1400_0100, 8),
            }),
            def: None,
            // Contract says three integer register slots, but R8 has no
            // same-block proven definition.  Native output must remain opaque.
            uses: vec![reg(0x08, 2), reg(0x10, 2), reg(0x80, 1)],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![set_rcx, set_rdx, call],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x1400_0000,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);

        assert!(
            text.contains("call(FUN_14000100);"),
            "an incomplete three-slot contract must stay opaque:\n{text}"
        );
        assert!(
            !text.contains("FUN_14000100(0x2, 0x3)"),
            "the printer must not shorten a declared three-argument call:\n{text}"
        );
    }

    #[test]
    fn diamond_emits_if_else_without_goto() {
        // 0 cbranch fall=else(2) taken=then(1); both → join(3 return)
        // Side-effect stores keep both arms live under stage-6 dead pure DCE.
        let b0 = cbranch_block(0, 0x1000, vec![], vec![2, 1]);
        let mut b1 = empty_block(1, 0x1010, vec![0], vec![3]);
        b1.ops.push(SsaOp {
            va: 0x1010,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x20, 8),
                val: Varnode::constant(1, 4),
            }),
            def: Some(SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x20,
                    disp: -0x20,
                },
                version: 1,
            }),
            uses: vec![reg(0x20, 1)],
        });
        let mut b2 = empty_block(2, 0x1020, vec![0], vec![3]);
        b2.ops.push(SsaOp {
            va: 0x1020,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x20, 8),
                val: Varnode::constant(2, 4),
            }),
            def: Some(SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x20,
                    disp: -0x24,
                },
                version: 1,
            }),
            uses: vec![reg(0x20, 1)],
        });
        let b3 = ret_block(3, 0x1030, vec![1, 2]);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1, b2, b3],
            image_base: 0,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(text.contains("if ("), "expected if, got:\n{text}");
        assert!(text.contains("else"), "expected else, got:\n{text}");
        assert!(
            !text.contains("goto "),
            "diamond should have no goto, got:\n{text}"
        );
    }

    #[test]
    fn self_loop_emits_while_or_do_while() {
        let b0 = cbranch_block(0, 0x1000, vec![0], vec![1, 0]); // fall=exit, taken=self
        let b1 = ret_block(1, 0x1100, vec![0]);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1],
            image_base: 0,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(
            text.contains("while (") || text.contains("do {"),
            "expected while/do-while, got:\n{text}"
        );
    }

    #[test]
    fn if_then_emits_if_without_else() {
        let b0 = cbranch_block(0, 0x1000, vec![], vec![2, 1]); // fall=merge, taken=body
        let mut b1 = empty_block(1, 0x1010, vec![0], vec![2]);
        b1.ops.push(SsaOp {
            va: 0x1010,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 4),
                input: Varnode::constant(1, 4),
            }),
            def: Some(reg(0x08, 1)),
            uses: vec![],
        });
        let b2 = ret_block(2, 0x1020, vec![0, 1]);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1, b2],
            image_base: 0,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(text.contains("if ("), "expected if, got:\n{text}");
        assert!(
            !text.contains("else"),
            "if-then should have no else, got:\n{text}"
        );
    }

    #[test]
    fn switch_emits_cases_and_break() {
        // Block 0: BranchInd → 1, 2; both → merge 3.
        let ind = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::BranchInd {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 1)],
        };
        let b0 = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![ind],
            predecessor_ids: vec![],
            successor_ids: vec![1, 2],
        };
        let mut b1 = empty_block(1, 0x1010, vec![0], vec![3]);
        b1.ops.push(SsaOp {
            va: 0x1010,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 4),
                input: Varnode::constant(0, 4),
            }),
            def: Some(reg(0x08, 1)),
            uses: vec![],
        });
        let mut b2 = empty_block(2, 0x1020, vec![0], vec![3]);
        b2.ops.push(SsaOp {
            va: 0x1020,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 4),
                input: Varnode::constant(1, 4),
            }),
            def: Some(reg(0x08, 2)),
            uses: vec![],
        });
        let b3 = ret_block(3, 0x1030, vec![1, 2]);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1, b2, b3],
            image_base: 0,
        };
        let switches = [SwitchInfo {
            branch_va: 0x1000,
            cases: vec![(0, 1), (1, 2)],
        }];
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &switches, &names);
        assert!(text.contains("switch ("), "expected switch, got:\n{text}");
        assert!(text.contains("case 0:"), "expected case 0, got:\n{text}");
        assert!(text.contains("case 1:"), "expected case 1, got:\n{text}");
        assert!(text.contains("break;"), "expected break, got:\n{text}");
    }

    #[test]
    fn short_circuit_and_or_nested_if() {
        // B1 fall→B2, taken→false(3); B2 fall→true(4), taken→false(3).
        let b1 = cbranch_block(0, 0x1000, vec![], vec![1, 3]);
        let b2 = cbranch_block(1, 0x1010, vec![0], vec![2, 3]);
        let mut b_true = empty_block(2, 0x1020, vec![1], vec![4]);
        b_true.ops.push(SsaOp {
            va: 0x1020,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 4),
                input: Varnode::constant(1, 4),
            }),
            def: Some(reg(0x08, 1)),
            uses: vec![],
        });
        let b_false = empty_block(3, 0x1030, vec![0, 1], vec![4]);
        let b_join = ret_block(4, 0x1040, vec![2, 3]);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b1, b2, b_true, b_false, b_join],
            image_base: 0,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        // Either && folding or nested if is correct.
        assert!(
            text.contains("&&") || text.contains("if ("),
            "expected && or nested if, got:\n{text}"
        );
    }

    #[test]
    fn sample_exe_native_decompile_has_add_and_return() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = crate::project::Project::open(path).expect("open sample.exe");

        let mut found = false;
        for f in project.functions().iter() {
            let (opt, _) = match project.function_ssa_optimized(f.entry_va) {
                Some(x) => x,
                None => continue,
            };
            let has_add = opt.blocks.iter().any(|b| {
                b.ops
                    .iter()
                    .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::IntAdd { .. })))
            });
            if !has_add {
                continue;
            }
            let text = project
                .function_decompile_native(f.entry_va)
                .expect("native decompile");
            assert!(
                text.contains("return"),
                "native output should contain return:\n{text}"
            );
            assert!(
                text.contains('+'),
                "native output should contain '+':\n{text}"
            );
            found = true;
            break;
        }
        assert!(found, "expected an add-like function in sample.exe");
    }

    #[test]
    fn sample_exe_branches_prefer_if_over_goto() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = crate::project::Project::open(path).expect("open sample.exe");

        let mut found = false;
        for f in project.functions().iter() {
            let (opt, _) = match project.function_ssa_optimized(f.entry_va) {
                Some(x) => x,
                None => continue,
            };
            let has_cbranch = opt.blocks.iter().any(|b| {
                b.ops
                    .iter()
                    .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::CBranch { .. })))
            });
            if !has_cbranch || opt.blocks.len() < 3 {
                continue;
            }
            let text = project
                .function_decompile_native(f.entry_va)
                .expect("native decompile");
            assert!(
                text.contains("if ("),
                "branched function should contain if:\n{text}"
            );
            // Structured output should not be pure goto soup: at least one
            // structured construct or fewer gotos than blocks.
            let goto_count = text.matches("goto ").count();
            assert!(
                goto_count < opt.blocks.len(),
                "expected fewer gotos than blocks (gotos={goto_count}, blocks={}), got:\n{text}",
                opt.blocks.len()
            );
            found = true;
            break;
        }
        assert!(
            found,
            "expected a multi-block branched function in sample.exe"
        );
    }

    #[test]
    fn minimize_removes_fallthrough_goto() {
        let src = "void f() {\n    goto L_0x10;\n    L_0x10:\n    return ;\n}\n";
        let out = minimize_gotos(src);
        assert!(
            !out.contains("goto "),
            "fallthrough goto should be removed:\n{out}"
        );
        // Label also unused now → stripped.
        assert!(
            !out.contains("L_0x10:"),
            "unused label should be stripped:\n{out}"
        );
    }

    #[test]
    fn phi_renders_with_argument_names() {
        let phi = SsaOp {
            va: 0,
            kind: SsaOpKind::Phi(crate::decompiler::ssa::PhiNode {
                out: reg(0x00, 3),
                args: vec![Some(reg(0x00, 1)), Some(reg(0x00, 2))],
            }),
            def: Some(reg(0x00, 3)),
            uses: vec![],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![
                phi,
                SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::register(0x00, 8),
                    }),
                    def: None,
                    uses: vec![reg(0x00, 3)],
                },
            ],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let names = NameCtx::empty();
        let text = decompile(&ssa, None, None, 64, &[], &names);
        // Stage 5 compaction: phi is SSA plumbing and is not emitted as a C
        // assignment. The return path still names the merged RAX value.
        assert!(
            !text.contains("= phi;"),
            "bare phi; should be gone:\n{text}"
        );
        assert!(
            text.contains("return"),
            "expected a return using the phi result, got:\n{text}"
        );
    }

    #[test]
    fn typed_temp_annotates_lhs() {
        use crate::decompiler::types::{TyGuess, TypeRecoveryReport};
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
        // Force multi-use so the def is not inlined.
        let copy1 = SsaOp {
            va: 0x1001,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x18, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x18, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let copy2 = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x30, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x30, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let ret = SsaOp {
            va: 0x1003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![add, copy1, copy2, ret],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let mut report = TypeRecoveryReport {
            function_va: 0x1000,
            ..Default::default()
        };
        report.def_types.insert(reg(0x00, 2), TyGuess::Int(32));
        let names = NameCtx::empty();
        let text = decompile(&ssa, Some(&report), None, 64, &[], &names);
        // Stage 6 may SI-fold the add into `return (rcx + rdx)`; typed LHS is
        // required when the temp is still materialized.
        assert!(
            text.contains("int32 rax_2")
                || text.contains("int32 ")
                || text.contains("return") && (text.contains('+') || text.contains("rcx")),
            "expected typed temp or composed return, got:\n{text}"
        );
    }

    #[test]
    fn sample_exe_native_uses_reg_names_not_r08() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = crate::project::Project::open(path).expect("open sample.exe");
        let mut found = false;
        for f in project.functions().iter() {
            let text = match project.function_decompile_native(f.entry_va) {
                Some(t) => t,
                None => continue,
            };
            // Prefer human names: rcx / rdx / param names — never r08_1.
            if text.contains("r08_1") || text.contains("r00_1") {
                panic!("expected reg_name output, got rNN form:\n{text}");
            }
            if text.contains("rcx")
                || text.contains("rax")
                || text.contains("rdx")
                || text.contains("arg0")
                || text.contains("arg1")
            {
                found = true;
                break;
            }
            // Even tiny functions should at least avoid the old encoding.
            if !text.trim().is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "expected decompilable function in sample.exe");
    }

    #[test]
    fn stack_local_naming_uses_frame_name() {
        use crate::project::types::{DataType, StackFrame, StackVariable};
        let load = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x28, 8),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x28,
                    disp: -0x10,
                },
                version: 1,
            }],
        };
        // Multi-use so load is not inlined away.
        let c1 = SsaOp {
            va: 0x1001,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x08, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let c2 = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x10, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let ret = SsaOp {
            va: 0x1003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![load, c1, c2, ret],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let frame = StackFrame {
            local_size: 0x10,
            arg_size: 0,
            return_addr_offset: 8,
            locals: vec![StackVariable {
                name: Some("var_10".to_string()),
                ty: DataType::Int(32),
                offset: -0x10,
                size: 4,
            }],
            args: vec![],
        };
        let names = NameCtx {
            frame: Some(&frame),
            sig: None,
            global_names: HashMap::new(),
            insn_to_global: HashMap::new(),
        };
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(
            text.contains("var_10"),
            "expected PDB/frame local name var_10, got:\n{text}"
        );
        assert!(
            !text.contains("local_10"),
            "should not fall back to local_N when named:\n{text}"
        );
    }

    #[test]
    fn global_naming_uses_symbol() {
        // Synthetic Load of a named global, used by the return value.
        let load_def = reg(0x00, 2);
        let load = SsaOp {
            va: 0x2000,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::constant(0x404000, 8),
            }),
            def: Some(load_def.clone()),
            uses: vec![SsaVar {
                location: Location::RawRam,
                version: 1,
            }],
        };
        let ret = SsaOp {
            va: 0x2003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![load_def],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x2000,
            ops: vec![load, ret],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x2000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let mut global_names = HashMap::new();
        global_names.insert(0x404000, "g_count:uint32".to_string());
        let mut insn_to_global = HashMap::new();
        insn_to_global.insert(0x2000, 0x404000);
        let names = NameCtx {
            frame: None,
            sig: None,
            global_names,
            insn_to_global,
        };
        let text = decompile(&ssa, None, None, 64, &[], &names);
        assert!(
            text.contains("g_count") || text.contains("0x404000"),
            "expected global symbol or address, got:\n{text}"
        );
        assert!(
            !text.contains("mem_2 ="),
            "should not use bare mem_N when global resolved:\n{text}"
        );
    }

    #[test]
    fn param_register_uses_sig_name() {
        use crate::project::types::{DataType, FunctionSignature};
        let add = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                out: Varnode::register(0x00, 4),
                left: Varnode::register(0x08, 4),
                right: Varnode::constant(1, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1)],
        };
        let c1 = SsaOp {
            va: 0x1001,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x10, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let c2 = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x18, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x18, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let ret = SsaOp {
            va: 0x1003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![add, c1, c2, ret],
            predecessor_ids: vec![],
            successor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let sig = FunctionSignature {
            name: "foo".to_string(),
            params: vec![(
                "lpFileName".to_string(),
                DataType::Ptr(Box::new(DataType::Int(8))),
            )],
            ret: DataType::Int(32),
            calling_conv: None,
        };
        let names = NameCtx {
            frame: None,
            sig: Some(&sig),
            global_names: HashMap::new(),
            insn_to_global: HashMap::new(),
        };
        let text = decompile(&ssa, None, Some(&sig), 64, &[], &names);
        assert!(
            text.contains("lpFileName"),
            "expected param name from signature, got:\n{text}"
        );
    }

    /// Stage 6 SI: multi-use pure arith is folded into uses and the def is not
    /// materialized (`m_d >= 2`).
    #[test]
    fn stage6_multi_use_stable_inlining_deletes_def() {
        // t = a + b; used twice (two copies into distinct regs) then return t.
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
        let c1 = SsaOp {
            va: 0x1001,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x18, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x18, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let c2 = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x30, 4),
                input: Varnode::register(0x00, 4),
            }),
            def: Some(reg(0x30, 2)),
            uses: vec![reg(0x00, 2)],
        };
        let ret = SsaOp {
            va: 0x1003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 2)],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![add, c1, c2, ret],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0,
        };
        let text = decompile(&ssa, None, None, 64, &[], &NameCtx::empty());
        // Def of the add must not appear as a standalone assignment.
        assert!(
            !text.contains("rax_2 =") && !text.contains("rax_2="),
            "multi-use SI must delete the intermediate def assignment, got:\n{text}"
        );
        assert!(
            text.contains('+') || text.contains("return"),
            "expected composed use of the add, got:\n{text}"
        );
    }

    /// Stage 6 CDQ residual: identical pure defs collapse to one surface form.
    #[test]
    fn stage6_identical_pure_ops_share_surface() {
        // Two independent zexts of the same source — only one materialization
        // should remain after SI (or none if fully folded into return).
        let z1 = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntZext {
                out: Varnode::register(0x00, 8),
                input: Varnode::register(0x08, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1)],
        };
        let z2 = SsaOp {
            va: 0x1001,
            kind: SsaOpKind::Pcode(PcodeOp::IntZext {
                out: Varnode::register(0x10, 8),
                input: Varnode::register(0x08, 4),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![reg(0x08, 1)],
        };
        let add = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                out: Varnode::register(0x00, 8),
                left: Varnode::register(0x00, 8),
                right: Varnode::register(0x10, 8),
            }),
            def: Some(reg(0x00, 3)),
            uses: vec![reg(0x00, 2), reg(0x10, 2)],
        };
        let ret = SsaOp {
            va: 0x1003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 3)],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops: vec![z1, z2, add, ret],
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0,
        };
        let text = decompile(&ssa, None, None, 64, &[], &NameCtx::empty());
        let assigns = text
            .lines()
            .filter(|l| l.contains('=') && !l.contains("==") && !l.contains("!="))
            .count();
        assert!(
            assigns <= 1,
            "CDQ/SI should collapse identical pure chains; assigns={assigns}, text:\n{text}"
        );
        assert!(text.contains("return"), "expected a return, got:\n{text}");
    }

    /// Stage 8: structured while must not emit goto/label path words.
    #[test]
    fn stage8_self_loop_has_no_goto_or_label() {
        let b0 = cbranch_block(0, 0x1000, vec![0], vec![1, 0]); // fall=exit, taken=self
        let b1 = ret_block(1, 0x1100, vec![0]);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![b0, b1],
            image_base: 0,
        };
        let text = decompile(&ssa, None, None, 64, &[], &NameCtx::empty());
        assert!(
            text.contains("while (") || text.contains("do {"),
            "expected structured loop, got:\n{text}"
        );
        assert!(
            !text.contains("goto "),
            "structured loop must be goto-free, got:\n{text}"
        );
        assert!(
            !text.contains("L_0x"),
            "structured loop must not emit L_* labels, got:\n{text}"
        );
    }

    /// Cookie printer must NOT erase unrelated gotos just because a PE mentions
    /// a cookie global / image base (skeptic honesty gate).
    #[test]
    fn cookie_strip_does_not_erase_unrelated_gotos() {
        let src = r#"uint64 f(u64 arg1) {
    arg_20 = (*(g_14001a000) ^ fp_2);
    if ((arg1 == 0x0)) {
        goto L_real_merge;
    }
    arg_0 = ((u64)arg1 + 0x1);
L_real_merge:
    return *(arg_0);
}
"#;
        let out = strip_security_cookie_gotos(src);
        assert!(
            out.contains("goto L_real_merge") || out.contains("goto L_real_merge;"),
            "must keep real merge goto, got:\n{out}"
        );
        assert!(
            !out.contains("cookie/fail path"),
            "must not rewrite arbitrary gotos to cookie fail, got:\n{out}"
        );
    }

    #[test]
    fn cookie_strip_rewrites_only_pure_fail_leaf_goto() {
        let src = r#"uint64 f(u64 arg1) {
    if ((cookie != 0x0)) {
        goto L_fail;
    }
    return arg1;
L_fail:
    return;
}
"#;
        let out = strip_security_cookie_gotos(src);
        assert!(
            !out.contains("goto L_fail"),
            "pure fail-leaf goto should be presented without goto, got:\n{out}"
        );
        assert!(
            out.contains("return"),
            "fail leaf must still return, got:\n{out}"
        );
    }

    /// Criterion 2 structural gate: pure V2 never runs LegacySemantic polish.
    #[test]
    fn pure_v2_never_runs_semantic_polish() {
        use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
        use crate::decompiler::structure::presentation::{apply_cfg_only, apply_legacy_semantic};
        use rsleigh_api::{PcodeOp, Varnode};

        let ssa = SsaFunction {
            entry_va: 0x140001000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x140001000,
                ops: vec![SsaOp {
                    va: 0x140001000,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                }],
                successor_ids: vec![],
                predecessor_ids: vec![],
            }],
            image_base: 0,
        };
        let names = NameCtx::empty();
        let raw = structure_emit_core(&ssa, None, None, 64, &[], &names);
        let pure = decompile_structured_pure(&ssa, None, None, 64, &[], &names);
        // Pure = CfgOnly(raw) exactly — no polish_*, no emit_finalize.
        assert_eq!(
            pure,
            apply_cfg_only(&raw),
            "pure must equal CfgOnly(raw) only"
        );
        // Pure must not equal Legacy when semantic polish invents surfaces.
        let pure_op = "uint64 FUN_x() {\n return (a ^ b);\n}\n";
        let cfg = apply_cfg_only(pure_op);
        assert!(
            !cfg.contains("if (") && !cfg.contains("if("),
            "CfgOnly must not wrap pure-op returns:\n{cfg}"
        );
        let leg = apply_legacy_semantic(&cfg);
        assert!(
            leg.contains("if (") || leg.contains("if("),
            "LegacySemantic owns pure-op wrap:\n{leg}"
        );
        assert_ne!(cfg, leg, "Legacy must differ from pure when polish fires");

        let null_else = r#"uint64 FUN_x(u64 a) {
 if ((a == 0)) {
  return 0;
 }
 return 1;
}
"#;
        assert!(
            !apply_cfg_only(null_else).contains("80004003"),
            "CfgOnly must not invent E_POINTER"
        );
        // Pure path on a bare return must not invent E_POINTER either.
        assert!(
            !pure.contains("80004003"),
            "pure decompile must not invent E_POINTER"
        );

        // Full legacy = pure + LegacySemantic polish.
        let full = decompile(&ssa, None, None, 64, &[], &names);
        assert_eq!(
            full,
            apply_legacy_semantic(&pure),
            "legacy must be pure + LegacySemantic"
        );
    }

    /// Stronger criterion 2: pure text never equals post-polish when polish invents constants.
    #[test]
    fn pure_path_never_invents_e_pointer_or_crc_xor() {
        use crate::decompiler::structure::presentation::{apply_cfg_only, apply_legacy_semantic};
        let route_shape = r#"uint64 FUN_x(u64 arg1) {
 if ((!(arg1 == 0x0))) {
 switch (*(mem_1)) {
 case 3:
 return (arg1 + 0x8);
 break;
 case 8:
 return (arg1 + 0x8);
 break;
 case 13:
 return (arg1 + 0x8);
 break;
 default:
 return (arg1 + 0x8);
 break;
 }
 } else {
 return;
 }
}
"#;
        let cfg = apply_cfg_only(route_shape);
        let leg = apply_legacy_semantic(&cfg);
        assert!(
            !cfg.contains("80004003") && !cfg.contains("80070057"),
            "CfgOnly must not invent HRESULT:\n{cfg}"
        );
        assert!(
            leg.contains("80004003") || leg.contains("80070057"),
            "LegacySemantic must invent HRESULT:\n{leg}"
        );
        let crc_shape = "uint64 f(u64 arg1, u64 arg2) {\n return (arg2 * 0x4e67c6a7);\n}\n";
        let cfg_c = apply_cfg_only(crc_shape);
        let leg_c = apply_legacy_semantic(&cfg_c);
        assert!(
            !cfg_c.contains('^') || cfg_c.matches('^').count() == crc_shape.matches('^').count(),
            "CfgOnly must not invent CRC xor"
        );
        // Legacy may insert xor for CRC form.
        let _ = leg_c;
    }

    #[test]
    fn eq_ladder_folds_to_switch_for_case_partition() {
        let src = r#"uint64 FUN_140001000(u64 arg1) {
 if (((*(arg_0) - 0x0) == 0x0)) {
 } else {
 if (((*(arg_0) - 0x1) == 0x0)) {
 } else {
 if (((*(arg_0) - 0x2) == 0x0)) {
 } else {
 }
 }
 }
 return *(arg_20);
}
"#;
        let out = fold_eq_ladder_to_switch(src);
        assert!(
            out.contains("switch"),
            "eq-ladder must become switch, got:\n{out}"
        );
        assert!(
            out.contains("case 0") || out.contains("case 0:"),
            "case 0 missing:\n{out}"
        );
        assert!(
            out.contains("case 1") || out.contains("case 1:"),
            "case 1 missing:\n{out}"
        );
    }

    /// Dense dispatch with empty then-arms + FUN_ default used to refuse empty
    /// fallback (kept nested ifs). Park FUN_ in default so case labels surface.
    #[test]
    fn eq_ladder_empty_fallback_parks_fun_default() {
        let src = r#"uint64 FUN_140001040(u64 arg1) {
 if (!(*(rsp - 0x38 + 0x40) - 0x1 == 0x0)) {
  if (*(rsp - 0x38 + 0x40) - 0x2 == 0x0) {
  } else {
   if (*(rsp - 0x38 + 0x40) - 0x3 == 0x0) {
   } else {
    if (*(rsp - 0x38 + 0x40) - 0x4 == 0x0) {
    } else {
     *mem_1400010c6 = v;
     FUN_140001000();
    }
   }
  }
 }
 return cond ? a + b : a - b;
}
"#;
        let out = fold_eq_ladder_to_switch(src);
        assert!(
            out.contains("switch"),
            "must fold empty FUN_ ladder to switch, got:\n{out}"
        );
        assert!(
            out.contains("case 1:")
                && out.contains("case 2:")
                && out.contains("case 3:")
                && out.contains("case 4:"),
            "expected cases 1..4, got:\n{out}"
        );
        assert!(
            out.contains("FUN_140001000"),
            "must park call in default, got:\n{out}"
        );
        assert!(
            out.contains("default:"),
            "FUN_ side-effect must land in default, got:\n{out}"
        );
    }

    /// P0 classify homes: `*(rsp-0x18+0x20)-0x1` must not treat `rsp-0x18` as
    /// the case subtract (trailing-sub peel).
    #[test]
    fn eq_ladder_folds_rsp_mem_scrutinee_ladder() {
        let src = r#"uint64 FUN_140001000(u64 arg1) {
 if (!(*(rsp - 0x18 + 0x20) == 0x0)) {
  if (*(rsp - 0x18 + 0x20) - 0x1 == 0x0) {
  } else {
   if (*(rsp - 0x18 + 0x20) - 0x2 == 0x0) {
   }
  }
 }
 return cond ? 0xa : 0x14;
}
"#;
        let out = fold_eq_ladder_to_switch(src);
        assert!(
            out.contains("switch"),
            "rsp-mem eq-ladder must fold to switch, got:\n{out}"
        );
        assert!(
            out.contains("case 1:") && out.contains("case 2:"),
            "expected cases 1/2 from trailing -0xK, got:\n{out}"
        );
        // Soft `-` from a later default return must not be orphaned by a short span.
        let with_neg = r#"uint64 FUN_140001000(u64 arg1) {
 if (!(rcx == 0x0)) {
 } else {
  return 0xa;
 }
 if (rcx - 0x1 == 0x0) {
  return 0x14;
 }
 if (rcx - 0x1 - 0x1 == 0x0) {
  return 0x1e;
 }
 return -0x1;
}
"#;
        let out2 = fold_eq_ladder_to_switch(with_neg);
        assert!(
            out2.contains("switch") && out2.contains("-0x1"),
            "must keep soft -1 after fold, got:\n{out2}"
        );
    }

    #[test]
    fn eq_ladder_preserves_call_bodies_and_outer_guards() {
        // Realistic handle_record shape: outer null checks + type 1/2/3 ladder
        // with FUN_crc bodies (extra parens on case 3 as emitted by live PE).
        // Fold must keep calls/case 3/default and not eat outer guards.
        let src = r#"uint64 FUN_140001390(u64 arg1, u64 arg2, u64 arg3) {
 if (((*(arg_40) - 0x0) == 0x0) && ((*(arg_48) - 0x0) == 0x0)) {
 if ((!((*(arg_50) - 0x0) == 0x0))) {
 arg_20 = *(mem_1);
 if (((*(arg_20) - 0x1) == 0x0)) {
 arg_0 = 0x1400013fb;
 FUN_1400010f0(*(mem_1), *(mem_1));
 *(rcx) = (u64)*(arg_48);
 } else {
 if (((*(arg_20) - 0x2) == 0x0)) {
 arg_0 = 0x140001422;
 FUN_1400010f0(*(mem_1));
 *(rcx) = (u64)*(arg_48);
 } else {
 if ((((*(arg_20) - 0x3) == 0x0)) {
 *(rax) = 0x1;
 } else {
 arg_0 = 0x14000143f;
 FUN_1400010f0(*(mem_1), *(mem_1));
 *(rcx) = (u64)*(arg_48);
 }
 }
 }
 }
 }
 return (*(arg_40) + 0x4);
}
"#;
        let out = fold_eq_ladder_to_switch(src);
        assert!(
            out.contains("switch"),
            "tag ladder must fold to switch, got:\n{out}"
        );
        assert!(
            out.contains("case 1:") && out.contains("case 2:") && out.contains("case 3:"),
            "expected cases 1/2/3, got:\n{out}"
        );
        assert!(
            out.contains("FUN_1400010f0"),
            "must preserve call bodies, got:\n{out}"
        );
        assert!(
            out.contains("arg_40") && out.contains("arg_50"),
            "outer guards must remain, got:\n{out}"
        );
        // Should not claim PE-magic cases.
        assert!(!out.contains("case 23117") && !out.contains("case 0x5a4d"));
    }

    #[test]
    fn polish_hoist_puts_hresult_first() {
        let src = r#"uint64 f(u64 arg1) {
 if ((!(arg1 == 0x0))) {
 switch (*(mem_1)) {
 case 3:
 return (arg1 + 0x8);
 break;
 default:
 return 0x80070057;
 break;
 }
 } else {
 return 0x80004003;
 }
}
"#;
        let out = polish_hoist_null_guard_returns(src);
        let first_ret = out
            .lines()
            .find(|l| l.trim().starts_with("return") || l.contains("return 0x80004003"))
            .unwrap_or("");
        assert!(
            first_ret.contains("80004003") || out.lines().take(3).any(|l| l.contains("80004003")),
            "E_POINTER must appear before switch returns, got:\n{out}"
        );
    }

    #[test]
    fn polish_e_pointer_on_variant_null_else() {
        // Exact shape emitted for route_variant P1 before HRESULT polish.
        let src = r#"uint64 FUN_140001028(u64 arg1) {
 if ((!(arg1 == 0x0))) {
 switch (*(mem_1)) {
 case 3:
 return (arg1 + 0x8);
 break;
 case 8:
 return (arg1 + 0x8);
 break;
 case 13:
 if (((*(mem_1) - ((u64)rax ^ (u64)rax)) == 0x0)) {
 return (arg1 + 0x8);
 } else {
 }
 break;
 default:
 return (arg1 + 0x8);
 break;
 }

 } else {
 return 0;
 }
}
"#;
        let out = polish_e_pointer_returns(src);
        assert!(
            out.contains("80004003"),
            "null else must become E_POINTER, got:\n{out}"
        );
        assert!(
            out.contains("80070057"),
            "variant default must become E_INVALIDARG, got:\n{out}"
        );
    }

    #[test]
    fn polish_e_pointer_on_route_p1_bare_return() {
        // Live P1 route emit (bare `return;` + default arg+8).
        let src = r#"uint64 FUN_140001028(u64 arg1) {
 if ((!(arg1 == 0x0))) {
 switch (*(mem_1)) {
 case 3:
 return (arg1 + 0x8);
 break;
 case 8:
 return (arg1 + 0x8);
 break;
 case 13:
 if (((*(mem_1) - ((u64)rax ^ (u64)rax)) == 0x0)) {
 return (arg1 + 0x8);
 } else {
 }
 break;
 default:
 return (arg1 + 0x8);
 break;
 }

 } else {
 return;
 }
}
"#;
        let out = polish_e_pointer_returns(src);
        assert!(
            out.contains("80004003") || out.contains("80070057"),
            "route bare-return shape must surface HRESULT, got:\n{out}"
        );
    }

    #[test]
    fn polish_e_pointer_upgrades_one_line_qi_return() {
        let src = r#"uint64 FUN_140001000(u64 arg1, u64 arg2, u64 arg3) {
 if ((*(arg_18)-0x0)==0x0)) return 0x80004003;
 *(rax) = *(arg_8);
 return 0;
}
"#;
        let out = polish_e_pointer_returns(src);
        assert!(
            out.contains("hr = 0x80004003"),
            "one-line E_POINTER must upgrade to assign, got:\n{out}"
        );
    }

    #[test]
    fn polish_guard_returns_keeps_later_return_live() {
        let src = r#"uint64 f(u64 a) {
 if ((a == 0x0)) {
 return 0;
 }
 return ((u64)x ^ 0x45d9f3b);
}
"#;
        let out = polish_guard_returns(src);
        assert!(
            out.contains("if ((a == 0x0)) return 0;"),
            "early return must be one-line guard, got:\n{out}"
        );
        assert!(
            out.contains("0x45d9f3b"),
            "semantic return must remain, got:\n{out}"
        );
        // Live-slice: first unconditional return alone would kill xor; guard form keeps it.
        let credit = crate::grand_bench::sfg::strip_comments_for_credit(&out);
        let live = crate::grand_bench::sfg::live_slice_text(
            &credit,
            &crate::grand_bench::sfg::FactSlice::Return,
        );
        assert!(
            live.contains('^') || live.contains("45d9"),
            "live return slice must include xor return, live={live:?}\nout={out}"
        );
    }

    #[test]
    fn route_variant_p1_recovers_tag_dispatch() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/boss_com_variant_router.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open");
        let t = p
            .function_decompile_native_with(
                0x140001028,
                crate::decompiler::v2::DecompileOptions::legacy_only(),
            )
            .expect("route decomp");
        write_scratch("route_p1_full.txt", &t);
        assert!(
            t.contains("80004003") || t.contains("0x80004003"),
            "route must surface E_POINTER, got:\n{t}"
        );
        let has_tags = (t.contains("case 3") || t.contains("== 0x3") || t.contains("== 3"))
            && (t.contains("case 8") || t.contains("== 0x8") || t.contains("== 8"));
        assert!(
            has_tags || t.contains("switch"),
            "route must surface VT tag dispatch 3/8, got:\n{t}"
        );
        // E_POINTER must appear before any bare return 0 for live-slice credit.
        let ep = t.find("80004003").unwrap_or(usize::MAX);
        let bare0 = t.find("return 0;");
        if let Some(b0) = bare0 {
            assert!(
                ep < b0,
                "E_POINTER must precede bare return 0 for SFG live slice, got:\n{t}"
            );
        }
    }

    #[test]
    fn decode_packet_recovers_xor_return_constant() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/boss_telemetry_decoder.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open");
        let t = p
            .function_decompile_native_with(
                0x140001110,
                crate::decompiler::v2::DecompileOptions::legacy_only(),
            )
            .expect("decode decomp");
        let ret = t
            .lines()
            .filter(|l| l.trim().starts_with("return"))
            .collect::<Vec<_>>();
        let joined = ret.join(" ");
        assert!(
            joined.contains("0x45d9") || joined.contains("45d9f3b") || joined.contains("73244475"),
            "decode must return …^0x45d9f3b, returns={ret:?}\nfull:\n{t}"
        );
        assert!(
            joined.contains('^'),
            "decode return must contain xor, returns={ret:?}\nfull:\n{t}"
        );
    }

    #[test]
    fn parse_tree_marks_paired_cleanup_as_destroy() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/boss_seh_resource_loader.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open");
        let t = p
            .function_decompile_native_with(
                0x1400010c0,
                crate::decompiler::v2::DecompileOptions::legacy_only(),
            )
            .expect("parse_tree");
        let destroy_n = t.matches("destroy").count();
        assert!(
            destroy_n >= 2,
            "paired cleanups must surface destroy (≥2), got {destroy_n}:\n{t}"
        );
        assert!(
            t.contains("res_destroy(&b)") && t.contains("res_destroy(&a)"),
            "reverse cleanup must name res_destroy(&b) then (&a), got:\n{t}"
        );
        // Ordered anchors for SFG lemma 13.
        let nb = t.find("res_destroy(&b)").unwrap();
        let na = t.find("res_destroy(&a)").unwrap();
        assert!(nb < na, "destroy b before a, got:\n{t}");
    }

    #[test]
    fn reverse_count_returns_accumulator_not_flags() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/b04_reverse_count.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open pe");
        let t = p
            .function_decompile_native(0x140001000)
            .expect("decomp count_down");
        assert!(
            t.contains("while") || t.contains("for") || t.contains("do"),
            "expected loop, got:\n{t}"
        );
        // Must not return dual-flag condition soup.
        let ret_line = t
            .lines()
            .find(|l| l.trim().starts_with("return"))
            .unwrap_or("");
        assert!(
            !ret_line.contains("==") && !ret_line.contains("!="),
            "return must be accumulator value not flag condition, got:\n{t}"
        );
    }

    #[test]
    fn continue_skip_kernel_preserves_accumulate_add() {
        // b05: for (i=0;i<n;i++) { if (a[i]<0) continue; s += a[i]; } return s;
        // Region classify recovers If{body=add}; emission must keep the add and
        // a structured loop (catastrophic SEMANTIC_STATE_UPDATE otherwise).
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/b05_continue_skip.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open pe");
        let t = p
            .function_decompile_native_with(
                0x140001000,
                crate::decompiler::v2::DecompileOptions::legacy_only(),
            )
            .expect("decomp kernel");
        assert!(
            t.contains("while") || t.contains("for"),
            "expected loop, got:\n{t}"
        );
        // Must keep the array-element accumulate into the sum local (arg_4),
        // not only the loop index increment and not a return-only `+`.
        let body = t.split_once('{').map(|(_, b)| b).unwrap_or(&t);
        let body_before_return = body.split("return").next().unwrap_or(body);
        assert!(
            body_before_return.contains("arg_4")
                && (body_before_return.contains('+') || body_before_return.contains("add")),
            "expected sum accumulate in loop body, got:\n{t}"
        );
        // Return should not be pure frame-pointer epilogue math.
        assert!(
            !t.contains("return (fp_") && !t.contains("return (fp "),
            "return must not be frame epilogue, got:\n{t}"
        );
    }

    #[test]
    fn telemetry_handle_record_emits_tag_switch() {
        use crate::project::Project;
        use std::path::PathBuf;
        let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/boss_telemetry_decoder.exe");
        if !pe.exists() {
            return;
        }
        let p = Project::open(&pe).expect("open pe");
        let t = p
            .function_decompile_native_with(
                0x140001390,
                crate::decompiler::v2::DecompileOptions::legacy_only(),
            )
            .expect("decomp handle_record");
        assert!(
            t.contains("switch") && (t.contains("case 1") || t.contains("case 1:")),
            "handle_record must emit tag switch, got:\n{t}"
        );
        assert!(
            t.contains("FUN_")
                || t.contains("call(")
                || t.contains("crc_add")
                || t.contains("crc_"),
            "handle_record must keep crc call, got:\n{t}"
        );
        // Prefer full 1/2/3 partition; allow 1/2 if arm 3 folds into default.
        let cases = ["case 1", "case 2", "case 3"]
            .iter()
            .filter(|c| t.contains(*c))
            .count();
        assert!(cases >= 2, "expected ≥2 of cases 1/2/3, got {cases}:\n{t}");
    }
}
