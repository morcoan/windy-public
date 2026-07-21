//! Region-tree → typed AST extraction for pure V2.
//!
//! Builds structured statements from [`DualDecompModel`] regions + SSA expression
//! recovery. Does **not** import structure::emit or presentation polish.

use std::collections::{HashMap, HashSet};

use pcode_ir::AddressSpaceId;
use rsleigh_api::PcodeOp;

use crate::decompiler::normalize::external_tail_call_target;
use crate::decompiler::ssa::{Location, SsaFunction, SsaOpKind};
use crate::decompiler::structure::rd_model::DualDecompModel;
use crate::decompiler::structure::region::{Region, SwitchInfo};

use super::ast::{CoverageMaps, Expr, Stmt, SwitchCase, TypedAst, TypedAstCandidate};
use super::contracts::ContractBundle;
use super::semantic::SemanticModel;
use super::ssa_expr::{
    best_return_of_function, build_expr_map, cond_expr_of_block, is_leaf_kernel,
    normalize_cond_expr, return_expr_of_exit,
};

/// Build the primary pure-V2 candidate from regions + SSA (no text polish).
pub fn extract_region_ast(
    ssa: &SsaFunction,
    sem: &SemanticModel,
    contracts: &ContractBundle,
    switches: &[SwitchInfo],
    name: &str,
    params: &[String],
) -> TypedAstCandidate {
    let mut dual = DualDecompModel::build(ssa, switches);
    // Checker-backed region rewrites (structural, not text polish).
    let selected = crate::decompiler::structure::rewrite::select_improving_moves(&dual);
    crate::decompiler::structure::rewrite::apply_moves(&mut dual, &selected, ssa);
    let _ = dual.sanitize_contracts(ssa);
    let env = build_expr_map(ssa);
    let mut edges = Vec::new();
    for (i, ss) in sem.succ.iter().enumerate() {
        for &t in ss {
            edges.push(format!("{i}->{t}"));
        }
    }

    // Leaf pure kernels: prefer branchless `return <expr>` (gold accepts this).
    let leaf = is_leaf_kernel(ssa);
    let return_block_count = ssa
        .blocks
        .iter()
        .filter(|block| {
            block
                .ops
                .iter()
                .any(|op| matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
        })
        .count();
    let best_ret = (return_block_count == 1)
        .then(|| best_return_of_function(ssa, &env))
        .flatten();
    let mut body = Vec::new();
    let mut effects = Vec::new();
    if leaf && return_block_count == 1 {
        if let Some(e) = best_ret.clone() {
            body.push(Stmt::Return { expr: Some(e) });
            effects.push("return".into());
            return TypedAstCandidate {
                ast: TypedAst {
                    name: name.into(),
                    params: params.to_vec(),
                    ret_ty: "uint64".into(),
                    body,
                },
                coverage: CoverageMaps { edges, effects },
                residual_edges: 0,
                case_partitions: contracts.cases.clone(),
                cost: 0,
                nesting: 0,
                hit_cap: false,
            };
        }
        // Leaf with contracts.has_return but no recovered expr.
        if contracts.has_return {
            body.push(Stmt::Return {
                expr: Some(Expr::Name { name: "ret".into() }),
            });
            effects.push("return".into());
            return TypedAstCandidate {
                ast: TypedAst {
                    name: name.into(),
                    params: params.to_vec(),
                    ret_ty: "uint64".into(),
                    body,
                },
                coverage: CoverageMaps { edges, effects },
                residual_edges: 0,
                case_partitions: contracts.cases.clone(),
                cost: 1,
                nesting: 0,
                hit_cap: false,
            };
        }
    }

    let mut emitted = HashSet::new();
    let start = ssa
        .blocks
        .iter()
        .position(|b| b.entry_va == ssa.entry_va)
        .unwrap_or(0) as u32;

    walk_region(
        ssa,
        &dual.regions,
        &env,
        &mut emitted,
        start,
        u32::MAX,
        &mut body,
        &mut effects,
        0,
    );

    // Residual unemitted blocks: only surface effects (skip jump-only / control tails).
    for i in 0..ssa.blocks.len() as u32 {
        if emitted.contains(&i) {
            continue;
        }
        if crate::decompiler::structure::cfg_norm::is_jump_only(&ssa.blocks[i as usize]) {
            emitted.insert(i);
            continue;
        }
        let block = &ssa.blocks[i as usize];
        let only_control = block.ops.iter().all(|op| {
            matches!(
                &op.kind,
                SsaOpKind::Phi(_)
                    | SsaOpKind::Pcode(
                        PcodeOp::Branch { .. }
                            | PcodeOp::CBranch { .. }
                            | PcodeOp::BranchInd { .. }
                            | PcodeOp::Return { .. }
                    )
            ) || crate::decompiler::normalize::is_frame_pointer_adjust(op)
                || crate::decompiler::normalize::is_param_home_store(op)
                || crate::decompiler::normalize::is_noise_stack_reload(op)
        });
        if only_control {
            emitted.insert(i);
            continue;
        }
        let has_surface = block.ops.iter().any(|op| {
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
        });
        if has_surface {
            emit_block_surface(ssa, i, &env, &mut body, &mut effects, /*label*/ false);
        }
        emitted.insert(i);
    }

    if contracts.has_return && !effects.iter().any(|e| e == "return") {
        // Ensure return surface when semantic says so.
        let single_exit_fallback = (return_block_count == 1)
            .then(|| best_ret.or_else(|| best_return_of_function(ssa, &env)))
            .flatten();
        if let Some(e) = single_exit_fallback {
            body.push(Stmt::Return { expr: Some(e) });
            effects.push("return".into());
        } else {
            body.push(Stmt::Return {
                expr: Some(Expr::Name { name: "ret".into() }),
            });
            effects.push("return".into());
        }
    }

    // A function-wide fallback is safe only for a single architectural exit.
    // Multi-exit functions retain each block's independently resolved value.
    if return_block_count == 1
        && let Some(rich) = best_return_of_function(ssa, &env)
    {
        let rich_score = matches!(
            rich,
            Expr::Compare { .. } | Expr::BinOp { .. } | Expr::UInt { .. }
        );
        if rich_score {
            for s in &mut body {
                if let Stmt::Return { expr } = s {
                    let thin = match expr {
                        Some(Expr::Name { .. }) | None => true,
                        Some(Expr::Compare { lhs, rhs, .. }) => {
                            matches!(lhs.as_ref(), Expr::Name { name } if name == "a" || name == "cond")
                                || matches!(rhs.as_ref(), Expr::Name { name } if name == "b" || name == "cond")
                        }
                        _ => false,
                    };
                    if thin {
                        *expr = Some(rich.clone());
                    }
                }
            }
        }
    }

    let residual = body
        .iter()
        .filter(|s| matches!(s, Stmt::Goto { .. }))
        .count();
    let nesting = count_nesting(&body);

    TypedAstCandidate {
        ast: TypedAst {
            name: name.into(),
            params: params.to_vec(),
            ret_ty: "uint64".into(),
            body,
        },
        coverage: CoverageMaps { edges, effects },
        residual_edges: residual,
        case_partitions: contracts.cases.clone(),
        cost: residual as i32 * 5 + nesting,
        nesting,
        hit_cap: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_region(
    ssa: &SsaFunction,
    regions: &HashMap<u32, Region>,
    env: &std::collections::HashMap<crate::decompiler::ssa::SsaVar, Expr>,
    emitted: &mut HashSet<u32>,
    entry: u32,
    stop: u32,
    out: &mut Vec<Stmt>,
    effects: &mut Vec<String>,
    depth: i32,
) {
    if depth > 64 {
        return;
    }
    let mut current = Some(entry);
    while let Some(b) = current {
        if b == stop || b as usize >= ssa.blocks.len() {
            break;
        }
        if emitted.contains(&b) {
            // Already structured — do not introduce residual gotos.
            break;
        }
        emitted.insert(b);
        let block = &ssa.blocks[b as usize];

        match regions.get(&b) {
            Some(Region::IfElse {
                then_entry,
                else_entry,
                merge,
                invert,
            }) => {
                emit_block_stmts(ssa, block, env, out, effects);
                let mut cond = cond_expr_of_block(block, env);
                if *invert {
                    cond = Expr::UnaryOp {
                        op: "!".into(),
                        arg: Box::new(cond),
                    };
                }
                cond = normalize_cond_expr(cond);
                let mut then_body = Vec::new();
                let mut else_body = Vec::new();
                walk_region(
                    ssa,
                    regions,
                    env,
                    emitted,
                    *then_entry,
                    *merge,
                    &mut then_body,
                    effects,
                    depth + 1,
                );
                walk_region(
                    ssa,
                    regions,
                    env,
                    emitted,
                    *else_entry,
                    *merge,
                    &mut else_body,
                    effects,
                    depth + 1,
                );
                out.push(Stmt::If {
                    cond,
                    then_body,
                    else_body,
                });
                current = Some(*merge);
            }
            Some(Region::If {
                body_entry,
                merge,
                invert,
            })
            | Some(Region::IfThenFallthrough {
                then_entry: body_entry,
                cont_entry: merge,
                invert,
                ..
            }) => {
                emit_block_stmts(ssa, block, env, out, effects);
                let mut cond = cond_expr_of_block(block, env);
                if *invert {
                    cond = Expr::UnaryOp {
                        op: "!".into(),
                        arg: Box::new(cond),
                    };
                }
                cond = normalize_cond_expr(cond);
                let mut then_body = Vec::new();
                walk_region(
                    ssa,
                    regions,
                    env,
                    emitted,
                    *body_entry,
                    *merge,
                    &mut then_body,
                    effects,
                    depth + 1,
                );
                out.push(Stmt::If {
                    cond,
                    then_body,
                    else_body: vec![],
                });
                current = Some(*merge);
            }
            Some(Region::While { body_entry, exit }) => {
                let cond = normalize_cond_expr(cond_expr_of_block(block, env));
                let mut body = Vec::new();
                emit_block_stmts(ssa, block, env, &mut body, effects);
                walk_region(
                    ssa,
                    regions,
                    env,
                    emitted,
                    *body_entry,
                    b,
                    &mut body,
                    effects,
                    depth + 1,
                );
                out.push(Stmt::While { cond, body });
                current = Some(*exit);
            }
            Some(Region::DoWhile {
                body_entry,
                cond_block: _,
                exit,
            }) => {
                let mut body = Vec::new();
                emit_block_stmts(ssa, block, env, &mut body, effects);
                walk_region(
                    ssa,
                    regions,
                    env,
                    emitted,
                    *body_entry,
                    b,
                    &mut body,
                    effects,
                    depth + 1,
                );
                let cond = cond_expr_of_block(block, env);
                out.push(Stmt::While { cond, body });
                current = Some(*exit);
            }
            Some(Region::Switch { cases, merge }) => {
                emit_block_stmts(ssa, block, env, out, effects);
                let scrutinee = cond_expr_of_block(block, env);
                let mut switch_cases = Vec::new();
                for (val, tgt) in cases {
                    let mut case_body = Vec::new();
                    walk_region(
                        ssa,
                        regions,
                        env,
                        emitted,
                        *tgt,
                        *merge,
                        &mut case_body,
                        effects,
                        depth + 1,
                    );
                    case_body.push(Stmt::Break);
                    switch_cases.push(SwitchCase {
                        values: vec![*val],
                        body: case_body,
                    });
                }
                out.push(Stmt::Switch {
                    scrutinee,
                    cases: switch_cases,
                    default_body: vec![],
                });
                current = Some(*merge);
            }
            Some(Region::Return) => {
                emit_block_stmts(ssa, block, env, out, effects);
                if !effects.iter().any(|e| e == "return")
                    && !block
                        .ops
                        .iter()
                        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
                {
                    let e = return_expr_of_exit(ssa, block.id, env);
                    out.push(Stmt::Return { expr: e });
                    effects.push("return".into());
                }
                current = None;
            }
            None => {
                // Straight-line / unstructured: no residual labels; prefer if for 2-way.
                emit_block_stmts(ssa, block, env, out, effects);
                let succs: Vec<u32> = block
                    .successor_ids
                    .iter()
                    .map(|&s| {
                        crate::decompiler::structure::cfg_norm::resolve_jump_target(ssa, s, 16)
                    })
                    .collect();
                if block
                    .ops
                    .iter()
                    .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
                {
                    current = None;
                } else {
                    match succs.len() {
                        0 => current = None,
                        1 => {
                            let s = succs[0];
                            if s == stop {
                                current = None;
                            } else if emitted.contains(&s) {
                                // Avoid rejoin goto when possible — stop.
                                current = None;
                            } else {
                                current = Some(s);
                            }
                        }
                        2 => {
                            // Residual CBranch → structured if (not dual goto).
                            let (fall, taken) = (succs[0], succs[1]);
                            let cond = cond_expr_of_block(block, env);
                            let mut then_body = Vec::new();
                            let mut else_body = Vec::new();
                            if !emitted.contains(&taken) && taken != stop {
                                walk_region(
                                    ssa,
                                    regions,
                                    env,
                                    emitted,
                                    taken,
                                    stop,
                                    &mut then_body,
                                    effects,
                                    depth + 1,
                                );
                            }
                            if !emitted.contains(&fall) && fall != stop {
                                walk_region(
                                    ssa,
                                    regions,
                                    env,
                                    emitted,
                                    fall,
                                    stop,
                                    &mut else_body,
                                    effects,
                                    depth + 1,
                                );
                            }
                            out.push(Stmt::If {
                                cond,
                                then_body,
                                else_body,
                            });
                            current = None;
                        }
                        _ => {
                            // Multi-way: emit surface only; do not spray gotos.
                            current = None;
                        }
                    }
                }
            }
        }
    }
}

fn emit_block_stmts(
    ssa: &SsaFunction,
    block: &crate::decompiler::ssa::SsaBlock,
    env: &std::collections::HashMap<crate::decompiler::ssa::SsaVar, Expr>,
    out: &mut Vec<Stmt>,
    effects: &mut Vec<String>,
) {
    for op in &block.ops {
        if crate::decompiler::normalize::is_frame_pointer_adjust(op)
            || crate::decompiler::normalize::is_param_home_store(op)
            || crate::decompiler::normalize::is_noise_stack_reload(op)
        {
            continue;
        }
        match &op.kind {
            SsaOpKind::Pcode(PcodeOp::Call { dest, .. }) => {
                let tgt = if matches!(dest.space, AddressSpaceId::Const | AddressSpaceId::Ram) {
                    format!("FUN_{:x}", dest.offset)
                } else {
                    format!("call_{:x}", op.va)
                };
                out.push(Stmt::Expr {
                    expr: Expr::Call {
                        target: tgt.clone(),
                        args: vec![],
                    },
                });
                effects.push(format!("call:{tgt}"));
            }
            // MSVC `inc ecx; jmp leaf` — recover as `return leaf(x + 1)`.
            SsaOpKind::Pcode(PcodeOp::Branch { dest, .. }) => {
                let Some(va) = external_tail_call_target(ssa, *dest) else {
                    continue;
                };
                let tgt = format!("FUN_{va:x}");
                let args = mid_tail_call_args(block, env);
                out.push(Stmt::Return {
                    expr: Some(Expr::Call {
                        target: tgt.clone(),
                        args,
                    }),
                });
                effects.push(format!("call:{tgt}"));
                effects.push("return".into());
            }
            SsaOpKind::Pcode(PcodeOp::CallInd { .. }) => {
                let tgt = format!("icall_{:x}", op.va);
                out.push(Stmt::Expr {
                    expr: Expr::Call {
                        target: tgt.clone(),
                        args: vec![],
                    },
                });
                effects.push(format!("call:{tgt}"));
            }
            SsaOpKind::Pcode(PcodeOp::Store { .. }) => {
                // Prefer pointer/value from uses when available.
                let dest = op
                    .uses
                    .first()
                    .map(|u| match u.location {
                        crate::decompiler::ssa::Location::StackSlot { disp, .. } => {
                            format!("*arg_{}", ((disp as u64) / 8).max(1))
                        }
                        crate::decompiler::ssa::Location::Register { base_offset } => {
                            format!("*{}", crate::decompiler::ssa::lower::reg_name(base_offset))
                        }
                        _ => format!("*mem_{:x}", op.va),
                    })
                    .unwrap_or_else(|| format!("*mem_{:x}", op.va));
                let val = op
                    .uses
                    .get(1)
                    .and_then(|u| env.get(u).cloned())
                    .or_else(|| op.uses.first().and_then(|u| env.get(u).cloned()))
                    .unwrap_or(Expr::Name { name: "v".into() });
                // Drop frame/spill soup stores (rsp/rbx save patterns).
                let val_s = format!("{val:?}");
                if dest.contains("rsp")
                    || dest.contains("rbx")
                    || dest.contains("rbp")
                    || val_s.contains("rsp")
                {
                    continue;
                }
                out.push(Stmt::Assign { dest, expr: val });
                effects.push(format!("store:{:x}", op.va));
            }
            SsaOpKind::Pcode(PcodeOp::Return { .. }) => {
                let e = return_expr_of_exit(ssa, block.id, env);
                out.push(Stmt::Return { expr: e });
                effects.push("return".into());
            }
            _ => {}
        }
    }
}

/// RCX (first Win64 arg) expression for `mid`-style tail calls.
fn mid_tail_call_args(
    block: &crate::decompiler::ssa::SsaBlock,
    env: &HashMap<crate::decompiler::ssa::SsaVar, Expr>,
) -> Vec<Expr> {
    const RCX: u64 = 0x08;
    for op in block.ops.iter().rev() {
        let Some(def) = op.def.as_ref() else {
            continue;
        };
        if matches!(def.location, Location::Register { base_offset } if base_offset == RCX) {
            if let Some(e) = env.get(def) {
                return vec![e.clone()];
            }
        }
    }
    vec![Expr::Name {
        name: "arg1".into(),
    }]
}

fn emit_block_surface(
    ssa: &SsaFunction,
    b: u32,
    env: &std::collections::HashMap<crate::decompiler::ssa::SsaVar, Expr>,
    out: &mut Vec<Stmt>,
    effects: &mut Vec<String>,
    label: bool,
) {
    if b as usize >= ssa.blocks.len() {
        return;
    }
    if label {
        out.push(Stmt::Label {
            name: format!("L_{b}"),
        });
    }
    emit_block_stmts(ssa, &ssa.blocks[b as usize], env, out, effects);
}

fn count_nesting(stmts: &[Stmt]) -> i32 {
    let mut n = 0i32;
    for s in stmts {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                n += 1 + count_nesting(then_body).max(count_nesting(else_body));
            }
            Stmt::While { body, .. } => n += 1 + count_nesting(body),
            Stmt::Switch {
                cases,
                default_body,
                ..
            } => {
                let mut m = count_nesting(default_body);
                for c in cases {
                    m = m.max(count_nesting(&c.body));
                }
                n += 1 + m;
            }
            _ => {}
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{Location, SsaBlock, SsaOp, SsaVar};
    use rsleigh_api::Varnode;

    #[test]
    fn region_ast_source_forbids_emit_and_presentation() {
        let src = include_str!("region_ast.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let forbid = [
            ["structure::", "emit"].concat(),
            ["presentation", "::"].concat(),
            ["apply_legacy", "_semantic"].concat(),
            ["polish_", "crc"].concat(),
        ];
        for f in &forbid {
            assert!(!code.contains(f), "region_ast must not use {f}");
        }
    }

    #[test]
    fn single_return_nonempty_ast() {
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
        let sem = SemanticModel::from_raw_pcode(&ssa);
        let contracts = ContractBundle::from_semantic(&ssa, &sem, &[]);
        let cand = extract_region_ast(&ssa, &sem, &contracts, &[], "FUN_x", &[]);
        assert!(!cand.ast.body.is_empty());
        assert!(
            cand.coverage.effects.iter().any(|e| e == "return"),
            "{:?}",
            cand.coverage.effects
        );
        // Must not be a polish RawBlock dump.
        assert!(
            !matches!(cand.ast.body[0], Stmt::RawBlock { .. }),
            "expected structured stmts, got {:?}",
            cand.ast.body
        );
    }

    #[test]
    fn multi_exit_leaf_keeps_hresult_and_success_returns_distinct() {
        let condition = SsaVar {
            location: Location::Register { base_offset: 8 },
            version: 1,
        };
        let failure = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let success = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 2,
        };
        let exit = |id: u32, va: u64, value: u64, var: SsaVar| SsaBlock {
            id,
            entry_va: va,
            ops: vec![
                SsaOp {
                    va,
                    kind: SsaOpKind::Pcode(PcodeOp::Copy {
                        out: Varnode::register(0, 4),
                        input: Varnode::constant(value, 4),
                    }),
                    def: Some(var.clone()),
                    uses: vec![],
                },
                SsaOp {
                    va: va + 1,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![var],
                },
            ],
            successor_ids: vec![],
            predecessor_ids: vec![0],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    entry_va: 0x1000,
                    ops: vec![SsaOp {
                        va: 0x1000,
                        kind: SsaOpKind::Pcode(PcodeOp::CBranch {
                            dest: Varnode::constant(0, 8),
                            cond: Varnode::register(8, 1),
                        }),
                        def: None,
                        uses: vec![condition],
                    }],
                    successor_ids: vec![1, 2],
                    predecessor_ids: vec![],
                },
                exit(1, 0x1010, 0x8000_4003, failure),
                exit(2, 0x1020, 0, success),
            ],
            image_base: 0,
        };
        let sem = SemanticModel::from_raw_pcode(&ssa);
        let contracts = ContractBundle::from_semantic(&ssa, &sem, &[]);
        let cand = extract_region_ast(&ssa, &sem, &contracts, &[], "query", &[]);

        fn return_classes(stmts: &[Stmt], out: &mut std::collections::BTreeSet<String>) {
            for stmt in stmts {
                match stmt {
                    Stmt::Return { expr: Some(expr) } => {
                        out.insert(super::super::ssa_expr::expr_class_tag(expr));
                    }
                    Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        return_classes(then_body, out);
                        return_classes(else_body, out);
                    }
                    Stmt::While { body, .. } => return_classes(body, out),
                    Stmt::Switch {
                        cases,
                        default_body,
                        ..
                    } => {
                        for case in cases {
                            return_classes(&case.body, out);
                        }
                        return_classes(default_body, out);
                    }
                    _ => {}
                }
            }
        }

        let mut classes = std::collections::BTreeSet::new();
        return_classes(&cand.ast.body, &mut classes);
        assert!(classes.contains("const:0x80004003"), "{cand:#?}");
        assert!(classes.contains("const:0"), "{cand:#?}");
        assert_eq!(classes.len(), 2, "{cand:#?}");
    }
}
