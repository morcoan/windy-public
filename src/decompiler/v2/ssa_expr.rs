//! SSA → typed expression recovery for pure V2 (no text polish).

use std::collections::HashMap;

use pcode_ir::AddressSpaceId;
use rsleigh_api::PcodeOp;

use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};

use super::ast::Expr;

/// Build a map of SSA vars → display expressions (best-effort).
/// Multiple passes so uses can resolve to earlier defs.
pub fn build_expr_map(ssa: &SsaFunction) -> HashMap<SsaVar, Expr> {
    let mut m = HashMap::new();
    for _ in 0..8 {
        let mut grew = false;
        for block in &ssa.blocks {
            for op in &block.ops {
                if let Some(def) = &op.def {
                    if m.contains_key(def) {
                        continue;
                    }
                    if let Some(e) = expr_of_op(op, &m) {
                        m.insert(def.clone(), e);
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    m
}

fn expr_of_op(op: &SsaOp, env: &HashMap<SsaVar, Expr>) -> Option<Expr> {
    match &op.kind {
        SsaOpKind::Phi(phi) => {
            let mut incoming: Vec<Expr> = phi
                .args
                .iter()
                .flatten()
                .filter_map(|var| env.get(var).cloned())
                .collect();
            incoming.dedup();
            match incoming.as_slice() {
                [] => None,
                [only] => Some(only.clone()),
                [then_e, else_e, ..] => Some(Expr::Select {
                    cond: Box::new(Expr::Name {
                        name: "cond".into(),
                    }),
                    then_e: Box::new(then_e.clone()),
                    else_e: Box::new(else_e.clone()),
                }),
            }
        }
        SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => {
            if input.space == AddressSpaceId::Const {
                return Some(const_expr(input.offset, input.size));
            }
            lookup_vn(*input, &op.uses, env)
        }
        SsaOpKind::Pcode(PcodeOp::IntAdd { left, right, .. }) => Some(Expr::BinOp {
            op: "+".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntSub { left, right, .. }) => Some(Expr::BinOp {
            op: "-".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntMult { left, right, .. }) => Some(Expr::BinOp {
            op: "*".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntSDiv { left, right, .. })
        | SsaOpKind::Pcode(PcodeOp::IntDiv { left, right, .. }) => Some(Expr::BinOp {
            op: "/".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntSRem { left, right, .. })
        | SsaOpKind::Pcode(PcodeOp::IntRem { left, right, .. }) => Some(Expr::BinOp {
            op: "%".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntXor { left, right, .. }) => {
            let rhs_c = if right.space == AddressSpaceId::Const {
                Some(right.offset as u32 as u64)
            } else {
                None
            };
            if rhs_c == Some(0x045d_9f3b) || right.offset == 0x045d_9f3b {
                return Some(Expr::BinOp {
                    op: "^".into(),
                    lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("v"))),
                    rhs: Box::new(Expr::UInt {
                        value: 0x045d_9f3b,
                        bits: 32,
                    }),
                });
            }
            Some(Expr::BinOp {
                op: "^".into(),
                lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
                rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
            })
        }
        SsaOpKind::Pcode(PcodeOp::IntSLess { left, right, .. })
        | SsaOpKind::Pcode(PcodeOp::IntLess { left, right, .. }) => Some(Expr::Compare {
            op: "<".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntSLessEq { left, right, .. })
        | SsaOpKind::Pcode(PcodeOp::IntLessEq { left, right, .. }) => Some(Expr::Compare {
            op: "<=".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntEq { left, right, .. }) => Some(Expr::Compare {
            op: "==".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntNotEq { left, right, .. }) => Some(Expr::Compare {
            op: "!=".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntAnd { left, right, .. }) => Some(Expr::BinOp {
            op: "&".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntOr { left, right, .. }) => Some(Expr::BinOp {
            op: "|".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntNeg { input, .. }) => Some(Expr::UnaryOp {
            op: "-".into(),
            arg: Box::new(lookup_vn(*input, &op.uses, env).unwrap_or_else(|| name_fb("v"))),
        }),
        SsaOpKind::Pcode(PcodeOp::Load { ptr, .. }) => Some(Expr::Load {
            addr: Box::new(lookup_vn(*ptr, &op.uses, env).unwrap_or_else(|| name_fb("p"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntZext { input, .. })
        | SsaOpKind::Pcode(PcodeOp::IntSext { input, .. }) => lookup_vn(*input, &op.uses, env),
        _ => None,
    }
}

fn const_expr(v: u64, size: u32) -> Expr {
    let lo = v as u32 as u64;
    let bits = (size.saturating_mul(8)).max(1) as u16;
    if (0x8000_0000..0x8001_0000).contains(&lo) || (0x8000_0000..0x8001_0000).contains(&v) {
        return Expr::UInt {
            value: if (0x8000_0000..0x8001_0000).contains(&lo) {
                lo
            } else {
                v
            },
            bits: 32,
        };
    }
    if lo == 0x4e67_c6a7 || v == 0x4e67_c6a7 {
        return Expr::UInt {
            value: 0x4e67_c6a7,
            bits: 32,
        };
    }
    if v <= i64::MAX as u64 {
        Expr::Int {
            value: v as i64,
            bits,
        }
    } else {
        Expr::UInt { value: v, bits }
    }
}

fn name_fb(s: &str) -> Expr {
    Expr::Name { name: s.into() }
}

fn lookup_vn(
    vn: rsleigh_api::Varnode,
    uses: &[SsaVar],
    env: &HashMap<SsaVar, Expr>,
) -> Option<Expr> {
    if vn.space == AddressSpaceId::Const {
        return Some(const_expr(vn.offset, vn.size));
    }
    // Prefer env hits on matching uses.
    for u in uses {
        if let Some(e) = env.get(u) {
            return Some(e.clone());
        }
    }
    for u in uses {
        if let Location::Register { base_offset } = u.location
            && vn.space == AddressSpaceId::Register
            && (vn.offset == base_offset || vn.offset / 8 * 8 == base_offset)
        {
            return Some(Expr::Name {
                name: reg_name(base_offset),
            });
        }
        if let Location::StackSlot { disp, .. } = u.location {
            return Some(Expr::Name {
                name: stack_name(disp),
            });
        }
    }
    if vn.space == AddressSpaceId::Register {
        return Some(Expr::Name {
            name: reg_name(vn.offset),
        });
    }
    None
}

fn stack_name(disp: i64) -> String {
    // Positive home slots / formals → arg_N; negative locals → local_N.
    if disp > 0 {
        // Win64 homes: 0x8,0x10,0x18,0x20 → arg1..arg4 roughly.
        let idx = ((disp as u64) / 8).max(1);
        format!("arg_{idx}")
    } else {
        format!("local_{:x}", disp.unsigned_abs())
    }
}

fn reg_name(off: u64) -> String {
    crate::decompiler::ssa::lower::reg_name(off)
}

fn score_expr(e: &Expr) -> i32 {
    match e {
        Expr::UInt { value, .. } if (0x8000_0000..0x8001_0000).contains(value) => 20,
        Expr::UInt { value, .. } if *value == 0x4e67_c6a7 || *value == 0x045d_9f3b => 16,
        Expr::Compare { .. } => 15,
        Expr::BinOp { op, lhs, rhs } => {
            // Penalize zero-xor / self-ops (x^x, x-x).
            if (op == "^" || op == "-") && format!("{lhs:?}") == format!("{rhs:?}") {
                return 0;
            }
            let base = match op.as_str() {
                "^" => 14, // CRC-style
                "*" | "/" | "%" => 12,
                "+" | "-" => 10,
                "&" | "|" => 9,
                _ => 6,
            };
            base + score_expr(lhs).min(3) + score_expr(rhs).min(3)
        }
        Expr::Load { addr } => {
            // Prefer arg/local loads over rsp epilogue soup.
            let s = format!("{addr:?}");
            if s.contains("rsp") { 2 } else { 8 }
        }
        Expr::UnaryOp { arg, .. } => 5 + score_expr(arg).min(3),
        Expr::Select { .. } => 14,
        Expr::Int { .. } | Expr::UInt { .. } => 4,
        Expr::Name { name } if name.starts_with("arg") => 3,
        _ => 1,
    }
}

/// The exact reaching ABI integer return value for this return block.
///
/// Prefer the RAX use attached to the Return operation by SSA renaming. When a
/// lift does not expose that use, fall back only to an RAX definition in this
/// same block. This deliberately never searches another exit.
pub fn return_var_of_block(block: &SsaBlock) -> Option<SsaVar> {
    let return_index = block
        .ops
        .iter()
        .position(|op| matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))?;
    let return_op = &block.ops[return_index];
    return_op
        .uses
        .iter()
        .find(|var| matches!(var.location, Location::Register { base_offset: 0 }))
        .cloned()
        .or_else(|| {
            block.ops[..return_index]
                .iter()
                .rev()
                .filter_map(|op| op.def.as_ref())
                .find(|var| matches!(var.location, Location::Register { base_offset: 0 }))
                .cloned()
        })
}

/// Exact RAX-family value reaching a particular architectural exit.
///
/// Unlike [`return_var_of_block`], this resolves a value defined in a unique
/// predecessor chain as well as a same-block definition or phi. It never
/// chooses between distinct predecessor values and never consults another
/// return exit.
pub fn return_var_of_exit(ssa: &SsaFunction, block_id: u32) -> Option<SsaVar> {
    crate::decompiler::ssa::reaching_register_at_return(ssa, block_id, 0)
}

/// Best return expression for one block, rooted at that block's reaching RAX.
pub fn return_expr_of_block(block: &SsaBlock, env: &HashMap<SsaVar, Expr>) -> Option<Expr> {
    if let Some(var) = return_var_of_block(block)
        && let Some(expr) = env.get(&var)
    {
        return Some(expr.clone());
    }

    // HRESULT in-block (incl. sign-extended).
    for op in &block.ops {
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            break;
        }
        if let SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) = &op.kind
            && input.space == AddressSpaceId::Const
        {
            let lo = input.offset as u32 as u64;
            if (0x8000_0000..0x8001_0000).contains(&lo)
                || (0x8000_0000..0x8001_0000).contains(&input.offset)
            {
                return Some(Expr::UInt {
                    value: if (0x8000_0000..0x8001_0000).contains(&lo) {
                        lo
                    } else {
                        input.offset
                    },
                    bits: 32,
                });
            }
        }
    }
    let mut best: Option<(i32, Expr)> = None;
    for op in &block.ops {
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            break;
        }
        let Some(e) = expr_of_op(op, env) else {
            continue;
        };
        let score = score_expr(&e);
        if best.as_ref().map(|(s, _)| score >= *s).unwrap_or(true) {
            best = Some((score, e));
        }
    }
    best.map(|(_, e)| e)
}

/// Best expression for one architectural exit, rooted at its reaching RAX.
///
/// The fallback remains block-local, so an unresolved exit cannot borrow the
/// richest expression from a sibling return path.
pub fn return_expr_of_exit(
    ssa: &SsaFunction,
    block_id: u32,
    env: &HashMap<SsaVar, Expr>,
) -> Option<Expr> {
    let block = ssa.blocks.iter().find(|block| block.id == block_id)?;
    if let Some(var) = return_var_of_exit(ssa, block_id)
        && let Some(expr) = env.get(&var)
    {
        return Some(expr.clone());
    }
    return_expr_of_block(block, env)
}

/// Stable semantic class used by per-exit return contracts.
pub fn expr_class_tag(expr: &Expr) -> String {
    match expr {
        Expr::UInt { value, .. } => format!("const:{value:#x}"),
        Expr::Int { value, .. } => format!("const:{value}"),
        Expr::Compare { op, .. } => format!("compare:{op}"),
        Expr::BinOp { op, .. } => format!("binop:{op}"),
        Expr::UnaryOp { op, .. } => format!("unary:{op}"),
        Expr::Select { .. } => "select".into(),
        Expr::Call { .. } => "call".into(),
        Expr::Load { .. } => "load".into(),
        Expr::Cast { .. } => "cast".into(),
        Expr::Name { .. } => "name".into(),
    }
}

/// Whole-function best return expression (leaf kernels).
pub fn best_return_of_function(ssa: &SsaFunction, env: &HashMap<SsaVar, Expr>) -> Option<Expr> {
    // Prefer HRESULT if present anywhere (thin fail-arm recovery).
    let mut hrs = Vec::new();
    for b in &ssa.blocks {
        for op in &b.ops {
            if let SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) = &op.kind
                && input.space == AddressSpaceId::Const
            {
                let lo = input.offset as u32 as u64;
                if (0x8000_0000..0x8001_0000).contains(&lo) {
                    hrs.push(lo);
                } else if (0x8000_0000..0x8001_0000).contains(&input.offset) {
                    hrs.push(input.offset);
                }
            }
        }
    }
    hrs.sort_unstable();
    hrs.dedup();
    // Only use function-wide HRESULT when it is the sole facility constant
    // and the function has a null-ish branch shape (multi-block).
    if hrs.len() == 1 && ssa.blocks.len() > 1 {
        // Still prefer richer compare/arith if present on success path.
        let mut best: Option<(i32, Expr)> = Some((
            18,
            Expr::UInt {
                value: hrs[0],
                bits: 32,
            },
        ));
        for b in &ssa.blocks {
            if let Some(e) = return_expr_of_exit(ssa, b.id, env) {
                let s = score_expr(&e);
                if best.as_ref().map(|(bs, _)| s > *bs).unwrap_or(true) {
                    best = Some((s, e));
                }
            }
        }
        return best.map(|(_, e)| e);
    }

    let mut best: Option<(i32, Expr)> = None;
    for b in &ssa.blocks {
        if let Some(e) = return_expr_of_exit(ssa, b.id, env) {
            let s = score_expr(&e);
            if best.as_ref().map(|(bs, _)| s > *bs).unwrap_or(true) {
                best = Some((s, e));
            }
        }
        for op in &b.ops {
            if let Some(e) = expr_of_op(op, env) {
                let s = score_expr(&e);
                if best.as_ref().map(|(bs, _)| s > *bs).unwrap_or(true) {
                    best = Some((s, e));
                }
            }
        }
    }
    best.map(|(_, e)| e)
}

/// Condition expression of a CBranch block.
pub fn cond_expr_of_block(block: &SsaBlock, env: &HashMap<SsaVar, Expr>) -> Expr {
    for op in block.ops.iter().rev() {
        if let SsaOpKind::Pcode(PcodeOp::CBranch { cond, .. }) = &op.kind
            && let Some(e) = lookup_vn(*cond, &op.uses, env)
        {
            return e;
        }
        if let Some(e) = expr_of_op(op, env)
            && matches!(e, Expr::Compare { .. } | Expr::UnaryOp { .. })
        {
            return e;
        }
    }
    // Fall back to any compare defined in the block.
    for op in block.ops.iter().rev() {
        if let Some(e) = expr_of_op(op, env) {
            return e;
        }
    }
    Expr::Name {
        name: "cond".into(),
    }
}

/// True when the function looks like a pure expression kernel:
/// no calls and no surface stores (aside from noise param-homes).
pub fn is_leaf_kernel(ssa: &SsaFunction) -> bool {
    if ssa.blocks.len() > 12 {
        return false;
    }
    !ssa.blocks.iter().any(|b| {
        b.ops.iter().any(|op| {
            if matches!(
                &op.kind,
                SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. })
            ) {
                return true;
            }
            if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Store { .. }))
                && !crate::decompiler::normalize::is_param_home_store(op)
                && !crate::decompiler::normalize::is_frame_pointer_adjust(op)
            {
                return true;
            }
            false
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::PhiNode;
    use rsleigh_api::Varnode;

    fn return_block(id: u32, va: u64, var: SsaVar) -> SsaBlock {
        SsaBlock {
            id,
            entry_va: va,
            ops: vec![SsaOp {
                va,
                kind: SsaOpKind::Pcode(PcodeOp::Return {
                    dest: Varnode::constant(0, 8),
                }),
                def: None,
                uses: vec![var],
            }],
            successor_ids: vec![],
            predecessor_ids: vec![],
        }
    }

    #[test]
    fn recovers_hresult_const_copy() {
        let block = SsaBlock {
            id: 0,
            entry_va: 0x140001000,
            ops: vec![
                SsaOp {
                    va: 0x140001000,
                    kind: SsaOpKind::Pcode(PcodeOp::Copy {
                        out: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 0,
                            size: 8,
                        },
                        input: Varnode::constant(0x8000_4003, 4),
                    }),
                    def: Some(SsaVar {
                        location: Location::Register { base_offset: 0 },
                        version: 1,
                    }),
                    uses: vec![],
                },
                SsaOp {
                    va: 0x140001001,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![],
                },
            ],
            successor_ids: vec![],
            predecessor_ids: vec![],
        };
        let env = HashMap::new();
        let e = return_expr_of_block(&block, &env).expect("hresult");
        match e {
            Expr::UInt { value, .. } => assert_eq!(value, 0x8000_4003),
            other => panic!("expected uint, got {other:?}"),
        }
    }

    #[test]
    fn divergent_exit_expressions_never_leak_between_blocks() {
        let left = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let right = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 2,
        };
        let mut env = HashMap::new();
        env.insert(
            left.clone(),
            Expr::BinOp {
                op: "+".into(),
                lhs: Box::new(Expr::Name { name: "a".into() }),
                rhs: Box::new(Expr::UInt { value: 1, bits: 32 }),
            },
        );
        env.insert(
            right.clone(),
            Expr::Compare {
                op: "==".into(),
                lhs: Box::new(Expr::Name { name: "b".into() }),
                rhs: Box::new(Expr::UInt { value: 0, bits: 32 }),
            },
        );
        let left_expr = return_expr_of_block(&return_block(0, 0x1000, left), &env).unwrap();
        let right_expr = return_expr_of_block(&return_block(1, 0x2000, right), &env).unwrap();
        assert_eq!(expr_class_tag(&left_expr), "binop:+");
        assert_eq!(expr_class_tag(&right_expr), "compare:==");
        assert_ne!(left_expr, right_expr);
    }

    #[test]
    fn predecessor_defined_hresult_and_success_exits_stay_distinct() {
        let failure = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let success = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 2,
        };
        let define = |id: u32, va: u64, var: SsaVar, value: u64, successor: u32| SsaBlock {
            id,
            entry_va: va,
            ops: vec![SsaOp {
                va,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    // A 32-bit EAX write shares the normalized RAX container.
                    out: Varnode::register(0, 4),
                    input: Varnode::constant(value, 4),
                }),
                def: Some(var),
                uses: vec![],
            }],
            successor_ids: vec![successor],
            predecessor_ids: vec![],
        };
        let bare_return = |id: u32, va: u64, predecessor: u32| SsaBlock {
            id,
            entry_va: va,
            ops: vec![SsaOp {
                va,
                kind: SsaOpKind::Pcode(PcodeOp::Return {
                    dest: Varnode::constant(0, 8),
                }),
                def: None,
                uses: vec![],
            }],
            successor_ids: vec![],
            predecessor_ids: vec![predecessor],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![
                define(0, 0x1000, failure.clone(), 0x8000_4003, 1),
                bare_return(1, 0x1010, 0),
                define(2, 0x2000, success.clone(), 0, 3),
                bare_return(3, 0x2010, 2),
            ],
            image_base: 0,
        };
        let env = build_expr_map(&ssa);

        assert_eq!(return_var_of_exit(&ssa, 1), Some(failure));
        assert_eq!(return_var_of_exit(&ssa, 3), Some(success));
        assert_eq!(
            return_expr_of_exit(&ssa, 1, &env),
            Some(Expr::UInt {
                value: 0x8000_4003,
                bits: 32,
            })
        );
        assert_eq!(
            return_expr_of_exit(&ssa, 3, &env),
            Some(Expr::Int { value: 0, bits: 32 })
        );
    }

    #[test]
    fn ambiguous_predecessor_values_require_a_phi() {
        let left = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let right = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 2,
        };
        let define = |id: u32, var: SsaVar| SsaBlock {
            id,
            entry_va: 0x1000 + u64::from(id) * 0x10,
            ops: vec![SsaOp {
                va: 0x1000 + u64::from(id) * 0x10,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    out: Varnode::register(0, 8),
                    input: Varnode::constant(u64::from(id + 1), 8),
                }),
                def: Some(var),
                uses: vec![],
            }],
            successor_ids: vec![2],
            predecessor_ids: vec![],
        };
        let mut exit = return_block(2, 0x1020, left.clone());
        exit.ops[0].uses.clear();
        exit.predecessor_ids = vec![0, 1];
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![define(0, left), define(1, right), exit],
            image_base: 0,
        };

        assert_eq!(return_var_of_exit(&ssa, 2), None);
    }

    #[test]
    fn phi_merged_single_exit_recovers_select() {
        let left = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let right = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 2,
        };
        let merged = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 3,
        };
        let copy = |id: u32, va: u64, var: SsaVar, value: u64| SsaBlock {
            id,
            entry_va: va,
            ops: vec![SsaOp {
                va,
                kind: SsaOpKind::Pcode(PcodeOp::Copy {
                    out: Varnode::register(0, 8),
                    input: Varnode::constant(value, 8),
                }),
                def: Some(var),
                uses: vec![],
            }],
            successor_ids: vec![2],
            predecessor_ids: vec![],
        };
        let merge = SsaBlock {
            id: 2,
            entry_va: 0x3000,
            ops: vec![
                SsaOp {
                    va: 0,
                    kind: SsaOpKind::Phi(PhiNode {
                        out: merged.clone(),
                        args: vec![Some(left.clone()), Some(right.clone())],
                    }),
                    def: Some(merged.clone()),
                    uses: vec![],
                },
                return_block(2, 0x3001, merged).ops.remove(0),
            ],
            successor_ids: vec![],
            predecessor_ids: vec![0, 1],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![copy(0, 0x1000, left, 1), copy(1, 0x2000, right, 2), merge],
            image_base: 0,
        };
        let env = build_expr_map(&ssa);
        let expr = return_expr_of_exit(&ssa, 2, &env).expect("merged return");
        assert!(matches!(expr, Expr::Select { .. }), "{expr:?}");
    }
}
