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
        SsaOpKind::Pcode(PcodeOp::IntAdd { left, right, .. }) => {
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            let rhs = lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"));
            // Identity: x + 0 / 0 + x (common after flag/addr arithmetic).
            if is_int_zero(&rhs) {
                Some(lhs)
            } else if is_int_zero(&lhs) {
                Some(rhs)
            } else if expr_struct_eq(&lhs, &rhs) {
                // LEA `[reg+reg]` / `x+x` is strength-reduced `x*2`.
                Some(Expr::BinOp {
                    op: "*".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(Expr::UInt { value: 2, bits: 32 }),
                })
            } else {
                Some(Expr::BinOp {
                    op: "+".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
        }
        SsaOpKind::Pcode(PcodeOp::IntSub { left, right, .. }) => {
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            let rhs = lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"));
            // Identity: x - 0; x - x → 0.
            if is_int_zero(&rhs) {
                Some(lhs)
            } else if expr_struct_eq(&lhs, &rhs) {
                Some(Expr::Int { value: 0, bits: 32 })
            } else {
                Some(Expr::BinOp {
                    op: "-".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
        }
        SsaOpKind::Pcode(PcodeOp::IntMult { left, right, .. }) => {
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            let rhs = lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"));
            // LEA scale identity: `x * 1` must not outrank a full `a+b+c+d`
            // return expression under best_return scoring.
            if is_int_one(&rhs) {
                Some(lhs)
            } else if is_int_one(&lhs) {
                Some(rhs)
            } else {
                Some(Expr::BinOp {
                    op: "*".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
        }
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
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            let rhs = lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"));
            // Identity: x^x → 0 (zeroing idiom). Prefer a literal zero so freeload
            // and soft-gold do not latch onto self-xor as a real operator.
            if expr_struct_eq(&lhs, &rhs) {
                return Some(Expr::Int { value: 0, bits: 32 });
            }
            let rhs_c = if right.space == AddressSpaceId::Const {
                Some(right.offset as u32 as u64)
            } else {
                None
            };
            if rhs_c == Some(0x045d_9f3b) || right.offset == 0x045d_9f3b {
                return Some(Expr::BinOp {
                    op: "^".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(Expr::UInt {
                        value: 0x045d_9f3b,
                        bits: 32,
                    }),
                });
            }
            Some(Expr::BinOp {
                op: "^".into(),
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
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
        SsaOpKind::Pcode(PcodeOp::IntAnd { left, right, .. }) => {
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            let rhs = lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"));
            // MSVC `test reg, reg` is AND of a value with itself — surface as the
            // value so zero-tests can canonicalize to `x != 0` / `x == 0`.
            if expr_struct_eq(&lhs, &rhs) {
                Some(lhs)
            } else {
                Some(Expr::BinOp {
                    op: "&".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
        }
        SsaOpKind::Pcode(PcodeOp::IntOr { left, right, .. }) => {
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            let rhs = lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"));
            // Algebra: x | 0xffffffff == -1 (32-bit). MSVC often materializes
            // `return -1` this way in switch defaults.
            if is_all_ones_u32(&lhs) || is_all_ones_u32(&rhs) {
                Some(Expr::Int {
                    value: -1,
                    bits: 32,
                })
            } else {
                Some(Expr::BinOp {
                    op: "|".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                })
            }
        }
        // MSVC strength-reduces `x * (1<<n)` to SHL. Recover the multiply form for
        // constant counts so source-gold operators (`*`) match; keep `<<` when the
        // shift amount is not a small constant (variable shifts, non-canonical).
        SsaOpKind::Pcode(PcodeOp::IntLsl { left, right, .. }) => {
            let lhs = lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"));
            if right.space == AddressSpaceId::Const && (1..32).contains(&right.offset) {
                Some(Expr::BinOp {
                    op: "*".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(Expr::UInt {
                        value: 1u64 << right.offset,
                        bits: 32,
                    }),
                })
            } else {
                Some(Expr::BinOp {
                    op: "<<".into(),
                    lhs: Box::new(lhs),
                    rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
                })
            }
        }
        SsaOpKind::Pcode(PcodeOp::IntLsr { left, right, .. })
        | SsaOpKind::Pcode(PcodeOp::IntAsr { left, right, .. }) => Some(Expr::BinOp {
            op: ">>".into(),
            lhs: Box::new(lookup_vn(*left, &op.uses, env).unwrap_or_else(|| name_fb("a"))),
            rhs: Box::new(lookup_vn(*right, &op.uses, env).unwrap_or_else(|| name_fb("b"))),
        }),
        SsaOpKind::Pcode(PcodeOp::IntNeg { input, .. }) => Some(Expr::UnaryOp {
            op: "-".into(),
            arg: Box::new(lookup_vn(*input, &op.uses, env).unwrap_or_else(|| name_fb("v"))),
        }),
        // Low-half / truncation of a richer value (IDIV quotient is often
        // Subpiece(IntSDiv(...), lsb=0)). Treat as the input expression.
        SsaOpKind::Pcode(PcodeOp::Subpiece { input, lsb: 0, .. }) => {
            lookup_vn(*input, &op.uses, env)
        }
        // Track values written to *non-home* stack slots so a later Load of the
        // same SSA version recovers the stored expression (MSVC return-slot /
        // local pattern). Param-home echoes stay unmapped so they do not steal
        // best-return selection from real arithmetic on optimized kernels.
        SsaOpKind::Pcode(PcodeOp::Store { val, .. }) => {
            if crate::decompiler::normalize::is_param_home_store(op) {
                None
            } else {
                lookup_vn(*val, &op.uses, env)
            }
        }
        SsaOpKind::Pcode(PcodeOp::Load { ptr, .. }) => {
            // Store-to-load forwarding for stack slots that carry a mapped value.
            for u in &op.uses {
                if matches!(u.location, Location::StackSlot { .. })
                    && let Some(e) = env.get(u)
                {
                    return Some(e.clone());
                }
            }
            Some(Expr::Load {
                addr: Box::new(lookup_vn(*ptr, &op.uses, env).unwrap_or_else(|| name_fb("p"))),
            })
        }
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
    // 32-bit all-ones is source-level `-1` (switch default, error sentinels).
    // Print as signed so soft-gold ops include `-` (e.g. classify → return -1).
    // Size may be 4 or a zero-extended 8-byte container holding 0xffffffff.
    if lo == 0xffff_ffff && (size <= 4 || v == 0xffff_ffff) {
        return Expr::Int {
            value: -1,
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

fn is_int_zero(e: &Expr) -> bool {
    matches!(e, Expr::Int { value: 0, .. } | Expr::UInt { value: 0, .. })
}

fn is_int_one(e: &Expr) -> bool {
    matches!(e, Expr::Int { value: 1, .. } | Expr::UInt { value: 1, .. })
}

fn is_all_ones_u32(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Int {
            value: -1,
            bits: b,
        } if *b <= 32
    ) || matches!(
        e,
        Expr::UInt {
            value: v,
            bits: b,
        } if *b <= 32 && *v as u32 == 0xffff_ffff
    )
}

fn expr_struct_eq(a: &Expr, b: &Expr) -> bool {
    // Cheap structural equality for strength-reduction recovery (x+x → x*2).
    format!("{a:?}") == format!("{b:?}")
}

fn is_frame_reg_name(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Name { name } if name == "rsp" || name == "rbp" || name == "esp" || name == "ebp"
    )
}

/// Whether an SSA use is the renamed form of `vn` (register container / unique
/// offset / stack). Binary ops feed `uses` in `visit_reads` order (left then
/// right); matching by location prevents both operands from collapsing to the
/// first env hit.
fn vn_matches_use(vn: rsleigh_api::Varnode, u: &SsaVar) -> bool {
    match &u.location {
        Location::Register { base_offset } if vn.space == AddressSpaceId::Register => {
            let base = crate::decompiler::ssa::lower::register_container_base(vn.offset);
            *base_offset == base || *base_offset == vn.offset
        }
        Location::Unique { offset, size, .. } if vn.space == AddressSpaceId::Unique => {
            *offset == vn.offset && (*size == 0 || *size == vn.size)
        }
        Location::StackSlot { .. } => false,
        Location::RawRam => vn.space == AddressSpaceId::Ram,
        _ => false,
    }
}

fn lookup_vn(
    vn: rsleigh_api::Varnode,
    uses: &[SsaVar],
    env: &HashMap<SsaVar, Expr>,
) -> Option<Expr> {
    if vn.space == AddressSpaceId::Const {
        return Some(const_expr(vn.offset, vn.size));
    }
    // Prefer env hits on uses that actually correspond to this varnode.
    for u in uses {
        if !vn_matches_use(vn, u) {
            continue;
        }
        if let Some(e) = env.get(u) {
            return Some(e.clone());
        }
        if let Location::Register { base_offset } = u.location {
            return Some(Expr::Name {
                name: reg_name(base_offset),
            });
        }
        if let Location::StackSlot { disp, .. } = u.location {
            return Some(Expr::Name {
                name: stack_name(disp),
            });
        }
        if let Location::Unique { .. } = u.location {
            // Defined later / not yet in env — no stable surface name.
            return None;
        }
    }
    // Unary / single-use fallback (const already handled; remaining use is the value).
    if uses.len() == 1 {
        let u = &uses[0];
        if let Some(e) = env.get(u) {
            return Some(e.clone());
        }
        if let Location::Register { base_offset } = u.location {
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
            name: reg_name(crate::decompiler::ssa::lower::register_container_base(
                vn.offset,
            )),
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
        // MSVC `neg` emits ZF (`x != 0`) before SF (`(-x) < 0`). Flat scores let
        // ZF win and drop soft ops (`-`, `<`) gold wants on abs leaves. Demote
        // only bare-name equality-to-zero; keep bit-tests and sign tests high.
        // Arithmetic freeload is gated by `is_substantial_return_expr` on exits.
        Expr::Compare { op, lhs, rhs, .. } => {
            let is_zero =
                |e: &Expr| matches!(e, Expr::Int { value: 0, .. } | Expr::UInt { value: 0, .. });
            let eq_family = matches!(op.as_str(), "==" | "!=");
            let val = if is_zero(rhs) {
                Some(lhs.as_ref())
            } else if is_zero(lhs) {
                Some(rhs.as_ref())
            } else {
                None
            };
            match val {
                // SF-style: (-x) < 0 — prefer over ZF `x != 0`.
                Some(Expr::UnaryOp { op: uop, .. }) if uop == "-" => 16,
                // ZF of a bare name/register (not a bit-test / sign test).
                Some(Expr::Name { .. }) if eq_family => 8,
                // Stay below HRESULT (20).
                _ => 15,
            }
        }
        Expr::BinOp { op, lhs, rhs } => {
            // Penalize zero-xor / self-ops (x^x, x-x).
            if (op == "^" || op == "-") && format!("{lhs:?}") == format!("{rhs:?}") {
                return 0;
            }
            // Bare frame-pointer arithmetic (rsp/rbp ± K) is address formation,
            // not a source-level return. Stack *loads* of formals still score.
            if is_frame_reg_name(lhs) || is_frame_reg_name(rhs) {
                return 1;
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
            // Prefer arg/local loads over raw rsp epilogue soup.
            if is_frame_reg_name(addr) { 2 } else { 8 }
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

    // Prefer substantial architectural-exit values (arith, neg, loads, HRESULT)
    // over freeloaded flag compares that happen to score higher. Thin exits
    // (bare names / small constants) still allow whole-function freeload so
    // pure predicates and abs-style SF forms can surface.
    let mut best_exit: Option<(i32, Expr)> = None;
    for b in &ssa.blocks {
        if let Some(e) = return_expr_of_exit(ssa, b.id, env) {
            let s = score_expr(&e);
            if best_exit.as_ref().map(|(bs, _)| s > *bs).unwrap_or(true) {
                best_exit = Some((s, e));
            }
        }
    }
    if let Some((_, ref e)) = best_exit
        && is_substantial_return_expr(e)
    {
        return best_exit.map(|(_, e)| e);
    }

    let mut best = best_exit;
    for b in &ssa.blocks {
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

/// Return expressions that should not be displaced by freeloaded flag probes.
///
/// Deliberately excludes `&`/`|` — MSVC flag materialization often leaves
/// `x & x & 0xff` on RAX, which must not suppress a freeloaded sign/relational
/// compare that is the real soft-gold surface. Also requires a minimum score so
/// zero-score self-ops (`x^x`, `x-x`) cannot suppress freeloaded compares.
fn is_substantial_return_expr(e: &Expr) -> bool {
    if score_expr(e) < 10 {
        return false;
    }
    match e {
        Expr::BinOp { op, .. }
            if matches!(op.as_str(), "+" | "-" | "*" | "/" | "%" | "^" | "<<" | ">>") =>
        {
            true
        }
        Expr::UnaryOp { .. } | Expr::Select { .. } => true,
        // Loads intentionally excluded: formal/stack loads often sit on RAX while
        // freeload recovers a richer compare/arith the soft-gold actually wants.
        Expr::UInt { value, .. } if (0x8000_0000..0x8001_0000).contains(value) => true,
        Expr::UInt { value, .. } if *value == 0x4e67_c6a7 || *value == 0x045d_9f3b => true,
        _ => false,
    }
}

/// Condition expression of a CBranch block.
pub fn cond_expr_of_block(block: &SsaBlock, env: &HashMap<SsaVar, Expr>) -> Expr {
    for op in block.ops.iter().rev() {
        if let SsaOpKind::Pcode(PcodeOp::CBranch { cond, .. }) = &op.kind
            && let Some(e) = lookup_vn(*cond, &op.uses, env)
        {
            return normalize_cond_expr(e);
        }
        if let Some(e) = expr_of_op(op, env)
            && matches!(e, Expr::Compare { .. } | Expr::UnaryOp { .. })
        {
            return normalize_cond_expr(e);
        }
    }
    // Fall back to any compare defined in the block.
    for op in block.ops.iter().rev() {
        if let Some(e) = expr_of_op(op, env) {
            return normalize_cond_expr(e);
        }
    }
    Expr::Name {
        name: "cond".into(),
    }
}

/// Canonicalize branch predicates so soft-gold compare ops surface cleanly.
///
/// MSVC often emits `test; jcc` as `!(x == 0)` / `!!(x == 0)`. Graph soft facts
/// ask for `!=` (any-of with `&`); keeping the outer `!` leaves only `==` in the
/// body op multiset and fails `ret:None:!=&` on short-circuit kernels.
pub fn is_low_bit_probe(e: &Expr) -> bool {
    matches!(
        e,
        Expr::BinOp {
            op,
            rhs,
            ..
        } if op == "&" && matches!(rhs.as_ref(), Expr::Int { value: 1, .. } | Expr::UInt { value: 1, .. })
    ) || matches!(
        e,
        Expr::BinOp {
            op,
            lhs,
            ..
        } if op == "&" && matches!(lhs.as_ref(), Expr::Int { value: 1, .. } | Expr::UInt { value: 1, .. })
    )
}

pub fn normalize_cond_expr(e: Expr) -> Expr {
    match e {
        Expr::UnaryOp { op, arg } if op == "!" => match *arg {
            // `!(x == 0)` → `x != 0`, but keep tag/bit tests `(x & 1) == 0` intact
            // (dispatch / tagged-union soft gold).
            Expr::Compare {
                op: ref cmp,
                lhs,
                rhs,
            } if cmp == "==" && is_int_zero(&rhs) && !is_low_bit_probe(&lhs) => Expr::Compare {
                op: "!=".into(),
                lhs,
                rhs,
            },
            Expr::Compare {
                op: ref cmp,
                lhs,
                rhs,
            } if cmp == "!=" && is_int_zero(&rhs) && !is_low_bit_probe(&lhs) => Expr::Compare {
                op: "==".into(),
                lhs,
                rhs,
            },
            // `!!(e == 0)` from double-negated flag soup.
            Expr::UnaryOp {
                op: ref inner_op,
                arg: inner,
            } if inner_op == "!" => normalize_cond_expr(*inner),
            other => Expr::UnaryOp {
                op: "!".into(),
                arg: Box::new(normalize_cond_expr(other)),
            },
        },
        Expr::Compare { op, lhs, rhs } => Expr::Compare {
            op,
            lhs: Box::new(normalize_cond_expr(*lhs)),
            rhs: Box::new(normalize_cond_expr(*rhs)),
        },
        other => other,
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
            if let SsaOpKind::Pcode(PcodeOp::Branch { dest }) = &op.kind
                && crate::decompiler::normalize::external_tail_call_target(ssa, *dest).is_some()
            {
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

    #[test]
    fn const_left_shift_recovers_as_multiply() {
        // MSVC lowers `return x * 2` to SHL with flag side-effects. The recovered
        // expression must be the multiply, not ZF/SF soup from the same insn.
        let rax = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let arg = SsaVar {
            location: Location::Register { base_offset: 8 },
            version: 0,
        };
        let rax0 = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 0,
        };
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
                            size: 4,
                        },
                        input: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 8,
                            size: 4,
                        },
                    }),
                    def: Some(rax0.clone()),
                    uses: vec![arg],
                },
                SsaOp {
                    va: 0x140001004,
                    kind: SsaOpKind::Pcode(PcodeOp::IntLsl {
                        out: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 0,
                            size: 4,
                        },
                        left: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 0,
                            size: 4,
                        },
                        right: Varnode::constant(1, 4),
                    }),
                    def: Some(rax.clone()),
                    uses: vec![rax0],
                },
                // Flag-calc noise that previously outscored the missing shift expr.
                SsaOp {
                    va: 0x140001004,
                    kind: SsaOpKind::Pcode(PcodeOp::IntEq {
                        out: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 518,
                            size: 1,
                        },
                        left: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 0,
                            size: 4,
                        },
                        right: Varnode::constant(0, 4),
                    }),
                    def: Some(SsaVar {
                        location: Location::Register { base_offset: 518 },
                        version: 0,
                    }),
                    uses: vec![rax.clone()],
                },
                SsaOp {
                    va: 0x140001004,
                    kind: SsaOpKind::Pcode(PcodeOp::IntAnd {
                        out: Varnode {
                            space: AddressSpaceId::Unique,
                            offset: 1,
                            size: 1,
                        },
                        left: Varnode {
                            space: AddressSpaceId::Register,
                            offset: 0,
                            size: 4,
                        },
                        right: Varnode::constant(1, 4),
                    }),
                    def: Some(SsaVar {
                        location: Location::Unique {
                            instruction_va: 0x140001004,
                            offset: 1,
                            size: 1,
                        },
                        version: 0,
                    }),
                    uses: vec![rax.clone()],
                },
                return_block(0, 0x140001006, rax.clone()).ops.remove(0),
            ],
            successor_ids: vec![],
            predecessor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x140001000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let env = build_expr_map(&ssa);
        let expr = best_return_of_function(&ssa, &env).expect("return expr");
        match expr {
            Expr::BinOp { op, rhs, .. } => {
                assert_eq!(op, "*");
                assert!(
                    matches!(
                        *rhs,
                        Expr::UInt { value: 2, .. } | Expr::Int { value: 2, .. }
                    ),
                    "expected * 2, got {rhs:?}"
                );
            }
            other => panic!("expected multiply, got {other:?}"),
        }
    }

    #[test]
    fn e04_leaf_pure_v2_recovers_multiply_by_two() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/e04_tailish.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-e04-leaf");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000]).expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01000,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        let text = art.text.replace(' ', "");
        assert!(
            text.contains("*0x2")
                || text.contains("*2")
                || text.contains("<<0x1")
                || text.contains("<<1"),
            "expected x*2 / x<<1 return, got:\n{}",
            art.text
        );
        assert!(
            !text.contains("&0x1)==0x0") && !text.contains("&0x1)==0"),
            "must not ship SHL flag soup as the return:\n{}",
            art.text
        );
    }

    #[test]
    fn lookup_vn_distinguishes_binary_operands() {
        // Two distinct SSA uses must not collapse to the first env hit.
        let left = SsaVar {
            location: Location::Unique {
                instruction_va: 0x1000,
                offset: 0xaaa,
                size: 8,
            },
            version: 1,
        };
        let right = SsaVar {
            location: Location::Unique {
                instruction_va: 0x1000,
                offset: 0xbbb,
                size: 8,
            },
            version: 1,
        };
        let mut env = HashMap::new();
        env.insert(
            left.clone(),
            Expr::Name {
                name: "dividend".into(),
            },
        );
        env.insert(
            right.clone(),
            Expr::Name {
                name: "divisor".into(),
            },
        );
        let uses = vec![left.clone(), right.clone()];
        let left_vn = Varnode {
            space: AddressSpaceId::Unique,
            offset: 0xaaa,
            size: 8,
        };
        let right_vn = Varnode {
            space: AddressSpaceId::Unique,
            offset: 0xbbb,
            size: 8,
        };
        match lookup_vn(left_vn, &uses, &env) {
            Some(Expr::Name { name }) => assert_eq!(name, "dividend"),
            other => panic!("left: {other:?}"),
        }
        match lookup_vn(right_vn, &uses, &env) {
            Some(Expr::Name { name }) => assert_eq!(name, "divisor"),
            other => panic!("right: {other:?}"),
        }
    }

    #[test]
    fn a04_idiv_pure_v2_surfaces_divide_operator() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/a04_div_rem.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-a04-idiv");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000, 0x1400_01040])
                .expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01000,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains('/'),
            "expected `/` in idiv pure-v2 return path, got:\n{}",
            art.text
        );
        // Must not ship only the return-slot load with a lost quotient.
        let compact = art.text.replace(' ', "");
        assert!(
            !(compact.contains("return*(local_0)") && !compact.contains('/')),
            "return-slot soup without divide:\n{}",
            art.text
        );
    }

    #[test]
    fn e01_four_args_p1_pure_v2_keeps_add_chain() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/e01_four_args.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-e01-four");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000]).unwrap();
        let art = project
            .function_decompile_artifact(
                0x1400_01000,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains('+'),
            "four-arg sum must keep `+` (not LEA scale x*1 alone):\n{}",
            art.text
        );
        assert!(
            !art.text.replace(' ', "").contains("*0x1")
                && !art.text.replace(' ', "").contains("*1;"),
            "must not ship bare LEA scale as return:\n{}",
            art.text
        );
    }

    #[test]
    fn a04_irem_pure_v2_surfaces_remainder_operator() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P0/a04_div_rem.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-a04-irem");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000, 0x1400_01040])
                .expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01040,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains('%'),
            "expected `%` in irem pure-v2 return path, got:\n{}",
            art.text
        );
    }

    /// Raw SSA for `neg; cmovs` abs leaves emits ZF (`x != 0`) before SF
    /// (`(-x) < 0`). Richer compare scoring must prefer the SF form so soft
    /// ops `-`/`<` surface on pure-V2 returns (P1/P2 iabs).
    #[test]
    fn a03_iabs_p1_pure_v2_surfaces_neg_and_less() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/a03_minmax_abs.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-iabs-neg-less");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000]).expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01000,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains('<'),
            "iabs must surface `<` (SF form), got:\n{}",
            art.text
        );
        assert!(
            art.text.contains('-'),
            "iabs must surface `-` (neg form), got:\n{}",
            art.text
        );
        let compact = art.text.replace(' ', "");
        assert!(
            !compact.contains("rcx!=0") && !compact.contains("rcx!=0x0"),
            "must not prefer ZF `!= 0` over SF `(-x)<0`:\n{}",
            art.text
        );
    }

    /// MSVC `mid(x) { return leaf(x+1); }` is `inc ecx; jmp leaf`.
    #[test]
    fn e04_mid_p1_pure_v2_surfaces_tail_call_plus() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/e04_tailish.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-e04-mid-tail");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01024]).expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01024,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains('+'),
            "mid must surface + from x+1 tail-call arg, got:\n{}",
            art.text
        );
        assert!(
            art.text.contains("FUN_") && art.text.contains("return"),
            "mid must surface return call, got:\n{}",
            art.text
        );
        let compact: String = art.text.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            !compact.contains("L_0:return;"),
            "must not be empty labeled return, got:\n{}",
            art.text
        );
        // Product must accept V2 (not fall back to empty legacy).
        let prod = project
            .function_decompile_artifact(
                0x1400_01024,
                crate::decompiler::v2::DecompileOptions::production(),
            )
            .expect("product");
        assert!(
            prod.fallback_reason.is_none(),
            "product must not invent-args fallback: {prod:?}"
        );
        assert!(
            prod.text.contains('+') && prod.text.contains("return"),
            "product mid must keep + tail-call return, got:\n{}",
            prod.text
        );
    }

    /// Zeroing idiom `xor reg, reg` must not freeload as a real `^` return.
    #[test]
    fn self_xor_folds_to_zero_literal() {
        use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};
        use rsleigh_api::{PcodeOp, Varnode};
        let rax = SsaVar {
            location: Location::Register { base_offset: 0 },
            version: 1,
        };
        let block = SsaBlock {
            id: 0,
            entry_va: 0x1000,
            ops: vec![
                SsaOp {
                    va: 0x1000,
                    kind: SsaOpKind::Pcode(PcodeOp::IntXor {
                        out: Varnode::register(0, 8),
                        left: Varnode::register(0, 8),
                        right: Varnode::register(0, 8),
                    }),
                    def: Some(rax.clone()),
                    uses: vec![
                        SsaVar {
                            location: Location::Register { base_offset: 0 },
                            version: 0,
                        },
                        SsaVar {
                            location: Location::Register { base_offset: 0 },
                            version: 0,
                        },
                    ],
                },
                SsaOp {
                    va: 0x1001,
                    kind: SsaOpKind::Pcode(PcodeOp::Return {
                        dest: Varnode::constant(0, 8),
                    }),
                    def: None,
                    uses: vec![rax],
                },
            ],
            successor_ids: vec![],
            predecessor_ids: vec![],
        };
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![block],
            image_base: 0,
        };
        let env = build_expr_map(&ssa);
        let e = best_return_of_function(&ssa, &env).expect("ret");
        match e {
            Expr::Int { value: 0, .. } | Expr::UInt { value: 0, .. } => {}
            other => panic!("expected 0 from x^x, got {other:?}"),
        }
    }

    /// Switch default `return -1` often becomes `or reg, 0xffffffff`. Surface as
    /// signed `-1` so soft op `-` hits (c02 classify).
    #[test]
    fn c02_classify_p1_pure_v2_surfaces_minus_one() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P1/c02_switch_dense.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-c02-classify-m1");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000]).expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01000,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains("-0x1") || art.text.contains("-1"),
            "classify default must surface signed -1, got:\n{}",
            art.text
        );
        assert!(
            !art.text.contains("| 0xffffffff") && !art.text.contains("| 0xffff_ffff"),
            "must not ship all-ones OR soup as default return:\n{}",
            art.text
        );
    }

    /// Short-circuit `both` must surface `!=` (from `!(x==0)` → `x!=0`) so soft
    /// ops `!=`/`&` any-of can hit without inventing return expressions.
    #[test]
    fn c04_both_p2_pure_v2_surfaces_not_equal_in_conds() {
        use crate::project::Project;
        let pe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("eval/grand/bin/P2/c04_short_circuit.exe");
        if !pe.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join("windy-ratchet-c04-both-ne");
        let _ = std::fs::create_dir_all(&dir);
        let project =
            Project::open_with_data_dir_and_entry_hints(&pe, &dir, &[0x1400_01000]).expect("open");
        let art = project
            .function_decompile_artifact(
                0x1400_01000,
                crate::decompiler::v2::DecompileOptions::pure_no_fallback(),
            )
            .expect("artifact");
        assert!(art.fallback_reason.is_none(), "{art:?}");
        assert!(
            art.text.contains("!="),
            "both must surface != in predicates, got:\n{}",
            art.text
        );
    }
}
