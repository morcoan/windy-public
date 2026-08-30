//! Conservative type recovery over the optimized SSA (Phase 4 + 4.1).
//!
//! Seed-and-propagate inference over the pruned SSA from
//! [`crate::decompiler::ssa::simplify`]. A *forward* pass seeds types from
//! P-code op semantics (arithmetic→Int, comparisons→Bool, float ops→Float/
//! Double, Copy/phi unify). A *backward* pass derives operand constraints
//! (`Store` ptr → `Ptr(val)`, `Load` ptr → `Ptr(out)`, arithmetic operands →
//! `Int(size)`, Copy input → def type), which types **live-in parameters**
//! (registers/stack-slots with no defining op).
//!
//! Recovered types project onto:
//! * **stack locals/args** — `Location::StackSlot` defs → `StackFrame`;
//! * **parameters** — fastcall GPR live-ins (RCX/RDX/R8/R9), XMM float live-ins,
//!   and cdecl positive-disp stack-slot live-ins;
//! * **return type** — meet of every `Return` register use;
//! * **global candidates** — `RawRam` Store/Load with a typed value, carrying
//!   the defining instruction VA for VA-resolution in the project layer.
//!
//! The pass never edits a `PcodeOp`; it only reads op semantics.

use std::collections::{HashMap, HashSet};

use pcode_ir::AddressSpaceId;
use rsleigh_api::{PcodeOp, Varnode};
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use crate::decompiler::ssa::lower::reg_name;
use crate::decompiler::ssa::{
    Location, SsaFunction, SsaOp, SsaOpKind, SsaVar, lower::register_container_base,
};
use crate::project::types::DataType;

/// A best-effort inferred type used during propagation. `Unknown` is the top;
/// `meet` collapses incompatible concrete guesses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum TyGuess {
    Unknown,
    Int(u8),
    Uint(u8),
    Bool,
    Float,
    Double,
    Ptr(Box<TyGuess>),
}

impl TyGuess {
    fn from_size_signed(size: u32) -> Self {
        Self::Int((size * 8) as u8)
    }
    fn from_size_unsigned(size: u32) -> Self {
        Self::Uint((size * 8) as u8)
    }

    fn is_float(&self) -> bool {
        matches!(self, Self::Float | Self::Double)
    }

    /// Convert to a `DataType`. `Unknown` falls back to an opaque `Unknown(N)`.
    pub fn to_data_type(&self, fallback_bits: u8) -> DataType {
        match self {
            Self::Unknown => DataType::Unknown(fallback_bits / 8),
            Self::Int(b) => DataType::Int(*b),
            Self::Uint(b) => DataType::Uint(*b),
            Self::Bool => DataType::Bool,
            Self::Float => DataType::Float,
            Self::Double => DataType::Double,
            Self::Ptr(inner) => DataType::Ptr(Box::new(inner.to_data_type(fallback_bits))),
        }
    }
}

/// Lattice meet: `Unknown` absorbs; equal guesses agree; differing concrete
/// guesses collapse to `Unknown` (we never invent a type the evidence lacks).
/// Same-width signed/unsigned merges to unsigned (a signed read fits unsigned).
fn meet(a: &TyGuess, b: &TyGuess) -> TyGuess {
    match (a, b) {
        (TyGuess::Unknown, other) | (other, TyGuess::Unknown) => other.clone(),
        (x, y) if x == y => x.clone(),
        (TyGuess::Int(b1), TyGuess::Uint(b2)) | (TyGuess::Uint(b1), TyGuess::Int(b2))
            if b1 == b2 =>
        {
            TyGuess::Uint(*b1)
        }
        _ => TyGuess::Unknown,
    }
}

/// x64 fastcall parameter registers (SLEIGH container bases) → ABI rank.
fn gpr_param_rank(base_offset: u64) -> Option<usize> {
    Some(match base_offset {
        0x08 => 0, // RCX
        0x10 => 1, // RDX
        0x80 => 2, // R8
        0x88 => 3, // R9
        _ => return None,
    })
}

/// Whether a register container base is a frame pointer (RSP/RBP).
fn is_frame_ptr(base_offset: u64) -> bool {
    base_offset == 0x20 || base_offset == 0x28
}

/// A recovered stack-local/arg retype suggestion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StackLocalType {
    pub offset: i64,
    pub ty: TyGuess,
    pub old_ty: TyGuess,
}

/// A recovered parameter type suggestion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParamType {
    pub rank: usize,
    pub ty: TyGuess,
    pub old_ty: TyGuess,
}

/// A recovered function return type (if any Return was seen).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReturnGuess {
    pub ty: TyGuess,
    pub old_ty: TyGuess,
}

/// A global re-typing candidate: a `RawRam` Store/Load whose value has a known
/// type. The instruction VA is used to re-resolve the global VA via the iced
/// instruction's memory operand in the project layer (SSA collapses globals to
/// `RawRam`, losing the VA).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GlobalCandidate {
    pub instruction_va: u64,
    pub ty: TyGuess,
}

/// A call-site type constraint: the callee's parameter types, keyed by the
/// call instruction VA. Used to seed the caller's arg-register lattice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallConstraint {
    pub call_va: u64,
    pub arg_types: Vec<TyGuess>,
}

/// Side-structure: the type-recovery report for one function.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TypeRecoveryReport {
    pub function_va: u64,
    pub locals: Vec<StackLocalType>,
    pub params: Vec<ParamType>,
    pub return_type: Option<ReturnGuess>,
    pub globals: Vec<GlobalCandidate>,
    /// Number of SSA defs that moved off `Unknown`.
    pub typed_def_count: usize,
    /// Number of locals whose recovered type differs from the placeholder.
    pub locals_retyped: usize,
    /// Per-def recovered types for the structurer and LLM export.
    /// Serialized as `[{ "var": "rax_2", "type": "int32" }, ...]`.
    #[serde(serialize_with = "serialize_def_types")]
    pub def_types: HashMap<SsaVar, TyGuess>,
    /// Inferred stack aggregates (Phase 7 B). Not part of lattice equality for
    /// older tests that construct reports by hand — default empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aggregates: Vec<crate::project::types::CompositeType>,
}

fn serialize_def_types<S>(map: &HashMap<SsaVar, TyGuess>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for (var, ty) in map {
        let label = match &var.location {
            Location::Register { base_offset } => {
                format!("{}_{}", reg_name(*base_offset), var.version)
            }
            Location::StackSlot { base_reg, disp } => {
                format!("stack_{:x}{disp:+}_v{}", base_reg, var.version)
            }
            Location::RawRam => format!("ram_v{}", var.version),
            Location::Unique {
                instruction_va,
                offset,
                size,
            } => format!("t_{offset:x}_{size}@{instruction_va:x}_v{}", var.version),
        };
        let ty_str = match ty {
            TyGuess::Unknown => "unknown".to_string(),
            TyGuess::Int(b) => format!("int{b}"),
            TyGuess::Uint(b) => format!("uint{b}"),
            TyGuess::Bool => "bool".to_string(),
            TyGuess::Float => "float".to_string(),
            TyGuess::Double => "double".to_string(),
            TyGuess::Ptr(inner) => {
                // Nested render via Debug for nested ptr depth.
                format!(
                    "{}*",
                    match inner.as_ref() {
                        TyGuess::Unknown => "unknown".to_string(),
                        TyGuess::Int(b) => format!("int{b}"),
                        TyGuess::Uint(b) => format!("uint{b}"),
                        TyGuess::Bool => "bool".to_string(),
                        TyGuess::Float => "float".to_string(),
                        TyGuess::Double => "double".to_string(),
                        TyGuess::Ptr(_) => format!("{inner:?}"),
                    }
                )
            }
        };
        seq.serialize_element(&serde_json::json!({ "var": label, "type": ty_str }))?;
    }
    seq.end()
}

/// Recover types for the function at `va` over its optimized SSA. Read-only —
/// produces a report; persistence is the caller's job (the MCP
/// `apply_type_recovery` tool turns this into an `Op::Batch`).
///
/// `call_constraints` seeds arg-register types at matching call sites from
/// known callee signatures (cross-function propagation).
pub fn recover_types(
    ssa: &SsaFunction,
    function_va: u64,
    bitness: u32,
    call_constraints: &[CallConstraint],
) -> TypeRecoveryReport {
    let ptr_bits = (bitness / 8 * 8) as u8;
    let mut types: HashMap<SsaVar, TyGuess> = HashMap::new();

    // Map each defined SsaVar to a defining op, to identify live-ins (params).
    let mut def_to_op: HashMap<SsaVar, ()> = HashMap::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            if let Some(d) = &op.def {
                def_to_op.insert(d.clone(), ());
            }
        }
    }

    let constraint_by_va: HashMap<u64, &CallConstraint> =
        call_constraints.iter().map(|c| (c.call_va, c)).collect();

    // Forward + backward interleaved fixpoint.
    let mut changed = true;
    let mut guard = 0;
    while changed && guard <= ssa.blocks.len() + 4 {
        changed = false;
        guard += 1;

        // Cross-function: seed arg registers at call sites with known callees.
        if seed_call_constraints(ssa, &constraint_by_va, &mut types) {
            changed = true;
        }

        // Forward: seed def types from op semantics.
        for block in &ssa.blocks {
            for op in &block.ops {
                if let Some(def) = &op.def {
                    let prev = types.get(def).cloned();
                    if let Some(next) = infer_def_type(op, &types, ptr_bits) {
                        let merged = match prev {
                            Some(p) => meet(&p, &next),
                            None => next,
                        };
                        if types.get(def) != Some(&merged) {
                            types.insert(def.clone(), merged);
                            changed = true;
                        }
                    }
                }
            }
        }

        // Backward: derive operand constraints and unify into use types (this
        // types live-in parameters, which have no defining op).
        for block in &ssa.blocks {
            for op in &block.ops {
                for (use_sv, constraint) in operand_constraints(op, &types) {
                    let prev = types.get(&use_sv).cloned().unwrap_or(TyGuess::Unknown);
                    let merged = meet(&prev, &constraint);
                    if merged != prev {
                        types.insert(use_sv, merged);
                        changed = true;
                    }
                }
            }
        }
    }

    // Project onto stack locals/args: StackSlot defs map to frame offsets.
    let mut locals: Vec<StackLocalType> = Vec::new();
    let mut seen_offsets: HashSet<i64> = HashSet::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            if let Some(def) = &op.def
                && let Location::StackSlot { base_reg: _, disp } = def.location
                && seen_offsets.insert(disp)
            {
                let ty = types.get(def).cloned().unwrap_or(TyGuess::Unknown);
                locals.push(StackLocalType {
                    offset: disp,
                    ty,
                    old_ty: TyGuess::Unknown,
                });
            }
        }
    }

    // Project onto parameters: live-in SsaVars (no defining op, version != 0)
    // that are used somewhere. Split into fastcall GPR / XMM_float / stack-arg.
    let live_ins = collect_live_ins(ssa, &def_to_op);
    let mut params: Vec<ParamType> = Vec::new();
    for sv in &live_ins {
        let ty = types.get(sv).cloned().unwrap_or(TyGuess::Unknown);
        let rank = match &sv.location {
            Location::Register { base_offset } => {
                if let Some(r) = gpr_param_rank(*base_offset) {
                    Some(r)
                } else if ty.is_float() && !is_frame_ptr(*base_offset) {
                    // XMM float param: rank by offset (best-effort ordering).
                    Some(0x100 + (*base_offset as usize))
                } else {
                    None
                }
            }
            Location::StackSlot { disp, .. } if *disp > 0 => {
                // cdecl stack arg: rank by disp ascending.
                Some(*disp as usize)
            }
            _ => None,
        };
        if let Some(rank) = rank {
            params.push(ParamType {
                rank,
                ty,
                old_ty: TyGuess::Unknown,
            });
        }
    }
    params.sort_by_key(|p| p.rank);
    // De-duplicate by rank (a live-in may appear via multiple ops).
    params.dedup_by(|a, b| a.rank == b.rank);

    // Project onto the return type: meet every Return op's register uses.
    let mut ret_guess: Option<TyGuess> = None;
    for block in &ssa.blocks {
        for op in &block.ops {
            if let SsaOpKind::Pcode(PcodeOp::Return { .. }) = &op.kind {
                for u in &op.uses {
                    if matches!(u.location, Location::Register { .. }) {
                        let t = types.get(u).cloned().unwrap_or(TyGuess::Unknown);
                        ret_guess = Some(match ret_guess {
                            Some(r) => meet(&r, &t),
                            None => t,
                        });
                    }
                }
            }
        }
    }

    // Project onto global candidates: RawRam Store/Load with a typed value.
    let mut globals: Vec<GlobalCandidate> = Vec::new();
    let mut seen_global_ops: HashSet<u64> = HashSet::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            if seen_global_ops.insert(op.va)
                && let Some(ty) = global_value_type(op, &types)
                && !matches!(ty, TyGuess::Unknown)
            {
                globals.push(GlobalCandidate {
                    instruction_va: op.va,
                    ty,
                });
            }
        }
    }

    let typed_def_count = types
        .values()
        .filter(|t| !matches!(t, TyGuess::Unknown))
        .count();
    let return_type = ret_guess
        .filter(|t| !matches!(t, TyGuess::Unknown))
        .map(|ty| ReturnGuess {
            ty,
            old_ty: TyGuess::Unknown,
        });

    // Phase 7 B: infer stack aggregates from contiguous typed locals.
    let aggregates =
        crate::decompiler::types::aggregate::infer_aggregates(ssa, &locals, function_va);

    TypeRecoveryReport {
        function_va,
        locals,
        params,
        return_type,
        globals,
        typed_def_count,
        locals_retyped: 0,
        def_types: types,
        aggregates,
    }
}

/// Seed arg-register types at call sites whose instruction VA has a known
/// callee signature. Walks each block tracking the current version of each
/// GPR so the constraint attaches to the value holding the argument.
fn seed_call_constraints(
    ssa: &SsaFunction,
    constraint_by_va: &HashMap<u64, &CallConstraint>,
    types: &mut HashMap<SsaVar, TyGuess>,
) -> bool {
    if constraint_by_va.is_empty() {
        return false;
    }
    let mut changed = false;
    for block in &ssa.blocks {
        // base_offset → current version at this program point
        let mut current: HashMap<u64, u32> = HashMap::new();
        for op in &block.ops {
            // Record uses before defs so live-ins establish a version.
            for u in &op.uses {
                if let Location::Register { base_offset } = u.location {
                    current.entry(base_offset).or_insert(u.version);
                }
            }
            if let Some(def) = &op.def
                && let Location::Register { base_offset } = def.location
            {
                current.insert(base_offset, def.version);
            }

            let is_call = matches!(
                &op.kind,
                SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. })
            );
            if !is_call {
                continue;
            }
            let Some(constraint) = constraint_by_va.get(&op.va) else {
                continue;
            };
            for (i, arg_ty) in constraint.arg_types.iter().enumerate() {
                if matches!(arg_ty, TyGuess::Unknown) {
                    continue;
                }
                let Some(base) = param_reg_base(i) else {
                    continue;
                };
                // Prefer the version live just before the call. If the call
                // itself defined a reg (unlikely), we already updated current
                // — re-walk uses is fine; fall back to version 1.
                let ver = current.get(&base).copied().unwrap_or(1);
                let sv = SsaVar {
                    location: Location::Register { base_offset: base },
                    version: ver,
                };
                let prev = types.get(&sv).cloned().unwrap_or(TyGuess::Unknown);
                let merged = meet(&prev, arg_ty);
                if merged != prev {
                    types.insert(sv, merged);
                    changed = true;
                }
            }
        }
    }
    changed
}

fn param_reg_base(rank: usize) -> Option<u64> {
    match rank {
        0 => Some(0x08), // RCX
        1 => Some(0x10), // RDX
        2 => Some(0x80), // R8
        3 => Some(0x88), // R9
        _ => None,
    }
}

/// Convert a project [`DataType`] into a best-effort [`TyGuess`] for lattice seeding.
pub fn data_type_to_ty_guess(dt: &DataType) -> TyGuess {
    match dt {
        DataType::Int(b) => TyGuess::Int(*b),
        DataType::Uint(b) => TyGuess::Uint(*b),
        DataType::Bool => TyGuess::Bool,
        DataType::Float => TyGuess::Float,
        DataType::Double => TyGuess::Double,
        DataType::Ptr(inner) => TyGuess::Ptr(Box::new(data_type_to_ty_guess(inner))),
        DataType::Void
        | DataType::Unknown(_)
        | DataType::Named(_)
        | DataType::Array(_, _)
        | DataType::FuncPtr { .. } => TyGuess::Unknown,
    }
}

/// Collect every SsaVar that is *used* but has no defining op (a live-in /
/// parameter), with version != 0.
fn collect_live_ins(ssa: &SsaFunction, def_to_op: &HashMap<SsaVar, ()>) -> Vec<SsaVar> {
    let mut seen: HashSet<SsaVar> = HashSet::new();
    let mut out: Vec<SsaVar> = Vec::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            for u in &op.uses {
                if u.version != 0 && !def_to_op.contains_key(u) && seen.insert(u.clone()) {
                    out.push(u.clone());
                }
            }
            if let SsaOpKind::Phi(phi) = &op.kind {
                for v in phi.args.iter().flatten() {
                    if v.version != 0 && !def_to_op.contains_key(v) && seen.insert(v.clone()) {
                        out.push(v.clone());
                    }
                }
            }
        }
    }
    out
}

/// Forward: infer the type of an op's def from its semantics + operand types.
fn infer_def_type(op: &SsaOp, types: &HashMap<SsaVar, TyGuess>, ptr_bits: u8) -> Option<TyGuess> {
    let kind = &op.kind;
    let out_size = pcode_out_size(kind).unwrap_or(0);
    match kind {
        SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => {
            Some(varnode_type(*input, &op.uses, types, ptr_bits))
        }
        SsaOpKind::Phi(phi) => {
            let mut acc: Option<TyGuess> = None;
            for v in phi.args.iter().flatten() {
                let t = types.get(v).cloned().unwrap_or(TyGuess::Unknown);
                acc = Some(match acc {
                    Some(a) => meet(&a, &t),
                    None => t,
                });
            }
            acc
        }
        // Comparisons / boolean ops -> Bool.
        SsaOpKind::Pcode(
            PcodeOp::IntEq { .. }
            | PcodeOp::IntNotEq { .. }
            | PcodeOp::IntLess { .. }
            | PcodeOp::IntLessEq { .. }
            | PcodeOp::IntSLess { .. }
            | PcodeOp::IntSLessEq { .. }
            | PcodeOp::IntCarry { .. }
            | PcodeOp::IntSCarry { .. }
            | PcodeOp::IntSBorrow { .. }
            | PcodeOp::BoolAnd { .. }
            | PcodeOp::BoolOr { .. }
            | PcodeOp::BoolXor { .. }
            | PcodeOp::BoolNot { .. }
            | PcodeOp::FloatEq { .. }
            | PcodeOp::FloatNotEq { .. }
            | PcodeOp::FloatLess { .. }
            | PcodeOp::FloatLessEq { .. }
            | PcodeOp::FloatNan { .. },
        ) => Some(TyGuess::Bool),
        // Signed division / remainder → signed result.
        SsaOpKind::Pcode(PcodeOp::IntSDiv { .. } | PcodeOp::IntSRem { .. }) if out_size > 0 => {
            Some(TyGuess::from_size_signed(out_size))
        }
        // Unsigned division / remainder → unsigned result.
        SsaOpKind::Pcode(PcodeOp::IntDiv { .. } | PcodeOp::IntRem { .. }) if out_size > 0 => {
            Some(TyGuess::from_size_unsigned(out_size))
        }
        // Arithmetic shift preserves sign; logical shift is unsigned.
        SsaOpKind::Pcode(PcodeOp::IntAsr { .. }) if out_size > 0 => {
            Some(TyGuess::from_size_signed(out_size))
        }
        SsaOpKind::Pcode(PcodeOp::IntLsr { .. }) if out_size > 0 => {
            Some(TyGuess::from_size_unsigned(out_size))
        }
        // Negation implies signedness.
        SsaOpKind::Pcode(PcodeOp::IntNeg { .. }) if out_size > 0 => {
            Some(TyGuess::from_size_signed(out_size))
        }
        // Other integer arithmetic: conservative signed default (meet resolves).
        SsaOpKind::Pcode(
            PcodeOp::IntAdd { .. }
            | PcodeOp::IntSub { .. }
            | PcodeOp::IntMult { .. }
            | PcodeOp::IntAnd { .. }
            | PcodeOp::IntOr { .. }
            | PcodeOp::IntXor { .. }
            | PcodeOp::IntNot { .. }
            | PcodeOp::IntLsl { .. },
        ) if out_size > 0 => Some(TyGuess::from_size_signed(out_size)),
        // Floating-point arithmetic -> Float/Double by output width.
        SsaOpKind::Pcode(
            PcodeOp::FloatAdd { .. }
            | PcodeOp::FloatSub { .. }
            | PcodeOp::FloatMult { .. }
            | PcodeOp::FloatDiv { .. }
            | PcodeOp::FloatNeg { .. }
            | PcodeOp::FloatAbs { .. }
            | PcodeOp::FloatSqrt { .. }
            | PcodeOp::Int2Float { .. }
            | PcodeOp::Float2Float { .. }
            | PcodeOp::Trunc { .. }
            | PcodeOp::FloatCeil { .. }
            | PcodeOp::FloatFloor { .. }
            | PcodeOp::FloatRound { .. },
        ) if out_size > 0 => {
            if out_size >= 8 {
                Some(TyGuess::Double)
            } else {
                Some(TyGuess::Float)
            }
        }
        SsaOpKind::Pcode(PcodeOp::IntSext { input, .. } | PcodeOp::IntZext { input, .. }) => {
            Some(varnode_type(*input, &op.uses, types, ptr_bits))
        }
        SsaOpKind::Pcode(PcodeOp::Subpiece { input, .. }) => {
            Some(varnode_type(*input, &op.uses, types, ptr_bits))
        }
        // Loads yield a value of the output width (pointee type unknown here).
        SsaOpKind::Pcode(PcodeOp::Load { out, .. }) if out.size > 0 => {
            Some(TyGuess::from_size_unsigned(out.size))
        }
        // Anything else with an output: best-effort unsigned of its width.
        SsaOpKind::Pcode(other) if out_size > 0 => Some(TyGuess::from_size_unsigned(out_size)),
        SsaOpKind::Pcode(_) => None,
    }
}

/// Backward: derive type constraints on an op's operands (uses). Each constraint
/// is a `(SsaVar, TyGuess)` to unify into the lattice — this types live-in
/// parameters, which have no defining op.
fn operand_constraints(op: &SsaOp, types: &HashMap<SsaVar, TyGuess>) -> Vec<(SsaVar, TyGuess)> {
    let mut out: Vec<(SsaVar, TyGuess)> = Vec::new();
    let def_ty = op.def.as_ref().and_then(|d| types.get(d).cloned());

    match &op.kind {
        // Copy: the input inherits the def's type.
        SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => {
            if let Some(u) = use_for_varnode(op, *input)
                && let Some(dt) = &def_ty
            {
                out.push((u.clone(), dt.clone()));
            }
        }
        // Signed binary ops: both operands are Int(width) — strong signed evidence.
        SsaOpKind::Pcode(
            PcodeOp::IntSDiv { left, right, .. }
            | PcodeOp::IntSRem { left, right, .. }
            | PcodeOp::IntSCarry { left, right, .. }
            | PcodeOp::IntSBorrow { left, right, .. }
            | PcodeOp::IntSLess { left, right, .. }
            | PcodeOp::IntSLessEq { left, right, .. }
            | PcodeOp::IntAsr { left, right, .. },
        ) => {
            for vn in [*left, *right] {
                if let Some(u) = use_for_varnode(op, vn) {
                    out.push((u.clone(), TyGuess::from_size_signed(vn.size)));
                }
            }
        }
        // Unsigned binary ops: both operands are Uint(width) — strong unsigned evidence.
        SsaOpKind::Pcode(
            PcodeOp::IntDiv { left, right, .. }
            | PcodeOp::IntRem { left, right, .. }
            | PcodeOp::IntCarry { left, right, .. }
            | PcodeOp::IntLsr { left, right, .. },
        ) => {
            for vn in [*left, *right] {
                if let Some(u) = use_for_varnode(op, vn) {
                    out.push((u.clone(), TyGuess::from_size_unsigned(vn.size)));
                }
            }
        }
        // Neutral binary ops (IntAdd/Sub/Mult/And/Or/Xor/Lsl/Eq/NotEq/Less/LessEq):
        // no signedness constraint — let meet resolve from stronger ops.
        // Unary: IntNeg/IntNot are also neutral for operand constraints.
        // BoolNot / Int2Float / popcount: constrain width as signed convention.
        SsaOpKind::Pcode(
            PcodeOp::BoolNot { input, .. }
            | PcodeOp::Int2Float { input, .. }
            | PcodeOp::Popcount { input, .. }
            | PcodeOp::Lzcount { input, .. },
        ) => {
            let input = *input;
            if let Some(u) = use_for_varnode(op, input) {
                out.push((u.clone(), TyGuess::from_size_signed(input.size)));
            }
        }
        // Store: the pointer operand is a pointer to the stored value's type.
        SsaOpKind::Pcode(PcodeOp::Store { ptr, val, .. }) => {
            let val_ty = use_for_varnode(op, *val).and_then(|u| types.get(u).cloned());
            if let Some(u) = use_for_varnode(op, *ptr) {
                // Register pointer (global): the register holds an address.
                let pointee = val_ty.clone().unwrap_or(TyGuess::Unknown);
                out.push((u.clone(), TyGuess::Ptr(Box::new(pointee))));
            } else if let Some(vt) = &val_ty {
                // Frame-relative: the StackSlot def holds the stored value.
                if let Some(def) = &op.def
                    && matches!(def.location, Location::StackSlot { .. })
                {
                    out.push((def.clone(), vt.clone()));
                }
            }
        }
        // Load: the single use is the resolved pointer location. A StackSlot use
        // holds the loaded value type directly; a Register use holds a pointer.
        SsaOpKind::Pcode(PcodeOp::Load { ptr, .. }) => {
            let _ = ptr;
            if let Some(u) = op.uses.first() {
                let constraint = match &u.location {
                    Location::StackSlot { .. } => def_ty.clone().unwrap_or(TyGuess::Unknown),
                    Location::Register { .. } | Location::Unique { .. } => {
                        // Register or instruction-scoped temp holding the pointer.
                        TyGuess::Ptr(Box::new(def_ty.clone().unwrap_or(TyGuess::Unknown)))
                    }
                    Location::RawRam => def_ty.clone().unwrap_or(TyGuess::Unknown),
                };
                out.push((u.clone(), constraint));
            }
        }
        // Phi: each arg unifies with the def's type.
        SsaOpKind::Phi(phi) => {
            if let Some(dt) = &def_ty {
                for v in phi.args.iter().flatten() {
                    out.push((v.clone(), dt.clone()));
                }
            }
        }
        _ => {}
    }
    out
}

/// Find the SsaVar in `op.uses` whose location matches `vn`.
///
/// Registers match by container base. Instruction-scoped Unique temps match by
/// exact `(instruction_va, offset, size)` so two lifts that reuse a SLEIGH
/// unique offset never alias.
fn use_for_varnode(op: &SsaOp, vn: Varnode) -> Option<&SsaVar> {
    match vn.space {
        AddressSpaceId::Register => {
            let base = register_container_base(vn.offset);
            op.uses.iter().find(|u| match u.location {
                Location::Register { base_offset } => base_offset == base,
                _ => false,
            })
        }
        AddressSpaceId::Unique => op.uses.iter().find(|u| match u.location {
            Location::Unique {
                instruction_va,
                offset,
                size,
            } => instruction_va == op.va && offset == vn.offset && size == vn.size,
            _ => false,
        }),
        _ => None,
    }
}

/// The typed value carried by a RawRam Store/Load (for global candidates).
/// Returns `None` for stack-slot memory.
fn global_value_type(op: &SsaOp, types: &HashMap<SsaVar, TyGuess>) -> Option<TyGuess> {
    match &op.kind {
        SsaOpKind::Pcode(PcodeOp::Store { ptr, val, .. }) => {
            // Only RawRam defs are global candidates (stack slots are locals).
            if let Some(def) = &op.def
                && !matches!(def.location, Location::RawRam)
            {
                return None;
            }
            let _ = ptr;
            use_for_varnode(op, *val).and_then(|u| types.get(u).cloned())
        }
        SsaOpKind::Pcode(PcodeOp::Load { out, .. }) => {
            if let Some(def) = &op.def
                && !matches!(def.location, Location::RawRam)
            {
                return None;
            }
            let _ = out;
            op.def.as_ref().and_then(|d| types.get(d).cloned())
        }
        _ => None,
    }
}

/// Approximate the output (def) varnode size of an op, for width-based seeding.
fn pcode_out_size(kind: &SsaOpKind) -> Option<u32> {
    match kind {
        SsaOpKind::Phi(_) => None,
        SsaOpKind::Pcode(op) => pcode_ir::get_output(op).map(|v| v.size),
    }
}

/// Map a P-code operand varnode to a [`TyGuess`], consulting known def types
/// for register operands (via the SSA `uses` parallel list).
fn varnode_type(
    vn: Varnode,
    uses: &[SsaVar],
    types: &HashMap<SsaVar, TyGuess>,
    _ptr_bits: u8,
) -> TyGuess {
    match vn.space {
        AddressSpaceId::Const => TyGuess::from_size_unsigned(vn.size),
        AddressSpaceId::Register => {
            let base = register_container_base(vn.offset);
            uses.iter()
                .find(|u| match u.location {
                    Location::Register { base_offset } => base_offset == base,
                    _ => false,
                })
                .and_then(|u| types.get(u).cloned())
                .unwrap_or(TyGuess::Unknown)
        }
        AddressSpaceId::Unique => uses
            .iter()
            .find(|u| match u.location {
                Location::Unique { offset, size, .. } => offset == vn.offset && size == vn.size,
                _ => false,
            })
            .and_then(|u| types.get(u).cloned())
            .unwrap_or_else(|| TyGuess::from_size_unsigned(vn.size)),
        AddressSpaceId::Ram => TyGuess::Ptr(Box::new(TyGuess::Unknown)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaOpKind};

    fn reg(offset: u64, version: u32) -> SsaVar {
        SsaVar {
            location: Location::Register {
                base_offset: offset,
            },
            version,
        }
    }

    fn build_single_block(ops: Vec<SsaOp>) -> SsaFunction {
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x1000,
                ops,
                predecessor_ids: vec![],
                successor_ids: vec![],
            }],
            image_base: 0x140000000,
        }
    }

    #[test]
    fn meet_concrete_equal() {
        assert_eq!(meet(&TyGuess::Int(32), &TyGuess::Int(32)), TyGuess::Int(32));
        assert_eq!(meet(&TyGuess::Unknown, &TyGuess::Int(32)), TyGuess::Int(32));
        assert_eq!(
            meet(&TyGuess::Int(32), &TyGuess::Uint(64)),
            TyGuess::Unknown
        );
    }

    #[test]
    fn meet_signs_collapse_to_unsigned() {
        assert_eq!(
            meet(&TyGuess::Int(32), &TyGuess::Uint(32)),
            TyGuess::Uint(32)
        );
    }

    #[test]
    fn meet_float_double_incompatible() {
        assert_eq!(meet(&TyGuess::Float, &TyGuess::Double), TyGuess::Unknown);
    }

    #[test]
    fn to_data_type_preserves_int() {
        assert_eq!(TyGuess::Int(32).to_data_type(64), DataType::Int(32));
        assert_eq!(TyGuess::Bool.to_data_type(64), DataType::Bool);
        assert_eq!(TyGuess::Float.to_data_type(64), DataType::Float);
        assert_eq!(TyGuess::Unknown.to_data_type(64), DataType::Unknown(8));
    }

    #[test]
    fn backward_types_live_in_param() {
        // A live-in RCX (reg 0x08, version 1) is used in IntSLess (signed
        // comparison). The backward pass must type the live-in RCX as Int(32).
        let cmp = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntSLess {
                out: Varnode::register(0x00, 1),
                left: Varnode::register(0x08, 4),
                right: Varnode::register(0x10, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1), reg(0x10, 1)],
        };
        let ssa = build_single_block(vec![cmp]);
        let report = recover_types(&ssa, 0x1000, 64, &[]);
        assert!(
            report
                .params
                .iter()
                .any(|p| p.rank == 0 && matches!(p.ty, TyGuess::Int(32))),
            "RCX live-in should be typed Int(32) via signed comparison: {:?}",
            report.params
        );
    }

    #[test]
    fn signed_ops_constrain_operands_to_int() {
        let cmp = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntSLess {
                out: Varnode::register(0x00, 1),
                left: Varnode::register(0x08, 4),
                right: Varnode::register(0x10, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1), reg(0x10, 1)],
        };
        let ssa = build_single_block(vec![cmp]);
        let report = recover_types(&ssa, 0x1000, 64, &[]);
        let rcx = reg(0x08, 1);
        let rdx = reg(0x10, 1);
        assert_eq!(report.def_types.get(&rcx), Some(&TyGuess::Int(32)));
        assert_eq!(report.def_types.get(&rdx), Some(&TyGuess::Int(32)));
    }

    #[test]
    fn unsigned_div_constrains_operands_to_uint() {
        let div = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntDiv {
                out: Varnode::register(0x00, 4),
                left: Varnode::register(0x08, 4),
                right: Varnode::register(0x10, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1), reg(0x10, 1)],
        };
        let ssa = build_single_block(vec![div]);
        let report = recover_types(&ssa, 0x1000, 64, &[]);
        let rcx = reg(0x08, 1);
        let rdx = reg(0x10, 1);
        assert_eq!(report.def_types.get(&rcx), Some(&TyGuess::Uint(32)));
        assert_eq!(report.def_types.get(&rdx), Some(&TyGuess::Uint(32)));
        // Def result of IntDiv is unsigned.
        assert_eq!(
            report.def_types.get(&reg(0x00, 2)),
            Some(&TyGuess::Uint(32))
        );
    }

    #[test]
    fn mixed_signed_unsigned_meets_to_uint() {
        // Same live-in used in IntSLess (Int) and IntDiv (Uint) → meet → Uint.
        let cmp = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::IntSLess {
                out: Varnode::register(0x00, 1),
                left: Varnode::register(0x08, 4),
                right: Varnode::constant(0, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1)],
        };
        let div = SsaOp {
            va: 0x1004,
            kind: SsaOpKind::Pcode(PcodeOp::IntDiv {
                out: Varnode::register(0x00, 4),
                left: Varnode::register(0x08, 4),
                right: Varnode::constant(2, 4),
            }),
            def: Some(reg(0x00, 3)),
            uses: vec![reg(0x08, 1)],
        };
        let ssa = build_single_block(vec![cmp, div]);
        let report = recover_types(&ssa, 0x1000, 64, &[]);
        let rcx = reg(0x08, 1);
        assert_eq!(
            report.def_types.get(&rcx),
            Some(&TyGuess::Uint(32)),
            "meet(Int, Uint) should be Uint: {:?}",
            report.def_types.get(&rcx)
        );
    }

    #[test]
    fn call_constraint_seeds_arg_register() {
        // Call at 0x1000 with constraint RCX → Int(32). Live-in RCX version 1
        // should be typed from the callee signature.
        let call = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Call {
                dest: Varnode::constant(0x2000, 8),
            }),
            def: None,
            uses: vec![],
        };
        // Use RCX after the call so it's a live-in param of this function.
        let add = SsaOp {
            va: 0x1004,
            kind: SsaOpKind::Pcode(PcodeOp::IntAdd {
                out: Varnode::register(0x00, 4),
                left: Varnode::register(0x08, 4),
                right: Varnode::constant(1, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![reg(0x08, 1)],
        };
        // Also use RCX *before* call so current-version tracking sees it.
        let copy = SsaOp {
            va: 0x0ff0,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x10, 4),
                input: Varnode::register(0x08, 4),
            }),
            def: Some(reg(0x10, 2)),
            uses: vec![reg(0x08, 1)],
        };
        let ssa = build_single_block(vec![copy, call, add]);
        let constraints = [CallConstraint {
            call_va: 0x1000,
            arg_types: vec![TyGuess::Int(32)],
        }];
        let report = recover_types(&ssa, 0x1000, 64, &constraints);
        let rcx = SsaVar {
            location: Location::Register { base_offset: 0x08 },
            version: 1,
        };
        assert!(
            matches!(report.def_types.get(&rcx), Some(TyGuess::Int(32))),
            "call constraint should type RCX_1 as Int(32): {:?}",
            report.def_types.get(&rcx)
        );
    }

    #[test]
    fn backward_store_types_pointer() {
        // Store val=RCX(1) to ptr=mem; the pointer operand's reaching def
        // should become Ptr(Int(32)) if RCX is typed.
        let copy = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x08, 4),
                input: Varnode::constant(42, 4),
            }),
            def: Some(reg(0x08, 2)),
            uses: vec![],
        };
        let store = SsaOp {
            va: 0x1002,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x20, 8),
                val: Varnode::register(0x08, 4),
            }),
            def: Some(SsaVar {
                location: Location::RawRam,
                version: 1,
            }),
            uses: vec![reg(0x08, 2), reg(0x20, 1)],
        };
        let ssa = build_single_block(vec![copy, store]);
        let report = recover_types(&ssa, 0x1000, 64, &[]);
        assert!(
            report.globals.iter().any(|g| g.instruction_va == 0x1002),
            "store should produce a global candidate"
        );
    }

    #[test]
    fn stack_arg_param_typed() {
        // A Load from a positive-disp StackSlot (arg) types the stack-slot
        // live-in as its loaded width.
        let load = SsaOp {
            va: 0x1000,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::register(0x28, 8),
            }),
            def: Some(reg(0x00, 2)),
            // The pointer is the frame pointer RBP (0x28) live-in version 1
            // resolving to StackSlot { disp: +8 }.
            uses: vec![SsaVar {
                location: Location::StackSlot {
                    base_reg: 0x28,
                    disp: 8,
                },
                version: 1,
            }],
        };
        let ssa = build_single_block(vec![load]);
        let report = recover_types(&ssa, 0x1000, 64, &[]);
        assert!(
            report
                .params
                .iter()
                .any(|p| matches!(p.ty, TyGuess::Uint(32))),
            "positive-disp stack-slot live-in should be a typed param: {:?}",
            report.params
        );
    }

    #[test]
    fn sample_exe_recovers_some_types() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/eval/fixtures/pe/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = crate::project::Project::open(path).expect("open sample.exe");

        let mut total_typed = 0usize;
        let mut saw_return_guess = false;
        let mut saw_local_typed = false;
        let mut saw_param_typed = false;
        let mut saw_global_candidate = false;
        for f in project.functions().iter() {
            let report = match project.function_types_recovered(f.entry_va) {
                Some(r) => r,
                None => continue,
            };
            total_typed += report.typed_def_count;
            if report.return_type.is_some() {
                saw_return_guess = true;
            }
            if report
                .locals
                .iter()
                .any(|l| !matches!(l.ty, TyGuess::Unknown))
            {
                saw_local_typed = true;
            }
            if report
                .params
                .iter()
                .any(|p| !matches!(p.ty, TyGuess::Unknown))
            {
                saw_param_typed = true;
            }
            if !report.globals.is_empty() {
                saw_global_candidate = true;
            }
        }
        assert!(total_typed > 0, "expected typed defs");
        assert!(
            saw_return_guess || saw_local_typed,
            "expected a recovered return type or typed local"
        );
        assert!(saw_param_typed, "expected at least one typed parameter");
        assert!(
            saw_global_candidate,
            "expected at least one global re-typing candidate"
        );
    }
}
