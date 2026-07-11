//! Native pseudo-C emission over optimized SSA — Phase 5.1 (full DREAM).
//!
//! Recursively walks classified regions (if/else, while, do-while, switch)
//! using the post-dominator tree. Gotos remain only for irreducible edges.
//! Single-use SSA expression folding is unchanged from the MVP.

use std::collections::{HashMap, HashSet};

use pcode_ir::AddressSpaceId;
use rsleigh_api::{PcodeOp, Varnode};

use crate::decompiler::ssa::lower::reg_name;
use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};
use crate::decompiler::types::TyGuess;
use crate::project::types::{FunctionSignature, StackFrame};

use super::pdom::{adj_from_ssa, analyze as analyze_pdom};
use super::region::{Region, SwitchInfo, cbranch_fall_taken, classify, detect_short_circuit};

/// Naming context for the native structurer: stack frame, signature params,
/// and global symbol names.
pub struct NameCtx<'a> {
    pub frame: Option<&'a StackFrame>,
    pub sig: Option<&'a FunctionSignature>,
    /// VA → annotated symbol name (from [`crate::ir::annotate::build_global_names`]).
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

/// SSA variables proved to occupy Windows x64 argument registers at a call.
///
/// P-code call operations do not themselves list ABI inputs, so this is built
/// from the semantic HIR bridge rather than by guessing from the native
/// printer.  The map is keyed by the exact block-local SSA operation position,
/// not by instruction VA: one machine instruction can lower to several P-code
/// operations.
#[derive(Default)]
struct RecoveredCallArguments {
    by_operation: HashMap<crate::decompiler::hir::SsaOperationKey, Vec<SsaVar>>,
}

impl RecoveredCallArguments {
    /// Recover only the register arguments that HIR can trace under the Win64
    /// ABI.  x86 keeps the old conservative printer path until it has its own
    /// calling-convention lifting pass.
    fn from_ssa(ssa: &SsaFunction, bitness: u32) -> Self {
        if bitness != 64 {
            return Self::default();
        }

        let mut lowering = crate::decompiler::hir::HirFunction::lower_from_ssa(ssa);
        lowering.lift_win64_calls(ssa);

        let ssa_by_value: HashMap<_, _> = lowering
            .values
            .iter()
            .map(|(ssa_var, value)| (*value, ssa_var.clone()))
            .collect();
        let mut by_operation = HashMap::new();

        for (key, call_id) in &lowering.call_sites {
            let Some(required_positions) = required_direct_win64_argument_positions(ssa, *key)
            else {
                continue;
            };
            if required_positions.is_empty() {
                // A known zero-argument contract is not yet distinguished from
                // an unresolved call by the native printer, so retain the
                // explicit opaque form rather than claim `target()` here.
                continue;
            }
            let Some(call) = lowering.hir.call_site(*call_id) else {
                continue;
            };
            let by_position = call
                .arguments
                .iter()
                .filter_map(|argument| {
                    ssa_by_value
                        .get(&argument.value)
                        .cloned()
                        .map(|variable| (argument.position, variable))
                })
                .collect::<HashMap<_, _>>();
            let arguments = required_positions
                .iter()
                .map(|position| by_position.get(position).cloned())
                .collect::<Option<Vec<_>>>();

            // Do not turn a partial HIR observation into a shorter, false
            // C-style call.  The native emitter only consumes a complete,
            // contiguous call contract; partial facts remain structured.
            if let Some(arguments) = arguments {
                by_operation.insert(*key, arguments);
            }
        }

        Self { by_operation }
    }

    fn arguments_for(&self, block_id: u32, operation_index: usize) -> Option<&[SsaVar]> {
        let operation_index = u32::try_from(operation_index).ok()?;
        self.by_operation
            .get(&crate::decompiler::hir::SsaOperationKey {
                block_id,
                operation_index,
            })
            .map(Vec::as_slice)
    }
}

/// Return all required logical GPR slots for a direct call whose SSA use list
/// was populated from a resolved Win64 ABI contract.  `None` means no safe
/// native call rendering (unknown/indirect/non-contiguous contract).
fn required_direct_win64_argument_positions(
    ssa: &SsaFunction,
    key: crate::decompiler::hir::SsaOperationKey,
) -> Option<Vec<u16>> {
    const WIN64_GPR_ARGUMENT_BASES: [u64; 4] = [0x08, 0x10, 0x80, 0x88];

    let operation = ssa
        .blocks
        .get(key.block_id as usize)?
        .ops
        .get(key.operation_index as usize)?;
    if !matches!(&operation.kind, SsaOpKind::Pcode(PcodeOp::Call { .. })) {
        return None;
    }

    let positions = WIN64_GPR_ARGUMENT_BASES
        .iter()
        .enumerate()
        .filter_map(|(position, base_offset)| {
            operation
                .uses
                .iter()
                .any(|use_var| {
                    matches!(use_var.location, Location::Register { base_offset: base } if base == *base_offset)
                })
                .then_some(position as u16)
        })
        .collect::<Vec<_>>();
    if positions
        .iter()
        .enumerate()
        .any(|(expected, actual)| *actual != expected as u16)
    {
        return None;
    }
    Some(positions)
}

/// Render `ssa` to structured C-ish pseudo-code. `switches` supplies resolved
/// jump-table case values (may be empty).
pub fn decompile(
    ssa: &SsaFunction,
    types: Option<&crate::decompiler::types::TypeRecoveryReport>,
    sig: Option<&FunctionSignature>,
    bitness: u32,
    switches: &[SwitchInfo],
    names: &NameCtx<'_>,
) -> String {
    let flat = flatten(ssa);
    let call_arguments = RecoveredCallArguments::from_ssa(ssa, bitness);
    let use_count = count_uses(ssa);
    let inline_exprs = build_inline_exprs(&flat, &use_count, names);
    let regions = classify(ssa, switches);
    let (_ipdom, _pdt_children, ve) = analyze_pdom(ssa);
    let (_succ, _pred) = adj_from_ssa(ssa);

    let mut out = String::new();
    let (ret, name, params) = render_signature(sig, ssa.entry_va);
    out.push_str(&format!("{} {}({}) {{\n", ret, name, params));

    // Phase 7 B: document inferred stack aggregates for the LLM.
    if let Some(report) = types {
        for agg in &report.aggregates {
            out.push_str(&format!(
                "    // struct {} {{ /* {} fields, {} bytes */ }}\n",
                agg.name,
                agg.fields.len(),
                agg.size
            ));
            if let Some(base) = crate::decompiler::types::aggregate::aggregate_base_offsets(
                &report.locals,
                std::slice::from_ref(agg),
            )
            .into_iter()
            .next()
            {
                for (i, f) in agg.fields.iter().enumerate() {
                    let abs = base.0 + f.offset as i64;
                    out.push_str(&format!(
                        "    // local_{:x} is field {i} of struct {}\n",
                        abs.unsigned_abs(),
                        agg.name
                    ));
                }
            }
        }
    }

    let mut emitted = HashSet::new();
    let mut ctx = EmitCtx {
        ssa,
        regions: &regions,
        inline_exprs: &inline_exprs,
        types,
        names,
        call_arguments: &call_arguments,
        ve,
        indent: 1,
    };

    if !ssa.blocks.is_empty() {
        emit_region(&mut out, &mut ctx, &mut emitted, 0, ve);
    }

    // Any remaining unreachable-from-entry (or irreducible) blocks: emit flat.
    for i in 0..ssa.blocks.len() as u32 {
        if !emitted.contains(&i) {
            emit_flat_block(&mut out, &mut ctx, &mut emitted, i);
        }
    }

    out.push_str("}\n");

    // S6: goto minimization.
    minimize_gotos(&out)
}

struct EmitCtx<'a> {
    ssa: &'a SsaFunction,
    regions: &'a HashMap<u32, Region>,
    inline_exprs: &'a HashMap<SsaVar, String>,
    types: Option<&'a crate::decompiler::types::TypeRecoveryReport>,
    names: &'a NameCtx<'a>,
    call_arguments: &'a RecoveredCallArguments,
    ve: u32,
    indent: usize,
}

fn ind(n: usize) -> String {
    "    ".repeat(n)
}

/// Recursively emit from `entry` until `stop` (exclusive). Each real block is
/// emitted at most once (`emitted` set).
fn emit_region(
    out: &mut String,
    ctx: &mut EmitCtx<'_>,
    emitted: &mut HashSet<u32>,
    entry: u32,
    stop: u32,
) {
    let mut current = Some(entry);
    while let Some(b) = current {
        if b == stop || b == ctx.ve {
            break;
        }
        if b as usize >= ctx.ssa.blocks.len() {
            break;
        }
        if emitted.contains(&b) {
            // Already emitted elsewhere — need a goto to reach it.
            let va = ctx.ssa.blocks[b as usize].entry_va;
            out.push_str(&format!("{}goto L_{:#x};\n", ind(ctx.indent), va));
            break;
        }

        let block = &ctx.ssa.blocks[b as usize];
        // Label only when this block is a goto target (multi-pred or later pass).
        // Always emit a label for now; S6 strips unused ones.
        out.push_str(&format!("{}L_{:#x}:\n", ind(ctx.indent), block.entry_va));
        emitted.insert(b);

        emit_block_statements(
            out,
            block,
            ctx.inline_exprs,
            ctx.types,
            ctx.names,
            ctx.call_arguments,
            ctx.indent,
        );

        // Short-circuit &&/|| (S5) — best-effort before region match.
        if let Some((op, _b2, _shared, true_tgt)) = detect_short_circuit(block, ctx.ssa)
            && let Some((c1, c2_block)) = short_circuit_conds(block, ctx)
        {
            let c2 = cond_of_block(
                &ctx.ssa.blocks[c2_block as usize],
                ctx.inline_exprs,
                ctx.names,
            )
            .unwrap_or_else(|| "/*c2*/".into());
            out.push_str(&format!(
                "{}if ({} {} {}) {{\n",
                ind(ctx.indent),
                c1,
                op,
                c2
            ));
            // Mark the second CBranch as emitted (its cond was folded).
            emitted.insert(c2_block);
            ctx.indent += 1;
            // Emit true path until shared false / merge.
            let merge = ctx
                .regions
                .get(&b)
                .and_then(|r| match r {
                    Region::IfElse { merge, .. } | Region::If { merge, .. } => Some(*merge),
                    _ => None,
                })
                .unwrap_or(true_tgt);
            // true_tgt may be the body; walk from true_tgt to merge.
            if !emitted.contains(&true_tgt) && true_tgt != merge {
                emit_region(out, ctx, emitted, true_tgt, merge);
            }
            ctx.indent -= 1;
            out.push_str(&format!("{}}}\n", ind(ctx.indent)));
            current = if merge != ctx.ve && (merge as usize) < ctx.ssa.blocks.len() {
                Some(merge)
            } else {
                None
            };
            continue;
        }

        match ctx.regions.get(&b).cloned() {
            Some(Region::Return) => {
                emit_return(out, block, ctx.inline_exprs, ctx.names, ctx.indent);
                current = None;
            }
            Some(Region::IfElse {
                then_entry,
                else_entry,
                merge,
            }) => {
                let cond = cond_of_block(block, ctx.inline_exprs, ctx.names)
                    .unwrap_or_else(|| "/*cond*/".into());
                out.push_str(&format!("{}if ({}) {{\n", ind(ctx.indent), cond));
                ctx.indent += 1;
                if then_entry != merge {
                    emit_region(out, ctx, emitted, then_entry, merge);
                }
                ctx.indent -= 1;
                out.push_str(&format!("{}}} else {{\n", ind(ctx.indent)));
                ctx.indent += 1;
                if else_entry != merge {
                    emit_region(out, ctx, emitted, else_entry, merge);
                }
                ctx.indent -= 1;
                out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                current = next_after_merge(merge, ctx);
            }
            Some(Region::If {
                body_entry,
                merge,
                invert,
            }) => {
                let cond = cond_of_block(block, ctx.inline_exprs, ctx.names)
                    .unwrap_or_else(|| "/*cond*/".into());
                let cond = if invert { format!("!({cond})") } else { cond };
                out.push_str(&format!("{}if ({}) {{\n", ind(ctx.indent), cond));
                ctx.indent += 1;
                if body_entry != merge {
                    emit_region(out, ctx, emitted, body_entry, merge);
                }
                ctx.indent -= 1;
                out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                current = next_after_merge(merge, ctx);
            }
            Some(Region::While { body_entry, exit }) => {
                let cond = while_cond(block, body_entry, ctx.inline_exprs, ctx.names);
                out.push_str(&format!("{}while ({}) {{\n", ind(ctx.indent), cond));
                ctx.indent += 1;
                // Body stops at header `b` so the back edge does not re-emit.
                if body_entry != b {
                    emit_region(out, ctx, emitted, body_entry, b);
                }
                ctx.indent -= 1;
                out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                current = next_after_merge(exit, ctx);
            }
            Some(Region::DoWhile {
                body_entry,
                cond_block,
                exit,
            }) => {
                out.push_str(&format!("{}do {{\n", ind(ctx.indent)));
                ctx.indent += 1;
                if body_entry == cond_block {
                    // Self-loop: statements already emitted above; body is empty
                    // relative to the condition (stmts sit before the CBranch).
                } else {
                    // Emit from body until cond_block (exclusive of re-emitting header).
                    emit_region(out, ctx, emitted, body_entry, cond_block);
                    // Emit cond_block statements (not its terminator).
                    if !emitted.contains(&cond_block) {
                        let cb = &ctx.ssa.blocks[cond_block as usize];
                        out.push_str(&format!("{}L_{:#x}:\n", ind(ctx.indent), cb.entry_va));
                        emitted.insert(cond_block);
                        emit_block_statements(
                            out,
                            cb,
                            ctx.inline_exprs,
                            ctx.types,
                            ctx.names,
                            ctx.call_arguments,
                            ctx.indent,
                        );
                    }
                }
                ctx.indent -= 1;
                let cond = cond_of_block(
                    &ctx.ssa.blocks[cond_block as usize],
                    ctx.inline_exprs,
                    ctx.names,
                )
                .unwrap_or_else(|| "/*cond*/".into());
                // Invert if the back edge is the fallthrough (cond false → loop).
                let cond =
                    do_while_cond_str(&ctx.ssa.blocks[cond_block as usize], body_entry, &cond);
                out.push_str(&format!("{}}} while ({});\n", ind(ctx.indent), cond));
                current = next_after_merge(exit, ctx);
            }
            Some(Region::Switch { cases, merge }) => {
                let val = switch_val(block, ctx.inline_exprs, ctx.names);
                out.push_str(&format!("{}switch ({}) {{\n", ind(ctx.indent), val));
                for (case_val, target) in &cases {
                    out.push_str(&format!("{}case {}:\n", ind(ctx.indent), case_val));
                    ctx.indent += 1;
                    if *target != merge && !emitted.contains(target) {
                        emit_region(out, ctx, emitted, *target, merge);
                    } else if emitted.contains(target) {
                        let va = ctx.ssa.blocks[*target as usize].entry_va;
                        out.push_str(&format!("{}goto L_{:#x};\n", ind(ctx.indent), va));
                    }
                    out.push_str(&format!("{}break;\n", ind(ctx.indent)));
                    ctx.indent -= 1;
                }
                out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                current = next_after_merge(merge, ctx);
            }
            None => {
                // Straight-line / unstructured terminator.
                current = emit_unstructured_term(out, ctx, emitted, b, stop);
            }
        }
    }
}

fn next_after_merge(merge: u32, ctx: &EmitCtx<'_>) -> Option<u32> {
    if merge == ctx.ve || merge as usize >= ctx.ssa.blocks.len() {
        None
    } else {
        Some(merge)
    }
}

fn emit_unstructured_term(
    out: &mut String,
    ctx: &EmitCtx<'_>,
    emitted: &HashSet<u32>,
    b: u32,
    stop: u32,
) -> Option<u32> {
    let block = &ctx.ssa.blocks[b as usize];
    let succs = &block.successor_ids;

    // Return without Region::Return (shouldn't happen often).
    if block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
    {
        emit_return(out, block, ctx.inline_exprs, ctx.names, ctx.indent);
        return None;
    }

    match succs.len() {
        0 => None,
        1 => {
            let s = succs[0];
            if s == stop || s == ctx.ve {
                return None;
            }
            if emitted.contains(&s) {
                let va = ctx.ssa.blocks[s as usize].entry_va;
                out.push_str(&format!("{}goto L_{:#x};\n", ind(ctx.indent), va));
                None
            } else {
                // Fall through into successor (no goto; label still present).
                Some(s)
            }
        }
        _ => {
            // Multi-way unstructured: goto each successor.
            for &s in succs {
                if s == stop || s as usize >= ctx.ssa.blocks.len() {
                    continue;
                }
                let va = ctx.ssa.blocks[s as usize].entry_va;
                out.push_str(&format!("{}goto L_{:#x};\n", ind(ctx.indent), va));
            }
            None
        }
    }
}

fn emit_flat_block(out: &mut String, ctx: &mut EmitCtx<'_>, emitted: &mut HashSet<u32>, b: u32) {
    if emitted.contains(&b) {
        return;
    }
    emit_region(out, ctx, emitted, b, ctx.ve);
}

fn emit_return(
    out: &mut String,
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    indent: usize,
) {
    // Prefer the last def of RAX/EAX (ABI integer return) before the Return.
    // Return p-code only carries the return *address*, not the value.
    let mut rax_rv: Option<String> = None;
    let mut term_va = 0u64;
    for op in &block.ops {
        if let Some(def) = &op.def
            && matches!(def.location, Location::Register { base_offset: 0 })
        {
            rax_rv = Some(
                inline_exprs
                    .get(def)
                    .cloned()
                    .unwrap_or_else(|| name_of(def, names, Some(op.va))),
            );
        }
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            term_va = op.va;
            break;
        }
    }
    if let Some(rv) = rax_rv.filter(|s| !s.is_empty()) {
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }
    // Fallback: any register use on the Return (legacy).
    let mut term = None;
    for op in &block.ops {
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            term = Some(op);
        }
    }
    let rv = term
        .map(|term| {
            term.uses
                .iter()
                .find(|u| matches!(u.location, Location::Register { base_offset: 0 }))
                .or_else(|| {
                    term.uses
                        .iter()
                        .find(|u| matches!(u.location, Location::Register { .. }))
                })
                .map(|u| {
                    inline_exprs
                        .get(u)
                        .cloned()
                        .unwrap_or_else(|| name_of(u, names, Some(term.va)))
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    if rv.is_empty() {
        let _ = term_va;
        out.push_str(&format!("{}return;\n", ind(indent)));
    } else {
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
    }
}

fn cond_of_block(
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
) -> Option<String> {
    for op in &block.ops {
        if let SsaOpKind::Pcode(PcodeOp::CBranch { cond, .. }) = &op.kind {
            return Some(render_varnode(*cond, &op.uses, inline_exprs, names, op.va));
        }
    }
    None
}

/// While condition: if the body is the fallthrough arm, invert the cond
/// (`if (cond) goto exit; fall body` → `while (!cond)`).
fn while_cond(
    block: &SsaBlock,
    body_entry: u32,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
) -> String {
    let cond = cond_of_block(block, inline_exprs, names).unwrap_or_else(|| "/*cond*/".into());
    if let Some((fall, _taken)) = cbranch_fall_taken(block)
        && fall == body_entry
    {
        return format!("!({cond})");
    }
    cond
}

fn do_while_cond_str(cond_block: &SsaBlock, body_entry: u32, cond: &str) -> String {
    // Back edge on fallthrough means we loop when cond is false → invert.
    if let Some((fall, taken)) = cbranch_fall_taken(cond_block)
        && fall == body_entry
        && taken != body_entry
    {
        return format!("!({cond})");
    }
    cond.to_string()
}

fn switch_val(
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
) -> String {
    for op in &block.ops {
        if let SsaOpKind::Pcode(PcodeOp::BranchInd { dest }) = &op.kind {
            return render_varnode(*dest, &op.uses, inline_exprs, names, op.va);
        }
    }
    "/*switch*/".to_string()
}

fn short_circuit_conds(b1: &SsaBlock, ctx: &EmitCtx<'_>) -> Option<(String, u32)> {
    let sc = detect_short_circuit(b1, ctx.ssa)?;
    let c1 = cond_of_block(b1, ctx.inline_exprs, ctx.names)?;
    Some((c1, sc.1))
}

// ─── Expression folding (unchanged from MVP) ────────────────────────────────

struct Flat {
    ops: Vec<(SsaOp, u32)>,
}

fn flatten(ssa: &SsaFunction) -> Flat {
    let mut ops = Vec::new();
    for (bi, block) in ssa.blocks.iter().enumerate() {
        for op in &block.ops {
            ops.push((op.clone(), bi as u32));
        }
    }
    Flat { ops }
}

fn count_uses(ssa: &SsaFunction) -> HashMap<SsaVar, usize> {
    let mut counts: HashMap<SsaVar, usize> = HashMap::new();
    for block in &ssa.blocks {
        for op in &block.ops {
            for u in &op.uses {
                *counts.entry(u.clone()).or_default() += 1;
            }
            if let SsaOpKind::Phi(phi) = &op.kind {
                for v in phi.args.iter().flatten() {
                    *counts.entry(v.clone()).or_default() += 1;
                }
            }
        }
    }
    counts
}

fn build_inline_exprs(
    flat: &Flat,
    use_count: &HashMap<SsaVar, usize>,
    names: &NameCtx<'_>,
) -> HashMap<SsaVar, String> {
    let mut out: HashMap<SsaVar, String> = HashMap::new();
    for (op, _) in &flat.ops {
        if let Some(def) = &op.def
            && is_inlineable(op)
            && use_count.get(def).copied().unwrap_or(0) == 1
        {
            let expr = render_op_expr(op, &out, names);
            out.insert(def.clone(), expr);
        }
    }
    out
}

fn is_inlineable(op: &SsaOp) -> bool {
    !matches!(&op.kind, SsaOpKind::Phi(_))
        && !matches!(
            &op.kind,
            SsaOpKind::Pcode(
                PcodeOp::Store { .. }
                    | PcodeOp::Load { .. }
                    | PcodeOp::Branch { .. }
                    | PcodeOp::CBranch { .. }
                    | PcodeOp::BranchInd { .. }
                    | PcodeOp::Call { .. }
                    | PcodeOp::CallInd { .. }
                    | PcodeOp::Return { .. }
                    | PcodeOp::CallOther { .. }
            )
        )
}

fn emit_block_statements(
    out: &mut String,
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    types: Option<&crate::decompiler::types::TypeRecoveryReport>,
    names: &NameCtx<'_>,
    call_arguments: &RecoveredCallArguments,
    indent: usize,
) {
    let pad = ind(indent);
    for (operation_index, op) in block.ops.iter().enumerate() {
        if is_terminator(op) {
            continue;
        }
        if let SsaOpKind::Phi(phi) = &op.kind {
            if let Some(def) = &op.def {
                let args: Vec<String> = phi
                    .args
                    .iter()
                    .map(|a| match a {
                        Some(v) => name_of(v, names, Some(op.va)),
                        None => "_".to_string(),
                    })
                    .collect();
                let lhs = typed_lhs(def, types, names, op.va);
                out.push_str(&format!("{}{} = phi({});\n", pad, lhs, args.join(", ")));
            }
            continue;
        }
        match &op.kind {
            SsaOpKind::Pcode(PcodeOp::Store { ptr, val, .. }) => {
                let p = render_varnode(*ptr, &op.uses, inline_exprs, names, op.va);
                let v = render_varnode(*val, &op.uses, inline_exprs, names, op.va);
                out.push_str(&format!("{}*({}) = {};\n", pad, p, v));
            }
            SsaOpKind::Pcode(PcodeOp::Call { dest, .. })
            | SsaOpKind::Pcode(PcodeOp::CallInd { dest, .. }) => {
                let target = render_call_target(*dest, &op.uses, inline_exprs, names, op.va);
                if let Some(arguments) = call_arguments.arguments_for(block.id, operation_index) {
                    let arguments = arguments
                        .iter()
                        .map(|argument| render_recovered_call_argument(argument, inline_exprs, names, op.va))
                        .collect::<Vec<_>>();
                    out.push_str(&format!("{}{}({});\n", pad, target, arguments.join(", ")));
                } else {
                    // Keep the legacy form when the current semantic pass
                    // cannot prove even the first ABI argument.  Rendering
                    // `target()` there would falsely assert a zero-argument
                    // call; full details remain in the structured evidence.
                    out.push_str(&format!("{}call({});\n", pad, target));
                }
            }
            SsaOpKind::Pcode(_) if is_inlineable(op) => {
                if let Some(def) = &op.def
                    && inline_exprs.get(def).is_none()
                {
                    let expr = render_op_expr(op, inline_exprs, names);
                    let lhs = typed_lhs(def, types, names, op.va);
                    out.push_str(&format!("{}{} = {};\n", pad, lhs, expr));
                }
            }
            SsaOpKind::Pcode(_) => {
                if let Some(def) = &op.def {
                    let expr = render_op_expr(op, inline_exprs, names);
                    let lhs = typed_lhs(def, types, names, op.va);
                    out.push_str(&format!("{}{} = {};\n", pad, lhs, expr));
                }
            }
            SsaOpKind::Phi(_) => {}
        }
    }
}

/// Render an argument recovered through the semantic HIR call bridge.
fn render_recovered_call_argument(
    argument: &SsaVar,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    call_va: u64,
) -> String {
    inline_exprs
        .get(argument)
        .cloned()
        .unwrap_or_else(|| name_of(argument, names, Some(call_va)))
}

/// Materialized def LHS, optionally prefixed with a recovered type annotation.
fn typed_lhs(
    def: &SsaVar,
    types: Option<&crate::decompiler::types::TypeRecoveryReport>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    let name = name_of(def, names, Some(op_va));
    if let Some(report) = types
        && let Some(ty) = report.def_types.get(def)
        && let Some(ts) = ty_guess_str(ty)
    {
        return format!("{ts} {name}");
    }
    name
}

fn ty_guess_str(ty: &TyGuess) -> Option<String> {
    match ty {
        TyGuess::Unknown => None,
        TyGuess::Int(b) => Some(format!("int{b}")),
        TyGuess::Uint(b) => Some(format!("uint{b}")),
        TyGuess::Bool => Some("bool".to_string()),
        TyGuess::Float => Some("float".to_string()),
        TyGuess::Double => Some("double".to_string()),
        TyGuess::Ptr(inner) => {
            let inner_s = ty_guess_str(inner).unwrap_or_else(|| "void".to_string());
            Some(format!("{inner_s}*"))
        }
    }
}

fn is_terminator(op: &SsaOp) -> bool {
    matches!(
        &op.kind,
        SsaOpKind::Pcode(
            PcodeOp::Branch { .. }
                | PcodeOp::CBranch { .. }
                | PcodeOp::BranchInd { .. }
                | PcodeOp::Return { .. }
        )
    )
}

/// Contextual SSA variable name: param registers, GPR names, stack locals,
/// and resolved globals.
fn name_of(sv: &SsaVar, names: &NameCtx<'_>, op_va: Option<u64>) -> String {
    match &sv.location {
        Location::Register { base_offset } => {
            // Param registers at version 1 → signature param names.
            if sv.version == 1
                && let Some(rank) = gpr_param_rank(*base_offset)
                && let Some(sig) = names.sig
                && let Some((pname, _)) = sig.params.get(rank)
                && !pname.is_empty()
            {
                return pname.clone();
            }
            let base = reg_name(*base_offset);
            if sv.version > 1 {
                format!("{base}_{}", sv.version)
            } else {
                base
            }
        }
        Location::StackSlot { base_reg: _, disp } => {
            if let Some(frame) = names.frame {
                let var = if *disp > 0 {
                    frame.args.iter().find(|a| a.offset == *disp)
                } else {
                    frame.locals.iter().find(|l| l.offset == *disp)
                };
                if let Some(v) = var
                    && let Some(n) = &v.name
                    && !n.is_empty()
                {
                    return n.clone();
                }
            }
            if *disp < 0 {
                format!("local_{:x}", disp.unsigned_abs())
            } else {
                format!("arg_{:x}", disp)
            }
        }
        Location::RawRam => {
            if let Some(insn_va) = op_va
                && let Some(gva) = names.insn_to_global.get(&insn_va)
                && let Some(n) = names.global_names.get(gva)
            {
                // Prefer bare symbol (strip `:type` annotation suffix for C-ish output).
                let bare = n.split(':').next().unwrap_or(n);
                return bare.to_string();
            }
            format!("mem_{}", sv.version)
        }
        Location::Unique {
            instruction_va,
            offset,
            size,
        } => {
            // Instruction-scoped P-code temporary (not a C local).
            if sv.version > 1 {
                format!("t_{offset:x}_{size}@{instruction_va:x}_{}", sv.version)
            } else {
                format!("t_{offset:x}_{size}@{instruction_va:x}")
            }
        }
    }
}

/// x64 fastcall GPR parameter rank (RCX/RDX/R8/R9).
fn gpr_param_rank(base_offset: u64) -> Option<usize> {
    match base_offset {
        0x08 => Some(0), // RCX
        0x10 => Some(1), // RDX
        0x80 => Some(2), // R8
        0x88 => Some(3), // R9
        _ => None,
    }
}

fn render_op_expr(
    op: &SsaOp,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
) -> String {
    let uses = &op.uses;
    match &op.kind {
        SsaOpKind::Phi(phi) => {
            let args: Vec<String> = phi
                .args
                .iter()
                .map(|a| match a {
                    Some(v) => name_of(v, names, Some(op.va)),
                    None => "_".to_string(),
                })
                .collect();
            format!("phi({})", args.join(", "))
        }
        SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => {
            render_varnode(*input, uses, inline_exprs, names, op.va)
        }
        SsaOpKind::Pcode(PcodeOp::IntAdd { left, right, .. }) => {
            format!(
                "({} + {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntSub { left, right, .. }) => {
            format!(
                "({} - {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntMult { left, right, .. }) => {
            format!(
                "({} * {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntAnd { left, right, .. }) => {
            format!(
                "({} & {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntOr { left, right, .. }) => {
            format!(
                "({} | {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntXor { left, right, .. }) => {
            format!(
                "({} ^ {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntLsl { left, right, .. }) => {
            format!(
                "({} << {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntLsr { left, right, .. }) => {
            format!(
                "({} >> {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntEq { left, right, .. }) => {
            format!(
                "({} == {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntNotEq { left, right, .. }) => {
            format!(
                "({} != {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntLess { left, right, .. }) => {
            format!(
                "({} < {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntLessEq { left, right, .. }) => {
            format!(
                "({} <= {})",
                vn(*left, uses, inline_exprs, names, op.va),
                vn(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntNeg { input, .. }) => {
            format!("(-{})", vn(*input, uses, inline_exprs, names, op.va))
        }
        SsaOpKind::Pcode(PcodeOp::IntNot { input, .. }) => {
            format!("(~{})", vn(*input, uses, inline_exprs, names, op.va))
        }
        SsaOpKind::Pcode(PcodeOp::BoolNot { input, .. }) => {
            format!("(!{})", vn(*input, uses, inline_exprs, names, op.va))
        }
        SsaOpKind::Pcode(PcodeOp::Load { .. }) => {
            // Pointer / resolved slot is the first SSA use (stack slot, RawRam, or register).
            if let Some(u) = uses.first() {
                let ptr = inline_exprs
                    .get(u)
                    .cloned()
                    .unwrap_or_else(|| name_of(u, names, Some(op.va)));
                format!("*({ptr})")
            } else {
                "*(/*ptr*/)".to_string()
            }
        }
        SsaOpKind::Pcode(PcodeOp::IntZext { input, .. } | PcodeOp::IntSext { input, .. }) => {
            format!("(u64){}", vn(*input, uses, inline_exprs, names, op.va))
        }
        SsaOpKind::Pcode(PcodeOp::Subpiece { input, .. }) => {
            format!("(u32){}", vn(*input, uses, inline_exprs, names, op.va))
        }
        SsaOpKind::Pcode(other) => {
            let mut parts: Vec<String> = Vec::new();
            pcode_ir::visit_reads(other, &mut |v| {
                parts.push(vn(*v, uses, inline_exprs, names, op.va));
            });
            format!("/*({:?})*/ {}", other, parts.join(","))
        }
    }
}

fn render_varnode(
    vn: Varnode,
    uses: &[SsaVar],
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    vn_operand(vn, uses, inline_exprs, names, op_va)
}

/// Resolve a call destination to a symbol name when the target is a constant VA.
fn render_call_target(
    dest: Varnode,
    uses: &[SsaVar],
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    let target_va = match dest.space {
        AddressSpaceId::Const | AddressSpaceId::Ram => Some(dest.offset),
        _ => None,
    };
    if let Some(va) = target_va {
        if let Some(n) = names.global_names.get(&va) {
            // Strip type annotations like `name:funcptr` for call syntax.
            let bare = n.split(':').next().unwrap_or(n);
            // Normalize legacy sub_* auto-names to FUN_* (matches gold fun_* aliases).
            if let Some(rest) = bare.strip_prefix("sub_") {
                return format!("FUN_{rest}");
            }
            return bare.to_string();
        }
        // Stable fallback: Ghidra-style FUN_ for stripped call targets.
        return format!("FUN_{va:08x}");
    }
    // Non-constant dest: still try to normalize any rendered sub_* form.
    let rendered = render_varnode(dest, uses, inline_exprs, names, op_va);
    if let Some(rest) = rendered.strip_prefix("sub_") {
        format!("FUN_{rest}")
    } else if let Some(rest) = rendered.strip_prefix("*0x") {
        // Direct call encoded as ram pointer — emit FUN_ when it matches a known entry.
        if let Ok(va) = u64::from_str_radix(rest, 16) {
            if let Some(n) = names.global_names.get(&va) {
                let bare = n.split(':').next().unwrap_or(n);
                if let Some(r) = bare.strip_prefix("sub_") {
                    return format!("FUN_{r}");
                }
                return bare.to_string();
            }
            return format!("FUN_{va:08x}");
        }
        rendered
    } else {
        rendered
    }
}

/// If `va` looks like a string pointer, return a C string literal for emit.
fn try_string_literal(names: &NameCtx<'_>, va: u64) -> Option<String> {
    // global_names may already hold `"hello"` style entries from the project layer.
    if let Some(n) = names.global_names.get(&va)
        && n.starts_with('"')
    {
        return Some(n.clone());
    }
    None
}

fn vn(
    v: Varnode,
    uses: &[SsaVar],
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    vn_operand(v, uses, inline_exprs, names, op_va)
}

fn vn_operand(
    v: Varnode,
    uses: &[SsaVar],
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    match v.space {
        AddressSpaceId::Const => {
            if let Some(lit) = try_string_literal(names, v.offset) {
                return lit;
            }
            if let Some(n) = names.global_names.get(&v.offset) {
                let bare = n.split(':').next().unwrap_or(n);
                if bare.starts_with('"') || bare.starts_with("sub_") || bare.starts_with("FUN_") {
                    return bare.to_string();
                }
            }
            format!("0x{:x}", v.offset)
        }
        AddressSpaceId::Register => uses
            .iter()
            .find(|u| {
                matches!(u.location, Location::Register { base_offset } if base_offset == v.offset)
            })
            .map(|u| {
                inline_exprs
                    .get(u)
                    .cloned()
                    .unwrap_or_else(|| name_of(u, names, Some(op_va)))
            })
            .unwrap_or_else(|| reg_name(v.offset)),
        AddressSpaceId::Unique => uses
            .iter()
            .find(|u| {
                matches!(
                    &u.location,
                    Location::Unique {
                        instruction_va,
                        offset,
                        size
                    } if *instruction_va == op_va && *offset == v.offset && *size == v.size
                )
            })
            .map(|u| {
                inline_exprs
                    .get(u)
                    .cloned()
                    .unwrap_or_else(|| name_of(u, names, Some(op_va)))
            })
            .unwrap_or_else(|| format!("t_{:x}", v.offset)),
        AddressSpaceId::Ram => {
            if let Some(lit) = try_string_literal(names, v.offset) {
                return lit;
            }
            if let Some(n) = names.global_names.get(&v.offset) {
                let bare = n.split(':').next().unwrap_or(n);
                return bare.to_string();
            }
            format!("*0x{:x}", v.offset)
        }
    }
}

fn render_signature(sig: Option<&FunctionSignature>, entry_va: u64) -> (String, String, String) {
    match sig {
        Some(s) => {
            let params = s
                .params
                .iter()
                .enumerate()
                .map(|(i, (n, t))| {
                    let name = if n.is_empty() {
                        format!("arg{i}")
                    } else {
                        n.clone()
                    };
                    format!("{} {}", ty_str(t), name)
                })
                .collect::<Vec<_>>()
                .join(", ");
            (ty_str(&s.ret), s.name.clone(), params)
        }
        None => (
            "void".to_string(),
            format!("FUN_{entry_va:08x}"),
            String::new(),
        ),
    }
}

/// Intentionally duplicates `DataTypeManager::render` so the structurer does
/// not need a threaded type-manager handle (signatures already carry concrete
/// `DataType` values).
fn ty_str(ty: &crate::project::types::DataType) -> String {
    use crate::project::types::DataType;
    match ty {
        DataType::Void => "void".to_string(),
        DataType::Bool => "bool".to_string(),
        DataType::Int(b) => format!("int{b}"),
        DataType::Uint(b) => format!("uint{b}"),
        DataType::Float => "float".to_string(),
        DataType::Double => "double".to_string(),
        DataType::Ptr(inner) => format!("{}*", ty_str(inner)),
        DataType::Array(inner, n) => format!("{}[{n}]", ty_str(inner)),
        DataType::FuncPtr { .. } => "void*".to_string(),
        DataType::Named(n) => n.clone(),
        DataType::Unknown(b) => format!("u{b}"),
    }
}

// ─── S6: goto minimization ──────────────────────────────────────────────────

/// Remove redundant fallthrough gotos and unused labels.
fn minimize_gotos(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    // Pass 1: drop `goto L_X;` when the next non-empty line is `L_X:`.
    let mut cleaned: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        if let Some(target) = parse_goto(trimmed) {
            // Look ahead for the label.
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j < lines.len()
                && let Some(label) = parse_label(lines[j].trim())
                && label == target
            {
                i += 1;
                continue; // drop the goto
            }
        }
        cleaned.push(line.to_string());
        i += 1;
    }

    // Pass 2: collect remaining goto targets.
    let mut targets: HashSet<String> = HashSet::new();
    for line in &cleaned {
        if let Some(t) = parse_goto(line.trim()) {
            targets.insert(t);
        }
    }

    // Pass 3: drop labels that are never targeted.
    let mut final_lines: Vec<String> = Vec::new();
    for line in cleaned {
        if let Some(label) = parse_label(line.trim())
            && !targets.contains(&label)
        {
            continue;
        }
        final_lines.push(line);
    }
    let mut out = final_lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn parse_goto(trimmed: &str) -> Option<String> {
    // `goto L_0x1234;`
    let t = trimmed.strip_prefix("goto ")?.strip_suffix(';')?.trim();
    if t.starts_with('L') {
        Some(t.to_string())
    } else {
        None
    }
}

fn parse_label(trimmed: &str) -> Option<String> {
    // `L_0x1234:`
    let t = trimmed.strip_suffix(':')?;
    if t.starts_with('L') {
        Some(t.to_string())
    } else {
        None
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::structure::region::SwitchInfo;

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
        let b0 = cbranch_block(0, 0x1000, vec![], vec![2, 1]);
        let mut b1 = empty_block(1, 0x1010, vec![0], vec![3]);
        b1.ops.push(SsaOp {
            va: 0x1010,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x00, 4),
                input: Varnode::constant(1, 4),
            }),
            def: Some(reg(0x00, 2)),
            uses: vec![],
        });
        let mut b2 = empty_block(2, 0x1020, vec![0], vec![3]);
        b2.ops.push(SsaOp {
            va: 0x1020,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x00, 4),
                input: Varnode::constant(2, 4),
            }),
            def: Some(reg(0x00, 3)),
            uses: vec![],
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
        assert!(
            text.contains("phi(rax, rax_2)") || text.contains("phi(rax, rax_2);"),
            "expected phi with arg names, got:\n{text}"
        );
        assert!(
            !text.contains("= phi;"),
            "bare phi; should be gone:\n{text}"
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
        assert!(
            text.contains("int32 rax_2") || text.contains("int32 "),
            "expected typed temp annotation, got:\n{text}"
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
        // Synthetic Load whose def is RawRam at a known instruction VA.
        let load = SsaOp {
            va: 0x2000,
            kind: SsaOpKind::Pcode(PcodeOp::Load {
                out: Varnode::register(0x00, 4),
                space: AddressSpaceId::Ram,
                ptr: Varnode::constant(0x404000, 8),
            }),
            def: Some(SsaVar {
                location: Location::RawRam,
                version: 2,
            }),
            uses: vec![],
        };
        let ret = SsaOp {
            va: 0x2003,
            kind: SsaOpKind::Pcode(PcodeOp::Return {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![reg(0x00, 1)],
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
            text.contains("g_count"),
            "expected global symbol name, got:\n{text}"
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
}
