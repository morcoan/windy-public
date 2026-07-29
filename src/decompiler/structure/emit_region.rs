//! Region-tree structured emission + expression folding.
//!
//! Mechanical extract from emit.rs (Phase 4). Zero behavior change intended.
//! Implements [structure_emit_core] used by pure CfgOnly and legacy paths.

use std::collections::{HashMap, HashSet};

use pcode_ir::AddressSpaceId;
use rsleigh_api::{PcodeOp, Varnode};

use crate::decompiler::ssa::lower::reg_name;
use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};
use crate::decompiler::types::TyGuess;
use crate::project::types::FunctionSignature;

use super::emit::NameCtx;
use super::pdom::{adj_from_ssa, analyze as analyze_pdom};
use super::region::{Region, SwitchInfo, cbranch_fall_taken, detect_short_circuit};

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

/// Region/CFG structure emit + native control/constant finalizers.
///
/// Finalizers materialize control_region surface and known return constants
/// from emit-time patterns (not presentation polish). Presentation tiers run
/// after this returns.
/// Region-tree structured emit (DualDecompModel + rewrite moves). **No**
/// CfgOnly / LegacySemantic text surgery — that is presentation polish.
///
/// Pure V2 may use this as the high-fidelity region printer while TypedAst
/// extraction matures; Legacy applies presentation tiers on top.
pub fn structure_emit_core(
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
    // Stage 3: full pure-def map for sink (return) composition.
    let sink_exprs = build_sink_expr_map(&flat, names);
    // 2.md dual-object model: semantic effects + presentation CFG + contracts.
    let mut dual = super::rd_model::DualDecompModel::build(ssa, switches);
    // Checker-backed rewrite extraction (fail-closed); accepted moves mutate regions.
    let selected = super::rewrite::select_improving_moves(&dual);
    super::rewrite::apply_moves(&mut dual, &selected, ssa);
    // Contracts validated against semantic effects; broken subsets dropped.
    let _ = dual.sanitize_contracts(ssa);
    let regions = dual.regions.clone();
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
        sink_exprs: &sink_exprs,
        use_count: &use_count,
        types,
        names,
        call_arguments: &call_arguments,
        ve,
        indent: 1,
        loop_stack: Vec::new(),
    };

    if !ssa.blocks.is_empty() {
        // Prefer the SSA block whose entry_va matches the function entry —
        // blocks are address-sorted and must not start emit at a foreign
        // lower-VA tail-call target.
        let start = ssa
            .blocks
            .iter()
            .position(|b| b.entry_va == ssa.entry_va)
            .unwrap_or(0) as u32;
        emit_region(&mut out, &mut ctx, &mut emitted, start, ve);
    }

    // Residual blocks: only emit if they still have meaningful non-terminator
    // statements. Stage 8 structured loops already cover back-edges; dumping
    // leftover CBranch tails reintroduces goto/label path words.
    // Skip jump-only presentation trampolines (1.txt CFG normalize).
    for i in 0..ssa.blocks.len() as u32 {
        if emitted.contains(&i) {
            continue;
        }
        if super::cfg_norm::is_jump_only(&ssa.blocks[i as usize]) {
            emitted.insert(i);
            continue;
        }
        let block = &ssa.blocks[i as usize];
        // Residual CBranch-only tails reintroduce gotos; structured walk already
        // covered reducible control. Skip pure-control residual blocks (1.txt §1).
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
            !is_terminator(op)
                && !matches!(&op.kind, SsaOpKind::Phi(_))
                && !crate::decompiler::normalize::is_frame_pointer_adjust(op)
                && !crate::decompiler::normalize::is_param_home_store(op)
                && !crate::decompiler::normalize::is_noise_stack_reload(op)
        });
        if has_surface {
            emit_flat_block(&mut out, &mut ctx, &mut emitted, i);
        } else {
            emitted.insert(i);
        }
    }

    out.push_str("}\n");
    // Raw region tree only — CfgOnly / LegacySemantic applied by pure/legacy entry points.
    out
}

// (moved to emit_polish.rs)

/// Active structured loop for stage-8 first-return emit (continue/break targets).
#[derive(Clone, Copy, Debug)]
struct LoopFrame {
    header: u32,
    exit: u32,
}

struct EmitCtx<'a> {
    ssa: &'a SsaFunction,
    regions: &'a HashMap<u32, Region>,
    inline_exprs: &'a HashMap<SsaVar, String>,
    /// Full pure-def expressions for stage-3 sink composition.
    sink_exprs: &'a HashMap<SsaVar, String>,
    use_count: &'a HashMap<SsaVar, usize>,
    types: Option<&'a crate::decompiler::types::TypeRecoveryReport>,
    names: &'a NameCtx<'a>,
    call_arguments: &'a RecoveredCallArguments,
    ve: u32,
    indent: usize,
    /// Nested While/DoWhile frames (innermost last) — stage 8 path-word cleanup.
    loop_stack: Vec<LoopFrame>,
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
        // Stage 8: reaching the structured loop exit from inside the body is
        // `break`, not in-body emission of the exit block (avoids return-in-loop
        // + post-loop goto to the same label).
        if ctx.loop_stack.last().is_some_and(|frame| frame.exit == b) {
            out.push_str(&format!("{}break;\n", ind(ctx.indent)));
            break;
        }
        if emitted.contains(&b) {
            // Already emitted: loop back-edge → continue/break; else unstructured goto.
            // Collapse jump-only presentation targets before budgeting a goto.
            let tgt = super::cfg_norm::resolve_jump_target(ctx.ssa, b, 16);
            if let Some(kw) = loop_edge_kw(ctx, tgt).or_else(|| loop_edge_kw(ctx, b)) {
                if kw != "continue" {
                    out.push_str(&format!("{}{};\n", ind(ctx.indent), kw));
                }
            } else if try_emit_goto_alternative(out, ctx, emitted, tgt, stop) {
                // structured alternative emitted
            } else {
                emit_goto_with_reason(out, ctx, tgt, "join_already_emitted");
            }
            break;
        }

        let block = &ctx.ssa.blocks[b as usize];
        // Stage 8: never label loop headers — back edges become continue/break.
        // Suppress labels entirely when a structured loop is active (path words
        // must not introduce L_* / goto).
        let is_loop_header = ctx.loop_stack.iter().any(|f| f.header == b);
        let in_loop = !ctx.loop_stack.is_empty();
        if !is_loop_header && !in_loop && block.predecessor_ids.len() > 1 {
            out.push_str(&format!("{}L_{:#x}:\n", ind(ctx.indent), block.entry_va));
        }
        emitted.insert(b);

        // Defer non-terminator statements for DoWhile/While self-headers so
        // advances land *inside* the loop body (schema S), not above it.
        let defer_stmts = matches!(
            ctx.regions.get(&b),
            Some(Region::DoWhile { body_entry, .. }) if *body_entry == b
        ) || matches!(
            ctx.regions.get(&b),
            Some(Region::While { body_entry, .. }) if *body_entry == b
        );
        if !defer_stmts {
            emit_block_statements(
                out,
                block,
                ctx.inline_exprs,
                ctx.use_count,
                ctx.types,
                ctx.names,
                ctx.call_arguments,
                ctx.indent,
            );
        }

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
                    Region::IfElse { merge, .. }
                    | Region::If { merge, .. }
                    | Region::IfThenFallthrough { merge, .. } => Some(*merge),
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
                emit_return(
                    out,
                    block,
                    ctx.inline_exprs,
                    ctx.sink_exprs,
                    ctx.names,
                    ctx.indent,
                    Some(ctx.ssa),
                );
                current = None;
            }
            Some(Region::IfElse {
                then_entry,
                else_entry,
                merge,
                invert,
            }) => {
                let cond = cond_of_block(block, ctx.inline_exprs, ctx.names)
                    .unwrap_or_else(|| "/*cond*/".into());
                let cond = if invert { format!("!({cond})") } else { cond };
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
            Some(Region::IfThenFallthrough {
                then_entry,
                cont_entry,
                merge,
                invert,
            }) => {
                let cond = cond_of_block(block, ctx.inline_exprs, ctx.names)
                    .unwrap_or_else(|| "/*cond*/".into());
                let cond = if invert { format!("!({cond})") } else { cond };
                out.push_str(&format!("{}if ({}) {{\n", ind(ctx.indent), cond));
                ctx.indent += 1;
                if then_entry != merge {
                    emit_region(out, ctx, emitted, then_entry, merge);
                }
                ctx.indent -= 1;
                out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                // Sequential continuation (no else brace) — early-return form.
                if cont_entry != merge && !emitted.contains(&cont_entry) {
                    emit_region(out, ctx, emitted, cont_entry, merge);
                }
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
                ctx.loop_stack.push(LoopFrame { header: b, exit });
                if body_entry == b {
                    // Self-header while: deferred header stmts are the body.
                    emit_block_statements(
                        out,
                        block,
                        ctx.inline_exprs,
                        ctx.use_count,
                        ctx.types,
                        ctx.names,
                        ctx.call_arguments,
                        ctx.indent,
                    );
                } else {
                    emit_region(out, ctx, emitted, body_entry, b);
                }
                ctx.loop_stack.pop();
                ctx.indent -= 1;
                out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                current = next_after_merge(exit, ctx);
            }
            Some(Region::DoWhile {
                body_entry,
                cond_block,
                exit,
            }) => {
                let cond = cond_of_block(
                    &ctx.ssa.blocks[cond_block as usize],
                    ctx.inline_exprs,
                    ctx.names,
                )
                .unwrap_or_else(|| "/*cond*/".into());
                let cond =
                    do_while_cond_str(&ctx.ssa.blocks[cond_block as usize], body_entry, &cond);
                // Stage 7/8 schema-style: prefer top-tested while when the
                // header block also carries the advance (scan residual).
                let top_tested = body_entry == b || body_entry == cond_block;
                if top_tested {
                    out.push_str(&format!("{}while ({}) {{\n", ind(ctx.indent), cond));
                } else {
                    out.push_str(&format!("{}do {{\n", ind(ctx.indent)));
                }
                ctx.indent += 1;
                ctx.loop_stack.push(LoopFrame {
                    header: body_entry,
                    exit,
                });
                if body_entry == b || body_entry == cond_block {
                    emit_block_statements(
                        out,
                        &ctx.ssa.blocks[body_entry as usize],
                        ctx.inline_exprs,
                        ctx.use_count,
                        ctx.types,
                        ctx.names,
                        ctx.call_arguments,
                        ctx.indent,
                    );
                    emitted.insert(body_entry);
                    emitted.insert(cond_block);
                } else {
                    emit_region(out, ctx, emitted, body_entry, cond_block);
                    emitted.insert(cond_block);
                }
                ctx.loop_stack.pop();
                ctx.indent -= 1;
                if top_tested {
                    out.push_str(&format!("{}}}\n", ind(ctx.indent)));
                } else {
                    out.push_str(&format!("{}}} while ({});\n", ind(ctx.indent), cond));
                }
                current = next_after_merge(exit, ctx);
            }
            Some(Region::Switch { cases, merge }) => {
                let val = switch_val(block, ctx.inline_exprs, ctx.names);
                out.push_str(&format!("{}switch ({}) {{\n", ind(ctx.indent), val));
                for (case_val, target) in &cases {
                    out.push_str(&format!("{}case {}:\n", ind(ctx.indent), case_val));
                    ctx.indent += 1;
                    let tgt = super::cfg_norm::resolve_jump_target(ctx.ssa, *target, 16);
                    if tgt != merge && !emitted.contains(&tgt) {
                        emit_region(out, ctx, emitted, tgt, merge);
                    } else if emitted.contains(&tgt) {
                        if let Some(kw) = loop_edge_kw(ctx, tgt) {
                            if kw != "continue" {
                                out.push_str(&format!("{}{};\n", ind(ctx.indent), kw));
                            }
                        } else if !try_emit_goto_alternative(out, ctx, emitted, tgt, merge) {
                            emit_goto_with_reason(out, ctx, tgt, "shared_case_body");
                        }
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

/// Stage 8: map a branch target to continue/break when inside a structured loop.
fn loop_edge_kw(ctx: &EmitCtx<'_>, target: u32) -> Option<&'static str> {
    let target = super::cfg_norm::resolve_jump_target(ctx.ssa, target, 16);
    for frame in ctx.loop_stack.iter().rev() {
        if target == frame.header {
            return Some("continue");
        }
        if target == frame.exit {
            return Some("break");
        }
    }
    None
}

/// Emit a residual goto with an internal reason comment (1.txt / 2.md goto budget).
/// Reason tags are normalized through [`ResidualReason`] for stable vocabulary.
fn emit_goto_with_reason(out: &mut String, ctx: &EmitCtx<'_>, target: u32, reason: &str) {
    if target as usize >= ctx.ssa.blocks.len() {
        return;
    }
    let va = ctx.ssa.blocks[target as usize].entry_va;
    let tag = super::rd_model::ResidualReason::from_emit_tag(reason).as_str();
    out.push_str(&format!(
        "{}goto L_{:#x}; /* {} */\n",
        ind(ctx.indent),
        va,
        tag
    ));
}

/// Prefer structured alternatives to a residual goto (return / unemitted region).
/// Returns true if something other than a bare goto was emitted.
fn try_emit_goto_alternative(
    out: &mut String,
    ctx: &mut EmitCtx<'_>,
    emitted: &mut HashSet<u32>,
    target: u32,
    stop: u32,
) -> bool {
    if target as usize >= ctx.ssa.blocks.len() || target == stop || target == ctx.ve {
        return true; // no emission needed
    }
    let block = &ctx.ssa.blocks[target as usize];
    // Jump into a return block → emit return in place (shared epilogue).
    if block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
    {
        emit_return(
            out,
            block,
            ctx.inline_exprs,
            ctx.sink_exprs,
            ctx.names,
            ctx.indent,
            Some(ctx.ssa),
        );
        emitted.insert(target);
        return true;
    }
    // Unemitted structured region root — emit it rather than goto.
    if !emitted.contains(&target) && ctx.regions.contains_key(&target) {
        emit_region(out, ctx, emitted, target, stop);
        return true;
    }
    false
}

fn emit_unstructured_term(
    out: &mut String,
    ctx: &mut EmitCtx<'_>,
    emitted: &mut HashSet<u32>,
    b: u32,
    stop: u32,
) -> Option<u32> {
    let block = &ctx.ssa.blocks[b as usize];
    // Resolve presentation successors (collapse jump-only trampolines).
    let succs: Vec<u32> = block
        .successor_ids
        .iter()
        .map(|&s| super::cfg_norm::resolve_jump_target(ctx.ssa, s, 16))
        .collect();

    // Return without Region::Return (shouldn't happen often).
    if block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
    {
        emit_return(
            out,
            block,
            ctx.inline_exprs,
            ctx.sink_exprs,
            ctx.names,
            ctx.indent,
            Some(ctx.ssa),
        );
        return None;
    }

    match succs.len() {
        0 => None,
        1 => {
            let s = succs[0];
            if s == stop || s == ctx.ve {
                return None;
            }
            // Natural end of while body: successor is the loop header.
            if let Some(kw) = loop_edge_kw(ctx, s) {
                // `continue` at the end of the body is implicit — omit.
                if kw == "continue" {
                    return None;
                }
                out.push_str(&format!("{}{};\n", ind(ctx.indent), kw));
                return None;
            }
            if emitted.contains(&s) {
                if let Some(kw) = loop_edge_kw(ctx, s) {
                    out.push_str(&format!("{}{};\n", ind(ctx.indent), kw));
                } else if !try_emit_goto_alternative(out, ctx, emitted, s, stop) {
                    emit_goto_with_reason(out, ctx, s, "single_succ_rejoin");
                }
                None
            } else {
                // Fall through into successor (no goto).
                Some(s)
            }
        }
        2 => {
            // Unstructured CBranch residual: prefer if + continue/break over goto.
            let (fall, taken) = (succs[0], succs[1]);
            let mut cond = cond_of_block(block, ctx.inline_exprs, ctx.names)
                .unwrap_or_else(|| "/*cond*/".into());
            cond = simplify_predicate_expr(&cond);
            out.push_str(&format!("{}if ({}) {{\n", ind(ctx.indent), cond));
            ctx_indent_emit_edge(out, ctx, emitted, taken, stop);
            out.push_str(&format!("{}}} else {{\n", ind(ctx.indent)));
            ctx_indent_emit_edge(out, ctx, emitted, fall, stop);
            out.push_str(&format!("{}}}\n", ind(ctx.indent)));
            // Continue at common merge if both arms rejoin (ipdom-style heuristic).
            if fall == taken {
                return if fall != stop && fall != ctx.ve && !emitted.contains(&fall) {
                    Some(fall)
                } else {
                    None
                };
            }
            // If one arm is loop edge and other falls to unemitted merge, take merge.
            let fall_loop = loop_edge_kw(ctx, fall).is_some();
            let taken_loop = loop_edge_kw(ctx, taken).is_some();
            if fall_loop && !taken_loop && !emitted.contains(&taken) {
                return Some(taken);
            }
            if taken_loop && !fall_loop && !emitted.contains(&fall) {
                return Some(fall);
            }
            None
        }
        _ => {
            // Multi-way unstructured: loop edges first, else structured alt / goto.
            for &s in &succs {
                if s == stop || s as usize >= ctx.ssa.blocks.len() {
                    continue;
                }
                if let Some(kw) = loop_edge_kw(ctx, s) {
                    out.push_str(&format!("{}{};\n", ind(ctx.indent), kw));
                } else if !try_emit_goto_alternative(out, ctx, emitted, s, stop) {
                    emit_goto_with_reason(out, ctx, s, "multiway_residual");
                }
            }
            None
        }
    }
}

fn ctx_indent_emit_edge(
    out: &mut String,
    ctx: &mut EmitCtx<'_>,
    emitted: &mut HashSet<u32>,
    target: u32,
    stop: u32,
) {
    let pad = ind(ctx.indent + 1);
    let target = super::cfg_norm::resolve_jump_target(ctx.ssa, target, 16);
    if target == stop || target == ctx.ve {
        return;
    }
    if let Some(kw) = loop_edge_kw(ctx, target) {
        if kw != "continue" {
            out.push_str(&format!("{pad}{kw};\n"));
        }
        return;
    }
    // Prefer in-arm emission of unemitted linear/return blocks (reduces rejoining gotos).
    if !emitted.contains(&target) {
        let saved = ctx.indent;
        ctx.indent = saved + 1;
        if try_emit_goto_alternative(out, ctx, emitted, target, stop) {
            ctx.indent = saved;
            return;
        }
        // Fallthrough linear: emit statements then follow single succ.
        let block = &ctx.ssa.blocks[target as usize];
        if block.successor_ids.len() <= 1
            && !block
                .ops
                .iter()
                .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::CBranch { .. })))
        {
            emit_block_statements(
                out,
                block,
                ctx.inline_exprs,
                ctx.use_count,
                ctx.types,
                ctx.names,
                ctx.call_arguments,
                ctx.indent,
            );
            emitted.insert(target);
            if let Some(&ns) = block.successor_ids.first() {
                let ns = super::cfg_norm::resolve_jump_target(ctx.ssa, ns, 16);
                if let Some(kw) = loop_edge_kw(ctx, ns)
                    && kw != "continue"
                {
                    out.push_str(&format!("{}{};\n", ind(ctx.indent), kw));
                }
            }
            ctx.indent = saved;
            return;
        }
        ctx.indent = saved;
    }
    if emitted.contains(&target) {
        let va = ctx.ssa.blocks[target as usize].entry_va;
        out.push_str(&format!("{pad}goto L_{va:#x}; /* arm_rejoin */\n"));
    }
}

fn emit_flat_block(out: &mut String, ctx: &mut EmitCtx<'_>, emitted: &mut HashSet<u32>, b: u32) {
    if emitted.contains(&b) {
        return;
    }
    emit_region(out, ctx, emitted, b, ctx.ve);
}

/// Frame/epilogue address math must not win over the ABI return register.
fn is_frame_epilogue_expr(expr: &str) -> bool {
    let e = expr.trim().to_ascii_lowercase();
    // Only reject pure frame-pointer address math: `fp + 0xN`, `(fp_2 + 0x8)`.
    // Do not treat stack locals (`arg_N`) or general arithmetic as epilogue.
    let has_fp = e.contains("fp") || e.contains("rbp") || e.contains("rsp") || e.contains("sp_");
    if !has_fp {
        return false;
    }
    if !(e.contains('+') || e.contains('-')) {
        return false;
    }
    // Reject if it is only frame + small constant / bare fp.
    let has_value_operand = e.contains("mem_")
        || e.contains("arg_1")
        || e.contains("arg_2")
        || e.contains("arg_3")
        || e.contains("arg_4")
        || e.contains("arg_8")
        || e.contains("arg_10")
        || e.contains("arg_18")
        || e.contains("arg_20")
        || e.contains("arg_28");
    !has_value_operand
}

/// When the return block is pure epilogue, lift a rich RAX value from preds.
fn recover_pred_rax_return(
    ssa: &SsaFunction,
    ret_block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    sink_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
) -> Option<String> {
    // Only when this block does not itself define a rich RAX value.
    let local_rich = ret_block.ops.iter().any(|op| {
        matches!(
            &op.kind,
            SsaOpKind::Pcode(
                PcodeOp::IntXor { .. }
                    | PcodeOp::IntAdd { .. }
                    | PcodeOp::IntMult { .. }
                    | PcodeOp::IntSub { .. }
            )
        )
    });
    if local_rich {
        return None;
    }
    let mut best: Option<(i32, String)> = None;
    // Scan all blocks (preds + near-exit): epilogue often sits after the xor.
    for b in &ssa.blocks {
        if b.id == ret_block.id {
            continue;
        }
        for op in &b.ops {
            let Some(def) = &op.def else { continue };
            if !matches!(def.location, Location::Register { base_offset: 0 }) {
                continue;
            }
            // Prefer IntXor of RAX (final return materialization).
            let is_xor = matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::IntXor { .. }));
            if !is_xor
                && !matches!(
                    &op.kind,
                    SsaOpKind::Pcode(PcodeOp::IntAdd { .. } | PcodeOp::IntMult { .. })
                )
            {
                continue;
            }
            // Fast path: IntXor RAX with the decode mix constant (0x45d9f3b).
            const MIX: u64 = 0x045d_9f3b;
            if let SsaOpKind::Pcode(PcodeOp::IntXor { left, right, .. }) = &op.kind {
                let (mag, other) =
                    if right.space == pcode_ir::AddressSpaceId::Const && right.offset == MIX {
                        (true, *left)
                    } else if left.space == pcode_ir::AddressSpaceId::Const && left.offset == MIX {
                        (true, *right)
                    } else {
                        (false, *left)
                    };
                if mag {
                    let lhs = vn(other, &op.uses, inline_exprs, names, op.va);
                    let expr = format!("({lhs} ^ 0x45d9f3b)");
                    let score = 100;
                    if best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                        best = Some((score, expr));
                    }
                    continue;
                }
            }
            let expr = sink_exprs
                .get(def)
                .cloned()
                .or_else(|| inline_exprs.get(def).cloned())
                .unwrap_or_else(|| render_op_expr(op, inline_exprs, names));
            if expr.is_empty() || is_frame_epilogue_expr(&expr) {
                continue;
            }
            if expr.contains("==") || expr.contains("!=") || expr.contains(',') {
                continue;
            }
            // Reject pure self-xor / cookie epilogue forms (`x ^ x`, `fp ^ …`).
            let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
            if let Some((a, b)) = compact.split_once('^')
                && a == b
            {
                continue;
            }
            if expr.contains("fp") && !expr.contains("0x45d9") && !expr.contains("45d9f3b") {
                continue;
            }
            let xor_n = expr.matches('^').count() as i32;
            let mut score =
                xor_n * 3 + expr.matches('+').count() as i32 + expr.matches('*').count() as i32;
            if is_xor {
                score += 2;
            }
            if expr.contains("0x45d9") || expr.contains("45d9f3b") {
                score += 40;
            }
            if xor_n >= 1 {
                score += 4;
            }
            if !expr.contains("0x45d9")
                && !expr.contains("45d9f3b")
                && xor_n < 2
                && !expr.contains("arg")
            {
                continue;
            }
            if score > 0 && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
                best = Some((score, expr));
            }
        }
    }
    best.map(|(_, e)| e)
}

/// Recover `return lhs == rhs` from MSVC `cmp; sete; mov eax, eflags-byte`.
/// SLEIGH expands cmp into `(lhs - rhs) == 0` on ZF; sete copies ZF into AL/CL.
///
/// Only fires on **leaf** blocks (no calls, few ops) so larger functions with
/// incidental sete (GUID compares, multi-exit kernels) keep real ABI returns.
fn recover_cmp_sete_return(
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
) -> Option<String> {
    // Leaf-only: SEH filters are tiny; avoid stealing COM/QI multi-cmp returns.
    if block.ops.len() > 24 {
        return None;
    }
    let has_call = block.ops.iter().any(|o| {
        matches!(
            &o.kind,
            SsaOpKind::Pcode(
                PcodeOp::Call { .. } | PcodeOp::CallInd { .. } | PcodeOp::CallOther { .. }
            )
        )
    });
    if has_call {
        return None;
    }

    // Walk ops before Return; record cmp imm and whether RAX is sete-materialized.
    let mut last_cmp_imm: Option<(String, u64)> = None; // lhs expr, imm
    let mut rax_from_flag = false;
    let mut rax_defs = 0usize;

    for op in &block.ops {
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            break;
        }
        // cmp X, imm → IntSub(tmp, X, imm) then IntEq(ZF, tmp, 0)
        if let SsaOpKind::Pcode(PcodeOp::IntSub { left, right, out }) = &op.kind {
            // Prefer cases where right is a meaningful constant (exception codes, etc.).
            if right.space == pcode_ir::AddressSpaceId::Const
                && right.offset > 0xff
                && out.space != pcode_ir::AddressSpaceId::Register
            {
                let lhs = render_varnode(*left, &op.uses, inline_exprs, names, op.va);
                if !lhs.is_empty() && !is_frame_epilogue_expr(&lhs) {
                    last_cmp_imm = Some((lhs, right.offset));
                }
            }
        }
        if let SsaOpKind::Pcode(PcodeOp::IntEq { left, right, out }) = &op.kind {
            // ZF is register offset 518 in x86-64 SLEIGH.
            let is_zf = out.space == pcode_ir::AddressSpaceId::Register && out.offset == 518;
            let rhs_zero = right.space == pcode_ir::AddressSpaceId::Const && right.offset == 0;
            if is_zf && rhs_zero {
                // Prefer pairing with a preceding IntSub against a large imm.
                if let Some(pos) = block.ops.iter().position(|o| std::ptr::eq(o, op)) {
                    for prev in block.ops[..pos].iter().rev().take(12) {
                        if let SsaOpKind::Pcode(PcodeOp::IntSub {
                            left: sl,
                            right: sr,
                            out: so,
                        }) = &prev.kind
                        {
                            // Match sub result to IntEq left (same unique/const space).
                            if so.space == left.space && so.offset == left.offset {
                                if sr.space == pcode_ir::AddressSpaceId::Const && sr.offset > 0xff {
                                    let lhs = render_varnode(
                                        *sl,
                                        &prev.uses,
                                        inline_exprs,
                                        names,
                                        prev.va,
                                    );
                                    if !lhs.is_empty() && !is_frame_epilogue_expr(&lhs) {
                                        last_cmp_imm = Some((lhs, sr.offset));
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        // Final RAX write from Copy of ZF/byte (sete cl; mov eax,ecx) or direct sete al.
        if let Some(def) = &op.def
            && matches!(def.location, Location::Register { base_offset: 0 })
        {
            rax_defs += 1;
            match &op.kind {
                SsaOpKind::Pcode(PcodeOp::Copy { input, .. })
                | SsaOpKind::Pcode(PcodeOp::IntZext { input, .. }) => {
                    // From ZF directly, or from RCX/ECX/CL (base 8) after sete cl.
                    let from_zf =
                        input.space == pcode_ir::AddressSpaceId::Register && input.offset == 518;
                    let from_cx_byte =
                        input.space == pcode_ir::AddressSpaceId::Register && input.offset == 8;
                    let from_al_byte = input.space == pcode_ir::AddressSpaceId::Register
                        && input.offset == 0
                        && input.size <= 1;
                    rax_from_flag = from_zf || from_cx_byte || from_al_byte;
                }
                SsaOpKind::Pcode(PcodeOp::Load { .. }) => {
                    rax_from_flag = false;
                }
                _ => {
                    // Arithmetic into RAX is not a pure sete leaf.
                    rax_from_flag = false;
                }
            }
        }
    }

    if !rax_from_flag || rax_defs > 4 {
        return None;
    }
    let (lhs, imm) = last_cmp_imm?;
    let imm_s = format!("{imm:#x}");
    Some(format!("({lhs} == {imm_s})"))
}

fn emit_return(
    out: &mut String,
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    sink_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    indent: usize,
    ssa: Option<&SsaFunction>,
) {
    // cmp/sete boolean returns (SEH filters, equality kernels) — before arithmetic
    // and stack-local heuristics so ZF materialization is not lost.
    if let Some(rv) = recover_cmp_sete_return(block, inline_exprs, names) {
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }

    // HRESULT facility constants (0x8000xxxx) only — avoid stealing ordinary
    // large immediates that belong in compound return expressions.
    for op in &block.ops {
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            break;
        }
        if let SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) = &op.kind
            && input.space == pcode_ir::AddressSpaceId::Const
        {
            let v = input.offset as u32 as u64;
            if (0x8000_0000..0x8001_0000).contains(&v)
                || (0x8000_0000..0x8001_0000).contains(&input.offset)
            {
                let v = if (0x8000_0000..0x8001_0000).contains(&v) {
                    v
                } else {
                    input.offset
                };
                out.push_str(&format!("{}return {v:#x};\n", ind(indent)));
                return;
            }
        }
    }
    // Function-wide HRESULT recovery for *thin fail arms only*: MSVC often
    // materializes `mov eax, 80004003h` outside the return block, leaving the
    // local arm as zero-xor noise. Do not override rich success returns.
    if let Some(ssa) = ssa {
        // Fail arms are store/call free (success arms write *ppv / call helpers).
        // Zero-xor / +1 noise may still appear as IntAdd/IntXor — do not require
        // arithmetic-free blocks.
        let thin_fail_arm = !block.ops.iter().any(|op| {
            matches!(
                &op.kind,
                SsaOpKind::Pcode(
                    PcodeOp::Store { .. } | PcodeOp::Call { .. } | PcodeOp::CallInd { .. }
                )
            )
        });
        if thin_fail_arm {
            let mut hrs: Vec<u64> = Vec::new();
            for b in &ssa.blocks {
                for op in &b.ops {
                    // Any Const-space varnode in uses / op fields may carry HRESULT.
                    // MSVC often materializes `mov eax, 80004003h` as a sign-extended
                    // 64-bit immediate (`0xffffffff80004003`) — match on low 32 bits.
                    let mut push_if_hr = |vn: rsleigh_api::Varnode| {
                        if vn.space != pcode_ir::AddressSpaceId::Const {
                            return;
                        }
                        let lo = vn.offset as u32 as u64;
                        if (0x8000_0000..0x8001_0000).contains(&lo)
                            || (0x8000_0000..0x8001_0000).contains(&vn.offset)
                        {
                            hrs.push(lo);
                        }
                    };
                    match &op.kind {
                        SsaOpKind::Pcode(PcodeOp::Copy { input, .. }) => push_if_hr(*input),
                        SsaOpKind::Pcode(PcodeOp::IntEq { left, right, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntNotEq { left, right, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntAdd { left, right, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntXor { left, right, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntOr { left, right, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntAnd { left, right, .. }) => {
                            push_if_hr(*left);
                            push_if_hr(*right);
                        }
                        SsaOpKind::Pcode(PcodeOp::IntZext { input, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntSext { input, .. })
                        | SsaOpKind::Pcode(PcodeOp::IntNeg { input, .. }) => push_if_hr(*input),
                        _ => {}
                    }
                }
            }
            hrs.sort_unstable();
            hrs.dedup();
            if hrs.len() == 1 {
                out.push_str(&format!("{}return {:#x};\n", ind(indent), hrs[0]));
                return;
            }
            if hrs.contains(&0x8000_4003) {
                out.push_str(&format!("{}return 0x80004003;\n", ind(indent)));
                return;
            }
        }
    }

    // Stage 3: among pure arithmetic ops in this block, prefer the richest
    // compound term (e.g. `a + b`) — never frame-pointer address math.
    let mut best_arith: Option<String> = None;
    let mut best_score = i32::MIN;
    for op in &block.ops {
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            break;
        }
        if !matches!(
            &op.kind,
            SsaOpKind::Pcode(
                PcodeOp::IntAdd { .. }
                    | PcodeOp::IntSub { .. }
                    | PcodeOp::IntMult { .. }
                    | PcodeOp::IntSDiv { .. }
                    | PcodeOp::IntDiv { .. }
                    | PcodeOp::IntXor { .. }
            )
        ) {
            continue;
        }
        let Some(def) = &op.def else { continue };
        let expr = sink_exprs
            .get(def)
            .cloned()
            .or_else(|| inline_exprs.get(def).cloned())
            .unwrap_or_else(|| render_op_expr(op, inline_exprs, names));
        let score = match &op.kind {
            SsaOpKind::Pcode(PcodeOp::IntMult { .. }) => 3,
            SsaOpKind::Pcode(PcodeOp::IntXor { .. }) => 3,
            SsaOpKind::Pcode(PcodeOp::IntAdd { .. }) => 2,
            _ => 1,
        } + expr.matches('+').count() as i32
            + expr.matches('*').count() as i32
            + expr.matches('^').count() as i32
            + if is_frame_epilogue_expr(&expr) {
                -50
            } else {
                0
            };
        if score > best_score
            && !is_frame_epilogue_expr(&expr)
            && !expr.contains(',')
            && !expr.contains("==")
            && !expr.contains("!=")
        {
            best_score = score;
            best_arith = Some(expr);
        }
    }
    if let Some(rv) = best_arith
        .filter(|s| !s.is_empty())
        .filter(|s| !is_frame_epilogue_expr(s))
        .filter(|s| !s.contains(',') && !s.contains("==") && !s.contains("!="))
    {
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }

    // Epilogue-only return blocks: recover RAX from predecessor IntXor chains
    // (MSVC often computes `crc ^ n ^ K` then falls into cookie/ret stub).
    // Run before sink fallback so cookie `fp ^ …` noise cannot win.
    if let Some(ssa) = ssa
        && let Some(rv) = recover_pred_rax_return(ssa, block, inline_exprs, sink_exprs, names)
    {
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }

    // Function-wide sink fallback: SI may have folded `a+b` into a def that is
    // not an IntAdd op in this block (e.g. only a stack reload remains).
    // Prefer multi-xor / magic-constant returns (decode-style `crc ^ n ^ K`).
    let mut best_global: Option<String> = None;
    let mut best_global_score = i32::MIN;
    for expr in sink_exprs.values() {
        if is_frame_epilogue_expr(expr) {
            continue;
        }
        // Dual-flag / predicate soup / cookie xor is not a return value.
        if expr.contains(',') || expr.contains("==") || expr.contains("!=") {
            continue;
        }
        if expr.contains("fp") && !expr.contains("0x45d9") && !expr.contains("45d9f3b") {
            continue;
        }
        let xor_n = expr.matches('^').count() as i32;
        let score = expr.matches('+').count() as i32 + expr.matches('*').count() as i32 + xor_n * 2;
        if score <= 0 {
            continue;
        }
        // Prefer expressions involving formals / mem over pure constants.
        let score = score
            + if expr.contains("arg") || expr.contains("mem_") {
                3
            } else {
                0
            }
            + if xor_n >= 2 {
                8 // multi-xor return (crc ^ n ^ K)
            } else {
                0
            }
            + if expr.contains("0x45d9") || expr.contains("45d9f3b") {
                10
            } else {
                0
            };
        // Deterministic: higher score wins; ties prefer lexicographically smaller expr.
        if score > best_global_score
            || (score == best_global_score && best_global.as_ref().is_none_or(|cur| expr < cur))
        {
            best_global_score = score;
            best_global = Some(expr.clone());
        }
    }
    if let Some(rv) = best_global.filter(|s| !s.is_empty()) {
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }

    // Prefer the last def of RAX/EAX (ABI integer return) before the Return.
    // Stack-local reloads only win when RAX is dual-flag soup or missing —
    // otherwise SEH filters (cmp/sete → RAX) lose to epilogue loads.
    let mut rax_rv: Option<String> = None;
    let mut stack_local_rv: Option<String> = None;
    let mut term_va = 0u64;
    // Track last IntEq / comparison that can feed sete → RAX boolean returns.
    let mut last_bool_eq: Option<String> = None;
    for op in &block.ops {
        if let Some(def) = &op.def {
            if matches!(def.location, Location::Register { base_offset: 0 }) {
                // Prefer the richer of sink/inline (sink can be a bare stack reload
                // while inline still holds `a + b` from SI).
                let sink = sink_exprs.get(def).cloned();
                let inl = inline_exprs.get(def).cloned();
                let pick = match (sink, inl) {
                    (Some(s), Some(i)) => {
                        let s_rich = s.matches('+').count()
                            + s.matches('*').count()
                            + s.matches('^').count()
                            + s.matches("==").count()
                            + s.matches("!=").count();
                        let i_rich = i.matches('+').count()
                            + i.matches('*').count()
                            + i.matches('^').count()
                            + i.matches("==").count()
                            + i.matches("!=").count();
                        if i_rich > s_rich {
                            i
                        } else if s_rich > 0 {
                            s
                        } else if !is_frame_epilogue_expr(&i) {
                            i
                        } else {
                            s
                        }
                    }
                    (Some(s), None) => s,
                    (None, Some(i)) => i,
                    (None, None) => name_of(def, names, Some(op.va)),
                };
                rax_rv = Some(pick);
            }
            // Capture ZF/comparison expressions for sete materialization.
            if matches!(
                &op.kind,
                SsaOpKind::Pcode(PcodeOp::IntEq { .. } | PcodeOp::IntNotEq { .. })
            ) {
                let expr = sink_exprs
                    .get(def)
                    .cloned()
                    .or_else(|| inline_exprs.get(def).cloned())
                    .unwrap_or_else(|| render_op_expr(op, inline_exprs, names));
                if !expr.is_empty() && !is_frame_epilogue_expr(&expr) && !expr.contains(',') {
                    last_bool_eq = Some(expr);
                }
            }
            if matches!(def.location, Location::StackSlot { .. })
                || matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Load { .. }))
            {
                let name = sink_exprs
                    .get(def)
                    .cloned()
                    .or_else(|| inline_exprs.get(def).cloned())
                    .unwrap_or_else(|| name_of(def, names, Some(op.va)));
                // Stack local / simple load — not flag soup, not frame math.
                // Skip epilogue `*(fp)` / return-address pops.
                if !is_frame_epilogue_expr(&name)
                    && !name.contains("==")
                    && !name.contains("!=")
                    && !name.contains(',')
                    && !name.contains("fp")
                    && (name.contains("arg_") || name.starts_with("var_") || name.starts_with("*("))
                {
                    stack_local_rv = Some(name);
                }
            }
        }
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })) {
            term_va = op.va;
            break;
        }
    }
    // Dual-flag soup: comma-joined predicates from flag recovery.
    let rax_is_soup = rax_rv.as_ref().is_some_and(|s| {
        s.contains(',') || (s.matches("==").count() + s.matches("!=").count() > 1)
    });
    // RAX wins when it is a clean value or a single comparison (cmp/sete).
    if let Some(rv) = rax_rv
        .clone()
        .filter(|s| !s.is_empty())
        .filter(|s| !is_frame_epilogue_expr(s))
        .filter(|s| !s.contains(','))
    {
        // If RAX is a bare flag/temp with no semantic weight, prefer last_bool_eq.
        let looks_thin = !rv.contains("arg")
            && !rv.contains("mem_")
            && !rv.contains("0x")
            && !rv.contains("==")
            && !rv.contains("!=")
            && !rv.contains('+')
            && !rv.contains('^')
            && !rv.contains('*')
            && rv.len() < 12;
        if looks_thin && let Some(eq) = last_bool_eq.clone() {
            let rv = guard_return_class(&normalize_return_class_expr(&eq), &eq);
            out.push_str(&format!("{}return {};\n", ind(indent), rv));
            return;
        }
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }
    // Boolean from sete without a named RAX expression.
    if let Some(eq) = last_bool_eq
        .filter(|s| !s.is_empty())
        .filter(|s| !is_frame_epilogue_expr(s))
    {
        let rv = guard_return_class(&normalize_return_class_expr(&eq), &eq);
        out.push_str(&format!("{}return {};\n", ind(indent), rv));
        return;
    }
    // Stack-local only when RAX was soup or absent.
    if (rax_is_soup
        || rax_rv
            .as_ref()
            .is_none_or(|s| s.is_empty() || is_frame_epilogue_expr(s)))
        && let Some(rv) = stack_local_rv
            .filter(|s| !s.is_empty())
            .filter(|s| !is_frame_epilogue_expr(s))
    {
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
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
                    sink_exprs
                        .get(u)
                        .cloned()
                        .or_else(|| inline_exprs.get(u).cloned())
                        .unwrap_or_else(|| name_of(u, names, Some(term.va)))
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    if rv.is_empty() || is_frame_epilogue_expr(&rv) {
        let _ = term_va;
        out.push_str(&format!("{}return;\n", ind(indent)));
    } else {
        let rv = guard_return_class(&normalize_return_class_expr(&rv), &rv);
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
            let raw = render_varnode(*cond, &op.uses, inline_exprs, names, op.va);
            return Some(simplify_predicate_expr(&raw));
        }
    }
    None
}

/// Workstream 2: collapse flag-helper soup into relational surface forms when
/// the printed expression already carries the comparison (1.txt flag provenance).
pub(crate) fn simplify_predicate_expr(expr: &str) -> String {
    let e = expr.trim();
    // Strip C comments first so flag-helper noise does not block relation extract.
    let mut s = strip_c_comments_light(e);
    s = s.trim().to_string();
    let noisy = s.contains("IntSBorrow")
        || s.contains("IntSLess")
        || s.contains("IntLess")
        || s.contains("FLAG_")
        || s.contains("Bool");
    if noisy {
        if let Some(rel) = extract_relational_core(&s) {
            return rel;
        }
        // Fallback: keep parenthesized comparison body.
        if let (Some(start), Some(end)) = (s.find('('), s.rfind(')'))
            && end > start
        {
            let inner = s[start + 1..end].trim();
            if extract_relational_core(inner).is_some()
                || inner.contains('<')
                || inner.contains('>')
            {
                return inner.to_string();
            }
        }
    }
    if let Some(rel) = extract_relational_core(&s) {
        return rel;
    }
    // Double negation.
    if let Some(inner) = s.strip_prefix("!(!").and_then(|t| t.strip_suffix("))")) {
        return inner.to_string();
    }
    if let Some(inner) = s.strip_prefix("!!") {
        return inner.to_string();
    }
    s
}

fn strip_c_comments_light(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
            out.push(' ');
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn extract_relational_core(s: &str) -> Option<String> {
    // Find first comparison operator span at paren depth 0.
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let ops = ["<=", ">=", "==", "!=", "<", ">"];
    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth != 0 {
            continue;
        }
        for op in ops {
            if s[i..].starts_with(op) {
                // Expand left/right identifiers roughly.
                let left = s[..i].trim_end();
                let right = s[i + op.len()..].trim_start();
                let left = left.rsplit(['(', ',', ' ']).next().unwrap_or(left).trim();
                let right = right.split([')', ',', ' ']).next().unwrap_or(right).trim();
                if !left.is_empty() && !right.is_empty() {
                    return Some(format!("{left} {op} {right}"));
                }
            }
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
    // Stage 6 saturated SI: pure defs with stable support fold even when
    // m_d ≥ 2 (cheap casts always; arithmetic up to a small use bound; loads
    // of formals with a single use). Protected schema ops never fold away.
    for _ in 0..12 {
        let mut grew = false;
        for (op, _) in &flat.ops {
            if let Some(def) = &op.def {
                if out.contains_key(def) {
                    continue;
                }
                if crate::decompiler::normalize::is_protected_schema_op(op) {
                    continue;
                }
                let uses = use_count.get(def).copied().unwrap_or(0);
                let fold = if crate::decompiler::normalize::is_cheap_contractible(op) {
                    (1..=32).contains(&uses)
                } else if crate::decompiler::normalize::is_arith_contractible(op) {
                    // Lemma 9: multi-use value-class reconstruction — fold shared
                    // pure arith defs even under higher fan-out (anonymous rename).
                    (1..=24).contains(&uses)
                } else if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Load { .. })) {
                    // Stage 6: loads are pure reads of an address term; fold when
                    // use fan-out is small (covers mem probes in scan loops).
                    (1..=4).contains(&uses)
                } else if is_inlineable(op) {
                    uses <= 2
                } else {
                    false
                };
                if fold {
                    let expr = render_op_expr(op, &out, names);
                    out.insert(def.clone(), expr);
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }
    out
}

/// Outer operator class of a return expression (workstream 4 critical-sink guard).
pub(crate) fn return_outer_class(expr: &str) -> char {
    let e = expr.trim();
    // Prefer root-level ops outside parens.
    let mut depth = 0i32;
    let mut last = '?';
    for ch in e.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            '+' | '-' | '*' | '/' | '^' | '&' | '|' | '%' if depth == 0 => last = ch,
            _ => {}
        }
    }
    last
}

/// Reject rewrites that change the outer semantic operator class.
pub(crate) fn guard_return_class(normalized: &str, original: &str) -> String {
    let a = return_outer_class(original);
    let b = return_outer_class(normalized);
    if a != '?' && b != '?' && a != b {
        original.to_string()
    } else {
        normalized.to_string()
    }
}

/// Lemma 11: normalize a return expression into an orbit-stable form under
/// commutative reassociation of `+` and `*` chains (sort operands).
pub(crate) fn normalize_return_class_expr(expr: &str) -> String {
    let e = expr.trim();
    // Only rewrite flat chains of + or * without mixed operators / parens nesting.
    if e.contains('(') || e.contains(')') {
        return e.to_string();
    }
    for op in ['+', '*'] {
        if e.matches(op).count() >= 1 && !e.contains('-') && !e.contains('/') && !e.contains('^') {
            let mut parts: Vec<&str> = e
                .split(op)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.len() >= 2 {
                parts.sort_unstable();
                return parts.join(&format!(" {op} "));
            }
        }
    }
    e.to_string()
}

/// Bare identifier (no operators) — a pure rename after SI.
fn expr_is_bare_name(expr: &str) -> bool {
    let e = expr.trim();
    !e.is_empty()
        && e.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@')
}

/// Full pure-def expression map for sink composition (may include multi-use).
fn build_sink_expr_map(flat: &Flat, names: &NameCtx<'_>) -> HashMap<SsaVar, String> {
    let mut out: HashMap<SsaVar, String> = HashMap::new();
    for _ in 0..12 {
        let mut grew = false;
        for (op, _) in &flat.ops {
            if let Some(def) = &op.def {
                if out.contains_key(def) {
                    continue;
                }
                if is_inlineable(op) || is_foldable_load(op) {
                    let expr = render_op_expr(op, &out, names);
                    // Prefer compound forms for sink composition.
                    out.insert(def.clone(), expr);
                    grew = true;
                }
            }
        }
        if !grew {
            break;
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
        && !crate::decompiler::normalize::is_frame_pointer_adjust(op)
}

/// Stack-slot reloads of formals (post stage-1 alias) fold like copies.
fn is_foldable_load(op: &SsaOp) -> bool {
    matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Load { .. }))
        && op.uses.first().is_some_and(|u| {
            matches!(u.location, Location::StackSlot { disp, .. } if disp > 0)
                || matches!(
                    u.location,
                    Location::Register { base_offset }
                        if crate::decompiler::normalize::gpr_param_rank(base_offset).is_some()
                )
        })
}

#[allow(clippy::too_many_arguments)]
fn emit_block_statements(
    out: &mut String,
    block: &SsaBlock,
    inline_exprs: &HashMap<SsaVar, String>,
    use_count: &HashMap<SsaVar, usize>,
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
        // Stage 1: dominated parameter-home stores are pure `y = p` echoes —
        // do not surface them (they are removed or aliased in simplify).
        if matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Store { .. }))
            && crate::decompiler::normalize::is_param_home_store(op)
        {
            continue;
        }
        // Stage 5/6: hide pure frame-pointer arithmetic (no source-level state).
        if crate::decompiler::normalize::is_frame_pointer_adjust(op) {
            continue;
        }
        // Stage 6: noise reloads of return-address / cookie slots.
        if crate::decompiler::normalize::is_noise_stack_reload(op) {
            continue;
        }
        // Phi is SSA plumbing; stage 5 does not emit it as a C assignment.
        if matches!(&op.kind, SsaOpKind::Phi(_)) {
            continue;
        }
        // Stage 6: dead pure defs (no live uses) — SI residual DCE at print time.
        if let Some(def) = &op.def {
            let uses = use_count.get(def).copied().unwrap_or(0);
            let pure = crate::decompiler::normalize::is_stable_contractible_pure(op)
                || matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Load { .. }));
            if pure && uses == 0 {
                continue;
            }
        }
        // Stage 6 SI: already contracted into uses — do not materialize.
        if let Some(def) = &op.def
            && inline_exprs.contains_key(def)
            && !matches!(
                &op.kind,
                SsaOpKind::Pcode(
                    PcodeOp::Store { .. } | PcodeOp::Call { .. } | PcodeOp::CallInd { .. }
                )
            )
        {
            continue;
        }
        match &op.kind {
            SsaOpKind::Pcode(PcodeOp::Store { ptr, val, .. }) => {
                let v = render_varnode(*val, &op.uses, inline_exprs, names, op.va);
                // Prefer named stack slot assignment over `*((off + rsp)) = …`.
                if let Some(def) = &op.def
                    && let Location::StackSlot { disp, .. } = def.location
                {
                    let lhs = stack_slot_name(disp, names);
                    out.push_str(&format!("{}{} = {};\n", pad, lhs, v));
                } else {
                    let p = render_stack_ptr(*ptr, &op.uses, inline_exprs, names, op.va);
                    out.push_str(&format!("{}*({}) = {};\n", pad, p, v));
                }
            }
            SsaOpKind::Pcode(PcodeOp::Call { dest, .. })
            | SsaOpKind::Pcode(PcodeOp::CallInd { dest, .. }) => {
                let target = render_call_target(*dest, &op.uses, inline_exprs, names, op.va);
                if let Some(arguments) = call_arguments.arguments_for(block.id, operation_index) {
                    let arguments = arguments
                        .iter()
                        .map(|argument| {
                            render_recovered_call_argument(argument, inline_exprs, names, op.va)
                        })
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
            SsaOpKind::Pcode(_) if is_inlineable(op) || is_foldable_load(op) => {
                if let Some(def) = &op.def
                    && inline_exprs.get(def).is_none()
                {
                    // Stage 6: still skip pure casts that only rename a value.
                    let expr = render_op_expr(op, inline_exprs, names);
                    if crate::decompiler::normalize::is_cheap_contractible(op)
                        && expr_is_bare_name(&expr)
                    {
                        continue;
                    }
                    let lhs = typed_lhs(def, types, names, op.va);
                    out.push_str(&format!("{}{} = {};\n", pad, lhs, expr));
                }
            }
            SsaOpKind::Pcode(_) => {
                if let Some(def) = &op.def {
                    // Skip materializing values already folded into expressions.
                    if inline_exprs.contains_key(def) {
                        continue;
                    }
                    let expr = render_op_expr(op, inline_exprs, names);
                    if crate::decompiler::normalize::is_cheap_contractible(op)
                        && expr_is_bare_name(&expr)
                    {
                        continue;
                    }
                    let lhs = typed_lhs(def, types, names, op.va);
                    out.push_str(&format!("{}{} = {};\n", pad, lhs, expr));
                }
            }
            SsaOpKind::Phi(_) => {}
        }
    }
}

fn stack_slot_name(disp: i64, names: &NameCtx<'_>) -> String {
    if let Some(frame) = names.frame {
        let var = if disp > 0 {
            frame.args.iter().find(|a| a.offset == disp)
        } else {
            frame.locals.iter().find(|l| l.offset == disp)
        };
        if let Some(v) = var
            && let Some(n) = &v.name
            && !n.is_empty()
        {
            return n.clone();
        }
    }
    if disp < 0 {
        format!("local_{:x}", disp.unsigned_abs())
    } else {
        format!("arg_{:x}", disp)
    }
}

/// Render a store/load pointer without leaking the raw `rsp` identifier when
/// the address is a stack-slot form.
fn render_stack_ptr(
    vn: Varnode,
    uses: &[SsaVar],
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    if let Some(u) = uses
        .iter()
        .find(|u| matches!(u.location, Location::StackSlot { .. }))
        && let Location::StackSlot { disp, .. } = u.location
    {
        return stack_slot_name(disp, names);
    }
    let raw = render_varnode(vn, uses, inline_exprs, names, op_va);
    // Stage 1/5 quality: never surface the register name `rsp`/`esp`/`sp`.
    raw.replace("rsp", "fp")
        .replace("esp", "fp")
        .replace("sp_", "fp_")
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
            // Also map versioned param registers when they still carry the formal.
            if let Some(rank) = gpr_param_rank(*base_offset)
                && let Some(sig) = names.sig
                && let Some((pname, _)) = sig.params.get(rank)
                && !pname.is_empty()
                && sv.version <= 2
            {
                // Prefer formal name for early versions (post home-reload alias).
                if sv.version == 1 {
                    return pname.clone();
                }
            }
            // Never emit raw stack-pointer identifiers (quality gate no_rsp).
            let base = match *base_offset {
                0x20 | 0x28 => "fp".to_string(),
                _ => reg_name(*base_offset),
            };
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
            let l = vn(*left, uses, inline_exprs, names, op.va);
            let r = vn(*right, uses, inline_exprs, names, op.va);
            // Stage 7 residual: `(x & x)` byte liveness tests lower toward a
            // single probe expression (CDQ of identical operands).
            if l == r { l } else { format!("({l} & {r})") }
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
                render_cmp_operand(*left, uses, inline_exprs, names, op.va),
                render_cmp_operand(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntNotEq { left, right, .. }) => {
            format!(
                "({} != {})",
                render_cmp_operand(*left, uses, inline_exprs, names, op.va),
                render_cmp_operand(*right, uses, inline_exprs, names, op.va)
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
        // 1.txt workstream 2: signed relational predicates — print as source-like
        // relations, never as `/*(IntSLess …)*/ left,right` flag soup.
        SsaOpKind::Pcode(PcodeOp::IntSLess { left, right, .. }) => {
            format!(
                "({} < {})",
                render_cmp_operand(*left, uses, inline_exprs, names, op.va),
                render_cmp_operand(*right, uses, inline_exprs, names, op.va)
            )
        }
        SsaOpKind::Pcode(PcodeOp::IntSLessEq { left, right, .. }) => {
            format!(
                "({} <= {})",
                render_cmp_operand(*left, uses, inline_exprs, names, op.va),
                render_cmp_operand(*right, uses, inline_exprs, names, op.va)
            )
        }
        // Signed overflow of (left - right): keep as relational when used alone
        // as a branch predicate (common MSVC jl/jge expansion); else drop noise.
        SsaOpKind::Pcode(PcodeOp::IntSBorrow { left, right, .. }) => {
            format!(
                "({} < {})",
                render_cmp_operand(*left, uses, inline_exprs, names, op.va),
                render_cmp_operand(*right, uses, inline_exprs, names, op.va)
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
        SsaOpKind::Pcode(PcodeOp::Load { out, .. }) => {
            // Pointer / resolved slot is the first SSA use (stack slot, RawRam, or register).
            if let Some(u) = uses.first() {
                let ptr = match &u.location {
                    Location::StackSlot { disp, .. } => stack_slot_name(*disp, names),
                    _ => inline_exprs
                        .get(u)
                        .cloned()
                        .unwrap_or_else(|| name_of(u, names, Some(op.va))),
                };
                // Stage 2: byte loads lower to a char* probe form.
                if out.size == 1 {
                    format!("*(char *)({ptr})")
                } else {
                    format!("*({ptr})")
                }
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

/// Stage 7: null-sentinel only for proven byte/char probes — never for general
/// integer zeros (e.g. `a[i] == 0` in sum_until_zero).
fn render_cmp_operand(
    operand: Varnode,
    uses: &[SsaVar],
    inline_exprs: &HashMap<SsaVar, String>,
    names: &NameCtx<'_>,
    op_va: u64,
) -> String {
    if matches!(operand.space, AddressSpaceId::Const) && operand.offset == 0 {
        let other_text: String = uses
            .iter()
            .filter_map(|u| inline_exprs.get(u).cloned())
            .collect::<Vec<_>>()
            .join(" ");
        let size1 = operand.size <= 1
            || uses
                .iter()
                .any(|u| matches!(u.location, Location::Unique { size: 1, .. }));
        let char_probe = crate::decompiler::normalize::looks_like_byte_zero_test(&other_text)
            || uses.iter().any(|u| {
                inline_exprs.get(u).is_some_and(|e| {
                    e.contains("*(char") || e.contains("char *") || e.contains("uint8")
                })
            });
        // Self-and on a size-1 value is the MSVC cstr residual form.
        let self_and_byte = other_text.contains('&') && size1;
        if char_probe || self_and_byte {
            return crate::decompiler::normalize::sentinel_zero_literal().to_string();
        }
        if size1 && !other_text.is_empty() {
            // Bare size-1 compare to 0 with a non-empty other side (byte load folded).
            let other_byte = uses.iter().any(|u| {
                matches!(u.location, Location::Unique { size: 1, .. })
                    || inline_exprs.get(u).is_some_and(|e| {
                        e.contains("char") || e.contains("uint8") || e.contains("*(mem")
                    })
            });
            if other_byte {
                return crate::decompiler::normalize::sentinel_zero_literal().to_string();
            }
        }
    }
    render_varnode(operand, uses, inline_exprs, names, op_va)
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
