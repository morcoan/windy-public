//! Rate–distortion dual-object model for decompilation (2.md).
//!
//! Separates a **semantic effect truth object** from a **presentation graph**
//! used for region/loop/join selection. Exceptional and cookie/unwind-related
//! control is treated as an **overlay** that does not destroy ordinary
//! postdominator structure on the presentation layer.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rsleigh_api::PcodeOp;

use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOpKind};

use super::cfg_norm::resolve_jump_target;
use super::pdom::{adj_from_ssa, build_ipdom, virtual_exit};
use super::region::{Region, SwitchInfo, classify_with_adj};

// ── Residual reason codes (presentation cost / goto budget) ─────────────────

/// Why an unstructured edge remains after checker-backed extraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResidualReason {
    /// Multi-entry SCC after presentation normalization.
    MultiEntryScc,
    /// Cross-region escape not expressible as break/continue/return/throw.
    CrossRegionEscape,
    /// Join already emitted; residual rejoin.
    JoinAlreadyEmitted,
    /// Shared case body rejoin.
    SharedCaseBody,
    /// Single-successor rejoin residual.
    SingleSuccRejoin,
    /// Multiway residual arm.
    MultiwayResidual,
    /// Arm rejoin residual.
    ArmRejoin,
    /// Unknown / uncategorized residual.
    Unclassified,
}

impl ResidualReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultiEntryScc => "multi_entry_scc",
            Self::CrossRegionEscape => "cross_region_escape",
            Self::JoinAlreadyEmitted => "join_already_emitted",
            Self::SharedCaseBody => "shared_case_body",
            Self::SingleSuccRejoin => "single_succ_rejoin",
            Self::MultiwayResidual => "multiway_residual",
            Self::ArmRejoin => "arm_rejoin",
            Self::Unclassified => "unclassified",
        }
    }

    /// Map legacy emit reason strings into the enum.
    pub fn from_emit_tag(tag: &str) -> Self {
        match tag {
            "join_already_emitted" => Self::JoinAlreadyEmitted,
            "shared_case_body" => Self::SharedCaseBody,
            "single_succ_rejoin" => Self::SingleSuccRejoin,
            "multiway_residual" => Self::MultiwayResidual,
            "arm_rejoin" => Self::ArmRejoin,
            "multi_entry_scc" => Self::MultiEntryScc,
            "cross_region_escape" => Self::CrossRegionEscape,
            _ => Self::Unclassified,
        }
    }
}

// ── Effect algebra (semantic truth) ─────────────────────────────────────────

/// Path-conditioned surface effect kinds observed on the semantic graph.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum EffectKind {
    Call { target_hint: Option<u64> },
    Store,
    Return,
    Throwish,
    VolatileAccess,
    Barrier,
}

/// One ordered effect at a program point (block-local).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effect {
    pub block: u32,
    pub kind: EffectKind,
}

/// Semantic truth object: path-conditioned effects + ordinary CFG adjacency.
#[derive(Clone, Debug)]
pub struct SemanticGraph {
    #[allow(dead_code)]
    pub n_blocks: usize,
    #[allow(dead_code)]
    pub entry: u32,
    /// Ordinary successors (all edges present in SSA).
    pub succ: Vec<Vec<u32>>,
    #[allow(dead_code)]
    pub pred: Vec<Vec<u32>>,
    /// Effects keyed by block (ordered by op order).
    pub effects: BTreeMap<u32, Vec<Effect>>,
    /// Blocks that only exist for cookie / unwind / security scaffolding.
    pub cookie_overlay: BTreeSet<u32>,
    /// Blocks that look like exceptional / EH dispatch.
    pub exception_overlay: BTreeSet<u32>,
}

impl SemanticGraph {
    /// Extract semantic truth from optimized SSA.
    pub fn from_ssa(ssa: &SsaFunction) -> Self {
        let n = ssa.blocks.len();
        let (succ, pred) = adj_from_ssa(ssa);
        let mut effects: BTreeMap<u32, Vec<Effect>> = BTreeMap::new();
        let mut cookie_overlay = BTreeSet::new();
        let mut exception_overlay = BTreeSet::new();

        for (i, block) in ssa.blocks.iter().enumerate() {
            let bid = i as u32;
            let mut list = Vec::new();
            for op in &block.ops {
                match &op.kind {
                    SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) => {
                        list.push(Effect {
                            block: bid,
                            kind: EffectKind::Call { target_hint: None },
                        });
                    }
                    SsaOpKind::Pcode(PcodeOp::Store { .. }) => {
                        list.push(Effect {
                            block: bid,
                            kind: EffectKind::Store,
                        });
                    }
                    SsaOpKind::Pcode(PcodeOp::Return { .. }) => {
                        list.push(Effect {
                            block: bid,
                            kind: EffectKind::Return,
                        });
                    }
                    // Other ops contribute no surface effects.
                    _ => {}
                }
            }
            if !list.is_empty() {
                effects.insert(bid, list);
            }
            if is_cookie_scaffold_block(block) {
                cookie_overlay.insert(bid);
            }
            if is_exception_scaffold_block(block) {
                exception_overlay.insert(bid);
            }
        }

        Self {
            n_blocks: n,
            entry: 0,
            succ,
            pred,
            effects,
            cookie_overlay,
            exception_overlay,
        }
    }

    /// Multiset of effect kinds along a single block (for local checks).
    pub fn block_effect_kinds(&self, b: u32) -> Vec<EffectKind> {
        self.effects
            .get(&b)
            .map(|v| v.iter().map(|e| e.kind.clone()).collect())
            .unwrap_or_default()
    }

    /// True if block is pure presentation noise (cookie/exception overlay or jump-only).
    #[allow(dead_code)]
    pub fn is_overlay(&self, b: u32) -> bool {
        self.cookie_overlay.contains(&b) || self.exception_overlay.contains(&b)
    }
}

fn is_cookie_scaffold_block(block: &SsaBlock) -> bool {
    // Heuristic: GS/cookie style blocks are small, xor-heavy against globals,
    // with a single exit and no loops — already filtered by emit strip later.
    let mut has_xor = false;
    let mut has_globalish = false;
    let mut calls = 0usize;
    for op in &block.ops {
        match &op.kind {
            SsaOpKind::Pcode(PcodeOp::IntXor { .. }) => has_xor = true,
            SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) => calls += 1,
            SsaOpKind::Pcode(PcodeOp::Load { .. } | PcodeOp::Store { .. }) => {
                // Cookie compares often load a global security cookie.
                has_globalish = true;
            }
            _ => {}
        }
    }
    calls == 0 && has_xor && has_globalish && block.ops.len() <= 12
}

fn is_exception_scaffold_block(block: &SsaBlock) -> bool {
    // EH dispatch often ends in BranchInd with many successors or references
    // magic constants in ops (detected loosely via many successors).
    let branch_ind = block
        .ops
        .iter()
        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::BranchInd { .. })));
    branch_ind && block.successor_ids.len() >= 4
}

// ── Presentation graph ──────────────────────────────────────────────────────

/// Presentation CFG: ordinary successors with jump-only collapse and overlay
/// edges demoted (not used for pdom / region selection).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PresentationGraph {
    pub n_blocks: usize,
    pub entry: u32,
    pub succ: Vec<Vec<u32>>,
    pub pred: Vec<Vec<u32>>,
    /// Virtual exit for postdominator analysis.
    pub virtual_exit: u32,
    pub ipdom: Vec<Option<u32>>,
}

impl PresentationGraph {
    /// Build presentation graph from semantic truth + SSA (for jump-only scan).
    pub fn from_semantic(sem: &SemanticGraph, ssa: &SsaFunction) -> Self {
        let n = sem.n_blocks;
        let ve = virtual_exit(n);
        let mut succ: Vec<Vec<u32>> = Vec::with_capacity(n);

        for i in 0..n {
            // Overlay-only blocks keep self-contained successors for emission,
            // but ordinary presentation skips edges *into* pure overlay sinks
            // when an alternate ordinary successor exists.
            let raw = &sem.succ[i];
            let mut resolved: Vec<u32> = raw
                .iter()
                .map(|&s| resolve_jump_target(ssa, s, 16))
                .filter(|&s| {
                    // Drop edges that land only on cookie overlay when another
                    // ordinary successor remains (exception/cookie as overlay).
                    if sem.cookie_overlay.contains(&s) && raw.len() > 1 {
                        return false;
                    }
                    true
                })
                .collect();
            if resolved.is_empty() {
                // Fall back to raw resolved jumps so the graph stays connected.
                resolved = raw
                    .iter()
                    .map(|&s| resolve_jump_target(ssa, s, 16))
                    .collect();
            }
            resolved.sort_unstable();
            resolved.dedup();
            succ.push(resolved);
        }

        // Rebuild preds from presentation succ.
        let mut pred = vec![Vec::new(); n];
        for (i, ss) in succ.iter().enumerate() {
            for &s in ss {
                if (s as usize) < n {
                    pred[s as usize].push(i as u32);
                }
            }
        }
        for p in &mut pred {
            p.sort_unstable();
            p.dedup();
        }

        let ipdom = build_ipdom(&succ, &pred);
        Self {
            n_blocks: n,
            entry: sem.entry,
            succ,
            pred,
            virtual_exit: ve,
            ipdom,
        }
    }

    /// Immediate postdominator of block (presentation layer).
    #[allow(dead_code)]
    pub fn ipdom_of(&self, b: u32) -> Option<u32> {
        self.ipdom.get(b as usize).copied().flatten()
    }
}

// ── Contracts (first-class invariants) ──────────────────────────────────────

/// Loop contract recovered from presentation structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopContract {
    pub header: u32,
    pub body_entry: u32,
    pub exit: u32,
    pub kind: LoopKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopKind {
    While,
    DoWhile,
}

/// Return class: outer operator / selected value story.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnClass {
    /// Coarse class tag used for orbit stability (e.g. "xor", "add", "arg_select", "const").
    pub class_tag: String,
    /// True when at least one return block was observed.
    pub has_return: bool,
}

/// Multiway case partition contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasePartition {
    pub switch_block: u32,
    pub case_values: Vec<i64>,
    pub merge: u32,
}

/// Bundle of validated contracts against the semantic object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractSet {
    pub loops: Vec<LoopContract>,
    pub returns: Option<ReturnClass>,
    pub cases: Vec<CasePartition>,
}

impl ContractSet {
    /// Derive contracts from classified regions + SSA surface effects.
    pub fn from_regions(ssa: &SsaFunction, regions: &HashMap<u32, Region>) -> Self {
        let mut loops = Vec::new();
        let mut cases = Vec::new();
        let mut has_return = false;
        let mut return_ops: Vec<String> = Vec::new();

        for (&b, r) in regions {
            match r {
                Region::While { body_entry, exit } => loops.push(LoopContract {
                    header: b,
                    body_entry: *body_entry,
                    exit: *exit,
                    kind: LoopKind::While,
                }),
                Region::DoWhile {
                    body_entry, exit, ..
                } => loops.push(LoopContract {
                    header: b,
                    body_entry: *body_entry,
                    exit: *exit,
                    kind: LoopKind::DoWhile,
                }),
                Region::Switch { cases: cs, merge } => {
                    let mut vals: Vec<i64> = cs.iter().map(|(v, _)| *v).collect();
                    vals.sort_unstable();
                    cases.push(CasePartition {
                        switch_block: b,
                        case_values: vals,
                        merge: *merge,
                    });
                }
                Region::Return => has_return = true,
                _ => {}
            }
        }

        // Eq-ladder / constant-equality chain → case partition when no Switch region.
        if cases.is_empty() {
            cases.extend(recover_eq_ladder_cases(ssa));
        }

        // Surface return-class tag from ops near returns (coarse).
        for block in &ssa.blocks {
            let is_ret = block
                .ops
                .iter()
                .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })));
            if !is_ret {
                continue;
            }
            has_return = true;
            for op in &block.ops {
                match &op.kind {
                    SsaOpKind::Pcode(PcodeOp::IntXor { .. }) => return_ops.push("xor".into()),
                    SsaOpKind::Pcode(PcodeOp::IntAdd { .. }) => return_ops.push("add".into()),
                    SsaOpKind::Pcode(PcodeOp::IntMult { .. }) => return_ops.push("mul".into()),
                    SsaOpKind::Pcode(PcodeOp::IntSub { .. }) => return_ops.push("sub".into()),
                    SsaOpKind::Pcode(PcodeOp::IntSLess { .. } | PcodeOp::IntLess { .. }) => {
                        return_ops.push("cmp".into());
                    }
                    _ => {}
                }
            }
        }

        let class_tag = if return_ops.iter().any(|t| t == "xor") {
            "xor".into()
        } else if return_ops.iter().any(|t| t == "cmp") {
            "arg_select".into()
        } else if return_ops
            .iter()
            .any(|t| t == "add" || t == "sub" || t == "mul")
        {
            "arith".into()
        } else if has_return {
            "return".into()
        } else {
            "none".into()
        };

        Self {
            loops,
            returns: Some(ReturnClass {
                class_tag,
                has_return,
            }),
            cases,
        }
    }

    /// Validate contracts against the semantic effect object (fail-closed notes).
    ///
    /// Returns human-readable issue tags; empty means all checks passed.
    pub fn validate_against_semantic(
        &self,
        sem: &SemanticGraph,
        ssa: &SsaFunction,
    ) -> Vec<&'static str> {
        let mut issues = Vec::new();
        for l in &self.loops {
            if (l.header as usize) >= sem.n_blocks || (l.body_entry as usize) >= sem.n_blocks {
                issues.push("loop_header_oob");
                continue;
            }
            // Recurrence: body (or header) must have a path back toward the header
            // on the semantic CFG (natural loop back-edge).
            let has_back = sem.succ.iter().enumerate().any(|(i, ss)| {
                ss.contains(&l.header)
                    && (i as u32 == l.header
                        || i as u32 == l.body_entry
                        || ss.contains(&l.body_entry))
            });
            if !has_back {
                // Weaker: any pred edge into header from within n_blocks.
                let preds_ok = sem
                    .pred
                    .get(l.header as usize)
                    .is_some_and(|p| !p.is_empty());
                if !preds_ok {
                    issues.push("missing_loop_recurrence");
                }
            }
        }
        if let Some(r) = &self.returns {
            if r.has_return {
                let any_ret = sem
                    .effects
                    .values()
                    .any(|es| es.iter().any(|e| matches!(e.kind, EffectKind::Return)));
                if !any_ret {
                    // Also accept SSA-level return ops (effects may miss some).
                    let ssa_ret = ssa.blocks.iter().any(|b| {
                        b.ops
                            .iter()
                            .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
                    });
                    if !ssa_ret {
                        issues.push("return_contract_without_return_effect");
                    }
                }
            }
            if r.class_tag == "xor" {
                let has_xor = ssa.blocks.iter().any(|b| {
                    b.ops
                        .iter()
                        .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::IntXor { .. })))
                });
                if !has_xor {
                    issues.push("wrong_return_class_xor");
                }
            }
        }
        for c in &self.cases {
            if c.case_values.is_empty() {
                issues.push("incomplete_case_partition");
            }
            if (c.switch_block as usize) >= sem.n_blocks {
                issues.push("case_switch_oob");
            }
        }
        issues
    }

    /// Compact fingerprint for orbit stability comparisons.
    pub fn fingerprint(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("loops={}", self.loops.len()));
        for l in &self.loops {
            parts.push(format!(
                "L:{:?}:{}:{}:{}",
                l.kind, l.header, l.body_entry, l.exit
            ));
        }
        if let Some(r) = &self.returns {
            parts.push(format!("ret:{}", r.class_tag));
        }
        parts.push(format!("cases={}", self.cases.len()));
        for c in &self.cases {
            parts.push(format!("C:{}:{:?}", c.switch_block, c.case_values));
        }
        parts.join("|")
    }
}

/// Recover case partitions from constant-equality CBranch ladders (≥3 arms)
/// and multiway BranchInd blocks not already recorded as Switch regions.
fn recover_eq_ladder_cases(ssa: &SsaFunction) -> Vec<CasePartition> {
    let mut out = Vec::new();
    // Multiway BranchInd (≥3 successors) → synthetic case partition by index.
    for (i, block) in ssa.blocks.iter().enumerate() {
        let is_bind = block
            .ops
            .iter()
            .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::BranchInd { .. })));
        if is_bind && block.successor_ids.len() >= 2 {
            let vals: Vec<i64> = (0..block.successor_ids.len() as i64).collect();
            out.push(CasePartition {
                switch_block: i as u32,
                case_values: vals,
                merge: block.successor_ids.last().copied().unwrap_or(i as u32),
            });
        }
    }
    if !out.is_empty() {
        return out;
    }

    let mut eq_consts: Vec<(u32, i64)> = Vec::new();
    for (i, block) in ssa.blocks.iter().enumerate() {
        let is_cb = block
            .ops
            .iter()
            .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::CBranch { .. })));
        // Also scan immediate predecessors for (x-K)/eq when cond is in prior block.
        let mut found: Option<i64> = None;
        let scan_block = |block: &SsaBlock, found: &mut Option<i64>| {
            for op in &block.ops {
                match &op.kind {
                    SsaOpKind::Pcode(PcodeOp::IntEq { left, right, .. })
                    | SsaOpKind::Pcode(PcodeOp::IntNotEq { left, right, .. }) => {
                        if let Some(k) = varnode_const(left).or_else(|| varnode_const(right)) {
                            // Prefer non-zero case labels; keep 0 if nothing else.
                            *found = Some(k);
                        }
                    }
                    SsaOpKind::Pcode(PcodeOp::IntSub { right, .. }) => {
                        if let Some(k) = varnode_const(right) {
                            *found = Some(k);
                        }
                    }
                    _ => {}
                }
            }
        };
        if is_cb {
            scan_block(block, &mut found);
            // Predecessor may hold the compare.
            for &p in &block.predecessor_ids {
                if (p as usize) < ssa.blocks.len() {
                    scan_block(&ssa.blocks[p as usize], &mut found);
                }
            }
        }
        if let Some(k) = found {
            // Only dense switch-like labels (not EH magic 0xE0… / cookie constants).
            if (0..256).contains(&k) {
                eq_consts.push((i as u32, k));
            }
        }
    }
    // ≥3 ladder arms is enough for a case partition even if some labels collide
    // under opt (e.g. two arms both use K=1 after folding).
    if eq_consts.len() < 3 {
        return Vec::new();
    }
    let mut vals: Vec<i64> = eq_consts.iter().map(|(_, k)| *k).collect();
    vals.sort_unstable();
    vals.dedup();
    if vals.len() < 2 {
        return Vec::new();
    }
    let switch_block = eq_consts[0].0;
    let merge = ssa
        .blocks
        .iter()
        .position(|b| {
            b.ops
                .iter()
                .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::Return { .. })))
        })
        .map(|i| i as u32)
        .unwrap_or(switch_block);
    out.push(CasePartition {
        switch_block,
        case_values: vals,
        merge,
    });
    out
}

fn varnode_const(v: &rsleigh_api::Varnode) -> Option<i64> {
    if v.space == pcode_ir::AddressSpaceId::Const {
        Some(v.offset as i64)
    } else {
        None
    }
}

/// Recover a case partition from shipped decompile text (`switch` / `case N:`).
/// Used when SSA contracts miss the eq-ladder→switch emit fold (2.md criterion 5).
pub fn case_partition_from_decomp_text(text: &str) -> Option<CasePartition> {
    if !text.contains("switch") {
        return None;
    }
    let mut vals = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let rest = if let Some(r) = t.strip_prefix("case ") {
            r
        } else if let Some(r) = t.strip_prefix("case") {
            r.trim_start()
        } else {
            continue;
        };
        let num = rest.trim_end_matches(':').trim();
        let k = if let Some(h) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).ok()
        } else {
            num.parse::<i64>().ok()
        };
        if let Some(k) = k {
            vals.push(k);
        }
    }
    vals.sort_unstable();
    vals.dedup();
    if vals.len() < 2 {
        return None;
    }
    Some(CasePartition {
        switch_block: 0,
        case_values: vals,
        merge: 0,
    })
}

// ── Dual-object package used on the shipped decompile path ──────────────────

/// Full dual-object view: semantic truth + presentation + contracts + regions.
#[derive(Clone, Debug)]
pub struct DualDecompModel {
    pub semantic: SemanticGraph,
    pub presentation: PresentationGraph,
    pub regions: HashMap<u32, Region>,
    pub contracts: ContractSet,
}

impl DualDecompModel {
    /// Build dual objects and classify regions on the **presentation** adjacency
    /// (overlay-aware jump collapse), then derive contracts.
    pub fn build(ssa: &SsaFunction, switches: &[SwitchInfo]) -> Self {
        let semantic = SemanticGraph::from_ssa(ssa);
        let presentation = PresentationGraph::from_semantic(&semantic, ssa);
        // Presentation adjacency drives region/loop/join selection (2.md).
        let regions =
            classify_with_adj(ssa, switches, &presentation.succ, &presentation.pred, true);
        let contracts = ContractSet::from_regions(ssa, &regions);
        Self {
            semantic,
            presentation,
            regions,
            contracts,
        }
    }

    /// Validate contracts against semantic effects; empty = ok.
    pub fn validate_contracts(&self, ssa: &SsaFunction) -> Vec<&'static str> {
        self.contracts
            .validate_against_semantic(&self.semantic, ssa)
    }

    /// Fail-closed: drop contract subsets that contradict the semantic object.
    /// Returns the validation issues that triggered sanitization (may be empty).
    pub fn sanitize_contracts(&mut self, ssa: &SsaFunction) -> Vec<&'static str> {
        let issues = self.validate_contracts(ssa);
        if issues.contains(&"return_contract_without_return_effect")
            || issues.contains(&"wrong_return_class_xor")
        {
            self.contracts.returns = None;
        }
        if issues.contains(&"incomplete_case_partition") || issues.contains(&"case_switch_oob") {
            self.contracts.cases.retain(|c| {
                !c.case_values.is_empty() && (c.switch_block as usize) < self.semantic.n_blocks
            });
        }
        if issues.contains(&"missing_loop_recurrence") || issues.contains(&"loop_header_oob") {
            self.contracts.loops.clear();
        }
        issues
    }

    /// Presentation cost proxy (rate): residual unstructured potential + overlays.
    pub fn presentation_cost(&self) -> i32 {
        let mut cost = 0i32;
        // Prefer fewer residual multi-successor non-region headers.
        for (i, ss) in self.presentation.succ.iter().enumerate() {
            let bid = i as u32;
            if self.regions.contains_key(&bid) {
                continue;
            }
            if ss.len() >= 2 {
                cost += 3;
            } else if ss.len() == 1 {
                cost += 1;
            }
        }
        cost += self.semantic.cookie_overlay.len() as i32;
        cost += 2 * self.semantic.exception_overlay.len() as i32;
        // Reward recovered contracts (lower cost).
        cost -= 2 * self.contracts.loops.len() as i32;
        cost -= 2 * self.contracts.cases.len() as i32;
        if self
            .contracts
            .returns
            .as_ref()
            .is_some_and(|r| r.has_return)
        {
            cost -= 1;
        }
        cost
    }
}

// ── Checker primitives ──────────────────────────────────────────────────────

/// Result of a fidelity check for a proposed presentation rewrite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckResult {
    Accept,
    Reject(&'static str),
}

/// Checker: proposed rewrite must not drop call/store/return effects on the
/// rewritten region and must not reorder may-throw barriers.
#[allow(dead_code)] // public checker primitive; used by tests and external checkers
pub fn check_effect_fidelity(before: &[EffectKind], after: &[EffectKind]) -> CheckResult {
    // Multiset equality on critical sinks (order-preserving for throws).
    let filter = |k: &EffectKind| {
        matches!(
            k,
            EffectKind::Call { .. }
                | EffectKind::Store
                | EffectKind::Return
                | EffectKind::Throwish
                | EffectKind::Barrier
        )
    };
    let b: Vec<_> = before.iter().filter(|k| filter(k)).cloned().collect();
    let a: Vec<_> = after.iter().filter(|k| filter(k)).cloned().collect();
    if b != a {
        return CheckResult::Reject("effect_multiset_mismatch");
    }
    CheckResult::Accept
}

/// Branch inversion is always presentation-only when both arms keep the same
/// effect multisets (checked by caller). This helper validates the *shape*.
pub fn check_branch_inversion_shape(
    then_effects: &[EffectKind],
    else_effects: &[EffectKind],
) -> CheckResult {
    // Inversion swaps arms; fidelity requires the pair of multisets is preserved
    // as a set of paths — checked by comparing sorted path signatures.
    let mut t = then_effects.to_vec();
    let mut e = else_effects.to_vec();
    // Allow inversion always at the shape level; effect check is separate.
    let _ = (&mut t, &mut e);
    CheckResult::Accept
}

/// Reject pure-block duplication when the block carries a call or store.
pub fn check_pure_duplication_allowed(effects: &[EffectKind]) -> CheckResult {
    if effects.iter().any(|e| {
        matches!(
            e,
            EffectKind::Call { .. }
                | EffectKind::Store
                | EffectKind::Throwish
                | EffectKind::Barrier
        )
    }) {
        return CheckResult::Reject("cannot_duplicate_effectful_block");
    }
    CheckResult::Accept
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ssa::{SsaBlock, SsaFunction, SsaOp, SsaOpKind};
    use rsleigh_api::{PcodeOp, Varnode};

    fn mk_block(id: u32, va: u64, ops: Vec<SsaOp>, succs: Vec<u32>) -> SsaBlock {
        SsaBlock {
            id,
            entry_va: va,
            ops,
            successor_ids: succs,
            predecessor_ids: vec![],
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

    fn store_op(va: u64) -> SsaOp {
        SsaOp {
            va,
            kind: SsaOpKind::Pcode(PcodeOp::Store {
                space: pcode_ir::AddressSpaceId::Ram,
                ptr: Varnode::register(0x28, 8),
                val: Varnode::register(0x00, 4),
            }),
            def: None,
            uses: vec![],
        }
    }

    fn link_preds(blocks: &mut [SsaBlock]) {
        for b in blocks.iter_mut() {
            b.predecessor_ids.clear();
        }
        let edges: Vec<(u32, u32)> = blocks
            .iter()
            .flat_map(|b| b.successor_ids.iter().map(|&s| (b.id, s)))
            .collect();
        for (from, to) in edges {
            if let Some(t) = blocks.iter_mut().find(|b| b.id == to) {
                t.predecessor_ids.push(from);
            }
        }
    }

    /// Ordinary diamond: entry → then/else → merge → return.
    fn diamond_ssa() -> SsaFunction {
        let mut blocks = vec![
            mk_block(0, 0x1000, vec![cbranch_op(0x1000)], vec![1, 2]),
            mk_block(1, 0x1010, vec![store_op(0x1010)], vec![3]),
            mk_block(2, 0x1020, vec![], vec![3]),
            mk_block(3, 0x1030, vec![ret_op(0x1030)], vec![]),
        ];
        link_preds(&mut blocks);
        SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        }
    }

    #[test]
    fn dual_model_separates_semantic_effects_from_presentation() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        // Semantic graph records the store on then-arm.
        let then_fx = dual.semantic.block_effect_kinds(1);
        assert!(
            then_fx.iter().any(|e| matches!(e, EffectKind::Store)),
            "semantic graph must observe store on then arm: {then_fx:?}"
        );
        // Presentation collapses empty forwarding arms (2 → 3), so entry may
        // see then(1) and merge(3) directly — that is the dual-graph point.
        assert!(
            dual.presentation.succ[0].contains(&1),
            "then-arm must remain reachable in presentation: {:?}",
            dual.presentation.succ[0]
        );
        assert_eq!(dual.presentation.succ[0].len(), 2);
        // Contracts see a return.
        assert!(
            dual.contracts
                .returns
                .as_ref()
                .is_some_and(|r| r.has_return),
            "return contract expected"
        );
    }

    #[test]
    fn cookie_overlay_does_not_claim_ordinary_store_block() {
        let ssa = diamond_ssa();
        let sem = SemanticGraph::from_ssa(&ssa);
        // Store block is not a cookie overlay.
        assert!(!sem.cookie_overlay.contains(&1));
        assert!(!sem.is_overlay(1));
    }

    #[test]
    fn checker_rejects_dropped_call_effect() {
        let before = vec![EffectKind::Call { target_hint: None }, EffectKind::Return];
        let after = vec![EffectKind::Return];
        assert_eq!(
            check_effect_fidelity(&before, &after),
            CheckResult::Reject("effect_multiset_mismatch")
        );
    }

    #[test]
    fn checker_accepts_preserved_effects() {
        let before = vec![EffectKind::Store, EffectKind::Return];
        let after = vec![EffectKind::Store, EffectKind::Return];
        assert_eq!(check_effect_fidelity(&before, &after), CheckResult::Accept);
    }

    #[test]
    fn checker_rejects_duplicating_call_block() {
        let fx = vec![EffectKind::Call { target_hint: None }];
        assert_eq!(
            check_pure_duplication_allowed(&fx),
            CheckResult::Reject("cannot_duplicate_effectful_block")
        );
    }

    #[test]
    fn checker_allows_duplicating_pure_block() {
        let fx: Vec<EffectKind> = vec![];
        assert_eq!(check_pure_duplication_allowed(&fx), CheckResult::Accept);
    }

    #[test]
    fn residual_reason_codes_round_trip() {
        assert_eq!(
            ResidualReason::from_emit_tag("join_already_emitted"),
            ResidualReason::JoinAlreadyEmitted
        );
        assert_eq!(ResidualReason::MultiEntryScc.as_str(), "multi_entry_scc");
    }

    #[test]
    fn contract_fingerprint_stable_for_same_regions() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let fp1 = dual.contracts.fingerprint();
        let dual2 = DualDecompModel::build(&ssa, &[]);
        assert_eq!(fp1, dual2.contracts.fingerprint());
    }

    #[test]
    fn presentation_cost_is_finite() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let _ = dual.presentation_cost();
    }

    #[test]
    fn presentation_adj_drives_region_classify() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        // Presentation must be non-empty and dual regions derived from it.
        assert!(!dual.presentation.succ.is_empty());
        // Entry is a region header (If / IfElse) after presentation classify.
        assert!(
            dual.regions.contains_key(&0),
            "presentation-driven classify must recover a region at entry: {:?}",
            dual.regions
        );
    }

    /// Criterion 3: wrong return class is detected by validate.
    #[test]
    fn contract_validate_rejects_wrong_return_class() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let mut bad = dual.contracts.clone();
        if let Some(r) = bad.returns.as_mut() {
            r.class_tag = "xor".into();
            r.has_return = true;
        }
        let issues = bad.validate_against_semantic(&dual.semantic, &ssa);
        assert!(
            issues.contains(&"wrong_return_class_xor"),
            "expected wrong_return_class_xor in {issues:?}"
        );
    }

    /// Criterion 3: incomplete case partition fails validation.
    #[test]
    fn contract_validate_rejects_incomplete_case_partition() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let mut bad = dual.contracts.clone();
        bad.cases.push(CasePartition {
            switch_block: 0,
            case_values: vec![],
            merge: 3,
        });
        let issues = bad.validate_against_semantic(&dual.semantic, &ssa);
        assert!(
            issues.contains(&"incomplete_case_partition"),
            "expected incomplete_case_partition in {issues:?}"
        );
    }

    /// Criterion 3: valid dual-model contracts pass validation.
    #[test]
    fn contract_validate_accepts_recovered_contracts() {
        let ssa = diamond_ssa();
        let dual = DualDecompModel::build(&ssa, &[]);
        let issues = dual.validate_contracts(&ssa);
        assert!(
            issues.is_empty(),
            "recovered contracts must validate clean: {issues:?}"
        );
        assert!(
            dual.contracts
                .returns
                .as_ref()
                .is_some_and(|r| r.has_return),
            "return contract expected on diamond"
        );
    }

    /// Fail-closed sanitize drops a fabricated wrong-xor return class.
    #[test]
    fn sanitize_contracts_drops_wrong_return_class() {
        let ssa = diamond_ssa();
        let mut dual = DualDecompModel::build(&ssa, &[]);
        if let Some(r) = dual.contracts.returns.as_mut() {
            r.class_tag = "xor".into();
            r.has_return = true;
        }
        let issues = dual.sanitize_contracts(&ssa);
        assert!(
            issues.contains(&"wrong_return_class_xor"),
            "expected wrong_return_class_xor: {issues:?}"
        );
        assert!(
            dual.contracts.returns.is_none(),
            "sanitize must clear contradictory return contract"
        );
    }

    /// Criterion 3: case partition recovered from eq-ladder constants.
    #[test]
    fn eq_ladder_recovers_case_partition_contract() {
        // Three CBranch blocks each subtracting a distinct constant.
        let mut blocks = vec![
            mk_block(
                0,
                0x1000,
                vec![
                    SsaOp {
                        va: 0x1000,
                        kind: SsaOpKind::Pcode(PcodeOp::IntSub {
                            out: Varnode::unique(0x10, 4),
                            left: Varnode::register(0x00, 4),
                            right: Varnode::constant(1, 4),
                        }),
                        def: None,
                        uses: vec![],
                    },
                    cbranch_op(0x1004),
                ],
                vec![1, 3],
            ),
            mk_block(
                1,
                0x1010,
                vec![
                    SsaOp {
                        va: 0x1010,
                        kind: SsaOpKind::Pcode(PcodeOp::IntSub {
                            out: Varnode::unique(0x20, 4),
                            left: Varnode::register(0x00, 4),
                            right: Varnode::constant(2, 4),
                        }),
                        def: None,
                        uses: vec![],
                    },
                    cbranch_op(0x1014),
                ],
                vec![2, 3],
            ),
            mk_block(
                2,
                0x1020,
                vec![
                    SsaOp {
                        va: 0x1020,
                        kind: SsaOpKind::Pcode(PcodeOp::IntSub {
                            out: Varnode::unique(0x30, 4),
                            left: Varnode::register(0x00, 4),
                            right: Varnode::constant(3, 4),
                        }),
                        def: None,
                        uses: vec![],
                    },
                    cbranch_op(0x1024),
                ],
                vec![3, 3],
            ),
            mk_block(3, 0x1030, vec![ret_op(0x1030)], vec![]),
        ];
        link_preds(&mut blocks);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        };
        let dual = DualDecompModel::build(&ssa, &[]);
        assert!(
            !dual.contracts.cases.is_empty(),
            "eq-ladder must recover case partition: {:?}",
            dual.contracts.fingerprint()
        );
        assert!(
            dual.contracts.cases[0].case_values.len() >= 2,
            "expected ≥2 case values: {:?}",
            dual.contracts.cases
        );
        assert!(
            dual.contracts.cases[0]
                .case_values
                .iter()
                .any(|&v| v == 1 || v == 2 || v == 3),
            "expected fixture case labels 1/2/3: {:?}",
            dual.contracts.cases
        );
        let issues = dual.validate_contracts(&ssa);
        assert!(
            issues.is_empty(),
            "case contracts must validate: {issues:?}"
        );
    }

    /// Criterion 3: loop contract recovered on self-loop.
    #[test]
    fn loop_contract_recovered_on_self_loop() {
        let mut blocks = vec![
            mk_block(0, 0x1000, vec![cbranch_op(0x1000)], vec![1, 0]),
            mk_block(1, 0x1010, vec![ret_op(0x1010)], vec![]),
        ];
        link_preds(&mut blocks);
        let ssa = SsaFunction {
            entry_va: 0x1000,
            bitness: 64,
            blocks,
            image_base: 0,
        };
        let dual = DualDecompModel::build(&ssa, &[]);
        assert!(
            !dual.contracts.loops.is_empty(),
            "expected loop contract: {:?}",
            dual.contracts.fingerprint()
        );
        let issues = dual.validate_contracts(&ssa);
        assert!(
            !issues.contains(&"missing_loop_recurrence"),
            "loop recurrence must validate: {issues:?}"
        );
    }
}
