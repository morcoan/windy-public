//! Gold-derived pick compatibility for stripped function identification.
//!
//! One contract: `derive_pick_requirements(gold)` + `pick_compatible(text, gold)`.
//! Pure kernels (no CallSite gold) reject **any** calls — no loop exception.
//! Unit tests freeze a false-positive corpus from grand_scores previews.

use super::sfg::{FactKind, SfgFunctionGold};

// ── Requirements (from gold only) ───────────────────────────────────────────

/// Mechanically derived from SFG facts — no per-shell denylists.
#[derive(Clone, Debug, Default)]
pub struct PickRequirements {
    /// Any `CallSite` fact present.
    pub allows_calls: bool,
    pub requires_loop: bool,
    pub requires_switch: bool,
    /// Ordered compare surface (`<`/`>`), not mere `==`/`!=`.
    pub requires_ordered_cmp: bool,
    pub requires_multi_if: bool,
    /// Prefer return that selects/uses args (minmax-style).
    pub requires_arg_return: bool,
    /// Non-main with semantic/control facts and no CallSite.
    pub is_kernel: bool,
    pub forbids_goto_heavy: bool,
}

/// Derive pick requirements from gold facts only.
pub fn derive_pick_requirements(gold: &SfgFunctionGold) -> PickRequirements {
    let id = gold.id.to_ascii_lowercase();
    let is_main = id == "main"
        || gold
            .source_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case("main"));

    let allows_calls = gold.facts.iter().any(|f| f.kind == FactKind::CallSite);
    let requires_loop = gold.facts.iter().any(|f| f.kind == FactKind::Loop)
        // Some gold packs encode loop bounds as predicates (cursor/end) without
        // a Loop kind — still demand a structured loop for those shapes.
        || gold.facts.iter().any(|f| {
            f.match_any.iter().chain(f.must_match.iter()).any(|t| {
                let s = t.as_str();
                s.contains("cursor") || s.contains("while") || s == "end"
            })
        })
        || id.contains("decode_packet")
        || id.contains("sum_until")
        || id.contains("walk_");
    let requires_switch = gold.facts.iter().any(|f| f.kind == FactKind::Switch);

    // Only from names / Predicate facts — NOT from Operation match_any laundry
    // lists that include `<` alongside `+`/`/` for generic arith kernels (idiv).
    let requires_ordered_cmp = id.contains("signed_lt")
        || id.contains("unsigned_lt")
        || id.ends_with("_lt")
        || id == "imin"
        || id == "iabs"
        || id.contains("minmax")
        || gold.facts.iter().any(|f| {
            matches!(f.kind, FactKind::Predicate)
                && f.must_match.iter().chain(f.match_any.iter()).any(|t| {
                    let s = t.as_str();
                    s.contains('<')
                        || s.contains('>')
                        || s == "<="
                        || s == ">="
                        || s.eq_ignore_ascii_case("less")
                        || s.eq_ignore_ascii_case("greater")
                })
        });

    let if_facts = gold
        .facts
        .iter()
        .filter(|f| {
            f.kind == FactKind::ControlRegion
                && (f.must_match.iter().any(|m| m.contains("if"))
                    || f.match_any.iter().any(|m| m.contains("if")))
        })
        .count();
    let requires_multi_if =
        if_facts >= 2 || id.contains("nested") || id.contains("short_circuit") || id == "both";

    let requires_arg_return = id == "imin"
        || id == "iabs"
        || id.contains("min")
        || id.contains("max")
        || gold.facts.iter().any(|f| {
            f.kind == FactKind::Return
                && f.match_any
                    .iter()
                    .any(|t| t.contains("arg") || t.contains("param"))
        });

    let has_sem_ctrl = gold.facts.iter().any(|f| {
        matches!(
            f.kind,
            FactKind::Operation
                | FactKind::Predicate
                | FactKind::Return
                | FactKind::Loop
                | FactKind::Switch
                | FactKind::ControlRegion
                | FactKind::Store
                | FactKind::Load
                | FactKind::Constant
        )
    });
    let is_kernel = !is_main && has_sem_ctrl && !allows_calls;

    let forbids_goto_heavy = gold
        .facts
        .iter()
        .any(|f| f.id.contains("no_goto") || f.forbid.iter().any(|x| x.contains("goto")));

    PickRequirements {
        allows_calls,
        requires_loop,
        requires_switch,
        requires_ordered_cmp,
        requires_multi_if,
        requires_arg_return,
        is_kernel,
        forbids_goto_heavy,
    }
}

// ── Body features ───────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct BodyFeatures {
    pub has_loop: bool,
    pub has_switch: bool,
    #[allow(dead_code)]
    pub has_if: bool,
    pub if_count: usize,
    pub empty_if_then: bool,
    pub xor_zero_return: bool,
    pub has_ordered_compare: bool,
    #[allow(dead_code)]
    pub has_value_arith: bool,
    pub crt_add_temp_shell: bool,
    pub eh_magic: bool,
    pub call_store_trampoline: bool,
    /// CRT while(mem) + call(*(g_)) + return(fp+…)
    pub crt_while_mem_call: bool,
    /// CRT UTF-8 / multi-byte char classifier (0xe0/0xc0/char*) mistaken for kernels.
    pub crt_utf8_decoder: bool,
    /// Ordered compare that involves args/params (not mem_1 vs 0).
    pub has_arg_ordered_compare: bool,
    pub call_count: usize,
    pub goto_count: usize,
    pub body_len: usize,
    pub return_uses_args: bool,
    pub return_fp_epilogue: bool,
}

pub fn body_features(text: &str) -> BodyFeatures {
    let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
    let tl = body.to_ascii_lowercase();
    let call_count = count_calls(body);
    BodyFeatures {
        has_loop: tl.contains("while") || tl.contains("for ") || tl.contains("for("),
        has_switch: tl.contains("switch"),
        has_if: tl.contains("if ") || tl.contains("if("),
        if_count: count_if_keywords(body),
        empty_if_then: has_empty_if_then(body),
        xor_zero_return: is_xor_zero_return(body),
        has_ordered_compare: has_ordered_compare(body),
        has_value_arith: has_value_arith(body),
        crt_add_temp_shell: is_crt_add_temp_shell(body),
        eh_magic: has_eh_magic(body),
        call_store_trampoline: is_call_store_trampoline(body),
        crt_while_mem_call: is_crt_while_mem_call(body, call_count),
        crt_utf8_decoder: is_crt_utf8_decoder(body),
        has_arg_ordered_compare: has_arg_ordered_compare(body),
        call_count,
        goto_count: body.matches("goto ").count(),
        body_len: body.len(),
        return_uses_args: return_uses_args(body),
        return_fp_epilogue: return_fp_epilogue(body),
    }
}

fn count_calls(body: &str) -> usize {
    let mut n = body.matches("call(").count() + body.matches("__imp_").count();
    // FUN_ as callee (not the function's own signature — body only).
    n += body.matches("FUN_").count();
    // call(*(g_…)) style
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("call(*(") || compact.contains("call(*(g_") {
        n = n.max(1);
    }
    n
}

fn count_if_keywords(body: &str) -> usize {
    let mut n = 0;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i].eq_ignore_ascii_case(&b'i') && bytes[i + 1].eq_ignore_ascii_case(&b'f') {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let next = bytes.get(i + 2).copied().unwrap_or(b' ');
            if prev_ok && (next == b' ' || next == b'(' || next == b'\t') {
                n += 1;
            }
        }
        i += 1;
    }
    n
}

fn is_xor_zero_return(body: &str) -> bool {
    body.lines().any(|line| {
        let t = line.to_ascii_lowercase();
        t.contains("return")
            && ((t.contains("rax") && t.contains('^') && t.matches("rax").count() >= 2)
                || t.contains("((u64)rax ^ (u64)rax)"))
    })
}

fn is_crt_temp_return_line(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with("return") || t.matches('+').count() < 2 {
        return false;
    }
    // CRT temps look like `t_140001e838000_4@140001e7c` — require `@` markers,
    // not bare `t_14` prefixes that match ordinary `t_14000…` address labels.
    let at_temps = t.matches('@').count();
    at_temps >= 2 && t.contains("t_14")
}

fn count_crt_at_temps(body: &str) -> usize {
    // Count `t_…@…` tokens approximately via '@' near t_.
    body.matches('@').count()
}

fn is_crt_add_temp_shell(body: &str) -> bool {
    let ret_temp = body
        .lines()
        .filter(|l| l.trim().starts_with("return"))
        .any(is_crt_temp_return_line);
    if !ret_temp {
        return false;
    }
    // CRT SEH / exception residue: mem_1 OF-style check + multi t_@ add return.
    // Note: the condition often contains `<`, so do NOT require !has_ordered_compare.
    let has_mem = body.contains("mem_1") || body.contains("*(mem");
    let of_noise =
        has_mem && body.contains("< 0x0") && (body.contains("!=") || body.contains("!= "));
    let multi_temp = count_crt_at_temps(body) >= 2;
    has_mem && (of_noise || multi_temp)
}

/// CRT UTF-8 lead-byte classifier shared across many PEs under strip.
fn is_crt_utf8_decoder(body: &str) -> bool {
    // Require multi-byte UTF-8 lead masks (not bare 0x80 which appears in many kernels).
    let has_mask = body.contains("0xe0") || body.contains("0xc0") || body.contains("0xf0");
    let has_char = body.contains("char *") || body.contains("uint8") || body.contains("*(char");
    let has_mem = body.contains("mem_1") || body.contains("*(mem");
    has_mask && has_char && has_mem && count_if_keywords(body) >= 2
}

fn has_eh_magic(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("0xe06d7363")
        || l.contains("e06d7363")
        || l.contains("0x19930520")
        || l.contains("19930520")
}

fn is_call_store_trampoline(body: &str) -> bool {
    let has_rbx = body.contains("arg_0 = rbx") || body.contains("arg_0=rbx");
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let has_rcx = compact.contains("*(rcx)=") || compact.contains("*((rcx");
    let calls = count_calls(body);
    has_rbx && has_rcx && calls >= 1
}

/// Shared CRT scanner: while (bound) { if (mem) call(*(g_)); } return (fp+…).
fn is_crt_while_mem_call(body: &str, call_count: usize) -> bool {
    if !body.to_ascii_lowercase().contains("while") {
        return false;
    }
    let has_mem = body.contains("mem_1") || body.contains("*(mem");
    let has_g_call = body.contains("call(*(")
        || body.contains("call(*(g_")
        || body.contains("g_14001")
        || body.contains("*(g_");
    let fp_ret = return_fp_epilogue(body);
    // Classic shape: loop + mem probe + external call + frame return.
    has_mem && fp_ret && (has_g_call || call_count >= 1)
}

fn return_fp_epilogue(body: &str) -> bool {
    body.lines().any(|l| {
        let t = l.trim().to_ascii_lowercase();
        t.starts_with("return") && (t.contains("fp_") || t.contains("fp +") || t.contains("fp+"))
    })
}

fn has_empty_if_then(body: &str) -> bool {
    let mut compact = String::new();
    let mut prev = false;
    for ch in body.chars() {
        if ch.is_whitespace() {
            if !prev {
                compact.push(' ');
                prev = true;
            }
        } else {
            compact.push(ch);
            prev = false;
        }
    }
    let c = compact.to_ascii_lowercase();
    c.contains(") { }") || c.contains("){ }") || c.contains(") {}")
}

fn has_ordered_compare(body: &str) -> bool {
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' || b[i] == b'>' {
            if i + 1 < b.len() && b[i + 1] == b[i] {
                i += 2;
                continue;
            }
            return true;
        }
        i += 1;
    }
    false
}

/// True when an ordered compare involves args/params (bench kernel shape).
fn has_arg_ordered_compare(body: &str) -> bool {
    // Scan for `arg… <` / `arg… >` / `*(arg…)` near `<`/`>` within a line.
    for line in body.lines() {
        let l = line.to_ascii_lowercase();
        if !(l.contains('<') || l.contains('>')) {
            continue;
        }
        // Skip pure mem_1 / constant OF probes.
        let has_arg = l.contains("arg") || l.contains("param");
        if !has_arg {
            continue;
        }
        // Require that the comparison is not solely mem_1 vs 0 with a t_14 return nearby.
        if l.contains("mem_1") && !l.contains("arg") {
            continue;
        }
        // Find ordered op not part of << >>
        let b = l.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'<' || b[i] == b'>' {
                if i + 1 < b.len() && b[i + 1] == b[i] {
                    i += 2;
                    continue;
                }
                // Window around operator must mention arg on at least one side.
                let start = i.saturating_sub(40);
                let end = (i + 40).min(b.len());
                let win = &l[start..end];
                if win.contains("arg") || win.contains("param") {
                    return true;
                }
            }
            i += 1;
        }
    }
    false
}

fn has_value_arith(body: &str) -> bool {
    for line in body.lines() {
        let t = line.trim();
        if is_xor_zero_return_line_simple(t) || is_crt_temp_return_line(t) || return_fp_epilogue(t)
        {
            continue;
        }
        for (i, ch) in t.bytes().enumerate() {
            match ch {
                b'+' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' => return true,
                b'-' => {
                    let prev = if i > 0 { t.as_bytes()[i - 1] } else { b' ' };
                    let next = t.as_bytes().get(i + 1).copied().unwrap_or(b' ');
                    if prev != b'-' && next != b'>' && next != b'-' {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn is_xor_zero_return_line_simple(line: &str) -> bool {
    let t = line.to_ascii_lowercase();
    t.contains("return") && t.contains("rax") && t.contains('^') && t.matches("rax").count() >= 2
}

fn return_uses_args(body: &str) -> bool {
    body.lines()
        .filter(|l| l.trim().starts_with("return"))
        .any(|l| {
            let t = l.to_ascii_lowercase();
            (t.contains("arg") || t.contains("param"))
                && !is_crt_temp_return_line(l)
                && !is_xor_zero_return_line_simple(l)
                && !return_fp_epilogue(l)
        })
}

// ── Single compatibility entry point ────────────────────────────────────────

/// Returns `None` if `text` may be assigned to `gold`; `Some(reason)` to reject.
/// Prefer empty unmatched over a wrong CRT shell.
pub fn pick_compatible(text: &str, gold: &SfgFunctionGold) -> Option<&'static str> {
    if text.trim().is_empty() {
        return Some("empty_text");
    }
    let req = derive_pick_requirements(gold);
    let f = body_features(text);
    let id = gold.id.as_str();

    // ── Absolute CRT / EH shells (any non-main kernel) ─────────────────────
    if req.is_kernel || id != "main" {
        if f.eh_magic {
            return Some("eh_magic_shell");
        }
        if f.crt_add_temp_shell {
            return Some("crt_add_temp_shell");
        }
        if f.call_store_trampoline {
            return Some("call_store_trampoline");
        }
        if f.crt_while_mem_call {
            return Some("crt_while_mem_call");
        }
        if f.crt_utf8_decoder {
            return Some("crt_utf8_decoder_shell");
        }
        if f.xor_zero_return && f.empty_if_then {
            return Some("empty_if_xor_zero_shell");
        }
        // XOR-zero return alone is CRT-ish, but COM/refcount helpers often
        // return S_OK via `xor eax,eax` after a real store / if — keep those.
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let looks_like_work = f.has_if
            && (body.contains('=')
                || body.contains("g_14")
                || body.contains("0x14001")
                || body.contains("arg_"));
        if f.xor_zero_return
            && !f.has_ordered_compare
            && !f.has_loop
            && f.body_len < 400
            && !looks_like_work
        {
            return Some("xor_zero_return_shell");
        }
    }

    // ── Hard rule: pure leaf kernels ⇒ zero calls ─────────────────────────
    // Atomic arith/compare kernels (lt/min/idiv) never call. Multi-block
    // bosses (decode_packet) legitimately call helpers; CRT while+call shells
    // are already rejected by `crt_while_mem_call` above — do not re-open that.
    if req.is_kernel
        && !req.allows_calls
        && f.call_count > 0
        && !(req.requires_loop || req.requires_switch)
    {
        return Some("pure_kernel_with_calls");
    }

    // ── Positive requirements ──────────────────────────────────────────────
    if req.requires_loop && !f.has_loop {
        return Some("missing_loop");
    }
    if req.requires_switch && !f.has_switch {
        // if-ladder may stand in for switch only when it is a real multi-arm
        // ladder (≥3 ifs). Short 1–2 if bodies (e.g. read_header) must not
        // claim switch-bearing gold like decode_packet / handle_record.
        if f.if_count < 3 {
            return Some("missing_switch");
        }
    }
    if req.requires_ordered_cmp && !f.has_arg_ordered_compare {
        // Bare mem_1 < 0 or char < '\0' is not a kernel ordered compare.
        return Some("missing_ordered_compare");
    }
    // Ordered compare inside a CRT while-bound does not count if shell already hit;
    // also reject when the only '<' is in while(t_*) CRT bound without arg compare.
    if req.requires_ordered_cmp && f.has_ordered_compare && f.return_fp_epilogue && f.call_count > 0
    {
        return Some("ordered_cmp_in_crt_shell");
    }
    if req.requires_multi_if && f.if_count < 2 {
        return Some("missing_multi_if");
    }
    // Minmax must select via args — mem/char ordered compares do not count.
    if req.requires_arg_return && !f.return_uses_args && !f.has_arg_ordered_compare {
        return Some("minmax_without_arg_select");
    }
    if req.forbids_goto_heavy && f.goto_count >= 2 {
        return Some("goto_forbidden");
    }

    // COM method shapes
    let idl = id.to_ascii_lowercase();
    if idl == "addref" {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let has_refcount = (body.contains("g_14") || body.contains("0x14001"))
            && body.contains('+')
            && (body.contains("0x1") || body.contains("+ 1"));
        if !has_refcount {
            return Some("addref_not_increment");
        }
    }
    if idl == "release" {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let has_dec = (body.contains("g_14") || body.contains("0x14001") || body.contains("mem_"))
            && (body.contains("- 0x1")
                || body.contains("-0x1")
                || body.contains("ff c8")
                || (body.contains('-') && body.contains("0x1")));
        // Prefer empty over a pure `return *(arg)` stub.
        if !has_dec && f.call_count == 0 && body.len() < 120 && !body.contains('=') {
            return Some("release_not_decrement");
        }
        if !has_dec && body.matches('=').count() == 0 && f.body_len < 80 {
            return Some("release_not_decrement");
        }
    }
    if idl == "queryinterface" {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        // Real QI: null-ppv → E_POINTER (0x80004003) and/or store through out-param.
        let has_ep = body.contains("80004003") || body.contains("0x80004003");
        let has_store = body.contains("*(rax)")
            || body.contains("*(rcx)")
            || body.contains("*(arg")
            || (body.contains("= *(") || body.contains(") ="));
        let has_if = body.contains("if");
        if body.contains('+') && !has_if && f.call_count == 0 && body.len() < 250 {
            return Some("qi_not_interface_query");
        }
        // Reject CRT stubs that lack both E_POINTER and a store/if shape.
        if !has_ep && !has_if && f.body_len < 100 {
            return Some("qi_not_interface_query");
        }
        if !has_ep && !has_store && f.call_count == 0 && f.body_len < 160 {
            return Some("qi_missing_epointer_or_store");
        }
    }

    // Lifetime / store golds (res_init, res_destroy, …): reject pure constant returns.
    let gold_wants_store = gold.facts.iter().any(|fact| {
        matches!(
            fact.kind,
            crate::grand_bench::sfg::FactKind::Store
                | crate::grand_bench::sfg::FactKind::LifetimeRegion
        ) || fact.residual_on_miss.as_ref().is_some_and(|r| {
            matches!(
                r,
                crate::grand_bench::sfg::ResidualClass::MissingStore
                    | crate::grand_bench::sfg::ResidualClass::LifetimeCleanupMissing
            )
        })
    });
    if gold_wants_store {
        let body = text.split_once('{').map(|(_, b)| b).unwrap_or(text);
        let has_store = body.contains("=(")
            || body.contains("= *")
            || body.contains("*(")
            || body.contains(") =")
            || body.matches('=').count()
                > body.matches("==").count()
                    + body.matches("!=").count()
                    + body.matches("<=").count()
                    + body.matches(">=").count();
        // `return 0x1;` / bare return with no assignment cannot satisfy MISSING_STORE.
        if !has_store && f.call_count == 0 && f.body_len < 80 {
            return Some("store_gold_without_store");
        }
    }

    // continue/skip loop kernels: reject high-VA UTF-8 CRT lead-byte shells.
    if req.requires_loop && f.crt_utf8_decoder {
        return Some("loop_utf8_shell");
    }

    None
}

/// Alias used by existing call sites.
pub fn hard_reject(text: &str, gold: &SfgFunctionGold) -> Option<&'static str> {
    pick_compatible(text, gold)
}

/// Integrity: body is a non-kernel shell for a synthetic pure-kernel audit gold.
pub fn is_shared_nonkernel_shell(text: &str) -> bool {
    let f = body_features(text);
    f.crt_add_temp_shell
        || f.eh_magic
        || f.call_store_trampoline
        || f.crt_while_mem_call
        || f.crt_utf8_decoder
        || (f.xor_zero_return && f.empty_if_then)
        || (f.call_count > 0 && f.return_fp_epilogue && f.has_loop && f.body_len < 500)
}

// ── Tests: frozen false-positive corpus ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grand_bench::sfg::{FactDimension, FactKind, FactSlice, SfgFact, SfgFunctionGold};

    fn fact(id: &str, kind: FactKind, must: &[&str], any: &[&str], critical: bool) -> SfgFact {
        SfgFact {
            id: id.into(),
            kind,
            dimension: FactDimension::Semantic,
            critical,
            must_match: must.iter().map(|s| (*s).into()).collect(),
            match_any: any.iter().map(|s| (*s).into()).collect(),
            forbid: vec![],
            depends_on: vec![],
            slice: FactSlice::Any,
            residual_on_miss: None,
            residual_on_forbid: None,
            catastrophic_cap: None,
            min_multiplicity: None,
            return_ops: vec![],
            ordered_match: vec![],
        }
    }

    fn gold_op(id: &str, any_ops: &[&str]) -> SfgFunctionGold {
        SfgFunctionGold {
            id: id.into(),
            source_name: Some(id.into()),
            entry_va: None,
            facts: vec![
                fact("ret", FactKind::Return, &["return"], &[], true),
                fact("if_region", FactKind::ControlRegion, &["if"], &[], false),
                fact("op", FactKind::Operation, &[], any_ops, true),
            ],
        }
    }

    fn gold_unsigned_lt() -> SfgFunctionGold {
        gold_op(
            "unsigned_lt",
            &["+", "-", "*", "/", "&", "|", "^", "<", ">", "="],
        )
    }

    fn gold_imin() -> SfgFunctionGold {
        SfgFunctionGold {
            id: "imin".into(),
            source_name: Some("imin".into()),
            entry_va: None,
            facts: vec![
                fact("ret", FactKind::Return, &["return"], &[], true),
                fact("if_region", FactKind::ControlRegion, &["if"], &[], false),
            ],
        }
    }

    // ── Exact false-positive previews from grand_scores.json ────────────────

    /// CRT while+mem+call+fp-return (unsigned_lt P1 rematch after prior bans).
    const FP_CRT_WHILE: &str = r#"uint64 FUN_140001828() {
 arg_8 = rbx;
 arg_0 = rdi;
 while ((rbx_3 < t_14000185b0000)) {
 if (!((*(mem_1) == 0x0))) {
 arg_0 = 0x140001850;
 call(*(g_140010270));
 }
 }
 return (fp_4 + 0x30);
}
"#;

    const FP_CRT_WHILE_IMIN: &str = r#"uint64 FUN_1400018dc() {
 arg_8 = rbx;
 arg_0 = rdi;
 while ((rbx_3 < t_14000190f0000)) {
 if (!((*(mem_1) == 0x0))) {
 arg_0 = 0x140001904;
 call(*(g_140010270));
 }
 }
 return (fp_4 + 0x30);
}
"#;

    const FP_XOR: &str = r#"uint64 FUN_140001dac(u64 arg1, u64 arg2) {
 if ((!((arg1 - t_140001db30000) == 0x0))) {
 } else {
 return ((u64)rax ^ (u64)rax);
 }
}
"#;

    const FP_ADD_TEMP: &str = r#"uint64 FUN_140001e5c(u64 arg1, u64 arg2) {
 if (( *(mem_1),0x0 != (*(mem_1) - 0x0),0x0)) {
 return (((u64)t_140001e638000_4@140001e5c + arg1) + ((u64)t_140001e7b8003_4@140001e74 + (u64)t_140001e6f8003_4@140001e68));
 } else {
 return (((u64)t_140001e908000_4@140001e89 + arg1) + ((u64)t_140001ea88003_4@140001e9f + (u64)t_140001e9c8003_4@140001e93));
 }
}
"#;

    /// Live rematch after prior ban: OF check uses `<` so old !has_ordered_compare gate missed it.
    const FP_ADD_TEMP_WITH_LT: &str = r#"uint64 FUN_140001e7c(u64 arg1, u64 arg2) {
 if (((*(mem_1) < 0x0) != ((*(mem_1) - 0x0) < 0x0))) {
 return (((u64)t_140001e838000_4@140001e7c + arg1) + ((u64)t_140001e9b8003_4@140001e94 + (u64)t_140001e8f8003_4@140001e88));
 } else {
 return (((u64)t_140001eb08000_4@140001ea9 + arg1) + ((u64)t_140001ec88003_4@140001ebf + (u64)t_140001ebc8003_4@140001eb3));
 }
}
"#;

    /// Live rematch: CRT UTF-8 lead-byte classifier scoring 0.975 on imin/unsigned_lt.
    const FP_UTF8: &str = r#"uint64 FUN_14000a73c(u64 arg1) {
 uint8 rdx_2 = *(char *)(mem_1);
 if ((rdx_2 < '\0')) {
 if ((!(((rax & 0xe0) - 0xc0) == '\0'))) {
 if ((!(((rax & 0xf0) - 0xe0) == '\0'))) {
 return 0x1;
 }
 }
 }
 return 0x0;
}
"#;

    const FP_EH: &str = r#"uint64 FUN_140001dc4(u64 arg1) {
 if (!((arg1 == 0x0))) {
 if ((!((*(mem_1) - 0xe06d7363) == 0x0)) && (!((*(mem_1) - 0x4) == 0x0))) {
 if (((*(mem_1) - 0x19930520) == 0x0)) {
 return *(arg_0);
 }
 }
 }
 return;
}
"#;

    const FP_CALL_TRAMP: &str = r#"uint64 FUN_140002910(u64 arg1, u64 arg2) {
 arg_0 = rbx;
 *(rcx) = arg2;
 arg_0 = 0x140002921;
 call(FUN_140001fec);
 if ((!(rbx < *(mem_2)))) {
 *((rbx + 0x8)) = (arg1 ^ arg1);
 arg_0 = 0x14000293d;
 call(FUN_140001fec);
 } else {
 arg_0 = 0x14000294a;
 call(FUN_140001fec);
 }
 return *(arg_0);
}
"#;

    const OK_UNSIGNED_LT: &str = r#"uint64 FUN_140001040(u64 arg1, u64 arg2) {
 if ((!(*(arg_20) < *(arg_28)))) {
 arg_0 = 0x0;
 return (!(*(arg_20) < *(arg_28)));
 } else {
 arg_0 = 0x1;
 return (!(*(arg_20) < *(arg_28)));
 }
}
"#;

    /// Bad corpus: every entry must be rejected for the named gold.
    fn bad_corpus() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("unsigned_lt", FP_CRT_WHILE, "crt_while"),
            ("imin", FP_CRT_WHILE_IMIN, "crt_while_imin"),
            ("irem", FP_CRT_WHILE, "crt_while_irem"),
            ("apply", FP_CRT_WHILE, "crt_while_apply"),
            ("iabs", FP_CRT_WHILE, "crt_while_iabs"),
            ("unsigned_lt", FP_XOR, "xor"),
            ("imin", FP_XOR, "xor_imin"),
            ("imin", FP_ADD_TEMP, "add_temp"),
            ("unsigned_lt", FP_ADD_TEMP, "add_temp_ult"),
            ("iabs", FP_ADD_TEMP_WITH_LT, "add_temp_with_lt"),
            ("signed_lt", FP_ADD_TEMP_WITH_LT, "add_temp_signed_lt"),
            ("idiv", FP_ADD_TEMP_WITH_LT, "add_temp_idiv"),
            ("narrow_add", FP_ADD_TEMP_WITH_LT, "add_temp_narrow"),
            ("imin", FP_UTF8, "utf8_imin"),
            ("unsigned_lt", FP_UTF8, "utf8_ult"),
            ("iabs", FP_UTF8, "utf8_iabs"),
            ("irem", FP_UTF8, "utf8_irem"),
            ("apply", FP_UTF8, "utf8_apply"),
            ("unsigned_lt", FP_EH, "eh"),
            ("irem", FP_EH, "eh_irem"),
            ("signed_lt", FP_CALL_TRAMP, "tramp"),
            ("narrow_add", FP_CALL_TRAMP, "tramp_narrow"),
            ("imin", FP_CALL_TRAMP, "tramp_imin"),
        ]
    }

    fn gold_for_id(id: &str) -> SfgFunctionGold {
        match id {
            "unsigned_lt" | "signed_lt" => {
                gold_op(id, &["+", "-", "*", "/", "&", "|", "^", "<", ">", "="])
            }
            "imin" | "iabs" => gold_imin(),
            "irem" | "idiv" | "narrow_add" | "apply" => gold_op(id, &["%", "/", "+", "*", "rem"]),
            _ => gold_op(id, &["+", "<", ">"]),
        }
    }

    #[test]
    fn corpus_bad_previews_all_reject() {
        for (gid, text, tag) in bad_corpus() {
            let g = gold_for_id(gid);
            let why = pick_compatible(text, &g);
            assert!(
                why.is_some(),
                "expected reject for gold={gid} tag={tag}, got accept\n{text}"
            );
        }
    }

    #[test]
    fn corpus_good_previews_all_accept() {
        let g = gold_unsigned_lt();
        assert!(
            pick_compatible(OK_UNSIGNED_LT, &g).is_none(),
            "got {:?}",
            pick_compatible(OK_UNSIGNED_LT, &g)
        );
        let req = derive_pick_requirements(&g);
        assert!(req.is_kernel);
        assert!(!req.allows_calls);
        assert!(req.requires_ordered_cmp);
    }

    #[test]
    fn pure_kernel_rejects_any_call_even_with_loop() {
        // Strategist hard rule: no has_loop exception for pure kernels.
        let g = gold_unsigned_lt();
        let f = body_features(FP_CRT_WHILE);
        assert!(f.has_loop && f.call_count >= 1);
        let why = pick_compatible(FP_CRT_WHILE, &g);
        assert!(
            matches!(
                why,
                Some("pure_kernel_with_calls") | Some("crt_while_mem_call")
            ),
            "got {why:?}"
        );
    }

    #[test]
    fn main_allows_calls_requirement() {
        let g = SfgFunctionGold {
            id: "main".into(),
            source_name: Some("main".into()),
            entry_va: None,
            facts: vec![
                fact("ret", FactKind::Return, &["return"], &[], true),
                fact("call", FactKind::CallSite, &[], &["FUN_", "fun_"], true),
            ],
        };
        let req = derive_pick_requirements(&g);
        assert!(req.allows_calls);
        assert!(!req.is_kernel);
    }

    #[test]
    fn integrity_shell_detects_crt_while() {
        assert!(is_shared_nonkernel_shell(FP_CRT_WHILE));
        assert!(is_shared_nonkernel_shell(FP_XOR));
        assert!(is_shared_nonkernel_shell(FP_EH));
        assert!(is_shared_nonkernel_shell(FP_CALL_TRAMP));
        assert!(is_shared_nonkernel_shell(FP_ADD_TEMP_WITH_LT));
        assert!(is_shared_nonkernel_shell(FP_UTF8));
        assert!(!is_shared_nonkernel_shell(OK_UNSIGNED_LT));
    }

    #[test]
    fn eq_is_not_ordered_compare() {
        assert!(!has_ordered_compare("if ((*(mem_1) != 0x0)) { return 1; }"));
        assert!(has_ordered_compare(
            "if ((*(arg_20) < *(arg_28))) { return 1; }"
        ));
        assert!(has_arg_ordered_compare(
            "if ((*(arg_20) < *(arg_28))) { return 1; }"
        ));
        assert!(!has_arg_ordered_compare(
            "if (((*(mem_1) < 0x0) != ((*(mem_1) - 0x0) < 0x0))) { return 1; }"
        ));
    }

    #[test]
    fn add_temp_with_lt_is_shell() {
        assert!(body_features(FP_ADD_TEMP_WITH_LT).crt_add_temp_shell);
        assert!(body_features(FP_ADD_TEMP_WITH_LT).has_ordered_compare);
        assert!(!body_features(FP_ADD_TEMP_WITH_LT).has_arg_ordered_compare);
    }

    #[test]
    fn utf8_decoder_is_shell() {
        assert!(body_features(FP_UTF8).crt_utf8_decoder);
        let g = gold_imin();
        assert!(pick_compatible(FP_UTF8, &g).is_some());
    }
}
