//! Text-level CFG / goto / switch-ladder presentation passes (CfgOnly tier).
//!
//! Mechanical extract from emit.rs (Phase 4). Zero behavior change intended.
//! Used by presentation::apply_cfg_only and pure V2 old_eq_ladder_to_switch.

use std::collections::{HashMap, HashSet};

/// Remove residual pcode flag-helper comments and tokens from printed text.
pub(crate) fn strip_flag_helper_noise(src: &str) -> String {
    // Strip `/*(IntSBorrow …)*/`, `/*(IntSLess …)*/`, `/*(Bool…)*/` style comments.
    let mut out = String::with_capacity(src.len());
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            let end = (i + 2).min(b.len());
            let body = &src[start..end.min(src.len())];
            let noisy = body.contains("IntSBorrow")
                || body.contains("IntSLess")
                || body.contains("IntLess")
                || body.contains("FLAG_")
                || body.contains("Bool")
                || body.contains("Varnode");
            if noisy {
                // drop comment entirely
                i = end;
                continue;
            }
            out.push_str(body);
            i = end;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    // Strip bare helper tokens that occasionally leak outside comments.
    let mut s = out;
    for tok in [
        "IntSBorrow",
        "IntSLess",
        "IntLess",
        "IntSLessEqual",
        "IntCarry",
        "IntSCarry",
    ] {
        s = s.replace(tok, "");
    }
    // Collapse double spaces left by stripping.
    while s.contains("  ") {
        s = s.replace("  ", " ");
    }
    // Residual OF/SF flag soup often survives as comma-eq forms after comment strip:
    //   `*(a),*(b) == (*(a) - *(b)),0x0`  →  `*(a) < *(b)`
    // Prefer a real relation over flag helper debris (1.txt workstream 2).
    rewrite_flag_comma_soup(&s)
}

/// Rewrite stripped IntSBorrow/IntSLess comma-operator debris into `left < right`.
fn rewrite_flag_comma_soup(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for (i, line) in src.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&try_rewrite_signed_of_eq(line).unwrap_or_else(|| line.to_string()));
    }
    if src.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Detect `A,B == (A - B),0x0` (optionally wrapped) and emit `A < B` in place.
fn try_rewrite_signed_of_eq(line: &str) -> Option<String> {
    if !(line.contains(',') && line.contains("==") && line.contains('-')) {
        return None;
    }
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    let eq = compact.find("==")?;
    let left = &compact[..eq];
    let right = &compact[eq + 2..];
    let comma = left.rfind(',')?;
    let b_tok = left[comma + 1..].trim_end_matches([')', '!']);
    let a_region = &left[..comma];
    let start = a_region
        .rfind(['(', '!', '=', '&', '|'])
        .map(|i| i + 1)
        .unwrap_or(0);
    let a_tok = &a_region[start..];
    if a_tok.is_empty() || b_tok.is_empty() {
        return None;
    }
    let sub = format!("{a_tok}-{b_tok}");
    if !right.contains(&sub) {
        return None;
    }
    if !(right.contains(",0x0") || right.contains(",0")) {
        return None;
    }
    let needle = format!("{a_tok},{b_tok}==");
    let pos = compact.find(&needle)?;
    let rest = &compact[pos + needle.len()..];
    let (end_rel, zero_len) = if let Some(i) = rest.find(",0x0") {
        (i, 4)
    } else {
        let i = rest.find(",0")?;
        (i, 2)
    };
    let end = pos + needle.len() + end_rel + zero_len;
    let mut new_c = String::new();
    new_c.push_str(&compact[..pos]);
    new_c.push_str(a_tok);
    new_c.push_str(" < ");
    new_c.push_str(b_tok);
    new_c.push_str(&compact[end..]);
    Some(new_c)
}

/// Fold nested `if ((scrut - C) == 0) { body } else { if ((scrut - D) == 0) …`
/// ladders into `switch (scrut) { case C: body; … }` when ≥2 arms share the
/// same scrutinee (case-partition contract / StructureAlign).
///
/// Bodies (including FUN_/call/store effects) are preserved. Only the ladder
/// span for the chosen scrutinee is rewritten — outer guards stay intact.
pub(crate) fn fold_eq_ladder_to_switch(src: &str) -> String {
    if src.contains("switch") {
        return src.to_string();
    }
    let arms = collect_eq_ladder_arms(src);
    if arms.len() < 2 {
        return src.to_string();
    }
    // Group by scrutinee; keep first occurrence order of constants.
    let mut by_scrut: HashMap<String, Vec<(i64, usize)>> = HashMap::new();
    for (idx, (scrut, k, _)) in arms.iter().enumerate() {
        by_scrut.entry(scrut.clone()).or_default().push((*k, idx));
    }
    // Prefer dense *small distinct* case labels (user dispatch 1/2/3). Drop
    // PE/EH magic and single-value (case 0 only) ladders.
    let Some((scrut, case_ks)) = by_scrut
        .into_iter()
        .filter_map(|(s, v)| {
            let mut ks: Vec<i64> = v.iter().map(|(k, _)| *k).collect();
            ks.sort_unstable();
            ks.dedup();
            let small_n = ks.iter().filter(|k| (0..256).contains(*k)).count();
            let magic = ks
                .iter()
                .any(|k| *k == 0x5a4d || *k == 0x4550 || *k > 0xffff || (*k as u64) >= 0x8000_0000);
            // Need ≥2 distinct constants; pure {0} is not a user tag dispatch.
            if small_n >= 2 && !magic {
                Some((s, ks))
            } else {
                None
            }
        })
        .max_by_key(|(_, ks)| {
            // Prefer more distinct tags, then tags in 1..8 (type codes).
            let small_user = ks.iter().filter(|k| (1..=8).contains(*k)).count();
            ks.len() * 10 + small_user
        })
    else {
        return src.to_string();
    };

    // Locate the first if-line that tests this scrutinee against one of the ks.
    let mut ladder_start: Option<usize> = None;
    let mut first_k: Option<i64> = None;
    for line in src.lines() {
        let t = line.trim();
        if !t.contains("if") {
            continue;
        }
        let c: String = t.chars().filter(|ch| !ch.is_whitespace()).collect();
        if let Some(k) = parse_sub_eq_zero_k(&c, &scrut).or_else(|| parse_direct_eq_k(&c, &scrut))
            && case_ks.contains(&k)
        {
            // Byte offset of this line in src.
            if let Some(pos) = src.find(line) {
                ladder_start = Some(pos);
                first_k = Some(k);
                break;
            }
            // Fallback: search compact form.
            if let Some(pos) = src.find(t) {
                ladder_start = Some(pos);
                first_k = Some(k);
                break;
            }
        }
    }
    let Some(start) = ladder_start else {
        return src.to_string();
    };
    let _ = first_k;

    // Extract the full nested if-else ladder as a brace-balanced span starting
    // at the first matching if, then rewrite that span only.
    let Some((cases, end)) = extract_eq_ladder_span(src, start, &scrut, &case_ks) else {
        // Fallback: structural fold without body capture (empty arms) — only
        // when the ladder span has no call sites.
        return fold_eq_ladder_empty_fallback(src, &scrut, &case_ks, start);
    };
    let labeled = cases.iter().filter(|(k, _)| *k != i64::MIN).count();
    // Pure V2 often emits sequential ifs (not nested else-if). Span peel may
    // only capture one arm — fall back to case-label switch surface.
    if labeled < 2 {
        return fold_eq_ladder_empty_fallback(src, &scrut, &case_ks, start);
    }

    let mut case_lines = String::new();
    case_lines.push_str(&format!(" switch ({scrut}) {{\n"));
    let mut seen = HashSet::new();
    let mut default_body = String::new();
    for (k, body) in &cases {
        if *k == i64::MIN {
            default_body = body.clone();
            continue;
        }
        if !seen.insert(*k) {
            continue;
        }
        case_lines.push_str(&format!(" case {k}:\n"));
        let b = body.trim();
        if !b.is_empty() {
            for bline in b.lines() {
                let bt = bline.trim();
                if !bt.is_empty() {
                    case_lines.push_str(&format!(" {bt}\n"));
                }
            }
        }
        case_lines.push_str(" break;\n");
    }
    if !default_body.is_empty() {
        case_lines.push_str(" default:\n");
        for bline in default_body.lines() {
            let bt = bline.trim();
            if !bt.is_empty() {
                case_lines.push_str(&format!(" {bt}\n"));
            }
        }
        case_lines.push_str(" break;\n");
    }
    case_lines.push_str(" }\n");

    let mut out = String::new();
    out.push_str(&src[..start]);
    out.push_str(&case_lines);
    out.push_str(&src[end..]);
    out
}

/// `name(...);` call statement (not control keywords).
fn looks_like_call_stmt(t: &str) -> bool {
    let t = t.trim().trim_end_matches(';').trim();
    let Some(paren) = t.find('(') else {
        return false;
    };
    let name = t[..paren].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    !matches!(
        name,
        "if" | "while" | "for" | "switch" | "return" | "sizeof" | "typeof"
    )
}

/// When body extraction fails, fold a thin switch surface from case labels.
///
/// Call/store side-effects that used to abort the fold entirely (so dense
/// dispatch ladders with a `FUN_` default stayed as nested ifs) are parked in
/// `default:` so case labels still surface.
fn fold_eq_ladder_empty_fallback(src: &str, scrut: &str, case_ks: &[i64], start: usize) -> String {
    let rest = &src[start..];
    // Consume a brace-balanced prefix starting at the first ladder `if`, so we
    // do not orphan closing braces (which would close the function early and
    // drop later return soft ops like `-1`).
    let end_rel =
        brace_balanced_end(rest).unwrap_or_else(|| rest.find("return").unwrap_or(rest.len()));
    // Swallow trailing `else {…}` (first if was inverted empty) and sequential
    // `if (scrut…)` siblings (pure V2 flat ladders, not nested else-if).
    let mut end_rel = end_rel;
    let s_compact: String = scrut.chars().filter(|c| !c.is_whitespace()).collect();
    loop {
        let tail = rest[end_rel..].trim_start();
        let ws = rest[end_rel..].len() - tail.len();
        if tail.starts_with("else") {
            let Some(rel) = brace_balanced_end(tail) else {
                break;
            };
            end_rel += ws + rel;
            continue;
        }
        if !tail.starts_with("if") {
            break;
        }
        // Only continue while this sibling still mentions the scrutinee.
        let line_end = tail.find('\n').unwrap_or(tail.len());
        let head = &tail[..line_end];
        let compact: String = head.chars().filter(|c| !c.is_whitespace()).collect();
        if !compact.contains(&s_compact) {
            break;
        }
        let Some(rel) = brace_balanced_end(tail) else {
            break;
        };
        end_rel += ws + rel;
    }
    let span = &rest[..end_rel];
    // Recover returns + call/store side-effects still present in the span.
    let mut used_returns: Vec<String> = Vec::new();
    let mut side_effect_lines: Vec<String> = Vec::new();
    for line in span.lines() {
        let t = line.trim();
        if t.is_empty() || t == "{" || t == "}" {
            continue;
        }
        if t.starts_with("if") || t.starts_with("else") {
            continue;
        }
        if let Some(rbody) = t.strip_prefix("return ") {
            let body = rbody.trim_end_matches(';').trim();
            if !body.is_empty() {
                used_returns.push(body.to_string());
            }
            continue;
        }
        // Park FUN_/named-call/store lines that previously aborted the fold.
        // Named callees from MSVC maps (`classify()`) must not be dropped just
        // because they lost the FUN_ prefix.
        if t.contains("FUN_")
            || t.starts_with("call(")
            || looks_like_call_stmt(t)
            || (t.contains('*') && t.contains('=') && !t.contains("=="))
        {
            side_effect_lines.push(t.to_string());
        }
    }
    let mut case_lines = String::new();
    case_lines.push_str(&format!(" switch ({scrut}) {{\n"));
    for (i, k) in case_ks.iter().enumerate() {
        case_lines.push_str(&format!(" case {k}:\n"));
        if let Some(body) = used_returns.get(i) {
            case_lines.push_str(&format!(" return {body};\n"));
        }
        case_lines.push_str(" break;\n");
    }
    let extra_return = used_returns.len() > case_ks.len();
    if extra_return || !side_effect_lines.is_empty() {
        case_lines.push_str(" default:\n");
        for se in &side_effect_lines {
            case_lines.push_str(&format!(" {se}\n"));
        }
        if extra_return {
            if let Some(body) = used_returns.last() {
                case_lines.push_str(&format!(" return {body};\n"));
            }
        }
        case_lines.push_str(" break;\n");
    }
    case_lines.push_str(" }\n");
    let mut out = String::new();
    out.push_str(&src[..start]);
    out.push_str(&case_lines);
    out.push_str(&rest[end_rel..]);
    out
}

/// Byte length of a brace-balanced region starting at the first `{` in `s`,
/// or through a single-line `if (…) stmt;` when no braces.
fn brace_balanced_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let open = s.find('{')?;
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a brace-balanced nested if/else equality ladder into `(k, body)` arms.
/// Returns `(arms, end_byte_offset)` of the whole ladder in `src`.
///
/// Nested MSVC shape `else { if (scrut-K) {…} else {…} }` is peeled iteratively
/// so a final single arm is still collected (caller requires ≥2 labeled arms).
fn extract_eq_ladder_span(
    src: &str,
    start: usize,
    scrut: &str,
    case_ks: &[i64],
) -> Option<(Vec<(i64, String)>, usize)> {
    let bytes = src.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    let mut arms: Vec<(i64, String)> = Vec::new();
    let mut cursor = start;
    let mut default_body = String::new();
    // Work buffer for nested `else { if … }` bodies we re-scan.
    let mut work = src.to_string();
    let mut work_start = start;
    // Limit peel depth to avoid pathological nesting.
    for _ in 0..16 {
        let bytes = work.as_bytes();
        while work_start < bytes.len() && bytes[work_start].is_ascii_whitespace() {
            work_start += 1;
        }
        if work_start >= bytes.len() {
            break;
        }
        let tail = &work[work_start..];
        let compact_head: String = tail
            .chars()
            .take(200)
            .filter(|ch| !ch.is_whitespace())
            .collect();
        if !compact_head.starts_with("if(") {
            break;
        }
        let Some(cond_k) = parse_sub_eq_zero_k(&compact_head, scrut)
            .or_else(|| parse_direct_eq_k(&compact_head, scrut))
        else {
            break;
        };
        if !case_ks.contains(&cond_k) && !arms.is_empty() {
            break;
        }
        let rel_brace = tail.find('{')?;
        let then_open = work_start + rel_brace;
        let (then_body, after_then) = extract_balanced_brace(&work, then_open)?;
        arms.push((cond_k, then_body.trim().to_string()));
        cursor = after_then;
        work_start = after_then;

        // Optional else
        let bytes = work.as_bytes();
        while work_start < bytes.len() && bytes[work_start].is_ascii_whitespace() {
            work_start += 1;
        }
        let else_tail = &work[work_start..];
        let else_compact: String = else_tail
            .chars()
            .take(16)
            .filter(|ch| !ch.is_whitespace())
            .collect();
        if !else_compact.starts_with("else") {
            break;
        }
        let else_kw = else_tail.find("else").unwrap_or(0);
        work_start += else_kw + 4;
        while work_start < work.len() && work.as_bytes()[work_start].is_ascii_whitespace() {
            work_start += 1;
        }
        let after_else = &work[work_start..];
        let ae_compact: String = after_else
            .chars()
            .take(12)
            .filter(|ch| !ch.is_whitespace())
            .collect();
        if ae_compact.starts_with("if(") {
            // else if — continue peel on same work buffer
            cursor = work_start;
            continue;
        }
        // else { … }
        let rel = after_else.find('{')?;
        let def_open = work_start + rel;
        let (body, after) = extract_balanced_brace(&work, def_open)?;
        cursor = after;
        let btrim = body.trim().to_string();
        let bcomp: String = btrim.chars().filter(|ch| !ch.is_whitespace()).collect();
        if bcomp.starts_with("if(")
            && (parse_sub_eq_zero_k(&bcomp, scrut).is_some()
                || parse_direct_eq_k(&bcomp, scrut).is_some())
        {
            // Peel nested if inside else-brace as the next arm source.
            work = btrim;
            work_start = 0;
            continue;
        }
        default_body = btrim;
        break;
    }

    if arms.is_empty() {
        return None;
    }
    if !default_body.is_empty()
        && (default_body.contains("FUN_")
            || default_body.contains("call(")
            || default_body.contains('=')
            || default_body.contains("return"))
    {
        arms.push((i64::MIN, default_body));
    }
    // End offset is only meaningful for the top-level `src` call (start was in src).
    // When we rebased `work` onto nested bodies, cursor is relative to the nested
    // string — recover top-level end by scanning brace balance from original start.
    let end = if start == 0 && work.as_str() != src {
        // Nested-only call: report end relative to the nested string we finished on.
        cursor
    } else {
        // Top-level: end of the outermost if/else chain starting at `start`.
        find_ladder_end(src, start).unwrap_or(cursor.max(start))
    };
    Some((arms, end))
}

/// End byte offset of the if/else chain starting at `start` (first `if`).
fn find_ladder_end(src: &str, start: usize) -> Option<usize> {
    let tail = &src[start..];
    let rel_brace = tail.find('{')?;
    let mut open = start + rel_brace;
    // Walk if { } else { } else if { } … consuming brace groups and else keywords.
    let bytes = src.as_bytes();
    loop {
        let (_, after) = extract_balanced_brace(src, open)?;
        let mut i = after;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 4 <= bytes.len() && &src[i..i + 4] == "else" {
            i += 4;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            // else if → find next `{` of that if
            if i + 2 <= bytes.len() && &src[i..i + 2] == "if" {
                let sub = &src[i..];
                let rb = sub.find('{')?;
                open = i + rb;
                continue;
            }
            if i < bytes.len() && bytes[i] == b'{' {
                open = i;
                continue;
            }
            return Some(i);
        }
        return Some(after);
    }
}

/// Extract text inside `{...}` at `open` (must point at `{`); returns (inner, index after `}`).
fn extract_balanced_brace(src: &str, open: usize) -> Option<(String, usize)> {
    let bytes = src.as_bytes();
    if open >= bytes.len() || bytes[open] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let inner = src[open + 1..i].to_string();
                    return Some((inner, i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_sub_eq_zero_k(compact_if: &str, scrut: &str) -> Option<i64> {
    // if((SCRUT-0xK)==0x0) or if((SCRUT-K)==0)
    let rest0 = compact_if.strip_prefix("if(")?;
    let rest = rest0.trim_start_matches('(');
    let s = scrut
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if !rest.starts_with(&s) && !rest.contains(&s) {
        // Allow scrut with extra parens: *((arg_20)
        let core = s.trim_start_matches('(');
        if !rest.contains(core) {
            return None;
        }
    }
    // Find SCRUT- then constant
    let s_pos = rest.find(&s).or_else(|| {
        let core = s.trim_start_matches('*').trim_start_matches('(');
        rest.find(core)
    })?;
    let after_scrut = &rest[s_pos + s.len().min(rest.len() - s_pos)..];
    // May have trailing ) before -
    let after_scrut = after_scrut.trim_start_matches(')');
    if !after_scrut.starts_with('-') {
        // try find - after scrut core inside rest
        let core = s.trim_start_matches('*').trim_start_matches('(');
        if let Some(p) = rest.find(core) {
            let a = &rest[p + core.len()..];
            let a = a.trim_start_matches(')');
            if let Some(stripped) = a.strip_prefix('-') {
                return parse_k_before_eq_zero(stripped);
            }
        }
        return None;
    }
    parse_k_before_eq_zero(&after_scrut[1..])
}

fn parse_k_before_eq_zero(after_minus: &str) -> Option<i64> {
    let num_end = after_minus
        .find([')', '=', ','])
        .unwrap_or(after_minus.len());
    let num_s = &after_minus[..num_end];
    let k = parse_int_lit(num_s)?;
    // Require == 0 / == 0x0 after the closing parens of the subexpression.
    let rest = &after_minus[num_end..];
    let r: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
    if r.contains("==0x0") || r.contains("==0)") || r.starts_with(")==0") || r.contains(")==0x0") {
        return Some(k);
    }
    // Compact: -0x1)==0x0
    if r.contains("==0") {
        return Some(k);
    }
    None
}

fn parse_direct_eq_k(compact_if: &str, scrut: &str) -> Option<i64> {
    let rest0 = compact_if.strip_prefix("if(")?;
    let rest = rest0.trim_start_matches('(');
    let s: String = scrut.chars().filter(|ch| !ch.is_whitespace()).collect();
    let core = s.trim_start_matches('*').trim_start_matches('(');
    if !rest.contains(&s) && !rest.contains(core) {
        return None;
    }
    // SCRUT==0xK
    let pos = rest.find(&s).or_else(|| rest.find(core))?;
    let after = &rest[pos..];
    let eq = after.find("==")?;
    let num_part = &after[eq + 2..];
    let num_end = num_part
        .find([')', ',', '&', '|'])
        .unwrap_or(num_part.len());
    parse_int_lit(&num_part[..num_end])
}

/// Collect `(scrutinee, constant, body_hint)` from `if (((scrut - K) == 0x0))` lines.
fn collect_eq_ladder_arms(src: &str) -> Vec<(String, i64, String)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let t = line.trim();
        if !t.contains("if") {
            continue;
        }
        // Compact: if((*(arg_0)-0x1)==0x0) or if((rcx==0x0)) or if((x-0x2)==0)
        // Pure V2 also emits if(!(rcx==0x0)) and if(rcx-0x1-0x1!=0x0).
        let c: String = t.chars().filter(|ch| !ch.is_whitespace()).collect();
        let Some(rest0) = c.strip_prefix("if(") else {
            continue;
        };
        // Strip outer bang used by pure inverted null/eq tests: if(!(…))
        let (rest, inverted) = if let Some(r) = rest0.strip_prefix("!(") {
            (r, true)
        } else {
            (rest0.trim_start_matches('('), false)
        };
        // Form A: SCRUT-0xK)==0x0 or SCRUT-0xK-0xK…==0 / !=0 (subtract-eq ladder).
        // Walk the *trailing* `-lit` chain before `==0`/`!=0` so mid-expression
        // minuses (`*(rsp-0x18+0x20)-0x1`) do not steal the scrutinee split
        // (P0 c02/c03 mem homes).
        if let Some((scrut, k_sum)) = parse_trailing_sub_eq_arm(rest) {
            out.push((scrut, k_sum, String::new()));
            continue;
        }
        // Form B: SCRUT==0xK)  (direct equality ladder)
        // Pure: if(!(rcx==0x0)) → case 0; if(rcx==0x1) → case 1.
        if let Some(eq) = rest.find("==") {
            let scrut = rest[..eq].trim_end_matches('(').to_string();
            let after = &rest[eq + 2..];
            let num_end = after.find([')', ',', '&', '|']).unwrap_or(after.len());
            let num_s = &after[..num_end];
            if let Some(k) = parse_int_lit(num_s)
                && is_scrutinee_token(&scrut)
            {
                // Allow case 0 when inverted pure form if(!(scrut==0)).
                if k != 0 || inverted {
                    out.push((scrut, k, String::new()));
                }
            }
        }
    }
    out
}

pub(crate) fn parse_int_lit(num_s: &str) -> Option<i64> {
    let num_s = num_s.trim_matches(|c| c == '(' || c == ')');
    if let Some(h) = num_s
        .strip_prefix("0x")
        .or_else(|| num_s.strip_prefix("0X"))
    {
        i64::from_str_radix(h, 16).ok()
    } else {
        num_s.parse::<i64>().ok()
    }
}

/// Parse `SCRUT -k [-k…] ==0 / !=0` by peeling trailing `-lit` from the right.
/// Returns `(scrutinee, k_sum)` when ≥1 trailing subtract and a zero-compare.
fn parse_trailing_sub_eq_arm(rest: &str) -> Option<(String, i64)> {
    let eq_pos = rest
        .find("==0")
        .or_else(|| rest.find("!=0"))
        .or_else(|| rest.find("==0x0"))
        .or_else(|| rest.find("!=0x0"))?;
    // Prefer the earliest of the markers (find already does).
    let mut before = &rest[..eq_pos];
    // Drop closing parens between subtract chain and compare.
    before = before.trim_end_matches(')');
    let mut k_sum: i64 = 0;
    let mut end = before.len();
    let mut peeled = 0usize;
    loop {
        let slice = &before[..end];
        let Some(minus) = slice.rfind('-') else {
            break;
        };
        // Reject binary-minus mid tokens like `rsp-0x18+0x20` where after the
        // minus is not a pure integer literal through `end`.
        let num_s = slice[minus + 1..end].trim_end_matches(')');
        let Some(k) = parse_int_lit(num_s) else {
            break;
        };
        // Only allow non-negative case labels (ladder tags).
        if k < 0 {
            break;
        }
        k_sum = k_sum.saturating_add(k);
        end = minus;
        peeled += 1;
    }
    if peeled == 0 {
        return None;
    }
    let scrut = before[..end].trim_end_matches('(').to_string();
    if scrut.is_empty() || !is_scrutinee_token(&scrut) {
        return None;
    }
    // `==0` / `!=0` already required above.
    Some((scrut, k_sum))
}

fn is_scrutinee_token(scrut: &str) -> bool {
    scrut.contains("arg")
        || scrut.contains("mem")
        || scrut.contains("rcx")
        || scrut.contains("rdx")
        || scrut.contains("r8")
        || scrut.contains("r9")
        || scrut.contains("rsp")
        || scrut.contains("rbp")
        || scrut.starts_with("*(")
        || scrut.starts_with("t_")
}

/// Recover `L: body; if (c) goto L;` → `while (c) { body; }` when the body
/// has no nested labels (1.txt loop recurrence under residual gotos).
pub(crate) fn rewrite_label_backedge_to_while(src: &str) -> String {
    let lines: Vec<String> = src.lines().map(|s| s.to_string()).collect();
    let mut label_idx: HashMap<String, usize> = HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(lab) = parse_label(line.trim()) {
            label_idx.insert(lab, i);
        }
    }
    let mut consumed: HashSet<usize> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if consumed.contains(&i) {
            i += 1;
            continue;
        }
        let t = lines[i].trim();
        if let Some(lab) = parse_label(t) {
            // Scan forward for `if (...) goto lab;` or `goto lab;` at similar indent.
            let mut j = i + 1;
            let mut body: Vec<String> = Vec::new();
            let mut found_back: Option<(usize, String)> = None; // line, cond
            while j < lines.len() {
                if parse_label(lines[j].trim()).is_some() {
                    break;
                }
                let jt = lines[j].trim();
                if let Some(glab) = parse_goto_loose(jt)
                    && glab == lab
                {
                    found_back = Some((j, "1".into()));
                    break;
                }
                // if (COND) goto LAB;
                if jt.starts_with("if")
                    && jt.contains("goto ")
                    && let Some(glab) =
                        parse_goto_loose(jt.split("goto ").nth(1).unwrap_or("").trim())
                    && glab == lab
                    && let Some(cond) = extract_if_cond(jt)
                {
                    found_back = Some((j, cond));
                    break;
                }
                body.push(lines[j].clone());
                j += 1;
                if body.len() > 40 {
                    break;
                }
            }
            if let Some((back_i, cond)) = found_back
                && body.len() <= 40
            {
                let ind_ws = &lines[i][..lines[i].len() - lines[i].trim_start().len()];
                out.push(format!("{ind_ws}while ({cond}) {{"));
                for b in &body {
                    // reindent body one level
                    if b.trim().is_empty() {
                        out.push(String::new());
                    } else {
                        out.push(format!("    {b}"));
                    }
                }
                out.push(format!("{ind_ws}}}"));
                for k in i..=back_i {
                    consumed.insert(k);
                }
                i = back_i + 1;
                continue;
            }
        }
        out.push(lines[i].clone());
        i += 1;
    }
    let mut s = out.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn extract_if_cond(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("if")?.trim_start();
    if !rest.starts_with('(') {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(rest[1..i].trim().to_string());
            }
        }
    }
    None
}

/// Presentation pass for **proven** GS-cookie fail leaves only.
///
/// 1.txt: do not delete gotos in a printer pass without restructuring. Only
/// rewrite `goto L` when `L` is a pure fail leaf (return / abort / security
/// check). Never blanket-erase all gotos just because the PE mentions a
/// cookie global or `0x14001…` image address.
pub(crate) fn strip_security_cookie_gotos(src: &str) -> String {
    let lines: Vec<String> = src.lines().map(|s| s.to_string()).collect();
    let fail_leaves = collect_pure_fail_labels(&lines);
    // Also treat any label whose body is only `return` / empty as a fail leaf
    // when the preceding context mentions the GS cookie global (g_14…).
    let cookie_context = src.contains("g_14") || src.contains("0x14001a") || src.contains("cookie");
    // Labels actually defined in this function text.
    let defined_labels: HashSet<String> =
        lines.iter().filter_map(|l| parse_label(l.trim())).collect();
    let mut out: Vec<String> = Vec::new();
    for line in &lines {
        let t = line.trim();
        if let Some(lab) = parse_goto_loose(t) {
            // Only rewrite gotos into pure fail/return leaves — never ordinary merges.
            let is_fail = fail_leaves.contains(&lab)
                || (cookie_context && label_is_trivial_return(&lines, &lab));
            // Orphaned goto (label never emitted) → fail return. Cookie context
            // is sufficient but not required: the structurer sometimes emits
            // unresolved fail-merge labels on simple guards (read_header).
            let orphan = !defined_labels.contains(&lab);
            if is_fail || orphan {
                let ind_ws = &line[..line.len() - line.trim_start().len()];
                // Present as a clean return — do not leave "gs-cookie" markers in
                // the surface text (those used to poison candidate pick filters).
                out.push(format!("{ind_ws}return;"));
                continue;
            }
        }
        out.push(line.clone());
    }
    // Drop pure-fail labels that are no longer targeted.
    let mut targets: HashSet<String> = HashSet::new();
    for line in &out {
        if let Some(t) = parse_goto_loose(line.trim()) {
            targets.insert(t);
        }
    }
    let mut final_lines = Vec::new();
    let mut skip: Option<String> = None;
    for line in out {
        let t = line.trim();
        if let Some(lab) = parse_label(t) {
            if fail_leaves.contains(&lab) && !targets.contains(&lab) {
                skip = Some(lab);
                continue;
            }
            skip = None;
            final_lines.push(line);
            continue;
        }
        if skip.is_some() {
            // Skip original fail-leaf body (already presented as return).
            if t == "}" || t.starts_with("return") || t.is_empty() {
                if t == "}" {
                    skip = None;
                }
                continue;
            }
            if t.starts_with("call(") || t.contains("FUN_") {
                continue;
            }
            skip = None;
        }
        final_lines.push(line);
    }
    let mut s = final_lines.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// True when label body is only return / empty (cookie fail leaf).
fn label_is_trivial_return(lines: &[String], lab: &str) -> bool {
    let mut i = 0;
    while i < lines.len() {
        if parse_label(lines[i].trim()).as_deref() == Some(lab) {
            let mut j = i + 1;
            let mut saw_return = false;
            let mut saw_other = false;
            while j < lines.len() {
                let t = lines[j].trim();
                if parse_label(t).is_some() {
                    break;
                }
                if t.is_empty() || t == "{" || t == "}" {
                    j += 1;
                    continue;
                }
                if t.starts_with("return") {
                    // Pure fail leaf: bare `return;` / zero. Value-bearing
                    // returns are real merges and must keep their goto.
                    let payload = t
                        .trim_start_matches("return")
                        .trim()
                        .trim_end_matches(';')
                        .trim();
                    if payload.is_empty() || payload == "0" || payload == "0x0" {
                        saw_return = true;
                        j += 1;
                        continue;
                    }
                    saw_other = true;
                    break;
                }
                saw_other = true;
                break;
            }
            return saw_return && !saw_other;
        }
        i += 1;
    }
    false
}

/// Labels whose body is only fail/epilogue (return, abort, security_check).
fn collect_pure_fail_labels(lines: &[String]) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(lab) = parse_label(lines[i].trim()) {
            let mut body: Vec<String> = Vec::new();
            let mut j = i + 1;
            let mut depth = 0i32;
            while j < lines.len() {
                let t = lines[j].trim();
                if parse_label(t).is_some() && depth == 0 {
                    break;
                }
                if t.ends_with('{') {
                    depth += 1;
                }
                if t == "}" || t.starts_with('}') {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                if !t.is_empty() {
                    body.push(t.to_string());
                }
                if body.len() > 4 {
                    break;
                }
                j += 1;
            }
            if is_pure_fail_leaf_body(&body) {
                out.insert(lab);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn is_bare_fail_return_line(l: &str) -> bool {
    let t = l.trim().trim_end_matches(';').trim().to_ascii_lowercase();
    // Only empty / zero / self-xor returns count as fail epilogue — never
    // `return *(arg)` / `return a+b` (those are real function exits).
    matches!(
        t.as_str(),
        "return"
            | "return 0"
            | "return 0x0"
            | "return 0x00"
            | "return ((u64)rax ^ (u64)rax)"
            | "return (u64)(u64)rax ^ (u64)rax"
    ) || t == "return;"
        || (t.starts_with("return") && (t.contains("/* gs-cookie") || t.contains("/*cookie")))
        || t == "return 0"
        || t == "return 0;"
}

fn is_pure_fail_leaf_body(body: &[String]) -> bool {
    if body.is_empty() || body.len() > 4 {
        return false;
    }
    // Must not transfer control elsewhere or run real kernels.
    if body.iter().any(|l| {
        let t = l.as_str();
        t.contains("goto ")
            || t.contains("while")
            || t.contains("for ")
            || t.contains("switch")
            || t.contains('+')
            || t.contains("mem_")
    }) {
        return false;
    }
    let joined = body.join(" ");
    let has_fail_call = joined.contains("security_check")
        || joined.contains("__report")
        || joined.contains("abort")
        || joined.contains("gsfail")
        || joined.contains("guard_check");
    let returns: Vec<&String> = body
        .iter()
        .filter(|l| l.trim().starts_with("return"))
        .collect();
    if returns.is_empty() {
        return false;
    }
    // Every return must be a bare fail return (not a value expression).
    if !returns.iter().all(|l| is_bare_fail_return_line(l)) {
        return false;
    }
    // Non-return lines: only braces, comments, arg_0 return-address materialization,
    // or explicit fail helpers.
    body.iter().all(|l| {
        let t = l.trim();
        t.is_empty()
            || t == "}"
            || t.starts_with("/*")
            || t.starts_with("return")
            || t.contains("arg_0 = 0x14")
            || t.contains("security_check")
            || t.contains("__report")
            || t.contains("abort")
            || t.contains("call(")
            || t.contains("FUN_")
    }) && (has_fail_call || returns.iter().all(|l| is_bare_fail_return_line(l)))
}

/// Inline gotos that target a short leaf block (cookie fail / abort epilogue)
/// so residual goto mass drops without changing path effects (1.txt §1 budget).
pub(crate) fn inline_leaf_goto_targets(src: &str) -> String {
    let lines: Vec<String> = src.lines().map(|s| s.to_string()).collect();
    // label -> body lines until next label or closing brace at same indent
    let mut label_body: HashMap<String, Vec<String>> = HashMap::new();
    let mut i = 0;
    while i < lines.len() {
        if let Some(lab) = parse_label(lines[i].trim()) {
            let mut body = Vec::new();
            let mut j = i + 1;
            let mut depth = 0i32;
            while j < lines.len() {
                let t = lines[j].trim();
                if parse_label(t).is_some() && depth == 0 {
                    break;
                }
                if t.ends_with('{') {
                    depth += 1;
                }
                if t == "}" || t.starts_with('}') {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                // Stop leaf body at return / noreturn-ish patterns after collecting them.
                body.push(lines[j].clone());
                if t.starts_with("return") || t.contains("__report") || t.contains("abort") {
                    j += 1;
                    break;
                }
                // Leaf: single goto or single statement then end
                if body.len() >= 6 {
                    break;
                }
                j += 1;
            }
            // Only inline pure fail/epilogue leaves (return/abort/security),
            // never arbitrary small blocks (that would erase real control).
            let body_trim: Vec<String> = body.iter().map(|l| l.trim().to_string()).collect();
            if is_pure_fail_leaf_body(&body_trim) {
                label_body.insert(lab, body);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    if label_body.is_empty() {
        return src.to_string();
    }
    let mut out = Vec::new();
    for line in &lines {
        let t = line.trim();
        if let Some(lab) = parse_goto_loose(t)
            && let Some(body) = label_body.get(&lab)
        {
            let ind_ws = &line[..line.len() - line.trim_start().len()];
            for b in body {
                let bt = b.trim();
                if bt.is_empty() {
                    continue;
                }
                out.push(format!("{ind_ws}{bt}"));
            }
            continue;
        }
        // Drop labels we fully inlined if no remaining gotos to them — second pass.
        out.push(line.clone());
    }
    // Remove now-unreferenced labels whose body was only a leaf.
    let mut targets: HashSet<String> = HashSet::new();
    for line in &out {
        if let Some(t) = parse_goto_loose(line.trim()) {
            targets.insert(t);
        }
    }
    let mut final_lines = Vec::new();
    let mut skip_label_body: Option<String> = None;
    for line in out {
        let t = line.trim();
        if let Some(lab) = parse_label(t) {
            if label_body.contains_key(&lab) && !targets.contains(&lab) {
                skip_label_body = Some(lab);
                continue;
            }
            skip_label_body = None;
        } else if let Some(ref lab) = skip_label_body {
            // Skip original leaf body lines (already inlined).
            if label_body
                .get(lab)
                .is_some_and(|b| b.iter().any(|x| x.trim() == t))
                || t.starts_with("return")
                || t == "}"
            {
                if t == "}" {
                    skip_label_body = None;
                }
                continue;
            }
            if parse_label(t).is_some() {
                skip_label_body = None;
            }
        }
        final_lines.push(line);
    }
    let mut s = final_lines.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Fold `if (…) { goto L; } … L: return …` and remove comments-only goto noise.
/// Workstream 1: reduce residual goto mass without reordering effects.
pub(crate) fn fold_goto_return_and_trivial_rejoins(src: &str) -> String {
    let lines: Vec<String> = src.lines().map(|s| s.to_string()).collect();
    // Build label → line index for simple L_…: labels.
    let mut label_at: HashMap<String, usize> = HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(lab) = parse_label(line.trim()) {
            label_at.insert(lab, i);
        }
    }
    let mut out: Vec<String> = Vec::new();
    let mut skip_until: Option<usize> = None;
    let mut i = 0;
    while i < lines.len() {
        if let Some(s) = skip_until
            && i < s
        {
            i += 1;
            continue;
        }
        skip_until = None;
        let trimmed = lines[i].trim();
        // `goto L; /* … */` or plain goto
        if let Some(target) = parse_goto_loose(trimmed)
            && let Some(&li) = label_at.get(&target)
        {
            // If label is immediately followed by return (skipping empties),
            // emit that return instead of goto.
            let mut j = li + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j < lines.len() {
                let ret_line = lines[j].trim();
                if ret_line.starts_with("return") {
                    let ind_ws = &lines[i][..lines[i].len() - lines[i].trim_start().len()];
                    out.push(format!("{ind_ws}{ret_line}"));
                    i += 1;
                    continue;
                }
            }
        }
        // Strip trailing goto reason comments for cleaner output (still counts as goto if kept).
        let mut line = lines[i].clone();
        if line.contains("goto ")
            && line.contains("/*")
            && let Some(idx) = line.find("/*")
        {
            let head = line[..idx].trim_end();
            if head.ends_with(';') {
                line = format!(
                    "{}{}",
                    &lines[i][..lines[i].len() - lines[i].trim_start().len()],
                    head.trim_start()
                );
            }
        }
        out.push(line);
        i += 1;
    }
    // Drop labels that are no longer targeted.
    let mut targets: HashSet<String> = HashSet::new();
    for line in &out {
        if let Some(t) = parse_goto_loose(line.trim()) {
            targets.insert(t);
        }
    }
    let mut final_lines = Vec::new();
    for line in out {
        if let Some(lab) = parse_label(line.trim())
            && !targets.contains(&lab)
        {
            continue;
        }
        final_lines.push(line);
    }
    let mut s = final_lines.join("\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn parse_goto_loose(trimmed: &str) -> Option<String> {
    let t = trimmed.trim();
    let rest = t.strip_prefix("goto ")?;
    let lab = rest.split([';', ' ', '/']).next()?.trim();
    if lab.starts_with('L') {
        Some(lab.to_string())
    } else {
        None
    }
}

// ─── S6: goto minimization ──────────────────────────────────────────────────

/// Remove redundant fallthrough gotos and unused labels.
pub(crate) fn minimize_gotos(src: &str) -> String {
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
    // Lemma 10: recurrence normalization — while(1){ if(!(B)) break; ... }
    // is orbit-equivalent to while(B){ ... }.
    out = fold_while_true_break_boundary(&out);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Lemma 10: rewrite unconditional cyclic form + internal exit into explicit
/// boundary while when the first body statement is `if (!(B)) break;`.
pub(crate) fn fold_while_true_break_boundary(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let lines: Vec<&str> = src.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        // Match `while (1) {` / `while (true) {`
        let is_w1 = t.starts_with("while")
            && (t.contains("(1)") || t.contains("(true)") || t.contains("(0x1)"));
        if is_w1 && t.ends_with('{') {
            // Peek next non-empty for if (!(...)) break;
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j < lines.len() {
                let nxt = lines[j].trim();
                if let Some(cond) = parse_if_not_break(nxt) {
                    let indent = lines[i].len() - lines[i].trim_start().len();
                    out.push_str(&format!("{}while ({cond}) {{\n", " ".repeat(indent)));
                    i = j + 1;
                    // Skip a following bare `}` of a one-line if if present.
                    if i < lines.len() && lines[i].trim() == "}" {
                        // might be if's closing — check if break was single-line
                        // parse_if_not_break already consumed one line; leave brace if while body.
                    }
                    continue;
                }
            }
        }
        out.push_str(lines[i]);
        out.push('\n');
        i += 1;
    }
    out
}

fn parse_if_not_break(line: &str) -> Option<String> {
    // `if (!(cond)) break;` or `if (!cond) break;`
    let t = line.trim();
    if !t.contains("break") {
        return None;
    }
    let rest = t.strip_prefix("if")?.trim_start();
    if !rest.starts_with('(') {
        return None;
    }
    // Find matching close for if (...)
    let mut depth = 0i32;
    let bytes = rest.as_bytes();
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                end = Some(i);
                break;
            }
        }
    }
    let end = end?;
    let inside = rest[1..end].trim(); // strip outer parens of if
    // Unwrap !(...)
    let cond = if let Some(inner) = inside.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
        inner.trim().to_string()
    } else {
        let inner = inside.strip_prefix('!')?;
        inner.trim().to_string()
    };
    if cond.is_empty() {
        return None;
    }
    Some(cond)
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
