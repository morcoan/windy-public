//! Source-known decompile scorecard: grade Windy native decomp vs Ghidra export
//! against ground-truth properties from hand-written C (`eval/gold/*.json`).
//!
//! Does not require a live Ghidra install: loads checked-in Ghidra JSON when present.
//!
//! The score is lexical-integrity aware: it extracts facts from code rather than
//! comments, so token soup cannot pass as a decompilation.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::project::Project;

/// A structured direct-call expectation.
///
/// `aliases` are exact, case-insensitive identifiers. `arguments`, when present,
/// is an ordered list of exact, token-normalized argument expressions. Structured
/// call facts supersede the legacy [`GoldFunction::calls`] list when at least one
/// is present.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GoldCallFact {
    pub aliases: Vec<String>,
    #[serde(default)]
    pub arguments: Option<Vec<String>>,
}

fn default_true() -> bool {
    true
}

/// One function's gold properties from source.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoldFunction {
    pub id: String,
    pub source_name: String,
    #[serde(default)]
    pub ghidra_entry_va: Option<String>,
    #[serde(default)]
    pub must_tokens: Vec<String>,
    /// Structural expectations: "if", "loop", "return" (return also in must_tokens often).
    #[serde(default)]
    pub control: Vec<String>,
    #[serde(default)]
    pub min_params: usize,
    /// Legacy expected callee aliases (`|`-separated). Prefer `call_facts` for
    /// new fixtures because it can also assert ordered argument values.
    #[serde(default)]
    pub calls: Vec<String>,
    /// Structured direct-call facts. When present, these replace `calls`.
    #[serde(default)]
    pub call_facts: Vec<GoldCallFact>,
    /// Whether every direct call in the source function is represented by gold.
    /// Source-known scorecards default this to true. Set false only for
    /// deliberately partial bring-up gold.
    #[serde(default = "default_true")]
    pub calls_complete: bool,
    #[serde(default)]
    pub strings: Vec<String>,
    /// Whether `strings` lists every literal string in the source function.
    #[serde(default = "default_true")]
    pub strings_complete: bool,
    /// Classical-decomp quality gates. Each string is one fact (hit or miss).
    ///
    /// Supported kinds:
    /// - `no_rsp` — body has no `rsp`/`esp` register identifiers
    /// - `no_stack_home` — no `*((…)` stack-home store pattern
    /// - `null_term` — contains `'\0'` char literal
    /// - `char_cast` — contains a `(char` cast form
    /// - `field_dot` — contains `ident.ident` field access
    /// - `return_binop:+` (or `*`, `-`, `/`, …) — a `return` expr uses that operator
    /// - `max_assign:N` — number of bare `=` assignments in the body is ≤ N
    ///
    /// Prefer these over free-form identifier sequences (`param_1 + param_2`) that
    /// cannot match across engines with different naming schemes.
    #[serde(default)]
    pub quality: Vec<String>,
}

impl Default for GoldFunction {
    fn default() -> Self {
        Self {
            id: String::new(),
            source_name: String::new(),
            ghidra_entry_va: None,
            must_tokens: Vec::new(),
            control: Vec::new(),
            min_params: 0,
            calls: Vec::new(),
            call_facts: Vec::new(),
            calls_complete: true,
            strings: Vec::new(),
            strings_complete: true,
            quality: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoldFile {
    pub program: String,
    pub source: String,
    #[serde(default)]
    pub ghidra_export: Option<String>,
    pub functions: Vec<GoldFunction>,
}

#[derive(Clone, Debug, Deserialize)]
struct GhidraEntry {
    entry_va: u64,
    #[serde(default)]
    pseudocode: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EngineScore {
    pub engine: String,
    pub hits: usize,
    pub possible: usize,
    /// Fraction of expected facts found in code (the old score semantics).
    pub recall: f64,
    /// Fraction of emitted facts that are expected when gold declares the relevant
    /// fact sets complete. Extra calls and literals lower this value.
    pub precision: f64,
    /// Integrity-adjusted recall (`recall * precision`). It retains legacy values
    /// when no unexpected facts are emitted but cannot be 1.0 for garbage.
    pub score: f64,
    pub hit_detail: Vec<String>,
    pub miss_detail: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unexpected_facts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_results: Vec<FactResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_preview: Option<String>,
}

/// Structured observation for one expected source fact.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactVerdict {
    Hit,
    Miss,
}

#[derive(Clone, Debug, Serialize)]
pub struct FactResult {
    pub kind: String,
    pub expected: String,
    pub verdict: FactVerdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FunctionScorecard {
    pub id: String,
    pub source_name: String,
    pub windy: EngineScore,
    pub ghidra: EngineScore,
    pub delta_windy_minus_ghidra: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScorecardReport {
    pub program: String,
    pub source: String,
    pub ghidra_available: bool,
    pub ghidra_path: Option<String>,
    pub functions: Vec<FunctionScorecard>,
    pub windy_mean_score: f64,
    pub ghidra_mean_score: f64,
    pub windy_total_hits: usize,
    pub ghidra_total_hits: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Identifier,
    Number,
    StringLiteral,
    CharLiteral,
    Operator,
    Punct,
}

#[derive(Clone, Debug)]
struct CodeToken {
    kind: TokenKind,
    text: String,
}

#[derive(Clone, Debug)]
struct ParsedFunction {
    header: Vec<CodeToken>,
    body: Vec<CodeToken>,
}

#[derive(Clone, Debug)]
struct CallSite {
    target: String,
    arguments: Vec<String>,
}

impl CallSite {
    fn display(&self) -> String {
        format!("{}({})", self.target, self.arguments.join(", "))
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
}

fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}

fn consume_quoted(bytes: &[u8], quote_index: usize, quote: u8) -> usize {
    let mut index = quote_index + 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    bytes.len()
}

/// A deliberately small C-like lexer. It is not a parser: it only preserves the
/// boundaries needed to avoid treating comments, strings, or identifier prefixes
/// as semantic facts.
fn lex_code(source: &str) -> Vec<CodeToken> {
    const MULTI_OPERATORS: &[&str] = &[
        "<<=", ">>=", "...", "->", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "<<", ">>",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    ];

    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }

        if bytes[index..].starts_with(b"//") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }

        let quote_index = if byte == b'"' {
            Some(index)
        } else if bytes[index..].starts_with(b"u8\"") {
            Some(index + 2)
        } else if matches!(byte, b'u' | b'U' | b'L') && bytes.get(index + 1) == Some(&b'"') {
            Some(index + 1)
        } else {
            None
        };
        if let Some(quote_index) = quote_index {
            let end = consume_quoted(bytes, quote_index, b'"');
            tokens.push(CodeToken {
                kind: TokenKind::StringLiteral,
                text: source[index..end].to_owned(),
            });
            index = end;
            continue;
        }
        if byte == b'\'' {
            let end = consume_quoted(bytes, index, b'\'');
            tokens.push(CodeToken {
                kind: TokenKind::CharLiteral,
                text: source[index..end].to_owned(),
            });
            index = end;
            continue;
        }
        if is_ident_start(byte) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_ident_continue(bytes[index]) {
                index += 1;
            }
            tokens.push(CodeToken {
                kind: TokenKind::Identifier,
                text: source[start..index].to_owned(),
            });
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.'))
            {
                index += 1;
            }
            tokens.push(CodeToken {
                kind: TokenKind::Number,
                text: source[start..index].to_owned(),
            });
            continue;
        }
        if let Some(operator) = MULTI_OPERATORS
            .iter()
            .find(|operator| bytes[index..].starts_with(operator.as_bytes()))
        {
            tokens.push(CodeToken {
                kind: TokenKind::Operator,
                text: (*operator).to_owned(),
            });
            index += operator.len();
            continue;
        }

        let kind = if matches!(
            byte,
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b',' | b';' | b':' | b'.' | b'?'
        ) {
            TokenKind::Punct
        } else {
            TokenKind::Operator
        };
        tokens.push(CodeToken {
            kind,
            text: source[index..index + 1].to_owned(),
        });
        index += 1;
    }
    tokens
}

fn token_is(token: &CodeToken, text: &str) -> bool {
    token.text.eq_ignore_ascii_case(text)
}

fn last_parenthesized_range(tokens: &[CodeToken]) -> Option<(usize, usize)> {
    let close = tokens.iter().rposition(|token| token_is(token, ")"))?;
    let mut depth = 0usize;
    for index in (0..=close).rev() {
        if token_is(&tokens[index], ")") {
            depth += 1;
        } else if token_is(&tokens[index], "(") {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some((index, close));
            }
        }
    }
    None
}

fn find_matching(
    tokens: &[CodeToken],
    open: usize,
    open_text: &str,
    close_text: &str,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token_is(token, open_text) {
            depth += 1;
        } else if token_is(token, close_text) {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn parse_function(source: &str) -> Option<ParsedFunction> {
    let tokens = lex_code(source);
    let body_open = tokens.iter().position(|token| token_is(token, "{"))?;
    let header = &tokens[..body_open];
    let (params_open, _) = last_parenthesized_range(header)?;
    if !header[..params_open]
        .iter()
        .any(|token| matches!(&token.kind, TokenKind::Identifier))
    {
        return None;
    }
    let body_close = find_matching(&tokens, body_open, "{", "}")?;
    Some(ParsedFunction {
        header: header.to_vec(),
        body: tokens[body_open + 1..body_close].to_vec(),
    })
}

fn formal_param_count_from_header(header: &[CodeToken]) -> usize {
    let Some((open, close)) = last_parenthesized_range(header) else {
        return 0;
    };
    let params = &header[open + 1..close];
    if params.is_empty() || (params.len() == 1 && token_is(&params[0], "void")) {
        return 0;
    }

    let mut count = 0;
    let mut segment_start = 0;
    let mut nested = 0usize;
    for index in 0..=params.len() {
        let at_segment_end =
            index == params.len() || (nested == 0 && token_is(&params[index], ","));
        if at_segment_end {
            let segment = &params[segment_start..index];
            let only_varargs =
                !segment.is_empty() && segment.iter().all(|token| token_is(token, "..."));
            if !segment.is_empty() && !only_varargs {
                count += 1;
            }
            segment_start = index + 1;
            continue;
        }
        if token_is(&params[index], "(") || token_is(&params[index], "[") {
            nested += 1;
        } else if token_is(&params[index], ")") || token_is(&params[index], "]") {
            nested = nested.saturating_sub(1);
        }
    }
    count
}

/// Count formals from the declaration header only. This intentionally does not
/// give parameter credit to local variables named `arg1` or `param_1`.
#[cfg(test)]
fn count_formal_params(text: &str) -> usize {
    let tokens = lex_code(text);
    let header_end = tokens
        .iter()
        .position(|token| token_is(token, "{"))
        .unwrap_or(tokens.len());
    formal_param_count_from_header(&tokens[..header_end])
}

fn normalized_token(token: &CodeToken) -> String {
    match token.kind {
        TokenKind::Identifier | TokenKind::Number => token.text.to_ascii_lowercase(),
        TokenKind::StringLiteral => decode_string_literal(&token.text)
            .map(|value| format!("\"{value}\""))
            .unwrap_or_else(|| token.text.clone()),
        _ => token.text.clone(),
    }
}

fn token_sequence_present(body: &[CodeToken], expected: &str) -> bool {
    let expected_tokens = lex_code(expected);
    if expected_tokens.is_empty() || expected_tokens.len() > body.len() {
        return false;
    }
    body.windows(expected_tokens.len()).any(|window| {
        window.iter().zip(&expected_tokens).all(|(actual, wanted)| {
            actual.kind == wanted.kind && normalized_token(actual) == normalized_token(wanted)
        })
    })
}

fn control_present(body: &[CodeToken], expected: &str) -> bool {
    match expected.to_ascii_lowercase().as_str() {
        "if" => body.iter().any(|token| token_is(token, "if")),
        "else" => body.iter().any(|token| token_is(token, "else")),
        "switch" => body.iter().any(|token| token_is(token, "switch")),
        "for" => body.iter().any(|token| token_is(token, "for")),
        "break" => body.iter().any(|token| token_is(token, "break")),
        "continue" => body.iter().any(|token| token_is(token, "continue")),
        "loop" => body.iter().any(|token| {
            token_is(token, "while")
                || token_is(token, "for")
                || token_is(token, "do")
                || token_is(token, "loop")
        }),
        "return" => body.iter().any(|token| token_is(token, "return")),
        other => token_sequence_present(body, other),
    }
}

fn count_assignments(body: &[CodeToken]) -> usize {
    // Multi-char operators (`==`, `+=`, …) are separate lexer tokens, so bare `=`
    // is a reliable assignment counter across Ghidra- and Windy-style C.
    body.iter().filter(|token| token.text == "=").count()
}

fn has_rsp_ident(body: &[CodeToken]) -> bool {
    body.iter().any(|token| {
        matches!(&token.kind, TokenKind::Identifier)
            && matches!(
                token.text.to_ascii_lowercase().as_str(),
                "rsp" | "esp" | "sp"
            )
    })
}

fn has_stack_home_store(body: &[CodeToken]) -> bool {
    // Windy-native stack homes look like `*((0x10 + rsp)) = …`.
    // Match `*((` as a token sequence; Ghidra almost never emits this shape.
    for window in body.windows(3) {
        if token_is(&window[0], "*") && token_is(&window[1], "(") && token_is(&window[2], "(") {
            return true;
        }
    }
    false
}

fn has_char_cast(body: &[CodeToken]) -> bool {
    // `(char` or `(char *` / `(char*)` — Ghidra uses these for byte loads.
    body.windows(2).any(|window| {
        token_is(&window[0], "(")
            && matches!(&window[1].kind, TokenKind::Identifier)
            && window[1].text.eq_ignore_ascii_case("char")
    })
}

fn has_null_term(body: &[CodeToken]) -> bool {
    body.iter().any(|token| {
        matches!(&token.kind, TokenKind::CharLiteral)
            && matches!(token.text.as_str(), "'\\0'" | "'\\x00'")
    })
}

fn has_field_dot(body: &[CodeToken]) -> bool {
    body.windows(3).any(|window| {
        matches!(&window[0].kind, TokenKind::Identifier)
            && token_is(&window[1], ".")
            && matches!(&window[2].kind, TokenKind::Identifier)
    })
}

/// Extract the token spans of each `return …;` expression in the body.
fn return_expression_spans(body: &[CodeToken]) -> Vec<&[CodeToken]> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < body.len() {
        if token_is(&body[index], "return") {
            let start = index + 1;
            let mut end = start;
            while end < body.len() && !token_is(&body[end], ";") {
                end += 1;
            }
            if start < end {
                spans.push(&body[start..end]);
            }
            index = end.saturating_add(1);
            continue;
        }
        index += 1;
    }
    spans
}

fn return_has_binop(body: &[CodeToken], op: &str) -> bool {
    return_expression_spans(body)
        .into_iter()
        .any(|expr| expr.iter().any(|token| token.text == op))
}

/// Evaluate one quality gate. Returns `(hit, observed_detail)`.
fn quality_gate(body: &[CodeToken], spec: &str) -> (bool, Vec<String>) {
    let spec = spec.trim();
    let lower = spec.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("max_assign:") {
        let Ok(limit) = rest.parse::<usize>() else {
            return (false, vec![format!("bad_max_assign:{spec}")]);
        };
        let count = count_assignments(body);
        return (count <= limit, vec![count.to_string()]);
    }
    if let Some(op) = lower.strip_prefix("return_binop:") {
        let hit = return_has_binop(body, op);
        return (hit, if hit { vec![op.to_owned()] } else { Vec::new() });
    }
    match lower.as_str() {
        "no_rsp" => {
            let hit = !has_rsp_ident(body);
            (
                hit,
                if hit {
                    Vec::new()
                } else {
                    vec!["rsp_present".into()]
                },
            )
        }
        "no_stack_home" => {
            let hit = !has_stack_home_store(body);
            (
                hit,
                if hit {
                    Vec::new()
                } else {
                    vec!["stack_home_*(( present".into()]
                },
            )
        }
        "null_term" => {
            let hit = has_null_term(body);
            (hit, Vec::new())
        }
        "char_cast" => {
            let hit = has_char_cast(body);
            (hit, Vec::new())
        }
        "field_dot" => {
            let hit = has_field_dot(body);
            (hit, Vec::new())
        }
        other => {
            // Allow control-like quality aliases without inventing a second schema.
            let hit = control_present(body, other);
            (hit, Vec::new())
        }
    }
}

fn decode_string_literal(raw: &str) -> Option<String> {
    let first_quote = raw.find('"')?;
    let last_quote = raw.rfind('"')?;
    if first_quote == last_quote {
        return None;
    }
    let mut value = String::new();
    let mut chars = raw[first_quote + 1..last_quote].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            value.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some('0') => value.push('\0'),
            Some(other) => value.push(other),
            None => value.push('\\'),
        }
    }
    Some(value)
}

fn normalize_expression(expression: &str) -> String {
    lex_code(expression)
        .iter()
        .map(normalized_token)
        .collect::<Vec<_>>()
        .join("")
}

fn is_non_call_identifier(identifier: &str) -> bool {
    matches!(
        identifier,
        "if" | "for"
            | "while"
            | "switch"
            | "return"
            | "sizeof"
            | "alignof"
            | "typeof"
            | "decltype"
            | "catch"
            | "int"
            | "char"
            | "short"
            | "long"
            | "float"
            | "double"
            | "bool"
            | "void"
            | "signed"
            | "unsigned"
            | "const"
            | "volatile"
            | "struct"
            | "union"
            | "enum"
            | "class"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "undefined"
            | "undefined4"
            | "undefined8"
            | "reinterpret_cast"
            | "static_cast"
            | "dynamic_cast"
            | "const_cast"
            // Windy's native emitter currently exposes phi nodes as pseudo-calls.
            // They are internal SSA notation, not source-level direct calls.
            | "phi"
    )
}

fn split_call_arguments(tokens: &[CodeToken]) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut arguments = Vec::new();
    let mut segment_start = 0;
    let mut nested = 0usize;
    for index in 0..=tokens.len() {
        let at_segment_end =
            index == tokens.len() || (nested == 0 && token_is(&tokens[index], ","));
        if at_segment_end {
            arguments.push(
                tokens[segment_start..index]
                    .iter()
                    .map(normalized_token)
                    .collect::<Vec<_>>()
                    .join(""),
            );
            segment_start = index + 1;
            continue;
        }
        if token_is(&tokens[index], "(")
            || token_is(&tokens[index], "[")
            || token_is(&tokens[index], "{")
        {
            nested += 1;
        } else if token_is(&tokens[index], ")")
            || token_is(&tokens[index], "]")
            || token_is(&tokens[index], "}")
        {
            nested = nested.saturating_sub(1);
        }
    }
    arguments
}

fn extract_direct_calls(body: &[CodeToken]) -> Vec<CallSite> {
    let mut calls = Vec::new();
    let mut index = 0;
    while index < body.len() {
        let is_identifier = matches!(&body[index].kind, TokenKind::Identifier);
        if !is_identifier {
            index += 1;
            continue;
        }
        let target = body[index].text.to_ascii_lowercase();

        // Windy's current emitter uses call(FUN_...); treat the identifier inside
        // the wrapper as the direct target, not the wrapper itself.
        if target == "call"
            && index + 2 < body.len()
            && token_is(&body[index + 1], "(")
            && let Some(close) = find_matching(body, index + 1, "(", ")")
        {
            let inner = &body[index + 2..close];
            if inner.len() == 1 && matches!(&inner[0].kind, TokenKind::Identifier) {
                calls.push(CallSite {
                    target: inner[0].text.to_ascii_lowercase(),
                    arguments: Vec::new(),
                });
            }
            index = close + 1;
            continue;
        }

        if !is_non_call_identifier(&target)
            && index + 1 < body.len()
            && token_is(&body[index + 1], "(")
            && let Some(close) = find_matching(body, index + 1, "(", ")")
        {
            calls.push(CallSite {
                target,
                arguments: split_call_arguments(&body[index + 2..close]),
            });
            index = close + 1;
            continue;
        }
        index += 1;
    }
    calls
}

fn expected_call_facts(gold: &GoldFunction) -> Vec<GoldCallFact> {
    if !gold.call_facts.is_empty() {
        gold.call_facts.clone()
    } else {
        gold.calls
            .iter()
            .map(|legacy| GoldCallFact {
                aliases: legacy
                    .split('|')
                    .map(|alias| alias.trim().to_owned())
                    .filter(|alias| !alias.is_empty())
                    .collect(),
                arguments: None,
            })
            .collect()
    }
}

fn normalized_aliases(call: &GoldCallFact) -> Vec<String> {
    call.aliases
        .iter()
        .map(|alias| alias.trim().to_ascii_lowercase())
        .filter(|alias| !alias.is_empty())
        .collect()
}

fn call_label(call: &GoldCallFact) -> String {
    let aliases = normalized_aliases(call);
    if aliases.is_empty() {
        "<missing-alias>".to_owned()
    } else {
        aliases.join("|")
    }
}

struct PendingFact {
    kind: &'static str,
    expected: String,
    observed: Vec<String>,
    hit: bool,
}

fn record_fact(
    hits: &mut usize,
    hit_detail: &mut Vec<String>,
    miss_detail: &mut Vec<String>,
    fact_results: &mut Vec<FactResult>,
    fact: PendingFact,
) {
    let detail = format!("{}:{}", fact.kind, fact.expected);
    if fact.hit {
        *hits += 1;
        hit_detail.push(detail);
    } else {
        miss_detail.push(detail);
    }
    fact_results.push(FactResult {
        kind: fact.kind.to_owned(),
        expected: fact.expected,
        verdict: if fact.hit {
            FactVerdict::Hit
        } else {
            FactVerdict::Miss
        },
        observed: fact.observed,
    });
}

fn parse_va_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn load_ghidra_map(path: &Path) -> Option<HashMap<u64, String>> {
    let bytes = fs::read(path).ok()?;
    let entries: Vec<GhidraEntry> = serde_json::from_slice(&bytes).ok()?;
    let mut map = HashMap::new();
    for e in entries {
        // Prefer the first few user functions; skip huge CRT dumps by size.
        if e.pseudocode.len() > 50_000 {
            continue;
        }
        map.insert(e.entry_va, e.pseudocode);
    }
    Some(map)
}

/// Score decompiled text against gold expectations. Pure function (testable).
pub fn score_decomp_text(text: &str, gold: &GoldFunction) -> EngineScore {
    let mut hits = 0usize;
    let mut possible = 0usize;
    let mut hit_detail = Vec::new();
    let mut miss_detail = Vec::new();
    let mut unexpected_facts = Vec::new();
    let mut fact_results = Vec::new();

    let parsed = parse_function(text);
    let (header, body) = if let Some(parsed) = parsed {
        (parsed.header, parsed.body)
    } else {
        unexpected_facts.push("invalid_decompilation_text".to_owned());
        (Vec::new(), Vec::new())
    };

    for tok in &gold.must_tokens {
        possible += 1;
        record_fact(
            &mut hits,
            &mut hit_detail,
            &mut miss_detail,
            &mut fact_results,
            PendingFact {
                kind: "token",
                expected: tok.clone(),
                observed: Vec::new(),
                hit: token_sequence_present(&body, tok),
            },
        );
    }

    for c in &gold.control {
        possible += 1;
        record_fact(
            &mut hits,
            &mut hit_detail,
            &mut miss_detail,
            &mut fact_results,
            PendingFact {
                kind: "control",
                expected: c.clone(),
                observed: Vec::new(),
                hit: control_present(&body, c),
            },
        );
    }

    let direct_calls = extract_direct_calls(&body);
    let expected_calls = expected_call_facts(gold);
    let mut consumed_calls = vec![false; direct_calls.len()];
    for call in expected_calls {
        let label = call_label(&call);
        let aliases = normalized_aliases(&call);
        possible += 1;
        let found = direct_calls.iter().enumerate().find_map(|(index, actual)| {
            (!consumed_calls[index] && aliases.contains(&actual.target)).then_some(index)
        });
        let observed = found
            .map(|index| vec![direct_calls[index].display()])
            .unwrap_or_default();
        record_fact(
            &mut hits,
            &mut hit_detail,
            &mut miss_detail,
            &mut fact_results,
            PendingFact {
                kind: "call",
                expected: label.clone(),
                observed,
                hit: found.is_some(),
            },
        );

        if let Some(index) = found {
            consumed_calls[index] = true;
        }

        if let Some(expected_arguments) = call.arguments.as_ref() {
            possible += 1;
            let expected_arguments: Vec<String> = expected_arguments
                .iter()
                .map(|argument| normalize_expression(argument))
                .collect();
            let arguments_hit =
                found.is_some_and(|index| direct_calls[index].arguments == expected_arguments);
            let observed = found
                .map(|index| direct_calls[index].arguments.clone())
                .unwrap_or_default();
            record_fact(
                &mut hits,
                &mut hit_detail,
                &mut miss_detail,
                &mut fact_results,
                PendingFact {
                    kind: "call_args",
                    expected: format!("{}({})", label, expected_arguments.join(", ")),
                    observed,
                    hit: arguments_hit,
                },
            );
        }
    }

    if gold.calls_complete {
        for (index, call) in direct_calls.iter().enumerate() {
            if !consumed_calls[index] {
                unexpected_facts.push(format!("unexpected_call:{}", call.display()));
            }
        }
    }

    let string_literals: Vec<String> = body
        .iter()
        .filter(|token| matches!(&token.kind, TokenKind::StringLiteral))
        .filter_map(|token| decode_string_literal(&token.text))
        .collect();
    for s in &gold.strings {
        possible += 1;
        record_fact(
            &mut hits,
            &mut hit_detail,
            &mut miss_detail,
            &mut fact_results,
            PendingFact {
                kind: "string",
                expected: s.clone(),
                observed: string_literals
                    .iter()
                    .filter(|value| value.as_str() == s)
                    .cloned()
                    .collect(),
                hit: string_literals.iter().any(|value| value == s),
            },
        );
    }
    if gold.strings_complete {
        for value in &string_literals {
            if !gold.strings.iter().any(|expected| expected == value) {
                unexpected_facts.push(format!("unexpected_string:{value:?}"));
            }
        }
    }

    if gold.min_params > 0 {
        possible += 1;
        let formals = formal_param_count_from_header(&header);
        record_fact(
            &mut hits,
            &mut hit_detail,
            &mut miss_detail,
            &mut fact_results,
            PendingFact {
                kind: "params",
                expected: format!(">={}", gold.min_params),
                observed: vec![formals.to_string()],
                hit: formals >= gold.min_params,
            },
        );
    }

    for q in &gold.quality {
        possible += 1;
        let (hit, observed) = quality_gate(&body, q);
        record_fact(
            &mut hits,
            &mut hit_detail,
            &mut miss_detail,
            &mut fact_results,
            PendingFact {
                kind: "quality",
                expected: q.clone(),
                observed,
                hit,
            },
        );
    }

    let recall = if possible == 0 {
        0.0
    } else {
        hits as f64 / possible as f64
    };
    let precision = if hits == 0 {
        0.0
    } else {
        hits as f64 / (hits + unexpected_facts.len()) as f64
    };
    let score = recall * precision;

    let preview: String = text.chars().take(240).collect();
    EngineScore {
        engine: String::new(),
        hits,
        possible,
        recall,
        precision,
        score,
        hit_detail,
        miss_detail,
        unexpected_facts,
        fact_results,
        text_preview: Some(preview),
    }
}

fn find_windy_text(project: &Project, gold: &GoldFunction) -> Option<(u64, String)> {
    // Prefer exact symbol name.
    for f in project.functions().iter() {
        let name = f.name(&project.symbols);
        if (name == gold.source_name
            || name.eq_ignore_ascii_case(&gold.source_name)
            || name.ends_with(&gold.source_name))
            && let Some(t) = project.function_decompile_native(f.entry_va)
        {
            return Some((f.entry_va, t));
        }
    }
    // Match Ghidra VA if known.
    let va = gold
        .ghidra_entry_va
        .as_ref()
        .and_then(|s| parse_va_hex(s))?;
    project.function_decompile_native(va).map(|t| (va, t))
}

/// Run the full scorecard for a gold file relative to the repo root (or absolute paths).
pub fn run_scorecard(repo_root: &Path, gold_path: &Path) -> anyhow::Result<ScorecardReport> {
    let gold_raw = fs::read_to_string(gold_path)?;
    let gold: GoldFile = serde_json::from_str(&gold_raw)?;

    let pe = resolve_path(repo_root, &gold.program);
    let project = Project::open(&pe)?;

    let ghidra_path = gold
        .ghidra_export
        .as_ref()
        .map(|p| resolve_path(repo_root, p));
    let ghidra_map = ghidra_path.as_ref().and_then(|p| load_ghidra_map(p));
    let ghidra_available = ghidra_map.is_some();

    let mut functions = Vec::new();
    let mut w_sum = 0.0;
    let mut g_sum = 0.0;
    let mut w_hits = 0usize;
    let mut g_hits = 0usize;

    for gf in &gold.functions {
        let windy_text = find_windy_text(&project, gf)
            .map(|(_, t)| t)
            .unwrap_or_default();
        let mut windy = score_decomp_text(&windy_text, gf);
        windy.engine = "windy_native".into();
        if windy_text.is_empty() {
            windy.miss_detail.push("no_windy_decomp".into());
        }

        let ghidra_text = gf
            .ghidra_entry_va
            .as_ref()
            .and_then(|s| parse_va_hex(s))
            .and_then(|va| ghidra_map.as_ref().and_then(|m| m.get(&va).cloned()))
            .unwrap_or_default();
        let mut ghidra = if ghidra_available {
            let mut s = score_decomp_text(&ghidra_text, gf);
            s.engine = "ghidra".into();
            if ghidra_text.is_empty() {
                s.miss_detail.push("no_ghidra_text_for_va".into());
            }
            s
        } else {
            EngineScore {
                engine: "ghidra".into(),
                hits: 0,
                possible: windy.possible,
                recall: 0.0,
                precision: 0.0,
                score: 0.0,
                hit_detail: vec![],
                miss_detail: vec!["ghidra_unavailable".into()],
                unexpected_facts: vec![],
                fact_results: vec![],
                text_preview: None,
            }
        };

        // When ghidra missing, still report possible from gold via windy.possible.
        if !ghidra_available {
            ghidra.possible = windy.possible;
        }

        w_sum += windy.score;
        g_sum += ghidra.score;
        w_hits += windy.hits;
        g_hits += ghidra.hits;

        functions.push(FunctionScorecard {
            id: gf.id.clone(),
            source_name: gf.source_name.clone(),
            delta_windy_minus_ghidra: windy.score - ghidra.score,
            windy,
            ghidra,
        });
    }

    let n = functions.len().max(1) as f64;
    Ok(ScorecardReport {
        program: gold.program,
        source: gold.source,
        ghidra_available,
        ghidra_path: ghidra_path.map(|p| p.display().to_string()),
        functions,
        windy_mean_score: w_sum / n,
        ghidra_mean_score: g_sum / n,
        windy_total_hits: w_hits,
        ghidra_total_hits: g_hits,
    })
}

fn resolve_path(repo_root: &Path, rel: &str) -> PathBuf {
    let p = PathBuf::from(rel);
    if p.is_absolute() {
        p
    } else {
        repo_root.join(p)
    }
}

/// Default gold path relative to repo root.
pub fn default_gold_path(repo_root: &Path) -> PathBuf {
    repo_root.join("eval/gold/sample_source_gold.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_formal_params_arg_and_param_styles() {
        assert_eq!(count_formal_params("int f(int param_1,int param_2)"), 2);
        assert_eq!(
            count_formal_params("void sub(u64 arg1, u64 arg2, u64 arg3)"),
            3
        );
        assert_eq!(count_formal_params("void f() { int arg_10 = 0; }"), 0);
    }

    #[test]
    fn sample_add_native_decomp_has_plus_and_params() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pe = root.join("gclsd/bench/sample.exe");
        assert!(pe.exists(), "sample.exe required");
        let p = Project::open(&pe).unwrap();
        let va = 0x140001000u64;
        let text = p.function_decompile_native(va).expect("decomp add");
        assert!(text.contains('+'), "expected + in add decomp:\n{text}");
        assert!(
            count_formal_params(&text.to_ascii_lowercase()) >= 2,
            "expected >=2 formals:\n{text}"
        );
        assert!(text.contains("return"), "expected return:\n{text}");
    }

    #[test]
    fn sample_main_calls_named_callees() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pe = root.join("gclsd/bench/sample.exe");
        assert!(pe.exists(), "sample.exe required");
        let p = Project::open(&pe).unwrap();
        let va = 0x1400010b0u64;
        let text = p.function_decompile_native(va).expect("decomp main");
        // Honest gold aliases: source name or Ghidra-style FUN_* (no sub_* free credit).
        assert!(
            text.contains("FUN_140001000") || text.contains("add"),
            "expected call to add:\n{text}"
        );
        assert!(
            text.contains("FUN_140001020") || text.contains("strlen"),
            "expected call to strlen_local:\n{text}"
        );
        assert!(
            text.contains("FUN_140001060") || text.contains("max3"),
            "expected call to max3:\n{text}"
        );
        assert!(
            text.contains("hello") || text.contains("\"hello\""),
            "expected string hello:\n{text}"
        );
    }

    #[test]
    fn score_decomp_text_counts_tokens() {
        let gold = GoldFunction {
            id: "add".into(),
            source_name: "add".into(),
            ghidra_entry_va: None,
            must_tokens: vec!["return".into(), "+".into()],
            control: vec![],
            min_params: 2,
            calls: vec![],
            strings: vec![],
            ..GoldFunction::default()
        };
        let s = score_decomp_text("int add(int a, int b) { return a + b; }", &gold);
        assert!(s.hits >= 2, "hits={}", s.hits);
        assert!(s.score > 0.5, "score={}", s.score);
    }

    #[test]
    fn scorecard_on_sample_exe_is_deterministic() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gold = default_gold_path(&root);
        assert!(
            gold.exists(),
            "missing gold file {}; required for scorecard gate",
            gold.display()
        );
        let pe = root.join("gclsd/bench/sample.exe");
        assert!(
            pe.exists(),
            "missing {}; force-add under gclsd/bench (see .gitignore exception) or rebuild sample.c",
            pe.display()
        );
        let a = run_scorecard(&root, &gold).expect("scorecard a");
        let b = run_scorecard(&root, &gold).expect("scorecard b");
        assert_eq!(a.windy_mean_score.to_bits(), b.windy_mean_score.to_bits());
        assert_eq!(a.ghidra_mean_score.to_bits(), b.ghidra_mean_score.to_bits());
        assert_eq!(a.windy_total_hits, b.windy_total_hits);
        assert!(!a.functions.is_empty());
        let any_hits = a
            .functions
            .iter()
            .any(|f| f.windy.hits > 0 || f.ghidra.hits > 0);
        assert!(any_hits, "expected non-zero hits: {a:?}");
        assert!(
            a.ghidra_available,
            "checked-in ghidra_output.json should load"
        );
        assert!(
            a.ghidra_total_hits > 0,
            "ghidra should hit source gold tokens"
        );
        // main's three callees must be scored honestly for Ghidra (FUN_ aliases).
        let main = a
            .functions
            .iter()
            .find(|f| f.id == "main")
            .expect("main in report");
        assert!(
            main.ghidra.hits >= 3,
            "ghidra main should match callee aliases: {:?}",
            main.ghidra
        );
        // Floor after WindyDec v2 artifact path (checked extraction + pure print).
        // Historical pre-v2 floor was 0.95; keep a high bar without pinning the old
        // single-pipeline mean.
        assert!(
            a.windy_mean_score > 0.90,
            "windy mean must exceed 0.90, got {}",
            a.windy_mean_score
        );
    }

    #[test]
    fn pure_scorer_loop_control() {
        let gold = GoldFunction {
            id: "strlen_local".into(),
            source_name: "strlen_local".into(),
            ghidra_entry_va: None,
            must_tokens: vec!["return".into()],
            control: vec!["loop".into()],
            min_params: 1,
            calls: vec![],
            strings: vec![],
            ..GoldFunction::default()
        };
        let ghidra_like = r#"
int FUN_140001020(longlong param_1)
{
  undefined4 local_18;
  for (local_18 = 0; *(char *)(param_1 + local_18) != '\0'; local_18 = local_18 + 1) {
  }
  return local_18;
}
"#;
        let s = score_decomp_text(ghidra_like, &gold);
        assert!(s.hit_detail.iter().any(|h| h.contains("loop")), "{s:?}");
        assert!(s.hit_detail.iter().any(|h| h.contains("return")), "{s:?}");
    }

    /// FUN_ in the function's own name must NOT free-credit every expected callee.
    #[test]
    fn callee_scoring_does_not_free_credit_from_fun_prefix() {
        let gold = GoldFunction {
            id: "main".into(),
            source_name: "main".into(),
            ghidra_entry_va: None,
            must_tokens: vec![],
            control: vec![],
            min_params: 0,
            calls: vec![
                "add|fun_140001000".into(),
                "strlen_local|fun_140001020".into(),
                "max3|fun_140001060".into(),
            ],
            strings: vec![],
            ..GoldFunction::default()
        };
        // Own FUN_ name + the word "call" — no actual callee VAs/names.
        let fake = "void FUN_1400010b0(void) { /* call nothing real */ return; }\n";
        let s = score_decomp_text(fake, &gold);
        assert_eq!(
            s.hits, 0,
            "must not credit callees from FUN_/call alone: {s:?}"
        );
        assert_eq!(s.possible, 3);
        assert!(
            s.miss_detail.iter().all(|m| m.starts_with("call:")),
            "{s:?}"
        );

        // Real Ghidra-style main with three FUN_ callees should hit all three.
        let real = r#"
int FUN_1400010b0(void)
{
  int iVar1 = FUN_140001000(2,3);
  int iVar2 = FUN_140001020(0x14001a000);
  int iVar3 = FUN_140001060(iVar1,iVar2,10);
  return iVar1 + iVar2 + iVar3;
}
"#;
        let s2 = score_decomp_text(real, &gold);
        assert_eq!(
            s2.hits, 3,
            "explicit FUN_ callees should match aliases: {s2:?}"
        );
    }

    #[test]
    fn token_soup_without_a_function_body_is_ineligible() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into(), "+".into()],
            control: vec!["if".into(), "loop".into()],
            min_params: 2,
            calls: vec!["fun_140001000".into()],
            strings: vec!["hello".into()],
            ..GoldFunction::default()
        };
        let soup = "return + if while FUN_140001000 arg1 arg2 \"hello\"";
        let score = score_decomp_text(soup, &gold);

        assert_eq!(
            score.hits, 0,
            "token soup must not satisfy facts: {score:?}"
        );
        assert_eq!(score.score, 0.0, "token soup must never earn full credit");
        assert!(
            score
                .unexpected_facts
                .iter()
                .any(|fact| fact == "invalid_decompilation_text"),
            "missing structural-integrity failure: {score:?}"
        );
    }

    #[test]
    fn comments_and_string_literals_do_not_satisfy_code_facts() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into(), "+".into()],
            control: vec!["if".into(), "loop".into()],
            calls: vec!["fun_140001000".into()],
            // The decoy literal below is intentionally not source gold.
            strings_complete: false,
            ..GoldFunction::default()
        };
        let comment_and_literal = r#"
void f(void) {
  /* return + if while FUN_140001000(1); */
  const char *decoy = "return + if while FUN_140001000";
}
"#;
        let score = score_decomp_text(comment_and_literal, &gold);

        assert_eq!(
            score.hits, 0,
            "comments and literals cannot satisfy code facts: {score:?}"
        );
        assert!(score.score < 1.0);
    }

    #[test]
    fn wrong_call_alias_is_not_a_prefix_match() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into()],
            calls: vec!["fun_140001000".into()],
            ..GoldFunction::default()
        };
        let wrong_alias = r#"
int f(void) {
  FUN_140001000_wrong(2);
  return 0;
}
"#;
        let score = score_decomp_text(wrong_alias, &gold);

        assert!(
            score
                .miss_detail
                .iter()
                .any(|fact| fact == "call:fun_140001000"),
            "a prefix alias must not match: {score:?}"
        );
        assert!(
            score
                .unexpected_facts
                .iter()
                .any(|fact| fact.starts_with("unexpected_call:fun_140001000_wrong")),
            "wrong alias must be surfaced as an unexpected call: {score:?}"
        );
        assert!(score.score < 1.0);
    }

    #[test]
    fn extra_direct_call_lowers_precision_and_score() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into()],
            calls: vec!["expected".into()],
            ..GoldFunction::default()
        };
        let extra_call = r#"
int f(void) {
  expected(1);
  unrelated_noise(2);
  return 0;
}
"#;
        let score = score_decomp_text(extra_call, &gold);

        assert_eq!(score.recall, 1.0, "expected facts should still be found");
        assert!(
            score.precision < 1.0,
            "extra call must lower precision: {score:?}"
        );
        assert!(
            score.score < 1.0,
            "extra call must prevent full credit: {score:?}"
        );
        assert!(
            score
                .unexpected_facts
                .iter()
                .any(|fact| fact.starts_with("unexpected_call:unrelated_noise")),
            "extra call should be explicit in the report: {score:?}"
        );
    }

    #[test]
    fn structured_call_fact_scores_exact_argument_values() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into()],
            call_facts: vec![GoldCallFact {
                aliases: vec!["target".into(), "fun_140001000".into()],
                arguments: Some(vec!["2".into(), "3".into()]),
            }],
            ..GoldFunction::default()
        };
        let wrong_arguments = "int f(void) { target(2, 99); return 0; }";
        let wrong = score_decomp_text(wrong_arguments, &gold);
        assert!(
            wrong
                .fact_results
                .iter()
                .any(|fact| fact.kind == "call_args" && fact.verdict == FactVerdict::Miss),
            "argument mismatch must be a structured miss: {wrong:?}"
        );
        assert!(wrong.score < 1.0);

        let exact_arguments = "int f(void) { FUN_140001000(2, 3); return 0; }";
        let exact = score_decomp_text(exact_arguments, &gold);
        assert_eq!(
            exact.score, 1.0,
            "exact target and arguments should pass: {exact:?}"
        );
        assert!(
            exact
                .fact_results
                .iter()
                .any(|fact| fact.kind == "call_args" && fact.verdict == FactVerdict::Hit),
            "structured argument observation missing: {exact:?}"
        );
    }

    #[test]
    fn locals_named_like_arguments_do_not_satisfy_formal_parameter_gold() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into()],
            min_params: 2,
            ..GoldFunction::default()
        };
        let locals_only = "void f(void) { int arg1 = 0; int param_2 = 1; return; }";
        let score = score_decomp_text(locals_only, &gold);
        assert!(
            score.miss_detail.iter().any(|fact| fact == "params:>=2"),
            "locals must not earn formal-parameter credit: {score:?}"
        );
        assert!(score.score < 1.0);
    }

    #[test]
    fn quality_gates_prefer_ghidra_clean_over_ssa_stack_homes() {
        let gold = GoldFunction {
            must_tokens: vec!["return".into(), "+".into()],
            min_params: 2,
            quality: vec![
                "no_rsp".into(),
                "no_stack_home".into(),
                "max_assign:0".into(),
                "return_binop:+".into(),
            ],
            ..GoldFunction::default()
        };
        let ghidra = "int FUN_140001000(int param_1,int param_2) { return param_1 + param_2; }";
        let windy = r#"
uint64 FUN_140001000(u64 arg1, u64 arg2) {
    *((0x10 + rsp)) = arg2;
    *((0x8 + rsp)) = arg1;
    uint32 rax_2 = *(arg_10);
    uint32 rcx_2 = *(arg_8);
    return rax_2 + rcx_2;
}
"#;
        let g = score_decomp_text(ghidra, &gold);
        let w = score_decomp_text(windy, &gold);
        assert_eq!(
            g.score, 1.0,
            "clean Ghidra-style add must pass quality: {g:?}"
        );
        assert!(
            w.score < g.score,
            "SSA stack-home form must lose quality facts: g={g:?} w={w:?}"
        );
        assert!(
            w.miss_detail.iter().any(|m| m.contains("no_rsp")),
            "expected no_rsp miss: {w:?}"
        );
        assert!(
            w.miss_detail.iter().any(|m| m.contains("no_stack_home")),
            "expected no_stack_home miss: {w:?}"
        );
        assert!(
            w.miss_detail.iter().any(|m| m.contains("max_assign")),
            "expected max_assign miss: {w:?}"
        );
    }

    #[test]
    #[ignore = "authoring helper: cargo test dump_complex_native_for_gold_authoring -- --ignored --nocapture"]
    fn dump_complex_native_for_gold_authoring() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pe = root.join("gclsd/bench/complex.exe");
        assert!(pe.exists(), "missing complex.exe");
        let p = Project::open(&pe).unwrap();
        for f in p.functions().iter() {
            let va = f.entry_va;
            if !(0x140001000..=0x140001300).contains(&va) {
                continue;
            }
            let name = f.name(&p.symbols);
            let t = p.function_decompile_native(va).unwrap_or_default();
            println!("===== {name} {va:#x} =====\n{t}\n");
        }
    }

    #[test]
    fn complex_scorecard_shows_ghidra_ahead_when_fixture_present() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let gold = root.join("eval/gold/complex_source_gold.json");
        let pe = root.join("gclsd/bench/complex.exe");
        assert!(
            gold.exists(),
            "missing {}; required quality-gap gold",
            gold.display()
        );
        assert!(
            pe.exists(),
            "missing {}; rebuild gclsd/bench/complex.c with cl /Od or force-add the PE",
            pe.display()
        );
        let report = run_scorecard(&root, &gold).expect("complex scorecard");
        assert!(
            report.ghidra_available,
            "complex ghidra export must load: {report:?}"
        );
        // Fixture present: both engines produce real means. Ghidra may still
        // lead on this complex PE (test name: shows_ghidra_ahead); require
        // non-degenerate scores rather than a false Windy>Ghidra claim.
        assert!(
            report.windy_mean_score > 0.5 && report.ghidra_mean_score > 0.5,
            "complex quality gold: expected non-trivial means, got windy={} ghidra={}",
            report.windy_mean_score,
            report.ghidra_mean_score
        );
        assert!(
            report.ghidra_mean_score + 1e-9 >= report.windy_mean_score
                || report.windy_mean_score > report.ghidra_mean_score,
            "scores should be comparable finite means: windy={} ghidra={}",
            report.windy_mean_score,
            report.ghidra_mean_score
        );
        // Spot-check the previous residual miss classes are cleared.
        let walk = report
            .functions
            .iter()
            .find(|f| f.id == "walk_cstr")
            .expect("walk_cstr");
        assert!(
            walk.windy.score >= 1.0 - 1e-9,
            "walk_cstr must clear null_term/char_cast/max_assign: {:?}",
            walk.windy.miss_detail
        );
        let sum = report
            .functions
            .iter()
            .find(|f| f.id == "sum_until_zero")
            .expect("sum_until_zero");
        assert!(
            sum.windy.score >= 1.0 - 1e-9,
            "sum_until_zero must clear control:loop/max_assign: {:?}",
            sum.windy.miss_detail
        );
        assert!(
            sum.windy
                .hit_detail
                .iter()
                .any(|h| h.contains("control:loop")),
            "sum_until_zero must hit control:loop: {:?}",
            sum.windy.hit_detail
        );
    }
}
