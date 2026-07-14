//! Tolerant C-like frontend for Grand graph gold (evaluator-only).
//!
//! Shared by offline source-graph generation and runtime decomp scoring.
//! Intentionally does **not** import the decompiler — measurement stays separate
//! from the pure engine.

use serde::{Deserialize, Serialize};

/// Token kinds for the small C-like lexer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Identifier,
    Number,
    StringLiteral,
    CharLiteral,
    Operator,
    Punct,
}

#[derive(Clone, Debug)]
pub struct CodeToken {
    pub kind: TokenKind,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct ParsedFunction {
    pub name: String,
    #[allow(dead_code)]
    pub header: Vec<CodeToken>,
    pub body: Vec<CodeToken>,
}

/// Effect / region summary extracted from source or decomp text.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtractedGraph {
    pub function_name: String,
    pub has_return: bool,
    /// Operators observed on live return expressions (`<`, `+`, `^`, …).
    pub return_ops: Vec<String>,
    /// Return expression classes present.
    pub return_classes: Vec<ReturnClass>,
    pub store_count: usize,
    pub call_targets: Vec<String>,
    pub switch_case_values: Vec<i64>,
    pub has_switch: bool,
    pub has_loop: bool,
    pub has_if: bool,
    /// True when a return carries a compare/select without requiring `if`.
    pub branchless_compare_return: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReturnClass {
    Compare,
    BinOp,
    Const,
    Load,
    Call,
    Name,
    Other,
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

/// Small C-like lexer (comments/strings stripped for structure).
pub fn lex_code(source: &str) -> Vec<CodeToken> {
    const MULTI_OPERATORS: &[&str] = &[
        "<<=", ">>=", "...", "->", "==", "!=", "<=", ">=", "&&", "||", "++", "--", "<<", ">>",
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    ];
    // Strip UTF-8 BOM if present (some Grand sources ship with BOM).
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        // Skip residual BOM-like / non-ascii lead bytes safely.
        if byte >= 0x80 {
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

fn function_name_from_header(header: &[CodeToken]) -> String {
    // Last identifier before the parameter list is the function name.
    let Some((params_open, _)) = last_parenthesized_range(header) else {
        return "unknown".into();
    };
    header[..params_open]
        .iter()
        .rev()
        .find(|t| matches!(t.kind, TokenKind::Identifier))
        .map(|t| t.text.clone())
        .unwrap_or_else(|| "unknown".into())
}

/// Parse the first top-level function-like unit from `source`.
pub fn parse_function(source: &str) -> Option<ParsedFunction> {
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
    let name = function_name_from_header(header);
    Some(ParsedFunction {
        name,
        header: header.to_vec(),
        body: tokens[body_open + 1..body_close].to_vec(),
    })
}

/// Parse all top-level functions from a C translation unit (best-effort).
pub fn parse_all_functions(source: &str) -> Vec<ParsedFunction> {
    let tokens = lex_code(source);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < tokens.len() {
        // Find next `{` that looks like a function body (preceded by `)`).
        let Some(rel) = tokens[i..].iter().position(|t| token_is(t, "{")) else {
            break;
        };
        let body_open = i + rel;
        if body_open == 0 {
            i += 1;
            continue;
        }
        // Walk back for matching `)` of parameter list.
        let header = &tokens[..body_open];
        let Some((params_open, params_close)) = last_parenthesized_range(header) else {
            i = body_open + 1;
            continue;
        };
        if params_close + 1 != body_open
            && !header[params_close + 1..body_open].iter().all(|t| {
                matches!(t.kind, TokenKind::Identifier) || token_is(t, "__declspec")
            } /* skip */)
        {
            // Allow attributes between ) and { loosely.
        }
        if !header[..params_open]
            .iter()
            .any(|token| matches!(&token.kind, TokenKind::Identifier))
        {
            i = body_open + 1;
            continue;
        }
        let Some(body_close) = find_matching(&tokens, body_open, "{", "}") else {
            break;
        };
        let name = function_name_from_header(&tokens[..body_open]);
        // Skip obvious non-functions / nested — only accept if name is not a type-only.
        if !matches!(
            name.as_str(),
            "if" | "for" | "while" | "switch" | "return" | "sizeof"
        ) {
            out.push(ParsedFunction {
                name,
                header: tokens[..body_open].to_vec(),
                body: tokens[body_open + 1..body_close].to_vec(),
            });
        }
        i = body_close + 1;
    }
    out
}

fn body_text(tokens: &[CodeToken]) -> String {
    tokens
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn classify_return_expr(expr: &str) -> (ReturnClass, Vec<String>) {
    let n = expr
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let mut ops = Vec::new();
    for op in [
        "<=", ">=", "==", "!=", "<<", ">>", "<", ">", "+", "-", "*", "/", "%", "^", "&", "|",
    ] {
        if n.contains(op) {
            // Avoid double-count of < inside <=
            if op == "<" && (n.contains("<=") || n.contains("<<")) {
                continue;
            }
            if op == ">" && (n.contains(">=") || n.contains(">>")) {
                continue;
            }
            ops.push(op.to_string());
        }
    }
    let class = if ops
        .iter()
        .any(|o| matches!(o.as_str(), "<" | ">" | "<=" | ">=" | "==" | "!="))
        || n.contains('?')
    {
        ReturnClass::Compare
    } else if ops
        .iter()
        .any(|o| matches!(o.as_str(), "+" | "-" | "*" | "/" | "%" | "^" | "&" | "|"))
    {
        ReturnClass::BinOp
    } else if n.contains('(') && n.chars().any(|c| c.is_ascii_alphabetic()) {
        ReturnClass::Call
    } else if n.contains('*') {
        ReturnClass::Load
    } else if n.chars().any(|c| c.is_ascii_digit()) {
        ReturnClass::Const
    } else if !n.is_empty() {
        ReturnClass::Name
    } else {
        ReturnClass::Other
    };
    (class, ops)
}

/// Extract a structure/effect graph from arbitrary C-like text (source or decomp).
pub fn extract_graph_from_text(text: &str) -> ExtractedGraph {
    let mut g = ExtractedGraph::default();
    if text.trim().is_empty() {
        return g;
    }
    // Prefer first parsed function body; fall back to whole text.
    let (name, body_tokens) = if let Some(pf) = parse_function(text) {
        g.function_name = pf.name.clone();
        (pf.name, pf.body)
    } else {
        g.function_name = "unit".into();
        ("unit".into(), lex_code(text))
    };
    let _ = name;
    let body = body_text(&body_tokens);
    let n = body
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();

    g.has_if = n.contains("if(") || body.to_ascii_lowercase().contains("if ");
    g.has_loop =
        n.contains("while") || n.contains("for(") || n.contains("for ") || n.contains("do{");
    g.has_switch = n.contains("switch");

    // Case values.
    let mut i = 0usize;
    let lower = body.to_ascii_lowercase();
    while let Some(pos) = lower[i..].find("case") {
        let start = i + pos + 4;
        let rest = lower[start..].trim_start();
        let num: String = rest
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == 'x' || *c == '-')
            .collect();
        if let Ok(v) = parse_case_int(&num) {
            g.switch_case_values.push(v);
        }
        i = start + 1;
    }

    // Stores: `*` lhs assignments or bare `x =` with star near.
    g.store_count = body.matches('*').count().min(
        body.matches('=')
            .count()
            .saturating_sub(body.matches("==").count() * 2),
    );

    // Calls: identifier(
    for (idx, tok) in body_tokens.iter().enumerate() {
        if matches!(tok.kind, TokenKind::Identifier)
            && !matches!(
                tok.text.as_str(),
                "if" | "while" | "for" | "switch" | "return" | "case" | "sizeof" | "typeof"
            )
            && body_tokens.get(idx + 1).is_some_and(|t| token_is(t, "("))
        {
            g.call_targets.push(tok.text.clone());
        }
    }

    // Returns: split on `return` keyword.
    let lower_body = body.to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(pos) = lower_body[search_from..].find("return") {
        let abs = search_from + pos;
        let after = &body[abs + 6..];
        let end = after
            .find(';')
            .or_else(|| after.find('{'))
            .unwrap_or(after.len().min(120));
        let expr = after[..end].trim();
        if !expr.is_empty() || after.trim_start().starts_with(';') {
            g.has_return = true;
            let (class, ops) = classify_return_expr(expr);
            if !g.return_classes.contains(&class) {
                g.return_classes.push(class.clone());
            }
            for o in ops {
                if !g.return_ops.contains(&o) {
                    g.return_ops.push(o);
                }
            }
            if matches!(class, ReturnClass::Compare) {
                g.branchless_compare_return = true;
            }
        }
        search_from = abs + 6;
    }
    // Whole-function compare return without keyword spacing.
    if !g.has_return && (n.contains("return") || body.contains("return")) {
        g.has_return = true;
        let (class, ops) = classify_return_expr(&body);
        g.return_classes.push(class.clone());
        g.return_ops.extend(ops);
        if matches!(class, ReturnClass::Compare) {
            g.branchless_compare_return = true;
        }
    }
    // Predicates on if/while also contribute compare ops (structured form of
    // branchless return a < b).
    let (_, body_ops) = classify_return_expr(&body);
    for o in body_ops {
        if matches!(o.as_str(), "<" | ">" | "<=" | ">=" | "==" | "!=") && !g.return_ops.contains(&o)
        {
            g.return_ops.push(o);
            if !g.return_classes.contains(&ReturnClass::Compare) {
                g.return_classes.push(ReturnClass::Compare);
            }
        }
    }
    g
}

fn parse_case_int(s: &str) -> Result<i64, ()> {
    let s = s.trim().trim_end_matches(':');
    if s.is_empty() {
        return Err(());
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).map_err(|_| ())
    } else {
        s.parse().map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branchless_compare_return_extracted() {
        let g = extract_graph_from_text("int f(int a,int b){ return a < b; }");
        assert!(g.has_return);
        assert!(g.branchless_compare_return);
        assert!(g.return_classes.contains(&ReturnClass::Compare));
        assert!(g.return_ops.iter().any(|o| o == "<"));
        assert!(!g.has_if);
    }

    #[test]
    fn if_form_also_has_compare_return() {
        let g = extract_graph_from_text("int f(int a,int b){ if(a<b) return 1; else return 0; }");
        assert!(g.has_if);
        assert!(g.has_return);
    }

    #[test]
    fn switch_cases_extracted() {
        let g = extract_graph_from_text(
            "int f(int n){ switch(n){ case 0: return 10; case 1: return 20; default: return -1; } }",
        );
        assert!(g.has_switch);
        assert!(g.switch_case_values.contains(&0));
        assert!(g.switch_case_values.contains(&1));
    }

    #[test]
    fn parse_a01_source_functions() {
        let src = include_str!("../../../eval/grand/src/a01_signed_rel.c");
        let fns = parse_all_functions(src);
        let names: Vec<_> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.iter().any(|n| *n == "signed_lt"), "names={names:?}");
    }
}
