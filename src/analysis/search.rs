
//! Global search across instructions, symbols, and strings. Designed to be
//! cheap enough to run on every keystroke in the UI while still covering the
//! whole image.

use regex::Regex;

use crate::project::Project;
use crate::disasm::Syntax;

/// One search result.
#[derive(Clone, Debug)]
pub enum SearchHit {
    /// An instruction whose mnemonic or operands matched.
    Instruction { va: u64, text: String },
    /// A symbol whose name matched.
    Symbol { va: u64, name: String },
    /// A string extracted from the image.
    String { offset: usize, value: String },
}

/// Search everything for `query`. Supports:
///   - hex literals (`0x1400`) and decimal integers → immediate value search
///   - leading `/` → regex over disassembly text
///   - plain text → case-insensitive substring in symbols, strings, and disassembly.
pub fn search_everything(project: &Project, query: &str) -> Vec<SearchHit> {
    if query.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    // Numeric immediate / VA search.
    if let Some(value) = parse_number(query) {
        out.extend(search_immediate(project, value));
    }

    // Symbol names.
    out.extend(search_symbols(project, query));

    // Petriage-extracted strings.
    out.extend(search_strings(project, query));

    // Disassembly text.
    if let Some(rx) = build_regex(query) {
        out.extend(search_instructions_regex(project, &rx));
    }

    out
}

fn parse_number(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn build_regex(query: &str) -> Option<Regex> {
    if let Some(pattern) = query.strip_prefix('/') {
        Regex::new(pattern).ok()
    } else {
        Regex::new(&regex::escape(query)).ok()
    }
}

fn search_immediate(project: &Project, value: u64) -> Vec<SearchHit> {
    let mut out = Vec::new();
    let names = project.symbols.to_resolver_map();
    let formatter = Syntax::Intel;

    for dec in project.analysis.code_index.iter() {
        let mut matched = false;
        for i in 0..dec.instr.op_count() {
            use iced_x86::OpKind;
            if matches!(
                dec.instr.op_kind(i),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            ) {
                let imm = dec.instr.immediate(i);
                if imm == value {
                    matched = true;
                    break;
                }
            }
        }
        if matched {
            out.push(SearchHit::Instruction {
                va: dec.ip,
                text: formatter.format_instruction(&dec.instr, &names),
            });
        }
    }

    // Also treat the number as a possible symbol VA.
    if let Some(name) = project.symbols.name(value) {
        out.push(SearchHit::Symbol {
            va: value,
            name: name.to_string(),
        });
    }

    out
}

fn search_symbols(project: &Project, query: &str) -> Vec<SearchHit> {
    let needle = query.to_ascii_lowercase();
    project
        .symbols
        .iter()
        .filter(|(_, sym)| sym.name.to_ascii_lowercase().contains(&needle))
        .map(|(va, sym)| SearchHit::Symbol {
            va,
            name: sym.name.clone(),
        })
        .collect()
}

fn search_strings(project: &Project, query: &str) -> Vec<SearchHit> {
    let needle = query.to_ascii_lowercase();
    project
        .pe
        .triage
        .strings
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|s| s.value.to_ascii_lowercase().contains(&needle))
        .map(|s| SearchHit::String {
            offset: s.offset,
            value: s.value.clone(),
        })
        .collect()
}

fn search_instructions_regex(project: &Project, rx: &Regex) -> Vec<SearchHit> {
    let names = project.symbols.to_resolver_map();
    let formatter = Syntax::Intel;
    project
        .analysis
        .code_index
        .iter()
        .filter_map(|dec| {
            let text = formatter.format_instruction(&dec.instr, &names);
            if rx.is_match(&text) {
                Some(SearchHit::Instruction { va: dec.ip, text })
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_and_dec() {
        assert_eq!(parse_number("0x10"), Some(16));
        assert_eq!(parse_number("42"), Some(42));
        assert!(parse_number("foo").is_none());
    }
}
