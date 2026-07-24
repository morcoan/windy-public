//! Global search across instructions, symbols, and strings. Designed to be
//! cheap enough to run on every keystroke in the UI while still covering the
//! whole image.

use std::time::Instant;

use iced_x86::{Formatter as _, IntelFormatter, SymbolResolver};
use regex::{Regex, RegexBuilder};

use crate::disasm::{Disassembler, Syntax, TableResolver};
use crate::project::Project;

const DEADLINE_CHECK_INTERVAL: usize = 4096;

/// Preformatted instruction text aligned with `CodeIndex::instrs`. Building
/// this once eliminates repeated formatter construction and symbol resolution
/// on every whole-image search.
#[derive(Clone, Debug)]
pub struct InstructionSearchIndex {
    texts: Vec<String>,
}

/// Memory-conscious exact immediate index. Sorted `(value, instruction_idx)`
/// pairs avoid the per-key allocation overhead of millions of HashMap posting
/// lists while retaining logarithmic lookup.
#[derive(Clone, Debug)]
pub struct ImmediateSearchIndex {
    postings: Vec<(u64, usize)>,
}

impl ImmediateSearchIndex {
    fn build(project: &Project, deadline: Option<Instant>) -> Option<Self> {
        let mut postings = Vec::new();
        for (index, decoded) in project.analysis.code_index.iter().enumerate() {
            if index % DEADLINE_CHECK_INTERVAL == 0
                && deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                return None;
            }
            let mut seen = [None; 5];
            let mut seen_len = 0usize;
            for operand in 0..decoded.instr.op_count() {
                use iced_x86::OpKind;
                if !matches!(
                    decoded.instr.op_kind(operand),
                    OpKind::Immediate8
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to16
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32to64
                ) {
                    continue;
                }
                let value = decoded.instr.immediate(operand);
                if seen[..seen_len].contains(&Some(value)) {
                    continue;
                }
                seen[seen_len] = Some(value);
                seen_len += 1;
                postings.push((value, index));
            }
        }
        postings.sort_unstable();
        Some(Self { postings })
    }

    fn instruction_indices(&self, value: u64) -> &[(u64, usize)] {
        let start = self
            .postings
            .partition_point(|(candidate, _)| *candidate < value);
        let end = self
            .postings
            .partition_point(|(candidate, _)| *candidate <= value);
        &self.postings[start..end]
    }
}

impl InstructionSearchIndex {
    fn build(project: &Project, deadline: Option<Instant>) -> Option<Self> {
        let resolver: Option<Box<dyn SymbolResolver>> =
            Some(Box::new(TableResolver::from_symbol_table(&project.symbols)));
        let mut formatter = IntelFormatter::with_options(resolver, None);
        let mut texts = Vec::with_capacity(project.analysis.code_index.len());
        for (index, decoded) in project.analysis.code_index.iter().enumerate() {
            if index % DEADLINE_CHECK_INTERVAL == 0
                && deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                return None;
            }
            let mut text = String::new();
            formatter.format(&decoded.instr, &mut text);
            texts.push(text);
        }
        Some(Self { texts })
    }
}

#[derive(Clone, Debug)]
pub struct SearchOutcome {
    pub hits: Vec<SearchHit>,
    pub timed_out: bool,
    pub instruction_index_ready: bool,
}

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
    search_everything_bounded(project, query, None).hits
}

/// Deadline-aware variant used by MCP. When the first broad search needs to
/// build the instruction-text cache, it stops cleanly at the deadline instead
/// of leaving an unbounded formatter scan running in the background.
pub fn search_everything_bounded(
    project: &Project,
    query: &str,
    deadline: Option<Instant>,
) -> SearchOutcome {
    if query.is_empty() {
        return SearchOutcome {
            hits: Vec::new(),
            timed_out: false,
            instruction_index_ready: project.analysis.instruction_search.get().is_some(),
        };
    }

    let mut out = Vec::new();

    // Numeric immediate / VA search.
    if let Some(value) = parse_number(query) {
        let (hits, timed_out) = search_immediate(project, value, deadline);
        out.extend(hits);
        out.extend(search_symbols(project, query));
        out.extend(search_strings(project, query));
        return SearchOutcome {
            hits: out,
            timed_out,
            instruction_index_ready: project.analysis.instruction_search.get().is_some(),
        };
    }

    // Symbol names.
    out.extend(search_symbols(project, query));

    // Petriage-extracted strings.
    out.extend(search_strings(project, query));

    // Disassembly text.
    if let Some(rx) = build_regex(query) {
        let (hits, timed_out) = search_instructions_regex(project, &rx, deadline);
        out.extend(hits);
        return SearchOutcome {
            hits: out,
            timed_out,
            instruction_index_ready: project.analysis.instruction_search.get().is_some(),
        };
    }

    SearchOutcome {
        hits: out,
        timed_out: false,
        instruction_index_ready: project.analysis.instruction_search.get().is_some(),
    }
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
        RegexBuilder::new(&regex::escape(query))
            .case_insensitive(true)
            .build()
            .ok()
    }
}

fn search_immediate(
    project: &Project,
    value: u64,
    deadline: Option<Instant>,
) -> (Vec<SearchHit>, bool) {
    let mut out = Vec::new();
    let immediate_search = &project.analysis.immediate_search;
    if immediate_search.get().is_none() {
        let Some(index) = ImmediateSearchIndex::build(project, deadline) else {
            return (Vec::new(), true);
        };
        let _ = immediate_search.set(index);
    }
    let index = immediate_search
        .get()
        .expect("immediate search index was initialized");
    let formatter = Disassembler::new_from_symbol_table(Syntax::Intel, &project.symbols);
    for &(_, instruction_index) in index.instruction_indices(value) {
        let decoded = &project.analysis.code_index.instrs[instruction_index];
        out.push(SearchHit::Instruction {
            va: decoded.ip,
            text: formatter.format(&decoded.instr),
        });
    }

    // Also treat the number as a possible symbol VA.
    if let Some(name) = project.symbols.name(value) {
        out.push(SearchHit::Symbol {
            va: value,
            name: name.to_string(),
        });
    }

    (out, false)
}

fn search_symbols(project: &Project, query: &str) -> Vec<SearchHit> {
    project
        .symbols
        .iter()
        .filter(|(_, sym)| contains_ascii_case_insensitive(&sym.name, query))
        .map(|(va, sym)| SearchHit::Symbol {
            va,
            name: sym.name.clone(),
        })
        .collect()
}

fn search_strings(project: &Project, query: &str) -> Vec<SearchHit> {
    project
        .pe
        .triage
        .strings
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|s| contains_ascii_case_insensitive(&s.value, query))
        .map(|s| SearchHit::String {
            offset: s.offset,
            value: s.value.clone(),
        })
        .collect()
}

fn search_instructions_regex(
    project: &Project,
    rx: &Regex,
    deadline: Option<Instant>,
) -> (Vec<SearchHit>, bool) {
    let instruction_search = &project.analysis.instruction_search;
    if instruction_search.get().is_none() {
        let Some(index) = InstructionSearchIndex::build(project, deadline) else {
            return (Vec::new(), true);
        };
        // A concurrent search may have populated the cache first; either copy
        // is equivalent, and the loser is dropped here.
        let _ = instruction_search.set(index);
    }
    let index = instruction_search
        .get()
        .expect("instruction search index was initialized");
    let mut hits = Vec::new();
    for (position, text) in index.texts.iter().enumerate() {
        if position % DEADLINE_CHECK_INTERVAL == 0
            && deadline.is_some_and(|deadline| Instant::now() >= deadline)
        {
            return (hits, true);
        }
        if rx.is_match(text) {
            hits.push(SearchHit::Instruction {
                va: project.analysis.code_index.instrs[position].ip,
                text: text.clone(),
            });
        }
    }
    (hits, false)
}

pub fn instruction_search_ready(project: &Project) -> bool {
    project.analysis.instruction_search.get().is_some()
}

pub fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
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

    #[test]
    fn ascii_substring_search_is_case_insensitive_without_allocating() {
        assert!(contains_ascii_case_insensitive("CreateFileW", "filew"));
        assert!(!contains_ascii_case_insensitive("CreateFileW", "socket"));
    }
}
