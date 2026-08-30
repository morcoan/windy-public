//! Lightweight evidence-card smoke metrics (no fake dump baseline).
//!
//! The real agent-loop benchmark lives in `eval/agent-bench` (workspace crate).
//! This module only checks that evidence cards remain non-empty on sample PEs
//! so CI still exercises the evidence pack without a tautological rate comparison.

use crate::llm::query::{EvidenceOpts, function_evidence};
use crate::project::Project;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceSmokeReport {
    pub functions_sampled: usize,
    pub cards_contract_v1: usize,
    pub cites: usize,
    pub token_proxy: f64,
}

fn token_proxy(s: &str) -> f64 {
    (s.len() as f64) / 4.0
}

fn count_cites(v: &serde_json::Value) -> usize {
    let mut n = 0;
    match v {
        serde_json::Value::Object(map) => {
            if map.contains_key("cite") {
                n += 1;
            }
            for child in map.values() {
                n += count_cites(child);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                n += count_cites(child);
            }
        }
        _ => {}
    }
    n
}

/// Sample largest functions and count contract-v1 evidence cards + cites.
pub fn run_evidence_smoke(project: &Project, limit: usize) -> EvidenceSmokeReport {
    let mut funcs: Vec<_> = project.functions().iter().collect();
    funcs.sort_by_key(|f| std::cmp::Reverse(f.size()));
    let sample: Vec<_> = funcs.into_iter().take(limit.max(1)).collect();

    let mut tokens = 0.0;
    let mut cites = 0usize;
    let mut cards_v1 = 0usize;

    for f in &sample {
        let va = f.entry_va;
        if let Some(card) = function_evidence(project, va, EvidenceOpts::default()) {
            tokens += token_proxy(&card.to_string());
            cites += count_cites(&card);
            if card
                .get("contract")
                .and_then(|c| c.get("version"))
                .and_then(|v| v.as_u64())
                == Some(1)
            {
                cards_v1 += 1;
            }
        }
    }

    EvidenceSmokeReport {
        functions_sampled: sample.len(),
        cards_contract_v1: cards_v1,
        cites,
        token_proxy: tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_cards_present_on_sample() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/eval/fixtures/pe/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe missing");
            return;
        }
        let project = Project::open(path).expect("open");
        let report = run_evidence_smoke(&project, 12);
        eprintln!("evidence_smoke={report:?}");
        assert!(report.cards_contract_v1 > 0, "expected contract-v1 cards");
        assert!(report.cites > 0, "expected cites on evidence cards");
        // Explicitly do NOT compare against a hardcoded dump rate of 0.0.
    }
}
