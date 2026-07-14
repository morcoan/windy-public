//! Scripted agent-loop metrics (W0 degrade-and-recover harness).
//!
//! North star: verified facts per 1k tokens for an evidence-first policy
//! versus a dump (agent_text) baseline.

use crate::llm::query::{EvidenceOpts, function_evidence};
use crate::llm::verify::{Claim, ClaimVerdict, verify_claims};
use crate::project::Project;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct AgentLoopReport {
    pub policy: String,
    pub functions_sampled: usize,
    pub tool_calls: usize,
    pub token_proxy: f64,
    pub cites: usize,
    pub supported_claims: usize,
    pub contradicted_claims: usize,
    pub cards_contract_v1: usize,
    pub verified_facts_per_1k_tokens: f64,
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

/// Run evidence-first vs dump baseline on `project` for up to `limit` largest functions.
pub fn run_agent_loop_eval(project: &Project, limit: usize) -> (AgentLoopReport, AgentLoopReport) {
    let mut funcs: Vec<_> = project.functions().iter().collect();
    funcs.sort_by_key(|f| std::cmp::Reverse(f.size()));
    let sample: Vec<_> = funcs.into_iter().take(limit.max(1)).collect();

    let mut e_tokens = 0.0;
    let mut e_tools = 0usize;
    let mut supported = 0usize;
    let mut contradicted = 0usize;
    let mut cites = 0usize;
    let mut cards_v1 = 0usize;
    let mut d_tokens = 0.0;
    let mut d_tools = 0usize;

    for f in &sample {
        let va = f.entry_va;
        if let Some(card) = function_evidence(project, va, EvidenceOpts::default()) {
            e_tools += 1;
            e_tokens += token_proxy(&card.to_string());
            cites += count_cites(&card);
            if card
                .get("contract")
                .and_then(|c| c.get("version"))
                .and_then(|v| v.as_u64())
                == Some(1)
            {
                cards_v1 += 1;
            }
            let apis = crate::llm::query::apis_called(project, va);
            if let Some(api) = apis.first() {
                e_tools += 1;
                for r in verify_claims(
                    project,
                    &[
                        Claim {
                            kind: "calls_api".into(),
                            function_va: format!("{va:#x}"),
                            api: Some(api.clone()),
                            ..Claim::default()
                        },
                        Claim {
                            kind: "calls_api".into(),
                            function_va: format!("{va:#x}"),
                            api: Some("TotallyFakeApi_XYZ".into()),
                            ..Claim::default()
                        },
                    ],
                ) {
                    match r.verdict {
                        ClaimVerdict::Supported => supported += 1,
                        ClaimVerdict::Contradicted => contradicted += 1,
                        ClaimVerdict::Unknown => {}
                    }
                }
            }
        }
        if let Some(text) = project.function_agent_text(va) {
            d_tools += 1;
            d_tokens += token_proxy(&text);
        }
    }

    let facts = supported + cites;
    let e_rate = if e_tokens > 0.0 {
        (facts as f64) / e_tokens * 1000.0
    } else {
        0.0
    };
    let d_rate = 0.0; // dump has no structured verified facts

    let evidence = AgentLoopReport {
        policy: "evidence".into(),
        functions_sampled: sample.len(),
        tool_calls: e_tools,
        token_proxy: e_tokens,
        cites,
        supported_claims: supported,
        contradicted_claims: contradicted,
        cards_contract_v1: cards_v1,
        verified_facts_per_1k_tokens: e_rate,
    };
    let dump = AgentLoopReport {
        policy: "dump".into(),
        functions_sampled: sample.len(),
        tool_calls: d_tools,
        token_proxy: d_tokens,
        cites: 0,
        supported_claims: 0,
        contradicted_claims: 0,
        cards_contract_v1: 0,
        verified_facts_per_1k_tokens: d_rate,
    };
    (evidence, dump)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_policy_beats_dump_on_sample() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe missing");
            return;
        }
        let project = Project::open(path).expect("open");
        let (ev, dump) = run_agent_loop_eval(&project, 12);
        eprintln!("evidence={ev:?}");
        eprintln!("dump={dump:?}");
        assert!(ev.cards_contract_v1 > 0);
        assert!(ev.cites > 0);
        assert!(ev.verified_facts_per_1k_tokens > dump.verified_facts_per_1k_tokens);
        if ev.supported_claims + ev.contradicted_claims > 0 {
            assert!(ev.supported_claims > 0);
            assert!(ev.contradicted_claims > 0);
        }
    }
}
