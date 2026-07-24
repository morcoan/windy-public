//! First-minute triage: rank functions by deterministic fixed-point signals.
//!
//! Composes call-graph degree, exports, imports, strings, size, BEL ontology
//! classes, and structural motifs. Ordering never depends on float comparison.

use serde::Serialize;
use serde_json::{Value, json};

use crate::analysis::functions::EdgeKind;
use crate::analysis::xrefs::XrefKind;
use crate::llm::query::{apis_called, strings_in_function};
use crate::project::Project;
use crate::project::symbols::SymbolKind;

/// Max functions returned by [`get_triage`].
pub const MAX_TRIAGE: usize = 64;

/// Integer score components (fixed-point; higher = more interesting).
#[derive(Clone, Debug, Default, Serialize)]
pub struct TriageSignals {
    pub export: u32,
    pub entry_or_export_seed: u32,
    pub callers: u32,
    pub callees: u32,
    pub imports: u32,
    pub strings: u32,
    pub size_bucket: u32,
    pub ontology: u32,
    pub motifs: u32,
    pub has_memory_card: u32,
}

impl TriageSignals {
    /// Deterministic total: weighted sum of integer components.
    pub fn score(&self) -> u64 {
        u64::from(self.export) * 50_000
            + u64::from(self.entry_or_export_seed) * 40_000
            + u64::from(self.callers) * 1_200
            + u64::from(self.callees) * 800
            + u64::from(self.imports) * 3_000
            + u64::from(self.strings) * 2_000
            + u64::from(self.size_bucket) * 500
            + u64::from(self.ontology) * 8_000
            + u64::from(self.motifs) * 6_000
            + u64::from(self.has_memory_card) * 5_000
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TriageHit {
    pub va: String,
    pub name: String,
    pub score: u64,
    pub size: u64,
    pub signals: TriageSignals,
    pub reasons: Vec<String>,
    pub apis: Vec<String>,
    pub sample_strings: Vec<String>,
    pub ontology: Vec<String>,
    pub motifs: Vec<String>,
}

/// Rank the most interesting functions for first-minute agent focus.
pub fn get_triage(project: &Project, limit: usize) -> Value {
    let limit = limit.clamp(1, MAX_TRIAGE);
    // Project open seeds focus at the PE entry point.
    let entry_va = project.focus.unwrap_or(0);

    // Precompute caller degree (xrefs Call → target).
    let mut caller_degree: std::collections::BTreeMap<u64, u32> = std::collections::BTreeMap::new();
    for func in project.analysis.functions.iter() {
        for block in &func.blocks {
            for edge in &block.successors {
                if edge.kind == EdgeKind::Call && edge.target != 0 {
                    *caller_degree.entry(edge.target).or_default() += 1;
                }
            }
        }
    }
    // Also count xrefs_to for functions that are jumped to.
    for func in project.analysis.functions.iter() {
        let n = project
            .xrefs_to(func.entry_va)
            .iter()
            .filter(|x| x.kind == XrefKind::Call)
            .count() as u32;
        let e = caller_degree.entry(func.entry_va).or_default();
        *e = (*e).max(n);
    }

    // BEL labels when ready (optional — triage still works cold).
    let bel = project.analysis.bel.get();
    let mut ontology_by_func: std::collections::BTreeMap<u64, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut motif_by_func: std::collections::BTreeMap<u64, Vec<String>> =
        std::collections::BTreeMap::new();

    if let Some(index) = bel {
        // Reverse map class_id → name for ontology labels on functions.
        let mut class_names: std::collections::BTreeMap<u32, String> =
            std::collections::BTreeMap::new();
        for (name, id) in &index.ontology.classes {
            class_names.insert(*id, name.to_string());
        }
        for (func_id, class_bits) in &index.ontology.func_labels {
            let Some(entity) = index.entities.get(*func_id as usize) else {
                continue;
            };
            let Some(va) = entity.va else {
                continue;
            };
            let labels: Vec<String> = class_bits
                .iter()
                .filter_map(|cid| class_names.get(&cid).cloned())
                .filter(|n| n != "evidence" && !n.contains('+'))
                .take(8)
                .collect();
            if !labels.is_empty() {
                ontology_by_func.insert(va, labels);
            }
        }
        for (motif_name, funcs) in &index.motifs.tokens {
            for fid in funcs.iter() {
                let Some(entity) = index.entities.get(fid as usize) else {
                    continue;
                };
                let Some(va) = entity.va else {
                    continue;
                };
                motif_by_func
                    .entry(va)
                    .or_default()
                    .push(motif_name.to_string());
            }
        }
        for v in motif_by_func.values_mut() {
            v.sort();
            v.dedup();
            v.truncate(8);
        }
    }

    let mut hits: Vec<TriageHit> = Vec::new();
    for func in project.analysis.functions.iter() {
        let va = func.entry_va;
        let name = func.name(&project.symbols);
        let size = func.size();
        let mut signals = TriageSignals::default();
        let mut reasons = Vec::new();

        let is_export = project
            .symbols
            .get(va)
            .is_some_and(|s| s.kind == SymbolKind::Export);
        if is_export {
            signals.export = 1;
            reasons.push("export".into());
        }
        if va == entry_va {
            signals.entry_or_export_seed = 1;
            reasons.push("pe_entry".into());
        }

        let callers = *caller_degree.get(&va).unwrap_or(&0);
        signals.callers = callers.min(255);
        if callers > 0 {
            reasons.push(format!("callers={callers}"));
        }

        let callees = func
            .blocks
            .iter()
            .flat_map(|b| b.successors.iter())
            .filter(|e| e.kind == EdgeKind::Call && e.target != 0)
            .count() as u32;
        signals.callees = callees.min(255);
        if callees > 4 {
            reasons.push(format!("callees={callees}"));
        }

        let apis = apis_called(project, va);
        signals.imports = (apis.len() as u32).min(32);
        if !apis.is_empty() {
            reasons.push(format!("imports={}", apis.len()));
        }

        let strings = strings_in_function(project, va, 4);
        signals.strings = (strings.len() as u32).min(32);
        if !strings.is_empty() {
            reasons.push(format!("strings={}", strings.len()));
        }

        // Size buckets: tiny noise → 0, medium → 1–3, large → 4–6
        signals.size_bucket = match size {
            0..=16 => 0,
            17..=64 => 1,
            65..=256 => 2,
            257..=1024 => 3,
            1025..=4096 => 4,
            4097..=16384 => 5,
            _ => 6,
        };

        let ontology = ontology_by_func.get(&va).cloned().unwrap_or_default();
        signals.ontology = (ontology.len() as u32).min(8);
        for o in ontology.iter().take(3) {
            reasons.push(format!("ontology:{o}"));
        }

        let motifs = motif_by_func.get(&va).cloned().unwrap_or_default();
        signals.motifs = (motifs.len() as u32).min(8);
        for m in motifs.iter().take(3) {
            reasons.push(format!("motif:{m}"));
        }

        if project.function_memory.contains_key(&va) {
            signals.has_memory_card = 1;
            reasons.push("memory_card".into());
        }

        let score = signals.score();
        // Drop pure noise: empty tiny leaf functions with no signals.
        if score == 0 && size < 32 && !is_export {
            continue;
        }

        hits.push(TriageHit {
            va: format!("{va:#x}"),
            name,
            score,
            size,
            signals,
            reasons,
            apis: apis.into_iter().take(8).collect(),
            sample_strings: strings.into_iter().take(4).map(|s| s.value).collect(),
            ontology,
            motifs,
        });
    }

    // Stable sort: score desc, then VA asc (deterministic).
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.va.cmp(&b.va)));
    hits.truncate(limit);

    let bel_ready = bel.is_some();
    json!({
        "functions": hits,
        "count": hits.len(),
        "bel_ready": bel_ready,
        "message": if bel_ready {
            "Ranked by export/entry, call degree, imports, strings, size, BEL ontology/motifs."
        } else {
            "BEL not ready; ranked without ontology/motif signals. Retry after get_server_status reports bel_ready."
        },
        "cite": { "kind": "triage", "limit": limit },
    })
}
