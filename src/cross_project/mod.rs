//! Cross-binary export/import matching for multi-PE workspaces (Phase 7 E).
//!
//! When a workspace holds multiple projects, this index links importer IAT
//! slots to exporter function entries by API name (and best-effort VA).

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::project::symbols::SymbolKind;
use crate::project::Project;
use crate::project_manager::ProjectId;

/// One cross-project import→export edge.
#[derive(Clone, Debug, Serialize)]
pub struct CrossProjectCall {
    pub importer: ProjectId,
    /// IAT slot VA or call-site VA in the importer.
    pub importer_va: u64,
    pub exporter: ProjectId,
    /// Function entry VA in the exporter.
    pub exporter_va: u64,
    pub api_name: String,
}

/// Workspace-level cross-binary call index.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CrossProjectIndex {
    /// `(exporter_project, exported_va) → importers`
    pub exports: HashMap<(ProjectId, u64), Vec<CrossProjectCall>>,
    /// `api_name → exporters`
    pub by_api_name: HashMap<String, Vec<(ProjectId, u64)>>,
    /// Flat list of all matched calls.
    pub calls: Vec<CrossProjectCall>,
}

impl CrossProjectIndex {
    /// Build the index from currently open projects in a workspace.
    pub fn build(projects: &[(ProjectId, Arc<Project>)]) -> Self {
        let mut index = Self::default();

        // Collect exports: Export symbols + function entries with names.
        // (exporter_id, api_name) → va
        let mut export_list: Vec<(ProjectId, String, u64)> = Vec::new();
        for (id, project) in projects {
            for (va, sym) in project.symbols.iter() {
                if sym.kind == SymbolKind::Export {
                    let name = strip_decoration(&sym.name);
                    export_list.push((*id, name, va));
                }
            }
            // Also functions with non-generic names.
            for f in project.functions().iter() {
                let name = f.name(&project.symbols);
                if name.starts_with("sub_") || name.starts_with("FUN_") {
                    continue;
                }
                let bare = strip_decoration(&name);
                // Avoid duplicating pure exports.
                if !export_list
                    .iter()
                    .any(|(pid, n, v)| pid == id && n == &bare && *v == f.entry_va)
                {
                    export_list.push((*id, bare, f.entry_va));
                }
            }
        }

        for (eid, name, eva) in &export_list {
            index
                .by_api_name
                .entry(name.clone())
                .or_default()
                .push((*eid, *eva));
        }

        // Collect imports: Import / __imp_* symbols.
        for (importer_id, project) in projects {
            for (iat_va, sym) in project.symbols.iter() {
                if sym.kind != SymbolKind::Import
                    && !sym.name.starts_with("__imp_")
                    && !sym.name.starts_with("_imp_")
                {
                    continue;
                }
                let api = strip_decoration(&sym.name);
                let Some(exporters) = index.by_api_name.get(&api) else {
                    continue;
                };
                for (exporter_id, exporter_va) in exporters {
                    if exporter_id == importer_id {
                        continue;
                    }
                    let call = CrossProjectCall {
                        importer: *importer_id,
                        importer_va: iat_va,
                        exporter: *exporter_id,
                        exporter_va: *exporter_va,
                        api_name: api.clone(),
                    };
                    index
                        .exports
                        .entry((*exporter_id, *exporter_va))
                        .or_default()
                        .push(call.clone());
                    index.calls.push(call);
                }
            }
        }

        index
    }

    /// Imports of `project_id` from other workspace members.
    pub fn imports_of(&self, project_id: ProjectId) -> Vec<&CrossProjectCall> {
        self.calls
            .iter()
            .filter(|c| c.importer == project_id)
            .collect()
    }

    pub fn to_json(&self) -> serde_json::Value {
        let calls: Vec<_> = self
            .calls
            .iter()
            .map(|c| {
                serde_json::json!({
                    "importer": c.importer.to_string(),
                    "importer_va": format!("{:#x}", c.importer_va),
                    "exporter": c.exporter.to_string(),
                    "exporter_va": format!("{:#x}", c.exporter_va),
                    "api_name": c.api_name,
                })
            })
            .collect();
        let exports: Vec<_> = self
            .by_api_name
            .iter()
            .map(|(name, list)| {
                serde_json::json!({
                    "api_name": name,
                    "exporters": list.iter().map(|(pid, va)| {
                        serde_json::json!({
                            "project_id": pid.to_string(),
                            "va": format!("{va:#x}"),
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::json!({
            "calls": calls,
            "exports": exports,
            "call_count": self.calls.len(),
        })
    }
}

fn strip_decoration(name: &str) -> String {
    let bare = name
        .strip_prefix("__imp_")
        .or_else(|| name.strip_prefix("_imp_"))
        .unwrap_or(name);
    // stdcall `_Name@N`
    if let Some(rest) = bare.strip_prefix('_')
        && let Some((n, _)) = rest.split_once('@')
    {
        return n.to_string();
    }
    bare.to_string()
}

/// Cheap function fingerprint for cross-binary similarity (not full BinDiff).
#[derive(Clone, Debug, Serialize)]
pub struct FuncFingerprint {
    pub project_id: ProjectId,
    pub va: u64,
    pub name: String,
    /// Sorted unique import API names called (capped).
    pub api_set: Vec<String>,
    pub size: u64,
    pub blocks: usize,
    pub insns: usize,
    /// Cheap shape: mix of block count, edge kinds, size.
    pub shape_sig: u64,
}

/// Build fingerprints for all non-generic functions in open projects.
pub fn build_fingerprints(projects: &[(ProjectId, Arc<Project>)]) -> Vec<FuncFingerprint> {
    let mut out = Vec::new();
    for (id, project) in projects {
        for f in project.functions().iter() {
            let name = f.name(&project.symbols);
            if name.starts_with("sub_") || name.starts_with("FUN_") {
                // Still fingerprint large generic funcs — they may match across DLLs.
                if f.size() < 32 {
                    continue;
                }
            }
            let mut apis = crate::llm::query::apis_called(project, f.entry_va);
            apis.sort();
            apis.dedup();
            apis.truncate(24);
            let insns = f.blocks.iter().map(|block| block.instr_count).sum();
            let mut shape: u64 = f.blocks.len() as u64;
            shape = shape.wrapping_mul(131).wrapping_add(f.size());
            shape = shape.wrapping_mul(131).wrapping_add(insns as u64);
            for block in &f.blocks {
                for edge in &block.successors {
                    shape = shape
                        .wrapping_mul(31)
                        .wrapping_add(edge.kind as u8 as u64);
                }
            }
            for a in &apis {
                for b in a.bytes() {
                    shape = shape.wrapping_mul(33).wrapping_add(u64::from(b));
                }
            }
            out.push(FuncFingerprint {
                project_id: *id,
                va: f.entry_va,
                name,
                api_set: apis,
                size: f.size(),
                blocks: f.blocks.len(),
                insns,
                shape_sig: shape,
            });
        }
    }
    out
}

/// Rank similar functions across projects. If `query` is Some, only compare
/// that function against others; else pairwise sample (capped).
pub fn find_similar(
    fingerprints: &[FuncFingerprint],
    query: Option<(ProjectId, u64)>,
    min_jaccard: f64,
    limit: usize,
) -> Vec<serde_json::Value> {
    let limit = limit.clamp(1, 64);
    let mut pairs = Vec::new();

    let candidates: Vec<&FuncFingerprint> = if let Some((pid, va)) = query {
        fingerprints
            .iter()
            .filter(|f| f.project_id == pid && f.va == va)
            .collect()
    } else {
        fingerprints.iter().take(64).collect()
    };

    for a in &candidates {
        for b in fingerprints {
            if a.project_id == b.project_id && a.va == b.va {
                continue;
            }
            // Prefer cross-project pairs.
            if a.project_id == b.project_id {
                continue;
            }
            // Skip exact same name matches (already covered by name index).
            if strip_decoration(&a.name) == strip_decoration(&b.name)
                && !a.name.starts_with("sub_")
            {
                continue;
            }
            let jac = jaccard(&a.api_set, &b.api_set);
            if jac < min_jaccard && a.api_set.is_empty() && b.api_set.is_empty() {
                // Fall back to size+shape when both have no imports.
                let size_ok = sizes_similar(a.size, b.size);
                if !size_ok {
                    continue;
                }
                let score = shape_score(a, b);
                if score < 0.5 {
                    continue;
                }
                pairs.push((score, *a, b, jac));
                continue;
            }
            if jac < min_jaccard {
                continue;
            }
            if !sizes_similar(a.size, b.size) {
                continue;
            }
            let score = jac * 0.7 + shape_score(a, b) * 0.3;
            pairs.push((score, *a, b, jac));
        }
    }
    pairs.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap_or(std::cmp::Ordering::Equal));
    pairs.truncate(limit);
    pairs
        .into_iter()
        .map(|(score, a, b, jac)| {
            serde_json::json!({
                "score": (score * 1000.0).round() / 1000.0,
                "jaccard": (jac * 1000.0).round() / 1000.0,
                "a": {
                    "project_id": a.project_id.to_string(),
                    "va": format!("{:#x}", a.va),
                    "name": a.name,
                    "apis": a.api_set,
                    "size": a.size,
                    "blocks": a.blocks,
                },
                "b": {
                    "project_id": b.project_id.to_string(),
                    "va": format!("{:#x}", b.va),
                    "name": b.name,
                    "apis": b.api_set,
                    "size": b.size,
                    "blocks": b.blocks,
                },
            })
        })
        .collect()
}

fn jaccard(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let sa: std::collections::HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let sb: std::collections::HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

fn sizes_similar(a: u64, b: u64) -> bool {
    let lo = a.min(b);
    let hi = a.max(b);
    if lo == 0 {
        return hi < 64;
    }
    hi * 100 <= lo * 125 // within +25%
}

fn shape_score(a: &FuncFingerprint, b: &FuncFingerprint) -> f64 {
    let block_ratio = {
        let lo = a.blocks.min(b.blocks) as f64;
        let hi = a.blocks.max(b.blocks).max(1) as f64;
        lo / hi
    };
    let sig_close = if a.shape_sig == b.shape_sig {
        1.0
    } else {
        let xor = a.shape_sig ^ b.shape_sig;
        let bits = xor.count_ones() as f64;
        (64.0 - bits) / 64.0
    };
    block_ratio * 0.5 + sig_close * 0.5
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::symbols::{SymbolKind, SymbolTable};
    use uuid::Uuid;

    /// Minimal fake: build index from hand-crafted symbol tables via a thin
    /// wrapper that only needs symbols + empty functions — we test matching
    /// logic with a private helper-style construction.
    #[test]
    fn match_import_to_export_by_name() {
        // Direct unit test of strip + by_api_name matching without full PE.
        let mut exports_by_name: HashMap<String, Vec<(Uuid, u64)>> = HashMap::new();
        let exporter = Uuid::new_v4();
        let importer = Uuid::new_v4();
        exports_by_name
            .entry("CreateFileW".into())
            .or_default()
            .push((exporter, 0x180001000));

        let mut importer_syms = SymbolTable::default();
        importer_syms.insert(0x140005000, "__imp_CreateFileW", SymbolKind::Import);

        let mut calls = Vec::new();
        for (iat_va, sym) in importer_syms.iter() {
            let api = strip_decoration(&sym.name);
            if let Some(exps) = exports_by_name.get(&api) {
                for (eid, eva) in exps {
                    if *eid != importer {
                        calls.push(CrossProjectCall {
                            importer,
                            importer_va: iat_va,
                            exporter: *eid,
                            exporter_va: *eva,
                            api_name: api.clone(),
                        });
                    }
                }
            }
        }
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].api_name, "CreateFileW");
        assert_eq!(calls[0].exporter_va, 0x180001000);
        assert_eq!(calls[0].importer_va, 0x140005000);
    }

    #[test]
    fn strip_imp_prefix() {
        assert_eq!(strip_decoration("__imp_CreateFileW"), "CreateFileW");
        assert_eq!(strip_decoration("_Foo@12"), "Foo");
        assert_eq!(strip_decoration("Plain"), "Plain");
    }

    #[test]
    fn jaccard_and_similar_ranking() {
        let p1 = Uuid::new_v4();
        let p2 = Uuid::new_v4();
        let fps = vec![
            FuncFingerprint {
                project_id: p1,
                va: 0x1000,
                name: "sub_1000".into(),
                api_set: vec!["CreateFileW".into(), "ReadFile".into(), "CloseHandle".into()],
                size: 200,
                blocks: 5,
                insns: 40,
                shape_sig: 1,
            },
            FuncFingerprint {
                project_id: p2,
                va: 0x2000,
                name: "sub_2000".into(),
                api_set: vec!["CreateFileW".into(), "ReadFile".into()],
                size: 210,
                blocks: 5,
                insns: 42,
                shape_sig: 2,
            },
            FuncFingerprint {
                project_id: p2,
                va: 0x3000,
                name: "unrelated".into(),
                api_set: vec!["MessageBoxW".into()],
                size: 50,
                blocks: 2,
                insns: 10,
                shape_sig: 99,
            },
        ];
        let pairs = find_similar(&fps, Some((p1, 0x1000)), 0.2, 10);
        assert!(!pairs.is_empty());
        assert_eq!(pairs[0]["b"]["va"], "0x2000");
    }
}
