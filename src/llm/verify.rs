//! Static claim verification for external agents.
//!
//! Agents submit structured hypotheses; windy returns support / contradict /
//! unknown with evidence pointers. No emulation, no LLM â€” pure static facts.
//! See `docs/contracts/claim_edge_registry_v1.md`.

use serde::{Deserialize, Serialize};

use crate::llm::query;
use crate::project::Project;
use crate::project::types::DataType;

/// Checker version for calibration logs.
pub const CLAIM_CHECKER_VERSION: &str = "claim_checker_v1";

/// Verdict for one claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    Supported,
    Contradicted,
    Unknown,
}

/// One structured claim an agent wants checked.
#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Claim {
    /// See claim_edge_registry_v1.md for closed kind set.
    pub kind: String,
    /// Target function VA (hex or decimal).
    pub function_va: String,
    #[serde(default)]
    pub api: Option<String>,
    #[serde(default)]
    pub string: Option<String>,
    #[serde(default)]
    pub stack_offset: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub data_type: Option<DataType>,
    #[serde(default)]
    pub type_str: Option<String>,
    #[serde(default)]
    pub count: Option<usize>,
    #[serde(default)]
    pub target_va: Option<String>,
    #[serde(default)]
    pub dll: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClaimResult {
    pub kind: String,
    pub function_va: String,
    pub verdict: ClaimVerdict,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub checker_ver: String,
}

/// One persisted claim evaluation (JSONL journal).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimEvaluationRecord {
    pub ts_unix_ms: u128,
    pub image_sha256: String,
    pub kind: String,
    pub function_va: String,
    pub verdict: String,
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub checker_ver: String,
}

/// Verify a batch of claims. Always returns one result per claim (never panics).
pub fn verify_claims(project: &Project, claims: &[Claim]) -> Vec<ClaimResult> {
    claims.iter().map(|c| verify_one(project, c)).collect()
}

/// Verify and append evaluation records to the project claim journal.
pub fn verify_claims_logged(
    project: &Project,
    claims: &[Claim],
    home_dir: Option<&std::path::Path>,
) -> std::io::Result<Vec<ClaimResult>> {
    let results = verify_claims(project, claims);
    if let Some(home) = home_dir {
        let journal = ClaimJournal::open(home, &project.image_sha256);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        for r in &results {
            journal.append(&ClaimEvaluationRecord {
                ts_unix_ms: now,
                image_sha256: project.image_sha256.clone(),
                kind: r.kind.clone(),
                function_va: r.function_va.clone(),
                verdict: match r.verdict {
                    ClaimVerdict::Supported => "supported",
                    ClaimVerdict::Contradicted => "contradicted",
                    ClaimVerdict::Unknown => "unknown",
                }
                .into(),
                evidence: r.evidence.clone(),
                detail: r.detail.clone(),
                checker_ver: r.checker_ver.clone(),
            })?;
        }
    }
    Ok(results)
}

/// Append-only claim evaluation journal keyed by image SHA256.
pub struct ClaimJournal {
    path: std::path::PathBuf,
}

impl ClaimJournal {
    pub fn open(home_dir: impl AsRef<std::path::Path>, sha256: &str) -> Self {
        let path = home_dir
            .as_ref()
            .join("projects")
            .join(format!("{sha256}.claims.jsonl"));
        Self { path }
    }

    pub fn append(&self, rec: &ClaimEvaluationRecord) -> std::io::Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_vec(rec).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&line)?;
        f.flush()?;
        Ok(())
    }
}

fn verify_one(project: &Project, claim: &Claim) -> ClaimResult {
    let Some(va) = parse_va_loose(&claim.function_va) else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("bad function_va".into()),
        );
    };
    if project.function_at(va).is_none() {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("function not found".into()),
        );
    }
    match claim.kind.as_str() {
        "calls_api" => verify_calls_api(project, va, claim),
        "has_string" => verify_has_string(project, va, claim),
        "local_name" => verify_local_name(project, va, claim),
        "local_type" => verify_local_type(project, va, claim),
        "param_count" => verify_param_count(project, va, claim),
        "signature_arity" => verify_signature_arity(project, va, claim),
        "calls_edge" => verify_calls_edge(project, va, claim),
        "imports_dll" => verify_imports_dll(project, va, claim),
        "xref_count_min" => verify_xref_count_min(project, va, claim),
        "memory_purpose_set" => verify_memory_purpose(project, va, claim),
        "callee_arity" => verify_callee_arity(project, va, claim),
        other => result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some(format!("unknown claim kind: {other}")),
        ),
    }
}

fn result(
    claim: &Claim,
    verdict: ClaimVerdict,
    evidence: Vec<String>,
    detail: Option<String>,
) -> ClaimResult {
    ClaimResult {
        kind: claim.kind.clone(),
        function_va: claim.function_va.clone(),
        verdict,
        evidence,
        detail,
        checker_ver: CLAIM_CHECKER_VERSION.into(),
    }
}

fn missing(claim: &Claim, field: &str) -> ClaimResult {
    result(
        claim,
        ClaimVerdict::Unknown,
        vec![],
        Some(format!("missing field: {field}")),
    )
}

fn verify_calls_api(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(api) = claim.api.as_deref() else {
        return missing(claim, "api");
    };
    let needle = normalize_api(api);
    let apis = query::apis_called(project, va);
    let callees = query::function_callees(project, va);
    let mut evidence = Vec::new();
    let mut hit = false;
    for a in &apis {
        if normalize_api(a) == needle || normalize_api(a).contains(&needle) {
            hit = true;
            evidence.push(format!("api:{a}"));
        }
    }
    for (cva, name) in &callees {
        let n = normalize_api(name);
        if n == needle || n.contains(&needle) || name.contains(api) {
            hit = true;
            evidence.push(format!("callee {cva:#x}:{name}"));
        }
    }
    result(
        claim,
        if hit {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        evidence,
        if hit {
            None
        } else {
            Some(format!(
                "no call to {api} among {} apis / {} callees",
                apis.len(),
                callees.len()
            ))
        },
    )
}

fn verify_has_string(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(s) = claim.string.as_deref() else {
        return missing(claim, "string");
    };
    let strings = query::strings_in_function(project, va, 1);
    let mut evidence = Vec::new();
    let mut hit = false;
    for sref in &strings {
        if sref.value.contains(s) {
            hit = true;
            evidence.push(format!("{:#x} ({}):{}", sref.va, sref.encoding, sref.value));
        }
    }
    result(
        claim,
        if hit {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        evidence,
        if hit {
            None
        } else {
            Some(format!(
                "substring not found in {} string(s)",
                strings.len()
            ))
        },
    )
}

fn verify_local_name(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(off_str) = claim.stack_offset.as_deref() else {
        return missing(claim, "stack_offset");
    };
    let Some(expected) = claim.name.as_deref() else {
        return missing(claim, "name");
    };
    let Some(offset) = parse_i64_offset(off_str) else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("bad stack_offset".into()),
        );
    };
    let frame = project
        .function_frames
        .get(&va)
        .or_else(|| project.function_at(va).and_then(|f| f.stack_frame.as_ref()));
    let Some(frame) = frame else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("no stack frame".into()),
        );
    };
    let var = frame
        .locals
        .iter()
        .chain(frame.args.iter())
        .find(|v| v.offset == offset);
    match var {
        None => result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some(format!("no local at offset {offset}")),
        ),
        Some(v) => {
            let actual = v.name.as_deref().unwrap_or("");
            let supported = actual == expected;
            result(
                claim,
                if supported {
                    ClaimVerdict::Supported
                } else if actual.is_empty() {
                    ClaimVerdict::Unknown
                } else {
                    ClaimVerdict::Contradicted
                },
                vec![format!(
                    "local[{offset}] name={actual:?} ty={}",
                    project.types.render(&v.ty)
                )],
                if supported {
                    None
                } else {
                    Some(format!("expected name {expected:?}, got {actual:?}"))
                },
            )
        }
    }
}

fn verify_local_type(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(off_str) = claim.stack_offset.as_deref() else {
        return missing(claim, "stack_offset");
    };
    let Some(offset) = parse_i64_offset(off_str) else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("bad stack_offset".into()),
        );
    };
    let frame = project
        .function_frames
        .get(&va)
        .or_else(|| project.function_at(va).and_then(|f| f.stack_frame.as_ref()));
    let Some(frame) = frame else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("no stack frame".into()),
        );
    };
    let Some(v) = frame
        .locals
        .iter()
        .chain(frame.args.iter())
        .find(|v| v.offset == offset)
    else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some(format!("no local at offset {offset}")),
        );
    };
    let rendered = project.types.render(&v.ty);
    let evidence = vec![format!("local[{offset}] ty={rendered}")];

    if let Some(expected_ty) = &claim.data_type {
        let ok = &v.ty == expected_ty || project.types.render(expected_ty) == rendered;
        return result(
            claim,
            if ok {
                ClaimVerdict::Supported
            } else if matches!(v.ty, DataType::Unknown(_)) {
                ClaimVerdict::Unknown
            } else {
                ClaimVerdict::Contradicted
            },
            evidence,
            if ok {
                None
            } else {
                Some(format!(
                    "expected {}, got {rendered}",
                    project.types.render(expected_ty)
                ))
            },
        );
    }
    if let Some(needle) = claim.type_str.as_deref() {
        let ok = rendered
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase());
        return result(
            claim,
            if ok {
                ClaimVerdict::Supported
            } else if matches!(v.ty, DataType::Unknown(_)) {
                ClaimVerdict::Unknown
            } else {
                ClaimVerdict::Contradicted
            },
            evidence,
            if ok {
                None
            } else {
                Some(format!("type {rendered:?} does not contain {needle:?}"))
            },
        );
    }
    missing(claim, "data_type or type_str")
}

fn verify_param_count(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(expected) = claim.count else {
        return missing(claim, "count");
    };
    let name = project
        .function_at(va)
        .map(|f| f.name(&project.symbols))
        .unwrap_or_default();
    let sig = project.function_signatures.get(&va).cloned().or_else(|| {
        let f = project.function_at(va)?;
        crate::analysis::signatures::recover_signature_with_db(
            f,
            &project.analysis.code_index,
            project.bitness,
            &name,
            Some(&project.sig_db),
        )
    });
    let Some(sig) = sig else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("no signature".into()),
        );
    };
    let actual = sig.params.len();
    result(
        claim,
        if actual == expected {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        vec![format!("signature.params.len={actual}")],
        if actual == expected {
            None
        } else {
            Some(format!("expected {expected} params, got {actual}"))
        },
    )
}

fn verify_signature_arity(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let callers = query::callers_with_args(project, va);
    let name = project
        .function_at(va)
        .map(|f| f.name(&project.symbols))
        .unwrap_or_default();
    let sig = project.function_signatures.get(&va).cloned().or_else(|| {
        let f = project.function_at(va)?;
        crate::analysis::signatures::recover_signature_with_db(
            f,
            &project.analysis.code_index,
            project.bitness,
            &name,
            Some(&project.sig_db),
        )
    });
    let recovered = sig.as_ref().map(|s| s.params.len());
    let mut evidence = Vec::new();
    if let Some(n) = recovered {
        evidence.push(format!("recovered_params={n}"));
    }
    evidence.push(format!("callers_observed={}", callers.len()));
    for c in callers.iter().take(8) {
        evidence.push(format!(
            "caller {} from {:#x} args={}",
            c.caller,
            c.from_va,
            c.args.len()
        ));
    }

    if let Some(expected) = claim.count {
        return match recovered {
            Some(n) if n == expected => result(claim, ClaimVerdict::Supported, evidence, None),
            Some(n) => result(
                claim,
                ClaimVerdict::Contradicted,
                evidence,
                Some(format!("recovered {n} != expected {expected}")),
            ),
            None => result(
                claim,
                ClaimVerdict::Unknown,
                evidence,
                Some("no recovered signature".into()),
            ),
        };
    }

    let Some(n) = recovered else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            evidence,
            Some("no recovered signature".into()),
        );
    };
    if callers.is_empty() {
        return result(
            claim,
            ClaimVerdict::Unknown,
            evidence,
            Some("no callers to compare".into()),
        );
    }
    let all_match = callers
        .iter()
        .all(|c| c.args.len() == n || c.args.is_empty());
    result(
        claim,
        if all_match {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Unknown
        },
        evidence,
        None,
    )
}

fn verify_calls_edge(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(t) = claim.target_va.as_deref() else {
        return missing(claim, "target_va");
    };
    let Some(target) = parse_va_loose(t) else {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("bad target_va".into()),
        );
    };
    let callees = query::function_callees(project, va);
    let hit = callees.iter().any(|(cva, _)| *cva == target);
    let evidence: Vec<_> = callees
        .iter()
        .take(16)
        .map(|(cva, name)| format!("{cva:#x}:{name}"))
        .collect();
    result(
        claim,
        if hit {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        evidence,
        if hit {
            None
        } else {
            Some(format!("no direct call edge to {target:#x}"))
        },
    )
}

fn verify_imports_dll(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(dll) = claim.dll.as_deref() else {
        return missing(claim, "dll");
    };
    let needle = dll
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_ascii_lowercase();
    let apis = query::apis_called(project, va);
    let mut evidence = Vec::new();
    let mut hit = false;
    // Best-effort: SigDB lookup by name â†’ owning DLL when available.
    for api in &apis {
        if let Some(sig) = project.sig_db.lookup_by_name(api) {
            // FunctionSignature may not store dll; use win32 lookup path if present.
            let _ = sig;
        }
        // Heuristic: if agent names dll and we call known apis from that dll via SigDB list.
        let list = project.sig_db.signatures_for_dll(&needle);
        if list.iter().any(|s| s.name.eq_ignore_ascii_case(api)) {
            hit = true;
            evidence.push(format!("api {api} in dll {needle}"));
        }
    }
    if evidence.is_empty() {
        // Fallback: contradict only if we have APIs but none matched the DLL catalog.
        if apis.is_empty() {
            return result(
                claim,
                ClaimVerdict::Unknown,
                vec![],
                Some("no imported APIs in function".into()),
            );
        }
        evidence = apis.iter().map(|a| format!("api:{a}")).collect();
    }
    result(
        claim,
        if hit {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        evidence,
        if hit {
            None
        } else {
            Some(format!("no API from dll {needle} among callees"))
        },
    )
}

fn verify_xref_count_min(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(min) = claim.count else {
        return missing(claim, "count");
    };
    let n = project.xrefs_to(va).len();
    result(
        claim,
        if n >= min {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        vec![format!("xrefs_to={n}")],
        if n >= min {
            None
        } else {
            Some(format!("expected >= {min} xrefs, got {n}"))
        },
    )
}

fn verify_memory_purpose(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    match project.function_memory.get(&va) {
        Some(card) if card.purpose.as_ref().is_some_and(|p| !p.is_empty()) => result(
            claim,
            ClaimVerdict::Supported,
            vec![format!("purpose={:?}", card.purpose)],
            None,
        ),
        Some(_) => result(
            claim,
            ClaimVerdict::Contradicted,
            vec!["memory card present but purpose empty".into()],
            Some("purpose not set".into()),
        ),
        None => result(
            claim,
            ClaimVerdict::Contradicted,
            vec![],
            Some("no function_memory card".into()),
        ),
    }
}

fn verify_callee_arity(project: &Project, va: u64, claim: &Claim) -> ClaimResult {
    let Some(expected) = claim.count else {
        return missing(claim, "count");
    };
    let callees = query::function_callees(project, va);
    let mut evidence = Vec::new();
    let mut hit = false;
    for (cva, name) in &callees {
        if let Some(api_filter) = claim.api.as_deref() {
            let n = normalize_api(name);
            let f = normalize_api(api_filter);
            if n != f && !n.contains(&f) && !name.contains(api_filter) {
                continue;
            }
        }
        let sig = project.function_signatures.get(cva).cloned().or_else(|| {
            project
                .sig_db
                .lookup_by_name(name.strip_prefix("__imp_").unwrap_or(name))
                .cloned()
        });
        if let Some(sig) = sig {
            evidence.push(format!("{name}@{cva:#x} params={}", sig.params.len()));
            if sig.params.len() == expected {
                hit = true;
            }
        }
    }
    if evidence.is_empty() {
        return result(
            claim,
            ClaimVerdict::Unknown,
            vec![],
            Some("no callee signatures resolved".into()),
        );
    }
    result(
        claim,
        if hit {
            ClaimVerdict::Supported
        } else {
            ClaimVerdict::Contradicted
        },
        evidence,
        if hit {
            None
        } else {
            Some(format!("no callee with arity {expected}"))
        },
    )
}

/// Auto consistency checks for a function (no freeform claims).
pub fn function_consistency(project: &Project, va: u64) -> Option<serde_json::Value> {
    let func = project.function_at(va)?;
    let name = func.name(&project.symbols);
    let mut checks = Vec::new();

    let sig = project.function_signatures.get(&va).cloned().or_else(|| {
        crate::analysis::signatures::recover_signature_with_db(
            func,
            &project.analysis.code_index,
            project.bitness,
            &name,
            Some(&project.sig_db),
        )
    });
    let param_n = sig.as_ref().map(|s| s.params.len()).unwrap_or(0);
    checks.push(serde_json::json!({
        "id": "has_signature",
        "status": if sig.is_some() { "pass" } else { "warn" },
        "detail": format!("params={param_n}"),
    }));

    let frame = project
        .function_frames
        .get(&va)
        .or(func.stack_frame.as_ref());
    if let Some(frame) = frame {
        let mut out_of_range = 0usize;
        if frame.local_size > 0 {
            for loc in &frame.locals {
                let extent = (-loc.offset) as u64;
                if extent > frame.local_size.saturating_add(loc.size as u64) {
                    out_of_range += 1;
                }
            }
        }
        checks.push(serde_json::json!({
            "id": "stack_locals_in_frame",
            "status": if out_of_range == 0 { "pass" } else { "warn" },
            "detail": format!(
                "local_size={} locals={} out_of_range={out_of_range}",
                frame.local_size,
                frame.locals.len()
            ),
        }));
    } else {
        checks.push(serde_json::json!({
            "id": "stack_locals_in_frame",
            "status": "unknown",
            "detail": "no frame",
        }));
    }

    let apis = query::apis_called(project, va);
    let mut missing_sig = Vec::new();
    for api in &apis {
        if project.sig_db.lookup_by_name(api).is_none() {
            missing_sig.push(api.clone());
        }
    }
    checks.push(serde_json::json!({
        "id": "import_sigs_known",
        "status": if missing_sig.is_empty() { "pass" } else { "warn" },
        "detail": if missing_sig.is_empty() {
            format!("{} imports all in SigDB", apis.len())
        } else {
            format!("missing_sigdb: {}", missing_sig.join(", "))
        },
    }));

    if let Some(sum) = query::function_ssa_optimized_summary(project, va) {
        checks.push(serde_json::json!({
            "id": "ssa_simplify",
            "status": "pass",
            "detail": format!(
                "ops {}â†’{} consts={}",
                sum.op_count_before, sum.op_count_after, sum.constants.len()
            ),
        }));
    } else {
        checks.push(serde_json::json!({
            "id": "ssa_simplify",
            "status": "unknown",
            "detail": "ssa unavailable",
        }));
    }

    let callers = query::function_callers(project, va);
    checks.push(serde_json::json!({
        "id": "call_graph",
        "status": "pass",
        "detail": format!(
            "callers={} callees={}",
            callers.len(),
            query::function_callees(project, va).len()
        ),
    }));

    // Citation discipline: memory card present?
    checks.push(serde_json::json!({
        "id": "memory_card",
        "status": if project.function_memory.contains_key(&va) { "pass" } else { "warn" },
        "detail": if project.function_memory.contains_key(&va) {
            "function_memory present"
        } else {
            "no function_memory; set_function_memory after renames"
        },
    }));

    let pass = checks.iter().filter(|c| c["status"] == "pass").count();
    let warn = checks.iter().filter(|c| c["status"] == "warn").count();

    Some(serde_json::json!({
        "va": format!("{va:#x}"),
        "name": name,
        "checks": checks,
        "summary": { "pass": pass, "warn": warn, "total": checks.len() },
        "contract": { "name": "consistency_report", "version": 1 },
    }))
}

fn normalize_api(s: &str) -> String {
    s.strip_prefix("__imp_")
        .unwrap_or(s)
        .trim()
        .to_ascii_lowercase()
}

fn parse_va_loose(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_i64_offset(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        i64::from_str_radix(hex, 16).ok().map(|v| -v)
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::op::Op;

    fn claim(kind: &str, va: &str) -> Claim {
        Claim {
            kind: kind.into(),
            function_va: va.into(),
            ..Claim::default()
        }
    }

    #[test]
    fn verify_calls_api_true_and_false_on_sample() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.exe");
        if !std::path::Path::new(path).exists() {
            return;
        }
        let project = Project::open(path).expect("open sample");
        let target = project.functions().iter().find_map(|f| {
            let apis = query::apis_called(&project, f.entry_va);
            if apis.is_empty() {
                None
            } else {
                Some((f.entry_va, apis[0].clone()))
            }
        });
        let Some((va, api)) = target else {
            return;
        };
        let va_s = format!("{va:#x}");
        let mut good = claim("calls_api", &va_s);
        good.api = Some(api);
        let mut bad = claim("calls_api", &va_s);
        bad.api = Some("ThisApiDoesNotExistXYZ".into());
        let results = verify_claims(&project, &[good, bad]);
        assert_eq!(results[0].verdict, ClaimVerdict::Supported);
        assert_eq!(results[1].verdict, ClaimVerdict::Contradicted);
        assert_eq!(results[0].checker_ver, CLAIM_CHECKER_VERSION);
    }

    #[test]
    fn verify_local_name_after_writeback() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.exe");
        if !std::path::Path::new(path).exists() {
            return;
        }
        let mut project = Project::open(path).expect("open");
        let va = project.focus.expect("focus");
        Op::SetStackLocalName {
            function_va: va,
            offset: -0x20,
            name: "verify_buf".into(),
            old_name: None,
        }
        .apply_to(&mut project);

        let va_s = format!("{va:#x}");
        let mut good = claim("local_name", &va_s);
        good.stack_offset = Some("-0x20".into());
        good.name = Some("verify_buf".into());
        let mut bad = claim("local_name", &va_s);
        bad.stack_offset = Some("-0x20".into());
        bad.name = Some("wrong_name".into());
        let results = verify_claims(&project, &[good, bad]);
        assert_eq!(results[0].verdict, ClaimVerdict::Supported);
        assert_eq!(results[1].verdict, ClaimVerdict::Contradicted);
    }

    #[test]
    fn consistency_runs_on_sample() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.exe");
        if !std::path::Path::new(path).exists() {
            return;
        }
        let project = Project::open(path).expect("open");
        let va = project.focus.expect("focus");
        let report = function_consistency(&project, va).expect("consistency");
        assert!(report["checks"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn memory_purpose_claim() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.exe");
        if !std::path::Path::new(path).exists() {
            return;
        }
        let mut project = Project::open(path).expect("open");
        let va = project.focus.expect("focus");
        let va_s = format!("{va:#x}");
        let before = verify_claims(&project, &[claim("memory_purpose_set", &va_s)]);
        assert_eq!(before[0].verdict, ClaimVerdict::Contradicted);
        Op::SetFunctionMemory {
            va,
            card: crate::project::memory::FunctionMemoryCard {
                va,
                purpose: Some("helper".into()),
                tags: vec![],
                key_apis: vec![],
                key_strings: vec![],
                purity: None,
                confidence: 50,
                updated_seq: 0,
            },
            old: None,
        }
        .apply_to(&mut project);
        let after = verify_claims(&project, &[claim("memory_purpose_set", &va_s)]);
        assert_eq!(after[0].verdict, ClaimVerdict::Supported);
    }
}
