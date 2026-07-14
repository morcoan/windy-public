//! Path-aware surface observations for v2 semantic fidelity.

use serde::{Deserialize, Serialize};

/// Stable observation identity within one function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ObservationId(u32);

impl ObservationId {
    pub const fn new(i: u32) -> Self {
        Self(i)
    }
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Kind of critical path observation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Call {
        target_hint: Option<u64>,
        arg_count: u8,
    },
    Load {
        is_stack: bool,
    },
    Store {
        is_stack: bool,
    },
    Return,
    ExceptionalExit,
    Barrier,
    Cleanup,
    CompilerArtifact {
        tag: String,
    },
}

/// One ordered observation at a program point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub id: ObservationId,
    pub block: u32,
    pub kind: ObservationKind,
    /// Instruction VA when known.
    pub va: Option<u64>,
    /// Ordinal within the block (effect order).
    pub ordinal: u32,
}

/// Multiset signature for checker equality (order-sensitive for throws/barriers).
/// Uses stable kind tokens (not Debug) so text-derived and SSA-derived stamps match.
pub fn critical_signature(obs: &[Observation]) -> Vec<String> {
    obs.iter()
        .filter(|o| {
            matches!(
                o.kind,
                ObservationKind::Call { .. }
                    | ObservationKind::Store { .. }
                    | ObservationKind::Return
                    | ObservationKind::ExceptionalExit
                    | ObservationKind::Barrier
                    | ObservationKind::Cleanup
            )
        })
        .map(|o| {
            let kind = match &o.kind {
                ObservationKind::Call { .. } => "call",
                ObservationKind::Store { .. } => "store",
                ObservationKind::Return => "return",
                ObservationKind::ExceptionalExit => "throw",
                ObservationKind::Barrier => "barrier",
                ObservationKind::Cleanup => "cleanup",
                ObservationKind::Load { .. } | ObservationKind::CompilerArtifact { .. } => "other",
            };
            format!("{kind}:{}", o.ordinal)
        })
        .collect()
}

/// Derive critical-effect multiset from decompiled C text.
/// Used by the checker so candidates cannot self-stamp; dropping a `return` /
/// store / call in the text fails the multiset check against HIR/SSA observations.
pub fn effects_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut ordinal = 0u32;
    // Split body into statement-ish fragments so signature lines and one-liners
    // still yield return/store/call effects.
    let mut stmts: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        // Drop pure signature-only lines without body content.
        if (t.starts_with("uint")
            || t.starts_with("int")
            || t.starts_with("void")
            || t.starts_with("bool"))
            && t.contains('(')
            && t.ends_with('{')
            && !t.contains('=')
            && !t.contains("return")
        {
            continue;
        }
        for part in t.split(';') {
            let p = part.trim().trim_matches('{').trim_matches('}').trim();
            if !p.is_empty() {
                stmts.push(p.to_string());
            }
        }
    }
    for t in stmts {
        let n = t.to_ascii_lowercase();
        let is_return = n.contains("return");
        let is_call = n.contains("call(")
            || n.contains("call (")
            || (n.contains("fun_") && n.contains('(') && !n.starts_with("fun_"));
        // Direct FUN_ call form: `FUN_1400...(args)` without call( prefix.
        let is_fun_call = !is_call
            && n.contains("fun_")
            && n.contains('(')
            && !n.starts_with("uint")
            && !n.starts_with("int")
            && !n.starts_with("void");
        let has_assign = n.contains('=')
            && !n.contains("==")
            && !n.contains("!=")
            && !n.contains("<=")
            && !n.contains(">=");
        let is_store = has_assign
            && !n.starts_with("return")
            && !n.starts_with("if")
            && !n.starts_with("while")
            && !n.starts_with("for")
            && !n.starts_with("switch")
            && !n.starts_with("case")
            && !n.starts_with("default")
            && (n.contains('*')
                || n.contains("arg_")
                || n.contains("local")
                || n.contains("mem_")
                || n.contains("g_")
                || n.contains("hr")
                || n.contains("*((")
                || n.contains("*p")
                || n.contains("*(p)"));
        let is_cleanup =
            n.contains("res_destroy") || n.contains("destroy(") || n.contains("release(");
        if is_store {
            out.push(format!("store:{ordinal}"));
            ordinal += 1;
        }
        if is_call || is_fun_call {
            out.push(format!("call:{ordinal}"));
            ordinal += 1;
        }
        if is_cleanup && !is_call && !is_fun_call {
            out.push(format!("cleanup:{ordinal}"));
            ordinal += 1;
        }
        if is_return {
            out.push(format!("return:{ordinal}"));
            ordinal += 1;
        }
    }
    out
}
