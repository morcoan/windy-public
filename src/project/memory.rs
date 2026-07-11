//! Durable per-function agent memory cards (Phase C).
//!
//! Agents write short purpose/tags after analysis; cards survive IDB reload
//! and surface in evidence packs so later sessions skip rediscovery.

use serde::{Deserialize, Serialize};

/// Agent-authored (or auto-seeded) understanding of one function.
///
/// Note: do **not** use `skip_serializing_if` here — postcard is positional and
/// skipped fields break IDB round-trips.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionMemoryCard {
    /// Function entry VA (also the map key; repeated for JSON convenience).
    pub va: u64,
    /// Short purpose line written by the agent.
    pub purpose: Option<String>,
    /// Freeform tags: "crypto", "io", "thunk", …
    pub tags: Vec<String>,
    /// Key imported APIs (auto-filled if empty on set).
    pub key_apis: Vec<String>,
    /// Key string literals (auto-filled if empty on set).
    pub key_strings: Vec<String>,
    /// Side-effect hint: pure | io | alloc | unknown
    pub purity: Option<String>,
    /// Confidence 0–100 (integer so Op can stay Eq).
    pub confidence: u8,
    /// Project op_seq when last updated.
    pub updated_seq: u64,
}

impl FunctionMemoryCard {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "va": format!("{:#x}", self.va),
            "purpose": self.purpose,
            "tags": self.tags,
            "key_apis": self.key_apis,
            "key_strings": self.key_strings,
            "purity": self.purity,
            "confidence": self.confidence,
            "updated_seq": self.updated_seq,
        })
    }

}
