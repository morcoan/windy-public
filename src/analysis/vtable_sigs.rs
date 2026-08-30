//! COM / interface vtable signature database (Phase 7 D).
//!
//! Mirrors the SigDB pattern: bundled JSON under `vtables/` plus optional
//! user overlays in the resolved Windy data directory's `vtables/` folder.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::project::types::{DataTypeManager, FunctionSignature};

/// One method in a vtable.
#[derive(Clone, Debug)]
pub struct VtableMethod {
    pub offset: u32,
    pub name: String,
    pub signature: FunctionSignature,
}

/// One COM / C++ interface vtable definition.
#[derive(Clone, Debug)]
pub struct VtableInterface {
    pub name: String,
    pub methods: Vec<VtableMethod>,
    /// offset → method index
    by_offset: HashMap<u32, usize>,
}

impl VtableInterface {
    pub fn method_at(&self, offset: u32) -> Option<&VtableMethod> {
        self.by_offset.get(&offset).map(|&i| &self.methods[i])
    }
}

#[derive(Debug, Deserialize)]
struct MethodEntry {
    offset: u32,
    name: String,
    #[serde(default)]
    params: Vec<(String, String)>,
    #[serde(default = "default_ret")]
    ret: String,
}

fn default_ret() -> String {
    "void".to_string()
}

#[derive(Debug, Deserialize)]
struct InterfaceEntry {
    interface: String,
    methods: Vec<MethodEntry>,
}

/// Hot-reloadable vtable signature database.
#[derive(Clone, Debug, Default)]
pub struct VtableDB {
    by_interface: HashMap<String, VtableInterface>,
    /// Canonical IUnknown offsets for heuristic annotation.
    iunknown_offsets: HashMap<u32, String>,
}

#[allow(dead_code)] // compatibility constructor plus MCP/project query surface
impl VtableDB {
    /// Load bundled defaults then overlay user + crate-adjacent `vtables/`.
    pub fn load() -> Self {
        Self::load_from(crate::project::persistence::windy_home_dir())
    }

    /// Load bundled defaults then overlay an explicit Windy data directory.
    pub fn load_from(home_dir: impl AsRef<Path>) -> Self {
        let types = DataTypeManager::new();
        let mut db = Self::default();
        db.load_bundled(&types);
        db.load_dir(home_dir.as_ref().join("vtables"), &types);
        if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
            db.load_dir(Path::new(&manifest).join("vtables"), &types);
        } else {
            db.load_dir(Path::new("vtables"), &types);
        }
        db.seed_iunknown_heuristics();
        db
    }

    /// Bundled defaults only (tests / no filesystem).
    #[allow(dead_code)]
    pub fn load_bundled_only() -> Self {
        let types = DataTypeManager::new();
        let mut db = Self::default();
        db.load_bundled(&types);
        db.seed_iunknown_heuristics();
        db
    }

    fn seed_iunknown_heuristics(&mut self) {
        self.iunknown_offsets.insert(0, "QueryInterface".into());
        self.iunknown_offsets.insert(8, "AddRef".into());
        self.iunknown_offsets.insert(16, "Release".into());
    }

    fn load_bundled(&mut self, types: &DataTypeManager) {
        const BUNDLED: &[(&str, &str)] = &[
            ("iunknown", include_str!("../../vtables/iunknown.json")),
            ("idispatch", include_str!("../../vtables/idispatch.json")),
            (
                "ienumstring",
                include_str!("../../vtables/ienumstring.json"),
            ),
            (
                "ipersistfile",
                include_str!("../../vtables/ipersistfile.json"),
            ),
            (
                "isequentialstream",
                include_str!("../../vtables/isequentialstream.json"),
            ),
            ("istream", include_str!("../../vtables/istream.json")),
        ];
        for (name, json) in BUNDLED {
            if let Err(e) = self.ingest_json(json, types) {
                tracing::warn!("bundled vtable {name}.json: {e}");
            }
        }
    }

    fn load_dir(&mut self, dir: impl AsRef<Path>, types: &DataTypeManager) {
        let dir = dir.as_ref();
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match fs::read_to_string(&path) {
                Ok(json) => {
                    if let Err(e) = self.ingest_json(&json, types) {
                        tracing::warn!("vtable file {}: {e}", path.display());
                    }
                }
                Err(e) => tracing::warn!("read {}: {e}", path.display()),
            }
        }
    }

    fn ingest_json(&mut self, json: &str, types: &DataTypeManager) -> Result<(), String> {
        // Accept either a single interface object or an array.
        let entries: Vec<InterfaceEntry> =
            if let Ok(one) = serde_json::from_str::<InterfaceEntry>(json) {
                vec![one]
            } else {
                serde_json::from_str(json).map_err(|e| format!("parse: {e}"))?
            };
        for entry in entries {
            let mut methods = Vec::new();
            let mut by_offset = HashMap::new();
            for m in entry.methods {
                let sig = FunctionSignature {
                    name: m.name.clone(),
                    params: m
                        .params
                        .into_iter()
                        .map(|(n, t)| {
                            (n, crate::analysis::win32_sigs::resolve_type_name(types, &t))
                        })
                        .collect(),
                    ret: crate::analysis::win32_sigs::resolve_type_name(types, &m.ret),
                    calling_conv: Some("stdcall".to_string()),
                };
                let idx = methods.len();
                by_offset.insert(m.offset, idx);
                methods.push(VtableMethod {
                    offset: m.offset,
                    name: m.name,
                    signature: sig,
                });
            }
            let iface = VtableInterface {
                name: entry.interface.clone(),
                methods,
                by_offset,
            };
            self.by_interface.insert(entry.interface, iface);
        }
        Ok(())
    }

    pub fn lookup(&self, interface: &str) -> Option<&VtableInterface> {
        self.by_interface.get(interface)
    }

    /// Resolve a vtable method by byte offset, preferring a named interface
    /// when provided; otherwise scan all interfaces then IUnknown heuristics.
    pub fn resolve_method(
        &self,
        offset: u32,
        preferred_interface: Option<&str>,
    ) -> Option<(String, &VtableMethod)> {
        if let Some(name) = preferred_interface
            && let Some(iface) = self.by_interface.get(name)
            && let Some(m) = iface.method_at(offset)
        {
            return Some((iface.name.clone(), m));
        }
        // Prefer IUnknown for the classic 0/8/16 offsets.
        if let Some(iface) = self.by_interface.get("IUnknown")
            && let Some(m) = iface.method_at(offset)
        {
            return Some((iface.name.clone(), m));
        }
        for iface in self.by_interface.values() {
            if let Some(m) = iface.method_at(offset) {
                return Some((iface.name.clone(), m));
            }
        }
        None
    }

    /// Heuristic: known COM slot without a full DB hit.
    pub fn heuristic_iunknown(&self, offset: u32) -> Option<&str> {
        self.iunknown_offsets.get(&offset).map(|s| s.as_str())
    }

    pub fn interfaces(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.by_interface.keys().cloned().collect();
        keys.sort();
        keys
    }

    pub fn len(&self) -> usize {
        self.by_interface.values().map(|i| i.methods.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_interface.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_iunknown() {
        let db = VtableDB::load_bundled_only();
        let iface = db.lookup("IUnknown").expect("IUnknown");
        assert_eq!(iface.methods.len(), 3);
        let qi = iface.method_at(0).expect("QueryInterface");
        assert_eq!(qi.name, "QueryInterface");
        let rel = iface.method_at(16).expect("Release");
        assert_eq!(rel.name, "Release");
        assert_eq!(rel.signature.ret, crate::project::types::DataType::Uint(32));
    }

    #[test]
    fn resolve_release_at_0x10() {
        let db = VtableDB::load_bundled_only();
        let (iface, m) = db.resolve_method(16, None).expect("Release");
        assert_eq!(iface, "IUnknown");
        assert_eq!(m.name, "Release");
    }

    #[test]
    fn interfaces_include_idispatch() {
        let db = VtableDB::load_bundled_only();
        let names = db.interfaces();
        assert!(names.iter().any(|n| n == "IUnknown"));
        assert!(names.iter().any(|n| n == "IDispatch"));
        assert!(db.len() >= 20, "expected >=20 methods, got {}", db.len());
    }
}
