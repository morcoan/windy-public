//! Win32 API signature database for LLM reverse engineering.
//!
//! Loads per-DLL JSON signature files from `~/.windy/signatures/` (user
//! overrides) plus the crate-bundled defaults under `signatures/`.  When an
//! LLM sees `__imp_CreateFileW`, this DB supplies the full parameter list so
//! type recovery and agent-text annotation no longer guess from training data.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::project::types::{DataType, DataTypeManager, FunctionSignature};

/// On-disk entry shape (matches the plan JSON schema).
#[derive(Debug, Deserialize)]
struct SigEntry {
    name: String,
    dll: String,
    params: Vec<(String, String)>,
    ret: String,
    #[serde(default)]
    calling_conv: Option<String>,
}

/// Hot-reloadable Win32 API signature database.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // MCP / agent / test surface
pub struct SigDB {
    /// `(dll_lower, api_name) → signature`
    by_key: HashMap<(String, String), FunctionSignature>,
    /// API name alone (first / preferred hit when DLL is unknown).
    by_name: HashMap<String, FunctionSignature>,
    /// DLL basename (no extension) → list of API names, for MCP listing.
    by_dll: HashMap<String, Vec<String>>,
}

#[allow(dead_code)] // MCP / agent / test surface
impl SigDB {
    /// Load bundled defaults then overlay `~/.windy/signatures/*.json`.
    pub fn load() -> Self {
        let types = DataTypeManager::new();
        let mut db = Self::default();
        db.load_bundled(&types);
        if let Some(dir) = user_signatures_dir() {
            db.load_dir(&dir, &types);
        }
        // Also load from the crate-adjacent `signatures/` on disk so developers
        // can edit JSON without a rebuild (overlays bundled).
        if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
            db.load_dir(Path::new(&manifest).join("signatures"), &types);
        } else {
            // Runtime: look next to the executable / cwd.
            db.load_dir(Path::new("signatures"), &types);
        }
        db
    }

    /// Load only bundled defaults (tests / no filesystem).
    pub fn load_bundled_only() -> Self {
        let types = DataTypeManager::new();
        let mut db = Self::default();
        db.load_bundled(&types);
        db
    }

    fn load_bundled(&mut self, types: &DataTypeManager) {
        const BUNDLED: &[(&str, &str)] = &[
            ("kernel32", include_str!("../../signatures/kernel32.json")),
            ("user32", include_str!("../../signatures/user32.json")),
            ("ntdll", include_str!("../../signatures/ntdll.json")),
            ("advapi32", include_str!("../../signatures/advapi32.json")),
        ];
        for (dll, json) in BUNDLED {
            if let Err(e) = self.ingest_json(json, Some(dll), types) {
                tracing::warn!("bundled {dll}.json: {e}");
            }
        }
    }

    /// Hot-reload: re-read user + on-disk directories (keeps bundled as base).
    pub fn reload(&mut self) {
        *self = Self::load();
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
            // Skip generator / non-sig files.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('_'))
            {
                continue;
            }
            let dll_hint = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase());
            match fs::read_to_string(&path) {
                Ok(json) => {
                    if let Err(e) = self.ingest_json(&json, dll_hint.as_deref(), types) {
                        tracing::warn!("sig file {}: {e}", path.display());
                    }
                }
                Err(e) => tracing::warn!("read {}: {e}", path.display()),
            }
        }
    }

    fn ingest_json(
        &mut self,
        json: &str,
        dll_hint: Option<&str>,
        types: &DataTypeManager,
    ) -> Result<(), String> {
        let entries: Vec<SigEntry> =
            serde_json::from_str(json).map_err(|e| format!("parse: {e}"))?;
        for entry in entries {
            let dll = normalize_dll(if entry.dll.is_empty() {
                dll_hint.unwrap_or("unknown")
            } else {
                &entry.dll
            });
            let sig = FunctionSignature {
                name: entry.name.clone(),
                params: entry
                    .params
                    .into_iter()
                    .map(|(n, t)| (n, resolve_type_name(types, &t)))
                    .collect(),
                ret: resolve_type_name(types, &entry.ret),
                calling_conv: entry.calling_conv.or_else(|| Some("stdcall".to_string())),
            };
            self.by_dll
                .entry(dll.clone())
                .or_default()
                .push(entry.name.clone());
            self.by_name
                .insert(entry.name.clone(), sig.clone());
            self.by_key.insert((dll, entry.name), sig);
        }
        Ok(())
    }

    /// Look up by `(dll, name)`. DLL may be `"kernel32"` or `"kernel32.dll"`.
    pub fn lookup(&self, dll: &str, name: &str) -> Option<&FunctionSignature> {
        let dll = normalize_dll(dll);
        self.by_key.get(&(dll, name.to_string()))
    }

    /// Look up by API name alone (IAT only carries `__imp_<Api>`).
    pub fn lookup_by_name(&self, name: &str) -> Option<&FunctionSignature> {
        // Strip common decoration prefixes.
        let bare = name
            .strip_prefix("__imp_")
            .or_else(|| name.strip_prefix("_imp_"))
            .unwrap_or(name);
        // Strip stdcall decoration `_Name@N`.
        let bare = bare
            .strip_prefix('_')
            .and_then(|s| s.split_once('@').map(|(n, _)| n))
            .unwrap_or(bare);
        self.by_name.get(bare)
    }

    /// All known DLL basenames (sorted).
    pub fn dlls(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.by_dll.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Signatures for one DLL (name-only list + full sigs).
    pub fn signatures_for_dll(&self, dll: &str) -> Vec<&FunctionSignature> {
        let dll = normalize_dll(dll);
        let Some(names) = self.by_dll.get(&dll) else {
            return Vec::new();
        };
        names
            .iter()
            .filter_map(|n| self.by_key.get(&(dll.clone(), n.clone())))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

fn normalize_dll(dll: &str) -> String {
    let lower = dll.to_ascii_lowercase();
    lower
        .strip_suffix(".dll")
        .unwrap_or(&lower)
        .to_string()
}

/// Resolve a JSON type name through the DataTypeManager, falling back to Named.
pub fn resolve_type_name(types: &DataTypeManager, name: &str) -> DataType {
    // Common pointer spellings.
    if let Some(inner) = name.strip_prefix("LP") {
        if inner.is_empty() {
            return DataType::Ptr(Box::new(DataType::Void));
        }
        // LPVOID already seeded; try full name first.
        if let Some(ty) = types.get(name) {
            return ty.clone();
        }
        // LPxxx → Ptr(xxx) when xxx is known, else Named.
        if let Some(ty) = types.get(inner) {
            return DataType::Ptr(Box::new(ty.clone()));
        }
        return DataType::Named(name.to_string());
    }
    if let Some(inner) = name.strip_prefix('P').filter(|s| {
        // PFOO but not PCWSTR (const wchar) which is seeded / Named.
        s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && !s.starts_with('C')
            && *s != "VOID"
    }) {
        if let Some(ty) = types.get(name) {
            return ty.clone();
        }
        if let Some(ty) = types.get(inner) {
            return DataType::Ptr(Box::new(ty.clone()));
        }
    }
    types
        .get(name)
        .cloned()
        .unwrap_or_else(|| DataType::Named(name.to_string()))
}

fn user_signatures_dir() -> Option<PathBuf> {
    directories::UserDirs::new().map(|u| u.home_dir().join(".windy").join("signatures"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_createfilew_has_seven_params() {
        let db = SigDB::load_bundled_only();
        let sig = db
            .lookup_by_name("CreateFileW")
            .expect("CreateFileW in kernel32");
        assert_eq!(sig.params.len(), 7, "CreateFileW must have 7 params");
        assert_eq!(sig.params[0].0, "lpFileName");
        assert_eq!(sig.name, "CreateFileW");
        // HANDLE is seeded as Ptr(Void) in DataTypeManager.
        assert_eq!(sig.ret, DataType::Ptr(Box::new(DataType::Void)));
    }

    #[test]
    fn lookup_strips_imp_prefix() {
        let db = SigDB::load_bundled_only();
        assert!(db.lookup_by_name("__imp_CreateFileW").is_some());
        assert!(db.lookup("kernel32.dll", "CreateFileW").is_some());
    }

    #[test]
    fn dlls_include_kernel32() {
        let db = SigDB::load_bundled_only();
        let dlls = db.dlls();
        assert!(dlls.iter().any(|d| d == "kernel32"));
        assert!(dlls.iter().any(|d| d == "ntdll"));
        assert!(db.len() >= 250, "expected bundled API count >= 250, got {}", db.len());
    }

    #[test]
    fn signatures_for_dll_returns_entries() {
        let db = SigDB::load_bundled_only();
        let k = db.signatures_for_dll("kernel32");
        assert!(k.len() >= 80);
        assert!(k.iter().any(|s| s.name == "CreateFileW"));
    }
}
