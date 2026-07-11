
//! Image-hash-keyed IDB persistence using `postcard`. Stores only metadata
//! (symbols, comments, types, frames) so a reopened PE rebuilds all analysis
//! from bytes and re-applies user edits.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use directories::UserDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::project::memory::FunctionMemoryCard;
use crate::project::symbols::AliasEvent;
use crate::project::{DataType, DataTypeManager, FunctionSignature, Project, StackFrame, SymbolKind};

/// Serializable project metadata.
///
/// Wire note: postcard is positional. v2 IDBs lack `function_memory`; load()
/// falls back to [`ProjectStateV2`] and upgrades.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectState {
    pub image_path: PathBuf,
    pub image_sha256: String,
    pub symbols: Vec<(u64, String, SymbolKind)>,
    pub comments_addr: Vec<(u64, String)>,
    pub comments_func: Vec<(u64, String)>,
    pub types: DataTypeManager,
    pub function_frames: BTreeMap<u64, StackFrame>,
    pub typed_globals: std::collections::HashMap<u64, DataType>,
    pub function_signatures: BTreeMap<u64, FunctionSignature>,
    pub focus: Option<u64>,
    /// Highest operation sequence number captured in this snapshot.
    pub seq: u64,
    pub version: u32,
    /// Agent memory cards (Phase C). Appended after version for cleaner
    /// migration: v2 decode uses [`ProjectStateV2`]; v3 includes this field.
    #[serde(default)]
    pub function_memory: BTreeMap<u64, FunctionMemoryCard>,
    /// Symbol rename lineage (v3+; empty on older loads).
    #[serde(default)]
    pub alias_history: Vec<AliasEvent>,
}

/// Pre-Phase-C IDB layout (version field typically 2).
#[derive(Clone, Debug, Deserialize)]
struct ProjectStateV2 {
    image_path: PathBuf,
    image_sha256: String,
    symbols: Vec<(u64, String, SymbolKind)>,
    comments_addr: Vec<(u64, String)>,
    comments_func: Vec<(u64, String)>,
    types: DataTypeManager,
    function_frames: BTreeMap<u64, StackFrame>,
    typed_globals: std::collections::HashMap<u64, DataType>,
    function_signatures: BTreeMap<u64, FunctionSignature>,
    focus: Option<u64>,
    seq: u64,
    version: u32,
}

impl From<ProjectStateV2> for ProjectState {
    fn from(v2: ProjectStateV2) -> Self {
        Self {
            image_path: v2.image_path,
            image_sha256: v2.image_sha256,
            symbols: v2.symbols,
            comments_addr: v2.comments_addr,
            comments_func: v2.comments_func,
            types: v2.types,
            function_frames: v2.function_frames,
            typed_globals: v2.typed_globals,
            function_signatures: v2.function_signatures,
            focus: v2.focus,
            seq: v2.seq,
            version: v2.version,
            function_memory: BTreeMap::new(),
            alias_history: Vec::new(),
        }
    }
}

impl ProjectState {
    /// v2: symbols/comments/types/frames. v3: + function_memory.
    const CURRENT_VERSION: u32 = 3;

    /// Capture all state that should survive across sessions.
    pub fn from_project(project: &Project) -> Self {
        Self {
            image_path: project.pe.path.clone(),
            image_sha256: project.image_sha256.clone(),
            symbols: project.symbols.entries(),
            comments_addr: project.comments.addr_entries(),
            comments_func: project.comments.function_entries(),
            types: project.types.clone(),
            function_frames: project.function_frames.clone(),
            typed_globals: (*project.typed_globals).clone(),
            function_signatures: (*project.function_signatures).clone(),
            focus: project.focus,
            seq: project.op_seq,
            version: Self::CURRENT_VERSION,
            function_memory: project.function_memory.clone(),
            alias_history: project.alias_history.clone(),
        }
    }

    /// Apply persisted user edits to a freshly analyzed project.
    pub fn apply(&self, project: &mut Project) {
        // Accept v2 (no memory) and v3.
        if self.version != 2 && self.version != Self::CURRENT_VERSION {
            return;
        }
        for (va, name, kind) in &self.symbols {
            project.symbols.insert(*va, name.clone(), *kind);
        }
        for (va, text) in &self.comments_addr {
            project.comments.set(*va, crate::project::comments::CommentScope::Address, text.clone());
        }
        for (va, text) in &self.comments_func {
            project.comments.set(*va, crate::project::comments::CommentScope::Function, text.clone());
        }
        project.types = self.types.clone();
        project.function_frames = self.function_frames.clone();
        project.typed_globals = Arc::new(self.typed_globals.clone());
        project.function_signatures = Arc::new(self.function_signatures.clone());
        project.function_memory = self.function_memory.clone();
        project.alias_history = self.alias_history.clone();
        Arc::make_mut(&mut project.analysis)
            .functions
            .apply_frames(&project.function_frames);
        project.op_seq = self.seq;
        if let Some(focus) = self.focus {
            project.focus = Some(focus);
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).context("serialize project state")
    }

    /// Deserialize from postcard bytes (v3, or v2 upgraded).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Prefer full take so trailing bytes force failure when the layout is wrong.
        match postcard::take_from_bytes::<ProjectState>(bytes) {
            Ok((state, [])) => return Ok(state),
            Ok((state, _)) if state.version >= Self::CURRENT_VERSION => return Ok(state),
            _ => {}
        }
        match postcard::take_from_bytes::<ProjectStateV2>(bytes) {
            Ok((v2, _)) => Ok(ProjectState::from(v2)),
            Err(e) => Err(anyhow::anyhow!("deserialize project state (v2/v3): {e}")),
        }
    }

    /// Persist to the central IDB store.
    pub fn save(&self) -> Result<()> {
        let path = idb_path(&self.image_sha256);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create projects directory")?;
        }
        let bytes = self.to_bytes()?;
        fs::write(&path, bytes).with_context(|| format!("write IDB {}", path.display()))?;
        Ok(())
    }

    /// Load from the central IDB store by SHA256, if present.
    pub fn load(sha256: &str) -> Option<Self> {
        let path = idb_path(sha256);
        if !path.exists() {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        Self::from_bytes(&bytes).ok()
    }
}

pub fn idb_path(sha256: &str) -> PathBuf {
    windy_home_dir().join("projects").join(format!("{sha256}.windy"))
}

pub fn windy_home_dir() -> PathBuf {
    if let Some(user) = UserDirs::new() {
        return user.home_dir().join(".windy");
    }
    PathBuf::from(".windy")
}

/// Compute the SHA256 hash of a file on disk.
pub fn hash_file(path: impl AsRef<Path>) -> Result<String> {
    let bytes = fs::read(path)?;
    Ok(hash_bytes(&bytes))
}

/// Compute the SHA256 hash of an in-memory buffer.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{:x}", digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_state() {
        let state = ProjectState {
            image_path: PathBuf::from("foo.exe"),
            image_sha256: hash_bytes(b"hello"),
            symbols: vec![(0x1234, "main".to_string(), SymbolKind::Function)],
            comments_addr: vec![(0x1234, "entry".to_string())],
            comments_func: vec![],
            types: DataTypeManager::new(),
            function_frames: BTreeMap::new(),
            typed_globals: std::collections::HashMap::new(),
            function_signatures: BTreeMap::new(),
            focus: Some(0x1234),
            seq: 42,
            version: ProjectState::CURRENT_VERSION,
            function_memory: BTreeMap::new(),
            alias_history: Vec::new(),
        };
        let bytes = state.to_bytes().unwrap();
        let loaded = ProjectState::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.symbols.len(), 1);
        assert_eq!(loaded.focus, Some(0x1234));
        assert_eq!(loaded.seq, 42);
    }

    #[test]
    fn function_memory_postcard_round_trip() {
        let mut memory = BTreeMap::new();
        memory.insert(
            0x1000,
            FunctionMemoryCard {
                va: 0x1000,
                purpose: Some("does a thing".into()),
                tags: vec!["io".into()],
                key_apis: vec!["ReadFile".into()],
                key_strings: vec![],
                purity: Some("io".into()),
                confidence: 70,
                updated_seq: 1,
            },
        );
        let state = ProjectState {
            image_path: PathBuf::from("foo.exe"),
            image_sha256: hash_bytes(b"mem"),
            symbols: vec![],
            comments_addr: vec![],
            comments_func: vec![],
            types: DataTypeManager::new(),
            function_frames: BTreeMap::new(),
            typed_globals: std::collections::HashMap::new(),
            function_signatures: BTreeMap::new(),
            focus: None,
            seq: 1,
            version: ProjectState::CURRENT_VERSION,
            function_memory: memory,
            alias_history: Vec::new(),
        };
        let loaded = ProjectState::from_bytes(&state.to_bytes().unwrap()).unwrap();
        assert_eq!(
            loaded.function_memory.get(&0x1000).and_then(|c| c.purpose.clone()),
            Some("does a thing".into())
        );
    }
}
