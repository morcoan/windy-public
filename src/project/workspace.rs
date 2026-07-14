//! Persistent named groups of project binaries (workspaces).
//!
//! A workspace is a lightweight, agent-facing container for related PE files.
//! Members are stored by SHA256 + original path so a workspace can be reopened
//! across sessions even though each session assigns fresh `ProjectId` UUIDs.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type WorkspaceId = Uuid;

/// A single member of a workspace. Project IDs are ephemeral, so members are
/// keyed by SHA256 with their original path retained for reopening.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceMember {
    pub sha256: String,
    pub path: PathBuf,
}

/// A persisted group of related projects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: Option<String>,
    pub members: Vec<WorkspaceMember>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl Workspace {
    pub fn new(id: WorkspaceId, name: Option<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            name,
            members: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn summary(&self) -> WorkspaceSummary {
        WorkspaceSummary {
            id: self.id,
            name: self.name.clone(),
            member_count: self.members.len(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    pub id: WorkspaceId,
    pub name: Option<String>,
    pub member_count: usize,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

/// Path to a workspace JSON file under a Windy home directory.
pub fn workspace_path(home_dir: impl AsRef<Path>, id: &str) -> PathBuf {
    home_dir
        .as_ref()
        .join("workspaces")
        .join(format!("{id}.json"))
}

/// Durably stores workspace metadata as one JSON file per workspace.
pub struct WorkspaceStore;

impl WorkspaceStore {
    /// Persist a workspace atomically (temp file + fsync + rename).
    pub fn save(home_dir: impl AsRef<Path>, workspace: &Workspace) -> Result<()> {
        let path = workspace_path(&home_dir, &workspace.id.to_string());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("create workspaces directory")?;
        }

        let tmp = path.with_extension("tmp");
        {
            let bytes = serde_json::to_vec_pretty(workspace).context("serialize workspace")?;
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)
                .context("create workspace temp file")?;
            file.write_all(&bytes)
                .and_then(|_| file.flush())
                .and_then(|_| file.sync_all())
                .context("write workspace file")?;
        }
        fs::rename(&tmp, &path).context("replace workspace file")?;
        Ok(())
    }

    /// Load a single workspace by id; on any failure return `None`.
    pub fn load(home_dir: impl AsRef<Path>, id: WorkspaceId) -> Option<Workspace> {
        let path = workspace_path(&home_dir, &id.to_string());
        if !path.exists() {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Load all readable workspaces, dropping corrupt files silently.
    pub fn list_all(home_dir: impl AsRef<Path>) -> Vec<Workspace> {
        let dir = home_dir.as_ref().join("workspaces");
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                && let Ok(id) = Uuid::parse_str(stem)
                && let Some(ws) = Self::load(&home_dir, id)
            {
                out.push(ws);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-ws-rt-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let id = Uuid::new_v4();
        let mut ws = Workspace::new(id, Some("test".to_string()));
        ws.members.push(WorkspaceMember {
            sha256: "abc".to_string(),
            path: PathBuf::from("/foo/bar.exe"),
        });

        WorkspaceStore::save(&tmp, &ws).unwrap();
        let loaded = WorkspaceStore::load(&tmp, id).unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.name, Some("test".to_string()));
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0].sha256, "abc");

        let list = WorkspaceStore::list_all(&tmp);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn corrupt_workspace_dropped() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-ws-bad-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let path = workspace_path(&tmp, &Uuid::new_v4().to_string());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json").unwrap();

        assert!(WorkspaceStore::list_all(&tmp).is_empty());

        fs::remove_dir_all(&tmp).ok();
    }
}
