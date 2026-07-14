//! Multi-project workspace manager for the Windy operator UI and MCP backend.
//!
//! Each loaded project lives behind an `ArcSwap` so the UI gets lock-free
//! reads while a per-project tokio task serializes all writes to a durable
//! append-only operation journal.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::project::Project;
pub use crate::project::activity_log::ActivityEvent;
use crate::project::activity_log::ActivityJournal;
use crate::project::op::Op;
use crate::project::op_log::Journal;
use crate::project::persistence::{hash_file, windy_home_dir};
use crate::project::workspace::{
    Workspace, WorkspaceId, WorkspaceMember, WorkspaceStore, WorkspaceSummary,
};

const ACTIVITY_CAPACITY: usize = 200;

/// Number of journaled ops the writer accumulates before auto-checkpointing
/// (persisting a full `ProjectState` snapshot and truncating the oplog). Bounds
/// oplog growth so a crash never replays an unbounded tail.
const CHECKPOINT_OPS: usize = 256;

pub type ProjectId = Uuid;

/// Shared handle to an open project.
pub struct ProjectHandle {
    pub id: ProjectId,
    pub path: PathBuf,
    read_state: Arc<ArcSwap<Project>>,
    write_tx: mpsc::UnboundedSender<WriteRequest>,
}

impl ProjectHandle {
    /// Lock-free snapshot of the current project state.
    pub fn get(&self) -> Arc<Project> {
        self.read_state.load_full()
    }
}

pub enum WriteRequest {
    Apply {
        client_id: String,
        op: Box<Op>,
        respond: oneshot::Sender<Result<Op, String>>,
    },
    UndoLast {
        client_id: String,
        respond: oneshot::Sender<Result<Op, String>>,
    },
    RedoLast {
        client_id: String,
        respond: oneshot::Sender<Result<Op, String>>,
    },
}

/// Per-client undo/redo stacks of applied operations.
#[derive(Default)]
struct UndoRedoStack {
    undo: Vec<Op>,
    redo: Vec<Op>,
}

/// Manages multiple loaded projects and their durable journals.
pub struct ProjectManager {
    runtime: Runtime,
    projects: Arc<std::sync::Mutex<BTreeMap<ProjectId, Arc<ProjectHandle>>>>,
    workspaces: Arc<std::sync::Mutex<BTreeMap<WorkspaceId, Workspace>>>,
    activity_log: Arc<std::sync::Mutex<VecDeque<ActivityEvent>>>,
    home_dir: PathBuf,
    /// Phase 7 E: cross-binary index keyed by workspace id (rebuilt on open).
    cross_project:
        Arc<std::sync::Mutex<BTreeMap<WorkspaceId, crate::cross_project::CrossProjectIndex>>>,
}

impl ProjectManager {
    #[allow(dead_code)] // compatibility entry point; app/CLI inject the resolved home
    pub fn new() -> Result<Self> {
        Self::with_home_dir(windy_home_dir())
    }

    /// Access the tokio runtime used by this manager.
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Windy home directory (journals, IDBs, claim logs).
    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }

    /// Construct a manager with an explicit Windy home directory.
    /// Useful for tests that must not pollute the user's default Windy data directory.
    pub fn with_home_dir(home_dir: impl Into<PathBuf>) -> Result<Self> {
        let runtime = Runtime::new().context("create tokio runtime")?;
        let home_dir = home_dir.into();
        let workspaces: BTreeMap<WorkspaceId, Workspace> = WorkspaceStore::list_all(&home_dir)
            .into_iter()
            .map(|ws| (ws.id, ws))
            .collect();
        Ok(Self {
            runtime,
            projects: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            workspaces: Arc::new(std::sync::Mutex::new(workspaces)),
            activity_log: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            home_dir,
            cross_project: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        })
    }

    /// Open a PE file, build a project, and start its write task.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<ProjectId> {
        let project = Project::open_with_data_dir(path, &self.home_dir)?;
        let id = ProjectId::new_v4();
        let path = project.pe.path.clone();
        let sha256 = project.image_sha256.clone();
        let read_state = Arc::new(ArcSwap::from(Arc::new(project)));
        let journal = Journal::open_in(&self.home_dir, &sha256);
        let activity_journal = ActivityJournal::open(&self.home_dir, &sha256);
        let (write_tx, write_rx) = mpsc::unbounded_channel();

        // Replay prior activity for this binary into the global feed so a
        // reopened project shows its history immediately.
        let backfill = activity_journal.read_tail(ACTIVITY_CAPACITY);
        if !backfill.is_empty() {
            let mut log = self.activity_log.lock().unwrap();
            merge_events(&mut log, backfill);
        }

        let activity_log = self.activity_log.clone();
        self.runtime.spawn(writer_loop(
            id,
            read_state.clone(),
            journal,
            activity_journal,
            write_rx,
            activity_log,
        ));

        let handle = Arc::new(ProjectHandle {
            id,
            path,
            read_state,
            write_tx,
        });
        self.projects.lock().unwrap().insert(id, handle);
        Ok(id)
    }

    /// Return recent activity, optionally filtered to a single project. The
    /// events are returned oldest first, up to `limit`.
    pub fn recent_activity_filtered(
        &self,
        limit: usize,
        project_id: Option<ProjectId>,
    ) -> Vec<ActivityEvent> {
        let log = self.activity_log.lock().unwrap();
        let filtered: Vec<_> = log
            .iter()
            .filter(|e| project_id.is_none_or(|id| e.project_id == id))
            .cloned()
            .collect();
        let start = filtered.len().saturating_sub(limit);
        filtered.into_iter().skip(start).take(limit).collect()
    }

    /// Get the latest snapshot of a project, if it is still open.
    pub fn get(&self, id: ProjectId) -> Option<Arc<Project>> {
        self.projects.lock().unwrap().get(&id).map(|h| h.get())
    }

    /// Start the MCP HTTP server bound to `addr`. Returns the actual port.
    pub fn start_http_server(
        self: &Arc<Self>,
        addr: SocketAddr,
    ) -> Result<crate::mcp::McpServerHandle> {
        let manager = self.clone();
        self.runtime
            .block_on(crate::mcp::serve_http(manager, addr))
            .context("start MCP HTTP server")
    }

    /// List currently open projects with lightweight metadata.
    pub fn list(&self) -> Vec<(ProjectId, PathBuf, usize, usize)> {
        self.projects
            .lock()
            .unwrap()
            .values()
            .map(|h| {
                let p = h.get();
                (
                    h.id,
                    h.path.clone(),
                    p.functions().len(),
                    p.analysis.code_index.len(),
                )
            })
            .collect()
    }

    /// Create a new empty workspace and persist it.
    pub fn create_workspace(&self, name: Option<String>) -> Result<WorkspaceId> {
        let id = WorkspaceId::new_v4();
        let ws = Workspace::new(id, name);
        WorkspaceStore::save(&self.home_dir, &ws)?;
        self.workspaces.lock().unwrap().insert(id, ws);
        Ok(id)
    }

    /// Open PE files and add them to a workspace. Returns per-file results.
    /// The workspace must already exist.
    pub fn add_files_to_workspace<P: AsRef<Path>>(
        &self,
        workspace_id: WorkspaceId,
        paths: Vec<P>,
    ) -> Result<Vec<(PathBuf, Result<ProjectId>)>> {
        let mut results = Vec::new();
        let mut new_members = Vec::new();

        for path in paths {
            let path = path.as_ref();
            match self.open(path) {
                Ok(project_id) => {
                    if let Some(project) = self.get(project_id) {
                        new_members.push(WorkspaceMember {
                            sha256: project.image_sha256.clone(),
                            path: project.pe.path.clone(),
                        });
                    }
                    results.push((path.to_path_buf(), Ok(project_id)));
                }
                Err(e) => results.push((path.to_path_buf(), Err(e))),
            }
        }

        if !new_members.is_empty() {
            let mut workspaces = self.workspaces.lock().unwrap();
            if let Some(ws) = workspaces.get_mut(&workspace_id) {
                ws.members.extend(new_members);
                ws.updated_at = SystemTime::now();
                WorkspaceStore::save(&self.home_dir, ws).ok();
            }
        }
        self.rebuild_cross_project_index(workspace_id);

        Ok(results)
    }

    /// Add an already-open project to a workspace.
    pub fn add_project_to_workspace(
        &self,
        workspace_id: WorkspaceId,
        project_id: ProjectId,
    ) -> Result<()> {
        let project = self.get(project_id).context("project not found")?;
        let member = WorkspaceMember {
            sha256: project.image_sha256.clone(),
            path: project.pe.path.clone(),
        };
        let mut workspaces = self.workspaces.lock().unwrap();
        let ws = workspaces
            .get_mut(&workspace_id)
            .context("workspace not found")?;
        ws.members.push(member);
        ws.updated_at = SystemTime::now();
        WorkspaceStore::save(&self.home_dir, ws)?;
        drop(workspaces);
        self.rebuild_cross_project_index(workspace_id);
        Ok(())
    }

    /// Reopen all members of a workspace. Returns per-member results with fresh
    /// project IDs. Members whose SHA256 no longer match their stored path are
    /// reported as errors and left in the workspace metadata for review.
    pub fn open_workspace(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<(PathBuf, Result<ProjectId>)>> {
        let ws = self
            .get_workspace(workspace_id)
            .context("workspace not found")?;
        let mut results = Vec::new();

        for member in &ws.members {
            let path = &member.path;
            let result = match hash_file(path) {
                Ok(current) if current == member.sha256 => self.open(path),
                Ok(_) => Err(anyhow::anyhow!(
                    "file SHA256 changed since workspace was saved"
                )),
                Err(e) => Err(e),
            };
            results.push((path.clone(), result));
        }

        self.rebuild_cross_project_index(workspace_id);
        Ok(results)
    }

    /// Rebuild the Phase 7 E cross-project index for a workspace from currently
    /// open project members that belong to it (matched by path).
    pub fn rebuild_cross_project_index(&self, workspace_id: WorkspaceId) {
        let Some(ws) = self.get_workspace(workspace_id) else {
            return;
        };
        let member_paths: HashSet<_> = ws.members.iter().map(|m| m.path.clone()).collect();
        let projects = self.projects.lock().unwrap();
        let mut pairs: Vec<(ProjectId, Arc<Project>)> = Vec::new();
        for h in projects.values() {
            if member_paths.contains(&h.path) {
                pairs.push((h.id, h.get()));
            }
        }
        drop(projects);
        // Also include all currently open projects if workspace members aren't
        // all open yet — match by path only.
        let index = crate::cross_project::CrossProjectIndex::build(&pairs);
        self.cross_project
            .lock()
            .unwrap()
            .insert(workspace_id, index);
    }

    /// Open projects that belong to this workspace (matched by path).
    pub fn workspace_projects(
        &self,
        workspace_id: WorkspaceId,
    ) -> Option<Vec<(ProjectId, Arc<Project>)>> {
        let ws = self.get_workspace(workspace_id)?;
        let member_paths: HashSet<_> = ws.members.iter().map(|m| m.path.clone()).collect();
        let projects = self.projects.lock().unwrap();
        let mut pairs: Vec<(ProjectId, Arc<Project>)> = Vec::new();
        for h in projects.values() {
            if member_paths.contains(&h.path) {
                pairs.push((h.id, h.get()));
            }
        }
        if pairs.is_empty() { None } else { Some(pairs) }
    }

    /// Cross-project call graph for a workspace (Phase 7 E).
    pub fn cross_project_index(
        &self,
        workspace_id: WorkspaceId,
    ) -> Option<crate::cross_project::CrossProjectIndex> {
        // Rebuild if missing (lazy).
        if !self
            .cross_project
            .lock()
            .unwrap()
            .contains_key(&workspace_id)
        {
            self.rebuild_cross_project_index(workspace_id);
        }
        self.cross_project
            .lock()
            .unwrap()
            .get(&workspace_id)
            .cloned()
    }

    /// Remove a member path from a workspace.
    pub fn remove_from_workspace(
        &self,
        workspace_id: WorkspaceId,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let path = path.as_ref();
        let mut workspaces = self.workspaces.lock().unwrap();
        let ws = workspaces
            .get_mut(&workspace_id)
            .context("workspace not found")?;
        ws.members.retain(|m| m.path != path);
        ws.updated_at = SystemTime::now();
        WorkspaceStore::save(&self.home_dir, ws)?;
        Ok(())
    }

    /// List all persisted workspaces.
    pub fn list_workspaces(&self) -> Vec<WorkspaceSummary> {
        self.workspaces
            .lock()
            .unwrap()
            .values()
            .map(Workspace::summary)
            .collect()
    }

    /// Look up a workspace by id, returning a full clone.
    pub fn get_workspace(&self, id: WorkspaceId) -> Option<Workspace> {
        self.workspaces.lock().unwrap().get(&id).cloned()
    }

    /// Apply an operation asynchronously (for use inside the MCP runtime).
    pub async fn apply_op(
        &self,
        id: ProjectId,
        client_id: impl Into<String>,
        op: Op,
    ) -> Result<Op> {
        let handle = self
            .projects
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .context("project not found")?;
        let (tx, rx) = oneshot::channel();
        handle
            .write_tx
            .send(WriteRequest::Apply {
                client_id: client_id.into(),
                op: Box::new(op),
                respond: tx,
            })
            .map_err(|_| anyhow::anyhow!("writer task closed"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("writer response cancelled"))?
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Undo the last operation submitted by `client_id` (asynchronous).
    pub async fn undo_last(&self, id: ProjectId, client_id: impl Into<String>) -> Result<Op> {
        let handle = self
            .projects
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .context("project not found")?;
        let (tx, rx) = oneshot::channel();
        handle
            .write_tx
            .send(WriteRequest::UndoLast {
                client_id: client_id.into(),
                respond: tx,
            })
            .map_err(|_| anyhow::anyhow!("writer task closed"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("writer response cancelled"))?
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Redo the last undone operation for `client_id` (asynchronous).
    pub async fn redo_last(&self, id: ProjectId, client_id: impl Into<String>) -> Result<Op> {
        let handle = self
            .projects
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .context("project not found")?;
        let (tx, rx) = oneshot::channel();
        handle
            .write_tx
            .send(WriteRequest::RedoLast {
                client_id: client_id.into(),
                respond: tx,
            })
            .map_err(|_| anyhow::anyhow!("writer task closed"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("writer response cancelled"))?
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Apply an operation synchronously (UI thread, not inside the runtime).
    pub fn apply_op_sync(&self, id: ProjectId, client_id: impl Into<String>, op: Op) -> Result<Op> {
        self.runtime.block_on(self.apply_op(id, client_id, op))
    }

    /// Undo the last operation from `client_id` synchronously (UI thread).
    pub fn undo_last_sync(&self, id: ProjectId, client_id: impl Into<String>) -> Result<Op> {
        self.runtime.block_on(self.undo_last(id, client_id))
    }

    /// Redo the last undone operation from `client_id` synchronously (UI thread).
    #[allow(dead_code)] // UI redo binding (Ctrl+Y); wired when UI gains redo
    pub fn redo_last_sync(&self, id: ProjectId, client_id: impl Into<String>) -> Result<Op> {
        self.runtime.block_on(self.redo_last(id, client_id))
    }
}

async fn writer_loop(
    id: ProjectId,
    read_state: Arc<ArcSwap<Project>>,
    journal: Journal,
    activity_journal: ActivityJournal,
    mut rx: mpsc::UnboundedReceiver<WriteRequest>,
    activity_log: Arc<std::sync::Mutex<VecDeque<ActivityEvent>>>,
) {
    let mut project = read_state.load_full().as_ref().clone();
    let mut history: HashMap<String, UndoRedoStack> = HashMap::new();
    let mut ops_since_save: usize = 0;

    while let Some(req) = rx.recv().await {
        match req {
            WriteRequest::Apply {
                client_id,
                op,
                respond,
            } => {
                let result = apply_one(&mut project, &journal, &client_id, *op, &mut history);
                read_state.store(Arc::new(project.clone()));
                if let Ok(ref applied) = result {
                    record_activity(
                        &activity_log,
                        &activity_journal,
                        id,
                        project.op_seq,
                        &client_id,
                        applied,
                    );
                }
                let _ = respond.send(result.map_err(|e| e.to_string()));
                // Auto-checkpoint: persist a full snapshot every CHECKPOINT_OPS
                // operations so the oplog tail is bounded.
                ops_since_save = ops_since_save.saturating_add(1);
                if ops_since_save >= CHECKPOINT_OPS {
                    if let Err(e) = project.save() {
                        tracing::warn!("auto-checkpoint save failed: {e}");
                    }
                    ops_since_save = 0;
                }
            }
            WriteRequest::UndoLast { client_id, respond } => {
                let result = undo_one(&mut project, &journal, &client_id, &mut history);
                read_state.store(Arc::new(project.clone()));
                if let Ok(ref applied) = result {
                    record_activity(
                        &activity_log,
                        &activity_journal,
                        id,
                        project.op_seq,
                        &client_id,
                        applied,
                    );
                }
                let _ = respond.send(result.map_err(|e| e.to_string()));
                ops_since_save = ops_since_save.saturating_add(1);
                if ops_since_save >= CHECKPOINT_OPS {
                    if let Err(e) = project.save() {
                        tracing::warn!("auto-checkpoint save failed: {e}");
                    }
                    ops_since_save = 0;
                }
            }
            WriteRequest::RedoLast { client_id, respond } => {
                let result = redo_one(&mut project, &journal, &client_id, &mut history);
                read_state.store(Arc::new(project.clone()));
                if let Ok(ref applied) = result {
                    record_activity(
                        &activity_log,
                        &activity_journal,
                        id,
                        project.op_seq,
                        &client_id,
                        applied,
                    );
                }
                let _ = respond.send(result.map_err(|e| e.to_string()));
                ops_since_save = ops_since_save.saturating_add(1);
                if ops_since_save >= CHECKPOINT_OPS {
                    if let Err(e) = project.save() {
                        tracing::warn!("auto-checkpoint save failed: {e}");
                    }
                    ops_since_save = 0;
                }
            }
        }
    }
}

fn record_activity(
    log: &std::sync::Mutex<VecDeque<ActivityEvent>>,
    journal: &ActivityJournal,
    project_id: ProjectId,
    seq: u64,
    client_id: &str,
    op: &Op,
) {
    let event = ActivityEvent {
        timestamp: SystemTime::now(),
        project_id,
        client_id: client_id.to_string(),
        op_summary: op.summary(),
        seq,
    };

    // Persist before inserting into the in-memory ring so a crash only loses
    // the live view, never the durable record.
    let _ = journal.append(&event);

    let mut log = log.lock().unwrap();
    if log.len() >= ACTIVITY_CAPACITY {
        log.pop_front();
    }
    log.push_back(event);
}

/// Merge additional events into the activity ring, keeping chronological order
/// and the capacity bound.
fn merge_events(log: &mut VecDeque<ActivityEvent>, mut extra: Vec<ActivityEvent>) {
    if extra.is_empty() {
        return;
    }
    extra.extend(log.iter().cloned());
    extra.sort_by_key(|e| e.timestamp);
    let start = extra.len().saturating_sub(ACTIVITY_CAPACITY);
    *log = extra.into_iter().skip(start).collect();
}

fn apply_one(
    project: &mut Project,
    journal: &Journal,
    client_id: &str,
    op: Op,
    history: &mut HashMap<String, UndoRedoStack>,
) -> Result<Op> {
    project.op_seq += 1;
    let applied = op.apply_to(project);
    journal.append(project.op_seq, &applied)?;
    let stack = history.entry(client_id.to_string()).or_default();
    stack.undo.push(applied.clone());
    stack.redo.clear();
    Ok(applied)
}

fn undo_one(
    project: &mut Project,
    journal: &Journal,
    client_id: &str,
    history: &mut HashMap<String, UndoRedoStack>,
) -> Result<Op> {
    let stack = history
        .get_mut(client_id)
        .context("no operations to undo")?;
    let last = stack.undo.pop().context("no operations to undo")?;
    let inv = last.inverse().context("operation is not invertible")?;
    project.op_seq += 1;
    let applied = inv.apply_to(project);
    journal.append(project.op_seq, &applied)?;
    // Keep the original applied op so redo can re-apply it.
    stack.redo.push(last);
    Ok(applied)
}

fn redo_one(
    project: &mut Project,
    journal: &Journal,
    client_id: &str,
    history: &mut HashMap<String, UndoRedoStack>,
) -> Result<Op> {
    let stack = history
        .get_mut(client_id)
        .context("no operations to redo")?;
    let op = stack.redo.pop().context("no operations to redo")?;
    project.op_seq += 1;
    // Re-apply the original (old_* already captured); apply_to preserves them.
    let applied = op.apply_to(project);
    journal.append(project.op_seq, &applied)?;
    stack.undo.push(applied.clone());
    Ok(applied)
}

/// Helper used by tests: verify the in-memory state of all open projects.
#[cfg(test)]
#[allow(dead_code)]
pub fn project_ids(manager: &ProjectManager) -> HashSet<ProjectId> {
    manager.projects.lock().unwrap().keys().copied().collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::project::comments::CommentScope;

    fn notepad_path() -> Option<PathBuf> {
        let p = PathBuf::from(r"C:\Windows\System32\notepad.exe");
        p.exists().then_some(p)
    }

    #[test]
    fn manager_creation_ok() {
        let _ = ProjectManager::new().unwrap();
    }

    #[test]
    fn apply_undo_redo_restores_state() {
        let exe = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !Path::new(exe).exists() {
            eprintln!("skipping redo_last: sample.exe not found");
            return;
        }
        let tmp = std::env::temp_dir().join(format!(
            "windy-redo-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let manager = ProjectManager::with_home_dir(&tmp).unwrap();
        let id = manager.open(exe).unwrap();
        // Unique VA + text so global IDB residue from prior runs cannot collide.
        let va = 0x14000_f00du64;
        let marker = format!("redo-test-{}", Uuid::new_v4());

        manager
            .apply_op_sync(
                id,
                "t",
                Op::SetComment {
                    va,
                    scope: CommentScope::Address,
                    text: marker.clone(),
                    old_text: None,
                },
            )
            .unwrap();
        let after_apply = manager
            .get(id)
            .unwrap()
            .comments
            .get(va, CommentScope::Address)
            .map(str::to_string);
        assert_eq!(after_apply.as_deref(), Some(marker.as_str()));

        manager.undo_last_sync(id, "t").unwrap();
        let after_undo = manager
            .get(id)
            .unwrap()
            .comments
            .get(va, CommentScope::Address)
            .map(str::to_string);
        assert_ne!(
            after_undo.as_deref(),
            Some(marker.as_str()),
            "undo should remove the applied marker comment"
        );

        manager.redo_last_sync(id, "t").unwrap();
        let after_redo = manager
            .get(id)
            .unwrap()
            .comments
            .get(va, CommentScope::Address)
            .map(str::to_string);
        assert_eq!(
            after_redo.as_deref(),
            Some(marker.as_str()),
            "redo should restore post-apply state"
        );

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn auto_checkpoint_bounds_oplog() {
        let exe = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !Path::new(exe).exists() {
            eprintln!("skipping auto-checkpoint: sample.exe not found");
            return;
        }
        let tmp = std::env::temp_dir().join(format!(
            "windy-autockpt-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        {
            let manager = ProjectManager::with_home_dir(&tmp).unwrap();
            let id = manager.open(exe).unwrap();
            let project = manager.get(id).unwrap();
            let sha256 = project.image_sha256.clone();

            // Apply well past the checkpoint threshold of 256 ops.
            for i in 0..(CHECKPOINT_OPS + 50) {
                manager
                    .apply_op_sync(
                        id,
                        "t",
                        Op::SetComment {
                            va: 0x1000u64 + i as u64,
                            scope: CommentScope::Address,
                            text: format!("n{i}"),
                            old_text: None,
                        },
                    )
                    .unwrap();
            }

            // After auto-checkpointing the durable oplog must be bounded: it should
            // hold far fewer records than the 306 we applied (the snapshot captured
            // the majority and truncated the tail).
            let journal = Journal::open(&sha256);
            let n = journal.read_all().len();
            assert!(
                n < CHECKPOINT_OPS,
                "oplog should be bounded by auto-checkpoint, got {n} records"
            );
            assert!(
                n <= 50,
                "only the un-checkpointed tail should remain, got {n}"
            );
        }

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn workspace_create_add_list_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-ws-mgr-rt-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let path = match notepad_path() {
            Some(p) => p,
            None => {
                eprintln!("skipping workspace round-trip: notepad.exe not found");
                return;
            }
        };

        let manager = ProjectManager::with_home_dir(&tmp).unwrap();
        let ws_id = manager.create_workspace(Some("test".to_string())).unwrap();

        let results = manager.add_files_to_workspace(ws_id, vec![&path]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok(), "{:?}", results[0].1);

        let summaries = manager.list_workspaces();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, ws_id);
        assert_eq!(summaries[0].member_count, 1);

        let ws = manager.get_workspace(ws_id).unwrap();
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].path, path);

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn workspace_persistence_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-ws-mgr-persist-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let path = match notepad_path() {
            Some(p) => p,
            None => {
                eprintln!("skipping workspace persistence: notepad.exe not found");
                return;
            }
        };

        let ws_id = {
            let manager = ProjectManager::with_home_dir(&tmp).unwrap();
            let ws_id = manager
                .create_workspace(Some("persist".to_string()))
                .unwrap();
            let results = manager.add_files_to_workspace(ws_id, vec![&path]).unwrap();
            assert!(results[0].1.is_ok());
            ws_id
        };

        {
            let manager = ProjectManager::with_home_dir(&tmp).unwrap();
            let summaries = manager.list_workspaces();
            assert_eq!(summaries.len(), 1);
            assert_eq!(summaries[0].id, ws_id);
            assert_eq!(summaries[0].member_count, 1);

            let ws = manager.get_workspace(ws_id).unwrap();
            assert_eq!(ws.members.len(), 1);
        }

        fs::remove_dir_all(&tmp).ok();
    }
}
