//! UI command-pattern layer for reversible project mutations.
//!
//! This module is the document/UI seam for imperative commands (`SetName`,
//! `SetComment`, `BatchRename`, `CommandStack`). The durable agent/MCP path
//! uses [`crate::project::op::Op`] instead; keep this layer for in-process UI
//! undo stacks that hold trait objects rather than serializable ops.

use crate::project::Project;
use crate::project::comments::CommentScope;
use crate::project::symbols::SymbolKind;

/// A reversible project mutation.
///
/// The command pattern is required because analysis results from LLMs will often
/// be wrong; the user must be able to undo batches of renames, type changes,
/// and comments.
#[allow(dead_code)] // UI command-pattern seam (Op path used by MCP/manager)
pub trait Command {
    fn apply(&mut self, project: &mut Project);
    fn undo(&mut self, project: &mut Project);
}

#[allow(dead_code)] // UI command-pattern seam
pub struct CommandStack {
    undo: Vec<Box<dyn Command>>,
    redo: Vec<Box<dyn Command>>,
}

// `Box<dyn Command>` does not implement Default, so the manual impl is required.
#[allow(clippy::derivable_impls)]
impl Default for CommandStack {
    fn default() -> Self {
        Self {
            undo: Vec::new(),
            redo: Vec::new(),
        }
    }
}

#[allow(dead_code)] // UI command-pattern seam
impl CommandStack {
    pub fn execute(&mut self, project: &mut Project, mut cmd: Box<dyn Command>) {
        cmd.apply(project);
        self.undo.push(cmd);
        self.redo.clear();
    }

    pub fn undo(&mut self, project: &mut Project) {
        if let Some(mut cmd) = self.undo.pop() {
            cmd.undo(project);
            self.redo.push(cmd);
        }
    }

    pub fn redo(&mut self, project: &mut Project) {
        if let Some(mut cmd) = self.redo.pop() {
            cmd.apply(project);
            self.undo.push(cmd);
        }
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }
}

#[allow(dead_code)] // UI command-pattern seam
pub struct SetName {
    addr: u64,
    new_name: String,
    kind: SymbolKind,
    old: Option<(String, SymbolKind)>,
}

#[allow(dead_code)] // UI command-pattern seam
impl SetName {
    pub fn new(addr: u64, name: impl Into<String>, kind: SymbolKind) -> Self {
        Self {
            addr,
            new_name: name.into(),
            kind,
            old: None,
        }
    }
}

impl Command for SetName {
    fn apply(&mut self, project: &mut Project) {
        self.old = project
            .symbols
            .get(self.addr)
            .map(|s| (s.name.clone(), s.kind));
        project
            .symbols
            .insert(self.addr, self.new_name.clone(), self.kind);
    }

    fn undo(&mut self, project: &mut Project) {
        match &self.old {
            Some((name, kind)) => {
                project.symbols.insert(self.addr, name.clone(), *kind);
            }
            None => {
                project.symbols.remove(self.addr);
            }
        }
    }
}

#[allow(dead_code)] // UI command-pattern seam
pub struct SetComment {
    addr: u64,
    text: String,
    scope: CommentScope,
    old: Option<String>,
}

#[allow(dead_code)] // UI command-pattern seam
impl SetComment {
    pub fn new(addr: u64, text: impl Into<String>, scope: CommentScope) -> Self {
        Self {
            addr,
            text: text.into(),
            scope,
            old: None,
        }
    }
}

impl Command for SetComment {
    fn apply(&mut self, project: &mut Project) {
        self.old = project
            .comments
            .get(self.addr, self.scope)
            .map(String::from);
        project
            .comments
            .set(self.addr, self.scope, self.text.clone());
    }

    fn undo(&mut self, project: &mut Project) {
        match &self.old {
            Some(t) => project.comments.set(self.addr, self.scope, t.clone()),
            None => project.comments.remove(self.addr, self.scope),
        }
    }
}

#[allow(dead_code)] // UI command-pattern seam
pub struct BatchRename {
    commands: Vec<Box<dyn Command>>,
}

#[allow(dead_code)] // UI command-pattern seam
impl BatchRename {
    pub fn new(commands: Vec<Box<dyn Command>>) -> Self {
        Self { commands }
    }
}

impl Command for BatchRename {
    fn apply(&mut self, project: &mut Project) {
        for cmd in &mut self.commands {
            cmd.apply(project);
        }
    }

    fn undo(&mut self, project: &mut Project) {
        for cmd in self.commands.iter_mut().rev() {
            cmd.undo(project);
        }
    }
}
