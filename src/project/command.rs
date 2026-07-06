#![allow(dead_code)] // Command stack seam; UI commands use this in Phase 3+

use crate::project::comments::CommentScope;
use crate::project::symbols::SymbolKind;
use crate::project::Project;

/// A reversible project mutation.
///
/// The command pattern is required because analysis results from LLMs will often
/// be wrong; the user must be able to undo batches of renames, type changes,
/// and comments.
pub trait Command {
    fn apply(&mut self, project: &mut Project);
    fn undo(&mut self, project: &mut Project);
}

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

pub struct SetName {
    addr: u64,
    new_name: String,
    kind: SymbolKind,
    old: Option<(String, SymbolKind)>,
}

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
        self.old = project.symbols.get(self.addr).map(|s| (s.name.clone(), s.kind));
        project
            .symbols
            .insert(self.addr, self.new_name.clone(), self.kind);
    }

    fn undo(&mut self, project: &mut Project) {
        if let Some((name, kind)) = self.old.take() {
            project.symbols.insert(self.addr, name, kind);
        } else {
            project.symbols.remove(self.addr);
        }
    }
}

pub struct SetComment {
    addr: u64,
    scope: CommentScope,
    new_text: String,
    old_text: Option<String>,
}

impl SetComment {
    pub fn new(addr: u64, text: impl Into<String>, scope: CommentScope) -> Self {
        Self {
            addr,
            scope,
            new_text: text.into(),
            old_text: None,
        }
    }
}

impl Command for SetComment {
    fn apply(&mut self, project: &mut Project) {
        self.old_text = project
            .comments
            .get(self.addr, self.scope)
            .map(String::from);
        project
            .comments
            .set(self.addr, self.scope, self.new_text.clone());
    }

    fn undo(&mut self, project: &mut Project) {
        match self.old_text.take() {
            Some(text) => project.comments.set(self.addr, self.scope, text),
            None => project.comments.remove(self.addr, self.scope),
        }
    }
}

/// Many renames/comments produced by an LLM applied as one undoable unit.
pub struct BatchRename {
    pub commands: Vec<Box<dyn Command>>,
}

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
