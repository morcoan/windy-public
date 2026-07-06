#![allow(dead_code)] // Command stack seam; UI commands use this in Phase 3+

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
