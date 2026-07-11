//! Serializable, undo-friendly project operations.
//!
//! Every agent-visible mutation is represented as an `Op`.  When an op is
//! applied the previous value is captured inside the op, producing a durable
//! record that can both be replayed after a crash and inverted for undo.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::project::comments::CommentScope;
use crate::project::symbols::SymbolKind;
use crate::project::memory::FunctionMemoryCard;
use crate::project::types::{DataType, FunctionSignature, StackFrame, StackVariable};
use crate::project::Project;

/// A single reversible project mutation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    RenameSymbol {
        va: u64,
        name: String,
        kind: SymbolKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_kind: Option<SymbolKind>,
    },
    SetComment {
        va: u64,
        scope: CommentScope,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_text: Option<String>,
    },
    SetFocus {
        va: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_focus: Option<u64>,
    },
    /// Retype a PDB global variable (keyed by VA). Captures the previous type
    /// so the durable journal can invert or replay the edit.
    SetGlobalType {
        va: u64,
        ty: DataType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_ty: Option<DataType>,
    },
    /// Override the recovered signature of a function (keyed by entry VA).
    SetFunctionSignature {
        va: u64,
        signature: FunctionSignature,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_signature: Option<FunctionSignature>,
    },
    /// Retype a recovered stack local by its frame-pointer offset within
    /// `function_va`'s [`StackFrame`]. The offset is the canonical signed
    /// displacement (negative for locals, positive for incoming stack args).
    /// Creates the slot if it does not yet exist.
    SetStackLocalType {
        function_va: u64,
        offset: i64,
        ty: DataType,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_ty: Option<DataType>,
    },
    /// Rename a recovered stack local/arg by frame-pointer offset. Creates the
    /// slot if missing so agents can name observed offsets before type recovery.
    SetStackLocalName {
        function_va: u64,
        offset: i64,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_name: Option<Option<String>>,
    },
    /// Rename a function parameter by index in the durable signature map.
    /// Extends the param list with Unknown placeholders if needed.
    SetParamName {
        function_va: u64,
        index: usize,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_name: Option<String>,
    },
    /// Set or replace the agent memory card for a function (Phase C).
    SetFunctionMemory {
        va: u64,
        card: FunctionMemoryCard,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<Option<FunctionMemoryCard>>,
    },
    Batch {
        ops: Vec<Op>,
    },
}

impl Op {
    /// Apply the operation, filling in any captured old values that are still
    /// `None`.  Returns the operation with old values populated.
    pub fn apply_to(self, project: &mut Project) -> Self {
        let mut op = self;
        op.capture_and_apply(project);
        op
    }

    fn capture_and_apply(&mut self, project: &mut Project) {
        match self {
            Op::RenameSymbol {
                va,
                name,
                kind,
                old_name,
                old_kind,
            } => {
                if old_name.is_none() {
                    *old_name = project.symbols.name(*va).map(String::from);
                    *old_kind = project.symbols.get(*va).map(|s| s.kind);
                }
                if let Some(prev) = old_name.as_ref() {
                    project.alias_history.push(crate::project::symbols::AliasEvent {
                        va: *va,
                        old_name: prev.clone(),
                        new_name: name.clone(),
                        source: "user".into(),
                        seq: project.op_seq.saturating_add(1),
                    });
                }
                project.symbols.insert(*va, name.clone(), *kind);
            }
            Op::SetComment {
                va,
                scope,
                text,
                old_text,
            } => {
                if old_text.is_none() {
                    *old_text = project.comments.get(*va, *scope).map(String::from);
                }
                project.comments.set(*va, *scope, text.clone());
            }
            Op::SetFocus { va, old_focus } => {
                if old_focus.is_none() {
                    *old_focus = project.focus;
                }
                if project.function_at(*va).is_some() {
                    project.focus = Some(*va);
                }
            }
            Op::SetGlobalType { va, ty, old_ty } => {
                if old_ty.is_none() {
                    *old_ty = project.typed_globals.get(va).cloned();
                }
                Arc::make_mut(&mut project.typed_globals).insert(*va, ty.clone());
            }
            Op::SetFunctionSignature {
                va,
                signature,
                old_signature,
            } => {
                if old_signature.is_none() {
                    *old_signature = project.function_signatures.get(va).cloned();
                }
                Arc::make_mut(&mut project.function_signatures).insert(*va, signature.clone());
                project.invalidate_ssa_cache(Some(*va));
            }
            Op::SetStackLocalType {
                function_va,
                offset,
                ty,
                old_ty,
            } => {
                let frame = project
                    .function_frames
                    .entry(*function_va)
                    .or_default();
                if old_ty.is_none() {
                    *old_ty = frame
                        .locals
                        .iter()
                        .chain(&frame.args)
                        .find(|v| v.offset == *offset)
                        .map(|v| v.ty.clone());
                }
                upsert_stack_var(frame, *offset, |v| {
                    v.ty = ty.clone();
                });
                project.invalidate_ssa_cache(Some(*function_va));
            }
            Op::SetStackLocalName {
                function_va,
                offset,
                name,
                old_name,
            } => {
                let frame = project
                    .function_frames
                    .entry(*function_va)
                    .or_default();
                if old_name.is_none() {
                    *old_name = Some(
                        frame
                            .locals
                            .iter()
                            .chain(&frame.args)
                            .find(|v| v.offset == *offset)
                            .and_then(|v| v.name.clone()),
                    );
                }
                upsert_stack_var(frame, *offset, |v| {
                    // Empty name clears the name (used by undo of create-and-name).
                    v.name = if name.is_empty() {
                        None
                    } else {
                        Some(name.clone())
                    };
                });
                // Names only annotate; SSA shape unchanged — still drop cache so
                // type recovery that re-reads frames stays coherent.
                project.invalidate_ssa_cache(Some(*function_va));
            }
            Op::SetParamName {
                function_va,
                index,
                name,
                old_name,
            } => {
                let sigs = Arc::make_mut(&mut project.function_signatures);
                let sig = sigs.entry(*function_va).or_insert_with(|| FunctionSignature {
                    name: project
                        .symbols
                        .name(*function_va)
                        .unwrap_or("sub")
                        .to_string(),
                    params: Vec::new(),
                    ret: DataType::Unknown(0),
                    calling_conv: None,
                });
                while sig.params.len() <= *index {
                    let i = sig.params.len();
                    sig.params
                        .push((format!("arg{i}"), DataType::Unknown(0)));
                }
                if old_name.is_none() {
                    *old_name = Some(sig.params[*index].0.clone());
                }
                sig.params[*index].0 = name.clone();
            }
            Op::SetFunctionMemory { va, card, old } => {
                if old.is_none() {
                    *old = Some(project.function_memory.get(va).cloned());
                }
                // Clear sentinel used by inverse when previous state was absent.
                if card.tags.as_slice() == ["__clear__"] && card.purpose.is_none() {
                    project.function_memory.remove(va);
                } else {
                    let mut card = card.clone();
                    card.va = *va;
                    card.updated_seq = project.op_seq.saturating_add(1);
                    project.function_memory.insert(*va, card);
                }
            }
            Op::Batch { ops } => {
                for child in ops.iter_mut() {
                    child.capture_and_apply(project);
                }
            }
        }
    }

    /// Produce the compensating operation that undoes this one.  Returns
    /// `None` if the op did not capture old state (it was never applied).
    pub fn inverse(&self) -> Option<Op> {
        match self {
            Op::RenameSymbol {
                va,
                name,
                kind,
                old_name,
                old_kind,
            } => {
                let new_name = old_name.clone().unwrap_or_default();
                let new_kind = old_kind.unwrap_or(*kind);
                Some(Op::RenameSymbol {
                    va: *va,
                    name: new_name,
                    kind: new_kind,
                    old_name: Some(name.clone()),
                    old_kind: Some(*kind),
                })
            }
            Op::SetComment {
                va,
                scope,
                text,
                old_text,
            } => {
                let new_text = old_text.clone().unwrap_or_default();
                Some(Op::SetComment {
                    va: *va,
                    scope: *scope,
                    text: new_text,
                    old_text: Some(text.clone()),
                })
            }
            Op::SetFocus { va, old_focus } => Some(Op::SetFocus {
                va: old_focus.unwrap_or(*va),
                old_focus: Some(*va),
            }),
            Op::SetGlobalType { va, ty, old_ty } => {
                let new_ty = old_ty.clone().unwrap_or(DataType::Unknown(0));
                Some(Op::SetGlobalType {
                    va: *va,
                    ty: new_ty,
                    old_ty: Some(ty.clone()),
                })
            }
            Op::SetFunctionSignature {
                va,
                signature,
                old_signature,
            } => {
                let new_sig = old_signature.clone().unwrap_or_else(|| FunctionSignature {
                    name: String::new(),
                    params: Vec::new(),
                    ret: DataType::Void,
                    calling_conv: None,
                });
                Some(Op::SetFunctionSignature {
                    va: *va,
                    signature: new_sig,
                    old_signature: Some(signature.clone()),
                })
            }
            Op::SetStackLocalType {
                function_va,
                offset,
                ty,
                old_ty,
            } => {
                let new_ty = old_ty.clone().unwrap_or(DataType::Unknown(0));
                Some(Op::SetStackLocalType {
                    function_va: *function_va,
                    offset: *offset,
                    ty: new_ty,
                    old_ty: Some(ty.clone()),
                })
            }
            Op::SetStackLocalName {
                function_va,
                offset,
                name,
                old_name,
            } => {
                let prev = old_name.clone().unwrap_or(None);
                Some(Op::SetStackLocalName {
                    function_va: *function_va,
                    offset: *offset,
                    name: prev.unwrap_or_default(),
                    old_name: Some(Some(name.clone())),
                })
            }
            Op::SetParamName {
                function_va,
                index,
                name,
                old_name,
            } => {
                let prev = old_name.clone().unwrap_or_default();
                Some(Op::SetParamName {
                    function_va: *function_va,
                    index: *index,
                    name: prev,
                    old_name: Some(name.clone()),
                })
            }
            Op::SetFunctionMemory { va, card, old } => {
                let prev = old.clone().unwrap_or(None);
                match prev {
                    Some(prev_card) => Some(Op::SetFunctionMemory {
                        va: *va,
                        card: prev_card,
                        old: Some(Some(card.clone())),
                    }),
                    None => {
                        // Undo = remove: apply empty card then remove in apply? Use empty purpose
                        // with a sentinel — store removal as Set with empty and special apply.
                        // Simpler: re-insert previous None by deleting on empty tags+purpose.
                        Some(Op::SetFunctionMemory {
                            va: *va,
                            card: FunctionMemoryCard {
                                va: *va,
                                purpose: None,
                                tags: vec!["__clear__".into()],
                                ..FunctionMemoryCard::default()
                            },
                            old: Some(Some(card.clone())),
                        })
                    }
                }
            }
            Op::Batch { ops } => {
                let inverse_ops: Vec<Op> = ops.iter().rev().filter_map(Op::inverse).collect();
                if inverse_ops.is_empty() {
                    None
                } else {
                    Some(Op::Batch { ops: inverse_ops })
                }
            }
        }
    }

    /// Short human-readable summary of the operation for activity feeds.
    pub fn summary(&self) -> String {
        match self {
            Op::RenameSymbol { va, name, .. } => format!("rename {va:#x} → {name}"),
            Op::SetComment { va, scope, .. } => match scope {
                CommentScope::Address => format!("comment at {va:#x}"),
                CommentScope::Function => format!("function comment at {va:#x}"),
            },
            Op::SetFocus { va, .. } => format!("focus {va:#x}"),
            Op::SetGlobalType { va, ty, .. } => {
                format!("retype {va:#x} -> {ty:?}")
            }
            Op::SetFunctionSignature { va, signature, .. } => {
                format!("signature {va:#x} -> {}", signature.name)
            }
            Op::SetStackLocalType {
                function_va,
                offset,
                ty,
                ..
            } => {
                format!("stack {function_va:#x}[{offset}] -> {ty:?}")
            }
            Op::SetStackLocalName {
                function_va,
                offset,
                name,
                ..
            } => {
                format!("stack name {function_va:#x}[{offset}] -> {name}")
            }
            Op::SetParamName {
                function_va,
                index,
                name,
                ..
            } => {
                format!("param {function_va:#x}[{index}] -> {name}")
            }
            Op::SetFunctionMemory { va, card, .. } => {
                let purpose = card.purpose.as_deref().unwrap_or("(memory)");
                format!("memory {va:#x}: {purpose}")
            }
            Op::Batch { ops } => format!("batch of {} ops", ops.len()),
        }
    }
}

/// Insert or update a stack variable at `offset` (locals ≤ 0, args > 0).
fn upsert_stack_var(frame: &mut StackFrame, offset: i64, mutate: impl FnOnce(&mut StackVariable)) {
    let list = if offset > 0 {
        &mut frame.args
    } else {
        &mut frame.locals
    };
    if let Some(v) = list.iter_mut().find(|v| v.offset == offset) {
        mutate(v);
        return;
    }
    let mut v = StackVariable {
        name: None,
        ty: DataType::Unknown(0),
        offset,
        size: 0,
    };
    mutate(&mut v);
    list.push(v);
    list.sort_by_key(|v| v.offset);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_rename_swaps_names() {
        let op = Op::RenameSymbol {
            va: 0x1000,
            name: "new".to_string(),
            kind: SymbolKind::User,
            old_name: Some("old".to_string()),
            old_kind: Some(SymbolKind::Function),
        };
        let inv = op.inverse().unwrap();
        match inv {
            Op::RenameSymbol { va, name, kind, .. } => {
                assert_eq!(va, 0x1000);
                assert_eq!(name, "old");
                assert_eq!(kind, SymbolKind::Function);
            }
            _ => panic!("expected RenameSymbol"),
        }
    }

    #[test]
    fn inverse_set_global_type_round_trips() {
        let op = Op::SetGlobalType {
            va: 0x2000,
            ty: DataType::Uint(32),
            old_ty: Some(DataType::Int(8)),
        };
        let inv = op.inverse().unwrap();
        match inv {
            Op::SetGlobalType { va, ty, old_ty, .. } => {
                assert_eq!(va, 0x2000);
                assert_eq!(ty, DataType::Int(8));
                assert_eq!(old_ty, Some(DataType::Uint(32)));
            }
            _ => panic!("expected SetGlobalType"),
        }
    }

    #[test]
    fn inverse_set_function_signature_round_trips() {
        let sig = FunctionSignature {
            name: "foo".to_string(),
            params: vec![("a".to_string(), DataType::Int(32))],
            ret: DataType::Void,
            calling_conv: Some("cdecl".to_string()),
        };
        let old = FunctionSignature {
            name: "foo".to_string(),
            params: vec![],
            ret: DataType::Int(32),
            calling_conv: None,
        };
        let op = Op::SetFunctionSignature {
            va: 0x3000,
            signature: sig.clone(),
            old_signature: Some(old.clone()),
        };
        let inv = op.inverse().unwrap();
        match inv {
            Op::SetFunctionSignature {
                va,
                signature,
                old_signature,
                ..
            } => {
                assert_eq!(va, 0x3000);
                assert_eq!(signature, old);
                assert_eq!(old_signature, Some(sig));
            }
            _ => panic!("expected SetFunctionSignature"),
        }
    }

    #[test]
    fn inverse_set_stack_local_type_round_trips() {
        let op = Op::SetStackLocalType {
            function_va: 0x4000,
            offset: -0x10,
            ty: DataType::Ptr(Box::new(DataType::Int(8))),
            old_ty: Some(DataType::Unknown(64)),
        };
        let inv = op.inverse().unwrap();
        match inv {
            Op::SetStackLocalType {
                function_va,
                offset,
                ty,
                old_ty,
                ..
            } => {
                assert_eq!(function_va, 0x4000);
                assert_eq!(offset, -0x10);
                assert_eq!(ty, DataType::Unknown(64));
                assert_eq!(old_ty, Some(DataType::Ptr(Box::new(DataType::Int(8)))));
            }
            _ => panic!("expected SetStackLocalType"),
        }
    }

    #[test]
    fn inverse_set_stack_local_name_round_trips() {
        let op = Op::SetStackLocalName {
            function_va: 0x4000,
            offset: -0x18,
            name: "buffer".to_string(),
            old_name: Some(Some("var_18".to_string())),
        };
        let inv = op.inverse().unwrap();
        match inv {
            Op::SetStackLocalName {
                function_va,
                offset,
                name,
                old_name,
                ..
            } => {
                assert_eq!(function_va, 0x4000);
                assert_eq!(offset, -0x18);
                assert_eq!(name, "var_18");
                assert_eq!(old_name, Some(Some("buffer".to_string())));
            }
            _ => panic!("expected SetStackLocalName"),
        }
    }

    #[test]
    fn inverse_set_param_name_round_trips() {
        let op = Op::SetParamName {
            function_va: 0x5000,
            index: 1,
            name: "path".to_string(),
            old_name: Some("arg1".to_string()),
        };
        let inv = op.inverse().unwrap();
        match inv {
            Op::SetParamName {
                function_va,
                index,
                name,
                old_name,
                ..
            } => {
                assert_eq!(function_va, 0x5000);
                assert_eq!(index, 1);
                assert_eq!(name, "arg1");
                assert_eq!(old_name, Some("path".to_string()));
            }
            _ => panic!("expected SetParamName"),
        }
    }
}
