//! Typed AST for pure V2 extraction and printing.
//!
//! Candidates are built from HIR + architectural CFG, never from Legacy text polish.

use serde::{Deserialize, Serialize};

use super::contracts::CaseContractV2;

/// Typed AST root for one function.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypedAst {
    pub name: String,
    pub params: Vec<String>,
    pub ret_ty: String,
    pub body: Vec<Stmt>,
}

/// Statement nodes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stmt {
    Label {
        name: String,
    },
    Goto {
        target: String,
    },
    Return {
        expr: Option<Expr>,
    },
    Assign {
        dest: String,
        expr: Expr,
    },
    Expr {
        expr: Expr,
    },
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    Switch {
        scrutinee: Expr,
        cases: Vec<SwitchCase>,
        default_body: Vec<Stmt>,
    },
    Break,
    Continue,
    Comment {
        text: String,
    },
    /// Temporary structured seed block (CfgOnly structure emit without polish).
    /// Printer emits text verbatim; no semantic rewrite.
    RawBlock {
        text: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwitchCase {
    pub values: Vec<i64>,
    pub body: Vec<Stmt>,
}

/// Expression nodes (exact bit widths optional until full HIR typing lands).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expr {
    Name {
        name: String,
    },
    Int {
        value: i64,
        bits: u16,
    },
    UInt {
        value: u64,
        bits: u16,
    },
    BinOp {
        op: String,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    UnaryOp {
        op: String,
        arg: Box<Expr>,
    },
    Cast {
        ty: String,
        arg: Box<Expr>,
    },
    Call {
        target: String,
        args: Vec<Expr>,
    },
    Load {
        addr: Box<Expr>,
    },
    Select {
        cond: Box<Expr>,
        then_e: Box<Expr>,
        else_e: Box<Expr>,
    },
    Compare {
        op: String,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
}

/// Coverage maps attached to a candidate (edge/effect identity lists).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoverageMaps {
    pub edges: Vec<String>,
    pub effects: Vec<String>,
}

/// One typed AST candidate with coverage and cost.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypedAstCandidate {
    pub ast: TypedAst,
    pub coverage: CoverageMaps,
    pub residual_edges: usize,
    pub case_partitions: Vec<CaseContractV2>,
    pub cost: i32,
    pub nesting: i32,
    pub hit_cap: bool,
}

impl TypedAst {
    pub fn empty_function(name: &str) -> Self {
        Self {
            name: name.into(),
            params: vec![],
            ret_ty: "uint64".into(),
            body: vec![],
        }
    }
}
