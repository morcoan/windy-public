//! Precedence-aware pure printer for [`TypedAst`] — no semantic rewrites.

use super::ast::{Expr, Stmt, TypedAst};

/// Format a typed AST to C text. Printer does not rewrite control or semantics.
pub fn print_typed_ast(ast: &TypedAst) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {}({}) {{\n",
        ast.ret_ty,
        ast.name,
        ast.params.join(", ")
    ));
    print_stmts(&ast.body, 1, &mut out);
    out.push_str("}\n");
    out
}

fn ind(n: usize) -> String {
    " ".repeat(n)
}

fn print_stmts(stmts: &[Stmt], depth: usize, out: &mut String) {
    for s in stmts {
        print_stmt(s, depth, out);
    }
}

fn print_stmt(s: &Stmt, depth: usize, out: &mut String) {
    let i = ind(depth);
    match s {
        Stmt::Label { name } => {
            out.push_str(&format!("{name}:\n"));
        }
        Stmt::Goto { target } => {
            out.push_str(&format!("{i}goto {target};\n"));
        }
        Stmt::Return { expr } => match expr {
            Some(e) => out.push_str(&format!("{i}return {};\n", print_expr(e, 0))),
            None => out.push_str(&format!("{i}return;\n")),
        },
        Stmt::Assign { dest, expr } => {
            out.push_str(&format!("{i}{dest} = {};\n", print_expr(expr, 0)));
        }
        Stmt::Expr { expr } => {
            out.push_str(&format!("{i}{};\n", print_expr(expr, 0)));
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            out.push_str(&format!("{i}if ({}) {{\n", print_expr(cond, 0)));
            print_stmts(then_body, depth + 1, out);
            if else_body.is_empty() {
                out.push_str(&format!("{i}}}\n"));
            } else {
                out.push_str(&format!("{i}}} else {{\n"));
                print_stmts(else_body, depth + 1, out);
                out.push_str(&format!("{i}}}\n"));
            }
        }
        Stmt::While { cond, body } => {
            out.push_str(&format!("{i}while ({}) {{\n", print_expr(cond, 0)));
            print_stmts(body, depth + 1, out);
            out.push_str(&format!("{i}}}\n"));
        }
        Stmt::Switch {
            scrutinee,
            cases,
            default_body,
        } => {
            out.push_str(&format!("{i}switch ({}) {{\n", print_expr(scrutinee, 0)));
            for c in cases {
                for v in &c.values {
                    out.push_str(&format!("{i} case {v}:\n"));
                }
                print_stmts(&c.body, depth + 1, out);
            }
            if !default_body.is_empty() {
                out.push_str(&format!("{i} default:\n"));
                print_stmts(default_body, depth + 1, out);
            }
            out.push_str(&format!("{i}}}\n"));
        }
        Stmt::Break => out.push_str(&format!("{i}break;\n")),
        Stmt::Continue => out.push_str(&format!("{i}continue;\n")),
        Stmt::Comment { text } => out.push_str(&format!("{i}/* {text} */\n")),
        Stmt::RawBlock { .. } => {
            // Pure path forbids RawBlock polish dumps — never short-circuit to
            // verbatim text. Emit a residual marker only (checker also rejects).
            out.push_str(&format!("{i}/* residual:raw_block_rejected */\n"));
        }
    }
}

/// Expression printer with minimal parenthesization by binding power.
pub fn print_expr(e: &Expr, parent_bp: u8) -> String {
    match e {
        Expr::Name { name } => name.clone(),
        Expr::Int { value, .. } => {
            if *value < 0 {
                format!("-{:#x}", (-value) as u64)
            } else {
                format!("{value:#x}")
            }
        }
        Expr::UInt { value, .. } => format!("{value:#x}"),
        Expr::BinOp { op, lhs, rhs } => {
            let bp = bin_bp(op);
            let s = format!("{} {} {}", print_expr(lhs, bp), op, print_expr(rhs, bp + 1));
            paren_if(s, bp < parent_bp)
        }
        Expr::UnaryOp { op, arg } => {
            let s = format!("{op}{}", print_expr(arg, 14));
            paren_if(s, 14 < parent_bp)
        }
        Expr::Cast { ty, arg } => format!("({ty}){}", print_expr(arg, 14)),
        Expr::Call { target, args } => {
            let a: Vec<String> = args.iter().map(|x| print_expr(x, 0)).collect();
            format!("{target}({})", a.join(", "))
        }
        Expr::Load { addr } => format!("*({})", print_expr(addr, 0)),
        Expr::Select {
            cond,
            then_e,
            else_e,
        } => {
            let s = format!(
                "{} ? {} : {}",
                print_expr(cond, 3),
                print_expr(then_e, 3),
                print_expr(else_e, 2)
            );
            paren_if(s, 2 < parent_bp)
        }
        Expr::Compare { op, lhs, rhs } => {
            let bp = 7;
            let s = format!("{} {} {}", print_expr(lhs, bp), op, print_expr(rhs, bp + 1));
            paren_if(s, bp < parent_bp)
        }
    }
}

fn bin_bp(op: &str) -> u8 {
    match op {
        "*" | "/" | "%" => 11,
        "+" | "-" => 10,
        "<<" | ">>" => 9,
        "&" => 6,
        "^" => 5,
        "|" => 4,
        "&&" => 3,
        "||" => 2,
        _ => 8,
    }
}

fn paren_if(s: String, need: bool) -> String {
    if need { format!("({s})") } else { s }
}

#[cfg(test)]
mod tests {
    use super::super::ast::TypedAst;
    use super::*;

    #[test]
    fn printer_formats_return_only() {
        let ast = TypedAst {
            name: "FUN_x".into(),
            params: vec!["u64 arg1".into()],
            ret_ty: "uint64".into(),
            body: vec![Stmt::Return {
                expr: Some(Expr::Int { value: 1, bits: 64 }),
            }],
        };
        let t = print_typed_ast(&ast);
        assert!(t.contains("return 0x1"), "{t}");
        assert!(t.contains("FUN_x"), "{t}");
        // No rewrite: no invented if.
        assert!(!t.contains("if ("), "{t}");
    }

    #[test]
    fn select_prints_as_ternary_not_if() {
        let e = Expr::Select {
            cond: Box::new(Expr::Compare {
                op: "<".into(),
                lhs: Box::new(Expr::Name { name: "a".into() }),
                rhs: Box::new(Expr::Name { name: "b".into() }),
            }),
            then_e: Box::new(Expr::Int { value: 1, bits: 32 }),
            else_e: Box::new(Expr::Int { value: 0, bits: 32 }),
        };
        let s = print_expr(&e, 0);
        assert!(s.contains('?'), "{s}");
        assert!(!s.contains("if"), "{s}");
    }
}
