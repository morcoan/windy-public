//! Tiered presentation after raw structure emit.
//!
//! **CfgOnly** — residual-goto reduction, switch-from-ladder fold, while rewrite,
//! flag-noise strip. **No** return/constant/resource/`polish_*` surgery.
//!
//! **LegacySemantic** — all `polish_*` that invent control keywords, HRESULT/CRC
//! constants, resource renames, xor-return hoists. **Legacy / ShadowV2 only**.
//!
//! Pure V2 authority lives in `decompiler::v2` (region_ast + typed AST printer)
//! and never imports this module.

use super::emit::{
    fold_eq_ladder_to_switch, fold_goto_return_and_trivial_rejoins, inline_leaf_goto_targets,
    minimize_gotos, polish_compare_return_to_if, polish_crc_xor_return,
    polish_dual_flag_zero_tests, polish_e_pointer_returns, polish_flag_lt_compares,
    polish_guard_returns, polish_hoist_null_guard_returns, polish_hoist_rich_xor_return,
    polish_loop_with_guard_if, polish_paired_cleanup_destroys, polish_pure_op_return_to_if,
    polish_resource_pair_names, polish_sentinel_literals, polish_switch_with_guard_if,
    polish_zero_returns, rewrite_label_backedge_to_while, strip_flag_helper_noise,
    strip_security_cookie_gotos,
};

/// Which presentation passes to run after `structure_emit_core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationTier {
    /// CFG cleanup only — pure V2 authority path.
    CfgOnly,
    /// CfgOnly + semantic text polish — Legacy fallback only.
    LegacySemantic,
}

/// Apply the named presentation tier to already-emitted core C text.
pub fn apply_presentation(core: &str, tier: PresentationTier) -> String {
    let cfg = apply_cfg_only(core);
    match tier {
        PresentationTier::CfgOnly => cfg,
        PresentationTier::LegacySemantic => apply_legacy_semantic(&cfg),
    }
}

/// CFG/region presentation only. Must never call semantic polish helpers.
pub fn apply_cfg_only(src: &str) -> String {
    let out = minimize_gotos(src);
    let out = fold_goto_return_and_trivial_rejoins(&out);
    let out = inline_leaf_goto_targets(&out);
    let out = strip_security_cookie_gotos(&out);
    let out = rewrite_label_backedge_to_while(&out);
    let out = fold_eq_ladder_to_switch(&out);
    // Flag soup strip is structural noise removal (not return/constant surgery).
    strip_flag_helper_noise(&out)
}

/// Semantic text polish owned exclusively by the Legacy fallback path.
///
/// Pure V2 never calls this. When pure CfgOnly text already equals the result
/// of this chain, the engine may ship V2; otherwise it falls back to Legacy
/// with reason `pure_needs_semantic_polish`.
pub fn apply_legacy_semantic(src: &str) -> String {
    let out = polish_sentinel_literals(src);
    let out = polish_zero_returns(&out);
    let out = polish_flag_lt_compares(&out);
    let out = polish_dual_flag_zero_tests(&out);
    let out = polish_guard_returns(&out);
    let out = polish_compare_return_to_if(&out);
    let out = polish_pure_op_return_to_if(&out);
    let out = polish_switch_with_guard_if(&out);
    let out = polish_loop_with_guard_if(&out);
    let out = polish_paired_cleanup_destroys(&out);
    let out = polish_resource_pair_names(&out);
    let out = polish_hoist_null_guard_returns(&out);
    let out = polish_hoist_rich_xor_return(&out);
    let out = polish_crc_xor_return(&out);
    let out = polish_e_pointer_returns(&out);
    // Nested keyword cleanup after control wraps (legacy-only).
    let out = super::emit::polish_nested_while_keyword(&out);
    super::emit::polish_nested_if_keyword(&out)
}

/// Names of semantic polish functions that **must not** appear in CfgOnly.
/// Used by the structural guard test (string-scanned in source).
#[cfg(test)]
pub const CFG_ONLY_FORBIDDEN_POLISH: &[&str] = &[
    "polish_crc_xor_return",
    "polish_e_pointer_returns",
    "polish_compare_return_to_if",
    "polish_pure_op_return_to_if",
    "polish_resource_pair_names",
    "polish_hoist_rich_xor_return",
    "polish_switch_with_guard_if",
    "polish_loop_with_guard_if",
    "polish_guard_returns",
    "polish_paired_cleanup_destroys",
    "polish_hoist_null_guard_returns",
    "polish_zero_returns",
    "polish_flag_lt_compares",
    "polish_dual_flag_zero_tests",
    "polish_sentinel_literals",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_only_does_not_invent_e_pointer() {
        let src = r#"uint64 FUN_x(u64 arg1) {
 if ((arg1 == 0)) {
  return 0;
 }
 return 1;
}
"#;
        let cfg = apply_cfg_only(src);
        assert!(
            !cfg.contains("80004003"),
            "CfgOnly must not invent E_POINTER:\n{cfg}"
        );
        let leg = apply_legacy_semantic(&cfg);
        // Legacy may or may not fire depending on shape; if it does, that's fine.
        let _ = leg;
    }

    #[test]
    fn cfg_only_does_not_wrap_pure_op_return() {
        let src = "uint64 FUN_x() {\n return (a ^ b);\n}\n";
        let cfg = apply_cfg_only(src);
        assert!(
            !cfg.contains("if (") && !cfg.contains("if("),
            "CfgOnly must not wrap pure-op returns:\n{cfg}"
        );
        let leg = apply_legacy_semantic(&cfg);
        assert!(
            leg.contains("if (") || leg.contains("if("),
            "LegacySemantic must wrap pure-op returns:\n{leg}"
        );
    }

    #[test]
    fn cfg_only_source_forbids_semantic_polish_names() {
        // Structural: the apply_cfg_only body in this file must not call forbidden polish.
        let src = include_str!("presentation.rs");
        // Isolate the apply_cfg_only function body.
        let start = src
            .find("pub fn apply_cfg_only")
            .expect("apply_cfg_only present");
        let rest = &src[start..];
        let end = rest
            .find("pub fn apply_legacy_semantic")
            .expect("apply_legacy_semantic after cfg");
        let body = &rest[..end];
        for name in CFG_ONLY_FORBIDDEN_POLISH {
            assert!(!body.contains(name), "apply_cfg_only must not call {name}");
        }
    }
}
