//! Pure pretty-printer: formats candidate text only (no semantic rewrites).

use super::extract::AstCandidate;

/// Format accepted candidate to final source text.
///
/// Plan requirement: the printer performs **no** semantic or control-flow
/// rewrites (no switch folding, no return polishing, no goto surgery).
pub fn print_candidate(cand: &AstCandidate) -> String {
    // Candidate text is already structured C from the extraction baseline
    // (legacy emit). Normalize line endings only.
    cand.text.replace("\r\n", "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::v2::extract::AstCandidate;

    #[test]
    fn printer_does_not_inject_switch() {
        let c = AstCandidate {
            text: "if (x == 0) { return 1; }".into(),
            edges_covered: 1,
            residual_edges: 0,
            effects_covered: 1,
            effect_signature: vec![],
            case_partitions: vec![],
            cost: 0,
            nesting: 1,
        };
        let out = print_candidate(&c);
        assert!(!out.contains("switch"));
        assert_eq!(out, c.text);
    }
}
