//! Conservative projection of SSA type recovery onto function signatures.
//!
//! [`TypeRecoveryReport`] is evidence gathered from one function's SSA.  A
//! recovered type is useful for improving a placeholder signature, but it
//! must never overwrite a PDB or user-provided declaration.  This module
//! keeps that policy separate from project persistence: callers supply the
//! provenance they know for the current signature, then persist the returned
//! value through the normal operation path if appropriate.

use crate::decompiler::types::recover::{TyGuess, TypeRecoveryReport};
use crate::project::types::{DataType, FunctionSignature};

/// Provenance of the signature being considered for SSA-based refinement.
///
/// Only a heuristic signature may be changed.  The source is explicit because
/// [`FunctionSignature`] intentionally carries no persistence/provenance
/// metadata of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureSource {
    /// A best-effort signature recovered from instructions or a non-authoritative database.
    Heuristic,
    /// A declaration recovered from PDB debug information.
    Pdb,
    /// A declaration supplied or explicitly edited by an operator.
    User,
}

impl SignatureSource {
    /// Whether this source must be kept exactly as supplied.
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::Pdb | Self::User)
    }
}

/// Refine a heuristic [`FunctionSignature`] using a [`TypeRecoveryReport`].
///
/// The merge intentionally has a small, one-way surface:
///
/// * PDB and user signatures are returned unchanged.
/// * A parameter changes only when its existing type is directly `Unknown` and
///   the recovery report has a concrete type at the same positional rank.
/// * A return type changes only from heuristic `void` to a concrete recovered
///   type.
/// * Parameter names, the function name, calling convention, parameter count,
///   and all already-concrete types are preserved.
///
/// `fallback_bits` is passed to [`TyGuess::to_data_type`] for nested unknown
/// members (normally the target bitness, such as `64`).  A recovered rank that
/// does not index an existing signature parameter is ignored rather than
/// inventing a new parameter.
pub fn refine_signature_from_recovery(
    signature: &FunctionSignature,
    source: SignatureSource,
    recovery: &TypeRecoveryReport,
    fallback_bits: u8,
) -> FunctionSignature {
    if source.is_authoritative() {
        return signature.clone();
    }

    let mut refined = signature.clone();

    for recovered in &recovery.params {
        if matches!(recovered.ty, TyGuess::Unknown) {
            continue;
        }
        let Some((_, existing_ty)) = refined.params.get_mut(recovered.rank) else {
            continue;
        };
        if matches!(existing_ty, DataType::Unknown(_)) {
            *existing_ty = recovered.ty.to_data_type(fallback_bits);
        }
    }

    if matches!(refined.ret, DataType::Void)
        && let Some(return_guess) = &recovery.return_type
        && !matches!(return_guess.ty, TyGuess::Unknown)
    {
        refined.ret = return_guess.ty.to_data_type(fallback_bits);
    }

    refined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::types::recover::{ParamType, ReturnGuess};

    fn heuristic_signature() -> FunctionSignature {
        FunctionSignature {
            name: "keep_this_name".to_string(),
            params: vec![
                ("first_name".to_string(), DataType::Unknown(8)),
                ("second_name".to_string(), DataType::Uint(16)),
            ],
            ret: DataType::Void,
            calling_conv: Some("fastcall".to_string()),
        }
    }

    fn report(params: Vec<ParamType>, return_type: Option<TyGuess>) -> TypeRecoveryReport {
        TypeRecoveryReport {
            function_va: 0x1400_0010,
            params,
            return_type: return_type.map(|ty| ReturnGuess {
                ty,
                old_ty: TyGuess::Unknown,
            }),
            ..TypeRecoveryReport::default()
        }
    }

    fn param(rank: usize, ty: TyGuess) -> ParamType {
        ParamType {
            rank,
            ty,
            old_ty: TyGuess::Unknown,
        }
    }

    #[test]
    fn heuristic_refinement_fills_only_unknown_in_range_parameters() {
        let signature = heuristic_signature();
        let recovery = report(
            vec![
                param(0, TyGuess::Int(32)),
                param(1, TyGuess::Uint(32)),
                param(2, TyGuess::Bool),
                param(3, TyGuess::Unknown),
            ],
            None,
        );

        let refined =
            refine_signature_from_recovery(&signature, SignatureSource::Heuristic, &recovery, 64);

        assert_eq!(refined.params.len(), 2, "must not invent parameters");
        assert_eq!(
            refined.params[0],
            ("first_name".to_string(), DataType::Int(32))
        );
        assert_eq!(
            refined.params[1],
            ("second_name".to_string(), DataType::Uint(16)),
            "a concrete signature type wins over SSA recovery"
        );
        assert_eq!(refined.name, signature.name);
        assert_eq!(refined.calling_conv, signature.calling_conv);
    }

    #[test]
    fn heuristic_void_return_changes_only_for_a_concrete_recovery() {
        let signature = heuristic_signature();
        let concrete = report(Vec::new(), Some(TyGuess::Ptr(Box::new(TyGuess::Uint(8)))));
        let unknown = report(Vec::new(), Some(TyGuess::Unknown));

        let concrete_refined =
            refine_signature_from_recovery(&signature, SignatureSource::Heuristic, &concrete, 64);
        let unknown_refined =
            refine_signature_from_recovery(&signature, SignatureSource::Heuristic, &unknown, 64);

        assert_eq!(
            concrete_refined.ret,
            DataType::Ptr(Box::new(DataType::Uint(8)))
        );
        assert_eq!(unknown_refined.ret, DataType::Void);
    }

    #[test]
    fn heuristic_non_void_return_is_not_replaced() {
        let mut signature = heuristic_signature();
        signature.ret = DataType::Int(64);
        let recovery = report(Vec::new(), Some(TyGuess::Uint(32)));

        let refined =
            refine_signature_from_recovery(&signature, SignatureSource::Heuristic, &recovery, 64);

        assert_eq!(refined.ret, DataType::Int(64));
    }

    #[test]
    fn pdb_and_user_signatures_are_never_refined() {
        let signature = heuristic_signature();
        let recovery = report(vec![param(0, TyGuess::Int(32))], Some(TyGuess::Uint(32)));

        for source in [SignatureSource::Pdb, SignatureSource::User] {
            let refined = refine_signature_from_recovery(&signature, source, &recovery, 64);
            assert_eq!(refined, signature, "{source:?} signature was changed");
        }
    }
}
