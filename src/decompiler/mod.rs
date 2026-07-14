//! Native decompiler pipeline.

/// Cache key for native decompiled output. A result is valid only while the
/// project image and operation sequence are unchanged.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DecompileCacheKey {
    pub image_sha256: String,
    pub va: u64,
    pub op_seq: u64,
}

pub mod analysis;
#[allow(dead_code)] // semantic HIR is additive until the call-lifting pass consumes it
pub mod hir;
pub mod normalize;
pub mod pcode;
pub mod ssa;
pub mod structure;
pub mod types;
/// WindyDec v2: semantic → contracts → checked extraction → pure printer.
pub mod v2;
