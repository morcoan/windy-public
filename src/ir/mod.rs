//! Intermediate representation seam.
//!
//! The decompiler's IR is P-code, lifted per-function from the executable
//! sections via the SLEIGH decoder in [`crate::decompiler::pcode`]. The older
//! iced-centric `Lifter` trait and `IcedLifter` identity lifter were retired in
//! Phase 1; instruction exports now carry `PcodeOp` lists directly. The
//! archived GCLSD authoring contract is available only with its opt-in feature.

pub mod agent_text;
pub mod annotate;
pub mod export;
#[cfg(feature = "gclsd-archive")]
pub mod gclsd;
