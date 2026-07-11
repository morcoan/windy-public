
//! Intermediate representation seam.
//!
//! The decompiler's IR is P-code, lifted per-function from the executable
//! sections via the SLEIGH decoder in [`crate::decompiler::pcode`]. The older
//! iced-centric `Lifter` trait and `IcedLifter` identity lifter were retired in
//! Phase 1; export and GCLSD input now carry `PcodeOp` lists directly
//! (see [`crate::ir::export::InstrExport::pcode_ops`] and
//! [`crate::ir::gclsd::GclsdInstr::pcode_ops`]).

pub mod agent_text;
pub mod annotate;
pub mod export;
pub mod gclsd;
