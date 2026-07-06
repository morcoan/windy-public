#![allow(dead_code)] // IR seam; actively used in Phase 5

pub mod export;

use iced_x86::Instruction;

/// Intermediate representation seam.
///
/// The long-term goal is to support a uniform IR (e.g. P-Code lifted from
/// Ghidra `.sla` files via the `pcode` crate). For the disassembler phase we
/// can start with a trivial identity lifter so the analysis API is already
/// IR-driven.
pub trait Lifter {
    type Op;
    fn lift(&self, instr: &Instruction) -> Vec<Self::Op>;
}

/// Identity lifter: keeps the raw `iced_x86::Instruction` as the IR op.
pub struct IcedLifter;

impl Lifter for IcedLifter {
    type Op = Instruction;

    fn lift(&self, instr: &Instruction) -> Vec<Self::Op> {
        vec![*instr]
    }
}
