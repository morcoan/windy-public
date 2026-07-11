
use std::collections::BTreeMap;

use iced_x86::{
    FlowControl, InstructionInfoFactory, OpAccess, OpKind, Register, UsedMemory,
};

use crate::analysis::code_index::{CodeIndex, DecodedInstr};
use crate::loader::address_space::AddressSpace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    JumpUnconditional,
    JumpTaken,
    DataRead,
    DataWrite,
    Indirect,
}

#[derive(Clone, Debug)]
pub struct Xref {
    pub from_va: u64,
    pub to_va: u64,
    pub kind: XrefKind,
}

/// Cross-reference look-up tables: code and data references between VAs.
#[derive(Default, Clone, Debug)]
pub struct XrefIndex {
    /// References *to* a given VA.
    pub to: BTreeMap<u64, Vec<Xref>>,
    /// References *from* a given VA.
    pub from: BTreeMap<u64, Vec<Xref>>,
}

impl XrefIndex {
    /// Build the code + data xref index. Data references include RIP-relative
    /// and absolute memory operands, plus 64-bit immediate operands that fall
    /// inside the image.
    pub fn build(code_index: &CodeIndex, address_space: &AddressSpace, bitness: u32) -> Self {
        let mut idx = Self::build_code(code_index);
        let mut info_factory = InstructionInfoFactory::new();

        for dec in code_index.iter() {
            add_memory_xrefs(dec, address_space, bitness, &mut info_factory, &mut idx);
            add_immediate_xrefs(dec, address_space, bitness, &mut idx);
        }

        idx
    }

    pub fn to(&self, va: u64) -> &[Xref] {
        self.to.get(&va).map(Vec::as_slice).unwrap_or_default()
    }

    pub fn from(&self, va: u64) -> &[Xref] {
        self.from.get(&va).map(Vec::as_slice).unwrap_or_default()
    }

    fn build_code(code_index: &CodeIndex) -> Self {
        let mut to: BTreeMap<u64, Vec<Xref>> = BTreeMap::new();
        let mut from: BTreeMap<u64, Vec<Xref>> = BTreeMap::new();

        for dec in code_index.iter() {
            let target = match dec.instr.flow_control() {
                FlowControl::Call => Some((dec.instr.near_branch_target(), XrefKind::Call)),
                FlowControl::UnconditionalBranch => {
                    Some((dec.instr.near_branch_target(), XrefKind::JumpUnconditional))
                }
                FlowControl::ConditionalBranch => {
                    Some((dec.instr.near_branch_target(), XrefKind::JumpTaken))
                }
                _ => None,
            };

            if let Some((to_va, kind)) = target {
                if to_va == 0 {
                    continue;
                }
                let xref = Xref {
                    from_va: dec.ip,
                    to_va,
                    kind,
                };
                to.entry(to_va).or_default().push(xref.clone());
                from.entry(dec.ip).or_default().push(xref);
            }
        }

        Self { to, from }
    }

    pub fn add(&mut self, to_va: u64, from_va: u64, kind: XrefKind) {
        let xref = Xref {
            from_va,
            to_va,
            kind,
        };
        self.to.entry(to_va).or_default().push(xref.clone());
        self.from.entry(from_va).or_default().push(xref);
    }
}

fn add_memory_xrefs(
    dec: &DecodedInstr,
    address_space: &AddressSpace,
    bitness: u32,
    info_factory: &mut InstructionInfoFactory,
    idx: &mut XrefIndex,
) {
    if !has_memory_operand(&dec.instr) {
        return;
    }

    let info = info_factory.info(&dec.instr);
    for um in info.used_memory() {
        let Some(target) = used_memory_target_va(&dec.instr, um, bitness) else {
            continue;
        };
        if target == 0 || !address_space.is_valid_va(target) {
            continue;
        }
        let kind = if is_write_access(um.access()) {
            XrefKind::DataWrite
        } else {
            XrefKind::DataRead
        };
        idx.add(target, dec.ip, kind);
    }
}

fn add_immediate_xrefs(
    dec: &DecodedInstr,
    address_space: &AddressSpace,
    bitness: u32,
    idx: &mut XrefIndex,
) {
    // Only treat wide immediates as probable pointers; on x64 a 32-bit
    // immediate is sign-extended and rarely a full VA.
    if bitness != 64 {
        return;
    }
    for i in 0..dec.instr.op_count() {
        if dec.instr.op_kind(i) == OpKind::Immediate64 {
            let target = dec.instr.immediate(i);
            if target != 0 && address_space.is_valid_va(target) {
                idx.add(target, dec.ip, XrefKind::DataRead);
            }
        }
    }
}

fn has_memory_operand(instr: &iced_x86::Instruction) -> bool {
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Memory {
            return true;
        }
    }
    false
}

fn used_memory_target_va(
    instr: &iced_x86::Instruction,
    um: &UsedMemory,
    bitness: u32,
) -> Option<u64> {
    if um.base() == Register::RIP && um.index() == Register::None && bitness == 64 {
        let disp = um.displacement() as i32 as i64;
        return Some(instr.next_ip().wrapping_add(disp as u64));
    }
    if um.base() == Register::None && um.index() == Register::None {
        return Some(um.displacement());
    }
    None
}

fn is_write_access(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}
