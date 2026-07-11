
use std::collections::BTreeMap;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction};

use crate::loader::address_space::{AddressSpace, Section};

/// A decoded instruction at a known virtual address, kept cheaply for random access.
#[derive(Clone, Debug)]
pub struct DecodedInstr {
    pub ip: u64,
    pub len: u8,
    pub bytes: [u8; 16],
    pub instr: Instruction,
}

impl DecodedInstr {
    pub fn bytes_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn next_ip(&self) -> u64 {
        self.ip.saturating_add(u64::from(self.len))
    }
}

/// Random-access code cache for every executable section, built by linear sweep.
#[derive(Clone, Debug)]
pub struct CodeIndex {
    pub instrs: Vec<DecodedInstr>,
    pub va_to_idx: BTreeMap<u64, usize>,
}

impl CodeIndex {
    pub fn build(image: &[u8], address_space: &AddressSpace, bitness: u32) -> Self {
        let mut instrs = Vec::new();
        let mut va_to_idx = BTreeMap::new();

        for section in address_space.exec_sections() {
            decode_section(image, address_space.image_base, bitness, section, &mut instrs, &mut va_to_idx);
        }

        Self { instrs, va_to_idx }
    }

    pub fn len(&self) -> usize {
        self.instrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instrs.is_empty()
    }

    pub fn at_va(&self, va: u64) -> Option<&DecodedInstr> {
        self.va_to_idx.get(&va).and_then(|&idx| self.instrs.get(idx))
    }

    #[allow(dead_code)] // Used by future index-based windowing callers
    pub fn idx_for_va(&self, va: u64) -> Option<usize> {
        self.va_to_idx.get(&va).copied()
    }

    /// Returns `count` instructions starting at the index closest to `va` (floor).
    pub fn window(&self, va: u64, count: usize) -> &[DecodedInstr] {
        let idx = self.va_to_idx.range(..=va).next_back().map(|(_, &i)| i).unwrap_or(0);
        let end = (idx + count).min(self.instrs.len());
        &self.instrs[idx..end]
    }

    pub fn iter(&self) -> impl Iterator<Item = &DecodedInstr> {
        self.instrs.iter()
    }

    /// Previous decoded instruction before `va` in linear-sweep order, if any.
    pub fn instruction_before(&self, va: u64) -> Option<&DecodedInstr> {
        let idx = self.va_to_idx.get(&va).copied()?;
        if idx == 0 {
            return None;
        }
        self.instrs.get(idx - 1)
    }
}

fn decode_section(
    image: &[u8],
    image_base: u64,
    bitness: u32,
    section: &Section,
    instrs: &mut Vec<DecodedInstr>,
    va_to_idx: &mut BTreeMap<u64, usize>,
) {
    let raw_start = section.raw_addr as usize;
    let raw_end = raw_start.saturating_add(section.raw_size as usize).min(image.len());
    if raw_start >= image.len() || raw_end <= raw_start {
        return;
    }

    let section_bytes = &image[raw_start..raw_end];
    let base_ip = image_base.saturating_add(u64::from(section.vaddr));
    let mut offset: usize = 0;

    while offset < section_bytes.len() {
        let ip = base_ip.saturating_add(offset as u64);
        let mut decoder = Decoder::with_ip(
            bitness,
            &section_bytes[offset..],
            ip,
            DecoderOptions::NONE,
        );
        let instr = decoder.decode();

        // Robustness: invalid bytes advance by one and retry.
        if instr.code() == Code::INVALID && instr.len() == 0 {
            offset = offset.saturating_add(1);
            continue;
        }

        let len = instr.len();
        if len == 0 {
            offset = offset.saturating_add(1);
            continue;
        }

        let mut bytes = [0u8; 16];
        let available = section_bytes[offset..].len().min(16).min(len);
        bytes[..available].copy_from_slice(&section_bytes[offset..offset + available]);

        va_to_idx.insert(ip, instrs.len());
        instrs.push(DecodedInstr {
            ip,
            len: len as u8,
            bytes,
            instr,
        });

        offset = offset.saturating_add(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_index() {
        let space = AddressSpace {
            image_base: 0x1_4000_0000,
            sections: vec![],
        };
        let idx = CodeIndex::build(&[], &space, 64);
        assert!(idx.is_empty());
    }
}
