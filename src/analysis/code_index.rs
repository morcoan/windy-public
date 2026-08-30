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
}

impl CodeIndex {
    pub fn build(image: &[u8], address_space: &AddressSpace, bitness: u32) -> Self {
        let mut sections: Vec<_> = address_space.exec_sections().collect();
        sections.sort_unstable_by_key(|section| section.vaddr);
        let estimated_instructions = sections
            .iter()
            .map(|section| section.raw_size as usize / 4)
            .sum();
        let mut instrs = Vec::with_capacity(estimated_instructions);

        for section in sections {
            decode_section(
                image,
                address_space.image_base,
                bitness,
                section,
                &mut instrs,
            );
        }

        // The VA-sorted vector is the index. An auxiliary entry-per-instruction
        // hash table dominated memory on large binaries and duplicated facts
        // already present here. Exact and floor lookups remain logarithmic.
        Self { instrs }
    }

    pub fn len(&self) -> usize {
        self.instrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instrs.is_empty()
    }

    pub fn at_va(&self, va: u64) -> Option<&DecodedInstr> {
        self.idx_for_va(va).and_then(|idx| self.instrs.get(idx))
    }

    pub fn idx_for_va(&self, va: u64) -> Option<usize> {
        self.instrs
            .binary_search_by_key(&va, |instruction| instruction.ip)
            .ok()
    }

    /// Returns `count` instructions starting at the index closest to `va` (floor).
    pub fn window(&self, va: u64, count: usize) -> &[DecodedInstr] {
        let idx = match self
            .instrs
            .binary_search_by_key(&va, |instruction| instruction.ip)
        {
            Ok(index) => index,
            Err(0) => 0,
            Err(index) => index - 1,
        };
        let end = (idx + count).min(self.instrs.len());
        &self.instrs[idx..end]
    }

    pub fn iter(&self) -> impl Iterator<Item = &DecodedInstr> {
        self.instrs.iter()
    }

    /// Previous decoded instruction before `va` in linear-sweep order, if any.
    pub fn instruction_before(&self, va: u64) -> Option<&DecodedInstr> {
        let idx = self.idx_for_va(va)?;
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
) {
    let raw_start = section.raw_addr as usize;
    let raw_end = raw_start
        .saturating_add(section.raw_size as usize)
        .min(image.len());
    if raw_start >= image.len() || raw_end <= raw_start {
        return;
    }

    let section_bytes = &image[raw_start..raw_end];
    let base_ip = image_base.saturating_add(u64::from(section.vaddr));
    let mut decoder = Decoder::with_ip(bitness, section_bytes, base_ip, DecoderOptions::NONE);

    // Reusing one decoder is materially faster on multi-million-instruction
    // images than reconstructing a decoder over the remaining slice for every
    // instruction.
    while decoder.can_decode() {
        let instr = decoder.decode();
        let ip = instr.ip();
        let offset = ip.saturating_sub(base_ip) as usize;

        // iced advances over invalid encodings. A zero-length result can only
        // occur at an exhausted/malformed tail; stop rather than spin.
        if instr.code() == Code::INVALID && instr.len() == 0 {
            break;
        }

        let len = instr.len();
        if len == 0 {
            break;
        }

        let mut bytes = [0u8; 16];
        let available = section_bytes[offset..].len().min(16).min(len);
        bytes[..available].copy_from_slice(&section_bytes[offset..offset + available]);

        instrs.push(DecodedInstr {
            ip,
            len: len as u8,
            bytes,
            instr,
        });
        if instrs.len() % 1_000_000 == 0 {
            tracing::info!(
                "Decoded {} million instructions...",
                instrs.len() / 1_000_000
            );
        }
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

    #[test]
    fn executable_sections_are_sorted_and_exact_lookup_is_stable() {
        // Two executable sections deliberately supplied in reverse VA order.
        let image = [0x90, 0xc3, 0, 0, 0x90, 0xc3];
        let space = AddressSpace {
            image_base: 0x1_4000_0000,
            sections: vec![
                Section {
                    vaddr: 0x2000,
                    vsize: 2,
                    raw_addr: 4,
                    raw_size: 2,
                    characteristics: 0x6000_0020,
                },
                Section {
                    vaddr: 0x1000,
                    vsize: 2,
                    raw_addr: 0,
                    raw_size: 2,
                    characteristics: 0x6000_0020,
                },
            ],
        };
        let idx = CodeIndex::build(&image, &space, 64);
        let low = space.image_base + 0x1000;
        let high = space.image_base + 0x2000;

        assert_eq!(idx.len(), 4);
        assert_eq!(
            idx.instrs.first().map(|instruction| instruction.ip),
            Some(low)
        );
        assert_eq!(
            idx.instrs.last().map(|instruction| instruction.ip),
            Some(high + 1)
        );
        assert_eq!(
            idx.at_va(high).map(|instruction| instruction.ip),
            Some(high)
        );
        assert_eq!(idx.idx_for_va(high), Some(2));
        assert_eq!(idx.window(low + 0x800, 1)[0].ip, low + 1);
        assert_eq!(
            idx.instruction_before(high + 1)
                .map(|instruction| instruction.ip),
            Some(high)
        );
    }
}
