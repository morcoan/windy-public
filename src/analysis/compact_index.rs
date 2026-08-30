//! Eight-byte instruction metadata partitions for explicit deep indexing.

use std::path::Path;

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstrMeta {
    pub rva: u32,
    pub flags: u16,
    pub len: u8,
    pub opcode_class: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionIndex {
    pub rva: u32,
    pub records: Vec<InstrMeta>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactIndex {
    pub sections: Vec<SectionIndex>,
    pub instructions: usize,
    pub elapsed_ms: u128,
    #[serde(default)]
    pub cache_hit: bool,
}

const FLAG_MEMORY: u16 = 1 << 0;
const FLAG_CONDITIONAL: u16 = 1 << 1;
const FLAG_INDIRECT: u16 = 1 << 2;
const FLAG_TERMINATOR: u16 = 1 << 3;

pub fn build_from_path(path: &Path) -> Result<CompactIndex> {
    let started = std::time::Instant::now();
    let pe = crate::loader::pe::LoadedPe::open_catalog(path)?;
    let optional = pe.triage.optional_header.as_ref();
    let sections = pe.triage.sections.as_deref().unwrap_or_default();
    let image_base = optional.map(|header| header.image_base).unwrap_or_default();
    let address_space = crate::loader::address_space::AddressSpace::new(image_base, sections);
    let magic = optional
        .map(|header| header.magic.as_str())
        .unwrap_or("PE32");
    let bitness = address_space.bitness(magic);
    let mut partitions = Vec::new();
    let mut instructions = 0usize;
    for section in address_space.exec_sections() {
        let start = section.raw_addr as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(pe.image.len());
        if start >= end {
            continue;
        }
        let section_va = image_base.saturating_add(u64::from(section.vaddr));
        let mut decoder = Decoder::with_ip(
            bitness,
            &pe.image[start..end],
            section_va,
            DecoderOptions::NONE,
        );
        let mut records = Vec::with_capacity((end - start) / 4);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.len() == 0 {
                break;
            }
            let rva = instruction.ip().saturating_sub(image_base);
            let Ok(rva) = u32::try_from(rva) else {
                continue;
            };
            let mut flags = 0u16;
            if (0..instruction.op_count()).any(|index| instruction.op_kind(index) == OpKind::Memory)
            {
                flags |= FLAG_MEMORY;
            }
            if instruction.flow_control() == FlowControl::ConditionalBranch {
                flags |= FLAG_CONDITIONAL;
            }
            if matches!(
                instruction.flow_control(),
                FlowControl::IndirectBranch | FlowControl::IndirectCall
            ) {
                flags |= FLAG_INDIRECT;
            }
            if matches!(
                instruction.flow_control(),
                FlowControl::Return
                    | FlowControl::UnconditionalBranch
                    | FlowControl::IndirectBranch
                    | FlowControl::Exception
            ) {
                flags |= FLAG_TERMINATOR;
            }
            records.push(InstrMeta {
                rva,
                flags,
                len: instruction.len() as u8,
                opcode_class: opcode_class(instruction.mnemonic(), instruction.flow_control()),
            });
        }
        instructions += records.len();
        partitions.push(SectionIndex {
            rva: section.vaddr,
            records,
        });
    }
    Ok(CompactIndex {
        sections: partitions,
        instructions,
        elapsed_ms: started.elapsed().as_millis(),
        cache_hit: false,
    })
}

pub fn load_or_build_cached(
    path: &Path,
    cache_root: &Path,
    image_sha256: &str,
    bitness: u32,
) -> Result<CompactIndex> {
    let started = std::time::Instant::now();
    let abi = format!("v3-deep-1-{bitness}-default");
    let cache_path =
        crate::analysis::structural_cache::partition_path(cache_root, "deep", image_sha256, &abi);
    if let Some(mut cached) =
        crate::analysis::structural_cache::load::<CompactIndex>(&cache_path, &abi, image_sha256)?
    {
        cached.elapsed_ms = started.elapsed().as_millis();
        cached.cache_hit = true;
        return Ok(cached);
    }
    let mut built = build_from_path(path)?;
    crate::analysis::structural_cache::store(&cache_path, &abi, image_sha256, &built)?;
    let _ = crate::analysis::structural_cache::prune_lru(
        &cache_root.join("structural"),
        crate::analysis::structural_cache::DEFAULT_MAX_BYTES,
    );
    built.cache_hit = false;
    Ok(built)
}

fn opcode_class(mnemonic: Mnemonic, flow: FlowControl) -> u8 {
    match flow {
        FlowControl::Call | FlowControl::IndirectCall => 2,
        FlowControl::Return => 3,
        FlowControl::ConditionalBranch
        | FlowControl::UnconditionalBranch
        | FlowControl::IndirectBranch => 1,
        _ => match mnemonic {
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Mul
            | Mnemonic::Imul
            | Mnemonic::Div
            | Mnemonic::Idiv => 4,
            Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Not
            | Mnemonic::Shl
            | Mnemonic::Shr => 5,
            Mnemonic::Cmp | Mnemonic::Test => 6,
            Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Push | Mnemonic::Pop => 7,
            _ => 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_record_is_exactly_eight_bytes() {
        assert_eq!(std::mem::size_of::<InstrMeta>(), 8);
    }
}
