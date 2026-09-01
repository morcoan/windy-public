//! Disk-backed eight-byte instruction metadata partitions for explicit deep indexing.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

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
    pub instructions: usize,
    pub file_offset: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactIndex {
    pub sections: Vec<SectionIndex>,
    pub instructions: usize,
    pub disk_bytes: u64,
    pub payload_sha256: String,
    pub elapsed_ms: u128,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(skip)]
    pub storage_path: Option<PathBuf>,
}

const FLAG_MEMORY: u16 = 1 << 0;
const FLAG_CONDITIONAL: u16 = 1 << 1;
const FLAG_INDIRECT: u16 = 1 << 2;
const FLAG_TERMINATOR: u16 = 1 << 3;
const WRITE_BUFFER_BYTES: usize = 1024 * 1024;

pub fn build_from_path(path: &Path) -> Result<CompactIndex> {
    let mut sink = std::io::sink();
    build_to_writer(path, &mut sink, None)
}

fn build_to_writer(
    path: &Path,
    writer: &mut dyn Write,
    storage_path: Option<PathBuf>,
) -> Result<CompactIndex> {
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
    let mut disk_bytes = 0u64;
    let mut digest = Sha256::new();
    let mut buffer = Vec::with_capacity(WRITE_BUFFER_BYTES);
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
        let section_offset =
            (instructions as u64).saturating_mul(std::mem::size_of::<InstrMeta>() as u64);
        let mut section_instructions = 0usize;
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
            let record = InstrMeta {
                rva,
                flags,
                len: instruction.len() as u8,
                opcode_class: opcode_class(instruction.mnemonic(), instruction.flow_control()),
            };
            buffer.extend_from_slice(&record.rva.to_le_bytes());
            buffer.extend_from_slice(&record.flags.to_le_bytes());
            buffer.push(record.len);
            buffer.push(record.opcode_class);
            section_instructions += 1;
            if buffer.len() >= WRITE_BUFFER_BYTES {
                writer.write_all(&buffer)?;
                digest.update(&buffer);
                disk_bytes = disk_bytes.saturating_add(buffer.len() as u64);
                buffer.clear();
            }
        }
        instructions += section_instructions;
        let section_bytes =
            (section_instructions as u64).saturating_mul(std::mem::size_of::<InstrMeta>() as u64);
        partitions.push(SectionIndex {
            rva: section.vaddr,
            instructions: section_instructions,
            file_offset: section_offset,
            bytes: section_bytes,
        });
    }
    if !buffer.is_empty() {
        writer.write_all(&buffer)?;
        digest.update(&buffer);
        disk_bytes = disk_bytes.saturating_add(buffer.len() as u64);
    }
    writer.flush()?;
    Ok(CompactIndex {
        sections: partitions,
        instructions,
        disk_bytes,
        payload_sha256: format!("{:x}", digest.finalize()),
        elapsed_ms: started.elapsed().as_millis(),
        cache_hit: false,
        storage_path,
    })
}

pub fn load_or_build_cached(
    path: &Path,
    cache_root: &Path,
    image_sha256: &str,
    bitness: u32,
) -> Result<CompactIndex> {
    let started = std::time::Instant::now();
    let abi = format!("v3-deep-2-{bitness}-disk");
    let cache_path =
        crate::analysis::structural_cache::partition_path(cache_root, "deep", image_sha256, &abi);
    let data_path = cache_path.with_extension("bin");
    if let Some(mut cached) =
        crate::analysis::structural_cache::load::<CompactIndex>(&cache_path, &abi, image_sha256)?
        && data_path
            .metadata()
            .is_ok_and(|metadata| metadata.len() == cached.disk_bytes)
    {
        cached.elapsed_ms = started.elapsed().as_millis();
        cached.cache_hit = true;
        cached.storage_path = Some(data_path);
        return Ok(cached);
    }
    let parent = data_path
        .parent()
        .context("deep-index cache path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".tmp-deep-{}.bin", Uuid::new_v4()));
    let file = File::create(&temporary)
        .with_context(|| format!("create deep-index partition {}", temporary.display()))?;
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_BYTES, file);
    let mut built = match build_to_writer(path, &mut writer, Some(data_path.clone())) {
        Ok(index) => index,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    writer.into_inner()?.sync_all()?;
    if data_path.exists() {
        fs::remove_file(&data_path)?;
    }
    fs::rename(&temporary, &data_path)
        .with_context(|| format!("install deep-index partition {}", data_path.display()))?;
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

    #[test]
    fn section_manifest_is_bounded_independent_of_instruction_count() {
        assert!(std::mem::size_of::<SectionIndex>() <= 32);
    }

    #[test]
    fn cached_index_streams_records_to_disk() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("eval/fixtures/pe/sample.exe");
        assert!(fixture.exists(), "sample.exe fixture is required");
        let root = std::env::temp_dir().join(format!("windy-deep-cache-test-{}", Uuid::new_v4()));
        let image_sha256 = crate::analysis::structural_cache::hash_path(&fixture).unwrap();
        let index = load_or_build_cached(&fixture, &root, &image_sha256, 64).unwrap();
        assert!(index.instructions > 0);
        assert_eq!(
            index.disk_bytes,
            (index.instructions * std::mem::size_of::<InstrMeta>()) as u64
        );
        let storage = index.storage_path.as_ref().expect("disk-backed path");
        assert_eq!(storage.metadata().unwrap().len(), index.disk_bytes);
        assert!(
            index
                .sections
                .iter()
                .all(|section| section.records_are_bounded())
        );
        let warm = load_or_build_cached(&fixture, &root, &image_sha256, 64).unwrap();
        assert!(warm.cache_hit);
        assert_eq!(warm.disk_bytes, index.disk_bytes);
        let _ = fs::remove_dir_all(root);
    }
}

impl SectionIndex {
    #[cfg(test)]
    fn records_are_bounded(&self) -> bool {
        self.bytes == (self.instructions * std::mem::size_of::<InstrMeta>()) as u64
    }
}
