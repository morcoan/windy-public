//! Manual import-table parser. Unlike petriage's name-only list, this recovers
//! the IAT slot virtual addresses so we can emit `__imp_<Api>` symbols.

use crate::loader::address_space::AddressSpace;

const IMAGE_IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

/// One entry in the import address table, paired with its name.
#[derive(Clone, Debug)]
pub struct ImportSlot {
    #[allow(dead_code)] // DLL name retained for import-tree UI
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// Virtual address of the IAT slot that the loader overwrites.
    pub iat_va: u64,
}

/// Parse the import directory and return a slot for every IAT entry.
pub fn parse_import_slots(
    image: &[u8],
    address_space: &AddressSpace,
    image_base: u64,
    bitness: u32,
) -> Option<Vec<ImportSlot>> {
    let (import_desc_rva, import_size) = import_directory_rva(image)?;
    if import_size == 0 {
        return Some(Vec::new());
    }
    let ptr_size = (bitness / 8) as usize;
    let desc_va = image_base + u64::from(import_desc_rva);
    let desc_bytes = address_space.slice_for_va(image, desc_va, import_size as usize)?;
    let max_descriptors = desc_bytes.len() / IMAGE_IMPORT_DESCRIPTOR_SIZE;

    let mut slots = Vec::new();
    for i in 0..max_descriptors {
        let off = i * IMAGE_IMPORT_DESCRIPTOR_SIZE;
        let desc = &desc_bytes[off..off + IMAGE_IMPORT_DESCRIPTOR_SIZE];
        let original_first_thunk = read_u32_le(&desc[0..4]);
        let name_rva = read_u32_le(&desc[12..16]);
        let first_thunk = read_u32_le(&desc[16..20]);

        if first_thunk == 0 {
            break; // null terminator
        }
        if name_rva == 0 {
            continue;
        }

        let dll = read_ascii_at_rva(image, address_space, image_base, name_rva)?;
        let ilt_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let iat_start_va = image_base + u64::from(first_thunk);

        let mut idx = 0usize;
        loop {
            let entry_va = image_base + u64::from(ilt_rva) + (idx * ptr_size) as u64;
            let entry_bytes = address_space.slice_for_va(image, entry_va, ptr_size)?;
            let entry = if ptr_size == 8 {
                read_u64_le(entry_bytes)
            } else {
                u64::from(read_u32_le(entry_bytes))
            };
            if entry == 0 {
                break;
            }

            let iat_va = iat_start_va + (idx * ptr_size) as u64;
            let is_ordinal = if ptr_size == 8 {
                (entry & (1u64 << 63)) != 0
            } else {
                (entry & (1u32 << 31) as u64) != 0
            };

            let (name, ordinal) = if is_ordinal {
                (
                    None,
                    Some((entry & 0xffff) as u16), // ordinal is low 16 bits
                )
            } else {
                let import_by_name_rva = (entry & 0xffff_ffff) as u32;
                (
                    read_ascii_at_rva(image, address_space, image_base, import_by_name_rva + 2),
                    None,
                )
            };

            slots.push(ImportSlot {
                dll: dll.clone(),
                name: name.clone(),
                ordinal,
                iat_va,
            });
            idx += 1;
        }
    }

    Some(slots)
}

fn import_directory_rva(image: &[u8]) -> Option<(u32, u32)> {
    if image.len() < 0x40 {
        return None;
    }
    let e_lfanew = read_u32_le(&image[0x3C..0x40]) as usize;
    let pe_offset = e_lfanew;
    if pe_offset.saturating_add(24) > image.len() {
        return None;
    }
    if &image[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
        return None;
    }
    let coff_offset = pe_offset + 4;
    let optional_offset = coff_offset + 20;
    let magic = read_u16_le(&image[optional_offset..optional_offset + 2]);

    let (data_dirs_offset, num_dirs_offset): (usize, usize) = match magic {
        0x10b => (96, 92),
        0x20b => (112, 108),
        _ => return None,
    };

    let num_dirs = read_u32_le(
        &image[optional_offset + num_dirs_offset..optional_offset + num_dirs_offset + 4],
    ) as usize;
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_IMPORT {
        return None;
    }

    let entry_offset = optional_offset + data_dirs_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
    if entry_offset.saturating_add(8) > image.len() {
        return None;
    }
    let rva = read_u32_le(&image[entry_offset..entry_offset + 4]);
    let size = read_u32_le(&image[entry_offset + 4..entry_offset + 8]);
    if rva == 0 || size == 0 {
        return None;
    }
    Some((rva, size))
}

fn read_ascii_at_rva(
    image: &[u8],
    address_space: &AddressSpace,
    image_base: u64,
    rva: u32,
) -> Option<String> {
    let va = image_base + u64::from(rva);
    let bytes = address_space.slice_for_va(image, va, 256)?;
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..len]).to_string())
}

fn read_u16_le(bytes: &[u8]) -> u16 {
    let b: [u8; 2] = bytes[..2.min(bytes.len())].try_into().unwrap_or_default();
    u16::from_le_bytes(b)
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let b: [u8; 4] = bytes[..4.min(bytes.len())].try_into().unwrap_or_default();
    u32::from_le_bytes(b)
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let b: [u8; 8] = bytes[..8.min(bytes.len())].try_into().unwrap_or_default();
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_image_returns_none() {
        let space = AddressSpace {
            image_base: 0,
            sections: vec![],
        };
        assert!(parse_import_slots(&[], &space, 0, 64).is_none());
    }
}
