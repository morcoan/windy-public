//! PE debug directory reader plus a byte-scan fallback that can recover a
//! CodeView PDB70 record even when the debug directory has been stripped.

use uuid::Uuid;

/// Parsed CodeView PDB70 record: the key needed to hit a symbol server.
#[derive(Clone, Debug)]
pub struct CodeViewRecord {
    pub guid: Uuid,
    pub age: u32,
    pub pdb_name: String,
}

impl CodeViewRecord {
    /// Symsrv-style cache key: lowercase hex of the GUID immediately followed
    /// by the decimal age, e.g. `abcdef...123`.
    pub fn guid_age(&self) -> String {
        format!("{}{}", self.guid.simple(), self.age)
    }

    /// Basename of the PDB (last path component).
    pub fn pdb_basename(&self) -> String {
        std::path::Path::new(&self.pdb_name)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| self.pdb_name.clone())
    }
}

const IMAGE_DEBUG_DIRECTORY_SIZE: usize = 28;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const RSDS: &[u8; 4] = b"RSDS";

/// Try the PE debug directory, then fall back to scanning the image for an
/// `RSDS` record. The scan is the "creative" bypass for packed/stripped
/// binaries: many packers erase the directory but leave the bytes.
pub fn find_codeview_record(image: &[u8]) -> Option<CodeViewRecord> {
    if let Some(rec) = find_codeview_in_debug_directory(image) {
        return Some(rec);
    }
    scan_image_for_rsds(image)
}

fn find_codeview_in_debug_directory(image: &[u8]) -> Option<CodeViewRecord> {
    let (debug_offset, debug_size) = debug_directory_location(image)?;
    if debug_size < IMAGE_DEBUG_DIRECTORY_SIZE as u32 {
        return None;
    }
    let debug_bytes = image.get(debug_offset..debug_offset.checked_add(debug_size as usize)?)?;
    let count = debug_bytes.len() / IMAGE_DEBUG_DIRECTORY_SIZE;

    for i in 0..count {
        let entry =
            &debug_bytes[i * IMAGE_DEBUG_DIRECTORY_SIZE..(i + 1) * IMAGE_DEBUG_DIRECTORY_SIZE];
        let ty = read_u32_le(&entry[12..16]);
        if ty != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let size_data = read_u32_le(&entry[16..20]) as usize;
        let ptr_raw = read_u32_le(&entry[24..28]) as usize;
        return parse_pdb70_at_offset(image, ptr_raw, size_data);
    }
    None
}

fn debug_directory_location(image: &[u8]) -> Option<(usize, u32)> {
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
    if optional_offset.saturating_add(2) > image.len() {
        return None;
    }
    let magic = read_u16_le(&image[optional_offset..optional_offset + 2]);

    // NumberOfRvaAndSizes is at the end of the Windows-specific fields.
    let (num_dirs_offset, data_dirs_offset): (usize, usize) = match magic {
        0x10b => (92, 96),   // PE32
        0x20b => (108, 112), // PE32+
        _ => return None,
    };

    let num_dirs_addr = optional_offset + num_dirs_offset;
    if num_dirs_addr.saturating_add(4) > image.len() {
        return None;
    }
    let num_dirs = read_u32_le(&image[num_dirs_addr..num_dirs_addr + 4]) as usize;
    if num_dirs <= 4 {
        return None; // debug directory index 4 not present
    }

    let debug_entry_offset = optional_offset + data_dirs_offset + 4 * 8;
    if debug_entry_offset.saturating_add(8) > image.len() {
        return None;
    }
    let rva = read_u32_le(&image[debug_entry_offset..debug_entry_offset + 4]);
    let size = read_u32_le(&image[debug_entry_offset + 4..debug_entry_offset + 8]);
    if rva == 0 || size == 0 {
        return None;
    }

    // Prefer the file offset via section mapping. The debug dir is normally
    // in an initialized section near the end of the image.
    let file_offset = rva_to_file_offset(image, rva as u64)?;
    Some((file_offset, size))
}

/// A minimal section table walk to convert a debug directory RVA to a file
/// offset. Only the first ten sections are searched; the debug directory is
/// almost always there.
fn rva_to_file_offset(image: &[u8], rva: u64) -> Option<usize> {
    let e_lfanew = read_u32_le(&image[0x3C..0x40]) as usize;
    let coff_offset = e_lfanew + 4;
    let num_sections = read_u16_le(&image[coff_offset + 2..coff_offset + 4]) as usize;
    let optional_size = read_u16_le(&image[coff_offset + 16..coff_offset + 18]) as usize;
    let optional_offset = coff_offset + 20;
    let section_table_offset = optional_offset + optional_size;

    for i in 0..num_sections.min(32) {
        let entry = section_table_offset + i * 40;
        if entry.saturating_add(40) > image.len() {
            break;
        }
        let vaddr = read_u32_le(&image[entry + 12..entry + 16]) as u64;
        let vsize = read_u32_le(&image[entry + 16..entry + 20]) as u64;
        let raw_addr = read_u32_le(&image[entry + 20..entry + 24]) as u64;
        let raw_size = read_u32_le(&image[entry + 24..entry + 28]) as u64;
        if rva >= vaddr && rva < vaddr.saturating_add(vsize) {
            let inside = rva - vaddr;
            if inside >= raw_size {
                return None;
            }
            return Some((raw_addr + inside) as usize);
        }
    }
    // Fallback: some tiny images map debug dir by raw pointer directly.
    if (rva as usize) < image.len() {
        return Some(rva as usize);
    }
    None
}

fn scan_image_for_rsds(image: &[u8]) -> Option<CodeViewRecord> {
    // Scanning the mapped file is fine; RSDS records are rare and the scan is
    // O(n). We use memchr-style 4-byte checks without allocating.
    let mut offset = 0;
    while offset + 24 < image.len() {
        if &image[offset..offset + 4] == RSDS
            && let Some(rec) = parse_pdb70_at_offset(image, offset, image.len() - offset)
            && rec.pdb_name.to_ascii_lowercase().ends_with(".pdb")
        {
            return Some(rec);
        }
        offset += 1;
    }
    None
}

fn parse_pdb70_at_offset(image: &[u8], offset: usize, size: usize) -> Option<CodeViewRecord> {
    if size < 24 {
        return None;
    }
    let rec = image.get(offset..offset.checked_add(size)?)?;
    // Signature already verified by caller; still require exactly RSDS.
    if &rec[0..4] != RSDS {
        return None;
    }
    let d1 = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
    let d2 = u16::from_le_bytes([rec[8], rec[9]]);
    let d3 = u16::from_le_bytes([rec[10], rec[11]]);
    let d4: [u8; 8] = rec[12..20].try_into().ok()?;
    let guid = Uuid::from_fields(d1, d2, d3, &d4);
    let age = u32::from_le_bytes([rec[20], rec[21], rec[22], rec[23]]);

    let name_start = 24;
    let name_bytes = rec
        .get(name_start..)?
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect::<Vec<u8>>();
    let pdb_name = String::from_utf8_lossy(&name_bytes).to_string();
    if pdb_name.is_empty() {
        return None;
    }
    Some(CodeViewRecord {
        guid,
        age,
        pdb_name,
    })
}

fn read_u16_le(bytes: &[u8]) -> u16 {
    let b: [u8; 2] = bytes[..2].try_into().unwrap_or_default();
    u16::from_le_bytes(b)
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let b: [u8; 4] = bytes[..4].try_into().unwrap_or_default();
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsds_scan_ignores_random_data() {
        let image = vec![0u8; 256];
        assert!(scan_image_for_rsds(&image).is_none());
    }
}
