//! Reconstruct an on-disk-like PE from a dump module's in-memory image.
//!
//! Full-memory user dumps store modules at their runtime base with the PE
//! mapped as the loader sees it (headers + sections at RVAs). Analysis expects
//! file-layout PE bytes. We:
//! 1. Copy present pages from the process memory map into a SizeOfImage buffer.
//! 2. Patch section headers so `PointerToRawData == VirtualAddress` and
//!    `FileAlignment == SectionAlignment`.
//! 3. Patch `ImageBase` to the runtime base so VAs match the live process.
//!
//! The result can be written and opened with the normal PE pipeline.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::{DumpModule, LoadedDump, ReadStatus};

/// Cap module extraction to avoid multi-GB single-module blowups.
const MAX_MODULE_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

/// Result of extracting a dump module into a PE-like image file.
#[derive(Clone, Debug)]
pub struct ExtractedModulePe {
    pub path: PathBuf,
    pub runtime_base: u64,
    pub size: u64,
    pub present_bytes: u64,
    pub module_name: String,
    pub identity_key: String,
}

impl LoadedDump {
    /// Extract `module` into a reconstructed PE under `out_dir` and return its path.
    pub fn extract_module_pe(
        &self,
        module: &DumpModule,
        out_dir: impl AsRef<Path>,
    ) -> Result<ExtractedModulePe> {
        if module.size == 0 {
            bail!("module {} has zero size", module.name);
        }
        if module.size > MAX_MODULE_IMAGE_BYTES {
            bail!(
                "module {} is {:.1} MiB (cap {} MiB); refuse full extract",
                module.name,
                module.size as f64 / (1024.0 * 1024.0),
                MAX_MODULE_IMAGE_BYTES / (1024 * 1024)
            );
        }
        if !module.has_pe_headers {
            bail!(
                "module {} @ {:#x} has no PE headers in the dump",
                module.name,
                module.base
            );
        }

        let size = module.size as usize;
        let mut image = vec![0u8; size];
        let mut present = 0u64;

        // Copy mapped ranges that intersect [base, base+size).
        let page = self.memory_map.regions_page(0, self.memory_map.region_count());
        let mod_end = module.base.saturating_add(module.size);
        for region in page {
            let r_end = region.va_start.saturating_add(region.size);
            if r_end <= module.base || region.va_start >= mod_end {
                continue;
            }
            let lo = region.va_start.max(module.base);
            let hi = r_end.min(mod_end);
            let copy_len = (hi - lo) as usize;
            let dst_off = (lo - module.base) as usize;
            match self.memory_map.read_at(lo, copy_len) {
                ReadStatus::Ok(bytes) | ReadStatus::Partial(bytes) => {
                    let n = bytes.len().min(copy_len).min(size.saturating_sub(dst_off));
                    if n > 0 {
                        image[dst_off..dst_off + n].copy_from_slice(&bytes[..n]);
                        present += n as u64;
                    }
                }
                ReadStatus::Unmapped => {}
            }
        }

        if present == 0 {
            bail!(
                "module {} @ {:#x}: no pages present in dump",
                module.name,
                module.base
            );
        }
        if image.len() < 0x40 || &image[0..2] != b"MZ" {
            bail!(
                "module {} @ {:#x}: extracted image is not a PE (missing MZ)",
                module.name,
                module.base
            );
        }

        patch_memory_image_as_pe(&mut image, module.base)
            .with_context(|| format!("patch PE headers for {}", module.name))?;

        let out_dir = out_dir.as_ref();
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("create {}", out_dir.display()))?;

        let safe_name = sanitize_module_filename(&module.name);
        let identity_key = format!(
            "dmpmod:{}:{}:{:x}:{:x}:{:x}",
            self.identity.session_key,
            safe_name.to_ascii_lowercase(),
            module.timestamp,
            module.size,
            module.checksum
        );
        let file_name = format!("{safe_name}_{:x}.pe.bin", module.base);
        let path = out_dir.join(&file_name);
        std::fs::write(&path, &image)
            .with_context(|| format!("write extracted PE {}", path.display()))?;

        tracing::info!(
            "Extracted dump module {} → {} ({:.1} MiB present / {:.1} MiB size, base={:#x})",
            module.name,
            path.display(),
            present as f64 / (1024.0 * 1024.0),
            module.size as f64 / (1024.0 * 1024.0),
            module.base
        );

        Ok(ExtractedModulePe {
            path,
            runtime_base: module.base,
            size: module.size,
            present_bytes: present,
            module_name: module.name.clone(),
            identity_key,
        })
    }
}

fn sanitize_module_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let mut out = String::with_capacity(base.len());
    for c in base.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("module");
    }
    out
}

/// Rewrite section table / optional header so the memory image is a valid PE file.
fn patch_memory_image_as_pe(image: &mut [u8], runtime_base: u64) -> Result<()> {
    if image.len() < 0x40 {
        bail!("image too small for DOS header");
    }
    let e_lfanew = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew.saturating_add(24) > image.len() {
        bail!("invalid e_lfanew");
    }
    if &image[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("missing PE signature");
    }
    let coff = e_lfanew + 4;
    let num_sections =
        u16::from_le_bytes(image[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_optional_header =
        u16::from_le_bytes(image[coff + 16..coff + 18].try_into().unwrap()) as usize;
    let opt = coff + 20;
    if opt + 2 > image.len() {
        bail!("truncated optional header");
    }
    let magic = u16::from_le_bytes(image[opt..opt + 2].try_into().unwrap());
    let (file_align_off, sect_align_off, image_base_off, image_base_size) = match magic {
        0x10b => (0x24usize, 0x20usize, 0x1Cusize, 4usize), // PE32
        0x20b => (0x24usize, 0x20usize, 0x18usize, 8usize), // PE32+
        _ => bail!("unknown optional header magic {magic:#x}"),
    };
    if opt + size_of_optional_header > image.len() {
        bail!("optional header extends past image");
    }

    // FileAlignment := SectionAlignment so raw offsets can equal RVAs.
    let sect_align = u32::from_le_bytes(
        image[opt + sect_align_off..opt + sect_align_off + 4]
            .try_into()
            .unwrap(),
    );
    if sect_align > 0 {
        image[opt + file_align_off..opt + file_align_off + 4]
            .copy_from_slice(&sect_align.to_le_bytes());
    }

    // ImageBase := runtime base (so VA math matches the process).
    match image_base_size {
        4 => {
            let v = (runtime_base & 0xffff_ffff) as u32;
            image[opt + image_base_off..opt + image_base_off + 4]
                .copy_from_slice(&v.to_le_bytes());
        }
        8 => {
            image[opt + image_base_off..opt + image_base_off + 8]
                .copy_from_slice(&runtime_base.to_le_bytes());
        }
        _ => unreachable!(),
    }

    let section_table = opt + size_of_optional_header;
    const SECTION_SIZE: usize = 40;
    for i in 0..num_sections {
        let sh = section_table + i * SECTION_SIZE;
        if sh + SECTION_SIZE > image.len() {
            break;
        }
        let virtual_size =
            u32::from_le_bytes(image[sh + 8..sh + 12].try_into().unwrap());
        let virtual_address =
            u32::from_le_bytes(image[sh + 12..sh + 16].try_into().unwrap());
        let mut size_of_raw =
            u32::from_le_bytes(image[sh + 16..sh + 20].try_into().unwrap());
        // Prefer virtual size for memory images (covers BSS-like tails present as zero).
        if virtual_size > size_of_raw {
            size_of_raw = virtual_size;
        }
        // PointerToRawData = VirtualAddress (memory layout).
        image[sh + 20..sh + 24].copy_from_slice(&virtual_address.to_le_bytes());
        image[sh + 16..sh + 20].copy_from_slice(&size_of_raw.to_le_bytes());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_chars() {
        assert_eq!(
            sanitize_module_filename(r"C:\Windows\System32\ntdll.dll"),
            "ntdll.dll"
        );
    }
}
