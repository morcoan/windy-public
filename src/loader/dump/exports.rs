//! Lightweight PE export-name lookup from dump process memory (no full project open).

use super::{LoadedDump, ReadStatus};

/// Resolve `va` to `module!export` or `module+offset` using dump modules.
pub fn resolve_va_symbol(dump: &LoadedDump, va: u64) -> Option<String> {
    let module = dump.module_at(va)?;
    let offset = va.saturating_sub(module.base);
    if let Some(name) = export_name_at(dump, module.base, module.size, offset) {
        return Some(format!("{}!{}", module.name, name));
    }
    Some(format!("{}+{:#x}", module.name, offset))
}

/// Look up an export whose RVA equals `rva` (offset from module base).
fn export_name_at(dump: &LoadedDump, base: u64, size: u64, rva: u64) -> Option<String> {
    // Read PE headers at base.
    let hdr = read_bytes(dump, base, 0x200)?;
    if hdr.len() < 0x40 || &hdr[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(hdr[0x3C..0x40].try_into().ok()?) as u64;
    let pe_hdr = read_bytes(dump, base + e_lfanew, 0x200)?;
    if pe_hdr.len() < 24 || &pe_hdr[0..4] != b"PE\0\0" {
        return None;
    }
    let magic = u16::from_le_bytes(pe_hdr[24..26].try_into().ok()?);
    let export_dir_off = match magic {
        0x10b => 24 + 96, // PE32 optional + data dirs start
        0x20b => 24 + 112,
        _ => return None,
    };
    if pe_hdr.len() < export_dir_off + 8 {
        // Need more of optional header + data directories.
        let pe_hdr = read_bytes(dump, base + e_lfanew, export_dir_off + 8)?;
        if pe_hdr.len() < export_dir_off + 8 {
            return None;
        }
        return export_name_from_dir(dump, base, size, rva, &pe_hdr, export_dir_off);
    }
    export_name_from_dir(dump, base, size, rva, &pe_hdr, export_dir_off)
}

fn export_name_from_dir(
    dump: &LoadedDump,
    base: u64,
    size: u64,
    rva: u64,
    pe_hdr: &[u8],
    export_dir_off: usize,
) -> Option<String> {
    let export_rva = u32::from_le_bytes(pe_hdr[export_dir_off..export_dir_off + 4].try_into().ok()?);
    let export_size =
        u32::from_le_bytes(pe_hdr[export_dir_off + 4..export_dir_off + 8].try_into().ok()?);
    if export_rva == 0 || export_size < 40 {
        return None;
    }
    if u64::from(export_rva) >= size {
        return None;
    }
    let dir = read_bytes(dump, base + u64::from(export_rva), 40)?;
    if dir.len() < 40 {
        return None;
    }
    let num_functions = u32::from_le_bytes(dir[20..24].try_into().ok()?);
    let num_names = u32::from_le_bytes(dir[24..28].try_into().ok()?);
    let addr_table_rva = u32::from_le_bytes(dir[28..32].try_into().ok()?);
    let name_ptr_rva = u32::from_le_bytes(dir[32..36].try_into().ok()?);
    let ord_table_rva = u32::from_le_bytes(dir[36..40].try_into().ok()?);

    if num_functions == 0 || num_functions > 100_000 {
        return None;
    }

    // Scan name table: ordinal -> function index -> function RVA.
    let nnames = num_names.min(50_000);
    for i in 0..nnames {
        let name_rva_bytes = read_bytes(
            dump,
            base + u64::from(name_ptr_rva) + u64::from(i) * 4,
            4,
        )?;
        if name_rva_bytes.len() < 4 {
            continue;
        }
        let name_rva = u32::from_le_bytes(name_rva_bytes[0..4].try_into().ok()?);
        let ord_bytes = read_bytes(
            dump,
            base + u64::from(ord_table_rva) + u64::from(i) * 2,
            2,
        )?;
        if ord_bytes.len() < 2 {
            continue;
        }
        let ord = u16::from_le_bytes(ord_bytes[0..2].try_into().ok()?) as u32;
        if ord >= num_functions {
            continue;
        }
        let func_rva_bytes = read_bytes(
            dump,
            base + u64::from(addr_table_rva) + u64::from(ord) * 4,
            4,
        )?;
        if func_rva_bytes.len() < 4 {
            continue;
        }
        let func_rva = u32::from_le_bytes(func_rva_bytes[0..4].try_into().ok()?);
        if u64::from(func_rva) != rva {
            continue;
        }
        // Read ASCII name.
        let name_bytes = read_bytes(dump, base + u64::from(name_rva), 128)?;
        let len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        if len == 0 {
            return None;
        }
        return Some(String::from_utf8_lossy(&name_bytes[..len]).into_owned());
    }
    None
}

fn read_bytes(dump: &LoadedDump, va: u64, len: usize) -> Option<Vec<u8>> {
    match dump.read_at(va, len) {
        ReadStatus::Ok(b) => Some(b.to_vec()),
        ReadStatus::Partial(b) if !b.is_empty() => Some(b.to_vec()),
        _ => None,
    }
}
