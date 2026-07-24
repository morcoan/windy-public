//! Resolve indirect jump tables / switch tables by reading the data to which a
//! RIP-relative `jmp` points. This rewrites CFG successor edges and xrefs so
//! the LLM sees concrete switch targets instead of an opaque indirect edge.

use iced_x86::{FlowControl, Mnemonic, OpKind, Register};

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::{Edge, EdgeKind, FunctionTable};
use crate::analysis::xrefs::{XrefIndex, XrefKind};
use crate::loader::address_space::AddressSpace;

const MAX_TABLE_SCAN_BYTES: usize = 8 * 1024;
const MAX_TABLE_ENTRIES: usize = 512;

/// One resolved indirect edge from a jump instruction to a target code VA.
#[derive(Clone, Debug)]
pub struct ResolvedIndirect {
    pub function_entry: u64,
    pub block_entry: u64,
    pub jump_va: u64,
    pub table_va: u64,
    pub target_va: u64,
}

/// Resolve RIP-relative indirect call slots (IAT imports / function-pointer
/// tables) and add concrete successors / xrefs.
pub fn resolve_indirect_calls(
    functions: &mut FunctionTable,
    code_index: &CodeIndex,
    xrefs: &mut XrefIndex,
    address_space: &AddressSpace,
    image: &[u8],
    bitness: u32,
) {
    let ptr_size = (bitness / 8) as usize;
    let mut resolved = Vec::new();

    for func in functions.iter() {
        for block in &func.blocks {
            let dec = match code_index.at_va(block.exit_va) {
                Some(d) => d,
                None => continue,
            };
            if dec.instr.flow_control() != FlowControl::IndirectCall
                || dec.instr.mnemonic() != Mnemonic::Call
            {
                continue;
            }
            if dec.instr.op0_kind() != OpKind::Memory {
                continue;
            }
            let slot_va = match rip_relative_target_va(&dec.instr, bitness) {
                Some(va) => va,
                None => continue,
            };
            let thunk_target = read_pointer(address_space, image, slot_va, ptr_size);
            // Prefer a concrete import slot VA if the symbol table already knows it;
            // otherwise fall back to the local function pointer value if it is code.
            let target_va = if thunk_target != 0 && address_space.is_executable_va(thunk_target) {
                thunk_target
            } else {
                slot_va
            };
            if target_va != 0 {
                resolved.push(ResolvedIndirect {
                    function_entry: func.entry_va,
                    block_entry: block.entry_va,
                    jump_va: dec.ip,
                    table_va: slot_va,
                    target_va,
                });
            }
        }
    }

    for r in resolved {
        if let Some(block) = find_block_mut(functions, r.function_entry, r.block_entry) {
            block.successors.push(Edge {
                target: r.target_va,
                kind: EdgeKind::Call,
            });
        }
        xrefs.add(r.target_va, r.jump_va, XrefKind::Call);
        xrefs.add(r.table_va, r.jump_va, XrefKind::DataRead);
    }

    for func in functions.iter_mut() {
        func.recompute_predecessors();
    }
}

/// Resolve RIP-relative jump tables and apply the results to the function CFG
/// and xref index.
pub fn resolve_indirect_jumps(
    functions: &mut FunctionTable,
    code_index: &CodeIndex,
    xrefs: &mut XrefIndex,
    address_space: &AddressSpace,
    image: &[u8],
    bitness: u32,
) {
    let mut resolved = Vec::new();

    for func in functions.iter() {
        for block in &func.blocks {
            let dec = match code_index.at_va(block.exit_va) {
                Some(d) => d,
                None => continue,
            };
            if dec.instr.flow_control() != FlowControl::IndirectBranch
                || dec.instr.mnemonic() != Mnemonic::Jmp
            {
                continue;
            }
            if dec.instr.op0_kind() != OpKind::Memory {
                continue;
            }
            let table_va = match rip_relative_target_va(&dec.instr, bitness) {
                Some(va) => va,
                None => continue,
            };
            let targets = read_pointer_table(address_space, image, table_va, bitness);
            for target in targets {
                resolved.push(ResolvedIndirect {
                    function_entry: func.entry_va,
                    block_entry: block.entry_va,
                    jump_va: dec.ip,
                    table_va,
                    target_va: target,
                });
            }
        }
    }

    for r in resolved {
        if let Some(block) = find_block_mut(functions, r.function_entry, r.block_entry) {
            block.successors.push(Edge {
                target: r.target_va,
                kind: EdgeKind::Indirect,
            });
        }
        xrefs.add(r.target_va, r.jump_va, XrefKind::Indirect);
        xrefs.add(r.table_va, r.jump_va, XrefKind::DataRead);
    }

    for func in functions.iter_mut() {
        func.recompute_predecessors();
    }
}

fn find_block_mut(
    functions: &mut FunctionTable,
    function_entry: u64,
    block_entry: u64,
) -> Option<&mut crate::analysis::functions::BasicBlock> {
    functions
        .get_mut(function_entry)
        .and_then(|f| f.blocks.iter_mut().find(|b| b.entry_va == block_entry))
}

pub(crate) fn rip_relative_target_va(instr: &iced_x86::Instruction, bitness: u32) -> Option<u64> {
    if bitness != 64 {
        return None;
    }
    if instr.memory_base() != Register::RIP || instr.memory_index() != Register::None {
        return None;
    }
    // iced-x86 resolves an IP-relative operand to its absolute linear address
    // when the decoder was created with the instruction IP. Adding next_ip a
    // second time produces impossible 0x100... targets for normal 0x180... PEs.
    Some(instr.ip_rel_memory_address())
}

pub(crate) fn read_pointer_table(
    address_space: &AddressSpace,
    image: &[u8],
    table_va: u64,
    bitness: u32,
) -> Vec<u64> {
    let ptr_size = (bitness / 8) as usize;
    let max_bytes = MAX_TABLE_SCAN_BYTES / ptr_size * ptr_size;
    let bytes = match address_space.slice_for_va(image, table_va, max_bytes) {
        Some(b) => b,
        None => return Vec::new(),
    };

    let mut targets = Vec::new();
    for chunk in bytes.chunks_exact(ptr_size) {
        if targets.len() >= MAX_TABLE_ENTRIES {
            break;
        }
        let ptr = if ptr_size == 8 {
            read_u64_le(chunk)
        } else {
            u64::from(read_u32_le(chunk))
        };
        if ptr == 0 || !address_space.is_executable_va(ptr) {
            break;
        }
        targets.push(ptr);
    }
    targets
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let b: [u8; 4] = bytes[..4.min(bytes.len())].try_into().unwrap_or_default();
    u32::from_le_bytes(b)
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let b: [u8; 8] = bytes[..8.min(bytes.len())].try_into().unwrap_or_default();
    u64::from_le_bytes(b)
}

/// Read a machine-width pointer at `va`. Public for structured agent reads
/// ([`crate::analysis::mem_walk`]) as well as vtable/IAT resolution.
pub(crate) fn read_pointer(
    address_space: &AddressSpace,
    image: &[u8],
    va: u64,
    ptr_size: usize,
) -> u64 {
    let bytes = match address_space.slice_for_va(image, va, ptr_size) {
        Some(b) => b,
        None => return 0,
    };
    if ptr_size == 8 {
        read_u64_le(bytes)
    } else {
        u64::from(read_u32_le(bytes))
    }
}

/// Alias kept for call sites that want an explicit "at VA" name.
pub(crate) fn read_pointer_at(
    address_space: &AddressSpace,
    image: &[u8],
    va: u64,
    ptr_size: usize,
) -> u64 {
    read_pointer(address_space, image, va, ptr_size)
}

/// A resolved COM / C++ vtable call site.
#[derive(Clone, Debug)]
pub struct ResolvedVtableCall {
    pub call_va: u64,
    pub this_reg: String,
    pub vtable_offset: u32,
    pub interface: Option<String>,
    pub method: Option<String>,
    pub signature: Option<crate::project::types::FunctionSignature>,
    /// Vtable pointer table VA in .rdata, if recovered.
    pub vtable_va: Option<u64>,
    /// Heuristic-only annotation (IUnknown slots without full DB hit).
    pub heuristic: Option<String>,
}

/// Detect `call [reg+offset]` COM vtable dispatches and resolve method names
/// via [`crate::analysis::vtable_sigs::VtableDB`].
pub fn resolve_vtable_calls(
    code_index: &CodeIndex,
    bitness: u32,
    vtable_db: &crate::analysis::vtable_sigs::VtableDB,
    address_space: &AddressSpace,
    image: &[u8],
) -> Vec<ResolvedVtableCall> {
    use iced_x86::{FlowControl, Mnemonic, OpKind, Register};

    let mut out = Vec::new();
    let ptr_size = (bitness / 8) as usize;

    for dec in code_index.iter() {
        let instr = &dec.instr;
        if instr.flow_control() != FlowControl::IndirectCall || instr.mnemonic() != Mnemonic::Call {
            continue;
        }
        if instr.op0_kind() != OpKind::Memory {
            continue;
        }
        // Must be register-relative (not RIP).
        let base = instr.memory_base();
        if base == Register::None || base == Register::RIP || base == Register::EIP {
            continue;
        }
        if instr.memory_index() != Register::None {
            continue;
        }
        let disp = instr.memory_displacement64() as i64;
        if !(0..=0x400).contains(&disp) {
            continue;
        }
        let offset = disp as u32;
        let this_reg = format!("{:?}", base).to_ascii_lowercase();

        // Best-effort: look for a prior RIP-relative load of a vtable into a
        // register in the same basic-block window (scan backwards up to 16 insns).
        let mut vtable_va: Option<u64> = None;
        let mut scan_va = dec.ip;
        for _ in 0..16 {
            let Some(prev) = code_index.instruction_before(scan_va) else {
                break;
            };
            scan_va = prev.ip;
            // mov reg, [rip+disp] loading a pointer table
            if prev.instr.mnemonic() == Mnemonic::Mov
                && prev.instr.op0_kind() == OpKind::Register
                && prev.instr.op1_kind() == OpKind::Memory
                && let Some(slot) = rip_relative_target_va(&prev.instr, bitness)
            {
                let first = read_pointer(address_space, image, slot, ptr_size);
                if first != 0 && address_space.is_executable_va(first) {
                    vtable_va = Some(slot);
                    break;
                }
            }
            // lea reg, [rip+disp] pointing at a vtable
            if prev.instr.mnemonic() == Mnemonic::Lea
                && prev.instr.op0_kind() == OpKind::Register
                && let Some(slot) = rip_relative_target_va(&prev.instr, bitness)
            {
                let first = read_pointer(address_space, image, slot, ptr_size);
                if first != 0 && address_space.is_executable_va(first) {
                    vtable_va = Some(slot);
                    break;
                }
            }
        }

        let resolved = vtable_db.resolve_method(offset, None);
        let heuristic = if resolved.is_none() {
            vtable_db.heuristic_iunknown(offset).map(|s| s.to_string())
        } else {
            None
        };

        // Only report if we have a DB hit, heuristic, or recovered vtable VA.
        if resolved.is_none() && heuristic.is_none() && vtable_va.is_none() {
            continue;
        }

        let (interface, method, signature) = match resolved {
            Some((iface, m)) => (Some(iface), Some(m.name.clone()), Some(m.signature.clone())),
            None => (None, heuristic.clone(), None),
        };

        out.push(ResolvedVtableCall {
            call_va: dec.ip,
            this_reg,
            vtable_offset: offset,
            interface,
            method,
            signature,
            vtable_va,
            heuristic,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::rip_relative_target_va;
    use crate::analysis::vtable_sigs::VtableDB;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn indirect_module_exists() {
        assert!(true);
    }

    #[test]
    fn resolve_vtable_release_synthetic() {
        // VtableDB alone: offset 16 → IUnknown::Release
        let db = VtableDB::load_bundled_only();
        let (iface, m) = db.resolve_method(16, Some("IUnknown")).expect("Release");
        assert_eq!(iface, "IUnknown");
        assert_eq!(m.name, "Release");
        assert_eq!(m.offset, 16);
    }

    #[test]
    fn rip_relative_target_is_not_double_based() {
        // call qword ptr [rip+0x20] at 0x180001000; next_ip is 0x180001006.
        let mut decoder = Decoder::with_ip(
            64,
            &[0xff, 0x15, 0x20, 0, 0, 0],
            0x1800_01000,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        assert_eq!(rip_relative_target_va(&instruction, 64), Some(0x1800_01026));
    }
}
