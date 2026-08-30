//! Best-effort recovery of function signatures. PDB-derived signatures are
//! preferred; this module provides architecture-specific heuristic fallbacks
//! so exports still show argument counts and registers for the LLM.

use std::collections::HashSet;

use iced_x86::{FlowControl, InstructionInfoFactory, OpAccess, Register};
use regex::Regex;

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::Function;
use crate::analysis::win32_sigs::SigDB;
use crate::project::types::{DataType, FunctionSignature};

const MAX_ENTRY_SCAN_INSTRUCTIONS: usize = 24;

/// Recover a signature for `func` if PDB did not provide one.
///
/// Prefer the Win32 SigDB when the function name (or IAT/thunk name) matches a
/// known API. Otherwise fall back to architecture-specific heuristic scanning
/// with placeholder parameter names (`arg1`, `arg2`, ...) and `Unknown` types.
#[allow(dead_code)] // thin wrapper; agents may call without a SigDB
pub fn recover_signature(
    func: &Function,
    code_index: &CodeIndex,
    bitness: u32,
    name: &str,
) -> Option<FunctionSignature> {
    recover_signature_with_db(func, code_index, bitness, name, None)
}

/// Like [`recover_signature`], but consults an explicit [`SigDB`] first.
pub fn recover_signature_with_db(
    func: &Function,
    code_index: &CodeIndex,
    bitness: u32,
    name: &str,
    sig_db: Option<&SigDB>,
) -> Option<FunctionSignature> {
    if let Some(db) = sig_db
        && let Some(sig) = db.lookup_by_name(name)
    {
        return Some(sig.clone());
    }
    if bitness == 64 {
        recover_x64_signature(func, code_index, name)
    } else {
        recover_x86_signature(func, code_index, name)
    }
}

fn recover_x64_signature(
    func: &Function,
    code_index: &CodeIndex,
    name: &str,
) -> Option<FunctionSignature> {
    let param_regs: [Register; 8] = [
        Register::RCX,
        Register::RDX,
        Register::R8,
        Register::R9,
        Register::XMM0,
        Register::XMM1,
        Register::XMM2,
        Register::XMM3,
    ];

    let mut params = Vec::new();
    let mut killed: HashSet<Register> = HashSet::new();
    let mut info_factory = InstructionInfoFactory::new();
    let mut va = func.entry_va;

    for _ in 0..MAX_ENTRY_SCAN_INSTRUCTIONS {
        let dec = code_index.at_va(va)?;
        let instr = &dec.instr;
        let info = info_factory.info(instr);

        for ur in info.used_registers() {
            // Normalize ECX→RCX, EDX→RDX, R8D→R8, etc. so 32-bit stores of
            // args still count as param reads.
            let r = full_gpr(ur.register());
            if !param_regs.contains(&r) {
                continue;
            }
            let access = ur.access();
            if is_write(access) {
                killed.insert(r);
            } else if is_read(access) && !killed.contains(&r) {
                params.push((format!("arg{}", params.len() + 1), DataType::Unknown(64)));
                killed.insert(r);
            }
        }

        match instr.flow_control() {
            FlowControl::Next => {
                va = dec.next_ip();
            }
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch => {
                break;
            }
            _ => break,
        }
    }

    Some(FunctionSignature {
        name: name_hint(name),
        params,
        ret: DataType::Void,
        calling_conv: Some("fastcall".to_string()),
    })
}

fn recover_x86_signature(
    func: &Function,
    code_index: &CodeIndex,
    name: &str,
) -> Option<FunctionSignature> {
    // Stdcall decoration: _Name@N where N is stack-arg bytes.
    let stdcall = Regex::new(r"^_([^@]+)@(\d+)$").ok()?;
    if let Some(cap) = stdcall.captures(name) {
        let bytes: u64 = cap[2].parse().ok()?;
        let count = (bytes / 4) as usize;
        let params = (0..count)
            .map(|i| (format!("arg{}", i + 1), DataType::Unknown(32)))
            .collect();
        return Some(FunctionSignature {
            name: name_hint(name),
            params,
            ret: DataType::Void,
            calling_conv: Some("stdcall".to_string()),
        });
    }

    // Cdecl / undecorated: try to count distinct positive [ebp+off] reads in
    // the entry block before the first call or branch.
    let mut offsets: Vec<u64> = Vec::new();
    let mut info_factory = InstructionInfoFactory::new();
    let mut va = func.entry_va;

    for _ in 0..MAX_ENTRY_SCAN_INSTRUCTIONS {
        let dec = code_index.at_va(va)?;
        let instr = &dec.instr;
        let info = info_factory.info(instr);

        for um in info.used_memory() {
            if um.base() == Register::EBP
                && um.index() == Register::None
                && um.displacement() >= 8
                && um.displacement() % 4 == 0
                && is_read(um.access())
            {
                offsets.push(um.displacement());
            }
        }

        match instr.flow_control() {
            FlowControl::Next => {
                va = dec.next_ip();
            }
            FlowControl::Call
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch => {
                break;
            }
            _ => break,
        }
    }

    offsets.sort_unstable();
    offsets.dedup();
    let params = offsets
        .into_iter()
        .enumerate()
        .map(|(i, _)| (format!("arg{}", i + 1), DataType::Unknown(32)))
        .collect();

    Some(FunctionSignature {
        name: name_hint(name),
        params,
        ret: DataType::Void,
        calling_conv: Some("cdecl".to_string()),
    })
}

fn name_hint(name: &str) -> String {
    if name.is_empty() {
        "sub".to_string()
    } else {
        name.to_string()
    }
}

fn is_read(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn is_write(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Map subregisters used in prologues (`ecx`, `edx`, `r8d`, …) to the full
/// 64-bit home registers that the Microsoft x64 ABI assigns to parameters.
fn full_gpr(r: Register) -> Register {
    match r {
        Register::ECX | Register::CX | Register::CL | Register::CH => Register::RCX,
        Register::EDX | Register::DX | Register::DL | Register::DH => Register::RDX,
        Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9D | Register::R9W | Register::R9L => Register::R9,
        other => other,
    }
}
