
//! Prologue-based stack-frame recovery for functions that do not have PDB
//! frame data. Extracts the local-variable size and synthesizes placeholder
//! typed locals that the decompiler/LLM can refine later.

use iced_x86::{Mnemonic, Register};

use crate::analysis::code_index::CodeIndex;
use crate::analysis::functions::FunctionTable;
use crate::project::types::{DataType, StackFrame, StackVariable};

const MAX_PROLOGUE_INSTRUCTIONS: usize = 12;
const MAX_LOCAL_SLOTS: usize = 64;

/// Fill in missing stack frames by inspecting function prologues.
pub fn recover_frames(functions: &mut FunctionTable, code_index: &CodeIndex, bitness: u32) {
    let ptr_size = (bitness / 8) as u64;
    for func in functions.iter_mut() {
        if func.stack_frame.is_some() {
            continue;
        }
        if let Some(frame) = analyze_prologue(func.entry_va, code_index, ptr_size, bitness) {
            func.stack_frame = Some(frame);
        }
    }
}

fn analyze_prologue(entry: u64, code_index: &CodeIndex, ptr_size: u64, bitness: u32) -> Option<StackFrame> {
    let mut uses_frame_pointer = false;
    let mut local_size = 0u64;
    let mut steps = 0;
    let mut va = entry;

    while let Some(dec) = code_index.at_va(va) {
        if steps >= MAX_PROLOGUE_INSTRUCTIONS {
            break;
        }
        steps += 1;
        let instr = &dec.instr;

        // push rbp / push ebp
        if instr.mnemonic() == Mnemonic::Push
            && matches!(instr.op0_register(), Register::RBP | Register::EBP)
        {
            uses_frame_pointer = true;
            va = dec.next_ip();
            continue;
        }

        // mov rbp, rsp / mov ebp, esp
        if instr.mnemonic() == Mnemonic::Mov
            && matches!(instr.op0_register(), Register::RBP | Register::EBP)
            && matches!(instr.op1_register(), Register::RSP | Register::ESP)
        {
            uses_frame_pointer = true;
            va = dec.next_ip();
            continue;
        }

        // sub rsp, N / sub esp, N
        if instr.mnemonic() == Mnemonic::Sub
            && matches!(instr.op0_register(), Register::RSP | Register::ESP | Register::RIP)
            && is_immediate_op(instr, 1)
        {
            let n = instr.immediate(1);
            if n > 0 && n <= 0x100_0000 {
                local_size = n;
            }
            va = dec.next_ip();
            continue;
        }

        // lea rsp, [rsp - N] is sometimes used instead of sub
        if instr.mnemonic() == Mnemonic::Lea
            && matches!(instr.op0_register(), Register::RSP | Register::ESP)
            && let Some(n) = lea_stack_adjustment(instr, bitness)
            && n > 0 && n <= 0x100_0000
        {
            local_size = n;
            va = dec.next_ip();
            continue;
        }

        // mov [rsp+...], reg  or  mov [rbp-...], reg are not prologue setup.
        // Any other instruction ends the prologue scan.
        if is_prologue_terminator(instr) {
            break;
        }

        va = dec.next_ip();
    }

    if local_size == 0 && !uses_frame_pointer {
        return None;
    }

    let return_addr_offset = ptr_size as i64;
    let bit_size = (ptr_size * 8) as u8;
    let mut locals = Vec::new();
    let mut offset = ptr_size;
    while offset <= local_size && locals.len() < MAX_LOCAL_SLOTS {
        locals.push(StackVariable {
            name: Some(format!("var_{:x}", offset)),
            ty: DataType::Unknown(bit_size),
            offset: -(offset as i64),
            size: ptr_size as u32,
        });
        offset += ptr_size;
    }

    Some(StackFrame {
        local_size,
        arg_size: 0,
        return_addr_offset,
        locals,
        args: Vec::new(),
    })
}

fn is_immediate_op(instr: &iced_x86::Instruction, op_index: u32) -> bool {
    use iced_x86::OpKind;
    matches!(
        instr.op_kind(op_index),
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn lea_stack_adjustment(instr: &iced_x86::Instruction, bitness: u32) -> Option<u64> {
    if instr.op0_kind() != iced_x86::OpKind::Register {
        return None;
    }
    if instr.memory_base() != Register::RSP && instr.memory_base() != Register::ESP {
        return None;
    }
    if instr.memory_index() != Register::None {
        return None;
    }
    let disp = instr.memory_displacement64();
    if bitness == 64 {
        // LEA RSP, [RSP + signed32]
        let signed = disp as i32 as i64;
        if signed < 0 {
            Some((-signed) as u64)
        } else {
            None
        }
    } else {
        Some(disp)
    }
}

fn is_prologue_terminator(instr: &iced_x86::Instruction) -> bool {
    use iced_x86::FlowControl;
    matches!(
        instr.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call
            | FlowControl::IndirectBranch
            | FlowControl::IndirectCall
    ) || instr.mnemonic() == Mnemonic::Nop
}

#[cfg(test)]
mod tests {
    #[test]
    fn stack_frame_module_exists() {
        assert!(true);
    }
}
