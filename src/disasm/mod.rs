#![allow(dead_code)] // disassemblyFormatter/rendering seam; actively used in Phase 2

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, MasmFormatter, NasmFormatter};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Syntax {
    #[default]
    Intel,
    Nasm,
    Masm,
}

impl Syntax {
    pub fn format_instruction(&self, instr: &Instruction) -> String {
        let mut output = String::new();
        match self {
            Syntax::Intel => IntelFormatter::new().format(instr, &mut output),
            Syntax::Nasm => NasmFormatter::new().format(instr, &mut output),
            Syntax::Masm => MasmFormatter::new().format(instr, &mut output),
        }
        output
    }
}

pub fn decode_range(
    bitness: u32,
    bytes: &[u8],
    start_ip: u64,
) -> impl Iterator<Item = Instruction> + '_ {
    let mut decoder = Decoder::with_ip(bitness, bytes, start_ip, DecoderOptions::NONE);
    std::iter::from_fn(move || {
        if decoder.can_decode() {
            Some(decoder.decode())
        } else {
            None
        }
    })
}
