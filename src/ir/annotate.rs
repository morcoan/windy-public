//! Type-aware operand annotation.
//!
//! Globals and IAT slots are annotated through a custom iced-x86 symbol
//! resolver, so `[rip+g_count]` becomes `[g_count:uint32]`.  Stack-relative
//! operands are regex-spliced afterwards using the function's recovered stack
//! frame.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use iced_x86::{Formatter as _, Instruction, IntelFormatter, SymbolResolver, SymbolResult};
use regex::Regex;

use crate::analysis::win32_sigs::SigDB;
use crate::project::symbols::SymbolTable;
use crate::project::types::{DataType, DataTypeManager, FunctionSignature, StackFrame};

/// Produce an annotated operand string for an instruction.
#[allow(dead_code)] // thin wrapper over `_with_db`
pub fn annotate_operands(
    instr: &Instruction,
    symbols: &SymbolTable,
    typed_globals: &HashMap<u64, DataType>,
    types: &DataTypeManager,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
    function_frame: Option<&StackFrame>,
) -> String {
    annotate_operands_with_db(
        instr,
        symbols,
        typed_globals,
        types,
        function_signatures,
        function_frame,
        None,
    )
}

/// Like [`annotate_operands`], but consults the Win32 [`SigDB`] for IAT slots.
pub fn annotate_operands_with_db(
    instr: &Instruction,
    symbols: &SymbolTable,
    typed_globals: &HashMap<u64, DataType>,
    types: &DataTypeManager,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
    function_frame: Option<&StackFrame>,
    sig_db: Option<&SigDB>,
) -> String {
    let resolver = TypedResolver::new(symbols, typed_globals, types, function_signatures, sig_db);
    let mut output = String::new();
    IntelFormatter::with_options(Some(Box::new(resolver)), None).format(instr, &mut output);

    // Split into mnemonic + the rest (operands).  We only annotate operands.
    let (mnemonic, operands) = if let Some(pos) = output.find(' ') {
        output.split_at(pos)
    } else {
        return output;
    };
    let operands = &operands[1..];
    let annotated = annotate_stack_operands(operands, function_frame, types);
    format!("{mnemonic} {annotated}")
}

/// Build the VA → annotated name map used by both the agent-text path and the
/// native structurer (`NameCtx::global_names`).
///
/// Annotation rules match the historical `TypedResolver` logic:
/// * typed globals → `name:ty`
/// * `__imp_*` IAT slots → `name:ret(*)(params)` (or `funcptr`)
/// * everything else → bare symbol name
#[allow(dead_code)] // thin wrapper over `_with_db`
pub fn build_global_names(
    symbols: &SymbolTable,
    typed_globals: &HashMap<u64, DataType>,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
    types: &DataTypeManager,
) -> HashMap<u64, String> {
    build_global_names_with_db(symbols, typed_globals, function_signatures, types, None)
}

/// Like [`build_global_names`], but prefers the Win32 SigDB for `__imp_*` slots.
pub fn build_global_names_with_db(
    symbols: &SymbolTable,
    typed_globals: &HashMap<u64, DataType>,
    function_signatures: &BTreeMap<u64, FunctionSignature>,
    types: &DataTypeManager,
    sig_db: Option<&SigDB>,
) -> HashMap<u64, String> {
    let mut annotated_names = HashMap::new();
    for (va, sym) in symbols.iter() {
        let name = &sym.name;
        let annotated = if let Some(ty) = typed_globals.get(&va) {
            format!("{name}:{}", types.render(ty))
        } else if let Some(api) = name.strip_prefix("__imp_") {
            let sig_text = sig_db
                .and_then(|db| db.lookup_by_name(api))
                .or_else(|| function_signatures.values().find(|s| s.name == api))
                .map(|s| render_signature(s, types))
                .unwrap_or_else(|| "funcptr".to_string());
            format!("{name}:{sig_text}")
        } else {
            name.clone()
        };
        annotated_names.insert(va, annotated);
    }
    annotated_names
}

/// Annotate bracketed stack-relative operands with recovered stack-variable
/// types, e.g. `[rbp-0x10]` -> `[rbp-0x10:var_10:unknown64]`.
fn annotate_stack_operands(
    operands: &str,
    function_frame: Option<&StackFrame>,
    types: &DataTypeManager,
) -> String {
    let frame = match function_frame {
        Some(f) => f,
        None => return operands.to_string(),
    };

    static STACK_RE: OnceLock<Regex> = OnceLock::new();
    let re = STACK_RE.get_or_init(|| {
        Regex::new(
            r"(?P<bracket>\[(?P<base>r?bp|r?sp)(?P<sign>[+-])(?P<disp>0x[0-9a-fA-F]+|\d+)\])",
        )
        .expect("valid stack regex")
    });

    re.replace_all(operands, |caps: &regex::Captures| {
        let bracket = &caps["bracket"];
        let base = &caps["base"];
        let sign = &caps["sign"];
        let disp_str = &caps["disp"];
        let disp = if let Some(hex) = disp_str.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).unwrap_or(0)
        } else {
            disp_str.parse().unwrap_or(0)
        };
        let signed = if sign == "-" {
            -(disp as i64)
        } else {
            disp as i64
        };

        let annotation = if base == "rbp" || base == "ebp" {
            frame_arg_or_local_type(frame, signed, types)
        } else {
            None
        };

        match annotation {
            Some(note) => format!("{bracket}:{note}"),
            None => bracket.to_string(),
        }
    })
    .into_owned()
}

fn frame_arg_or_local_type(
    frame: &StackFrame,
    offset: i64,
    types: &DataTypeManager,
) -> Option<String> {
    let var = if offset > 0 {
        frame.args.iter().find(|a| a.offset == offset)
    } else {
        frame.locals.iter().find(|l| l.offset == offset)
    };
    var.map(|v| {
        let ty = types.render(&v.ty);
        match &v.name {
            Some(n) => format!("{n}:{ty}"),
            None => ty,
        }
    })
}

fn render_signature(sig: &FunctionSignature, types: &DataTypeManager) -> String {
    let params = sig
        .params
        .iter()
        .map(|(_, t)| types.render(t))
        .collect::<Vec<_>>()
        .join(",");
    let ret = types.render(&sig.ret);
    format!("{ret}(*)({params})")
}

struct TypedResolver {
    annotated_names: HashMap<u64, String>,
}

impl TypedResolver {
    fn new(
        symbols: &SymbolTable,
        typed_globals: &HashMap<u64, DataType>,
        types: &DataTypeManager,
        function_signatures: &BTreeMap<u64, FunctionSignature>,
        sig_db: Option<&SigDB>,
    ) -> Self {
        Self {
            annotated_names: build_global_names_with_db(
                symbols,
                typed_globals,
                function_signatures,
                types,
                sig_db,
            ),
        }
    }
}

impl SymbolResolver for TypedResolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        self.annotated_names
            .get(&address)
            .map(|s| SymbolResult::with_str(address, s))
    }
}
