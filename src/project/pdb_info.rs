//! Parse a downloaded PDB and extract symbols, stack-frame records, and a
//! starter type library. All operations are best-effort; failures are reported
//! inside [`PdbInfo`] instead of halting analysis.

use std::collections::{BTreeMap, HashMap};
use std::ops::Deref;
use std::path::PathBuf;

use anyhow::{Context, Result};
use fallible_iterator::FallibleIterator;
use tracing::{info, warn};

use crate::loader::debug_dir::{CodeViewRecord, find_codeview_record};
use crate::loader::pe::LoadedPe;
use crate::project::demangle::demangle_or_raw;
use crate::project::symbols::{SymbolKind, SymbolTable};
use crate::project::symsrv::SymbolStore;
use crate::project::types::{
    CompositeKind, CompositeType, DataType, DataTypeManager, FunctionSignature, StackFrame,
};

/// Everything recovered from a PDB that should outlive the file bytes.
#[derive(Clone, Debug, Default)]
pub struct PdbInfo {
    pub loaded: bool,
    pub source: Option<PathBuf>,
    pub record: Option<CodeViewRecord>,
    pub symbols: Vec<(u64, String)>,
    pub frames: BTreeMap<u64, StackFrame>,
    pub types: DataTypeManager,
    /// Global data symbols mapped to their PDB type.
    pub typed_globals: HashMap<u64, DataType>,
    /// Function signatures discovered from PDB `Procedure` symbols keyed by
    /// the function entry RVA.
    pub named_signatures: BTreeMap<u64, FunctionSignature>,
    pub error: Option<String>,
}

impl PdbInfo {
    /// Locate, cache, and parse the PDB using an explicit Windy data root.
    /// This never fails outright; it records an error and returns partial or
    /// empty information if symbols cannot be obtained.
    pub fn load_for_pe_in(pe: &LoadedPe, home_dir: impl AsRef<std::path::Path>) -> Self {
        let rec = match find_codeview_record(pe.image.deref()) {
            Some(r) => r,
            None => {
                return Self {
                    error: Some("no CodeView record found (directory or RSDS scan)".to_string()),
                    ..Default::default()
                };
            }
        };

        let store = SymbolStore::with_home_dir(home_dir);
        let path = match store.resolve_with_download(&rec, should_download_public_symbols(pe)) {
            Some(p) => p,
            None => {
                // Fallback: a relative CodeView path may refer to a PDB next to the PE.
                let rel = std::path::Path::new(&rec.pdb_name);
                let next_to_pe = pe.path.with_file_name(rel);
                if next_to_pe.exists() {
                    next_to_pe
                } else {
                    return Self {
                        record: Some(rec),
                        error: Some(
                            "PDB not available locally and could not be downloaded".to_string(),
                        ),
                        ..Default::default()
                    };
                }
            }
        };

        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                return Self {
                    record: Some(rec),
                    error: Some(format!("failed to read cached PDB: {e}")),
                    ..Default::default()
                };
            }
        };

        match Self::parse(&bytes) {
            Ok(mut info) => {
                info.record = Some(rec);
                info.source = Some(path);
                info.loaded = true;
                info
            }
            Err(e) => Self {
                record: Some(rec),
                source: Some(path),
                error: Some(format!("PDB parse failed: {e:#}")),
                ..Default::default()
            },
        }
    }

    /// Parse a PDB from raw bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let cursor = std::io::Cursor::new(bytes);
        let mut pdb = ::pdb::PDB::open(cursor).context("open PDB")?;
        let address_map = pdb.address_map().context("address map")?;

        let mut symbols: Vec<(u64, String)> = Vec::new();
        // (rva, raw_name, type_index) for global data symbols; resolved after
        // the type stream is parsed.
        let mut data_symbols: Vec<(u64, String, ::pdb::TypeIndex)> = Vec::new();
        // (rva, name, type_index) for Procedure symbols; resolved after the
        // type stream is parsed into real signatures.
        let mut procedure_symbols: Vec<(u64, String, ::pdb::TypeIndex)> = Vec::new();

        let symbol_table = pdb.global_symbols().context("global symbols")?;
        let mut iter = symbol_table.iter();
        while let Some(symbol) = iter.next()? {
            if let Ok(data) = symbol.parse() {
                match data {
                    ::pdb::SymbolData::Public(data) => {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let name = demangle_or_raw(&data.name.to_string());
                            if !name.is_empty() {
                                symbols.push((rva.0 as u64, name));
                            }
                        }
                    }
                    ::pdb::SymbolData::Procedure(data) => {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let name = demangle_or_raw(&data.name.to_string());
                            if !name.is_empty() {
                                let rva = rva.0 as u64;
                                symbols.push((rva, name.clone()));
                                procedure_symbols.push((rva, name, data.type_index));
                            }
                        }
                    }
                    ::pdb::SymbolData::Thunk(data) => {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let name = demangle_or_raw(&data.name.to_string());
                            if !name.is_empty() {
                                symbols.push((rva.0 as u64, name));
                            }
                        }
                    }
                    ::pdb::SymbolData::Label(data) => {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let name = demangle_or_raw(&data.name.to_string());
                            if !name.is_empty() {
                                symbols.push((rva.0 as u64, name));
                            }
                        }
                    }
                    ::pdb::SymbolData::Data(data) => {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let name = demangle_or_raw(&data.name.to_string());
                            if !name.is_empty() {
                                symbols.push((rva.0 as u64, name.clone()));
                                data_symbols.push((rva.0 as u64, name, data.type_index));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut frames: BTreeMap<u64, StackFrame> = BTreeMap::new();
        let frame_table = pdb.frame_table().context("frame table")?;
        let mut iter = frame_table.iter();
        while let Some(frame) = iter.next()? {
            if let Some(rva) = frame.code_start.to_rva(&address_map) {
                frames.insert(
                    rva.0 as u64,
                    StackFrame {
                        local_size: u64::from(frame.locals_size),
                        arg_size: u64::from(frame.params_size),
                        return_addr_offset: 8,
                        locals: Vec::new(),
                        args: Vec::new(),
                    },
                );
            }
        }

        let mut types = DataTypeManager::new();
        let mut type_map: TypeMap = BTreeMap::new();
        let mut arg_lists: ArgLists = BTreeMap::new();
        let mut procedures: ProcedureMap = BTreeMap::new();
        if let Ok(type_info) = pdb.type_information() {
            let loaded = load_types(&type_info).unwrap_or_else(|e| {
                warn!("type load partially failed: {e}");
                (
                    DataTypeManager::new(),
                    BTreeMap::new(),
                    BTreeMap::new(),
                    BTreeMap::new(),
                )
            });
            types = loaded.0;
            type_map = loaded.1;
            arg_lists = loaded.2;
            procedures = loaded.3;
        }

        let mut typed_globals: HashMap<u64, DataType> = HashMap::new();
        for (rva, _name, type_index) in data_symbols {
            if type_index.0 == 0 {
                continue;
            }
            if let Some(ty) = type_map.get(&type_index).cloned() {
                typed_globals.insert(rva, ty);
            }
        }

        let mut named_signatures: BTreeMap<u64, FunctionSignature> = BTreeMap::new();
        for (rva, name, type_index) in procedure_symbols {
            if type_index.0 == 0 {
                continue;
            }
            if let Some(sig) = build_signature(name, type_index, &type_map, &arg_lists, &procedures)
            {
                named_signatures.insert(rva, sig);
            }
        }

        info!(
            "PDB loaded: {} symbols, {} frames, {} composites, {} typed globals, {} signatures",
            symbols.len(),
            frames.len(),
            types.iter_composites().count(),
            typed_globals.len(),
            named_signatures.len()
        );

        Ok(Self {
            loaded: true,
            source: None,
            record: None,
            symbols,
            frames,
            types,
            typed_globals,
            named_signatures,
            error: None,
        })
    }

    /// Apply PDB data to project structures. Code/data symbol classification
    /// uses the address space of the loaded image.
    pub fn apply(
        &self,
        address_space: &crate::loader::AddressSpace,
        symbols: &mut SymbolTable,
        frames: &mut BTreeMap<u64, StackFrame>,
        types: &mut DataTypeManager,
        typed_globals: &mut HashMap<u64, DataType>,
        named_signatures: &mut BTreeMap<u64, FunctionSignature>,
    ) {
        for (va, name) in &self.symbols {
            let kind = if address_space.is_executable_va(*va) {
                SymbolKind::Function
            } else {
                SymbolKind::Data
            };
            symbols.insert(*va, name.clone(), kind);
        }
        frames.extend(self.frames.clone());
        typed_globals.extend(self.typed_globals.clone());
        named_signatures.extend(self.named_signatures.clone());
        for composite in self.types.iter_composites() {
            types.add_composite(composite.clone());
        }
        for sig in self.types.iter_signatures() {
            types.add_signature(sig.clone());
        }
    }
}

fn should_download_public_symbols(pe: &LoadedPe) -> bool {
    match std::env::var("WINDY_SYMBOL_DOWNLOAD")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "always" | "1" | "true" | "yes" => return true,
        "never" | "0" | "false" | "no" | "local" => return false,
        "auto" | "" => {}
        _ => {}
    }

    // Keep the public release's established automatic behavior. The private
    // beta defaults to a fast auto policy and still checks all local/bundled
    // symbol locations before making this decision.
    if !cfg!(feature = "beta") {
        return true;
    }
    pe.triage
        .authenticode
        .as_ref()
        .and_then(|authenticode| authenticode.signer.as_ref())
        .is_some_and(|signer| signer.subject.to_ascii_lowercase().contains("microsoft"))
        || pe
            .triage
            .resources
            .as_ref()
            .and_then(|resources| resources.version_info.as_ref())
            .is_some_and(|version| {
                version.string_info.iter().any(|entry| {
                    entry.key.eq_ignore_ascii_case("CompanyName")
                        && entry.value.to_ascii_lowercase().contains("microsoft")
                })
            })
}

type TypeMap = BTreeMap<::pdb::TypeIndex, DataType>;
type ArgLists = BTreeMap<::pdb::TypeIndex, Vec<::pdb::TypeIndex>>;
type ProcedureMap = BTreeMap<::pdb::TypeIndex, ::pdb::ProcedureType>;

fn load_types(
    type_info: &::pdb::TypeInformation,
) -> Result<(DataTypeManager, TypeMap, ArgLists, ProcedureMap)> {
    use ::pdb::TypeData;

    let mut manager = DataTypeManager::new();
    let mut map: TypeMap = BTreeMap::new();
    let mut arg_lists: ArgLists = BTreeMap::new();
    let mut procedures: ProcedureMap = BTreeMap::new();
    let mut iter = type_info.iter();

    while let Some(typ) = iter.next()? {
        let index = typ.index();
        let data = typ.parse().ok();
        let mapped = data.as_ref().map(|d| map_type_data(d, &map));
        if let Some(ty) = mapped {
            map.insert(index, ty.clone());
            match data {
                Some(TypeData::Class(class)) => {
                    manager.add_composite(CompositeType {
                        kind: match class.kind {
                            ::pdb::ClassKind::Class => CompositeKind::Struct,
                            _ => CompositeKind::Struct,
                        },
                        name: format!("{}", class.name),
                        size: class.size,
                        align: 8,
                        fields: Vec::new(),
                        variants: Vec::new(),
                    });
                }
                Some(TypeData::Union(union_type)) => {
                    manager.add_composite(CompositeType {
                        kind: CompositeKind::Union,
                        name: format!("{}", union_type.name),
                        size: union_type.size,
                        align: 8,
                        fields: Vec::new(),
                        variants: Vec::new(),
                    });
                }
                Some(TypeData::Enumeration(enm)) => {
                    let base = resolve_type_index(enm.underlying_type, &map);
                    manager.add_composite(CompositeType {
                        kind: CompositeKind::Enum,
                        name: format!("{}", enm.name),
                        size: base.size(64),
                        align: 8,
                        fields: Vec::new(),
                        variants: Vec::new(),
                    });
                }
                Some(TypeData::ArgumentList(args)) => {
                    arg_lists.insert(index, args.arguments.clone());
                }
                Some(TypeData::Procedure(proc)) => {
                    procedures.insert(index, proc);
                }
                _ => {}
            }
        }
    }

    // Procedure types become function-pointer nodes so other types that
    // reference them can render something other than a placeholder name.
    for (index, proc) in &procedures {
        let ret = proc
            .return_type
            .and_then(|t| map.get(&t).cloned())
            .unwrap_or(DataType::Void);
        let params: Vec<DataType> = arg_lists
            .get(&proc.argument_list)
            .map(|list| {
                list.iter()
                    .map(|t| map.get(t).cloned().unwrap_or(DataType::Unknown(0)))
                    .collect()
            })
            .unwrap_or_default();
        map.insert(
            *index,
            DataType::FuncPtr {
                params,
                return_type: Box::new(ret),
            },
        );
    }

    Ok((manager, map, arg_lists, procedures))
}

fn map_type_data(data: &::pdb::TypeData, map: &BTreeMap<::pdb::TypeIndex, DataType>) -> DataType {
    use ::pdb::TypeData;
    match data {
        TypeData::Primitive(primitive) => map_primitive(primitive),
        TypeData::Pointer(pointer) => {
            let inner = resolve_type_index(pointer.underlying_type, map);
            DataType::Ptr(Box::new(inner))
        }
        TypeData::Array(array) => {
            let elem = resolve_type_index(array.element_type, map);
            // PDB `dimensions` are byte sizes; convert to element count.
            let elem_size = elem.size(64).max(1);
            let byte_size: u64 = array.dimensions.iter().map(|&d| u64::from(d)).product();
            DataType::Array(Box::new(elem), byte_size / elem_size)
        }
        TypeData::Class(class) => DataType::Named(format!("{}", class.name)),
        TypeData::Union(union_type) => DataType::Named(format!("{}", union_type.name)),
        TypeData::Enumeration(enm) => DataType::Named(format!("{}", enm.name)),
        TypeData::Procedure(_) => DataType::Named(type_data_name_hint(data)),
        TypeData::Bitfield(bitfield) => resolve_type_index(bitfield.underlying_type, map),
        TypeData::Modifier(modifier) => resolve_type_index(modifier.underlying_type, map),
        _ => DataType::Unknown(0),
    }
}

fn resolve_type_index(
    index: ::pdb::TypeIndex,
    map: &BTreeMap<::pdb::TypeIndex, DataType>,
) -> DataType {
    map.get(&index)
        .cloned()
        .unwrap_or_else(|| DataType::Named(format!("__T{index:?}")))
}

fn map_primitive(primitive: &::pdb::PrimitiveType) -> DataType {
    use ::pdb::{Indirection, PrimitiveKind};

    let base = match primitive.kind {
        PrimitiveKind::Void => DataType::Void,
        PrimitiveKind::Char | PrimitiveKind::RChar | PrimitiveKind::RChar16 => DataType::Int(8),
        PrimitiveKind::UChar => DataType::Uint(8),
        PrimitiveKind::WChar | PrimitiveKind::RChar32 => DataType::Uint(16),
        PrimitiveKind::I8 => DataType::Int(8),
        PrimitiveKind::U8 => DataType::Uint(8),
        PrimitiveKind::Short | PrimitiveKind::I16 => DataType::Int(16),
        PrimitiveKind::UShort | PrimitiveKind::U16 => DataType::Uint(16),
        PrimitiveKind::Long | PrimitiveKind::I32 => DataType::Int(32),
        PrimitiveKind::ULong | PrimitiveKind::U32 => DataType::Uint(32),
        PrimitiveKind::Quad | PrimitiveKind::I64 => DataType::Int(64),
        PrimitiveKind::UQuad | PrimitiveKind::U64 => DataType::Uint(64),
        PrimitiveKind::Octa | PrimitiveKind::I128 => DataType::Int(128),
        PrimitiveKind::UOcta | PrimitiveKind::U128 => DataType::Uint(128),
        PrimitiveKind::F16 => DataType::Float,
        PrimitiveKind::F32 | PrimitiveKind::F32PP | PrimitiveKind::F48 => DataType::Float,
        PrimitiveKind::F64 => DataType::Double,
        PrimitiveKind::F80 | PrimitiveKind::F128 => DataType::Double,
        PrimitiveKind::Bool8
        | PrimitiveKind::Bool16
        | PrimitiveKind::Bool32
        | PrimitiveKind::Bool64 => DataType::Bool,
        PrimitiveKind::HRESULT => DataType::Int(32),
        PrimitiveKind::NoType | _ => DataType::Unknown(0),
    };

    if let Some(Indirection::Near32 | Indirection::Near64 | Indirection::Far32) =
        primitive.indirection
    {
        if matches!(base, DataType::Void) {
            DataType::Ptr(Box::new(DataType::Void))
        } else {
            DataType::Ptr(Box::new(base))
        }
    } else {
        base
    }
}

fn type_data_name_hint(data: &::pdb::TypeData) -> String {
    match data {
        ::pdb::TypeData::Class(class) => format!("{}", class.name),
        ::pdb::TypeData::Union(union_type) => format!("{}", union_type.name),
        ::pdb::TypeData::Enumeration(enm) => format!("{}", enm.name),
        _ => "__".to_string(),
    }
}

fn build_signature(
    name: String,
    type_index: ::pdb::TypeIndex,
    map: &TypeMap,
    arg_lists: &ArgLists,
    procedures: &ProcedureMap,
) -> Option<FunctionSignature> {
    let proc = procedures.get(&type_index)?;
    let ret = proc
        .return_type
        .and_then(|t| map.get(&t).cloned())
        .unwrap_or(DataType::Void);
    let params: Vec<(String, DataType)> = arg_lists
        .get(&proc.argument_list)
        .map(|list| {
            list.iter()
                .enumerate()
                .map(|(i, t)| {
                    let ty = map.get(t).cloned().unwrap_or(DataType::Unknown(0));
                    (format!("arg{}", i + 1), ty)
                })
                .collect()
        })
        .unwrap_or_default();
    let calling_conv = calling_conv_name(proc.attributes.calling_convention());
    Some(FunctionSignature {
        name,
        params,
        ret,
        calling_conv,
    })
}

fn calling_conv_name(cc: u8) -> Option<String> {
    Some(
        match cc {
            0x00 => "cdecl",
            0x03 => "stdcall",
            0x05 => "fastcall",
            0x0A => "thiscall",
            0x14 => "clrcall",
            0x15 => "inline",
            0x16 => "vectorcall",
            _ => return None,
        }
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_info_default() {
        let info = PdbInfo::default();
        assert!(!info.loaded);
        assert!(info.symbols.is_empty());
    }
}
