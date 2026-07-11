
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A compact, serializable type node.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub enum DataType {
    Void,
    Bool,
    /// Signed integer of `bits` width (1, 8, 16, 32, 64).
    Int(u8),
    /// Unsigned integer of `bits` width.
    Uint(u8),
    Float,
    Double,
    /// Pointer to another type.
    Ptr(Box<DataType>),
    /// Array of `count` elements of element type.
    Array(Box<DataType>, u64),
    /// Function pointer: parameters and return type.
    FuncPtr {
        params: Vec<DataType>,
        #[serde(rename = "ret")]
        return_type: Box<DataType>,
    },
    /// Reference to a named typedef, struct, union, or enum.
    Named(String),
    /// Unknown but with a known byte width.
    Unknown(u8),
}

impl DataType {
    #[allow(dead_code)] // type construction helpers for agents/UI
    pub fn pointer_to(ty: impl Into<DataType>) -> Self {
        Self::Ptr(Box::new(ty.into()))
    }

    #[allow(dead_code)] // type construction helpers for agents/UI
    pub fn array_of(ty: impl Into<DataType>, count: u64) -> Self {
        Self::Array(Box::new(ty.into()), count)
    }

    /// Approximate size in bytes; returns 0 for Void, 8 for pointers if bitness unknown.
    pub fn size(&self, bitness: u32) -> u64 {
        match self {
            Self::Void => 0,
            Self::Bool => 1,
            Self::Int(b) | Self::Uint(b) | Self::Unknown(b) => u64::from(*b) / 8,
            Self::Float => 4,
            Self::Double => 8,
            Self::Ptr(_) | Self::FuncPtr { .. } => u64::from(bitness / 8),
            Self::Array(elem, count) => elem.size(bitness).saturating_mul(*count),
            Self::Named(_) => 0, // resolved by caller if needed
        }
    }
}

impl From<&str> for DataType {
    fn from(s: &str) -> Self {
        Self::Named(s.to_string())
    }
}

impl From<String> for DataType {
    fn from(s: String) -> Self {
        Self::Named(s)
    }
}

/// One field inside a struct or union.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Field {
    pub name: String,
    pub ty: DataType,
    pub offset: u64,
    /// Bit offset for bit-fields; used by PDB bit types.
    pub bit_offset: Option<u8>,
}

/// One variant inside an enum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// Classification of a composite type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum CompositeKind {
    Struct,
    Union,
    Enum,
}

/// A struct, union, or enum definition keyed by name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CompositeType {
    pub kind: CompositeKind,
    pub name: String,
    pub size: u64,
    pub align: u8,
    pub fields: Vec<Field>,
    pub variants: Vec<EnumVariant>,
}

/// Function signature used by type-aware decompilation and stack-frame recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<(String, DataType)>,
    pub ret: DataType,
    pub calling_conv: Option<String>,
}

/// A typed variable located on the stack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StackVariable {
    pub name: Option<String>,
    pub ty: DataType,
    /// Byte offset relative to the canonical frame pointer (RBP on x64 or
    /// EBP on x86), or to the stack pointer if no frame pointer exists.
    pub offset: i64,
    pub size: u32,
}

/// Recovered stack layout for a function.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    /// Size of all local variables in bytes (negative offsets).
    pub local_size: u64,
    /// Size of stack arguments in bytes (positive offsets above return address).
    pub arg_size: u64,
    /// Offset of the saved return address relative to RBP/EPS (typically +8/+4).
    pub return_addr_offset: i64,
    /// Local variables (negative offsets from canonical frame pointer).
    pub locals: Vec<StackVariable>,
    /// Incoming stack arguments (positive offsets from canonical frame pointer).
    pub args: Vec<StackVariable>,
}

/// Project-wide named / composite type repository.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataTypeManager {
    named: HashMap<String, DataType>,
    composites: HashMap<String, CompositeType>,
    signatures: HashMap<String, FunctionSignature>,
}

#[allow(dead_code)] // DataTypeManager is the project type-system seam
impl DataTypeManager {
    pub fn new() -> Self {
        let mut out = Self::default();
        out.seed_primitives();
        out
    }

    fn seed_primitives(&mut self) {
        let primitives = [
            ("void", DataType::Void),
            ("bool", DataType::Bool),
            ("char", DataType::Int(8)),
            ("unsigned char", DataType::Uint(8)),
            ("short", DataType::Int(16)),
            ("unsigned short", DataType::Uint(16)),
            ("int", DataType::Int(32)),
            ("unsigned int", DataType::Uint(32)),
            ("long", DataType::Int(32)),
            ("unsigned long", DataType::Uint(32)),
            ("long long", DataType::Int(64)),
            ("unsigned long long", DataType::Uint(64)),
            ("int8", DataType::Int(8)),
            ("uint8", DataType::Uint(8)),
            ("int16", DataType::Int(16)),
            ("uint16", DataType::Uint(16)),
            ("int32", DataType::Int(32)),
            ("uint32", DataType::Uint(32)),
            ("int64", DataType::Int(64)),
            ("uint64", DataType::Uint(64)),
            ("float", DataType::Float),
            ("double", DataType::Double),
            ("size_t", DataType::Uint(64)), // assume x64; caller may override
            ("ssize_t", DataType::Int(64)),
            ("HRESULT", DataType::Int(32)),
            ("BOOL", DataType::Int(32)),
            ("DWORD", DataType::Uint(32)),
            ("WORD", DataType::Uint(16)),
            ("BYTE", DataType::Uint(8)),
            ("QWORD", DataType::Uint(64)),
            ("UINT", DataType::Uint(32)),
            ("ULONG", DataType::Uint(32)),
            ("LONG", DataType::Int(32)),
            ("SHORT", DataType::Int(16)),
            ("USHORT", DataType::Uint(16)),
            ("SIZE_T", DataType::Uint(64)),
            ("ULONGLONG", DataType::Uint(64)),
            ("ULONG_PTR", DataType::Uint(64)),
            ("LONG_PTR", DataType::Int(64)),
            ("INT_PTR", DataType::Int(64)),
            ("UINT_PTR", DataType::Uint(64)),
            ("NTSTATUS", DataType::Int(32)),
            ("LSTATUS", DataType::Int(32)),
            ("ACCESS_MASK", DataType::Uint(32)),
            ("BOOLEAN", DataType::Uint(8)),
            ("ATOM", DataType::Uint(16)),
            ("WPARAM", DataType::Uint(64)),
            ("LPARAM", DataType::Int(64)),
            ("LRESULT", DataType::Int(64)),
            // Handles / opaque pointers (Win32).
            ("HANDLE", DataType::Ptr(Box::new(DataType::Void))),
            ("HMODULE", DataType::Ptr(Box::new(DataType::Void))),
            ("HINSTANCE", DataType::Ptr(Box::new(DataType::Void))),
            ("HWND", DataType::Ptr(Box::new(DataType::Void))),
            ("HDC", DataType::Ptr(Box::new(DataType::Void))),
            ("HMENU", DataType::Ptr(Box::new(DataType::Void))),
            ("HICON", DataType::Ptr(Box::new(DataType::Void))),
            ("HCURSOR", DataType::Ptr(Box::new(DataType::Void))),
            ("HBRUSH", DataType::Ptr(Box::new(DataType::Void))),
            ("HKEY", DataType::Ptr(Box::new(DataType::Void))),
            ("HLOCAL", DataType::Ptr(Box::new(DataType::Void))),
            ("HGLOBAL", DataType::Ptr(Box::new(DataType::Void))),
            ("SC_HANDLE", DataType::Ptr(Box::new(DataType::Void))),
            ("FARPROC", DataType::Ptr(Box::new(DataType::Void))),
            ("LPVOID", DataType::Ptr(Box::new(DataType::Void))),
            ("PVOID", DataType::Ptr(Box::new(DataType::Void))),
            ("LPCVOID", DataType::Ptr(Box::new(DataType::Void))),
            ("LPCSTR", DataType::Ptr(Box::new(DataType::Int(8)))),
            ("LPSTR", DataType::Ptr(Box::new(DataType::Int(8)))),
            ("PCSTR", DataType::Ptr(Box::new(DataType::Int(8)))),
            ("LPWSTR", DataType::Ptr(Box::new(DataType::Uint(16)))),
            ("LPCWSTR", DataType::Ptr(Box::new(DataType::Uint(16)))),
            ("PCWSTR", DataType::Ptr(Box::new(DataType::Uint(16)))),
            ("PWSTR", DataType::Ptr(Box::new(DataType::Uint(16)))),
            ("LPDWORD", DataType::Ptr(Box::new(DataType::Uint(32)))),
            ("PDWORD", DataType::Ptr(Box::new(DataType::Uint(32)))),
            ("PHANDLE", DataType::Ptr(Box::new(DataType::Ptr(Box::new(DataType::Void))))),
            ("PBOOL", DataType::Ptr(Box::new(DataType::Int(32)))),
            ("LPBOOL", DataType::Ptr(Box::new(DataType::Int(32)))),
        ];
        for (name, ty) in primitives {
            self.named.insert(name.to_string(), ty);
        }
    }

    pub fn add(&mut self, name: impl Into<String>, ty: DataType) {
        self.named.insert(name.into(), ty);
    }

    pub fn get(&self, name: &str) -> Option<&DataType> {
        self.named.get(name)
    }

    pub fn resolve(&self, ty: &DataType) -> DataType {
        match ty {
            DataType::Named(n) => self.named.get(n).cloned().unwrap_or(DataType::Unknown(0)),
            DataType::Ptr(inner) => DataType::Ptr(Box::new(self.resolve(inner))),
            DataType::Array(inner, count) => {
                DataType::Array(Box::new(self.resolve(inner)), *count)
            }
            DataType::FuncPtr { params, return_type } => DataType::FuncPtr {
                params: params.iter().map(|p| self.resolve(p)).collect(),
                return_type: Box::new(self.resolve(return_type)),
            },
            other => other.clone(),
        }
    }

    pub fn add_composite(&mut self, composite: CompositeType) {
        let name = composite.name.clone();
        self.composites.insert(name.clone(), composite);
        // Allow lookup as a named type.
        self.named.insert(name.clone(), DataType::Named(name));
    }

    pub fn composite(&self, name: &str) -> Option<&CompositeType> {
        self.composites.get(name)
    }

    pub fn iter_composites(&self) -> impl Iterator<Item = &CompositeType> {
        self.composites.values()
    }

    pub fn add_signature(&mut self, sig: FunctionSignature) {
        self.signatures.insert(sig.name.clone(), sig);
    }

    pub fn signature(&self, name: &str) -> Option<&FunctionSignature> {
        self.signatures.get(name)
    }

    pub fn iter_signatures(&self) -> impl Iterator<Item = &FunctionSignature> {
        self.signatures.values()
    }

    /// Render a type to a compact C-ish string for LLM export.
    pub fn render(&self, ty: &DataType) -> String {
        match ty {
            DataType::Void => "void".to_string(),
            DataType::Bool => "bool".to_string(),
            DataType::Int(b) => format!("int{b}"),
            DataType::Uint(b) => format!("uint{b}"),
            DataType::Float => "float".to_string(),
            DataType::Double => "double".to_string(),
            DataType::Ptr(inner) => format!("{}*", self.render(inner)),
            DataType::Array(inner, count) => format!("{}[{}]", self.render(inner), count),
            DataType::FuncPtr { params, return_type } => {
                let params = params
                    .iter()
                    .map(|p| self.render(p))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{}(*)({})", self.render(return_type), params)
            }
            DataType::Named(n) => n.clone(),
            DataType::Unknown(b) => format!("unknown{b}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_seeded() {
        let mgr = DataTypeManager::new();
        assert_eq!(mgr.get("int"), Some(&DataType::Int(32)));
        assert_eq!(mgr.get("LPWSTR"), Some(&DataType::Ptr(Box::new(DataType::Uint(16)))));
    }

    #[test]
    fn composite_round_trip() {
        let mut mgr = DataTypeManager::new();
        mgr.add_composite(CompositeType {
            kind: CompositeKind::Struct,
            name: "POINT".to_string(),
            size: 8,
            align: 4,
            fields: vec![
                Field {
                    name: "x".to_string(),
                    ty: DataType::Int(32),
                    offset: 0,
                    bit_offset: None,
                },
                Field {
                    name: "y".to_string(),
                    ty: DataType::Int(32),
                    offset: 4,
                    bit_offset: None,
                },
            ],
            variants: vec![],
        });
        assert_eq!(mgr.composite("POINT").unwrap().size, 8);
        assert_eq!(mgr.render(&DataType::Named("POINT".to_string())), "POINT");
    }
}
