//! Semantic high-level IR foundations.
//!
//! This module is deliberately additive.  It does not change the frozen
//! P-code, the current SSA construction, or the existing emitter.  Instead it
//! provides the typed identities and ABI facts needed by a future semantic
//! lowering pass: values retain source provenance, register aliases are kept as
//! slices of one physical register, memory is partitioned into objects, and
//! calls carry their actual Windows x64 ABI contract.
//!
//! `lower_from_ssa` is intentionally a lossless bridge rather than a new
//! decompiler.  It gives every current SSA value a [`ValueId`] and preserves the
//! P-code instruction VA on its operation and defining value.  More precise
//! lifting (unique-space values, alias analysis, and call argument recovery)
//! can be layered on top without changing this public currency.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use pcode_ir::AddressSpaceId;

use crate::decompiler::pcode::{PcodeOp, Varnode};
use crate::decompiler::ssa::{Location, SsaBlock, SsaFunction, SsaOp, SsaOpKind, SsaVar};

/// Bytes of caller-allocated home space required by the Windows x64 ABI.
pub const WIN64_SHADOW_SPACE_BYTES: u32 = 32;

/// Alignment and slot width for stack-passed Windows x64 arguments.
pub const WIN64_STACK_ARGUMENT_SLOT_BYTES: u32 = 8;

/// Number of architecturally addressable x86 vector register files (ZMM0..31).
pub const X86_MAX_VECTOR_REGISTER_COUNT: u8 = 32;

/// A stable semantic SSA value identity.
///
/// IDs are local to one [`HirFunction`].  They are intentionally not tied to a
/// physical location: a value may originate in a register, a unique temporary,
/// a memory load, or a future synthesized expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ValueId(u32);

impl ValueId {
    /// Construct an ID from its zero-based arena index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Return the zero-based arena index.
    pub const fn index(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A stable memory-object identity local to one [`HirFunction`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MemoryObjectId(u32);

impl MemoryObjectId {
    /// Construct an ID from its zero-based arena index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Return the zero-based arena index.
    pub const fn index(self) -> u32 {
        self.0
    }
}

impl fmt::Display for MemoryObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mem{}", self.0)
    }
}

/// A stable call-site identity local to one [`HirFunction`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CallSiteId(u32);

impl CallSiteId {
    /// Construct an ID from its zero-based arena index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Return the zero-based arena index.
    pub const fn index(self) -> u32 {
        self.0
    }
}

impl fmt::Display for CallSiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call{}", self.0)
    }
}

/// A stable operation identity local to one [`HirFunction`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct OperationId(u32);

impl OperationId {
    /// Construct an ID from its zero-based arena index.
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Return the zero-based arena index.
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// A version of one partitioned memory object.
///
/// Versions are meaningful only together with a [`MemoryObjectId`], so the
/// entry version of two different objects does not alias by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct MemoryVersion(u32);

impl MemoryVersion {
    /// Initial, function-entry version of a memory object.
    pub const ENTRY: Self = Self(0);

    /// Construct a version number.
    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    /// Return the underlying version number.
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Source position for one lifted P-code operation in the compatibility bridge.
///
/// Current [`SsaFunction`]s preserve the machine-instruction VA but not the
/// original per-instruction P-code index.  `lowered_operation_ordinal` is
/// therefore the stable, block-local SSA operation ordinal (the same ordinal
/// as [`SsaOperationKey::operation_index`]), not a claim about raw P-code order
/// inside one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PcodeOrigin {
    /// Virtual address of the machine instruction that produced the P-code.
    pub instruction_va: u64,
    /// Stable block-local ordinal assigned by the SSA compatibility bridge.
    pub lowered_operation_ordinal: u32,
}

impl PcodeOrigin {
    /// Construct one P-code source position.
    pub const fn new(instruction_va: u64, lowered_operation_ordinal: u32) -> Self {
        Self {
            instruction_va,
            lowered_operation_ordinal,
        }
    }
}

/// An inclusive range of raw P-code positions contributing to an HIR fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OriginSpan {
    /// First contributing P-code operation.
    pub first: PcodeOrigin,
    /// Last contributing P-code operation.
    pub last: PcodeOrigin,
}

impl OriginSpan {
    /// Create a range.  Callers preserve execution order when spanning more
    /// than one operation; a single operation should use [`Self::single`].
    pub const fn new(first: PcodeOrigin, last: PcodeOrigin) -> Self {
        Self { first, last }
    }

    /// Create a span covering exactly one lowered P-code operation.
    pub const fn single(instruction_va: u64, lowered_operation_ordinal: u32) -> Self {
        let origin = PcodeOrigin::new(instruction_va, lowered_operation_ordinal);
        Self::new(origin, origin)
    }
}

/// Why an HIR fact exists in addition to its raw P-code source spans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvenanceKind {
    /// Directly lifted from a P-code operation.
    Lifted,
    /// An ABI rule supplied the fact (for example, a Win64 argument register).
    Abi,
    /// A CFG merge introduced a phi-like value.
    Phi,
    /// A function-entry value has no in-function definition.
    Entry,
    /// A semantics-preserving simplification introduced the fact.
    Simplified,
    /// Type, target, or other static recovery introduced the fact.
    Recovered,
    /// A deliberately source-less synthetic fact.
    #[default]
    Synthetic,
}

/// Raw evidence attached to an HIR value, operation, object, or call.
///
/// `primary` is the direct source for the fact where one exists.  The
/// contributors preserve all additional source ranges when a pass combines
/// multiple inputs.  Source-less ABI and synthetic facts use `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Direct source range, if this fact has one.
    pub primary: Option<OriginSpan>,
    /// Additional contributing source ranges.
    pub contributors: Vec<OriginSpan>,
    /// The pass or rule that created the fact.
    pub kind: ProvenanceKind,
}

impl Provenance {
    /// Provenance for a direct P-code lifting result.
    pub fn lifted(span: OriginSpan) -> Self {
        Self {
            primary: Some(span),
            contributors: Vec::new(),
            kind: ProvenanceKind::Lifted,
        }
    }

    /// Provenance for a derived fact with optional direct source evidence.
    pub fn derived(
        kind: ProvenanceKind,
        primary: Option<OriginSpan>,
        contributors: Vec<OriginSpan>,
    ) -> Self {
        Self {
            primary,
            contributors,
            kind,
        }
    }

    /// Source-less provenance for a synthetic or ABI-derived fact.
    pub fn synthetic(kind: ProvenanceKind) -> Self {
        Self::derived(kind, None, Vec::new())
    }

    /// Iterate the primary source first, followed by every contributor.
    pub fn spans(&self) -> impl Iterator<Item = &OriginSpan> {
        self.primary.iter().chain(self.contributors.iter())
    }
}

impl Default for Provenance {
    fn default() -> Self {
        Self::synthetic(ProvenanceKind::Synthetic)
    }
}

/// Canonical x86-64 general-purpose register containers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Gpr {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

/// Canonical physical x86-64 register storage.
///
/// A [`Register::Vector`] is the one physical vector register file.  Its
/// slices model XMM/YMM/ZMM aliases, rather than treating those names as
/// independent registers.  Vector indices 0 through 31 are valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Register {
    /// A 64-bit general-purpose register container.
    Gpr(Gpr),
    /// The 64-bit instruction pointer.
    Rip,
    /// A canonical 512-bit vector register file (ZMMn).
    Vector(u8),
    /// The 64-bit architectural flags container.
    Rflags,
}

impl Register {
    /// Maximum representable width of the canonical physical register.
    pub const fn container_bits(self) -> Option<u16> {
        match self {
            Self::Gpr(_) | Self::Rip | Self::Rflags => Some(64),
            Self::Vector(index) if index < X86_MAX_VECTOR_REGISTER_COUNT => Some(512),
            Self::Vector(_) => None,
        }
    }

    /// Construct a checked canonical vector register.
    pub const fn vector(index: u8) -> Option<Self> {
        if index < X86_MAX_VECTOR_REGISTER_COUNT {
            Some(Self::Vector(index))
        } else {
            None
        }
    }
}

/// Failure to construct a valid physical-register slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterSliceError {
    /// The vector register index is outside the architectural range.
    InvalidVectorRegister { index: u8 },
    /// A zero-bit slice has no semantic value.
    EmptySlice,
    /// The requested range exceeds the canonical register container.
    OutOfBounds {
        /// Target physical register.
        register: Register,
        /// First bit in the target register.
        bit_offset: u16,
        /// Requested number of bits.
        bit_width: u16,
        /// Capacity of the target physical register.
        container_bits: u16,
    },
}

impl fmt::Display for RegisterSliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVectorRegister { index } => {
                write!(f, "vector register index {index} is outside 0..32")
            }
            Self::EmptySlice => write!(f, "a register slice must contain at least one bit"),
            Self::OutOfBounds {
                register,
                bit_offset,
                bit_width,
                container_bits,
            } => write!(
                f,
                "slice {register:?}[{bit_offset}..{}] exceeds its {container_bits}-bit container",
                u32::from(*bit_offset) + u32::from(*bit_width),
            ),
        }
    }
}

impl std::error::Error for RegisterSliceError {}

/// A bit-exact view into a canonical physical register.
///
/// The checked constructor prevents accidental alias bugs: `AL`, `AH`, `AX`,
/// `EAX`, and `RAX` are all slices of `Register::Gpr(Gpr::Rax)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegisterSlice {
    register: Register,
    bit_offset: u16,
    bit_width: u16,
}

impl RegisterSlice {
    /// Construct a checked slice of a physical register.
    pub fn new(
        register: Register,
        bit_offset: u16,
        bit_width: u16,
    ) -> Result<Self, RegisterSliceError> {
        let container_bits = match register.container_bits() {
            Some(bits) => bits,
            None => match register {
                Register::Vector(index) => {
                    return Err(RegisterSliceError::InvalidVectorRegister { index });
                }
                _ => unreachable!("only vector registers can be invalid"),
            },
        };
        if bit_width == 0 {
            return Err(RegisterSliceError::EmptySlice);
        }
        let end = u32::from(bit_offset) + u32::from(bit_width);
        if end > u32::from(container_bits) {
            return Err(RegisterSliceError::OutOfBounds {
                register,
                bit_offset,
                bit_width,
                container_bits,
            });
        }
        Ok(Self {
            register,
            bit_offset,
            bit_width,
        })
    }

    /// Whole 64-bit GPR container.
    pub const fn gpr(register: Gpr) -> Self {
        Self {
            register: Register::Gpr(register),
            bit_offset: 0,
            bit_width: 64,
        }
    }

    /// Low 128-bit XMM view of a vector register.
    pub fn xmm(index: u8) -> Result<Self, RegisterSliceError> {
        Self::new(Register::Vector(index), 0, 128)
    }

    /// Low 256-bit YMM view of a vector register.
    pub fn ymm(index: u8) -> Result<Self, RegisterSliceError> {
        Self::new(Register::Vector(index), 0, 256)
    }

    /// Full 512-bit ZMM view of a vector register.
    pub fn zmm(index: u8) -> Result<Self, RegisterSliceError> {
        Self::new(Register::Vector(index), 0, 512)
    }

    /// Whole physical register, including full vector storage where relevant.
    pub fn full(register: Register) -> Result<Self, RegisterSliceError> {
        let container_bits = match register.container_bits() {
            Some(bits) => bits,
            None => match register {
                Register::Vector(index) => {
                    return Err(RegisterSliceError::InvalidVectorRegister { index });
                }
                _ => unreachable!("only vector registers can be invalid"),
            },
        };
        Self::new(register, 0, container_bits)
    }

    /// The physical register containing this slice.
    pub const fn register(self) -> Register {
        self.register
    }

    /// Bit offset from the low bit of the physical register.
    pub const fn bit_offset(self) -> u16 {
        self.bit_offset
    }

    /// Width of this slice in bits.
    pub const fn bit_width(self) -> u16 {
        self.bit_width
    }

    /// Whether two slices touch at least one common physical bit.
    pub fn overlaps(self, other: Self) -> bool {
        if self.register != other.register {
            return false;
        }
        let self_end = u32::from(self.bit_offset) + u32::from(self.bit_width);
        let other_end = u32::from(other.bit_offset) + u32::from(other.bit_width);
        u32::from(self.bit_offset) < other_end && u32::from(other.bit_offset) < self_end
    }

    /// The architectural effect of assigning this exact register slice.
    pub const fn write_semantics(self) -> RegisterWriteSemantics {
        match self.register {
            // All 32-bit GPR writes zero-extend their 64-bit container in
            // long mode, including R8D through R15D.
            Register::Gpr(_) if self.bit_offset == 0 && self.bit_width == 32 => {
                RegisterWriteSemantics::ZeroExtendToContainer
            }
            _ => RegisterWriteSemantics::PreserveOutsideSlice,
        }
    }
}

/// How a write to a [`RegisterSlice`] affects bits outside that slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterWriteSemantics {
    /// Unwritten container bits retain their previous value.
    PreserveOutsideSlice,
    /// A 32-bit x86-64 GPR write clears the high 32 bits of the container.
    ZeroExtendToContainer,
}

/// One semantic SSA value in HIR.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Value {
    /// Stable value identity.
    pub id: ValueId,
    /// Width in bits when known.  Current SSA discards some varnode widths, so
    /// the compatibility lowering leaves it unknown rather than inventing one.
    pub bit_width: Option<u16>,
    /// Raw source and derivation evidence.
    pub provenance: Provenance,
}

impl Value {
    /// Create a value.  [`HirFunction::add_value`] assigns normal arena IDs.
    pub fn new(id: ValueId, bit_width: Option<u16>, provenance: Provenance) -> Self {
        Self {
            id,
            bit_width,
            provenance,
        }
    }
}

/// Coarse alias partition for a memory object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AliasClass {
    Stack,
    Global,
    ReadOnlyData,
    Import,
    Tls,
    Heap,
    Unknown,
}

/// Semantic category of one memory object.
///
/// Each object has its own MemorySSA version stream.  `Unknown` is an explicit
/// conservative escape hatch, not an implicit catch-all for every RAM access.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryObjectKind {
    /// A frame-relative stack slot at the given signed displacement.
    StackSlot { frame_offset: i64 },
    /// Writable image or process global at an absolute VA.
    Global { va: u64 },
    /// Read-only image data, such as a string literal or vtable, at an absolute VA.
    ReadOnlyData { va: u64 },
    /// An import address-table slot at an absolute VA.
    ImportSlot { iat_va: u64 },
    /// A thread-local object at a TLS-relative offset.
    Tls { offset: i64 },
    /// A heap object identified, when possible, by the SSA value returned by
    /// its allocator call.
    Heap { allocation: Option<ValueId> },
    /// A conservative unresolved alias partition.
    Unknown,
}

impl MemoryObjectKind {
    /// Return the coarse alias partition for this object kind.
    pub const fn alias_class(&self) -> AliasClass {
        match self {
            Self::StackSlot { .. } => AliasClass::Stack,
            Self::Global { .. } => AliasClass::Global,
            Self::ReadOnlyData { .. } => AliasClass::ReadOnlyData,
            Self::ImportSlot { .. } => AliasClass::Import,
            Self::Tls { .. } => AliasClass::Tls,
            Self::Heap { .. } => AliasClass::Heap,
            Self::Unknown => AliasClass::Unknown,
        }
    }
}

/// One partitioned memory object tracked by HIR.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryObject {
    /// Stable object identity.
    pub id: MemoryObjectId,
    /// Alias category and address identity where known.
    pub kind: MemoryObjectKind,
    /// Object size in bytes when statically known.
    pub size_bytes: Option<u64>,
    /// Object alignment in bytes when statically known.
    pub alignment: Option<u32>,
    /// Evidence supporting the object classification.
    pub provenance: Provenance,
}

impl MemoryObject {
    /// Create a memory object.  [`HirFunction::add_memory_object`] assigns
    /// normal arena IDs.
    pub fn new(
        id: MemoryObjectId,
        kind: MemoryObjectKind,
        size_bytes: Option<u64>,
        alignment: Option<u32>,
        provenance: Provenance,
    ) -> Self {
        Self {
            id,
            kind,
            size_bytes,
            alignment,
            provenance,
        }
    }

    /// Return the object's coarse alias partition.
    pub const fn alias_class(&self) -> AliasClass {
        self.kind.alias_class()
    }
}

/// A typed reference to one version of a partitioned memory object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemoryAccess {
    /// Target memory object.
    pub object: MemoryObjectId,
    /// Byte displacement within the object.
    pub byte_offset: i64,
    /// Number of accessed bytes.
    pub width_bytes: u32,
    /// Reaching version for a load, or produced version for a store.
    pub version: MemoryVersion,
}

/// Target of a Windows x64 call.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallTarget {
    /// Direct relative or absolute target in the current image.
    Direct { va: u64 },
    /// Imported target reached through an IAT slot.
    Import {
        /// IAT slot address.
        iat_va: u64,
        /// Best known import name, if symbols were available.
        symbol: Option<String>,
    },
    /// An indirect target expression plus optional resolved candidate VAs.
    Indirect {
        /// Pointer value evaluated by the call.
        target: ValueId,
        /// Candidate function VAs from dataflow, CFG, vtables, or signatures.
        candidates: Vec<u64>,
    },
    /// The target was not recoverable.
    Unknown,
}

/// ABI class used to select a Windows x64 argument location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Win64ArgumentClass {
    /// Integer, pointer, or scalar aggregate representation.
    Integer,
    /// Scalar floating-point representation.
    FloatingPoint,
    /// Aggregate passed indirectly through a pointer.
    AggregateByReference,
    /// The type is not known well enough to infer a register location.
    Unknown,
}

/// Physical location carrying one Windows x64 argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Win64ArgumentLocation {
    /// A register slice carries the argument.
    Register(RegisterSlice),
    /// A caller-stack location measured from RSP immediately before `call`.
    ///
    /// The first stack argument is at offset 32, after the four home slots.
    Stack { offset_from_pre_call_rsp: u32 },
}

impl Win64ArgumentLocation {
    /// Return the ordinary Windows x64 location for an ABI argument position.
    ///
    /// The method returns `None` for a register-positioned `Unknown` argument;
    /// a lifter that knows the observed register can construct it explicitly.
    pub fn standard(position: u16, class: Win64ArgumentClass) -> Option<Self> {
        if position >= 4 {
            return Some(Self::Stack {
                offset_from_pre_call_rsp: WIN64_SHADOW_SPACE_BYTES
                    + WIN64_STACK_ARGUMENT_SLOT_BYTES * u32::from(position - 4),
            });
        }

        match class {
            Win64ArgumentClass::Integer | Win64ArgumentClass::AggregateByReference => {
                let gpr = match position {
                    0 => Gpr::Rcx,
                    1 => Gpr::Rdx,
                    2 => Gpr::R8,
                    3 => Gpr::R9,
                    _ => unreachable!("position is checked to be below four"),
                };
                Some(Self::Register(RegisterSlice::gpr(gpr)))
            }
            Win64ArgumentClass::FloatingPoint => Some(Self::Register(
                RegisterSlice::xmm(position as u8)
                    .expect("the first four vector register indices are valid"),
            )),
            Win64ArgumentClass::Unknown => None,
        }
    }

    /// Whether this location is a caller-stack argument slot.
    pub const fn is_stack(self) -> bool {
        matches!(self, Self::Stack { .. })
    }
}

/// One logical Windows x64 argument and every location used to pass it.
///
/// Most arguments have one location.  `locations` is a vector because varargs
/// and ABI adaptations can mirror a floating-point value in more than one
/// register without creating a second logical argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Win64Argument {
    /// Zero-based argument position in the logical function signature.
    pub position: u16,
    /// Semantic value passed to the callee.
    pub value: ValueId,
    /// Best known ABI class.
    pub class: Win64ArgumentClass,
    /// One or more concrete register or stack locations.
    pub locations: Vec<Win64ArgumentLocation>,
}

impl Win64Argument {
    /// Create an explicit argument representation.
    pub fn new(
        position: u16,
        value: ValueId,
        class: Win64ArgumentClass,
        locations: Vec<Win64ArgumentLocation>,
    ) -> Self {
        Self {
            position,
            value,
            class,
            locations,
        }
    }

    /// Create an ordinary Windows x64 argument when its ABI class is known.
    pub fn standard(position: u16, value: ValueId, class: Win64ArgumentClass) -> Option<Self> {
        Win64ArgumentLocation::standard(position, class)
            .map(|location| Self::new(position, value, class, vec![location]))
    }
}

/// ABI class of a Windows x64 call result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Win64ResultClass {
    /// Integer or pointer result in RAX.
    Integer,
    /// Floating-point result in XMM0.
    FloatingPoint,
    /// Aggregate result materialized through a hidden caller-provided pointer.
    AggregateIndirect,
    /// The result class is not known yet.
    Unknown,
}

/// Concrete destination of a Windows x64 call result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Win64ResultLocation {
    /// A register slice carries the result.
    Register(RegisterSlice),
    /// The result was written through a caller-provided storage pointer.
    Indirect {
        /// Pointer value passed to the callee for result storage.
        storage_pointer: ValueId,
        /// Some ABI implementations also return that pointer in RAX.
        returned_pointer: Option<RegisterSlice>,
    },
}

/// One semantic value produced by a Windows x64 call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Win64Result {
    /// Semantic result value.
    pub value: ValueId,
    /// Recovered result ABI class.
    pub class: Win64ResultClass,
    /// Concrete ABI destination.
    pub location: Win64ResultLocation,
}

impl Win64Result {
    /// Ordinary integer or pointer result in RAX.
    pub fn integer(value: ValueId) -> Self {
        Self {
            value,
            class: Win64ResultClass::Integer,
            location: Win64ResultLocation::Register(RegisterSlice::gpr(Gpr::Rax)),
        }
    }

    /// Ordinary floating-point result in XMM0.
    pub fn floating_point(value: ValueId) -> Self {
        Self {
            value,
            class: Win64ResultClass::FloatingPoint,
            location: Win64ResultLocation::Register(RegisterSlice::xmm(0).expect("XMM0 is valid")),
        }
    }

    /// Aggregate result written to caller storage, conventionally returning the
    /// storage pointer in RAX as well.
    pub fn aggregate_indirect(value: ValueId, storage_pointer: ValueId) -> Self {
        Self {
            value,
            class: Win64ResultClass::AggregateIndirect,
            location: Win64ResultLocation::Indirect {
                storage_pointer,
                returned_pointer: Some(RegisterSlice::gpr(Gpr::Rax)),
            },
        }
    }
}

/// Memory effect of a call after applying any known purity/effect summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryClobber {
    /// The call is known not to write memory.
    None,
    /// The call may write the listed partitioned objects.
    Objects(Vec<MemoryObjectId>),
    /// The call may write any memory object that can alias its arguments.
    Unknown,
}

/// Volatile state at a call boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallClobbers {
    /// Register slices whose values cannot be used after the call.
    pub registers: Vec<RegisterSlice>,
    /// Memory partitions potentially changed by the call.
    pub memory: MemoryClobber,
}

impl CallClobbers {
    /// Default Windows x64 volatile state for a call with no stronger summary.
    pub fn windows_x64_default() -> Self {
        let mut registers = vec![
            RegisterSlice::gpr(Gpr::Rax),
            RegisterSlice::gpr(Gpr::Rcx),
            RegisterSlice::gpr(Gpr::Rdx),
            RegisterSlice::gpr(Gpr::R8),
            RegisterSlice::gpr(Gpr::R9),
            RegisterSlice::gpr(Gpr::R10),
            RegisterSlice::gpr(Gpr::R11),
            RegisterSlice::full(Register::Rflags).expect("RFLAGS is valid"),
        ];
        for index in 0..6 {
            registers
                .push(RegisterSlice::zmm(index).expect("the first six vector registers are valid"));
        }
        Self {
            registers,
            memory: MemoryClobber::Unknown,
        }
    }

    /// Return whether an overlapping register slice is clobbered.
    pub fn clobbers_register(&self, register: RegisterSlice) -> bool {
        self.registers
            .iter()
            .copied()
            .any(|clobber| clobber.overlaps(register))
    }

    /// Return whether a memory object may be clobbered.
    pub fn clobbers_memory(&self, object: MemoryObjectId) -> bool {
        match &self.memory {
            MemoryClobber::None => false,
            MemoryClobber::Objects(objects) => objects.contains(&object),
            MemoryClobber::Unknown => true,
        }
    }
}

/// Semantic Windows x64 call representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Win64CallSite {
    /// Source evidence for the call instruction and recovered target.
    pub provenance: Provenance,
    /// Direct, import, indirect, or unknown target.
    pub target: CallTarget,
    /// Ordered logical arguments with concrete ABI locations.
    pub arguments: Vec<Win64Argument>,
    /// Optional result when the caller observes one.
    pub result: Option<Win64Result>,
    /// Volatile state and memory effects after the call.
    pub clobbers: CallClobbers,
}

impl Win64CallSite {
    /// Create a call with the ordinary conservative Windows x64 clobber set.
    pub fn new(provenance: Provenance, target: CallTarget, arguments: Vec<Win64Argument>) -> Self {
        Self {
            provenance,
            target,
            arguments,
            result: None,
            clobbers: CallClobbers::windows_x64_default(),
        }
    }

    /// Minimum caller stack area occupied by shadow space and stack arguments.
    pub fn required_outgoing_stack_bytes(&self) -> u32 {
        self.arguments
            .iter()
            .flat_map(|argument| argument.locations.iter())
            .filter_map(|location| match location {
                Win64ArgumentLocation::Stack {
                    offset_from_pre_call_rsp,
                } => Some(offset_from_pre_call_rsp + WIN64_STACK_ARGUMENT_SLOT_BYTES),
                Win64ArgumentLocation::Register(_) => None,
            })
            .max()
            .unwrap_or(WIN64_SHADOW_SPACE_BYTES)
            .max(WIN64_SHADOW_SPACE_BYTES)
    }
}

/// Generic operation category retained by the SSA compatibility bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirOperationKind {
    /// A raw P-code operation whose exact opcode remains in the frozen source IR.
    Pcode,
    /// A semantic CFG merge introduced from an SSA phi node.
    Phi,
    /// Expression-level select (CMOV/setcc micro-control reduced instruction-locally).
    Select,
    /// Memory load through a partitioned object.
    Load,
    /// Memory store through a partitioned object.
    Store,
    /// Call site (Win64 ABI facts live on [`Win64CallSite`]).
    Call,
    /// Cast / width change with exact bit widths on values.
    Cast,
    /// Compare producing a 1-bit or flag-derived boolean.
    Compare,
}

/// A value-def/use operation in the HIR provenance trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirOperation {
    /// Stable operation identity.
    pub id: OperationId,
    /// Compatibility operation category.
    pub kind: HirOperationKind,
    /// Values read by the operation.
    pub inputs: Vec<ValueId>,
    /// Value defined by the operation, where applicable.
    pub output: Option<ValueId>,
    /// Raw source and derivation evidence.
    pub provenance: Provenance,
}

/// One `SsaFunction` operation's stable position for [`SsaLowering`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaOperationKey {
    /// Existing SSA basic-block ID.
    pub block_id: u32,
    /// Zero-based operation index in that block.
    pub operation_index: u32,
}

/// Result of the pure compatibility bridge from current SSA into HIR.
#[derive(Clone, Debug)]
pub struct SsaLowering {
    /// New HIR arena carrying value identities and P-code provenance.
    pub hir: HirFunction,
    /// Mapping from current location/version SSA variables to HIR values.
    pub values: HashMap<SsaVar, ValueId>,
    /// Mapping from current SSA operation positions to HIR operations.
    pub operations: HashMap<SsaOperationKey, OperationId>,
    /// Call facts lifted from a current SSA operation, keyed by that operation.
    ///
    /// This keeps [`lift_win64_calls`] idempotent without attaching mutable
    /// analysis state to the frozen SSA form itself.
    pub call_sites: HashMap<SsaOperationKey, CallSiteId>,
}

impl SsaLowering {
    /// Add conservative Windows x64 call facts from the source SSA function.
    pub fn lift_win64_calls(&mut self, ssa: &SsaFunction) -> Vec<CallSiteId> {
        lift_win64_calls(ssa, self)
    }

    /// Resolve the source SSA value recorded for one architectural return.
    pub fn exit_ssa_var(&self, block_id: u32) -> Option<&SsaVar> {
        let value = self.hir.exit_values.get(&block_id)?;
        self.values
            .iter()
            .find_map(|(var, id)| (id == value).then_some(var))
    }
}

/// Arena-backed semantic HIR for one function.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HirFunction {
    values: Vec<Value>,
    operations: Vec<HirOperation>,
    memory_objects: Vec<MemoryObject>,
    call_sites: Vec<Win64CallSite>,
    /// Per-exit reaching return values (block_id → value), not global richest-expr.
    #[serde(default)]
    pub exit_values: BTreeMap<u32, ValueId>,
    /// MemorySSA version counters per object (entry = 0).
    #[serde(default)]
    pub memory_versions: BTreeMap<MemoryObjectId, MemoryVersion>,
}

impl HirFunction {
    /// Allocate a semantic value and return its stable local ID.
    pub fn add_value(&mut self, bit_width: Option<u16>, provenance: Provenance) -> ValueId {
        let id = ValueId::new(
            u32::try_from(self.values.len())
                .expect("a HIR function cannot contain over u32 values"),
        );
        self.values.push(Value::new(id, bit_width, provenance));
        id
    }

    /// Allocate a provenance-trace operation and return its stable local ID.
    pub fn add_operation(
        &mut self,
        kind: HirOperationKind,
        inputs: Vec<ValueId>,
        output: Option<ValueId>,
        provenance: Provenance,
    ) -> OperationId {
        let id = OperationId::new(
            u32::try_from(self.operations.len())
                .expect("a HIR function cannot contain over u32 operations"),
        );
        self.operations.push(HirOperation {
            id,
            kind,
            inputs,
            output,
            provenance,
        });
        id
    }

    /// Allocate a partitioned memory object and return its stable local ID.
    pub fn add_memory_object(
        &mut self,
        kind: MemoryObjectKind,
        size_bytes: Option<u64>,
        alignment: Option<u32>,
        provenance: Provenance,
    ) -> MemoryObjectId {
        let id = MemoryObjectId::new(
            u32::try_from(self.memory_objects.len())
                .expect("a HIR function cannot contain over u32 memory objects"),
        );
        self.memory_objects.push(MemoryObject::new(
            id, kind, size_bytes, alignment, provenance,
        ));
        id
    }

    /// Allocate a Windows x64 call site and return its stable local ID.
    pub fn add_call_site(&mut self, call_site: Win64CallSite) -> CallSiteId {
        let id = CallSiteId::new(
            u32::try_from(self.call_sites.len())
                .expect("a HIR function cannot contain over u32 call sites"),
        );
        self.call_sites.push(call_site);
        id
    }

    /// Look up a value by stable ID.
    pub fn value(&self, id: ValueId) -> Option<&Value> {
        self.values.get(id.index() as usize)
    }

    /// Mutably look up a value by stable ID.
    pub fn value_mut(&mut self, id: ValueId) -> Option<&mut Value> {
        self.values.get_mut(id.index() as usize)
    }

    /// Look up an operation by stable ID.
    pub fn operation(&self, id: OperationId) -> Option<&HirOperation> {
        self.operations.get(id.index() as usize)
    }

    /// Look up a memory object by stable ID.
    pub fn memory_object(&self, id: MemoryObjectId) -> Option<&MemoryObject> {
        self.memory_objects.get(id.index() as usize)
    }

    /// Look up a call site by stable ID.
    pub fn call_site(&self, id: CallSiteId) -> Option<&Win64CallSite> {
        self.call_sites.get(id.index() as usize)
    }

    /// All values in stable ID order.
    pub fn values(&self) -> &[Value] {
        &self.values
    }

    /// All operation traces in stable ID order.
    pub fn operations(&self) -> &[HirOperation] {
        &self.operations
    }

    /// All memory objects in stable ID order.
    pub fn memory_objects(&self) -> &[MemoryObject] {
        &self.memory_objects
    }

    /// All call sites in stable ID order.
    pub fn call_sites(&self) -> &[Win64CallSite] {
        &self.call_sites
    }

    /// Build the additive provenance/value bridge from the existing SSA form.
    pub fn lower_from_ssa(ssa: &SsaFunction) -> SsaLowering {
        lower_from_ssa(ssa)
    }

    /// Verify arena identities and every cross-reference in this HIR function.
    pub fn validate(&self) -> Result<(), HirValidationError> {
        for (index, value) in self.values.iter().enumerate() {
            let expected = ValueId::new(
                u32::try_from(index).expect("a HIR function cannot contain over u32 values"),
            );
            if value.id != expected {
                return Err(HirValidationError::ValueIdMismatch {
                    expected,
                    actual: value.id,
                });
            }
            if value.bit_width == Some(0) {
                return Err(HirValidationError::InvalidValueWidth { value: value.id });
            }
        }

        for (index, object) in self.memory_objects.iter().enumerate() {
            let expected = MemoryObjectId::new(
                u32::try_from(index)
                    .expect("a HIR function cannot contain over u32 memory objects"),
            );
            if object.id != expected {
                return Err(HirValidationError::MemoryObjectIdMismatch {
                    expected,
                    actual: object.id,
                });
            }
            if object.size_bytes == Some(0) {
                return Err(HirValidationError::InvalidMemoryObjectSize { object: object.id });
            }
            if let Some(alignment) = object.alignment
                && !alignment.is_power_of_two()
            {
                return Err(HirValidationError::InvalidMemoryAlignment {
                    object: object.id,
                    alignment,
                });
            }
            if let MemoryObjectKind::Heap {
                allocation: Some(value),
            } = object.kind
            {
                self.require_value(value)?;
            }
        }

        for (index, operation) in self.operations.iter().enumerate() {
            let expected = OperationId::new(
                u32::try_from(index).expect("a HIR function cannot contain over u32 operations"),
            );
            if operation.id != expected {
                return Err(HirValidationError::OperationIdMismatch {
                    expected,
                    actual: operation.id,
                });
            }
            for value in &operation.inputs {
                self.require_value(*value)?;
            }
            if let Some(value) = operation.output {
                self.require_value(value)?;
            }
        }

        for value in self.exit_values.values() {
            self.require_value(*value)?;
        }

        for (index, call_site) in self.call_sites.iter().enumerate() {
            let call = CallSiteId::new(
                u32::try_from(index).expect("a HIR function cannot contain over u32 call sites"),
            );
            if let CallTarget::Indirect { target, .. } = call_site.target {
                self.require_value(target)?;
            }

            let mut positions = BTreeSet::new();
            for argument in &call_site.arguments {
                self.require_value(argument.value)?;
                if !positions.insert(argument.position) {
                    return Err(HirValidationError::DuplicateArgumentPosition {
                        call,
                        position: argument.position,
                    });
                }
                if argument.locations.is_empty() {
                    return Err(HirValidationError::EmptyArgumentLocations {
                        call,
                        position: argument.position,
                    });
                }
                for location in &argument.locations {
                    if let Win64ArgumentLocation::Stack {
                        offset_from_pre_call_rsp,
                    } = location
                        && (*offset_from_pre_call_rsp < WIN64_SHADOW_SPACE_BYTES
                            || *offset_from_pre_call_rsp % WIN64_STACK_ARGUMENT_SLOT_BYTES != 0)
                    {
                        return Err(HirValidationError::InvalidStackArgumentLocation {
                            call,
                            position: argument.position,
                            offset_from_pre_call_rsp: *offset_from_pre_call_rsp,
                        });
                    }
                }
            }

            if let Some(result) = &call_site.result {
                self.require_value(result.value)?;
                if let Win64ResultLocation::Indirect {
                    storage_pointer, ..
                } = result.location
                {
                    self.require_value(storage_pointer)?;
                }
            }

            if let MemoryClobber::Objects(objects) = &call_site.clobbers.memory {
                for object in objects {
                    self.require_memory_object(*object)?;
                }
            }
        }

        Ok(())
    }

    fn require_value(&self, value: ValueId) -> Result<(), HirValidationError> {
        if self.value(value).is_some() {
            Ok(())
        } else {
            Err(HirValidationError::UnknownValue { value })
        }
    }

    fn require_memory_object(&self, object: MemoryObjectId) -> Result<(), HirValidationError> {
        if self.memory_object(object).is_some() {
            Ok(())
        } else {
            Err(HirValidationError::UnknownMemoryObject { object })
        }
    }
}

/// Structural error reported by [`HirFunction::validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HirValidationError {
    ValueIdMismatch {
        expected: ValueId,
        actual: ValueId,
    },
    OperationIdMismatch {
        expected: OperationId,
        actual: OperationId,
    },
    MemoryObjectIdMismatch {
        expected: MemoryObjectId,
        actual: MemoryObjectId,
    },
    InvalidValueWidth {
        value: ValueId,
    },
    InvalidMemoryObjectSize {
        object: MemoryObjectId,
    },
    InvalidMemoryAlignment {
        object: MemoryObjectId,
        alignment: u32,
    },
    UnknownValue {
        value: ValueId,
    },
    UnknownMemoryObject {
        object: MemoryObjectId,
    },
    EmptyArgumentLocations {
        call: CallSiteId,
        position: u16,
    },
    DuplicateArgumentPosition {
        call: CallSiteId,
        position: u16,
    },
    InvalidStackArgumentLocation {
        call: CallSiteId,
        position: u16,
        offset_from_pre_call_rsp: u32,
    },
}

impl fmt::Display for HirValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueIdMismatch { expected, actual } => {
                write!(f, "value arena expected {expected}, found {actual}")
            }
            Self::OperationIdMismatch { expected, actual } => {
                write!(
                    f,
                    "operation arena expected op{}, found op{}",
                    expected.index(),
                    actual.index()
                )
            }
            Self::MemoryObjectIdMismatch { expected, actual } => {
                write!(f, "memory arena expected {expected}, found {actual}")
            }
            Self::InvalidValueWidth { value } => write!(f, "{value} has a zero-bit width"),
            Self::InvalidMemoryObjectSize { object } => {
                write!(f, "{object} has a zero-byte size")
            }
            Self::InvalidMemoryAlignment { object, alignment } => {
                write!(f, "{object} has non-power-of-two alignment {alignment}")
            }
            Self::UnknownValue { value } => write!(f, "reference to unknown {value}"),
            Self::UnknownMemoryObject { object } => {
                write!(f, "reference to unknown {object}")
            }
            Self::EmptyArgumentLocations { call, position } => {
                write!(f, "{call} argument {position} has no physical locations")
            }
            Self::DuplicateArgumentPosition { call, position } => {
                write!(f, "{call} contains duplicate argument position {position}")
            }
            Self::InvalidStackArgumentLocation {
                call,
                position,
                offset_from_pre_call_rsp,
            } => write!(
                f,
                "{call} argument {position} uses invalid caller-stack offset {offset_from_pre_call_rsp}",
            ),
        }
    }
}

impl std::error::Error for HirValidationError {}

/// Pure bridge from the existing SSA side-layer to the additive HIR arena.
///
/// Every [`SsaVar`] receives one stable [`ValueId`].  P-code operations retain
/// their instruction VA in [`PcodeOrigin`]; phis retain an explicit synthetic
/// provenance because they have no raw P-code operation.  The bridge makes no
/// claim that current SSA locations are precise memory objects or register
/// slices. Instruction-scoped SLEIGH `Unique` values retain their known
/// varnode width; all other compatibility values remain width-unknown. The
/// bridge does not manufacture call arguments.
pub fn lower_from_ssa(ssa: &SsaFunction) -> SsaLowering {
    let mut hir = HirFunction::default();
    let mut values = HashMap::new();
    let mut operations = HashMap::new();

    for block in &ssa.blocks {
        for (index, ssa_op) in block.ops.iter().enumerate() {
            let operation_index =
                u32::try_from(index).expect("an SSA block cannot contain over u32 operations");
            let key = SsaOperationKey {
                block_id: block.id,
                operation_index,
            };

            let (kind, input_vars, output_var, provenance) = match &ssa_op.kind {
                SsaOpKind::Pcode(_) => (
                    HirOperationKind::Pcode,
                    ssa_op.uses.clone(),
                    ssa_op.def.clone(),
                    Provenance::lifted(OriginSpan::single(ssa_op.va, operation_index)),
                ),
                SsaOpKind::Phi(phi) => (
                    HirOperationKind::Phi,
                    phi.args.iter().flatten().cloned().collect(),
                    Some(phi.out.clone()),
                    Provenance::synthetic(ProvenanceKind::Phi),
                ),
            };

            let use_provenance = Provenance::derived(
                ProvenanceKind::Entry,
                provenance.primary,
                provenance.contributors.clone(),
            );
            let inputs = input_vars
                .iter()
                .cloned()
                .map(|var| ensure_ssa_value(&mut hir, &mut values, var, &use_provenance, false))
                .collect();
            let output = output_var
                .map(|var| ensure_ssa_value(&mut hir, &mut values, var, &provenance, true));
            let id = hir.add_operation(kind, inputs, output, provenance);
            operations.insert(key, id);
        }
    }

    // Record each architectural exit independently. This follows the reaching
    // RAX-family SSA value through a unique predecessor chain and accepts
    // merges only through an explicit phi or an identical incoming value.
    // Never select a value from a different exit or a function-wide heuristic.
    for block in &ssa.blocks {
        if let Some(var) = crate::decompiler::ssa::reaching_register_at_return(ssa, block.id, 0)
            && let Some(value) = values.get(&var).copied()
        {
            hir.exit_values.insert(block.id, value);
        }
    }

    SsaLowering {
        hir,
        values,
        operations,
        call_sites: HashMap::new(),
    }
}

/// Lift conservative Windows x64 call facts from an existing SSA function.
///
/// The pass is deliberately local and pure: it consults only `ssa` and the
/// value/operation maps produced by [`lower_from_ssa`].  For each `Call` or
/// `CallInd`, it preserves the source operation provenance, records a direct
/// target when P-code carries an address, or records an indirect target only
/// when an HIR value is available.  It records RCX/RDX/R8/R9 arguments only
/// when a resolved call contract added that register as an SSA use and the
/// same block defines a reaching value after any earlier call.
///
/// It never creates a return value, synthetic stack argument, or missing
/// register value.  Call sites receive [`CallClobbers::windows_x64_default`]
/// through [`Win64CallSite::new`].  The returned IDs are only the facts created
/// by this invocation; a repeated invocation is idempotent.
pub fn lift_win64_calls(ssa: &SsaFunction, lowering: &mut SsaLowering) -> Vec<CallSiteId> {
    let mut lifted = Vec::new();

    for block in &ssa.blocks {
        for (index, ssa_op) in block.ops.iter().enumerate() {
            let dest = match &ssa_op.kind {
                SsaOpKind::Pcode(PcodeOp::Call { dest })
                | SsaOpKind::Pcode(PcodeOp::CallInd { dest }) => *dest,
                SsaOpKind::Pcode(PcodeOp::Branch { dest }) => {
                    if crate::decompiler::normalize::external_tail_call_target(ssa, *dest).is_some()
                    {
                        *dest
                    } else {
                        continue;
                    }
                }
                // apply(f,x) optimizes to `jmp rax` (BranchInd) — still a call site.
                SsaOpKind::Pcode(PcodeOp::BranchInd { dest })
                    if dest.space == pcode_ir::AddressSpaceId::Register
                        && ssa.blocks.len() == 1 =>
                {
                    *dest
                }
                _ => continue,
            };
            let operation_index =
                u32::try_from(index).expect("an SSA block cannot contain over u32 operations");
            let key = SsaOperationKey {
                block_id: block.id,
                operation_index,
            };
            if lowering.call_sites.contains_key(&key) {
                continue;
            }

            // A lowering built from some other SSA function is not trustworthy
            // evidence.  Skip it rather than inventing a source ordinal.
            let Some(operation_id) = lowering.operations.get(&key).copied() else {
                continue;
            };
            let Some(operation) = lowering.hir.operation(operation_id) else {
                continue;
            };
            let provenance = Provenance::derived(
                ProvenanceKind::Abi,
                operation.provenance.primary,
                operation.provenance.contributors.clone(),
            );
            let target = lift_call_target(block, index, ssa_op, dest, &lowering.values);
            let arguments = lift_same_block_win64_arguments(block, index, ssa_op, &lowering.values);

            let call_id = lowering
                .hir
                .add_call_site(Win64CallSite::new(provenance, target, arguments));
            lowering.call_sites.insert(key, call_id);
            lifted.push(call_id);
        }
    }

    lifted
}

/// x86-64 SLEIGH register-container offsets in Windows x64 integer argument order.
const WIN64_GPR_ARGUMENT_REGISTERS: [(u64, Gpr); 4] = [
    (0x08, Gpr::Rcx),
    (0x10, Gpr::Rdx),
    (0x80, Gpr::R8),
    (0x88, Gpr::R9),
];

fn lift_call_target(
    block: &SsaBlock,
    call_index: usize,
    call_op: &SsaOp,
    dest: Varnode,
    values: &HashMap<SsaVar, ValueId>,
) -> CallTarget {
    match dest.space {
        // SLEIGH uses Const for ordinary direct calls.  Ram is retained here
        // for its existing direct-address representation in the lifter/export
        // path; both forms carry a concrete target VA rather than a value.
        AddressSpaceId::Const | AddressSpaceId::Ram => CallTarget::Direct { va: dest.offset },
        AddressSpaceId::Register => {
            let base = crate::decompiler::ssa::lower::register_container_base(dest.offset);
            let target = reaching_register_for_indirect_target(block, call_index, call_op, base)
                .and_then(|var| values.get(&var).copied());
            target
                .map(|target| CallTarget::Indirect {
                    target,
                    candidates: Vec::new(),
                })
                .unwrap_or(CallTarget::Unknown)
        }
        // A Unique varnode is instruction-scoped. Match all three identity
        // components against the CallInd operation, not merely its raw SLEIGH
        // offset: offsets are reused by different decoded instructions.
        AddressSpaceId::Unique => call_op
            .uses
            .iter()
            .find(|use_var| {
                matches!(
                    &use_var.location,
                    Location::Unique {
                        instruction_va,
                        offset,
                        size,
                    } if *instruction_va == call_op.va
                        && *offset == dest.offset
                        && *size == dest.size
                )
            })
            .and_then(|var| values.get(var).copied())
            .map(|target| CallTarget::Indirect {
                target,
                candidates: Vec::new(),
            })
            .unwrap_or(CallTarget::Unknown),
    }
}

fn lift_same_block_win64_arguments(
    block: &SsaBlock,
    call_index: usize,
    call_op: &SsaOp,
    values: &HashMap<SsaVar, ValueId>,
) -> Vec<Win64Argument> {
    // Indirect targets do not yet carry an authoritative call contract in the
    // SSA sidecar.  Preserve their target evidence, but avoid turning a target
    // register or unrelated live register into a fabricated argument list.
    //
    // Direct CALL: only GPRs listed in the call's ABI uses.
    // Tail BRANCH (MSVC `jmp leaf`): claim RCX only when locally defined before
    // the branch — matches `mid(x){return leaf(x+1);}` without inventing args.
    let is_direct_call = matches!(&call_op.kind, SsaOpKind::Pcode(PcodeOp::Call { .. }));
    let is_tail_branch = matches!(&call_op.kind, SsaOpKind::Pcode(PcodeOp::Branch { .. }));
    if !is_direct_call && !is_tail_branch {
        return Vec::new();
    }

    WIN64_GPR_ARGUMENT_REGISTERS
        .iter()
        .enumerate()
        .filter_map(|(position, (base, _register))| {
            if is_direct_call {
                let required_by_contract = call_op.uses.iter().any(|use_var| {
                    matches!(use_var.location, Location::Register { base_offset } if base_offset == *base)
                });
                if !required_by_contract {
                    return None;
                }
            } else if *base != 0x08 {
                // Tail-jmp: only first integer arg (RCX).
                return None;
            }
            let var = same_block_reaching_register(block, call_index, *base)?;
            let value = values.get(&var).copied()?;
            Win64Argument::standard(position as u16, value, Win64ArgumentClass::Integer)
        })
        .collect()
}

/// Return a same-block reaching register definition, without crossing a call.
///
/// This deliberately does not fall back to a block-entry SSA use.  A caller's
/// register arguments are a useful fact only when this lightweight pass can
/// point to a local definition; wider inter-block dataflow belongs in a later
/// analysis pass.
fn same_block_reaching_register(
    block: &SsaBlock,
    call_index: usize,
    base_offset: u64,
) -> Option<SsaVar> {
    for prior in block.ops[..call_index].iter().rev() {
        if is_pcode_call(prior) {
            return None;
        }
        if let Some(def) = &prior.def
            && matches!(def.location, Location::Register { base_offset: base } if base == base_offset)
        {
            return Some(def.clone());
        }
    }
    None
}

/// Resolve an indirect target from a register, allowing an entry value only if
/// there was no earlier call in the same block to invalidate it.
fn reaching_register_for_indirect_target(
    block: &SsaBlock,
    call_index: usize,
    call_op: &SsaOp,
    base_offset: u64,
) -> Option<SsaVar> {
    for prior in block.ops[..call_index].iter().rev() {
        if is_pcode_call(prior) {
            return None;
        }
        if let Some(def) = &prior.def
            && matches!(def.location, Location::Register { base_offset: base } if base == base_offset)
        {
            return Some(def.clone());
        }
    }
    call_op
        .uses
        .iter()
        .find(|use_var| {
            matches!(use_var.location, Location::Register { base_offset: base } if base == base_offset)
        })
        .cloned()
}

fn is_pcode_call(op: &SsaOp) -> bool {
    matches!(
        &op.kind,
        SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. })
    )
}

fn ensure_ssa_value(
    hir: &mut HirFunction,
    values: &mut HashMap<SsaVar, ValueId>,
    var: SsaVar,
    provenance: &Provenance,
    is_definition: bool,
) -> ValueId {
    if let Some(id) = values.get(&var).copied() {
        if is_definition {
            hir.value_mut(id)
                .expect("SSA value map only contains HIR arena IDs")
                .provenance = provenance.clone();
        }
        return id;
    }

    let id = hir.add_value(ssa_value_bit_width(&var), provenance.clone());
    values.insert(var, id);
    id
}

/// Recover a width only where the current SSA location itself preserves it.
///
/// Register and memory locations are deliberately container/coarse-grained in
/// the compatibility SSA layer, so assigning them a width here would be a
/// guess. A namespaced Unique location, however, originates from one exact
/// P-code varnode and retains its byte width.
fn ssa_value_bit_width(var: &SsaVar) -> Option<u16> {
    let Location::Unique { size, .. } = &var.location else {
        return None;
    };
    let bits = u16::try_from(*size).ok()?.checked_mul(8)?;
    (bits != 0).then_some(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pcode::{PcodeOp, Varnode};
    use crate::decompiler::ssa::{Location, SsaBlock, SsaOp};

    fn provenance_at(va: u64) -> Provenance {
        Provenance::lifted(OriginSpan::single(va, 0))
    }

    fn ssa_var(offset: u64, version: u32) -> SsaVar {
        SsaVar {
            location: Location::Register {
                base_offset: offset,
            },
            version,
        }
    }

    fn define_register(va: u64, offset: u64, version: u32) -> SsaOp {
        SsaOp {
            va,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(offset, 8),
                input: Varnode::constant(u64::from(version), 8),
            }),
            def: Some(ssa_var(offset, version)),
            uses: Vec::new(),
        }
    }

    fn direct_call(va: u64, target: u64, uses: Vec<SsaVar>) -> SsaOp {
        SsaOp {
            va,
            kind: SsaOpKind::Pcode(PcodeOp::Call {
                dest: Varnode::constant(target, 8),
            }),
            def: None,
            uses,
        }
    }

    fn single_block_ssa(ops: Vec<SsaOp>) -> SsaFunction {
        SsaFunction {
            entry_va: 0x401000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x401000,
                ops,
                predecessor_ids: Vec::new(),
                successor_ids: Vec::new(),
            }],
            image_base: 0x140000000,
        }
    }

    #[test]
    fn lowering_records_distinct_rax_values_for_each_exit() {
        let make_exit = |id: u32, va: u64, version: u32| {
            let rax = ssa_var(0, version);
            SsaBlock {
                id,
                entry_va: va,
                ops: vec![
                    define_register(va, 0, version),
                    SsaOp {
                        va: va + 1,
                        kind: SsaOpKind::Pcode(PcodeOp::Return {
                            dest: Varnode::constant(0, 8),
                        }),
                        def: None,
                        uses: vec![rax],
                    },
                ],
                predecessor_ids: Vec::new(),
                successor_ids: Vec::new(),
            }
        };
        let ssa = SsaFunction {
            entry_va: 0x401000,
            bitness: 64,
            blocks: vec![make_exit(0, 0x401000, 1), make_exit(1, 0x402000, 2)],
            image_base: 0x140000000,
        };
        let lowered = lower_from_ssa(&ssa);
        assert_eq!(lowered.hir.exit_values.len(), 2);
        assert_ne!(lowered.hir.exit_values[&0], lowered.hir.exit_values[&1]);
        assert_eq!(lowered.exit_ssa_var(0), Some(&ssa_var(0, 1)));
        assert_eq!(lowered.exit_ssa_var(1), Some(&ssa_var(0, 2)));
        assert!(lowered.hir.validate().is_ok());
    }

    #[test]
    fn lowering_records_rax_defined_in_an_exit_predecessor() {
        let rax = ssa_var(0, 1);
        let ssa = SsaFunction {
            entry_va: 0x401000,
            bitness: 64,
            blocks: vec![
                SsaBlock {
                    id: 0,
                    entry_va: 0x401000,
                    ops: vec![define_register(0x401000, 0, 1)],
                    predecessor_ids: Vec::new(),
                    successor_ids: vec![1],
                },
                SsaBlock {
                    id: 1,
                    entry_va: 0x401010,
                    ops: vec![SsaOp {
                        va: 0x401010,
                        kind: SsaOpKind::Pcode(PcodeOp::Return {
                            dest: Varnode::constant(0, 8),
                        }),
                        def: None,
                        uses: Vec::new(),
                    }],
                    predecessor_ids: vec![0],
                    successor_ids: Vec::new(),
                },
            ],
            image_base: 0x140000000,
        };

        let lowered = lower_from_ssa(&ssa);
        assert_eq!(lowered.exit_ssa_var(1), Some(&rax));
        assert!(lowered.hir.validate().is_ok());
    }

    #[test]
    fn register_slices_model_aliases_and_zero_extension() {
        let rax = RegisterSlice::gpr(Gpr::Rax);
        let eax = RegisterSlice::new(Register::Gpr(Gpr::Rax), 0, 32).unwrap();
        let ah = RegisterSlice::new(Register::Gpr(Gpr::Rax), 8, 8).unwrap();
        let al = RegisterSlice::new(Register::Gpr(Gpr::Rax), 0, 8).unwrap();

        assert!(rax.overlaps(eax));
        assert!(eax.overlaps(ah));
        assert!(!al.overlaps(ah));
        assert_eq!(
            eax.write_semantics(),
            RegisterWriteSemantics::ZeroExtendToContainer
        );
        assert_eq!(
            ah.write_semantics(),
            RegisterWriteSemantics::PreserveOutsideSlice
        );
        assert!(matches!(
            RegisterSlice::new(Register::Gpr(Gpr::Rax), 63, 2),
            Err(RegisterSliceError::OutOfBounds { .. })
        ));
        assert!(matches!(
            RegisterSlice::xmm(X86_MAX_VECTOR_REGISTER_COUNT),
            Err(RegisterSliceError::InvalidVectorRegister { .. })
        ));
    }

    #[test]
    fn memory_objects_keep_partitions_and_memory_versions_explicit() {
        let mut hir = HirFunction::default();
        let stack = hir.add_memory_object(
            MemoryObjectKind::StackSlot {
                frame_offset: -0x20,
            },
            Some(16),
            Some(8),
            provenance_at(0x401000),
        );
        let string = hir.add_memory_object(
            MemoryObjectKind::ReadOnlyData {
                va: 0x0001_4001_a000,
            },
            Some(6),
            Some(1),
            provenance_at(0x401004),
        );
        let access = MemoryAccess {
            object: stack,
            byte_offset: 4,
            width_bytes: 4,
            version: MemoryVersion::ENTRY,
        };

        assert_eq!(
            hir.memory_object(stack).unwrap().alias_class(),
            AliasClass::Stack
        );
        assert_eq!(
            hir.memory_object(string).unwrap().alias_class(),
            AliasClass::ReadOnlyData
        );
        assert_eq!(access.version, MemoryVersion::ENTRY);
        assert_eq!(access.object, stack);
        assert!(hir.validate().is_ok());
    }

    #[test]
    fn win64_call_models_slots_result_and_volatile_state() {
        let mut hir = HirFunction::default();
        let a = hir.add_value(Some(64), provenance_at(0x401000));
        let b = hir.add_value(Some(64), provenance_at(0x401000));
        let c = hir.add_value(Some(64), provenance_at(0x401000));
        let d = hir.add_value(Some(64), provenance_at(0x401000));
        let e = hir.add_value(Some(64), provenance_at(0x401000));
        let result = hir.add_value(Some(64), provenance_at(0x401005));
        let arguments = vec![
            Win64Argument::standard(0, a, Win64ArgumentClass::Integer).unwrap(),
            Win64Argument::standard(1, b, Win64ArgumentClass::FloatingPoint).unwrap(),
            Win64Argument::standard(2, c, Win64ArgumentClass::Integer).unwrap(),
            Win64Argument::standard(3, d, Win64ArgumentClass::Integer).unwrap(),
            Win64Argument::standard(4, e, Win64ArgumentClass::Integer).unwrap(),
        ];
        let mut call = Win64CallSite::new(
            provenance_at(0x401005),
            CallTarget::Direct { va: 0x401100 },
            arguments,
        );
        call.result = Some(Win64Result::integer(result));

        assert_eq!(
            call.arguments[0].locations,
            vec![Win64ArgumentLocation::Register(RegisterSlice::gpr(
                Gpr::Rcx
            ))]
        );
        assert_eq!(
            call.arguments[1].locations,
            vec![Win64ArgumentLocation::Register(
                RegisterSlice::xmm(1).unwrap()
            )]
        );
        assert_eq!(
            call.arguments[4].locations,
            vec![Win64ArgumentLocation::Stack {
                offset_from_pre_call_rsp: 32
            }]
        );
        assert_eq!(call.required_outgoing_stack_bytes(), 40);
        assert!(
            call.clobbers
                .clobbers_register(RegisterSlice::gpr(Gpr::Rax))
        );
        assert!(
            !call
                .clobbers
                .clobbers_register(RegisterSlice::gpr(Gpr::Rbx))
        );
        assert!(
            call.clobbers
                .clobbers_register(RegisterSlice::xmm(0).unwrap())
        );

        hir.add_call_site(call);
        assert!(hir.validate().is_ok());
    }

    #[test]
    fn validation_rejects_dangling_values_and_bad_stack_slots() {
        let mut hir = HirFunction::default();
        let known = hir.add_value(Some(64), provenance_at(0x401000));
        let argument = Win64Argument::new(
            0,
            ValueId::new(42),
            Win64ArgumentClass::Integer,
            vec![Win64ArgumentLocation::Stack {
                offset_from_pre_call_rsp: 8,
            }],
        );
        hir.add_call_site(Win64CallSite::new(
            provenance_at(0x401010),
            CallTarget::Indirect {
                target: known,
                candidates: Vec::new(),
            },
            vec![argument],
        ));

        assert!(matches!(
            hir.validate(),
            Err(HirValidationError::UnknownValue { value: ValueId(42) })
        ));
    }

    #[test]
    fn ssa_bridge_assigns_one_value_per_ssa_var_and_preserves_pcode_va() {
        let rcx_entry = ssa_var(0x08, 1);
        let rax_result = ssa_var(0x00, 2);
        let copy = SsaOp {
            va: 0x401000,
            kind: SsaOpKind::Pcode(PcodeOp::Copy {
                out: Varnode::register(0x00, 8),
                input: Varnode::register(0x08, 8),
            }),
            def: Some(rax_result.clone()),
            uses: vec![rcx_entry.clone()],
        };
        let ssa = SsaFunction {
            entry_va: 0x401000,
            bitness: 64,
            blocks: vec![SsaBlock {
                id: 0,
                entry_va: 0x401000,
                ops: vec![copy],
                predecessor_ids: Vec::new(),
                successor_ids: Vec::new(),
            }],
            image_base: 0x140000000,
        };

        let lowered = lower_from_ssa(&ssa);
        let input = lowered.values[&rcx_entry];
        let output = lowered.values[&rax_result];
        assert_ne!(input, output);
        let operation = lowered
            .hir
            .operation(
                lowered.operations[&SsaOperationKey {
                    block_id: 0,
                    operation_index: 0,
                }],
            )
            .unwrap();
        assert_eq!(operation.inputs, vec![input]);
        assert_eq!(operation.output, Some(output));
        assert_eq!(operation.kind, HirOperationKind::Pcode);
        assert_eq!(
            operation.provenance.primary,
            Some(OriginSpan::single(0x401000, 0))
        );
        assert_eq!(
            lowered.hir.value(output).unwrap().provenance.primary,
            Some(OriginSpan::single(0x401000, 0))
        );
        assert!(lowered.hir.validate().is_ok());
    }

    #[test]
    fn win64_call_lifter_recovers_direct_target_and_same_block_gpr_args() {
        let rcx = ssa_var(0x08, 2);
        let rdx = ssa_var(0x10, 2);
        let r8 = ssa_var(0x80, 2);
        let ssa = single_block_ssa(vec![
            define_register(0x401000, 0x08, 2),
            define_register(0x401004, 0x10, 2),
            define_register(0x401008, 0x80, 2),
            direct_call(
                0x40100c,
                0x401100,
                vec![rcx.clone(), rdx.clone(), r8.clone()],
            ),
        ]);
        let mut lowered = lower_from_ssa(&ssa);
        let values_before = lowered.hir.values().len();
        let lifted = lift_win64_calls(&ssa, &mut lowered);

        assert_eq!(lifted.len(), 1);
        assert_eq!(lowered.hir.values().len(), values_before);
        let call = lowered.hir.call_site(lifted[0]).unwrap();
        assert_eq!(call.target, CallTarget::Direct { va: 0x401100 });
        assert_eq!(
            call.arguments
                .iter()
                .map(|argument| (argument.position, argument.value))
                .collect::<Vec<_>>(),
            vec![
                (0, lowered.values[&rcx]),
                (1, lowered.values[&rdx]),
                (2, lowered.values[&r8]),
            ]
        );
        assert_eq!(
            call.arguments[0].locations,
            vec![Win64ArgumentLocation::Register(RegisterSlice::gpr(
                Gpr::Rcx
            ))]
        );
        assert_eq!(
            call.arguments[1].locations,
            vec![Win64ArgumentLocation::Register(RegisterSlice::gpr(
                Gpr::Rdx
            ))]
        );
        assert_eq!(
            call.arguments[2].locations,
            vec![Win64ArgumentLocation::Register(RegisterSlice::gpr(Gpr::R8))]
        );
        assert!(
            call.result.is_none(),
            "the pass must not invent a return value"
        );
        assert!(
            call.arguments.iter().all(|argument| argument
                .locations
                .iter()
                .all(|location| !location.is_stack())),
            "the pass must not invent stack arguments"
        );
        assert_eq!(
            call.required_outgoing_stack_bytes(),
            WIN64_SHADOW_SPACE_BYTES
        );
        assert_eq!(
            call.provenance.primary,
            Some(OriginSpan::single(0x40100c, 3))
        );
        assert_eq!(call.provenance.kind, ProvenanceKind::Abi);
        assert!(
            call.clobbers
                .clobbers_register(RegisterSlice::gpr(Gpr::Rax))
        );
        assert!(
            !call
                .clobbers
                .clobbers_register(RegisterSlice::gpr(Gpr::Rbx))
        );
        assert!(lowered.hir.validate().is_ok());

        assert!(
            lift_win64_calls(&ssa, &mut lowered).is_empty(),
            "lifting must be idempotent"
        );
    }

    #[test]
    fn win64_call_lifter_recovers_indirect_target_without_fabricated_values() {
        let target_register = ssa_var(0x00, 2);
        let call_indirect = SsaOp {
            va: 0x401008,
            kind: SsaOpKind::Pcode(PcodeOp::CallInd {
                dest: Varnode::register(0x00, 8),
            }),
            def: None,
            uses: vec![target_register.clone()],
        };
        let ssa = single_block_ssa(vec![
            define_register(0x401000, 0x00, 2),
            define_register(0x401004, 0x08, 2),
            call_indirect,
        ]);
        let mut lowered = lower_from_ssa(&ssa);
        let values_before = lowered.hir.values().len();
        let lifted = lowered.lift_win64_calls(&ssa);

        assert_eq!(lifted.len(), 1);
        assert_eq!(lowered.hir.values().len(), values_before);
        let call = lowered.hir.call_site(lifted[0]).unwrap();
        assert_eq!(
            call.target,
            CallTarget::Indirect {
                target: lowered.values[&target_register],
                candidates: Vec::new(),
            }
        );
        assert!(
            call.arguments.is_empty(),
            "indirect calls must not receive an inferred argument contract"
        );
        assert!(call.result.is_none());
        assert!(call.arguments.iter().all(|argument| {
            argument
                .locations
                .iter()
                .all(|location| !location.is_stack())
        }));
        assert!(lowered.hir.validate().is_ok());
    }

    #[test]
    fn win64_call_lifter_does_not_reuse_register_args_across_a_call() {
        let rcx = ssa_var(0x08, 2);
        let ssa = single_block_ssa(vec![
            define_register(0x401000, 0x08, 2),
            direct_call(0x401004, 0x401100, vec![rcx.clone()]),
            direct_call(0x401008, 0x401200, vec![rcx]),
        ]);
        let mut lowered = lower_from_ssa(&ssa);
        let lifted = lift_win64_calls(&ssa, &mut lowered);

        assert_eq!(lifted.len(), 2);
        assert_eq!(lowered.hir.call_site(lifted[0]).unwrap().arguments.len(), 1);
        assert!(
            lowered
                .hir
                .call_site(lifted[1])
                .unwrap()
                .arguments
                .is_empty(),
            "volatile argument registers must not be carried across a call"
        );
        assert!(lowered.hir.validate().is_ok());
    }
}
