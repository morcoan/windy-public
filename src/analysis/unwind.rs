//! Windows x64 runtime-function metadata.
//!
//! PE32+ images record non-leaf function ranges in data-directory entry 3
//! (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`), conventionally stored in `.pdata`.
//! The records are authoritative function-boundary candidates on x64, so this
//! module parses them conservatively and leaves policy (such as seeding the
//! recursive-descent discoverer) to its caller.

use crate::loader::address_space::AddressSpace;

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_RUNTIME_FUNCTION_ENTRY_SIZE: usize = 12;
const UNWIND_INFO_HEADER_SIZE: usize = 4;
const MAX_UNWIND_INFO_FIXED_BYTES: usize = 528;

/// `UNWIND_INFO` flag: language-specific exception handler is present.
pub const UNW_FLAG_EHANDLER: u8 = 0x01;
/// `UNWIND_INFO` flag: language-specific termination handler is present.
pub const UNW_FLAG_UHANDLER: u8 = 0x02;
/// `UNWIND_INFO` flag: the trailing data is a chained `RUNTIME_FUNCTION`.
pub const UNW_FLAG_CHAININFO: u8 = 0x04;

const UNWIND_KNOWN_FLAGS: u8 = UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_EPILOG: u8 = 6;
const UWOP_SPARE: u8 = 7;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

// Offsets relative to the start of IMAGE_OPTIONAL_HEADER64.
const OPTIONAL_HEADER64_NUMBER_OF_RVA_AND_SIZES: usize = 108;
const OPTIONAL_HEADER64_DATA_DIRECTORIES: usize = 112;

/// One x64 `RUNTIME_FUNCTION` record from the PE exception directory.
///
/// `begin_va..end_va` is an end-exclusive executable range.  The parser
/// retains both RVA and VA forms so downstream analyses can use an address
/// directly while serializers can retain the on-disk provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
    pub begin_va: u64,
    pub end_va: u64,
    pub unwind_info_va: u64,
    /// Parsed bounded `UNWIND_INFO` prefix, when the referenced `.xdata`
    /// range is mapped and structurally valid. A missing value never makes the
    /// authoritative `.pdata` function range unusable.
    pub unwind_info: Option<UnwindInfo>,
}

impl RuntimeFunction {
    /// True when `va` is inside this function's end-exclusive range.
    pub fn contains_va(&self, va: u64) -> bool {
        self.begin_va <= va && va < self.end_va
    }

    /// Size of the runtime-function range in bytes.
    pub fn size(&self) -> u64 {
        self.end_va.saturating_sub(self.begin_va)
    }
}

/// Parsed x64 runtime-function metadata.
///
/// Invalid individual records are omitted rather than becoming function
/// seeds.  `rejected_entries` lets callers decide whether an incomplete table
/// is acceptable for their use case.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeFunctionTable {
    pub entries: Vec<RuntimeFunction>,
    pub rejected_entries: usize,
}

impl RuntimeFunctionTable {
    /// True when every directory record supplied a usable executable range.
    pub fn is_complete(&self) -> bool {
        self.rejected_entries == 0
    }

    /// Entry addresses suitable for later function-discovery seeding.
    pub fn entry_points(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.iter().map(|entry| entry.begin_va)
    }
}

/// Parsed AMD64 `UNWIND_INFO` version 1 or 2 metadata.
///
/// The parser deliberately stops at the known fixed prefix of language
/// handler data. Language-specific handler data has no common format, so only
/// its starting offset is exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindInfo {
    /// Format version. This parser accepts only versions 1 and 2.
    pub version: u8,
    /// Raw five-bit `UNWIND_INFO` flags field.
    pub flags: u8,
    /// Size of the function prologue in bytes.
    pub prolog_size: u8,
    /// Number of two-byte slots occupied by unwind codes, excluding alignment
    /// padding.
    pub code_slots: u8,
    /// Frame-pointer register number, or `None` when the function has no
    /// frame pointer.
    pub frame_register: Option<u8>,
    /// Raw, 16-byte-scaled frame-pointer offset from `RSP`.
    pub frame_offset: u8,
    /// `frame_offset` expressed in bytes.
    pub frame_offset_bytes: u16,
    /// Decoded unwind operations in their on-disk order.
    pub codes: Vec<UnwindCode>,
    /// DWORD-aligned byte offset at which a handler RVA or chained entry
    /// begins, if one is present.
    pub tail_offset: usize,
    /// Handler or chain metadata following the unwind-code array.
    pub tail: UnwindInfoTail,
}

impl UnwindInfo {
    /// True when this record names an exception handler.
    pub fn has_exception_handler(&self) -> bool {
        self.flags & UNW_FLAG_EHANDLER != 0
    }

    /// True when this record names a termination handler.
    pub fn has_termination_handler(&self) -> bool {
        self.flags & UNW_FLAG_UHANDLER != 0
    }

    /// True when this record chains to another runtime-function entry.
    pub fn is_chained(&self) -> bool {
        self.flags & UNW_FLAG_CHAININFO != 0
    }
}

/// Fixed trailing metadata after a version 1 or 2 `UNWIND_INFO` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnwindInfoTail {
    /// No language handler and no chained runtime-function entry.
    None,
    /// A language-specific exception and/or termination handler.
    Handler {
        /// Image-relative address of the handler routine.
        handler_rva: u32,
        /// First byte of handler-specific data. Its format and length are
        /// owned by the handler and intentionally not parsed here.
        handler_data_offset: usize,
    },
    /// A secondary unwind record whose tail contains another
    /// `RUNTIME_FUNCTION` entry.
    Chained {
        runtime_function: ChainedRuntimeFunction,
    },
}

/// Image-relative runtime-function entry embedded in chained unwind metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChainedRuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
}

/// One decoded operation beginning at an `UNWIND_CODE` slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindCode {
    /// Zero-based index into the `UNWIND_INFO` unwind-code slot array.
    pub slot_index: u8,
    /// Offset in the prologue, or version-2 epilogue size for `UWOP_EPILOG`.
    pub code_offset: u8,
    /// Raw four-bit operation code.
    pub operation_code: u8,
    /// Raw four-bit operation-information field.
    pub operation_info: u8,
    /// Number of two-byte slots consumed by this operation.
    pub slots_used: u8,
    /// Decoded operation semantics.
    pub operation: UnwindOperation,
}

/// Semantics of a supported version 1 or 2 AMD64 unwind operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnwindOperation {
    PushNonVol {
        register: u8,
    },
    AllocLarge {
        size: u32,
    },
    AllocSmall {
        size: u16,
    },
    SetFpReg,
    SaveNonVol {
        register: u8,
        stack_offset: u32,
    },
    SaveNonVolFar {
        register: u8,
        stack_offset: u32,
    },
    /// Version-2 marker describing an epilogue relative to the function end.
    Epilog {
        epilog_size: u8,
        offset_from_function_end: u16,
    },
    /// Version-2 reserved three-slot encoding, retained without assigning
    /// semantics to its payload.
    Spare {
        payload: u32,
    },
    SaveXmm128 {
        register: u8,
        stack_offset: u32,
    },
    SaveXmm128Far {
        register: u8,
        stack_offset: u32,
    },
    PushMachFrame {
        has_error_code: bool,
    },
}

/// Parse a standalone AMD64 `UNWIND_INFO` version 1 or 2 byte sequence.
///
/// Returns `None` for an unsupported version, reserved flags, malformed
/// operation, illegal flag combination, or truncated fixed metadata. Version
/// 3 deliberately has a separate format and is not accepted here.
pub fn parse_unwind_info(bytes: &[u8]) -> Option<UnwindInfo> {
    let header = bytes.get(..UNWIND_INFO_HEADER_SIZE)?;
    let version = header[0] & 0x07;
    let flags = header[0] >> 3;
    if !matches!(version, 1 | 2) || flags & !UNWIND_KNOWN_FLAGS != 0 {
        return None;
    }

    let has_handler = flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0;
    let is_chained = flags & UNW_FLAG_CHAININFO != 0;
    if has_handler && is_chained {
        return None;
    }

    let prolog_size = header[1];
    let code_slots = header[2];
    let frame_register_number = header[3] & 0x0f;
    let frame_offset = header[3] >> 4;
    if frame_register_number == 0 && frame_offset != 0 {
        return None;
    }

    let codes_len = usize::from(code_slots).checked_mul(2)?;
    let codes_end = UNWIND_INFO_HEADER_SIZE.checked_add(codes_len)?;
    bytes.get(..codes_end)?;
    let tail_offset = align_to_dword(codes_end)?;
    // The code-slot array is DWORD aligned even when it has an odd declared
    // count, in which case a final unused slot is present.
    bytes.get(..tail_offset)?;

    let mut codes = Vec::new();
    let mut slot_index = 0usize;
    while slot_index < usize::from(code_slots) {
        let code = parse_unwind_code(bytes, version, slot_index, usize::from(code_slots))?;
        slot_index = slot_index.checked_add(usize::from(code.slots_used))?;
        codes.push(code);
    }

    let tail = if is_chained {
        let begin_rva = read_u32_le(bytes, tail_offset)?;
        let end_rva = read_u32_le(bytes, tail_offset.checked_add(4)?)?;
        let unwind_info_rva = read_u32_le(bytes, tail_offset.checked_add(8)?)?;
        UnwindInfoTail::Chained {
            runtime_function: ChainedRuntimeFunction {
                begin_rva,
                end_rva,
                unwind_info_rva,
            },
        }
    } else if has_handler {
        let handler_rva = read_u32_le(bytes, tail_offset)?;
        UnwindInfoTail::Handler {
            handler_rva,
            handler_data_offset: tail_offset.checked_add(4)?,
        }
    } else {
        UnwindInfoTail::None
    };

    Some(UnwindInfo {
        version,
        flags,
        prolog_size,
        code_slots,
        frame_register: (frame_register_number != 0).then_some(frame_register_number),
        frame_offset,
        frame_offset_bytes: u16::from(frame_offset) * 16,
        codes,
        tail_offset,
        tail,
    })
}

/// Read and parse the bounded fixed prefix of an AMD64 `UNWIND_INFO` at a
/// virtual address.
///
/// The only unbounded portion of an unwind record is handler-specific data.
/// This helper reads at most the header, code slots, alignment, and one
/// handler RVA or chained runtime-function entry (528 bytes maximum), then
/// delegates to [`parse_unwind_info`].
pub fn parse_unwind_info_at(
    image: &[u8],
    address_space: &AddressSpace,
    unwind_info_va: u64,
) -> Option<UnwindInfo> {
    let header = address_space.slice_for_va(image, unwind_info_va, UNWIND_INFO_HEADER_SIZE)?;
    let minimum_size = unwind_info_minimum_size(header)?;
    let bytes = address_space.slice_for_va(image, unwind_info_va, minimum_size)?;
    parse_unwind_info(bytes)
}

fn unwind_info_minimum_size(header: &[u8]) -> Option<usize> {
    let header = header.get(..UNWIND_INFO_HEADER_SIZE)?;
    let code_slots = usize::from(header[2]);
    let codes_end = UNWIND_INFO_HEADER_SIZE.checked_add(code_slots.checked_mul(2)?)?;
    let tail_offset = align_to_dword(codes_end)?;
    let flags = header[0] >> 3;
    let minimum_size = if flags & UNW_FLAG_CHAININFO != 0 {
        tail_offset.checked_add(IMAGE_RUNTIME_FUNCTION_ENTRY_SIZE)?
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        tail_offset.checked_add(4)?
    } else {
        tail_offset
    };
    (minimum_size <= MAX_UNWIND_INFO_FIXED_BYTES).then_some(minimum_size)
}

fn parse_unwind_code(
    bytes: &[u8],
    version: u8,
    slot_index: usize,
    total_slots: usize,
) -> Option<UnwindCode> {
    let code_offset = unwind_code_byte(bytes, slot_index, 0)?;
    let packed = unwind_code_byte(bytes, slot_index, 1)?;
    let operation_code = packed & 0x0f;
    let operation_info = packed >> 4;
    let slots_used = unwind_code_slots(version, operation_code, operation_info)?;
    if !code_slots_available(slot_index, total_slots, usize::from(slots_used)) {
        return None;
    }

    let operation = match operation_code {
        UWOP_PUSH_NONVOL => UnwindOperation::PushNonVol {
            register: operation_info,
        },
        UWOP_ALLOC_LARGE => {
            let size = if operation_info == 0 {
                u32::from(unwind_code_u16(bytes, slot_index.checked_add(1)?)?) * 8
            } else {
                unwind_code_u32(bytes, slot_index.checked_add(1)?)?
            };
            UnwindOperation::AllocLarge { size }
        }
        UWOP_ALLOC_SMALL => UnwindOperation::AllocSmall {
            size: u16::from(operation_info) * 8 + 8,
        },
        UWOP_SET_FPREG => UnwindOperation::SetFpReg,
        UWOP_SAVE_NONVOL => UnwindOperation::SaveNonVol {
            register: operation_info,
            stack_offset: u32::from(unwind_code_u16(bytes, slot_index.checked_add(1)?)?) * 8,
        },
        UWOP_SAVE_NONVOL_FAR => UnwindOperation::SaveNonVolFar {
            register: operation_info,
            stack_offset: unwind_code_u32(bytes, slot_index.checked_add(1)?)?,
        },
        UWOP_EPILOG => {
            let next_code_offset = unwind_code_byte(bytes, slot_index.checked_add(1)?, 0)?;
            let next_info = unwind_code_byte(bytes, slot_index.checked_add(1)?, 1)? >> 4;
            let offset_from_function_end = if operation_info == 0 {
                (u16::from(next_info) << 8) | u16::from(next_code_offset)
            } else {
                u16::from(code_offset)
            };
            UnwindOperation::Epilog {
                epilog_size: code_offset,
                offset_from_function_end,
            }
        }
        UWOP_SPARE => UnwindOperation::Spare {
            payload: unwind_code_u32(bytes, slot_index.checked_add(1)?)?,
        },
        UWOP_SAVE_XMM128 => UnwindOperation::SaveXmm128 {
            register: operation_info,
            stack_offset: u32::from(unwind_code_u16(bytes, slot_index.checked_add(1)?)?) * 16,
        },
        UWOP_SAVE_XMM128_FAR => UnwindOperation::SaveXmm128Far {
            register: operation_info,
            stack_offset: unwind_code_u32(bytes, slot_index.checked_add(1)?)?,
        },
        UWOP_PUSH_MACHFRAME => UnwindOperation::PushMachFrame {
            has_error_code: operation_info == 1,
        },
        _ => return None,
    };

    Some(UnwindCode {
        slot_index: u8::try_from(slot_index).ok()?,
        code_offset,
        operation_code,
        operation_info,
        slots_used,
        operation,
    })
}

fn unwind_code_slots(version: u8, operation_code: u8, operation_info: u8) -> Option<u8> {
    match operation_code {
        UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL => Some(1),
        UWOP_SET_FPREG if operation_info == 0 => Some(1),
        UWOP_PUSH_MACHFRAME if operation_info <= 1 => Some(1),
        UWOP_ALLOC_LARGE => match operation_info {
            0 => Some(2),
            1 => Some(3),
            _ => None,
        },
        UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => Some(2),
        UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => Some(3),
        UWOP_EPILOG if version == 2 && operation_info <= 1 => Some(2),
        UWOP_SPARE if version == 2 => Some(3),
        _ => None,
    }
}

fn code_slots_available(slot_index: usize, total_slots: usize, needed_slots: usize) -> bool {
    total_slots
        .checked_sub(slot_index)
        .is_some_and(|remaining| remaining >= needed_slots)
}

fn unwind_code_byte(bytes: &[u8], slot_index: usize, byte_index: usize) -> Option<u8> {
    let slot_offset = UNWIND_INFO_HEADER_SIZE.checked_add(slot_index.checked_mul(2)?)?;
    bytes.get(slot_offset.checked_add(byte_index)?).copied()
}

fn unwind_code_u16(bytes: &[u8], slot_index: usize) -> Option<u16> {
    let offset = UNWIND_INFO_HEADER_SIZE.checked_add(slot_index.checked_mul(2)?)?;
    read_u16_le(bytes, offset)
}

fn unwind_code_u32(bytes: &[u8], slot_index: usize) -> Option<u32> {
    let low = u32::from(unwind_code_u16(bytes, slot_index)?);
    let high = u32::from(unwind_code_u16(bytes, slot_index.checked_add(1)?)?);
    Some(low | (high << 16))
}

fn align_to_dword(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

/// Parse the x64 PE exception directory into conservative runtime-function
/// ranges.
///
/// Returns `None` when `image` is not a well-formed AMD64 PE32+ header or its
/// exception-directory declaration is malformed.  A valid AMD64 image without
/// exception metadata returns an empty table.  Entries with an invalid or
/// non-executable range are skipped and counted in `rejected_entries`.
pub fn parse_runtime_functions(
    image: &[u8],
    address_space: &AddressSpace,
) -> Option<RuntimeFunctionTable> {
    let Some((directory_rva, directory_size)) = exception_directory(image)? else {
        return Some(RuntimeFunctionTable::default());
    };

    let directory_size = usize::try_from(directory_size).ok()?;
    if directory_size == 0 || directory_size % IMAGE_RUNTIME_FUNCTION_ENTRY_SIZE != 0 {
        return None;
    }

    let directory_va = address_space
        .image_base
        .checked_add(u64::from(directory_rva))?;
    let directory = address_space.slice_for_va(image, directory_va, directory_size)?;

    let mut table = RuntimeFunctionTable::default();
    for record in directory.chunks_exact(IMAGE_RUNTIME_FUNCTION_ENTRY_SIZE) {
        let begin_rva = read_u32_le(record, 0)?;
        let end_rva = read_u32_le(record, 4)?;
        let unwind_info_rva = read_u32_le(record, 8)?;

        let Some((begin_va, end_va)) = executable_range(address_space, begin_rva, end_rva) else {
            table.rejected_entries += 1;
            continue;
        };
        let Some(unwind_info_va) = address_space
            .image_base
            .checked_add(u64::from(unwind_info_rva))
        else {
            table.rejected_entries += 1;
            continue;
        };

        table.entries.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_info_rva,
            begin_va,
            end_va,
            unwind_info_va,
            unwind_info: parse_unwind_info_at(image, address_space, unwind_info_va),
        });
    }

    // The PE/COFF specification requires `.pdata` to be sorted by begin RVA.
    // Sorting defensively gives consumers a stable table even for a malformed
    // producer that happened to emit otherwise usable records.
    table
        .entries
        .sort_unstable_by_key(|entry| (entry.begin_va, entry.end_va, entry.unwind_info_va));
    Some(table)
}

/// Return the exception directory when the PE header is a valid AMD64 PE32+
/// header. `Some(None)` means a valid x64 PE that simply has no directory.
fn exception_directory(image: &[u8]) -> Option<Option<(u32, u32)>> {
    if image.get(0..2)? != b"MZ" {
        return None;
    }
    let pe_offset = usize::try_from(read_u32_le(image, 0x3c)?).ok()?;
    if image.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }

    let coff_offset = pe_offset.checked_add(4)?;
    if read_u16_le(image, coff_offset)? != IMAGE_FILE_MACHINE_AMD64 {
        return None;
    }
    let optional_header_size = usize::from(read_u16_le(image, coff_offset.checked_add(16)?)?);
    let optional_offset = coff_offset.checked_add(20)?;
    let optional_end = optional_offset.checked_add(optional_header_size)?;
    image.get(optional_offset..optional_end)?;

    let magic_offset = optional_field_offset(optional_offset, optional_end, 0, 2)?;
    if read_u16_le(image, magic_offset)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return None;
    }

    let number_of_directories_offset = optional_field_offset(
        optional_offset,
        optional_end,
        OPTIONAL_HEADER64_NUMBER_OF_RVA_AND_SIZES,
        4,
    )?;
    let number_of_directories =
        usize::try_from(read_u32_le(image, number_of_directories_offset)?).ok()?;
    if number_of_directories <= IMAGE_DIRECTORY_ENTRY_EXCEPTION {
        return Some(None);
    }

    let directory_relative_offset = OPTIONAL_HEADER64_DATA_DIRECTORIES
        .checked_add(IMAGE_DIRECTORY_ENTRY_EXCEPTION.checked_mul(8)?)?;
    let directory_offset =
        optional_field_offset(optional_offset, optional_end, directory_relative_offset, 8)?;
    let rva = read_u32_le(image, directory_offset)?;
    let size = read_u32_le(image, directory_offset.checked_add(4)?)?;
    match (rva, size) {
        (0, 0) => Some(None),
        (0, _) | (_, 0) => None,
        _ => Some(Some((rva, size))),
    }
}

/// Validate a candidate range against the current address space.  An end
/// address equal to the section end is valid because PE function ranges are
/// end-exclusive.
fn executable_range(
    address_space: &AddressSpace,
    begin_rva: u32,
    end_rva: u32,
) -> Option<(u64, u64)> {
    if begin_rva >= end_rva {
        return None;
    }
    let begin_va = address_space.image_base.checked_add(u64::from(begin_rva))?;
    let end_va = address_space.image_base.checked_add(u64::from(end_rva))?;

    let section = address_space.section_at_va(begin_va)?;
    if !section.is_executable() {
        return None;
    }
    let section_begin_va = address_space
        .image_base
        .checked_add(u64::from(section.vaddr))?;
    // The loader maps at least the initialized bytes, even when raw size is
    // larger than virtual size because of section-file alignment.
    let section_size = u64::from(section.vsize.max(section.raw_size));
    let section_end_va = section_begin_va.checked_add(section_size)?;
    (begin_va >= section_begin_va && end_va <= section_end_va).then_some((begin_va, end_va))
}

fn optional_field_offset(
    optional_offset: usize,
    optional_end: usize,
    relative_offset: usize,
    width: usize,
) -> Option<usize> {
    let offset = optional_offset.checked_add(relative_offset)?;
    (offset.checked_add(width)? <= optional_end).then_some(offset)
}

fn read_u16_le(image: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = image.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(image: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = image.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::address_space::Section;

    const IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
    const PE_OFFSET: usize = 0x80;
    const OPTIONAL_OFFSET: usize = PE_OFFSET + 4 + 20;
    const PDATA_RAW_OFFSET: usize = 0x500;

    fn write_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_x64_image(
        records: &[(u32, u32, u32)],
        directory_size: u32,
    ) -> (Vec<u8>, AddressSpace) {
        let mut image = vec![0u8; 0x800];
        image[0..2].copy_from_slice(b"MZ");
        write_u32(&mut image, 0x3c, PE_OFFSET as u32);
        image[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        let coff_offset = PE_OFFSET + 4;
        write_u16(&mut image, coff_offset, IMAGE_FILE_MACHINE_AMD64);
        write_u16(&mut image, coff_offset + 2, 3);
        write_u16(&mut image, coff_offset + 16, 0xf0);

        write_u16(&mut image, OPTIONAL_OFFSET, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        write_u32(
            &mut image,
            OPTIONAL_OFFSET + OPTIONAL_HEADER64_NUMBER_OF_RVA_AND_SIZES,
            16,
        );
        let directory_offset = OPTIONAL_OFFSET
            + OPTIONAL_HEADER64_DATA_DIRECTORIES
            + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        let directory_rva = u32::from(directory_size != 0) * 0x2000;
        write_u32(&mut image, directory_offset, directory_rva);
        write_u32(&mut image, directory_offset + 4, directory_size);

        for (index, &(begin_rva, end_rva, unwind_info_rva)) in records.iter().enumerate() {
            let record_offset = PDATA_RAW_OFFSET + index * IMAGE_RUNTIME_FUNCTION_ENTRY_SIZE;
            write_u32(&mut image, record_offset, begin_rva);
            write_u32(&mut image, record_offset + 4, end_rva);
            write_u32(&mut image, record_offset + 8, unwind_info_rva);
        }

        let address_space = AddressSpace {
            image_base: IMAGE_BASE,
            sections: vec![
                Section {
                    vaddr: 0x1000,
                    vsize: 0x300,
                    raw_addr: 0x200,
                    raw_size: 0x300,
                    characteristics: 0x6000_0020,
                },
                Section {
                    vaddr: 0x2000,
                    vsize: 0x100,
                    raw_addr: PDATA_RAW_OFFSET as u32,
                    raw_size: 0x100,
                    characteristics: 0x4000_0040,
                },
                Section {
                    vaddr: 0x3000,
                    vsize: 0x100,
                    raw_addr: 0x600,
                    raw_size: 0x100,
                    characteristics: 0x4000_0040,
                },
            ],
        };
        (image, address_space)
    }

    #[test]
    fn parses_version_one_header_frame_and_code_records() {
        let bytes = [
            1,    // version 1, no flags
            0x0f, // prologue size
            4,    // four code slots
            0x25, // RBP frame pointer, offset 2 * 16
            12,
            (3 << 4) | UWOP_SAVE_NONVOL,
            4,
            0, // save RBX at stack offset 4 * 8
            7,
            (7 << 4) | UWOP_ALLOC_SMALL,
            3,
            (5 << 4) | UWOP_PUSH_NONVOL,
        ];

        let info = parse_unwind_info(&bytes).expect("valid UNWIND_INFO v1");
        assert_eq!(info.version, 1);
        assert_eq!(info.prolog_size, 0x0f);
        assert_eq!(info.code_slots, 4);
        assert_eq!(info.frame_register, Some(5));
        assert_eq!(info.frame_offset, 2);
        assert_eq!(info.frame_offset_bytes, 32);
        assert_eq!(info.tail_offset, 12);
        assert_eq!(info.codes.len(), 3);
        assert_eq!(
            info.codes[0].operation,
            UnwindOperation::SaveNonVol {
                register: 3,
                stack_offset: 32,
            }
        );
        assert_eq!(
            info.codes[1].operation,
            UnwindOperation::AllocSmall { size: 64 }
        );
        assert_eq!(
            info.codes[2].operation,
            UnwindOperation::PushNonVol { register: 5 }
        );
        assert_eq!(info.tail, UnwindInfoTail::None);
    }

    #[test]
    fn parses_version_two_epilog_records() {
        let bytes = [
            2, // version 2, no flags
            5,
            3, // two slots for UWOP_EPILOG, one for UWOP_ALLOC_SMALL
            0,
            5,
            (1 << 4) | UWOP_EPILOG,
            0,
            0, // second epilog slot
            2,
            UWOP_ALLOC_SMALL,
            0,
            0, // alignment slot
        ];

        let info = parse_unwind_info(&bytes).expect("valid UNWIND_INFO v2");
        assert_eq!(info.version, 2);
        assert_eq!(info.codes.len(), 2);
        assert_eq!(info.codes[0].slots_used, 2);
        assert_eq!(
            info.codes[0].operation,
            UnwindOperation::Epilog {
                epilog_size: 5,
                offset_from_function_end: 5,
            }
        );
        assert_eq!(
            info.codes[1].operation,
            UnwindOperation::AllocSmall { size: 8 }
        );
        assert_eq!(info.tail_offset, 12);
    }

    #[test]
    fn rejects_truncated_or_malformed_unwind_code_arrays() {
        let truncated = [
            1,
            4,
            2, // claims two slots but supplies only one
            0,
            4,
            UWOP_ALLOC_LARGE,
        ];
        assert!(parse_unwind_info(&truncated).is_none());

        let missing_alignment_slot = [1, 1, 1, 0, 1, UWOP_ALLOC_SMALL];
        assert!(parse_unwind_info(&missing_alignment_slot).is_none());

        let malformed = [
            1,
            1,
            1,
            0,
            1,
            (1 << 4) | UWOP_SET_FPREG, // reserved op-info must be zero
        ];
        assert!(parse_unwind_info(&malformed).is_none());
    }

    #[test]
    fn parses_chained_runtime_function_tail() {
        let mut bytes = vec![
            1 | (UNW_FLAG_CHAININFO << 3),
            3,
            1,
            0,
            3,
            UWOP_ALLOC_SMALL,
            0,
            0, // required alignment slot before the chained entry
        ];
        bytes.extend_from_slice(&0x1000u32.to_le_bytes());
        bytes.extend_from_slice(&0x1040u32.to_le_bytes());
        bytes.extend_from_slice(&0x3000u32.to_le_bytes());

        let info = parse_unwind_info(&bytes).expect("valid chained UNWIND_INFO");
        assert!(info.is_chained());
        assert!(!info.has_exception_handler());
        assert_eq!(info.tail_offset, 8);
        assert_eq!(
            info.tail,
            UnwindInfoTail::Chained {
                runtime_function: ChainedRuntimeFunction {
                    begin_rva: 0x1000,
                    end_rva: 0x1040,
                    unwind_info_rva: 0x3000,
                },
            }
        );
    }

    #[test]
    fn parses_language_handler_tail_without_interpreting_handler_data() {
        let mut bytes = vec![1 | ((UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) << 3), 2, 0, 0];
        bytes.extend_from_slice(&0x4455u32.to_le_bytes());
        bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // opaque handler data

        let info = parse_unwind_info(&bytes).expect("valid handler UNWIND_INFO");
        assert!(info.has_exception_handler());
        assert!(info.has_termination_handler());
        assert!(!info.is_chained());
        assert_eq!(
            info.tail,
            UnwindInfoTail::Handler {
                handler_rva: 0x4455,
                handler_data_offset: 8,
            }
        );
    }

    #[test]
    fn rejects_truncated_or_conflicting_unwind_tails() {
        let truncated_chain = [1 | (UNW_FLAG_CHAININFO << 3), 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_unwind_info(&truncated_chain).is_none());

        let conflicting_flags = [1 | ((UNW_FLAG_EHANDLER | UNW_FLAG_CHAININFO) << 3), 0, 0, 0];
        assert!(parse_unwind_info(&conflicting_flags).is_none());
    }

    #[test]
    fn runtime_function_entries_attach_bounded_unwind_metadata() {
        let records = [(0x1010, 0x1040, 0x3000)];
        let (mut image, address_space) = synthetic_x64_image(&records, 12);
        image[0x600..0x606].copy_from_slice(&[1, 3, 1, 0, 3, UWOP_ALLOC_SMALL]);

        let table = parse_runtime_functions(&image, &address_space).expect("valid x64 PE");
        let info = table.entries[0]
            .unwind_info
            .as_ref()
            .expect("mapped unwind info should parse");
        assert_eq!(info.prolog_size, 3);
        assert_eq!(
            info.codes[0].operation,
            UnwindOperation::AllocSmall { size: 8 }
        );
    }

    #[test]
    fn parses_x64_exception_directory_and_exposes_entry_points() {
        let records = [(0x1010, 0x1040, 0x3000), (0x1080, 0x10c0, 0x3010)];
        let (image, address_space) = synthetic_x64_image(&records, 24);

        let table = parse_runtime_functions(&image, &address_space).expect("valid x64 PE");
        assert!(table.is_complete());
        assert_eq!(table.rejected_entries, 0);
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].begin_rva, 0x1010);
        assert_eq!(table.entries[0].begin_va, IMAGE_BASE + 0x1010);
        assert_eq!(table.entries[0].end_va, IMAGE_BASE + 0x1040);
        assert_eq!(table.entries[0].unwind_info_va, IMAGE_BASE + 0x3000);
        assert!(table.entries[0].contains_va(IMAGE_BASE + 0x103f));
        assert!(!table.entries[0].contains_va(IMAGE_BASE + 0x1040));
        assert_eq!(table.entries[0].size(), 0x30);
        assert_eq!(
            table.entry_points().collect::<Vec<_>>(),
            vec![IMAGE_BASE + 0x1010, IMAGE_BASE + 0x1080]
        );
    }

    #[test]
    fn skips_invalid_ranges_without_poisoning_valid_entries() {
        let records = [
            (0x1010, 0x1040, 0x3000), // valid executable range
            (0x1050, 0x1050, 0x3010), // empty range
            (0x2000, 0x2010, 0x3020), // .pdata is not executable
            (0x1280, 0x1310, 0x3030), // extends beyond .text
        ];
        let (image, address_space) = synthetic_x64_image(&records, 48);

        let table = parse_runtime_functions(&image, &address_space).expect("valid directory");
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].begin_rva, 0x1010);
        assert_eq!(table.rejected_entries, 3);
        assert!(!table.is_complete());
    }

    #[test]
    fn accepts_an_end_address_at_the_executable_section_boundary() {
        let records = [(0x1200, 0x1300, 0x3000)];
        let (image, address_space) = synthetic_x64_image(&records, 12);

        let table = parse_runtime_functions(&image, &address_space).expect("valid range");
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].end_va, IMAGE_BASE + 0x1300);
    }

    #[test]
    fn malformed_directory_size_is_rejected() {
        let records = [(0x1010, 0x1040, 0x3000)];
        let (image, address_space) = synthetic_x64_image(&records, 13);

        assert!(parse_runtime_functions(&image, &address_space).is_none());
    }

    #[test]
    fn x64_pe_without_exception_directory_has_an_empty_table() {
        let (image, address_space) = synthetic_x64_image(&[], 0);

        let table = parse_runtime_functions(&image, &address_space).expect("valid x64 PE");
        assert!(table.entries.is_empty());
        assert!(table.is_complete());
    }

    #[test]
    fn non_amd64_images_are_not_interpreted_as_x64_runtime_tables() {
        let records = [(0x1010, 0x1040, 0x3000)];
        let (mut image, address_space) = synthetic_x64_image(&records, 12);
        write_u16(&mut image, PE_OFFSET + 4, 0xaa64); // ARM64

        assert!(parse_runtime_functions(&image, &address_space).is_none());
    }
}
