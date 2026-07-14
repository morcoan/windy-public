use petriage::analysis::SectionInfo;

/// A normalized PE section with both virtual and on-disk layout.
#[derive(Clone, Debug, Default)]
pub struct Section {
    /// Virtual address (RVA) of the section in memory.
    pub vaddr: u32,
    /// Virtual size in memory.
    pub vsize: u32,
    /// Offset of the section in the file image.
    pub raw_addr: u32,
    /// Size of initialized data in the file.
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// IMAGE_SCN_MEM_EXECUTE
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

    pub fn is_executable(&self) -> bool {
        (self.characteristics & Self::IMAGE_SCN_MEM_EXECUTE) != 0
    }

    /// True if `va` falls within the section's virtual address range.
    pub fn contains_va(&self, image_base: u64, va: u64) -> bool {
        let start = image_base + u64::from(self.vaddr);
        let end = start.saturating_add(u64::from(self.vsize));
        va >= start && va < end
    }

    /// Convert a VA inside this section to a file offset, if it maps to initialized bytes.
    pub fn va_to_offset(&self, image_base: u64, va: u64) -> Option<u64> {
        if !self.contains_va(image_base, va) {
            return None;
        }
        let rva = va.saturating_sub(image_base);
        let section_rva = u64::from(self.vaddr);
        let offset_in_section = rva.saturating_sub(section_rva);
        if offset_in_section >= u64::from(self.raw_size) {
            return None;
        }
        Some(u64::from(self.raw_addr).saturating_add(offset_in_section))
    }
}

impl From<&SectionInfo> for Section {
    fn from(s: &SectionInfo) -> Self {
        Self {
            vaddr: s.virtual_address,
            vsize: s.virtual_size,
            raw_addr: s.raw_address,
            raw_size: s.raw_size,
            characteristics: s.characteristics,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AddressSpace {
    pub image_base: u64,
    pub sections: Vec<Section>,
}

impl AddressSpace {
    pub fn new(image_base: u64, sections: &[SectionInfo]) -> Self {
        Self {
            image_base,
            sections: sections.iter().map(Section::from).collect(),
        }
    }

    pub fn section_at_va(&self, va: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.contains_va(self.image_base, va))
    }

    pub fn is_executable_va(&self, va: u64) -> bool {
        self.section_at_va(va)
            .map(Section::is_executable)
            .unwrap_or(false)
    }

    /// True if `va` falls within any loaded section (code or data).
    pub fn is_valid_va(&self, va: u64) -> bool {
        self.section_at_va(va).is_some()
    }

    /// True if `va` maps to a loaded section that is not marked executable.
    pub fn is_data_va(&self, va: u64) -> bool {
        self.section_at_va(va)
            .map(|s| !s.is_executable())
            .unwrap_or(false)
    }

    /// Convert a file offset back to the VA of the byte it maps to.
    #[allow(dead_code)] // Used by PDB/string context queries
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        let offset_u32 = u32::try_from(offset).ok()?;
        let section = self.sections.iter().find(|s| {
            offset_u32 >= s.raw_addr && offset_u32 < s.raw_addr.saturating_add(s.raw_size)
        })?;
        let section_offset = offset.saturating_sub(u64::from(section.raw_addr));
        Some(self.image_base + u64::from(section.vaddr) + section_offset)
    }

    pub fn exec_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_executable())
    }

    pub fn slice_for_va<'a>(&self, image: &'a [u8], va: u64, len: usize) -> Option<&'a [u8]> {
        let section = self.section_at_va(va)?;
        let file_offset = section.va_to_offset(self.image_base, va)? as usize;
        image.get(file_offset..file_offset.checked_add(len)?)
    }

    pub fn bitness(&self, magic: &str) -> u32 {
        if magic.contains("PE32+") || magic.contains("0x20b") {
            64
        } else {
            32
        }
    }
}
