//! Sparse process virtual address map backed by minidump memory streams.

use minidump::{UnifiedMemory, UnifiedMemoryList};
use serde::Serialize;

/// One contiguous range of process memory stored in the dump file.
#[derive(Clone, Debug, Serialize)]
pub struct MemoryRegion {
    pub va_start: u64,
    pub size: u64,
    /// Offset of the first byte of this region within the dump file image.
    /// `None` when only a borrowed slice is available (should not happen for
    /// our mmap-backed index build, but kept for safety).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
}

/// Result of a sparse process-memory read.
#[derive(Debug)]
pub enum ReadStatus<'a> {
    /// Full `len` bytes available as a contiguous slice into the dump mmap.
    Ok(&'a [u8]),
    /// Some leading bytes available, then a gap (caller may use what is there).
    Partial(&'a [u8]),
    /// No mapping at `va`.
    Unmapped,
}

impl<'a> ReadStatus<'a> {
    pub fn ok(self) -> Option<&'a [u8]> {
        match self {
            ReadStatus::Ok(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_slice(&self) -> Option<&[u8]> {
        match self {
            ReadStatus::Ok(b) | ReadStatus::Partial(b) => Some(*b),
            ReadStatus::Unmapped => None,
        }
    }
}

/// Sorted, non-overlapping process VA → dump-file ranges.
///
/// Byte slices point into the dump mmap. The parent [`super::LoadedDump`] owns
/// the mmap for the full lifetime of this map.
#[derive(Clone, Debug, Default)]
pub struct ProcessMemoryMap {
    regions: Vec<IndexedRegion>,
    total_bytes: u64,
    source: MemorySource,
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub enum MemorySource {
    #[default]
    None,
    MemoryList,
    Memory64List,
    Mixed,
}

#[derive(Clone, Debug)]
struct IndexedRegion {
    va_start: u64,
    size: u64,
    /// Pointer into dump mmap; valid for LoadedDump lifetime.
    data: *const u8,
}

// SAFETY: regions only alias the dump mmap which is immutable and outlives us
// via LoadedDump ownership.
unsafe impl Send for ProcessMemoryMap {}
unsafe impl Sync for ProcessMemoryMap {}

impl ProcessMemoryMap {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_unified(list: Option<&UnifiedMemoryList<'_>>) -> Self {
        let Some(list) = list else {
            return Self::empty();
        };

        let mut regions = Vec::new();
        let mut total_bytes = 0u64;
        let mut saw_32 = false;
        let mut saw_64 = false;

        for mem in list.by_addr() {
            match &mem {
                UnifiedMemory::Memory(_) => saw_32 = true,
                UnifiedMemory::Memory64(_) => saw_64 = true,
            }
            let va_start = mem.base_address();
            let bytes = mem.bytes();
            if bytes.is_empty() {
                continue;
            }
            let size = bytes.len() as u64;
            total_bytes = total_bytes.saturating_add(size);
            regions.push(IndexedRegion {
                va_start,
                size,
                data: bytes.as_ptr(),
            });
        }

        regions.sort_unstable_by_key(|r| r.va_start);
        let regions = merge_adjacent(regions);

        let source = match (saw_32, saw_64) {
            (false, false) => MemorySource::None,
            (true, false) => MemorySource::MemoryList,
            (false, true) => MemorySource::Memory64List,
            (true, true) => MemorySource::Mixed,
        };

        Self {
            regions,
            total_bytes,
            source,
        }
    }

    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn source_label(&self) -> &'static str {
        match self.source {
            MemorySource::None => "none",
            MemorySource::MemoryList => "MemoryList",
            MemorySource::Memory64List => "Memory64List",
            MemorySource::Mixed => "mixed",
        }
    }

    /// Public region list for MCP pagination.
    pub fn regions_page(&self, offset: usize, limit: usize) -> Vec<MemoryRegion> {
        self.regions
            .iter()
            .skip(offset)
            .take(limit)
            .map(|r| MemoryRegion {
                va_start: r.va_start,
                size: r.size,
                file_offset: None,
            })
            .collect()
    }

    /// Fraction of `[base, base+size)` covered by dump memory (0.0–1.0).
    pub fn coverage_ratio(&self, base: u64, size: u64) -> f32 {
        if size == 0 {
            return 0.0;
        }
        let end = base.saturating_add(size);
        let mut covered = 0u64;
        let start_idx = self
            .regions
            .partition_point(|r| r.va_start.saturating_add(r.size) <= base);
        for r in self.regions.iter().skip(start_idx) {
            if r.va_start >= end {
                break;
            }
            let lo = r.va_start.max(base);
            let hi = r.va_start.saturating_add(r.size).min(end);
            if hi > lo {
                covered = covered.saturating_add(hi - lo);
            }
        }
        (covered as f64 / size as f64).clamp(0.0, 1.0) as f32
    }

    /// Binary-search read of up to `len` bytes at process VA.
    pub fn read_at(&self, va: u64, len: usize) -> ReadStatus<'_> {
        if len == 0 {
            return ReadStatus::Ok(&[]);
        }
        // First region whose end > va.
        let idx = self
            .regions
            .partition_point(|r| r.va_start.saturating_add(r.size) <= va);
        if idx >= self.regions.len() {
            return ReadStatus::Unmapped;
        }
        let r = &self.regions[idx];
        if va < r.va_start || va >= r.va_start.saturating_add(r.size) {
            return ReadStatus::Unmapped;
        }
        self.slice_from_region(idx, va, len)
    }

    fn slice_from_region(&self, idx: usize, va: u64, len: usize) -> ReadStatus<'_> {
        let r = &self.regions[idx];
        let offset = (va - r.va_start) as usize;
        let avail = (r.size as usize).saturating_sub(offset);
        if avail == 0 {
            return ReadStatus::Unmapped;
        }
        let take = avail.min(len);
        // SAFETY: data points into dump mmap owned by LoadedDump; region size
        // matches the original slice length captured at index build.
        let slice = unsafe { std::slice::from_raw_parts(r.data.add(offset), take) };
        if take == len {
            ReadStatus::Ok(slice)
        } else {
            ReadStatus::Partial(slice)
        }
    }

    /// True if any byte of `[va, va+1)` is mapped.
    pub fn contains_va(&self, va: u64) -> bool {
        !matches!(self.read_at(va, 1), ReadStatus::Unmapped)
    }
}

fn merge_adjacent(regions: Vec<IndexedRegion>) -> Vec<IndexedRegion> {
    if regions.is_empty() {
        return regions;
    }
    let mut out = Vec::with_capacity(regions.len());
    let mut cur = regions[0].clone();
    for next in regions.into_iter().skip(1) {
        let cur_end = cur.va_start.saturating_add(cur.size);
        let cur_data_end = unsafe { cur.data.add(cur.size as usize) };
        if next.va_start == cur_end && next.data == cur_data_end {
            cur.size = cur.size.saturating_add(next.size);
        } else {
            out.push(cur);
            cur = next;
        }
    }
    out.push(cur);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_from_parts(parts: &[(u64, &[u8])]) -> ProcessMemoryMap {
        let mut regions = Vec::new();
        let mut total = 0u64;
        for &(va, bytes) in parts {
            total += bytes.len() as u64;
            regions.push(IndexedRegion {
                va_start: va,
                size: bytes.len() as u64,
                data: bytes.as_ptr(),
            });
        }
        ProcessMemoryMap {
            regions,
            total_bytes: total,
            source: MemorySource::MemoryList,
        }
    }

    #[test]
    fn read_hits_and_misses() {
        let buf_a = vec![0xAAu8; 16];
        let buf_b = vec![0xBBu8; 8];
        let a: &'static [u8] = Box::leak(buf_a.into_boxed_slice());
        let b: &'static [u8] = Box::leak(buf_b.into_boxed_slice());
        let map = map_from_parts(&[(0x1000, a), (0x2000, b)]);
        match map.read_at(0x1004, 4) {
            ReadStatus::Ok(s) => assert_eq!(s, &[0xAA; 4]),
            other => panic!("expected Ok, got {other:?}"),
        }
        assert!(matches!(map.read_at(0x1800, 4), ReadStatus::Unmapped));
        match map.read_at(0x2006, 4) {
            ReadStatus::Partial(s) => assert_eq!(s.len(), 2),
            other => panic!("expected Partial, got {other:?}"),
        }
        assert!((map.coverage_ratio(0x1000, 32) - 0.5).abs() < 0.01);
    }
}
