use std::fs::File;
use std::ops::Deref;
use std::path::Path;

use anyhow::Result;
use memmap2::Mmap;

pub mod pe;

/// A file-backed, read-only memory map.
///
/// Owns both the underlying `File` and the `Mmap` so the bytes remain valid
/// for the lifetime of this object.
pub struct MappedImage {
    _file: File,
    mmap: Mmap,
}

impl MappedImage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(Self { _file: file, mmap })
    }
}

impl Deref for MappedImage {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.mmap
    }
}
