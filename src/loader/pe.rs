use std::path::{Path, PathBuf};

use anyhow::Result;
use petriage::analysis::{AnalysisOptions, AnalysisResult, analyze};
use petriage::parse_pe_lenient;

use crate::loader::MappedImage;

/// A loaded Windows PE with cheap mmap access and PETriage structure metadata.
pub struct LoadedPe {
    /// Original path on disk.
    pub path: PathBuf,
    /// Memory-mapped file contents.
    pub image: MappedImage,
    /// petriage surface-analysis result.
    pub triage: AnalysisResult,
    /// Warning emitted during lenient parsing.
    pub parse_warning: Option<String>,
}

impl LoadedPe {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_profile(path, true)
    }

    /// Essential PE catalog for demand-driven target admission. This avoids
    /// whole-file strings, hashes, resources, overlays, and Authenticode; the
    /// full profile remains available when a function/global stage is promoted.
    pub fn open_catalog(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_profile(path, false)
    }

    fn open_profile(path: impl AsRef<Path>, full: bool) -> Result<Self> {
        let path = path.as_ref();
        let label = path.display().to_string();
        let image = MappedImage::open(path)?;

        let (gob_pe, warning) = parse_pe_lenient(&image, &label)
            .map_err(|e| anyhow::anyhow!("PE parse failed: {e}"))?;

        // The catalog profile intentionally touches only structural tables.
        // Full triage remains demand-driven behind analysis promotion.
        let opts = AnalysisOptions {
            show_headers: true,
            show_sections: true,
            show_imports: true,
            show_exports: true,
            show_strings: full,
            show_hashes: full,
            show_overlay: full,
            show_resources: full,
            show_authenticode: full,
            show_all: full,
            min_str_len: 4,
            file_name: label,
            opsec_strict: false,
        };
        let triage = analyze(&image, &gob_pe, &opts);

        Ok(Self {
            path: path.to_path_buf(),
            image,
            triage,
            parse_warning: warning,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_load_notepad() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping smoke test: {path} not found");
            return;
        }

        let pe = LoadedPe::open(path).expect("should load notepad.exe");
        assert!(!pe.path.as_os_str().is_empty());
        assert!(!pe.image.is_empty());
        assert!(pe.triage.sections.as_ref().is_some_and(|s| !s.is_empty()));
    }
}
