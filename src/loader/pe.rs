use std::path::{Path, PathBuf};

use anyhow::Result;
use exe::pe::VecPE;
use petriage::analysis::{analyze, AnalysisOptions, AnalysisResult};
use petriage::parse_pe_lenient;

use crate::loader::MappedImage;

/// A loaded Windows PE with both cheap mmap access and exe-rs structural access.
#[allow(dead_code)] // exe_pe is the structural seam for Phase 2+
pub struct LoadedPe {
    /// Original path on disk.
    pub path: PathBuf,
    /// Memory-mapped file contents.
    pub image: MappedImage,
    /// exe-rs PE representation for header/section/import manipulation.
    pub exe_pe: VecPE,
    /// petriage surface-analysis result.
    pub triage: AnalysisResult,
    /// Warning emitted during lenient parsing.
    pub parse_warning: Option<String>,
}

impl LoadedPe {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let label = path.display().to_string();
        let image = MappedImage::open(path)?;

        let (gob_pe, warning) = parse_pe_lenient(&image, &label)
            .map_err(|e| anyhow::anyhow!("PE parse failed: {e}"))?;

        // Show everything in the triage summary; low string threshold for the UI.
        let opts = AnalysisOptions {
            show_headers: true,
            show_sections: true,
            show_imports: true,
            show_exports: true,
            show_strings: true,
            show_hashes: true,
            show_overlay: true,
            show_resources: true,
            show_authenticode: true,
            show_all: true,
            min_str_len: 4,
            file_name: label,
            opsec_strict: false,
        };
        let triage = analyze(&image, &gob_pe, &opts);

        // exe-rs makes a private copy of the bytes so PETriage keeps cheap mmap access.
        let exe_pe = VecPE::from_disk_data(&image[..]);

        Ok(Self {
            path: path.to_path_buf(),
            image,
            exe_pe,
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
        assert!(pe.image.len() > 0);
        assert!(pe.triage.sections.as_ref().map_or(false, |s| !s.is_empty()));
    }
}
