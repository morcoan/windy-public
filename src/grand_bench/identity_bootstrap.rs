//! Offline identity bootstrap for strict Grand v2.
//!
//! Writes compatibility identity-map files from linker-derived manifest
//! entries. No decompiler output or source gold participates in identity.

use std::fs;
use std::path::{Path, PathBuf};

use super::suite::{ManifestFunction, load_manifest};

#[allow(dead_code)] // used by bootstrap_identity_maps (test-gated + tooling)
fn resolve_repo_path(repo: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() { pb } else { repo.join(p) }
}

/// Materialize linker-derived manifest identities as legacy sidecar files.
///
/// Writes `{out_dir}/{program_id}_{profile}.json` with `Vec<ManifestFunction>`.
#[allow(dead_code)] // invoked from tests / offline bootstrap jobs
pub fn bootstrap_identity_maps(
    repo: &Path,
    manifest_path: &Path,
    out_dir: &Path,
) -> anyhow::Result<usize> {
    fs::create_dir_all(out_dir)?;
    let manifest = load_manifest(manifest_path)?;
    let mut n = 0usize;
    for bin in &manifest.binaries {
        let pe = resolve_repo_path(repo, &bin.pe_path);
        if !pe.exists() || bin.function_map.is_empty() {
            continue;
        }
        let path = out_dir.join(format!("{}_{}.json", bin.program_id, bin.profile));
        fs::write(&path, serde_json::to_string_pretty(&bin.function_map)?)?;
        n += 1;
    }
    Ok(n)
}

/// Load a frozen identity map if present.
pub fn load_identity_map(path: &Path) -> Option<Vec<ManifestFunction>> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_writes_identity_for_smoke_binary() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let Ok(scratch) = std::env::var("WINDY_SCRATCH") else {
            return;
        };
        let mini = PathBuf::from(&scratch).join("mini_strict_manifest.json");
        if !mini.exists() {
            return;
        }
        let out = PathBuf::from(&scratch).join("identity_maps");
        let n = bootstrap_identity_maps(&root, &mini, &out).expect("bootstrap");
        assert!(n >= 1, "expected at least one binary map");
        let any = std::fs::read_dir(&out)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().is_some_and(|x| x == "json"));
        assert!(any, "no identity json written to {}", out.display());
    }

    /// Full-suite identity freeze (gated by WINDY_BOOTSTRAP_FULL=1).
    #[test]
    fn bootstrap_full_manifest_identity_maps() {
        if std::env::var("WINDY_BOOTSTRAP_FULL").ok().as_deref() != Some("1") {
            return;
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let scratch =
            std::env::var("WINDY_SCRATCH").expect("WINDY_BOOTSTRAP_FULL=1 requires WINDY_SCRATCH");
        let man = root.join("eval/grand/manifest.json");
        let out = PathBuf::from(&scratch).join("identity_maps");
        let n = bootstrap_identity_maps(&root, &man, &out).expect("full bootstrap");
        assert!(n >= 64, "expected many binaries, got {n}");
    }
}
