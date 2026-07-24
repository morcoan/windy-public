//! Symsrv-compatible symbol cache with transparent download from the
//! Microsoft public symbol server. Supports a bundled `./symbols` folder,
//! the resolved Windy data directory's `symbols` cache, and interop with any symsrv-style
//! directory the user drops files into.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::loader::debug_dir::CodeViewRecord;
use crate::project::persistence::windy_home_dir;

const SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SymbolStore {
    cache_dir: PathBuf,
    /// Optional directory next to the binary (./symbols) shipped with the tool.
    bundle_dir: Option<PathBuf>,
    server: String,
}

impl Default for SymbolStore {
    fn default() -> Self {
        Self::new_central()
    }
}

impl SymbolStore {
    /// Central cache under the resolved Windy data directory plus an optional
    /// bundled `./symbols`.
    pub fn new_central() -> Self {
        Self::with_home_dir(windy_home_dir())
    }

    /// Symbol cache under an explicit Windy data directory.
    pub fn with_home_dir(home_dir: impl AsRef<Path>) -> Self {
        let cache_dir = home_dir.as_ref().join("symbols");
        let bundle_dir = bundled_symbols_dir();
        Self {
            cache_dir,
            bundle_dir,
            server: SYMBOL_SERVER.to_string(),
        }
    }

    /// Resolve a PDB record to a local file path. The file is fetched once and
    /// cached forever afterwards.
    #[allow(dead_code)] // public-channel compatibility; beta selects policy explicitly
    pub fn resolve(&self, rec: &CodeViewRecord) -> Option<PathBuf> {
        self.resolve_with_download(rec, true)
    }

    /// Resolve locally first and optionally query Microsoft's public symbol
    /// server. Private beta uses this to avoid a guaranteed 30-second network
    /// miss for unsigned/private game modules.
    pub fn resolve_with_download(
        &self,
        rec: &CodeViewRecord,
        allow_public_download: bool,
    ) -> Option<PathBuf> {
        let original = Path::new(&rec.pdb_name);
        if original.is_absolute() && original.exists() {
            info!(
                "PDB {} found at original build path {}",
                rec.pdb_basename(),
                original.display()
            );
            return Some(original.to_path_buf());
        }
        if let Some(path) = self.find_bundle(rec) {
            info!("PDB {} found in bundled symbols", rec.pdb_basename());
            return Some(path);
        }
        if let Some(path) = self.find_cache(rec) {
            info!(
                "PDB {} found in cache {}",
                rec.pdb_basename(),
                path.display()
            );
            return Some(path);
        }
        if !allow_public_download {
            debug!(
                "Skipping Microsoft symbol server for private/non-Microsoft PDB {}",
                rec.pdb_basename()
            );
            return None;
        }
        match self.download_and_cache(rec) {
            Ok(path) => Some(path),
            Err(e) => {
                info!("No PDB (normal for private binaries). Continuing without symbols.");
                debug!("PDB fetch failed for {}: {e}", rec.pdb_basename());
                None
            }
        }
    }

    fn pdb_path(&self, rec: &CodeViewRecord, base: &Path) -> PathBuf {
        base.join(rec.pdb_basename())
            .join(rec.guid_age())
            .join(rec.pdb_basename())
    }

    fn find_bundle(&self, rec: &CodeViewRecord) -> Option<PathBuf> {
        let dir = self.bundle_dir.as_ref()?;
        let path = self.pdb_path(rec, dir);
        path.exists().then_some(path)
    }

    fn find_cache(&self, rec: &CodeViewRecord) -> Option<PathBuf> {
        let path = self.pdb_path(rec, &self.cache_dir);
        path.exists().then_some(path)
    }

    fn download_and_cache(&self, rec: &CodeViewRecord) -> Result<PathBuf> {
        let url = format!(
            "{}/{}/{}/{}",
            self.server,
            percent_encode(&rec.pdb_basename()),
            rec.guid_age(),
            percent_encode(&rec.pdb_basename())
        );
        info!("fetching PDB from {}", url);

        let response = ureq::get(&url)
            .timeout(REQUEST_TIMEOUT)
            .call()
            .with_context(|| format!("HTTP request failed: {url}"))?;

        let mut reader = response.into_reader();
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .context("failed to read PDB response")?;

        if bytes.len() < 32 {
            anyhow::bail!("PDB response too small ({} bytes)", bytes.len());
        }

        let path = self.pdb_path(rec, &self.cache_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create cache dir {}", parent.display()))?;
        }
        fs::write(&path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
        info!("cached PDB to {} ({} bytes)", path.display(), bytes.len());
        Ok(path)
    }
}

fn bundled_symbols_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.join("symbols");
    if dir.exists() { Some(dir) } else { None }
}

/// Minimal percent-encoding for symbol names; PDB names virtually never need it,
/// but keeps the URL valid if a path separator slips through.
fn percent_encode(s: &str) -> String {
    s.replace(' ', "%20")
        .replace('%', "%25")
        .replace('/', "%2F")
        .replace('\\', "%5C")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_age_format() {
        let rec = CodeViewRecord {
            guid: uuid::Uuid::nil(),
            age: 7,
            pdb_name: "ntdll.pdb".to_string(),
        };
        assert_eq!(rec.guid_age(), "000000000000000000000000000000007");
        assert_eq!(rec.pdb_basename(), "ntdll.pdb");
    }

    #[test]
    fn explicit_home_roots_the_symbol_cache() {
        let home = PathBuf::from("isolated-windy-home");
        let store = SymbolStore::with_home_dir(&home);
        assert_eq!(store.cache_dir, home.join("symbols"));
    }
}
