//! Checksummed immutable partitions for demand-driven structural analysis.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Envelope {
    abi: String,
    image_sha256: String,
    payload_sha256: String,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PathHashMemo {
    canonical_path: String,
    bytes: u64,
    modified_nanos: u128,
    sha256: String,
}

pub fn hash_path(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn hash_path_memoized(path: &Path, cache_root: &Path) -> Result<String> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?;
    let metadata = canonical.metadata()?;
    let modified_nanos = metadata
        .modified()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let canonical_text = canonical.to_string_lossy().to_string();
    let path_key = crate::project::persistence::hash_bytes(canonical_text.as_bytes());
    let abi = "v3-path-hash-1";
    let memo_path = partition_path(cache_root, "path-hash", &path_key, abi);
    if let Some(memo) = load::<PathHashMemo>(&memo_path, abi, &path_key)?
        && memo.canonical_path == canonical_text
        && memo.bytes == metadata.len()
        && memo.modified_nanos == modified_nanos
    {
        return Ok(memo.sha256);
    }
    let sha256 = hash_path(&canonical)?;
    let memo = PathHashMemo {
        canonical_path: canonical_text,
        bytes: metadata.len(),
        modified_nanos,
        sha256: sha256.clone(),
    };
    store(&memo_path, abi, &path_key, &memo)?;
    Ok(sha256)
}

pub fn pe_bitness(path: &Path) -> Result<u32> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos).context("read DOS header")?;
    if &dos[..2] != b"MZ" {
        anyhow::bail!("not a PE image");
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    file.seek(SeekFrom::Start(pe_offset + 24))?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)
        .context("read optional-header magic")?;
    match u16::from_le_bytes(magic) {
        0x20b => Ok(64),
        0x10b => Ok(32),
        value => anyhow::bail!("unsupported PE optional-header magic {value:#x}"),
    }
}

pub fn partition_path(root: &Path, partition: &str, image_sha256: &str, abi: &str) -> PathBuf {
    root.join("structural")
        .join(partition)
        .join(format!("{image_sha256}-{abi}.postcard"))
}

pub fn load<T: DeserializeOwned>(path: &Path, abi: &str, image_sha256: &str) -> Result<Option<T>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let envelope: Envelope = match postcard::from_bytes(&bytes) {
        Ok(envelope) => envelope,
        Err(_) => return Ok(None),
    };
    if envelope.abi != abi || envelope.image_sha256 != image_sha256 {
        return Ok(None);
    }
    let payload_sha256 = crate::project::persistence::hash_bytes(&envelope.payload);
    if payload_sha256 != envelope.payload_sha256 {
        return Ok(None);
    }
    let decoded = postcard::from_bytes(&envelope.payload).ok();
    if decoded.is_some()
        && let Ok(file) = File::options().write(true).open(path)
    {
        let _ = file.set_times(std::fs::FileTimes::new().set_modified(SystemTime::now()));
    }
    Ok(decoded)
}

pub fn store<T: Serialize>(path: &Path, abi: &str, image_sha256: &str, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("structural cache path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let payload = postcard::to_allocvec(value).context("serialize structural partition")?;
    let envelope = Envelope {
        abi: abi.to_string(),
        image_sha256: image_sha256.to_string(),
        payload_sha256: crate::project::persistence::hash_bytes(&payload),
        payload,
    };
    let bytes = postcard::to_allocvec(&envelope).context("serialize cache envelope")?;
    let nonce = Uuid::new_v4();
    let temporary = parent.join(format!(".tmp-{nonce}"));
    let quarantine = parent.join(format!(".invalid-{nonce}"));
    {
        let mut file =
            File::create(&temporary).with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    let quarantined = if path.exists() {
        fs::rename(path, &quarantine)
            .with_context(|| format!("quarantine stale cache {}", path.display()))?;
        true
    } else {
        false
    };
    if let Err(error) = fs::rename(&temporary, path) {
        if quarantined {
            let _ = fs::rename(&quarantine, path);
        }
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("install cache {}", path.display()));
    }
    if quarantined {
        let _ = fs::remove_file(quarantine);
    }
    Ok(())
}

pub fn prune_lru(root: &Path, max_bytes: u64) -> Result<(u64, usize)> {
    fn visit(directory: &Path, files: &mut Vec<(SystemTime, u64, PathBuf)>) -> Result<()> {
        if !directory.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                visit(&path, files)?;
            } else if path
                .extension()
                .is_some_and(|extension| extension == "postcard")
            {
                files.push((
                    metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    metadata.len(),
                    path,
                ));
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    visit(root, &mut files)?;
    files.sort_unstable_by_key(|(modified, _, _)| *modified);
    let mut bytes: u64 = files.iter().map(|(_, size, _)| size).sum();
    let mut removed = 0usize;
    for (_, size, path) in files {
        if bytes <= max_bytes {
            break;
        }
        if fs::remove_file(&path).is_ok() {
            bytes = bytes.saturating_sub(size);
            removed += 1;
        }
    }
    Ok((bytes, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_and_abi_reject_stale_or_corrupt_partitions() {
        let root = std::env::temp_dir().join(format!("windy-cache-test-{}", Uuid::new_v4()));
        let path = partition_path(&root, "sketch", "abc", "abi1");
        store(&path, "abi1", "abc", &vec![1u32, 2, 3]).unwrap();
        assert_eq!(
            load::<Vec<u32>>(&path, "abi1", "abc").unwrap(),
            Some(vec![1, 2, 3])
        );
        assert!(load::<Vec<u32>>(&path, "abi2", "abc").unwrap().is_none());
        fs::write(&path, b"corrupt").unwrap();
        assert!(load::<Vec<u32>>(&path, "abi1", "abc").unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }
}
