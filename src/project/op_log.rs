//! Append-only, crash-safe operation journal for every project.
//!
//! Each record is length-prefixed postcard bytes.  Recovery scans forward and
//! drops the last record if it is torn, so an unfinished write can never
//! corrupt earlier history.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::project::op::Op;
use crate::project::persistence::{idb_path, idb_path_in};

/// A durable log of project mutations.
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    /// Open (or create) the journal for a project keyed by its image SHA256.
    #[allow(dead_code)] // compatibility entry point; runtime code uses open_in
    pub fn open(sha256: &str) -> Self {
        let mut path = idb_path(sha256);
        path.set_extension("oplog");
        Self { path }
    }

    /// Open a journal under an explicit Windy data directory.
    pub fn open_in(home_dir: impl AsRef<std::path::Path>, sha256: &str) -> Self {
        let mut path = idb_path_in(home_dir, sha256);
        path.set_extension("oplog");
        Self { path }
    }

    /// Open a journal at an explicit path. Mainly useful for tests.
    #[cfg(test)]
    pub fn open_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Append an operation as one newline-delimited JSON record and fsync.
    pub fn append(&self, seq: u64, op: &Op) -> Result<()> {
        let record = JournalRecord {
            seq,
            op: op.clone(),
        };
        let mut line = serde_json::to_vec(&record).context("serialize op")?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create projects directory")?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("open oplog for append")?;
        file.write_all(&line)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .context("append op to oplog")?;
        Ok(())
    }

    /// Read all valid newline-delimited records.  A torn/incomplete last line
    /// is silently dropped, so a crash can never corrupt earlier history.
    pub fn read_all(&self) -> Vec<JournalRecord> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break, // torn UTF-8 tail
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line) {
                Ok(record) => records.push(record),
                Err(_) => break, // partial JSON line from a crash
            }
        }
        records
    }

    /// Remove all records whose sequence number is <= `seq`.  Used after a
    /// snapshot has durably captured them.
    pub fn truncate_through(&self, seq: u64) -> Result<()> {
        let records: Vec<_> = self
            .read_all()
            .into_iter()
            .filter(|r| r.seq > seq)
            .collect();
        let tmp = self.path.with_extension("oplog.tmp");
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create projects directory")?;
        }
        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)
                .context("create truncated oplog")?;
            for record in &records {
                let mut line = serde_json::to_vec(record).context("serialize op")?;
                line.push(b'\n');
                file.write_all(&line)?;
            }
            file.flush()?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path).context("replace oplog with truncated version")?;
        Ok(())
    }

    /// Highest sequence number present in the log, if any.
    #[allow(dead_code)] // used by recovery / status tooling
    pub fn head_seq(&self) -> Option<u64> {
        self.read_all().last().map(|r| r.seq)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JournalRecord {
    pub seq: u64,
    pub op: Op,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::op::Op;
    use crate::project::symbols::SymbolKind;

    #[test]
    fn append_and_read_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-oplog-rt-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_file(&tmp);
        let journal = Journal::open_path(&tmp);

        let op = Op::RenameSymbol {
            va: 0x1000,
            name: "foo".to_string(),
            kind: SymbolKind::User,
            old_name: None,
            old_kind: None,
        };
        journal.append(1, &op).unwrap();
        journal.append(2, &op).unwrap();

        let records = journal.read_all();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].seq, 1);
        assert_eq!(records[1].seq, 2);

        fs::remove_file(&tmp).ok();
    }

    #[test]
    fn torn_tail_dropped() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-oplog-torn-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_file(&tmp);
        let journal = Journal::open_path(&tmp);

        let op = Op::RenameSymbol {
            va: 0x1000,
            name: "foo".to_string(),
            kind: SymbolKind::User,
            old_name: None,
            old_kind: None,
        };
        journal.append(1, &op).unwrap();

        // Append a half length prefix to simulate a crash mid-write.
        let mut file = OpenOptions::new().append(true).open(&tmp).unwrap();
        file.write_all(&[0xff, 0xff, 0x00, 0x00]).unwrap();
        drop(file);

        let records = journal.read_all();
        assert_eq!(records.len(), 1);

        fs::remove_file(&tmp).ok();
    }
}
