//! Append-only crash-safe activity journal for every project.
//!
//! Each record is one newline-delimited JSON line. Recovery scans forward and
//! drops a torn/incomplete last line, so a crash can never corrupt earlier
//! history. This is separate from the operation journal (`op_log.rs`): the
//! activity log stores human-readable summaries intended for the operator UI,
//! while the operation journal stores reversible machine state changes.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single mutation event visible to the operator UI and persisted per project.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub timestamp: SystemTime,
    pub project_id: Uuid,
    pub client_id: String,
    pub op_summary: String,
    pub seq: u64,
}

/// Durable per-project activity log keyed by image SHA256.
pub struct ActivityJournal {
    path: PathBuf,
}

impl ActivityJournal {
    /// Open (or create) the activity log for a project under `home_dir`.
    pub fn open(home_dir: impl AsRef<Path>, sha256: &str) -> Self {
        let path = home_dir
            .as_ref()
            .join("projects")
            .join(format!("{sha256}.activity"));
        Self { path }
    }

    /// Open a journal at an explicit path. Mainly useful for tests.
    #[cfg(test)]
    pub fn open_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Append an activity event as one JSON line and fsync.
    pub fn append(&self, event: &ActivityEvent) -> Result<()> {
        let mut line = serde_json::to_vec(event).context("serialize activity event")?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create projects directory")?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("open activity log for append")?;
        file.write_all(&line)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .context("append activity event")?;
        Ok(())
    }

    /// Read the most recent `limit` valid records in chronological order.
    /// A torn/incomplete last line is silently dropped.
    pub fn read_tail(&self, limit: usize) -> Vec<ActivityEvent> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line) {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        let start = events.len().saturating_sub(limit);
        events.into_iter().skip(start).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn append_and_read_tail_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-activity-rt-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let _ = fs::remove_file(&tmp);
        let journal = ActivityJournal::open_path(&tmp);

        for i in 1..=5u64 {
            let event = ActivityEvent {
                timestamp: SystemTime::now(),
                project_id: Uuid::new_v4(),
                client_id: "test".to_string(),
                op_summary: format!("op {i}"),
                seq: i,
            };
            journal.append(&event).unwrap();
        }

        let tail = journal.read_tail(3);
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);

        fs::remove_file(&tmp).ok();
    }

    #[test]
    fn torn_tail_dropped() {
        let tmp = std::env::temp_dir().join(format!(
            "windy-activity-torn-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let _ = fs::remove_file(&tmp);
        let journal = ActivityJournal::open_path(&tmp);

        let event = ActivityEvent {
            timestamp: SystemTime::now(),
            project_id: Uuid::new_v4(),
            client_id: "test".to_string(),
            op_summary: "ok".to_string(),
            seq: 1,
        };
        journal.append(&event).unwrap();

        let mut file = OpenOptions::new().append(true).open(&tmp).unwrap();
        file.write_all(b"{\"torn\": ").unwrap();
        drop(file);

        let events = journal.read_tail(10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 1);

        fs::remove_file(&tmp).ok();
    }
}
