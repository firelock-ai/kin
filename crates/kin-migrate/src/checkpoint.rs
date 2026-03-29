// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Migration checkpoint mechanism.
//!
//! Every `CHECKPOINT_INTERVAL` commits, write progress to
//! `.kin/migrate-checkpoint.json` so that interrupted migrations can resume.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{MigrateError, Result};

/// How often (in commits) to write a checkpoint.
pub const CHECKPOINT_INTERVAL: usize = 100;

/// Persistent checkpoint written to `.kin/migrate-checkpoint.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateCheckpoint {
    /// The last commit hash that was fully processed.
    pub last_commit: String,
    /// Total commits processed so far.
    pub total_processed: usize,
    /// Timestamp when the checkpoint was written.
    pub timestamp: DateTime<Utc>,
    /// Total entities extracted so far.
    pub entities_extracted: usize,
    /// Total relations extracted so far.
    pub relations_extracted: usize,
    /// Total files indexed so far.
    pub files_indexed: usize,
}

impl MigrateCheckpoint {
    /// Create a new checkpoint.
    pub fn new(
        last_commit: String,
        total_processed: usize,
        entities_extracted: usize,
        relations_extracted: usize,
        files_indexed: usize,
    ) -> Self {
        Self {
            last_commit,
            total_processed,
            timestamp: Utc::now(),
            entities_extracted,
            relations_extracted,
            files_indexed,
        }
    }
}

/// Resolve the checkpoint file path for a target directory.
pub fn checkpoint_path(target: &Path) -> PathBuf {
    target.join(".kin").join("migrate-checkpoint.json")
}

/// Write a checkpoint to disk.
pub fn write_checkpoint(target: &Path, checkpoint: &MigrateCheckpoint) -> Result<()> {
    let path = checkpoint_path(target);
    let json = serde_json::to_string_pretty(checkpoint)?;
    std::fs::write(&path, json).map_err(|e| MigrateError::io(&path, e))?;
    Ok(())
}

/// Read a checkpoint from disk if it exists.
pub fn read_checkpoint(target: &Path) -> Result<Option<MigrateCheckpoint>> {
    let path = checkpoint_path(target);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path).map_err(|e| MigrateError::io(&path, e))?;
    let checkpoint: MigrateCheckpoint = serde_json::from_str(&content)?;
    Ok(Some(checkpoint))
}

/// Remove the checkpoint file after a successful migration.
pub fn clear_checkpoint(target: &Path) -> Result<()> {
    let path = checkpoint_path(target);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| MigrateError::io(&path, e))?;
    }
    Ok(())
}

/// Determine whether a checkpoint should be written at the given commit count.
pub fn should_checkpoint(commits_processed: usize) -> bool {
    commits_processed > 0 && commits_processed % CHECKPOINT_INTERVAL == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_interval_is_100() {
        assert_eq!(CHECKPOINT_INTERVAL, 100);
    }

    #[test]
    fn should_checkpoint_at_intervals() {
        assert!(!should_checkpoint(0));
        assert!(!should_checkpoint(1));
        assert!(!should_checkpoint(99));
        assert!(should_checkpoint(100));
        assert!(!should_checkpoint(101));
        assert!(should_checkpoint(200));
        assert!(should_checkpoint(300));
    }

    #[test]
    fn write_and_read_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();

        let cp = MigrateCheckpoint::new("abc123".to_string(), 150, 42, 10, 5);

        write_checkpoint(dir.path(), &cp).unwrap();
        let loaded = read_checkpoint(dir.path()).unwrap().unwrap();

        assert_eq!(loaded.last_commit, "abc123");
        assert_eq!(loaded.total_processed, 150);
        assert_eq!(loaded.entities_extracted, 42);
        assert_eq!(loaded.relations_extracted, 10);
        assert_eq!(loaded.files_indexed, 5);
    }

    #[test]
    fn read_checkpoint_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_checkpoint(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn clear_checkpoint_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();

        let cp = MigrateCheckpoint::new("def456".to_string(), 200, 0, 0, 0);
        write_checkpoint(dir.path(), &cp).unwrap();

        assert!(checkpoint_path(dir.path()).exists());
        clear_checkpoint(dir.path()).unwrap();
        assert!(!checkpoint_path(dir.path()).exists());
    }

    #[test]
    fn clear_checkpoint_noop_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        // Should not error when checkpoint doesn't exist
        clear_checkpoint(dir.path()).unwrap();
    }

    #[test]
    fn checkpoint_serializes_to_json() {
        let cp = MigrateCheckpoint::new("aaa".to_string(), 100, 50, 20, 10);
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("aaa"));
        assert!(json.contains("100"));
        let parsed: MigrateCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.last_commit, "aaa");
    }

    #[test]
    fn checkpoint_path_is_correct() {
        let path = checkpoint_path(Path::new("/project"));
        assert_eq!(path, PathBuf::from("/project/.kin/migrate-checkpoint.json"));
    }
}
