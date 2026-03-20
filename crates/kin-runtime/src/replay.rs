// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::run::{RunStatus, ValidationRun};

/// Replay metadata for reproducing a validation run.
///
/// Contains enough information to re-execute the same command in
/// the same workspace state, allowing evidence verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMetadata {
    /// Original run ID.
    pub original_run_id: String,
    /// Command that was executed.
    pub command: String,
    /// Working directory.
    pub working_dir: String,
    /// Workspace snapshot ID at the time of the run.
    pub snapshot_id: Option<String>,
    /// Original run status (for comparison on replay).
    pub original_status: RunStatus,
    /// Original exit code.
    pub original_exit_code: Option<i32>,
    /// Original duration in milliseconds.
    pub original_duration_ms: Option<u64>,
    /// When the original run was executed.
    pub original_timestamp: Option<DateTime<Utc>>,
    /// When this replay metadata was created.
    pub created_at: DateTime<Utc>,
}

/// Extract replay metadata from a completed validation run.
pub fn extract_replay_metadata(run: &ValidationRun) -> ReplayMetadata {
    ReplayMetadata {
        original_run_id: run.id.clone(),
        command: run.command.clone(),
        working_dir: run.working_dir.clone(),
        snapshot_id: run.snapshot_id.clone(),
        original_status: run.status,
        original_exit_code: run.exit_code,
        original_duration_ms: run.duration_ms,
        original_timestamp: run.started_at,
        created_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::{create_run, RunOptions};

    #[test]
    fn extract_replay_from_run() {
        let run = create_run(RunOptions {
            label: "test".into(),
            command: "cargo test".into(),
            working_dir: "/home/user/project".into(),
            snapshot_id: Some("snap-abc".into()),
        });

        let replay = extract_replay_metadata(&run);
        assert_eq!(replay.original_run_id, run.id);
        assert_eq!(replay.command, "cargo test");
        assert_eq!(replay.working_dir, "/home/user/project");
        assert_eq!(replay.snapshot_id, Some("snap-abc".into()));
        assert_eq!(replay.original_status, RunStatus::Pending);
    }

    #[test]
    fn replay_metadata_serializes() {
        let run = create_run(RunOptions {
            label: "serialize".into(),
            command: "make test".into(),
            working_dir: "/tmp".into(),
            snapshot_id: None,
        });

        let replay = extract_replay_metadata(&run);
        let json = serde_json::to_string(&replay).unwrap();
        let parsed: ReplayMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.command, "make test");
        assert_eq!(parsed.original_status, RunStatus::Pending);
    }
}
