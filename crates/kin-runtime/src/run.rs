// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::process::Command;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{Result, RuntimeError};
use crate::evidence::CapturedEvidence;

/// Status of a validation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    /// Run is queued but not started.
    Pending,
    /// Run is currently executing.
    Running,
    /// Run completed successfully (exit code 0).
    Passed,
    /// Run completed with failures (non-zero exit).
    Failed,
    /// Run was cancelled or timed out.
    Cancelled,
    /// Run encountered an internal error.
    Error,
}

/// A validation run captures a command execution with full evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRun {
    /// Unique run ID.
    pub id: String,
    /// Human-readable label for the run.
    pub label: String,
    /// The command that was executed.
    pub command: String,
    /// Working directory for the command.
    pub working_dir: String,
    /// Current status.
    pub status: RunStatus,
    /// Exit code (if completed).
    pub exit_code: Option<i32>,
    /// When the run was created.
    pub created_at: DateTime<Utc>,
    /// When the run started executing.
    pub started_at: Option<DateTime<Utc>>,
    /// When the run finished.
    pub finished_at: Option<DateTime<Utc>>,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Captured evidence (stdout, stderr, test results).
    pub evidence: Option<CapturedEvidence>,
    /// Workspace snapshot ID at run time.
    pub snapshot_id: Option<String>,
}

/// Options for creating a validation run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Human-readable label.
    pub label: String,
    /// Command to execute (passed to shell).
    pub command: String,
    /// Working directory.
    pub working_dir: String,
    /// Workspace snapshot ID to associate with this run.
    pub snapshot_id: Option<String>,
}

/// Create a new validation run (pending state).
pub fn create_run(opts: RunOptions) -> ValidationRun {
    ValidationRun {
        id: uuid::Uuid::new_v4().to_string(),
        label: opts.label,
        command: opts.command,
        working_dir: opts.working_dir,
        status: RunStatus::Pending,
        exit_code: None,
        created_at: Utc::now(),
        started_at: None,
        finished_at: None,
        duration_ms: None,
        evidence: None,
        snapshot_id: opts.snapshot_id,
    }
}

/// Execute a validation run, capturing stdout/stderr as evidence.
///
/// The command is executed via the system shell (`sh -c` on Unix).
/// Returns the updated run with evidence and final status.
pub fn execute_run(mut run: ValidationRun) -> Result<ValidationRun> {
    run.status = RunStatus::Running;
    run.started_at = Some(Utc::now());

    info!(
        run_id = %run.id,
        label = %run.label,
        command = %run.command,
        "executing validation run"
    );

    let start = Instant::now();

    let output = Command::new("sh")
        .arg("-c")
        .arg(&run.command)
        .current_dir(&run.working_dir)
        .output()
        .map_err(|e| {
            RuntimeError::CommandFailed(format!("failed to execute '{}': {}", run.command, e))
        })?;

    let elapsed = start.elapsed();
    run.duration_ms = Some(elapsed.as_millis() as u64);
    run.finished_at = Some(Utc::now());
    run.exit_code = output.status.code();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    run.evidence = Some(CapturedEvidence {
        stdout: if stdout.is_empty() {
            None
        } else {
            Some(stdout)
        },
        stderr: if stderr.is_empty() {
            None
        } else {
            Some(stderr)
        },
        test_results: Vec::new(),
    });

    if output.status.success() {
        run.status = RunStatus::Passed;
        info!(
            run_id = %run.id,
            duration_ms = run.duration_ms.unwrap_or(0),
            "validation run passed"
        );
    } else {
        run.status = RunStatus::Failed;
        warn!(
            run_id = %run.id,
            exit_code = ?run.exit_code,
            duration_ms = run.duration_ms.unwrap_or(0),
            "validation run failed"
        );
    }

    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_run_is_pending() {
        let run = create_run(RunOptions {
            label: "test".into(),
            command: "echo hello".into(),
            working_dir: "/tmp".into(),
            snapshot_id: None,
        });
        assert_eq!(run.status, RunStatus::Pending);
        assert!(run.exit_code.is_none());
        assert!(run.evidence.is_none());
        assert!(!run.id.is_empty());
    }

    #[test]
    fn execute_echo_passes() {
        let run = create_run(RunOptions {
            label: "echo test".into(),
            command: "echo hello".into(),
            working_dir: "/tmp".into(),
            snapshot_id: None,
        });
        let result = execute_run(run).unwrap();
        assert_eq!(result.status, RunStatus::Passed);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.duration_ms.is_some());
        let ev = result.evidence.unwrap();
        assert!(ev.stdout.unwrap().contains("hello"));
    }

    #[test]
    fn execute_failing_command() {
        let run = create_run(RunOptions {
            label: "fail test".into(),
            command: "exit 1".into(),
            working_dir: "/tmp".into(),
            snapshot_id: None,
        });
        let result = execute_run(run).unwrap();
        assert_eq!(result.status, RunStatus::Failed);
        assert_eq!(result.exit_code, Some(1));
    }

    #[test]
    fn execute_captures_stderr() {
        let run = create_run(RunOptions {
            label: "stderr test".into(),
            command: "echo error_output >&2".into(),
            working_dir: "/tmp".into(),
            snapshot_id: None,
        });
        let result = execute_run(run).unwrap();
        let ev = result.evidence.unwrap();
        assert!(ev.stderr.unwrap().contains("error_output"));
    }

    #[test]
    fn run_serializes() {
        let run = create_run(RunOptions {
            label: "serialize test".into(),
            command: "true".into(),
            working_dir: "/tmp".into(),
            snapshot_id: Some("snap-abc123".into()),
        });
        let json = serde_json::to_string(&run).unwrap();
        let parsed: ValidationRun = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label, "serialize test");
        assert_eq!(parsed.snapshot_id, Some("snap-abc123".into()));
    }

    #[test]
    fn run_status_values() {
        assert_ne!(RunStatus::Pending, RunStatus::Running);
        assert_ne!(RunStatus::Passed, RunStatus::Failed);
        assert_ne!(RunStatus::Cancelled, RunStatus::Error);
    }
}
