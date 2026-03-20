// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use tracing::info;

use crate::error::{Result, RuntimeError};
use crate::workspace::{MaterializeStrategy, MaterializedWorkspace};

/// Configuration for materializing a workspace.
#[derive(Debug, Clone, Default)]
pub struct MaterializeConfig {
    pub strategy: Option<MaterializeStrategy>,
    pub keep: bool,
    pub scope: Option<String>,
}

/// Result of an execution run.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub workspace_path: PathBuf,
    pub strategy_used: MaterializeStrategy,
}

/// Context for executing a command in a materialized workspace.
#[derive(Debug)]
pub struct ExecContext {
    pub workspace: MaterializedWorkspace,
    pub command: String,
    pub args: Vec<String>,
}

impl ExecContext {
    /// Run the command in the materialized workspace directory.
    pub fn run(&self) -> Result<ExecResult> {
        let full_command = if self.args.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.args.join(" "))
        };

        info!(
            command = %full_command,
            workspace = %self.workspace.root.display(),
            "executing in materialized workspace"
        );

        let start = Instant::now();

        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", &full_command])
                .current_dir(&self.workspace.root)
                .output()
        } else {
            Command::new("sh")
                .args(["-c", &full_command])
                .current_dir(&self.workspace.root)
                .output()
        }
        .map_err(|e| RuntimeError::CommandFailed(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms,
            workspace_path: self.workspace.root.clone(),
            strategy_used: self.workspace.strategy,
        })
    }
}

/// Materialize a workspace and execute a command in it.
///
/// This is the high-level entry point combining workspace materialization + execution.
pub fn exec_in_workspace(
    working_dir: &Path,
    command: &str,
    config: &MaterializeConfig,
) -> Result<ExecResult> {
    let workspace_dir = tempfile::tempdir().map_err(|e| RuntimeError::io(working_dir, e))?;
    let workspace_path = workspace_dir.path().to_path_buf();

    // Prevent tempdir from being dropped (we manage cleanup ourselves)
    std::mem::forget(workspace_dir);

    if let Some(ref scope) = config.scope {
        info!(scope = %scope, "exec scope filter active");
    }

    let workspace = MaterializedWorkspace::create(
        working_dir,
        &workspace_path,
        config.strategy,
        config.scope.as_deref(),
    )?;

    let ctx = ExecContext {
        workspace,
        command: command.to_string(),
        args: Vec::new(),
    };

    ctx.run()
}

/// Clean up a workspace directory. Call this after `exec_in_workspace` if `keep` is false.
pub fn cleanup_workspace(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path).map_err(|e| RuntimeError::io(path, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn exec_in_workspace_runs_command() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("data.txt"), "hello world").unwrap();

        let config = MaterializeConfig::default();

        let result = exec_in_workspace(src.path(), "cat data.txt", &config).unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.trim(), "hello world");
        assert!(result.stderr.is_empty());
        assert_ne!(result.workspace_path, src.path());
        assert!(result.duration_ms < 10_000); // sanity: under 10s

        let _ = cleanup_workspace(&result.workspace_path);
    }

    #[test]
    fn exec_in_workspace_captures_exit_code() {
        let src = tempfile::tempdir().unwrap();

        let config = MaterializeConfig::default();

        let result = exec_in_workspace(src.path(), "exit 42", &config).unwrap();

        assert_eq!(result.exit_code, 42);

        let _ = cleanup_workspace(&result.workspace_path);
    }

    #[test]
    fn exec_in_workspace_captures_stderr() {
        let src = tempfile::tempdir().unwrap();

        let config = MaterializeConfig::default();

        let result = exec_in_workspace(src.path(), "echo err_msg >&2", &config).unwrap();

        assert!(result.stderr.contains("err_msg"));

        let _ = cleanup_workspace(&result.workspace_path);
    }

    #[test]
    fn exec_in_workspace_measures_duration() {
        let src = tempfile::tempdir().unwrap();

        let config = MaterializeConfig::default();

        let result = exec_in_workspace(src.path(), "true", &config).unwrap();

        assert_eq!(result.exit_code, 0);
        // Duration should be non-negative (it's u64, so always >= 0)
        assert!(result.duration_ms < 10_000);

        let _ = cleanup_workspace(&result.workspace_path);
    }

    #[test]
    fn exec_context_with_args() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.txt"), "aaa").unwrap();
        fs::write(src.path().join("b.txt"), "bbb").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let workspace = MaterializedWorkspace::create(
            src.path(),
            dst.path(),
            Some(MaterializeStrategy::Copy),
            None,
        )
        .unwrap();

        let ctx = ExecContext {
            workspace,
            command: "ls".to_string(),
            args: vec!["-1".to_string()],
        };

        let result = ctx.run().unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("a.txt"));
        assert!(result.stdout.contains("b.txt"));
    }

    #[test]
    fn exec_context_reports_strategy() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("x.txt"), "x").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let workspace = MaterializedWorkspace::create(
            src.path(),
            dst.path(),
            Some(MaterializeStrategy::Copy),
            None,
        )
        .unwrap();

        let ctx = ExecContext {
            workspace,
            command: "true".to_string(),
            args: Vec::new(),
        };

        let result = ctx.run().unwrap();
        assert_eq!(result.strategy_used, MaterializeStrategy::Copy);
    }

    #[test]
    fn cleanup_workspace_removes_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep(); // prevent auto-cleanup
        fs::write(path.join("file.txt"), "data").unwrap();

        assert!(path.exists());
        cleanup_workspace(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_nonexistent_is_ok() {
        let path = PathBuf::from("/tmp/kin-test-nonexistent-cleanup-path");
        assert!(!path.exists());
        cleanup_workspace(&path).unwrap(); // should not error
    }
}
