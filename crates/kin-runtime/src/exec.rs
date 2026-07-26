// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use tracing::info;

use crate::error::{Result, RuntimeError};
use crate::workspace::{MaterializeStrategy, MaterializedWorkspace};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::MaterializationSourceKind;
    use std::fs;

    fn exact_workspace(root: PathBuf) -> MaterializedWorkspace {
        MaterializedWorkspace::from_existing(
            root,
            MaterializeStrategy::Copy,
            MaterializationSourceKind::ExactTree,
        )
    }

    #[test]
    fn exec_context_with_args() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a.txt"), "aaa").unwrap();
        fs::write(src.path().join("b.txt"), "bbb").unwrap();

        let dst = tempfile::tempdir().unwrap();
        fs::copy(src.path().join("a.txt"), dst.path().join("a.txt")).unwrap();
        fs::copy(src.path().join("b.txt"), dst.path().join("b.txt")).unwrap();
        let workspace = exact_workspace(dst.path().to_path_buf());

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
        fs::copy(src.path().join("x.txt"), dst.path().join("x.txt")).unwrap();
        let workspace = exact_workspace(dst.path().to_path_buf());

        let ctx = ExecContext {
            workspace,
            command: "true".to_string(),
            args: Vec::new(),
        };

        let result = ctx.run().unwrap();
        assert_eq!(result.strategy_used, MaterializeStrategy::Copy);
    }
}
