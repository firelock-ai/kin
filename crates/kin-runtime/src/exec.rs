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
        self.workspace
            .revalidate()
            .map_err(|error| RuntimeError::Other(format!("revalidate exact workspace: {error}")))?;
        let full_command = if self.args.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.args.join(" "))
        };

        info!(
            command = %full_command,
            workspace = %self.workspace.root().display(),
            "executing in materialized workspace"
        );

        let start = Instant::now();

        let output = if cfg!(target_os = "windows") {
            Command::new("cmd")
                .args(["/C", &full_command])
                .current_dir(self.workspace.root())
                .output()
        } else {
            Command::new("sh")
                .args(["-c", &full_command])
                .current_dir(self.workspace.root())
                .output()
        }
        .map_err(|e| RuntimeError::CommandFailed(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms,
            workspace_path: self.workspace.root().to_path_buf(),
            strategy_used: self.workspace.strategy(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_workspace(files: &[(&str, &[u8])]) -> (tempfile::TempDir, MaterializedWorkspace) {
        let repository = tempfile::tempdir().unwrap();
        kin_core::init(repository.path()).unwrap();
        let paths = files
            .iter()
            .map(|(path, _)| kin_model::RepoPath::from_utf8((*path).to_string()).unwrap())
            .collect::<Vec<_>>();
        let entries = paths
            .iter()
            .zip(files.iter())
            .map(|(path, (_, body))| {
                (
                    path,
                    kin_model::TreeEntry::blob(
                        kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(body)),
                        false,
                    ),
                    *body,
                )
            })
            .collect::<Vec<_>>();
        let freeze = kin_core::ExactProjectionFreeze::acquire_existing(repository.path()).unwrap();
        let (projection, _) = freeze
            .materialize_session_source_tree(
                "session-runtime-exec",
                br#"{"schema":1}"#,
                entries
                    .iter()
                    .map(|(path, entry, body)| (*path, *entry, *body)),
            )
            .unwrap();
        (
            repository,
            MaterializedWorkspace::from_exact_session(projection, MaterializeStrategy::Copy),
        )
    }

    #[test]
    fn exec_context_with_args() {
        let (_repository, workspace) = exact_workspace(&[("a.txt", b"aaa"), ("b.txt", b"bbb")]);

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
        let (_repository, workspace) = exact_workspace(&[("x.txt", b"x")]);

        let ctx = ExecContext {
            workspace,
            command: "true".to_string(),
            args: Vec::new(),
        };

        let result = ctx.run().unwrap();
        assert_eq!(result.strategy_used, MaterializeStrategy::Copy);
    }
}
