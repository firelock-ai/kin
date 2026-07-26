// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{MigrateError, Result};

/// Metadata about a scanned Git repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoScan {
    /// Path to the repository root.
    pub root: PathBuf,
    /// Default branch name (e.g., "main", "master").
    pub default_branch: Option<String>,
}

/// Scan a Git repository to gather metadata for migration planning.
///
/// This phase deliberately does not walk the working tree. Repository
/// membership comes from the imported Git tree; scanning only identifies the
/// repository root and selected branch.
pub fn scan_repo(repo_path: &Path) -> Result<RepoScan> {
    if !repo_path.exists() {
        return Err(MigrateError::SourceNotFound(
            repo_path.display().to_string(),
        ));
    }

    let root = repo_path
        .canonicalize()
        .map_err(|error| MigrateError::io(repo_path, error))?;
    let git_probe = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "--git-dir"])
        .output()
        .map_err(|error| MigrateError::io(&root, error))?;
    if !git_probe.status.success() {
        return Err(MigrateError::NotAGitRepo(repo_path.display().to_string()));
    }

    info!(
        path = %root.display(),
        "scanned repository"
    );

    Ok(RepoScan {
        default_branch: detect_default_branch(&root),
        root,
    })
}

/// Detect the checked-out branch without interpreting `.git` internals. This
/// also works for linked worktrees where `.git` is a file.
fn detect_default_branch(repo_path: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_git_repo() -> Option<tempfile::TempDir> {
        let dir = tempfile::tempdir().unwrap();
        let output = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(dir.path())
            .output()
            .ok()?;
        output.status.success().then_some(dir)
    }

    #[test]
    fn scan_valid_repo() {
        let Some(dir) = make_git_repo() else {
            return;
        };
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Hello").unwrap();

        let scan = scan_repo(dir.path()).unwrap();
        assert_eq!(scan.root, dir.path().canonicalize().unwrap());
        assert_eq!(scan.default_branch, Some("main".to_string()));
    }

    #[test]
    fn scan_missing_dir_fails() {
        let err = scan_repo(Path::new("/nonexistent/repo")).unwrap_err();
        assert!(matches!(err, MigrateError::SourceNotFound(_)));
    }

    #[test]
    fn scan_non_git_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let err = scan_repo(dir.path()).unwrap_err();
        assert!(matches!(err, MigrateError::NotAGitRepo(_)));
    }

    #[test]
    fn scan_does_not_derive_membership_from_worktree_files() {
        let Some(dir) = make_git_repo() else {
            return;
        };
        std::fs::write(dir.path().join("untracked.rs"), "fn untracked() {}").unwrap();
        let scan = scan_repo(dir.path()).unwrap();
        assert_eq!(scan.root, dir.path().canonicalize().unwrap());
    }

    #[test]
    fn detect_default_branch_name() {
        let Some(dir) = make_git_repo() else {
            return;
        };
        let branch = detect_default_branch(dir.path());
        assert_eq!(branch, Some("main".to_string()));
    }

    #[test]
    fn repo_scan_serializes() {
        let scan = RepoScan {
            root: PathBuf::from("/project"),
            default_branch: Some("main".into()),
        };
        let json = serde_json::to_string(&scan).unwrap();
        let parsed: RepoScan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.default_branch.as_deref(), Some("main"));
    }
}
