// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

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
    /// Number of commits (approximate for large repos).
    pub commit_count: usize,
    /// List of branch names.
    pub branches: Vec<String>,
    /// List of source files that can be indexed (by extension).
    pub source_files: Vec<PathBuf>,
}

/// Supported source file extensions for entity extraction.
const SOURCE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "py", "go", "java", "rs", "c", "h", "cpp", "hpp", "cc", "cxx", "cs",
    "rb",
];

/// Scan a Git repository to gather metadata for migration planning.
///
/// This is a lightweight operation that checks the repo structure
/// and counts commits/branches without reading full history.
pub fn scan_repo(repo_path: &Path) -> Result<RepoScan> {
    if !repo_path.exists() {
        return Err(MigrateError::SourceNotFound(
            repo_path.display().to_string(),
        ));
    }

    let git_dir = repo_path.join(".git");
    if !git_dir.exists() {
        return Err(MigrateError::NotAGitRepo(repo_path.display().to_string()));
    }

    // Scan for source files (non-recursive into .git or .kin).
    let source_files = find_source_files(repo_path)?;

    info!(
        path = %repo_path.display(),
        source_files = source_files.len(),
        "scanned repository"
    );

    Ok(RepoScan {
        root: repo_path.to_path_buf(),
        default_branch: detect_default_branch(repo_path),
        commit_count: 0, // Filled by deeper scan if needed.
        branches: vec![],
        source_files,
    })
}

/// Walk the directory tree to find source files by extension.
fn find_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    walk_dir(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_dir(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|e| MigrateError::io(dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| MigrateError::io(dir, e))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Skip hidden directories and common non-source dirs.
        if name.starts_with('.')
            || name == "node_modules"
            || name == "target"
            || name == "__pycache__"
            || name == "vendor"
            || name == "build"
        {
            continue;
        }

        if path.is_dir() {
            walk_dir(root, &path, files)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if SOURCE_EXTENSIONS.contains(&ext) {
                // Store relative path.
                if let Ok(rel) = path.strip_prefix(root) {
                    files.push(rel.to_path_buf());
                }
            }
        }
    }

    Ok(())
}

/// Detect the default branch name from HEAD reference.
fn detect_default_branch(repo_path: &Path) -> Option<String> {
    let head_path = repo_path.join(".git/HEAD");
    let content = std::fs::read_to_string(head_path).ok()?;
    let trimmed = content.trim();
    // HEAD format: "ref: refs/heads/main"
    trimmed
        .strip_prefix("ref: refs/heads/")
        .map(|rest| rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        dir
    }

    #[test]
    fn scan_valid_repo() {
        let dir = make_git_repo();
        // Add a source file.
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Hello").unwrap();

        let scan = scan_repo(dir.path()).unwrap();
        assert_eq!(scan.root, dir.path());
        assert_eq!(scan.default_branch, Some("main".to_string()));
        assert_eq!(scan.source_files.len(), 1); // Only .rs, not .md
        assert_eq!(scan.source_files[0], PathBuf::from("main.rs"));
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
    fn scan_skips_hidden_dirs() {
        let dir = make_git_repo();
        let hidden = dir.path().join(".hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::write(hidden.join("secret.rs"), "fn secret() {}").unwrap();
        std::fs::write(dir.path().join("visible.rs"), "fn visible() {}").unwrap();

        let scan = scan_repo(dir.path()).unwrap();
        assert_eq!(scan.source_files.len(), 1);
        assert_eq!(scan.source_files[0], PathBuf::from("visible.rs"));
    }

    #[test]
    fn scan_walks_subdirectories() {
        let dir = make_git_repo();
        let sub = dir.path().join("src");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("lib.rs"), "pub mod foo;").unwrap();
        std::fs::write(dir.path().join("main.py"), "print('hello')").unwrap();

        let scan = scan_repo(dir.path()).unwrap();
        assert_eq!(scan.source_files.len(), 2);
    }

    #[test]
    fn detect_default_branch_name() {
        let dir = make_git_repo();
        let branch = detect_default_branch(dir.path());
        assert_eq!(branch, Some("main".to_string()));
    }

    #[test]
    fn repo_scan_serializes() {
        let scan = RepoScan {
            root: PathBuf::from("/project"),
            default_branch: Some("main".into()),
            commit_count: 42,
            branches: vec!["main".into(), "feature".into()],
            source_files: vec![PathBuf::from("src/lib.rs")],
        };
        let json = serde_json::to_string(&scan).unwrap();
        let parsed: RepoScan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.commit_count, 42);
    }
}
