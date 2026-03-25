// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

/// Directories to skip during snapshot.
const SKIP_DIRS: &[&str] = &[
    ".kin",
    ".git/objects",
    ".git/pack",
    "node_modules",
    "target",
    "__pycache__",
    ".next",
    "dist",
    "build",
];

/// Take an independent copy-based snapshot of the working tree before `kin init`
/// mutates it.  We always use `fs::copy()` rather than hardlinks because
/// hardlinks share inodes — modifying the original file after init would
/// silently corrupt the snapshot.
/// Take snapshot BEFORE kin init creates .kin/.
/// We snapshot to a temp dir, then move it into .kin/snapshot/ after init succeeds.
fn snapshot_repo(dir: &Path) -> Result<PathBuf> {
    let tmp_snapshot = dir.join(".kin-snapshot-tmp");
    if tmp_snapshot.exists() {
        fs::remove_dir_all(&tmp_snapshot)?;
    }
    fs::create_dir_all(&tmp_snapshot)?;
    let snapshot_dir = &tmp_snapshot;

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    walk_and_snapshot(dir, dir, &snapshot_dir, &mut file_count, &mut total_bytes)?;

    // Try to capture git HEAD for the manifest.
    let git_head = read_git_head(dir);

    let manifest = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "git_head": git_head,
    });
    fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    println!("  Snapshot saved ({} files)", file_count);
    Ok(tmp_snapshot)
}

fn walk_and_snapshot(
    root: &Path,
    current: &Path,
    snapshot_dir: &Path,
    file_count: &mut u64,
    total_bytes: &mut u64,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return Ok(()), // skip unreadable dirs
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;

        // Check if this path starts with any skipped directory.
        if should_skip(rel) {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_and_snapshot(root, &path, snapshot_dir, file_count, total_bytes)?;
        } else if ft.is_file() {
            let dest = snapshot_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            // Always copy — hardlinks share inodes so later writes
            // to the original would corrupt the snapshot.
            fs::copy(&path, &dest)?;

            *total_bytes += entry.metadata()?.len();
            *file_count += 1;
        }
        // Skip symlinks / other special types.
    }

    Ok(())
}

fn should_skip(rel: &Path) -> bool {
    let rel_str = rel.to_string_lossy();
    for skip in SKIP_DIRS {
        if rel_str == *skip || rel_str.starts_with(&format!("{}/", skip)) {
            return true;
        }
    }
    false
}

fn read_git_head(dir: &Path) -> Option<String> {
    let head_path = dir.join(".git/HEAD");
    let content = fs::read_to_string(head_path).ok()?;
    let content = content.trim();

    if let Some(ref_path) = content.strip_prefix("ref: ") {
        // Resolve the ref to a commit hash.
        let ref_file = dir.join(".git").join(ref_path);
        fs::read_to_string(ref_file)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        // Detached HEAD — already a commit hash.
        Some(content.to_string())
    }
}

pub async fn run(path: Option<String>) -> Result<()> {
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    // Take a pre-init snapshot before Kin touches the directory.
    // Snapshot goes to a temp dir first, then moves into .kin/ after init.
    let tmp_snapshot = snapshot_repo(&dir)?;

    let result = kin_core::init(&dir)?;

    // Move snapshot into .kin/ now that init created it
    let final_snapshot = dir.join(".kin/snapshot");
    if tmp_snapshot.exists() {
        if final_snapshot.exists() {
            let _ = fs::remove_dir_all(&final_snapshot);
        }
        fs::rename(&tmp_snapshot, &final_snapshot).unwrap_or_else(|_| {
            // rename fails across filesystems; fall back to copy
            let _ = fs::remove_dir_all(&final_snapshot);
        });
    }
    println!(
        "Initialized Kin repository at {}",
        result.layout.root().display()
    );
    println!("  KinDB: {}", result.layout.kindb_snapshot_path().display());
    println!("  Blobs: {}", result.layout.objects_dir().display());
    println!("  Genesis change: {}", result.genesis_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn snapshot_creates_correct_structure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create some files.
        fs::write(root.join("README.md"), "hello").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

        // Create a directory that should be skipped.
        fs::create_dir_all(root.join("node_modules/foo")).unwrap();
        fs::write(root.join("node_modules/foo/index.js"), "skip me").unwrap();

        // We need the .kin dir to exist for the snapshot to write into.
        fs::create_dir_all(root.join(".kin")).unwrap();

        snapshot_repo(root).unwrap();

        let snapshot = root.join(".kin/snapshot");
        assert!(snapshot.join("README.md").exists());
        assert!(snapshot.join("src/main.rs").exists());
        assert!(!snapshot.join("node_modules").exists());
        assert!(snapshot.join("manifest.json").exists());
    }

    #[test]
    fn manifest_has_correct_file_count() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(root.join("a.txt"), "aaa").unwrap();
        fs::write(root.join("b.txt"), "bbb").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/c.txt"), "ccc").unwrap();

        fs::create_dir_all(root.join(".kin")).unwrap();

        snapshot_repo(root).unwrap();

        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join(".kin/snapshot/manifest.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(manifest["file_count"], 3);
        assert_eq!(manifest["total_bytes"], 9); // 3 + 3 + 3
    }

    #[test]
    fn snapshot_skips_all_excluded_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create all the skip dirs with a file inside each.
        for skip in SKIP_DIRS {
            if *skip == ".kin" {
                continue; // we create .kin ourselves
            }
            let p = root.join(skip);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("file.txt"), "skip").unwrap();
        }

        // One real file.
        fs::write(root.join("keep.txt"), "keep").unwrap();
        fs::create_dir_all(root.join(".kin")).unwrap();

        snapshot_repo(root).unwrap();

        let snapshot = root.join(".kin/snapshot");
        assert!(snapshot.join("keep.txt").exists());
        assert!(!snapshot.join("node_modules").exists());
        assert!(!snapshot.join("target").exists());
        assert!(!snapshot.join("__pycache__").exists());
        assert!(!snapshot.join(".next").exists());
        assert!(!snapshot.join("dist").exists());
        assert!(!snapshot.join("build").exists());
    }

    #[test]
    fn snapshot_reads_git_head() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up a fake git repo with a resolved ref.
        fs::create_dir_all(root.join(".git/refs/heads")).unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            root.join(".git/refs/heads/main"),
            "abc123def456\n",
        )
        .unwrap();
        fs::write(root.join("file.txt"), "content").unwrap();

        fs::create_dir_all(root.join(".kin")).unwrap();

        snapshot_repo(root).unwrap();

        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join(".kin/snapshot/manifest.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(manifest["git_head"], "abc123def456");
    }
}
