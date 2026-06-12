// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

/// `kin stash push` — Save the current overlay state to .kin/stashes/.
pub async fn push() -> Result<()> {
    let layout = discover_layout_from_cwd()?;
    push_with_layout(&layout)
}

/// `kin stash pop` — Restore the most recent stash entry.
pub async fn pop() -> Result<()> {
    let layout = discover_layout_from_cwd()?;
    pop_with_layout(&layout)
}

fn discover_layout_from_cwd() -> Result<kin_core::KinLayout> {
    kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))
}

fn push_with_layout(layout: &kin_core::KinLayout) -> Result<()> {
    let stash_dir = layout.stashes_dir();
    fs::create_dir_all(&stash_dir)?;

    let entries = list_stash_entries(&stash_dir)?;
    let index = entries.len();
    let stash_file = stash_dir.join(format!("stash-{}.json", index));

    let current_branch = kin_core::read_current_branch(layout)?;

    // Snapshot working directory files.
    let work_dir = layout.working_dir();
    let file_snapshots = collect_file_snapshots(work_dir)?;
    let file_count = file_snapshots.len();

    let snapshot = serde_json::json!({
        "index": index,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "current_branch": current_branch.to_string(),
        "file_snapshots": file_snapshots,
    });

    fs::write(&stash_file, serde_json::to_string_pretty(&snapshot)?)?;
    let cleared_count = remove_snapshot_files(work_dir, &file_snapshots)?;

    println!("Saved working state to stash@{{{}}}", index);
    println!("  {} file(s) snapshot", file_count);
    println!("  {} file(s) cleared from working directory", cleared_count);
    println!("  File: {}", stash_file.display());

    Ok(())
}

fn pop_with_layout(layout: &kin_core::KinLayout) -> Result<()> {
    let stash_dir = layout.stashes_dir();
    let entries = list_stash_entries(&stash_dir)?;

    if entries.is_empty() {
        println!("No stash entries found.");
        return Ok(());
    }

    let latest = &entries[entries.len() - 1];
    let content = fs::read_to_string(latest)?;
    let snapshot: serde_json::Value = serde_json::from_str(&content)?;

    let index = snapshot["index"].as_u64().unwrap_or(0);

    // Legacy stashes may contain a `branches` field; it is ignored — graph-native
    // branch snapshot/restore requires real daemon/graph wiring (out of scope here).

    // Restore current branch if stored.
    if let Some(branch_str) = snapshot["current_branch"].as_str() {
        kin_core::write_current_branch(layout, &kin_model::BranchName::new(branch_str))?;
    }

    let file_snapshots: BTreeMap<String, String> =
        serde_json::from_value(snapshot["file_snapshots"].clone()).unwrap_or_default();

    // Remove newly created files before restoring the stashed snapshot.
    let work_dir = layout.working_dir();
    let removed_count = remove_extra_snapshot_files(work_dir, &file_snapshots)?;
    let mut restored_count = 0usize;

    // Restore file snapshots into the working directory.
    for (rel_path, content) in &file_snapshots {
        let dest = work_dir.join(rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, content)?;
        restored_count += 1;
    }

    // Remove the stash file.
    fs::remove_file(latest)?;

    println!("Applied stash@{{{}}}", index);
    println!("  {} extra file(s) removed", removed_count);
    println!("  {} file(s) restored", restored_count);
    println!("Dropped stash@{{{}}}", index);

    Ok(())
}

/// `kin stash list` — Show all stash entries.
pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let stash_dir = layout.stashes_dir();
    let entries = list_stash_entries(&stash_dir)?;

    if entries.is_empty() {
        println!("No stash entries.");
        return Ok(());
    }

    for entry in &entries {
        let content = fs::read_to_string(entry)?;
        let snapshot: serde_json::Value = serde_json::from_str(&content)?;
        let index = snapshot["index"].as_u64().unwrap_or(0);
        let ts = snapshot["timestamp"].as_str().unwrap_or("unknown");
        let branch = snapshot["current_branch"].as_str().unwrap_or("unknown");
        let file_count = snapshot["file_snapshots"]
            .as_object()
            .map_or(0, |m| m.len());
        println!(
            "stash@{{{}}}: saved at {} (branch: {}, {} file(s))",
            index, ts, branch, file_count
        );
    }

    Ok(())
}

// -- Helpers --

/// File extensions we consider source files for snapshotting.
const SNAPSHOT_EXTENSIONS: &[&str] = &["rs", "ts", "js", "py", "go", "java", "tsx", "jsx"];

/// Recursively collect source files from `root`, returning a map of
/// relative-path -> file-content.  Skips hidden directories and `.kin/`.
fn collect_file_snapshots(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    collect_files_recursive(root, root, &mut out)?;
    Ok(out)
}

fn remove_snapshot_files(root: &Path, snapshots: &BTreeMap<String, String>) -> Result<usize> {
    let mut removed = 0usize;
    for rel_path in snapshots.keys() {
        let path = root.join(rel_path);
        if path.exists() {
            fs::remove_file(&path)?;
            removed += 1;
            prune_empty_parents(root, path.parent());
        }
    }
    Ok(removed)
}

fn remove_extra_snapshot_files(root: &Path, snapshots: &BTreeMap<String, String>) -> Result<usize> {
    let current = collect_file_snapshots(root)?;
    let mut removed = 0usize;

    for rel_path in current.keys() {
        if snapshots.contains_key(rel_path) {
            continue;
        }

        let path = root.join(rel_path);
        if path.exists() {
            fs::remove_file(&path)?;
            removed += 1;
            prune_empty_parents(root, path.parent());
        }
    }

    Ok(removed)
}

fn collect_files_recursive(
    base: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, String>,
) -> Result<()> {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };

    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Skip hidden dirs/files and .kin/.
        if name.starts_with('.') || name == ".kin" {
            continue;
        }

        if path.is_dir() {
            collect_files_recursive(base, &path, out)?;
        } else if path.is_file() {
            let ext_match = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| SNAPSHOT_EXTENSIONS.contains(&ext));
            if ext_match {
                if let Ok(content) = fs::read_to_string(&path) {
                    let rel = path
                        .strip_prefix(base)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .to_string();
                    out.insert(rel, content);
                }
            }
        }
    }
    Ok(())
}

fn prune_empty_parents(root: &Path, start: Option<&Path>) {
    let mut current = start;
    while let Some(dir) = current {
        if dir == root {
            break;
        }

        let is_empty = match fs::read_dir(dir) {
            Ok(mut entries) => entries.next().is_none(),
            Err(_) => false,
        };

        if is_empty {
            let parent = dir.parent();
            let _ = fs::remove_dir(dir);
            current = parent;
        } else {
            break;
        }
    }
}

fn list_stash_entries(stash_dir: &PathBuf) -> Result<Vec<PathBuf>> {
    if !stash_dir.exists() {
        return Ok(vec![]);
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(stash_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "json")
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("stash-"))
        })
        .collect();

    entries.sort();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn push_clears_snapshotted_files() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn kept() {}\n").unwrap();

        push_with_layout(&layout).unwrap();

        assert!(!dir.path().join("src/lib.rs").exists());
        assert!(dir.path().join(".kin/stashes/stash-0.json").exists());
    }

    #[tokio::test]
    async fn pop_restores_stashed_files_and_removes_newer_files() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn original() {}\n").unwrap();

        push_with_layout(&layout).unwrap();

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/extra.rs"), "pub fn extra() {}\n").unwrap();
        pop_with_layout(&layout).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("src/lib.rs")).unwrap(),
            "pub fn original() {}\n"
        );
        assert!(!dir.path().join("src/extra.rs").exists());
        assert!(!dir.path().join(".kin/stashes/stash-0.json").exists());
    }

    #[tokio::test]
    async fn push_stash_has_no_branches_field() {
        // Locks removal of the dead InMemoryGraph branch ops: new stashes must not
        // contain a `branches` field (the throwaway graph was a silent no-op).
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "fn foo() {}\n").unwrap();

        push_with_layout(&layout).unwrap();

        let stash = layout.stashes_dir().join("stash-0.json");
        let val: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(stash).unwrap()).unwrap();
        assert!(
            val.get("branches").is_none(),
            "stash must not include `branches` (dead field removed)"
        );
    }

    #[tokio::test]
    async fn pop_ignores_branches_field_in_legacy_stash() {
        // Legacy stashes may have a `branches` array; pop must silently ignore it
        // and still restore file snapshots correctly.
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let stash_dir = layout.stashes_dir();
        std::fs::create_dir_all(&stash_dir).unwrap();
        let legacy = serde_json::json!({
            "index": 0,
            "timestamp": "2026-01-01T00:00:00Z",
            "current_branch": "main",
            "branches": [{"name": "main", "head": "aa".repeat(32)}],
            "file_snapshots": {"src/lib.rs": "fn original() {}\n"}
        });
        std::fs::write(
            stash_dir.join("stash-0.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        pop_with_layout(&layout).unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("src/lib.rs")).unwrap(),
            "fn original() {}\n",
            "legacy stash with branches field must still restore file snapshots"
        );
    }
}
