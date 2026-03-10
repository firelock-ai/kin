use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

/// `kin stash push` — Save the current overlay state to .kin/stashes/.
pub async fn push() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let stash_dir = layout.stashes_dir();
    fs::create_dir_all(&stash_dir)?;

    let entries = list_stash_entries(&stash_dir)?;
    let index = entries.len();
    let stash_file = stash_dir.join(format!("stash-{}.json", index));

    // Serialize the current working copy overlay from the graph.
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;
    let current_branch = kin_core::read_current_branch(&layout)?;

    // Capture a snapshot: branch heads + current branch + timestamp + file snapshots.
    use kin_model::GraphStore;
    let branches = graph.list_branches()?;

    // Snapshot working directory files.
    let work_dir = layout.working_dir();
    let file_snapshots = collect_file_snapshots(work_dir)?;
    let file_count = file_snapshots.len();

    let snapshot = serde_json::json!({
        "index": index,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "current_branch": current_branch.to_string(),
        "branches": branches.iter().map(|b| {
            serde_json::json!({
                "name": b.name.to_string(),
                "head": b.head.to_string(),
            })
        }).collect::<Vec<_>>(),
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

/// `kin stash pop` — Restore the most recent stash entry.
pub async fn pop() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

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

    // Restore branch heads from the stash.
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    if let Some(branches) = snapshot["branches"].as_array() {
        use kin_model::GraphStore;
        for branch_val in branches {
            if let (Some(name), Some(head_str)) =
                (branch_val["name"].as_str(), branch_val["head"].as_str())
            {
                if let Ok(bytes) = hex::decode(head_str) {
                    if bytes.len() == 32 {
                        let hash = kin_model::Hash256::from_bytes(bytes.try_into().unwrap());
                        let branch_name = kin_model::BranchName::new(name);
                        let change_id = kin_model::SemanticChangeId(hash);
                        let _ = graph.update_branch_head(&branch_name, &change_id);
                    }
                }
            }
        }
    }

    // Restore current branch if stored.
    if let Some(branch_str) = snapshot["current_branch"].as_str() {
        kin_core::write_current_branch(&layout, &kin_model::BranchName::new(branch_str))?;
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
const SNAPSHOT_EXTENSIONS: &[&str] = &[
    "rs", "ts", "js", "py", "go", "java", "tsx", "jsx",
];

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
                .map_or(false, |ext| SNAPSHOT_EXTENSIONS.contains(&ext));
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
            p.extension().map_or(false, |ext| ext == "json")
                && p.file_name()
                    .map_or(false, |n| n.to_string_lossy().starts_with("stash-"))
        })
        .collect();

    entries.sort();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn current_dir_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct CurrentDirGuard {
        original: PathBuf,
    }

    impl CurrentDirGuard {
        fn enter(path: &Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { original }
        }
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    #[tokio::test]
    async fn push_clears_snapshotted_files() {
        let _cwd_guard = current_dir_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn kept() {}\n").unwrap();
        let _current_dir = CurrentDirGuard::enter(dir.path());

        push().await.unwrap();

        assert!(!dir.path().join("src/lib.rs").exists());
        assert!(dir.path().join(".kin/stashes/stash-0.json").exists());
    }

    #[tokio::test]
    async fn pop_restores_stashed_files_and_removes_newer_files() {
        let _cwd_guard = current_dir_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn original() {}\n").unwrap();
        let _current_dir = CurrentDirGuard::enter(dir.path());

        push().await.unwrap();

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/extra.rs"), "pub fn extra() {}\n").unwrap();
        pop().await.unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("src/lib.rs")).unwrap(),
            "pub fn original() {}\n"
        );
        assert!(!dir.path().join("src/extra.rs").exists());
        assert!(!dir.path().join(".kin/stashes/stash-0.json").exists());
    }
}
