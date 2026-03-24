// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{bail, Result};
use dialoguer::Confirm;
use kin_core::KinLayout;
use std::fs;
use std::path::Path;

/// Restore the project to its pre-Kin state using the snapshot taken during `kin init`.
pub async fn run(force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let layout = KinLayout::discover(&cwd)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository"))?;

    let snapshot_dir = layout.root().join("snapshot");
    if !snapshot_dir.exists() {
        bail!("No snapshot found. Cannot eject.");
    }

    let manifest_path = snapshot_dir.join("manifest.json");
    let manifest: serde_json::Value = if manifest_path.exists() {
        serde_json::from_str(&fs::read_to_string(&manifest_path)?)?
    } else {
        bail!("Snapshot manifest missing. Cannot verify restore.");
    };

    let file_count = manifest["file_count"].as_u64().unwrap_or(0);

    // Confirm with the user unless --force.
    if !force {
        println!("This will:");
        println!("  - Stop kin-daemon and kin-vfs-daemon");
        println!("  - Restore {} files from snapshot", file_count);
        println!("  - Remove the .kin/ directory entirely");
        println!();

        let confirmed = Confirm::new()
            .with_prompt("Continue?")
            .default(false)
            .interact()?;

        if !confirmed {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Best-effort daemon shutdown.
    stop_daemons(layout.root());

    // Restore files from snapshot to the project root.
    let working_dir = layout.working_dir().to_path_buf();
    let mut restored: u64 = 0;
    restore_files(&snapshot_dir, &snapshot_dir, &working_dir, &mut restored)?;

    // Remove .kin/ entirely.
    let kin_dir = layout.root().to_path_buf();
    fs::remove_dir_all(&kin_dir)?;

    println!(
        "Kin removed. Your files are restored to pre-init state ({} files).",
        restored
    );
    Ok(())
}

/// Walk the snapshot directory and copy each file back to the project root.
fn restore_files(
    snapshot_root: &Path,
    current: &Path,
    working_dir: &Path,
    restored: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();

        // Skip the manifest itself — it's metadata, not a user file.
        if path.file_name().map(|f| f == "manifest.json").unwrap_or(false)
            && path.parent() == Some(snapshot_root)
        {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            restore_files(snapshot_root, &path, working_dir, restored)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(snapshot_root)?;
            let dest = working_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&path, &dest)?;
            *restored += 1;
        }
    }
    Ok(())
}

/// Best-effort attempt to stop running Kin daemons.
fn stop_daemons(kin_root: &Path) {
    // Try PID file for kin-daemon.
    kill_pid_file(&kin_root.join("daemon.pid"));
    // Try PID file for kin-vfs-daemon.
    kill_pid_file(&kin_root.join("vfs.pid"));
}

fn kill_pid_file(path: &Path) {
    if let Ok(content) = fs::read_to_string(path) {
        if let Ok(pid) = content.trim().parse::<u32>() {
            // SIGTERM via `kill` command — best effort, ignore errors.
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .output();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: set up a fake Kin repo with a snapshot.
    fn setup_fake_repo(dir: &Path) {
        let kin = dir.join(".kin");
        let snapshot = kin.join("snapshot");
        fs::create_dir_all(&snapshot).unwrap();
        fs::create_dir_all(snapshot.join("src")).unwrap();

        // Snapshot files.
        fs::write(snapshot.join("README.md"), "hello").unwrap();
        fs::write(snapshot.join("src/main.rs"), "fn main() {}").unwrap();

        // Manifest.
        let manifest = serde_json::json!({
            "timestamp": "2026-03-23T00:00:00Z",
            "file_count": 2,
            "total_bytes": 17,
            "git_head": null,
        });
        fs::write(
            snapshot.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // Some Kin-internal files that should be removed on eject.
        fs::write(kin.join("config.toml"), "[core]").unwrap();
    }

    #[test]
    fn eject_restores_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        setup_fake_repo(root);

        let snapshot_dir = root.join(".kin/snapshot");
        let working_dir = root.to_path_buf();
        let mut restored = 0u64;
        restore_files(&snapshot_dir, &snapshot_dir, &working_dir, &mut restored).unwrap();

        assert_eq!(restored, 2);
        assert_eq!(fs::read_to_string(root.join("README.md")).unwrap(), "hello");
        assert_eq!(
            fs::read_to_string(root.join("src/main.rs")).unwrap(),
            "fn main() {}"
        );
    }

    #[test]
    fn eject_removes_kin_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        setup_fake_repo(root);

        // Restore files first.
        let snapshot_dir = root.join(".kin/snapshot");
        let working_dir = root.to_path_buf();
        let mut restored = 0u64;
        restore_files(&snapshot_dir, &snapshot_dir, &working_dir, &mut restored).unwrap();

        // Then remove .kin/.
        fs::remove_dir_all(root.join(".kin")).unwrap();

        assert!(!root.join(".kin").exists());
        // But restored files should still be there.
        assert!(root.join("README.md").exists());
        assert!(root.join("src/main.rs").exists());
    }

    #[test]
    fn eject_manifest_skip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        setup_fake_repo(root);

        let snapshot_dir = root.join(".kin/snapshot");
        let working_dir = root.to_path_buf();
        let mut restored = 0u64;
        restore_files(&snapshot_dir, &snapshot_dir, &working_dir, &mut restored).unwrap();

        // manifest.json should NOT be restored to the project root.
        assert!(!root.join("manifest.json").exists());
    }
}
