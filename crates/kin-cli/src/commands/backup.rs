// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Schema token stamped on every `kin backup list --json` answer.
pub const BACKUP_LIST_SCHEMA: &str = "kin.backup.list.v1";

/// `kin backup create` — Create a timestamped backup of the graph snapshot.
pub async fn create(tag: Option<String>) -> Result<()> {
    let layout = discover_layout()?;
    let snapshot_path = layout.kindb_snapshot_path();

    if !snapshot_path.exists() {
        anyhow::bail!("no graph snapshot found at {}", snapshot_path.display());
    }

    let backups_dir = layout.backups_dir();
    fs::create_dir_all(&backups_dir).with_context(|| {
        format!(
            "failed to create backups directory {}",
            backups_dir.display()
        )
    })?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let backup_name = match &tag {
        Some(t) => format!("graph-{}-{}.kndb", timestamp, sanitize_tag(t)),
        None => format!("graph-{}.kndb", timestamp),
    };
    let backup_path = backups_dir.join(&backup_name);

    let data = fs::read(&snapshot_path)
        .with_context(|| format!("failed to read snapshot {}", snapshot_path.display()))?;

    let checksum = Sha256::digest(&data);
    let size = data.len();

    fs::write(&backup_path, &data)
        .with_context(|| format!("failed to write backup {}", backup_path.display()))?;

    println!("Backup created: {}", backup_name);
    println!("  Size: {} bytes", size);
    println!("  SHA-256: {}", hex::encode(checksum));
    println!("  Path: {}", backup_path.display());

    Ok(())
}

/// One backup on disk, as both the table and the JSON surface describe it.
#[derive(Debug, Serialize)]
pub struct BackupEntry {
    /// Backup filename, the token `kin backup restore` matches against.
    pub name: String,
    /// Absolute path to the backup file.
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct BackupListJson {
    pub schema: &'static str,
    pub count: usize,
    pub backups: Vec<BackupEntry>,
}

/// The backups directory's contents, projected for display.
///
/// Reads the same `list_backup_entries` walk the text path has always used, so
/// the two surfaces cannot report different sets.
fn collect_backups(backups_dir: &PathBuf) -> Result<Vec<BackupEntry>> {
    let mut backups = Vec::new();
    for path in list_backup_entries(backups_dir)? {
        let meta = fs::metadata(&path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?;
        backups.push(BackupEntry {
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            path: path.display().to_string(),
            size_bytes: meta.len(),
        });
    }
    Ok(backups)
}

/// `kin backup list` — List available backups.
pub async fn list(json: bool) -> Result<()> {
    let layout = discover_layout()?;
    let backups_dir = layout.backups_dir();

    let backups = collect_backups(&backups_dir)?;

    // An empty set is an ANSWER, not an absence, so `--json` emits the same
    // stamped envelope with a zero count rather than the prose the table shows.
    // A caller parsing this must never have to distinguish "no backups" from
    // "not JSON".
    if json {
        let payload = BackupListJson {
            schema: BACKUP_LIST_SCHEMA,
            count: backups.len(),
            backups,
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    if backups.is_empty() {
        println!("No backups found.");
        return Ok(());
    }

    println!("{} backup(s):", backups.len());
    for entry in &backups {
        println!("  {} ({} bytes)", entry.name, entry.size_bytes);
    }

    Ok(())
}

/// `kin backup restore` — Restore a graph snapshot from a backup.
pub async fn restore(name: Option<String>, latest: bool) -> Result<()> {
    let layout = discover_layout()?;
    require_explicit_offline_restore(&layout)?;
    let backups_dir = layout.backups_dir();
    let snapshot_path = layout.kindb_snapshot_path();

    let entries = list_backup_entries(&backups_dir)?;

    if entries.is_empty() {
        anyhow::bail!("no backups found in {}", backups_dir.display());
    }

    let backup_path = if latest {
        // Entries are sorted ascending by name (timestamp-based), so last is most recent.
        entries.last().unwrap().clone()
    } else if let Some(ref name) = name {
        // Allow specifying a partial or full backup filename.
        let matched: Vec<_> = entries
            .iter()
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().contains(name.as_str()))
                    .unwrap_or(false)
            })
            .collect();

        match matched.len() {
            0 => anyhow::bail!("no backup matching '{}'", name),
            1 => matched[0].clone(),
            _ => {
                println!("Multiple backups match '{}':", name);
                for m in &matched {
                    println!("  {}", m.file_name().unwrap_or_default().to_string_lossy());
                }
                anyhow::bail!("specify a more precise name to disambiguate");
            }
        }
    } else {
        anyhow::bail!("specify --latest or provide a backup name");
    };

    let backup_name = backup_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Validate the backup file before restoring.
    let data = fs::read(&backup_path)
        .with_context(|| format!("failed to read backup {}", backup_path.display()))?;

    kin_db::GraphSnapshot::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("backup is corrupt or invalid: {e}"))?;

    // Back up the current snapshot before overwriting (safety net).
    if snapshot_path.exists() {
        let safety_name = format!(
            "graph-pre-restore-{}.kndb",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        let safety_path = backups_dir.join(&safety_name);
        fs::copy(&snapshot_path, &safety_path).with_context(|| {
            format!(
                "failed to safety-copy current snapshot to {}",
                safety_path.display()
            )
        })?;
        println!("Current snapshot saved as: {}", safety_name);
    }

    // Atomic restore: write to tmp, fsync, rename.
    let tmp_path = snapshot_path.with_extension("kndb.restore-tmp");
    {
        use std::io::Write;
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("failed to create tmp file {}", tmp_path.display()))?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp_path, &snapshot_path).with_context(|| {
        format!(
            "failed to rename {} → {}",
            tmp_path.display(),
            snapshot_path.display()
        )
    })?;

    println!("Restored from: {}", backup_name);
    println!("  Size: {} bytes", data.len());

    Ok(())
}

/// `kin backup delete` — Delete a specific backup.
pub async fn delete(name: String) -> Result<()> {
    let layout = discover_layout()?;
    let backups_dir = layout.backups_dir();

    let entries = list_backup_entries(&backups_dir)?;
    let matched: Vec<_> = entries
        .iter()
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(name.as_str()))
                .unwrap_or(false)
        })
        .collect();

    match matched.len() {
        0 => anyhow::bail!("no backup matching '{}'", name),
        1 => {
            let path = matched[0];
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            fs::remove_file(path)
                .with_context(|| format!("failed to delete {}", path.display()))?;
            println!("Deleted backup: {}", file_name);
        }
        _ => {
            println!("Multiple backups match '{}':", name);
            for m in &matched {
                println!("  {}", m.file_name().unwrap_or_default().to_string_lossy());
            }
            anyhow::bail!("specify a more precise name to disambiguate");
        }
    }

    Ok(())
}

// -- Helpers --

fn discover_layout() -> Result<kin_core::KinLayout> {
    crate::commands::require_repository_layout()
}

fn require_explicit_offline_restore(layout: &kin_core::KinLayout) -> Result<()> {
    if let Some(url) = crate::daemon_client::resolve_daemon_url_if_running(layout) {
        anyhow::bail!(
            "refusing to restore a graph snapshot while the Kin daemon is running at {url}; \
             stop the daemon first so restore cannot race daemon-owned graph state"
        );
    }

    let allowed = std::env::var("KIN_ALLOW_OFFLINE_RESTORE")
        .ok()
        .map(|value| offline_restore_env_allowed(&value))
        .unwrap_or(false);
    if !allowed {
        anyhow::bail!(
            "offline backup restore is an emergency repair path; set \
             KIN_ALLOW_OFFLINE_RESTORE=1 after confirming no Kin daemon is running"
        );
    }

    Ok(())
}

fn offline_restore_env_allowed(value: &str) -> bool {
    matches!(value, "1" | "true" | "TRUE" | "yes" | "YES")
}

fn list_backup_entries(backups_dir: &PathBuf) -> Result<Vec<PathBuf>> {
    if !backups_dir.exists() {
        return Ok(vec![]);
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(backups_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "kndb")
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("graph-"))
        })
        .collect();

    entries.sort();
    Ok(entries)
}

/// Sanitize a user-provided tag for use in filenames.
fn sanitize_tag(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_list_backup() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        // Create a valid snapshot file.
        let snapshot = kin_db::GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        fs::create_dir_all(layout.kindb_dir()).unwrap();
        fs::write(layout.kindb_snapshot_path(), &bytes).unwrap();

        // Run backup create (uses cwd, so we need to change the discover).
        let backups_dir = layout.backups_dir();
        fs::create_dir_all(&backups_dir).unwrap();

        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let backup_name = format!("graph-{}.kndb", timestamp);
        let backup_path = backups_dir.join(&backup_name);
        fs::write(&backup_path, &bytes).unwrap();

        let entries = list_backup_entries(&backups_dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("graph-"));
    }

    /// An empty backups directory is an answer, so the envelope still goes out
    /// stamped with a zero count.
    ///
    /// This is the property the whole flag exists for: a caller must never have
    /// to tell "no backups" apart from "not JSON", which is exactly what the
    /// text path's `No backups found.` forces it to do.
    #[test]
    fn the_json_surface_answers_an_empty_directory_with_a_stamped_zero() {
        let dir = tempfile::tempdir().unwrap();
        let backups = collect_backups(&dir.path().to_path_buf()).unwrap();
        assert!(backups.is_empty());

        let payload = BackupListJson {
            schema: BACKUP_LIST_SCHEMA,
            count: backups.len(),
            backups,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["schema"], BACKUP_LIST_SCHEMA);
        assert_eq!(value["count"].as_u64().unwrap(), 0);
        assert!(
            value["backups"].is_array(),
            "the list must be present and empty, never absent"
        );
    }

    /// Sizes and names are read off the files rather than restated, and the
    /// count matches the list it describes.
    #[test]
    fn the_json_surface_reports_the_backups_on_disk_with_their_real_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let backups_dir = dir.path().to_path_buf();
        fs::write(backups_dir.join("graph-20260101-000000.kndb"), b"abcde").unwrap();
        fs::write(backups_dir.join("graph-20260102-000000.kndb"), b"xy").unwrap();
        // Neither the extension nor the prefix matches, so neither may appear.
        fs::write(backups_dir.join("graph-notes.txt"), b"ignored").unwrap();
        fs::write(backups_dir.join("other-20260103-000000.kndb"), b"ignored").unwrap();

        let backups = collect_backups(&backups_dir).unwrap();
        let names: Vec<&str> = backups.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["graph-20260101-000000.kndb", "graph-20260102-000000.kndb"]
        );
        assert_eq!(backups[0].size_bytes, 5);
        assert_eq!(backups[1].size_bytes, 2);
        assert!(backups[0].path.ends_with("graph-20260101-000000.kndb"));

        let payload = BackupListJson {
            schema: BACKUP_LIST_SCHEMA,
            count: backups.len(),
            backups,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value["count"].as_u64().unwrap() as usize,
            value["backups"].as_array().unwrap().len()
        );
    }

    #[test]
    fn sanitize_tag_strips_special_chars() {
        assert_eq!(sanitize_tag("v1.0-beta"), "v1_0-beta");
        assert_eq!(sanitize_tag("pre release!"), "pre_release_");
        assert_eq!(sanitize_tag("normal_tag"), "normal_tag");
    }

    #[test]
    fn sanitize_tag_truncates_long_input() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_tag(&long).len(), 64);
    }

    #[tokio::test]
    async fn restore_validates_backup() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let backups_dir = layout.backups_dir();
        fs::create_dir_all(&backups_dir).unwrap();

        // Write an invalid backup file.
        let bad_path = backups_dir.join("graph-20260101-000000.kndb");
        fs::write(&bad_path, b"not a valid snapshot").unwrap();

        // Attempting to restore should fail validation.
        let entries = list_backup_entries(&backups_dir).unwrap();
        assert_eq!(entries.len(), 1);

        let data = fs::read(&entries[0]).unwrap();
        let result = kin_db::GraphSnapshot::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn offline_restore_requires_explicit_env_value() {
        assert!(offline_restore_env_allowed("1"));
        assert!(offline_restore_env_allowed("true"));
        assert!(offline_restore_env_allowed("YES"));
        assert!(!offline_restore_env_allowed(""));
        assert!(!offline_restore_env_allowed("0"));
        assert!(!offline_restore_env_allowed("false"));
    }

    #[tokio::test]
    async fn restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        // Create a valid snapshot with some data.
        let mut snapshot = kin_db::GraphSnapshot::empty();
        let artifact_id = kin_model::ArtifactId::new();
        let artifact_path = kin_model::RepoPath::from_utf8("main.rs").unwrap();
        snapshot.resolved_tree =
            kin_model::ResolvedTree::from_artifacts([kin_model::ResolvedArtifact::new(
                artifact_id,
                artifact_path.clone(),
                kin_model::TreeEntry::blob(kin_model::Hash256::from_bytes([42; 32]), false),
            )])
            .unwrap();
        let bytes = snapshot.to_bytes().unwrap();
        fs::create_dir_all(layout.kindb_dir()).unwrap();
        fs::write(layout.kindb_snapshot_path(), &bytes).unwrap();

        // Create a backup.
        let backups_dir = layout.backups_dir();
        fs::create_dir_all(&backups_dir).unwrap();
        let backup_path = backups_dir.join("graph-20260325-120000.kndb");
        fs::write(&backup_path, &bytes).unwrap();

        // Overwrite snapshot with an empty one.
        let empty = kin_db::GraphSnapshot::empty().to_bytes().unwrap();
        fs::write(layout.kindb_snapshot_path(), &empty).unwrap();

        // Verify it's empty now.
        let current = fs::read(layout.kindb_snapshot_path()).unwrap();
        let loaded = kin_db::GraphSnapshot::from_bytes(&current).unwrap();
        assert!(loaded.resolved_tree.is_empty());

        // Restore from backup (simulate the restore logic).
        let backup_data = fs::read(&backup_path).unwrap();
        kin_db::GraphSnapshot::from_bytes(&backup_data).unwrap(); // validation
        fs::write(layout.kindb_snapshot_path(), &backup_data).unwrap();

        // Verify restoration.
        let restored_data = fs::read(layout.kindb_snapshot_path()).unwrap();
        let restored = kin_db::GraphSnapshot::from_bytes(&restored_data).unwrap();
        assert_eq!(restored.resolved_tree.len(), 1);
        assert_eq!(
            restored.resolved_tree.artifact_id_at_path(&artifact_path),
            Some(artifact_id)
        );
    }
}
