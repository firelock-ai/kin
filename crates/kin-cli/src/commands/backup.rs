// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Schema token stamped on every `kin backup list --json` answer.
pub const BACKUP_LIST_SCHEMA: &str = "kin.backup.list.v1";

/// Restore complete native authority without replacing an existing repository.
pub async fn restore_carrier(carrier: PathBuf, destination: PathBuf) -> Result<()> {
    super::recovery_carrier::ensure_platform()?;
    let destination = std::path::absolute(destination)?;
    if destination.file_name() != Some(std::ffi::OsStr::new(".kin")) {
        anyhow::bail!("restore --target must name an absent .kin directory in the destination working directory");
    }
    let carrier = carrier.canonicalize().context("resolve recovery carrier")?;
    let destination = destination
        .parent()
        .context("restore target needs a working directory")?
        .canonicalize()
        .context("resolve destination working directory")?
        .join(".kin");
    super::recovery_carrier::restore(&carrier, &destination, |_, _| Ok(()))?;
    println!("Restored native repository: {}", destination.display());
    Ok(())
}

/// Create a complete carrier beside, never inside, the repository state.
pub async fn create(tag: Option<String>, output: Option<PathBuf>) -> Result<()> {
    super::recovery_carrier::ensure_platform()?;
    let layout = discover_layout()?;
    let destination = match output {
        Some(path) => path,
        None => {
            let backups = backups_directory(&layout)?;
            fs::create_dir_all(&backups)?;
            let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S-%f");
            let suffix = tag
                .as_deref()
                .map(sanitize_tag)
                .unwrap_or_else(|| "native".into());
            backups.join(format!("{timestamp}-{suffix}"))
        }
    };
    create_carrier_at(&layout, &destination)?;
    println!("Native recovery backup created: {}", destination.display());
    Ok(())
}

pub(super) fn create_carrier_at(
    layout: &kin_core::KinLayout,
    destination: &std::path::Path,
) -> Result<()> {
    super::recovery_carrier::ensure_platform()?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?;
    let backend = kin_db::LocalFileBackend::new(layout.kindb_dir());
    let frozen = kin_db::LocalRepositoryAuthorityFreeze::open_existing_read_only(
        binding.repository_id().clone(),
        &backend,
    )?;
    if !frozen
        .authority()
        .metadata()
        .workspaces
        .iter()
        .any(|workspace| workspace.workspace_id == binding.workspace_id())
    {
        anyhow::bail!("repository authority does not contain its manifest workspace");
    }
    let manifest = super::recovery_carrier::Manifest {
        schema: String::new(),
        source_root: layout.root().to_path_buf(),
        repository_id: binding.repository_id().to_string(),
        workspace_id: binding.workspace_id().to_string(),
        layout_version: layout.read_version()?,
        roots: frozen.roots().clone(),
        files: Default::default(),
    };
    super::recovery_carrier::publish(layout.root(), destination, manifest)
}

/// One backup on disk, as both the table and the JSON surface describe it.
#[derive(Debug, Serialize)]
pub struct BackupEntry {
    /// Exact carrier directory name.
    pub name: String,
    /// Path to the complete carrier directory.
    pub path: String,
    pub size_bytes: u64,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BackupListJson {
    pub schema: &'static str,
    pub count: usize,
    pub backups: Vec<BackupEntry>,
}

fn backups_directory(layout: &kin_core::KinLayout) -> Result<PathBuf> {
    let identity = kin_core::KinManifest::load(&layout.manifest_path())?;
    let directory = layout
        .root()
        .parent()
        .and_then(|working| working.parent())
        .context("default backups need a parent outside the working directory; use --output")?
        .join(format!(
            ".kin-backups-{}",
            hex::encode(Sha256::digest(identity.repo_id.as_bytes()))
        ));
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            anyhow::bail!("default recovery backup directory must be a real directory, not a link")
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    Ok(directory)
}

fn collect_backups(backups_dir: &PathBuf) -> Result<Vec<BackupEntry>> {
    if !backups_dir.exists() {
        return Ok(Vec::new());
    }
    let mut backups = Vec::new();
    for entry in fs::read_dir(backups_dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let result = super::recovery_carrier::inspect(&path).and_then(|manifest| {
            manifest.files.values().try_fold(0u64, |size, file| {
                size.checked_add(file.size).context("backup size overflow")
            })
        });
        let (size_bytes, error) = match result {
            Ok(size) => (size, None),
            Err(error) => (0, Some(format!("{error:#}"))),
        };
        backups.push(BackupEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            path: path.display().to_string(),
            size_bytes,
            valid: error.is_none(),
            error,
        });
    }
    backups.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(backups)
}

fn backup_list_payload(backups: Vec<BackupEntry>) -> BackupListJson {
    BackupListJson {
        schema: BACKUP_LIST_SCHEMA,
        count: backups.len(),
        backups,
    }
}

/// List complete carriers in the default directory outside repository state.
pub async fn list(json: bool, directory: Option<PathBuf>) -> Result<()> {
    let directory = match directory {
        Some(path) => path.canonicalize().context("resolve backup directory")?,
        None => backups_directory(&discover_layout()?)?,
    };
    let backups = collect_backups(&directory)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&backup_list_payload(backups))?
        );
    } else if backups.is_empty() {
        println!("No recovery backups found.");
    } else {
        for backup in backups {
            if let Some(error) = backup.error {
                println!("{} INVALID: {}", backup.path, error);
                continue;
            }
            println!(
                "{} ({} payload bytes) {}",
                backup.name, backup.size_bytes, backup.path
            );
        }
    }
    Ok(())
}

/// Legacy graph-only files cannot replace complete native authority safely.
pub async fn restore(_name: Option<String>, _latest: bool) -> Result<()> {
    anyhow::bail!("graph-only in-place restore is unsupported; preserve the repository and legacy backup intact. Restore a complete carrier with --from <carrier> --target <fresh-working-directory>/.kin. A Git export or graph snapshot does not retain all native state")
}

/// Delete one explicitly named, validated carrier from the default directory.
pub async fn delete(name: String) -> Result<()> {
    let layout = discover_layout()?;
    let directory = backups_directory(&layout)?;
    let mut components = std::path::Path::new(&name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        anyhow::bail!("backup delete requires one exact carrier directory name");
    }
    super::recovery_carrier::validate(&directory.join(&name))?;
    let parent = cap_std::fs::Dir::open_ambient_dir(&directory, cap_std::ambient_authority())?;
    parent.remove_dir_all(&name)?;
    println!("Permanently deleted recovery backup: {}", name);
    Ok(())
}

fn discover_layout() -> Result<kin_core::KinLayout> {
    crate::commands::require_repository_layout()
}

fn sanitize_tag(tag: &str) -> String {
    tag.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_json_surface_answers_an_empty_directory_with_a_stamped_zero() {
        let scratch = tempfile::tempdir().unwrap();
        let value = serde_json::to_value(backup_list_payload(
            collect_backups(&scratch.path().to_path_buf()).unwrap(),
        ))
        .unwrap();
        assert_eq!(value["schema"], BACKUP_LIST_SCHEMA);
        assert_eq!(value["count"], 0);
        assert_eq!(value["backups"], serde_json::json!([]));
    }

    #[test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    fn the_json_surface_lists_actual_current_format_carriers() {
        let scratch = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = scratch.path().join("source");
        fs::create_dir(&source).unwrap();
        let initialized = kin_core::init(&source).unwrap();
        let backups = backups_directory(&initialized.layout).unwrap();
        fs::create_dir(&backups).unwrap();
        create_carrier_at(&initialized.layout, &backups.join("first")).unwrap();
        let entries = collect_backups(&backups).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "first");
        assert!(entries[0].size_bytes > 0);
        assert!(entries[0].path.ends_with("/first"));
        assert!(!backups.starts_with(&source));
        let value = serde_json::to_value(backup_list_payload(entries)).unwrap();
        assert_eq!(value["count"], value["backups"].as_array().unwrap().len());
        fs::write(backups.join("first/COMPLETE"), b"invalid").unwrap();
        create_carrier_at(&initialized.layout, &backups.join("second")).unwrap();
        let entries = collect_backups(&backups).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].valid);
        assert!(entries[0].error.is_some());
        assert!(entries[1].valid);
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    async fn explicit_listing_survives_loss_of_the_original_kin_directory() {
        let scratch = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = scratch.path().join("source");
        fs::create_dir(&source).unwrap();
        let initialized = kin_core::init(&source).unwrap();
        let backups = backups_directory(&initialized.layout).unwrap();
        fs::create_dir(&backups).unwrap();
        create_carrier_at(&initialized.layout, &backups.join("saved")).unwrap();
        fs::rename(
            initialized.layout.root(),
            scratch.path().join("original-state-preserved"),
        )
        .unwrap();
        list(true, Some(backups.clone())).await.unwrap();
        assert!(collect_backups(&backups).unwrap()[0].valid);
    }

    #[tokio::test]
    async fn legacy_restore_refuses_without_discovering_or_mutating_a_repository() {
        let error = restore(Some("old-snapshot".into()), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("preserve"));
        assert!(error.to_string().contains("--from"));
    }

    #[test]
    fn tags_are_bounded_filename_components() {
        assert_eq!(sanitize_tag("../pre release!"), "___pre_release_");
        assert_eq!(sanitize_tag("a-b_c"), "a-b_c");
        assert_eq!(sanitize_tag(&"a".repeat(100)).len(), 64);
    }
}
