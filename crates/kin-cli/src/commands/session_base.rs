// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Base-version tracking for session workspaces.
//!
//! When a session workspace is materialized from graph truth, Kin records the
//! state it started from: the graph head it was projected from and the exact
//! [`kin_model::TreeEntry`] for every path materialized into it. Reconcile reads
//! this recorded base to replay only the workspace's own change-set instead of
//! force-syncing whole-tree state, so a workspace reconciled after the source
//! has advanced never reverts intervening source changes. Content, executable
//! mode, and symbolic-link identity all participate in that comparison.
//!
//! The manifest is stored under a reserved `.kin-session/` directory inside
//! the workspace. Exact tree snapshots exclude that control-plane directory
//! directly; language and enrichment filters never participate in the
//! decision.

use std::collections::BTreeMap;
#[cfg(any(unix, windows))]
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
#[cfg(any(unix, windows))]
use cap_fs_ext::DirExt;
use kin_model::{SemanticChangeId, TreeEntry, TreeEntryKind};
use serde::{Deserialize, Serialize};

/// Workspace-relative directory that holds Kin's session-runtime metadata.
const META_DIR: &str = ".kin-session";
/// File (within [`META_DIR`]) that records the workspace's base state.
const BASE_FILE: &str = "reconcile-base.json";

/// Recorded starting point of a session workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBase {
    /// Graph head (branch head change id) the workspace was projected from.
    pub base_head: SemanticChangeId,
    /// Repo-relative path -> exact graph entry for every materialized path.
    pub tree: BTreeMap<String, TreeEntry>,
}

/// Path to the base manifest for a session workspace.
fn base_manifest_path(session_dir: &Path) -> PathBuf {
    session_dir.join(META_DIR).join(BASE_FILE)
}

/// Read one exact filesystem entry without following symbolic links.
pub(crate) fn read_disk_entry(path: &Path) -> Result<Option<(TreeEntry, Vec<u8>)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!("inspect {}: {}", path.display(), error));
        }
    };

    let (content, kind) = if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)
            .map_err(|error| anyhow::anyhow!("read symbolic link {}: {}", path.display(), error))?;
        #[cfg(unix)]
        let content = {
            use std::os::unix::ffi::OsStrExt;
            target.as_os_str().as_bytes().to_vec()
        };
        #[cfg(not(unix))]
        let content = target
            .to_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "symbolic-link target is not exactly representable on this platform: {}",
                    path.display()
                )
            })?
            .as_bytes()
            .to_vec();
        (content, TreeEntryKind::Symlink)
    } else if metadata.is_file() {
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        (
            std::fs::read(path)
                .map_err(|error| anyhow::anyhow!("read {}: {}", path.display(), error))?,
            TreeEntryKind::Regular { executable },
        )
    } else {
        anyhow::bail!(
            "session tree contains an unsupported filesystem object at {}",
            path.display()
        );
    };

    Ok(Some((
        TreeEntry {
            blob_hash: kin_blobs::digest(&content),
            kind,
        },
        content,
    )))
}

/// Snapshot every repository entry under `root` into exact tree semantics.
///
/// Only Kin's own control-plane paths are excluded. Language support and
/// enrichment policy never decide whether a repository path participates in
/// version-control truth.
pub fn snapshot_dir(root: &Path) -> Result<BTreeMap<String, TreeEntry>> {
    let mut tree = BTreeMap::new();
    snapshot_dir_recursive(root, root, &mut tree)?;
    Ok(tree)
}

fn snapshot_dir_recursive(
    directory: &Path,
    root: &Path,
    tree: &mut BTreeMap<String, TreeEntry>,
) -> Result<()> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| anyhow::anyhow!("read directory {}: {}", directory.display(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            anyhow::anyhow!("read directory {}: {}", directory.display(), error)
        })?;
        let name = entry.file_name();
        let name_text = name.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "session tree path is not valid UTF-8 under {}",
                directory.display()
            )
        })?;
        if (directory == root && name_text == super::session_process::SESSION_CONTEXT_FILE)
            || matches!(name_text, META_DIR | ".kin" | ".git" | ".git-export")
        {
            continue;
        }

        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| anyhow::anyhow!("inspect {}: {}", path.display(), error))?;
        if file_type.is_dir() {
            snapshot_dir_recursive(&path, root, tree)?;
            continue;
        }

        let relative = path.strip_prefix(root).map_err(|_| {
            anyhow::anyhow!("session path escaped snapshot root: {}", path.display())
        })?;
        let relative = relative.to_str().ok_or_else(|| {
            anyhow::anyhow!("session tree path is not valid UTF-8: {}", path.display())
        })?;
        let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
        let (entry, _) = read_disk_entry(&path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "session tree entry disappeared during snapshot: {}",
                path.display()
            )
        })?;
        tree.insert(relative, entry);
    }
    Ok(())
}

/// Persist a base manifest into a session workspace.
pub fn write_base(session_dir: &Path, base: &SessionBase) -> Result<()> {
    let path = base_manifest_path(session_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create session metadata directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    let json = serde_json::to_vec_pretty(base)
        .map_err(|e| anyhow::anyhow!("failed to serialize session base: {}", e))?;
    std::fs::write(&path, json)
        .map_err(|e| anyhow::anyhow!("failed to write session base {}: {}", path.display(), e))?;
    Ok(())
}

/// Load the required exact base for a session workspace.
pub(crate) fn load_base(session_dir: &Path) -> Result<SessionBase> {
    let path = base_manifest_path(session_dir);
    let bytes = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("failed to read session base {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse session base {}: {}", path.display(), e))
}

/// Record the base state of a freshly materialized session workspace.
///
/// Immediately after materialization the workspace is byte-identical to the
/// graph truth it was projected from, so hashing the workspace itself captures
/// the correct base.
pub fn record_materialized_base(session_dir: &Path, base_head: SemanticChangeId) -> Result<()> {
    let tree = snapshot_dir(session_dir)?;
    write_base(session_dir, &SessionBase { base_head, tree })
}

#[cfg(any(unix, windows))]
/// Persist the graph-authoritative base supplied by the materializer through
/// the retained session-directory capability.
///
/// The caller must derive `base.tree` from the preflighted graph tree. This
/// function deliberately does not discover files from the live workspace,
/// where a concurrent insertion or mutation could otherwise be mistaken for
/// graph truth.
pub fn record_preflighted_graph_base_in_dir(
    session_dir: &cap_std::fs::Dir,
    base: &SessionBase,
) -> Result<()> {
    session_dir.create_dir(META_DIR).map_err(|error| {
        anyhow::anyhow!(
            "failed to create capability-rooted session metadata directory: {}",
            error
        )
    })?;
    let metadata_dir = session_dir.open_dir_nofollow(META_DIR).map_err(|error| {
        anyhow::anyhow!(
            "failed to open capability-rooted session metadata directory: {}",
            error
        )
    })?;
    let json = serde_json::to_vec_pretty(base)
        .map_err(|error| anyhow::anyhow!("failed to serialize session base: {}", error))?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut base_file = metadata_dir
        .open_with(BASE_FILE, &options)
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to create capability-rooted session base manifest: {}",
                error
            )
        })?;
    base_file.write_all(&json).map_err(|error| {
        anyhow::anyhow!(
            "failed to write capability-rooted session base manifest: {}",
            error
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_tracks_heterogeneous_repository_entries_exactly() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::create_dir_all(root.join(".kin/private")).unwrap();
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(root.join(".git-export/cache")).unwrap();
        std::fs::create_dir_all(root.join(".kin-session")).unwrap();

        std::fs::write(
            root.join("docker-compose.yml"),
            b"services:\n  app:\n    image: alpine\n",
        )
        .unwrap();
        std::fs::write(root.join("node_modules/pkg/index.unknown"), b"\0\xffopaque").unwrap();
        std::fs::write(root.join("assets/model.bin"), [0, 1, 2, 255]).unwrap();
        std::fs::write(root.join(".kin/private/state"), b"control").unwrap();
        std::fs::write(root.join(".git/HEAD"), b"control").unwrap();
        std::fs::write(root.join(".git-export/cache/state"), b"control").unwrap();
        std::fs::write(root.join(".kin-session/reconcile-base.json"), b"control").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let executable = root.join("run-tool");
            std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            symlink("docker-compose.yml", root.join("compose-current")).unwrap();
        }

        let tree = snapshot_dir(root).unwrap();

        assert_eq!(
            tree.get("docker-compose.yml"),
            Some(&TreeEntry::regular(
                kin_blobs::digest(b"services:\n  app:\n    image: alpine\n"),
                false,
            ))
        );
        assert_eq!(
            tree.get("node_modules/pkg/index.unknown"),
            Some(&TreeEntry::regular(
                kin_blobs::digest(b"\0\xffopaque"),
                false,
            ))
        );
        assert_eq!(
            tree.get("assets/model.bin"),
            Some(&TreeEntry::regular(
                kin_blobs::digest(&[0, 1, 2, 255]),
                false,
            ))
        );
        assert!(!tree.keys().any(|path| {
            path.starts_with(".kin/")
                || path.starts_with(".git/")
                || path.starts_with(".git-export/")
                || path.starts_with(".kin-session/")
        }));

        #[cfg(unix)]
        {
            assert_eq!(
                tree.get("run-tool"),
                Some(&TreeEntry::regular(
                    kin_blobs::digest(b"#!/bin/sh\nexit 0\n"),
                    true,
                ))
            );
            assert_eq!(
                tree.get("compose-current"),
                Some(&TreeEntry::symlink(kin_blobs::digest(
                    b"docker-compose.yml"
                )))
            );
        }
    }

    #[test]
    fn load_base_rejects_missing_and_legacy_manifests() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        assert!(load_base(root).is_err());

        std::fs::create_dir_all(root.join(META_DIR)).unwrap();
        std::fs::write(
            base_manifest_path(root),
            br#"{"base_head":null,"files":{"README.md":"legacy"}}"#,
        )
        .unwrap();
        let error = load_base(root).unwrap_err().to_string();
        assert!(
            error.contains("failed to parse session base"),
            "unexpected error: {error}"
        );
    }
}
