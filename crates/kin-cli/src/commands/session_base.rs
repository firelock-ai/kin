// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact base tracking for session workspaces.
//!
//! The manifest stores only the immutable graph head that was materialized.
//! Reconcile resolves identity-bearing base truth from that head; it never
//! serializes a second path-keyed authority copy into the workspace.

use std::collections::BTreeMap;
#[cfg(any(unix, windows))]
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(any(unix, windows))]
use cap_fs_ext::DirExt;
use kin_model::{Hash256, RepoPath, SemanticChangeId, TreeEntry};
use serde::{Deserialize, Serialize};

const META_DIR: &str = ".kin-session";
const BASE_FILE: &str = "reconcile-base.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBase {
    /// Immutable graph head projected into this workspace.
    pub base_head: SemanticChangeId,
}

fn base_manifest_path(session_dir: &Path) -> PathBuf {
    session_dir.join(META_DIR).join(BASE_FILE)
}

/// Read one exact host entry without following symbolic links.
pub(crate) fn read_disk_entry(path: &Path) -> Result<Option<(TreeEntry, Vec<u8>)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!("inspect {}: {}", path.display(), error));
        }
    };

    let (content, entry) = if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path)
            .with_context(|| format!("read symbolic link {}", path.display()))?;
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
        let hash = Hash256::from_bytes(kin_blobs::digest(&content).0);
        (content, TreeEntry::symlink(hash))
    } else if metadata.file_type().is_file() {
        let content = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        let hash = Hash256::from_bytes(kin_blobs::digest(&content).0);
        (content, TreeEntry::blob(hash, executable))
    } else {
        anyhow::bail!(
            "session tree contains an unsupported filesystem object at {}",
            path.display()
        );
    };

    Ok(Some((entry, content)))
}

/// Complete byte-exact observation of a session workspace.
///
/// This is an explicit reconcile input boundary, not a semantic query path.
/// It admits every regular file and symlink independent of language support
/// while excluding only Kin/Git control metadata.
pub fn snapshot_dir(root: &Path) -> Result<BTreeMap<RepoPath, TreeEntry>> {
    let scan = kin_index::scan_repository(
        root,
        &kin_index::RepositoryIgnore::default(),
        std::iter::empty(),
    )
    .map_err(kin_index::IndexError::from)?;
    let mut tree = BTreeMap::new();
    for scanned in scan.entries() {
        let content = kin_index::read_verified_scanned_entry(scanned)
            .with_context(|| format!("re-read session entry {}", scanned.repo_path))?;
        let hash = Hash256::from_bytes(kin_blobs::digest(&content).0);
        anyhow::ensure!(
            hash.0 == scanned.content_hash,
            "session entry changed after complete scan: {}",
            scanned.repo_path
        );
        let entry = match scanned.kind {
            kin_index::ScannedEntryKind::Regular { executable } => {
                TreeEntry::blob(hash, executable)
            }
            kin_index::ScannedEntryKind::Symlink => TreeEntry::symlink(hash),
        };
        tree.insert(scanned.repo_path.clone(), entry);
    }
    Ok(tree)
}

pub fn write_base(session_dir: &Path, base: &SessionBase) -> Result<()> {
    let path = base_manifest_path(session_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create session metadata directory {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(base).context("serialize session base")?;
    std::fs::write(&path, json)
        .with_context(|| format!("write session base {}", path.display()))?;
    Ok(())
}

pub(crate) fn load_base(session_dir: &Path) -> Result<SessionBase> {
    let path = base_manifest_path(session_dir);
    let bytes =
        std::fs::read(&path).with_context(|| format!("read session base {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse session base {}", path.display()))
}

pub fn record_materialized_base(session_dir: &Path, base_head: SemanticChangeId) -> Result<()> {
    write_base(session_dir, &SessionBase { base_head })
}

#[cfg(any(unix, windows))]
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
    let json = serde_json::to_vec_pretty(base).context("serialize session base")?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut base_file = metadata_dir
        .open_with(BASE_FILE, &options)
        .context("create capability-rooted session base manifest")?;
    base_file
        .write_all(&json)
        .context("write capability-rooted session base manifest")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_tracks_heterogeneous_entries_and_non_utf8_paths_exactly() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::create_dir_all(root.join(".kin/private")).unwrap();
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::create_dir_all(root.join(".kin-session")).unwrap();
        std::fs::write(root.join("compose.yaml"), b"services: {}\n").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.unknown"), b"\0\xffopaque").unwrap();
        std::fs::write(root.join("assets/model.bin"), [0, 1, 2, 255]).unwrap();
        std::fs::write(root.join(".kin/private/state"), b"control").unwrap();
        std::fs::write(root.join(".git/HEAD"), b"control").unwrap();
        std::fs::write(root.join(".kin-session/reconcile-base.json"), b"control").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::{symlink, PermissionsExt};

            let executable = root.join("run-tool");
            std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            symlink("compose.yaml", root.join("compose-current")).unwrap();
            let raw = std::ffi::OsStr::from_bytes(b"opaque-\xff");
            std::fs::write(root.join(raw), b"non-utf8 path").unwrap();
        }

        let tree = snapshot_dir(root).unwrap();
        let compose = RepoPath::from_utf8("compose.yaml").unwrap();
        assert_eq!(
            tree.get(&compose),
            Some(&TreeEntry::blob(
                Hash256::from_bytes(kin_blobs::digest(b"services: {}\n").0),
                false,
            ))
        );
        assert!(tree
            .keys()
            .all(|path| !kin_index::is_repository_control_path(path)));

        #[cfg(unix)]
        {
            assert!(tree.contains_key(&RepoPath::from_bytes(b"opaque-\xff".to_vec()).unwrap()));
            assert!(matches!(
                tree.get(&RepoPath::from_utf8("run-tool").unwrap()),
                Some(TreeEntry::Blob {
                    executable: true,
                    ..
                })
            ));
            assert!(matches!(
                tree.get(&RepoPath::from_utf8("compose-current").unwrap()),
                Some(TreeEntry::Symlink { .. })
            ));
        }
    }

    #[test]
    fn manifest_records_only_graph_head_and_rejects_legacy_tree_copies() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let base_head = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        write_base(root, &SessionBase { base_head }).unwrap();

        let json = std::fs::read_to_string(base_manifest_path(root)).unwrap();
        assert!(json.contains("base_head"));
        assert!(!json.contains("\"tree\""));
        assert_eq!(load_base(root).unwrap().base_head, base_head);

        std::fs::write(
            base_manifest_path(root),
            format!(r#"{{"base_head":"{base_head}","tree":{{}}}}"#),
        )
        .unwrap();
        assert!(load_base(root).is_err());
    }
}
