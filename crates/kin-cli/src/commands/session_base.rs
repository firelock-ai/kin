// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Base-version tracking for session workspaces.
//!
//! When a session workspace is materialized from graph truth, Kin records the
//! state it started from: the graph head it was projected from and a content
//! hash for every file materialized into it. Reconcile reads this recorded base
//! to replay only the workspace's own change-set instead of force-syncing whole
//! tree state, so a workspace reconciled after the source has advanced never
//! reverts the intervening source changes.
//!
//! The manifest is stored under a `.kin-session/` directory inside the
//! workspace. That prefix is excluded by every graph file-collection path
//! (`kin_index::should_skip_dir`), so the manifest is never materialized,
//! diffed, reconciled, or indexed as project content, and it is removed with
//! the workspace on cleanup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Workspace-relative directory that holds Kin's session-runtime metadata.
const META_DIR: &str = ".kin-session";
/// File (within [`META_DIR`]) that records the workspace's base state.
const BASE_FILE: &str = "reconcile-base.json";

/// Recorded starting point of a session workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBase {
    /// Graph head (branch head change id) the workspace was projected from.
    ///
    /// Used for provenance and conflict reporting; the file manifest is the
    /// authoritative base for change-set computation.
    #[serde(default)]
    pub base_head: Option<String>,
    /// Repo-relative path -> content hash for every materialized file.
    pub files: BTreeMap<String, String>,
}

/// Path to the base manifest for a session workspace.
fn base_manifest_path(session_dir: &Path) -> PathBuf {
    session_dir.join(META_DIR).join(BASE_FILE)
}

/// Hash every collectable file under `root` into a `path -> content-hash` map.
///
/// Uses the same file-collection policy as reconcile (`collect_relative_files`)
/// so a base captured at materialization and a state hashed at reconcile are
/// directly comparable.
pub fn hash_dir(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut manifest = BTreeMap::new();
    for rel in super::reconcile::collect_relative_files(root)? {
        let abs = root.join(&rel);
        let content = std::fs::read(&abs).map_err(|e| {
            anyhow::anyhow!(
                "failed to read {} for session base manifest: {}",
                abs.display(),
                e
            )
        })?;
        manifest.insert(
            rel.to_string_lossy().into_owned(),
            kin_blobs::digest(&content).to_string(),
        );
    }
    Ok(manifest)
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

/// Load a session workspace's recorded base, if one was captured.
///
/// Returns `Ok(None)` for legacy workspaces materialized before base tracking.
pub(crate) fn load_base(session_dir: &Path) -> Result<Option<SessionBase>> {
    let path = base_manifest_path(session_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let base = serde_json::from_slice(&bytes).map_err(|e| {
                anyhow::anyhow!("failed to parse session base {}: {}", path.display(), e)
            })?;
            Ok(Some(base))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(
            "failed to read session base {}: {}",
            path.display(),
            e
        )),
    }
}

/// Record the base state of a freshly materialized session workspace.
///
/// Immediately after materialization the workspace is byte-identical to the
/// graph truth it was projected from, so hashing the workspace itself captures
/// the correct base.
pub fn record_materialized_base(session_dir: &Path, base_head: Option<String>) -> Result<()> {
    let files = hash_dir(session_dir)?;
    write_base(session_dir, &SessionBase { base_head, files })
}
