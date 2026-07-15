// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared onboarding finalization steps.
//!
//! Both `kin init` and `kin migrate` call these functions after the graph
//! has been populated with entities and relations. They guarantee that
//! every onboarded repo ends up with:
//!
//! 1. A persisted `.kidx` read index for fast CLI queries.
//! 2. A snapshot directory suitable for `kin eject`.
//! 3. A registry entry in `~/.kin/registry.toml`.
//! 4. A best-effort LSP cold-sweep trigger.

use std::fs;
use std::path::Path;

use tracing::{info, warn};

use crate::error::{MigrateError, Result};

/// Build and persist the `.kidx` read index next to the KinDB snapshot.
///
/// The read index materializes graph data into a compact, mmap-friendly
/// format that `kin locate`, `kin trace`, and other CLI queries use for
/// sub-millisecond lookups without loading the full in-memory graph.
pub fn build_and_save_kidx(snapshot_path: &Path, graph: &kin_db::InMemoryGraph) -> Result<()> {
    let _span = tracing::info_span!(
        "kin.migrate.build_and_save_kidx",
        snapshot = %snapshot_path.display()
    )
    .entered();
    let read_index = {
        let _span = tracing::info_span!("kin.migrate.build_read_index").entered();
        kin_db::ReadIndex::from_graph(graph).map_err(|e| MigrateError::Graph(e.to_string()))?
    };
    let idx_path = snapshot_path.with_extension("kidx");
    {
        let _span = tracing::info_span!(
            "kin.migrate.save_read_index",
            path = %idx_path.display()
        )
        .entered();
        read_index
            .save(&idx_path)
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
    }
    info!(path = %idx_path.display(), "read index (.kidx) persisted");
    Ok(())
}

/// Create or verify the eject snapshot directory inside `.kin/`.
///
/// `kin eject` restores the project to its pre-Kin state by copying files
/// back from `.kin/snapshot/`. If the snapshot directory already exists
/// (e.g. from `kin init`), this is a no-op. When called from `kin migrate`
/// on an in-place repo, it creates the snapshot from the current working tree.
pub fn ensure_eject_snapshot(repo_root: &Path, kin_root: &Path) -> Result<()> {
    let snapshot_dir = kin_root.join("snapshot");
    if snapshot_dir.exists() {
        info!("eject snapshot already exists, skipping");
        return Ok(());
    }

    fs::create_dir_all(&snapshot_dir)
        .map_err(|e| MigrateError::Other(format!("failed to create snapshot dir: {e}")))?;

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    snapshot_walk(
        repo_root,
        repo_root,
        &snapshot_dir,
        &mut file_count,
        &mut total_bytes,
    )?;

    let manifest = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "file_count": file_count,
        "total_bytes": total_bytes,
    });
    fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)
            .map_err(|e| MigrateError::Other(format!("manifest serialization: {e}")))?,
    )
    .map_err(|e| MigrateError::Other(format!("failed to write snapshot manifest: {e}")))?;

    info!(
        files = file_count,
        bytes = total_bytes,
        "eject snapshot created"
    );
    Ok(())
}

/// Register the repo in `~/.kin/registry.toml` with its entity count.
pub fn update_registry(repo_root: &Path, entity_count: usize) {
    let repo_id = repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    if let Err(e) = kin_core::registry::KinRegistry::update(|registry| {
        registry.upsert(repo_id, canonical, entity_count);
    }) {
        warn!(error = %e, "failed to update global registry");
    }
}

/// Best-effort trigger of the daemon LSP cold sweep.
///
/// Returns `true` if the sweep was successfully triggered.
pub async fn trigger_lsp_sweep() -> bool {
    let Some(daemon_url) = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return false;
    };
    let url = format!("{}/v1/lsp/sweep", daemon_url.trim_end_matches('/'));
    match reqwest::Client::new()
        .post(&url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!("LSP cold sweep triggered");
            true
        }
        _ => false,
    }
}

// --- snapshot helpers ---

fn snapshot_walk(
    root: &Path,
    current: &Path,
    dest_root: &Path,
    file_count: &mut u64,
    total_bytes: &mut u64,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries {
        let entry = entry.map_err(|e| MigrateError::Other(format!("snapshot readdir: {e}")))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map_err(|e| MigrateError::Other(format!("snapshot strip_prefix: {e}")))?;

        if snapshot_should_skip(rel) {
            continue;
        }

        let ft = entry
            .file_type()
            .map_err(|e| MigrateError::Other(format!("snapshot file_type: {e}")))?;
        if ft.is_dir() {
            snapshot_walk(root, &path, dest_root, file_count, total_bytes)?;
        } else if ft.is_file() {
            let dest = dest_root.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| MigrateError::Other(format!("snapshot mkdir: {e}")))?;
            }
            fs::copy(&path, &dest)
                .map_err(|e| MigrateError::Other(format!("snapshot copy: {e}")))?;
            *total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
            *file_count += 1;
        }
    }
    Ok(())
}

fn snapshot_should_skip(rel: &Path) -> bool {
    let s = rel.to_string_lossy();
    if s.starts_with(".kin") {
        return true;
    }
    for skip in &[".git/objects", ".git/pack"] {
        if s == *skip || s.starts_with(&format!("{skip}/")) {
            return true;
        }
    }
    for skip in kin_index::SKIP_DIRS {
        if s == *skip || s.starts_with(&format!("{skip}/")) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_skip_filters_kin_dirs() {
        assert!(snapshot_should_skip(Path::new(".kin")));
        assert!(snapshot_should_skip(Path::new(".kin/snapshot")));
        assert!(snapshot_should_skip(Path::new(".kin-snapshot-tmp")));
        assert!(!snapshot_should_skip(Path::new("src/main.rs")));
        assert!(!snapshot_should_skip(Path::new("README.md")));
    }

    #[test]
    fn snapshot_skip_filters_git_internals() {
        assert!(snapshot_should_skip(Path::new(".git/objects")));
        assert!(snapshot_should_skip(Path::new(".git/objects/pack/foo")));
        assert!(snapshot_should_skip(Path::new(".git/pack")));
        assert!(!snapshot_should_skip(Path::new(".git/HEAD")));
        assert!(!snapshot_should_skip(Path::new(".git/config")));
    }

    #[test]
    fn update_registry_does_not_panic_on_missing_home() {
        let tmp = tempfile::tempdir().unwrap();
        // Should not panic even if ~/.kin doesn't exist.
        update_registry(tmp.path(), 42);
    }
}
