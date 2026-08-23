// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared onboarding finalization steps.
//!
//! `kin init` and `kin migrate` share only the finalization operations that
//! preserve graph authority:
//!
//! 1. A persisted `.kidx` read index for fast CLI queries.
//! 2. A registry entry in the registry this home resolves to
//!    (`KIN_REGISTRY_PATH`, else `<KIN_HOME>/registry.toml`, else
//!    `~/.kin/registry.toml`).
//! 3. A best-effort LSP cold-sweep trigger.
//!
use std::path::Path;

use tracing::info;

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

/// Register the repo in this home's resolved registry with its entity count.
pub fn update_registry(repo_root: &Path, entity_count: usize) -> Result<()> {
    let repo_id = repo_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    kin_core::registry::KinRegistry::update(|registry| {
        registry.upsert(repo_id, canonical, entity_count);
    })
    .map_err(|e| MigrateError::Other(format!("failed to update local registry authority: {e}")))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_registry_does_not_panic_on_missing_home() {
        let tmp = tempfile::tempdir().unwrap();
        // Point the registry authority at a path whose parent directory does
        // not exist yet. That is the condition under test, and it keeps the
        // test off the operator's real resolved registry: writing there mutates the
        // developer's own repo list, and the exclusive lock it takes has no
        // timeout, so a `kin` process holding that lock would block this test
        // forever.
        let registry_path = tmp.path().join("registry-home/registry.toml");
        let _registry = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path);

        update_registry(tmp.path(), 42).unwrap();

        assert!(
            registry_path.exists(),
            "the registry authority must be created under the missing home"
        );
    }
}
