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
///
/// The id recorded is the identity the repository publishes in its own manifest,
/// so the registry and the daemon's startup authority pin speak one alphabet.
/// This used to record `repo_root.file_name()`, the directory name, while the
/// manifest minted a UUID, and the daemon refused every sibling whose two
/// identities disagreed, which was all of them.
///
/// The directory name remains the fallback for a repository with no readable
/// manifest. A row that names the path badly is still a row; refusing to
/// register would lose the repository entirely over a file this function is not
/// the right place to repair.
pub fn update_registry(repo_root: &Path, entity_count: usize) -> Result<()> {
    let repo_id =
        kin_core::registry::published_repository_identity(repo_root).unwrap_or_else(|| {
            repo_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string()
        });
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

    /// The registry records the identity the repository publishes, not the name
    /// of the directory it happens to sit in.
    ///
    /// Asserted against the manifest itself rather than against a string this
    /// test writes. The whole defect was two producers writing the same concept
    /// in two alphabets, so a test that spells the expected id out would be the
    /// same mistake one layer up: it would pass while the two real producers
    /// disagreed. The directory is deliberately named so a directory-name id and
    /// a manifest id cannot be confused.
    #[test]
    fn the_registry_records_the_identity_the_repository_publishes() {
        let parent = tempfile::tempdir().unwrap();
        let repo_root = parent.path().join("some-checkout-directory");
        std::fs::create_dir_all(&repo_root).unwrap();
        kin_core::init(&repo_root).unwrap();

        let registry_path = parent.path().join("registry-home/registry.toml");
        let _registry = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path);
        update_registry(&repo_root, 7).unwrap();

        let published = kin_core::registry::published_repository_identity(&repo_root)
            .expect("an initialized repository publishes an identity");
        let registry = kin_core::registry::KinRegistry::load_from(&registry_path).unwrap();
        let row = registry
            .repos
            .iter()
            .find(|repo| {
                repo.path
                    .canonicalize()
                    .ok()
                    .zip(repo_root.canonicalize().ok())
                    .is_some_and(|(recorded, expected)| recorded == expected)
            })
            .expect("the repository must be registered");

        assert_eq!(
            row.id, published,
            "the registry id must be the manifest's identity, not the directory name"
        );
        assert_ne!(
            row.id, "some-checkout-directory",
            "recording the directory name is the defect this replaced"
        );
    }

    /// The fallback, which must stay. A repository with no readable manifest is
    /// still registered under its directory name, because losing the row
    /// entirely over an unreadable file is worse than naming it badly.
    #[test]
    fn a_repository_with_no_manifest_is_still_registered_under_its_directory_name() {
        let parent = tempfile::tempdir().unwrap();
        let repo_root = parent.path().join("unmanifested-checkout");
        std::fs::create_dir_all(&repo_root).unwrap();

        let registry_path = parent.path().join("registry-home/registry.toml");
        let _registry = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path);
        update_registry(&repo_root, 0).unwrap();

        let registry = kin_core::registry::KinRegistry::load_from(&registry_path).unwrap();
        assert_eq!(
            registry.repos.len(),
            1,
            "the row must exist even with no manifest to read"
        );
        assert_eq!(registry.repos[0].id, "unmanifested-checkout");
    }

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
