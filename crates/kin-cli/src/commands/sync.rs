// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin sync` — reconcile the working tree into the existing graph after a bulk
//! change such as `git checkout`.
//!
//! This is a thin, deterministic wrapper over the daemon's
//! `sync_filesystem_with_graph` pass (the same disk-vs-graph content-hash diff
//! that runs at daemon startup). It adds/modifies/deletes graph entities to
//! match the on-disk working tree and leaves the vector index frozen: changed
//! entities are queued for the next embed pass, while unchanged entities keep
//! their existing vectors. Run `kin embed --max-seconds N` afterwards to embed
//! only the queued diff.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Request body for `POST /sync`.
///
/// The sync target is always the daemon's own working tree, so no parameters are
/// required. Kept as a named type so the wire shape stays an explicit `{}` and
/// can grow compatibly without breaking older callers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncRequest {}

/// Summary of a working-tree → graph reconcile (`POST /sync`).
///
/// Mirrors the deterministic add/modify/delete diff that
/// `sync_filesystem_with_graph` applied. The harness uses this to confirm that a
/// `git checkout` → `kin sync` step reconciled only the changed files and queued
/// only the changed entities for embedding (everything else keeps its vector).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncSummary {
    /// True when the sync applied at least one graph mutation.
    pub reconciled: bool,
    /// Entities added across all reconciled files.
    pub entities_added: usize,
    /// Entities modified across all reconciled files.
    pub entities_modified: usize,
    /// Entities deleted (from modified files and from removed files).
    pub entities_deleted: usize,
    /// Number of files whose on-disk content differed from the graph and were
    /// reconciled.
    pub files_changed: usize,
    /// Entities queued for embedding after the sync — the diff a subsequent
    /// `kin embed` pass will process. Reconcile auto-queues changed entities
    /// (`ChangedThisSync` recency); the vector index itself stays frozen until an
    /// embed pass runs, so unchanged entities keep their vectors.
    pub embed_queued: usize,
}

/// `kin sync` — POST the daemon `/sync` route for the current repo's working
/// tree and print the reconcile summary.
pub async fn run(json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let summary = run_daemon_sync(&layout).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if summary.reconciled {
        println!(
            "Reconciled {} file(s): +{} added, ~{} modified, -{} deleted entities. \
             {} entit{} queued for embedding (unchanged entities keep their vectors).",
            summary.files_changed,
            summary.entities_added,
            summary.entities_modified,
            summary.entities_deleted,
            summary.embed_queued,
            if summary.embed_queued == 1 { "y" } else { "ies" },
        );
    } else {
        println!("Already in sync: the working tree matches the graph (0 files changed).");
    }
    Ok(())
}

/// Resolve (auto-starting if needed) the repo daemon and POST `/sync`, exactly
/// like `kin embed`/`kin locate` resolve their daemon.
async fn run_daemon_sync(layout: &kin_core::KinLayout) -> Result<SyncSummary> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for sync but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .sync(&SyncRequest::default())
        .await
        .map_err(|e| anyhow::anyhow!("daemon sync failed: {e:#}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_request_serializes_to_empty_object() {
        // The harness lane depends on `{}` being the request body.
        assert_eq!(serde_json::to_string(&SyncRequest::default()).unwrap(), "{}");
    }

    #[test]
    fn sync_summary_round_trips_with_expected_fields() {
        let summary = SyncSummary {
            reconciled: true,
            entities_added: 3,
            entities_modified: 2,
            entities_deleted: 1,
            files_changed: 4,
            embed_queued: 5,
        };
        let json = serde_json::to_value(&summary).unwrap();
        for key in [
            "reconciled",
            "entities_added",
            "entities_modified",
            "entities_deleted",
            "files_changed",
            "embed_queued",
        ] {
            assert!(json.get(key).is_some(), "summary JSON is missing `{key}`");
        }
        let back: SyncSummary = serde_json::from_value(json).unwrap();
        assert!(back.reconciled);
        assert_eq!(back.entities_added, 3);
        assert_eq!(back.entities_modified, 2);
        assert_eq!(back.entities_deleted, 1);
        assert_eq!(back.files_changed, 4);
        assert_eq!(back.embed_queued, 5);
    }
}
