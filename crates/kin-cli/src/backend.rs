// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! KinDB graph backend — daemon-first, offline fallback.
//!
//! The primary entry point is [`open_snapshot_daemon_first`] which tries
//! the daemon's `/graph/bootstrap` endpoint for a warm graph, then falls
//! back to the local snapshot when the daemon is unavailable.
//!
//! The synchronous [`open_kindb_snapshot`] is kept for daemon/runtime
//! internals and tests that cannot use the async runtime.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const SNAPSHOT_OPEN_MAX_ATTEMPTS: usize = 6;
const SNAPSHOT_OPEN_INITIAL_DELAY_MS: u64 = 10;

/// Path where KinDB stores its snapshot file within a `.kin/` layout.
pub fn kindb_snapshot_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_snapshot_path()
}

fn is_transient_lock_error(message: &str) -> bool {
    message.contains("another process may be using this database")
        || message.contains("Resource temporarily unavailable")
        || message.contains("failed to acquire exclusive lock")
}

/// Open a snapshot directly from disk. Used by daemon internals, tests,
/// and as the offline fallback in [`open_snapshot_daemon_first`].
pub fn open_kindb_snapshot(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let _span = tracing::info_span!(
        "kindb.open_snapshot",
        path = %kindb_snapshot_path(layout).display()
    )
    .entered();
    let path = kindb_snapshot_path(layout);
    let mut attempts = 0usize;
    let mut delay = Duration::from_millis(SNAPSHOT_OPEN_INITIAL_DELAY_MS);

    loop {
        match kin_db::SnapshotManager::open(&path) {
            Ok(snapshot) => return Ok(snapshot),
            Err(kin_db::KinDbError::LockError(message))
                if attempts + 1 < SNAPSHOT_OPEN_MAX_ATTEMPTS
                    && is_transient_lock_error(&message) =>
            {
                attempts += 1;
                thread::sleep(delay);
                delay = std::cmp::min(delay.saturating_mul(2), Duration::from_millis(100));
            }
            Err(err) => return Err(err),
        }
    }
}

/// Path where the HNSW vector index is stored alongside the graph snapshot.
pub fn vector_index_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_vector_index_path()
}

/// Daemon-first graph open: tries the daemon's `/graph/bootstrap` endpoint
/// for a warm, authoritative graph snapshot, then falls back to the local
/// snapshot when the daemon is unavailable or `KIN_OFFLINE` is set.
///
/// When the daemon is reachable the returned `SnapshotManager` holds:
///   - the daemon's live graph (swapped in via RCU)
///   - the local snapshot path + lock (so `.save()` still persists locally)
///
/// This makes every CLI command daemon-consistent without changing callers.
/// Also loads the HNSW vector index if it exists on disk, enabling semantic
/// search in `kin locate` and `kin search --semantic`.
pub async fn open_snapshot_daemon_first(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    let _span = tracing::info_span!(
        "kin.backend.open_snapshot_daemon_first",
        snapshot = %kindb_snapshot_path(layout).display()
    )
    .entered();
    // Respect explicit offline mode
    if std::env::var("KIN_OFFLINE").is_ok() {
        return open_kindb_snapshot(layout);
    }

    // Try daemon bootstrap
    match fetch_daemon_graph().await {
        Some(graph) => {
            let snap = open_kindb_snapshot(layout)?;
            snap.swap(graph);
            load_vector_index_if_exists(&snap, layout);
            Ok(snap)
        }
        None => open_kindb_snapshot(layout),
    }
}

/// Load the persisted HNSW vector index into the graph if available.
/// Non-fatal: if the file doesn't exist or fails to load, semantic search
/// gracefully returns empty results.
fn load_vector_index_if_exists(snap: &kin_db::SnapshotManager, layout: &kin_core::KinLayout) {
    let _span = tracing::info_span!(
        "kindb.load_vector_index_if_exists",
        path = %vector_index_path(layout).display()
    )
    .entered();
    let path = vector_index_path(layout);
    if path.exists() {
        let graph = snap.graph();
        match graph.load_vector_index(&path) {
            Ok(count) => {
                if count > 0 {
                    tracing::debug!(count, path = %path.display(), "loaded vector index from disk");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "failed to load vector index (non-fatal)");
            }
        }
    }
}

/// Fetch the graph from the daemon's `/graph/bootstrap` endpoint.
/// Returns `None` if the daemon is unreachable or returns an error.
async fn fetch_daemon_graph() -> Option<kin_db::InMemoryGraph> {
    let _span = tracing::info_span!("kin.backend.fetch_daemon_graph").entered();
    let base_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    let resp = client
        .get(format!(
            "{}/graph/bootstrap",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let bytes = resp.bytes().await.ok()?;
    let snapshot = kin_db::GraphSnapshot::from_bytes(&bytes).ok()?;
    Some(kin_db::InMemoryGraph::from_snapshot(snapshot))
}
