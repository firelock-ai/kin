// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! KinDB graph backend — daemon-first, offline fallback.
//!
//! The primary entry point is [`open_snapshot_daemon_first`] which tries
//! the daemon's `/mcp/bootstrap` endpoint for a warm graph, then falls
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

/// Daemon-first graph open: tries the daemon's `/mcp/bootstrap` endpoint
/// for a warm, authoritative graph snapshot, then falls back to the local
/// snapshot when the daemon is unavailable or `KIN_OFFLINE` is set.
///
/// When the daemon is reachable the returned `SnapshotManager` holds:
///   - the daemon's live graph (swapped in via RCU)
///   - the local snapshot path + lock (so `.save()` still persists locally)
///
/// This makes every CLI command daemon-consistent without changing callers.
pub async fn open_snapshot_daemon_first(
    layout: &kin_core::KinLayout,
) -> std::result::Result<kin_db::SnapshotManager, kin_db::KinDbError> {
    // Respect explicit offline mode
    if std::env::var("KIN_OFFLINE").is_ok() {
        return open_kindb_snapshot(layout);
    }

    // Try daemon bootstrap
    match fetch_daemon_graph().await {
        Some(graph) => {
            let snap = open_kindb_snapshot(layout)?;
            snap.swap(graph);
            Ok(snap)
        }
        None => open_kindb_snapshot(layout),
    }
}

/// Fetch the graph from the daemon's `/mcp/bootstrap` endpoint.
/// Returns `None` if the daemon is unreachable or returns an error.
async fn fetch_daemon_graph() -> Option<kin_db::InMemoryGraph> {
    let base_url = std::env::var("KIN_DAEMON_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    let resp = client
        .get(format!("{}/mcp/bootstrap", base_url.trim_end_matches('/')))
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

/// Open the KinDB graph store and execute a closure with a reference.
///
/// Usage:
/// ```ignore
/// with_read_store!(layout, |graph| {
///     let entities = graph.list_all_entities()?;
///     Ok(())
/// })
/// ```
macro_rules! with_read_store {
    ($layout:expr, |$graph:ident| $body:expr) => {{
        let _snap = crate::backend::open_kindb_snapshot(&$layout)?;
        let _arc = _snap.graph();
        let $graph = &*_arc;
        $body
    }};
}

pub(crate) use with_read_store;
