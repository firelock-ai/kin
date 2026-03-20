// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! KinDB graph backend.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const SNAPSHOT_OPEN_MAX_ATTEMPTS: usize = 6;
const SNAPSHOT_OPEN_INITIAL_DELAY_MS: u64 = 10;

/// Path where KinDB stores its snapshot file within a `.kin/` layout.
pub fn kindb_snapshot_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_snapshot_path()
}

/// Path where KinDB stores its vector embeddings within a `.kin/` layout.
pub fn kindb_vectors_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.root().join("kindb").join("vectors.json")
}

fn is_transient_lock_error(message: &str) -> bool {
    message.contains("another process may be using this database")
        || message.contains("Resource temporarily unavailable")
        || message.contains("failed to acquire exclusive lock")
}

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
                if attempts + 1 < SNAPSHOT_OPEN_MAX_ATTEMPTS && is_transient_lock_error(&message) =>
            {
                attempts += 1;
                thread::sleep(delay);
                delay = std::cmp::min(delay.saturating_mul(2), Duration::from_millis(100));
            }
            Err(err) => return Err(err),
        }
    }
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
