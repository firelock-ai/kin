// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! KinDB graph backend.

use std::path::PathBuf;

/// Path where KinDB stores its snapshot file within a `.kin/` layout.
pub fn kindb_snapshot_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_snapshot_path()
}

/// Path where KinDB stores its vector embeddings within a `.kin/` layout.
pub fn kindb_vectors_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.root().join("kindb").join("vectors.json")
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
        let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&$layout))?;
        let _arc = _snap.graph();
        let $graph = &*_arc;
        $body
    }};
}

pub(crate) use with_read_store;
