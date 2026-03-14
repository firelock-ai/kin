//! Backend dispatch for KuzuDB vs KinDB graph stores.
//!
//! Set `KIN_BACKEND=kindb` (or `kin-db`) to use KinDB instead of KuzuDB.

use std::path::PathBuf;

/// Which graph backend to use.
pub enum Backend {
    Kuzu,
    KinDb,
}

impl Backend {
    /// Determine the backend from the `KIN_BACKEND` environment variable.
    /// Defaults to `Kuzu` if unset or unrecognized.
    pub fn from_env() -> Self {
        match std::env::var("KIN_BACKEND").ok().as_deref() {
            Some("kindb") | Some("kin-db") | Some("KinDb") | Some("KinDB") => Backend::KinDb,
            _ => Backend::Kuzu,
        }
    }
}

/// Path where KinDB stores its snapshot file within a `.kin/` layout.
pub fn kindb_snapshot_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.root().join("kindb").join("graph.kndb")
}

/// Path where KinDB stores its vector embeddings within a `.kin/` layout.
pub fn kindb_vectors_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.root().join("kindb").join("vectors.json")
}

/// Open the appropriate graph backend and execute a closure with a reference.
///
/// The closure `$body` receives `$graph` bound to `&impl GraphStore`.
/// The macro monomorphizes the body for each backend so the concrete type
/// is known at compile time.
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
        match crate::backend::Backend::from_env() {
            crate::backend::Backend::Kuzu => {
                let _store =
                    kin_db::InMemoryGraph::open_read_only(&$layout.graph_dir())?;
                let $graph = &_store;
                $body
            }
            crate::backend::Backend::KinDb => {
                let _snap = kin_db::SnapshotManager::open(
                    crate::backend::kindb_snapshot_path(&$layout),
                )?;
                let _arc = _snap.graph();
                let $graph = &*_arc;
                $body
            }
        }
    }};
}

pub(crate) use with_read_store;
