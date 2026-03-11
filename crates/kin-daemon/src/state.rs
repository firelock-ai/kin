use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_graph::KuzuGraphStore;
use kin_model::{GraphOverlay, WorkingCopy};
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;

use crate::error::{DaemonError, Result};
use crate::session_registry::SessionCoordinator;

/// Shared daemon state. All mutable state is behind RwLock for
/// concurrent access from the reconciliation loop and API handlers.
pub struct DaemonState {
    pub layout: KinLayout,
    pub graph: Arc<KuzuGraphStore>,
    pub blobs: Arc<BlobStore>,
    pub working_copy: RwLock<WorkingCopy>,
    pub reconciler: RwLock<Reconciler>,
    /// Session and intent coordinator (Phase 7).
    pub coordinator: SessionCoordinator,
}

impl DaemonState {
    /// Open an existing .kin/ directory and create daemon state.
    pub fn open(layout: KinLayout) -> Result<Self> {
        let graph = KuzuGraphStore::open(layout.graph_dir()).map_err(DaemonError::from)?;
        let blobs = BlobStore::new(layout.objects_dir()).map_err(DaemonError::from)?;

        // Compute the deterministic genesis change ID.
        let genesis = kin_core::build_genesis_change();
        let working_copy = WorkingCopy {
            base_change: genesis.id,
            uncommitted_mutations: GraphOverlay::default(),
        };

        let reconciler = Reconciler::new(layout.working_dir().to_path_buf());

        let graph = Arc::new(graph);
        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        Ok(Self {
            layout,
            graph,
            blobs: Arc::new(blobs),
            working_copy: RwLock::new(working_copy),
            reconciler: RwLock::new(reconciler),
            coordinator,
        })
    }
}
