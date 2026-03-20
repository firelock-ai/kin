// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_model::{GraphOverlay, WorkingCopy};
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::error::{DaemonError, Result};
use crate::session_registry::SessionCoordinator;

/// Reconciliation loop status values.
pub const RECON_IDLE: u8 = 0;
pub const RECON_PROCESSING: u8 = 1;

/// Shared daemon state. All mutable state is behind RwLock for
/// concurrent access from the reconciliation loop and API handlers.
pub struct DaemonState {
    pub layout: KinLayout,
    pub graph: Arc<kin_db::InMemoryGraph>,
    pub blobs: Arc<BlobStore>,
    pub working_copy: RwLock<WorkingCopy>,
    pub reconciler: RwLock<Reconciler>,
    /// Session and intent coordinator (Phase 7).
    pub coordinator: SessionCoordinator,
    /// When the daemon was started (for uptime reporting).
    pub started_at: Instant,
    /// Whether the daemon has been initialized (snapshot loaded or first reconciliation done).
    pub is_initialized: AtomicBool,
    /// Current reconciliation status (RECON_IDLE or RECON_PROCESSING).
    pub reconciliation_status: AtomicU8,
}

impl DaemonState {
    /// Look for the `.kin/kindb/graph.kndb` snapshot file in the workspace.
    fn find_kndb_path(layout: &KinLayout) -> Option<std::path::PathBuf> {
        let kndb_path = layout.kindb_snapshot_path();
        if kndb_path.exists() {
            Some(kndb_path)
        } else {
            None
        }
    }

    /// Open an existing .kin/ directory and create daemon state.
    pub fn open(layout: KinLayout) -> Result<Self> {
        let (graph, loaded_snapshot) = if let Some(kndb_path) = Self::find_kndb_path(&layout) {
            match kin_db::SnapshotManager::open(&kndb_path) {
                Ok(snapshot_mgr) => {
                    let g = snapshot_mgr.graph();
                    info!("Loaded graph from {}", kndb_path.display());
                    (g, true)
                }
                Err(e) => {
                    warn!(
                        "Failed to load graph from {}: {}, starting empty",
                        kndb_path.display(),
                        e
                    );
                    (Arc::new(kin_db::InMemoryGraph::new()), false)
                }
            }
        } else {
            (Arc::new(kin_db::InMemoryGraph::new()), false)
        };

        let blobs = BlobStore::new(layout.objects_dir()).map_err(DaemonError::from)?;

        // Compute the deterministic genesis change ID.
        let genesis = kin_core::build_genesis_change();
        let working_copy = WorkingCopy {
            base_change: genesis.id,
            uncommitted_mutations: GraphOverlay::default(),
        };

        let reconciler = Reconciler::new(layout.working_dir().to_path_buf());

        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        Ok(Self {
            layout,
            graph,
            blobs: Arc::new(blobs),
            working_copy: RwLock::new(working_copy),
            reconciler: RwLock::new(reconciler),
            coordinator,
            started_at: Instant::now(),
            is_initialized: AtomicBool::new(loaded_snapshot),
            reconciliation_status: AtomicU8::new(RECON_IDLE),
        })
    }

    /// Return the current reconciliation status as a human-readable string.
    pub fn reconciliation_status_str(&self) -> &'static str {
        match self.reconciliation_status.load(Ordering::Relaxed) {
            RECON_PROCESSING => "processing",
            _ => "idle",
        }
    }
}
