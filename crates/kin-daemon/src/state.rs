// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_db::StorageBackend;
use kin_model::{GraphOverlay, WorkingCopy};
use kin_projection::ProjectionState;
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
    /// Cached FileLayouts for all tracked files.
    /// Populated on init, updated on commits.
    pub projection: RwLock<ProjectionState>,
    /// Session and intent coordinator (Phase 7).
    pub coordinator: SessionCoordinator,
    /// When the daemon was started (for uptime reporting).
    pub started_at: Instant,
    /// Whether the daemon has been initialized (snapshot loaded or first reconciliation done).
    pub is_initialized: AtomicBool,
    /// Current reconciliation status (RECON_IDLE or RECON_PROCESSING).
    pub reconciliation_status: AtomicU8,
    /// Pluggable storage backend for snapshot persistence.
    /// `None` = legacy file-based path (via SnapshotManager).
    /// `Some` = StorageBackend (LocalFile for CLI, GCS for cloud).
    pub storage_backend: Option<Box<dyn StorageBackend>>,
    /// Generation from the last snapshot load (for CAS on save).
    pub snapshot_generation: AtomicU64,
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
            projection: RwLock::new(ProjectionState::new()),
            coordinator,
            started_at: Instant::now(),
            is_initialized: AtomicBool::new(loaded_snapshot),
            reconciliation_status: AtomicU8::new(RECON_IDLE),
            storage_backend: None,
            snapshot_generation: AtomicU64::new(0),
        })
    }

    /// Open with a pluggable storage backend (GCS, local files, etc.).
    ///
    /// Loads the graph from `backend.load_snapshot(repo_id)` instead of
    /// the local `.kin/kindb/graph.kndb` file. Used in cloud deployments
    /// where graph snapshots live in GCS.
    pub fn open_with_backend(
        layout: KinLayout,
        backend: Box<dyn StorageBackend>,
        repo_id: &str,
    ) -> Result<Self> {
        let (graph, generation, loaded_snapshot) =
            match backend.load_snapshot(repo_id).map_err(DaemonError::from)? {
                Some((bytes, gen)) => {
                    let snapshot = kin_db::GraphSnapshot::from_bytes(&bytes)
                        .map_err(DaemonError::from)?;
                    let g = kin_db::InMemoryGraph::from_snapshot(snapshot);
                    info!(repo_id, generation = gen, "loaded graph from storage backend");
                    (Arc::new(g), gen, true)
                }
                None => {
                    info!(repo_id, "no snapshot found, starting with empty graph");
                    (Arc::new(kin_db::InMemoryGraph::new()), 0, false)
                }
            };

        let blobs = BlobStore::new(layout.objects_dir()).map_err(DaemonError::from)?;
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
            projection: RwLock::new(ProjectionState::new()),
            coordinator,
            started_at: Instant::now(),
            is_initialized: AtomicBool::new(loaded_snapshot),
            reconciliation_status: AtomicU8::new(RECON_IDLE),
            storage_backend: Some(backend),
            snapshot_generation: AtomicU64::new(generation),
        })
    }

    /// Save the current graph via the storage backend (CAS write).
    ///
    /// Returns the new generation on success. Fails if another writer
    /// committed since our last load (generation mismatch).
    pub fn save_snapshot(&self, repo_id: &str) -> Result<()> {
        let Some(backend) = &self.storage_backend else {
            return Ok(()); // No backend — legacy file path handles its own saves
        };

        let snapshot = self.graph.to_snapshot();
        let bytes = snapshot.to_bytes().map_err(DaemonError::from)?;
        let expected_gen = self.snapshot_generation.load(Ordering::SeqCst);

        let new_gen = backend
            .save_snapshot(repo_id, &bytes, expected_gen)
            .map_err(DaemonError::from)?;

        self.snapshot_generation.store(new_gen, Ordering::SeqCst);
        info!(repo_id, generation = new_gen, "saved snapshot to storage backend");
        Ok(())
    }

    /// Rebuild projection state from the current graph.
    ///
    /// Reads all FileLayouts from the graph, loads their on-disk content,
    /// and registers each in ProjectionState. Called after graph init or commit.
    pub async fn rebuild_projection(&self) -> Result<()> {
        let mut projection = self.projection.write().await;
        // TODO: iterate tracked files from graph, build FileLayout for each,
        // read file content from working_dir, and call projection.register_file().
        // For now, start empty — populated when graph is loaded.
        *projection = ProjectionState::new();
        Ok(())
    }

    /// Return the current reconciliation status as a human-readable string.
    pub fn reconciliation_status_str(&self) -> &'static str {
        match self.reconciliation_status.load(Ordering::Relaxed) {
            RECON_PROCESSING => "processing",
            _ => "idle",
        }
    }
}
