// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_db::StorageBackend;
use kin_model::{EntityId, FilePathId, GraphOverlay, GraphStore, WorkingCopy};
use kin_projection::ProjectionState;
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::error::{DaemonError, Result};
use crate::session_registry::SessionCoordinator;

/// Reconciliation loop status values.
pub const RECON_IDLE: u8 = 0;
pub const RECON_PROCESSING: u8 = 1;

/// SSE invalidation events pushed to subscribers (VFS daemon, spine, KinLab).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum DaemonEvent {
    /// An entity was created, modified, or deleted.
    EntityChanged {
        entity_id: EntityId,
        change_type: ChangeType,
        file_path: Option<String>,
    },
    /// Files were added or removed from the tracked tree.
    TreeChanged {
        paths_added: Vec<String>,
        paths_removed: Vec<String>,
    },
    /// A session's overlay was updated.
    OverlayUpdated {
        session_id: String,
    },
    /// The graph root hash changed (commit happened).
    GraphRootChanged {
        old_root_hash: Option<String>,
        new_root_hash: String,
    },
}

/// Type of entity change for SSE events.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

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
    /// Broadcast channel for SSE invalidation events.
    /// Subscribers (VFS daemon, spine, KinLab) receive real-time notifications.
    pub event_tx: tokio::sync::broadcast::Sender<DaemonEvent>,
    /// Per-session overlay mutations. Each agent session gets its own overlay
    /// so uncommitted work is isolated. Read merge order:
    /// committed graph → global overlay (working_copy) → session overlay.
    pub session_overlays: RwLock<std::collections::HashMap<kin_model::SessionId, kin_model::GraphOverlay>>,
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
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
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
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Get or create a session-scoped overlay for the given session.
    pub async fn get_or_create_session_overlay(
        &self,
        session_id: &kin_model::SessionId,
    ) -> kin_model::GraphOverlay {
        let overlays = self.session_overlays.read().await;
        if let Some(overlay) = overlays.get(session_id) {
            return overlay.clone();
        }
        drop(overlays);
        let mut overlays = self.session_overlays.write().await;
        overlays
            .entry(session_id.clone())
            .or_insert_with(kin_model::GraphOverlay::default)
            .clone()
    }

    /// Update a session's overlay with new mutations.
    pub async fn update_session_overlay(
        &self,
        session_id: &kin_model::SessionId,
        overlay: kin_model::GraphOverlay,
    ) {
        let mut overlays = self.session_overlays.write().await;
        overlays.insert(session_id.clone(), overlay);
        self.emit_event(DaemonEvent::OverlayUpdated {
            session_id: session_id.to_string(),
        });
    }

    /// Drop a session's overlay (on session end or commit).
    pub async fn remove_session_overlay(&self, session_id: &kin_model::SessionId) {
        let mut overlays = self.session_overlays.write().await;
        overlays.remove(session_id);
    }

    /// Emit an SSE event to all subscribers. Non-blocking — if no subscribers, the event is dropped.
    pub fn emit_event(&self, event: DaemonEvent) {
        // broadcast::send returns Err if no receivers — that's fine, just means nobody's listening
        let _ = self.event_tx.send(event);
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
    /// Groups all entities by file, builds a FileLayout for each file
    /// (mapping entity IDs to byte ranges from their SourceSpan), reads
    /// the file content from the working directory, and registers each
    /// in ProjectionState. Called after graph init or commit.
    pub async fn rebuild_projection(&self) -> Result<()> {
        use kin_model::{EntityFilter, FileLayout, FilePathId, ImportSection, SourceRegion};
        use std::collections::HashMap;

        let mut projection = self.projection.write().await;
        *projection = ProjectionState::new();

        // Get all entities from the graph.
        let all_entities = self
            .graph
            .query_entities(&EntityFilter::default())
            .map_err(DaemonError::from)?;

        if all_entities.is_empty() {
            return Ok(());
        }

        // Group entities by file, keeping only those with spans.
        let mut by_file: HashMap<FilePathId, Vec<&kin_model::Entity>> = HashMap::new();
        for entity in &all_entities {
            if let (Some(file_id), Some(_span)) = (&entity.file_origin, &entity.span) {
                by_file.entry(FilePathId(file_id.0.clone())).or_default().push(entity);
            }
        }

        let working_dir = self.layout.working_dir();
        let mut registered = 0usize;

        for (file_id, mut entities) in by_file {
            // Sort entities by byte offset for correct region ordering.
            entities.sort_by_key(|e| e.span.as_ref().map(|s| s.start_byte).unwrap_or(0));

            // Build SourceRegion list with trivia gaps between entities.
            let file_path = working_dir.join(&file_id.0);
            let content = match std::fs::read(&file_path) {
                Ok(c) => c,
                Err(_) => {
                    // File may have been deleted or not yet materialized — skip.
                    continue;
                }
            };
            let file_len = content.len();

            let mut regions = Vec::new();
            let mut cursor = 0usize;

            for entity in &entities {
                let span = entity.span.as_ref().unwrap();
                let start = span.start_byte;
                let end = span.end_byte.min(file_len);

                // Trivia before this entity (whitespace, comments, etc.)
                if start > cursor {
                    regions.push(SourceRegion::Trivia {
                        byte_range: cursor..start,
                    });
                }

                // The entity itself.
                if start < end && end <= file_len {
                    regions.push(SourceRegion::EntityRef {
                        entity_id: entity.id,
                        byte_range: start..end,
                    });
                }

                cursor = end;
            }

            // Trailing trivia after last entity.
            if cursor < file_len {
                regions.push(SourceRegion::Trivia {
                    byte_range: cursor..file_len,
                });
            }

            let layout = FileLayout {
                file_id: file_id.clone(),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions,
            };

            projection.register_file(layout, content);
            registered += 1;
        }

        info!(files = registered, "rebuilt projection state from graph");
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
