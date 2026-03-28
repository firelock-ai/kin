// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_db::StorageBackend;
use kin_model::{EntityId, EntityStore, GraphOverlay, WorkingCopy};
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
    OverlayUpdated { session_id: String },
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
    /// Monotonically increasing version counter for VFS cache invalidation.
    /// Incremented on every graph mutation (reconcile, commit, overlay update).
    /// Unlike entity_count, this never decreases on deletions.
    pub vfs_version: AtomicU64,
    /// Broadcast channel for SSE invalidation events.
    /// Subscribers (VFS daemon, spine, KinLab) receive real-time notifications.
    pub event_tx: tokio::sync::broadcast::Sender<DaemonEvent>,
    /// Per-session overlay mutations. Each agent session gets its own overlay
    /// so uncommitted work is isolated. Read merge order:
    /// committed graph → global overlay (working_copy) → session overlay.
    pub session_overlays:
        RwLock<std::collections::HashMap<kin_model::SessionId, kin_model::GraphOverlay>>,
    /// Cross-repo federation spine. Populated lazily when repos are registered
    /// with the spine service. `None` until the spine is activated.
    ///
    /// Uses the `SpineBackend` trait to abstract over storage:
    /// - `InMemorySpineBackend`: local dev / single daemon (default)
    /// - `FirestoreSpineBackend`: cloud / stateless daemon pool (when GOOGLE_CLOUD_PROJECT is set)
    pub spine: Option<Arc<dyn kin_spine::SpineBackend>>,
    /// Maps repo_id to a lazily-loaded graph. Graphs are loaded from the
    /// storage backend on first access. Only active when `storage_backend`
    /// is `Some` (cloud / multi-repo mode).
    pub repo_graphs: RwLock<HashMap<String, Arc<kin_db::InMemoryGraph>>>,
    /// Optional allowlist for cloud repo discovery. When present, only these
    /// repo IDs are visible through the multi-repo HTTP API.
    pub allowed_repo_ids: Option<HashSet<String>>,
}

impl DaemonState {
    /// Load the persisted VFS version counter from `.kin/vfs_version`.
    /// Returns 0 if the file doesn't exist or can't be parsed.
    fn load_persisted_vfs_version(layout: &KinLayout) -> u64 {
        let path = layout.root().join("vfs_version");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

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
        let text_index_path = layout.text_index_dir();
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
                    (
                        Arc::new(kin_db::InMemoryGraph::with_text_index(
                            text_index_path.clone(),
                        )),
                        false,
                    )
                }
            }
        } else {
            (
                Arc::new(kin_db::InMemoryGraph::with_text_index(
                    text_index_path.clone(),
                )),
                false,
            )
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

        // Resume from the last persisted VFS version so kin-vfs clients
        // don't see a reset after daemon restart.
        let persisted_vfs_version = Self::load_persisted_vfs_version(&layout);

        let mut state = Self {
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
            vfs_version: AtomicU64::new(persisted_vfs_version),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
            spine: None,
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
        };
        state.initialize_spine();
        Ok(state)
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
        allowed_repo_ids: Option<HashSet<String>>,
    ) -> Result<Self> {
        let text_index_path = layout.text_index_dir();
        let (graph, generation, loaded_snapshot) =
            match backend.load_snapshot(repo_id).map_err(DaemonError::from)? {
                Some((bytes, gen)) => {
                    let snapshot =
                        kin_db::GraphSnapshot::from_bytes(&bytes).map_err(DaemonError::from)?;
                    let g = kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        snapshot,
                        text_index_path.clone(),
                    );
                    info!(
                        repo_id,
                        generation = gen,
                        "loaded graph from storage backend"
                    );
                    (Arc::new(g), gen, true)
                }
                None => {
                    info!(repo_id, "no snapshot found, starting with empty graph");
                    // In cloud mode, an empty graph IS the valid initial state.
                    // Mark as initialized so the readiness probe passes.
                    (
                        Arc::new(kin_db::InMemoryGraph::with_text_index(
                            text_index_path.clone(),
                        )),
                        0,
                        true,
                    )
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

        let persisted_vfs_version = Self::load_persisted_vfs_version(&layout);

        let mut state = Self {
            layout,
            graph: Arc::clone(&graph),
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
            vfs_version: AtomicU64::new(persisted_vfs_version),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
            spine: None,
            repo_graphs: RwLock::new(HashMap::new()), // populated below
            allowed_repo_ids,
        };

        // Pre-load repos into the map BEFORE any async context.
        // We use get_mut() since no one else has a reference yet.
        let graphs = state.repo_graphs.get_mut();
        graphs.insert(repo_id.to_string(), graph);

        state.initialize_spine();
        Ok(state)
    }

    /// Returns a reference to the spine backend, if activated.
    pub fn spine(&self) -> Option<&dyn kin_spine::SpineBackend> {
        self.spine.as_ref().map(|s| s.as_ref())
    }

    /// Initialize the spine from the loaded graph and global registry.
    ///
    /// Backend selection:
    /// - If `GOOGLE_CLOUD_PROJECT` is set AND the `firestore` feature is enabled
    ///   on kin-spine: uses `FirestoreSpineBackend` (write-through to Firestore,
    ///   reads from local cache). This enables the stateless daemon pool.
    /// - Otherwise: uses `InMemorySpineBackend` (current behavior, no external deps).
    pub fn initialize_spine(&mut self) {
        let backend: Arc<dyn kin_spine::SpineBackend> = self.create_spine_backend();

        // Register the primary (this daemon's) repo.
        let repo_id = self
            .layout
            .root()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("default");

        if let Ok(entities) = self.graph.list_all_entities() {
            let entries: Vec<kin_spine::EntityEntry> = entities
                .iter()
                .map(|e| kin_spine::EntityEntry {
                    repo_id: repo_id.to_string(),
                    entity_id: e.id,
                    name: e.name.clone(),
                    kind: e.kind,
                    signature: e.signature.clone(),
                    fingerprint: e.fingerprint.clone(),
                    file_path: e.file_origin.as_ref().map(|f| f.0.clone()),
                })
                .collect();
            let root_hash = format!("init-{}", entities.len());
            backend.register_repo(repo_id, entries, &root_hash);
            info!(
                repo_id,
                entities = entities.len(),
                "registered primary repo in spine"
            );
        }

        // Register sibling repos from the global registry.
        if let Ok(registry) = kin_core::registry::KinRegistry::load() {
            let cwd_canonical = self
                .layout
                .root()
                .canonicalize()
                .unwrap_or_else(|_| self.layout.root().to_path_buf());

            for repo in &registry.repos {
                let repo_canonical = repo
                    .path
                    .canonicalize()
                    .unwrap_or_else(|_| repo.path.clone());
                if repo_canonical == cwd_canonical || cwd_canonical.starts_with(&repo_canonical) {
                    continue; // skip primary
                }

                let kndb_path = repo.path.join(".kin").join("kindb").join("graph.kndb");
                if !kndb_path.exists() {
                    continue;
                }

                let kndb_clone = kndb_path.clone();
                let sibling_id = repo.id.clone();
                let handle = std::thread::Builder::new()
                    .name(format!("spine-load-{}", repo.id))
                    .spawn(move || -> Option<kin_db::InMemoryGraph> {
                        let snap = kin_db::SnapshotManager::open(&kndb_clone).ok()?;
                        let arc = snap.graph();
                        drop(snap);
                        std::sync::Arc::try_unwrap(arc).ok()
                    });

                if let Ok(h) = handle {
                    if let Ok(Some(sibling_graph)) = h.join() {
                        if let Ok(entities) = sibling_graph.list_all_entities() {
                            let entries: Vec<kin_spine::EntityEntry> = entities
                                .iter()
                                .map(|e| kin_spine::EntityEntry {
                                    repo_id: sibling_id.clone(),
                                    entity_id: e.id,
                                    name: e.name.clone(),
                                    kind: e.kind,
                                    signature: e.signature.clone(),
                                    fingerprint: e.fingerprint.clone(),
                                    file_path: e.file_origin.as_ref().map(|f| f.0.clone()),
                                })
                                .collect();
                            let count = entries.len();
                            backend.register_repo(&sibling_id, entries, "");
                            info!(repo_id = %sibling_id, entities = count, "registered sibling in spine");
                        }
                    }
                }
            }
        }

        self.spine = Some(backend);
        info!("spine index initialized");
    }

    /// Create the appropriate spine backend based on environment.
    fn create_spine_backend(&self) -> Arc<dyn kin_spine::SpineBackend> {
        #[cfg(feature = "firestore")]
        {
            if let Ok(project_id) = std::env::var("GOOGLE_CLOUD_PROJECT") {
                let database_id = std::env::var("FIRESTORE_DATABASE_ID").ok();
                info!(
                    project = %project_id,
                    database = database_id.as_deref().unwrap_or("(default)"),
                    "using Firestore spine backend for stateless daemon pool"
                );
                let backend = kin_spine::FirestoreSpineBackend::new(project_id, database_id);
                // Hydrate cache from Firestore (best-effort on startup).
                if let Err(e) = backend.hydrate() {
                    warn!(error = %e, "Firestore hydration failed, starting with empty cache");
                }
                return Arc::new(backend);
            }
        }

        info!("using in-memory spine backend (local dev mode)");
        Arc::new(kin_spine::InMemorySpineBackend::new())
    }

    /// Load a repo's graph from the storage backend (synchronous).
    /// Used internally for pre-loading and by `get_repo_graph`.
    fn load_repo_graph(&self, repo_id: &str) -> Result<Arc<kin_db::InMemoryGraph>> {
        let Some(backend) = &self.storage_backend else {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "no storage backend configured for multi-repo mode".to_string(),
            )));
        };
        match backend.load_snapshot(repo_id).map_err(DaemonError::from)? {
            Some((bytes, gen)) => {
                let snapshot =
                    kin_db::GraphSnapshot::from_bytes(&bytes).map_err(DaemonError::from)?;
                let text_index_path = self.layout.text_index_dir();
                let graph = Arc::new(kin_db::InMemoryGraph::from_snapshot_with_text_index(
                    snapshot,
                    text_index_path,
                ));
                info!(
                    repo_id,
                    generation = gen,
                    "loaded repo graph from storage backend"
                );
                Ok(graph)
            }
            None => Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!("repo '{}' not found in storage", repo_id),
            ))),
        }
    }

    /// Get or lazy-load a repo's graph from the storage backend.
    ///
    /// Returns the cached graph if already loaded, otherwise loads from
    /// the storage backend and caches it. Only usable when a storage
    /// backend is configured (cloud / multi-repo mode).
    pub async fn get_repo_graph(&self, repo_id: &str) -> Result<Arc<kin_db::InMemoryGraph>> {
        if let Some(allowed_repo_ids) = &self.allowed_repo_ids {
            if !allowed_repo_ids.contains(repo_id) {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!("repo '{}' is not configured for this daemon", repo_id),
                )));
            }
        }
        // Fast path: check if already loaded.
        {
            let graphs = self.repo_graphs.read().await;
            if let Some(g) = graphs.get(repo_id) {
                return Ok(Arc::clone(g));
            }
        }
        // Slow path: load from backend.
        let graph = self.load_repo_graph(repo_id)?;
        let mut graphs = self.repo_graphs.write().await;
        // Double-check: another task may have loaded it while we were loading.
        graphs
            .entry(repo_id.to_string())
            .or_insert_with(|| Arc::clone(&graph));
        Ok(graph)
    }

    /// List repo IDs that are currently loaded in the multi-repo cache.
    pub async fn list_loaded_repos(&self) -> Vec<String> {
        let graphs = self.repo_graphs.read().await;
        graphs.keys().cloned().collect()
    }

    /// List all repos available in storage (GCS bucket listing).
    ///
    /// When a storage backend is configured, discovers repos directly from
    /// storage — no env vars needed. Falls back to loaded repo keys in
    /// local mode.
    pub fn list_available_repos(&self) -> Result<Vec<String>> {
        let mut repos = if let Some(backend) = &self.storage_backend {
            backend.list_repos().map_err(DaemonError::from)?
        } else {
            // Local mode: return the loaded repo_graphs keys.
            let graphs = self
                .repo_graphs
                .try_read()
                .map(|g| g.keys().cloned().collect())
                .unwrap_or_default();
            graphs
        };
        if let Some(allowed_repo_ids) = &self.allowed_repo_ids {
            repos.retain(|repo_id| allowed_repo_ids.contains(repo_id));
        }
        repos.sort();
        repos.dedup();
        Ok(repos)
    }

    /// Bump the monotonic VFS version counter. Call after every graph mutation.
    ///
    /// Persists the new value to `.kin/vfs_version` so that the counter survives
    /// daemon restarts and kin-vfs clients don't see a reset to 0.
    pub fn bump_version(&self) {
        let v = self.vfs_version.fetch_add(1, Ordering::SeqCst) + 1;
        // Persist asynchronously — don't block the mutation path.
        let path = self.layout.root().join("vfs_version");
        let _ = std::fs::write(&path, v.to_string());
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
        self.bump_version();
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
    ///
    /// After a successful save, writes the new generation number to
    /// `.kin/kindb/generation` so CLI and MCP processes can detect
    /// when their loaded snapshot is stale (P2-2.7).
    pub fn save_snapshot(&self) -> Result<()> {
        let repo_id = std::env::var("KIN_REPO_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                self.layout
                    .working_dir()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.to_string())
            })
            .unwrap_or_else(|| "default".to_string());

        let new_gen = if let Some(backend) = &self.storage_backend {
            let snapshot = self.graph.to_snapshot();
            let bytes = snapshot.to_bytes().map_err(DaemonError::from)?;
            let expected_gen = self.snapshot_generation.load(Ordering::SeqCst);

            backend
                .save_snapshot(&repo_id, &bytes, expected_gen)
                .map_err(DaemonError::from)?
        } else {
            kin_db::SnapshotManager::save_graph(self.layout.kindb_snapshot_path(), self.graph.as_ref())
                .map_err(DaemonError::from)?;
            self.snapshot_generation.load(Ordering::SeqCst).saturating_add(1)
        };

        self.snapshot_generation.store(new_gen, Ordering::SeqCst);

        // Write generation marker so CLI/MCP can detect stale snapshots.
        self.write_generation_marker(new_gen);
        self.save_read_index()?;

        info!(
            repo_id,
            generation = new_gen,
            "saved snapshot to storage backend"
        );
        Ok(())
    }

    fn save_read_index(&self) -> Result<()> {
        let index = kin_db::ReadIndex::from_graph(self.graph.as_ref()).map_err(DaemonError::from)?;
        let idx_path = self.layout.kindb_snapshot_path().with_extension("kidx");
        index.save(&idx_path).map_err(DaemonError::from)
    }

    /// Write the generation number to `.kin/kindb/generation`.
    ///
    /// CLI and MCP processes read this file before queries and compare it
    /// to their loaded generation. If different, they know the daemon has
    /// committed a newer snapshot and should reload.
    fn write_generation_marker(&self, generation: u64) {
        let gen_path = self.layout.root().join("kindb").join("generation");
        let _ = std::fs::write(&gen_path, generation.to_string());
    }

    /// Read the current snapshot generation from `.kin/kindb/generation`.
    ///
    /// Returns 0 if the file doesn't exist. CLI and MCP can call this
    /// before queries to check if the daemon has committed a newer snapshot
    /// than what they have loaded in memory.
    pub fn read_generation_marker(layout: &KinLayout) -> u64 {
        let gen_path = layout.root().join("kindb").join("generation");
        std::fs::read_to_string(&gen_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
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
                by_file
                    .entry(FilePathId(file_id.0.clone()))
                    .or_default()
                    .push(entity);
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
