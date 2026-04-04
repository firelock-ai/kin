// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_db::StorageBackend;
use kin_model::{EntityId, EntityStore, GraphOverlay, WorkingCopy};
use kin_projection::ProjectionState;
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;
use tracing::info;

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

/// Request sent from the reconcile loop to the LSP enrichment worker.
#[derive(Debug)]
pub struct LspEnrichmentRequest {
    /// Path to the changed file.
    pub file_path: std::path::PathBuf,
    /// Entity IDs that were added or modified — only these get queried via LSP.
    pub changed_entity_ids: Vec<kin_model::EntityId>,
}

/// Messages sent to the LSP enrichment worker.
#[derive(Debug)]
pub enum LspEnrichmentMessage {
    /// Incremental: enrich only these specific changed entities.
    Incremental(LspEnrichmentRequest),
    /// Cold sweep: enrich ALL entities in the graph, file by file.
    /// Triggered after init/migrate/reconcile.
    Sweep,
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
    /// Cross-repo federation spine. Initialized lazily on first access via
    /// `ensure_spine()` to avoid blocking daemon startup.
    ///
    /// Uses the `SpineBackend` trait to abstract over storage:
    /// - `InMemorySpineBackend`: local dev / single daemon (default)
    /// - `FirestoreSpineBackend`: cloud / stateless daemon pool (when GOOGLE_CLOUD_PROJECT is set)
    pub spine: std::sync::OnceLock<Arc<dyn kin_spine::SpineBackend>>,
    /// Maps repo_id to a lazily-loaded graph. Graphs are loaded from the
    /// storage backend on first access. Only active when `storage_backend`
    /// is `Some` (cloud / multi-repo mode).
    pub repo_graphs: RwLock<HashMap<String, Arc<kin_db::InMemoryGraph>>>,
    /// Optional allowlist for cloud repo discovery. When present, only these
    /// repo IDs are visible through the multi-repo HTTP API.
    pub allowed_repo_ids: Option<HashSet<String>>,
    /// True when the in-memory graph has been mutated since the last save.
    /// The background persistence task checks this to decide when to flush.
    pub dirty: AtomicBool,
    /// When the last successful background save completed.
    pub last_save: std::sync::Mutex<Instant>,
    /// Channel for LSP enrichment messages (incremental or sweep).
    /// None if LSP enrichment is disabled (no servers found).
    pub lsp_enrichment_tx: Option<tokio::sync::mpsc::Sender<LspEnrichmentMessage>>,
}

impl DaemonState {
    fn spine_disabled() -> bool {
        std::env::var("KIN_DISABLE_SPINE")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    }

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
                    return Err(DaemonError::Io(std::io::Error::other(format!(
                        "failed to load persisted graph snapshot from {}: {}",
                        kndb_path.display(),
                        e
                    ))));
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

        let mut reconciler = Reconciler::new(layout.working_dir().to_path_buf());
        // Seed LKG from persisted graph so the first reconcile after daemon
        // startup only reports truly changed entities, not all of them.
        reconciler.seed_lkg_entities_from_graph(graph.as_ref());

        // Wire the traffic checker so reconcile mutations are gated by active
        // intents/leases. Without this, check_scopes() in the reconciler
        // returns empty warnings and all mutations proceed unchecked.
        let traffic_checker =
            crate::traffic_adapter::CoordinatorTrafficChecker::new(Arc::clone(&graph));
        reconciler.set_traffic_checker(Box::new(traffic_checker));

        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        // Register a daemon-system session so the reconcile loop's traffic
        // checks correctly exclude daemon-owned intents from blocking itself.
        let daemon_session_id = coordinator
            .register_session(
                "kin-daemon",
                "reconcile-loop",
                kin_model::session::SessionTransport::Cli,
                None,
                layout.working_dir().to_path_buf(),
                kin_model::session::SessionCapabilities::default(),
            )
            .unwrap_or_else(|e| {
                tracing::warn!("failed to register daemon session: {e}");
                kin_model::SessionId::new()
            });
        reconciler.set_session_id(daemon_session_id);

        // Resume from the last persisted VFS version so kin-vfs clients
        // don't see a reset after daemon restart.
        let persisted_vfs_version = Self::load_persisted_vfs_version(&layout);

        let state = Self {
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
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            last_save: std::sync::Mutex::new(Instant::now()),
            lsp_enrichment_tx: None,
        };
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
        let mut reconciler = Reconciler::new(layout.working_dir().to_path_buf());
        reconciler.seed_lkg_entities_from_graph(graph.as_ref());

        let traffic_checker =
            crate::traffic_adapter::CoordinatorTrafficChecker::new(Arc::clone(&graph));
        reconciler.set_traffic_checker(Box::new(traffic_checker));

        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        let daemon_session_id = coordinator
            .register_session(
                "kin-daemon",
                "reconcile-loop",
                kin_model::session::SessionTransport::Cli,
                None,
                layout.working_dir().to_path_buf(),
                kin_model::session::SessionCapabilities::default(),
            )
            .unwrap_or_else(|e| {
                tracing::warn!("failed to register daemon session: {e}");
                kin_model::SessionId::new()
            });
        reconciler.set_session_id(daemon_session_id);

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
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()), // populated below
            allowed_repo_ids,
            dirty: AtomicBool::new(false),
            last_save: std::sync::Mutex::new(Instant::now()),
            lsp_enrichment_tx: None,
        };

        // Pre-load repos into the map BEFORE any async context.
        // We use get_mut() since no one else has a reference yet.
        let graphs = state.repo_graphs.get_mut();
        graphs.insert(repo_id.to_string(), graph);

        Ok(state)
    }

    /// Returns a reference to the spine backend, if already initialized.
    /// Returns `None` until `ensure_spine()` has been called.
    pub fn spine(&self) -> Option<&dyn kin_spine::SpineBackend> {
        self.spine.get().map(|s| s.as_ref())
    }

    /// Lazily initialize the spine and return a reference to it.
    /// Returns `None` if spine is disabled via `KIN_DISABLE_SPINE`.
    pub fn ensure_spine(&self) -> Option<&dyn kin_spine::SpineBackend> {
        if Self::spine_disabled() {
            return None;
        }
        if self.spine.get().is_none() {
            self.initialize_spine_lazy();
        }
        self.spine.get().map(|s| s.as_ref())
    }

    /// Lazily initialize the spine from the loaded graph and global registry.
    /// Called by `ensure_spine()` on first access. Thread-safe via `OnceLock`.
    ///
    /// Backend selection:
    /// - If `GOOGLE_CLOUD_PROJECT` is set AND the `firestore` feature is enabled
    ///   on kin-spine: uses `FirestoreSpineBackend` (write-through to Firestore,
    ///   reads from local cache). This enables the stateless daemon pool.
    /// - Otherwise: uses `InMemorySpineBackend` (current behavior, no external deps).
    fn initialize_spine_lazy(&self) {
        let _ = self.spine.get_or_init(|| {
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
                        role: Some(e.role),
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
                    if repo_canonical == cwd_canonical
                        || cwd_canonical.starts_with(&repo_canonical)
                    {
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
                                        role: Some(e.role),
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

            info!("spine index initialized");
            backend
        });
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

    /// Persist the latest projection truth for a reconcile outcome into the graph
    /// before snapshot save so restart-time rebuild stays graph-backed.
    pub fn persist_projection_truth_from_reconcile(
        &self,
        reconciler: &Reconciler,
        outcome: &kin_reconcile::ReconcileOutcome,
    ) -> Result<()> {
        match outcome {
            kin_reconcile::ReconcileOutcome::Updated { file_id, .. } => {
                let layout = reconciler
                    .projection()
                    .get_layout(file_id)
                    .cloned()
                    .ok_or_else(|| {
                        DaemonError::Io(std::io::Error::other(format!(
                            "projection layout missing for {}",
                            file_id
                        )))
                    })?;
                let content = reconciler
                    .projection()
                    .get_content(file_id)
                    .ok_or_else(|| {
                        DaemonError::Io(std::io::Error::other(format!(
                            "projection content missing for {}",
                            file_id
                        )))
                    })?;
                self.graph
                    .upsert_file_layout(&layout)
                    .map_err(DaemonError::from)?;
                self.graph
                    .set_file_hash(&file_id.0, kin_blobs::digest_bytes(content));
            }
            kin_reconcile::ReconcileOutcome::FileRemoved { file_id, .. } => {
                self.graph
                    .delete_file_layout(file_id)
                    .map_err(DaemonError::from)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Bump the monotonic VFS version counter. Call after every graph mutation.
    ///
    /// Persists the new value to `.kin/vfs_version` so that the counter survives
    /// daemon restarts and kin-vfs clients don't see a reset to 0.
    /// Also marks the graph as dirty for background persistence.
    pub fn bump_version(&self) {
        let v = self.vfs_version.fetch_add(1, Ordering::SeqCst) + 1;
        self.mark_dirty();
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
            kin_db::SnapshotManager::save_graph(
                self.layout.kindb_snapshot_path(),
                self.graph.as_ref(),
            )
            .map_err(DaemonError::from)?;
            self.snapshot_generation
                .load(Ordering::SeqCst)
                .saturating_add(1)
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
        let index =
            kin_db::ReadIndex::from_graph(self.graph.as_ref()).map_err(DaemonError::from)?;
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
    /// Hydrates persisted file layouts from graph truth, falling back to
    /// span-based reconstruction only for older snapshots that do not yet
    /// persist layouts. Called after graph init or commit.
    pub async fn rebuild_projection(&self) -> Result<()> {
        let mut projection = self.projection.write().await;
        *projection = ProjectionState::from_graph(self.graph.as_ref(), self.blobs.as_ref())
            .map_err(DaemonError::from)?;
        let registered = projection.file_ids().len();

        info!(
            files = registered,
            "rebuilt projection state from persisted graph truth"
        );
        Ok(())
    }

    /// Mark the graph as dirty (mutated since last save).
    /// Called after any graph mutation. The background persistence task
    /// will flush to disk when it sees this flag.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Mark the graph as clean (just saved). Records the save timestamp.
    pub fn mark_clean(&self) {
        self.dirty.store(false, Ordering::SeqCst);
        if let Ok(mut last) = self.last_save.lock() {
            *last = Instant::now();
        }
    }

    /// Check if the graph has unsaved mutations.
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::SeqCst)
    }

    /// Duration since the last successful save.
    pub fn time_since_save(&self) -> Duration {
        self.last_save
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Queue changed entities for background LSP enrichment (non-blocking).
    /// No-op if LSP enrichment is not available.
    pub fn queue_lsp_enrichment(&self, request: LspEnrichmentRequest) {
        if let Some(ref tx) = self.lsp_enrichment_tx {
            // Try-send to avoid blocking the reconcile loop.
            // If the channel is full, skip this request — it'll be picked up next time.
            let _ = tx.try_send(LspEnrichmentMessage::Incremental(request));
        }
    }

    /// Queue a cold sweep that enriches ALL entities in the graph via LSP.
    /// Triggered after init/migrate/reconcile. No-op if LSP enrichment is not available.
    pub fn queue_lsp_sweep(&self) {
        if let Some(ref tx) = self.lsp_enrichment_tx {
            let _ = tx.try_send(LspEnrichmentMessage::Sweep);
        }
    }

    /// Return the current reconciliation status as a human-readable string.
    pub fn reconciliation_status_str(&self) -> &'static str {
        match self.reconciliation_status.load(Ordering::Relaxed) {
            RECON_PROCESSING => "processing",
            _ => "idle",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        FileLayout, FilePathId, GraphOverlay, ImportSection, ParseCompleteness, WorkingCopy,
    };
    use kin_reconcile::ReconcileOutcome;

    fn simple_layout(file_id: &FilePathId) -> FileLayout {
        FileLayout {
            file_id: file_id.clone(),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![],
        }
    }

    fn test_state(layout: KinLayout, working_dir: &std::path::Path) -> DaemonState {
        let graph = Arc::new(kin_db::InMemoryGraph::with_text_index(
            layout.text_index_dir(),
        ));
        let blobs = BlobStore::new(layout.objects_dir()).unwrap();
        let genesis = kin_core::build_genesis_change();
        let working_copy = WorkingCopy {
            base_change: genesis.id,
            uncommitted_mutations: GraphOverlay::default(),
        };
        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        DaemonState {
            layout,
            graph,
            blobs: Arc::new(blobs),
            working_copy: RwLock::new(working_copy),
            reconciler: RwLock::new(Reconciler::new(working_dir.to_path_buf())),
            projection: RwLock::new(ProjectionState::new()),
            coordinator,
            started_at: Instant::now(),
            is_initialized: AtomicBool::new(false),
            reconciliation_status: AtomicU8::new(RECON_IDLE),
            storage_backend: None,
            snapshot_generation: AtomicU64::new(0),
            vfs_version: AtomicU64::new(0),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            last_save: std::sync::Mutex::new(Instant::now()),
            lsp_enrichment_tx: None,
        }
    }

    #[test]
    fn persist_projection_truth_stores_layout_and_hash() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let mut reconciler = Reconciler::new(repo_dir.path().to_path_buf());
        let file_id = FilePathId::new("src/lib.rs");
        let content = b"fn persisted() {}\n".to_vec();

        reconciler
            .projection_mut()
            .register_file(simple_layout(&file_id), content.clone());

        state
            .persist_projection_truth_from_reconcile(
                &reconciler,
                &ReconcileOutcome::Updated {
                    file_id: file_id.clone(),
                    added: vec![],
                    modified: vec![],
                    removed: vec![],
                    collision_warnings: vec![],
                },
            )
            .unwrap();

        let persisted_layout = state.graph.get_file_layout(&file_id).unwrap().unwrap();
        assert_eq!(persisted_layout.file_id, file_id);
        assert_eq!(
            state.graph.get_file_hash(&file_id.0),
            Some(kin_blobs::digest_bytes(&content))
        );
    }

    #[test]
    fn open_fails_when_persisted_snapshot_is_corrupt() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        std::fs::write(layout.kindb_snapshot_path(), b"not-a-valid-kndb").unwrap();

        let err = match DaemonState::open(layout) {
            Ok(_) => panic!("expected corrupt snapshot open to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("failed to load persisted graph snapshot"));
        assert!(message.contains("graph.kndb"));
    }
}
