// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_db::StorageBackend;
use kin_model::{EntityId, EntityStore, FilePathId, GraphOverlay, WorkingCopy};
use kin_projection::ProjectionState;
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

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
        /// Originating session, when the change came from a request that carried
        /// one (the VFS `/vfs/file-changed` and `/vfs/write-notify` handlers).
        /// `None` for anonymous FS-reconcile-loop changes — never inferred by
        /// time-correlating `OverlayUpdated` with later events. Additive: `serde`
        /// default keeps existing payloads and consumers working unchanged.
        #[serde(default)]
        session_id: Option<String>,
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

#[derive(Debug, Default)]
pub struct ProjectionChangedSet {
    pub upserted: HashSet<FilePathId>,
    pub removed: HashSet<FilePathId>,
}

impl ProjectionChangedSet {
    pub fn is_empty(&self) -> bool {
        self.upserted.is_empty() && self.removed.is_empty()
    }

    pub fn record_reconcile_outcome(&mut self, outcome: &kin_reconcile::ReconcileOutcome) {
        match outcome {
            kin_reconcile::ReconcileOutcome::Updated { file_id, .. } => {
                self.upsert(file_id.clone());
            }
            kin_reconcile::ReconcileOutcome::FileRemoved { file_id, .. } => {
                self.remove(file_id.clone());
            }
            _ => {}
        }
    }

    pub fn upsert(&mut self, file_id: FilePathId) {
        self.removed.remove(&file_id);
        self.upserted.insert(file_id);
    }

    pub fn remove(&mut self, file_id: FilePathId) {
        self.upserted.remove(&file_id);
        self.removed.insert(file_id);
    }
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

/// Maximum number of concurrent temporal scopes before LRU eviction.
const MAX_CONCURRENT_SCOPES: usize = 5;

/// Default TTL for temporal scopes (30 minutes).
pub const DEFAULT_SCOPE_TTL: Duration = Duration::from_secs(30 * 60);

/// A temporal scope pins a session to a specific historical ref.
/// All queries for this session use the cached historical graph
/// instead of the live HEAD graph.
pub struct TemporalScope {
    /// Original ref string (e.g., "git:abc123", "main", "HEAD~5")
    pub ref_string: String,
    /// Resolved semantic change ID
    pub head: kin_model::SemanticChangeId,
    /// Cached reconstructed historical graph
    pub cached_graph: Arc<kin_db::InMemoryGraph>,
    /// When the scope was created
    pub created_at: Instant,
    /// Time-to-live — scope auto-expires after this duration
    pub ttl: Duration,
}

impl TemporalScope {
    /// Check whether this scope has expired.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
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
    /// Per-session temporal scopes. When a session has an active scope,
    /// all queries see the cached historical graph instead of the live graph.
    /// Max MAX_CONCURRENT_SCOPES sessions can have active scopes simultaneously.
    pub session_scopes: RwLock<HashMap<kin_model::SessionId, TemporalScope>>,
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
    /// Serializes explicit `/embed` requests with the background embedding
    /// worker so they cannot drain queues and mutate the vector index
    /// concurrently.
    pub embedding_work: Mutex<()>,
    /// Serializes the entire snapshot/index/vector save sequence so the
    /// persistence loop, idle-shutdown flush, and embedding worker can never
    /// interleave saves. Holding this across the kndb + kidx writes (and the
    /// embed worker's kvec write) keeps the on-disk trio from tearing when two
    /// writers fire at once. Held only for the synchronous save critical
    /// section — never across an `.await` or another lock.
    pub persist_lock: Mutex<()>,
    /// When the last successful background save completed.
    pub last_save: std::sync::Mutex<Instant>,
    /// When the graph was last mutated (`mark_dirty`). The background
    /// persistence task debounces its idle flush on this clock — quiet since
    /// the last MUTATION — which is distinct from `last_save` (how long dirty
    /// state has sat unpersisted, the periodic durability bound).
    pub last_mutation: std::sync::Mutex<Instant>,
    /// Number of daemon-side embed passes (`POST /embed`) currently in
    /// flight. While nonzero the background idle flush stays suppressed: the
    /// embed handler persists its own progress (pre-pass snapshot, per-batch
    /// kvec, post-pass snapshot), and a full-graph flush on every starved
    /// feed gap multiplies FS events that starve the feed further.
    pub active_embed_passes: AtomicU32,
    /// Last externally visible daemon activity, measured as milliseconds since
    /// `started_at`. Used by opt-in idle shutdown for CLI-autostarted daemons.
    pub last_activity_ms: AtomicU64,
    /// Number of API requests currently being handled.
    pub active_requests: AtomicU64,
    /// Channel for LSP enrichment messages (incremental or sweep).
    /// None if LSP enrichment is disabled (no servers found).
    pub lsp_enrichment_tx: Option<tokio::sync::mpsc::Sender<LspEnrichmentMessage>>,
    /// Cached SemanticChangeId → Git OID mapping for fast scope switching.
    /// Built lazily on first `set_scope` call, reused for subsequent calls.
    pub change_oid_cache: std::sync::RwLock<Option<kin_core::ChangeOidCache>>,
    /// Repo ID resolved once at construction. Cached to avoid re-reading
    /// `.kin/manifest.json` on every snapshot save — under high host
    /// concurrency those reads contend and surface as opaque "Core error"
    /// shutdown-save failures (SP-20).
    pub cached_repo_id: String,
    /// True when the daemon is shutting down.
    pub is_shutdown: AtomicBool,
    /// Entity count of the last graph snapshot successfully written to disk,
    /// seeded from the snapshot loaded at startup. The shutdown flush compares
    /// the live in-memory entity count against this baseline and refuses to
    /// overwrite a large on-disk snapshot with a drastically-collapsed in-memory
    /// graph (the graph-wipe-on-kill class — e.g. a transient empty/bare checkout
    /// reconciled as all-deleted). Keyed on the GRAPH, independent of the vector
    /// index, which self-heals on load. Updated after every successful save.
    pub persisted_entity_count: AtomicU64,
    /// True when the last filesystem-sync tick refused to apply its deletions
    /// because they would have wiped most of the graph-known files (a transient
    /// empty/incomplete checkout misread as "delete everything"). Surfaced as a
    /// daemon-health signal; cleared on the next tick whose deletions are within
    /// the anti-wipe threshold.
    pub mass_deletion_blocked: AtomicBool,
    /// True when the background embedding worker has permanently stopped (it
    /// exhausted its consecutive-panic budget). The graph/locate/reconcile
    /// surfaces keep serving — embeddings are a DERIVED index — but the vector
    /// index will not advance until the daemon restarts. Surfaced as a
    /// daemon-health signal so this degraded state is LOUD, never silent (the
    /// worker dying must NOT take the whole daemon down).
    pub embed_worker_failed: AtomicBool,
    /// Durable store for in-flight MCP transactions, keyed by transaction id.
    ///
    /// Each `/mcp/tools/call` rebuilds a fresh `SessionRegistry` for the request,
    /// so transaction state (begin → stage → validate → commit issued across
    /// separate HTTP calls) must live here to survive between calls; sessions and
    /// intents persist through the graph, but transactions have no graph backing.
    pub mcp_transactions: Mutex<HashMap<String, kin_mcp::McpTransaction>>,
}

/// Minimum baseline count before an anti-wipe guard can fire. Below this, the
/// set is small enough that a collapse is not catastrophic (and fresh-init /
/// tiny-repo states would false-positive).
pub(crate) const WIPE_GUARD_MIN_BASELINE: u64 = 16;

/// Shared anti-wipe predicate: does dropping from a `baseline` count to a
/// `current` count constitute a drastic collapse (more than ~75% vanished) that
/// a guard should refuse? Returns false for trivially small baselines. Kept pure
/// so the threshold is unit-testable, and shared by both the shutdown graph
/// flush (entity counts) and the fs-sync mass-deletion guard (file counts) so
/// the two stay consistent.
pub(crate) fn graph_collapse_is_wipe(current: u64, baseline: u64) -> bool {
    if baseline < WIPE_GUARD_MIN_BASELINE {
        return false;
    }
    current.saturating_mul(4) < baseline
}

impl DaemonState {
    /// Load a persisted vector-index sidecar into a graph that was NOT built
    /// through `SnapshotManager` (the storage-backend path uses
    /// `InMemoryGraph::from_snapshot_with_text_index`, which does not load the
    /// sidecar). Uses kin-db's sanctioned validated entry point, which checks the
    /// sidecar against the graph root hash + live embedder before installing —
    /// never a raw `load_vector_index`, which would install a stale-dimension
    /// index and trigger the embed-worker reset loop. Safely no-ops when there is
    /// no sidecar, a stale one, or no recorded root hash to validate against.
    ///
    /// The `SnapshotManager::open` / `open_read_only_for_locate` path already
    /// performs this validated load during construction, so it does not call this.
    fn load_validated_vector_index(layout: &KinLayout, graph: &kin_db::InMemoryGraph) {
        let snapshot_path = layout.kindb_snapshot_path();
        let expected_embedder_identity = kin_buildinfo::sha_with_dirty(kin_buildinfo::get());
        match kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
            graph,
            &snapshot_path,
            Some(expected_embedder_identity.as_str()),
        ) {
            Ok(true) => {
                debug!(path = %snapshot_path.display(), "loaded validated persisted vector index");
            }
            Ok(false) => {}
            Err(error) => {
                debug!(
                    error = %error,
                    path = %snapshot_path.display(),
                    "failed to load persisted vector index"
                );
            }
        }
    }

    fn spine_disabled() -> bool {
        std::env::var("KIN_DISABLE_SPINE")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    }

    fn locate_only_snapshot_mode() -> bool {
        std::env::var("KIN_DAEMON_LOCATE_ONLY")
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
        let locate_only = Self::locate_only_snapshot_mode();
        let (graph, loaded_snapshot) = if let Some(kndb_path) = Self::find_kndb_path(&layout) {
            let snapshot_mgr = if locate_only {
                kin_db::SnapshotManager::open_read_only_for_locate(&kndb_path)
            } else {
                kin_db::SnapshotManager::open(&kndb_path)
            };
            match snapshot_mgr {
                Ok(snapshot_mgr) => {
                    let g = snapshot_mgr.graph();
                    info!(
                        locate_only = locate_only,
                        "Loaded graph from {}",
                        kndb_path.display()
                    );
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
        // No post-open vector-index load here: `SnapshotManager::open` /
        // `open_read_only_for_locate` already performed the validated load during
        // graph construction. A raw force-load on top would re-install a stale
        // sidecar and trigger the embed-worker reset loop.

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

        let explicit_repo_id = std::env::var("KIN_REPO_ID").ok();
        let cached_repo_id =
            kin_core::manifest::resolve_repo_id(&layout, explicit_repo_id.as_deref())
                .map_err(DaemonError::from)?;

        // Baseline for the shutdown anti-wipe guard: the entity count loaded
        // from the on-disk snapshot. Read before `graph` is moved into the state.
        let loaded_entity_count = graph.entity_count();

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
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            last_activity_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            change_oid_cache: std::sync::RwLock::new(None),
            cached_repo_id,
            is_shutdown: AtomicBool::new(false),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
            embed_worker_failed: AtomicBool::new(false),
            mcp_transactions: Mutex::new(HashMap::new()),
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
        // The backend path builds the graph via `from_snapshot_with_text_index`,
        // which does NOT load the vector-index sidecar — do the validated load
        // here (no-ops if no/stale sidecar).
        Self::load_validated_vector_index(&layout, graph.as_ref());
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

        // Baseline for the shutdown anti-wipe guard (entity count loaded from
        // the backend snapshot).
        let loaded_entity_count = graph.entity_count();

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
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()), // populated below
            allowed_repo_ids,
            dirty: AtomicBool::new(false),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            last_activity_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            change_oid_cache: std::sync::RwLock::new(None),
            cached_repo_id: repo_id.to_string(),
            is_shutdown: AtomicBool::new(false),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
            embed_worker_failed: AtomicBool::new(false),
            mcp_transactions: Mutex::new(HashMap::new()),
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
                let root_hash = hex::encode(self.graph.compute_root_hash());
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

    /// Set a temporal scope for a session. If max concurrent scopes reached,
    /// evict the oldest expired scope, or the oldest scope overall.
    pub async fn set_session_scope(
        &self,
        session_id: &kin_model::SessionId,
        ref_string: String,
        head: kin_model::SemanticChangeId,
        cached_graph: Arc<kin_db::InMemoryGraph>,
    ) {
        let mut scopes = self.session_scopes.write().await;

        // Evict expired scopes first
        scopes.retain(|_, scope| !scope.is_expired());

        // If still at capacity and this is a new session, evict oldest
        if scopes.len() >= MAX_CONCURRENT_SCOPES && !scopes.contains_key(session_id) {
            if let Some(oldest_id) = scopes
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(id, _)| *id)
            {
                scopes.remove(&oldest_id);
                info!(evicted = %oldest_id, "evicted oldest scope to make room");
            }
        }

        scopes.insert(
            *session_id,
            TemporalScope {
                ref_string,
                head,
                cached_graph,
                created_at: Instant::now(),
                ttl: DEFAULT_SCOPE_TTL,
            },
        );
    }

    /// Clear a session's temporal scope.
    pub async fn clear_session_scope(&self, session_id: &kin_model::SessionId) {
        let mut scopes = self.session_scopes.write().await;
        scopes.remove(session_id);
    }

    /// Get the temporal scope for a session, if any and not expired.
    pub async fn get_session_scope(
        &self,
        session_id: &kin_model::SessionId,
    ) -> Option<(String, kin_model::SemanticChangeId, Instant, Duration)> {
        let scopes = self.session_scopes.read().await;
        scopes.get(session_id).and_then(|scope| {
            if scope.is_expired() {
                None
            } else {
                Some((
                    scope.ref_string.clone(),
                    scope.head,
                    scope.created_at,
                    scope.ttl,
                ))
            }
        })
    }

    /// Get the graph for a session: scoped historical graph if session has
    /// an active scope, otherwise the live HEAD graph.
    pub async fn graph_for_session(
        &self,
        session_id: &kin_model::SessionId,
    ) -> Arc<kin_db::InMemoryGraph> {
        let scopes = self.session_scopes.read().await;
        if let Some(scope) = scopes.get(session_id) {
            if !scope.is_expired() {
                return Arc::clone(&scope.cached_graph);
            }
        }
        Arc::clone(&self.graph)
    }

    /// Scoped graph for a WRITE (reconcile). Returns the session's private
    /// scoped graph ONLY if a live (non-expired) scope exists, refreshing its
    /// TTL so an in-use session cannot expire mid-task. Returns `None` when no
    /// live scope exists — callers MUST treat `None` as an error and MUST NOT
    /// fall back to the shared HEAD graph for a write. Falling back would leak
    /// one session's workspace edits into every other session's HEAD reads and
    /// silently diverge in-memory HEAD from the durable snapshot.
    pub async fn scoped_graph_for_write(
        &self,
        session_id: &kin_model::SessionId,
    ) -> Option<Arc<kin_db::InMemoryGraph>> {
        let mut scopes = self.session_scopes.write().await;
        scopes.retain(|_, scope| !scope.is_expired());
        let scope = scopes.get_mut(session_id)?;
        scope.created_at = Instant::now();
        Some(Arc::clone(&scope.cached_graph))
    }

    /// Resolve the graph for a request: scoped historical graph when the
    /// session has an active temporal scope, otherwise the live HEAD graph.
    /// When `session_id` is `None`, always returns HEAD.
    pub async fn graph_for_request(
        &self,
        session_id: Option<&kin_model::SessionId>,
    ) -> Arc<kin_db::InMemoryGraph> {
        match session_id {
            Some(sid) => self.graph_for_session(sid).await,
            None => Arc::clone(&self.graph),
        }
    }

    /// Emit an SSE event to all subscribers. Non-blocking — if no subscribers, the event is dropped.
    pub fn emit_event(&self, event: DaemonEvent) {
        match self.event_tx.send(event) {
            Ok(_) => {}
            Err(_) => {
                debug!("broadcast event dropped, no active subscribers");
            }
        }
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
        self.save_snapshot_impl(false)
    }

    pub fn save_snapshot_full(&self) -> Result<()> {
        self.save_snapshot_impl(true)
    }

    fn save_snapshot_impl(&self, force_full: bool) -> Result<()> {
        // Serialize the whole kndb + generation-marker + kidx write sequence
        // against any other save (persist loop, idle flush, embed worker).
        // Without this, two concurrent saves race on the shared tmp paths and
        // can leave a torn kndb/kidx pair. Held only for this synchronous body
        // (no `.await` inside), so a std Mutex is sound.
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| DaemonError::Io(std::io::Error::other("persist lock poisoned")))?;

        let repo_id = self.cached_repo_id.as_str();
        let expected_gen = self.snapshot_generation.load(Ordering::SeqCst);

        let new_gen = if let Some(backend) = &self.storage_backend {
            if force_full || self.graph.full_snapshot_required() {
                let (bytes, _) = self
                    .graph
                    .serialize_snapshot_borrowed()
                    .map_err(DaemonError::from)?;
                let generation = backend
                    .save_snapshot(repo_id, &bytes, expected_gen)
                    .map_err(DaemonError::from)?;
                backend.clear_deltas(repo_id).map_err(DaemonError::from)?;
                self.graph.clear_pending_delta();
                self.graph.clear_full_snapshot_required();
                generation
            } else if let Some(delta) = self.graph.pending_delta_snapshot(expected_gen) {
                let bytes = delta.to_bytes().map_err(DaemonError::from)?;
                let generation = backend
                    .save_delta(repo_id, &bytes, expected_gen)
                    .map_err(DaemonError::from)?;
                self.graph.clear_pending_delta();
                self.graph.flush_text_index().map_err(DaemonError::from)?;
                generation
            } else {
                self.graph.flush_text_index().map_err(DaemonError::from)?;
                expected_gen
            }
        } else if force_full {
            kin_db::SnapshotManager::save_graph(
                self.layout.kindb_snapshot_path(),
                self.graph.as_ref(),
            )
            .map_err(DaemonError::from)?;
            expected_gen.saturating_add(1)
        } else {
            kin_db::SnapshotManager::save_graph_delta(
                self.layout.kindb_snapshot_path(),
                self.graph.as_ref(),
                expected_gen,
            )
            .map_err(DaemonError::from)?
            .unwrap_or(expected_gen)
        };

        self.snapshot_generation.store(new_gen, Ordering::SeqCst);

        if new_gen != expected_gen || force_full {
            // Write generation marker so CLI/MCP can detect stale snapshots.
            self.write_generation_marker(new_gen);
            self.save_read_index()?;
        }

        // The on-disk snapshot now reflects the current graph; advance the
        // anti-wipe baseline so a later shutdown is measured against what was
        // actually persisted.
        self.record_persisted_entity_count();

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
        let tmp_path = gen_path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp_path, generation.to_string())
            .and_then(|_| std::fs::rename(&tmp_path, &gen_path))
        {
            warn!(error = %e, "failed to write generation marker");
        }
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
    /// Primary path: loads each persisted [`FileLayout`] and its blob-backed
    /// base content from graph truth via [`ProjectionState::from_graph`].
    ///
    /// Fallback path: if a file layout exists in the graph but its file hash
    /// has not yet been persisted (older snapshots from before FIR-929 started
    /// writing hashes), `from_graph` returns
    /// [`ProjectionError::BaseContentUnavailable`].  Rather than hard-failing
    /// and leaving the daemon unable to serve VFS reads or accept projected
    /// writes, the fallback iterates layouts individually: files whose hash IS
    /// present are loaded from blobs (graph-backed); files whose hash is absent
    /// are loaded from the working-directory copy on disk (migration-debt path).
    /// Files that are neither in blobs nor on disk are skipped with a warning.
    ///
    /// Called after graph init, snapshot load, or a write-notify reconcile.
    pub async fn rebuild_projection(&self) -> Result<()> {
        let mut projection = self.projection.write().await;

        // Fast path: all file hashes persisted — build directly from graph truth.
        match ProjectionState::from_graph(self.graph.as_ref(), self.blobs.as_ref()) {
            Ok(state) => {
                let registered = state.file_ids().len();
                *projection = state;
                info!(
                    files = registered,
                    "rebuilt projection state from persisted graph truth"
                );
                return Ok(());
            }
            Err(kin_projection::ProjectionError::BaseContentUnavailable { .. }) => {
                // Fall through to the per-file fallback below.
            }
            Err(e) => return Err(DaemonError::from(e)),
        }

        // Fallback path: some file hashes are absent (older snapshot).
        // Build the projection file-by-file, reading from disk when blobs lack
        // the content.  This is migration debt — once all snapshots are on the
        // FIR-929 schema (hashes always persisted) this path becomes unreachable.
        let layouts = self.graph.list_file_layouts().map_err(DaemonError::from)?;
        let mut new_projection = ProjectionState::new();
        let mut loaded = 0usize;
        let mut disk_fallback = 0usize;
        let mut skipped = 0usize;

        for layout in layouts {
            let file_id = layout.file_id.clone();

            // Try to load content from blobs (graph-backed, preferred).
            // InMemoryGraph::get_file_hash takes &str and returns Option<[u8; 32]>.
            let blob_content = self
                .graph
                .get_file_hash(&file_id.0)
                .and_then(|raw| self.blobs.read(&kin_blobs::Hash256::from_bytes(raw)).ok());

            if let Some(content) = blob_content {
                new_projection.register_file(layout, content);
                loaded += 1;
                continue;
            }

            // Blob not available: fall back to the on-disk working copy.
            let file_path = self.layout.working_dir().join(file_id.0.as_str());
            match std::fs::read(&file_path) {
                Ok(content) => {
                    new_projection.register_file(layout, content);
                    disk_fallback += 1;
                }
                Err(e) => {
                    // File is neither in blobs nor on disk (deleted, not yet
                    // checked out, etc.) — skip it rather than hard-failing.
                    warn!(
                        file = %file_id,
                        error = %e,
                        "FIR-904·4: skipping projection rebuild for file not in blobs or disk \
                         (migration-debt fallback)"
                    );
                    skipped += 1;
                }
            }
        }

        *projection = new_projection;
        info!(
            files = loaded + disk_fallback,
            graph_backed = loaded,
            disk_fallback = disk_fallback,
            skipped = skipped,
            "rebuilt projection state via per-file fallback (older snapshot without file hashes)"
        );
        Ok(())
    }

    /// Refresh projection state for a touched-file set.
    ///
    /// This is the warm path after reconcile/VFS writes: removed files are
    /// evicted from the projection cache, and added/modified files are loaded
    /// from graph-owned layout + blob content. Missing hashes retain the same
    /// per-file working-tree fallback used by `rebuild_projection`.
    pub async fn refresh_projection(&self, changed: &ProjectionChangedSet) -> Result<()> {
        if changed.is_empty() {
            return Ok(());
        }

        let mut projection = self.projection.write().await;
        let mut loaded = 0usize;
        let mut disk_fallback = 0usize;
        let mut removed = 0usize;
        let mut skipped = 0usize;

        for file_id in &changed.removed {
            projection.remove_file(file_id);
            removed += 1;
        }

        for file_id in &changed.upserted {
            let Some(layout) = self
                .graph
                .get_file_layout(file_id)
                .map_err(DaemonError::from)?
            else {
                projection.remove_file(file_id);
                skipped += 1;
                continue;
            };

            let blob_content = self
                .graph
                .get_file_hash(&file_id.0)
                .and_then(|raw| self.blobs.read(&kin_blobs::Hash256::from_bytes(raw)).ok());

            if let Some(content) = blob_content {
                projection.register_file(layout, content);
                loaded += 1;
                continue;
            }

            let file_path = self.layout.working_dir().join(file_id.0.as_str());
            match std::fs::read(&file_path) {
                Ok(content) => {
                    projection.register_file(layout, content);
                    disk_fallback += 1;
                }
                Err(e) => {
                    projection.remove_file(file_id);
                    warn!(
                        file = %file_id,
                        error = %e,
                        "skipping projection refresh for file not in blobs or disk"
                    );
                    skipped += 1;
                }
            }
        }

        info!(
            upserted = loaded + disk_fallback,
            graph_backed = loaded,
            disk_fallback,
            removed,
            skipped,
            "refreshed projection state for changed files"
        );
        Ok(())
    }

    /// Mark the graph as dirty (mutated since last save).
    /// Called after any graph mutation. The background persistence task
    /// will flush to disk when it sees this flag.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::SeqCst);
        if let Ok(mut last) = self.last_mutation.lock() {
            *last = Instant::now();
        }
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

    /// Whether persisting the current in-memory graph on shutdown would overwrite
    /// a substantially larger on-disk snapshot with a drastically-collapsed one.
    ///
    /// This is the GRAPH-level anti-wipe guard (mirrors loop_runner's
    /// mass-deletion principle): if the live entity count has collapsed to less
    /// than a quarter of the last persisted count, the in-memory graph is most
    /// likely the victim of a transient wipe (e.g. an empty/bare checkout
    /// reconciled as all-deleted) rather than a real edit, so the shutdown flush
    /// must be skipped. It is deliberately independent of the vector index: a
    /// stale kvec self-heals on load and is not a reason to block the graph flush.
    ///
    /// The asymmetry favors skipping: a false positive is cheap (the larger
    /// snapshot reloads and re-reconciles against the filesystem next startup),
    /// while a false negative is expensive (a full re-index/re-embed from an
    /// emptied graph).
    pub fn shutdown_flush_would_wipe_graph(&self) -> bool {
        graph_collapse_is_wipe(
            self.graph.entity_count() as u64,
            self.persisted_entity_count.load(Ordering::SeqCst),
        )
    }

    /// Record that the on-disk snapshot now holds the current graph's entity
    /// count. Called after every successful save so the anti-wipe baseline
    /// tracks what is actually persisted.
    pub fn record_persisted_entity_count(&self) {
        self.persisted_entity_count
            .store(self.graph.entity_count() as u64, Ordering::SeqCst);
    }

    /// True when the most recent filesystem-sync tick refused a mass deletion
    /// (its removals would have wiped most of the graph-known files). Surfaced
    /// as a daemon-health signal.
    pub fn is_mass_deletion_blocked(&self) -> bool {
        self.mass_deletion_blocked.load(Ordering::Relaxed)
    }

    /// Duration since the last successful save.
    pub fn time_since_save(&self) -> Duration {
        self.last_save
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Duration since the last graph mutation (`mark_dirty`).
    pub fn time_since_mutation(&self) -> Duration {
        self.last_mutation
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// True while at least one daemon-side embed pass is in flight.
    pub fn embed_pass_active(&self) -> bool {
        self.active_embed_passes.load(Ordering::SeqCst) > 0
    }

    /// Mark a daemon-side embed pass as in flight for the lifetime of the
    /// returned guard. Counter-based so overlapping callers compose; the
    /// guard decrements on drop, including error returns and panic unwinds
    /// out of the embed handler.
    pub fn begin_embed_pass(&self) -> EmbedPassGuard<'_> {
        self.active_embed_passes.fetch_add(1, Ordering::SeqCst);
        EmbedPassGuard(self)
    }

    /// Record externally visible daemon activity.
    pub fn touch_activity(&self) {
        let elapsed_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.last_activity_ms.store(elapsed_ms, Ordering::SeqCst);
    }

    /// Track the start of an API request.
    pub fn begin_request(&self) {
        self.active_requests.fetch_add(1, Ordering::SeqCst);
        self.touch_activity();
    }

    /// Track the end of an API request.
    pub fn end_request(&self) {
        self.touch_activity();
        let _ = self
            .active_requests
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_sub(1))
            });
    }

    /// Number of API requests currently in flight.
    pub fn active_request_count(&self) -> u64 {
        self.active_requests.load(Ordering::SeqCst)
    }

    /// Duration since the last recorded external activity.
    pub fn idle_duration(&self) -> Duration {
        let now_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let last_ms = self.last_activity_ms.load(Ordering::SeqCst);
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }

    /// Whether an agent/user session is currently active. The daemon's own
    /// reconcile-loop session is intentionally ignored.
    pub fn has_external_sessions(&self) -> bool {
        self.coordinator
            .list_sessions()
            .map(|sessions| {
                sessions
                    .iter()
                    .any(|session| session.vendor != "kin-daemon")
            })
            .unwrap_or(true)
    }

    /// Queue changed entities for background LSP enrichment (non-blocking).
    /// No-op if LSP enrichment is not available.
    pub fn queue_lsp_enrichment(&self, request: LspEnrichmentRequest) {
        if let Some(ref tx) = self.lsp_enrichment_tx {
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                tx.try_send(LspEnrichmentMessage::Incremental(request))
            {
                warn!("LSP enrichment channel full, incremental request dropped");
            }
        }
    }

    /// Queue a cold sweep that enriches ALL entities in the graph via LSP.
    /// Triggered after init/migrate/reconcile. No-op if LSP enrichment is not available.
    pub fn queue_lsp_sweep(&self) {
        if let Some(ref tx) = self.lsp_enrichment_tx {
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                tx.try_send(LspEnrichmentMessage::Sweep)
            {
                warn!("LSP enrichment channel full, sweep request dropped");
            }
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

/// RAII marker for an in-flight daemon-side embed pass. Decrements the pass
/// counter on drop so the background idle flush resumes even when the embed
/// handler exits early.
pub struct EmbedPassGuard<'a>(&'a DaemonState);

impl Drop for EmbedPassGuard<'_> {
    fn drop(&mut self) {
        self.0.active_embed_passes.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::VectorIndex;
    use kin_model::{
        Entity, EntityKind, EntityMetadata, FileLayout, FilePathId, FingerprintAlgorithm,
        GraphOverlay, Hash256, ImportSection, LanguageId, ParseCompleteness, SemanticFingerprint,
        Visibility, WorkingCopy,
    };
    use kin_reconcile::ReconcileOutcome;
    use serde_json::json;

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
        let loaded_entity_count = graph.entity_count();

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
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            last_activity_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            change_oid_cache: std::sync::RwLock::new(None),
            cached_repo_id: "test-repo".to_string(),
            is_shutdown: AtomicBool::new(false),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
            embed_worker_failed: AtomicBool::new(false),
            mcp_transactions: Mutex::new(HashMap::new()),
        }
    }

    fn test_entity(name: &str, file_path: &str) -> Entity {
        Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file_path)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn entity_changed_serializes_session_attribution() {
        // An attributed change carries the originating session on the SSE wire,
        // so Mission Control can render "<session> -> entity <id>".
        let event = DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Modified,
            file_path: Some("crates/kin-daemon/src/api.rs".to_string()),
            session_id: Some("mission-ctl-7".to_string()),
        };
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["type"], json!("EntityChanged"));
        assert_eq!(v["session_id"], json!("mission-ctl-7"));
    }

    #[test]
    fn entity_changed_anonymous_session_is_null() {
        // FS-reconcile changes have no owning agent: session_id renders null, which
        // Mission Control reads as "unattributed" (never a fabricated guess).
        let event = DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Created,
            file_path: Some("src/lib.rs".to_string()),
            session_id: None,
        };
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["session_id"], serde_json::Value::Null);
    }

    #[test]
    fn entity_changed_legacy_payload_without_session_defaults_to_none() {
        // Backward compatibility: a pre-attribution payload (no session_id field)
        // must still deserialize, defaulting session_id to None. This is the
        // `#[serde(default)]` additive contract the change relies on.
        let mut payload = serde_json::to_value(DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Modified,
            file_path: Some("api.rs".to_string()),
            session_id: Some("dropme".to_string()),
        })
        .unwrap();
        payload.as_object_mut().unwrap().remove("session_id");
        let event: DaemonEvent = serde_json::from_value(payload).unwrap();
        match event {
            DaemonEvent::EntityChanged { session_id, .. } => assert!(session_id.is_none()),
            other => panic!("expected EntityChanged, got {other:?}"),
        }
    }

    #[test]
    fn emit_event_delivers_session_attribution_to_subscriber() {
        // The real /events emit path: emit_event -> broadcast -> SSE subscriber.
        // An attributed event reaches a subscriber with its session intact.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let mut rx = state.event_tx.subscribe();
        state.emit_event(DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Modified,
            file_path: Some("crates/kin-daemon/src/api.rs".to_string()),
            session_id: Some("mission-ctl-7".to_string()),
        });
        match rx.try_recv().expect("event delivered to SSE subscriber") {
            DaemonEvent::EntityChanged { session_id, .. } => {
                assert_eq!(session_id.as_deref(), Some("mission-ctl-7"));
            }
            other => panic!("expected EntityChanged, got {other:?}"),
        }
    }

    #[test]
    fn embed_pass_guard_tracks_in_flight_passes() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        assert!(!state.embed_pass_active());

        let outer = state.begin_embed_pass();
        let inner = state.begin_embed_pass();
        assert!(state.embed_pass_active());

        drop(inner);
        assert!(
            state.embed_pass_active(),
            "outer pass still in flight after inner guard drops"
        );

        drop(outer);
        assert!(!state.embed_pass_active());
    }

    #[test]
    fn mark_dirty_advances_the_mutation_clock() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        std::thread::sleep(Duration::from_millis(25));
        assert!(state.time_since_mutation() >= Duration::from_millis(20));
        state.mark_dirty();
        assert!(state.time_since_mutation() < Duration::from_millis(20));
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

    #[test]
    fn open_rejects_stale_vector_index_sidecar() {
        // A persisted vector sidecar whose metadata root hash does NOT match the
        // graph must be REJECTED on open, not installed. Installing a stale-
        // dimension index is exactly what triggered the embed-worker reset loop;
        // `DaemonState::open` now relies solely on the validated load that
        // `SnapshotManager::open` performs during construction (no raw force-load
        // override). The embed worker rebuilds the index from the live embedder.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let snapshot_path = layout.kindb_snapshot_path();
        let vector_path = layout.kindb_vector_index_path();
        let metadata_path = vector_path.with_extension("kvec.meta.json");

        let mgr = kin_db::SnapshotManager::open(&snapshot_path).unwrap();
        let graph = mgr.graph();
        let entity = test_entity("vector_reader", "src/lib.rs");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        // Write a sidecar with a deliberately mismatched (stale) root hash.
        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        std::fs::write(
            &metadata_path,
            serde_json::to_vec(&json!({
                "version": 1,
                "graph_root_hash": hex::encode([42u8; 32]),
                "dimensions": 4,
                "indexed": 1
            }))
            .unwrap(),
        )
        .unwrap();
        drop(mgr);

        let state = DaemonState::open(layout).unwrap();
        assert_eq!(
            state.graph.embedding_status().indexed,
            0,
            "stale-root-hash vector sidecar must be rejected, not installed"
        );
    }

    fn make_scoped_graph_with_entity(name: &str, file_path: &str) -> Arc<kin_db::InMemoryGraph> {
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        graph.upsert_entity(&test_entity(name, file_path)).unwrap();
        graph
    }

    #[tokio::test]
    async fn graph_for_request_returns_head_when_session_is_none() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let resolved = state.graph_for_request(None).await;
        assert!(Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn graph_for_request_returns_head_when_session_has_no_scope() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let session_id = kin_model::SessionId::new();
        let resolved = state.graph_for_request(Some(&session_id)).await;
        assert!(Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn graph_for_request_returns_scoped_graph_when_session_has_active_scope() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // Plant a different entity in HEAD vs. the scoped historical graph
        // so we can detect which graph routing returned.
        state
            .graph
            .upsert_entity(&test_entity("head_only_fn", "src/head.rs"))
            .unwrap();
        let scoped_graph = make_scoped_graph_with_entity("historical_fn", "src/old.rs");

        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([7; 32]));
        state
            .set_session_scope(
                &session_id,
                "git:abc123".to_string(),
                head,
                Arc::clone(&scoped_graph),
            )
            .await;

        let resolved = state.graph_for_request(Some(&session_id)).await;
        // Routed graph must be the scoped one, not HEAD.
        assert!(Arc::ptr_eq(&resolved, &scoped_graph));
        assert!(!Arc::ptr_eq(&resolved, &state.graph));

        // And the routed graph must see historical entities and NOT HEAD-only ones.
        let entities = resolved.list_all_entities().unwrap();
        assert!(
            entities.iter().any(|e| e.name == "historical_fn"),
            "scoped graph should expose historical entity"
        );
        assert!(
            entities.iter().all(|e| e.name != "head_only_fn"),
            "scoped graph must not leak HEAD-only entity"
        );
    }

    #[tokio::test]
    async fn graph_for_request_falls_back_to_head_after_scope_cleared() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let scoped_graph = make_scoped_graph_with_entity("historical_fn", "src/old.rs");
        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([9; 32]));
        state
            .set_session_scope(
                &session_id,
                "git:def456".to_string(),
                head,
                Arc::clone(&scoped_graph),
            )
            .await;
        state.clear_session_scope(&session_id).await;

        let resolved = state.graph_for_request(Some(&session_id)).await;
        assert!(Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn touch_activity_resets_idle_clock() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // `last_activity_ms` is seeded to 0, so before any activity the idle
        // clock counts from `started_at`. Let real time pass, then confirm the
        // idle duration has grown.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let before = state.idle_duration();
        assert!(
            before >= Duration::from_millis(20),
            "idle clock should count from startup until first activity, got {before:?}"
        );

        // The idle monitor calls touch_activity() when it starts so the idle
        // window begins from readiness, not process construction. Confirm the
        // clock resets back toward zero.
        state.touch_activity();
        let after = state.idle_duration();
        assert!(
            after < before,
            "touch_activity must reset the idle clock: before={before:?} after={after:?}"
        );
    }

    #[tokio::test]
    async fn scoped_graph_for_write_returns_none_without_scope() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let session_id = kin_model::SessionId::new();
        // No scope was ever opened for this session: a write must NOT silently
        // fall back to the shared HEAD graph.
        assert!(state.scoped_graph_for_write(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn scoped_graph_for_write_returns_private_scope_not_head() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        state
            .graph
            .upsert_entity(&test_entity("head_only_fn", "src/head.rs"))
            .unwrap();
        let scoped_graph = make_scoped_graph_with_entity("scoped_fn", "src/scoped.rs");

        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([3; 32]));
        state
            .set_session_scope(
                &session_id,
                "git:abc123".to_string(),
                head,
                Arc::clone(&scoped_graph),
            )
            .await;

        let resolved = state
            .scoped_graph_for_write(&session_id)
            .await
            .expect("live scope should yield a write graph");
        // Must be the session's private scoped graph, never the shared HEAD.
        assert!(Arc::ptr_eq(&resolved, &scoped_graph));
        assert!(!Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn scoped_graph_for_write_returns_none_when_scope_expired() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let scoped_graph = make_scoped_graph_with_entity("scoped_fn", "src/scoped.rs");
        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([4; 32]));
        {
            let mut scopes = state.session_scopes.write().await;
            scopes.insert(
                session_id,
                TemporalScope {
                    ref_string: "git:abc123".to_string(),
                    head,
                    cached_graph: Arc::clone(&scoped_graph),
                    // Already expired: created in the past with a zero TTL.
                    created_at: Instant::now() - Duration::from_secs(60),
                    ttl: Duration::from_secs(0),
                },
            );
        }

        // An expired scope is not a live scope; a write must not fall through
        // to HEAD just because a stale entry lingers in the map.
        assert!(state.scoped_graph_for_write(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn scoped_graph_for_write_refreshes_ttl() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let scoped_graph = make_scoped_graph_with_entity("scoped_fn", "src/scoped.rs");
        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([5; 32]));
        // Plant a scope with a short TTL whose deadline is close.
        {
            let mut scopes = state.session_scopes.write().await;
            scopes.insert(
                session_id,
                TemporalScope {
                    ref_string: "git:abc123".to_string(),
                    head,
                    cached_graph: Arc::clone(&scoped_graph),
                    created_at: Instant::now() - Duration::from_millis(80),
                    ttl: Duration::from_millis(100),
                },
            );
        }

        // First write succeeds AND slides the TTL window (created_at reset).
        assert!(state.scoped_graph_for_write(&session_id).await.is_some());

        // Sleep past the ORIGINAL deadline. Without the TTL slide the scope
        // would now be expired; with it, the scope is still live.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            state.scoped_graph_for_write(&session_id).await.is_some(),
            "in-use scope must not expire mid-task; TTL should slide on each write"
        );
    }

    #[test]
    fn persist_lock_serializes_concurrent_saves() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        state
            .graph
            .upsert_entity(&test_entity("locked_fn", "src/lib.rs"))
            .unwrap();

        // Hold the persist lock to mimic an in-flight save, then launch a
        // second save on another thread. It must NOT complete until we release
        // the guard — proving the two saves can never interleave.
        let guard = state.persist_lock.lock().unwrap();
        let completed = Arc::new(AtomicBool::new(false));

        let saver_state = Arc::clone(&state);
        let saver_completed = Arc::clone(&completed);
        let handle = std::thread::spawn(move || {
            saver_state.save_snapshot().unwrap();
            saver_completed.store(true, Ordering::SeqCst);
        });

        // Give the spawned save ample time to run if it were NOT blocked.
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !completed.load(Ordering::SeqCst),
            "save_snapshot must block while the persist lock is held"
        );

        // Release the lock; the blocked save now proceeds to completion.
        drop(guard);
        handle.join().unwrap();
        assert!(
            completed.load(Ordering::SeqCst),
            "save_snapshot must complete once the persist lock is released"
        );
    }

    #[test]
    fn sequential_saves_leave_consistent_kndb_kidx_pair() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let kndb_path = init.layout.kindb_snapshot_path();
        let kidx_path = kndb_path.with_extension("kidx");
        let state = test_state(init.layout, repo_dir.path());
        state
            .graph
            .upsert_entity(&test_entity("paired_fn", "src/lib.rs"))
            .unwrap();

        // Two back-to-back saves (as the persist loop + flush would issue) must
        // each leave both halves of the on-disk pair present and reloadable —
        // no torn kndb without its kidx, and no kidx without its kndb.
        state.save_snapshot().unwrap();
        state.save_snapshot().unwrap();

        assert!(kndb_path.exists(), "graph.kndb must exist after save");
        assert!(kidx_path.exists(), "graph.kidx must exist after save");

        // The kndb must reload as a valid snapshot exposing the saved entity.
        let mgr = kin_db::SnapshotManager::open(&kndb_path).unwrap();
        let reloaded = mgr.graph();
        let entities = reloaded.list_all_entities().unwrap();
        assert!(
            entities.iter().any(|e| e.name == "paired_fn"),
            "reloaded snapshot must contain the saved entity"
        );
    }

    #[test]
    fn graph_collapse_is_wipe_threshold() {
        // Below the min baseline: never a wipe, even at total collapse.
        assert!(!graph_collapse_is_wipe(0, WIPE_GUARD_MIN_BASELINE - 1));
        // At/above baseline with a >75% collapse → wipe.
        assert!(graph_collapse_is_wipe(0, 1000)); // total wipe
        assert!(graph_collapse_is_wipe(100, 1000)); // 90% gone
        assert!(graph_collapse_is_wipe(249, 1000)); // just over 75% gone (249*4=996<1000)
                                                    // Exactly a quarter remaining is NOT a wipe (250*4=1000, not < 1000).
        assert!(!graph_collapse_is_wipe(250, 1000));
        // Growth or steady state is never a wipe.
        assert!(!graph_collapse_is_wipe(1000, 1000));
        assert!(!graph_collapse_is_wipe(2000, 1000));
    }

    #[tokio::test]
    async fn shutdown_wipe_guard_blocks_drastic_graph_collapse() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // Populate a non-trivial graph and record it as the persisted baseline.
        for i in 0..20 {
            state
                .graph
                .upsert_entity(&test_entity(&format!("fn_{i}"), &format!("src/f{i}.rs")))
                .unwrap();
        }
        let n = state.graph.entity_count() as u64;
        assert!(
            n >= WIPE_GUARD_MIN_BASELINE,
            "test needs a non-trivial graph (got {n})"
        );
        state.record_persisted_entity_count();
        assert_eq!(state.persisted_entity_count.load(Ordering::SeqCst), n);

        // current == baseline → no collapse, flush allowed.
        assert!(!state.shutdown_flush_would_wipe_graph());

        // A much larger prior on-disk snapshot vs the live graph (>75% collapse)
        // → guard fires and the flush is skipped.
        state.persisted_entity_count.store(n * 5, Ordering::SeqCst);
        assert!(state.shutdown_flush_would_wipe_graph());

        // A moderate drop (50%) is a legitimate edit, NOT a wipe.
        state.persisted_entity_count.store(n * 2, Ordering::SeqCst);
        assert!(!state.shutdown_flush_would_wipe_graph());
    }
}
