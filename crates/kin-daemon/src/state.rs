// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kin_blobs::BlobStore;
use kin_core::KinLayout;
use kin_db::StorageBackend;
use kin_model::{
    EntityId, EntityStore, FilePathId, GraphOverlay, Hash256, SemanticChangeId, WorkingCopy,
};
use kin_projection::ProjectionState;
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::{DaemonError, Result};
use crate::session_registry::SessionCoordinator;

/// Reconciliation loop status values.
pub const RECON_IDLE: u8 = 0;
pub const RECON_PROCESSING: u8 = 1;

/// On-disk home for in-flight MCP transactions.
///
/// Lives under `.kin/` (not the working tree), so it is never reconciled or
/// committed. The in-memory `DaemonState::mcp_transactions` is the live copy;
/// this file is its durable mirror so a daemon restart mid-transaction does not
/// silently drop staged-but-uncommitted work — stdio-MCP and HTTP-MCP then
/// behave identically across a restart, not just across HTTP calls.
pub(crate) fn mcp_transactions_disk_path(layout: &KinLayout) -> std::path::PathBuf {
    layout.root().join("mcp_transactions.json")
}

/// Load persisted in-flight MCP transactions on daemon startup. A missing file
/// (clean start) or an unreadable/corrupt one yields an empty set — startup must
/// never fail on transaction-state recovery — but corruption is surfaced loudly
/// in the log so the loss is never silent.
pub(crate) fn load_persisted_mcp_transactions(
    layout: &KinLayout,
) -> HashMap<String, kin_mcp::McpTransaction> {
    let path = mcp_transactions_disk_path(layout);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(err) => {
            warn!(path = %path.display(), error = %err, "failed to read persisted MCP transactions; starting with none");
            return HashMap::new();
        }
    };
    match serde_json::from_slice::<HashMap<String, kin_mcp::McpTransaction>>(&bytes) {
        Ok(store) => {
            if !store.is_empty() {
                info!(
                    count = store.len(),
                    "restored in-flight MCP transactions from disk across daemon restart"
                );
            }
            store
        }
        Err(err) => {
            warn!(path = %path.display(), error = %err, "persisted MCP transactions are corrupt; starting with none");
            HashMap::new()
        }
    }
}

/// Durably mirror the in-memory MCP transaction store to disk. Writes via a
/// temp file + atomic rename so a crash mid-write can never leave a torn file.
/// Best-effort: a write failure is logged, never propagated — the in-memory
/// store remains authoritative for the running daemon.
pub(crate) fn write_persisted_mcp_transactions(
    layout: &KinLayout,
    store: &HashMap<String, kin_mcp::McpTransaction>,
) {
    let path = mcp_transactions_disk_path(layout);
    let bytes = match serde_json::to_vec(store) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(error = %err, "failed to serialize MCP transactions for durable persistence");
            return;
        }
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(err) = std::fs::write(&tmp, &bytes) {
        warn!(path = %tmp.display(), error = %err, "failed to write MCP transactions temp file");
        return;
    }
    if let Err(err) = std::fs::rename(&tmp, &path) {
        warn!(path = %path.display(), error = %err, "failed to commit MCP transactions file");
        let _ = std::fs::remove_file(&tmp);
    }
}

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

/// Outcome of ingesting one repo's graph into the spine from durable storage.
///
/// Returned by [`DaemonState::ingest_repo_into_spine`] and surfaced by the
/// `POST /spine/repos/{repo_id}/ingest` route so the hosted control plane can
/// gate the cross-repo org graph on real, graph-derived counts.
#[derive(Debug, Clone)]
pub struct SpineIngestOutcome {
    /// The repo that was ingested.
    pub repo_id: String,
    /// Graph root hash of the ingested snapshot (cache-coherence key).
    pub root_hash: String,
    /// Entities registered into the spine for this repo.
    pub entity_count: usize,
    /// `Calls`/`References` relations scanned for cross-repo candidates.
    pub relation_count: usize,
    /// Relations the cross-repo resolver can bind into xref edges (out-of-repo
    /// target carrying an `import_source` + imported-symbol token). The org
    /// graph's real cross-repo edges come from these.
    pub resolvable_relations: usize,
}

/// Outcome of refreshing cross-repo edges across every registered repo.
///
/// Returned by [`DaemonState::refresh_all_cross_repo_edges`] and surfaced by the
/// `POST /spine/refresh-cross-repo-edges` route. The hosted import orchestrator
/// runs this final pass once every repo is registered so cross-repo edges
/// emanate from every repo (kin-db→kin-search, kin-model→kin-vector, …), not
/// only the anchor.
#[derive(Debug, Clone)]
pub struct SpineRefreshOutcome {
    /// Repos whose outgoing cross-repo edges were re-resolved.
    pub repos_refreshed: usize,
    /// Total cross-repo edges in the spine after the refresh pass.
    pub cross_repo_edges: usize,
}

/// Exact graph identity for a materialized committed VFS tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VfsTreeCacheKey {
    pub head: Option<SemanticChangeId>,
    pub version: u64,
}

/// Graph-derived file tree and timestamps shared by the VFS endpoints.
#[derive(Debug)]
pub(crate) struct VfsTreeSnapshot {
    pub key: VfsTreeCacheKey,
    pub files: Arc<HashMap<FilePathId, Hash256>>,
    pub timestamps: Arc<HashMap<FilePathId, u64>>,
}

/// One detached graph mutation batch that has not yet been acknowledged by
/// durable backend authority. Dropping the guard before `complete` forces the
/// next save through a full snapshot, so an error cannot silently discard the
/// batch while mutations arriving during backend I/O remain independently
/// pending.
struct GraphPersistenceAttempt<'a> {
    graph: &'a kin_db::InMemoryGraph,
    epoch: Option<kin_db::PersistenceEpoch>,
}

impl<'a> GraphPersistenceAttempt<'a> {
    fn new(graph: &'a kin_db::InMemoryGraph, epoch: kin_db::PersistenceEpoch) -> Self {
        Self {
            graph,
            epoch: Some(epoch),
        }
    }

    fn complete(mut self) {
        if let Some(epoch) = self.epoch.take() {
            let completed = self.graph.complete_persistence(epoch);
            debug_assert!(completed, "persistence epoch must still be in flight");
        }
    }
}

impl Drop for GraphPersistenceAttempt<'_> {
    fn drop(&mut self) {
        if let Some(epoch) = self.epoch.take() {
            self.graph.fail_persistence(epoch);
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct VfsTreeBuildTestHook {
    pub materialized: Arc<std::sync::Barrier>,
    pub resume: Arc<std::sync::Barrier>,
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
    /// A graph authority commit advanced, but its local generation marker and
    /// read index have not both been durably finalized yet. A save with no new
    /// graph mutations still retries this work.
    post_commit_finalization_pending: AtomicBool,
    #[cfg(test)]
    finalization_fail_once: AtomicBool,
    /// Monotonically increasing version counter for VFS cache invalidation.
    /// Incremented on every graph mutation (reconcile, commit, overlay update).
    /// Unlike entity_count, this never decreases on deletions.
    pub vfs_version: AtomicU64,
    /// Materialized committed VFS view keyed by exact graph head + monotonic version.
    /// Endpoint handlers never return this entry unless its key still matches live graph truth.
    pub(crate) vfs_tree_cache: std::sync::RwLock<Option<Arc<VfsTreeSnapshot>>>,
    /// Single-flight coordinator for cold VFS materialization. Waiters recheck the cache after
    /// acquiring this lock, so one exact head/version is replayed at most once.
    pub(crate) vfs_tree_build_lock: tokio::sync::Mutex<()>,
    #[cfg(test)]
    pub(crate) vfs_tree_build_count: AtomicU64,
    #[cfg(test)]
    pub(crate) vfs_tree_build_test_hook: std::sync::Mutex<Option<VfsTreeBuildTestHook>>,
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
    /// Monotonic acknowledgement fence for `dirty`. A mutation increments this
    /// before a later `mark_clean` can clear the flag, so a save finishing at
    /// the same time as a new mutation cannot erase that mutation's wakeup.
    mutation_epoch: AtomicU64,
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
    /// True after a bounded explicit embed pass has claimed the embed resource.
    /// The background worker stays paused so a time-limited foreground command
    /// cannot return while the daemon keeps draining the same large backfill.
    pub background_embed_paused: AtomicBool,
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
    /// Cached locate entity-rankings keyed by paging-cursor key, so `kin locate
    /// --next` (and `semantic_locate` cursors) page a held ranking without
    /// re-running retrieval. Bounded by [`LOCATE_RANKING_CACHE_CAP`].
    pub locate_rankings: Mutex<HashMap<String, CachedLocateRanking>>,
    /// Cached `semantic_locate` result pages keyed by paging-cursor key.
    pub semantic_locate_pages: Mutex<HashMap<String, CachedSemanticPage>>,
    /// Serializes lazy git-ancestry hydration — the full-history import behind a
    /// `review`/`history`/`blame`/`locate --ref`/`scope` ref that names an
    /// unimported Git commit. At most one such import runs at a time: two
    /// concurrent deep imports roughly double peak memory and can OOM-kill the
    /// daemon. Concurrent requests for the SAME unimported commit coalesce —
    /// whoever wins the gate imports it, and later waiters observe it already
    /// present (the get-or-build guard in `hydrate_imported_git_ref`) and skip
    /// the re-import. Held across the request `.await` (and moved into the
    /// `set_scope` blocking task), so it is a tokio mutex behind an `Arc` — not
    /// the std locks used for the synchronous critical sections above.
    pub hydration_gate: Arc<tokio::sync::Mutex<()>>,
}

/// Cached full locate entity-ranking for cursor paging. The daemon caches the
/// FULL ranked entity list once per (query, ref/scope, graph-version) so a
/// follow-up page (`kin locate --next`) windows the next slice with no retrieval
/// re-run. `graph_version` is checked on lookup so a stale page (the graph moved
/// under the cursor) is rejected rather than served.
pub struct CachedLocateRanking {
    pub entities: Vec<kin_cli::commands::locate::LocateEntity>,
    pub graph_version: u64,
    pub created: Instant,
}

/// Cached full `semantic_locate` result rows for cursor paging — the entity-
/// granularity analogue of [`CachedLocateRanking`], holding the already-projected
/// per-entity JSON rows so a follow-up page is a pure window.
pub struct CachedSemanticPage {
    pub rows: Vec<serde_json::Value>,
    pub graph_version: u64,
    pub created: Instant,
}

/// Soft cap on distinct rankings retained for paging; the oldest is evicted past
/// this bound. Paging is a short-lived read-after-read, so a small cache covers
/// the realistic concurrent-cursor count without unbounded growth.
pub const LOCATE_RANKING_CACHE_CAP: usize = 64;

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
        if kndb_path.exists()
            || kin_db::SnapshotManager::local_authority_exists(kndb_path.as_path())
        {
            Some(kndb_path)
        } else {
            None
        }
    }

    /// Open an existing .kin/ directory and create daemon state.
    pub fn open(layout: KinLayout) -> Result<Self> {
        // Up-front compatibility gate. A repo created by a pre-0.2 kin carries
        // an on-disk graph/index that this build's post-load embed/readiness
        // path cannot serve. Without this gate the daemon loads the snapshot,
        // then readiness never arrives and the CLI supervisor kills the process
        // with a bare SIGTERM — opaque to the user. Refuse here, before opening
        // kin-db or starting the embed worker, with an actionable error naming
        // the version gap and the rebuild commands.
        match kin_core::manifest::check_manifest_compatibility(&layout.manifest_path())
            .map_err(DaemonError::from)?
        {
            kin_core::manifest::ManifestCompatibility::Compatible => {}
            incompatible => {
                if let Some(message) = incompatible.incompatibility_message() {
                    return Err(DaemonError::IncompatibleRepo(message));
                }
            }
        }

        // Reclaim stale repo locks (daemon.lock + kin-db's graph.lock) left by a
        // dead daemon whose forked child leaked the flock fd — otherwise the
        // SnapshotManager::open below fails with a spurious lock error (os error
        // 35) even though no live daemon owns the repo. A no-op unless the
        // recorded owner PID is present and dead, so a live daemon's locks are
        // never touched.
        let _ = crate::lifecycle::reclaim_stale_locks(layout.root());

        let text_index_path = layout.text_index_dir();
        let locate_only = Self::locate_only_snapshot_mode();
        let (graph, generation, loaded_snapshot) =
            if let Some(kndb_path) = Self::find_kndb_path(&layout) {
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
                        (g, snapshot_mgr.generation(), true)
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
                    kin_db::GENERATION_INIT,
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
            snapshot_generation: AtomicU64::new(generation),
            post_commit_finalization_pending: AtomicBool::new(false),
            #[cfg(test)]
            finalization_fail_once: AtomicBool::new(false),
            vfs_version: AtomicU64::new(persisted_vfs_version),
            vfs_tree_cache: std::sync::RwLock::new(None),
            vfs_tree_build_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            vfs_tree_build_count: AtomicU64::new(0),
            #[cfg(test)]
            vfs_tree_build_test_hook: std::sync::Mutex::new(None),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
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
            locate_rankings: Mutex::new(HashMap::new()),
            semantic_locate_pages: Mutex::new(HashMap::new()),
            hydration_gate: Arc::new(tokio::sync::Mutex::new(())),
        };
        // Restore in-flight MCP transactions persisted before a restart
        // so staged-but-uncommitted work is not silently dropped across a daemon
        // bounce — stdio-MCP and HTTP-MCP behave identically across a restart.
        *state
            .mcp_transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            load_persisted_mcp_transactions(&state.layout);
        state
            .repo_graphs
            .get_mut()
            .insert(state.cached_repo_id.clone(), Arc::clone(&state.graph));

        // The loaded graph is the validated durable generation and the state
        // is not externally visible yet. Heal derived artifacts directly from
        // it; reopening would duplicate the full graph at peak startup memory.
        // Locate-only graphs deliberately omit non-locate relations, so they
        // may advance the freshness marker but must never replace the canonical
        // general-purpose read index with a partial one.
        if loaded_snapshot {
            if locate_only {
                state.finalize_loaded_locate_generation(generation)?;
            } else {
                state
                    .post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                state.finalize_loaded_generation(generation)?;
            }
        }
        state.register_daemon_system_session();
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
            match kin_db::load_recovered_snapshot(backend.as_ref(), repo_id)
                .map_err(DaemonError::from)?
            {
                Some(recovered) => {
                    let g = kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        recovered.snapshot,
                        text_index_path.clone(),
                    );
                    info!(
                        repo_id,
                        generation = recovered.generation,
                        deltas_replayed = recovered.deltas_applied,
                        "loaded graph from storage backend"
                    );
                    (Arc::new(g), recovered.generation, true)
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
            post_commit_finalization_pending: AtomicBool::new(false),
            #[cfg(test)]
            finalization_fail_once: AtomicBool::new(false),
            vfs_version: AtomicU64::new(persisted_vfs_version),
            vfs_tree_cache: std::sync::RwLock::new(None),
            vfs_tree_build_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            vfs_tree_build_count: AtomicU64::new(0),
            #[cfg(test)]
            vfs_tree_build_test_hook: std::sync::Mutex::new(None),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()), // populated below
            allowed_repo_ids,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
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
            locate_rankings: Mutex::new(HashMap::new()),
            semantic_locate_pages: Mutex::new(HashMap::new()),
            hydration_gate: Arc::new(tokio::sync::Mutex::new(())),
        };

        // Restore in-flight MCP transactions persisted before a restart.
        *state
            .mcp_transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            load_persisted_mcp_transactions(&state.layout);

        // Pre-load repos into the map BEFORE any async context.
        // We use get_mut() since no one else has a reference yet.
        let graphs = state.repo_graphs.get_mut();
        graphs.insert(repo_id.to_string(), graph);

        // The recovered graph is already the exact validated authority view
        // and the state is not externally visible yet. Reuse it for startup
        // artifacts instead of downloading and decoding the backend twice.
        state
            .post_commit_finalization_pending
            .store(true, Ordering::SeqCst);
        state.finalize_loaded_generation(generation)?;
        state.register_daemon_system_session();

        Ok(state)
    }

    /// Register the daemon-owned reconcile session only after startup-derived
    /// artifacts have been built from the exact loaded authority graph.
    fn register_daemon_system_session(&mut self) {
        let daemon_session_id = self
            .coordinator
            .register_session(
                "kin-daemon",
                "reconcile-loop",
                kin_model::session::SessionTransport::Cli,
                None,
                self.layout.working_dir().to_path_buf(),
                kin_model::session::SessionCapabilities::default(),
            )
            .unwrap_or_else(|error| {
                tracing::warn!("failed to register daemon session: {error}");
                kin_model::SessionId::new()
            });
        self.reconciler.get_mut().set_session_id(daemon_session_id);
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

            // Per-repo (id, entities, relations) captured during registration and
            // replayed into cross-repo edge resolution once every repo is indexed.
            let mut repo_relations: Vec<(String, Vec<kin_model::Entity>, Vec<kin_model::Relation>)> =
                Vec::new();

            // Register the primary (this daemon's) repo.
            let default_repo = self
                .layout
                .working_dir()
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("default");
            let repo_id_str = std::env::var("KIN_PRIMARY_REPO_ID").unwrap_or_else(|_| default_repo.to_string());
            let repo_id = repo_id_str.as_str();

            if let Ok(entities) = self.graph.list_all_entities() {
                let entries = Self::entities_to_spine_entries(repo_id, &entities);
                let root_hash = hex::encode(self.graph.compute_root_hash());
                backend.register_repo(repo_id, entries, &root_hash);
                info!(
                    repo_id,
                    entities = entities.len(),
                    "registered primary repo in spine"
                );
                let relations = Self::collect_spine_relations(self.graph.as_ref(), &entities);
                repo_relations.push((repo_id.to_string(), entities, relations));
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
                                let entries =
                                    Self::entities_to_spine_entries(&sibling_id, &entities);
                                let count = entries.len();
                                backend.register_repo(&sibling_id, entries, "");
                                info!(repo_id = %sibling_id, entities = count, "registered sibling in spine");
                                let relations =
                                    Self::collect_spine_relations(&sibling_graph, &entities);
                                repo_relations.push((sibling_id.clone(), entities, relations));
                            }
                        }
                    }
                }
            }

            // With every reachable repo indexed, resolve unresolved imports into
            // cross-repo reference edges so federated impact/xref can traverse them.
            let registry_ids: Vec<String> = backend.registered_repo_ids().into_iter().collect();
            for (rid, entities, relations) in &repo_relations {
                backend.refresh_cross_repo_edges(rid, entities, relations, &registry_ids);
            }

            info!(
                cross_repo_edges = backend.edge_count(),
                "spine index initialized"
            );
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

    /// Collect the entity-level reference edges the spine uses to resolve
    /// cross-repo imports. Only `Calls`/`References` edges carry the
    /// `import_source` the cross-repo resolver keys on, so the scan is limited
    /// to those kinds. Edges are read per source entity (outgoing only), so each
    /// relation is yielded exactly once.
    fn collect_spine_relations(
        graph: &kin_db::InMemoryGraph,
        entities: &[kin_model::Entity],
    ) -> Vec<kin_model::Relation> {
        let kinds = [
            kin_model::RelationKind::Calls,
            kin_model::RelationKind::References,
        ];
        let mut relations = Vec::new();
        for entity in entities {
            if let Ok(rels) = graph.get_relations(&entity.id, &kinds) {
                relations.extend(rels);
            }
        }
        relations
    }

    /// Project a repo's graph entities into the metadata-only `EntityEntry`
    /// rows the spine indexes. The spine never stores entity bodies — just
    /// enough (name, kind, signature, fingerprint, role) to resolve cross-repo
    /// references — so this is the single mapping used by both the local
    /// sibling-scan path and the cloud ingest path.
    fn entities_to_spine_entries(
        repo_id: &str,
        entities: &[kin_model::Entity],
    ) -> Vec<kin_spine::EntityEntry> {
        entities
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
            .collect()
    }

    /// Ingest a repo's graph into the spine from durable storage — the
    /// production multi-repo write path.
    ///
    /// Unlike `initialize_spine_lazy`, which only discovers siblings from the
    /// local `registry.toml` + on-disk `.kndb` files (absent in a hosted pod),
    /// this loads the named repo's graph through the configured
    /// [`StorageBackend`](kin_db::StorageBackend) — the GCS blob store in
    /// cloud — and registers its entity metadata (write-through to the durable
    /// spine store). This is what lets a single-repo pod build a spine holding
    /// ≥2 repos so `/spine/xref` returns non-empty cross-repo edges.
    ///
    /// `refresh_cross_repo_edges`: when `true` (the cross-repo anchor, e.g.
    /// `kin`), re-resolve this repo's unresolved imports against the now
    /// multi-repo spine and materialize the cross-repo edges. Sibling repos are
    /// ingested with `false` (metadata only); the anchor pass binds the edges.
    ///
    /// `get_repo_graph` enforces the `allowed_repo_ids` (`KIN_REPO_IDS`) gate and
    /// caches the loaded graph, so repeated ingests of the same repo reuse it.
    pub async fn ingest_repo_into_spine(
        &self,
        repo_id: &str,
        refresh_cross_repo_edges: bool,
    ) -> Result<SpineIngestOutcome> {
        let Some(spine) = self.ensure_spine() else {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "spine disabled via KIN_DISABLE_SPINE".to_string(),
            )));
        };

        // Load the repo's graph from durable storage (GCS in cloud). This is the
        // blob-store read boundary that replaces the local-disk `.kndb` lookup.
        let graph = self.get_repo_graph(repo_id).await?;

        let entities = graph
            .list_all_entities()
            .map_err(|e| DaemonError::Graph(kin_db::KinDbError::StorageError(e.to_string())))?;

        let entries = Self::entities_to_spine_entries(repo_id, &entities);
        let entity_count = entries.len();
        let root_hash = hex::encode(graph.compute_root_hash());

        // Write-through: register this repo's metadata into the spine store so a
        // freshly started (stateless) pod can hydrate it and resolve against it.
        spine.register_repo(repo_id, entries, &root_hash);

        let relations = Self::collect_spine_relations(graph.as_ref(), &entities);
        let relation_count = relations.len();

        // Count the relations the resolver can actually bind into cross-repo
        // edges, against the spine's current registered-repo set. This is the
        // honest "can this materialize edges" signal the control plane gates on
        // — it is derived from graph truth, never a heuristic.
        let registry_ids: Vec<String> = spine.registered_repo_ids().into_iter().collect();
        let resolvable_relations =
            kin_spine::collect_unresolved_imports(&entities, &relations, repo_id, &registry_ids)
                .len();

        if refresh_cross_repo_edges {
            // Re-resolve this repo's imports now that the sibling metadata is in
            // the spine, materializing (and write-through persisting) the
            // cross-repo edges that back `/spine/xref`.
            spine.refresh_cross_repo_edges(repo_id, &entities, &relations, &registry_ids);
        }

        info!(
            repo_id,
            entities = entity_count,
            relations = relation_count,
            resolvable_relations,
            refreshed = refresh_cross_repo_edges,
            cross_repo_edges = spine.edge_count(),
            "ingested repo into spine from storage"
        );

        Ok(SpineIngestOutcome {
            repo_id: repo_id.to_string(),
            root_hash,
            entity_count,
            relation_count,
            resolvable_relations,
        })
    }

    /// Refresh cross-repo edges for EVERY registered repo, mirroring the local
    /// [`Self::initialize_spine_lazy`] "register all, then resolve all" pass.
    ///
    /// The per-repo ingest path only materializes the anchor repo's edges, so a
    /// repo ingested before its dependency was registered never forms its
    /// outgoing edges. This final pass — run by the hosted orchestrator once
    /// every repo is registered — loads each registered repo's graph from
    /// durable storage (the blob store, never on-disk siblings) and re-resolves
    /// its imports against the now-complete spine. It is idempotent: each repo's
    /// existing edges are removed and re-materialized.
    pub async fn refresh_all_cross_repo_edges(&self) -> Result<SpineRefreshOutcome> {
        let Some(spine) = self.ensure_spine() else {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "spine disabled via KIN_DISABLE_SPINE".to_string(),
            )));
        };

        // Resolve against the full registered-repo set, sorted for a
        // deterministic pass order.
        let mut registry_ids: Vec<String> = spine.registered_repo_ids().into_iter().collect();
        registry_ids.sort();

        let mut repos_refreshed = 0usize;
        for repo_id in &registry_ids {
            // Load this repo's graph from durable storage (cached after the first
            // load). Skip a repo this pod cannot load rather than aborting the
            // whole pass — the others still refresh.
            let graph = match self.get_repo_graph(repo_id).await {
                Ok(graph) => graph,
                Err(e) => {
                    warn!(repo_id, error = %e, "skipping cross-repo refresh: graph load failed");
                    continue;
                }
            };
            let entities = match graph.list_all_entities() {
                Ok(entities) => entities,
                Err(e) => {
                    warn!(repo_id, error = %e, "skipping cross-repo refresh: entity listing failed");
                    continue;
                }
            };
            let relations = Self::collect_spine_relations(graph.as_ref(), &entities);
            spine.refresh_cross_repo_edges(repo_id, &entities, &relations, &registry_ids);
            repos_refreshed += 1;
        }

        info!(
            repos_refreshed,
            cross_repo_edges = spine.edge_count(),
            "refreshed cross-repo edges across all registered repos"
        );

        Ok(SpineRefreshOutcome {
            repos_refreshed,
            cross_repo_edges: spine.edge_count(),
        })
    }

    /// Load a repo's graph from the storage backend (synchronous).
    /// Used internally for pre-loading and by `get_repo_graph`.
    fn load_repo_graph(&self, repo_id: &str) -> Result<Arc<kin_db::InMemoryGraph>> {
        let Some(backend) = &self.storage_backend else {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "no storage backend configured for multi-repo mode".to_string(),
            )));
        };
        match kin_db::load_recovered_snapshot(backend.as_ref(), repo_id)
            .map_err(DaemonError::from)?
        {
            Some(recovered) => {
                let text_index_path = self.layout.text_index_dir();
                let graph = Arc::new(kin_db::InMemoryGraph::from_snapshot_with_text_index(
                    recovered.snapshot,
                    text_index_path,
                ));
                info!(
                    repo_id,
                    generation = recovered.generation,
                    deltas_replayed = recovered.deltas_applied,
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
        // Retire the old materialization at the same publication boundary. Requests that
        // already cloned it may finish against the pre-mutation head; every request that
        // observes the new version must rebuild or reuse a snapshot with the new key.
        let mut cache = self
            .vfs_tree_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cache = None;
        drop(cache);
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
    /// `.kin/kindb/head-generation` so CLI and MCP processes can detect
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
        let mut committed = false;

        let new_gen = if let Some(backend) = &self.storage_backend {
            if force_full
                || expected_gen == kin_db::GENERATION_INIT
                || self.graph.full_snapshot_required()
                || !backend.supports_incremental_deltas()
            {
                let (bytes, graph_root_hash, persistence_epoch) = self
                    .graph
                    .begin_snapshot_persistence(None)
                    .map_err(DaemonError::from)?;
                let persistence_attempt =
                    GraphPersistenceAttempt::new(self.graph.as_ref(), persistence_epoch);
                // Keep every fallible derived-index operation before the
                // authority commit. If it fails, the RAII attempt forces a full
                // retry and the backend generation remains unchanged.
                kin_db::SnapshotManager::persist_snapshot_sidecars_for_epoch(
                    self.layout.kindb_snapshot_path().as_path(),
                    self.graph.as_ref(),
                    graph_root_hash,
                    persistence_epoch,
                )
                .map_err(DaemonError::from)?;
                let generation = backend
                    .save_snapshot(repo_id, &bytes, expected_gen)
                    .map_err(DaemonError::from)?;
                // From this point on the authority commit is irreversible.
                // Advance the CAS cursor and acknowledge only this detached
                // batch before attempting cleanup or local finalization.
                self.snapshot_generation.store(generation, Ordering::SeqCst);
                persistence_attempt.complete();
                self.post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                committed = true;
                if let Err(error) = backend.clear_deltas(repo_id) {
                    warn!(
                        repo_id,
                        generation,
                        error = %error,
                        "snapshot committed; deferred stale delta cleanup"
                    );
                }
                generation
            } else if let Some((delta, persistence_epoch)) =
                self.graph.begin_delta_persistence(expected_gen)
            {
                let persistence_attempt =
                    GraphPersistenceAttempt::new(self.graph.as_ref(), persistence_epoch);
                let bytes = delta.to_bytes().map_err(DaemonError::from)?;
                // A text-index failure must precede the durable delta commit.
                // The index is derived and root-stamped; the authority write is
                // the point after which this method must not lose its cursor.
                kin_db::SnapshotManager::invalidate_derived_sidecars(
                    self.layout.kindb_snapshot_path(),
                    self.graph.as_ref(),
                )
                .map_err(DaemonError::from)?;
                let generation = backend
                    .save_delta(repo_id, &bytes, expected_gen)
                    .map_err(DaemonError::from)?;
                self.snapshot_generation.store(generation, Ordering::SeqCst);
                persistence_attempt.complete();
                self.post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                committed = true;
                generation
            } else {
                self.graph.flush_text_index().map_err(DaemonError::from)?;
                expected_gen
            }
        } else if force_full {
            let (_, generation) = kin_db::SnapshotManager::save_graph_with_expected_generation(
                self.layout.kindb_snapshot_path(),
                self.graph.as_ref(),
                expected_gen,
            )
            .map_err(DaemonError::from)?;
            committed = true;
            generation
        } else {
            let generation = kin_db::SnapshotManager::save_graph_delta(
                self.layout.kindb_snapshot_path(),
                self.graph.as_ref(),
                expected_gen,
            )
            .map_err(DaemonError::from)?;
            committed = generation.is_some();
            generation.unwrap_or(expected_gen)
        };

        self.snapshot_generation.store(new_gen, Ordering::SeqCst);

        if committed {
            self.post_commit_finalization_pending
                .store(true, Ordering::SeqCst);
        }
        if self.post_commit_finalization_pending.load(Ordering::SeqCst) {
            self.finalize_committed_generation(new_gen)?;
        }

        info!(
            repo_id,
            generation = new_gen,
            committed,
            "saved snapshot to storage backend"
        );
        Ok(())
    }

    /// Incremental per-batch embed-progress flush for the background
    /// embed worker.
    ///
    /// Persists this batch's vectors — plus any concurrent graph delta from LSP
    /// enrichment that kept the graph dirty during embed — via
    /// `SnapshotManager::flush_embed_progress`, which appends only the delta and
    /// the vector sidecar and NEVER re-serializes the whole (~1 GB) graph. The
    /// old worker leaned on the periodic full `save_snapshot` to land the graph
    /// side, which is O(graph) per tick and is what wedged the daemon at scale.
    ///
    /// Mirrors `save_snapshot_impl`'s persist-lock + generation-cursor + marker
    /// discipline so the two persistence paths compose safely (the shared
    /// `persist_lock` serializes them and keeps `snapshot_generation` consistent).
    /// Returns the persisted resume `pending` count — derived from graph-vs-index
    /// truth, so it survives a crash/reopen and reaches zero only at full
    /// coverage.
    #[cfg(feature = "embeddings")]
    pub fn flush_embed_progress(&self) -> Result<usize> {
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| DaemonError::Io(std::io::Error::other("persist lock poisoned")))?;
        let base_gen = self.snapshot_generation.load(Ordering::SeqCst);
        let embedder_identity = kin_buildinfo::sha_with_dirty(kin_buildinfo::get());
        let outcome = kin_db::SnapshotManager::flush_embed_progress(
            self.layout.kindb_snapshot_path(),
            self.graph.as_ref(),
            base_gen,
            Some(embedder_identity.as_str()),
        )
        .map_err(DaemonError::from)?;
        // The graph moved (a delta was appended) only when `generation` is Some;
        // advance the cursor + publish the marker so CLI/MCP reload, exactly as
        // save_snapshot_impl does. A vectors-only batch leaves the graph at
        // `base_gen`, so the cursor stays put.
        if let Some(generation) = outcome.generation {
            self.snapshot_generation.store(generation, Ordering::SeqCst);
            self.post_commit_finalization_pending
                .store(true, Ordering::SeqCst);
        }
        if self.post_commit_finalization_pending.load(Ordering::SeqCst) {
            let generation = self.snapshot_generation.load(Ordering::SeqCst);
            self.finalize_committed_generation(generation)?;
        }
        Ok(outcome.status.pending)
    }

    #[cfg(not(feature = "embeddings"))]
    pub fn flush_embed_progress(&self) -> Result<usize> {
        Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
            "this Kin build does not include embedding support".to_string(),
        )))
    }

    /// Force the derived vector sidecar to disk regardless of the in-run flush
    /// throttle.
    ///
    /// While an embed drains, `flush_embed_progress` checkpoints the sidecar on a
    /// throttle rather than every batch, so a pass that ends time-limited (queue
    /// not yet drained) can leave the vectors embedded since the last throttle
    /// tick in memory only. Calling this at a pass boundary lands them durably,
    /// so a graceful daemon exit before the next pass resumes with the full pass
    /// persisted instead of re-deriving that last window. The vector index is a
    /// pure sidecar (not in the merkle root), so this never advances the graph
    /// generation. Cost is one index serialize per time-limited pass, not per
    /// batch.
    #[cfg(feature = "vector")]
    pub fn persist_vector_sidecar(&self) -> Result<()> {
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| DaemonError::Io(std::io::Error::other("persist lock poisoned")))?;
        let embedder_identity = kin_buildinfo::sha_with_dirty(kin_buildinfo::get());
        kin_db::SnapshotManager::save_vector_index_for_graph(
            self.layout.kindb_snapshot_path(),
            self.graph.as_ref(),
            Some(embedder_identity.as_str()),
        )
        .map_err(DaemonError::from)
    }

    #[cfg(not(feature = "vector"))]
    pub fn persist_vector_sidecar(&self) -> Result<()> {
        Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
            "this Kin build does not include vector support".to_string(),
        )))
    }

    /// Finish local artifacts for one already-committed authority generation.
    ///
    /// The read index is rebuilt from reopened durable authority, not the live
    /// graph, which may already contain mutations that arrived after the
    /// committed batch. It is staged off-path, the old canonical index is
    /// removed, the generation marker is durably published, and only then is
    /// the staged index promoted. Every crash point therefore leaves either the
    /// old generation or a missing derived index, never a stale canonical index
    /// presented as current authority.
    fn finalize_committed_generation(&self, generation: u64) -> Result<()> {
        #[cfg(test)]
        if self.finalization_fail_once.swap(false, Ordering::SeqCst) {
            return Err(DaemonError::Io(std::io::Error::other(
                "injected post-commit finalization failure",
            )));
        }

        let authority_graph = self.load_committed_authority_graph(generation)?;
        self.finalize_generation_from_graph(generation, authority_graph.as_ref())
    }

    /// Finish startup artifacts from the graph that was just loaded and
    /// validated before the state is exposed to any request or mutator.
    /// Reopening the same authority here doubles graph memory and repeats
    /// remote snapshot I/O on every healthy restart.
    fn finalize_loaded_generation(&self, generation: u64) -> Result<()> {
        self.finalize_generation_from_graph(generation, self.graph.as_ref())
    }

    /// A locate-only graph is intentionally incomplete for general-purpose
    /// references and traces, so it cannot rebuild the canonical read index.
    /// Remove any older index before publishing the loaded authority head;
    /// a missing derived index is fail-safe, while an old index paired with a
    /// new marker would advertise a mixed-generation state.
    fn finalize_loaded_locate_generation(&self, generation: u64) -> Result<()> {
        self.invalidate_canonical_read_index()?;
        self.write_generation_marker(generation)
    }

    fn finalize_generation_from_graph(
        &self,
        generation: u64,
        authority_graph: &kin_db::InMemoryGraph,
    ) -> Result<()> {
        let (staged_index, persisted_entity_count) =
            self.stage_read_index_from_graph(generation, authority_graph)?;
        let index_path = self.invalidate_canonical_read_index()?;
        self.write_generation_marker(generation)?;
        if let Err(error) = std::fs::rename(&staged_index, &index_path) {
            return Err(DaemonError::Io(error));
        }
        if let Some(parent) = index_path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(DaemonError::Io)?;
        }
        self.persisted_entity_count
            .store(persisted_entity_count, Ordering::SeqCst);
        self.post_commit_finalization_pending
            .store(false, Ordering::SeqCst);
        Ok(())
    }

    fn invalidate_canonical_read_index(&self) -> Result<std::path::PathBuf> {
        let index_path = self.layout.kindb_snapshot_path().with_extension("kidx");
        match std::fs::remove_file(&index_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(DaemonError::Io(error)),
        }
        if let Some(parent) = index_path.parent() {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(DaemonError::Io)?;
        }
        Ok(index_path)
    }

    fn load_committed_authority_graph(
        &self,
        generation: u64,
    ) -> Result<Arc<kin_db::InMemoryGraph>> {
        let authority_graph = if let Some(backend) = &self.storage_backend {
            match kin_db::load_recovered_snapshot(backend.as_ref(), &self.cached_repo_id)
                .map_err(DaemonError::from)?
            {
                Some(recovered) => {
                    if recovered.generation != generation {
                        return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                            format!(
                                "post-commit authority moved for repo {}: expected generation {generation}, recovered {}; reopen before finalizing derived indexes",
                                self.cached_repo_id, recovered.generation
                            ),
                        )));
                    }
                    Arc::new(kin_db::InMemoryGraph::from_snapshot(recovered.snapshot))
                }
                None if generation == kin_db::GENERATION_INIT => Arc::clone(&self.graph),
                None => {
                    return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                        format!(
                            "committed generation {generation} for repo {} is missing during read-index finalization",
                            self.cached_repo_id
                        ),
                    )))
                }
            }
        } else {
            let snapshot =
                kin_db::SnapshotManager::open_read_only(self.layout.kindb_snapshot_path())
                    .map_err(DaemonError::from)?;
            let observed_generation = snapshot.generation();
            if observed_generation != generation {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!(
                        "post-commit authority moved for repo {}: expected generation {generation}, recovered {observed_generation}; reopen before finalizing derived indexes",
                        self.cached_repo_id
                    ),
                )));
            }
            snapshot.graph()
        };
        Ok(authority_graph)
    }

    fn stage_read_index_from_graph(
        &self,
        generation: u64,
        authority_graph: &kin_db::InMemoryGraph,
    ) -> Result<(std::path::PathBuf, u64)> {
        let index = kin_db::ReadIndex::from_graph(authority_graph).map_err(DaemonError::from)?;
        let idx_path = self.layout.kindb_snapshot_path().with_extension("kidx");
        if let Some(parent) = idx_path.parent() {
            std::fs::create_dir_all(parent).map_err(DaemonError::Io)?;
        }
        let mut staged_name = std::ffi::OsString::from(idx_path.as_os_str());
        staged_name.push(format!(".pending-{generation}-{}", std::process::id()));
        let staged_path = std::path::PathBuf::from(staged_name);
        index.save(&staged_path).map_err(DaemonError::from)?;
        Ok((staged_path, authority_graph.entity_count() as u64))
    }

    /// Write the durable authority head to `.kin/kindb/head-generation`.
    ///
    /// KinDB owns `.kin/kindb/generation` as the generation of its legacy
    /// `graph.kndb` compatibility projection. A delta commit advances graph
    /// authority without advancing that projection, so using the legacy path
    /// as the daemon freshness marker makes the next authority read look like
    /// a mixed-version legacy writer and correctly fail closed.
    ///
    /// CLI and MCP processes read this file before queries and compare it
    /// to their loaded generation. If different, they know the daemon has
    /// committed a newer snapshot and should reload.
    fn write_generation_marker(&self, generation: u64) -> Result<()> {
        use std::io::Write;

        let gen_path = self.layout.kindb_head_generation_path();
        let tmp_path = gen_path.with_extension(format!("tmp-{}", std::process::id()));
        let parent = gen_path.parent().ok_or_else(|| {
            DaemonError::Io(std::io::Error::other(
                "generation marker path has no parent directory",
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(DaemonError::Io)?;
        {
            let mut file = std::fs::File::create(&tmp_path).map_err(DaemonError::Io)?;
            file.write_all(generation.to_string().as_bytes())
                .map_err(DaemonError::Io)?;
            file.sync_all().map_err(DaemonError::Io)?;
        }
        if let Err(error) = std::fs::rename(&tmp_path, &gen_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(DaemonError::Io(error));
        }
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(DaemonError::Io)?;
        Ok(())
    }

    /// Read the current durable authority head from
    /// `.kin/kindb/head-generation`.
    ///
    /// Returns 0 if the file doesn't exist. CLI and MCP can call this
    /// before queries to check if the daemon has committed a newer snapshot
    /// than what they have loaded in memory.
    pub fn read_generation_marker(layout: &KinLayout) -> u64 {
        let gen_path = layout.kindb_head_generation_path();
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
    /// has not yet been persisted (older snapshots from before file hashes were
    /// always written), `from_graph` returns
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
        // current schema (hashes always persisted) this path becomes unreachable.
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
                        "skipping projection rebuild for file not in blobs or disk \
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
        self.mutation_epoch.fetch_add(1, Ordering::SeqCst);
        self.dirty.store(true, Ordering::SeqCst);
        if let Ok(mut last) = self.last_mutation.lock() {
            *last = Instant::now();
        }
    }

    /// Mark the graph as clean (just saved). Records the save timestamp.
    pub fn mark_clean(&self) {
        let observed_epoch = self.mutation_epoch.load(Ordering::SeqCst);
        self.dirty.store(false, Ordering::SeqCst);
        // A detached backend batch, a later active delta, or a mutation epoch
        // that changed across the clear all mean this save did not acknowledge
        // the latest graph truth. Re-arm the persistence wakeup instead of
        // losing the concurrent mutation.
        if self.mutation_epoch.load(Ordering::SeqCst) != observed_epoch
            || self.graph.has_unpersisted_changes()
            || self.post_commit_finalization_pending.load(Ordering::SeqCst)
        {
            self.dirty.store(true, Ordering::SeqCst);
            return;
        }
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

    /// True when the background embedding worker should stand down.
    pub fn background_embed_paused(&self) -> bool {
        self.background_embed_paused.load(Ordering::SeqCst)
    }

    /// Pause background embedding. Explicit `kin embed` requests can still run.
    pub fn pause_background_embed(&self) {
        self.background_embed_paused.store(true, Ordering::SeqCst);
    }

    /// Resume background embedding after unbounded or fully completed embed work.
    pub fn resume_background_embed(&self) {
        self.background_embed_paused.store(false, Ordering::SeqCst);
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
    #[cfg(feature = "vector")]
    use kin_db::VectorIndex;
    use kin_model::{
        Entity, EntityKind, EntityMetadata, FileLayout, FilePathId, FingerprintAlgorithm,
        GraphOverlay, Hash256, ImportSection, LanguageId, ParseCompleteness, SemanticFingerprint,
        Visibility, WorkingCopy,
    };
    use kin_reconcile::ReconcileOutcome;
    use serde_json::json;

    struct CleanupFailOnceBackend {
        inner: kin_db::LocalFileBackend,
        fail_cleanup: AtomicBool,
        delta_block: Option<DeltaSaveBlock>,
        recovery_loads: Option<Arc<AtomicU64>>,
    }

    struct DeltaSaveBlock {
        reached_backend: Arc<std::sync::Barrier>,
        resume_backend: Arc<std::sync::Barrier>,
        block_once: AtomicBool,
    }

    impl CleanupFailOnceBackend {
        fn new(path: &std::path::Path, fail_cleanup: bool) -> Self {
            Self {
                inner: kin_db::LocalFileBackend::new(path),
                fail_cleanup: AtomicBool::new(fail_cleanup),
                delta_block: None,
                recovery_loads: None,
            }
        }

        fn blocking_delta(
            path: &std::path::Path,
            reached_backend: Arc<std::sync::Barrier>,
            resume_backend: Arc<std::sync::Barrier>,
        ) -> Self {
            Self {
                inner: kin_db::LocalFileBackend::new(path),
                fail_cleanup: AtomicBool::new(false),
                delta_block: Some(DeltaSaveBlock {
                    reached_backend,
                    resume_backend,
                    block_once: AtomicBool::new(true),
                }),
                recovery_loads: None,
            }
        }

        fn counting_load(path: &std::path::Path, recovery_loads: Arc<AtomicU64>) -> Self {
            Self {
                inner: kin_db::LocalFileBackend::new(path),
                fail_cleanup: AtomicBool::new(false),
                delta_block: None,
                recovery_loads: Some(recovery_loads),
            }
        }
    }

    impl kin_db::StorageBackend for CleanupFailOnceBackend {
        fn supports_incremental_deltas(&self) -> bool {
            true
        }

        fn load_snapshot(
            &self,
            repo_id: &str,
        ) -> std::result::Result<Option<(Vec<u8>, kin_db::Generation)>, kin_db::KinDbError>
        {
            self.inner.load_snapshot(repo_id)
        }

        fn load_snapshot_authority(
            &self,
            repo_id: &str,
        ) -> std::result::Result<Option<kin_db::SnapshotAuthority>, kin_db::KinDbError> {
            self.inner.load_snapshot_authority(repo_id)
        }

        fn load_recovery_state(
            &self,
            repo_id: &str,
        ) -> std::result::Result<kin_db::SnapshotRecoveryState, kin_db::KinDbError> {
            if let Some(loads) = &self.recovery_loads {
                loads.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.load_recovery_state(repo_id)
        }

        fn save_snapshot(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_gen: kin_db::Generation,
        ) -> std::result::Result<kin_db::Generation, kin_db::KinDbError> {
            self.inner.save_snapshot(repo_id, data, expected_gen)
        }

        fn save_delta(
            &self,
            repo_id: &str,
            delta_data: &[u8],
            base_gen: kin_db::Generation,
        ) -> std::result::Result<kin_db::Generation, kin_db::KinDbError> {
            if let Some(block) = &self.delta_block {
                if block.block_once.swap(false, Ordering::SeqCst) {
                    block.reached_backend.wait();
                    block.resume_backend.wait();
                }
            }
            self.inner.save_delta(repo_id, delta_data, base_gen)
        }

        fn load_deltas_since(
            &self,
            repo_id: &str,
            since_gen: kin_db::Generation,
        ) -> std::result::Result<Vec<(Vec<u8>, kin_db::Generation)>, kin_db::KinDbError> {
            self.inner.load_deltas_since(repo_id, since_gen)
        }

        fn clear_deltas(&self, repo_id: &str) -> std::result::Result<(), kin_db::KinDbError> {
            if self.fail_cleanup.swap(false, Ordering::SeqCst) {
                return Err(kin_db::KinDbError::StorageError(
                    "injected delta cleanup failure".to_string(),
                ));
            }
            self.inner.clear_deltas(repo_id)
        }

        fn save_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
            data: &[u8],
        ) -> std::result::Result<(), kin_db::KinDbError> {
            self.inner.save_overlay(repo_id, session_id, data)
        }

        fn load_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, kin_db::KinDbError> {
            self.inner.load_overlay(repo_id, session_id)
        }

        fn delete_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
        ) -> std::result::Result<(), kin_db::KinDbError> {
            self.inner.delete_overlay(repo_id, session_id)
        }

        fn list_repos(&self) -> std::result::Result<Vec<String>, kin_db::KinDbError> {
            self.inner.list_repos()
        }
    }

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
        let snapshot_generation =
            if kin_db::SnapshotManager::local_authority_exists(layout.kindb_snapshot_path()) {
                kin_db::SnapshotManager::open_read_only(layout.kindb_snapshot_path())
                    .unwrap()
                    .generation()
            } else {
                kin_db::GENERATION_INIT
            };
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
            snapshot_generation: AtomicU64::new(snapshot_generation),
            post_commit_finalization_pending: AtomicBool::new(false),
            #[cfg(test)]
            finalization_fail_once: AtomicBool::new(false),
            vfs_version: AtomicU64::new(0),
            vfs_tree_cache: std::sync::RwLock::new(None),
            vfs_tree_build_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            vfs_tree_build_count: AtomicU64::new(0),
            #[cfg(test)]
            vfs_tree_build_test_hook: std::sync::Mutex::new(None),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_overlays: RwLock::new(std::collections::HashMap::new()),
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
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
            locate_rankings: Mutex::new(HashMap::new()),
            semantic_locate_pages: Mutex::new(HashMap::new()),
            hydration_gate: Arc::new(tokio::sync::Mutex::new(())),
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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
    fn background_embed_pause_latch_round_trips() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        assert!(!state.background_embed_paused());

        state.pause_background_embed();
        assert!(state.background_embed_paused());

        state.resume_background_embed();
        assert!(!state.background_embed_paused());
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
    #[serial_test::serial]
    fn spine_init_materializes_cross_repo_edges() {
        use kin_db::{InMemoryGraph, SnapshotManager};
        use kin_model::{
            GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
        };

        // A sibling repo whose persisted graph exposes the entity the primary
        // repo references across the repo boundary. The spine resolves a
        // cross-repo reference by matching the imported-symbol evidence on the
        // primary's relation against an indexed entity name, so the sibling
        // entity is named with the real symbol the reference imports.
        let sibling_id = "sibling-lib";
        let external_id = kin_model::EntityId::new();
        let imported_symbol = "remote_call";

        let sibling_dir = tempfile::tempdir().unwrap();
        let sibling_init = kin_core::init(sibling_dir.path()).unwrap();
        let sibling_graph = InMemoryGraph::new();
        sibling_graph
            .batch_upsert_entities(&[test_entity(imported_symbol, "src/lib.rs")])
            .unwrap();
        SnapshotManager::save_graph(sibling_init.layout.kindb_snapshot_path(), &sibling_graph)
            .unwrap();

        // The primary repo: a caller entity plus an unresolved cross-repo call
        // tagged with the sibling repo as its import source.
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let state = test_state(primary_init.layout, primary_dir.path());
        let caller = test_entity("caller", "src/main.rs");
        state
            .graph
            .batch_upsert_entities(std::slice::from_ref(&caller))
            .unwrap();
        state
            .graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(external_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some(sibling_id.to_string()),
                evidence: vec![RelationEvidence {
                    token: Some(imported_symbol.to_string()),
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();

        // Point the global registry at a temp file naming only the sibling so
        // init discovers and indexes it alongside the primary.
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry {
            repos: vec![kin_core::registry::RegisteredRepo {
                id: sibling_id.to_string(),
                path: sibling_dir.path().to_path_buf(),
                entities: 1,
                last_commit: String::new(),
                dependencies: vec![],
            }],
        }
        .save_to(&registry_path)
        .unwrap();

        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

        let (repo_count, edge_count) = {
            let spine = state.ensure_spine().expect("spine must be enabled");
            (spine.repo_count(), spine.edge_count())
        };

        // Restore the process-global env before asserting so a failure can never
        // leak the override into other tests.
        match prev_registry {
            Some(v) => std::env::set_var("KIN_REGISTRY_PATH", v),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }
        if let Some(v) = prev_disable {
            std::env::set_var("KIN_DISABLE_SPINE", v);
        }

        assert!(
            repo_count >= 2,
            "primary and sibling repos must both be indexed (got {repo_count})"
        );
        assert!(
            edge_count > 0,
            "cross-repo edges must materialize after spine init (got {edge_count})"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ingest_repo_into_spine_serves_non_empty_xref_from_storage_only() {
        // Hosted org-graph demo in miniature, against the PRODUCTION ingest
        // write path. A hosted pod runs one repo and owns no local sibling
        // checkouts and no `registry.toml`: the cross-repo index must be built
        // by loading sibling graphs from the durable StorageBackend (GCS in
        // cloud, a `LocalFileBackend` rooted at `v2/` here — the same
        // `v2/<repo>/graph.kndb` layout) via `ingest_repo_into_spine`, NOT from
        // on-disk `.kndb` siblings the way `initialize_spine_lazy` does.
        //
        // Two repos land in storage the way cloud ingestion sees them: the
        // sibling `kin-db` (which exports `InMemoryGraph`) and the primary
        // `kin`, whose caller references `kin_db::InMemoryGraph` across the repo
        // boundary. After ingesting both, `/spine/xref` for the primary caller
        // must return a non-empty cross-repo edge bound to the store-resident
        // sibling entity.
        use kin_db::{InMemoryGraph, LocalFileBackend, StorageBackend, GENERATION_INIT};
        use kin_model::{
            GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
        };

        let sibling_id = "kin-db";
        let primary_id = "kin";
        let imported_symbol = "InMemoryGraph";

        // The durable store, standing in for the GCS bucket (no local-disk
        // siblings, no registry).
        let storage = tempfile::tempdir().unwrap();
        let v2_root = storage.path().join("v2");

        // ── Ingestion source: seed the sibling graph into storage ─────────
        // Only the sibling's serialized graph reaches storage — never a local
        // `.kndb` next to the pod's repo.
        let sibling_entity = test_entity(imported_symbol, "src/lib.rs");
        let sibling_graph = InMemoryGraph::new();
        sibling_graph
            .batch_upsert_entities(std::slice::from_ref(&sibling_entity))
            .unwrap();
        {
            let seed_backend = LocalFileBackend::new(&v2_root);
            let bytes = sibling_graph.to_snapshot().to_bytes().unwrap();
            seed_backend
                .save_snapshot(sibling_id, &bytes, GENERATION_INIT)
                .unwrap();
        }

        // ── The hosted pod: serves `kin`, knows `kin`+`kin-db` via KIN_REPO_IDS
        // The pod is opened over the same storage backend; `allowed_repo_ids`
        // mirrors `KIN_REPO_IDS=kin,kin-db` so the daemon may load the sibling
        // graph from storage on demand.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let allowed: HashSet<String> = [primary_id.to_string(), sibling_id.to_string()]
            .into_iter()
            .collect();
        let state = DaemonState::open_with_backend(
            init.layout,
            Box::new(LocalFileBackend::new(&v2_root)),
            primary_id,
            Some(allowed),
        )
        .unwrap();

        // Build the primary repo's served graph: a caller plus an unresolved
        // cross-repo `Calls` to `kin_db::InMemoryGraph`, carrying the
        // `import_source` and the imported-symbol token the resolver binds on.
        let caller = test_entity("open_graph", "src/graph.rs");
        state
            .graph
            .batch_upsert_entities(std::slice::from_ref(&caller))
            .unwrap();
        state
            .graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(kin_model::EntityId::new()),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some(sibling_id.to_string()),
                evidence: vec![RelationEvidence {
                    token: Some(format!("kin_db::{imported_symbol}")),
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();

        // Spine must be enabled for this test regardless of ambient env.
        // Point discovery at an explicitly empty registry: this hosted path is
        // proving storage-only sibling ingestion and must never scan a user's
        // real global registry (which can contain multi-gigabyte graphs).
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

        // ── Drive the production ingest route logic ───────────────────────
        // Sibling first (metadata only), then the anchor with edge refresh —
        // exactly the order the control-plane orchestrator POSTs.
        let sibling_outcome = state
            .ingest_repo_into_spine(sibling_id, false)
            .await
            .expect("sibling ingest from storage");
        let primary_outcome = state
            .ingest_repo_into_spine(primary_id, true)
            .await
            .expect("primary ingest + cross-repo edge refresh");

        // Restore env before asserting so a failure cannot leak the override.
        if let Some(v) = prev_disable {
            std::env::set_var("KIN_DISABLE_SPINE", v);
        }
        match prev_registry {
            Some(v) => std::env::set_var("KIN_REGISTRY_PATH", v),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }

        // The sibling was loaded purely from storage (it has no local `.kndb`).
        assert_eq!(
            sibling_outcome.entity_count, 1,
            "sibling entity metadata must load from the storage backend"
        );
        // The anchor reports a resolvable relation — the honest "this can
        // materialize a cross-repo edge" signal the control plane gates on.
        assert_eq!(
            primary_outcome.resolvable_relations, 1,
            "the primary's cross-repo call must be classified resolvable"
        );

        let spine = state.spine().expect("spine initialized by ingest");
        assert!(
            spine.repo_count() >= 2,
            "primary and sibling must both be registered (got {})",
            spine.repo_count()
        );

        // ── The contract the demo needs: non-empty cross-repo xref ────────
        // This is exactly what `GET /spine/xref?repo=kin&entity=<caller>` reads.
        assert!(
            spine.edge_count() >= 1,
            "spine must hold a cross-repo edge after ingest (got {})",
            spine.edge_count()
        );
        let xref = spine.cross_repo_edges_for(primary_id, &caller.id);
        assert!(
            !xref.is_empty(),
            "/spine/xref for the primary caller must be non-empty with storage-only siblings"
        );
        let edge = &xref[0];
        assert_eq!(edge.src_repo, primary_id);
        assert_eq!(
            edge.dst_repo, sibling_id,
            "edge must cross into the sibling repo loaded from storage"
        );
        assert_eq!(
            edge.dst_entity, sibling_entity.id,
            "edge must bind to the storage-resident sibling entity, not a local guess"
        );

        // The boundary is crossable from the sibling side too — the federated
        // reachability the org graph renders.
        let impact = spine.federated_impact(sibling_id, &sibling_entity.id, 5);
        assert!(
            impact.repos_involved.contains(&primary_id.to_string()),
            "changing the sibling entity must impact the primary repo across the boundary"
        );
    }

    #[test]
    fn open_fails_when_persisted_snapshot_is_corrupt() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let snapshot_path = layout.kindb_snapshot_path();
        let mut authority_name = std::ffi::OsString::from(snapshot_path.as_os_str());
        authority_name.push(".authority.json");
        let authority: serde_json::Value =
            serde_json::from_slice(&std::fs::read(authority_name).unwrap()).unwrap();
        let snapshot_file = authority["snapshot_file"].as_str().unwrap();
        let mut versions_name = std::ffi::OsString::from(snapshot_path.as_os_str());
        versions_name.push(".snapshots");
        let authoritative_snapshot = std::path::PathBuf::from(versions_name).join(snapshot_file);
        std::fs::write(authoritative_snapshot, b"not-a-valid-kndb").unwrap();

        let err = match DaemonState::open(layout) {
            Ok(_) => panic!("expected corrupt snapshot open to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("failed to load persisted graph snapshot"));
        assert!(message.contains("graph.kndb"));
    }

    #[test]
    fn open_rejects_pre_0_2_repo_with_actionable_error() {
        // A repo created by a pre-0.2 kin must be refused UP FRONT with
        // a clear, actionable error — never loaded into a daemon that then fails
        // readiness and gets SIGTERM-killed by the supervisor. The gate fires
        // before the graph snapshot is touched, so a tiny manifest fixture (just
        // the version field) is enough to reproduce it.
        let repo_dir = tempfile::tempdir().unwrap();
        let kin_dir = repo_dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("manifest.json"), r#"{"kin_version":"0.1.0"}"#).unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);

        let err = match DaemonState::open(layout) {
            Ok(_) => panic!("expected pre-0.2 repo open to be refused"),
            Err(err) => err,
        };
        assert!(
            matches!(err, DaemonError::IncompatibleRepo(_)),
            "expected IncompatibleRepo, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("0.1.0"),
            "message must name the found version: {message}"
        );
        assert!(
            message.contains("0.2"),
            "message must name the required floor: {message}"
        );
        assert!(
            message.contains("kin migrate") && message.contains("kin embed --rebuild"),
            "message must name the rebuild commands: {message}"
        );
    }

    #[test]
    fn open_accepts_current_version_repo() {
        // The complement to the gate test: a repo stamped at the current build
        // version opens cleanly (the gate must not false-positive on fresh repos).
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        DaemonState::open(init.layout).expect("current-version repo must open");
    }

    #[cfg(feature = "vector")]
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

    #[test]
    fn first_publish_commit_persists_under_v2_repo_prefix_and_reloads_with_refs() {
        // Hosted publish->serve: a full-content commit into the served
        // graph must persist through the StorageBackend at `<prefix>/<repo>/graph.kndb`
        // (the GCS `v2/<repo>/` layout, reproduced here with a LocalFileBackend rooted
        // at `v2/`) and survive a pod restart with its branch refs intact. A fresh
        // served graph has no branch, so the branch is created before the head update
        // (update_branch_head errors NotFound otherwise).
        use kin_db::LocalFileBackend;
        use kin_model::{
            AuthorId, Branch, BranchName, ChangeStore, EntityDelta, SemanticChange,
            SemanticChangeId, Timestamp,
        };

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;

        let storage = tempfile::tempdir().unwrap();
        let v2_root = storage.path().join("v2");
        let repo_id = "kin";
        let branch_name = BranchName::new("main");

        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(LocalFileBackend::new(&v2_root)),
            repo_id,
            None,
        )
        .unwrap();
        assert_eq!(
            state.graph.entity_count(),
            0,
            "a fresh hosted repo starts with an empty served graph"
        );

        let entity = test_entity("served_fn", "src/lib.rs");
        state.graph.upsert_entity(&entity).unwrap();

        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([7; 32])),
            parents: vec![],
            author: AuthorId::new("tester"),
            message: "first publish".to_string(),
            timestamp: Timestamp::now(),
            entity_deltas: vec![EntityDelta::Added(entity.clone())],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        let change_id = change.id;
        state
            .graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: change_id,
            })
            .unwrap();
        state.graph.create_change(&change).unwrap();
        state
            .graph
            .update_branch_head(&branch_name, &change_id)
            .unwrap();
        state.save_snapshot_full().unwrap();

        let persisted = v2_root.join(repo_id).join("graph.kndb");
        assert!(
            persisted.exists(),
            "served commit must persist under v2/<repo>/graph.kndb at {}",
            persisted.display()
        );

        drop(state);

        let reopened = DaemonState::open_with_backend(
            layout,
            Box::new(LocalFileBackend::new(&v2_root)),
            repo_id,
            None,
        )
        .unwrap();
        assert_eq!(
            reopened.graph.entity_count(),
            1,
            "published content must survive reload from the v2 backend"
        );
        let branches = reopened.graph.list_branches().unwrap();
        assert!(
            branches
                .iter()
                .any(|b| b.name == branch_name && b.head == change_id),
            "published branch head must be visible after reload (refs non-empty)"
        );
    }

    #[test]
    fn storage_backend_replays_sequential_deltas_after_restart() {
        use kin_db::LocalFileBackend;

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "restart-repo";

        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .unwrap();

        let base = test_entity("base_entity", "src/base.rs");
        state.graph.upsert_entity(&base).unwrap();
        state
            .save_snapshot()
            .expect("generation zero must promote a full base snapshot");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);

        let first_delta_entity = test_entity("first_delta_entity", "src/first.rs");
        state.graph.upsert_entity(&first_delta_entity).unwrap();
        state.save_snapshot().expect("persist first delta");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 2);

        let second_delta_entity = test_entity("second_delta_entity", "src/second.rs");
        state.graph.upsert_entity(&second_delta_entity).unwrap();
        state.save_snapshot().expect("persist second delta");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 3);
        drop(state);

        let reopened = DaemonState::open_with_backend(
            layout,
            Box::new(LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .expect("base snapshot plus deltas must reopen");
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 3);
        let entities = reopened.graph.list_all_entities().unwrap();
        let names: HashSet<_> = entities.iter().map(|entity| entity.name.as_str()).collect();
        assert_eq!(entities.len(), 3);
        assert!(names.contains("base_entity"));
        assert!(names.contains("first_delta_entity"));
        assert!(names.contains("second_delta_entity"));
    }

    #[test]
    fn backend_acknowledgement_preserves_mutation_arriving_during_delta_io() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "concurrent-delta-ack";
        let reached_backend = Arc::new(std::sync::Barrier::new(2));
        let resume_backend = Arc::new(std::sync::Barrier::new(2));

        let state = Arc::new(
            DaemonState::open_with_backend(
                layout.clone(),
                Box::new(CleanupFailOnceBackend::blocking_delta(
                    storage.path(),
                    Arc::clone(&reached_backend),
                    Arc::clone(&resume_backend),
                )),
                repo_id,
                None,
            )
            .unwrap(),
        );
        state
            .graph
            .upsert_entity(&test_entity("base_entity", "src/base.rs"))
            .unwrap();
        state.mark_dirty();
        state.save_snapshot().expect("persist full base");
        state.mark_clean();
        assert!(!state.is_dirty());

        state
            .graph
            .upsert_entity(&test_entity("first_delta", "src/first.rs"))
            .unwrap();
        state.mark_dirty();
        let save_state = Arc::clone(&state);
        let save_thread = std::thread::spawn(move || save_state.save_snapshot());
        reached_backend.wait();

        // This mutation lands after the first delta was detached but before its
        // backend authority commit. Acknowledging the first batch must not clear
        // this second mutation.
        state
            .graph
            .upsert_entity(&test_entity("during_io", "src/during.rs"))
            .unwrap();
        state.mark_dirty();
        resume_backend.wait();
        save_thread.join().unwrap().expect("persist first delta");
        // Production callers mark clean after a successful save. The later
        // mutation must keep the background persistence wakeup armed.
        state.mark_clean();
        assert!(state.is_dirty());
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 2);

        state
            .save_snapshot()
            .expect("later mutation must remain pending for the next delta");
        state.mark_clean();
        assert!(!state.is_dirty());
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 3);
        drop(state);

        let reopened = DaemonState::open_with_backend(
            layout,
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .expect("both detached batches must reopen exactly");
        let names: HashSet<_> = reopened
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .map(|entity| entity.name)
            .collect();
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 3);
        assert_eq!(names.len(), 3);
        assert!(names.contains("base_entity"));
        assert!(names.contains("first_delta"));
        assert!(names.contains("during_io"));
    }

    #[test]
    fn post_commit_finalization_retries_without_recommitting_graph() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "finalization-retry";
        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .unwrap();

        state
            .graph
            .upsert_entity(&test_entity("committed", "src/committed.rs"))
            .unwrap();
        state.finalization_fail_once.store(true, Ordering::SeqCst);
        let error = state
            .save_snapshot()
            .expect_err("injected local finalization must surface after commit");
        assert!(error
            .to_string()
            .contains("injected post-commit finalization failure"));
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 0);
        assert!(state
            .post_commit_finalization_pending
            .load(Ordering::SeqCst));

        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        assert_eq!(kin_db::ReadIndex::load(&idx_path).unwrap().entity_count, 0);
        state
            .save_snapshot()
            .expect("no-op save must retry local finalization");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 1);
        assert!(!state
            .post_commit_finalization_pending
            .load(Ordering::SeqCst));
        assert_eq!(kin_db::ReadIndex::load(&idx_path).unwrap().entity_count, 1);
    }

    #[test]
    fn backend_reopen_heals_stale_generation_marker_and_read_index() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "marker-heal";

        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("persisted", "src/persisted.rs"))
            .unwrap();
        state.save_snapshot().unwrap();
        drop(state);

        let marker = layout.kindb_head_generation_path();
        std::fs::write(&marker, "0").unwrap();
        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        std::fs::remove_file(&idx_path).unwrap();

        let reopened = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .expect("reopen must heal artifacts from durable authority");
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 1);
        assert_eq!(kin_db::ReadIndex::load(&idx_path).unwrap().entity_count, 1);
    }

    #[test]
    fn backend_startup_reuses_the_single_recovered_graph() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "single-startup-load";

        let seeded_graph = kin_db::InMemoryGraph::new();
        seeded_graph
            .upsert_entity(&test_entity("loaded_once", "src/loaded.rs"))
            .unwrap();
        let seed_backend = kin_db::LocalFileBackend::new(storage.path());
        seed_backend
            .save_snapshot(
                repo_id,
                &seeded_graph.to_snapshot().to_bytes().unwrap(),
                kin_db::GENERATION_INIT,
            )
            .unwrap();

        let recovery_loads = Arc::new(AtomicU64::new(0));
        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(CleanupFailOnceBackend::counting_load(
                storage.path(),
                Arc::clone(&recovery_loads),
            )),
            repo_id,
            None,
        )
        .expect("startup must finalize from the graph it already recovered");

        assert_eq!(recovery_loads.load(Ordering::SeqCst), 1);
        assert_eq!(state.graph.entity_count(), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 1);
        assert_eq!(
            kin_db::ReadIndex::load(&layout.kindb_snapshot_path().with_extension("kidx"))
                .unwrap()
                .entity_count,
            1
        );
    }

    #[test]
    fn default_local_save_restart_save_recovers_authority_generation() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;

        let first = DaemonState::open(layout.clone()).unwrap();
        let initial_generation = first.snapshot_generation.load(Ordering::SeqCst);
        first
            .graph
            .upsert_entity(&test_entity("first_local", "src/first.rs"))
            .unwrap();
        first.save_snapshot().unwrap();
        assert_eq!(
            first.snapshot_generation.load(Ordering::SeqCst),
            initial_generation + 1
        );
        drop(first);

        let second = DaemonState::open(layout.clone()).unwrap();
        assert_eq!(
            second.snapshot_generation.load(Ordering::SeqCst),
            initial_generation + 1
        );
        second
            .graph
            .upsert_entity(&test_entity("second_local", "src/second.rs"))
            .unwrap();
        second.save_snapshot().unwrap();
        assert_eq!(
            second.snapshot_generation.load(Ordering::SeqCst),
            initial_generation + 2
        );
        drop(second);

        let reopened = DaemonState::open(layout.clone()).unwrap();
        assert_eq!(
            reopened.snapshot_generation.load(Ordering::SeqCst),
            initial_generation + 2
        );
        assert_eq!(
            DaemonState::read_generation_marker(&layout),
            initial_generation + 2
        );
        let names: HashSet<_> = reopened
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .map(|entity| entity.name)
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains("first_local"));
        assert!(names.contains("second_local"));
    }

    #[test]
    fn default_local_force_full_rejects_stale_daemon_generation() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let snapshot_path = layout.kindb_snapshot_path();
        let state = DaemonState::open(layout.clone()).unwrap();
        let stale_generation = state.snapshot_generation.load(Ordering::SeqCst);

        let external = kin_db::InMemoryGraph::new();
        let external_entity = test_entity("external_writer", "src/external.rs");
        external.upsert_entity(&external_entity).unwrap();
        let (_, external_generation) =
            kin_db::SnapshotManager::save_graph_with_expected_generation(
                &snapshot_path,
                &external,
                stale_generation,
            )
            .unwrap();
        assert_eq!(external_generation, stale_generation + 1);

        let stale_entity = test_entity("stale_daemon", "src/stale.rs");
        state.graph.upsert_entity(&stale_entity).unwrap();
        let error = state
            .save_snapshot_full()
            .expect_err("stale full daemon writer must lose the generation CAS");
        assert!(error.to_string().contains(&format!(
            "expected {stale_generation}, found {external_generation}"
        )));
        assert_eq!(
            state.snapshot_generation.load(Ordering::SeqCst),
            stale_generation,
            "failed stale save must not advance its in-memory cursor"
        );
        drop(state);

        let reopened = DaemonState::open(layout).unwrap();
        assert_eq!(
            reopened.snapshot_generation.load(Ordering::SeqCst),
            external_generation
        );
        assert!(reopened
            .graph
            .get_entity(&external_entity.id)
            .unwrap()
            .is_some());
        assert!(reopened
            .graph
            .get_entity(&stale_entity.id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn default_local_reopen_heals_crash_between_authority_commit_and_finalization() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let snapshot_path = layout.kindb_snapshot_path();
        let index_path = snapshot_path.with_extension("kidx");

        let state = DaemonState::open(layout.clone()).unwrap();
        let base_generation = state.snapshot_generation.load(Ordering::SeqCst);
        let entity = test_entity("authority_only", "src/authority.rs");
        state.graph.upsert_entity(&entity).unwrap();

        // Commit graph authority directly, then simulate process death before
        // DaemonState can publish either its marker or read index. Removing the
        // canonical compatibility projection additionally proves discovery and
        // reopen follow the atomic authority sidecar.
        let (_, generation) = kin_db::SnapshotManager::save_graph_with_generation(
            &snapshot_path,
            state.graph.as_ref(),
        )
        .unwrap();
        assert_eq!(generation, base_generation + 1);
        assert_eq!(
            DaemonState::read_generation_marker(&layout),
            base_generation
        );
        assert_eq!(
            kin_db::ReadIndex::load(&index_path).unwrap().entity_count,
            0
        );
        drop(state);
        std::fs::remove_file(&snapshot_path).unwrap();

        let reopened = DaemonState::open(layout.clone())
            .expect("validated local authority must heal derived artifacts before serving");
        assert_eq!(
            reopened.snapshot_generation.load(Ordering::SeqCst),
            base_generation + 1
        );
        assert_eq!(
            DaemonState::read_generation_marker(&layout),
            base_generation + 1
        );
        assert_eq!(
            kin_db::ReadIndex::load(&index_path).unwrap().entity_count,
            1
        );
        assert_eq!(
            reopened.graph.get_entity(&entity.id).unwrap().unwrap().name,
            "authority_only"
        );
    }

    #[test]
    fn default_local_finalization_rejects_newer_external_authority() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let snapshot_path = layout.kindb_snapshot_path();
        let index_path = snapshot_path.with_extension("kidx");

        let state = DaemonState::open(layout.clone()).unwrap();
        state
            .graph
            .upsert_entity(&test_entity("daemon_generation", "src/daemon.rs"))
            .unwrap();
        state.save_snapshot().unwrap();
        let daemon_generation = state.snapshot_generation.load(Ordering::SeqCst);
        let daemon_index_count = kin_db::ReadIndex::load(&index_path).unwrap().entity_count;

        let external_graph = {
            let snapshot = kin_db::SnapshotManager::open_read_only(&snapshot_path).unwrap();
            snapshot.graph()
        };
        external_graph
            .upsert_entity(&test_entity("external_generation", "src/external.rs"))
            .unwrap();
        let (_, external_generation) =
            kin_db::SnapshotManager::save_graph_with_expected_generation(
                &snapshot_path,
                external_graph.as_ref(),
                daemon_generation,
            )
            .unwrap();
        assert_eq!(external_generation, daemon_generation + 1);

        state
            .post_commit_finalization_pending
            .store(true, Ordering::SeqCst);
        let error = state
            .finalize_committed_generation(daemon_generation)
            .expect_err("derived artifacts must not mix two authority generations");
        assert!(error.to_string().contains(&format!(
            "expected generation {daemon_generation}, recovered {external_generation}"
        )));
        assert_eq!(
            DaemonState::read_generation_marker(&layout),
            daemon_generation,
            "a failed stale finalization must not publish the newer authority under the old cursor"
        );
        assert_eq!(
            kin_db::ReadIndex::load(&index_path).unwrap().entity_count,
            daemon_index_count,
            "a failed stale finalization must preserve the last coherent canonical index"
        );
        assert!(state
            .post_commit_finalization_pending
            .load(Ordering::SeqCst));
    }

    #[test]
    fn committed_full_snapshot_cleanup_failure_does_not_wedge_next_cas() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "cleanup-retry";

        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(CleanupFailOnceBackend::new(storage.path(), true)),
            repo_id,
            None,
        )
        .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("base_entity", "src/base.rs"))
            .unwrap();
        state
            .save_snapshot()
            .expect("committed snapshot survives cleanup failure");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);

        state
            .graph
            .upsert_entity(&test_entity("next_entity", "src/next.rs"))
            .unwrap();
        state
            .save_snapshot()
            .expect("next delta CAS uses committed generation, not stale cursor");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 2);
        drop(state);

        let reopened = DaemonState::open_with_backend(
            layout,
            Box::new(CleanupFailOnceBackend::new(storage.path(), false)),
            repo_id,
            None,
        )
        .expect("snapshot plus next delta reopens after cleanup failure");
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 2);
        assert_eq!(reopened.graph.entity_count(), 2);
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
    fn locate_only_finalization_invalidates_canonical_index_before_head_marker() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let index_path = layout.kindb_snapshot_path().with_extension("kidx");
        std::fs::write(&index_path, b"stale canonical index").unwrap();
        let legacy_generation = layout.kindb_dir().join("generation");
        std::fs::write(&legacy_generation, "0").unwrap();
        let state = test_state(layout.clone(), repo_dir.path());

        state.finalize_loaded_locate_generation(7).unwrap();

        assert!(
            !index_path.exists(),
            "a partial locate graph must never replace or retain a canonical full read index"
        );
        assert_eq!(DaemonState::read_generation_marker(&layout), 7);
        assert_eq!(
            std::fs::read_to_string(legacy_generation).unwrap(),
            "0",
            "locate-only freshness must not mutate KinDB's legacy projection marker"
        );
    }

    #[test]
    fn sequential_saves_leave_consistent_kndb_kidx_pair() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let kndb_path = layout.kindb_snapshot_path();
        let kidx_path = kndb_path.with_extension("kidx");
        let legacy_projection_generation = layout.kindb_dir().join("generation");
        std::fs::write(&legacy_projection_generation, "0").unwrap();
        let state = test_state(layout.clone(), repo_dir.path());
        state
            .graph
            .upsert_entity(&test_entity("paired_fn", "src/lib.rs"))
            .unwrap();

        // Two back-to-back saves (as the persist loop + flush would issue) must
        // each leave both halves of the on-disk pair present and reloadable —
        // no torn kndb without its kidx, and no kidx without its kndb.
        state.save_snapshot().unwrap();
        assert_eq!(
            std::fs::read_to_string(&legacy_projection_generation)
                .unwrap()
                .trim(),
            "0"
        );
        state.save_snapshot().unwrap();

        assert_eq!(
            DaemonState::read_generation_marker(&layout),
            2,
            "the daemon freshness marker must follow the durable authority head"
        );
        assert_eq!(
            std::fs::read_to_string(&legacy_projection_generation)
                .unwrap()
                .trim(),
            "0",
            "a delta must not mislabel the legacy full-snapshot projection as current"
        );

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

    #[cfg(feature = "embeddings")]
    #[test]
    fn flush_embed_progress_persists_snapshot_and_reports_pending() {
        // The incremental flush persists the snapshot (full bundle on
        // the first write) and returns the persisted resume count. With no
        // embedder run the lone entity stays unembedded, so `pending` reflects it
        // — proving the flush composes the graph-delta + sidecar write and reads
        // coverage from persisted graph-vs-index truth.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        state
            .graph
            .upsert_entity(&test_entity("embed_me", "src/lib.rs"))
            .unwrap();
        state.graph.queue_missing_for_embedding();

        let pending = state.flush_embed_progress().expect("flush must succeed");
        assert!(
            state.layout.kindb_snapshot_path().exists(),
            "flush must persist the snapshot bundle"
        );
        assert!(
            pending >= 1,
            "the unembedded entity must remain pending (no embedder ran); got {pending}"
        );
    }

    #[test]
    fn persisted_mcp_transactions_missing_file_loads_empty() {
        // A clean start (no mcp_transactions.json) yields an empty set,
        // never an error — startup must not fail on transaction recovery.
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().to_path_buf());
        assert!(load_persisted_mcp_transactions(&layout).is_empty());
    }

    #[test]
    fn persisted_mcp_transactions_round_trip_through_disk() {
        // A staged transaction written to the durable mirror reloads
        // intact — the mechanism that lets begin/stage survive a daemon restart.
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().to_path_buf());
        let mut store = HashMap::new();
        store.insert(
            "tx-1".to_string(),
            kin_mcp::McpTransaction {
                transaction_id: "tx-1".to_string(),
                session_id: "sess".to_string(),
                scope: "file:src/lib.rs".to_string(),
                state: "active".to_string(),
                staged_operations: Vec::new(),
            },
        );
        write_persisted_mcp_transactions(&layout, &store);
        assert!(mcp_transactions_disk_path(&layout).exists());

        let restored = load_persisted_mcp_transactions(&layout);
        assert_eq!(restored.len(), 1);
        assert_eq!(
            restored.get("tx-1").map(|t| t.scope.as_str()),
            Some("file:src/lib.rs")
        );
    }

    #[test]
    fn persisted_mcp_transactions_corrupt_file_degrades_to_empty() {
        // A torn/corrupt mirror degrades to empty (logged loud, never a
        // startup crash) rather than poisoning daemon boot.
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().to_path_buf());
        std::fs::write(mcp_transactions_disk_path(&layout), b"{not valid json").unwrap();
        assert!(load_persisted_mcp_transactions(&layout).is_empty());
    }
}
