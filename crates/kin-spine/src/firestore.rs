// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Store-backed spine backend.
//!
//! [`FirestoreSpineBackend`] keeps every read on a fast in-memory cache. Durable
//! writes stage immutable cursor-bound publications and become visible only
//! through one atomic repository-head compare-and-swap. Startup hydration
//! follows committed heads only; unreachable partial stages and legacy rows are
//! never mixed into the cache.
//!
//! The production store is [`FirestoreStore`] (behind the `firestore` feature),
//! which talks to the Firestore v1 REST API authenticated via the GCE metadata
//! server (Workload Identity on GKE).
//!
//! Firestore v2 collections:
//! ```text
//! spine_repo_heads_v2/{sha256(repo_id)}
//!   repository head payload
//!
//! spine_publications_v2/{publication_id}
//!   immutable publication manifest
//!
//! spine_stages_v2/{publication_id}
//!   revision-fenced cleanup marker written before any staged rows
//!
//! spine_entities_v2/{publication_id}_{entity_id}
//!   repo_id, source_cursor, publication_id, payload
//!
//! spine_edges_v2/{publication_id}_{sha256(edge)}
//!   repo_id, source_cursor, publication_id, payload
//! ```
//!
//! `payload` carries the JSON-serialized `EntityEntry` / `CrossRepoEdge` and is
//! the authoritative copy used to rebuild the cache; the sibling fields stay
//! human-readable for the Firestore console and back the by-repo delete queries.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use kin_model::{Entity, EntityId, EntityKind, Relation, SemanticFingerprint};
use parking_lot::Mutex as ParkingMutex;
use tracing::{error, info, warn};

use crate::backend::{
    InMemorySpineBackend, PreparedRepoSpinePublication, SpineBackend, SpineError,
};
use crate::federation::FederatedImpact;
use crate::index::{CrossRepoEdge, CrossRepoEdgesSnapshot, EntityEntry};
use crate::publication::{
    CanonicalRepoPublication, RepoPublicationCommit, RepoPublicationHead,
    RepoPublicationPhase, RepoSpinePublication, SpineRolloutFence, SpineRolloutFenceCommit,
    SpineRolloutFenceEvidence, SpineSourceCursor,
};
#[cfg(test)]
use crate::publication::SpineRolloutRepositoryFence;
use crate::store::{
    LoadedRepoPublication, LoadedSpineRolloutFence, PreparedStorePublication,
    RepoPublicationCleanupProgress, SpineStore, StoreHeadPrecondition,
};

const CLEANUP_DOCUMENTS_PER_COMMIT: usize = 100;
const CLEANUP_PASSES_PER_TERMINAL_OUTCOME: usize = 4;
const CLEANUP_CONTINUATION_RETRY_LIMIT: usize = 8;
const CLEANUP_CONTINUATION_PASS_LIMIT: usize = 64;
const CLEANUP_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

struct CleanupSweepGate {
    running: bool,
    next_due: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RolloutFenceReconciliation {
    CandidateCurrent(SpineRolloutFenceEvidence),
    NewerOrDifferent(Option<SpineRolloutFenceEvidence>),
    Retry,
}

fn classify_rollout_fence_reconciliation(
    candidate: &SpineRolloutFence,
    observed: Option<&LoadedSpineRolloutFence>,
) -> RolloutFenceReconciliation {
    let Some(observed) = observed else {
        return RolloutFenceReconciliation::Retry;
    };
    if observed.fence.payload_sha256 == candidate.payload_sha256 {
        return RolloutFenceReconciliation::CandidateCurrent(observed.evidence());
    }
    if observed.fence.scope != candidate.scope
        || observed.fence.rollout_fence >= candidate.rollout_fence
    {
        return RolloutFenceReconciliation::NewerOrDifferent(Some(observed.evidence()));
    }
    RolloutFenceReconciliation::Retry
}

/// Spine backend that reads from an in-memory cache and publishes through a
/// durable [`SpineStore`].
///
/// Strategy: stage and CAS through the store, then install the committed
/// publication in the local cache. On startup,
/// [`hydrate`](FirestoreSpineBackend::hydrate) follows durable heads into the
/// cache. Hot reads remain in memory without making uncommitted rows visible.
pub struct FirestoreSpineBackend {
    /// Local in-memory cache — all reads go here.
    cache: InMemorySpineBackend,
    /// Keep one process's durable head transitions and local cache installs in
    /// the same order. Firestore's precondition is still the cross-pod arbiter.
    refresh_write_lock: ParkingMutex<()>,
    /// Repository heads are append-only. If a head that this process has
    /// already served disappears, refresh fails instead of leaving stale local
    /// authority visible behind a nominally successful reload.
    known_durable_repos: ParkingMutex<Option<HashSet<String>>>,
    /// Durable backing store; the only seam that touches an external system.
    store: Arc<dyn SpineStore>,
    /// At most one background cleanup continuation per repository in this
    /// process. Firestore marker revisions remain the cross-pod arbiter.
    cleanup_workers: Arc<ParkingMutex<HashSet<String>>>,
    /// Request-time freshness may call hydrate for every authority read. One
    /// process-wide, TTL-gated maintenance sweep prevents that path from
    /// spawning one cleanup thread and query per repository on every request.
    cleanup_sweep_gate: Arc<ParkingMutex<CleanupSweepGate>>,
    publication_backend_id: crate::backend::SpinePublicationBackendId,
}

impl FirestoreSpineBackend {
    /// Create a Firestore-backed spine backend.
    ///
    /// `project_id`: GCP project ID.
    /// `database_id`: Firestore database (typically "(default)").
    #[cfg(feature = "firestore")]
    pub fn new(project_id: String, database_id: Option<String>) -> Self {
        Self::with_store(Arc::new(FirestoreStore::new(project_id, database_id)))
    }

    /// Create a backend over an arbitrary durable store.
    ///
    /// This is the seam used both by the Firestore constructor and by tests that
    /// inject an in-memory store.
    pub fn with_store(store: Arc<dyn SpineStore>) -> Self {
        Self {
            cache: InMemorySpineBackend::new(),
            refresh_write_lock: ParkingMutex::new(()),
            known_durable_repos: ParkingMutex::new(None),
            store,
            cleanup_workers: Arc::new(ParkingMutex::new(HashSet::new())),
            cleanup_sweep_gate: Arc::new(ParkingMutex::new(CleanupSweepGate {
                running: false,
                next_due: Instant::now(),
            })),
            publication_backend_id: crate::backend::SpinePublicationBackendId::new(),
        }
    }

    fn load_stable_rollout_and_publications(
        &self,
        operation: &str,
    ) -> Result<(LoadedSpineRolloutFence, Vec<LoadedRepoPublication>), SpineError> {
        for _ in 0..3 {
            let selected = self.store.load_rollout_fence()?.ok_or_else(|| {
                SpineError::Backend(format!(
                    "{operation} requires an active durable spine rollout fence"
                ))
            })?;
            let publications = self.store.load_repo_publications()?;
            let observed = self.store.load_rollout_fence()?.ok_or_else(|| {
                SpineError::Backend(format!(
                    "durable spine rollout fence disappeared during {operation}"
                ))
            })?;
            if selected == observed {
                return Ok((selected, publications));
            }
        }
        Err(SpineError::Backend(format!(
            "durable spine rollout fence did not stabilize after three {operation} attempts"
        )))
    }

    /// Persist the one-way boundary after every legacy repository has a valid
    /// v2 head and older cursorless writers have been removed from service.
    ///
    /// This method verifies coverage immediately before asking the store to
    /// create its immutable marker. It is intentionally explicit and is never
    /// called automatically during a rolling deployment.
    pub fn complete_legacy_migration(&self) -> Result<(), SpineError> {
        let _migration = self.refresh_write_lock.lock();
        let (active_rollout_fence, loaded) =
            self.load_stable_rollout_and_publications("legacy migration completion")?;
        for publication in &loaded {
            active_rollout_fence
                .fence
                .validate_publication_repo(&publication.head.repo_id)?;
        }
        let legacy_repos = self.store.load_repos()?;
        let legacy_edges = self.store.load_edges()?;
        let committed_repo_ids = loaded
            .iter()
            .map(|publication| publication.head.repo_id.clone())
            .collect::<HashSet<_>>();
        let uncovered_legacy = legacy_repos
            .iter()
            .map(|repo| repo.repo_id.clone())
            .chain(legacy_edges.iter().flat_map(|edge| {
                [edge.src_repo.clone(), edge.dst_repo.clone()]
            }))
            .filter(|repo_id| !committed_repo_ids.contains(repo_id))
            .collect::<std::collections::BTreeSet<_>>();
        if !uncovered_legacy.is_empty() {
            return Err(SpineError::Backend(format!(
                "legacy spine migration cannot complete while repositories lack v2 heads: {}",
                uncovered_legacy.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
        self.store.complete_legacy_migration(&active_rollout_fence)?;
        Ok(())
    }

    /// Continue marker-fenced cleanup outside the publication latency path.
    ///
    /// Each Firestore commit remains capped at 100 writes. The worker keeps
    /// following the store's explicit `more` result until the repo is drained,
    /// including when no later user publication arrives. Repeated contention or
    /// transport failure is bounded and loud; every surviving row remains
    /// discoverable through its stage marker for a later refresh to reschedule.
    fn schedule_cleanup_continuation(&self, active_head: RepoPublicationHead) {
        let repo_id = active_head.repo_id.clone();
        {
            let mut workers = self.cleanup_workers.lock();
            if !workers.insert(repo_id.clone()) {
                return;
            }
        }

        let store = Arc::clone(&self.store);
        let workers = Arc::clone(&self.cleanup_workers);
        let thread_repo_id = repo_id.clone();
        let spawn = std::thread::Builder::new()
            .name(format!("spine-cleanup-{repo_id}"))
            .spawn(move || {
                let mut consecutive_failures = 0usize;
                let mut passes = 0usize;
                let mut cleanup_more = true;
                while cleanup_more && passes < CLEANUP_CONTINUATION_PASS_LIMIT {
                    passes += 1;
                    match store.cleanup_repo_publications(
                        &active_head,
                        CLEANUP_DOCUMENTS_PER_COMMIT,
                    ) {
                        Ok(progress) if !progress.more => cleanup_more = false,
                        Ok(progress) if progress.deleted > 0 => {
                            consecutive_failures = 0;
                        }
                        Ok(_) => {
                            consecutive_failures += 1;
                            if consecutive_failures >= CLEANUP_CONTINUATION_RETRY_LIMIT {
                                warn!(
                                    repo_id = %thread_repo_id,
                                    attempts = consecutive_failures,
                                    "spine cleanup continuation made no progress; leaving marker-discoverable work for a later refresh"
                                );
                                cleanup_more = false;
                            }
                            std::thread::yield_now();
                        }
                        Err(error) => {
                            consecutive_failures += 1;
                            if consecutive_failures >= CLEANUP_CONTINUATION_RETRY_LIMIT {
                                warn!(
                                    repo_id = %thread_repo_id,
                                    attempts = consecutive_failures,
                                    error = %error,
                                    "spine cleanup continuation exhausted bounded retries; leaving marker-discoverable work for a later refresh"
                                );
                                cleanup_more = false;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(
                                10 * consecutive_failures as u64,
                            ));
                        }
                    }
                }
                if cleanup_more {
                    warn!(
                        repo_id = %thread_repo_id,
                        passes,
                        "spine cleanup continuation reached its bounded pass limit; leaving marker-discoverable work for the next maintenance sweep"
                    );
                }
                workers.lock().remove(&thread_repo_id);
            });
        if let Err(error) = spawn {
            self.cleanup_workers.lock().remove(&repo_id);
            warn!(
                repo_id = %repo_id,
                error = %error,
                "failed to start spine cleanup continuation"
            );
        }
    }

    /// Schedule at most one process-wide cleanup discovery sweep per TTL.
    ///
    /// The sweep visits repositories serially. It takes one bounded cleanup
    /// pass to prove whether work exists and continues only repositories whose
    /// store result says `more`. Publication commits schedule known pending work
    /// directly, so this scan exists only to recover abandoned stages after a
    /// writer process dies.
    fn schedule_cleanup_sweep(&self, active_heads: Vec<RepoPublicationHead>) {
        if active_heads.is_empty() {
            return;
        }
        let now = Instant::now();
        {
            let mut gate = self.cleanup_sweep_gate.lock();
            if gate.running || now < gate.next_due {
                return;
            }
            gate.running = true;
            gate.next_due = now + CLEANUP_SWEEP_INTERVAL;
        }

        let store = Arc::clone(&self.store);
        let workers = Arc::clone(&self.cleanup_workers);
        let gate = Arc::clone(&self.cleanup_sweep_gate);
        let spawn = std::thread::Builder::new()
            .name("spine-cleanup-sweep".to_string())
            .spawn(move || {
                for active_head in active_heads {
                    let repo_id = active_head.repo_id.clone();
                    {
                        let mut active = workers.lock();
                        if !active.insert(repo_id.clone()) {
                            continue;
                        }
                    }

                    let mut consecutive_failures = 0usize;
                    let mut passes = 0usize;
                    let mut cleanup_more = true;
                    while cleanup_more && passes < CLEANUP_CONTINUATION_PASS_LIMIT {
                        passes += 1;
                        match store.cleanup_repo_publications(
                            &active_head,
                            CLEANUP_DOCUMENTS_PER_COMMIT,
                        ) {
                            Ok(progress) if !progress.more => cleanup_more = false,
                            Ok(progress) if progress.deleted > 0 => {
                                consecutive_failures = 0;
                            }
                            Ok(_) => {
                                consecutive_failures += 1;
                                if consecutive_failures >= CLEANUP_CONTINUATION_RETRY_LIMIT {
                                    warn!(
                                        repo_id = %repo_id,
                                        attempts = consecutive_failures,
                                        "spine cleanup sweep made no progress; leaving marker-discoverable work for a later TTL"
                                    );
                                    cleanup_more = false;
                                }
                            }
                            Err(error) => {
                                consecutive_failures += 1;
                                if consecutive_failures >= CLEANUP_CONTINUATION_RETRY_LIMIT {
                                    warn!(
                                        repo_id = %repo_id,
                                        attempts = consecutive_failures,
                                        error = %error,
                                        "spine cleanup sweep exhausted bounded retries; leaving marker-discoverable work for a later TTL"
                                    );
                                    cleanup_more = false;
                                }
                            }
                        }
                    }
                    if cleanup_more {
                        warn!(
                            repo_id = %repo_id,
                            passes,
                            "spine cleanup sweep reached its bounded pass limit; leaving marker-discoverable work for a later TTL"
                        );
                    }
                    workers.lock().remove(&repo_id);
                }
                gate.lock().running = false;
            });
        if let Err(error) = spawn {
            let mut gate = self.cleanup_sweep_gate.lock();
            gate.running = false;
            gate.next_due = Instant::now();
            warn!(error = %error, "failed to start spine cleanup maintenance sweep");
        }
    }

    /// Refresh the local cache from the durable store.
    ///
    /// Loads every committed repository head and its validated immutable rows
    /// into the in-memory cache. Every call re-reads the stable durable head set
    /// so a non-writing pod cannot serve a prior winner indefinitely. A failed
    /// load leaves the previous known cache installed but returns an error, and
    /// hosted request boundaries must refuse to serve through that error.
    pub fn hydrate(&self) -> Result<(), SpineError> {
        let _hydrate = self.refresh_write_lock.lock();

        info!("refreshing spine cache from durable committed heads...");

        let (active_rollout_fence, loaded) =
            self.load_stable_rollout_and_publications("hydration")?;

        // Legacy rows have no cursor or committed head. During migration they
        // remain physically present but cannot be served. Refuse startup until
        // every legacy repository has a v2 head, then ignore legacy collections
        // permanently. This prevents a partial migration from silently dropping
        // one repository or mixing generations.
        let legacy_migration_complete = self.store.legacy_migration_complete()?;
        if !legacy_migration_complete {
            let legacy_repos = self.store.load_repos()?;
            let legacy_edges = self.store.load_edges()?;
            let committed_repo_ids = loaded
                .iter()
                .map(|publication| publication.head.repo_id.clone())
                .collect::<HashSet<_>>();
            let uncovered_legacy = legacy_repos
                .iter()
                .map(|repo| repo.repo_id.clone())
                .chain(legacy_edges.iter().flat_map(|edge| {
                    [edge.src_repo.clone(), edge.dst_repo.clone()]
                }))
                .filter(|repo_id| !committed_repo_ids.contains(repo_id))
                .collect::<std::collections::BTreeSet<_>>();
            if !uncovered_legacy.is_empty() {
                return Err(SpineError::Backend(format!(
                    "legacy spine rows have no committed cursor-bound head for repositories: {}; republish them before hydration",
                    uncovered_legacy.into_iter().collect::<Vec<_>>().join(", ")
                )));
            }
        }

        let mut canonical = Vec::with_capacity(loaded.len());
        let mut seen_repos = HashSet::with_capacity(loaded.len());
        for publication in loaded {
            active_rollout_fence
                .fence
                .validate_publication_repo(&publication.head.repo_id)?;
            if !seen_repos.insert(publication.head.repo_id.clone()) {
                return Err(SpineError::Serialization(format!(
                    "multiple committed heads loaded for repo {}",
                    publication.head.repo_id
                )));
            }
            canonical.push(CanonicalRepoPublication::validate_loaded(
                publication.head,
                publication.entries,
                publication.outgoing_edges,
            )?);
        }

        let durable_repo_ids = canonical
            .iter()
            .map(|publication| publication.head.repo_id.clone())
            .collect::<HashSet<_>>();
        {
            let known = self.known_durable_repos.lock();
            if let Some(previous) = known.as_ref() {
                let disappeared = previous
                    .difference(&durable_repo_ids)
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                if !disappeared.is_empty() {
                    return Err(SpineError::Backend(format!(
                        "committed spine repository heads disappeared even though head deletion is unsupported: {}",
                        disappeared.into_iter().collect::<Vec<_>>().join(", ")
                    )));
                }
            }
        }

        let repo_count = canonical.len();
        let active_heads = canonical
            .iter()
            .map(|publication| publication.head.clone())
            .collect::<Vec<_>>();
        let entity_count: usize = canonical
            .iter()
            .map(|publication| publication.publication.entries.len())
            .sum();
        let edge_count: usize = canonical
            .iter()
            .map(|publication| {
                publication
                    .publication
                    .outgoing_edges
                    .as_ref()
                    .map_or(0, Vec::len)
            })
            .sum();

        // Install every committed root first. Edge publications carry a root
        // map for the whole hydrated set, so resolving one repo before later
        // roots exist would leave an otherwise complete earlier repo dirty.
        for publication in &canonical {
            let candidate = &publication.publication;
            self.cache.index().install_repo_publication(
                &candidate.repo_id,
                candidate.entries.clone(),
                &candidate.root_hash,
                candidate.source_cursor,
                None,
                None,
            );
        }
        for publication in canonical {
            let candidate = publication.publication;
            if candidate.outgoing_edges.is_some() {
                self.cache.index().install_repo_publication(
                    &candidate.repo_id,
                    candidate.entries,
                    &candidate.root_hash,
                    candidate.source_cursor,
                    candidate.outgoing_edges,
                    candidate.resolution_roots.as_ref(),
                );
            }
        }
        *self.known_durable_repos.lock() = Some(durable_repo_ids);

        info!(
            repos = repo_count,
            entities = entity_count,
            edges = edge_count,
            "spine cache committed-head refresh complete"
        );
        self.schedule_cleanup_sweep(active_heads);
        Ok(())
    }
}

impl SpineBackend for FirestoreSpineBackend {
    fn advance_rollout_fence(
        &self,
        fence: SpineRolloutFence,
    ) -> Result<SpineRolloutFenceCommit, SpineError> {
        let _fence_write = self.refresh_write_lock.lock();
        self.store.advance_rollout_fence(fence)
    }

    fn active_rollout_fence(&self) -> Result<LoadedSpineRolloutFence, SpineError> {
        self.store.load_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend("active durable spine rollout fence is missing".to_string())
        })
    }

    fn complete_legacy_migration(&self) -> Result<(), SpineError> {
        FirestoreSpineBackend::complete_legacy_migration(self)
    }

    fn refresh_committed_publications(&self) -> Result<(), SpineError> {
        self.hydrate()
    }

    fn prepare_repo_publication(
        &self,
        publication: RepoSpinePublication,
    ) -> Result<PreparedRepoSpinePublication, SpineError> {
        let prepared = self.store.prepare_repo_publication(publication)?;
        Ok(PreparedRepoSpinePublication::bind(
            self.publication_backend_id,
            prepared,
        ))
    }

    fn commit_repo_publication(
        &self,
        prepared: PreparedRepoSpinePublication,
    ) -> Result<RepoPublicationCommit, SpineError> {
        let prepared =
            prepared.into_store_preparation(self.publication_backend_id)?;

        // Serialize the durable CAS and local installation in this process. The
        // Firestore precondition arbitrates across processes; this lock prevents
        // a slower local installer from overwriting the cache after a later CAS.
        let _commit = self.refresh_write_lock.lock();
        let mut outcome = self.store.commit_repo_publication(&prepared)?;

        // A second pod may advance the head immediately after this pod's CAS,
        // or the CAS response itself may have required reconciliation. Resolve
        // the stable durable winner and install that publication, never the
        // caller's merely prepared rows.
        let repo_id = prepared.candidate_head().repo_id.clone();
        let winner = self.store.load_repo_publication(&repo_id)?;
        let Some(winner) = winner else {
            if matches!(&outcome, RepoPublicationCommit::Conflict(_)) {
                return Ok(outcome);
            }
            return Err(SpineError::Backend(format!(
                "repo {repo_id} has no committed publication after its successful head CAS"
            )));
        };
        let winner = CanonicalRepoPublication::validate_loaded(
            winner.head,
            winner.entries,
            winner.outgoing_edges,
        )?;
        if winner.head.publication_id != prepared.candidate_head().publication_id
            && !matches!(&outcome, RepoPublicationCommit::Conflict(_))
        {
            outcome = RepoPublicationCommit::Conflict(
                crate::publication::RepoPublicationConflict::against(
                    prepared.candidate_head().source_cursor,
                    Some(&winner.head),
                ),
            );
        }

        let winner_head = winner.head.clone();
        let publication = winner.publication;
        self.cache.index().install_repo_publication(
            &publication.repo_id,
            publication.entries,
            &publication.root_hash,
            publication.source_cursor,
            publication.outgoing_edges,
            publication.resolution_roots.as_ref(),
        );
        if let RepoPublicationCommit::Conflict(conflict) = &outcome {
            warn!(
                repo_id = %repo_id,
                attempted_cursor = %prepared.candidate_head().source_cursor,
                observed_cursor = ?conflict.observed_cursor,
                "durable spine head compare-and-swap lost"
            );
        }
        let mut cleanup_more = false;
        for _ in 0..CLEANUP_PASSES_PER_TERMINAL_OUTCOME {
            match self.store.cleanup_repo_publications(
                &winner_head,
                CLEANUP_DOCUMENTS_PER_COMMIT,
            ) {
                Ok(progress) => {
                    cleanup_more = progress.more;
                    if !progress.more {
                        break;
                    }
                }
                Err(error) => {
                    warn!(
                        repo_id = %repo_id,
                        error = %error,
                        "bounded unreachable spine-row cleanup deferred"
                    );
                    cleanup_more = false;
                    break;
                }
            }
        }
        if cleanup_more {
            self.schedule_cleanup_continuation(winner_head);
        }
        Ok(outcome)
    }

    fn source_cursor(&self, repo_id: &str) -> Option<SpineSourceCursor> {
        self.cache.index().source_cursor(repo_id)
    }

    fn register_repo(&self, repo_id: &str, entries: Vec<EntityEntry>, root_hash: &str) {
        let _ = (entries, root_hash);
        error!(
            repo_id,
            "refusing cursorless Firestore spine registration; use prepare_repo_publication and commit_repo_publication"
        );
    }

    fn resolve(
        &self,
        name: &str,
        kind: Option<EntityKind>,
        reference_fingerprint: Option<&SemanticFingerprint>,
    ) -> Vec<EntityEntry> {
        // Always read from the local cache (populated by committed publication
        // installs and hydration).
        self.cache.resolve(name, kind, reference_fingerprint)
    }

    fn lookup_by_id(&self, repo_id: &str, entity_id: &EntityId) -> Option<EntityEntry> {
        self.cache.lookup_by_id(repo_id, entity_id)
    }

    fn cross_repo_edges_for(&self, repo_id: &str, entity_id: &EntityId) -> Vec<CrossRepoEdge> {
        self.cache.cross_repo_edges_for(repo_id, entity_id)
    }

    fn authority_complete(&self) -> bool {
        // The same fail-closed rule the snapshot below applies, said directly.
        // The trait's default derives this by materializing the whole snapshot,
        // which for this backend clones every cached edge and entity to arrive
        // at a constant. Stating it here keeps the policy in one readable place
        // per backend rather than emergent from what the default happens to
        // read, and a health probe stops paying a full clone for one boolean.
        false
    }

    fn cross_repo_edges_snapshot(&self) -> CrossRepoEdgesSnapshot {
        // Durable rows and this pod's graph refreshes are useful advisory
        // positives, but neither can prove that every other pod observed the
        // same registered roots. Keep completeness fail-closed until the
        // durable backend owns a shared pass/root CAS.
        let mut snapshot = self.cache.cross_repo_edges_snapshot();
        snapshot.complete = false;
        snapshot
    }

    fn cross_repo_xref_response(
        &self,
        repo_id: &str,
        entity_id: &EntityId,
    ) -> crate::SpineXrefResponse {
        let mut response = self.cache.cross_repo_xref_response(repo_id, entity_id);
        response.authority_complete = false;
        response
    }

    fn add_cross_repo_edge(&self, edge: CrossRepoEdge) {
        error!(
            repo_id = %edge.src_repo,
            "refusing cursorless Firestore spine edge write; publish a complete cursor-bound edge phase"
        );
    }

    fn root_hash(&self, repo_id: &str) -> Option<String> {
        self.cache.root_hash(repo_id)
    }

    fn entity_count(&self) -> usize {
        self.cache.entity_count()
    }

    fn repo_count(&self) -> usize {
        self.cache.repo_count()
    }

    fn edge_count(&self) -> usize {
        self.cache.edge_count()
    }

    fn registered_repo_ids(&self) -> HashSet<String> {
        self.cache.registered_repo_ids()
    }

    fn derive_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    ) -> Result<Vec<CrossRepoEdge>, SpineError> {
        self.cache
            .derive_cross_repo_edges(repo_id, entities, relations, registry_repo_ids)
    }

    fn refresh_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    ) {
        let _ = (entities, relations, registry_repo_ids);
        self.cache.invalidate_cross_repo_edges(repo_id);
        error!(
            repo_id,
            "refusing cursorless Firestore spine edge refresh; publish a complete cursor-bound edge phase"
        );
    }

    fn invalidate_cross_repo_edges(&self, repo_id: &str) {
        self.cache.invalidate_cross_repo_edges(repo_id);
    }

    fn begin_cross_repo_refresh_pass(
        &self,
        authority_roots: &BTreeMap<String, String>,
    ) -> Option<u64> {
        self.cache.begin_cross_repo_refresh_pass(authority_roots)
    }

    fn finish_cross_repo_refresh_pass(
        &self,
        token: u64,
        authority_roots: &BTreeMap<String, String>,
        _success: bool,
    ) -> bool {
        // Clear this pod's lease while deliberately retaining its dirty set.
        // A successful local pass cannot be published as globally complete
        // without a shared durable epoch/root compare-and-swap.
        let _ = self
            .cache
            .finish_cross_repo_refresh_pass(token, authority_roots, false);
        false
    }

    fn federated_impact(
        &self,
        start_repo: &str,
        start_entity: &EntityId,
        max_depth: u32,
    ) -> FederatedImpact {
        self.cache
            .federated_impact(start_repo, start_entity, max_depth)
    }
}

/// Firestore-backed [`SpineStore`] using the v1 REST API.
///
/// Authentication is via the GCE metadata server (Workload Identity on GKE).
#[cfg(feature = "firestore")]
pub struct FirestoreStore {
    /// GCP project ID.
    project_id: String,
    /// Firestore database ID (default: "(default)").
    database_id: String,
    /// HTTP client for Firestore REST API calls.
    client: reqwest::Client,
    /// Cached access token + expiry.
    token: parking_lot::RwLock<Option<(String, std::time::Instant)>>,
}

#[cfg(feature = "firestore")]
impl FirestoreStore {
    /// Create a new Firestore store.
    pub fn new(project_id: String, database_id: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to create HTTP client");

        Self {
            project_id,
            database_id: database_id.unwrap_or_else(|| "(default)".to_string()),
            client,
            token: parking_lot::RwLock::new(None),
        }
    }

    /// Base URL for the Firestore REST API documents endpoint.
    fn base_url(&self) -> String {
        format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents",
            self.project_id, self.database_id
        )
    }

    fn document_name(&self, collection: &str, document_id: &str) -> String {
        format!(
            "projects/{}/databases/{}/documents/{collection}/{document_id}",
            self.project_id, self.database_id
        )
    }

    fn document_url(&self, collection: &str, document_id: &str) -> String {
        format!("{}/{collection}/{document_id}", self.base_url())
    }

    /// Drive one Firestore future without panicking when the synchronous store
    /// boundary is reached from a daemon async worker.
    ///
    /// The daemon uses a multi-thread Tokio runtime, where `block_in_place`
    /// hands the worker's other tasks off before this thread blocks. A
    /// current-thread runtime has no worker to hand off, so fail loudly instead
    /// of invoking `Handle::block_on` and panicking. Synchronous callers get a
    /// short-lived current-thread runtime.
    fn run_async<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, SpineError>>,
    ) -> Result<T, SpineError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
            {
                tokio::task::block_in_place(|| handle.block_on(future))
            }
            Ok(_) => Err(SpineError::Backend(
                "synchronous Firestore spine access requires a blocking handoff outside a current-thread Tokio runtime"
                    .to_string(),
            )),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    SpineError::Backend(format!(
                        "failed to create Firestore request runtime: {error}"
                    ))
                })?
                .block_on(future),
        }
    }

    /// Get an access token from the GCE metadata server.
    /// Caches the token for its lifetime minus a 60-second buffer.
    fn get_access_token(&self) -> Result<String, SpineError> {
        {
            let cached = self.token.read();
            if let Some((ref token, ref expiry)) = *cached {
                if std::time::Instant::now() < *expiry {
                    return Ok(token.clone());
                }
            }
        }

        let client = self.client.clone();
        let token_result = self.run_async(async {
            let resp = client
                .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
                .header("Metadata-Flavor", "Google")
                .send()
                .await
                .map_err(|e| SpineError::Auth(format!("metadata server request failed: {e}")))?;

            if !resp.status().is_success() {
                return Err(SpineError::Auth(format!(
                    "metadata server returned {}",
                    resp.status()
                )));
            }

            let body: serde_json::Value = resp.json().await.map_err(|e| {
                SpineError::Auth(format!("failed to parse token response: {e}"))
            })?;

            let access_token = body["access_token"]
                .as_str()
                .ok_or_else(|| SpineError::Auth("no access_token in response".to_string()))?
                .to_string();

            let expires_in = body["expires_in"].as_u64().unwrap_or(3600);
            let expiry =
                std::time::Instant::now() + std::time::Duration::from_secs(expires_in.saturating_sub(60));

            Ok((access_token, expiry))
        })?;

        let (access_token, expiry) = token_result;
        let mut cached = self.token.write();
        *cached = Some((access_token.clone(), expiry));
        Ok(access_token)
    }

    /// List every document in a collection, following pagination.
    fn list_all_documents(&self, collection: &str) -> Result<Vec<serde_json::Value>, SpineError> {
        let token = self.get_access_token()?;
        self.run_async(async {
            let mut documents = Vec::new();
            let mut page_token: Option<String> = None;

            loop {
                let mut url = format!("{}/{}?pageSize=300", self.base_url(), collection);
                if let Some(ref pt) = page_token {
                    url.push_str("&pageToken=");
                    url.push_str(pt);
                }

                let resp = self
                    .client
                    .get(&url)
                    .bearer_auth(&token)
                    .send()
                    .await
                    .map_err(|e| SpineError::Http(format!("list {collection} failed: {e}")))?;

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(SpineError::Http(format!(
                        "list {collection} failed ({status}): {body}"
                    )));
                }

                let body: serde_json::Value = resp.json().await.map_err(|e| {
                    SpineError::Serialization(format!("failed to parse {collection} list: {e}"))
                })?;

                if let Some(docs) = body.get("documents").and_then(|d| d.as_array()) {
                    documents.extend(docs.iter().cloned());
                }

                match body.get("nextPageToken").and_then(|t| t.as_str()) {
                    Some(next) if !next.is_empty() => page_token = Some(next.to_string()),
                    _ => break,
                }
            }

            Ok(documents)
        })
    }

    /// Read one document and retain Firestore's server revision for a later
    /// compare-and-swap. A 404 is a proved missing head, not an empty success.
    fn get_document(
        &self,
        collection: &str,
        document_id: &str,
    ) -> Result<Option<serde_json::Value>, SpineError> {
        let token = self.get_access_token()?;
        let url = self.document_url(collection, document_id);
        self.run_async(async {
            let response = self
                .client
                .get(&url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|error| {
                    SpineError::Http(format!("read {collection}/{document_id} failed: {error}"))
                })?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "read {collection}/{document_id} failed ({status}): {body}"
                )));
            }
            response.json().await.map(Some).map_err(|error| {
                SpineError::Serialization(format!(
                    "failed to parse {collection}/{document_id}: {error}"
                ))
            })
        })
    }

    /// Query one equality-indexed field. Publication ids and repository ids
    /// are both single-field indexes, so this requires no composite index.
    fn query_documents(
        &self,
        collection: &str,
        field: &str,
        value: &str,
        limit: Option<usize>,
    ) -> Result<Vec<serde_json::Value>, SpineError> {
        let token = self.get_access_token()?;
        let url = format!("{}:runQuery", self.base_url());
        let mut structured_query = serde_json::json!({
            "from": [{ "collectionId": collection }],
            "where": {
                "fieldFilter": {
                    "field": { "fieldPath": field },
                    "op": "EQUAL",
                    "value": { "stringValue": value }
                }
            }
        });
        if let Some(limit) = limit {
            structured_query["limit"] = serde_json::json!(limit);
        }
        let query = serde_json::json!({ "structuredQuery": structured_query });
        self.run_async(async {
            let response = self
                .client
                .post(&url)
                .bearer_auth(&token)
                .json(&query)
                .send()
                .await
                .map_err(|error| {
                    SpineError::Http(format!("query {collection} failed: {error}"))
                })?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "query {collection} failed ({status}): {body}"
                )));
            }
            let results: Vec<serde_json::Value> = response.json().await.map_err(|error| {
                SpineError::Serialization(format!(
                    "failed to parse {collection} query: {error}"
                ))
            })?;
            Ok(results
                .into_iter()
                .filter_map(|result| result.get("document").cloned())
                .collect())
        })
    }

    /// Commit staged row writes or bounded cleanup deletes in batches limited
    /// by both Firestore's write count and request-size envelopes.
    fn commit_write_batches(
        &self,
        writes: Vec<serde_json::Value>,
        operation: &str,
    ) -> Result<(), SpineError> {
        const MAX_WRITES: usize = 100;
        const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;

        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        let mut batch = Vec::new();
        let mut estimated_bytes = 0usize;
        for write in writes {
            let write_bytes = serde_json::to_vec(&write)
                .map_err(|error| {
                    SpineError::Serialization(format!(
                        "failed to size {operation} write: {error}"
                    ))
                })?
                .len();
            if write_bytes > MAX_JSON_BYTES {
                return Err(SpineError::Serialization(format!(
                    "one {operation} document exceeds the bounded Firestore request envelope"
                )));
            }
            if !batch.is_empty()
                && (batch.len() >= MAX_WRITES
                    || estimated_bytes.saturating_add(write_bytes) > MAX_JSON_BYTES)
            {
                self.commit_write_batch(&token, &url, &batch, operation)?;
                batch.clear();
                estimated_bytes = 0;
            }
            estimated_bytes = estimated_bytes.saturating_add(write_bytes);
            batch.push(write);
        }
        if !batch.is_empty() {
            self.commit_write_batch(&token, &url, &batch, operation)?;
        }
        Ok(())
    }

    fn commit_write_batch(
        &self,
        token: &str,
        url: &str,
        writes: &[serde_json::Value],
        operation: &str,
    ) -> Result<(), SpineError> {
        let body = serde_json::json!({ "writes": writes });
        self.run_async(async {
            let response = self
                .client
                .post(url)
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .map_err(|error| {
                    SpineError::Http(format!("{operation} commit failed: {error}"))
                })?;
            if !response.status().is_success() {
                let status = response.status();
                let response_body = response.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "{operation} commit failed ({status}): {response_body}"
                )));
            }
            // A successful Firestore Commit is atomic for every write in the
            // request. Do not turn an acknowledged commit into an ambiguous
            // local error merely because its informational response body was
            // truncated or could not be decoded.
            Ok(())
        })
    }

    fn read_repo_head(
        &self,
        repo_id: &str,
    ) -> Result<(Option<RepoPublicationHead>, StoreHeadPrecondition), SpineError> {
        let document_id = sha256_hex(repo_id.as_bytes());
        match self.get_document("spine_repo_heads_v2", &document_id)? {
            Some(document) => {
                let head: RepoPublicationHead = doc_payload(&document, "repo head")?;
                head.validate()?;
                if head.repo_id != repo_id {
                    return Err(SpineError::Serialization(format!(
                        "spine head document id collision: requested {repo_id}, loaded {}",
                        head.repo_id
                    )));
                }
                let update_time = document
                    .get("updateTime")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        SpineError::Serialization(format!(
                            "repo {repo_id} head is missing Firestore updateTime"
                        ))
                    })?
                    .to_string();
                Ok((
                    Some(head),
                    StoreHeadPrecondition::Revision(update_time),
                ))
            }
            None => Ok((None, StoreHeadPrecondition::Missing)),
        }
    }

    fn read_rollout_fence(
        &self,
    ) -> Result<Option<LoadedSpineRolloutFence>, SpineError> {
        let Some(document) = self.get_document("spine_control_v2", "rollout_fence")? else {
            return Ok(None);
        };
        self.parse_rollout_fence_document(&document).map(Some)
    }

    fn parse_rollout_fence_document(
        &self,
        document: &serde_json::Value,
    ) -> Result<LoadedSpineRolloutFence, SpineError> {
        let expected_name = self.document_name("spine_control_v2", "rollout_fence");
        if document.get("name").and_then(serde_json::Value::as_str)
            != Some(expected_name.as_str())
        {
            return Err(SpineError::Serialization(
                "spine rollout fence is stored under the wrong document identity".to_string(),
            ));
        }
        let fence: SpineRolloutFence = doc_payload(&document, "spine rollout fence")?;
        fence.validate()?;
        let expected_fields = firestore_rollout_fence_fields(&fence)?;
        if document.get("fields") != Some(&expected_fields) {
            return Err(SpineError::Serialization(
                "spine rollout fence sibling fields do not exactly match its canonical payload"
                    .to_string(),
            ));
        }
        let update_time = document
            .get("updateTime")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SpineError::Serialization(
                    "spine rollout fence is missing Firestore updateTime".to_string(),
                )
            })?
            .to_string();
        Ok(LoadedSpineRolloutFence { fence, update_time })
    }

    fn list_repo_heads(
        &self,
    ) -> Result<BTreeMap<String, (RepoPublicationHead, String)>, SpineError> {
        let mut heads = BTreeMap::new();
        for document in self.list_all_documents("spine_repo_heads_v2")? {
            let head: RepoPublicationHead = doc_payload(&document, "repo head")?;
            head.validate()?;
            let expected_name = self.document_name(
                "spine_repo_heads_v2",
                &sha256_hex(head.repo_id.as_bytes()),
            );
            if document.get("name").and_then(serde_json::Value::as_str)
                != Some(expected_name.as_str())
            {
                return Err(SpineError::Serialization(format!(
                    "repo {} head is stored under the wrong document identity",
                    head.repo_id
                )));
            }
            let update_time = document
                .get("updateTime")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SpineError::Serialization(format!(
                        "repo {} head is missing Firestore updateTime",
                        head.repo_id
                    ))
                })?
                .to_string();
            let repo_id = head.repo_id.clone();
            if heads.insert(repo_id.clone(), (head, update_time)).is_some() {
                return Err(SpineError::Serialization(format!(
                    "multiple durable spine heads loaded for repo {repo_id}"
                )));
            }
        }
        Ok(heads)
    }

    fn load_publication_for_head(
        &self,
        head: &RepoPublicationHead,
    ) -> Result<LoadedRepoPublication, SpineError> {
        let manifest_document = self
            .get_document("spine_publications_v2", &head.publication_id)?
            .ok_or_else(|| {
                SpineError::Serialization(format!(
                    "repo {} head references missing publication manifest {}",
                    head.repo_id, head.publication_id
                ))
            })?;
        let manifest: RepoPublicationHead =
            doc_payload(&manifest_document, "publication manifest")?;
        validate_publication_row(&manifest_document, &manifest, "publication manifest")?;
        let expected_manifest_name =
            self.document_name("spine_publications_v2", &head.publication_id);
        if manifest_document
            .get("name")
            .and_then(serde_json::Value::as_str)
            != Some(expected_manifest_name.as_str())
        {
            return Err(SpineError::Serialization(format!(
                "repo {} publication {} is stored under the wrong document identity",
                head.repo_id, head.publication_id
            )));
        }
        if &manifest != head {
            return Err(SpineError::Serialization(format!(
                "repo {} head and publication manifest {} disagree",
                head.repo_id, head.publication_id
            )));
        }

        let entity_documents = self.query_documents(
            "spine_entities_v2",
            "publication_id",
            &head.publication_id,
            None,
        )?;
        let mut entries = Vec::with_capacity(entity_documents.len());
        for document in &entity_documents {
            validate_publication_row(document, head, "entity")?;
            let entry: EntityEntry = doc_payload(document, "entity")?;
            let expected_name = self.document_name(
                "spine_entities_v2",
                &format!("{}_{}", head.publication_id, entry.entity_id),
            );
            if document.get("name").and_then(serde_json::Value::as_str)
                != Some(expected_name.as_str())
            {
                return Err(SpineError::Serialization(format!(
                    "repo {} publication {} has an entity under the wrong document identity",
                    head.repo_id, head.publication_id
                )));
            }
            entries.push(entry);
        }

        let edge_documents = self.query_documents(
            "spine_edges_v2",
            "publication_id",
            &head.publication_id,
            None,
        )?;
        let mut outgoing_edges = Vec::with_capacity(edge_documents.len());
        for document in &edge_documents {
            validate_publication_row(document, head, "edge")?;
            let edge: CrossRepoEdge = doc_payload(document, "edge")?;
            let payload = serde_json::to_string(&edge).map_err(|error| {
                SpineError::Serialization(format!(
                    "failed to serialize edge document identity: {error}"
                ))
            })?;
            let expected_name = self.document_name(
                "spine_edges_v2",
                &format!("{}_{}", head.publication_id, sha256_hex(payload.as_bytes())),
            );
            if document.get("name").and_then(serde_json::Value::as_str)
                != Some(expected_name.as_str())
            {
                return Err(SpineError::Serialization(format!(
                    "repo {} publication {} has an edge under the wrong document identity",
                    head.repo_id, head.publication_id
                )));
            }
            outgoing_edges.push(edge);
        }

        Ok(LoadedRepoPublication {
            head: head.clone(),
            entries,
            outgoing_edges,
        })
    }

    fn get_document_by_name(
        &self,
        document_name: &str,
    ) -> Result<Option<serde_json::Value>, SpineError> {
        let prefix = format!(
            "projects/{}/databases/{}/documents/",
            self.project_id, self.database_id
        );
        let relative = document_name.strip_prefix(&prefix).ok_or_else(|| {
            SpineError::Serialization(format!(
                "Firestore document {document_name} is outside the configured database"
            ))
        })?;
        let (collection, document_id) = relative.split_once('/').ok_or_else(|| {
            SpineError::Serialization(format!(
                "Firestore document {document_name} has no collection/document identity"
            ))
        })?;
        if document_id.contains('/') {
            return Err(SpineError::Serialization(format!(
                "nested Firestore document {document_name} is not a spine publication row"
            )));
        }
        self.get_document(collection, document_id)
    }

    fn stage_marker_fields(
        &self,
        head: &RepoPublicationHead,
    ) -> Result<serde_json::Value, SpineError> {
        let payload = serde_json::to_string(head).map_err(|error| {
            SpineError::Serialization(format!("failed to serialize stage marker: {error}"))
        })?;
        Ok(serde_json::json!({
            "repo_id": { "stringValue": head.repo_id },
            "source_cursor": { "stringValue": head.source_cursor.to_string() },
            "publication_id": { "stringValue": head.publication_id },
            "phase": { "stringValue": phase_name(head.phase) },
            "payload": { "stringValue": payload }
        }))
    }

    fn stage_marker_write(
        &self,
        head: &RepoPublicationHead,
        current_document: serde_json::Value,
    ) -> Result<serde_json::Value, SpineError> {
        Ok(serde_json::json!({
            "update": {
                "name": self.document_name("spine_stages_v2", &head.publication_id),
                "fields": self.stage_marker_fields(head)?
            },
            "currentDocument": current_document
        }))
    }

    fn immutable_update_write(
        &self,
        name: String,
        fields: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "update": { "name": name, "fields": fields },
            "currentDocument": { "exists": false }
        })
    }

    fn validate_existing_immutable_write(
        &self,
        write: &serde_json::Value,
        what: &str,
    ) -> Result<bool, SpineError> {
        let update = write.get("update").ok_or_else(|| {
            SpineError::Serialization(format!("{what} immutable write has no update"))
        })?;
        let name = update
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SpineError::Serialization(format!("{what} immutable write has no document name"))
            })?;
        let expected_fields = update.get("fields").ok_or_else(|| {
            SpineError::Serialization(format!("{what} immutable write has no fields"))
        })?;
        let Some(existing) = self.get_document_by_name(name)? else {
            return Ok(false);
        };
        if existing.get("name").and_then(serde_json::Value::as_str) != Some(name)
            || existing.get("fields") != Some(expected_fields)
        {
            return Err(SpineError::Serialization(format!(
                "{what} already exists with different bytes at {name}"
            )));
        }
        Ok(true)
    }

    fn ensure_immutable_document(
        &self,
        write: serde_json::Value,
        operation: &str,
    ) -> Result<(), SpineError> {
        match self.commit_write_batches(vec![write.clone()], operation) {
            Ok(()) => Ok(()),
            Err(commit_error) => {
                if self.validate_existing_immutable_write(&write, operation)? {
                    Ok(())
                } else {
                    Err(SpineError::Backend(format!(
                        "{commit_error}; {operation} was not durably created"
                    )))
                }
            }
        }
    }

    /// Commit immutable rows in bounded atomic batches. Every batch also
    /// updates the stage marker with an `exists` precondition. Cleanup uses the
    /// marker's exact updateTime, so a racing writer and cleaner cannot both
    /// commit: either the whole row batch remains discoverable through the
    /// marker or the whole cleanup wins and the row batch is rejected.
    fn commit_immutable_stage_batches(
        &self,
        head: &RepoPublicationHead,
        writes: Vec<serde_json::Value>,
    ) -> Result<(), SpineError> {
        const MAX_DATA_WRITES: usize = 99;
        const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;

        let marker_write = self.stage_marker_write(
            head,
            serde_json::json!({ "exists": true }),
        )?;
        let marker_bytes = serde_json::to_vec(&marker_write)
            .map_err(|error| {
                SpineError::Serialization(format!(
                    "failed to size stage marker heartbeat: {error}"
                ))
            })?
            .len();
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        let mut batch = Vec::new();
        let mut estimated_bytes = marker_bytes;
        for write in writes {
            let write_bytes = serde_json::to_vec(&write)
                .map_err(|error| {
                    SpineError::Serialization(format!(
                        "failed to size immutable stage write: {error}"
                    ))
                })?
                .len();
            if write_bytes.saturating_add(marker_bytes) > MAX_JSON_BYTES {
                return Err(SpineError::Serialization(
                    "one immutable stage document exceeds the bounded Firestore request envelope"
                        .to_string(),
                ));
            }
            if !batch.is_empty()
                && (batch.len() >= MAX_DATA_WRITES
                    || estimated_bytes.saturating_add(write_bytes) > MAX_JSON_BYTES)
            {
                self.commit_immutable_stage_batch(
                    &token,
                    &url,
                    head,
                    &marker_write,
                    batch,
                )?;
                batch = Vec::new();
                estimated_bytes = marker_bytes;
            }
            estimated_bytes = estimated_bytes.saturating_add(write_bytes);
            batch.push(write);
        }
        if !batch.is_empty() {
            self.commit_immutable_stage_batch(
                &token,
                &url,
                head,
                &marker_write,
                batch,
            )?;
        }
        Ok(())
    }

    fn commit_immutable_stage_batch(
        &self,
        token: &str,
        url: &str,
        head: &RepoPublicationHead,
        marker_write: &serde_json::Value,
        mut pending: Vec<serde_json::Value>,
    ) -> Result<(), SpineError> {
        let mut last_error = None;
        for _ in 0..3 {
            let mut atomic_writes = pending.clone();
            atomic_writes.push(marker_write.clone());
            match self.commit_write_batch(
                token,
                url,
                &atomic_writes,
                "stage immutable spine publication rows",
            ) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }

            let marker = self
                .get_document("spine_stages_v2", &head.publication_id)?
                .ok_or_else(|| {
                    SpineError::Backend(format!(
                        "publication {} stage marker disappeared while immutable rows were being written",
                        head.publication_id
                    ))
                })?;
            if marker.get("fields") != Some(&self.stage_marker_fields(head)?) {
                return Err(SpineError::Serialization(format!(
                    "publication {} stage marker changed identity while rows were being written",
                    head.publication_id
                )));
            }

            let mut missing = Vec::new();
            for write in pending {
                if !self.validate_existing_immutable_write(
                    &write,
                    "immutable spine publication row",
                )? {
                    missing.push(write);
                }
            }
            if missing.is_empty() {
                return Ok(());
            }
            pending = missing;
        }
        Err(SpineError::Backend(format!(
            "{}; immutable stage batch did not converge after three reconciliation attempts",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "stage commit failed".to_string())
        )))
    }

    fn stage_publication(&self, prepared: &PreparedStorePublication) -> Result<(), SpineError> {
        let publication = prepared.publication();
        let head = prepared.candidate_head();
        let cursor = publication.source_cursor.to_string();
        self.ensure_immutable_document(
            self.stage_marker_write(head, serde_json::json!({ "exists": false }))?,
            "stage immutable spine publication marker",
        )?;

        let mut writes = Vec::with_capacity(
            publication.entries.len()
                + publication
                    .outgoing_edges
                    .as_ref()
                    .map_or(0, Vec::len)
                + 1,
        );

        for entry in &publication.entries {
            let payload = serde_json::to_string(entry).map_err(|error| {
                SpineError::Serialization(format!("failed to serialize entity: {error}"))
            })?;
            let document_id = format!("{}_{}", head.publication_id, entry.entity_id);
            writes.push(self.immutable_update_write(
                self.document_name("spine_entities_v2", &document_id),
                serde_json::json!({
                        "repo_id": { "stringValue": publication.repo_id },
                        "source_cursor": { "stringValue": cursor },
                        "publication_id": { "stringValue": head.publication_id },
                        "root_hash": { "stringValue": publication.root_hash },
                        "payload": { "stringValue": payload }
                }),
            ));
        }
        if let Some(edges) = &publication.outgoing_edges {
            for edge in edges {
                let payload = serde_json::to_string(edge).map_err(|error| {
                    SpineError::Serialization(format!("failed to serialize edge: {error}"))
                })?;
                let document_id = format!(
                    "{}_{}",
                    head.publication_id,
                    sha256_hex(payload.as_bytes())
                );
                writes.push(self.immutable_update_write(
                    self.document_name("spine_edges_v2", &document_id),
                    serde_json::json!({
                            "repo_id": { "stringValue": publication.repo_id },
                            "source_cursor": { "stringValue": cursor },
                            "publication_id": { "stringValue": head.publication_id },
                            "payload": { "stringValue": payload }
                    }),
                ));
            }
        }

        // The manifest is staged last. A failed earlier batch can leave orphan
        // rows, but no head or complete manifest can reach them.
        let manifest_payload = serde_json::to_string(head).map_err(|error| {
            SpineError::Serialization(format!("failed to serialize publication manifest: {error}"))
        })?;
        writes.push(self.immutable_update_write(
            self.document_name("spine_publications_v2", &head.publication_id),
            serde_json::json!({
                    "repo_id": { "stringValue": publication.repo_id },
                    "source_cursor": { "stringValue": cursor },
                    "publication_id": { "stringValue": head.publication_id },
                    "phase": { "stringValue": phase_name(head.phase) },
                    "payload": { "stringValue": manifest_payload }
            }),
        ));
        self.commit_immutable_stage_batches(head, writes)
    }

    fn commit_head_and_rollout_fence(
        &self,
        prepared: &PreparedStorePublication,
    ) -> Result<RepoPublicationCommit, SpineError> {
        let head = prepared.candidate_head();
        let prepared_fence = prepared.rollout_fence().ok_or_else(|| {
            SpineError::Backend(
                "hosted spine publication was prepared without a rollout fence".to_string(),
            )
        })?;
        let document_id = sha256_hex(head.repo_id.as_bytes());
        let head_write = firestore_head_write(
            self.document_name("spine_repo_heads_v2", &document_id),
            head,
            prepared.head_precondition(),
        )?;
        let fence_write = firestore_rollout_fence_write(
            self.document_name("spine_control_v2", "rollout_fence"),
            &prepared_fence.fence,
            &StoreHeadPrecondition::Revision(prepared_fence.update_time.clone()),
        )?;
        let body = serde_json::json!({ "writes": [head_write, fence_write] });
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        let response = self.run_async(async {
            let response = self.client
                .post(&url)
                .bearer_auth(&token)
                .json(&body)
                .send()
                .await
                .map_err(|error| SpineError::Http(format!("head CAS failed: {error}")))?;
            let status = response.status();
            if status.is_success() {
                Ok((status, None))
            } else {
                Ok((status, Some(response.text().await.unwrap_or_default())))
            }
        });
        let (status, response_body) = match response {
            Ok(response) => response,
            Err(error) => {
                return self.reconcile_ambiguous_head(prepared, error.to_string());
            }
        };
        if status.is_success() {
            // The head update and equivalent fence update are one Firestore
            // Commit. The fence's exact updateTime precondition makes a writer
            // prepared before a changed rollout lose atomically. Firestore may
            // retain updateTime for a byte-equivalent update, which is desired:
            // the GCS control record's evidence stays stable until rollout
            // itself changes the payload.
            return Ok(match prepared.terminal_result() {
                Some(RepoPublicationCommit::AlreadyCommitted { .. }) => {
                    RepoPublicationCommit::AlreadyCommitted {
                        source_cursor: head.source_cursor,
                    }
                }
                _ => RepoPublicationCommit::Committed {
                    source_cursor: head.source_cursor,
                },
            });
        }

        self.reconcile_ambiguous_head(
            prepared,
            format!(
                "head CAS failed ({status}): {}",
                response_body.unwrap_or_default()
            ),
        )
    }

    /// Resolve every non-acknowledged CAS by re-reading the durable head.
    ///
    /// A transport error can arrive after Firestore committed. Returning it
    /// directly would leave the local pod behind durable truth. The re-read
    /// makes an exact candidate idempotent, a changed revision a typed conflict,
    /// and an unchanged precondition explicitly indeterminate. The latter is a
    /// loud failure that the caller may safely retry with the same preparation.
    fn reconcile_ambiguous_head(
        &self,
        prepared: &PreparedStorePublication,
        cause: String,
    ) -> Result<RepoPublicationCommit, SpineError> {
        let candidate = prepared.candidate_head();
        let prepared_fence = prepared.rollout_fence().ok_or_else(|| {
            SpineError::Backend(format!(
                "{cause}; publication preparation carried no rollout fence"
            ))
        })?;
        let (observed_fence, observed, observed_precondition) = {
            let mut stable = None;
            for _ in 0..3 {
                let fence_before = self.read_rollout_fence().map_err(|reconcile_error| {
                    SpineError::Backend(format!(
                        "{cause}; rollout fence outcome is indeterminate because reconciliation failed: {reconcile_error}"
                    ))
                })?;
                let (observed, observed_precondition) =
                    self.read_repo_head(&candidate.repo_id).map_err(|reconcile_error| {
                        SpineError::Backend(format!(
                            "{cause}; durable head outcome is indeterminate because reconciliation failed: {reconcile_error}"
                        ))
                    })?;
                let fence_after = self.read_rollout_fence().map_err(|reconcile_error| {
                    SpineError::Backend(format!(
                        "{cause}; rollout fence outcome is indeterminate because reconciliation failed: {reconcile_error}"
                    ))
                })?;
                if fence_before == fence_after {
                    stable = Some((fence_after, observed, observed_precondition));
                    break;
                }
            }
            stable.ok_or_else(|| {
                SpineError::Backend(format!(
                    "{cause}; rollout fence did not stabilize around the durable head reread"
                ))
            })?
        };
        let fence_matches = observed_fence.as_ref().is_some_and(|current| {
            current.fence.payload_sha256 == prepared_fence.fence.payload_sha256
                && current.update_time == prepared_fence.update_time
        });
        if !fence_matches {
            return Ok(RepoPublicationCommit::Conflict(
                crate::publication::RepoPublicationConflict::against_rollout_fence(
                    candidate.source_cursor,
                    prepared_fence.fence.rollout_fence,
                    observed.as_ref(),
                    observed_fence.as_ref().map(|current| &current.fence),
                ),
            ));
        }
        if observed
            .as_ref()
            .is_some_and(|winner| winner.publication_id == candidate.publication_id)
        {
            return Ok(RepoPublicationCommit::AlreadyCommitted {
                source_cursor: candidate.source_cursor,
            });
        }
        if &observed_precondition == prepared.head_precondition() {
            return Err(SpineError::Backend(format!(
                "{cause}; durable head retained the prepared precondition, so the CAS did not establish a committed winner"
            )));
        }
        let Some(observed) = observed.as_ref() else {
            return Err(SpineError::Backend(format!(
                "{cause}; durable head disappeared while reconciling the CAS"
            )));
        };
        Ok(RepoPublicationCommit::Conflict(
            crate::publication::RepoPublicationConflict::against(
                candidate.source_cursor,
                Some(observed),
            ),
        ))
    }
}

#[cfg(feature = "firestore")]
fn firestore_head_write(
    document_name: String,
    head: &RepoPublicationHead,
    precondition: &StoreHeadPrecondition,
) -> Result<serde_json::Value, SpineError> {
    let payload = serde_json::to_string(head).map_err(|error| {
        SpineError::Serialization(format!("failed to serialize repo head: {error}"))
    })?;
    let current_document = match precondition {
        StoreHeadPrecondition::Missing => serde_json::json!({ "exists": false }),
        StoreHeadPrecondition::Revision(update_time) => {
            serde_json::json!({ "updateTime": update_time })
        }
    };
    Ok(serde_json::json!({
        "update": {
            "name": document_name,
            "fields": {
                "repo_id": { "stringValue": head.repo_id },
                "source_cursor": { "stringValue": head.source_cursor.to_string() },
                "publication_id": { "stringValue": head.publication_id },
                "phase": { "stringValue": phase_name(head.phase) },
                "payload": { "stringValue": payload }
            }
        },
        "currentDocument": current_document
    }))
}

#[cfg(feature = "firestore")]
fn firestore_rollout_fence_write(
    document_name: String,
    fence: &SpineRolloutFence,
    precondition: &StoreHeadPrecondition,
) -> Result<serde_json::Value, SpineError> {
    fence.validate()?;
    let current_document = match precondition {
        StoreHeadPrecondition::Missing => serde_json::json!({ "exists": false }),
        StoreHeadPrecondition::Revision(update_time) => {
            serde_json::json!({ "updateTime": update_time })
        }
    };
    Ok(serde_json::json!({
        "update": {
            "name": document_name,
            "fields": firestore_rollout_fence_fields(fence)?
        },
        "currentDocument": current_document
    }))
}

#[cfg(feature = "firestore")]
fn firestore_rollout_fence_fields(
    fence: &SpineRolloutFence,
) -> Result<serde_json::Value, SpineError> {
    let payload = serde_json::to_string(fence).map_err(|error| {
        SpineError::Serialization(format!("failed to serialize spine rollout fence: {error}"))
    })?;
    Ok(serde_json::json!({
        "schema": { "stringValue": fence.schema },
        "scope": { "stringValue": fence.scope },
        "rollout_fence": { "integerValue": fence.rollout_fence.to_string() },
        "payload_sha256": { "stringValue": fence.payload_sha256 },
        "payload": { "stringValue": payload }
    }))
}

#[cfg(feature = "firestore")]
fn doc_payload<T: serde::de::DeserializeOwned>(
    doc: &serde_json::Value,
    what: &str,
) -> Result<T, SpineError> {
    let payload = doc
        .get("fields")
        .and_then(|f| f.get("payload"))
        .and_then(|p| p.get("stringValue"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| SpineError::Serialization(format!("{what} document missing payload")))?;
    serde_json::from_str(payload)
        .map_err(|e| SpineError::Serialization(format!("failed to parse {what} payload: {e}")))
}

#[cfg(feature = "firestore")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(feature = "firestore")]
fn phase_name(phase: RepoPublicationPhase) -> &'static str {
    match phase {
        RepoPublicationPhase::Metadata => "metadata",
        RepoPublicationPhase::Edges => "edges",
    }
}

#[cfg(feature = "firestore")]
fn document_string_field<'a>(
    document: &'a serde_json::Value,
    field: &str,
) -> Option<&'a str> {
    document
        .get("fields")
        .and_then(|fields| fields.get(field))
        .and_then(|value| value.get("stringValue"))
        .and_then(serde_json::Value::as_str)
}

#[cfg(feature = "firestore")]
fn validate_publication_row(
    document: &serde_json::Value,
    head: &RepoPublicationHead,
    kind: &str,
) -> Result<(), SpineError> {
    let repo_id = document_string_field(document, "repo_id").ok_or_else(|| {
        SpineError::Serialization(format!("{kind} row missing repo_id"))
    })?;
    let source_cursor = document_string_field(document, "source_cursor").ok_or_else(|| {
        SpineError::Serialization(format!("{kind} row missing source_cursor"))
    })?;
    let publication_id = document_string_field(document, "publication_id").ok_or_else(|| {
        SpineError::Serialization(format!("{kind} row missing publication_id"))
    })?;
    if repo_id != head.repo_id
        || source_cursor != head.source_cursor.to_string()
        || publication_id != head.publication_id
    {
        return Err(SpineError::Serialization(format!(
            "{kind} row does not match committed head {} for repo {}",
            head.publication_id, head.repo_id
        )));
    }
    Ok(())
}

#[cfg(feature = "firestore")]
fn loaded_repos_from_documents(
    docs: &[serde_json::Value],
) -> Result<Vec<crate::store::LoadedRepo>, SpineError> {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;

    let mut by_repo: HashMap<String, (String, Vec<EntityEntry>)> = HashMap::new();
    for doc in docs {
        let entry: EntityEntry = doc_payload(doc, "entity")?;
        let root_hash = doc
            .get("fields")
            .and_then(|f| f.get("root_hash"))
            .and_then(|h| h.get("stringValue"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        match by_repo.entry(entry.repo_id.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert((root_hash, vec![entry]));
            }
            Entry::Occupied(mut occupied) => {
                if occupied.get().0 != root_hash {
                    return Err(SpineError::Serialization(format!(
                        "mixed root hashes for repo {} in spine_entities",
                        occupied.key()
                    )));
                }
                occupied.get_mut().1.push(entry);
            }
        }
    }

    let mut repos = by_repo
        .into_iter()
        .map(|(repo_id, (root_hash, entries))| crate::store::LoadedRepo {
            repo_id,
            root_hash,
            entries,
        })
        .collect::<Vec<_>>();
    repos.sort_by(|a, b| a.repo_id.cmp(&b.repo_id));
    Ok(repos)
}

#[cfg(feature = "firestore")]
impl SpineStore for FirestoreStore {
    fn load_rollout_fence(&self) -> Result<Option<LoadedSpineRolloutFence>, SpineError> {
        self.read_rollout_fence()
    }

    fn advance_rollout_fence(
        &self,
        candidate: SpineRolloutFence,
    ) -> Result<SpineRolloutFenceCommit, SpineError> {
        candidate.validate()?;
        let mut last_error = None;
        for _ in 0..3 {
            let observed = self.read_rollout_fence()?;
            match classify_rollout_fence_reconciliation(&candidate, observed.as_ref()) {
                RolloutFenceReconciliation::CandidateCurrent(evidence) => {
                    return Ok(SpineRolloutFenceCommit::AlreadyCurrent(evidence));
                }
                RolloutFenceReconciliation::NewerOrDifferent(observed) => {
                    return Ok(SpineRolloutFenceCommit::Conflict {
                        attempted_rollout_fence: candidate.rollout_fence,
                        observed,
                    });
                }
                RolloutFenceReconciliation::Retry => {}
            }
            let precondition = observed.as_ref().map_or(
                StoreHeadPrecondition::Missing,
                |current| StoreHeadPrecondition::Revision(current.update_time.clone()),
            );
            let write = firestore_rollout_fence_write(
                self.document_name("spine_control_v2", "rollout_fence"),
                &candidate,
                &precondition,
            )?;
            if let Err(error) = self.commit_write_batches(
                vec![write],
                "advance durable spine rollout fence",
            ) {
                last_error = Some(error);
            }

            // A transport failure or failed precondition can race with either a
            // successful identical retry, a newer rollout, or an unrelated
            // spine commit's equivalent fence update. Durable reread decides.
            let reconciled = self.read_rollout_fence()?;
            match classify_rollout_fence_reconciliation(&candidate, reconciled.as_ref()) {
                RolloutFenceReconciliation::CandidateCurrent(evidence) => {
                    return Ok(SpineRolloutFenceCommit::Advanced(evidence));
                }
                RolloutFenceReconciliation::NewerOrDifferent(observed) => {
                    return Ok(SpineRolloutFenceCommit::Conflict {
                        attempted_rollout_fence: candidate.rollout_fence,
                        observed,
                    });
                }
                RolloutFenceReconciliation::Retry => {}
            }
        }
        Err(SpineError::Backend(format!(
            "durable spine rollout fence did not converge after three CAS attempts: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "candidate was never observed durably".to_string())
        )))
    }

    fn legacy_migration_complete(&self) -> Result<bool, SpineError> {
        let Some(document) = self.get_document("spine_metadata_v2", "legacy_migration")? else {
            return Ok(false);
        };
        let expected_name = self.document_name("spine_metadata_v2", "legacy_migration");
        if document.get("name").and_then(serde_json::Value::as_str)
            != Some(expected_name.as_str())
        {
            return Err(SpineError::Serialization(
                "legacy migration marker is stored under the wrong document identity".to_string(),
            ));
        }
        let fields = document.get("fields").ok_or_else(|| {
            SpineError::Serialization("legacy migration marker has no fields".to_string())
        })?;
        let schema_version = fields
            .get("schema_version")
            .and_then(|value| value.get("integerValue"))
            .and_then(serde_json::Value::as_str);
        let state = fields
            .get("state")
            .and_then(|value| value.get("stringValue"))
            .and_then(serde_json::Value::as_str);
        let rollout_payload_sha256 = fields
            .get("rollout_payload_sha256")
            .and_then(|value| value.get("stringValue"))
            .and_then(serde_json::Value::as_str);
        let rollout_update_time = fields
            .get("rollout_update_time")
            .and_then(|value| value.get("stringValue"))
            .and_then(serde_json::Value::as_str);
        let rollout_fence = fields
            .get("rollout_fence")
            .and_then(|value| value.get("integerValue"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<u64>().ok());
        if schema_version != Some("2")
            || state != Some("complete")
            || !rollout_payload_sha256.is_some_and(|value| {
                value.strip_prefix("sha256:").is_some_and(|digest| {
                    digest.len() == 64
                        && digest.bytes().all(|byte| {
                            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                        })
                })
            })
            || !rollout_update_time.is_some_and(|value| !value.is_empty())
            || !rollout_fence.is_some_and(|value| value > 0)
        {
            return Err(SpineError::Serialization(
                "legacy migration marker has unsupported contents".to_string(),
            ));
        }
        Ok(true)
    }

    fn complete_legacy_migration(
        &self,
        rollout_fence: &LoadedSpineRolloutFence,
    ) -> Result<(), SpineError> {
        let write = self.immutable_update_write(
            self.document_name("spine_metadata_v2", "legacy_migration"),
            serde_json::json!({
                "schema_version": { "integerValue": "2" },
                "state": { "stringValue": "complete" },
                "rollout_fence": { "integerValue": rollout_fence.fence.rollout_fence.to_string() },
                "rollout_payload_sha256": { "stringValue": rollout_fence.fence.payload_sha256 },
                "rollout_update_time": { "stringValue": rollout_fence.update_time }
            }),
        );
        self.ensure_immutable_document(write, "complete legacy spine migration")
    }

    fn prepare_repo_publication(
        &self,
        publication: RepoSpinePublication,
    ) -> Result<PreparedStorePublication, SpineError> {
        let rollout_fence = self.read_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend(
                "cannot prepare a hosted spine publication without an active durable rollout fence"
                    .to_string(),
            )
        })?;
        let (observed_head, precondition) = self.read_repo_head(&publication.repo_id)?;
        let prepared = PreparedStorePublication::new_fenced(
            publication,
            observed_head,
            precondition,
            rollout_fence,
        )?;
        if prepared.requires_staging() {
            self.stage_publication(&prepared)?;
            let staged = self.load_publication_for_head(prepared.candidate_head())?;
            CanonicalRepoPublication::validate_loaded(
                staged.head,
                staged.entries,
                staged.outgoing_edges,
            )?;
        }
        Ok(prepared)
    }

    fn commit_repo_publication(
        &self,
        prepared: &PreparedStorePublication,
    ) -> Result<RepoPublicationCommit, SpineError> {
        if let Some(RepoPublicationCommit::Conflict(conflict)) = prepared.terminal_result() {
            return Ok(RepoPublicationCommit::Conflict(conflict));
        }
        self.commit_head_and_rollout_fence(prepared)
    }

    fn load_repo_publications(&self) -> Result<Vec<LoadedRepoPublication>, SpineError> {
        let mut last_movement = String::new();
        for attempt in 1..=3 {
            let selected_heads = self.list_repo_heads()?;
            let loaded = selected_heads
                .values()
                .map(|(head, _)| self.load_publication_for_head(head))
                .collect::<Result<Vec<_>, _>>();
            let observed_heads = self.list_repo_heads()?;
            if selected_heads == observed_heads {
                let mut publications = loaded?;
                publications.sort_by(|left, right| left.head.repo_id.cmp(&right.head.repo_id));
                return Ok(publications);
            }
            last_movement = format!(
                "committed spine heads moved during hydration attempt {attempt}"
            );
        }
        Err(SpineError::Backend(format!(
            "{last_movement}; durable spine heads did not stabilize after three attempts"
        )))
    }

    fn load_repo_publication(
        &self,
        repo_id: &str,
    ) -> Result<Option<LoadedRepoPublication>, SpineError> {
        for _ in 0..3 {
            let (selected, selected_precondition) = self.read_repo_head(repo_id)?;
            let Some(selected) = selected else {
                return Ok(None);
            };
            let loaded = self.load_publication_for_head(&selected);
            let (observed, observed_precondition) = self.read_repo_head(repo_id)?;
            if observed.as_ref() == Some(&selected)
                && observed_precondition == selected_precondition
            {
                return loaded.map(Some);
            }
        }
        Err(SpineError::Backend(format!(
            "repo {repo_id} durable spine head did not stabilize after three attempts"
        )))
    }

    fn cleanup_repo_publications(
        &self,
        active_head: &RepoPublicationHead,
        max_rows: usize,
    ) -> Result<RepoPublicationCleanupProgress, SpineError> {
        if max_rows == 0 {
            return Ok(RepoPublicationCleanupProgress::default());
        }
        let (durable_head, _) = self.read_repo_head(&active_head.repo_id)?;
        let durable_head = durable_head.ok_or_else(|| {
            SpineError::Backend(format!(
                "repo {} has no durable head during publication cleanup",
                active_head.repo_id
            ))
        })?;
        // Another pod may have advanced the head after this pod committed. Use
        // the re-read winner as the deletion boundary, never the stale caller's
        // candidate. A losing future-cursor candidate is simply preserved for a
        // later retry; it is not evidence that the durable winner moved back.
        let active_head = &durable_head;
        let stage_documents = self.query_documents(
            "spine_stages_v2",
            "repo_id",
            &active_head.repo_id,
            None,
        )?;
        let mut stale = Vec::new();
        for document in stage_documents {
            let head: RepoPublicationHead = doc_payload(&document, "publication stage marker")?;
            head.validate()?;
            validate_publication_row(&document, &head, "publication stage marker")?;
            let expected_stage_name = self.document_name(
                "spine_stages_v2",
                &head.publication_id,
            );
            if document
                .get("name")
                .and_then(serde_json::Value::as_str)
                != Some(expected_stage_name.as_str())
            {
                return Err(SpineError::Serialization(format!(
                    "repo {} publication stage {} is stored under the wrong document identity",
                    head.repo_id, head.publication_id
                )));
            }
            if head.repo_id != active_head.repo_id {
                return Err(SpineError::Serialization(format!(
                    "publication cleanup query for repo {} returned a manifest owned by {}",
                    active_head.repo_id, head.repo_id
                )));
            }
            if head.publication_id == active_head.publication_id {
                continue;
            }
            let safe = head.source_cursor < active_head.source_cursor
                || (head.source_cursor == active_head.source_cursor
                    && head.phase <= active_head.phase);
            if safe {
                stale.push((head, document));
            }
        }
        stale.sort_by(|(left, _), (right, _)| {
            left.source_cursor
                .cmp(&right.source_cursor)
                .then_with(|| left.phase.cmp(&right.phase))
                .then_with(|| left.publication_id.cmp(&right.publication_id))
        });
        let more_candidates = stale.len() > 1;
        let Some((stale_head, stage_document)) = stale.into_iter().next() else {
            return Ok(RepoPublicationCleanupProgress::default());
        };

        let stage_revision = stage_document
            .get("updateTime")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SpineError::Serialization(format!(
                    "publication stage {} is missing Firestore updateTime",
                    stale_head.publication_id
                ))
            })?;
        let max_writes = max_rows.min(100);
        if max_writes < 2 {
            // Every non-empty cleanup commit needs one exact-revision stage
            // marker write beside at least one deletion.
            return Ok(RepoPublicationCleanupProgress {
                deleted: 0,
                more: true,
            });
        }
        let deletion_budget = max_writes - 1;
        let mut delete_names = Vec::new();
        let mut all_rows_enumerated = true;
        for collection in ["spine_entities_v2", "spine_edges_v2"] {
            if delete_names.len() >= deletion_budget {
                all_rows_enumerated = false;
                break;
            }
            let remaining = deletion_budget - delete_names.len();
            let mut documents = self.query_documents(
                collection,
                "publication_id",
                &stale_head.publication_id,
                Some(remaining.saturating_add(1)),
            )?;
            if documents.len() > remaining {
                all_rows_enumerated = false;
                documents.truncate(remaining);
            }
            for document in documents {
                validate_publication_row(&document, &stale_head, collection)?;
                let name = document
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        SpineError::Serialization(format!(
                            "{collection} cleanup row is missing its document name"
                        ))
                    })?;
                let expected_name = if collection == "spine_entities_v2" {
                    let entry: EntityEntry = doc_payload(&document, "cleanup entity")?;
                    self.document_name(
                        collection,
                        &format!("{}_{}", stale_head.publication_id, entry.entity_id),
                    )
                } else {
                    let edge: CrossRepoEdge = doc_payload(&document, "cleanup edge")?;
                    let payload = serde_json::to_string(&edge).map_err(|error| {
                        SpineError::Serialization(format!(
                            "failed to serialize cleanup edge identity: {error}"
                        ))
                    })?;
                    self.document_name(
                        collection,
                        &format!(
                            "{}_{}",
                            stale_head.publication_id,
                            sha256_hex(payload.as_bytes())
                        ),
                    )
                };
                if name != expected_name {
                    return Err(SpineError::Serialization(format!(
                        "{collection} cleanup row is stored under the wrong document identity"
                    )));
                }
                delete_names.push(name.to_string());
            }
        }

        let mut manifest_remains = false;
        if all_rows_enumerated && delete_names.len() < deletion_budget {
            if let Some(manifest_document) = self.get_document(
                "spine_publications_v2",
                &stale_head.publication_id,
            )? {
                let manifest: RepoPublicationHead =
                    doc_payload(&manifest_document, "cleanup publication manifest")?;
                if manifest != stale_head {
                    return Err(SpineError::Serialization(format!(
                        "cleanup publication manifest {} does not match its stage marker",
                        stale_head.publication_id
                    )));
                }
                validate_publication_row(
                    &manifest_document,
                    &stale_head,
                    "cleanup publication manifest",
                )?;
                let manifest_name = manifest_document
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        SpineError::Serialization(
                            "publication manifest is missing its document name".to_string(),
                        )
                    })?;
                let expected_manifest_name = self.document_name(
                    "spine_publications_v2",
                    &stale_head.publication_id,
                );
                if manifest_name != expected_manifest_name {
                    return Err(SpineError::Serialization(format!(
                        "cleanup publication manifest {} is stored under the wrong document identity",
                        stale_head.publication_id
                    )));
                }
                delete_names.push(manifest_name.to_string());
            }
        } else if all_rows_enumerated {
            manifest_remains = self
                .get_document("spine_publications_v2", &stale_head.publication_id)?
                .is_some();
        }
        let can_remove_stage = all_rows_enumerated && !manifest_remains;
        if delete_names.is_empty() && !can_remove_stage {
            return Ok(RepoPublicationCleanupProgress {
                deleted: 0,
                more: true,
            });
        }
        let mut writes = delete_names
            .iter()
            .map(|name| serde_json::json!({ "delete": name }))
            .collect::<Vec<_>>();
        if can_remove_stage {
            let stage_name = stage_document
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SpineError::Serialization(
                        "publication stage marker is missing its document name".to_string(),
                    )
                })?;
            writes.push(serde_json::json!({
                "delete": stage_name,
                "currentDocument": { "updateTime": stage_revision }
            }));
        } else {
            writes.push(self.stage_marker_write(
                &stale_head,
                serde_json::json!({ "updateTime": stage_revision }),
            )?);
        }
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        self.commit_write_batch(
            &token,
            &url,
            &writes,
            "cleanup unreachable spine publication",
        )?;
        let deleted = delete_names.len() + usize::from(can_remove_stage);
        Ok(RepoPublicationCleanupProgress {
            deleted,
            more: more_candidates || !can_remove_stage,
        })
    }

    fn load_repos(&self) -> Result<Vec<crate::store::LoadedRepo>, SpineError> {
        let docs = self.list_all_documents("spine_entities")?;
        loaded_repos_from_documents(&docs)
    }

    fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError> {
        let docs = self.list_all_documents("spine_edges")?;
        docs.iter().map(|doc| doc_payload(doc, "edge")).collect()
    }

    fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError> {
        let _ = (entry, root_hash);
        Err(SpineError::Backend(
            "legacy cursorless Firestore entity writes are disabled; use a cursor-bound publication"
                .to_string(),
        ))
    }

    fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError> {
        let _ = repo_id;
        Err(SpineError::Backend(
            "legacy Firestore entity deletion is disabled; committed heads own visibility"
                .to_string(),
        ))
    }

    fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError> {
        let _ = edge;
        Err(SpineError::Backend(
            "legacy cursorless Firestore edge writes are disabled; use a cursor-bound publication"
                .to_string(),
        ))
    }

    fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError> {
        let _ = repo_id;
        Err(SpineError::Backend(
            "legacy Firestore edge deletion is disabled; committed heads own visibility"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LoadedRepo;
    use kin_model::{
        EntityKind, EntityRole, FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId,
        RelationEvidence, RelationId, RelationKind, RelationOrigin, SemanticFingerprint,
        Visibility,
    };
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    /// In-memory [`SpineStore`] fake. Mirrors staged rows and a revision-checked
    /// repository head without any network.
    struct FakeSpineStore {
        // (root_hash, entries) keyed by repo_id.
        repos: Mutex<HashMap<String, (String, Vec<EntityEntry>)>>,
        edges: Mutex<Vec<CrossRepoEdge>>,
        publication_state: Mutex<FakePublicationState>,
        rollout_fence_state: Mutex<Option<(u64, SpineRolloutFence)>>,
        fail_next_load_edges: AtomicBool,
        fail_stage_after_rows: AtomicUsize,
        fail_next_commit: AtomicBool,
        lose_next_commit_response_after_apply: AtomicBool,
        lose_next_rollout_fence_response_after_apply: AtomicBool,
        /// Test-only mutant that drops the required durable reread after a lost
        /// rollout-fence response.
        disable_rollout_fence_reconciliation: AtomicBool,
        atomicity_available: AtomicBool,
        /// Test-only mutant switch. Production stores have no such path.
        disable_head_precondition: AtomicBool,
        /// Test-only mutant switch restoring the paused pre-rollout writer.
        disable_rollout_fence_precondition: AtomicBool,
        /// Test-only mutant switch for the stage-marker cleanup fence.
        disable_stage_fence: AtomicBool,
        /// Optional deterministic pause after cleanup snapshots a stage but
        /// before its exact-revision atomic delete commit.
        cleanup_snapshot_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
        /// Optional deterministic pause after hydration snapshots heads but
        /// before it reads the corresponding immutable rows.
        load_snapshot_barrier: Mutex<Option<Arc<std::sync::Barrier>>>,
        /// Keep staged rows in place while a race or cleanup assertion inspects
        /// them. Production cleanup remains enabled and bounded.
        disable_cleanup: AtomicBool,
        cleanup_calls: AtomicUsize,
        legacy_migration_complete: AtomicBool,
    }

    #[derive(Default)]
    struct FakePublicationState {
        heads: HashMap<String, (u64, RepoPublicationHead)>,
        stages: HashMap<String, RepoPublicationHead>,
        manifests: HashMap<String, RepoPublicationHead>,
        entity_rows: HashMap<String, Vec<EntityEntry>>,
        edge_rows: HashMap<String, Vec<CrossRepoEdge>>,
        stage_revisions: HashMap<String, u64>,
    }

    impl Default for FakeSpineStore {
        fn default() -> Self {
            Self {
                repos: Mutex::new(HashMap::new()),
                edges: Mutex::new(Vec::new()),
                publication_state: Mutex::new(FakePublicationState::default()),
                rollout_fence_state: Mutex::new(Some((1, default_test_rollout_fence()))),
                fail_next_load_edges: AtomicBool::new(false),
                fail_stage_after_rows: AtomicUsize::new(usize::MAX),
                fail_next_commit: AtomicBool::new(false),
                lose_next_commit_response_after_apply: AtomicBool::new(false),
                lose_next_rollout_fence_response_after_apply: AtomicBool::new(false),
                disable_rollout_fence_reconciliation: AtomicBool::new(false),
                atomicity_available: AtomicBool::new(true),
                disable_head_precondition: AtomicBool::new(false),
                disable_rollout_fence_precondition: AtomicBool::new(false),
                disable_stage_fence: AtomicBool::new(false),
                cleanup_snapshot_barrier: Mutex::new(None),
                load_snapshot_barrier: Mutex::new(None),
                disable_cleanup: AtomicBool::new(false),
                cleanup_calls: AtomicUsize::new(0),
                legacy_migration_complete: AtomicBool::new(false),
            }
        }
    }

    fn test_rollout_fence(
        rollout_fence: u64,
        token: &str,
        repo_ids: &[&str],
    ) -> SpineRolloutFence {
        let expected = repo_ids
            .iter()
            .map(|repo_id| (*repo_id).to_string())
            .collect::<Vec<_>>();
        let rows = repo_ids
            .iter()
            .enumerate()
            .map(|(index, repo_id)| SpineRolloutRepositoryFence {
                repo_id: (*repo_id).to_string(),
                pre_fence_generation: 100 + index as u64,
                fenced_generation: 200 + index as u64,
                snapshot_schema: 4,
                e_tag: Some(format!("etag-{repo_id}-{rollout_fence}")),
            })
            .collect();
        SpineRolloutFence::new_exact(
            "gcs://test-bucket/test-prefix".to_string(),
            rollout_fence,
            token,
            &expected,
            rows,
        )
        .unwrap()
    }

    fn default_test_rollout_fence() -> SpineRolloutFence {
        test_rollout_fence(
            1,
            "test-rollout-1",
            &["consumer", "provider", "repo", "repo-a", "repo-b", "source"],
        )
    }

    fn merge_fake_immutable_rows<T: Clone + PartialEq>(
        rows: &mut HashMap<String, Vec<T>>,
        publication_id: &str,
        candidate: Vec<T>,
        kind: &str,
    ) -> Result<(), SpineError> {
        if let Some(existing) = rows.get(publication_id) {
            if existing
                .iter()
                .any(|row| !candidate.iter().any(|expected| expected == row))
            {
                return Err(SpineError::Serialization(format!(
                    "immutable fake {kind} row changed under publication {publication_id}"
                )));
            }
        }
        rows.insert(publication_id.to_string(), candidate);
        Ok(())
    }

    impl SpineStore for FakeSpineStore {
        fn load_rollout_fence(&self) -> Result<Option<LoadedSpineRolloutFence>, SpineError> {
            Ok(self
                .rollout_fence_state
                .lock()
                .unwrap()
                .as_ref()
                .map(|(revision, fence)| LoadedSpineRolloutFence {
                    fence: fence.clone(),
                    update_time: revision.to_string(),
                }))
        }

        fn advance_rollout_fence(
            &self,
            candidate: SpineRolloutFence,
        ) -> Result<SpineRolloutFenceCommit, SpineError> {
            candidate.validate()?;
            let mut state = self.rollout_fence_state.lock().unwrap();
            if let Some((revision, current)) = state.as_ref() {
                if current.payload_sha256 == candidate.payload_sha256 {
                    return Ok(SpineRolloutFenceCommit::AlreadyCurrent(
                        SpineRolloutFenceEvidence {
                            rollout_fence: current.rollout_fence,
                            payload_sha256: current.payload_sha256.clone(),
                            update_time: revision.to_string(),
                        },
                    ));
                }
                if current.scope != candidate.scope
                    || current.rollout_fence >= candidate.rollout_fence
                {
                    return Ok(SpineRolloutFenceCommit::Conflict {
                        attempted_rollout_fence: candidate.rollout_fence,
                        observed: Some(SpineRolloutFenceEvidence {
                            rollout_fence: current.rollout_fence,
                            payload_sha256: current.payload_sha256.clone(),
                            update_time: revision.to_string(),
                        }),
                    });
                }
            }
            let next_revision = state
                .as_ref()
                .map_or(1, |(revision, _)| revision.saturating_add(1));
            *state = Some((next_revision, candidate.clone()));
            let lost = self
                .lose_next_rollout_fence_response_after_apply
                .swap(false, Ordering::SeqCst);
            let observed = state.as_ref().expect("just installed rollout fence");
            let evidence = SpineRolloutFenceEvidence {
                rollout_fence: observed.1.rollout_fence,
                payload_sha256: observed.1.payload_sha256.clone(),
                update_time: observed.0.to_string(),
            };
            if lost {
                if self
                    .disable_rollout_fence_reconciliation
                    .load(Ordering::SeqCst)
                {
                    return Err(SpineError::Backend(
                        "injected lost rollout-fence response without durable reconciliation"
                            .to_string(),
                    ));
                }
                let observed = LoadedSpineRolloutFence {
                    fence: observed.1.clone(),
                    update_time: observed.0.to_string(),
                };
                return match classify_rollout_fence_reconciliation(
                    &candidate,
                    Some(&observed),
                ) {
                    RolloutFenceReconciliation::CandidateCurrent(evidence) => {
                        Ok(SpineRolloutFenceCommit::Advanced(evidence))
                    }
                    RolloutFenceReconciliation::NewerOrDifferent(observed) => {
                        Ok(SpineRolloutFenceCommit::Conflict {
                            attempted_rollout_fence: candidate.rollout_fence,
                            observed,
                        })
                    }
                    RolloutFenceReconciliation::Retry => Err(SpineError::Backend(
                        "lost rollout-fence response remained indeterminate".to_string(),
                    )),
                };
            }
            Ok(SpineRolloutFenceCommit::Advanced(evidence))
        }

        fn legacy_migration_complete(&self) -> Result<bool, SpineError> {
            Ok(self.legacy_migration_complete.load(Ordering::SeqCst))
        }

        fn complete_legacy_migration(
            &self,
            _rollout_fence: &LoadedSpineRolloutFence,
        ) -> Result<(), SpineError> {
            self.legacy_migration_complete.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn prepare_repo_publication(
            &self,
            publication: RepoSpinePublication,
        ) -> Result<PreparedStorePublication, SpineError> {
            if !self.atomicity_available.load(Ordering::SeqCst) {
                return Err(SpineError::Backend(
                    "injected atomic publication unavailable".to_string(),
                ));
            }
            let rollout_fence = self.load_rollout_fence()?.ok_or_else(|| {
                SpineError::Backend("fake active rollout fence is missing".to_string())
            })?;
            let mut state = self.publication_state.lock().unwrap();
            let observed = state.heads.get(&publication.repo_id).cloned();
            let (precondition, observed_head) = match observed {
                Some((revision, head)) => (
                    StoreHeadPrecondition::Revision(revision.to_string()),
                    Some(head),
                ),
                None => (StoreHeadPrecondition::Missing, None),
            };
            let prepared = PreparedStorePublication::new_fenced(
                publication,
                observed_head,
                precondition,
                rollout_fence,
            )?;
            if !prepared.requires_staging() {
                return Ok(prepared);
            }

            let publication_id = prepared.candidate_head().publication_id.clone();
            if let Some(existing) = state.stages.get(&publication_id) {
                if existing != prepared.candidate_head() {
                    return Err(SpineError::Serialization(format!(
                        "immutable fake stage marker changed under publication {publication_id}"
                    )));
                }
            } else {
                state
                    .stages
                    .insert(publication_id.clone(), prepared.candidate_head().clone());
                state.stage_revisions.insert(publication_id.clone(), 1);
            }

            let candidate = prepared.publication();
            let fail_after = self.fail_stage_after_rows.swap(usize::MAX, Ordering::SeqCst);
            let mut written = 0usize;
            let mut entities = Vec::new();
            for entry in &candidate.entries {
                if written == fail_after {
                    merge_fake_immutable_rows(
                        &mut state.entity_rows,
                        &publication_id,
                        entities,
                        "entity",
                    )?;
                    *state.stage_revisions.entry(publication_id.clone()).or_default() += 1;
                    return Err(SpineError::Backend(
                        "injected entity stage failure".to_string(),
                    ));
                }
                entities.push(entry.clone());
                written += 1;
            }
            let mut edges = Vec::new();
            for edge in candidate.outgoing_edges.as_deref().unwrap_or_default() {
                if written == fail_after {
                    merge_fake_immutable_rows(
                        &mut state.entity_rows,
                        &publication_id,
                        entities,
                        "entity",
                    )?;
                    merge_fake_immutable_rows(
                        &mut state.edge_rows,
                        &publication_id,
                        edges,
                        "edge",
                    )?;
                    *state.stage_revisions.entry(publication_id.clone()).or_default() += 1;
                    return Err(SpineError::Backend(
                        "injected edge stage failure".to_string(),
                    ));
                }
                edges.push(edge.clone());
                written += 1;
            }
            merge_fake_immutable_rows(
                &mut state.entity_rows,
                &publication_id,
                entities,
                "entity",
            )?;
            merge_fake_immutable_rows(
                &mut state.edge_rows,
                &publication_id,
                edges,
                "edge",
            )?;
            if let Some(existing) = state.manifests.get(&publication_id) {
                if existing != prepared.candidate_head() {
                    return Err(SpineError::Serialization(format!(
                        "immutable fake manifest changed under publication {publication_id}"
                    )));
                }
            } else {
                state
                    .manifests
                    .insert(publication_id.clone(), prepared.candidate_head().clone());
            }
            *state.stage_revisions.entry(publication_id).or_default() += 1;
            Ok(prepared)
        }

        fn commit_repo_publication(
            &self,
            prepared: &PreparedStorePublication,
        ) -> Result<RepoPublicationCommit, SpineError> {
            if !self.atomicity_available.load(Ordering::SeqCst) {
                return Err(SpineError::Backend(
                    "injected atomic publication unavailable".to_string(),
                ));
            }
            if self.fail_next_commit.swap(false, Ordering::SeqCst) {
                return Err(SpineError::Backend(
                    "injected head commit failure".to_string(),
                ));
            }
            let candidate = prepared.candidate_head().clone();
            if let Some(RepoPublicationCommit::Conflict(conflict)) = prepared.terminal_result() {
                return Ok(RepoPublicationCommit::Conflict(conflict));
            }
            let prepared_fence = prepared.rollout_fence().ok_or_else(|| {
                SpineError::Backend(
                    "fake hosted publication was prepared without a rollout fence".to_string(),
                )
            })?;
            // Holding the fence lock through the head transition models one
            // Firestore Commit containing both exact preconditions.
            let fence_state = self.rollout_fence_state.lock().unwrap();
            let fence_matches = self
                .disable_rollout_fence_precondition
                .load(Ordering::SeqCst)
                || fence_state.as_ref().is_some_and(|(revision, fence)| {
                    revision.to_string() == prepared_fence.update_time
                        && fence.payload_sha256 == prepared_fence.fence.payload_sha256
                });
            let mut state = self.publication_state.lock().unwrap();
            let current = state.heads.get(&candidate.repo_id).cloned();
            if !fence_matches {
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against_rollout_fence(
                        candidate.source_cursor,
                        prepared_fence.fence.rollout_fence,
                        current.as_ref().map(|(_, head)| head),
                        fence_state.as_ref().map(|(_, fence)| fence),
                    ),
                ));
            }
            let precondition_matches = self.disable_head_precondition.load(Ordering::SeqCst)
                || match (prepared.head_precondition(), &current) {
                    (StoreHeadPrecondition::Missing, None) => true,
                    (StoreHeadPrecondition::Revision(expected), Some((revision, _))) => {
                        expected == &revision.to_string()
                    }
                    _ => false,
            };
            if !precondition_matches {
                if current
                    .as_ref()
                    .is_some_and(|(_, head)| head.publication_id == candidate.publication_id)
                {
                    return Ok(RepoPublicationCommit::AlreadyCommitted {
                        source_cursor: candidate.source_cursor,
                    });
                }
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against(
                        candidate.source_cursor,
                        current.as_ref().map(|(_, head)| head),
                    ),
                ));
            }
            if matches!(
                prepared.terminal_result(),
                Some(RepoPublicationCommit::AlreadyCommitted { .. })
            ) {
                if current
                    .as_ref()
                    .is_some_and(|(_, head)| head.publication_id == candidate.publication_id)
                {
                    return Ok(RepoPublicationCommit::AlreadyCommitted {
                        source_cursor: candidate.source_cursor,
                    });
                }
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against(
                        candidate.source_cursor,
                        current.as_ref().map(|(_, head)| head),
                    ),
                ));
            }
            if !state.manifests.contains_key(&candidate.publication_id) {
                return Err(SpineError::Backend(
                    "staged publication manifest is missing".to_string(),
                ));
            }
            let next_revision = match current.as_ref() {
                Some((revision, _)) => revision.checked_add(1).ok_or_else(|| {
                    SpineError::Backend("fake spine head revision exhausted".to_string())
                })?,
                None => 1,
            };
            state
                .heads
                .insert(candidate.repo_id.clone(), (next_revision, candidate.clone()));
            if self
                .lose_next_commit_response_after_apply
                .swap(false, Ordering::SeqCst)
            {
                // The fake store models the production contract: an applied
                // CAS whose response is lost is reconciled by rereading the
                // durable head before control returns to the backend.
                let observed = state.heads.get(&candidate.repo_id).map(|(_, head)| head);
                if observed
                    .is_some_and(|head| head.publication_id == candidate.publication_id)
                {
                    return Ok(RepoPublicationCommit::AlreadyCommitted {
                        source_cursor: candidate.source_cursor,
                    });
                }
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against(
                        candidate.source_cursor,
                        observed,
                    ),
                ));
            }
            Ok(RepoPublicationCommit::Committed {
                source_cursor: candidate.source_cursor,
            })
        }

        fn load_repo_publications(&self) -> Result<Vec<LoadedRepoPublication>, SpineError> {
            if !self.atomicity_available.load(Ordering::SeqCst) {
                return Err(SpineError::Backend(
                    "injected atomic publication unavailable".to_string(),
                ));
            }
            for _ in 0..3 {
                let selected_heads = self.publication_state.lock().unwrap().heads.clone();
                if let Some(barrier) = self.load_snapshot_barrier.lock().unwrap().take() {
                    barrier.wait();
                    barrier.wait();
                }
                let loaded = {
                    let state = self.publication_state.lock().unwrap();
                    selected_heads
                        .values()
                        .map(|(_, head)| {
                            let manifest =
                                state.manifests.get(&head.publication_id).ok_or_else(|| {
                                    SpineError::Serialization(format!(
                                        "missing fake manifest {}",
                                        head.publication_id
                                    ))
                                })?;
                            if manifest != head {
                                return Err(SpineError::Serialization(
                                    "fake head and manifest disagree".to_string(),
                                ));
                            }
                            Ok(LoadedRepoPublication {
                                head: head.clone(),
                                entries: state
                                    .entity_rows
                                    .get(&head.publication_id)
                                    .cloned()
                                    .unwrap_or_default(),
                                outgoing_edges: state
                                    .edge_rows
                                    .get(&head.publication_id)
                                    .cloned()
                                    .unwrap_or_default(),
                            })
                        })
                        .collect::<Result<Vec<_>, SpineError>>()
                };
                if self.publication_state.lock().unwrap().heads == selected_heads {
                    return loaded;
                }
            }
            Err(SpineError::Backend(
                "fake durable spine heads did not stabilize after three attempts".to_string(),
            ))
        }

        fn cleanup_repo_publications(
            &self,
            active_head: &RepoPublicationHead,
            max_rows: usize,
        ) -> Result<RepoPublicationCleanupProgress, SpineError> {
            self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
            if max_rows == 0 || self.disable_cleanup.load(Ordering::SeqCst) {
                return Ok(RepoPublicationCleanupProgress::default());
            }
            let (publication_id, expected_revision, entity_take, edge_take, remove_manifest, remove_stage) = {
                let state = self.publication_state.lock().unwrap();
                let durable_head = state
                    .heads
                    .get(&active_head.repo_id)
                    .map(|(_, head)| head.clone())
                    .ok_or_else(|| {
                        SpineError::Backend(
                            "fake store has no durable head during cleanup".to_string(),
                        )
                    })?;
                let mut candidates = state
                    .stages
                    .values()
                    .filter(|head| {
                        head.repo_id == durable_head.repo_id
                            && head.publication_id != durable_head.publication_id
                            && (head.source_cursor < durable_head.source_cursor
                                || (head.source_cursor == durable_head.source_cursor
                                    && head.phase <= durable_head.phase))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                candidates.sort_by(|left, right| {
                    left.source_cursor
                        .cmp(&right.source_cursor)
                        .then_with(|| left.phase.cmp(&right.phase))
                        .then_with(|| left.publication_id.cmp(&right.publication_id))
                });
                let Some(stale) = candidates.into_iter().next() else {
                    return Ok(RepoPublicationCleanupProgress::default());
                };
                let expected_revision = state
                    .stage_revisions
                    .get(&stale.publication_id)
                    .copied()
                    .ok_or_else(|| {
                        SpineError::Serialization(format!(
                            "fake stage {} has no revision",
                            stale.publication_id
                        ))
                    })?;
                let entity_len = state
                    .entity_rows
                    .get(&stale.publication_id)
                    .map_or(0, Vec::len);
                let entity_take = entity_len.min(max_rows);
                let remaining = max_rows - entity_take;
                let edge_len = state
                    .edge_rows
                    .get(&stale.publication_id)
                    .map_or(0, Vec::len);
                let edge_take = edge_len.min(remaining);
                let rows_empty_after = entity_take == entity_len && edge_take == edge_len;
                let mut planned = entity_take + edge_take;
                let remove_manifest = rows_empty_after
                    && planned < max_rows
                    && state.manifests.contains_key(&stale.publication_id);
                planned += usize::from(remove_manifest);
                let remove_stage = rows_empty_after && planned < max_rows;
                (
                    stale.publication_id,
                    expected_revision,
                    entity_take,
                    edge_take,
                    remove_manifest,
                    remove_stage,
                )
            };

            if let Some(barrier) = self.cleanup_snapshot_barrier.lock().unwrap().take() {
                barrier.wait();
                barrier.wait();
            }

            let mut state = self.publication_state.lock().unwrap();
            if !self.disable_stage_fence.load(Ordering::SeqCst)
                && state.stage_revisions.get(&publication_id).copied()
                    != Some(expected_revision)
            {
                return Ok(RepoPublicationCleanupProgress {
                    deleted: 0,
                    more: true,
                });
            }
            let mut deleted = 0usize;
            if let Some(rows) = state.entity_rows.get_mut(&publication_id) {
                let take = entity_take.min(rows.len());
                rows.drain(..take);
                deleted += take;
            }
            if let Some(rows) = state.edge_rows.get_mut(&publication_id) {
                let take = edge_take.min(rows.len());
                rows.drain(..take);
                deleted += take;
            }
            if remove_manifest && state.manifests.remove(&publication_id).is_some() {
                deleted += 1;
            }
            if remove_stage && state.stages.remove(&publication_id).is_some() {
                state.stage_revisions.remove(&publication_id);
                deleted += 1;
            } else if let Some(revision) = state.stage_revisions.get_mut(&publication_id) {
                *revision += 1;
            }
            let durable_head = state
                .heads
                .get(&active_head.repo_id)
                .map(|(_, head)| head)
                .expect("fake durable head remains during cleanup");
            let more = state.stages.values().any(|head| {
                head.repo_id == durable_head.repo_id
                    && head.publication_id != durable_head.publication_id
                    && (head.source_cursor < durable_head.source_cursor
                        || (head.source_cursor == durable_head.source_cursor
                            && head.phase <= durable_head.phase))
            });
            Ok(RepoPublicationCleanupProgress { deleted, more })
        }

        fn load_repos(&self) -> Result<Vec<LoadedRepo>, SpineError> {
            Ok(self
                .repos
                .lock()
                .unwrap()
                .iter()
                .map(|(repo_id, (root_hash, entries))| LoadedRepo {
                    repo_id: repo_id.clone(),
                    root_hash: root_hash.clone(),
                    entries: entries.clone(),
                })
                .collect())
        }

        fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError> {
            if self.fail_next_load_edges.swap(false, Ordering::SeqCst) {
                return Err(SpineError::Backend(
                    "injected load_edges failure".to_string(),
                ));
            }
            Ok(self.edges.lock().unwrap().clone())
        }

        fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError> {
            let mut repos = self.repos.lock().unwrap();
            let bucket = repos
                .entry(entry.repo_id.clone())
                .or_insert_with(|| (root_hash.to_string(), Vec::new()));
            bucket.0 = root_hash.to_string();
            bucket.1.push(entry.clone());
            Ok(())
        }

        fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError> {
            self.repos.lock().unwrap().remove(repo_id);
            Ok(())
        }

        fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError> {
            self.edges.lock().unwrap().push(edge.clone());
            Ok(())
        }

        fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError> {
            self.edges.lock().unwrap().retain(|e| e.src_repo != repo_id);
            Ok(())
        }
    }

    fn test_fp() -> SemanticFingerprint {
        SemanticFingerprint {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        }
    }

    fn test_entry(repo: &str, name: &str, kind: EntityKind) -> EntityEntry {
        EntityEntry {
            repo_id: repo.to_string(),
            entity_id: EntityId::new(),
            name: name.to_string(),
            kind,
            signature: format!("fn {name}()"),
            fingerprint: test_fp(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(EntityRole::Source),
        }
    }

    fn local_entity(id: EntityId, name: &str) -> Entity {
        use kin_model::EntityMetadata;
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: test_fp(),
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn external_call(src: EntityId, dst: EntityId, import_source: &str, token: &str) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some(import_source.to_string()),
            evidence: vec![RelationEvidence {
                token: Some(token.to_string()),
                ..RelationEvidence::default()
            }],
        }
    }

    fn cursor(value: u64) -> SpineSourceCursor {
        SpineSourceCursor::from_backend_generation(value)
    }

    fn metadata_publication(
        repo_id: &str,
        source_cursor: u64,
        root_hash: &str,
        entries: Vec<EntityEntry>,
    ) -> RepoSpinePublication {
        RepoSpinePublication {
            repo_id: repo_id.to_string(),
            source_cursor: cursor(source_cursor),
            root_hash: root_hash.to_string(),
            entries,
            outgoing_edges: None,
            resolution_roots: None,
        }
    }

    fn edge_publication<const N: usize>(
        repo_id: &str,
        source_cursor: u64,
        root_hash: &str,
        entries: Vec<EntityEntry>,
        edges: Vec<CrossRepoEdge>,
        roots: [(&str, &str); N],
    ) -> RepoSpinePublication {
        RepoSpinePublication {
            repo_id: repo_id.to_string(),
            source_cursor: cursor(source_cursor),
            root_hash: root_hash.to_string(),
            entries,
            outgoing_edges: Some(edges),
            resolution_roots: Some(
                roots
                    .into_iter()
                    .map(|(repo, root)| (repo.to_string(), root.to_string()))
                    .collect(),
            ),
        }
    }

    fn publish(
        backend: &FirestoreSpineBackend,
        publication: RepoSpinePublication,
    ) -> RepoPublicationCommit {
        let prepared = backend
            .prepare_repo_publication(publication)
            .expect("prepare publication");
        backend
            .commit_repo_publication(prepared)
            .expect("commit publication")
    }

    fn publish_success(
        backend: &FirestoreSpineBackend,
        publication: RepoSpinePublication,
    ) {
        assert!(matches!(
            publish(backend, publication),
            RepoPublicationCommit::Committed { .. }
                | RepoPublicationCommit::AlreadyCommitted { .. }
        ));
    }

    fn committed_head(store: &FakeSpineStore, repo_id: &str) -> RepoPublicationHead {
        store
            .publication_state
            .lock()
            .unwrap()
            .heads
            .get(repo_id)
            .map(|(_, head)| head.clone())
            .expect("committed repo head")
    }

    fn commit_store_success(
        store: &FakeSpineStore,
        prepared: &PreparedStorePublication,
    ) {
        assert!(matches!(
            store
                .commit_repo_publication(prepared)
                .expect("commit fake store publication"),
            RepoPublicationCommit::Committed { .. }
                | RepoPublicationCommit::AlreadyCommitted { .. }
        ));
    }

    #[test]
    fn reopen_restores_only_committed_heads_with_edges_and_cursors() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        assert!(matches!(
            publish(
                &writer,
                metadata_publication("provider", 11, "provider-root", vec![provider.clone()])
            ),
            RepoPublicationCommit::Committed { .. }
        ));
        let edge = CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: consumer.entity_id,
            dst_repo: "provider".to_string(),
            dst_entity: provider.entity_id,
            confidence: 0.9,
        };
        assert!(matches!(
            publish(
                &writer,
                edge_publication(
                    "consumer",
                    12,
                    "consumer-root",
                    vec![consumer.clone()],
                    vec![edge],
                    [
                        ("consumer", "consumer-root"),
                        ("provider", "provider-root"),
                    ],
                )
            ),
            RepoPublicationCommit::Committed { .. }
        ));

        let reader = FirestoreSpineBackend::with_store(store);
        assert_eq!(reader.entity_count(), 0, "cache empty before hydrate");
        reader.hydrate().expect("hydrate");
        assert_eq!(reader.repo_count(), 2);
        assert_eq!(reader.entity_count(), 2);
        assert_eq!(reader.edge_count(), 1);
        assert_eq!(reader.source_cursor("provider"), Some(cursor(11)));
        assert_eq!(reader.source_cursor("consumer"), Some(cursor(12)));
        let resolved = reader.resolve("provide", Some(EntityKind::Function), None);
        assert_eq!(resolved.len(), 1);
        let edges = reader.cross_repo_edges_for("provider", &provider.entity_id);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].src_repo, "consumer");
        assert!(!reader.cross_repo_edges_snapshot().complete);
    }

    #[test]
    fn two_repo_edge_heads_reopen_against_one_complete_root_map() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        publish_success(
            &writer,
            metadata_publication("provider", 13, "provider-root", vec![provider.clone()]),
        );
        publish_success(
            &writer,
            metadata_publication("consumer", 14, "consumer-root", vec![consumer.clone()]),
        );
        let roots = [
            ("consumer", "consumer-root"),
            ("provider", "provider-root"),
        ];
        publish_success(
            &writer,
            edge_publication(
                "provider",
                13,
                "provider-root",
                vec![provider.clone()],
                Vec::new(),
                roots,
            ),
        );
        publish_success(
            &writer,
            edge_publication(
                "consumer",
                14,
                "consumer-root",
                vec![consumer.clone()],
                vec![CrossRepoEdge {
                    src_repo: "consumer".to_string(),
                    src_entity: consumer.entity_id,
                    dst_repo: "provider".to_string(),
                    dst_entity: provider.entity_id,
                    confidence: 0.9,
                }],
                roots,
            ),
        );

        let reader = FirestoreSpineBackend::with_store(store);
        reader.hydrate().expect("hydrate both committed edge heads");
        assert_eq!(reader.source_cursor("provider"), Some(cursor(13)));
        assert_eq!(reader.source_cursor("consumer"), Some(cursor(14)));
        assert!(reader.cache.index().authority_is_complete());
    }

    #[test]
    fn detached_edge_derivation_does_not_mutate_until_edge_head_commits() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        publish_success(
            &backend,
            metadata_publication("provider", 20, "provider-root", vec![provider.clone()]),
        );
        publish_success(
            &backend,
            metadata_publication("consumer", 21, "consumer-root", vec![consumer.clone()]),
        );
        let registry = vec!["consumer".to_string(), "provider".to_string()];
        let consumer_entity = local_entity(consumer.entity_id, "consume");
        let relations = vec![external_call(
            consumer.entity_id,
            EntityId::new(),
            "provider",
            "provide",
        )];
        let derived = backend
            .derive_cross_repo_edges("consumer", &[consumer_entity], &relations, &registry)
            .expect("derive detached edge replacement");
        assert_eq!(derived.len(), 1);
        assert_eq!(backend.edge_count(), 0, "derivation is not publication");

        publish_success(
            &backend,
            edge_publication(
                "consumer",
                21,
                "consumer-root",
                vec![consumer],
                derived,
                [
                    ("consumer", "consumer-root"),
                    ("provider", "provider-root"),
                ],
            ),
        );
        assert_eq!(backend.edge_count(), 1);
    }

    fn run_stale_writer_race(
        disable_head_precondition: bool,
    ) -> (RepoPublicationCommit, RepoPublicationHead) {
        let store = Arc::new(FakeSpineStore::default());
        store.disable_cleanup.store(true, Ordering::SeqCst);
        let seed = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &seed,
            metadata_publication(
                "repo",
                1,
                "root-1",
                vec![test_entry("repo", "v1", EntityKind::Function)],
            ),
        );
        let stale_pod = FirestoreSpineBackend::with_store(store.clone());
        let winner_pod = FirestoreSpineBackend::with_store(store.clone());
        let stale_prepared = stale_pod
            .prepare_repo_publication(metadata_publication(
                "repo",
                2,
                "root-2",
                vec![test_entry("repo", "v2", EntityKind::Function)],
            ))
            .expect("stale pod stages from cursor 1");
        let winner_prepared = winner_pod
            .prepare_repo_publication(metadata_publication(
                "repo",
                3,
                "root-3",
                vec![test_entry("repo", "v3", EntityKind::Function)],
            ))
            .expect("winner stages from cursor 1");
        assert!(matches!(
            winner_pod
                .commit_repo_publication(winner_prepared)
                .expect("winner commits"),
            RepoPublicationCommit::Committed { source_cursor }
                if source_cursor == cursor(3)
        ));
        store
            .disable_head_precondition
            .store(disable_head_precondition, Ordering::SeqCst);
        let stale_outcome = stale_pod
            .commit_repo_publication(stale_prepared)
            .expect("stale commit is classified");
        let durable = committed_head(&store, "repo");
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().expect("reopen committed head");
        assert_eq!(reopened.source_cursor("repo"), Some(durable.source_cursor));
        (stale_outcome, durable)
    }

    #[test]
    fn cross_pod_head_cas_rejects_stale_writer_and_exposes_winner_cursor() {
        let (outcome, durable) = run_stale_writer_race(false);
        assert!(matches!(
            outcome,
            RepoPublicationCommit::Conflict(ref conflict)
                if conflict.attempted_cursor == cursor(2)
                    && conflict.observed_cursor == Some(cursor(3))
        ));
        assert_eq!(durable.source_cursor, cursor(3));
        assert_eq!(durable.root_hash, "root-3");
    }

    #[test]
    fn stale_writer_race_falsification_detects_missing_head_precondition() {
        let (outcome, durable) = run_stale_writer_race(true);
        assert!(matches!(
            outcome,
            RepoPublicationCommit::Committed { source_cursor }
                if source_cursor == cursor(2)
        ));
        assert_eq!(durable.source_cursor, cursor(2));
        assert_eq!(durable.root_hash, "root-2");
    }

    #[test]
    fn conflict_retry_recaptures_and_advances_from_observed_winner() {
        let store = Arc::new(FakeSpineStore::default());
        store.disable_cleanup.store(true, Ordering::SeqCst);
        let seed = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &seed,
            metadata_publication(
                "repo",
                1,
                "r1",
                vec![test_entry("repo", "v1", EntityKind::Function)],
            ),
        );
        let retrying = FirestoreSpineBackend::with_store(store.clone());
        let winner = FirestoreSpineBackend::with_store(store.clone());
        let stale = retrying
            .prepare_repo_publication(metadata_publication(
                "repo",
                2,
                "r2",
                vec![test_entry("repo", "v2", EntityKind::Function)],
            ))
            .unwrap();
        publish_success(
            &winner,
            metadata_publication(
                "repo",
                3,
                "r3",
                vec![test_entry("repo", "v3", EntityKind::Function)],
            ),
        );
        assert!(matches!(
            retrying.commit_repo_publication(stale).unwrap(),
            RepoPublicationCommit::Conflict(ref conflict)
                if conflict.observed_cursor == Some(cursor(3))
        ));
        assert_eq!(retrying.source_cursor("repo"), Some(cursor(3)));
        assert_eq!(retrying.resolve("v3", None, None).len(), 1);
        assert!(retrying.resolve("v2", None, None).is_empty());
        assert!(matches!(
            publish(
                &retrying,
                metadata_publication(
                    "repo",
                    4,
                    "r4",
                    vec![test_entry("repo", "v4", EntityKind::Function)],
                )
            ),
            RepoPublicationCommit::Committed { source_cursor }
                if source_cursor == cursor(4)
        ));
        assert_eq!(committed_head(&store, "repo").source_cursor, cursor(4));
    }

    #[test]
    fn same_cursor_edge_phase_cannot_downgrade_to_metadata() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        publish_success(
            &backend,
            metadata_publication("provider", 8, "provider-root", vec![provider.clone()]),
        );
        let metadata = metadata_publication(
            "consumer",
            9,
            "consumer-root",
            vec![consumer.clone()],
        );
        publish_success(&backend, metadata.clone());
        publish_success(
            &backend,
            edge_publication(
                "consumer",
                9,
                "consumer-root",
                vec![consumer.clone()],
                vec![CrossRepoEdge {
                    src_repo: "consumer".to_string(),
                    src_entity: consumer.entity_id,
                    dst_repo: "provider".to_string(),
                    dst_entity: provider.entity_id,
                    confidence: 0.95,
                }],
                [
                    ("consumer", "consumer-root"),
                    ("provider", "provider-root"),
                ],
            ),
        );
        let prepared = backend.prepare_repo_publication(metadata).unwrap();
        let outcome = backend.commit_repo_publication(prepared).unwrap();
        assert!(matches!(
            outcome,
            RepoPublicationCommit::Conflict(ref conflict)
                if conflict.observed_cursor == Some(cursor(9))
                    && conflict.observed_phase == Some(RepoPublicationPhase::Edges)
        ));
        assert_eq!(
            committed_head(&store, "consumer").phase,
            RepoPublicationPhase::Edges
        );
        assert_eq!(backend.edge_count(), 1);
    }

    #[test]
    fn same_cursor_edge_upgrade_cannot_change_the_metadata_domain() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        let original = test_entry("repo", "original", EntityKind::Function);
        publish_success(
            &backend,
            metadata_publication("repo", 31, "original-root", vec![original]),
        );

        let changed = test_entry("repo", "changed", EntityKind::Function);
        let prepared = backend
            .prepare_repo_publication(edge_publication(
                "repo",
                31,
                "changed-root",
                vec![changed],
                Vec::new(),
                [("repo", "changed-root")],
            ))
            .expect("classify same-cursor edge candidate");
        let outcome = backend
            .commit_repo_publication(prepared)
            .expect("return typed conflict");
        assert!(matches!(
            outcome,
            RepoPublicationCommit::Conflict(ref conflict)
                if conflict.attempted_cursor == cursor(31)
                    && conflict.observed_cursor == Some(cursor(31))
                    && conflict.observed_phase == Some(RepoPublicationPhase::Metadata)
        ));
        assert_eq!(backend.root_hash("repo").as_deref(), Some("original-root"));
        assert_eq!(backend.resolve("original", None, None).len(), 1);
        assert!(backend.resolve("changed", None, None).is_empty());
    }

    #[test]
    fn edge_publication_rejects_a_source_root_watermark_mismatch() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        let source = test_entry("source", "caller", EntityKind::Function);
        let error = backend
            .prepare_repo_publication(edge_publication(
                "source",
                10,
                "entity-root",
                vec![source],
                Vec::new(),
                [("source", "different-resolution-root")],
            ))
            .expect_err("source entity and resolution roots are one authority fact");
        assert!(error
            .to_string()
            .contains("source root different from its entity root"));
    }

    #[test]
    fn same_root_new_source_cursor_is_a_real_commit() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                30,
                "same-root",
                vec![test_entry("repo", "first", EntityKind::Function)],
            ),
        );
        let outcome = publish(
            &backend,
            metadata_publication(
                "repo",
                31,
                "same-root",
                vec![test_entry("repo", "second", EntityKind::Function)],
            ),
        );
        assert!(matches!(
            outcome,
            RepoPublicationCommit::Committed { source_cursor }
                if source_cursor == cursor(31)
        ));
        assert_eq!(backend.root_hash("repo").as_deref(), Some("same-root"));
        assert_eq!(backend.source_cursor("repo"), Some(cursor(31)));
        assert_eq!(backend.resolve("second", None, None).len(), 1);
    }

    #[test]
    fn identical_publication_is_idempotent() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        let publication = metadata_publication(
            "repo",
            40,
            "root",
            vec![test_entry("repo", "only", EntityKind::Function)],
        );
        publish_success(&backend, publication.clone());
        assert!(matches!(
            publish(&backend, publication),
            RepoPublicationCommit::AlreadyCommitted { source_cursor }
                if source_cursor == cursor(40)
        ));
    }

    #[test]
    fn concurrent_identical_publications_converge_as_already_committed() {
        let store = Arc::new(FakeSpineStore::default());
        let first = FirestoreSpineBackend::with_store(store.clone());
        let second = FirestoreSpineBackend::with_store(store);
        let publication = metadata_publication(
            "repo",
            41,
            "root",
            vec![test_entry("repo", "only", EntityKind::Function)],
        );
        let first_prepared = first
            .prepare_repo_publication(publication.clone())
            .unwrap();
        let second_prepared = second.prepare_repo_publication(publication).unwrap();
        assert!(matches!(
            first.commit_repo_publication(first_prepared).unwrap(),
            RepoPublicationCommit::Committed { .. }
        ));
        assert!(matches!(
            second.commit_repo_publication(second_prepared).unwrap(),
            RepoPublicationCommit::AlreadyCommitted { source_cursor }
                if source_cursor == cursor(41)
        ));
        assert_eq!(second.source_cursor("repo"), Some(cursor(41)));
    }

    #[test]
    fn immutable_stage_retry_refuses_a_tampered_content_addressed_row() {
        let store = FakeSpineStore::default();
        let publication = metadata_publication(
            "repo",
            42,
            "root",
            vec![test_entry("repo", "authentic", EntityKind::Function)],
        );
        let prepared = store
            .prepare_repo_publication(publication.clone())
            .expect("initial immutable stage");
        let publication_id = prepared.candidate_head().publication_id.clone();
        store
            .publication_state
            .lock()
            .unwrap()
            .entity_rows
            .get_mut(&publication_id)
            .expect("staged entity row")[0]
            .name = "tampered".to_string();

        let error = store
            .prepare_repo_publication(publication)
            .expect_err("retry must not overwrite content-addressed bytes");
        assert!(error
            .to_string()
            .contains("immutable fake entity row changed"));
        assert_eq!(
            store
                .publication_state
                .lock()
                .unwrap()
                .entity_rows
                .get(&publication_id)
                .expect("tampered row remains untouched")[0]
                .name,
            "tampered"
        );
    }

    #[test]
    fn entity_stage_failure_is_invisible_on_reopen() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                50,
                "old-root",
                vec![test_entry("repo", "old", EntityKind::Function)],
            ),
        );
        store.fail_stage_after_rows.store(0, Ordering::SeqCst);
        let error = backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                51,
                "new-root",
                vec![test_entry("repo", "new", EntityKind::Function)],
            ))
            .expect_err("entity staging fault must fail prepare");
        assert!(error.to_string().contains("entity stage failure"));
        assert_eq!(committed_head(&store, "repo").source_cursor, cursor(50));
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().expect("reopen old committed head");
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(50)));
        assert_eq!(reopened.resolve("old", None, None).len(), 1);
        assert!(reopened.resolve("new", None, None).is_empty());
    }

    #[test]
    fn edge_stage_failure_keeps_metadata_head_and_zero_edges() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        publish_success(
            &backend,
            metadata_publication("provider", 60, "provider-root", vec![provider.clone()]),
        );
        publish_success(
            &backend,
            metadata_publication("consumer", 61, "consumer-root", vec![consumer.clone()]),
        );
        store.fail_stage_after_rows.store(1, Ordering::SeqCst);
        let error = backend
            .prepare_repo_publication(edge_publication(
                "consumer",
                61,
                "consumer-root",
                vec![consumer.clone()],
                vec![CrossRepoEdge {
                    src_repo: "consumer".to_string(),
                    src_entity: consumer.entity_id,
                    dst_repo: "provider".to_string(),
                    dst_entity: provider.entity_id,
                    confidence: 0.9,
                }],
                [
                    ("consumer", "consumer-root"),
                    ("provider", "provider-root"),
                ],
            ))
            .expect_err("edge staging fault must fail prepare");
        assert!(error.to_string().contains("edge stage failure"));
        assert_eq!(
            committed_head(&store, "consumer").phase,
            RepoPublicationPhase::Metadata
        );
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().expect("metadata head remains valid");
        assert_eq!(reopened.edge_count(), 0);
    }

    #[test]
    fn head_commit_fault_leaves_staged_candidate_invisible() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                70,
                "old-root",
                vec![test_entry("repo", "old", EntityKind::Function)],
            ),
        );
        let prepared = backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                71,
                "new-root",
                vec![test_entry("repo", "new", EntityKind::Function)],
            ))
            .expect("stage candidate");
        store.fail_next_commit.store(true, Ordering::SeqCst);
        let error = backend
            .commit_repo_publication(prepared)
            .expect_err("head fault must fail commit");
        assert!(error.to_string().contains("head commit failure"));
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().expect("reopen old head");
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(70)));
        assert!(reopened.resolve("new", None, None).is_empty());
    }

    #[test]
    fn lost_commit_response_reconciles_and_installs_the_durable_head() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let prepared = backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                72,
                "root-72",
                vec![test_entry("repo", "committed", EntityKind::Function)],
            ))
            .expect("stage candidate");
        store
            .lose_next_commit_response_after_apply
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            backend
                .commit_repo_publication(prepared)
                .expect("ambiguous response is reconciled"),
            RepoPublicationCommit::AlreadyCommitted { source_cursor }
                if source_cursor == cursor(72)
        ));
        assert_eq!(committed_head(&store, "repo").source_cursor, cursor(72));
        assert_eq!(backend.source_cursor("repo"), Some(cursor(72)));
        assert_eq!(backend.resolve("committed", None, None).len(), 1);
    }

    #[test]
    fn prepared_but_uncommitted_candidate_is_invisible_on_reopen() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                75,
                "old-root",
                vec![test_entry("repo", "old", EntityKind::Function)],
            ),
        );
        let _prepared = backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                76,
                "new-root",
                vec![test_entry("repo", "new", EntityKind::Function)],
            ))
            .expect("stage without committing");
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().expect("head still references old publication");
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(75)));
        assert!(reopened.resolve("new", None, None).is_empty());
    }

    #[test]
    fn hydration_retries_when_cleanup_removes_the_selected_old_head() {
        let store = Arc::new(FakeSpineStore::default());
        let first = store
            .prepare_repo_publication(metadata_publication(
                "repo",
                77,
                "old-root",
                vec![test_entry("repo", "old", EntityKind::Function)],
            ))
            .unwrap();
        commit_store_success(store.as_ref(), &first);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        *store.load_snapshot_barrier.lock().unwrap() = Some(barrier.clone());
        let reopened = Arc::new(FirestoreSpineBackend::with_store(store.clone()));
        let hydrating = reopened.clone();
        let load = std::thread::spawn(move || hydrating.hydrate());

        barrier.wait();
        let second = store
            .prepare_repo_publication(metadata_publication(
                "repo",
                78,
                "new-root",
                vec![test_entry("repo", "new", EntityKind::Function)],
            ))
            .unwrap();
        commit_store_success(store.as_ref(), &second);
        assert_eq!(
            store
                .cleanup_repo_publications(second.candidate_head(), 10)
                .unwrap()
                .deleted,
            3,
            "the old row, manifest, and marker are reclaimed"
        );
        barrier.wait();

        load.join()
            .expect("hydration thread")
            .expect("moved head is retried");
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(78)));
        assert_eq!(reopened.resolve("new", None, None).len(), 1);
        assert!(reopened.resolve("old", None, None).is_empty());
    }

    #[test]
    fn corrupt_committed_manifest_rows_fail_reopen_loudly() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                80,
                "root",
                vec![test_entry("repo", "present", EntityKind::Function)],
            ),
        );
        let head = committed_head(&store, "repo");
        store
            .publication_state
            .lock()
            .unwrap()
            .entity_rows
            .get_mut(&head.publication_id)
            .expect("active entity rows")
            .clear();
        let reopened = FirestoreSpineBackend::with_store(store);
        let error = reopened
            .hydrate()
            .expect_err("committed row-count mismatch must fail");
        assert!(error
            .to_string()
            .contains("expected 1 entities but loaded 0"));
    }

    #[test]
    fn tampered_row_content_fails_manifest_digest_validation() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                81,
                "root",
                vec![test_entry("repo", "authentic", EntityKind::Function)],
            ),
        );
        let head = committed_head(&store, "repo");
        store
            .publication_state
            .lock()
            .unwrap()
            .entity_rows
            .get_mut(&head.publication_id)
            .expect("active entity rows")[0]
            .name = "tampered".to_string();
        let reopened = FirestoreSpineBackend::with_store(store);
        let error = reopened
            .hydrate()
            .expect_err("content tamper must change the canonical digest");
        assert!(error.to_string().contains("failed manifest validation"));
    }

    fn run_cleanup_stage_fence_race(
        disable_stage_fence: bool,
    ) -> (usize, bool, usize) {
        let store = Arc::new(FakeSpineStore::default());
        let seed = store
            .prepare_repo_publication(metadata_publication("repo", 1, "r1", Vec::new()))
            .unwrap();
        commit_store_success(store.as_ref(), &seed);
        let stale = store
            .prepare_repo_publication(metadata_publication(
                "repo",
                2,
                "r2",
                vec![test_entry("repo", "first", EntityKind::Function)],
            ))
            .unwrap();
        let stale_id = stale.candidate_head().publication_id.clone();
        let winner = store
            .prepare_repo_publication(metadata_publication("repo", 3, "r3", Vec::new()))
            .unwrap();
        commit_store_success(store.as_ref(), &winner);

        // Remove the older seed stage so the deterministic race selects the
        // paused cursor-2 writer next.
        assert_eq!(
            store
                .cleanup_repo_publications(winner.candidate_head(), 10)
                .unwrap()
                .deleted,
            2
        );
        store
            .disable_stage_fence
            .store(disable_stage_fence, Ordering::SeqCst);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        *store.cleanup_snapshot_barrier.lock().unwrap() = Some(barrier.clone());
        let cleanup_store = store.clone();
        let winner_head = winner.candidate_head().clone();
        let cleanup = std::thread::spawn(move || {
            cleanup_store
                .cleanup_repo_publications(&winner_head, 10)
                .unwrap()
                .deleted
        });

        barrier.wait();
        {
            let mut state = store.publication_state.lock().unwrap();
            state
                .entity_rows
                .get_mut(&stale_id)
                .expect("stale stage rows")
                .push(test_entry("repo", "late", EntityKind::Function));
            *state
                .stage_revisions
                .get_mut(&stale_id)
                .expect("stale stage revision") += 1;
        }
        barrier.wait();
        let deleted = cleanup.join().unwrap();
        let state = store.publication_state.lock().unwrap();
        (
            deleted,
            state.stages.contains_key(&stale_id),
            state.entity_rows.get(&stale_id).map_or(0, Vec::len),
        )
    }

    #[test]
    fn cleanup_stage_revision_fences_a_late_losing_writer_batch() {
        let (deleted, stage_exists, row_count) = run_cleanup_stage_fence_race(false);
        assert_eq!(deleted, 0, "the stale cleanup snapshot must lose its CAS");
        assert!(stage_exists, "late rows must remain discoverable by their marker");
        assert_eq!(row_count, 2);
    }

    #[test]
    fn cleanup_fence_falsification_strands_the_late_row_without_marker_cas() {
        let (_deleted, stage_exists, row_count) = run_cleanup_stage_fence_race(true);
        assert!(!stage_exists, "the mutant recreates the missing marker race");
        assert_eq!(row_count, 1, "the late row is orphaned by the mutant");
    }

    #[test]
    fn bounded_cleanup_never_deletes_a_future_staged_publication() {
        let store = FakeSpineStore::default();
        let first = store
            .prepare_repo_publication(metadata_publication(
                "repo",
                90,
                "r90",
                vec![test_entry("repo", "v90", EntityKind::Function)],
            ))
            .unwrap();
        commit_store_success(&store, &first);
        let future = store
            .prepare_repo_publication(metadata_publication(
                "repo",
                92,
                "r92",
                vec![test_entry("repo", "v92", EntityKind::Function)],
            ))
            .unwrap();
        let future_id = future.candidate_head().publication_id.clone();
        let middle = store
            .prepare_repo_publication(metadata_publication(
                "repo",
                91,
                "r91",
                vec![test_entry("repo", "v91", EntityKind::Function)],
            ))
            .unwrap();
        let middle_head = middle.candidate_head().clone();
        commit_store_success(&store, &middle);

        assert_eq!(
            store
                .cleanup_repo_publications(&middle_head, 1)
                .unwrap()
                .deleted,
            1
        );
        {
            let state = store.publication_state.lock().unwrap();
            assert!(state.manifests.contains_key(&future_id));
            assert!(state.entity_rows.contains_key(&future_id));
            assert!(state
                .manifests
                .contains_key(&first.candidate_head().publication_id));
        }
        assert_eq!(
            store
                .cleanup_repo_publications(&middle_head, 1)
                .unwrap()
                .deleted,
            1
        );
        let state = store.publication_state.lock().unwrap();
        assert!(state.manifests.contains_key(&future_id));
        assert!(!state
            .manifests
            .contains_key(&first.candidate_head().publication_id));
    }

    #[test]
    fn bounded_cleanup_reclaims_rows_from_a_failed_partial_stage() {
        let store = FakeSpineStore::default();
        let first = store
            .prepare_repo_publication(metadata_publication("repo", 1, "r1", Vec::new()))
            .unwrap();
        commit_store_success(&store, &first);

        let partial = metadata_publication(
            "repo",
            2,
            "r2",
            vec![
                test_entry("repo", "first_partial", EntityKind::Function),
                test_entry("repo", "second_partial", EntityKind::Function),
            ],
        );
        let partial_id = partial
            .clone()
            .canonicalize()
            .expect("canonical partial publication")
            .head
            .publication_id;
        store.fail_stage_after_rows.store(1, Ordering::SeqCst);
        assert!(store.prepare_repo_publication(partial).is_err());
        {
            let state = store.publication_state.lock().unwrap();
            assert!(state.stages.contains_key(&partial_id));
            assert!(!state.manifests.contains_key(&partial_id));
            assert_eq!(state.entity_rows.get(&partial_id).map(Vec::len), Some(1));
        }

        let winner = store
            .prepare_repo_publication(metadata_publication("repo", 3, "r3", Vec::new()))
            .unwrap();
        commit_store_success(&store, &winner);
        assert_eq!(
            store
                .cleanup_repo_publications(winner.candidate_head(), 10)
                .unwrap()
                .deleted,
            2,
            "first pass removes cursor 1's manifest and stage marker"
        );
        assert_eq!(
            store
                .cleanup_repo_publications(winner.candidate_head(), 10)
                .unwrap()
                .deleted,
            2,
            "second pass removes the partial row and its stage marker"
        );
        let state = store.publication_state.lock().unwrap();
        assert!(!state.stages.contains_key(&partial_id));
        assert!(!state.entity_rows.contains_key(&partial_id));
    }

    #[test]
    fn cleanup_continuation_drains_a_large_stage_without_another_publication() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let entries = (0..650)
            .map(|index| {
                test_entry(
                    "repo",
                    &format!("entity_{index:03}"),
                    EntityKind::Function,
                )
            })
            .collect();
        let large = metadata_publication("repo", 1, "large", entries);
        let large_id = large.clone().canonicalize().unwrap().head.publication_id;
        publish_success(&backend, large);
        publish_success(
            &backend,
            metadata_publication("repo", 2, "winner", Vec::new()),
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let drained = {
                let state = store.publication_state.lock().unwrap();
                !state.stages.contains_key(&large_id)
                    && !state.manifests.contains_key(&large_id)
                    && !state.entity_rows.contains_key(&large_id)
            };
            if drained {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "scheduled bounded cleanup must drain beyond the four inline passes"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(backend.cleanup_workers.lock().is_empty());
    }

    #[test]
    fn stale_cleanup_request_re_reads_and_preserves_the_winner() {
        let store = FakeSpineStore::default();
        let first = store
            .prepare_repo_publication(metadata_publication("repo", 1, "r1", Vec::new()))
            .unwrap();
        commit_store_success(&store, &first);
        let second = store
            .prepare_repo_publication(metadata_publication("repo", 2, "r2", Vec::new()))
            .unwrap();
        commit_store_success(&store, &second);
        let third = store
            .prepare_repo_publication(metadata_publication("repo", 3, "r3", Vec::new()))
            .unwrap();
        let winner_id = third.candidate_head().publication_id.clone();
        commit_store_success(&store, &third);

        // Model pod two advancing the head before pod one's post-commit cleanup.
        // The stale caller passes cursor 2, but cleanup must re-read cursor 3.
        assert_eq!(
            store
                .cleanup_repo_publications(second.candidate_head(), 10)
                .unwrap()
                .deleted,
            2
        );
        let state = store.publication_state.lock().unwrap();
        assert_eq!(
            state.heads.get("repo").map(|(_, head)| head.source_cursor),
            Some(cursor(3))
        );
        assert!(state.manifests.contains_key(&winner_id));
    }

    #[test]
    fn legacy_rows_require_a_v2_head_then_remain_ignored() {
        let store = Arc::new(FakeSpineStore::default());
        let legacy = test_entry("repo", "legacy", EntityKind::Function);
        store.write_entity(&legacy, "legacy-root").unwrap();
        let blocked = FirestoreSpineBackend::with_store(store.clone());
        let error = blocked
            .hydrate()
            .expect_err("uncovered legacy repo must block migration");
        assert!(error
            .to_string()
            .contains("legacy spine rows have no committed cursor-bound head"));
        let error = blocked
            .complete_legacy_migration()
            .expect_err("uncovered legacy rows must prevent the one-way marker");
        assert!(error
            .to_string()
            .contains("repositories lack v2 heads"));

        let publisher = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &publisher,
            metadata_publication(
                "repo",
                100,
                "current-root",
                vec![test_entry("repo", "current", EntityKind::Function)],
            ),
        );
        publisher
            .complete_legacy_migration()
            .expect("covered legacy rows can receive the durable completion marker");
        store.fail_next_load_edges.store(true, Ordering::SeqCst);
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened
            .hydrate()
            .expect("durable completion marker removes legacy collections from cold reopen");
        assert!(reopened.resolve("legacy", None, None).is_empty());
        assert_eq!(reopened.resolve("current", None, None).len(), 1);
    }

    #[test]
    fn unavailable_atomicity_blocks_prepare_and_hydration() {
        let store = Arc::new(FakeSpineStore::default());
        store.atomicity_available.store(false, Ordering::SeqCst);
        let backend = FirestoreSpineBackend::with_store(store);
        let error = backend
            .prepare_repo_publication(metadata_publication("repo", 1, "root", Vec::new()))
            .expect_err("prepare must fail without atomic CAS");
        assert!(error.to_string().contains("atomic publication unavailable"));
        let error = backend
            .hydrate()
            .expect_err("hydrate must fail without committed-head reads");
        assert!(error.to_string().contains("atomic publication unavailable"));
    }

    #[test]
    fn prepared_token_cannot_cross_backend_instances() {
        let store = Arc::new(FakeSpineStore::default());
        let first = FirestoreSpineBackend::with_store(store.clone());
        let second = FirestoreSpineBackend::with_store(store);
        let prepared = first
            .prepare_repo_publication(metadata_publication("repo", 1, "root", Vec::new()))
            .unwrap();
        let error = second
            .commit_repo_publication(prepared)
            .expect_err("owner binding must reject a foreign token");
        assert!(error.to_string().contains("belongs to another backend"));
    }

    #[test]
    fn cursorless_legacy_mutations_are_refused_without_store_or_cache_changes() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let entry = test_entry("repo", "value", EntityKind::Function);
        backend.register_repo("repo", vec![entry.clone()], "root");
        backend.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo".to_string(),
            src_entity: entry.entity_id,
            dst_repo: "other".to_string(),
            dst_entity: EntityId::new(),
            confidence: 0.5,
        });
        backend.refresh_cross_repo_edges("repo", &[], &[], &["repo".to_string()]);
        assert_eq!(backend.repo_count(), 0);
        assert_eq!(backend.edge_count(), 0);
        assert!(store.load_repos().unwrap().is_empty());
        assert!(store.load_edges().unwrap().is_empty());
        assert!(store.load_repo_publications().unwrap().is_empty());
    }

    #[test]
    fn committed_head_refresh_advances_an_idle_reader() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &writer,
            metadata_publication(
                "repo-a",
                1,
                "a",
                vec![test_entry("repo-a", "a", EntityKind::Function)],
            ),
        );
        let reader = FirestoreSpineBackend::with_store(store);
        reader.hydrate().unwrap();
        publish_success(
            &writer,
            metadata_publication(
                "repo-b",
                1,
                "b",
                vec![test_entry("repo-b", "b", EntityKind::Function)],
            ),
        );
        reader.refresh_committed_publications().unwrap();
        assert_eq!(reader.repo_count(), 2);
        assert_eq!(
            reader.registered_repo_ids(),
            HashSet::from(["repo-a".to_string(), "repo-b".to_string()])
        );
    }

    #[test]
    fn initial_snapshot_cursor_can_advance_to_a_later_generation() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        assert!(matches!(
            publish(
                &backend,
                metadata_publication("repo", 0, "empty-root", Vec::new())
            ),
            RepoPublicationCommit::Committed { source_cursor }
                if source_cursor == cursor(0)
        ));
        assert_eq!(backend.source_cursor("repo"), Some(cursor(0)));

        assert!(matches!(
            publish(
                &backend,
                metadata_publication(
                    "repo",
                    1,
                    "nonempty-root",
                    vec![test_entry("repo", "now_present", EntityKind::Function)],
                )
            ),
            RepoPublicationCommit::Committed { source_cursor }
                if source_cursor == cursor(1)
        ));
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().unwrap();
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(1)));
        assert_eq!(reopened.resolve("now_present", None, None).len(), 1);
    }

    #[test]
    fn rollout_fence_requires_the_exact_fleet_and_nonzero_gcs_generations() {
        let expected = ["a", "b", "c", "d", "e"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let rows = expected
            .iter()
            .enumerate()
            .map(|(index, repo_id)| SpineRolloutRepositoryFence {
                repo_id: repo_id.clone(),
                pre_fence_generation: 10 + index as u64,
                fenced_generation: 20 + index as u64,
                snapshot_schema: 4,
                e_tag: Some(format!("etag-{repo_id}")),
            })
            .collect::<Vec<_>>();

        assert!(SpineRolloutFence::new_exact(
            "gcs://bucket/prefix".to_string(),
            1,
            "token",
            &expected,
            rows[..4].to_vec(),
        )
        .is_err());

        let mut unrelated = rows.clone();
        unrelated[4].repo_id = "unrelated".to_string();
        assert!(SpineRolloutFence::new_exact(
            "gcs://bucket/prefix".to_string(),
            1,
            "token",
            &expected,
            unrelated,
        )
        .is_err());

        let good = SpineRolloutFence::new_exact(
            "gcs://bucket/prefix".to_string(),
            1,
            "token",
            &expected,
            rows.clone(),
        )
        .unwrap();
        assert!(good
            .validate_exact_fleet("gcs://wrong/prefix", &expected)
            .is_err());
        assert!(good
            .validate_exact_fleet("gcs://bucket/prefix", &expected[..4])
            .is_err());

        let mut zero = rows;
        zero[0].pre_fence_generation = 0;
        assert!(SpineRolloutFence::new_exact(
            "gcs://bucket/prefix".to_string(),
            1,
            "token",
            &expected,
            zero,
        )
        .is_err());
    }

    #[test]
    fn paused_pre_rollout_writer_loses_and_the_fence_mutant_restores_the_race() {
        let fleet = ["consumer", "provider", "repo", "repo-a", "repo-b", "source"];
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let paused = backend
            .prepare_repo_publication(metadata_publication("repo", 7, "root", Vec::new()))
            .unwrap();
        let next = test_rollout_fence(2, "test-rollout-2", &fleet);
        assert!(matches!(
            backend.advance_rollout_fence(next),
            Ok(SpineRolloutFenceCommit::Advanced(_))
        ));
        let conflict = backend.commit_repo_publication(paused).unwrap();
        assert!(matches!(
            conflict,
            RepoPublicationCommit::Conflict(RepoPublicationConflict {
                attempted_rollout_fence: Some(1),
                observed_rollout_fence: Some(2),
                observed_cursor: None,
                ..
            })
        ));
        assert!(store.publication_state.lock().unwrap().heads.is_empty());

        let mutant_store = Arc::new(FakeSpineStore::default());
        let mutant = FirestoreSpineBackend::with_store(mutant_store.clone());
        let paused = mutant
            .prepare_repo_publication(metadata_publication("repo", 7, "root", Vec::new()))
            .unwrap();
        assert!(matches!(
            mutant.advance_rollout_fence(test_rollout_fence(
                2,
                "test-rollout-2",
                &fleet,
            )),
            Ok(SpineRolloutFenceCommit::Advanced(_))
        ));
        mutant_store
            .disable_rollout_fence_precondition
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            mutant.commit_repo_publication(paused).unwrap(),
            RepoPublicationCommit::Committed { .. }
        ));
    }

    #[test]
    fn identical_paused_writer_cannot_bypass_a_newer_rollout_fence() {
        let fleet = ["consumer", "provider", "repo", "repo-a", "repo-b", "source"];
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        let publication = metadata_publication("repo", 9, "root", Vec::new());
        publish_success(&backend, publication.clone());
        let paused_identical = backend.prepare_repo_publication(publication).unwrap();
        backend
            .advance_rollout_fence(test_rollout_fence(2, "test-rollout-2", &fleet))
            .unwrap();
        assert!(matches!(
            backend.commit_repo_publication(paused_identical).unwrap(),
            RepoPublicationCommit::Conflict(RepoPublicationConflict {
                attempted_rollout_fence: Some(1),
                observed_rollout_fence: Some(2),
                ..
            })
        ));
    }

    #[test]
    fn rollout_fence_lost_response_reconciles_and_the_mutant_loses_evidence() {
        let fleet = ["consumer", "provider", "repo", "repo-a", "repo-b", "source"];
        let candidate = test_rollout_fence(2, "test-rollout-2", &fleet);
        let store = Arc::new(FakeSpineStore::default());
        store
            .lose_next_rollout_fence_response_after_apply
            .store(true, Ordering::SeqCst);
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let evidence = match backend
            .advance_rollout_fence(candidate.clone())
            .unwrap()
        {
            SpineRolloutFenceCommit::Advanced(evidence) => evidence,
            other => panic!("lost response should reconcile as advanced, got {other:?}"),
        };
        assert_eq!(
            store.load_rollout_fence().unwrap().unwrap().evidence(),
            evidence
        );
        assert_eq!(
            backend.advance_rollout_fence(candidate).unwrap(),
            SpineRolloutFenceCommit::AlreadyCurrent(evidence)
        );

        let mutant_store = Arc::new(FakeSpineStore::default());
        mutant_store
            .lose_next_rollout_fence_response_after_apply
            .store(true, Ordering::SeqCst);
        mutant_store
            .disable_rollout_fence_reconciliation
            .store(true, Ordering::SeqCst);
        let mutant = FirestoreSpineBackend::with_store(mutant_store.clone());
        assert!(mutant
            .advance_rollout_fence(test_rollout_fence(
                2,
                "test-rollout-2",
                &fleet,
            ))
            .is_err());
        assert_eq!(
            mutant_store
                .load_rollout_fence()
                .unwrap()
                .unwrap()
                .fence
                .rollout_fence,
            2,
            "mutant applied the CAS but failed to recover its evidence"
        );
    }

    #[test]
    fn writer_before_firestore_fence_remains_visible_only_for_daemon_root_reproof() {
        let fleet = ["consumer", "provider", "repo", "repo-a", "repo-b", "source"];
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &writer,
            metadata_publication("repo", 41, "same-bytes-root", Vec::new()),
        );
        writer
            .advance_rollout_fence(test_rollout_fence(2, "test-rollout-2", &fleet))
            .unwrap();

        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().unwrap();
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(41)));
        assert_eq!(reopened.root_hash("repo").as_deref(), Some("same-bytes-root"));
        assert_eq!(
            reopened.active_rollout_fence().unwrap().fence.rollout_fence,
            2
        );
        // KinDB cursor 41 and the GCS object generations in the active fence are
        // intentionally not compared. The daemon must re-probe its post-fence
        // graph cursor and prove this content root before serving readiness.
    }

    #[test]
    fn refresh_rechecks_unsealed_legacy_rows_and_ttl_gates_cleanup_discovery() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("repo", 1, "root", Vec::new()),
        );
        backend.hydrate().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while backend.cleanup_sweep_gate.lock().running {
            assert!(Instant::now() < deadline, "initial cleanup sweep must finish");
            std::thread::yield_now();
        }
        let calls_after_first_refresh = store.cleanup_calls.load(Ordering::SeqCst);
        backend.hydrate().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(
            store.cleanup_calls.load(Ordering::SeqCst),
            calls_after_first_refresh,
            "a no-op authority refresh inside the TTL must not rescan every repo"
        );

        store
            .repos
            .lock()
            .unwrap()
            .insert("provider".to_string(), ("legacy".to_string(), Vec::new()));
        let error = backend
            .hydrate()
            .expect_err("an unsealed process must recheck late legacy rows");
        assert!(error.to_string().contains("repositories: provider"));
    }

    #[test]
    fn missing_or_disappearing_durable_authority_fails_refresh() {
        let missing_store = Arc::new(FakeSpineStore::default());
        *missing_store.rollout_fence_state.lock().unwrap() = None;
        let missing = FirestoreSpineBackend::with_store(missing_store);
        assert!(missing.hydrate().is_err());
        assert!(missing
            .prepare_repo_publication(metadata_publication("repo", 1, "root", Vec::new()))
            .is_err());

        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("repo", 1, "root", Vec::new()),
        );
        backend.hydrate().unwrap();
        store.publication_state.lock().unwrap().heads.remove("repo");
        let error = backend
            .hydrate()
            .expect_err("an append-only committed head must not disappear silently");
        assert!(error.to_string().contains("heads disappeared"));
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn firestore_head_write_always_carries_the_exact_precondition() {
        let head = metadata_publication("repo", 7, "root", Vec::new())
            .canonicalize()
            .unwrap()
            .head;
        let missing = firestore_head_write(
            "projects/p/databases/d/documents/spine_repo_heads_v2/repo".to_string(),
            &head,
            &StoreHeadPrecondition::Missing,
        )
        .unwrap();
        assert_eq!(
            missing
                .pointer("/currentDocument/exists")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert!(missing
            .pointer("/currentDocument/updateTime")
            .is_none());

        let revision = firestore_head_write(
            "projects/p/databases/d/documents/spine_repo_heads_v2/repo".to_string(),
            &head,
            &StoreHeadPrecondition::Revision("2026-08-27T12:00:00Z".to_string()),
        )
        .unwrap();
        assert_eq!(
            revision
                .pointer("/currentDocument/updateTime")
                .and_then(serde_json::Value::as_str),
            Some("2026-08-27T12:00:00Z")
        );
        assert!(revision.pointer("/currentDocument/exists").is_none());
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn firestore_rollout_fence_write_is_exact_and_revision_checked() {
        let fence = test_rollout_fence(
            2,
            "test-rollout-2",
            &["consumer", "provider", "repo", "repo-a", "repo-b", "source"],
        );
        let write = firestore_rollout_fence_write(
            "projects/p/databases/d/documents/spine_control_v2/rollout_fence".to_string(),
            &fence,
            &StoreHeadPrecondition::Revision("2026-08-27T12:00:00Z".to_string()),
        )
        .unwrap();
        assert_eq!(
            write
                .pointer("/currentDocument/updateTime")
                .and_then(serde_json::Value::as_str),
            Some("2026-08-27T12:00:00Z")
        );
        assert_eq!(
            write.pointer("/update/fields"),
            Some(&firestore_rollout_fence_fields(&fence).unwrap())
        );

        let missing = firestore_rollout_fence_write(
            "projects/p/databases/d/documents/spine_control_v2/rollout_fence".to_string(),
            &fence,
            &StoreHeadPrecondition::Missing,
        )
        .unwrap();
        assert_eq!(
            missing
                .pointer("/currentDocument/exists")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn production_store_refuses_every_legacy_mutation_entrypoint() {
        let store = FirestoreStore::new("project".to_string(), None);
        let entry = test_entry("repo", "value", EntityKind::Function);
        let edge = CrossRepoEdge {
            src_repo: "repo".to_string(),
            src_entity: entry.entity_id,
            dst_repo: "other".to_string(),
            dst_entity: EntityId::new(),
            confidence: 0.5,
        };
        assert!(store.write_entity(&entry, "root").is_err());
        assert!(store.delete_repo_entities("repo").is_err());
        assert!(store.write_edge(&edge).is_err());
        assert!(store.delete_repo_edges("repo").is_err());
    }

}
