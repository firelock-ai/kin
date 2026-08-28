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
use std::sync::atomic::Ordering;

use kin_model::{Entity, EntityId, EntityKind, Relation, SemanticFingerprint};
use parking_lot::Mutex as ParkingMutex;
use tracing::{error, info, warn};

use crate::backend::{
    InMemorySpineBackend, PreparedRepoSpinePublication, SpineBackend, SpineError,
};
use crate::federation::FederatedImpact;
use crate::index::{
    CommittedRepoIndexPublication, CrossRepoEdge, CrossRepoEdgesSnapshot, EntityEntry,
};
use crate::publication::{
    CanonicalRepoPublication, LegacySpineWriterDrainAttestation, RepoPublicationCommit,
    RepoPublicationHead, RepoSpinePublication, SpineRolloutFence, SpineRolloutFenceCommit,
    SpineRolloutFenceEvidence, SpineSourceCursor,
};
// The durable store shapes below are named only by the Firestore REST paths and
// by the in-process fake the tests drive. A default-feature library build
// compiles neither, so importing them unconditionally is an unused import, and
// this crate is built with warnings denied.
#[cfg(any(feature = "firestore", test))]
use crate::publication::RepoPublicationPhase;
#[cfg(test)]
use crate::publication::SpineRolloutRepositoryFence;
// Firestore-only, not firestore-or-test. The fake that used these under a plain
// `test` build now lives in `test_support` and imports them itself, so keeping
// the `test` arm here made them unused on the default shape, where warnings are
// denied.
#[cfg(all(test, not(feature = "firestore")))]
use crate::store::PreparedStorePublication;
use crate::store::{LoadedRepoPublication, LoadedSpineRolloutFence, SpineStore};
#[cfg(feature = "firestore")]
use crate::store::{
    PreparedStorePublication, RepoPublicationCleanupProgress, StoreHeadPrecondition,
    StorePublicationStageGuard, StoreRepoHeadGuard,
};

const CLEANUP_DOCUMENTS_PER_COMMIT: usize = 100;
const CLEANUP_PASSES_PER_TERMINAL_OUTCOME: usize = 4;
const CLEANUP_CONTINUATION_RETRY_LIMIT: usize = 8;
const CLEANUP_CONTINUATION_PASS_LIMIT: usize = 64;
const CLEANUP_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

#[cfg(feature = "firestore")]
const FIRESTORE_MAX_WRITES_PER_COMMIT: usize = 100;

#[cfg(feature = "firestore")]
const FIRESTORE_MAX_COMMIT_JSON_BYTES: usize = 8 * 1024 * 1024;

#[cfg(feature = "firestore")]
const STAGE_MARKER_REVISION_HASH_DOMAIN: &[u8] = b"kin.spine-stage-marker-revision.v1\0";

#[cfg(feature = "firestore")]
const LEGACY_MIGRATION_HEAD_SET_HASH_DOMAIN: &[u8] = b"kin.spine-legacy-migration-head-set.v1\0";

#[cfg(feature = "firestore")]
const LEGACY_MIGRATION_SEAL_SCHEMA: &str = "kin.spine-legacy-migration-seal.v1";

#[cfg(feature = "firestore")]
const LEGACY_MIGRATION_MARKER_DOCUMENT_ID: &str = "legacy_migration";

#[cfg(feature = "firestore")]
const LEGACY_MIGRATION_SEAL_DOCUMENT_ID: &str = "legacy_migration_seal_v1";

#[cfg(feature = "firestore")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct StageMarkerProgress {
    stage_sequence: u64,
    revision_kind: String,
    revision_sha256: String,
}

#[cfg(feature = "firestore")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LegacyMigrationSeal {
    schema: String,
    scope: String,
    repository_ids: Vec<String>,
    rollout_fence_evidence: SpineRolloutFenceEvidence,
    writer_drain: LegacySpineWriterDrainAttestation,
    sealed_heads: Vec<RepoPublicationHead>,
    head_set_sha256: String,
}

#[cfg(feature = "firestore")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum LegacyMigrationMarker {
    Absent,
    Predecessor {
        fields: serde_json::Value,
        update_time: String,
    },
    CanonicalSeal {
        seal: LegacyMigrationSeal,
    },
}

#[cfg(feature = "firestore")]
fn legacy_migration_head_set_sha256(
    scope: &str,
    rollout_fence_evidence: &SpineRolloutFenceEvidence,
    sealed_heads: &[RepoPublicationHead],
) -> Result<String, SpineError> {
    use sha2::{Digest, Sha256};

    let payload =
        serde_json::to_vec(&(scope, rollout_fence_evidence, sealed_heads)).map_err(|error| {
            SpineError::Serialization(format!(
                "failed to serialize legacy migration head-set evidence: {error}"
            ))
        })?;
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_MIGRATION_HEAD_SET_HASH_DOMAIN);
    hasher.update(payload);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

#[cfg(feature = "firestore")]
impl LegacyMigrationSeal {
    fn build(
        active: &LoadedSpineRolloutFence,
        writer_drain: LegacySpineWriterDrainAttestation,
        mut sealed_heads: Vec<RepoPublicationHead>,
    ) -> Result<Self, SpineError> {
        writer_drain.validate()?;
        if writer_drain.rollout_fence_evidence != active.evidence() {
            return Err(SpineError::Backend(
                "legacy migration writer-drain evidence does not match the active rollout fence"
                    .to_string(),
            ));
        }
        sealed_heads.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
        for head in &sealed_heads {
            head.validate()?;
        }
        let repository_ids = active
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<Vec<_>>();
        let observed_ids = sealed_heads
            .iter()
            .map(|head| head.repo_id.clone())
            .collect::<Vec<_>>();
        if observed_ids != repository_ids {
            return Err(SpineError::Backend(
                "legacy migration seal requires one committed head for every exact fleet repository"
                    .to_string(),
            ));
        }
        let rollout_fence_evidence = active.evidence();
        let head_set_sha256 = legacy_migration_head_set_sha256(
            &active.fence.scope,
            &rollout_fence_evidence,
            &sealed_heads,
        )?;
        Ok(Self {
            schema: LEGACY_MIGRATION_SEAL_SCHEMA.to_string(),
            scope: active.fence.scope.clone(),
            repository_ids,
            rollout_fence_evidence,
            writer_drain,
            sealed_heads,
            head_set_sha256,
        })
    }

    fn validate_against_active(&self, active: &LoadedSpineRolloutFence) -> Result<(), SpineError> {
        if self.schema != LEGACY_MIGRATION_SEAL_SCHEMA {
            return Err(SpineError::Serialization(format!(
                "unsupported legacy migration seal schema {}",
                self.schema
            )));
        }
        self.writer_drain.validate()?;
        if self.writer_drain.rollout_fence_evidence != self.rollout_fence_evidence {
            return Err(SpineError::Serialization(
                "legacy migration seal writer-drain evidence is not self-consistent".to_string(),
            ));
        }
        let expected_repository_ids = active
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<Vec<_>>();
        if self.scope != active.fence.scope
            || self.repository_ids != expected_repository_ids
            || self.rollout_fence_evidence.rollout_fence > active.fence.rollout_fence
        {
            return Err(SpineError::Backend(
                "legacy migration seal does not belong to the active rollout scope and exact fleet"
                    .to_string(),
            ));
        }
        if self.rollout_fence_evidence.rollout_fence == active.fence.rollout_fence
            && self.rollout_fence_evidence != active.evidence()
        {
            return Err(SpineError::Backend(
                "legacy migration seal carries different evidence for the active rollout fence"
                    .to_string(),
            ));
        }
        let observed_ids = self
            .sealed_heads
            .iter()
            .map(|head| head.repo_id.clone())
            .collect::<Vec<_>>();
        for head in &self.sealed_heads {
            head.validate()?;
        }
        if observed_ids != self.repository_ids
            || self.head_set_sha256
                != legacy_migration_head_set_sha256(
                    &self.scope,
                    &self.rollout_fence_evidence,
                    &self.sealed_heads,
                )?
        {
            return Err(SpineError::Serialization(
                "legacy migration seal head-set evidence is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "firestore")]
fn firestore_legacy_migration_seal_fields(
    seal: &LegacyMigrationSeal,
) -> Result<serde_json::Value, SpineError> {
    let payload = serde_json::to_string(seal).map_err(|error| {
        SpineError::Serialization(format!(
            "failed to serialize legacy migration seal: {error}"
        ))
    })?;
    Ok(serde_json::json!({
        "schema": { "stringValue": LEGACY_MIGRATION_SEAL_SCHEMA },
        "state": { "stringValue": "complete" },
        "head_set_sha256": { "stringValue": seal.head_set_sha256 },
        "payload": { "stringValue": payload }
    }))
}

#[cfg(feature = "firestore")]
fn document_update_time(document: &serde_json::Value, what: &str) -> Result<String, SpineError> {
    document
        .get("updateTime")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            SpineError::Serialization(format!("{what} document is missing Firestore updateTime"))
        })
}

#[cfg(feature = "firestore")]
fn parse_legacy_migration_seal_document(
    document: &serde_json::Value,
    expected_name: &str,
) -> Result<(LegacyMigrationSeal, String), SpineError> {
    if document.get("name").and_then(serde_json::Value::as_str) != Some(expected_name) {
        return Err(SpineError::Serialization(
            "legacy migration seal is stored under the wrong document identity".to_string(),
        ));
    }
    let seal: LegacyMigrationSeal = doc_payload(document, "legacy migration seal")?;
    let expected_fields = firestore_legacy_migration_seal_fields(&seal)?;
    if document.get("fields") != Some(&expected_fields) {
        return Err(SpineError::Serialization(
            "legacy migration seal sibling fields do not exactly match its canonical payload"
                .to_string(),
        ));
    }
    Ok((
        seal,
        document_update_time(document, "legacy migration seal")?,
    ))
}

#[cfg(feature = "firestore")]
fn parse_legacy_migration_marker_document(
    document: Option<&serde_json::Value>,
    expected_name: &str,
) -> Result<LegacyMigrationMarker, SpineError> {
    let Some(document) = document else {
        return Ok(LegacyMigrationMarker::Absent);
    };
    if document.get("name").and_then(serde_json::Value::as_str) != Some(expected_name) {
        return Err(SpineError::Serialization(
            "legacy migration marker is stored under the wrong document identity".to_string(),
        ));
    }
    let update_time = document_update_time(document, "legacy migration marker")?;
    let fields = document.get("fields").ok_or_else(|| {
        SpineError::Serialization("legacy migration marker has no fields".to_string())
    })?;

    let predecessor_two_fields = serde_json::json!({
        "schema_version": { "integerValue": "2" },
        "state": { "stringValue": "complete" }
    });
    if fields == &predecessor_two_fields {
        return Ok(LegacyMigrationMarker::Predecessor {
            fields: fields.clone(),
            update_time,
        });
    }

    let rollout_fence = fields
        .get("rollout_fence")
        .and_then(|value| value.get("integerValue"))
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<u64>().ok());
    let rollout_payload_sha256 = fields
        .get("rollout_payload_sha256")
        .and_then(|value| value.get("stringValue"))
        .and_then(serde_json::Value::as_str);
    let rollout_update_time = fields
        .get("rollout_update_time")
        .and_then(|value| value.get("stringValue"))
        .and_then(serde_json::Value::as_str);
    if let (Some(rollout_fence), Some(rollout_payload_sha256), Some(rollout_update_time)) =
        (rollout_fence, rollout_payload_sha256, rollout_update_time)
    {
        let canonical_digest =
            rollout_payload_sha256
                .strip_prefix("sha256:")
                .is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                });
        let predecessor_five_fields = serde_json::json!({
            "schema_version": { "integerValue": "2" },
            "state": { "stringValue": "complete" },
            "rollout_fence": { "integerValue": rollout_fence.to_string() },
            "rollout_payload_sha256": { "stringValue": rollout_payload_sha256 },
            "rollout_update_time": { "stringValue": rollout_update_time }
        });
        if rollout_fence > 0
            && canonical_digest
            && !rollout_update_time.is_empty()
            && fields == &predecessor_five_fields
        {
            return Ok(LegacyMigrationMarker::Predecessor {
                fields: fields.clone(),
                update_time,
            });
        }
    }

    if fields.get("payload").is_some() {
        let (seal, _) = parse_legacy_migration_seal_document(document, expected_name)?;
        return Ok(LegacyMigrationMarker::CanonicalSeal { seal });
    }

    Err(SpineError::Serialization(
        "legacy migration marker has unsupported or mixed contents".to_string(),
    ))
}

#[cfg(feature = "firestore")]
fn require_exact_legacy_migration_seal(
    attempted: &LegacyMigrationSeal,
    observed: &LegacyMigrationSeal,
) -> Result<(), SpineError> {
    if attempted == observed {
        Ok(())
    } else {
        Err(SpineError::Backend(
            "a different immutable legacy migration seal already exists".to_string(),
        ))
    }
}

struct CleanupSweepGate {
    running: bool,
    next_due: Instant,
}

// Reconciliation and cleanup-safety are decided only by the Firestore REST
// paths and by the fake the tests drive, so a default-feature library build
// compiles neither caller and every item below is dead code there.
#[cfg(any(feature = "firestore", feature = "test-support", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RolloutFenceReconciliation {
    CandidateCurrent(SpineRolloutFenceEvidence),
    NewerOrDifferent(Option<SpineRolloutFenceEvidence>),
    Retry,
}

#[cfg(any(feature = "firestore", feature = "test-support", test))]
pub(crate) fn classify_rollout_fence_reconciliation(
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

/// How long a stage above the active cursor is protected from cleanup.
///
/// A stage above the active cursor belongs to a writer that may be paused
/// rather than dead, so reclaiming it on sight races a live writer and can
/// delete rows a durable head is about to name. But nothing else reclaimed it
/// either: before this constant existed, a writer that staged a newer cursor
/// and died left its rows for good, while the cleanup sweep's own doc comment
/// claimed to recover exactly that case.
///
/// One hour. A prepare-to-commit window is seconds and a paused writer is
/// minutes, so an hour is a dead writer with margin. The cost of being wrong in
/// the safe direction is one stage's storage for an hour; the cost of being
/// wrong in the other direction is a committed head naming deleted rows, which
/// is why the margin is generous rather than tight.
#[cfg(any(feature = "firestore", feature = "test-support", test))]
pub(crate) const STAGE_TTL: Duration = Duration::from_secs(3600);

/// Whether cleanup may reclaim `staged`, given the active head and how old the
/// stage marker is.
///
/// At or below the active cursor the stage is a terminal loser and reclaiming
/// it cannot race anything: its captured precondition can no longer win.
/// ABOVE the active cursor it belongs to a writer that has not committed yet,
/// and only its age separates a paused writer from a dead one, so the TTL is
/// the whole test there.
///
/// An absent or unreadable age counts as young. Reclaiming on a missing
/// timestamp would be reclaiming on no evidence, and the direction to fail in
/// is the one that keeps a live writer's rows.
#[cfg(any(feature = "firestore", feature = "test-support", test))]
pub(crate) fn publication_stage_is_cleanup_safe(
    staged: &RepoPublicationHead,
    active: &RepoPublicationHead,
    marker_age: Option<Duration>,
) -> bool {
    if staged.source_cursor < active.source_cursor
        || (staged.source_cursor == active.source_cursor && staged.phase <= active.phase)
    {
        return true;
    }
    marker_age.is_some_and(|age| age >= STAGE_TTL)
}

/// How long ago Firestore last changed this document, from its own `updateTime`.
///
/// `None` when the field is absent or unparseable, or when the stamp is in the
/// future, which a caller must read as "young" rather than as "unknown, so
/// reclaim".
#[cfg(feature = "firestore")]
fn firestore_document_age(document: &serde_json::Value) -> Option<Duration> {
    let raw = document
        .get("updateTime")
        .and_then(serde_json::Value::as_str)?;
    let stamped = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    (chrono::Utc::now() - stamped.with_timezone(&chrono::Utc))
        .to_std()
        .ok()
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
    pub fn complete_legacy_migration(
        &self,
        writer_drain: LegacySpineWriterDrainAttestation,
    ) -> Result<(), SpineError> {
        let _migration = self.refresh_write_lock.lock();
        writer_drain.validate()?;
        let (active_rollout_fence, loaded) =
            self.load_stable_rollout_and_publications("legacy migration completion")?;
        if writer_drain.rollout_fence_evidence != active_rollout_fence.evidence() {
            return Err(SpineError::Backend(
                "legacy writer-drain attestation does not bind the exact active rollout fence"
                    .to_string(),
            ));
        }
        for publication in &loaded {
            active_rollout_fence
                .fence
                .validate_publication_repo(&publication.head.repo_id)?;
        }
        let expected_repo_ids = active_rollout_fence
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let committed_repo_ids = loaded
            .iter()
            .map(|publication| publication.head.repo_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if committed_repo_ids != expected_repo_ids {
            return Err(SpineError::Backend(format!(
                "legacy spine migration requires exact active-fleet v2 heads: expected {}, observed {}",
                expected_repo_ids.iter().cloned().collect::<Vec<_>>().join(", "),
                committed_repo_ids.iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        let legacy_repos = self.store.load_repos()?;
        let legacy_edges = self.store.load_edges()?;
        let uncovered_legacy = legacy_repos
            .iter()
            .map(|repo| repo.repo_id.clone())
            .chain(
                legacy_edges
                    .iter()
                    .flat_map(|edge| [edge.src_repo.clone(), edge.dst_repo.clone()]),
            )
            .filter(|repo_id| !committed_repo_ids.contains(repo_id))
            .collect::<std::collections::BTreeSet<_>>();
        if !uncovered_legacy.is_empty() {
            return Err(SpineError::Backend(format!(
                "legacy spine migration cannot complete while repositories lack v2 heads: {}",
                uncovered_legacy.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
        self.store
            .complete_legacy_migration(&active_rollout_fence, &writer_drain)?;
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
    ///
    /// It can now actually do that. A dead writer's stage sits ABOVE the active
    /// cursor, and cleanup preserved every such stage unconditionally, so this
    /// comment described a recovery that never happened: the rows stayed for
    /// good. Reclamation above the cursor is gated on [`STAGE_TTL`] instead, so
    /// the sweep drains a dead writer's stage once its marker is older than
    /// that and leaves a paused writer's alone before it.
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

        // A point-in-time scan of the legacy collections cannot prove an old
        // cursorless binary will not append another invisible row afterward.
        // Reader installation therefore requires the durable, externally
        // attested one-way migration seal even when the legacy collections are
        // currently empty or every visible row happens to be covered.
        if !self.store.legacy_migration_complete()? {
            return Err(SpineError::Backend(
                "hosted spine reads remain sealed until the durable legacy writer-drain migration marker is complete"
                    .to_string(),
            ));
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
        let expected_repo_ids = active_rollout_fence
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<HashSet<_>>();
        if durable_repo_ids != expected_repo_ids {
            return Err(SpineError::Backend(format!(
                "committed spine head set does not equal the active exact fleet: expected {}, observed {}",
                {
                    let mut ids = expected_repo_ids.iter().cloned().collect::<Vec<_>>();
                    ids.sort();
                    ids.join(", ")
                },
                {
                    let mut ids = durable_repo_ids.iter().cloned().collect::<Vec<_>>();
                    ids.sort();
                    ids.join(", ")
                }
            )));
        }
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

        let replacement = canonical
            .into_iter()
            .map(|publication| {
                let candidate = publication.publication;
                CommittedRepoIndexPublication {
                    repo_id: candidate.repo_id,
                    entries: candidate.entries,
                    root_hash: candidate.root_hash,
                    source_cursor: candidate.source_cursor,
                    outgoing_edges: candidate.outgoing_edges,
                    resolution_roots: candidate.resolution_roots,
                }
            })
            .collect();
        self.cache
            .index()
            .replace_committed_repo_publications(replacement, |_| {});
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

    fn complete_legacy_migration(
        &self,
        writer_drain: LegacySpineWriterDrainAttestation,
    ) -> Result<(), SpineError> {
        FirestoreSpineBackend::complete_legacy_migration(self, writer_drain)
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

    fn prepare_repo_publication_bound(
        &self,
        publication: RepoSpinePublication,
        expected_rollout_fence: &SpineRolloutFenceEvidence,
    ) -> Result<PreparedRepoSpinePublication, SpineError> {
        let prepared = self
            .store
            .prepare_repo_publication_bound(publication, expected_rollout_fence)?;
        Ok(PreparedRepoSpinePublication::bind(
            self.publication_backend_id,
            prepared,
        ))
    }

    fn commit_repo_publication(
        &self,
        prepared: PreparedRepoSpinePublication,
    ) -> Result<RepoPublicationCommit, SpineError> {
        let prepared = prepared.into_store_preparation(self.publication_backend_id)?;

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
        // Reconcile in BOTH directions against the stable durable winner.
        //
        // The winner was just loaded under the head/rows/head fence, so its
        // identity is the authority on what happened, not the CAS response. A
        // winner that is not the candidate turns a reported success into a
        // conflict. A winner that IS the candidate turns a reported conflict
        // into an idempotent already-committed: the durable head holds exactly
        // this publication, which is what already-committed means, and a
        // publication id is a digest over the canonicalized publication alone,
        // so equality here is content equality and nothing weaker.
        //
        // Only the first direction existed, so two writers racing identical
        // content both did the right thing durably and the loser was told it
        // had lost. The caller's contract is that a conflict names a different
        // winner it must reconcile to; reporting one whose winner is the
        // caller's own publication asks it to reconcile to itself.
        if winner.head.publication_id == prepared.candidate_head().publication_id {
            if let RepoPublicationCommit::Conflict(conflict) = &outcome {
                // Content equality has two producers and only one of them is
                // idempotency. A writer refused for a stale rollout fence or a
                // moved dependency head can carry byte-identical content and
                // must still lose, because its conflict is about authority and
                // not about what it wrote: admitting it would let a paused
                // writer bypass a fence that advanced under it. Those two
                // constructors are the only ones that populate the fence and
                // dependency fields, and a plain head CAS leaves every one of
                // them None, so this separates the cases exactly.
                let authority_conflict = conflict.attempted_rollout_fence.is_some()
                    || conflict.observed_rollout_fence.is_some()
                    || conflict.observed_dependency_repo.is_some();
                if !authority_conflict {
                    outcome = RepoPublicationCommit::AlreadyCommitted {
                        source_cursor: winner.head.source_cursor,
                    };
                }
            }
        } else if !matches!(&outcome, RepoPublicationCommit::Conflict(_)) {
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
            match self
                .store
                .cleanup_repo_publications(&winner_head, CLEANUP_DOCUMENTS_PER_COMMIT)
            {
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
        // Every durable edge head is bound to the exact root map it resolved
        // against, and its head commit CAS-guards each sibling head plus the
        // rollout fence. Hydration installs the full stable head set as one
        // cache generation, so the index's dirty/closed check is now the exact
        // committed-head completeness predicate rather than a pod-local guess.
        self.cache.authority_complete()
    }

    fn cross_repo_edges_snapshot(&self) -> CrossRepoEdgesSnapshot {
        self.cache.cross_repo_edges_snapshot()
    }

    fn cross_repo_xref_response(
        &self,
        repo_id: &str,
        entity_id: &EntityId,
    ) -> crate::SpineXrefResponse {
        self.cache.cross_repo_xref_response(repo_id, entity_id)
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
        success: bool,
    ) -> bool {
        self.cache
            .finish_cross_repo_refresh_pass(token, authority_roots, success)
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
                .map_err(|error| SpineError::Http(format!("query {collection} failed: {error}")))?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "query {collection} failed ({status}): {body}"
                )));
            }
            let results: Vec<serde_json::Value> = response.json().await.map_err(|error| {
                SpineError::Serialization(format!("failed to parse {collection} query: {error}"))
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
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        let mut batch = Vec::new();
        let mut estimated_bytes = 0usize;
        for write in writes {
            let write_bytes = serde_json::to_vec(&write)
                .map_err(|error| {
                    SpineError::Serialization(format!("failed to size {operation} write: {error}"))
                })?
                .len();
            if write_bytes > FIRESTORE_MAX_COMMIT_JSON_BYTES {
                return Err(SpineError::Serialization(format!(
                    "one {operation} document exceeds the bounded Firestore request envelope"
                )));
            }
            if !batch.is_empty()
                && (batch.len() >= FIRESTORE_MAX_WRITES_PER_COMMIT
                    || estimated_bytes.saturating_add(write_bytes)
                        > FIRESTORE_MAX_COMMIT_JSON_BYTES)
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

    /// Commit an authority transition that is correct only when every guard
    /// and winner write shares one Firestore Commit. Unlike bulk staging and
    /// cleanup, this helper refuses rather than chunking.
    fn commit_atomic_write_set(
        &self,
        writes: Vec<serde_json::Value>,
        operation: &str,
    ) -> Result<(), SpineError> {
        validate_single_commit_envelope(&writes, operation)?;
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        self.commit_write_batch(&token, &url, &writes, operation)
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
                .map_err(|error| SpineError::Http(format!("{operation} commit failed: {error}")))?;
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
                Ok((Some(head), StoreHeadPrecondition::Revision(update_time)))
            }
            None => Ok((None, StoreHeadPrecondition::Missing)),
        }
    }

    fn read_publication_dependency_heads(
        &self,
        publication: &RepoSpinePublication,
    ) -> Result<BTreeMap<String, StoreRepoHeadGuard>, SpineError> {
        let mut guards = BTreeMap::new();
        let Some(resolution_roots) = publication.resolution_roots.as_ref() else {
            return Ok(guards);
        };
        for (repo_id, expected_root) in resolution_roots {
            if repo_id == &publication.repo_id {
                continue;
            }
            let (head, precondition) = self.read_repo_head(repo_id)?;
            let head = head.ok_or_else(|| {
                SpineError::Backend(format!(
                    "repo {} edge publication cannot resolve against missing committed head {repo_id}",
                    publication.repo_id
                ))
            })?;
            if head.root_hash != *expected_root {
                return Err(SpineError::Backend(format!(
                    "repo {} edge publication resolved {repo_id} at root {expected_root}, but durable head is at {}",
                    publication.repo_id, head.root_hash
                )));
            }
            guards.insert(repo_id.clone(), StoreRepoHeadGuard { head, precondition });
        }
        Ok(guards)
    }

    fn read_rollout_fence(&self) -> Result<Option<LoadedSpineRolloutFence>, SpineError> {
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
        if document.get("name").and_then(serde_json::Value::as_str) != Some(expected_name.as_str())
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
            let expected_name =
                self.document_name("spine_repo_heads_v2", &sha256_hex(head.repo_id.as_bytes()));
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

    fn stage_marker_revision_sha256(
        head: &RepoPublicationHead,
        revision_kind: &str,
        stage_sequence: u64,
        revision_payload: &[u8],
    ) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(STAGE_MARKER_REVISION_HASH_DOMAIN);
        hasher.update(head.publication_id.as_bytes());
        hasher.update([0]);
        hasher.update(revision_kind.as_bytes());
        hasher.update([0]);
        hasher.update(stage_sequence.to_be_bytes());
        hasher.update(revision_payload);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn initial_stage_marker_progress(
        head: &RepoPublicationHead,
    ) -> Result<StageMarkerProgress, SpineError> {
        let payload = serde_json::to_vec(head).map_err(|error| {
            SpineError::Serialization(format!(
                "failed to serialize initial stage marker revision: {error}"
            ))
        })?;
        Ok(StageMarkerProgress {
            stage_sequence: 0,
            revision_kind: "stage".to_string(),
            revision_sha256: Self::stage_marker_revision_sha256(head, "stage", 0, &payload),
        })
    }

    fn stage_batch_progress(
        head: &RepoPublicationHead,
        stage_sequence: u64,
        writes: &[serde_json::Value],
    ) -> Result<StageMarkerProgress, SpineError> {
        let payload = serde_json::to_vec(writes).map_err(|error| {
            SpineError::Serialization(format!(
                "failed to serialize immutable stage batch revision: {error}"
            ))
        })?;
        Ok(StageMarkerProgress {
            stage_sequence,
            revision_kind: "stage".to_string(),
            revision_sha256: Self::stage_marker_revision_sha256(
                head,
                "stage",
                stage_sequence,
                &payload,
            ),
        })
    }

    fn cleanup_stage_progress(
        head: &RepoPublicationHead,
        current: &StageMarkerProgress,
        stage_revision: &str,
        delete_names: &[String],
    ) -> Result<StageMarkerProgress, SpineError> {
        let payload = serde_json::to_vec(&(
            stage_revision,
            current.stage_sequence,
            &current.revision_sha256,
            delete_names,
        ))
        .map_err(|error| {
            SpineError::Serialization(format!(
                "failed to serialize cleanup stage marker revision: {error}"
            ))
        })?;
        Ok(StageMarkerProgress {
            stage_sequence: current.stage_sequence,
            revision_kind: "cleanup".to_string(),
            revision_sha256: Self::stage_marker_revision_sha256(
                head,
                "cleanup",
                current.stage_sequence,
                &payload,
            ),
        })
    }

    fn committed_stage_progress(
        head: &RepoPublicationHead,
        current: &StorePublicationStageGuard,
    ) -> Result<StageMarkerProgress, SpineError> {
        let payload = serde_json::to_vec(&(
            current.stage_sequence,
            &current.revision_sha256,
            &current.update_time,
            &head.publication_id,
        ))
        .map_err(|error| {
            SpineError::Serialization(format!(
                "failed to serialize committed stage marker revision: {error}"
            ))
        })?;
        Ok(StageMarkerProgress {
            stage_sequence: current.stage_sequence,
            revision_kind: "committed".to_string(),
            revision_sha256: Self::stage_marker_revision_sha256(
                head,
                "committed",
                current.stage_sequence,
                &payload,
            ),
        })
    }

    fn committed_stage_marker_write(
        &self,
        head: &RepoPublicationHead,
        current: &StorePublicationStageGuard,
    ) -> Result<serde_json::Value, SpineError> {
        let progress = Self::committed_stage_progress(head, current)?;
        self.stage_marker_write(
            head,
            &progress,
            serde_json::json!({ "updateTime": current.update_time }),
        )
    }

    fn stage_marker_fields(
        &self,
        head: &RepoPublicationHead,
        progress: &StageMarkerProgress,
    ) -> Result<serde_json::Value, SpineError> {
        if !matches!(
            progress.revision_kind.as_str(),
            "stage" | "committed" | "cleanup"
        ) || !progress
            .revision_sha256
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(SpineError::Serialization(
                "stage marker revision is not canonical".to_string(),
            ));
        }
        let payload = serde_json::to_string(head).map_err(|error| {
            SpineError::Serialization(format!("failed to serialize stage marker: {error}"))
        })?;
        Ok(serde_json::json!({
            "repo_id": { "stringValue": head.repo_id },
            "source_cursor": { "stringValue": head.source_cursor.to_string() },
            "publication_id": { "stringValue": head.publication_id },
            "phase": { "stringValue": phase_name(head.phase) },
            "stage_sequence": { "integerValue": progress.stage_sequence.to_string() },
            "revision_kind": { "stringValue": progress.revision_kind },
            "revision_sha256": { "stringValue": progress.revision_sha256 },
            "payload": { "stringValue": payload }
        }))
    }

    fn parse_stage_marker_progress(
        &self,
        document: &serde_json::Value,
        head: &RepoPublicationHead,
    ) -> Result<StageMarkerProgress, SpineError> {
        let fields = document.get("fields").ok_or_else(|| {
            SpineError::Serialization(format!(
                "publication {} stage marker has no fields",
                head.publication_id
            ))
        })?;
        let stage_sequence = fields
            .get("stage_sequence")
            .and_then(|value| value.get("integerValue"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                SpineError::Serialization(format!(
                    "publication {} stage marker has no valid stage sequence",
                    head.publication_id
                ))
            })?;
        let revision_kind = fields
            .get("revision_kind")
            .and_then(|value| value.get("stringValue"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SpineError::Serialization(format!(
                    "publication {} stage marker has no revision kind",
                    head.publication_id
                ))
            })?
            .to_string();
        let revision_sha256 = fields
            .get("revision_sha256")
            .and_then(|value| value.get("stringValue"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                SpineError::Serialization(format!(
                    "publication {} stage marker has no revision digest",
                    head.publication_id
                ))
            })?
            .to_string();
        let progress = StageMarkerProgress {
            stage_sequence,
            revision_kind,
            revision_sha256,
        };
        if document.get("fields") != Some(&self.stage_marker_fields(head, &progress)?) {
            return Err(SpineError::Serialization(format!(
                "publication {} stage marker fields do not exactly match its immutable head",
                head.publication_id
            )));
        }
        Ok(progress)
    }

    fn stage_marker_write(
        &self,
        head: &RepoPublicationHead,
        progress: &StageMarkerProgress,
        current_document: serde_json::Value,
    ) -> Result<serde_json::Value, SpineError> {
        Ok(serde_json::json!({
            "update": {
                "name": self.document_name("spine_stages_v2", &head.publication_id),
                "fields": self.stage_marker_fields(head, progress)?
            },
            "currentDocument": current_document
        }))
    }

    /// Build the exact Firestore writes for one immutable row batch and its
    /// marker heartbeat. The marker digest is bound to `certified_writes`, not
    /// merely the outstanding retry subset, so a partial-response retry emits
    /// the same marker bytes while every distinct original batch must emit a
    /// distinct value. Keeping this construction in one helper also gives the
    /// regression tests the production write shape instead of a parallel fake.
    fn immutable_stage_batch_writes(
        &self,
        head: &RepoPublicationHead,
        stage_sequence: u64,
        certified_writes: &[serde_json::Value],
        pending_writes: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Value>, SpineError> {
        let progress = Self::stage_batch_progress(head, stage_sequence, certified_writes)?;
        let marker_write =
            self.stage_marker_write(head, &progress, serde_json::json!({ "exists": true }))?;
        let mut atomic_writes = pending_writes.to_vec();
        atomic_writes.push(marker_write);
        Ok(atomic_writes)
    }

    fn ensure_stage_marker(&self, head: &RepoPublicationHead) -> Result<(), SpineError> {
        let initial = Self::initial_stage_marker_progress(head)?;
        let write =
            self.stage_marker_write(head, &initial, serde_json::json!({ "exists": false }))?;
        match self.commit_write_batches(vec![write], "stage immutable spine publication marker") {
            Ok(()) => Ok(()),
            Err(commit_error) => {
                let existing = self
                    .get_document("spine_stages_v2", &head.publication_id)?
                    .ok_or_else(|| {
                        SpineError::Backend(format!(
                            "{commit_error}; publication {} stage marker was not durably created",
                            head.publication_id
                        ))
                    })?;
                let existing_head: RepoPublicationHead =
                    doc_payload(&existing, "spine stage marker")?;
                if existing_head != *head {
                    return Err(SpineError::Serialization(format!(
                        "publication {} stage marker already exists with another immutable head",
                        head.publication_id
                    )));
                }
                let progress = self.parse_stage_marker_progress(&existing, head)?;
                if progress.revision_kind == "cleanup" {
                    return Err(SpineError::Backend(format!(
                        "publication {} is already under marker-fenced cleanup",
                        head.publication_id
                    )));
                }
                Ok(())
            }
        }
    }

    fn observe_stage_guard(
        &self,
        head: &RepoPublicationHead,
    ) -> Result<Option<StorePublicationStageGuard>, SpineError> {
        let Some(document) = self.get_document("spine_stages_v2", &head.publication_id)? else {
            return Ok(None);
        };
        let marker_head: RepoPublicationHead = doc_payload(&document, "spine stage marker")?;
        if marker_head != *head {
            return Ok(None);
        }
        let progress = self.parse_stage_marker_progress(&document, head)?;
        if progress.revision_kind != "stage" {
            return Ok(None);
        }
        let update_time = document
            .get("updateTime")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                SpineError::Serialization(format!(
                    "publication {} final stage marker has no Firestore updateTime",
                    head.publication_id
                ))
            })?
            .to_string();
        Ok(Some(StorePublicationStageGuard {
            stage_sequence: progress.stage_sequence,
            revision_sha256: progress.revision_sha256,
            update_time,
        }))
    }

    fn read_stage_guard(
        &self,
        head: &RepoPublicationHead,
    ) -> Result<StorePublicationStageGuard, SpineError> {
        self.observe_stage_guard(head)?.ok_or_else(|| {
            SpineError::Backend(format!(
                "publication {} final stage marker is missing or no longer prepared",
                head.publication_id
            ))
        })
    }

    fn immutable_update_write(&self, name: String, fields: serde_json::Value) -> serde_json::Value {
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

        let initial_progress = Self::initial_stage_marker_progress(head)?;
        let marker_write = self.stage_marker_write(
            head,
            &initial_progress,
            serde_json::json!({ "exists": true }),
        )?;
        let marker_bytes = serde_json::to_vec(&marker_write)
            .map_err(|error| {
                SpineError::Serialization(format!("failed to size stage marker heartbeat: {error}"))
            })?
            .len()
            .saturating_add(32);
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        let mut batch = Vec::new();
        let mut estimated_bytes = marker_bytes;
        let mut stage_sequence = 1_u64;
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
                self.commit_immutable_stage_batch(&token, &url, head, stage_sequence, batch)?;
                stage_sequence = stage_sequence.checked_add(1).ok_or_else(|| {
                    SpineError::Backend(format!(
                        "publication {} exhausted its stage batch sequence",
                        head.publication_id
                    ))
                })?;
                batch = Vec::new();
                estimated_bytes = marker_bytes;
            }
            estimated_bytes = estimated_bytes.saturating_add(write_bytes);
            batch.push(write);
        }
        if !batch.is_empty() {
            self.commit_immutable_stage_batch(&token, &url, head, stage_sequence, batch)?;
        }
        Ok(())
    }

    fn commit_immutable_stage_batch(
        &self,
        token: &str,
        url: &str,
        head: &RepoPublicationHead,
        stage_sequence: u64,
        mut pending: Vec<serde_json::Value>,
    ) -> Result<(), SpineError> {
        let certified_writes = pending.clone();
        let progress = Self::stage_batch_progress(head, stage_sequence, &certified_writes)?;
        let mut last_error = None;
        for _ in 0..3 {
            let atomic_writes = self.immutable_stage_batch_writes(
                head,
                stage_sequence,
                &certified_writes,
                &pending,
            )?;
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
            let marker_head: RepoPublicationHead = doc_payload(&marker, "spine stage marker")?;
            if marker_head != *head {
                return Err(SpineError::Serialization(format!(
                    "publication {} stage marker changed identity while rows were being written",
                    head.publication_id
                )));
            }
            let observed_progress = self.parse_stage_marker_progress(&marker, head)?;

            let mut missing = Vec::new();
            for write in &pending {
                if !self
                    .validate_existing_immutable_write(write, "immutable spine publication row")?
                {
                    missing.push(write.clone());
                }
            }
            if missing.is_empty() {
                return Ok(());
            }
            if observed_progress.revision_kind == "cleanup" {
                return Err(SpineError::Backend(format!(
                    "publication {} began marker-fenced cleanup while stage batch {} was in flight",
                    head.publication_id, stage_sequence
                )));
            }
            if observed_progress.stage_sequence > stage_sequence {
                return Err(SpineError::Serialization(format!(
                    "publication {} stage marker advanced past batch {} while that batch still has missing rows",
                    head.publication_id, stage_sequence
                )));
            }
            if observed_progress.stage_sequence == stage_sequence {
                if observed_progress.revision_sha256 != progress.revision_sha256 {
                    return Err(SpineError::Serialization(format!(
                        "publication {} stage batch {} has conflicting immutable bytes",
                        head.publication_id, stage_sequence
                    )));
                }
                return Err(SpineError::Serialization(format!(
                    "publication {} stage marker certifies batch {} but that batch has missing rows",
                    head.publication_id, stage_sequence
                )));
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
        self.ensure_stage_marker(head)?;

        let mut writes = Vec::with_capacity(
            publication.entries.len() + publication.outgoing_edges.as_ref().map_or(0, Vec::len) + 1,
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
                let document_id =
                    format!("{}_{}", head.publication_id, sha256_hex(payload.as_bytes()));
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

    fn prepare_repo_publication_with_expected_fence(
        &self,
        publication: RepoSpinePublication,
        expected_rollout_fence: Option<&SpineRolloutFenceEvidence>,
    ) -> Result<PreparedStorePublication, SpineError> {
        let rollout_fence = self.read_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend(
                "cannot prepare a hosted spine publication without an active durable rollout fence"
                    .to_string(),
            )
        })?;
        if expected_rollout_fence.is_some_and(|expected| rollout_fence.evidence() != *expected) {
            return Err(SpineError::Backend(format!(
                "repo {} publication refused before staging because Firestore rollout evidence differs from the admitted GCS authority",
                publication.repo_id
            )));
        }
        let (observed_head, precondition) = self.read_repo_head(&publication.repo_id)?;
        let dependency_heads = self.read_publication_dependency_heads(&publication)?;
        let mut prepared = PreparedStorePublication::new_fenced(
            publication,
            observed_head,
            precondition,
            dependency_heads,
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
            let stage_guard = self.read_stage_guard(prepared.candidate_head())?;
            prepared = prepared.bind_stage_guard(stage_guard)?;
        }
        Ok(prepared)
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
        let mut writes = vec![head_write, fence_write];
        for (repo_id, guard) in prepared.dependency_heads() {
            writes.push(firestore_head_write(
                self.document_name("spine_repo_heads_v2", &sha256_hex(repo_id.as_bytes())),
                &guard.head,
                &guard.precondition,
            )?);
        }
        if prepared.requires_staging() {
            let stage_guard = prepared.stage_guard().ok_or_else(|| {
                SpineError::Backend(format!(
                    "repo {} publication has no final stage-marker CAS guard",
                    head.repo_id
                ))
            })?;
            writes.push(self.committed_stage_marker_write(head, stage_guard)?);
        }
        let body = serde_json::json!({ "writes": writes });
        let token = self.get_access_token()?;
        let url = format!("{}:commit", self.base_url());
        let response = self.run_async(async {
            let response = self
                .client
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
        let (observed_fence, observed, observed_precondition, observed_dependencies) = {
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
                let observed_dependencies = prepared
                    .dependency_heads()
                    .keys()
                    .map(|repo_id| {
                        self.read_repo_head(repo_id)
                            .map(|observed| (repo_id.clone(), observed))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()
                    .map_err(|reconcile_error| {
                        SpineError::Backend(format!(
                            "{cause}; dependency-head outcome is indeterminate because reconciliation failed: {reconcile_error}"
                        ))
                    })?;
                let fence_after = self.read_rollout_fence().map_err(|reconcile_error| {
                    SpineError::Backend(format!(
                        "{cause}; rollout fence outcome is indeterminate because reconciliation failed: {reconcile_error}"
                    ))
                })?;
                if fence_before == fence_after {
                    stable = Some((
                        fence_after,
                        observed,
                        observed_precondition,
                        observed_dependencies,
                    ));
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
        if let Some(expected_stage) = prepared.stage_guard() {
            let observed_stage = self.observe_stage_guard(candidate).map_err(|error| {
                SpineError::Backend(format!(
                    "{cause}; repo {} stage-marker outcome is indeterminate, attempted cursor {}, observed head cursor {:?}: {error}",
                    candidate.repo_id,
                    candidate.source_cursor,
                    observed.as_ref().map(|head| head.source_cursor)
                ))
            })?;
            if observed_stage.as_ref() != Some(expected_stage) {
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against(
                        candidate.source_cursor,
                        observed.as_ref(),
                    ),
                ));
            }
        }
        for (repo_id, guard) in prepared.dependency_heads() {
            let (observed_dependency, observed_dependency_precondition) =
                observed_dependencies.get(repo_id).ok_or_else(|| {
                    SpineError::Backend(format!(
                        "{cause}; dependency-head reconciliation omitted {repo_id}"
                    ))
                })?;
            if observed_dependency_precondition != &guard.precondition
                || observed_dependency.as_ref() != Some(&guard.head)
            {
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against_dependency(
                        candidate.source_cursor,
                        repo_id,
                        observed_dependency.as_ref(),
                    ),
                ));
            }
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
fn firestore_legacy_migration_marker_guard_write(
    document_name: String,
    marker: &LegacyMigrationMarker,
    seal: &LegacyMigrationSeal,
) -> Result<serde_json::Value, SpineError> {
    match marker {
        LegacyMigrationMarker::Absent => Ok(serde_json::json!({
            "update": {
                "name": document_name,
                "fields": firestore_legacy_migration_seal_fields(seal)?
            },
            "currentDocument": { "exists": false }
        })),
        LegacyMigrationMarker::Predecessor {
            fields,
            update_time,
        } => Ok(serde_json::json!({
            "update": {
                "name": document_name,
                "fields": fields
            },
            "currentDocument": { "updateTime": update_time }
        })),
        LegacyMigrationMarker::CanonicalSeal { .. } => Err(SpineError::Backend(
            "a canonical legacy migration seal must be reconciled before finalizing an upgrade"
                .to_string(),
        )),
    }
}

#[cfg(feature = "firestore")]
fn firestore_legacy_migration_finalize_writes(
    marker_document_name: String,
    marker: &LegacyMigrationMarker,
    seal_document_name: String,
    seal: &LegacyMigrationSeal,
) -> Result<[serde_json::Value; 2], SpineError> {
    Ok([
        firestore_legacy_migration_marker_guard_write(marker_document_name, marker, seal)?,
        serde_json::json!({
            "update": {
                "name": seal_document_name,
                "fields": firestore_legacy_migration_seal_fields(seal)?
            },
            "currentDocument": { "exists": false }
        }),
    ])
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

/// Assemble every write the one-way legacy migration seal commits together.
///
/// The seal is correct only if the fleet fence, each exact repository head, the
/// historical marker guard and the new canonical seal all land in a single
/// Firestore Commit: any split leaves a durable head naming content another
/// writer may still reclaim. Assembly is separated from the reads that produce
/// the preconditions so the operation set itself can be asserted without a
/// network, which is the only way a test can prove the count rather than
/// rebuild it. For the hosted five-repository contract this is eight writes:
/// one fence, five heads, the marker guard and the seal.
#[cfg(feature = "firestore")]
fn legacy_migration_seal_write_set(
    rollout_fence_document_name: String,
    rollout_fence: &LoadedSpineRolloutFence,
    guarded_heads: &[(String, RepoPublicationHead, StoreHeadPrecondition)],
    marker_document_name: String,
    marker: &LegacyMigrationMarker,
    seal_document_name: String,
    seal: &LegacyMigrationSeal,
) -> Result<Vec<serde_json::Value>, SpineError> {
    let mut writes = Vec::with_capacity(guarded_heads.len() + 3);
    writes.push(firestore_rollout_fence_write(
        rollout_fence_document_name,
        &rollout_fence.fence,
        &StoreHeadPrecondition::Revision(rollout_fence.update_time.clone()),
    )?);
    for (document_name, head, precondition) in guarded_heads {
        writes.push(firestore_head_write(
            document_name.clone(),
            head,
            precondition,
        )?);
    }
    writes.extend(firestore_legacy_migration_finalize_writes(
        marker_document_name,
        marker,
        seal_document_name,
        seal,
    )?);
    Ok(writes)
}

#[cfg(feature = "firestore")]
fn validate_single_commit_envelope(
    writes: &[serde_json::Value],
    operation: &str,
) -> Result<(), SpineError> {
    if writes.is_empty() {
        return Err(SpineError::Serialization(format!(
            "{operation} requires at least one Firestore write"
        )));
    }
    if writes.len() > FIRESTORE_MAX_WRITES_PER_COMMIT {
        return Err(SpineError::Serialization(format!(
            "{operation} requires {} Firestore writes, above the one-Commit limit {}",
            writes.len(),
            FIRESTORE_MAX_WRITES_PER_COMMIT
        )));
    }
    let mut encoded_bytes = 0usize;
    for write in writes {
        let write_bytes = serde_json::to_vec(write)
            .map_err(|error| {
                SpineError::Serialization(format!("failed to size {operation} write: {error}"))
            })?
            .len();
        encoded_bytes = encoded_bytes.checked_add(write_bytes).ok_or_else(|| {
            SpineError::Serialization(format!("{operation} Firestore request size overflowed"))
        })?;
    }
    if encoded_bytes > FIRESTORE_MAX_COMMIT_JSON_BYTES {
        return Err(SpineError::Serialization(format!(
            "{operation} requires {encoded_bytes} encoded bytes, above the one-Commit limit {FIRESTORE_MAX_COMMIT_JSON_BYTES}"
        )));
    }
    Ok(())
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
fn document_string_field<'a>(document: &'a serde_json::Value, field: &str) -> Option<&'a str> {
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
    let repo_id = document_string_field(document, "repo_id")
        .ok_or_else(|| SpineError::Serialization(format!("{kind} row missing repo_id")))?;
    let source_cursor = document_string_field(document, "source_cursor")
        .ok_or_else(|| SpineError::Serialization(format!("{kind} row missing source_cursor")))?;
    let publication_id = document_string_field(document, "publication_id")
        .ok_or_else(|| SpineError::Serialization(format!("{kind} row missing publication_id")))?;
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
            let precondition = observed
                .as_ref()
                .map_or(StoreHeadPrecondition::Missing, |current| {
                    StoreHeadPrecondition::Revision(current.update_time.clone())
                });
            let write = firestore_rollout_fence_write(
                self.document_name("spine_control_v2", "rollout_fence"),
                &candidate,
                &precondition,
            )?;
            if let Err(error) =
                self.commit_write_batches(vec![write], "advance durable spine rollout fence")
            {
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
        let active = self.read_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend(
                "legacy migration state cannot be validated without an active rollout fence"
                    .to_string(),
            )
        })?;
        if let Some(document) =
            self.get_document("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID)?
        {
            let expected_name =
                self.document_name("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID);
            let (seal, _) = parse_legacy_migration_seal_document(&document, &expected_name)?;
            seal.validate_against_active(&active)?;
            return Ok(true);
        }

        let document =
            self.get_document("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID)?;
        let expected_name =
            self.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        match parse_legacy_migration_marker_document(document.as_ref(), &expected_name)? {
            LegacyMigrationMarker::Absent | LegacyMigrationMarker::Predecessor { .. } => Ok(false),
            LegacyMigrationMarker::CanonicalSeal { seal, .. } => {
                seal.validate_against_active(&active)?;
                Ok(true)
            }
        }
    }

    fn complete_legacy_migration(
        &self,
        rollout_fence: &LoadedSpineRolloutFence,
        writer_drain: &LegacySpineWriterDrainAttestation,
    ) -> Result<(), SpineError> {
        writer_drain.validate()?;
        if writer_drain.rollout_fence_evidence != rollout_fence.evidence() {
            return Err(SpineError::Backend(
                "legacy migration completion received writer-drain evidence for another rollout fence"
                    .to_string(),
            ));
        }
        let loaded = self.load_repo_publications()?;
        let mut heads = Vec::with_capacity(loaded.len());
        for publication in loaded {
            let head = publication.head.clone();
            CanonicalRepoPublication::validate_loaded(
                publication.head,
                publication.entries,
                publication.outgoing_edges,
            )?;
            heads.push(head);
        }
        let seal = LegacyMigrationSeal::build(rollout_fence, writer_drain.clone(), heads.clone())?;

        let seal_document_name =
            self.document_name("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID);
        if let Some(document) =
            self.get_document("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID)?
        {
            let (observed, _) =
                parse_legacy_migration_seal_document(&document, &seal_document_name)?;
            observed.validate_against_active(rollout_fence)?;
            return require_exact_legacy_migration_seal(&seal, &observed);
        }

        let marker_document =
            self.get_document("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID)?;
        let marker_document_name =
            self.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        let marker = parse_legacy_migration_marker_document(
            marker_document.as_ref(),
            &marker_document_name,
        )?;
        if let LegacyMigrationMarker::CanonicalSeal { seal: observed, .. } = &marker {
            observed.validate_against_active(rollout_fence)?;
            return require_exact_legacy_migration_seal(&seal, observed);
        }

        let mut guarded_heads = Vec::with_capacity(heads.len());
        for head in &heads {
            let (observed, precondition) = self.read_repo_head(&head.repo_id)?;
            if observed.as_ref() != Some(head) {
                return Err(SpineError::Backend(format!(
                    "repo {} head moved while the legacy migration seal was prepared",
                    head.repo_id
                )));
            }
            guarded_heads.push((
                self.document_name("spine_repo_heads_v2", &sha256_hex(head.repo_id.as_bytes())),
                head.clone(),
                precondition,
            ));
        }
        let writes = legacy_migration_seal_write_set(
            self.document_name("spine_control_v2", "rollout_fence"),
            rollout_fence,
            &guarded_heads,
            marker_document_name,
            &marker,
            seal_document_name.clone(),
            &seal,
        )?;
        match self.commit_atomic_write_set(writes, "complete legacy spine migration") {
            Ok(()) => Ok(()),
            Err(commit_error) => {
                let Some(document) =
                    self.get_document("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID)?
                else {
                    return Err(SpineError::Backend(format!(
                        "{commit_error}; legacy migration seal was not durably created"
                    )));
                };
                let (observed, _) =
                    parse_legacy_migration_seal_document(&document, &seal_document_name)?;
                require_exact_legacy_migration_seal(&seal, &observed).map_err(|_| {
                    SpineError::Backend(format!(
                        "{commit_error}; a different legacy migration seal won"
                    ))
                })
            }
        }
    }

    fn prepare_repo_publication(
        &self,
        publication: RepoSpinePublication,
    ) -> Result<PreparedStorePublication, SpineError> {
        self.prepare_repo_publication_with_expected_fence(publication, None)
    }

    fn prepare_repo_publication_bound(
        &self,
        publication: RepoSpinePublication,
        expected_rollout_fence: &SpineRolloutFenceEvidence,
    ) -> Result<PreparedStorePublication, SpineError> {
        self.prepare_repo_publication_with_expected_fence(publication, Some(expected_rollout_fence))
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
            last_movement =
                format!("committed spine heads moved during hydration attempt {attempt}");
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
        let stage_documents =
            self.query_documents("spine_stages_v2", "repo_id", &active_head.repo_id, None)?;
        let mut stale = Vec::new();
        for document in stage_documents {
            let head: RepoPublicationHead = doc_payload(&document, "publication stage marker")?;
            head.validate()?;
            validate_publication_row(&document, &head, "publication stage marker")?;
            let progress = self.parse_stage_marker_progress(&document, &head)?;
            let expected_stage_name = self.document_name("spine_stages_v2", &head.publication_id);
            if document.get("name").and_then(serde_json::Value::as_str)
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
            let safe = publication_stage_is_cleanup_safe(
                &head,
                active_head,
                firestore_document_age(&document),
            );
            if safe {
                stale.push((head, document, progress));
            }
        }
        stale.sort_by(|(left, _, _), (right, _, _)| {
            left.source_cursor
                .cmp(&right.source_cursor)
                .then_with(|| left.phase.cmp(&right.phase))
                .then_with(|| left.publication_id.cmp(&right.publication_id))
        });
        let more_candidates = stale.len() > 1;
        let Some((stale_head, stage_document, stage_progress)) = stale.into_iter().next() else {
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
            if let Some(manifest_document) =
                self.get_document("spine_publications_v2", &stale_head.publication_id)?
            {
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
                let expected_manifest_name =
                    self.document_name("spine_publications_v2", &stale_head.publication_id);
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
            let cleanup_progress = Self::cleanup_stage_progress(
                &stale_head,
                &stage_progress,
                stage_revision,
                &delete_names,
            )?;
            writes.push(self.stage_marker_write(
                &stale_head,
                &cleanup_progress,
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
    use crate::publication::RepoPublicationConflict;
    use crate::test_support::*;
    use kin_model::{
        EntityKind, EntityRole, FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId,
        RelationEvidence, RelationId, RelationKind, RelationOrigin, SemanticFingerprint,
        Visibility,
    };

    /// In-memory [`SpineStore`] fake. Mirrors staged rows and a revision-checked
    /// repository head without any network.
    /// Two-party rendezvous with a deadline, used by the race fixtures below.
    ///
    /// `std::sync::Barrier` has no timed wait, and the fake reaches its
    /// rendezvous only on the paths that actually select a stage or a head:
    /// every other path returns earlier. So a change in what production selects
    /// turns a race test from a failure into a permanent hang. Measured, not
    /// hypothesised: two of these ran 13305 seconds before a signal stopped
    /// them, and 112 of the suite's 145 tests never ran as a result, which is
    /// strictly worse than a red test because it reports nothing at all. A
    /// bounded wait turns the same mismatch into a named failure in seconds and
    /// says which side never arrived.
    fn test_writer_drain(store: &FakeSpineStore) -> LegacySpineWriterDrainAttestation {
        LegacySpineWriterDrainAttestation {
            schema: crate::publication::LEGACY_SPINE_WRITER_DRAIN_SCHEMA.to_string(),
            rollout_fence_evidence: store
                .load_rollout_fence()
                .unwrap()
                .expect("test rollout fence")
                .evidence(),
            daemon_image_sha256: format!("sha256:{}", "a".repeat(64)),
            drain_proof_sha256: format!("sha256:{}", "b".repeat(64)),
        }
    }

    #[cfg(feature = "firestore")]
    fn legacy_migration_fixture() -> (LoadedSpineRolloutFence, LegacyMigrationSeal) {
        let loaded = LoadedSpineRolloutFence {
            fence: test_rollout_fence(7, "legacy-fixture-rollout", &["repo"]),
            update_time: "2026-08-27T12:00:00.000000Z".to_string(),
        };
        let writer_drain = LegacySpineWriterDrainAttestation {
            schema: crate::publication::LEGACY_SPINE_WRITER_DRAIN_SCHEMA.to_string(),
            rollout_fence_evidence: loaded.evidence(),
            daemon_image_sha256: format!("sha256:{}", "a".repeat(64)),
            drain_proof_sha256: format!("sha256:{}", "b".repeat(64)),
        };
        let head = metadata_publication("repo", 41, "fixture-root", Vec::new())
            .into_canonical()
            .unwrap()
            .head;
        let seal = LegacyMigrationSeal::build(&loaded, writer_drain, vec![head]).unwrap();
        (loaded, seal)
    }

    fn seal_fake_for_current_heads(store: &FakeSpineStore) {
        let mut repo_ids = store
            .publication_state
            .lock()
            .unwrap()
            .heads
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        repo_ids.sort();
        assert!(
            !repo_ids.is_empty(),
            "a migration seal requires at least one committed head"
        );
        let repo_id_refs = repo_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let mut rollout = store.rollout_fence_state.lock().unwrap();
        let active_ids = rollout
            .as_ref()
            .map(|(_, fence)| {
                fence
                    .repositories
                    .iter()
                    .map(|row| row.repo_id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if active_ids != repo_ids {
            let next_revision = rollout
                .as_ref()
                .map_or(1, |(revision, _)| revision.saturating_add(1));
            let next_fence = rollout
                .as_ref()
                .map_or(1, |(_, fence)| fence.rollout_fence.saturating_add(1));
            *rollout = Some((
                next_revision,
                test_rollout_fence(next_fence, "test-migration-seal", &repo_id_refs),
            ));
        }
        drop(rollout);
        let active = store
            .load_rollout_fence()
            .unwrap()
            .expect("migration-seal rollout fence");
        store
            .complete_legacy_migration(&active, &test_writer_drain(store))
            .expect("seal current fake head set");
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

    /// Publish and require a success outcome, naming what came back instead.
    ///
    /// This helper is called from most tests in this module, so a bare
    /// `assert!(matches!(..))` here reports only "assertion failed" at one
    /// shared line: it names neither the outcome nor which caller produced it.
    /// The repo and cursor identify the call site and the Debug outcome says
    /// whether a conflict, and which one, is what actually happened.
    fn publish_success(backend: &FirestoreSpineBackend, publication: RepoSpinePublication) {
        let repo_id = publication.repo_id.clone();
        let source_cursor = publication.source_cursor;
        let outcome = publish(backend, publication);
        assert!(
            matches!(
                outcome,
                RepoPublicationCommit::Committed { .. }
                    | RepoPublicationCommit::AlreadyCommitted { .. }
            ),
            "publishing repo {repo_id} at cursor {source_cursor} must commit or read as \
             already committed, got {outcome:?}"
        );
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

    fn commit_store_success(store: &FakeSpineStore, prepared: &PreparedStorePublication) {
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
                    [("consumer", "consumer-root"), ("provider", "provider-root"),],
                )
            ),
            RepoPublicationCommit::Committed { .. }
        ));

        seal_fake_for_current_heads(&store);
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
        let roots = [("consumer", "consumer-root"), ("provider", "provider-root")];
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

        seal_fake_for_current_heads(&store);
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
                [("consumer", "consumer-root"), ("provider", "provider-root")],
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
        seal_fake_for_current_heads(&store);
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
        let metadata = metadata_publication("consumer", 9, "consumer-root", vec![consumer.clone()]);
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
                [("consumer", "consumer-root"), ("provider", "provider-root")],
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
        let first_prepared = first.prepare_repo_publication(publication.clone()).unwrap();
        let second_prepared = second.prepare_repo_publication(publication).unwrap();
        // Confirm the premise before grading the outcome. Convergence here rests
        // entirely on the publication id being a function of content alone, so
        // if two backends given identical input disagree on it, the conflict
        // below is the symptom and this is the defect. Asserting it separately
        // is what tells those two apart; the conflict payload carries only the
        // observed id, so it cannot.
        let first_id = first_prepared.candidate_head().publication_id.clone();
        let second_id = second_prepared.candidate_head().publication_id.clone();
        assert_eq!(
            first_id, second_id,
            "two backends preparing identical content must derive the same \
             content-addressed publication id"
        );
        assert!(matches!(
            first.commit_repo_publication(first_prepared).unwrap(),
            RepoPublicationCommit::Committed { .. }
        ));
        // Named rather than matched bare: a conflict here is the interesting
        // outcome and `assert!(matches!(..))` would hide which one it was.
        let converged = second.commit_repo_publication(second_prepared).unwrap();
        assert!(
            matches!(
                converged,
                RepoPublicationCommit::AlreadyCommitted { source_cursor }
                    if source_cursor == cursor(41)
            ),
            "a second writer committing the identical publication must converge as \
             already committed at cursor 41; candidate id {first_id}, got {converged:?}"
        );
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
        seal_fake_for_current_heads(&store);
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
                [("consumer", "consumer-root"), ("provider", "provider-root")],
            ))
            .expect_err("edge staging fault must fail prepare");
        assert!(error.to_string().contains("edge stage failure"));
        assert_eq!(
            committed_head(&store, "consumer").phase,
            RepoPublicationPhase::Metadata
        );
        seal_fake_for_current_heads(&store);
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
        seal_fake_for_current_heads(&store);
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
        seal_fake_for_current_heads(&store);
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened
            .hydrate()
            .expect("head still references old publication");
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
        seal_fake_for_current_heads(&store);

        let barrier = Arc::new(BoundedRendezvous::new());
        *store.load_snapshot_barrier.lock().unwrap() = Some(barrier.clone());
        let reopened = Arc::new(FirestoreSpineBackend::with_store(store.clone()));
        let hydrating = reopened.clone();
        let load = std::thread::spawn(move || hydrating.hydrate());

        barrier.wait("hydration snapshot race, test main");
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
        barrier.wait("hydration snapshot race, test main");

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
        seal_fake_for_current_heads(&store);
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
        seal_fake_for_current_heads(&store);
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
        disable_distinct_stage_heartbeat: bool,
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
        store
            .disable_distinct_stage_heartbeat
            .store(disable_distinct_stage_heartbeat, Ordering::SeqCst);
        let barrier = Arc::new(BoundedRendezvous::new());
        *store.cleanup_snapshot_barrier.lock().unwrap() = Some(barrier.clone());
        let cleanup_store = store.clone();
        let winner_head = winner.candidate_head().clone();
        let cleanup = std::thread::spawn(move || {
            cleanup_store
                .cleanup_repo_publications(&winner_head, 10)
                .unwrap()
                .deleted
        });

        barrier.wait("late-row cleanup race, test main");
        {
            let mut state = store.publication_state.lock().unwrap();
            state
                .entity_rows
                .get_mut(&stale_id)
                .expect("stale stage rows")
                .push(test_entry("repo", "late", EntityKind::Function));
            let current_marker = state
                .stage_marker_values
                .get(&stale_id)
                .cloned()
                .expect("stale stage marker value");
            let late_marker = if store
                .disable_distinct_stage_heartbeat
                .load(Ordering::SeqCst)
            {
                current_marker
            } else {
                FakeStageMarkerValue {
                    stage_sequence: current_marker.stage_sequence + 1,
                    revision_kind: "stage",
                    revision_nonce: "late-distinct-row-batch".to_string(),
                }
            };
            apply_fake_stage_marker(&mut state, &stale_id, late_marker);
        }
        barrier.wait("late-row cleanup race, test main");
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
        let (deleted, stage_exists, row_count) = run_cleanup_stage_fence_race(false, false);
        assert_eq!(deleted, 0, "the stale cleanup snapshot must lose its CAS");
        assert!(
            stage_exists,
            "late rows must remain discoverable by their marker"
        );
        assert_eq!(row_count, 2);
    }

    #[test]
    fn cleanup_fence_falsification_strands_the_late_row_without_marker_cas() {
        let (_deleted, stage_exists, row_count) = run_cleanup_stage_fence_race(true, false);
        assert!(
            !stage_exists,
            "the mutant recreates the missing marker race"
        );
        assert_eq!(row_count, 1, "the late row is orphaned by the mutant");
    }

    #[test]
    fn byte_identical_stage_heartbeat_falsification_strands_the_late_row() {
        let (_deleted, stage_exists, row_count) = run_cleanup_stage_fence_race(false, true);
        assert!(
            !stage_exists,
            "a byte-identical marker write retains its Firestore updateTime and lets stale cleanup win"
        );
        assert_eq!(row_count, 1, "the mutant strands the distinct late row");
    }

    fn run_equal_cursor_edge_stage_cleanup_race(
        disable_stage_head_precondition: bool,
    ) -> (bool, bool, bool) {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("provider", 1, "provider-r1", Vec::new()),
        );
        publish_success(
            &backend,
            metadata_publication("source", 7, "source-r7", Vec::new()),
        );
        publish_success(
            &backend,
            edge_publication(
                "source",
                7,
                "source-r7",
                Vec::new(),
                Vec::new(),
                [("provider", "provider-r1"), ("source", "source-r7")],
            ),
        );
        let old_source_head = committed_head(&store, "source");
        publish_success(
            &backend,
            metadata_publication("provider", 2, "provider-r2", Vec::new()),
        );
        let prepared = backend
            .prepare_repo_publication(edge_publication(
                "source",
                7,
                "source-r7",
                Vec::new(),
                Vec::new(),
                [("provider", "provider-r2"), ("source", "source-r7")],
            ))
            .expect("same-cursor edge replacement stages against the new dependency root");
        let candidate_id = prepared.candidate_head().publication_id.clone();
        store
            .disable_stage_head_precondition
            .store(disable_stage_head_precondition, Ordering::SeqCst);
        let cleanup = store
            .cleanup_repo_publications(&old_source_head, 100)
            .expect("bounded cleanup result");
        assert!(
            cleanup.deleted > 0,
            "cleanup must win before the paused writer"
        );
        let commit = backend.commit_repo_publication(prepared);
        let commit_conflicted = matches!(commit, Ok(RepoPublicationCommit::Conflict(_)));
        let candidate_became_head = committed_head(&store, "source").publication_id == candidate_id;
        seal_fake_for_current_heads(&store);
        let reopened = FirestoreSpineBackend::with_store(store);
        let reopen_succeeded = reopened.hydrate().is_ok();
        (commit_conflicted, candidate_became_head, reopen_succeeded)
    }

    #[test]
    fn stage_marker_cas_makes_a_paused_same_cursor_edge_writer_lose_cleanup() {
        let (commit_conflicted, candidate_became_head, reopen_succeeded) =
            run_equal_cursor_edge_stage_cleanup_race(false);
        assert!(commit_conflicted);
        assert!(!candidate_became_head);
        assert!(
            reopen_succeeded,
            "the prior durable winner must still reopen"
        );
    }

    #[test]
    fn missing_stage_head_guard_falsification_commits_a_head_to_deleted_rows() {
        let (commit_conflicted, candidate_became_head, reopen_succeeded) =
            run_equal_cursor_edge_stage_cleanup_race(true);
        assert!(!commit_conflicted);
        assert!(candidate_became_head);
        assert!(
            !reopen_succeeded,
            "dropping the marker precondition lets the durable head point at deleted rows"
        );
    }

    /// What the cleanup-snapshot race leaves behind, at both surfaces.
    ///
    /// Completeness is reported for the writer's live cache and for a reopened
    /// backend separately, with the dirty set beside each, because the boolean
    /// alone cannot say whether a repository is dirty for having a pending edge
    /// publication or for never publishing edges at all.
    struct CleanupSnapshotRace {
        deleted: usize,
        reopen_succeeded: bool,
        writer_complete: bool,
        writer_dirty: std::collections::BTreeSet<String>,
        reopened_complete: bool,
        reopened_dirty: std::collections::BTreeSet<String>,
    }

    fn run_cleanup_snapshot_before_head_commit_race(
        disable_stage_head_precondition: bool,
    ) -> CleanupSnapshotRace {
        run_cleanup_snapshot_race(disable_stage_head_precondition, false)
    }

    fn run_cleanup_snapshot_race(
        disable_stage_head_precondition: bool,
        provider_publishes_edges: bool,
    ) -> CleanupSnapshotRace {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("provider", 1, "provider-r1", Vec::new()),
        );
        publish_success(
            &backend,
            metadata_publication("source", 7, "source-r7", Vec::new()),
        );
        publish_success(
            &backend,
            edge_publication(
                "source",
                7,
                "source-r7",
                Vec::new(),
                Vec::new(),
                [("provider", "provider-r1"), ("source", "source-r7")],
            ),
        );
        let old_head = committed_head(&store, "source");
        publish_success(
            &backend,
            metadata_publication("provider", 2, "provider-r2", Vec::new()),
        );
        if provider_publishes_edges {
            // AFTER provider@2, not before it. Giving the provider edges at
            // cursor 1 and then letting the fixture publish provider@2 metadata
            // leaves it dirty again, so that arm controls for nothing: it varies
            // the provider's history without changing the state under test. A
            // control has to give the provider a CURRENT edge publication,
            // resolved against the roots that hold at the end. The first
            // attempt got this wrong and the printout caught it.
            publish_success(
                &backend,
                edge_publication(
                    "provider",
                    2,
                    "provider-r2",
                    Vec::new(),
                    Vec::new(),
                    [("provider", "provider-r2"), ("source", "source-r7")],
                ),
            );
        }
        let prepared = backend
            .prepare_repo_publication(edge_publication(
                "source",
                7,
                "source-r7",
                Vec::new(),
                Vec::new(),
                [("provider", "provider-r2"), ("source", "source-r7")],
            ))
            .unwrap();
        let candidate_id = prepared.candidate_head().publication_id.clone();
        store
            .disable_stage_head_precondition
            .store(disable_stage_head_precondition, Ordering::SeqCst);
        let barrier = Arc::new(BoundedRendezvous::new());
        *store.cleanup_snapshot_barrier.lock().unwrap() = Some(barrier.clone());
        let cleanup_store = store.clone();
        let cleanup = std::thread::spawn(move || {
            cleanup_store
                .cleanup_repo_publications(&old_head, 100)
                .unwrap()
                .deleted
        });

        barrier.wait("cleanup-snapshot-before-head-commit race, test main");
        let outcome = backend.commit_repo_publication(prepared).unwrap();
        assert!(matches!(outcome, RepoPublicationCommit::Committed { .. }));
        assert_eq!(
            committed_head(&store, "source").publication_id,
            candidate_id
        );
        barrier.wait("cleanup-snapshot-before-head-commit race, test main");
        let deleted = cleanup.join().unwrap();
        seal_fake_for_current_heads(&store);
        let reopened = FirestoreSpineBackend::with_store(store);
        let reopen_succeeded = reopened.hydrate().is_ok();
        CleanupSnapshotRace {
            deleted,
            reopen_succeeded,
            writer_complete: backend.authority_complete(),
            writer_dirty: backend.cache.index().dirty_edge_repos(),
            reopened_complete: reopened.authority_complete(),
            reopened_dirty: reopened.cache.index().dirty_edge_repos(),
        }
    }

    #[test]
    fn committed_marker_revision_defeats_a_cleanup_snapshot_from_the_old_head() {
        let race = run_cleanup_snapshot_before_head_commit_race(false);
        assert_eq!(race.deleted, 0, "cleanup's old marker revision must lose");
        assert!(
            race.reopen_succeeded,
            "the committed winner must reopen cold"
        );
        // The provider in this fixture publishes metadata only, and a metadata
        // publication keeps that repository's outgoing topology unresolved, so
        // the fleet is not edge-complete at either surface. Certifying it would
        // answer "what does provider reference" with an empty set AND call that
        // set authoritative. See `SpineIndex::authority_is_complete`.
        assert!(
            !race.writer_complete && !race.reopened_complete,
            "a fleet with a metadata-only repository must not certify completeness: \
             writer_dirty {:?}, reopened_dirty {:?}",
            race.writer_dirty,
            race.reopened_dirty
        );
    }

    #[test]
    fn committed_marker_mutant_lets_old_cleanup_delete_the_new_winner() {
        let race = run_cleanup_snapshot_before_head_commit_race(true);
        assert!(
            race.deleted > 0,
            "the mutant cleanup must delete winner rows"
        );
        assert!(
            !race.reopen_succeeded,
            "the mutant durable head must fail cold reopen"
        );
    }

    /// A metadata-only repository blocks fleet edge completeness, at both
    /// surfaces, and a current edge publication unblocks it.
    ///
    /// Both arms, because neither alone pins the rule: the refusal would pass
    /// on an index that never certified anything, and the acceptance would pass
    /// on one that certified everything. Both surfaces, because the writer's
    /// live cache and a reopened backend reach completeness by different paths
    /// and the property has to hold on the one a caller actually reads.
    ///
    /// The dirty set is asserted beside the boolean because the boolean alone
    /// cannot say WHY: a repository with a pending edge publication and one
    /// that never publishes edges both read false, and only the first is a
    /// transient.
    #[test]
    fn a_metadata_only_repository_blocks_completeness_at_both_surfaces() {
        let main = run_cleanup_snapshot_race(false, false);
        assert!(
            !main.writer_complete && !main.reopened_complete,
            "a metadata-only provider leaves its outgoing topology unresolved, so neither \
             surface may certify completeness: writer_dirty {:?}, reopened_dirty {:?}",
            main.writer_dirty,
            main.reopened_dirty
        );
        let provider_only: std::collections::BTreeSet<String> =
            ["provider".to_string()].into_iter().collect();
        assert_eq!(
            main.writer_dirty, provider_only,
            "the provider must be the reason, not something else"
        );
        assert_eq!(
            main.reopened_dirty, provider_only,
            "hydration does not clear a metadata-only repository either"
        );

        let control = run_cleanup_snapshot_race(false, true);
        assert!(
            control.writer_complete && control.reopened_complete,
            "a provider with a current edge publication must let both surfaces certify: \
             writer_dirty {:?}, reopened_dirty {:?}",
            control.writer_dirty,
            control.reopened_dirty
        );
        assert!(
            control.writer_dirty.is_empty() && control.reopened_dirty.is_empty(),
            "the control must converge at both surfaces, or it cannot isolate the \
             metadata-only case: writer {:?}, reopened {:?}",
            control.writer_dirty,
            control.reopened_dirty
        );
    }

    #[test]
    fn static_source_edge_generations_are_drained_after_sibling_advances() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("provider", 1, "provider-r1", Vec::new()),
        );
        publish_success(
            &backend,
            metadata_publication("source", 7, "source-r7", Vec::new()),
        );
        publish_success(
            &backend,
            edge_publication(
                "source",
                7,
                "source-r7",
                Vec::new(),
                Vec::new(),
                [("provider", "provider-r1"), ("source", "source-r7")],
            ),
        );

        for generation in 2..=12 {
            let provider_root = format!("provider-r{generation}");
            publish_success(
                &backend,
                metadata_publication("provider", generation, &provider_root, Vec::new()),
            );
            publish_success(
                &backend,
                edge_publication(
                    "source",
                    7,
                    "source-r7",
                    Vec::new(),
                    Vec::new(),
                    [
                        ("provider", provider_root.as_str()),
                        ("source", "source-r7"),
                    ],
                ),
            );
            let state = store.publication_state.lock().unwrap();
            let source_stages = state
                .stages
                .values()
                .filter(|head| head.repo_id == "source")
                .count();
            assert_eq!(
                source_stages, 1,
                "only the active static-source edge generation may remain after bounded cleanup"
            );
        }
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
            .into_canonical()
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
            .map(|index| test_entry("repo", &format!("entity_{index:03}"), EntityKind::Function))
            .collect();
        let large = metadata_publication("repo", 1, "large", entries);
        let large_id = large.clone().into_canonical().unwrap().head.publication_id;
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
        *store.rollout_fence_state.lock().unwrap() =
            Some((1, test_rollout_fence(1, "legacy-cutover", &["repo"])));
        let legacy = test_entry("repo", "legacy", EntityKind::Function);
        store.write_entity(&legacy, "legacy-root").unwrap();
        let blocked = FirestoreSpineBackend::with_store(store.clone());
        let error = blocked
            .hydrate()
            .expect_err("an unsealed legacy boundary must block every read");
        assert!(error
            .to_string()
            .contains("legacy writer-drain migration marker"));
        let error = blocked
            .complete_legacy_migration(test_writer_drain(&store))
            .expect_err("missing exact-fleet heads must prevent the one-way marker");
        assert!(error.to_string().contains("exact active-fleet v2 heads"));

        let publisher = FirestoreSpineBackend::with_store(store.clone());
        // One entry value, built once and reused. `test_entry` mints a fresh
        // `EntityId` on every call, so building it twice changes the entity set
        // under one cursor, and a metadata change at a fixed cursor is refused:
        // this test would then never reach the metadata-to-edges upgrade it
        // exists to exercise. The refusal itself is the subject of
        // `a_same_cursor_metadata_change_is_refused_and_the_next_cursor_takes_it`.
        let current = test_entry("repo", "current", EntityKind::Function);
        publish_success(
            &publisher,
            metadata_publication("repo", 100, "current-root", vec![current.clone()]),
        );
        publish_success(
            &publisher,
            edge_publication(
                "repo",
                100,
                "current-root",
                vec![current],
                Vec::new(),
                [("repo", "current-root")],
            ),
        );
        publisher
            .complete_legacy_migration(test_writer_drain(&store))
            .expect("exact edge-complete fleet plus drain proof can receive the durable marker");
        store.fail_next_load_edges.store(true, Ordering::SeqCst);
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened
            .hydrate()
            .expect("durable completion marker removes legacy collections from cold reopen");
        assert!(reopened.resolve("legacy", None, None).is_empty());
        assert_eq!(reopened.resolve("current", None, None).len(), 1);
    }

    /// Metadata moves with the cursor or not at all.
    ///
    /// A source cursor names one frame of the repository. Two different entity
    /// sets published under the same cursor are two frames wearing one
    /// identity, which is exactly the ambiguity an exact compare-and-swap
    /// exists to prevent: a reader that has resolved against one of them has no
    /// way to tell it is now holding the other. So the same-cursor change is
    /// refused, and the way to publish it is to advance the cursor, where the
    /// receipt names the frame the caller is now on.
    ///
    /// Both arms are here on purpose. The refusal alone would pass on a store
    /// that refused every publication, and the acceptance alone would pass on
    /// one that accepted every publication; only the pair pins the rule.
    #[test]
    fn a_same_cursor_metadata_change_is_refused_and_the_next_cursor_takes_it() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store);
        publish_success(
            &backend,
            metadata_publication(
                "repo",
                7,
                "root-at-7",
                vec![test_entry("repo", "first", EntityKind::Function)],
            ),
        );

        let changed = publish(
            &backend,
            metadata_publication(
                "repo",
                7,
                "root-at-7",
                vec![test_entry("repo", "second", EntityKind::Function)],
            ),
        );
        assert!(
            matches!(changed, RepoPublicationCommit::Conflict(_)),
            "a metadata change under an unchanged cursor must be refused, got {changed:?}"
        );

        let advanced = publish(
            &backend,
            metadata_publication(
                "repo",
                8,
                "root-at-8",
                vec![test_entry("repo", "second", EntityKind::Function)],
            ),
        );
        assert!(
            matches!(
                advanced,
                RepoPublicationCommit::Committed { source_cursor } if source_cursor == cursor(8)
            ),
            "the same change at the next cursor must commit with a receipt naming that \
             cursor, got {advanced:?}"
        );
        assert_eq!(backend.source_cursor("repo"), Some(cursor(8)));
        assert_eq!(backend.root_hash("repo").as_deref(), Some("root-at-8"));
    }

    /// Stage a newer cursor, never commit it, and watch the TTL decide.
    ///
    /// Both arms are one fixture differing only in the marker's age, which is
    /// the only input the rule reads. Without the young arm the aged arm would
    /// pass on a cleanup that reclaimed everything above the cursor, which is
    /// exactly the behaviour that races a live writer.
    #[test]
    fn a_stage_above_the_cursor_survives_until_stage_ttl_then_drains() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("repo", 5, "root-5", Vec::new()),
        );
        let active = committed_head(&store, "repo");

        // A writer stages a NEWER cursor and never commits.
        let paused = backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                6,
                "root-6",
                vec![test_entry("repo", "later", EntityKind::Function)],
            ))
            .expect("a newer stage prepares");
        let staged_id = paused.candidate_head().publication_id.clone();
        assert!(
            store
                .publication_state
                .lock()
                .unwrap()
                .stages
                .contains_key(&staged_id),
            "the fixture must actually leave a stage above the cursor"
        );

        let young = store
            .cleanup_repo_publications(&active, 100)
            .expect("cleanup runs against the committed head");
        assert_eq!(
            young.deleted, 0,
            "a stage above the cursor younger than STAGE_TTL belongs to a writer that may be \
             paused, and reclaiming it races a live writer"
        );
        assert!(
            store
                .publication_state
                .lock()
                .unwrap()
                .stages
                .contains_key(&staged_id),
            "the young stage must still be there"
        );

        store.age_stage(&staged_id, STAGE_TTL);
        let mut drained = 0usize;
        for _ in 0..8 {
            let progress = store
                .cleanup_repo_publications(&active, 100)
                .expect("cleanup runs against the committed head");
            drained += progress.deleted;
            if !progress.more {
                break;
            }
        }
        assert!(
            drained > 0,
            "a stage older than STAGE_TTL is a dead writer's and must drain"
        );
        assert!(
            !store
                .publication_state
                .lock()
                .unwrap()
                .stages
                .contains_key(&staged_id),
            "the aged stage's marker must be gone once it has drained"
        );
    }

    /// A writer that comes back after its stage was reclaimed must lose.
    ///
    /// Two refusals, because they are different guards and either alone would
    /// let the other regress: the stage precondition refuses a writer whose
    /// marker no longer exists, and the rollout fence refuses one whose fence
    /// moved under it. The TTL is only safe because both hold.
    #[test]
    fn a_writer_returning_after_its_stage_drained_is_refused() {
        let fleet = ["repo"];
        let store = Arc::new(FakeSpineStore::default());
        *store.rollout_fence_state.lock().unwrap() =
            Some((1, test_rollout_fence(1, "ttl-rollout-1", &fleet)));
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("repo", 5, "root-5", Vec::new()),
        );
        let active = committed_head(&store, "repo");

        let paused = backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                6,
                "root-6",
                vec![test_entry("repo", "later", EntityKind::Function)],
            ))
            .expect("a newer stage prepares");
        let staged_id = paused.candidate_head().publication_id.clone();
        store.age_stage(&staged_id, STAGE_TTL);
        for _ in 0..8 {
            let progress = store
                .cleanup_repo_publications(&active, 100)
                .expect("cleanup runs against the committed head");
            if !progress.more {
                break;
            }
        }
        assert!(
            !store
                .publication_state
                .lock()
                .unwrap()
                .stages
                .contains_key(&staged_id),
            "the fixture must reclaim the stage before the writer returns"
        );

        let refused = backend
            .commit_repo_publication(paused)
            .expect("a returning writer is classified, not an error");
        assert!(
            matches!(refused, RepoPublicationCommit::Conflict(_)),
            "a writer whose stage marker was reclaimed must lose its precondition, got \
             {refused:?}"
        );

        // The precondition on its own, isolated. Reclamation removes the
        // marker AND the manifest, so the arm above cannot show WHICH guard
        // refused: both halves of the stage precondition read absent and the
        // commit would fail on the missing manifest regardless. Moving only the
        // marker's revision leaves every other row in place, so a refusal here
        // can only have come from the revision comparison.
        let intact_store = Arc::new(FakeSpineStore::default());
        let intact_backend = FirestoreSpineBackend::with_store(intact_store.clone());
        publish_success(
            &intact_backend,
            metadata_publication("repo", 5, "root-5", Vec::new()),
        );
        let intact_paused = intact_backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                6,
                "root-6",
                vec![test_entry("repo", "later", EntityKind::Function)],
            ))
            .expect("a newer stage prepares");
        let intact_id = intact_paused.candidate_head().publication_id.clone();
        intact_store.bump_stage_revision(&intact_id);
        {
            let state = intact_store.publication_state.lock().unwrap();
            assert!(
                state.stages.contains_key(&intact_id) && state.manifests.contains_key(&intact_id),
                "the stage and its manifest must survive, or this arm proves nothing about \
                 the precondition"
            );
        }
        let moved = intact_backend
            .commit_repo_publication(intact_paused)
            .expect("a writer whose marker moved is classified, not an error");
        assert!(
            matches!(moved, RepoPublicationCommit::Conflict(_)),
            "a writer whose stage marker revision moved under it must lose its \
             precondition, got {moved:?}"
        );

        // The fence half, on the same shape: a returning writer whose rollout
        // fence advanced under it loses on the fence, and says so.
        let fenced_store = Arc::new(FakeSpineStore::default());
        *fenced_store.rollout_fence_state.lock().unwrap() =
            Some((1, test_rollout_fence(1, "ttl-rollout-1", &fleet)));
        let fenced_backend = FirestoreSpineBackend::with_store(fenced_store.clone());
        publish_success(
            &fenced_backend,
            metadata_publication("repo", 5, "root-5", Vec::new()),
        );
        let fenced_paused = fenced_backend
            .prepare_repo_publication(metadata_publication(
                "repo",
                6,
                "root-6",
                vec![test_entry("repo", "later", EntityKind::Function)],
            ))
            .expect("a newer stage prepares");
        assert!(
            matches!(
                fenced_backend
                    .advance_rollout_fence(test_rollout_fence(2, "ttl-rollout-2", &fleet))
                    .unwrap(),
                SpineRolloutFenceCommit::Advanced(_)
            ),
            "the fence this writer is paused behind must actually advance"
        );
        let fence_refused = fenced_backend
            .commit_repo_publication(fenced_paused)
            .expect("a fence-losing writer is classified, not an error");
        assert!(
            matches!(
                fence_refused,
                RepoPublicationCommit::Conflict(RepoPublicationConflict {
                    attempted_rollout_fence: Some(1),
                    ..
                })
            ),
            "the fence refusal must name the fence the writer attempted, got {fence_refused:?}"
        );
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
    fn gcs_evidence_mismatch_refuses_before_any_stage_write() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        let mut wrong = store
            .load_rollout_fence()
            .unwrap()
            .expect("active fake rollout fence")
            .evidence();
        wrong.update_time = "different-firestore-revision".to_string();
        let publication = metadata_publication(
            "repo",
            1,
            "root",
            vec![test_entry("repo", "never-staged", EntityKind::Function)],
        );
        let publication_id = publication
            .clone()
            .into_canonical()
            .unwrap()
            .head
            .publication_id;

        let error = backend
            .prepare_repo_publication_bound(publication, &wrong)
            .expect_err("cross-backend evidence mismatch must fail before staging");
        assert!(error.to_string().contains("refused before staging"));
        let state = store.publication_state.lock().unwrap();
        assert!(!state.stages.contains_key(&publication_id));
        assert!(!state.manifests.contains_key(&publication_id));
        assert!(!state.entity_rows.contains_key(&publication_id));
        assert!(!state.edge_rows.contains_key(&publication_id));
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
        *store.rollout_fence_state.lock().unwrap() =
            Some((1, test_rollout_fence(1, "idle-reader", &["repo-a"])));
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
        seal_fake_for_current_heads(&store);
        let reader = FirestoreSpineBackend::with_store(store.clone());
        reader.hydrate().unwrap();
        publish_success(
            &writer,
            metadata_publication(
                "repo-a",
                2,
                "a2",
                vec![test_entry("repo-a", "a2", EntityKind::Function)],
            ),
        );
        reader.refresh_committed_publications().unwrap();
        assert_eq!(reader.repo_count(), 1);
        assert_eq!(reader.source_cursor("repo-a"), Some(cursor(2)));
        assert_eq!(
            reader.registered_repo_ids(),
            HashSet::from(["repo-a".to_string()])
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
        seal_fake_for_current_heads(&store);
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
            mutant.advance_rollout_fence(test_rollout_fence(2, "test-rollout-2", &fleet,)),
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
        assert!(
            matches!(
                backend
                    .advance_rollout_fence(test_rollout_fence(2, "test-rollout-2", &fleet))
                    .unwrap(),
                SpineRolloutFenceCommit::Advanced(_)
            ),
            "the fence this test pauses a writer behind must actually advance"
        );
        assert!(matches!(
            backend.commit_repo_publication(paused_identical).unwrap(),
            RepoPublicationCommit::Conflict(RepoPublicationConflict {
                attempted_rollout_fence: Some(1),
                observed_rollout_fence: Some(2),
                ..
            })
        ));
    }

    fn run_paused_edge_writer_against_dependency_head(
        disable_dependency_head_precondition: bool,
    ) -> (RepoPublicationCommit, bool) {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("provider", 1, "provider-r1", Vec::new()),
        );
        publish_success(
            &backend,
            metadata_publication("source", 5, "source-r5", Vec::new()),
        );
        let paused = backend
            .prepare_repo_publication(edge_publication(
                "source",
                5,
                "source-r5",
                Vec::new(),
                Vec::new(),
                [("provider", "provider-r1"), ("source", "source-r5")],
            ))
            .expect("edge writer captures the provider head");
        publish_success(
            &backend,
            metadata_publication("provider", 2, "provider-r2", Vec::new()),
        );
        store
            .disable_dependency_head_precondition
            .store(disable_dependency_head_precondition, Ordering::SeqCst);
        let outcome = backend
            .commit_repo_publication(paused)
            .expect("paused edge commit is classified");
        seal_fake_for_current_heads(&store);
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().expect("durable heads remain readable");
        (outcome, reopened.authority_complete())
    }

    #[test]
    fn paused_edge_writer_loses_when_a_dependency_head_advances() {
        let (outcome, complete) = run_paused_edge_writer_against_dependency_head(false);
        assert!(matches!(
            outcome,
            RepoPublicationCommit::Conflict(RepoPublicationConflict {
                observed_dependency_repo: Some(ref repo_id),
                observed_dependency_cursor: Some(observed),
                ..
            }) if repo_id == "provider" && observed == cursor(2)
        ));
        assert!(
            !complete,
            "source metadata still needs a current edge publication"
        );
    }

    #[test]
    fn dependency_head_guard_falsification_commits_stale_resolution_roots() {
        let (outcome, complete) = run_paused_edge_writer_against_dependency_head(true);
        assert!(matches!(outcome, RepoPublicationCommit::Committed { .. }));
        assert!(
            !complete,
            "the mutant commits an edge head resolved against the replaced provider root"
        );
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
        let evidence = match backend.advance_rollout_fence(candidate.clone()).unwrap() {
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
            .advance_rollout_fence(test_rollout_fence(2, "test-rollout-2", &fleet,))
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
        let fleet = ["repo"];
        let store = Arc::new(FakeSpineStore::default());
        *store.rollout_fence_state.lock().unwrap() =
            Some((1, test_rollout_fence(1, "test-rollout-1", &fleet)));
        let writer = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &writer,
            metadata_publication("repo", 41, "same-bytes-root", Vec::new()),
        );
        assert!(
            matches!(
                writer
                    .advance_rollout_fence(test_rollout_fence(2, "test-rollout-2", &fleet))
                    .unwrap(),
                SpineRolloutFenceCommit::Advanced(_)
            ),
            "the fence this writer publishes behind must actually advance"
        );

        seal_fake_for_current_heads(&store);
        let reopened = FirestoreSpineBackend::with_store(store);
        reopened.hydrate().unwrap();
        assert_eq!(reopened.source_cursor("repo"), Some(cursor(41)));
        assert_eq!(
            reopened.root_hash("repo").as_deref(),
            Some("same-bytes-root")
        );
        assert_eq!(
            reopened.active_rollout_fence().unwrap().fence.rollout_fence,
            2
        );
        // KinDB cursor 41 and the GCS object generations in the active fence are
        // intentionally not compared. The daemon must re-probe its post-fence
        // graph cursor and prove this content root before serving readiness.
    }

    #[test]
    fn sealed_refresh_ignores_late_legacy_rows_and_ttl_gates_cleanup_discovery() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());
        publish_success(
            &backend,
            metadata_publication("repo", 1, "root", Vec::new()),
        );
        seal_fake_for_current_heads(&store);
        backend.hydrate().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while backend.cleanup_sweep_gate.lock().running {
            assert!(
                Instant::now() < deadline,
                "initial cleanup sweep must finish"
            );
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
        store.fail_next_load_edges.store(true, Ordering::SeqCst);
        backend
            .hydrate()
            .expect("a sealed process must never consult late legacy rows");
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
        seal_fake_for_current_heads(&store);
        backend.hydrate().unwrap();
        store.publication_state.lock().unwrap().heads.remove("repo");
        let error = backend
            .hydrate()
            .expect_err("an append-only committed head must not disappear silently");
        assert!(error.to_string().contains("active exact fleet"));
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn firestore_head_write_always_carries_the_exact_precondition() {
        let head = metadata_publication("repo", 7, "root", Vec::new())
            .into_canonical()
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
        assert!(missing.pointer("/currentDocument/updateTime").is_none());

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

    /// Build a five-repository seal fixture matching the hosted fleet contract.
    #[cfg(feature = "firestore")]
    fn five_repository_seal_fixture() -> (
        [&'static str; 5],
        LoadedSpineRolloutFence,
        Vec<RepoPublicationHead>,
        LegacyMigrationSeal,
    ) {
        let fleet = ["kin", "kin-db", "kin-lsp", "kin-model", "kin-search"];
        let loaded = LoadedSpineRolloutFence {
            fence: test_rollout_fence(7, "five-repo-rollout", &fleet),
            update_time: "2026-08-27T12:00:00.000000Z".to_string(),
        };
        let writer_drain = LegacySpineWriterDrainAttestation {
            schema: crate::publication::LEGACY_SPINE_WRITER_DRAIN_SCHEMA.to_string(),
            rollout_fence_evidence: loaded.evidence(),
            daemon_image_sha256: format!("sha256:{}", "a".repeat(64)),
            drain_proof_sha256: format!("sha256:{}", "b".repeat(64)),
        };
        let heads = fleet
            .iter()
            .map(|repo_id| {
                metadata_publication(repo_id, 41, &format!("{repo_id}-root"), Vec::new())
                    .into_canonical()
                    .unwrap()
                    .head
            })
            .collect::<Vec<_>>();
        let seal = LegacyMigrationSeal::build(&loaded, writer_drain, heads.clone()).unwrap();
        (fleet, loaded, heads, seal)
    }

    /// The seal is a single-Commit authority transition, so the operation set it
    /// assembles is itself the contract: one fleet fence, one head per exact
    /// repository, the historical marker guard and the new canonical seal. The
    /// focused tests beside this one inspect the two migration-specific writes
    /// and cannot see a fence or head write going missing from the whole.
    #[cfg(feature = "firestore")]
    #[test]
    fn legacy_migration_seal_assembles_exactly_eight_unique_guarded_writes() {
        let store = FirestoreStore::new("project".to_string(), None);
        let (fleet, loaded, heads, seal) = five_repository_seal_fixture();
        assert_eq!(
            fleet.len(),
            5,
            "the hosted contract is a five-repository fleet"
        );

        let guarded_heads = heads
            .iter()
            .enumerate()
            .map(|(index, head)| {
                (
                    store
                        .document_name("spine_repo_heads_v2", &sha256_hex(head.repo_id.as_bytes())),
                    head.clone(),
                    StoreHeadPrecondition::Revision(format!("2026-08-27T12:00:0{index}.000000Z")),
                )
            })
            .collect::<Vec<_>>();
        let fence_document_name = store.document_name("spine_control_v2", "rollout_fence");
        let marker_document_name =
            store.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        let seal_document_name =
            store.document_name("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID);

        let writes = legacy_migration_seal_write_set(
            fence_document_name.clone(),
            &loaded,
            &guarded_heads,
            marker_document_name.clone(),
            &LegacyMigrationMarker::Absent,
            seal_document_name.clone(),
            &seal,
        )
        .unwrap();

        assert_eq!(
            writes.len(),
            3 + fleet.len(),
            "the seal commits one fence, one head per repository, the marker guard and the seal"
        );
        assert_eq!(
            writes.len(),
            8,
            "the five-repository contract is eight writes"
        );

        let mut expected = std::collections::BTreeSet::new();
        expected.insert(fence_document_name);
        expected.insert(marker_document_name);
        expected.insert(seal_document_name);
        for head in &heads {
            expected.insert(
                store.document_name("spine_repo_heads_v2", &sha256_hex(head.repo_id.as_bytes())),
            );
        }
        let observed = writes
            .iter()
            .map(|write| {
                write
                    .pointer("/update/name")
                    .and_then(serde_json::Value::as_str)
                    .expect("every seal write targets a named document")
                    .to_string()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            observed.len(),
            writes.len(),
            "two seal writes addressed the same document, so one operation was lost"
        );
        assert_eq!(
            observed, expected,
            "the assembled document set is not the exact fence, five heads, marker and seal"
        );

        for write in &writes {
            let name = write
                .pointer("/update/name")
                .and_then(serde_json::Value::as_str)
                .unwrap();
            assert!(
                write.get("currentDocument").is_some(),
                "seal write for {name} carries no precondition, so it would overwrite blind"
            );
        }

        validate_single_commit_envelope(&writes, "complete legacy spine migration")
            .expect("the exact five-repository seal must fit one Firestore Commit");
    }

    /// The atomic helper refuses rather than chunking, and it must refuse before
    /// it reaches the network. With no ambient credentials the very next step
    /// after validation is a metadata-server token fetch, so an `Auth` error
    /// here would prove validation ran too late.
    #[cfg(feature = "firestore")]
    #[test]
    fn atomic_write_set_refuses_an_over_count_write_set_before_any_request() {
        let store = FirestoreStore::new("project".to_string(), None);
        let write = serde_json::json!({
            "update": { "name": "projects/p/databases/d/documents/c/d", "fields": {} },
            "currentDocument": { "exists": false }
        });
        let writes = vec![write; FIRESTORE_MAX_WRITES_PER_COMMIT + 1];

        let error = store
            .commit_atomic_write_set(writes, "test atomic operation")
            .expect_err("a write set above the one-Commit count limit must be refused");
        assert!(
            matches!(error, SpineError::Serialization(_)),
            "the refusal must come from envelope validation, not from a network step: {error:?}"
        );
        assert!(
            error.to_string().contains("above the one-Commit limit"),
            "the refusal must name the count envelope: {error}"
        );
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn atomic_write_set_refuses_an_over_size_write_set_before_any_request() {
        let store = FirestoreStore::new("project".to_string(), None);
        // Four writes, each a quarter of the request envelope, so no single
        // document is oversized and only the sum can trip the limit.
        let payload = "x".repeat(FIRESTORE_MAX_COMMIT_JSON_BYTES / 4);
        let write = serde_json::json!({
            "update": {
                "name": "projects/p/databases/d/documents/c/d",
                "fields": { "payload": { "stringValue": payload } }
            },
            "currentDocument": { "exists": false }
        });
        let writes = vec![write; 5];

        let error = store
            .commit_atomic_write_set(writes, "test atomic operation")
            .expect_err("a write set above the one-Commit size limit must be refused");
        assert!(
            matches!(error, SpineError::Serialization(_)),
            "the refusal must come from envelope validation, not from a network step: {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("encoded bytes, above the one-Commit limit"),
            "the refusal must name the encoded-size envelope: {error}"
        );
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn released_legacy_marker_shapes_require_an_attested_upgrade() {
        let store = FirestoreStore::new("project".to_string(), None);
        let marker_name =
            store.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        let two_field = serde_json::json!({
            "name": marker_name,
            "updateTime": "2026-08-27T10:00:00Z",
            "fields": {
                "schema_version": { "integerValue": "2" },
                "state": { "stringValue": "complete" }
            }
        });
        assert!(matches!(
            parse_legacy_migration_marker_document(Some(&two_field), &marker_name).unwrap(),
            LegacyMigrationMarker::Predecessor { fields, update_time }
                if fields == two_field["fields"]
                    && update_time == "2026-08-27T10:00:00Z"
        ));

        let five_field = serde_json::json!({
            "name": marker_name,
            "updateTime": "2026-08-27T11:00:00Z",
            "fields": {
                "schema_version": { "integerValue": "2" },
                "state": { "stringValue": "complete" },
                "rollout_fence": { "integerValue": "6" },
                "rollout_payload_sha256": { "stringValue": format!("sha256:{}", "c".repeat(64)) },
                "rollout_update_time": { "stringValue": "2026-08-27T10:59:59Z" }
            }
        });
        assert!(matches!(
            parse_legacy_migration_marker_document(Some(&five_field), &marker_name).unwrap(),
            LegacyMigrationMarker::Predecessor { fields, update_time }
                if fields == five_field["fields"]
                    && update_time == "2026-08-27T11:00:00Z"
        ));
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn legacy_marker_parser_rejects_mixed_extra_or_malformed_fields() {
        let store = FirestoreStore::new("project".to_string(), None);
        let marker_name =
            store.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        let mut extra = serde_json::json!({
            "name": marker_name,
            "updateTime": "2026-08-27T10:00:00Z",
            "fields": {
                "schema_version": { "integerValue": "2" },
                "state": { "stringValue": "complete" },
                "unexpected": { "stringValue": "must-fail" }
            }
        });
        assert!(parse_legacy_migration_marker_document(Some(&extra), &marker_name).is_err());

        extra["fields"] = serde_json::json!({
            "schema_version": { "integerValue": "2" },
            "state": { "stringValue": "complete" },
            "rollout_fence": { "integerValue": "0" },
            "rollout_payload_sha256": { "stringValue": format!("sha256:{}", "c".repeat(64)) },
            "rollout_update_time": { "stringValue": "2026-08-27T10:00:00Z" }
        });
        assert!(parse_legacy_migration_marker_document(Some(&extra), &marker_name).is_err());

        extra["fields"]["rollout_fence"] = serde_json::json!({ "integerValue": "6" });
        extra["fields"]["rollout_payload_sha256"] =
            serde_json::json!({ "stringValue": format!("sha256:{}", "C".repeat(64)) });
        assert!(parse_legacy_migration_marker_document(Some(&extra), &marker_name).is_err());
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn canonical_legacy_seal_requires_exact_identity_and_sibling_fields() {
        let store = FirestoreStore::new("project".to_string(), None);
        let (_, seal) = legacy_migration_fixture();
        let seal_name = store.document_name("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID);
        let document = serde_json::json!({
            "name": seal_name,
            "updateTime": "2026-08-27T12:01:00Z",
            "fields": firestore_legacy_migration_seal_fields(&seal).unwrap()
        });
        let (parsed, update_time) =
            parse_legacy_migration_seal_document(&document, &seal_name).unwrap();
        assert_eq!(parsed, seal);
        assert_eq!(update_time, "2026-08-27T12:01:00Z");

        let mut wrong_sibling = document.clone();
        wrong_sibling["fields"]["state"] = serde_json::json!({ "stringValue": "incomplete" });
        assert!(parse_legacy_migration_seal_document(&wrong_sibling, &seal_name).is_err());

        let wrong_name = store.document_name("spine_metadata_v2", "sibling_only");
        assert!(parse_legacy_migration_seal_document(&document, &wrong_name).is_err());
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn canonical_seal_under_released_identity_remains_readable_but_immutable() {
        let store = FirestoreStore::new("project".to_string(), None);
        let (_, seal) = legacy_migration_fixture();
        let marker_name =
            store.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        let document = serde_json::json!({
            "name": marker_name,
            "updateTime": "2026-08-27T12:01:00Z",
            "fields": firestore_legacy_migration_seal_fields(&seal).unwrap()
        });
        assert!(matches!(
            parse_legacy_migration_marker_document(Some(&document), &marker_name).unwrap(),
            LegacyMigrationMarker::CanonicalSeal { seal: observed, .. } if observed == seal
        ));
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn legacy_upgrade_atomically_verifies_marker_and_creates_new_seal() {
        let store = FirestoreStore::new("project".to_string(), None);
        let (_, seal) = legacy_migration_fixture();
        let marker_name =
            store.document_name("spine_metadata_v2", LEGACY_MIGRATION_MARKER_DOCUMENT_ID);
        let seal_name = store.document_name("spine_metadata_v2", LEGACY_MIGRATION_SEAL_DOCUMENT_ID);
        let writes = firestore_legacy_migration_finalize_writes(
            marker_name.clone(),
            &LegacyMigrationMarker::Predecessor {
                fields: serde_json::json!({
                    "schema_version": { "integerValue": "2" },
                    "state": { "stringValue": "complete" }
                }),
                update_time: "marker-revision".to_string(),
            },
            seal_name.clone(),
            &seal,
        )
        .unwrap();
        assert_eq!(
            writes[0]
                .pointer("/update/name")
                .and_then(serde_json::Value::as_str),
            Some(marker_name.as_str())
        );
        assert_eq!(
            writes[0]
                .pointer("/currentDocument/updateTime")
                .and_then(serde_json::Value::as_str),
            Some("marker-revision")
        );
        assert!(writes[0].get("verify").is_none());
        assert!(writes[0].get("delete").is_none());
        assert_eq!(
            writes[1]
                .pointer("/update/name")
                .and_then(serde_json::Value::as_str),
            Some(seal_name.as_str())
        );
        assert_eq!(
            writes[1]
                .pointer("/currentDocument/exists")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            writes[1].pointer("/update/fields"),
            Some(&firestore_legacy_migration_seal_fields(&seal).unwrap())
        );

        let absent = firestore_legacy_migration_finalize_writes(
            marker_name,
            &LegacyMigrationMarker::Absent,
            seal_name,
            &seal,
        )
        .unwrap();
        assert!(absent[0].get("verify").is_none());
        assert!(absent[0].get("delete").is_none());
        assert_eq!(
            absent[0]
                .pointer("/currentDocument/exists")
                .and_then(serde_json::Value::as_bool),
            Some(false),
            "an old marker appearing after an absent read must fail the atomic create"
        );
        assert_eq!(
            absent[0].pointer("/update/fields"),
            Some(&firestore_legacy_migration_seal_fields(&seal).unwrap()),
            "an absent predecessor identity is sealed in the same commit as the new identity"
        );
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn legacy_seal_replay_requires_the_exact_attestation() {
        let (active, seal) = legacy_migration_fixture();
        require_exact_legacy_migration_seal(&seal, &seal).unwrap();

        let mut different_drain = seal.writer_drain.clone();
        different_drain.drain_proof_sha256 = format!("sha256:{}", "d".repeat(64));
        let different =
            LegacyMigrationSeal::build(&active, different_drain, seal.sealed_heads.clone())
                .unwrap();
        assert!(require_exact_legacy_migration_seal(&different, &seal).is_err());
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn production_stage_batch_writes_change_marker_bytes_for_distinct_batches() {
        let store = FirestoreStore::new("project".to_string(), None);
        let head = metadata_publication("repo", 7, "root", Vec::new())
            .into_canonical()
            .unwrap()
            .head;
        let first_row = serde_json::json!({
            "update": {
                "name": "projects/project/databases/(default)/documents/spine_entities_v2/first",
                "fields": { "payload": { "stringValue": "first" } }
            },
            "currentDocument": { "exists": false }
        });
        let second_row = serde_json::json!({
            "update": {
                "name": "projects/project/databases/(default)/documents/spine_entities_v2/second",
                "fields": { "payload": { "stringValue": "second" } }
            },
            "currentDocument": { "exists": false }
        });

        let first = store
            .immutable_stage_batch_writes(
                &head,
                1,
                std::slice::from_ref(&first_row),
                std::slice::from_ref(&first_row),
            )
            .unwrap();
        let retry = store
            .immutable_stage_batch_writes(
                &head,
                1,
                std::slice::from_ref(&first_row),
                std::slice::from_ref(&first_row),
            )
            .unwrap();
        let distinct = store
            .immutable_stage_batch_writes(
                &head,
                1,
                std::slice::from_ref(&second_row),
                std::slice::from_ref(&second_row),
            )
            .unwrap();
        let marker_fields = |writes: &[serde_json::Value]| {
            writes
                .last()
                .and_then(|write| write.pointer("/update/fields"))
                .cloned()
                .expect("production stage batch must end with its marker write")
        };

        assert_eq!(
            marker_fields(&first),
            marker_fields(&retry),
            "an identical retry must retain the exact marker bytes"
        );
        assert_ne!(
            marker_fields(&first),
            marker_fields(&distinct),
            "a distinct immutable row batch must change the actual marker write"
        );
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn production_head_commit_changes_marker_bytes_under_the_exact_stage_revision() {
        let store = FirestoreStore::new("project".to_string(), None);
        let head = metadata_publication("repo", 8, "root", Vec::new())
            .into_canonical()
            .unwrap()
            .head;
        let row = serde_json::json!({
            "update": {
                "name": "projects/project/databases/(default)/documents/spine_entities_v2/row",
                "fields": { "payload": { "stringValue": "row" } }
            },
            "currentDocument": { "exists": false }
        });
        let staged = store
            .immutable_stage_batch_writes(
                &head,
                4,
                std::slice::from_ref(&row),
                std::slice::from_ref(&row),
            )
            .unwrap();
        let staged_marker = staged.last().expect("stage marker write");
        let stage_guard = StorePublicationStageGuard {
            stage_sequence: 4,
            revision_sha256: staged_marker
                .pointer("/update/fields/revision_sha256/stringValue")
                .and_then(serde_json::Value::as_str)
                .expect("stage marker revision digest")
                .to_string(),
            update_time: "2026-08-27T12:34:56Z".to_string(),
        };
        let committed = store
            .committed_stage_marker_write(&head, &stage_guard)
            .unwrap();

        assert_ne!(
            staged_marker.pointer("/update/fields"),
            committed.pointer("/update/fields"),
            "the production head-commit marker must not be byte-identical to the prepared marker"
        );
        assert_eq!(
            committed
                .pointer("/currentDocument/updateTime")
                .and_then(serde_json::Value::as_str),
            Some(stage_guard.update_time.as_str()),
            "the changed marker write must retain the exact prepared Firestore revision precondition"
        );
        assert_eq!(
            committed
                .pointer("/update/fields/revision_kind/stringValue")
                .and_then(serde_json::Value::as_str),
            Some("committed")
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
