// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! In-memory durable spine store, and the race scaffolding around it.
//!
//! This is the ONE fake for the durable publication contract. It backs
//! `FirestoreSpineBackend::with_store`, so a consumer gets the real backend
//! over a fake transport rather than a second implementation of the CAS
//! semantics. Two fakes drift in exactly the direction that keeps both suites
//! green, which is why the daemon's composed rollout path and this crate's own
//! suite share this one.
//!
//! Compiled for this crate's tests and for any consumer enabling
//! `test-support`. It is not part of the product surface.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::backend::SpineError;
use crate::firestore::{
    classify_rollout_fence_reconciliation, publication_stage_is_cleanup_safe,
    RolloutFenceReconciliation,
};
use crate::index::{CrossRepoEdge, EntityEntry};
use crate::publication::{
    LegacySpineWriterDrainAttestation, RepoPublicationCommit, RepoPublicationHead,
    RepoSpinePublication, SpineRolloutFence, SpineRolloutFenceCommit, SpineRolloutFenceEvidence,
    SpineRolloutRepositoryFence,
};
use crate::store::{
    LoadedRepo, LoadedRepoPublication, LoadedSpineRolloutFence, PreparedStorePublication,
    RepoPublicationCleanupProgress, SpineStore, StoreHeadPrecondition, StorePublicationStageGuard,
    StoreRepoHeadGuard,
};

pub fn test_rollout_fence(rollout_fence: u64, token: &str, repo_ids: &[&str]) -> SpineRolloutFence {
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

pub fn default_test_rollout_fence() -> SpineRolloutFence {
    test_rollout_fence(
        1,
        "test-rollout-1",
        &["consumer", "provider", "repo", "repo-a", "repo-b", "source"],
    )
}

pub struct BoundedRendezvous {
    /// (parties arrived in the current phase, phase number)
    pub inner: Mutex<(usize, u64)>,
    pub signal: std::sync::Condvar,
}

impl BoundedRendezvous {
    pub const DEADLINE: Duration = Duration::from_secs(30);

    pub fn new() -> Self {
        Self {
            inner: Mutex::new((0, 0)),
            signal: std::sync::Condvar::new(),
        }
    }

    /// Arrive and wait for the other party, or panic naming this side.
    pub fn wait(&self, who: &str) {
        let mut state = self.inner.lock().unwrap();
        let phase = state.1;
        state.0 += 1;
        if state.0 == 2 {
            state.0 = 0;
            state.1 += 1;
            self.signal.notify_all();
            return;
        }
        let (_state, timeout) = self
            .signal
            .wait_timeout_while(state, Self::DEADLINE, |state| state.1 == phase)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "{who} waited {:?} at a two-party rendezvous the other side never reached; \
             the fake reaches its rendezvous only after it selects a stage or head, so \
             this means production selected nothing on the path under test",
            Self::DEADLINE
        );
    }
}

pub struct FakeSpineStore {
    // (root_hash, entries) keyed by repo_id.
    pub repos: Mutex<HashMap<String, (String, Vec<EntityEntry>)>>,
    pub edges: Mutex<Vec<CrossRepoEdge>>,
    pub publication_state: Mutex<FakePublicationState>,
    pub rollout_fence_state: Mutex<Option<(u64, SpineRolloutFence)>>,
    pub fail_next_load_edges: AtomicBool,
    pub fail_stage_after_rows: AtomicUsize,
    pub fail_next_commit: AtomicBool,
    pub lose_next_commit_response_after_apply: AtomicBool,
    pub lose_next_rollout_fence_response_after_apply: AtomicBool,
    /// Test-only mutant that drops the required durable reread after a lost
    /// rollout-fence response.
    pub disable_rollout_fence_reconciliation: AtomicBool,
    pub atomicity_available: AtomicBool,
    /// Test-only mutant switch. Production stores have no such path.
    pub disable_head_precondition: AtomicBool,
    /// Test-only mutant switch restoring the paused pre-rollout writer.
    pub disable_rollout_fence_precondition: AtomicBool,
    /// Test-only mutant restoring an edge writer paused while a sibling
    /// repository head advances after resolution.
    pub disable_dependency_head_precondition: AtomicBool,
    /// Test-only mutant switch for the stage-marker cleanup fence.
    pub disable_stage_fence: AtomicBool,
    /// Test-only mutant that restores the byte-identical marker heartbeat
    /// whose Firestore updateTime may remain unchanged for a distinct batch.
    pub disable_distinct_stage_heartbeat: AtomicBool,
    /// Test-only mutant dropping the final stage-marker precondition from
    /// the atomic head commit.
    pub disable_stage_head_precondition: AtomicBool,
    /// Optional deterministic pause after cleanup snapshots a stage but
    /// before its exact-revision atomic delete commit.
    pub cleanup_snapshot_barrier: Mutex<Option<Arc<BoundedRendezvous>>>,
    /// Optional deterministic pause after hydration snapshots heads but
    /// before it reads the corresponding immutable rows.
    pub load_snapshot_barrier: Mutex<Option<Arc<BoundedRendezvous>>>,
    /// Keep staged rows in place while a race or cleanup assertion inspects
    /// them. Production cleanup remains enabled and bounded.
    pub disable_cleanup: AtomicBool,
    pub cleanup_calls: AtomicUsize,
    pub legacy_migration_seal: Mutex<
        Option<(
            LoadedSpineRolloutFence,
            LegacySpineWriterDrainAttestation,
            Vec<RepoPublicationHead>,
        )>,
    >,
}

#[derive(Default)]
pub struct FakePublicationState {
    pub heads: HashMap<String, (u64, RepoPublicationHead)>,
    pub stages: HashMap<String, RepoPublicationHead>,
    pub manifests: HashMap<String, RepoPublicationHead>,
    pub entity_rows: HashMap<String, Vec<EntityEntry>>,
    pub edge_rows: HashMap<String, Vec<CrossRepoEdge>>,
    pub stage_marker_values: HashMap<String, FakeStageMarkerValue>,
    pub stage_revisions: HashMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeStageMarkerValue {
    pub stage_sequence: u64,
    pub revision_kind: &'static str,
    pub revision_nonce: String,
}

pub fn apply_fake_stage_marker(
    state: &mut FakePublicationState,
    publication_id: &str,
    marker: FakeStageMarkerValue,
) {
    let changed = state.stage_marker_values.get(publication_id) != Some(&marker);
    if !changed {
        return;
    }
    state
        .stage_marker_values
        .insert(publication_id.to_string(), marker);
    match state.stage_revisions.get_mut(publication_id) {
        Some(revision) => *revision += 1,
        None => {
            state.stage_revisions.insert(publication_id.to_string(), 1);
        }
    }
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
            disable_dependency_head_precondition: AtomicBool::new(false),
            disable_stage_fence: AtomicBool::new(false),
            disable_distinct_stage_heartbeat: AtomicBool::new(false),
            disable_stage_head_precondition: AtomicBool::new(false),
            cleanup_snapshot_barrier: Mutex::new(None),
            load_snapshot_barrier: Mutex::new(None),
            disable_cleanup: AtomicBool::new(false),
            cleanup_calls: AtomicUsize::new(0),
            legacy_migration_seal: Mutex::new(None),
        }
    }
}

pub fn merge_fake_immutable_rows<T: Clone + PartialEq>(
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
            if current.scope != candidate.scope || current.rollout_fence >= candidate.rollout_fence
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
            return match classify_rollout_fence_reconciliation(&candidate, Some(&observed)) {
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
        let seal = self.legacy_migration_seal.lock().unwrap();
        let Some((sealed_fence, writer_drain, sealed_heads)) = seal.as_ref() else {
            return Ok(false);
        };
        writer_drain.validate()?;
        let current = self.load_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend(
                "fake legacy migration seal has no active rollout fence".to_string(),
            )
        })?;
        let sealed_ids = sealed_fence
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.as_str())
            .collect::<Vec<_>>();
        let current_ids = current
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.as_str())
            .collect::<Vec<_>>();
        let head_ids = sealed_heads
            .iter()
            .map(|head| head.repo_id.as_str())
            .collect::<Vec<_>>();
        if sealed_fence.fence.scope != current.fence.scope
            || sealed_ids != current_ids
            || head_ids != current_ids
            || sealed_fence.fence.rollout_fence > current.fence.rollout_fence
            || writer_drain.rollout_fence_evidence != sealed_fence.evidence()
        {
            return Err(SpineError::Backend(
                "fake legacy migration seal does not match active authority".to_string(),
            ));
        }
        Ok(true)
    }

    fn complete_legacy_migration(
        &self,
        rollout_fence: &LoadedSpineRolloutFence,
        writer_drain: &LegacySpineWriterDrainAttestation,
    ) -> Result<(), SpineError> {
        writer_drain.validate()?;
        if writer_drain.rollout_fence_evidence != rollout_fence.evidence() {
            return Err(SpineError::Backend(
                "fake writer-drain attestation does not match rollout fence".to_string(),
            ));
        }
        let state = self.publication_state.lock().unwrap();
        let mut heads = state
            .heads
            .values()
            .map(|(_, head)| head.clone())
            .collect::<Vec<_>>();
        heads.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
        let expected_ids = rollout_fence
            .fence
            .repositories
            .iter()
            .map(|row| row.repo_id.as_str())
            .collect::<Vec<_>>();
        let observed_ids = heads
            .iter()
            .map(|head| head.repo_id.as_str())
            .collect::<Vec<_>>();
        if observed_ids != expected_ids {
            return Err(SpineError::Backend(
                "fake legacy migration seal requires exact fleet heads".to_string(),
            ));
        }
        drop(state);
        let candidate = (rollout_fence.clone(), writer_drain.clone(), heads);
        let mut seal = self.legacy_migration_seal.lock().unwrap();
        if let Some(existing) = seal.as_ref() {
            if existing != &candidate {
                return Err(SpineError::Backend(
                    "a different fake legacy migration seal already exists".to_string(),
                ));
            }
            return Ok(());
        }
        *seal = Some(candidate);
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
        let mut dependency_heads = BTreeMap::new();
        for (repo_id, expected_root) in publication
            .resolution_roots
            .as_ref()
            .into_iter()
            .flat_map(|roots| roots.iter())
        {
            if repo_id == &publication.repo_id {
                continue;
            }
            let (revision, head) = state.heads.get(repo_id).cloned().ok_or_else(|| {
                SpineError::Backend(format!(
                    "fake edge publication cannot resolve against missing head {repo_id}"
                ))
            })?;
            if head.root_hash != *expected_root {
                return Err(SpineError::Backend(format!(
                    "fake edge publication resolved {repo_id} at {expected_root}, but head is at {}",
                    head.root_hash
                )));
            }
            dependency_heads.insert(
                repo_id.clone(),
                StoreRepoHeadGuard {
                    head,
                    precondition: StoreHeadPrecondition::Revision(revision.to_string()),
                },
            );
        }
        let mut prepared = PreparedStorePublication::new_fenced(
            publication,
            observed_head,
            precondition,
            dependency_heads,
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
            apply_fake_stage_marker(
                &mut state,
                &publication_id,
                FakeStageMarkerValue {
                    stage_sequence: 0,
                    revision_kind: "stage",
                    revision_nonce: format!("init:{publication_id}"),
                },
            );
        }

        let candidate = prepared.publication();
        let fail_after = self
            .fail_stage_after_rows
            .swap(usize::MAX, Ordering::SeqCst);
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
                apply_fake_stage_marker(
                    &mut state,
                    &publication_id,
                    FakeStageMarkerValue {
                        stage_sequence: 1,
                        revision_kind: "stage",
                        revision_nonce: format!("entity-partial:{written}"),
                    },
                );
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
                merge_fake_immutable_rows(&mut state.edge_rows, &publication_id, edges, "edge")?;
                apply_fake_stage_marker(
                    &mut state,
                    &publication_id,
                    FakeStageMarkerValue {
                        stage_sequence: 1,
                        revision_kind: "stage",
                        revision_nonce: format!("edge-partial:{written}"),
                    },
                );
                return Err(SpineError::Backend(
                    "injected edge stage failure".to_string(),
                ));
            }
            edges.push(edge.clone());
            written += 1;
        }
        merge_fake_immutable_rows(&mut state.entity_rows, &publication_id, entities, "entity")?;
        merge_fake_immutable_rows(&mut state.edge_rows, &publication_id, edges, "edge")?;
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
        apply_fake_stage_marker(
            &mut state,
            &publication_id,
            FakeStageMarkerValue {
                stage_sequence: 2,
                revision_kind: "stage",
                revision_nonce: format!(
                    "complete:{}:{}:{}",
                    candidate.entries.len(),
                    candidate.outgoing_edges.as_ref().map_or(0, Vec::len),
                    candidate.phase() as u8
                ),
            },
        );
        let final_marker = state
            .stage_marker_values
            .get(&publication_id)
            .cloned()
            .expect("fake final stage marker");
        let final_revision = state
            .stage_revisions
            .get(&publication_id)
            .copied()
            .expect("fake final stage revision");
        prepared = prepared.bind_stage_guard(StorePublicationStageGuard {
            stage_sequence: final_marker.stage_sequence,
            revision_sha256: final_marker.revision_nonce,
            update_time: final_revision.to_string(),
        })?;
        Ok(prepared)
    }

    fn prepare_repo_publication_bound(
        &self,
        publication: RepoSpinePublication,
        expected_rollout_fence: &SpineRolloutFenceEvidence,
    ) -> Result<PreparedStorePublication, SpineError> {
        let active = self.load_rollout_fence()?.ok_or_else(|| {
            SpineError::Backend("fake active rollout fence is missing".to_string())
        })?;
        if active.evidence() != *expected_rollout_fence {
            return Err(SpineError::Backend(format!(
                "repo {} fake publication refused before staging because rollout evidence differs from the admitted authority",
                publication.repo_id
            )));
        }
        self.prepare_repo_publication(publication)
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
        if prepared.requires_staging()
            && !self.disable_stage_head_precondition.load(Ordering::SeqCst)
        {
            let expected_stage = prepared.stage_guard().ok_or_else(|| {
                SpineError::Backend(
                    "fake hosted publication has no final stage-marker guard".to_string(),
                )
            })?;
            let observed_revision = state
                .stage_revisions
                .get(&candidate.publication_id)
                .copied();
            let observed_marker = state.stage_marker_values.get(&candidate.publication_id);
            let stage_matches = observed_revision
                .is_some_and(|revision| revision.to_string() == expected_stage.update_time)
                && observed_marker.is_some_and(|marker| {
                    marker.stage_sequence == expected_stage.stage_sequence
                        && marker.revision_kind == "stage"
                        && marker.revision_nonce == expected_stage.revision_sha256
                });
            if !stage_matches {
                return Ok(RepoPublicationCommit::Conflict(
                    crate::publication::RepoPublicationConflict::against(
                        candidate.source_cursor,
                        current.as_ref().map(|(_, head)| head),
                    ),
                ));
            }
        }
        if !self
            .disable_dependency_head_precondition
            .load(Ordering::SeqCst)
        {
            for (repo_id, guard) in prepared.dependency_heads() {
                let observed_dependency = state.heads.get(repo_id).cloned();
                let dependency_matches = match (&guard.precondition, &observed_dependency) {
                    (StoreHeadPrecondition::Revision(expected), Some((revision, head))) => {
                        expected == &revision.to_string() && head == &guard.head
                    }
                    _ => false,
                };
                if !dependency_matches {
                    return Ok(RepoPublicationCommit::Conflict(
                        crate::publication::RepoPublicationConflict::against_dependency(
                            candidate.source_cursor,
                            repo_id,
                            observed_dependency.as_ref().map(|(_, head)| head),
                        ),
                    ));
                }
            }
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
        if !self.disable_stage_head_precondition.load(Ordering::SeqCst) {
            if let Some(stage_guard) = prepared.stage_guard() {
                apply_fake_stage_marker(
                    &mut state,
                    &candidate.publication_id,
                    FakeStageMarkerValue {
                        stage_sequence: stage_guard.stage_sequence,
                        revision_kind: "committed",
                        revision_nonce: format!(
                            "committed:{}:{}",
                            stage_guard.revision_sha256, candidate.publication_id
                        ),
                    },
                );
            }
        }
        let next_revision = match current.as_ref() {
            Some((revision, _)) => revision.checked_add(1).ok_or_else(|| {
                SpineError::Backend("fake spine head revision exhausted".to_string())
            })?,
            None => 1,
        };
        state.heads.insert(
            candidate.repo_id.clone(),
            (next_revision, candidate.clone()),
        );
        if self
            .lose_next_commit_response_after_apply
            .swap(false, Ordering::SeqCst)
        {
            // The fake store models the production contract: an applied
            // CAS whose response is lost is reconciled by rereading the
            // durable head before control returns to the backend.
            let observed = state.heads.get(&candidate.repo_id).map(|(_, head)| head);
            if observed.is_some_and(|head| head.publication_id == candidate.publication_id) {
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
            // Same guard-lifetime rule as the cleanup rendezvous below.
            let rendezvous = self.load_snapshot_barrier.lock().unwrap().take();
            if let Some(barrier) = rendezvous {
                barrier.wait("fake store hydration snapshot");
                barrier.wait("fake store hydration snapshot");
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
        let (
            publication_id,
            expected_revision,
            entity_take,
            edge_take,
            remove_manifest,
            remove_stage,
        ) = {
            let state = self.publication_state.lock().unwrap();
            let durable_head = state
                .heads
                .get(&active_head.repo_id)
                .map(|(_, head)| head.clone())
                .ok_or_else(|| {
                    SpineError::Backend("fake store has no durable head during cleanup".to_string())
                })?;
            let mut candidates = state
                .stages
                .values()
                .filter(|head| {
                    head.repo_id == durable_head.repo_id
                        && head.publication_id != durable_head.publication_id
                        && publication_stage_is_cleanup_safe(head, &durable_head)
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

        // Take the rendezvous out of the mutex BEFORE waiting. As an
        // `if let` scrutinee the guard lives to the end of the block, so it
        // was held across both waits, and the committing thread re-enters
        // cleanup and blocks on this same mutex: a deadlock that an untimed
        // Barrier turns into a permanent hang.
        let rendezvous = self.cleanup_snapshot_barrier.lock().unwrap().take();
        if let Some(barrier) = rendezvous {
            barrier.wait("fake store cleanup snapshot");
            barrier.wait("fake store cleanup snapshot");
        }

        let mut state = self.publication_state.lock().unwrap();
        if !self.disable_stage_fence.load(Ordering::SeqCst)
            && state.stage_revisions.get(&publication_id).copied() != Some(expected_revision)
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
            state.stage_marker_values.remove(&publication_id);
            state.stage_revisions.remove(&publication_id);
            deleted += 1;
        } else {
            let stage_sequence = state
                .stage_marker_values
                .get(&publication_id)
                .map_or(0, |marker| marker.stage_sequence);
            apply_fake_stage_marker(
                &mut state,
                &publication_id,
                FakeStageMarkerValue {
                    stage_sequence,
                    revision_kind: "cleanup",
                    revision_nonce: format!(
                        "cleanup:{expected_revision}:{entity_take}:{edge_take}:{}",
                        usize::from(remove_manifest)
                    ),
                },
            );
        }
        let durable_head = state
            .heads
            .get(&active_head.repo_id)
            .map(|(_, head)| head)
            .expect("fake durable head remains during cleanup");
        let more = state.stages.values().any(|head| {
            head.repo_id == durable_head.repo_id
                && head.publication_id != durable_head.publication_id
                && publication_stage_is_cleanup_safe(head, durable_head)
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
