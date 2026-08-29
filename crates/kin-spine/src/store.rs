// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persistence boundary for a store-backed spine.
//!
//! A [`SpineStore`] is the durable store behind [`crate::FirestoreSpineBackend`]:
//! it stages immutable cursor-bound entity and edge rows, atomically advances a
//! repository head, and reloads only rows reachable from committed heads. The
//! store is the only seam that talks to an external system, so publication and
//! hydration can be exercised end-to-end against an in-memory fake.

use crate::backend::SpineError;
use crate::index::{CrossRepoEdge, EntityEntry};
use crate::publication::{
    CanonicalRepoPublication, LegacySpineWriterDrainAttestation, RepoPublicationCommit,
    RepoPublicationConflict, RepoPublicationHead, RepoSpinePublication, SpineRolloutFence,
    SpineRolloutFenceCommit, SpineRolloutFenceEvidence,
};
use std::collections::BTreeMap;

/// A repo's persisted entity set together with its graph root hash.
#[derive(Debug, Clone)]
pub struct LoadedRepo {
    pub repo_id: String,
    pub root_hash: String,
    pub entries: Vec<EntityEntry>,
}

/// One publication reached through a committed durable repository head.
#[derive(Debug, Clone)]
pub struct LoadedRepoPublication {
    pub head: RepoPublicationHead,
    pub entries: Vec<EntityEntry>,
    pub outgoing_edges: Vec<CrossRepoEdge>,
}

/// Result of one bounded unreachable-publication cleanup pass.
#[must_use = "cleanup continuation must be scheduled while more is true"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepoPublicationCleanupProgress {
    pub deleted: usize,
    pub more: bool,
}

/// Active durable fleet fence plus its exact Firestore document revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSpineRolloutFence {
    pub fence: SpineRolloutFence,
    pub update_time: String,
}

impl LoadedSpineRolloutFence {
    pub fn evidence(&self) -> SpineRolloutFenceEvidence {
        SpineRolloutFenceEvidence {
            rollout_fence: self.fence.rollout_fence,
            payload_sha256: self.fence.payload_sha256.clone(),
            update_time: self.update_time.clone(),
        }
    }
}

/// Store-native precondition captured with the repository head read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreHeadPrecondition {
    Missing,
    Revision(String),
}

/// One sibling repository head captured while preparing an edge publication.
///
/// The edge rows are valid only for the exact `resolution_roots` recorded in
/// their publication. Durable stores same-bytes-write every guarded sibling
/// head in the source head's atomic commit, so a sibling publication that wins
/// after resolution but before commit forces the stale edge writer to lose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRepoHeadGuard {
    pub head: RepoPublicationHead,
    pub precondition: StoreHeadPrecondition,
}

/// Exact final stage-marker state captured after all immutable rows and the
/// manifest have been staged. Durable head commit conditionally same-bytes
/// writes this marker in the same transaction as the head, fleet fence, and
/// dependency guards. Cleanup and a paused writer therefore cannot both win.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePublicationStageGuard {
    pub stage_sequence: u64,
    pub revision_sha256: String,
    pub update_time: String,
}

#[derive(Debug, Clone)]
enum PreparedStoreDisposition {
    Publish,
    AlreadyCommitted,
    Conflict(RepoPublicationConflict),
}

/// Opaque store preparation retained across the daemon's source-cursor probe.
///
/// The durable implementation stages immutable rows before returning this
/// token. Committing it may mutate only the one repository head and must apply
/// `head_precondition` atomically with that write.
#[derive(Debug, Clone)]
pub struct PreparedStorePublication {
    canonical: CanonicalRepoPublication,
    observed_head: Option<RepoPublicationHead>,
    head_precondition: StoreHeadPrecondition,
    dependency_heads: BTreeMap<String, StoreRepoHeadGuard>,
    stage_guard: Option<StorePublicationStageGuard>,
    rollout_fence: Option<LoadedSpineRolloutFence>,
    disposition: PreparedStoreDisposition,
}

impl PreparedStorePublication {
    /// Validate a candidate against the head observed by a store.
    ///
    /// Stores call this after reading the head and before staging. An older
    /// candidate cursor, an incompatible same-cursor manifest, or a phase
    /// downgrade is a typed conflict and can never become a head write.
    pub fn new(
        publication: RepoSpinePublication,
        observed_head: Option<RepoPublicationHead>,
        head_precondition: StoreHeadPrecondition,
    ) -> Result<Self, SpineError> {
        Self::new_inner(
            publication,
            observed_head,
            head_precondition,
            BTreeMap::new(),
            None,
        )
    }

    /// Validate a local/in-memory edge publication with exact sibling-head
    /// guards. Durable hosted stores use [`Self::new_fenced`] so the same token
    /// also captures the active rollout fence.
    pub fn new_with_dependencies(
        publication: RepoSpinePublication,
        observed_head: Option<RepoPublicationHead>,
        head_precondition: StoreHeadPrecondition,
        dependency_heads: BTreeMap<String, StoreRepoHeadGuard>,
    ) -> Result<Self, SpineError> {
        Self::new_inner(
            publication,
            observed_head,
            head_precondition,
            dependency_heads,
            None,
        )
    }

    /// Validate a durable publication while binding it to the exact active
    /// rollout-fence revision. Hosted stores must use this constructor.
    pub fn new_fenced(
        publication: RepoSpinePublication,
        observed_head: Option<RepoPublicationHead>,
        head_precondition: StoreHeadPrecondition,
        dependency_heads: BTreeMap<String, StoreRepoHeadGuard>,
        rollout_fence: LoadedSpineRolloutFence,
    ) -> Result<Self, SpineError> {
        rollout_fence.fence.validate()?;
        rollout_fence
            .fence
            .validate_publication_repo(&publication.repo_id)?;
        if rollout_fence.update_time.is_empty() {
            return Err(SpineError::Backend(
                "active spine rollout fence is missing its durable revision".to_string(),
            ));
        }
        Self::new_inner(
            publication,
            observed_head,
            head_precondition,
            dependency_heads,
            Some(rollout_fence),
        )
    }

    fn new_inner(
        publication: RepoSpinePublication,
        observed_head: Option<RepoPublicationHead>,
        head_precondition: StoreHeadPrecondition,
        dependency_heads: BTreeMap<String, StoreRepoHeadGuard>,
        rollout_fence: Option<LoadedSpineRolloutFence>,
    ) -> Result<Self, SpineError> {
        match (&observed_head, &head_precondition) {
            (None, StoreHeadPrecondition::Missing)
            | (Some(_), StoreHeadPrecondition::Revision(_)) => {}
            _ => {
                return Err(SpineError::Backend(
                    "spine head read and compare-and-swap precondition disagree".to_string(),
                ));
            }
        }
        if let Some(head) = &observed_head {
            head.validate()?;
        }
        let canonical = publication.into_canonical()?;
        let expected_dependencies = canonical
            .head
            .resolution_roots
            .iter()
            .filter(|(repo_id, _)| *repo_id != &canonical.head.repo_id)
            .map(|(repo_id, root_hash)| (repo_id.clone(), root_hash.clone()))
            .collect::<BTreeMap<_, _>>();
        if dependency_heads.len() != expected_dependencies.len()
            || dependency_heads.keys().ne(expected_dependencies.keys())
        {
            return Err(SpineError::Backend(format!(
                "repo {} publication did not capture every exact resolution dependency head",
                canonical.head.repo_id
            )));
        }
        for (repo_id, guard) in &dependency_heads {
            guard.head.validate()?;
            if guard.head.repo_id != *repo_id
                || expected_dependencies.get(repo_id) != Some(&guard.head.root_hash)
                || !matches!(guard.precondition, StoreHeadPrecondition::Revision(_))
            {
                return Err(SpineError::Backend(format!(
                    "repo {} publication dependency guard for {repo_id} does not match its exact committed root/revision",
                    canonical.head.repo_id
                )));
            }
        }
        let disposition = match observed_head.as_ref() {
            Some(head) if head.publication_id == canonical.head.publication_id => {
                PreparedStoreDisposition::AlreadyCommitted
            }
            Some(head)
                if canonical.head.source_cursor < head.source_cursor
                    || (canonical.head.source_cursor == head.source_cursor
                        && (canonical.head.phase < head.phase
                            || canonical.head.root_hash != head.root_hash
                            || canonical.head.metadata_sha256 != head.metadata_sha256
                            || (canonical.head.phase == head.phase
                                && (canonical.head.phase
                                    != crate::publication::RepoPublicationPhase::Edges
                                    || canonical.head.resolution_roots
                                        == head.resolution_roots)))) =>
            {
                PreparedStoreDisposition::Conflict(RepoPublicationConflict::against(
                    canonical.head.source_cursor,
                    Some(head),
                ))
            }
            _ => PreparedStoreDisposition::Publish,
        };
        Ok(Self {
            canonical,
            observed_head,
            head_precondition,
            dependency_heads,
            stage_guard: None,
            rollout_fence,
            disposition,
        })
    }

    pub fn publication(&self) -> &RepoSpinePublication {
        &self.canonical.publication
    }

    pub fn candidate_head(&self) -> &RepoPublicationHead {
        &self.canonical.head
    }

    pub fn observed_head(&self) -> Option<&RepoPublicationHead> {
        self.observed_head.as_ref()
    }

    pub fn head_precondition(&self) -> &StoreHeadPrecondition {
        &self.head_precondition
    }

    pub fn dependency_heads(&self) -> &BTreeMap<String, StoreRepoHeadGuard> {
        &self.dependency_heads
    }

    pub fn bind_stage_guard(
        mut self,
        stage_guard: StorePublicationStageGuard,
    ) -> Result<Self, SpineError> {
        if !self.requires_staging()
            || stage_guard.update_time.is_empty()
            || stage_guard.revision_sha256.is_empty()
        {
            return Err(SpineError::Backend(format!(
                "repo {} publication cannot bind an invalid final stage-marker guard",
                self.canonical.head.repo_id
            )));
        }
        self.stage_guard = Some(stage_guard);
        Ok(self)
    }

    pub fn stage_guard(&self) -> Option<&StorePublicationStageGuard> {
        self.stage_guard.as_ref()
    }

    pub fn rollout_fence(&self) -> Option<&LoadedSpineRolloutFence> {
        self.rollout_fence.as_ref()
    }

    pub fn rollout_fence_evidence(&self) -> Option<SpineRolloutFenceEvidence> {
        self.rollout_fence
            .as_ref()
            .map(LoadedSpineRolloutFence::evidence)
    }

    pub fn requires_staging(&self) -> bool {
        matches!(self.disposition, PreparedStoreDisposition::Publish)
    }

    pub fn terminal_result(&self) -> Option<RepoPublicationCommit> {
        match &self.disposition {
            PreparedStoreDisposition::Publish => None,
            PreparedStoreDisposition::AlreadyCommitted => {
                Some(RepoPublicationCommit::AlreadyCommitted {
                    source_cursor: self.canonical.head.source_cursor,
                })
            }
            PreparedStoreDisposition::Conflict(conflict) => {
                Some(RepoPublicationCommit::Conflict(conflict.clone()))
            }
        }
    }
}

/// Durable storage for spine metadata.
///
/// Methods are synchronous to match the [`crate::SpineBackend`] call sites; an
/// implementation backed by a network service bridges async internally. The
/// legacy row methods remain only for migration inspection and must not be used
/// as an authority publication path.
pub trait SpineStore: Send + Sync {
    /// Load the active fleet rollout fence and its exact durable revision.
    /// Hosted publication and hydration fail loudly when it is absent.
    fn load_rollout_fence(&self) -> Result<Option<LoadedSpineRolloutFence>, SpineError> {
        Err(SpineError::Backend(
            "durable spine rollout fence is unsupported by this store".to_string(),
        ))
    }

    /// Atomically create or advance the fleet fence. Implementations reconcile
    /// ambiguous results by rereading durable state. An identical payload is
    /// idempotent; a newer durable rollout is a typed stale conflict.
    fn advance_rollout_fence(
        &self,
        _fence: SpineRolloutFence,
    ) -> Result<SpineRolloutFenceCommit, SpineError> {
        Err(SpineError::Backend(
            "atomic spine rollout fencing is unsupported by this store".to_string(),
        ))
    }

    /// Whether an operator has durably declared the legacy collections closed
    /// to every old writer. Once true, readers must never consult those
    /// obsolete rows again.
    fn legacy_migration_complete(&self) -> Result<bool, SpineError> {
        Ok(false)
    }

    /// Persist the one-way legacy migration completion marker.
    ///
    /// Callers may invoke this only after every legacy repository has a valid
    /// v2 head and the deployment has excluded older cursorless writers.
    fn complete_legacy_migration(
        &self,
        _rollout_fence: &LoadedSpineRolloutFence,
        _writer_drain: &LegacySpineWriterDrainAttestation,
    ) -> Result<(), SpineError> {
        Err(SpineError::Backend(
            "durable legacy spine migration completion is unsupported by this store".to_string(),
        ))
    }

    /// Stage an immutable cursor-bound publication and capture the current head
    /// compare-and-swap precondition. The default fails loudly: a durable store
    /// must explicitly opt into atomic publication.
    fn prepare_repo_publication(
        &self,
        _publication: RepoSpinePublication,
    ) -> Result<PreparedStorePublication, SpineError> {
        Err(SpineError::Backend(
            "cursor-bound spine publication is unsupported by this store".to_string(),
        ))
    }

    /// Prepare only against the exact rollout authority already admitted by
    /// the external GCS control record. Reading whichever Firestore fence is
    /// active is not sufficient: the caller's evidence is the cross-backend
    /// binding, and any mismatch or absence fails before commit.
    fn prepare_repo_publication_bound(
        &self,
        publication: RepoSpinePublication,
        expected_rollout_fence: &SpineRolloutFenceEvidence,
    ) -> Result<PreparedStorePublication, SpineError> {
        let prepared = self.prepare_repo_publication(publication)?;
        if prepared.rollout_fence_evidence().as_ref() != Some(expected_rollout_fence) {
            return Err(SpineError::Backend(format!(
                "repo {} publication prepared against Firestore rollout evidence different from the GCS control record",
                prepared.candidate_head().repo_id
            )));
        }
        Ok(prepared)
    }

    /// Atomically move one repository head if and only if the preparation's
    /// exact precondition still holds.
    fn commit_repo_publication(
        &self,
        _prepared: &PreparedStorePublication,
    ) -> Result<RepoPublicationCommit, SpineError> {
        Err(SpineError::Backend(
            "atomic spine head compare-and-swap is unsupported by this store".to_string(),
        ))
    }

    /// Load only publications reachable from committed repository heads.
    fn load_repo_publications(&self) -> Result<Vec<LoadedRepoPublication>, SpineError> {
        Err(SpineError::Backend(
            "committed-head spine hydration is unsupported by this store".to_string(),
        ))
    }

    /// Load one repository through its stable committed head.
    ///
    /// Durable stores should override this with a bounded head, rows, head
    /// read so a commit path need not hydrate every repository merely to
    /// reconcile one winner. The compatibility default filters the full
    /// committed-head load and remains fail-loud when that primitive is absent.
    fn load_repo_publication(
        &self,
        repo_id: &str,
    ) -> Result<Option<LoadedRepoPublication>, SpineError> {
        Ok(self
            .load_repo_publications()?
            .into_iter()
            .find(|publication| publication.head.repo_id == repo_id))
    }

    /// Delete at most `max_rows` unreachable rows that are provably unable to
    /// win over `active_head`. Cleanup is outside the commit path and must never
    /// delete a newer staged cursor or a same-cursor edge upgrade.
    fn cleanup_repo_publications(
        &self,
        _active_head: &RepoPublicationHead,
        _max_rows: usize,
    ) -> Result<RepoPublicationCleanupProgress, SpineError> {
        Err(SpineError::Backend(
            "bounded spine publication cleanup is unsupported by this store".to_string(),
        ))
    }

    /// Load every persisted repo (entities grouped by repo, with root hash).
    fn load_repos(&self) -> Result<Vec<LoadedRepo>, SpineError>;

    /// Load every persisted cross-repo edge.
    fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError>;

    /// Persist one entity belonging to `root_hash`'s repo, replacing any prior
    /// copy of the same entity.
    fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError>;

    /// Remove every persisted entity for `repo_id`.
    fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError>;

    /// Persist one cross-repo edge.
    fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError>;

    /// Remove every persisted edge whose source repo is `repo_id`.
    fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError>;
}
