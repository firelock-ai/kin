// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Authority frames: the O(change) persistence unit of repository authority.
//!
//! A repository-authority successor differs from its predecessor in exactly
//! the ways `prepare_successor` mutates it: new immutable changes, one appended
//! operation record and its receipt, and envelope collections that are
//! appended to, upserted, or replaced. An [`AuthorityFrame`] carries that
//! mutation as the writer already accumulated it, so it is drained from the
//! successor rather than computed by diffing two snapshots, and it carries the
//! results of the mutation (the successor workspace state, the successor ref
//! state) rather than the transaction, so recovery applies it without paying
//! for base-graph materialization again.
//!
//! Wire format, identical in layout to the KNDD graph delta so every reader
//! that does not know frames refuses at the first four bytes:
//!   [4B magic "KNAF"] [4B version LE] [8B body_len LE] [body ...] [32B SHA-256]
//!
//! The body is a MessagePack-serialized [`AuthorityFrame`]. The struct is
//! encoded positionally, so its fields are only ever appended, and any change
//! to what a field means bumps [`AuthorityFrame::CURRENT_VERSION`]. The version
//! in the header is derived from the contents
//! ([`AuthorityFrame::wire_version`]): a frame that moves no collaboration
//! record keeps the version 2 body byte for byte.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use kin_model::{
    Actor, ActorId, Annotation, AnnotationId, Approval, Assertion, AssertionId, AuditEvent,
    Contract, ContractId, Delegation, ExternalChangeAlias, ExternalObjectRecord,
    FrozenLocalOverlay, GitExternalAuthority, MergeTransactionRecord, MockHint,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryId, RepositoryOperationRecord,
    RepositoryRefState, Review, ReviewAssignment, ReviewDecision, ReviewDiscussion, ReviewId,
    ReviewNote, SemanticChange, TestCase, TestId, VerificationRun, VerificationRunId, WorkId,
    WorkItem, WorkLink, WorkspaceState,
};

use crate::error::KinDbError;
use crate::storage::backend::Generation;
use crate::storage::format::GraphSnapshot;
use crate::storage::repository::{
    derive_change_children, ChangeAdmissionPolicy, PersistedRepositoryAuthority,
    PublicationPhaseTimer,
};

/// How a frame moves the envelope's Git external authority.
///
/// The envelope value is an `Option`, so a removal is an absence, and an
/// absence nested inside another `Option` does not survive MessagePack:
/// `Some(None)` and `None` both encode as nil. The patch is therefore an
/// explicit three-way enum, and every variant has its own wire shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GitExternalAuthorityPatch {
    /// The successor carries the base's Git authority unchanged.
    Unchanged,
    /// The successor installed or replaced the Git authority with this value.
    Set(GitExternalAuthority),
    /// The successor removed the Git authority.
    Cleared,
}

impl GitExternalAuthorityPatch {
    /// The patch that carries `base` to `successor`.
    pub fn between(
        base: &Option<GitExternalAuthority>,
        successor: &Option<GitExternalAuthority>,
    ) -> Self {
        if successor == base {
            Self::Unchanged
        } else {
            match successor {
                Some(authority) => Self::Set(authority.clone()),
                None => Self::Cleared,
            }
        }
    }

    fn apply_to(&self, target: &mut Option<GitExternalAuthority>) {
        match self {
            Self::Unchanged => {}
            Self::Set(authority) => *target = Some(authority.clone()),
            Self::Cleared => *target = None,
        }
    }
}

/// The collaboration records one successor added or replaced, as the
/// successor holds them.
///
/// A transaction moves collaboration only through its collaboration delta,
/// and the commit path admits a delta in one way: a keyed entry replaces
/// whatever is held under its key, and an unkeyed record is appended unless an
/// identical one is already held. So a successor's collaboration differs from
/// its base only by keyed values that are new or replaced and by records
/// appended after every record of the base, and this carries exactly that. A
/// keyed collection carries the successor's value for every key whose value is
/// new or moved, sorted strictly by the key's MessagePack encoding so one
/// successor always encodes to one byte string. An unkeyed collection carries
/// the successor's records past the base's, in the successor's order.
///
/// A removal or a rewrite cannot be said here, and nothing can produce one: a
/// collaboration delta has no removal form. The drain refuses a successor that
/// would need one, and the writer persists that successor whole.
///
/// The fields are the seventeen collections the collaboration root folds, in
/// fold order, named by [`Self::COLLECTIONS`]. Positional like the frame, so a
/// field is only ever appended.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollaborationPatch {
    pub work_items: Vec<(WorkId, WorkItem)>,
    pub annotations: Vec<(AnnotationId, Annotation)>,
    pub work_links: Vec<WorkLink>,
    pub reviews: Vec<(ReviewId, Review)>,
    /// A review's decision history, whole, as the snapshot holds it.
    pub review_decisions: Vec<(ReviewId, Vec<ReviewDecision>)>,
    pub review_notes: Vec<ReviewNote>,
    pub review_discussions: Vec<ReviewDiscussion>,
    /// A review's assignment set, whole, as the snapshot holds it.
    pub review_assignments: Vec<(ReviewId, Vec<ReviewAssignment>)>,
    pub test_cases: Vec<(TestId, TestCase)>,
    pub assertions: Vec<(AssertionId, Assertion)>,
    pub verification_runs: Vec<(VerificationRunId, VerificationRun)>,
    pub mock_hints: Vec<MockHint>,
    pub contracts: Vec<(ContractId, Contract)>,
    pub actors: Vec<(ActorId, Actor)>,
    pub delegations: Vec<Delegation>,
    pub approvals: Vec<Approval>,
    pub audit_events: Vec<AuditEvent>,
}

impl CollaborationPatch {
    /// The collections this patch carries, in field order, which is the fold
    /// order of the collaboration root. A test holds this equal to the
    /// collaboration model's own list, so a collection the model gains without
    /// a field here fails that test rather than costing a full snapshot per
    /// publication with nothing red.
    pub const COLLECTIONS: [&'static str; 17] = [
        "work_items",
        "annotations",
        "work_links",
        "reviews",
        "review_decisions",
        "review_notes",
        "review_discussions",
        "review_assignments",
        "test_cases",
        "assertions",
        "verification_runs",
        "mock_hints",
        "contracts",
        "actors",
        "delegations",
        "approvals",
        "audit_events",
    ];

    /// Whether this patch moves no collaboration record.
    pub fn is_empty(&self) -> bool {
        let Self {
            work_items,
            annotations,
            work_links,
            reviews,
            review_decisions,
            review_notes,
            review_discussions,
            review_assignments,
            test_cases,
            assertions,
            verification_runs,
            mock_hints,
            contracts,
            actors,
            delegations,
            approvals,
            audit_events,
        } = self;
        work_items.is_empty()
            && annotations.is_empty()
            && work_links.is_empty()
            && reviews.is_empty()
            && review_decisions.is_empty()
            && review_notes.is_empty()
            && review_discussions.is_empty()
            && review_assignments.is_empty()
            && test_cases.is_empty()
            && assertions.is_empty()
            && verification_runs.is_empty()
            && mock_hints.is_empty()
            && contracts.is_empty()
            && actors.is_empty()
            && delegations.is_empty()
            && approvals.is_empty()
            && audit_events.is_empty()
    }

    /// The collaboration `next` added or replaced over `current`, or the
    /// record class it removed or rewrote, which no frame can carry.
    fn drain(current: &GraphSnapshot, next: &GraphSnapshot) -> Result<Self, KinDbError> {
        Ok(Self {
            work_items: keyed_changes(&current.work_items, &next.work_items, "work item")?,
            annotations: keyed_changes(&current.annotations, &next.annotations, "annotation")?,
            work_links: appended_records(&current.work_links, &next.work_links, "work link")?,
            reviews: keyed_changes(&current.reviews, &next.reviews, "review")?,
            review_decisions: keyed_changes(
                &current.review_decisions,
                &next.review_decisions,
                "review decision history",
            )?,
            review_notes: appended_records(
                &current.review_notes,
                &next.review_notes,
                "review note",
            )?,
            review_discussions: appended_records(
                &current.review_discussions,
                &next.review_discussions,
                "review discussion",
            )?,
            review_assignments: keyed_changes(
                &current.review_assignments,
                &next.review_assignments,
                "review assignment set",
            )?,
            test_cases: keyed_changes(&current.test_cases, &next.test_cases, "test case")?,
            assertions: keyed_changes(&current.assertions, &next.assertions, "assertion")?,
            verification_runs: keyed_changes(
                &current.verification_runs,
                &next.verification_runs,
                "verification run",
            )?,
            mock_hints: appended_records(&current.mock_hints, &next.mock_hints, "mock hint")?,
            contracts: keyed_changes(&current.contracts, &next.contracts, "contract")?,
            actors: keyed_changes(&current.actors, &next.actors, "actor")?,
            delegations: appended_records(&current.delegations, &next.delegations, "delegation")?,
            approvals: appended_records(&current.approvals, &next.approvals, "approval")?,
            audit_events: appended_records(
                &current.audit_events,
                &next.audit_events,
                "audit event",
            )?,
        })
    }

    /// Refuse a patch whose keyed collections are not in their one canonical
    /// order, which is also what refuses a key carried twice.
    fn validate_shape(&self) -> Result<(), KinDbError> {
        let Self {
            work_items,
            annotations,
            work_links: _,
            reviews,
            review_decisions,
            review_notes: _,
            review_discussions: _,
            review_assignments,
            test_cases,
            assertions,
            verification_runs,
            mock_hints: _,
            contracts,
            actors,
            delegations: _,
            approvals: _,
            audit_events: _,
        } = self;
        require_keyed_order(work_items, "collaboration work items")?;
        require_keyed_order(annotations, "collaboration annotations")?;
        require_keyed_order(reviews, "collaboration reviews")?;
        require_keyed_order(review_decisions, "collaboration review decisions")?;
        require_keyed_order(review_assignments, "collaboration review assignments")?;
        require_keyed_order(test_cases, "collaboration test cases")?;
        require_keyed_order(assertions, "collaboration assertions")?;
        require_keyed_order(verification_runs, "collaboration verification runs")?;
        require_keyed_order(contracts, "collaboration contracts")?;
        require_keyed_order(actors, "collaboration actors")?;
        Ok(())
    }

    /// Replace every keyed value this patch carries and append every record,
    /// in place. It cannot fail, which is what lets [`AuthorityFrame::apply`]
    /// run it after every check that can.
    fn apply_to(&self, snapshot: &mut GraphSnapshot) {
        let Self {
            work_items,
            annotations,
            work_links,
            reviews,
            review_decisions,
            review_notes,
            review_discussions,
            review_assignments,
            test_cases,
            assertions,
            verification_runs,
            mock_hints,
            contracts,
            actors,
            delegations,
            approvals,
            audit_events,
        } = self;
        upsert(&mut snapshot.work_items, work_items);
        upsert(&mut snapshot.annotations, annotations);
        snapshot.work_links.extend(work_links.iter().cloned());
        upsert(&mut snapshot.reviews, reviews);
        upsert(&mut snapshot.review_decisions, review_decisions);
        snapshot.review_notes.extend(review_notes.iter().cloned());
        snapshot
            .review_discussions
            .extend(review_discussions.iter().cloned());
        upsert(&mut snapshot.review_assignments, review_assignments);
        upsert(&mut snapshot.test_cases, test_cases);
        upsert(&mut snapshot.assertions, assertions);
        upsert(&mut snapshot.verification_runs, verification_runs);
        snapshot.mock_hints.extend(mock_hints.iter().cloned());
        upsert(&mut snapshot.contracts, contracts);
        upsert(&mut snapshot.actors, actors);
        snapshot.delegations.extend(delegations.iter().cloned());
        snapshot.approvals.extend(approvals.iter().cloned());
        snapshot.audit_events.extend(audit_events.iter().cloned());
    }
}

/// One acknowledged successor of a repository-authority state, as a patch over
/// the state it extends.
///
/// Every sequence with set semantics is carried in canonical sorted order so
/// that encoding the same successor twice yields identical bytes, which is what
/// makes an exact retry of a frame append idempotent at the backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityFrame {
    /// Envelope schema of the base and the successor.
    pub schema_version: u32,
    pub repository_id: RepositoryId,
    /// The one operation this successor appended. Its `roots_before` names
    /// the exact predecessor state and its `roots_after` names the successor.
    pub operation: RepositoryOperationRecord,
    /// Successor changes absent from the base, sorted by identity.
    pub changes: Vec<SemanticChange>,
    /// Admission policies for exactly the changes above, sorted by change id.
    pub admission_policies: Vec<ChangeAdmissionPolicy>,
    /// External object records absent from the base, sorted by object id.
    pub external_objects: Vec<ExternalObjectRecord>,
    /// External change aliases absent from the base, sorted by object id.
    pub aliases: Vec<ExternalChangeAlias>,
    /// How the successor moved the Git authority, if it did.
    pub git_external_authority: GitExternalAuthorityPatch,
    /// The successor's complete ref state; refs move and disappear.
    pub ref_state: RepositoryRefState,
    /// Successor workspaces that differ from the base, sorted by workspace id.
    pub workspaces: Vec<WorkspaceState>,
    /// The successor's complete local overlay list.
    pub local_overlays: Vec<FrozenLocalOverlay>,
    /// The successor's complete merge record list; records are removed too.
    pub merge_transactions: Vec<MergeTransactionRecord>,
    /// The collaboration records the successor added or replaced.
    ///
    /// Appended in version 3 and skipped when empty, so a frame that moves no
    /// collaboration serializes as exactly the twelve-element version 2 body
    /// and a version 2 body decodes with an empty patch.
    #[serde(default, skip_serializing_if = "CollaborationPatch::is_empty")]
    pub collaboration: CollaborationPatch,
}

impl AuthorityFrame {
    /// Magic bytes for the frame file header: "KNAF".
    pub const MAGIC: [u8; 4] = *b"KNAF";

    /// Newest frame format version this binary reads and writes.
    ///
    /// Version 3 appends [`CollaborationPatch`]. A frame is written at the
    /// version its contents need ([`Self::wire_version`]), so only a frame
    /// that carries collaboration is a version 3 frame.
    pub const CURRENT_VERSION: u32 = 3;

    /// The oldest frame format version this binary reads, and the version a
    /// frame that carries no collaboration is still written at.
    ///
    /// Version 1 carried the Git authority patch as a nested `Option`, which
    /// the wire cannot represent; it never reached a release, and a reader
    /// refuses it by version rather than misreading it.
    pub const MIN_SUPPORTED_VERSION: u32 = 2;

    /// Size of the SHA-256 checksum appended to the wire format.
    pub const CHECKSUM_LEN: usize = 32;

    const HEADER_LEN: usize = 16;

    /// The version these exact contents are written at.
    ///
    /// Derived from the contents, as a snapshot's version is: a frame that
    /// carries collaboration needs the version 3 body, and every other frame
    /// keeps the version 2 body byte for byte. So a store stays readable by a
    /// version 2 reader until it holds its first collaboration frame, and a
    /// version 2 reader refuses that frame by version rather than misreading
    /// it.
    pub fn wire_version(&self) -> u32 {
        if self.collaboration.is_empty() {
            Self::MIN_SUPPORTED_VERSION
        } else {
            Self::CURRENT_VERSION
        }
    }

    /// Logical generation of the successor this frame produces.
    pub fn generation(&self) -> Generation {
        self.operation.roots_after.generation
    }

    /// Logical generation of the state this frame extends.
    pub fn base_generation(&self) -> Generation {
        self.operation.roots_before.generation
    }

    /// Whether `data` starts like a frame. Cheap enough to classify a journal
    /// entry before deciding which decoder owns it.
    pub fn is_frame_bytes(data: &[u8]) -> bool {
        data.len() >= 4 && data[0..4] == Self::MAGIC
    }

    /// Serialize the frame with header and SHA-256 checksum.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KinDbError> {
        let body = rmp_serde::to_vec(self).map_err(|error| {
            KinDbError::StorageError(format!("authority frame serialization failed: {error}"))
        })?;
        let mut buf = Vec::with_capacity(Self::HEADER_LEN + body.len() + Self::CHECKSUM_LEN);
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&self.wire_version().to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend_from_slice(&body);
        let hash = Sha256::digest(&body);
        buf.extend_from_slice(&hash);
        Ok(buf)
    }

    /// Validate the header and body checksum and return the body slice.
    ///
    /// Storage uses this to refuse a frame it cannot vouch for without decoding
    /// its body; recovery decodes the returned body afterwards.
    pub fn verify_frame_bytes(data: &[u8]) -> Result<&[u8], KinDbError> {
        Self::verified_version_and_body(data).map(|(_, body)| body)
    }

    /// The header's declared version and the checksummed body.
    fn verified_version_and_body(data: &[u8]) -> Result<(u32, &[u8]), KinDbError> {
        if data.len() < Self::HEADER_LEN {
            return Err(KinDbError::StorageError(
                "authority frame too small for header".to_string(),
            ));
        }
        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(KinDbError::StorageError(format!(
                "invalid authority frame magic bytes: expected KNAF, got {magic:?}"
            )));
        }
        let version = u32::from_le_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| KinDbError::SliceConversionError("version bytes".to_string()))?,
        );
        if version > Self::CURRENT_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported authority frame version: {version} (this kin-db reads versions {} to {}); \
                 a newer kin-db wrote it, so open this store with a kin built on a kin-db that reads \
                 frame version {version}",
                Self::MIN_SUPPORTED_VERSION,
                Self::CURRENT_VERSION
            )));
        }
        if version < Self::MIN_SUPPORTED_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported authority frame version: {version} (this kin-db reads versions {} to {})",
                Self::MIN_SUPPORTED_VERSION,
                Self::CURRENT_VERSION
            )));
        }
        let body_len = u64::from_le_bytes(
            data[8..16]
                .try_into()
                .map_err(|_| KinDbError::SliceConversionError("body_len bytes".to_string()))?,
        );
        let body_len = usize::try_from(body_len).map_err(|_| {
            KinDbError::StorageError(
                "authority frame header body length overflows usize".to_string(),
            )
        })?;
        let body_end = Self::HEADER_LEN.checked_add(body_len).ok_or_else(|| {
            KinDbError::StorageError(
                "authority frame header body length overflows usize".to_string(),
            )
        })?;
        let checksum_end = body_end.checked_add(Self::CHECKSUM_LEN).ok_or_else(|| {
            KinDbError::StorageError(
                "authority frame header body length overflows usize".to_string(),
            )
        })?;
        if data.len() < checksum_end {
            return Err(KinDbError::StorageError(
                "authority frame truncated".to_string(),
            ));
        }
        if data.len() > checksum_end {
            return Err(KinDbError::StorageError(
                "authority frame carries trailing bytes past its checksum".to_string(),
            ));
        }
        let body = &data[Self::HEADER_LEN..body_end];
        let stored_hash = &data[body_end..checksum_end];
        let computed_hash = Sha256::digest(body);
        if stored_hash != computed_hash.as_slice() {
            return Err(KinDbError::StorageError(
                "authority frame checksum mismatch: file is corrupted".to_string(),
            ));
        }
        Ok((version, body))
    }

    /// Deserialize a frame from bytes with header and checksum validation.
    ///
    /// The header must declare the version the decoded contents are written
    /// at, so a frame has exactly one legal encoding: a version 2 header over
    /// a body that carries collaboration, or a version 3 header over one that
    /// carries none, is refused rather than read.
    pub fn from_bytes(data: &[u8]) -> Result<Self, KinDbError> {
        let (declared, body) = Self::verified_version_and_body(data)?;
        let frame: Self = rmp_serde::from_slice(body).map_err(|error| {
            KinDbError::StorageError(format!("authority frame deserialization failed: {error}"))
        })?;
        if frame.wire_version() != declared {
            return Err(KinDbError::StorageError(format!(
                "authority frame declares version {declared} but its contents are written at \
                 version {}; a frame is version {} exactly when it carries collaboration records",
                frame.wire_version(),
                Self::CURRENT_VERSION
            )));
        }
        frame.validate_shape()?;
        Ok(frame)
    }

    fn validate_shape(&self) -> Result<(), KinDbError> {
        self.operation.validate().map_err(|error| {
            KinDbError::StorageError(format!(
                "authority frame carries an invalid operation record: {error}"
            ))
        })?;
        if self.operation.repository_id != self.repository_id {
            return Err(KinDbError::StorageError(format!(
                "authority frame for repository {} carries an operation of repository {}",
                self.repository_id, self.operation.repository_id
            )));
        }
        let expected_generation = self.base_generation().checked_add(1).ok_or_else(|| {
            KinDbError::StorageError("authority frame generation exhausted".to_string())
        })?;
        if self.generation() != expected_generation {
            return Err(KinDbError::StorageError(format!(
                "authority frame moves generation {} to {}, not to its successor",
                self.base_generation(),
                self.generation()
            )));
        }
        require_sorted_unique_by(&self.changes, |change| change.id, "frame changes")?;
        require_sorted_unique_by(
            &self.admission_policies,
            |policy| policy.change_id,
            "frame admission policies",
        )?;
        require_sorted_unique_by(
            &self.external_objects,
            |record| record.object,
            "frame external objects",
        )?;
        require_sorted_unique_by(&self.aliases, |alias| alias.oid, "frame aliases")?;
        require_sorted_unique_by(
            &self.workspaces,
            |workspace| workspace.workspace_id,
            "frame workspaces",
        )?;
        self.collaboration.validate_shape()?;
        Ok(())
    }

    /// Encode the mutation that carried `current` to `next` as the frame the
    /// writer may persist, proven from its own wire bytes.
    ///
    /// This is the only way to obtain a [`ProvenFrame`], and it returns one
    /// only after the frame has been drained, serialized, decoded back from
    /// exactly the bytes that will be persisted, applied to a copy of
    /// `current` with the reader's own [`apply`](Self::apply), and compared
    /// with `next` collection by collection. A frame the wire cannot carry, or
    /// a drain that misses a mutation, is refused here, and the caller persists
    /// a full snapshot instead.
    ///
    /// Both snapshots must carry a repository authority envelope, and `next`
    /// must be the immediate successor of `current`. This computes no diff over
    /// the store: new changes are found by probing the successor's change ids
    /// against the base, and every sorted envelope sequence is walked once
    /// against its base counterpart.
    pub(crate) fn encode_proven(
        current: &GraphSnapshot,
        next: &GraphSnapshot,
    ) -> Result<ProvenFrame, KinDbError> {
        let mut timer = PublicationPhaseTimer::start();
        #[allow(unused_mut)]
        let mut frame = Self::drain(current, next)?;
        #[cfg(test)]
        if let Some(tamper) = take_drained_frame_tamper() {
            tamper(&mut frame);
        }
        let drain_ms = timer.lap_ms();
        let bytes = frame.to_bytes()?;
        let serialize_ms = timer.lap_ms();
        Self::from_bytes(&bytes)?.prove_reproduces(current, next)?;
        let self_check_ms = timer.lap_ms();
        Ok(ProvenFrame {
            bytes,
            drain_ms,
            serialize_ms,
            self_check_ms,
        })
    }

    /// The proven frame decoded from its bytes, for tests that inspect what
    /// the writer built.
    #[cfg(test)]
    pub(crate) fn encode(
        current: &GraphSnapshot,
        next: &GraphSnapshot,
    ) -> Result<Self, KinDbError> {
        Self::from_bytes(Self::encode_proven(current, next)?.bytes())
    }

    /// The writer's proof, run over this frame's own wire bytes, for tests
    /// that build or alter a frame by hand and need the proof's verdict.
    #[cfg(test)]
    pub(crate) fn prove_from_own_bytes(
        &self,
        current: &GraphSnapshot,
        next: &GraphSnapshot,
    ) -> Result<(), KinDbError> {
        Self::from_bytes(&self.to_bytes()?)?.prove_reproduces(current, next)
    }

    /// Drain the mutation into a frame without proving reproduction.
    fn drain(current: &GraphSnapshot, next: &GraphSnapshot) -> Result<Self, KinDbError> {
        let base = current.repository_authority.as_ref().ok_or_else(|| {
            KinDbError::StorageError(
                "authority frame base carries no repository authority envelope".to_string(),
            )
        })?;
        let successor = next.repository_authority.as_ref().ok_or_else(|| {
            KinDbError::StorageError(
                "authority frame successor carries no repository authority envelope".to_string(),
            )
        })?;
        if successor.repository_id != base.repository_id {
            return Err(KinDbError::StorageError(format!(
                "authority frame successor belongs to repository {}, base to {}",
                successor.repository_id, base.repository_id
            )));
        }
        if successor.schema_version != base.schema_version {
            return Err(KinDbError::StorageError(format!(
                "authority frame successor envelope schema {} differs from base schema {}",
                successor.schema_version, base.schema_version
            )));
        }
        let operation = successor.operation_log.last().cloned().ok_or_else(|| {
            KinDbError::StorageError(
                "authority frame successor carries no operation record".to_string(),
            )
        })?;
        if operation.roots_before != base.roots {
            return Err(KinDbError::StorageError(
                "authority frame successor's last operation does not start from the base roots"
                    .to_string(),
            ));
        }
        if operation.roots_after != successor.roots {
            return Err(KinDbError::StorageError(
                "authority frame successor's last operation does not end at the successor roots"
                    .to_string(),
            ));
        }

        let mut changes = Vec::new();
        for id in next.changes.change_ids()? {
            if !current.changes.contains_change(&id) {
                changes.push(next.changes.read_change(&id)?.ok_or_else(|| {
                    KinDbError::StorageError(format!("successor change {id} is missing"))
                })?);
            }
        }
        changes.sort_by_key(|change| change.id);
        let mut new_change_ids: Vec<_> = changes.iter().map(|change| change.id).collect();
        new_change_ids.sort_unstable();
        let admission_policies = successor
            .admission_policies
            .iter()
            .filter(|policy| new_change_ids.binary_search(&policy.change_id).is_ok())
            .cloned()
            .collect();
        let external_objects = absent_from_base(
            &base.external_objects,
            &successor.external_objects,
            |record| record.object,
        );
        let aliases = absent_from_base(&base.aliases, &successor.aliases, |alias| alias.oid);
        let git_external_authority = GitExternalAuthorityPatch::between(
            &base.git_external_authority,
            &successor.git_external_authority,
        );
        let base_workspaces: BTreeMap<_, _> = base
            .workspaces
            .iter()
            .map(|workspace| (workspace.workspace_id, workspace))
            .collect();
        let workspaces = successor
            .workspaces
            .iter()
            .filter(|workspace| base_workspaces.get(&workspace.workspace_id) != Some(workspace))
            .cloned()
            .collect();

        let frame = Self {
            schema_version: successor.schema_version,
            repository_id: successor.repository_id.clone(),
            operation,
            changes,
            admission_policies,
            external_objects,
            aliases,
            git_external_authority,
            ref_state: successor.ref_state.clone(),
            workspaces,
            local_overlays: successor.local_overlays.clone(),
            merge_transactions: successor.merge_transactions.clone(),
            collaboration: CollaborationPatch::drain(current, next)?,
        };
        frame.validate_shape()?;
        Ok(frame)
    }

    /// The writer's own check that the reader's [`apply`](Self::apply)
    /// reconstructs `next` from `current` and this frame.
    ///
    /// The frame is applied to a copy of `current` through the exact reader
    /// code path and the result is compared with `next` whole: every
    /// `GraphSnapshot` collection, not only the ones a frame patches, so a
    /// mutation the drain missed anywhere in the successor is refused here.
    fn prove_reproduces(
        &self,
        current: &GraphSnapshot,
        next: &GraphSnapshot,
    ) -> Result<(), KinDbError> {
        let mut reconstructed = current.clone();
        self.apply(&mut reconstructed)?;
        if let Some(collection) = first_difference(&reconstructed, next)? {
            return Err(KinDbError::StorageError(format!(
                "authority frame for generation {} does not reproduce the successor: {collection} differ; refusing to persist it",
                self.generation()
            )));
        }
        Ok(())
    }

    /// Apply this frame to the state it extends, in place.
    ///
    /// Every refusal here is a corruption or a wrong-base signal, and nothing
    /// is applied when any check fails: the envelope is rebuilt privately and
    /// swapped in only after every collection accepted its patch.
    pub(crate) fn apply(&self, base: &mut GraphSnapshot) -> Result<(), KinDbError> {
        let base_envelope = base.repository_authority.as_ref().ok_or_else(|| {
            KinDbError::StorageError(format!(
                "authority frame for generation {} was applied to a snapshot with no repository authority envelope",
                self.generation()
            ))
        })?;
        for change in &self.changes {
            if base.changes.contains_key(&change.id) {
                return Err(KinDbError::StorageError(format!(
                    "authority frame for generation {} re-adds change {} the base already carries",
                    self.generation(),
                    change.id
                )));
            }
        }
        let envelope = self.apply_to_envelope(base_envelope.clone())?;
        let mut changes = base.changes.clone();
        for change in &self.changes {
            changes.append_change(change.clone())?;
        }
        let change_children = derive_change_children(&changes)?;
        base.changes = changes;
        base.change_children = change_children;
        base.entity_revisions.clear();
        base.repository_authority = Some(envelope);
        // Last, and unable to fail: every check that can refuse this frame
        // has already passed, so a refused frame applies nothing.
        self.collaboration.apply_to(base);
        Ok(())
    }

    /// Apply only this frame's envelope patch, to an envelope read on its own.
    ///
    /// `pub(crate)` for the envelope-only open, which decodes the authority
    /// envelope without the history the same bytes carry and then walks the
    /// acknowledged journal forward onto it.
    ///
    /// What this does NOT do, said here because the difference is the whole
    /// safety argument: [`Self::apply`] additionally refuses a frame that
    /// re-adds a change the base already carries, and it cannot be run here
    /// because an envelope-only read holds no change map to compare against.
    /// That check is about the HISTORY the frame carries, not about the
    /// envelope it patches, so an envelope built here is the same envelope
    /// `apply` would produce; what an envelope-only reader gives up is
    /// noticing that the frame's history half is malformed. A reader that
    /// needs the history opens in full and gets the check.
    ///
    /// Every envelope-level refusal is still here, and the load-bearing one is
    /// `roots_before`: a frame applies only to the exact envelope its operation
    /// names, so a frame walked onto the wrong base refuses rather than
    /// producing a plausible wrong envelope.
    pub(crate) fn apply_to_envelope(
        &self,
        mut envelope: PersistedRepositoryAuthority,
    ) -> Result<PersistedRepositoryAuthority, KinDbError> {
        let generation = self.generation();
        if envelope.repository_id != self.repository_id {
            return Err(KinDbError::StorageError(format!(
                "authority frame for generation {generation} belongs to repository {}, not {}",
                self.repository_id, envelope.repository_id
            )));
        }
        if envelope.schema_version != self.schema_version {
            return Err(KinDbError::StorageError(format!(
                "authority frame for generation {generation} carries envelope schema {}, base carries {}",
                self.schema_version, envelope.schema_version
            )));
        }
        if self.operation.roots_before != envelope.roots {
            return Err(KinDbError::StorageError(format!(
                "authority frame for generation {generation} does not extend the base it was applied to: the base is at generation {}, and its roots differ from the frame's roots_before",
                envelope.roots.generation
            )));
        }
        merge_absent(
            &mut envelope.admission_policies,
            &self.admission_policies,
            |policy| policy.change_id,
            "admission policy",
            generation,
        )?;
        merge_absent(
            &mut envelope.external_objects,
            &self.external_objects,
            |record| record.object,
            "external object",
            generation,
        )?;
        merge_absent(
            &mut envelope.aliases,
            &self.aliases,
            |alias| alias.oid,
            "external alias",
            generation,
        )?;
        self.git_external_authority
            .apply_to(&mut envelope.git_external_authority);
        envelope.ref_state = self.ref_state.clone();
        let mut workspaces: BTreeMap<_, _> = envelope
            .workspaces
            .drain(..)
            .map(|workspace| (workspace.workspace_id, workspace))
            .collect();
        for workspace in &self.workspaces {
            workspaces.insert(workspace.workspace_id, workspace.clone());
        }
        envelope.workspaces = workspaces.into_values().collect();
        envelope.local_overlays = self.local_overlays.clone();
        envelope.merge_transactions = self.merge_transactions.clone();

        let operation = self.operation.clone();
        if envelope
            .receipts
            .iter()
            .any(|receipt| receipt.operation_id == operation.operation_id)
        {
            return Err(KinDbError::StorageError(format!(
                "authority frame for generation {generation} repeats operation {}, which the base already receipts",
                operation.operation_id
            )));
        }
        let receipt = RepositoryCommitReceipt {
            operation_id: operation.operation_id,
            repository_id: operation.repository_id.clone(),
            transaction_hash: operation.transaction_hash,
            outcome: RepositoryCommitOutcome::Committed,
            generation,
            roots_before: operation.roots_before.clone(),
            roots_after: operation.roots_after.clone(),
            operation: operation.clone(),
        };
        receipt.validate().map_err(|error| {
            KinDbError::StorageError(format!(
                "authority frame for generation {generation} derives an invalid receipt: {error}"
            ))
        })?;
        envelope.roots = operation.roots_after.clone();
        // Trimmed, for the reason the commit path trims: the log entry pushed
        // on the line above IS this receipt's operation record (FIR-3064).
        envelope
            .receipts
            .push(crate::storage::repository::PersistedCommitReceipt::trimmed(
                &receipt,
            ));
        envelope.operation_log.push(operation);
        envelope
            .receipts
            .sort_by_key(|receipt| receipt.operation_id);
        // The writer trims every receipt whose operation the log already holds,
        // so the reader does too. This is not an optimization on this side, it
        // is what makes the two sides agree: `prove_reproduces` compares the
        // reconstructed snapshot with the successor through `first_difference`,
        // which compares `repository_authority` by `PartialEq`, so trimming on
        // one side only would make the writer refuse its own frame and rewrite
        // the whole base instead of appending to the journal.
        envelope.trim_receipts_the_log_already_holds();
        Ok(envelope)
    }
}

/// One frame the writer may persist: its exact wire bytes, decoded back from
/// those bytes and proven to reproduce the successor, with the split of the
/// writer-side work that proved it.
///
/// The fields are private and the only constructor is
/// [`AuthorityFrame::encode_proven`], so no caller can hand storage frame
/// bytes the writer has not proven from those same bytes.
pub(crate) struct ProvenFrame {
    bytes: Vec<u8>,
    drain_ms: u128,
    serialize_ms: u128,
    self_check_ms: u128,
}

impl ProvenFrame {
    /// The frame's wire bytes, exactly the bytes the proof decoded.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Milliseconds spent draining the mutation into the frame.
    pub(crate) fn drain_ms(&self) -> u128 {
        self.drain_ms
    }

    /// Milliseconds spent on MessagePack plus the header and checksum.
    pub(crate) fn serialize_ms(&self) -> u128 {
        self.serialize_ms
    }

    /// Milliseconds spent decoding the bytes back, applying the decoded frame
    /// to a copy of the base, and comparing the result with the successor.
    pub(crate) fn self_check_ms(&self) -> u128 {
        self.self_check_ms
    }
}

#[cfg(test)]
thread_local! {
    static DRAINED_FRAME_TAMPER: std::cell::RefCell<Option<Box<dyn FnOnce(&mut AuthorityFrame)>>> =
        const { std::cell::RefCell::new(None) };
}

/// Mutate the next frame the production writer drains on this thread, after
/// it is drained and before it is serialized and proven.
///
/// This is the fault hook that makes the writer's proof falsifiable: a frame
/// tampered here decodes and applies cleanly, so only the proof can tell that
/// it does not reproduce the successor.
#[cfg(test)]
pub(crate) fn tamper_with_next_drained_frame(tamper: impl FnOnce(&mut AuthorityFrame) + 'static) {
    DRAINED_FRAME_TAMPER.with(|slot| *slot.borrow_mut() = Some(Box::new(tamper)));
}

#[cfg(test)]
fn take_drained_frame_tamper() -> Option<Box<dyn FnOnce(&mut AuthorityFrame)>> {
    DRAINED_FRAME_TAMPER.with(|slot| slot.borrow_mut().take())
}

/// Name the first `GraphSnapshot` collection in which `reconstructed` differs
/// from `next`, or `None` when the two are the same state.
///
/// Both snapshots are destructured field by field with no rest pattern, so a
/// collection added to `GraphSnapshot` later does not compile here until this
/// comparison names it. Collections whose element types carry `PartialEq` are
/// compared directly; the others are compared element by element through the
/// MessagePack form a full snapshot would have persisted them in.
pub(crate) fn first_difference(
    reconstructed: &GraphSnapshot,
    next: &GraphSnapshot,
) -> Result<Option<&'static str>, KinDbError> {
    let GraphSnapshot {
        // Bound and not compared, for the same reason `materialized_graph` is
        // below and downstream of it. The version a snapshot declares is a pure
        // function of whether it carries a section, and a frame deliberately
        // carries none, so a reconstruction is v13 while a successor that
        // stamped one is v14. Comparing the version here would compare the
        // derived form of a field this function has already decided not to
        // compare, and it would refuse every frame written after the first
        // section, which is a refusal about the frame format rather than about
        // the successor it is checking.
        version: _,
        entities,
        relations,
        outgoing,
        incoming,
        changes,
        change_children,
        work_items,
        annotations,
        work_links,
        reviews,
        review_decisions,
        review_notes,
        review_discussions,
        review_assignments,
        test_cases,
        assertions,
        verification_runs,
        mock_hints,
        contracts,
        actors,
        delegations,
        approvals,
        audit_events,
        shallow_files,
        file_layouts,
        structured_artifacts,
        opaque_artifacts,
        resolved_tree,
        sessions,
        intents,
        downstream_warnings,
        entity_revisions,
        repository_authority,
        external_references,
        // Bound and not compared, and this is the one binding here that costs
        // something, so the reason is written out. A frame does not carry the
        // materialized graph: it is a resolution of the history at one change,
        // the frame's job is to move the history by O(change), and carrying a
        // whole resolved graph per frame is the cost that unit exists to
        // avoid. So a frame-reconstructed snapshot keeps the base's section
        // while `next` may carry a newer one, and requiring them equal would
        // refuse every frame after the first section is written.
        //
        // Ignoring it is safe for a reason no other field here can claim: a
        // section is trusted only when its `resolved_at` equals the change the
        // reader wants, and a change id is a Merkle hash over its own deltas
        // and parents. So an older section is either still exactly the right
        // answer or is refused at read time. The worst a missed mutation costs
        // here is a replay, never a wrong graph.
        materialized_graph: _,
    } = reconstructed;
    let GraphSnapshot {
        version: _,
        entities: next_entities,
        relations: next_relations,
        outgoing: next_outgoing,
        incoming: next_incoming,
        changes: next_changes,
        change_children: next_change_children,
        work_items: next_work_items,
        annotations: next_annotations,
        work_links: next_work_links,
        reviews: next_reviews,
        review_decisions: next_review_decisions,
        review_notes: next_review_notes,
        review_discussions: next_review_discussions,
        review_assignments: next_review_assignments,
        test_cases: next_test_cases,
        assertions: next_assertions,
        verification_runs: next_verification_runs,
        mock_hints: next_mock_hints,
        contracts: next_contracts,
        actors: next_actors,
        delegations: next_delegations,
        approvals: next_approvals,
        audit_events: next_audit_events,
        shallow_files: next_shallow_files,
        file_layouts: next_file_layouts,
        structured_artifacts: next_structured_artifacts,
        opaque_artifacts: next_opaque_artifacts,
        resolved_tree: next_resolved_tree,
        sessions: next_sessions,
        intents: next_intents,
        downstream_warnings: next_downstream_warnings,
        entity_revisions: next_entity_revisions,
        repository_authority: next_repository_authority,
        external_references: next_external_references,
        materialized_graph: _,
    } = next;
    let checks = [
        ("entities", entities == next_entities),
        ("relations", relations == next_relations),
        ("outgoing adjacency", outgoing == next_outgoing),
        ("incoming adjacency", incoming == next_incoming),
        ("changes", same_changes(changes, next_changes)?),
        ("change children", change_children == next_change_children),
        (
            "work items",
            same_serialized_map(work_items, next_work_items),
        ),
        (
            "annotations",
            same_serialized_map(annotations, next_annotations),
        ),
        ("work links", work_links == next_work_links),
        ("reviews", same_serialized_map(reviews, next_reviews)),
        (
            "review decisions",
            same_serialized_map(review_decisions, next_review_decisions),
        ),
        (
            "review notes",
            same_serialized_seq(review_notes, next_review_notes),
        ),
        (
            "review discussions",
            same_serialized_seq(review_discussions, next_review_discussions),
        ),
        (
            "review assignments",
            same_serialized_map(review_assignments, next_review_assignments),
        ),
        (
            "test cases",
            same_serialized_map(test_cases, next_test_cases),
        ),
        (
            "assertions",
            same_serialized_map(assertions, next_assertions),
        ),
        (
            "verification runs",
            same_serialized_map(verification_runs, next_verification_runs),
        ),
        (
            "mock hints",
            same_serialized_seq(mock_hints, next_mock_hints),
        ),
        ("contracts", same_serialized_map(contracts, next_contracts)),
        ("actors", same_serialized_map(actors, next_actors)),
        (
            "delegations",
            same_serialized_seq(delegations, next_delegations),
        ),
        ("approvals", same_serialized_seq(approvals, next_approvals)),
        (
            "audit events",
            same_serialized_seq(audit_events, next_audit_events),
        ),
        (
            "shallow files",
            same_serialized_seq(shallow_files, next_shallow_files),
        ),
        (
            "file layouts",
            same_serialized_seq(file_layouts, next_file_layouts),
        ),
        (
            "structured artifacts",
            same_serialized_seq(structured_artifacts, next_structured_artifacts),
        ),
        (
            "opaque artifacts",
            same_serialized_seq(opaque_artifacts, next_opaque_artifacts),
        ),
        ("resolved trees", resolved_tree == next_resolved_tree),
        ("sessions", same_serialized_map(sessions, next_sessions)),
        ("intents", same_serialized_map(intents, next_intents)),
        (
            "downstream warnings",
            downstream_warnings == next_downstream_warnings,
        ),
        (
            "entity revisions",
            same_serialized_map(entity_revisions, next_entity_revisions),
        ),
        (
            "repository authority envelopes",
            repository_authority == next_repository_authority,
        ),
        (
            "external references",
            external_references == next_external_references,
        ),
    ];
    Ok(checks
        .into_iter()
        .find_map(|(collection, same)| (!same).then_some(collection)))
}

fn same_changes(left: &super::ChangeMap, right: &super::ChangeMap) -> Result<bool, KinDbError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for id in left.change_ids()? {
        let Some(left_change) = left.read_change(&id)? else {
            return Ok(false);
        };
        if right.read_change(&id)?.as_ref() != Some(&left_change) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn same_serialized<T: Serialize>(left: &T, right: &T) -> bool {
    match (rmp_serde::to_vec(left), rmp_serde::to_vec(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn same_serialized_seq<T: Serialize>(left: &[T], right: &[T]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| same_serialized(left, right))
}

fn same_serialized_map<K: Eq + Hash, V: Serialize>(
    left: &HashMap<K, V>,
    right: &HashMap<K, V>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(key, value)| {
            right
                .get(key)
                .is_some_and(|other| same_serialized(value, other))
        })
}

/// Successor entries whose key is absent from the sorted, unique base
/// sequence, in the successor's order.
fn absent_from_base<T: Clone, K: Ord>(
    base: &[T],
    successor: &[T],
    key: impl Fn(&T) -> K,
) -> Vec<T> {
    let base_keys: Vec<K> = base.iter().map(&key).collect();
    successor
        .iter()
        .filter(|entry| base_keys.binary_search(&key(entry)).is_err())
        .cloned()
        .collect()
}

/// The successor entries whose key the base does not hold, or holds with
/// another value, sorted strictly by the key's MessagePack encoding.
///
/// A base key the successor no longer holds is a removal. No collaboration
/// delta can make one and no frame can carry one, so it is refused by name
/// rather than dropped, and the writer persists that successor whole.
fn keyed_changes<K, V>(
    base: &HashMap<K, V>,
    successor: &HashMap<K, V>,
    label: &str,
) -> Result<Vec<(K, V)>, KinDbError>
where
    K: Copy + Eq + Hash + Serialize + std::fmt::Debug,
    V: Clone + PartialEq,
{
    if let Some(removed) = base.keys().find(|key| !successor.contains_key(*key)) {
        return Err(KinDbError::StorageError(format!(
            "authority frame cannot carry a successor that no longer holds {label} {removed:?}; \
             a frame only adds or replaces collaboration records"
        )));
    }
    let mut changed = Vec::new();
    for (key, value) in successor {
        if base.get(key) != Some(value) {
            changed.push((encoded_key(key)?, *key, value.clone()));
        }
    }
    changed.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(changed
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .collect())
}

/// The successor's records past every record of the base, in the successor's
/// order.
///
/// The base must be exactly the successor's prefix. A record the successor
/// dropped, rewrote or moved is not something appending reproduces, so it is
/// refused by name rather than papered over.
fn appended_records<T: Clone + PartialEq>(
    base: &[T],
    successor: &[T],
    label: &str,
) -> Result<Vec<T>, KinDbError> {
    match successor.get(..base.len()) {
        Some(prefix) if prefix == base => Ok(successor[base.len()..].to_vec()),
        _ => Err(KinDbError::StorageError(format!(
            "authority frame cannot carry a successor whose {label} records are not the base's \
             records followed by new ones; a frame only appends collaboration records"
        ))),
    }
}

/// The canonical order of a collaboration key: its MessagePack encoding.
fn encoded_key<K: Serialize>(key: &K) -> Result<Vec<u8>, KinDbError> {
    rmp_serde::to_vec(key).map_err(|error| {
        KinDbError::StorageError(format!(
            "authority frame collaboration key serialization failed: {error}"
        ))
    })
}

/// Replace or insert every carried value under its key.
fn upsert<K: Copy + Eq + Hash, V: Clone>(target: &mut HashMap<K, V>, entries: &[(K, V)]) {
    for (key, value) in entries {
        target.insert(*key, value.clone());
    }
}

/// Refuse keyed entries that are not strictly increasing by encoded key.
fn require_keyed_order<K: Serialize, V>(entries: &[(K, V)], label: &str) -> Result<(), KinDbError> {
    let mut previous: Option<Vec<u8>> = None;
    for (key, _) in entries {
        let current = encoded_key(key)?;
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Err(KinDbError::StorageError(format!(
                "authority {label} are not in canonical unique order"
            )));
        }
        previous = Some(current);
    }
    Ok(())
}

/// Merge sorted, unique `incoming` into sorted, unique `existing`, refusing any
/// key the base already carries.
fn merge_absent<T: Clone, K: Ord + std::fmt::Debug>(
    existing: &mut Vec<T>,
    incoming: &[T],
    key: impl Fn(&T) -> K,
    label: &str,
    generation: Generation,
) -> Result<(), KinDbError> {
    if incoming.is_empty() {
        return Ok(());
    }
    let mut merged: BTreeMap<K, T> = existing
        .drain(..)
        .map(|entry| (key(&entry), entry))
        .collect();
    for entry in incoming {
        let entry_key = key(entry);
        if merged.contains_key(&entry_key) {
            return Err(KinDbError::StorageError(format!(
                "authority frame for generation {generation} re-adds {label} {entry_key:?}, which the base already carries"
            )));
        }
        merged.insert(entry_key, entry.clone());
    }
    *existing = merged.into_values().collect();
    Ok(())
}

fn require_sorted_unique_by<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    label: &str,
) -> Result<(), KinDbError> {
    let mut previous: Option<K> = None;
    for value in values {
        let current = key(value);
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Err(KinDbError::StorageError(format!(
                "authority {label} are not in canonical unique order"
            )));
        }
        previous = Some(current);
    }
    Ok(())
}

/// Digest that names an authority head reconstructed from one full snapshot
/// and an ordered chain of acknowledged frames.
///
/// It is the SHA-256 over the base digest followed by every acknowledged frame
/// digest in generation order, each as its raw 32 bytes. Journal-free
/// authority is named by the base digest alone, so this is only ever computed
/// when at least one frame is acknowledged.
pub fn journal_sha256(
    snapshot_sha256: &str,
    frame_sha256s: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<String, KinDbError> {
    let mut hasher = Sha256::new();
    hasher.update(decode_digest(snapshot_sha256, "snapshot")?);
    for frame in frame_sha256s {
        hasher.update(decode_digest(frame.as_ref(), "authority frame")?);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn decode_digest(hex_digest: &str, label: &str) -> Result<[u8; 32], KinDbError> {
    let bytes = hex::decode(hex_digest).map_err(|error| {
        KinDbError::StorageError(format!("{label} digest {hex_digest} is not hex: {error}"))
    })?;
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        KinDbError::StorageError(format!("{label} digest {hex_digest} is not 32 bytes"))
    })
}

/// The frame exactly as kin-db 0.7.112 declared it: twelve positional fields
/// under a version 2 header.
///
/// Kept verbatim (the registry's 0.7.112 `authority_frame.rs` is the file this
/// revision started from) so a test can hold every frame this binary writes
/// without collaboration byte-identical to what that release writes for the
/// same successor, which is what keeps such a store readable by it.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyFrameV2 {
    pub schema_version: u32,
    pub repository_id: RepositoryId,
    pub operation: RepositoryOperationRecord,
    pub changes: Vec<SemanticChange>,
    pub admission_policies: Vec<ChangeAdmissionPolicy>,
    pub external_objects: Vec<ExternalObjectRecord>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub git_external_authority: GitExternalAuthorityPatch,
    pub ref_state: RepositoryRefState,
    pub workspaces: Vec<WorkspaceState>,
    pub local_overlays: Vec<FrozenLocalOverlay>,
    pub merge_transactions: Vec<MergeTransactionRecord>,
}

#[cfg(test)]
impl LegacyFrameV2 {
    /// Every field of `frame` except the collaboration patch it cannot hold.
    pub(crate) fn from_frame(frame: &AuthorityFrame) -> Self {
        Self {
            schema_version: frame.schema_version,
            repository_id: frame.repository_id.clone(),
            operation: frame.operation.clone(),
            changes: frame.changes.clone(),
            admission_policies: frame.admission_policies.clone(),
            external_objects: frame.external_objects.clone(),
            aliases: frame.aliases.clone(),
            git_external_authority: frame.git_external_authority.clone(),
            ref_state: frame.ref_state.clone(),
            workspaces: frame.workspaces.clone(),
            local_overlays: frame.local_overlays.clone(),
            merge_transactions: frame.merge_transactions.clone(),
        }
    }

    /// The bytes 0.7.112's `AuthorityFrame::to_bytes` writes for this frame.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let body = rmp_serde::to_vec(self).expect("a legacy frame serializes");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"KNAF");
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend_from_slice(&body);
        buf.extend_from_slice(&Sha256::digest(&body));
        buf
    }
}

#[cfg(test)]
impl CollaborationPatch {
    /// How many entries this patch carries in the collection named `name`,
    /// one of [`Self::COLLECTIONS`]. Panics on any other name, so a table
    /// driven by the collaboration model's list stops on a collection the
    /// patch does not have.
    pub(crate) fn len_of(&self, name: &str) -> usize {
        match name {
            "work_items" => self.work_items.len(),
            "annotations" => self.annotations.len(),
            "work_links" => self.work_links.len(),
            "reviews" => self.reviews.len(),
            "review_decisions" => self.review_decisions.len(),
            "review_notes" => self.review_notes.len(),
            "review_discussions" => self.review_discussions.len(),
            "review_assignments" => self.review_assignments.len(),
            "test_cases" => self.test_cases.len(),
            "assertions" => self.assertions.len(),
            "verification_runs" => self.verification_runs.len(),
            "mock_hints" => self.mock_hints.len(),
            "contracts" => self.contracts.len(),
            "actors" => self.actors.len(),
            "delegations" => self.delegations.len(),
            "approvals" => self.approvals.len(),
            "audit_events" => self.audit_events.len(),
            other => panic!("the collaboration patch has no collection named {other}"),
        }
    }

    /// Drop every entry of the collection named `name`; panics like
    /// [`Self::len_of`].
    pub(crate) fn clear(&mut self, name: &str) {
        match name {
            "work_items" => self.work_items.clear(),
            "annotations" => self.annotations.clear(),
            "work_links" => self.work_links.clear(),
            "reviews" => self.reviews.clear(),
            "review_decisions" => self.review_decisions.clear(),
            "review_notes" => self.review_notes.clear(),
            "review_discussions" => self.review_discussions.clear(),
            "review_assignments" => self.review_assignments.clear(),
            "test_cases" => self.test_cases.clear(),
            "assertions" => self.assertions.clear(),
            "verification_runs" => self.verification_runs.clear(),
            "mock_hints" => self.mock_hints.clear(),
            "contracts" => self.contracts.clear(),
            "actors" => self.actors.clear(),
            "delegations" => self.delegations.clear(),
            "approvals" => self.approvals.clear(),
            "audit_events" => self.audit_events.clear(),
            other => panic!("the collaboration patch has no collection named {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exhaustiveness guard. The patch names exactly the collections the
    /// collaboration model has, in its fold order, and its own fields are
    /// those names. A collection the model gains without a patch field goes
    /// red on the first assertion, a patch field renamed or dropped on the
    /// second. The destructuring below is the compiler's half: it names every
    /// field of the model's delta with no rest pattern, so an eighteenth
    /// field stops this module compiling until someone looks here.
    #[test]
    fn the_patch_carries_every_collection_the_collaboration_model_has() {
        assert_eq!(
            CollaborationPatch::COLLECTIONS,
            kin_model::COLLABORATION_COLLECTIONS,
            "the frame's collaboration patch and the collaboration model name different \
             collections; give the patch a field, a drain arm and an apply arm for each"
        );
        let named = serde_json::to_value(CollaborationPatch::default()).unwrap();
        let mut fields: Vec<&str> = named
            .as_object()
            .expect("the patch serializes as a map of its fields")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        let mut expected = kin_model::COLLABORATION_COLLECTIONS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            fields, expected,
            "the patch's fields are not the collections it names"
        );
        let empty = CollaborationPatch::default();
        for name in kin_model::COLLABORATION_COLLECTIONS {
            assert_eq!(empty.len_of(name), 0, "{name}");
        }
        let kin_model::CollaborationDelta {
            work_items: _,
            annotations: _,
            work_links: _,
            reviews: _,
            review_decisions: _,
            review_notes: _,
            review_discussions: _,
            review_assignments: _,
            test_cases: _,
            assertions: _,
            verification_runs: _,
            mock_hints: _,
            contracts: _,
            actors: _,
            delegations: _,
            approvals: _,
            audit_events: _,
        } = kin_model::CollaborationDelta::default();
    }

    /// A version outside the ones this binary reads is refused before any
    /// body is decoded, and a frame too new to read says what to do about it.
    #[test]
    fn frame_versions_outside_the_supported_range_refuse_by_name() {
        let body = b"never decoded";
        for (version, needle) in [
            (1, "this kin-db reads versions 2 to 3"),
            (
                AuthorityFrame::CURRENT_VERSION + 1,
                "a newer kin-db wrote it, so open this store with a kin built on a kin-db that \
                 reads frame version 4",
            ),
        ] {
            let mut bytes = frame_bytes_from(body);
            bytes[4..8].copy_from_slice(&u32::to_le_bytes(version));
            let error = AuthorityFrame::verify_frame_bytes(&bytes)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("unsupported authority frame version") && error.contains(needle),
                "version {version}: {error}"
            );
        }
        for version in [
            AuthorityFrame::MIN_SUPPORTED_VERSION,
            AuthorityFrame::CURRENT_VERSION,
        ] {
            let mut bytes = frame_bytes_from(body);
            bytes[4..8].copy_from_slice(&version.to_le_bytes());
            assert_eq!(AuthorityFrame::verify_frame_bytes(&bytes).unwrap(), body);
        }
    }

    fn frame_bytes_from(body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&AuthorityFrame::MAGIC);
        buf.extend_from_slice(&AuthorityFrame::CURRENT_VERSION.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(&Sha256::digest(body));
        buf
    }

    #[test]
    fn frame_bytes_are_verified_before_any_body_is_decoded() {
        let body = b"not a frame body, and never decoded here";
        let bytes = frame_bytes_from(body);
        assert_eq!(AuthorityFrame::verify_frame_bytes(&bytes).unwrap(), body);
        assert!(AuthorityFrame::is_frame_bytes(&bytes));

        let mut wrong_magic = bytes.clone();
        wrong_magic[0..4].copy_from_slice(b"KNDD");
        assert!(!AuthorityFrame::is_frame_bytes(&wrong_magic));
        let error = AuthorityFrame::verify_frame_bytes(&wrong_magic).unwrap_err();
        assert!(
            error.to_string().contains("invalid authority frame magic"),
            "{error}"
        );

        let mut future_version = bytes.clone();
        future_version[4..8].copy_from_slice(&(AuthorityFrame::CURRENT_VERSION + 1).to_le_bytes());
        let error = AuthorityFrame::verify_frame_bytes(&future_version).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported authority frame version"),
            "{error}"
        );

        let truncated = &bytes[..bytes.len() - 5];
        let error = AuthorityFrame::verify_frame_bytes(truncated).unwrap_err();
        assert!(error.to_string().contains("truncated"), "{error}");

        let mut trailing = bytes.clone();
        trailing.push(0);
        let error = AuthorityFrame::verify_frame_bytes(&trailing).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"), "{error}");

        let mut flipped = bytes.clone();
        flipped[20] ^= 0x01;
        let error = AuthorityFrame::verify_frame_bytes(&flipped).unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"), "{error}");

        let mut overflowing = bytes.clone();
        overflowing[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let error = AuthorityFrame::verify_frame_bytes(&overflowing).unwrap_err();
        assert!(
            error.to_string().contains("overflows") || error.to_string().contains("truncated"),
            "{error}"
        );

        assert!(AuthorityFrame::verify_frame_bytes(&bytes[..10]).is_err());
    }

    #[test]
    fn a_verified_frame_with_an_undecodable_body_still_refuses() {
        let bytes = frame_bytes_from(b"\xc1");
        let error = AuthorityFrame::from_bytes(&bytes).unwrap_err();
        assert!(
            error.to_string().contains("deserialization failed"),
            "{error}"
        );
    }

    /// The removal patch exists because a nested `Option` cannot say
    /// "cleared" on this wire: `Some(None)` and `None` are one nil byte each
    /// and decode as `None`. The unit-shaped variants of the patch encode
    /// distinctly and come back as themselves; the `Set` variant is exercised
    /// with a real Git authority by the repository tests.
    #[test]
    fn a_nested_option_cannot_carry_a_removal_but_the_patch_can() {
        let nested_removed = rmp_serde::to_vec(&Some(None::<u32>)).unwrap();
        let nested_unchanged = rmp_serde::to_vec(&None::<Option<u32>>).unwrap();
        assert_eq!(nested_removed, nested_unchanged, "both are one nil byte");
        let decoded: Option<Option<u32>> = rmp_serde::from_slice(&nested_removed).unwrap();
        assert_eq!(decoded, None, "the removal decodes as unchanged");

        let unchanged = rmp_serde::to_vec(&GitExternalAuthorityPatch::Unchanged).unwrap();
        let cleared = rmp_serde::to_vec(&GitExternalAuthorityPatch::Cleared).unwrap();
        assert_ne!(unchanged, cleared);
        assert_eq!(
            rmp_serde::from_slice::<GitExternalAuthorityPatch>(&unchanged).unwrap(),
            GitExternalAuthorityPatch::Unchanged
        );
        assert_eq!(
            rmp_serde::from_slice::<GitExternalAuthorityPatch>(&cleared).unwrap(),
            GitExternalAuthorityPatch::Cleared
        );

        assert_eq!(
            GitExternalAuthorityPatch::between(&None, &None),
            GitExternalAuthorityPatch::Unchanged
        );
    }

    #[test]
    fn the_journal_digest_is_ordered_and_binds_the_base() {
        let base = hex::encode(Sha256::digest(b"base"));
        let first = hex::encode(Sha256::digest(b"frame one"));
        let second = hex::encode(Sha256::digest(b"frame two"));
        let chain = journal_sha256(&base, [&first, &second]).unwrap();
        assert_eq!(chain, journal_sha256(&base, [&first, &second]).unwrap());
        assert_ne!(chain, journal_sha256(&base, [&second, &first]).unwrap());
        assert_ne!(chain, journal_sha256(&base, [&first]).unwrap());
        assert_ne!(
            chain,
            journal_sha256(
                &hex::encode(Sha256::digest(b"other base")),
                [&first, &second]
            )
            .unwrap()
        );
        assert!(journal_sha256("not hex", [&first]).is_err());
        assert!(journal_sha256(&base, ["abcd"]).is_err());
    }
}
