// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable merge-transaction authority.
//!
//! A three-way merge that composes cleanly publishes in one repository
//! transaction and needs no record. A merge that does not compose has, until
//! now, had nowhere to live: the conflict set existed only in the composing
//! process, so an interrupted or partially resolved merge could not be graph
//! truth and was refused whole rather than parked.
//!
//! This module is where such a merge lives. The record binds both parents and
//! their single base, the exact pre-merge workspace it must be able to restore,
//! and one entry per conflicting identity carrying both sides, the base, and
//! that entry's resolution. It terminates by publishing a merge change or by
//! aborting back to the recorded restore point.
//!
//! Two properties are structural rather than conventional. Sides are bound by
//! content digest and recovered from the bound changes, so a resolution that
//! claims to take a side can be checked against history instead of trusted. And
//! the record carries its own identity hash, so a persistence layer that folds
//! it into an authority root cannot accept one that was not built here.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::{
    identity::canonical_json_bytes, ArtifactId, AuthorId, EffectiveAdmissionPolicyStamp, Entity,
    EntityId, GraphNodeId, Hash256, LocatedEntry, ModelError, OperationId, RefName, RefTarget,
    Relation, RelationId, RepoPath, RepositoryId, ResolvedArtifact, Result, SemanticChangeId,
    Timestamp, WorkspaceHead, WorkspaceId,
};

/// Durable merge-transaction schema. Version 1 is the first shape: repository
/// authority before it had no merge record at all, so there is nothing to
/// decode compatibly.
pub const MERGE_TRANSACTION_SCHEMA_VERSION: u32 = 1;

/// Which of the three-way inputs a value or resolution refers to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MergeSide {
    /// The single merge base both branches descend from.
    Base,
    /// The branch being merged into, which is the merge change's first parent.
    Ours,
    /// The branch being merged in.
    Theirs,
}

/// The exact identity one conflict is reported and resolved against.
///
/// Identity is never a path for artifacts: they carry a stable `ArtifactId`, so
/// a move on one side against an edit on the other is still one artifact. The
/// `Path` variant is a different thing entirely, a contested location rather
/// than a contested value.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema, Hash,
)]
#[serde(tag = "subject", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeConflictSubject {
    Entity {
        entity: EntityId,
    },
    Relation {
        relation: RelationId,
    },
    Artifact {
        artifact: ArtifactId,
    },
    /// Both sides placed distinct artifacts at one repository path. Every
    /// per-artifact three-way was clean; the composed tree is not.
    Path {
        path: RepoPath,
    },
}

impl MergeConflictSubject {
    /// Whether a resolution payload of this kind can settle this subject.
    fn accepts(&self, payload: &MergeResolutionPayload) -> bool {
        matches!(
            (self, payload),
            (Self::Entity { .. }, MergeResolutionPayload::Entity(_))
                | (Self::Relation { .. }, MergeResolutionPayload::Relation(_))
                | (Self::Artifact { .. }, MergeResolutionPayload::Artifact(_))
                | (Self::Path { .. }, MergeResolutionPayload::PathOwner { .. })
                | (_, MergeResolutionPayload::Removed)
        )
    }
}

/// Why one identity failed to compose, typed rather than described.
///
/// The daemon renders these into refusal and listing prose. A durable record a
/// command reads back must not carry that prose as its only classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "divergence", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeDivergence {
    /// Present in the base and moved to different values on both sides.
    ChangedBothSides,
    /// Absent from the base and added independently with different values.
    AddedBothSides,
    /// Changed on the branch being merged into, removed on the source branch.
    ChangedOursRemovedTheirs,
    /// Removed on the branch being merged into, changed on the source branch.
    RemovedOursChangedTheirs,
    /// Distinct surviving artifacts claim one repository path.
    PathCollision { artifacts: Vec<ArtifactId> },
    /// A surviving relation points at a node neither composed side kept.
    DanglingEndpoint { endpoint: GraphNodeId },
}

/// One side's value, bound by content rather than embedded.
///
/// `Present` carries a domain-separated digest of the exact value that side
/// holds. The value itself stays in history, recoverable by resolving the graph
/// at the change this record binds for that side, so the record never becomes a
/// second, drifting copy of graph truth. A consumer settling an entry by taking
/// a side re-materializes the value and checks it against this digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "value", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeSideValue {
    /// The identity does not exist on this side.
    Absent,
    Present {
        content: Hash256,
    },
}

impl MergeSideValue {
    pub fn entity(value: Option<&Entity>) -> Result<Self> {
        Self::from_value(b"kin-merge-side-entity-v1\0", value)
    }

    pub fn relation(value: Option<&Relation>) -> Result<Self> {
        Self::from_value(b"kin-merge-side-relation-v1\0", value)
    }

    pub fn artifact(value: Option<&ResolvedArtifact>) -> Result<Self> {
        Self::from_value(b"kin-merge-side-artifact-v1\0", value)
    }

    fn from_value(domain: &[u8], value: Option<&impl Serialize>) -> Result<Self> {
        match value {
            None => Ok(Self::Absent),
            Some(value) => Ok(Self::Present {
                content: hash_canonical(domain, value)?,
            }),
        }
    }

    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }
}

/// An explicitly authored resolution value.
///
/// Taking a side covers every case where one of the three inputs is the answer,
/// including removal when that side is absent. A payload is for the rest: a
/// value neither side holds, a contested path's owner, and removal when no side
/// is absent, which is what a dangling endpoint leaves behind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "payload", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeResolutionPayload {
    /// The identity does not survive the merge.
    Removed,
    Entity(Box<Entity>),
    Relation(Box<Relation>),
    Artifact(LocatedEntry),
    /// This artifact keeps the contested path. Every other claimant is settled
    /// through its own entry.
    PathOwner {
        artifact: ArtifactId,
    },
}

/// Who settled an entry, when, and through which repository transaction.
///
/// `operation_id` is the load-bearing field: it ties the resolution to one
/// committed transaction in the operation log, so the chain from an open merge
/// to each of its resolutions is auditable without trusting the record's own
/// account of itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeResolutionProvenance {
    pub actor: AuthorId,
    pub operation_id: OperationId,
    pub resolved_at: Timestamp,
}

impl MergeResolutionProvenance {
    pub fn validate(&self) -> Result<()> {
        if self.operation_id.as_uuid().is_nil() {
            return Err(ModelError::InvalidOperation(
                "merge resolution provenance operation id must not be nil".to_string(),
            ));
        }
        if self.actor.0.trim().is_empty() {
            return Err(ModelError::InvalidOperation(
                "merge resolution provenance requires an actor".to_string(),
            ));
        }
        Ok(())
    }
}

/// How one conflicting identity has been settled, if it has.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "resolution", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeEntryResolution {
    /// Nothing has settled this entry. `kin conflicts` lists exactly these.
    Unresolved,
    /// Settled by binding one side's exact value, which may be absent.
    Side {
        side: MergeSide,
        provenance: MergeResolutionProvenance,
    },
    /// Settled by an explicitly authored value.
    Payload {
        payload: MergeResolutionPayload,
        provenance: MergeResolutionProvenance,
    },
}

impl MergeEntryResolution {
    pub const fn is_resolved(&self) -> bool {
        !matches!(self, Self::Unresolved)
    }

    fn provenance(&self) -> Option<&MergeResolutionProvenance> {
        match self {
            Self::Unresolved => None,
            Self::Side { provenance, .. } | Self::Payload { provenance, .. } => Some(provenance),
        }
    }
}

/// One conflicting identity, its three inputs, and its resolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeConflictEntry {
    pub subject: MergeConflictSubject,
    pub divergence: MergeDivergence,
    pub base: MergeSideValue,
    pub ours: MergeSideValue,
    pub theirs: MergeSideValue,
    /// Qualified name, file, or path at whichever side still carries the
    /// identity, so a listing is actionable. Identity stays the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub resolution: MergeEntryResolution,
}

impl MergeConflictEntry {
    /// Fail closed on an entry that does not describe a real conflict.
    ///
    /// A record whose entries can disagree with the composition that produced
    /// them is worse than no record: a consumer would settle conflicts that the
    /// merge never had, or miss ones it did.
    pub fn validate(&self) -> Result<()> {
        // Two of the four conflict producers are not value divergences at all,
        // so the sides mean something different in each case and are checked
        // separately rather than under one rule.
        match &self.divergence {
            MergeDivergence::ChangedBothSides => {
                self.require_sides(true, true, "changed on both sides")?;
                self.require_sides_differ()?;
                if !self.base.is_present() {
                    return Err(ModelError::InvalidOperation(
                        "a merge conflict changed on both sides must exist at the base".to_string(),
                    ));
                }
            }
            MergeDivergence::AddedBothSides => {
                self.require_sides(true, true, "added on both sides")?;
                self.require_sides_differ()?;
                if self.base.is_present() {
                    return Err(ModelError::InvalidOperation(
                        "a merge conflict added on both sides must be absent at the base"
                            .to_string(),
                    ));
                }
            }
            MergeDivergence::ChangedOursRemovedTheirs => {
                self.require_sides(true, false, "changed here and removed there")?;
            }
            MergeDivergence::RemovedOursChangedTheirs => {
                self.require_sides(false, true, "removed here and changed there")?;
            }
            MergeDivergence::PathCollision { artifacts } => {
                if !matches!(self.subject, MergeConflictSubject::Path { .. }) {
                    return Err(ModelError::InvalidOperation(
                        "a path collision must be reported against a path subject".to_string(),
                    ));
                }
                let unique: BTreeSet<_> = artifacts.iter().collect();
                if unique.len() != artifacts.len() {
                    return Err(ModelError::InvalidOperation(
                        "a path collision repeats an artifact".to_string(),
                    ));
                }
                if artifacts.len() < 2 {
                    return Err(ModelError::InvalidOperation(
                        "a path collision requires at least two distinct artifacts".to_string(),
                    ));
                }
                // A contested path has no value on any side: every claiming
                // artifact composed cleanly on its own, and two of them can
                // legitimately hold identical content. The claimants above are
                // the whole of the conflict, so a side digest here would be
                // decoration a caller could put anything into.
                if self.base.is_present() || self.ours.is_present() || self.theirs.is_present() {
                    return Err(ModelError::InvalidOperation(
                        "a contested path is described by its claimants, not by side values"
                            .to_string(),
                    ));
                }
            }
            MergeDivergence::DanglingEndpoint { .. } => {
                if !matches!(self.subject, MergeConflictSubject::Relation { .. }) {
                    return Err(ModelError::InvalidOperation(
                        "a dangling endpoint must be reported against a relation subject"
                            .to_string(),
                    ));
                }
                // The relation itself composed cleanly; what broke is the node
                // it points at. Both sides therefore agree far more often than
                // not, and requiring them to differ would make this conflict
                // unrecordable.
                if !self.ours.is_present() && !self.theirs.is_present() {
                    return Err(ModelError::InvalidOperation(
                        "a dangling endpoint requires a relation that survived on a side"
                            .to_string(),
                    ));
                }
            }
        }
        if matches!(self.subject, MergeConflictSubject::Path { .. })
            != matches!(self.divergence, MergeDivergence::PathCollision { .. })
        {
            return Err(ModelError::InvalidOperation(
                "a path subject and a path collision must be reported together".to_string(),
            ));
        }
        if let Some(label) = &self.label {
            if label.trim().is_empty() {
                return Err(ModelError::InvalidOperation(
                    "a merge conflict label must not be blank".to_string(),
                ));
            }
        }
        match &self.resolution {
            MergeEntryResolution::Unresolved => {}
            MergeEntryResolution::Side { side, provenance } => {
                provenance.validate()?;
                if *side == MergeSide::Base && !self.base.is_present() {
                    return Err(ModelError::InvalidOperation(
                        "a merge entry cannot take an absent base side".to_string(),
                    ));
                }
                if matches!(self.subject, MergeConflictSubject::Path { .. }) {
                    return Err(ModelError::InvalidOperation(
                        "a contested path has no side to take; resolve it with an owner"
                            .to_string(),
                    ));
                }
            }
            MergeEntryResolution::Payload {
                payload,
                provenance,
            } => {
                provenance.validate()?;
                if !self.subject.accepts(payload) {
                    return Err(ModelError::InvalidOperation(
                        "merge resolution payload does not match its conflict subject".to_string(),
                    ));
                }
                if let (
                    MergeConflictSubject::Path { .. },
                    MergeResolutionPayload::PathOwner { artifact },
                ) = (&self.subject, payload)
                {
                    if let MergeDivergence::PathCollision { artifacts } = &self.divergence {
                        if !artifacts.contains(artifact) {
                            return Err(ModelError::InvalidOperation(
                                "a contested path must be kept by one of its claimants".to_string(),
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn require_sides(&self, ours: bool, theirs: bool, label: &str) -> Result<()> {
        if self.ours.is_present() != ours || self.theirs.is_present() != theirs {
            return Err(ModelError::InvalidOperation(format!(
                "a merge conflict {label} does not match the sides it records"
            )));
        }
        Ok(())
    }

    /// Composition decides by whole value, so two sides that agree are not a
    /// conflict. Only value divergences are held to this.
    fn require_sides_differ(&self) -> Result<()> {
        if self.ours == self.theirs {
            return Err(ModelError::InvalidOperation(
                "a merge conflict requires both sides to differ".to_string(),
            ));
        }
        Ok(())
    }

    /// Whether two entries describe the same conflict, ignoring resolution.
    ///
    /// Resolving a merge settles entries; it never restates what the conflict
    /// was. Anything else would let a resolution quietly rewrite the merge it
    /// claims to be resolving.
    fn describes_same_conflict(&self, other: &Self) -> bool {
        self.subject == other.subject
            && self.divergence == other.divergence
            && self.base == other.base
            && self.ours == other.ours
            && self.theirs == other.theirs
            && self.label == other.label
    }
}

/// The transaction that opened this merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeOpening {
    pub operation_id: OperationId,
    pub actor: AuthorId,
    pub opened_at: Timestamp,
}

/// Both parents, their single base, and the refs they were resolved from.
///
/// The merge change this record terminates in carries ordered parents with
/// `ours_change` first, which is what history replay validates, so the binding
/// records that order rather than leaving it to the publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeParentBinding {
    /// Active branch, which the merge publishes into.
    pub target_ref: RefName,
    /// Branch being merged in.
    pub source_ref: RefName,
    pub base_change: SemanticChangeId,
    pub ours_change: SemanticChangeId,
    pub theirs_change: SemanticChangeId,
    /// Exact resolved target of `target_ref` when the merge opened, which the
    /// terminating transaction compare-and-swaps against.
    pub ours_target: RefTarget,
    pub theirs_target: RefTarget,
}

impl MergeParentBinding {
    pub fn validate(&self) -> Result<()> {
        if !self.target_ref.is_branch() || !self.source_ref.is_branch() {
            return Err(ModelError::InvalidOperation(
                "a merge binds two branches below refs/heads/".to_string(),
            ));
        }
        if self.target_ref == self.source_ref {
            return Err(ModelError::InvalidOperation(
                "a merge cannot bind one branch as both sides".to_string(),
            ));
        }
        if self.ours_change == self.theirs_change {
            return Err(ModelError::InvalidOperation(
                "a merge cannot bind one change as both parents".to_string(),
            ));
        }
        if self.base_change == self.ours_change || self.base_change == self.theirs_change {
            return Err(ModelError::InvalidOperation(
                "a merge whose base is one of its parents composes without conflicts and needs no \
                 record"
                    .to_string(),
            ));
        }
        for (label, target) in [("ours", &self.ours_target), ("theirs", &self.theirs_target)] {
            if matches!(target, RefTarget::Symbolic { .. }) {
                return Err(ModelError::InvalidOperation(format!(
                    "merge {label} target must be resolved, not symbolic"
                )));
            }
        }
        Ok(())
    }
}

/// The exact workspace an abort must restore.
///
/// These are the fields a `WorkspaceExpectation::MustEqual` compares, captured
/// before the merge moved anything. Abort is not "undo whatever happened"; it
/// is "prove the workspace equals this again".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeWorkspaceRestorePoint {
    pub generation: u64,
    pub head: WorkspaceHead,
    pub base_target: Option<RefTarget>,
    pub base_tree_hash: Option<Hash256>,
    pub tree_hash: Hash256,
    pub semantic_overlay_hash: Hash256,
    pub admission_policy: EffectiveAdmissionPolicyStamp,
}

impl MergeWorkspaceRestorePoint {
    pub fn validate(&self) -> Result<()> {
        if self.base_target.is_some() != self.base_tree_hash.is_some() {
            return Err(ModelError::InvalidOperation(
                "merge restore point base target and base tree must both be present or absent"
                    .to_string(),
            ));
        }
        match &self.head {
            WorkspaceHead::Symbolic { target } => {
                if !target.is_branch() {
                    return Err(ModelError::InvalidOperation(
                        "merge restore point symbolic head must name a branch".to_string(),
                    ));
                }
            }
            WorkspaceHead::Detached { .. } => {
                return Err(ModelError::InvalidOperation(
                    "a merge publishes into the active branch and cannot restore a detached head"
                        .to_string(),
                ))
            }
        }
        Ok(())
    }
}

/// How a merge ended, or that it has not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeTransactionState {
    /// Conflicts remain, or every entry is settled but the merge change has not
    /// been published yet. This is the only state whose entries may change.
    InProgress,
    /// Published as this merge change, whose ordered parents are the binding's
    /// `ours_change` then `theirs_change`.
    Committed {
        merge_change: SemanticChangeId,
        operation_id: OperationId,
        committed_at: Timestamp,
    },
    /// Abandoned, with the workspace proven equal to the recorded restore point.
    Aborted {
        operation_id: OperationId,
        actor: AuthorId,
        aborted_at: Timestamp,
    },
}

impl MergeTransactionState {
    pub const fn is_in_progress(&self) -> bool {
        matches!(self, Self::InProgress)
    }

    pub const fn is_terminal(&self) -> bool {
        !self.is_in_progress()
    }
}

/// A merge that could not compose, held as graph truth until it terminates.
///
/// At most one record exists per workspace. A terminal record is retained as
/// the durable account of the last merge on that workspace and is replaced when
/// the next merge opens, so "is a merge in progress" is a state check rather
/// than an existence check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeTransactionRecord {
    pub schema_version: u32,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub opened: MergeOpening,
    pub binding: MergeParentBinding,
    pub restore: MergeWorkspaceRestorePoint,
    /// One entry per conflicting identity, in canonical subject order.
    pub entries: Vec<MergeConflictEntry>,
    pub state: MergeTransactionState,
    /// Identity over every field above. A persistence layer recomputes it, so a
    /// record assembled outside this type cannot be accepted.
    pub hash: Hash256,
}

#[derive(Serialize)]
struct MergeTransactionIdentity<'a> {
    schema_version: u32,
    repository_id: &'a RepositoryId,
    workspace_id: WorkspaceId,
    opened: &'a MergeOpening,
    binding: &'a MergeParentBinding,
    restore: &'a MergeWorkspaceRestorePoint,
    entries: &'a [MergeConflictEntry],
    state: &'a MergeTransactionState,
}

impl MergeTransactionRecord {
    /// Open a merge that did not compose, from its conflict set.
    ///
    /// Entries are sorted into canonical subject order here rather than trusted
    /// to arrive that way, so two composers that found the same conflicts in a
    /// different order produce the same record and the same identity.
    pub fn open(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        opened: MergeOpening,
        binding: MergeParentBinding,
        restore: MergeWorkspaceRestorePoint,
        mut entries: Vec<MergeConflictEntry>,
    ) -> Result<Self> {
        entries.sort_by(|left, right| left.subject.cmp(&right.subject));
        let mut record = Self {
            schema_version: MERGE_TRANSACTION_SCHEMA_VERSION,
            repository_id,
            workspace_id,
            opened,
            binding,
            restore,
            entries,
            state: MergeTransactionState::InProgress,
            hash: Hash256::from_bytes([0; 32]),
        };
        record.hash = record.identity_hash()?;
        record.validate()?;
        Ok(record)
    }

    /// Settle one entry, returning the successor record.
    ///
    /// The conflict itself is carried through untouched; only its resolution
    /// moves. Settling an unknown subject fails rather than appending a
    /// conflict the merge never found.
    pub fn resolve_entry(
        &self,
        subject: &MergeConflictSubject,
        resolution: MergeEntryResolution,
    ) -> Result<Self> {
        if !self.state.is_in_progress() {
            return Err(ModelError::InvalidOperation(
                "a terminated merge transaction cannot resolve further entries".to_string(),
            ));
        }
        let mut next = self.clone();
        let entry = next
            .entries
            .iter_mut()
            .find(|entry| &entry.subject == subject)
            .ok_or_else(|| {
                ModelError::InvalidOperation(
                    "merge transaction has no conflict for that subject".to_string(),
                )
            })?;
        entry.resolution = resolution;
        next.hash = next.identity_hash()?;
        next.validate()?;
        Ok(next)
    }

    /// Terminate the merge, returning the successor record.
    pub fn terminate(&self, state: MergeTransactionState) -> Result<Self> {
        if !self.state.is_in_progress() {
            return Err(ModelError::InvalidOperation(
                "a merge transaction terminates once".to_string(),
            ));
        }
        let mut next = self.clone();
        next.state = state;
        next.hash = next.identity_hash()?;
        next.validate()?;
        Ok(next)
    }

    pub fn identity_hash(&self) -> Result<Hash256> {
        hash_canonical(
            b"kin-merge-transaction-v1\0",
            &MergeTransactionIdentity {
                schema_version: self.schema_version,
                repository_id: &self.repository_id,
                workspace_id: self.workspace_id,
                opened: &self.opened,
                binding: &self.binding,
                restore: &self.restore,
                entries: &self.entries,
                state: &self.state,
            },
        )
    }

    /// Entries no resolution has settled. This is what `kin conflicts` lists.
    pub fn unresolved(&self) -> impl Iterator<Item = &MergeConflictEntry> {
        self.entries
            .iter()
            .filter(|entry| !entry.resolution.is_resolved())
    }

    pub fn is_fully_resolved(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.resolution.is_resolved())
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != MERGE_TRANSACTION_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported merge transaction schema version {}",
                self.schema_version
            )));
        }
        if self.opened.operation_id.as_uuid().is_nil() {
            return Err(ModelError::InvalidOperation(
                "merge transaction opening operation id must not be nil".to_string(),
            ));
        }
        if self.opened.actor.0.trim().is_empty() {
            return Err(ModelError::InvalidOperation(
                "merge transaction requires an opening actor".to_string(),
            ));
        }
        self.binding.validate()?;
        self.restore.validate()?;
        if let WorkspaceHead::Symbolic { target } = &self.restore.head {
            if target != &self.binding.target_ref {
                return Err(ModelError::InvalidOperation(
                    "merge restore point head does not match the branch the merge publishes into"
                        .to_string(),
                ));
            }
        }
        if self.restore.base_target.as_ref() != Some(&self.binding.ours_target) {
            return Err(ModelError::InvalidOperation(
                "merge restore point base target does not match the recorded first parent"
                    .to_string(),
            ));
        }
        if self.entries.is_empty() {
            return Err(ModelError::InvalidOperation(
                "a merge transaction record requires at least one conflict".to_string(),
            ));
        }
        let mut previous: Option<&MergeConflictSubject> = None;
        for entry in &self.entries {
            entry.validate()?;
            if previous.is_some_and(|last| last >= &entry.subject) {
                return Err(ModelError::InvalidOperation(
                    "merge transaction entries are not in canonical unique subject order"
                        .to_string(),
                ));
            }
            previous = Some(&entry.subject);
        }
        match &self.state {
            MergeTransactionState::InProgress => {}
            MergeTransactionState::Committed {
                merge_change: _,
                operation_id,
                ..
            } => {
                if operation_id.as_uuid().is_nil() {
                    return Err(ModelError::InvalidOperation(
                        "a committed merge transaction requires its publishing operation"
                            .to_string(),
                    ));
                }
                if !self.is_fully_resolved() {
                    return Err(ModelError::InvalidOperation(
                        "a merge transaction cannot commit with unresolved conflicts".to_string(),
                    ));
                }
            }
            MergeTransactionState::Aborted {
                operation_id,
                actor,
                ..
            } => {
                if operation_id.as_uuid().is_nil() {
                    return Err(ModelError::InvalidOperation(
                        "an aborted merge transaction requires its aborting operation".to_string(),
                    ));
                }
                if actor.0.trim().is_empty() {
                    return Err(ModelError::InvalidOperation(
                        "an aborted merge transaction requires an actor".to_string(),
                    ));
                }
            }
        }
        let computed = self.identity_hash()?;
        if computed != self.hash {
            return Err(ModelError::InvalidOperation(format!(
                "merge transaction hash {} recomputes to {}",
                self.hash, computed
            )));
        }
        Ok(())
    }
}

/// Exact, self-inverting transition of one workspace's merge record.
///
/// `new: None` drops the record outright, which the local-overlay delta this
/// follows deliberately refuses for itself. A workspace may legitimately end up
/// with no merge history; it may never end up with no admission overlay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MergeTransactionDelta {
    pub old: Option<MergeTransactionRecord>,
    pub new: Option<MergeTransactionRecord>,
}

impl MergeTransactionDelta {
    /// Open a merge on a workspace that has no record.
    pub fn open(new: MergeTransactionRecord) -> Self {
        Self {
            old: None,
            new: Some(new),
        }
    }

    /// Advance an existing record, whether by resolving or by terminating.
    pub fn update(old: MergeTransactionRecord, new: MergeTransactionRecord) -> Self {
        Self {
            old: Some(old),
            new: Some(new),
        }
    }

    /// Drop a workspace's merge record entirely.
    pub fn drop_record(old: MergeTransactionRecord) -> Self {
        Self {
            old: Some(old),
            new: None,
        }
    }

    pub fn inverse(&self) -> Self {
        Self {
            old: self.new.clone(),
            new: self.old.clone(),
        }
    }

    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        self.new
            .as_ref()
            .or(self.old.as_ref())
            .map(|record| record.workspace_id)
    }

    pub fn validate(&self) -> Result<()> {
        if self.old.is_none() && self.new.is_none() {
            return Err(ModelError::InvalidOperation(
                "merge transaction delta has no old or new record".to_string(),
            ));
        }
        if self.old == self.new {
            return Err(ModelError::InvalidOperation(
                "merge transaction delta is a no-op".to_string(),
            ));
        }
        if let Some(old) = &self.old {
            old.validate()?;
        }
        if let Some(new) = &self.new {
            new.validate()?;
        }
        match (&self.old, &self.new) {
            (None, Some(new)) => {
                if new.state.is_terminal() {
                    return Err(ModelError::InvalidOperation(
                        "a merge transaction cannot be recorded already terminated".to_string(),
                    ));
                }
            }
            (Some(old), Some(new)) => {
                if old.repository_id != new.repository_id || old.workspace_id != new.workspace_id {
                    return Err(ModelError::InvalidOperation(
                        "merge transaction delta changes the repository or workspace it binds"
                            .to_string(),
                    ));
                }
                self.validate_transition(old, new)?;
            }
            (Some(_), None) | (None, None) => {}
        }
        Ok(())
    }

    fn validate_transition(
        &self,
        old: &MergeTransactionRecord,
        new: &MergeTransactionRecord,
    ) -> Result<()> {
        let same_merge =
            old.opened == new.opened && old.binding == new.binding && old.restore == new.restore;
        if old.state.is_terminal() {
            // The previous merge ended, so this can only be the next one
            // opening over it. Continuing a terminated merge, or replacing one
            // terminal record with another, would rewrite settled history.
            if same_merge || new.state.is_terminal() {
                return Err(ModelError::InvalidOperation(
                    "a terminated merge transaction can only be replaced by a new merge"
                        .to_string(),
                ));
            }
            return Ok(());
        }
        if !same_merge {
            return Err(ModelError::InvalidOperation(
                "a merge transaction is already in progress for this workspace".to_string(),
            ));
        }
        if new.entries.len() != old.entries.len()
            || !old
                .entries
                .iter()
                .zip(&new.entries)
                .all(|(left, right)| left.describes_same_conflict(right))
        {
            return Err(ModelError::InvalidOperation(
                "a merge transaction cannot change the conflicts it recorded".to_string(),
            ));
        }
        if matches!(new.state, MergeTransactionState::Committed { .. }) {
            for (left, right) in old.entries.iter().zip(&new.entries) {
                if left.resolution != right.resolution {
                    return Err(ModelError::InvalidOperation(
                        "a merge transaction publishes the resolutions it already recorded; \
                         resolve and commit are separate transactions"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Every operation this delta's resolutions and terminal state name.
    ///
    /// A persistence layer uses this to prove each named operation is one the
    /// repository actually committed, so a resolution cannot cite a transaction
    /// that never happened.
    pub fn referenced_operations(&self) -> Vec<OperationId> {
        let mut operations = BTreeSet::new();
        for record in [self.old.as_ref(), self.new.as_ref()].into_iter().flatten() {
            operations.insert(record.opened.operation_id);
            for entry in &record.entries {
                if let Some(provenance) = entry.resolution.provenance() {
                    operations.insert(provenance.operation_id);
                }
            }
            match &record.state {
                MergeTransactionState::InProgress => {}
                MergeTransactionState::Committed { operation_id, .. }
                | MergeTransactionState::Aborted { operation_id, .. } => {
                    operations.insert(*operation_id);
                }
            }
        }
        operations.into_iter().collect()
    }
}

fn hash_canonical(domain: &[u8], value: &impl Serialize) -> Result<Hash256> {
    let payload = canonical_json_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(payload.len())
            .map_err(|_| {
                ModelError::InvalidOperation("merge identity payload exceeds u64".to_string())
            })?
            .to_le_bytes(),
    );
    hasher.update(payload);
    Ok(Hash256::from_bytes(hasher.finalize().into()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        AdmissionCase, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm,
        FrozenLocalOverlay, LanguageId, SemanticFingerprint, SharedAdmissionPolicy, TreeEntry,
        Visibility,
    };
    use uuid::Uuid;

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp::from(chrono::DateTime::from_timestamp(seconds, 0).unwrap())
    }

    fn change(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn policy(workspace_id: WorkspaceId) -> EffectiveAdmissionPolicyStamp {
        let shared = SharedAdmissionPolicy::empty(0);
        let local =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: local.stamp(),
        }
    }

    fn entity(id: u128, name: &str) -> Entity {
        Entity {
            id: EntityId(Uuid::from_u128(id)),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([id as u8; 32]),
                signature_hash: Hash256::from_bytes([id as u8; 32]),
                behavior_hash: Hash256::from_bytes([id as u8; 32]),
                equivalence_hash: Hash256::from_bytes([id as u8; 32]),
                stability_score: 1.0,
            },
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

    fn provenance(operation: u128) -> MergeResolutionProvenance {
        MergeResolutionProvenance {
            actor: AuthorId::new("resolver"),
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            resolved_at: timestamp(1_700_000_100),
        }
    }

    fn entity_entry() -> MergeConflictEntry {
        MergeConflictEntry {
            subject: MergeConflictSubject::Entity {
                entity: EntityId(Uuid::from_u128(1)),
            },
            divergence: MergeDivergence::ChangedBothSides,
            base: MergeSideValue::entity(Some(&entity(1, "base"))).unwrap(),
            ours: MergeSideValue::entity(Some(&entity(1, "ours"))).unwrap(),
            theirs: MergeSideValue::entity(Some(&entity(1, "theirs"))).unwrap(),
            label: Some("compose in src/merge.rs".to_string()),
            resolution: MergeEntryResolution::Unresolved,
        }
    }

    fn artifact_entry() -> MergeConflictEntry {
        MergeConflictEntry {
            subject: MergeConflictSubject::Artifact {
                artifact: ArtifactId(Uuid::from_u128(2)),
            },
            divergence: MergeDivergence::ChangedOursRemovedTheirs,
            base: MergeSideValue::Present {
                content: Hash256::from_bytes([0x10; 32]),
            },
            ours: MergeSideValue::Present {
                content: Hash256::from_bytes([0x11; 32]),
            },
            theirs: MergeSideValue::Absent,
            label: Some("README.md".to_string()),
            resolution: MergeEntryResolution::Unresolved,
        }
    }

    fn opening() -> MergeOpening {
        MergeOpening {
            operation_id: OperationId::from_uuid(Uuid::from_u128(100)),
            actor: AuthorId::new("merger"),
            opened_at: timestamp(1_700_000_000),
        }
    }

    fn binding() -> MergeParentBinding {
        MergeParentBinding {
            target_ref: RefName::branch(b"main").unwrap(),
            source_ref: RefName::branch(b"feature").unwrap(),
            base_change: change(0x01),
            ours_change: change(0x02),
            theirs_change: change(0x03),
            ours_target: RefTarget::change(change(0x02)),
            theirs_target: RefTarget::change(change(0x03)),
        }
    }

    fn restore(workspace_id: WorkspaceId) -> MergeWorkspaceRestorePoint {
        MergeWorkspaceRestorePoint {
            generation: 4,
            head: WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap(),
            },
            base_target: Some(RefTarget::change(change(0x02))),
            base_tree_hash: Some(Hash256::from_bytes([0x20; 32])),
            tree_hash: Hash256::from_bytes([0x20; 32]),
            semantic_overlay_hash: Hash256::from_bytes([0x21; 32]),
            admission_policy: policy(workspace_id),
        }
    }

    /// A valid open merge record, shared with the repository transaction tests.
    pub(crate) fn sample_record(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
    ) -> MergeTransactionRecord {
        MergeTransactionRecord::open(
            repository_id,
            workspace_id,
            opening(),
            binding(),
            restore(workspace_id),
            vec![artifact_entry(), entity_entry()],
        )
        .unwrap()
    }

    fn record() -> MergeTransactionRecord {
        sample_record(
            RepositoryId::new("repo").unwrap(),
            WorkspaceId::from_uuid(Uuid::from_u128(9)),
        )
    }

    fn resolve_all(record: &MergeTransactionRecord) -> MergeTransactionRecord {
        let mut settled = record.clone();
        for subject in record
            .entries
            .iter()
            .map(|entry| entry.subject.clone())
            .collect::<Vec<_>>()
        {
            settled = settled
                .resolve_entry(
                    &subject,
                    MergeEntryResolution::Side {
                        side: MergeSide::Ours,
                        provenance: provenance(101),
                    },
                )
                .unwrap();
        }
        settled
    }

    #[test]
    fn an_opened_record_is_canonically_ordered_and_self_verifying() {
        let record = record();
        record.validate().unwrap();
        // Entries were supplied artifact-first; identity must not depend on
        // the order a composer happened to find its conflicts in.
        let subjects: Vec<_> = record.entries.iter().map(|entry| &entry.subject).collect();
        let mut sorted = subjects.clone();
        sorted.sort();
        assert_eq!(subjects, sorted);
        assert_eq!(record.unresolved().count(), 2);
        assert!(!record.is_fully_resolved());
        assert!(record.state.is_in_progress());

        let reordered = MergeTransactionRecord::open(
            RepositoryId::new("repo").unwrap(),
            WorkspaceId::from_uuid(Uuid::from_u128(9)),
            opening(),
            binding(),
            restore(WorkspaceId::from_uuid(Uuid::from_u128(9))),
            vec![entity_entry(), artifact_entry()],
        )
        .unwrap();
        assert_eq!(reordered.hash, record.hash);
    }

    #[test]
    fn a_tampered_record_fails_its_own_identity() {
        let mut forged = record();
        forged.entries[0].label = Some("something else".to_string());
        assert!(forged
            .validate()
            .unwrap_err()
            .to_string()
            .contains("recomputes to"));

        // An abort is legal at any resolution state, so a forged one passes
        // every structural rule. Only the identity hash catches it.
        let mut forged_abort = record();
        forged_abort.state = MergeTransactionState::Aborted {
            operation_id: OperationId::from_uuid(Uuid::from_u128(102)),
            actor: AuthorId::new("merger"),
            aborted_at: timestamp(1_700_000_200),
        };
        assert!(forged_abort
            .validate()
            .unwrap_err()
            .to_string()
            .contains("recomputes to"));

        // A forged commit is caught earlier still, because it claims to have
        // settled conflicts the record itself lists as open.
        let mut forged_commit = record();
        forged_commit.state = MergeTransactionState::Committed {
            merge_change: change(0x04),
            operation_id: OperationId::from_uuid(Uuid::from_u128(102)),
            committed_at: timestamp(1_700_000_200),
        };
        assert!(forged_commit
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot commit with unresolved conflicts"));
    }

    #[test]
    fn a_serialized_record_round_trips_exactly() {
        let record = record();
        let json = serde_json::to_string(&record).unwrap();
        let parsed: MergeTransactionRecord = serde_json::from_str(&json).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn an_entry_must_describe_a_real_divergence() {
        let mut agreed = entity_entry();
        agreed.theirs = agreed.ours;
        assert!(agreed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("both sides to differ"));

        let mut absent_base = entity_entry();
        absent_base.base = MergeSideValue::Absent;
        assert!(absent_base
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must exist at the base"));

        let mut added_both = entity_entry();
        added_both.divergence = MergeDivergence::AddedBothSides;
        assert!(added_both
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must be absent at the base"));

        let mut miscounted = artifact_entry();
        miscounted.divergence = MergeDivergence::ChangedBothSides;
        assert!(miscounted
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not match the sides it records"));

        let mut blank = entity_entry();
        blank.label = Some("   ".to_string());
        assert!(blank
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must not be blank"));
    }

    #[test]
    fn a_contested_path_is_resolved_by_owner_and_never_by_taking_a_side() {
        let claimants = vec![
            ArtifactId(Uuid::from_u128(5)),
            ArtifactId(Uuid::from_u128(6)),
        ];
        let mut entry = MergeConflictEntry {
            subject: MergeConflictSubject::Path {
                path: RepoPath::from_bytes(b"src/lib.rs".to_vec()).unwrap(),
            },
            divergence: MergeDivergence::PathCollision {
                artifacts: claimants.clone(),
            },
            base: MergeSideValue::Absent,
            ours: MergeSideValue::Absent,
            theirs: MergeSideValue::Absent,
            label: Some("src/lib.rs".to_string()),
            resolution: MergeEntryResolution::Unresolved,
        };
        entry.validate().unwrap();

        // Two artifacts can hold identical content and still contest a path,
        // so side values would be meaningless here and are refused outright.
        let mut with_sides = entry.clone();
        with_sides.ours = MergeSideValue::Present {
            content: Hash256::from_bytes([0x30; 32]),
        };
        assert!(with_sides
            .validate()
            .unwrap_err()
            .to_string()
            .contains("described by its claimants"));

        entry.resolution = MergeEntryResolution::Side {
            side: MergeSide::Ours,
            provenance: provenance(103),
        };
        assert!(entry
            .validate()
            .unwrap_err()
            .to_string()
            .contains("has no side to take"));

        entry.resolution = MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::PathOwner {
                artifact: ArtifactId(Uuid::from_u128(7)),
            },
            provenance: provenance(103),
        };
        assert!(entry
            .validate()
            .unwrap_err()
            .to_string()
            .contains("kept by one of its claimants"));

        entry.resolution = MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::PathOwner {
                artifact: claimants[0],
            },
            provenance: provenance(103),
        };
        entry.validate().unwrap();

        let mut single = entry.clone();
        single.divergence = MergeDivergence::PathCollision {
            artifacts: vec![claimants[0]],
        };
        assert!(single
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least two distinct artifacts"));

        let mut repeated = entry;
        repeated.divergence = MergeDivergence::PathCollision {
            artifacts: vec![claimants[0], claimants[0]],
        };
        assert!(repeated
            .validate()
            .unwrap_err()
            .to_string()
            .contains("repeats an artifact"));
    }

    #[test]
    fn a_subject_only_accepts_a_payload_of_its_own_kind() {
        let mut entry = entity_entry();
        entry.resolution = MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::Artifact(LocatedEntry::new(
                RepoPath::from_bytes(b"src/lib.rs".to_vec()).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([0x40; 32]), false),
            )),
            provenance: provenance(104),
        };
        assert!(entry
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not match its conflict subject"));

        entry.resolution = MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::Entity(Box::new(entity(1, "settled"))),
            provenance: provenance(104),
        };
        entry.validate().unwrap();

        // Removal settles any subject: it is the answer a dangling endpoint
        // leaves when neither side is absent.
        entry.resolution = MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::Removed,
            provenance: provenance(104),
        };
        entry.validate().unwrap();
    }

    #[test]
    fn a_dangling_endpoint_is_recordable_with_both_sides_agreeing() {
        let mut entry = entity_entry();
        entry.divergence = MergeDivergence::DanglingEndpoint {
            endpoint: GraphNodeId::Entity(EntityId(Uuid::from_u128(8))),
        };
        assert!(entry
            .validate()
            .unwrap_err()
            .to_string()
            .contains("against a relation subject"));

        // The relation composed cleanly, which is exactly why both sides hold
        // the same value. Only its endpoint failed to survive.
        let surviving = MergeSideValue::Present {
            content: Hash256::from_bytes([0x50; 32]),
        };
        let mut relation = MergeConflictEntry {
            subject: MergeConflictSubject::Relation {
                relation: RelationId(Uuid::from_u128(3)),
            },
            divergence: MergeDivergence::DanglingEndpoint {
                endpoint: GraphNodeId::Entity(EntityId(Uuid::from_u128(8))),
            },
            base: surviving,
            ours: surviving,
            theirs: surviving,
            label: Some("calls removed_helper".to_string()),
            resolution: MergeEntryResolution::Unresolved,
        };
        relation.validate().unwrap();

        // Settling it means the edge does not survive; no side offers that,
        // because every side still has the edge.
        relation.resolution = MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::Removed,
            provenance: provenance(107),
        };
        relation.validate().unwrap();

        let mut vanished = relation;
        vanished.ours = MergeSideValue::Absent;
        vanished.theirs = MergeSideValue::Absent;
        assert!(vanished
            .validate()
            .unwrap_err()
            .to_string()
            .contains("survived on a side"));
    }

    #[test]
    fn an_absent_base_side_cannot_be_taken() {
        let mut entry = MergeConflictEntry {
            subject: MergeConflictSubject::Entity {
                entity: EntityId(Uuid::from_u128(1)),
            },
            divergence: MergeDivergence::AddedBothSides,
            base: MergeSideValue::Absent,
            ours: MergeSideValue::entity(Some(&entity(1, "ours"))).unwrap(),
            theirs: MergeSideValue::entity(Some(&entity(1, "theirs"))).unwrap(),
            label: None,
            resolution: MergeEntryResolution::Unresolved,
        };
        entry.validate().unwrap();
        entry.resolution = MergeEntryResolution::Side {
            side: MergeSide::Base,
            provenance: provenance(105),
        };
        assert!(entry
            .validate()
            .unwrap_err()
            .to_string()
            .contains("absent base side"));

        // Taking a side that removed the identity is legitimate: it is how a
        // removal is settled without an authored payload.
        let mut removed = artifact_entry();
        removed.resolution = MergeEntryResolution::Side {
            side: MergeSide::Theirs,
            provenance: provenance(105),
        };
        removed.validate().unwrap();
    }

    #[test]
    fn a_binding_refuses_shapes_that_are_not_a_conflicting_merge() {
        let mut same_branch = binding();
        same_branch.source_ref = same_branch.target_ref.clone();
        assert!(same_branch
            .validate()
            .unwrap_err()
            .to_string()
            .contains("both sides"));

        let mut base_is_parent = binding();
        base_is_parent.base_change = base_is_parent.theirs_change;
        assert!(base_is_parent
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs no record"));

        let mut symbolic = binding();
        symbolic.ours_target = RefTarget::Symbolic {
            target: RefName::branch(b"main").unwrap(),
        };
        assert!(symbolic
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must be resolved, not symbolic"));
    }

    #[test]
    fn a_restore_point_binds_the_branch_and_parent_the_merge_publishes_from() {
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(9));
        let mut drifted = restore(workspace_id);
        drifted.head = WorkspaceHead::Symbolic {
            target: RefName::branch(b"other").unwrap(),
        };
        let mut record = record();
        record.restore = drifted;
        record.hash = record.identity_hash().unwrap();
        assert!(record
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not match the branch the merge publishes into"));

        let mut wrong_parent = record.clone();
        wrong_parent.restore = restore(workspace_id);
        wrong_parent.restore.base_target = Some(RefTarget::change(change(0x07)));
        wrong_parent.hash = wrong_parent.identity_hash().unwrap();
        assert!(wrong_parent
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not match the recorded first parent"));

        let mut detached = restore(workspace_id);
        detached.head = WorkspaceHead::Detached {
            target: RefTarget::change(change(0x02)),
        };
        assert!(detached
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot restore a detached head"));
    }

    #[test]
    fn resolving_settles_a_known_subject_and_nothing_else() {
        let record = record();
        let subject = record.entries[0].subject.clone();
        let settled = record
            .resolve_entry(
                &subject,
                MergeEntryResolution::Side {
                    side: MergeSide::Theirs,
                    provenance: provenance(106),
                },
            )
            .unwrap();
        assert_eq!(settled.unresolved().count(), 1);
        assert_ne!(settled.hash, record.hash);

        assert!(record
            .resolve_entry(
                &MergeConflictSubject::Entity {
                    entity: EntityId(Uuid::from_u128(999)),
                },
                MergeEntryResolution::Side {
                    side: MergeSide::Ours,
                    provenance: provenance(106),
                },
            )
            .unwrap_err()
            .to_string()
            .contains("no conflict for that subject"));

        let terminated = resolve_all(&record)
            .terminate(MergeTransactionState::Committed {
                merge_change: change(0x04),
                operation_id: OperationId::from_uuid(Uuid::from_u128(107)),
                committed_at: timestamp(1_700_000_300),
            })
            .unwrap();
        assert!(terminated
            .resolve_entry(
                &subject,
                MergeEntryResolution::Side {
                    side: MergeSide::Ours,
                    provenance: provenance(106),
                },
            )
            .unwrap_err()
            .to_string()
            .contains("cannot resolve further entries"));
        assert!(terminated
            .terminate(MergeTransactionState::Aborted {
                operation_id: OperationId::from_uuid(Uuid::from_u128(108)),
                actor: AuthorId::new("merger"),
                aborted_at: timestamp(1_700_000_400),
            })
            .unwrap_err()
            .to_string()
            .contains("terminates once"));
    }

    #[test]
    fn a_merge_cannot_commit_with_unresolved_conflicts_but_may_abort() {
        let record = record();
        assert!(record
            .terminate(MergeTransactionState::Committed {
                merge_change: change(0x04),
                operation_id: OperationId::from_uuid(Uuid::from_u128(109)),
                committed_at: timestamp(1_700_000_300),
            })
            .unwrap_err()
            .to_string()
            .contains("cannot commit with unresolved conflicts"));

        let aborted = record
            .terminate(MergeTransactionState::Aborted {
                operation_id: OperationId::from_uuid(Uuid::from_u128(110)),
                actor: AuthorId::new("merger"),
                aborted_at: timestamp(1_700_000_400),
            })
            .unwrap();
        aborted.validate().unwrap();
        assert!(aborted.state.is_terminal());
        // Abort keeps the restore point it opened with; that is the whole
        // point of recording one.
        assert_eq!(aborted.restore, record.restore);
    }

    #[test]
    fn a_live_merge_blocks_a_second_merge_on_the_same_workspace() {
        let live = record();
        let mut second = binding();
        second.source_ref = RefName::branch(b"other").unwrap();
        second.theirs_change = change(0x05);
        second.theirs_target = RefTarget::change(change(0x05));
        let competing = MergeTransactionRecord::open(
            live.repository_id.clone(),
            live.workspace_id,
            MergeOpening {
                operation_id: OperationId::from_uuid(Uuid::from_u128(200)),
                actor: AuthorId::new("other"),
                opened_at: timestamp(1_700_000_500),
            },
            second,
            restore(live.workspace_id),
            vec![entity_entry()],
        )
        .unwrap();

        assert!(
            MergeTransactionDelta::update(live.clone(), competing.clone())
                .validate()
                .unwrap_err()
                .to_string()
                .contains("already in progress")
        );

        // The same merge, once terminated, is what makes room for the next one.
        let aborted = live
            .terminate(MergeTransactionState::Aborted {
                operation_id: OperationId::from_uuid(Uuid::from_u128(201)),
                actor: AuthorId::new("merger"),
                aborted_at: timestamp(1_700_000_600),
            })
            .unwrap();
        MergeTransactionDelta::update(aborted.clone(), competing)
            .validate()
            .unwrap();

        assert!(
            MergeTransactionDelta::update(aborted.clone(), aborted.clone())
                .validate()
                .unwrap_err()
                .to_string()
                .contains("no-op")
        );

        let recommitted = aborted.clone();
        assert!(
            MergeTransactionDelta::update(aborted, resolve_all(&live))
                .validate()
                .unwrap_err()
                .to_string()
                .contains("can only be replaced by a new merge"),
            "a terminated merge must not be reopened as itself"
        );
        drop(recommitted);
    }

    #[test]
    fn a_delta_cannot_rewrite_the_conflicts_it_recorded() {
        let live = record();
        let mut rewritten = live.clone();
        rewritten.entries.remove(0);
        rewritten.hash = rewritten.identity_hash().unwrap();
        assert!(MergeTransactionDelta::update(live.clone(), rewritten)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot change the conflicts it recorded"));

        let mut relabelled = live.clone();
        relabelled.entries[0].label = Some("renamed".to_string());
        relabelled.hash = relabelled.identity_hash().unwrap();
        assert!(MergeTransactionDelta::update(live, relabelled)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot change the conflicts it recorded"));
    }

    #[test]
    fn committing_publishes_the_resolutions_already_recorded() {
        let live = record();
        let settled = resolve_all(&live);
        let committed = settled
            .terminate(MergeTransactionState::Committed {
                merge_change: change(0x04),
                operation_id: OperationId::from_uuid(Uuid::from_u128(300)),
                committed_at: timestamp(1_700_000_700),
            })
            .unwrap();
        MergeTransactionDelta::update(settled, committed.clone())
            .validate()
            .unwrap();

        // Settling the last entry and publishing in one step would let a commit
        // introduce a resolution nothing ever listed as pending.
        assert!(MergeTransactionDelta::update(live, committed)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("resolve and commit are separate transactions"));
    }

    #[test]
    fn a_delta_refuses_shapes_that_are_not_a_transition() {
        assert!(MergeTransactionDelta {
            old: None,
            new: None,
        }
        .validate()
        .unwrap_err()
        .to_string()
        .contains("no old or new record"));

        let live = record();
        let born_terminal = live
            .terminate(MergeTransactionState::Aborted {
                operation_id: OperationId::from_uuid(Uuid::from_u128(400)),
                actor: AuthorId::new("merger"),
                aborted_at: timestamp(1_700_000_800),
            })
            .unwrap();
        assert!(MergeTransactionDelta::open(born_terminal.clone())
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot be recorded already terminated"));

        let mut moved = live.clone();
        moved.workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(77));
        moved.hash = moved.identity_hash().unwrap();
        assert!(MergeTransactionDelta::update(live.clone(), moved)
            .validate()
            .unwrap_err()
            .to_string()
            .contains("changes the repository or workspace it binds"));

        MergeTransactionDelta::drop_record(live.clone())
            .validate()
            .unwrap();
        MergeTransactionDelta::open(live.clone())
            .validate()
            .unwrap();
        assert_eq!(
            MergeTransactionDelta::open(live.clone()).workspace_id(),
            Some(live.workspace_id)
        );
        assert_eq!(
            MergeTransactionDelta::open(live.clone()).inverse(),
            MergeTransactionDelta::drop_record(live)
        );
    }

    #[test]
    fn referenced_operations_name_every_transaction_the_record_cites() {
        let live = record();
        let settled = live
            .resolve_entry(
                &live.entries[0].subject,
                MergeEntryResolution::Side {
                    side: MergeSide::Ours,
                    provenance: provenance(500),
                },
            )
            .unwrap();
        let operations = MergeTransactionDelta::update(live, settled).referenced_operations();
        assert!(operations.contains(&OperationId::from_uuid(Uuid::from_u128(100))));
        assert!(operations.contains(&OperationId::from_uuid(Uuid::from_u128(500))));
        assert_eq!(operations.len(), 2);
    }

    #[test]
    fn side_values_agree_exactly_when_their_values_do() {
        let left = MergeSideValue::entity(Some(&entity(1, "same"))).unwrap();
        let right = MergeSideValue::entity(Some(&entity(1, "same"))).unwrap();
        assert_eq!(left, right);
        assert_ne!(
            left,
            MergeSideValue::entity(Some(&entity(1, "different"))).unwrap()
        );
        assert_eq!(
            MergeSideValue::entity(None).unwrap(),
            MergeSideValue::Absent
        );
        assert!(!MergeSideValue::Absent.is_present());

        // Domains are separated, so an entity and a relation that happen to
        // serialize alike are not mistaken for one another.
        let relation_side = MergeSideValue::relation(Some(&Relation {
            id: RelationId(Uuid::from_u128(1)),
            kind: crate::RelationKind::Calls,
            src: GraphNodeId::Entity(EntityId(Uuid::from_u128(1))),
            dst: GraphNodeId::Entity(EntityId(Uuid::from_u128(2))),
            confidence: 1.0,
            origin: crate::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }))
        .unwrap();
        assert_ne!(relation_side, left);
    }
}
