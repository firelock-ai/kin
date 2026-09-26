// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

use crate::admission::AdmissionPolicyDelta;
use crate::entity::Entity;
use crate::external_reference::ExternalReferenceDelta;
use crate::ids::*;
use crate::relation::Relation;
use crate::resolution::ResolutionRecordDelta;
use crate::retrieval::ArtifactId;
use crate::review::RiskSummary;
use crate::timestamp::Timestamp;

/// Kin's native commit, the unit of semantic history.
///
/// Persisted positionally in every snapshot that carries history, so the
/// crate-level positional-wire rule applies: a new field goes last, and only a
/// trailing field may skip serialization.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticChange {
    /// Content-addressed hash.
    pub id: SemanticChangeId,
    /// Native provenance or the exact external commit identity imported.
    pub origin: ChangeOrigin,
    /// Ordered parent list: empty for genesis, one for an ordinary change, and
    /// any number for a merge. Order and repeated parent entries are preserved
    /// exactly for lossless Git commit import.
    pub parents: Vec<SemanticChangeId>,
    pub timestamp: Timestamp,
    /// Human or assistant.
    pub author: AuthorId,
    pub message: String,
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    /// Exact changes to the repository tree, including code, configuration,
    /// documentation, assets, and files in unsupported languages.
    pub tree_deltas: Vec<TreeDelta>,
    /// History-versioned admission policy transition, when the policy changes.
    pub admission_policy_delta: Option<AdmissionPolicyDelta>,
    pub projected_files: Vec<FilePathId>,
    pub spec_link: Option<SpecId>,
    pub evidence: Vec<EvidenceId>,
    pub risk_summary: Option<RiskSummary>,
    /// Exact transitions of first-class external-symbol endpoints.
    ///
    /// Additive for positional-wire compatibility: the hand-written
    /// `Serialize` below omits it when it is empty and nothing after it is
    /// present, and writes it, even empty, whenever resolution records follow.
    /// It declares no serde skip of its own because it is not the last field.
    #[serde(default)]
    pub external_reference_deltas: Vec<ExternalReferenceDelta>,
    /// Exact transitions of resolution records: proof contexts, call-site
    /// ledgers and dispatch sets.
    ///
    /// Deliberately last and omitted when empty, so every change written
    /// before it keeps its exact bytes and its identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_record_deltas: Vec<ResolutionRecordDelta>,
}

/// Positional-wire serialization. Changes persist inside a MessagePack
/// snapshot, where a struct is an array and position decides the mapping, so
/// a trailing field may be omitted only when every field after it is omitted
/// too. `external_reference_deltas` is written, even empty, whenever
/// resolution records follow it; a change carrying neither serializes to the
/// bytes it always did. A name-keyed format omits each empty field on its own,
/// so the JSON a change's identity is computed over is unchanged too.
impl Serialize for SemanticChange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let has_records = !self.resolution_record_deltas.is_empty();
        // Name-keyed formats address a field by name, so each empty field is
        // omitted on its own, exactly as the derive this replaced wrote them.
        // A positional format writes a field whenever a later one follows.
        let has_external = !self.external_reference_deltas.is_empty()
            || (has_records && !serializer.is_human_readable());
        let mut out = serializer.serialize_struct(
            "SemanticChange",
            14 + usize::from(has_external) + usize::from(has_records),
        )?;
        out.serialize_field("id", &self.id)?;
        out.serialize_field("origin", &self.origin)?;
        out.serialize_field("parents", &self.parents)?;
        out.serialize_field("timestamp", &self.timestamp)?;
        out.serialize_field("author", &self.author)?;
        out.serialize_field("message", &self.message)?;
        out.serialize_field("entity_deltas", &self.entity_deltas)?;
        out.serialize_field("relation_deltas", &self.relation_deltas)?;
        out.serialize_field("tree_deltas", &self.tree_deltas)?;
        out.serialize_field("admission_policy_delta", &self.admission_policy_delta)?;
        out.serialize_field("projected_files", &self.projected_files)?;
        out.serialize_field("spec_link", &self.spec_link)?;
        out.serialize_field("evidence", &self.evidence)?;
        out.serialize_field("risk_summary", &self.risk_summary)?;
        if has_external {
            out.serialize_field("external_reference_deltas", &self.external_reference_deltas)?;
        } else {
            out.skip_field("external_reference_deltas")?;
        }
        if has_records {
            out.serialize_field("resolution_record_deltas", &self.resolution_record_deltas)?;
        } else {
            out.skip_field("resolution_record_deltas")?;
        }
        out.end()
    }
}

/// Immutable provenance that participates in semantic-change identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChangeOrigin {
    Native,
    GitCommit { oid: GitObjectId },
}

/// A query projection of a change onto one entity, never a replayable change.
///
/// The original content-addressed identity and ancestry remain exact. Counts
/// describe the original change; only `entity_deltas` is narrowed. Keeping this
/// separate from `SemanticChange` prevents a partial payload from being mistaken
/// for the complete object whose hash is `id`.
#[derive(Debug, Clone, Serialize)]
pub struct EntityHistoryEntry {
    pub id: SemanticChangeId,
    pub origin: ChangeOrigin,
    pub parents: Option<Vec<SemanticChangeId>>,
    pub timestamp: Timestamp,
    pub author: Option<AuthorId>,
    pub message: Option<String>,
    pub metadata_omissions: BTreeMap<String, usize>,
    pub entity_deltas: Option<Vec<EntityDelta>>,
    pub focal_delta_count: usize,
    pub entity_deltas_omitted: usize,
    pub focal_delta_operations: BTreeMap<String, usize>,
    pub entity_delta_count: usize,
    pub relation_delta_count: usize,
    pub tree_delta_count: usize,
    pub external_reference_delta_count: usize,
    pub resolution_record_delta_count: usize,
    pub admission_policy_changed: bool,
    pub projected_file_count: usize,
    pub evidence_count: usize,
    pub risk_summary_present: bool,
    pub spec_link: Option<SpecId>,
}

/// A bounded page and the complete history's lightweight identity.
#[derive(Debug, Clone)]
pub struct EntityHistoryPage {
    pub entries: Vec<EntityHistoryEntry>,
    pub change_count: usize,
    pub latest_change_id: Option<SemanticChangeId>,
}

impl EntityHistoryEntry {
    pub fn for_entity(change: &SemanticChange, id: &EntityId) -> Option<Self> {
        let focal: Vec<_> = change
            .entity_deltas
            .iter()
            .filter(|delta| {
                delta.old_state().is_some_and(|entity| entity.id == *id)
                    || delta.new_state().is_some_and(|entity| entity.id == *id)
            })
            .collect();
        if focal.is_empty() {
            return None;
        }
        // Inspect a borrowed projection before cloning. A huge source preview
        // or metadata value must not be copied into every history page.
        struct SizeLimit(usize);
        impl std::io::Write for SizeLimit {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if bytes.len() > self.0 {
                    return Err(std::io::Error::other("focal history detail limit"));
                }
                self.0 -= bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let include_details = serde_json::to_writer(SizeLimit(12_000), &focal).is_ok();
        let parents_fit = serde_json::to_writer(SizeLimit(12_000), &change.parents).is_ok();
        let mut metadata_omissions = BTreeMap::new();
        if !parents_fit {
            metadata_omissions.insert("parents".into(), change.parents.len());
        }
        if change.author.0.len() > 512 {
            metadata_omissions.insert("author_utf8_bytes".into(), change.author.0.len());
        }
        if change.message.len() > 4096 {
            metadata_omissions.insert("message_utf8_bytes".into(), change.message.len());
        }
        let mut operations = BTreeMap::new();
        for delta in &focal {
            let operation = match delta {
                EntityDelta::Added { .. } => "added",
                EntityDelta::Modified { .. } => "modified",
                EntityDelta::Removed { .. } => "removed",
            };
            *operations.entry(operation.to_string()).or_insert(0) += 1;
        }
        Some(Self {
            id: change.id,
            origin: change.origin,
            parents: parents_fit.then(|| change.parents.clone()),
            timestamp: change.timestamp.clone(),
            author: (change.author.0.len() <= 512).then(|| change.author.clone()),
            message: (change.message.len() <= 4096).then(|| change.message.clone()),
            metadata_omissions,
            entity_deltas: include_details
                .then(|| focal.iter().map(|delta| (**delta).clone()).collect()),
            focal_delta_count: focal.len(),
            entity_deltas_omitted: if include_details { 0 } else { focal.len() },
            focal_delta_operations: operations,
            entity_delta_count: change.entity_deltas.len(),
            relation_delta_count: change.relation_deltas.len(),
            tree_delta_count: change.tree_deltas.len(),
            external_reference_delta_count: change.external_reference_deltas.len(),
            resolution_record_delta_count: change.resolution_record_deltas.len(),
            admission_policy_changed: change.admission_policy_delta.is_some(),
            projected_file_count: change.projected_files.len(),
            evidence_count: change.evidence.len(),
            risk_summary_present: change.risk_summary.is_some(),
            spec_link: change.spec_link,
        })
    }
}

impl SemanticChange {
    pub fn transaction_delta(&self) -> TransactionDelta {
        TransactionDelta {
            entity_deltas: self.entity_deltas.clone(),
            relation_deltas: self.relation_deltas.clone(),
            tree_deltas: self.tree_deltas.clone(),
            admission_policy_delta: self.admission_policy_delta.clone(),
            external_reference_deltas: self.external_reference_deltas.clone(),
            resolution_record_deltas: self.resolution_record_deltas.clone(),
        }
    }
}

/// Delta for a single entity within a SemanticChange.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityDelta {
    Added { new: Entity },
    Modified { old: Entity, new: Entity },
    Removed { old: Entity },
}

impl EntityDelta {
    pub const fn target_id(&self) -> EntityId {
        match self {
            Self::Added { new } | Self::Modified { new, .. } => new.id,
            Self::Removed { old } => old.id,
        }
    }

    pub const fn old_state(&self) -> Option<&Entity> {
        match self {
            Self::Added { .. } => None,
            Self::Modified { old, .. } | Self::Removed { old } => Some(old),
        }
    }

    pub const fn new_state(&self) -> Option<&Entity> {
        match self {
            Self::Added { new } | Self::Modified { new, .. } => Some(new),
            Self::Removed { .. } => None,
        }
    }

    pub fn inverse(&self) -> Self {
        match self {
            Self::Added { new } => Self::Removed { old: new.clone() },
            Self::Modified { old, new } => Self::Modified {
                old: new.clone(),
                new: old.clone(),
            },
            Self::Removed { old } => Self::Added { new: old.clone() },
        }
    }
}

/// Delta for a single relation within a SemanticChange.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationDelta {
    Added { new: Relation },
    Modified { old: Relation, new: Relation },
    Removed { old: Relation },
}

impl RelationDelta {
    pub const fn target_id(&self) -> RelationId {
        match self {
            Self::Added { new } | Self::Modified { new, .. } => new.id,
            Self::Removed { old } => old.id,
        }
    }

    pub const fn old_state(&self) -> Option<&Relation> {
        match self {
            Self::Added { .. } => None,
            Self::Modified { old, .. } | Self::Removed { old } => Some(old),
        }
    }

    pub const fn new_state(&self) -> Option<&Relation> {
        match self {
            Self::Added { new } | Self::Modified { new, .. } => Some(new),
            Self::Removed { .. } => None,
        }
    }

    pub fn inverse(&self) -> Self {
        match self {
            Self::Added { new } => Self::Removed { old: new.clone() },
            Self::Modified { old, new } => Self::Modified {
                old: new.clone(),
                new: old.clone(),
            },
            Self::Removed { old } => Self::Added { new: old.clone() },
        }
    }
}

/// Delta for a batch of transactional graph changes.
///
/// Persisted positionally, so the crate-level positional-wire rule applies: a
/// new field goes last, and only a trailing field may skip serialization.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransactionDelta {
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    pub tree_deltas: Vec<TreeDelta>,
    pub admission_policy_delta: Option<AdmissionPolicyDelta>,
    /// Additive for positional-wire compatibility, and written even empty
    /// whenever resolution records follow it; see the `Serialize` below.
    #[serde(default)]
    pub external_reference_deltas: Vec<ExternalReferenceDelta>,
    /// Exact transitions of resolution records. Deliberately last and omitted
    /// when empty, so a delta without any keeps its exact bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_record_deltas: Vec<ResolutionRecordDelta>,
}

/// Positional-wire serialization, by the rule [`SemanticChange`]'s follows: a
/// trailing field is omitted only when every field after it is omitted too.
impl Serialize for TransactionDelta {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let has_records = !self.resolution_record_deltas.is_empty();
        // Name-keyed formats address a field by name, so each empty field is
        // omitted on its own, exactly as the derive this replaced wrote them.
        // A positional format writes a field whenever a later one follows.
        let has_external = !self.external_reference_deltas.is_empty()
            || (has_records && !serializer.is_human_readable());
        let mut out = serializer.serialize_struct(
            "TransactionDelta",
            4 + usize::from(has_external) + usize::from(has_records),
        )?;
        out.serialize_field("entity_deltas", &self.entity_deltas)?;
        out.serialize_field("relation_deltas", &self.relation_deltas)?;
        out.serialize_field("tree_deltas", &self.tree_deltas)?;
        out.serialize_field("admission_policy_delta", &self.admission_policy_delta)?;
        if has_external {
            out.serialize_field("external_reference_deltas", &self.external_reference_deltas)?;
        } else {
            out.skip_field("external_reference_deltas")?;
        }
        if has_records {
            out.serialize_field("resolution_record_deltas", &self.resolution_record_deltas)?;
        } else {
            out.skip_field("resolution_record_deltas")?;
        }
        out.end()
    }
}

impl TransactionDelta {
    pub fn inverse(&self) -> Self {
        Self {
            entity_deltas: self
                .entity_deltas
                .iter()
                .map(EntityDelta::inverse)
                .collect(),
            relation_deltas: self
                .relation_deltas
                .iter()
                .map(RelationDelta::inverse)
                .collect(),
            tree_deltas: self.tree_deltas.iter().map(TreeDelta::inverse).collect(),
            admission_policy_delta: self
                .admission_policy_delta
                .as_ref()
                .map(AdmissionPolicyDelta::inverse),
            external_reference_deltas: self
                .external_reference_deltas
                .iter()
                .map(ExternalReferenceDelta::inverse)
                .collect(),
            resolution_record_deltas: self
                .resolution_record_deltas
                .iter()
                .map(ResolutionRecordDelta::inverse)
                .collect(),
        }
    }
}

/// Exact materialization of one leaf in the repository tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeEntry {
    Blob {
        hash: Hash256,
        executable: bool,
    },
    /// The referenced blob contains the byte-exact link target.
    Symlink {
        target_blob: Hash256,
    },
    /// A Git submodule pointer. The target need not exist in this repository's
    /// object database.
    Gitlink {
        target: GitObjectId,
    },
}

impl TreeEntry {
    pub const fn blob(hash: Hash256, executable: bool) -> Self {
        Self::Blob { hash, executable }
    }

    pub const fn symlink(target_blob: Hash256) -> Self {
        Self::Symlink { target_blob }
    }

    pub const fn gitlink(target: GitObjectId) -> Self {
        Self::Gitlink { target }
    }

    pub const fn blob_identity(&self) -> Option<Hash256> {
        match self {
            Self::Blob { hash, .. } => Some(*hash),
            Self::Symlink { target_blob } => Some(*target_blob),
            Self::Gitlink { .. } => None,
        }
    }
}

/// One artifact's exact location and materialization at a repository ref.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocatedEntry {
    pub path: RepoPath,
    pub entry: TreeEntry,
}

impl LocatedEntry {
    pub const fn new(path: RepoPath, entry: TreeEntry) -> Self {
        Self { path, entry }
    }
}

/// Exact transition for one stable artifact identity in the repository tree.
///
/// `Updated` covers content edits, mode changes, moves, and move-plus-edit.
/// Paths are locations only; identity is always carried by `artifact_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeDelta {
    Added {
        artifact_id: ArtifactId,
        new: LocatedEntry,
    },
    Updated {
        artifact_id: ArtifactId,
        old: LocatedEntry,
        new: LocatedEntry,
    },
    Removed {
        artifact_id: ArtifactId,
        old: LocatedEntry,
    },
}

impl TreeDelta {
    pub const fn artifact_id(&self) -> ArtifactId {
        match self {
            Self::Added { artifact_id, .. }
            | Self::Updated { artifact_id, .. }
            | Self::Removed { artifact_id, .. } => *artifact_id,
        }
    }

    pub const fn old_state(&self) -> Option<&LocatedEntry> {
        match self {
            Self::Added { .. } => None,
            Self::Updated { old, .. } | Self::Removed { old, .. } => Some(old),
        }
    }

    pub const fn new_state(&self) -> Option<&LocatedEntry> {
        match self {
            Self::Added { new, .. } | Self::Updated { new, .. } => Some(new),
            Self::Removed { .. } => None,
        }
    }

    pub const fn is_added(&self) -> bool {
        matches!(self, Self::Added { .. })
    }

    pub const fn is_updated(&self) -> bool {
        matches!(self, Self::Updated { .. })
    }

    pub const fn is_removed(&self) -> bool {
        matches!(self, Self::Removed { .. })
    }

    pub fn inverse(&self) -> Self {
        match self {
            Self::Added { artifact_id, new } => Self::Removed {
                artifact_id: *artifact_id,
                old: new.clone(),
            },
            Self::Updated {
                artifact_id,
                old,
                new,
            } => Self::Updated {
                artifact_id: *artifact_id,
                old: new.clone(),
                new: old.clone(),
            },
            Self::Removed { artifact_id, old } => Self::Added {
                artifact_id: *artifact_id,
                new: old.clone(),
            },
        }
    }
}

/// One active artifact in a resolved repository tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedArtifact {
    pub artifact_id: ArtifactId,
    pub path: RepoPath,
    pub entry: TreeEntry,
}

impl ResolvedArtifact {
    pub const fn new(artifact_id: ArtifactId, path: RepoPath, entry: TreeEntry) -> Self {
        Self {
            artifact_id,
            path,
            entry,
        }
    }

    pub fn located_entry(&self) -> LocatedEntry {
        LocatedEntry::new(self.path.clone(), self.entry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TreeStateError {
    #[error("artifact {artifact_id:?} occurs more than once in the resolved tree")]
    DuplicateArtifact { artifact_id: ArtifactId },
    #[error("repository path {path} occurs more than once in the resolved tree")]
    DuplicatePath { path: RepoPath },
    #[error("tree transaction contains more than one delta for artifact {artifact_id:?}")]
    DuplicateDelta { artifact_id: ArtifactId },
    #[error("artifact {artifact_id:?} already exists in the parent tree")]
    ArtifactAlreadyExists { artifact_id: ArtifactId },
    #[error("artifact {artifact_id:?} does not exist in the parent tree")]
    ArtifactMissing { artifact_id: ArtifactId },
    #[error("artifact {artifact_id:?} parent state does not match the delta's old location")]
    OldStateMismatch { artifact_id: ArtifactId },
    #[error("artifact {artifact_id:?} update is a no-op")]
    NoopUpdate { artifact_id: ArtifactId },
    #[error("repository path {path} remains occupied after applying the transaction")]
    PathOccupied { path: RepoPath },
}

/// Exact active repository state with mutually validated identity and path
/// indexes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedTree {
    by_id: BTreeMap<ArtifactId, ResolvedArtifact>,
    by_path: BTreeMap<RepoPath, ArtifactId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResolvedTreeWire {
    artifacts: Vec<ResolvedArtifact>,
}

impl ResolvedTree {
    pub fn from_artifacts(
        artifacts: impl IntoIterator<Item = ResolvedArtifact>,
    ) -> Result<Self, TreeStateError> {
        let mut tree = Self::default();
        for artifact in artifacts {
            if tree.by_id.contains_key(&artifact.artifact_id) {
                return Err(TreeStateError::DuplicateArtifact {
                    artifact_id: artifact.artifact_id,
                });
            }
            if tree.by_path.contains_key(&artifact.path) {
                return Err(TreeStateError::DuplicatePath {
                    path: artifact.path,
                });
            }
            tree.by_path
                .insert(artifact.path.clone(), artifact.artifact_id);
            tree.by_id.insert(artifact.artifact_id, artifact);
        }
        Ok(tree)
    }

    pub fn get(&self, artifact_id: &ArtifactId) -> Option<&ResolvedArtifact> {
        self.by_id.get(artifact_id)
    }

    pub fn artifact_id_at_path(&self, path: &RepoPath) -> Option<ArtifactId> {
        self.by_path.get(path).copied()
    }

    pub fn artifact_at_path(&self, path: &RepoPath) -> Option<&ResolvedArtifact> {
        self.artifact_id_at_path(path)
            .and_then(|artifact_id| self.by_id.get(&artifact_id))
    }

    pub fn artifacts(
        &self,
    ) -> impl ExactSizeIterator<Item = &ResolvedArtifact> + DoubleEndedIterator {
        self.by_id.values()
    }

    pub fn artifacts_by_path(
        &self,
    ) -> impl ExactSizeIterator<Item = &ResolvedArtifact> + DoubleEndedIterator {
        self.by_path
            .values()
            .map(|artifact_id| &self.by_id[artifact_id])
    }

    pub fn into_artifacts(
        self,
    ) -> impl ExactSizeIterator<Item = ResolvedArtifact> + DoubleEndedIterator {
        self.by_id.into_values()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Validate all old sides against the same parent state, then apply every
    /// removal before every insertion. This makes swaps and rename cycles
    /// atomic instead of order-dependent.
    pub fn apply(&self, deltas: &[TreeDelta]) -> Result<Self, TreeStateError> {
        let mut touched = BTreeSet::new();
        for delta in deltas {
            let artifact_id = delta.artifact_id();
            if !touched.insert(artifact_id) {
                return Err(TreeStateError::DuplicateDelta { artifact_id });
            }
            match delta {
                TreeDelta::Added { .. } => {
                    if self.by_id.contains_key(&artifact_id) {
                        return Err(TreeStateError::ArtifactAlreadyExists { artifact_id });
                    }
                }
                TreeDelta::Updated { old, new, .. } => {
                    let Some(current) = self.by_id.get(&artifact_id) else {
                        return Err(TreeStateError::ArtifactMissing { artifact_id });
                    };
                    if current.path != old.path || current.entry != old.entry {
                        return Err(TreeStateError::OldStateMismatch { artifact_id });
                    }
                    if old == new {
                        return Err(TreeStateError::NoopUpdate { artifact_id });
                    }
                }
                TreeDelta::Removed { old, .. } => {
                    let Some(current) = self.by_id.get(&artifact_id) else {
                        return Err(TreeStateError::ArtifactMissing { artifact_id });
                    };
                    if current.path != old.path || current.entry != old.entry {
                        return Err(TreeStateError::OldStateMismatch { artifact_id });
                    }
                }
            }
        }

        let mut next = self.clone();
        for delta in deltas {
            if let Some(old) = delta.old_state() {
                next.by_path.remove(&old.path);
                next.by_id.remove(&delta.artifact_id());
            }
        }
        for delta in deltas {
            let Some(new) = delta.new_state() else {
                continue;
            };
            let artifact_id = delta.artifact_id();
            if next.by_path.contains_key(&new.path) {
                return Err(TreeStateError::PathOccupied {
                    path: new.path.clone(),
                });
            }
            if next.by_id.contains_key(&artifact_id) {
                return Err(TreeStateError::ArtifactAlreadyExists { artifact_id });
            }
            let artifact = ResolvedArtifact::new(artifact_id, new.path.clone(), new.entry);
            next.by_path.insert(new.path.clone(), artifact_id);
            next.by_id.insert(artifact_id, artifact);
        }
        Ok(next)
    }
}

impl Serialize for ResolvedTree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ResolvedTreeWire {
            artifacts: self.by_id.values().cloned().collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResolvedTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ResolvedTreeWire::deserialize(deserializer)?;
        Self::from_artifacts(wire.artifacts).map_err(D::Error::custom)
    }
}

impl JsonSchema for ResolvedTree {
    fn schema_name() -> String {
        "ResolvedTree".to_string()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        ResolvedTreeWire::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn blob(byte: u8, executable: bool) -> TreeEntry {
        TreeEntry::blob(Hash256::from_bytes([byte; 32]), executable)
    }

    fn artifact(artifact_id: ArtifactId, path_value: &str, entry: TreeEntry) -> ResolvedArtifact {
        ResolvedArtifact::new(artifact_id, path(path_value), entry)
    }

    #[test]
    fn tree_entry_constructors_preserve_exact_materialization() {
        let regular = blob(0x11, false);
        let executable = blob(0x22, true);
        let symlink = TreeEntry::symlink(Hash256::from_bytes([0x33; 32]));
        let gitlink = TreeEntry::gitlink(GitObjectId::sha1([0x44; 20]));

        assert!(matches!(
            regular,
            TreeEntry::Blob {
                executable: false,
                ..
            }
        ));
        assert!(matches!(
            executable,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
        assert!(matches!(symlink, TreeEntry::Symlink { .. }));
        assert!(matches!(gitlink, TreeEntry::Gitlink { .. }));
        assert_eq!(gitlink.blob_identity(), None);
    }

    #[test]
    fn tree_delta_roundtrip_preserves_complete_transition() {
        let artifact_id = ArtifactId::new();
        let old_entry = blob(0x44, false);
        let new_entry = TreeEntry::symlink(Hash256::from_bytes([0x55; 32]));
        let delta = TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(path("compose.yaml"), old_entry),
            new: LocatedEntry::new(path("deploy/compose.yaml"), new_entry),
        };

        let json = serde_json::to_string(&delta).unwrap();
        let parsed: TreeDelta = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, delta);
        assert_eq!(parsed.artifact_id(), artifact_id);
        assert_eq!(parsed.old_state().unwrap().entry, old_entry);
        assert_eq!(parsed.new_state().unwrap().entry, new_entry);
        assert!(parsed.is_updated());
    }

    #[test]
    fn legacy_tree_payloads_are_rejected() {
        let entry = serde_json::json!({
            "blob_hash": Hash256::from_bytes([0x77; 32]),
            "kind": { "type": "regular", "executable": false }
        });
        let legacy = serde_json::json!({
            "operation": "modified",
            "file_id": "compose.yaml",
            "old_entry": entry,
            "new_entry": entry
        });
        assert!(serde_json::from_value::<TreeDelta>(legacy).is_err());
    }

    #[test]
    fn tree_delta_variants_expose_only_valid_sides() {
        let artifact_id = ArtifactId::new();
        let entry = blob(0x66, false);
        let added = TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(path("Dockerfile"), entry),
        };
        let removed = TreeDelta::Removed {
            artifact_id,
            old: LocatedEntry::new(path("Dockerfile"), entry),
        };

        assert_eq!(added.old_state(), None);
        assert_eq!(added.new_state().unwrap().entry, entry);
        assert!(added.is_added());
        assert_eq!(removed.old_state().unwrap().entry, entry);
        assert_eq!(removed.new_state(), None);
        assert!(removed.is_removed());
    }

    #[test]
    fn resolved_tree_rejects_duplicate_identity_and_path() {
        let first = ArtifactId::new();
        let second = ArtifactId::new();
        let entry = blob(0x10, false);

        assert!(matches!(
            ResolvedTree::from_artifacts([
                artifact(first, "a", entry),
                artifact(first, "b", entry)
            ]),
            Err(TreeStateError::DuplicateArtifact { .. })
        ));
        assert!(matches!(
            ResolvedTree::from_artifacts([
                artifact(first, "a", entry),
                artifact(second, "a", entry)
            ]),
            Err(TreeStateError::DuplicatePath { .. })
        ));
    }

    #[test]
    fn resolved_tree_iteration_is_deterministic_by_identity_or_path() {
        let first = ArtifactId(uuid::Uuid::from_u128(1));
        let second = ArtifactId(uuid::Uuid::from_u128(2));
        let tree = ResolvedTree::from_artifacts([
            artifact(second, "a", blob(0x20, false)),
            artifact(first, "z", blob(0x10, false)),
        ])
        .unwrap();

        assert_eq!(
            tree.artifacts()
                .map(|artifact| artifact.artifact_id)
                .collect::<Vec<_>>(),
            vec![first, second]
        );
        assert_eq!(
            tree.artifacts_by_path()
                .map(|artifact| artifact.path.clone())
                .collect::<Vec<_>>(),
            vec![path("a"), path("z")]
        );
        assert_eq!(
            tree.into_artifacts()
                .map(|artifact| artifact.artifact_id)
                .collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[test]
    fn resolved_tree_applies_modify_chmod_move_and_move_edit() {
        let artifact_id = ArtifactId::new();
        let v1 = LocatedEntry::new(path("src/app"), blob(0x11, false));
        let tree = ResolvedTree::default()
            .apply(&[TreeDelta::Added {
                artifact_id,
                new: v1.clone(),
            }])
            .unwrap();
        let v2 = LocatedEntry::new(path("src/app"), blob(0x22, true));
        let tree = tree
            .apply(&[TreeDelta::Updated {
                artifact_id,
                old: v1,
                new: v2.clone(),
            }])
            .unwrap();
        let v3 = LocatedEntry::new(path("bin/app"), blob(0x33, true));
        let tree = tree
            .apply(&[TreeDelta::Updated {
                artifact_id,
                old: v2,
                new: v3.clone(),
            }])
            .unwrap();

        assert_eq!(tree.get(&artifact_id).unwrap().path, path("bin/app"));
        assert_eq!(tree.get(&artifact_id).unwrap().entry, v3.entry);
    }

    #[test]
    fn path_reuse_can_replace_identity_atomically() {
        let old_id = ArtifactId::new();
        let new_id = ArtifactId::new();
        let old = LocatedEntry::new(path("README.md"), blob(0x40, false));
        let tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            old_id,
            old.path.clone(),
            old.entry,
        )])
        .unwrap();
        let new = LocatedEntry::new(path("README.md"), blob(0x41, false));
        let tree = tree
            .apply(&[
                TreeDelta::Removed {
                    artifact_id: old_id,
                    old,
                },
                TreeDelta::Added {
                    artifact_id: new_id,
                    new,
                },
            ])
            .unwrap();

        assert_eq!(tree.artifact_id_at_path(&path("README.md")), Some(new_id));
        assert!(tree.get(&old_id).is_none());
    }

    #[test]
    fn swaps_and_rename_cycles_are_atomic() {
        let a = ArtifactId::new();
        let b = ArtifactId::new();
        let c = ArtifactId::new();
        let a_old = LocatedEntry::new(path("a"), blob(0x51, false));
        let b_old = LocatedEntry::new(path("b"), blob(0x52, false));
        let c_old = LocatedEntry::new(path("c"), blob(0x53, false));
        let tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(a, a_old.path.clone(), a_old.entry),
            ResolvedArtifact::new(b, b_old.path.clone(), b_old.entry),
            ResolvedArtifact::new(c, c_old.path.clone(), c_old.entry),
        ])
        .unwrap();
        let tree = tree
            .apply(&[
                TreeDelta::Updated {
                    artifact_id: a,
                    old: a_old,
                    new: LocatedEntry::new(path("b"), blob(0x51, false)),
                },
                TreeDelta::Updated {
                    artifact_id: b,
                    old: b_old,
                    new: LocatedEntry::new(path("c"), blob(0x52, false)),
                },
                TreeDelta::Updated {
                    artifact_id: c,
                    old: c_old,
                    new: LocatedEntry::new(path("a"), blob(0x53, false)),
                },
            ])
            .unwrap();

        assert_eq!(tree.artifact_id_at_path(&path("a")), Some(c));
        assert_eq!(tree.artifact_id_at_path(&path("b")), Some(a));
        assert_eq!(tree.artifact_id_at_path(&path("c")), Some(b));
    }

    #[test]
    fn resolved_tree_serde_revalidates_indexes() {
        let id = ArtifactId::new();
        let tree = ResolvedTree::from_artifacts([artifact(id, "compose.yaml", blob(0x61, false))])
            .unwrap();
        let encoded = serde_json::to_vec(&tree).unwrap();
        let decoded: ResolvedTree = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, tree);

        let mut value = serde_json::to_value(&tree).unwrap();
        let duplicate = value["artifacts"][0].clone();
        value["artifacts"].as_array_mut().unwrap().push(duplicate);
        assert!(serde_json::from_value::<ResolvedTree>(value).is_err());
    }
}
