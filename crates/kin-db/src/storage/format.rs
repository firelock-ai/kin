// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::HashMap as FastHashMap;
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::storage::change_validation::validate_semantic_change_entries;
use crate::types::*;

/// Statistics from a snapshot compaction pass.
///
/// Reports what was removed during garbage collection so callers can
/// log or surface compaction results.
#[derive(Debug, Clone, Default)]
pub struct CompactionStats {
    /// Relations removed because src or dst entity no longer exists.
    pub orphaned_relations_removed: usize,
    /// Outgoing edge-list entries cleaned (non-existent entities or relations).
    pub orphaned_outgoing_cleaned: usize,
    /// Incoming edge-list entries cleaned (non-existent entities or relations).
    pub orphaned_incoming_cleaned: usize,
    /// Mock hints removed (non-existent test).
    pub orphaned_mock_hints_removed: usize,
    /// Downstream warnings removed (non-existent intent or entity).
    pub orphaned_downstream_warnings_removed: usize,
    /// Approvals removed (non-existent change).
    pub orphaned_approvals_removed: usize,
    /// Delegations removed (non-existent actor).
    pub orphaned_delegations_removed: usize,
    /// Entity count before compaction.
    pub entities_before: usize,
    /// Relation count before compaction.
    pub relations_before: usize,
    /// Relation count after compaction.
    pub relations_after: usize,
}

impl CompactionStats {
    /// Total number of orphaned items removed across all collections.
    pub fn total_removed(&self) -> usize {
        self.orphaned_relations_removed
            + self.orphaned_outgoing_cleaned
            + self.orphaned_incoming_cleaned
            + self.orphaned_mock_hints_removed
            + self.orphaned_downstream_warnings_removed
            + self.orphaned_approvals_removed
            + self.orphaned_delegations_removed
    }

    /// True if compaction removed nothing (graph was already clean).
    pub fn is_clean(&self) -> bool {
        self.total_removed() == 0
    }
}

/// The serializable snapshot of the entire graph state.
///
/// This is the on-disk format. We use std::collections::HashMap here
/// (not hashbrown) for stable serde compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSnapshot {
    pub version: u32,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub outgoing: HashMap<EntityId, Vec<RelationId>>,
    pub incoming: HashMap<EntityId, Vec<RelationId>>,
    pub changes: HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub branches: HashMap<BranchName, Branch>,
    pub work_items: HashMap<WorkId, WorkItem>,
    pub annotations: HashMap<AnnotationId, Annotation>,
    pub work_links: Vec<WorkLink>,
    pub reviews: HashMap<ReviewId, Review>,
    pub review_decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    pub review_notes: Vec<ReviewNote>,
    pub review_discussions: Vec<ReviewDiscussion>,
    pub review_assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
    pub test_cases: HashMap<TestId, TestCase>,
    pub assertions: HashMap<AssertionId, Assertion>,
    pub verification_runs: HashMap<VerificationRunId, VerificationRun>,
    pub mock_hints: Vec<MockHint>,
    pub contracts: HashMap<ContractId, Contract>,
    pub actors: HashMap<ActorId, Actor>,
    pub delegations: Vec<Delegation>,
    pub approvals: Vec<Approval>,
    pub audit_events: Vec<AuditEvent>,
    pub shallow_files: Vec<ShallowTrackedFile>,
    pub file_layouts: Vec<FileLayout>,
    pub structured_artifacts: Vec<StructuredArtifact>,
    pub opaque_artifacts: Vec<OpaqueArtifact>,
    /// Exact graph-owned repository tree. Artifact identity, byte-exact path,
    /// content identity, and materialization kind are one validated authority.
    pub resolved_tree: ResolvedTree,
    pub sessions: HashMap<SessionId, AgentSession>,
    pub intents: HashMap<IntentId, Intent>,
    pub downstream_warnings: Vec<(IntentId, EntityId, String)>,
    pub entity_revisions: HashMap<EntityId, Vec<EntityRevision>>,
}

/// Lightweight snapshot view for locate-only cold starts.
///
/// This intentionally decodes only the graph domains that `kin locate`
/// actually reads at query time:
/// - entities and relations
/// - semantic changes (for co-change time decay)
/// - file/artifact metadata
///
/// Large persisted adjacency lists (`outgoing`, `incoming`) are skipped here
/// because `InMemoryGraph::from_snapshot_*` rebuilds them from `relations`
/// anyway, so decoding them only adds cold-start cost.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LocateGraphSnapshot {
    pub version: u32,
    pub entities: FastHashMap<EntityId, Entity>,
    pub relations: FastHashMap<RelationId, Relation>,
    pub changes: FastHashMap<SemanticChangeId, SemanticChange>,
    pub shallow_files: Vec<ShallowTrackedFile>,
    pub file_layouts: Vec<FileLayout>,
    pub structured_artifacts: Vec<StructuredArtifact>,
    pub opaque_artifacts: Vec<OpaqueArtifact>,
    pub resolved_tree: ResolvedTree,
}

fn relation_kind_used_by_locate(kind: RelationKind) -> bool {
    matches!(
        kind,
        RelationKind::Calls
            | RelationKind::Includes
            | RelationKind::UsesMacro
            | RelationKind::Imports
            | RelationKind::References
            | RelationKind::Implements
            | RelationKind::Extends
            | RelationKind::Contains
            | RelationKind::Tests
            | RelationKind::DependsOn
            | RelationKind::CoChanges
    )
}

struct FilteredLocateRelation(Option<Relation>);

impl<'de> Deserialize<'de> for FilteredLocateRelation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FilteredLocateRelationVisitor;

        impl<'de> Visitor<'de> for FilteredLocateRelationVisitor {
            type Value = FilteredLocateRelation;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("Relation sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let id = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let kind = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                if !relation_kind_used_by_locate(kind) {
                    for index in 2..8 {
                        let _: IgnoredAny = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                    }
                    while let Some(_) = seq.next_element::<IgnoredAny>()? {}
                    return Ok(FilteredLocateRelation(None));
                }

                let src = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let dst = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let confidence = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                let origin = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                let created_in = seq.next_element()?.unwrap_or(None);
                let import_source = seq.next_element()?.unwrap_or(None);
                while let Some(_) = seq.next_element::<IgnoredAny>()? {}

                Ok(FilteredLocateRelation(Some(Relation {
                    id,
                    kind,
                    src,
                    dst,
                    confidence,
                    origin,
                    created_in,
                    import_source,
                    evidence: Vec::new(),
                })))
            }
        }

        deserializer.deserialize_seq(FilteredLocateRelationVisitor)
    }
}

struct FilteredLocateRelationMap(FastHashMap<RelationId, Relation>);

impl<'de> Deserialize<'de> for FilteredLocateRelationMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FilteredLocateRelationMapVisitor;

        impl<'de> Visitor<'de> for FilteredLocateRelationMapVisitor {
            type Value = FilteredLocateRelationMap;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("relation map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut relations = FastHashMap::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(_relation_id) = map.next_key::<RelationId>()? {
                    if let Some(relation) = map.next_value::<FilteredLocateRelation>()?.0 {
                        relations.insert(relation.id, relation);
                    }
                }
                Ok(FilteredLocateRelationMap(relations))
            }
        }

        deserializer.deserialize_map(FilteredLocateRelationMapVisitor)
    }
}

impl GraphSnapshot {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 10;

    /// The only on-disk format version this pre-release binary accepts.
    pub const MIN_SUPPORTED_VERSION: u32 = Self::CURRENT_VERSION;

    /// Magic bytes for the file header: "KNDB"
    pub const MAGIC: [u8; 4] = *b"KNDB";

    /// Size of the checksum appended to every current snapshot.
    pub const CHECKSUM_LEN: usize = 32;

    /// Optional trailer magic that binds a persisted graph-root cache value to
    /// the already-verified snapshot body checksum.
    const ROOT_HASH_TRAILER_MAGIC: [u8; 4] = *b"KRTH";
    const ROOT_HASH_TRAILER_LEN: usize = 4 + 32 + 32;

    pub fn empty() -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            entities: HashMap::new(),
            relations: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            changes: HashMap::new(),
            change_children: HashMap::new(),
            branches: HashMap::new(),
            work_items: HashMap::new(),
            annotations: HashMap::new(),
            work_links: Vec::new(),
            reviews: HashMap::new(),
            review_decisions: HashMap::new(),
            review_notes: Vec::new(),
            review_discussions: Vec::new(),
            review_assignments: HashMap::new(),
            test_cases: HashMap::new(),
            assertions: HashMap::new(),
            verification_runs: HashMap::new(),
            mock_hints: Vec::new(),
            contracts: HashMap::new(),
            actors: HashMap::new(),
            delegations: Vec::new(),
            approvals: Vec::new(),
            audit_events: Vec::new(),
            shallow_files: Vec::new(),
            file_layouts: Vec::new(),
            structured_artifacts: Vec::new(),
            opaque_artifacts: Vec::new(),
            resolved_tree: ResolvedTree::default(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
            entity_revisions: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn admit_artifact_for_test(&mut self, path: String, entry: TreeEntry) -> ArtifactId {
        let path = RepoPath::from_utf8(&path).expect("valid test repository path");
        let existing = self.resolved_tree.artifact_at_path(&path).cloned();
        let artifact_id = existing
            .as_ref()
            .map(|artifact| artifact.artifact_id)
            .unwrap_or_else(ArtifactId::new);
        let mut artifacts: Vec<_> = self.resolved_tree.clone().into_artifacts().collect();
        artifacts.retain(|artifact| artifact.artifact_id != artifact_id);
        artifacts.push(ResolvedArtifact::new(artifact_id, path, entry));
        self.resolved_tree =
            ResolvedTree::from_artifacts(artifacts).expect("valid test repository tree");
        artifact_id
    }

    #[cfg(test)]
    pub(crate) fn tree_entry_for_test(&self, path: &str) -> Option<TreeEntry> {
        let path = RepoPath::from_utf8(path).ok()?;
        self.resolved_tree
            .artifact_at_path(&path)
            .map(|artifact| artifact.entry)
    }

    #[cfg(test)]
    pub(crate) fn has_artifact_path_for_test(&self, path: &str) -> bool {
        self.tree_entry_for_test(path).is_some()
    }

    /// Compact the snapshot by removing orphaned data.
    ///
    /// Performs garbage collection across all cross-referenced collections:
    /// - Relations whose src or dst entity no longer exists
    /// - Outgoing/incoming edge lists referencing non-existent entities or relations
    /// - Mock hints for non-existent tests
    /// - Downstream warnings for non-existent intents or entities
    /// - Approvals for non-existent changes
    /// - Delegations for non-existent actors
    ///
    /// For graphs with >500K entities, orphaned data can accumulate significantly
    /// after bulk deletions or re-indexes. This method ensures the snapshot
    /// contains only reachable, consistent data before serialization.
    pub fn compact(&mut self) -> CompactionStats {
        let mut stats = CompactionStats::default();
        stats.entities_before = self.entities.len();
        stats.relations_before = self.relations.len();

        // Build reference sets once — these are the "live" IDs.
        let entity_ids: HashSet<EntityId> = self.entities.keys().copied().collect();
        let test_ids: HashSet<TestId> = self.test_cases.keys().copied().collect();
        let contract_ids: HashSet<ContractId> = self.contracts.keys().copied().collect();
        let work_ids: HashSet<WorkId> = self.work_items.keys().copied().collect();
        let run_ids: HashSet<VerificationRunId> = self.verification_runs.keys().copied().collect();

        // 1. Remove orphaned relations (missing node on either endpoint)
        let before = self.relations.len();
        let artifact_ids: HashSet<ArtifactId> = self
            .resolved_tree
            .artifacts()
            .map(|artifact| artifact.artifact_id)
            .collect();
        self.relations.retain(|_, rel| {
            graph_node_exists(
                rel.src,
                &entity_ids,
                &artifact_ids,
                &test_ids,
                &contract_ids,
                &work_ids,
                &run_ids,
            ) && graph_node_exists(
                rel.dst,
                &entity_ids,
                &artifact_ids,
                &test_ids,
                &contract_ids,
                &work_ids,
                &run_ids,
            )
        });
        stats.orphaned_relations_removed = before - self.relations.len();

        // 2. Clean outgoing edge lists
        let live_relations: HashSet<RelationId> = self.relations.keys().copied().collect();
        let before = self.outgoing.len();
        self.outgoing.retain(|eid, _| entity_ids.contains(eid));
        for rels in self.outgoing.values_mut() {
            rels.retain(|rid| live_relations.contains(rid));
        }
        self.outgoing.retain(|_, rels| !rels.is_empty());
        stats.orphaned_outgoing_cleaned = before.saturating_sub(self.outgoing.len());

        // 3. Clean incoming edge lists
        let before = self.incoming.len();
        self.incoming.retain(|eid, _| entity_ids.contains(eid));
        for rels in self.incoming.values_mut() {
            rels.retain(|rid| live_relations.contains(rid));
        }
        self.incoming.retain(|_, rels| !rels.is_empty());
        stats.orphaned_incoming_cleaned = before.saturating_sub(self.incoming.len());

        // 4. Clean mock hints for non-existent tests
        let before = self.mock_hints.len();
        self.mock_hints
            .retain(|hint| test_ids.contains(&hint.test_id));
        stats.orphaned_mock_hints_removed = before - self.mock_hints.len();

        // 5. Clean downstream warnings for non-existent intents or entities
        let intent_ids: HashSet<IntentId> = self.intents.keys().copied().collect();
        let before = self.downstream_warnings.len();
        self.downstream_warnings
            .retain(|(iid, eid, _)| intent_ids.contains(iid) && entity_ids.contains(eid));
        stats.orphaned_downstream_warnings_removed = before - self.downstream_warnings.len();

        // 6. Clean approvals for non-existent changes
        let change_ids: HashSet<SemanticChangeId> = self.changes.keys().copied().collect();
        let before = self.approvals.len();
        self.approvals.retain(|a| change_ids.contains(&a.change_id));
        stats.orphaned_approvals_removed = before - self.approvals.len();

        // 7. Clean delegations for non-existent actors
        let actor_ids: HashSet<ActorId> = self.actors.keys().copied().collect();
        let before = self.delegations.len();
        self.delegations
            .retain(|d| actor_ids.contains(&d.principal) && actor_ids.contains(&d.delegate));
        stats.orphaned_delegations_removed = before - self.delegations.len();

        stats.relations_after = self.relations.len();
        stats
    }

    /// Serialize the snapshot to bytes with a header and checksum.
    ///
    /// Wire format:
    ///   [4B magic] [4B version LE] [8B body_len LE] [body ...] [32B checksum]
    ///
    /// The checksum is computed over the msgpack body only.
    ///
    /// For large graphs (>500K entities), this avoids cloning the entire
    /// snapshot by serializing directly when the version already matches.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(None)
    }

    /// Like [`to_bytes`] but appends a verified root-hash trailer so open
    /// paths can reuse the persisted Merkle root without recomputing it from
    /// the decoded snapshot.
    pub fn to_bytes_with_persisted_root_hash(
        &self,
        root_hash: [u8; 32],
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(Some(root_hash))
    }

    fn to_bytes_inner(
        &self,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(crate::error::KinDbError::StorageError(format!(
                "refusing to serialize snapshot body version {}; current schema is exactly v{}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }
        self.validate_storage_admission()?;
        let body = rmp_serde::to_vec(self).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("serialization failed: {e}"))
        })?;

        let trailer_len = persisted_root_hash
            .map(|_| Self::ROOT_HASH_TRAILER_LEN)
            .unwrap_or(0);
        // Pre-allocate: header (16B) + body + checksum (32B) + optional trailer
        let mut buf = Vec::with_capacity(16 + body.len() + Self::CHECKSUM_LEN + trailer_len);
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&Self::CURRENT_VERSION.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);

        // Append checksum of the body.
        let body_checksum: [u8; 32] = Sha256::digest(&body).into();
        buf.extend_from_slice(&body_checksum);
        if let Some(root_hash) = persisted_root_hash {
            Self::append_root_hash_trailer(&mut buf, body_checksum, root_hash);
        }

        Ok(buf)
    }

    /// Deserialize a snapshot from bytes (with header validation).
    ///
    /// The pre-release v10 format is the first format with one validated,
    /// identity-bearing universal repository tree. Earlier split tree/index
    /// snapshots fail closed and must be rebuilt.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash(data).map(|(snapshot, _)| snapshot)
    }

    pub(crate) fn from_bytes_with_persisted_root_hash(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, true)
    }

    pub(crate) fn from_bytes_with_persisted_root_hash_unverified(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, false)
    }

    fn from_bytes_with_persisted_root_hash_inner(
        data: &[u8],
        verify_checksum: bool,
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        let frame = {
            let _span = tracing::info_span!("kindb.snapshot.decode_frame").entered();
            Self::decode_frame(data, verify_checksum)?
        };
        let snapshot = match frame.version {
            Self::CURRENT_VERSION => Self::decode_current_snapshot(frame.body)?,
            _ => unreachable!("decode_frame validates supported versions"),
        };
        snapshot.validate_storage_admission()?;
        let persisted_root_hash = if verify_checksum {
            Self::decode_root_hash_trailer(data, &frame)?
        } else {
            let _span = tracing::info_span!("kindb.snapshot.skip_checksum_verification").entered();
            Self::decode_root_hash_trailer_unverified(data, frame.checksum_end)?
        };
        Ok((snapshot, persisted_root_hash))
    }

    fn decode_frame(
        data: &[u8],
        verify_checksum: bool,
    ) -> Result<SnapshotFrame<'_>, crate::error::KinDbError> {
        if data.len() < 16 {
            return Err(crate::error::KinDbError::StorageError(
                "file too small for header".to_string(),
            ));
        }

        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(crate::error::KinDbError::StorageError(format!(
                "invalid magic bytes: expected KNDB, got {:?}",
                magic
            )));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "version bytes: expected 4-byte slice".to_string(),
            )
        })?);
        let body_len = u64::from_le_bytes(data[8..16].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "body_len bytes: expected 8-byte slice".to_string(),
            )
        })?) as usize;
        // Checked add: an adversarial body_len near usize::MAX would otherwise
        // wrap `16 + body_len`, defeating the bounds check and panicking on the
        // `data[16..16 + body_len]` slice below (found by fuzzing).
        let body_end = 16usize.checked_add(body_len).ok_or_else(|| {
            crate::error::KinDbError::StorageError(
                "snapshot header body length overflows usize".to_string(),
            )
        })?;
        if data.len() < body_end {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot file truncated: body extends past end of data".to_string(),
            ));
        }
        let body = &data[16..body_end];

        match version {
            Self::CURRENT_VERSION => {
                let checksum_end = Self::require_checksum_slot(data, body_len, "v10")?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, "v10")?)
                } else {
                    None
                };
                Ok(SnapshotFrame {
                    version,
                    body,
                    body_checksum,
                    checksum_end,
                })
            }
            version if version < Self::MIN_SUPPORTED_VERSION => {
                Err(crate::error::KinDbError::snapshot_schema_too_old(
                    version,
                    Self::MIN_SUPPORTED_VERSION,
                    Self::CURRENT_VERSION,
                ))
            }
            _ => Err(crate::error::KinDbError::snapshot_schema_too_new(
                version,
                Self::MIN_SUPPORTED_VERSION,
                Self::CURRENT_VERSION,
            )),
        }
    }

    fn decode_current_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.decode_current_snapshot").entered();
        rmp_serde::from_slice(body).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
        })
    }

    pub(crate) fn validate_storage_admission(&self) -> Result<(), crate::error::KinDbError> {
        validate_semantic_change_entries(self.changes.iter(), "snapshot")?;
        self.validate_enrichment_admission()
    }

    fn validate_enrichment_admission(&self) -> Result<(), crate::error::KinDbError> {
        let file_ids = self
            .shallow_files
            .iter()
            .map(|file| &file.file_id)
            .chain(self.file_layouts.iter().map(|layout| &layout.file_id))
            .chain(
                self.structured_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            )
            .chain(
                self.opaque_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            );
        for file_id in file_ids {
            let path = RepoPath::from_utf8(&file_id.0).map_err(|error| {
                crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment has invalid repository path {}: {error}",
                    file_id.0
                ))
            })?;
            if self.resolved_tree.artifact_id_at_path(&path).is_none() {
                return Err(crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment exists without admitted repository identity at {}",
                    file_id.0
                )));
            }
        }
        Ok(())
    }

    fn verify_checksum(
        data: &[u8],
        body_len: usize,
        version_label: &str,
    ) -> Result<[u8; 32], crate::error::KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.verify_checksum", version = version_label)
            .entered();
        let checksum_end = Self::require_checksum_slot(data, body_len, version_label)?;
        let checksum_start = checksum_end - Self::CHECKSUM_LEN;
        let body = &data[16..16 + body_len];
        let stored_hash = &data[checksum_start..checksum_start + Self::CHECKSUM_LEN];
        let computed_hash: [u8; 32] = Sha256::digest(body).into();

        if stored_hash != computed_hash.as_slice() {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot checksum mismatch: file is corrupted".to_string(),
            ));
        }

        Ok(computed_hash)
    }

    fn require_checksum_slot(
        data: &[u8],
        body_len: usize,
        version_label: &str,
    ) -> Result<usize, crate::error::KinDbError> {
        // Checked add to avoid wrapping on an adversarial body_len.
        let checksum_end = 16usize
            .checked_add(body_len)
            .and_then(|start| start.checked_add(Self::CHECKSUM_LEN))
            .ok_or_else(|| {
                crate::error::KinDbError::StorageError(format!(
                    "{version_label} snapshot body length overflows usize"
                ))
            })?;
        if data.len() < checksum_end {
            return Err(crate::error::KinDbError::StorageError(format!(
                "{version_label} snapshot missing checksum"
            )));
        }
        Ok(checksum_end)
    }

    fn append_root_hash_trailer(buf: &mut Vec<u8>, body_checksum: [u8; 32], root_hash: [u8; 32]) {
        buf.extend_from_slice(&Self::ROOT_HASH_TRAILER_MAGIC);
        buf.extend_from_slice(&root_hash);
        buf.extend_from_slice(&Self::root_hash_trailer_digest(body_checksum, root_hash));
    }

    fn decode_root_hash_trailer(
        data: &[u8],
        frame: &SnapshotFrame<'_>,
    ) -> Result<Option<[u8; 32]>, crate::error::KinDbError> {
        let Some(body_checksum) = frame.body_checksum else {
            return Ok(None);
        };

        let extra = &data[frame.checksum_end..];
        if extra.len() < 4 {
            return Ok(None);
        }
        if extra[..4] != Self::ROOT_HASH_TRAILER_MAGIC {
            return Ok(None);
        }
        if extra.len() < Self::ROOT_HASH_TRAILER_LEN {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot root-hash trailer is truncated".to_string(),
            ));
        }

        let root_hash = extra[4..36].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "root-hash trailer root bytes: expected 32-byte slice".to_string(),
            )
        })?;
        let stored_digest: [u8; 32] = extra[36..68].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "root-hash trailer digest bytes: expected 32-byte slice".to_string(),
            )
        })?;
        let expected_digest = Self::root_hash_trailer_digest(body_checksum, root_hash);
        if stored_digest != expected_digest {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot root-hash trailer mismatch: file is corrupted".to_string(),
            ));
        }

        Ok(Some(root_hash))
    }

    fn decode_root_hash_trailer_unverified(
        data: &[u8],
        checksum_end: usize,
    ) -> Result<Option<[u8; 32]>, crate::error::KinDbError> {
        let extra = &data[checksum_end..];
        if extra.len() < 4 {
            return Ok(None);
        }
        if extra[..4] != Self::ROOT_HASH_TRAILER_MAGIC {
            return Ok(None);
        }
        if extra.len() < Self::ROOT_HASH_TRAILER_LEN {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot root-hash trailer is truncated".to_string(),
            ));
        }

        let root_hash = extra[4..36].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "root-hash trailer root bytes: expected 32-byte slice".to_string(),
            )
        })?;
        Ok(Some(root_hash))
    }

    fn root_hash_trailer_digest(body_checksum: [u8; 32], root_hash: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(Self::ROOT_HASH_TRAILER_MAGIC);
        hasher.update(body_checksum);
        hasher.update(root_hash);
        hasher.finalize().into()
    }
}

impl LocateGraphSnapshot {
    pub(crate) fn from_bytes_with_persisted_root_hash(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, true)
    }

    pub(crate) fn from_bytes_with_persisted_root_hash_unverified(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, false)
    }

    fn from_bytes_with_persisted_root_hash_inner(
        data: &[u8],
        verify_checksum: bool,
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        let frame = {
            let _span = tracing::info_span!("kindb.snapshot.decode_locate_frame").entered();
            GraphSnapshot::decode_frame(data, verify_checksum)?
        };
        let snapshot = match frame.version {
            GraphSnapshot::CURRENT_VERSION => Self::decode_current_snapshot(frame.body)?,
            _ => unreachable!("decode_frame validates supported versions"),
        };
        snapshot.validate_storage_admission()?;
        let persisted_root_hash = if verify_checksum {
            GraphSnapshot::decode_root_hash_trailer(data, &frame)?
        } else {
            let _span = tracing::info_span!("kindb.snapshot.skip_locate_checksum").entered();
            GraphSnapshot::decode_root_hash_trailer_unverified(data, frame.checksum_end)?
        };
        Ok((snapshot, persisted_root_hash))
    }

    fn decode_current_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        rmp_serde::from_slice(body).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
        })
    }

    fn validate_storage_admission(&self) -> Result<(), crate::error::KinDbError> {
        validate_semantic_change_entries(self.changes.iter(), "locate snapshot")?;
        self.validate_enrichment_admission()
    }

    fn validate_enrichment_admission(&self) -> Result<(), crate::error::KinDbError> {
        let file_ids = self
            .shallow_files
            .iter()
            .map(|file| &file.file_id)
            .chain(self.file_layouts.iter().map(|layout| &layout.file_id))
            .chain(
                self.structured_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            )
            .chain(
                self.opaque_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            );
        for file_id in file_ids {
            let path = RepoPath::from_utf8(&file_id.0).map_err(|error| {
                crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment has invalid repository path {}: {error}",
                    file_id.0
                ))
            })?;
            if self.resolved_tree.artifact_id_at_path(&path).is_none() {
                return Err(crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment exists without admitted repository identity at {}",
                    file_id.0
                )));
            }
        }
        Ok(())
    }
}

impl GraphSnapshot {
    pub(crate) fn persisted_root_hash_from_bytes_unverified(
        data: &[u8],
    ) -> Result<Option<[u8; 32]>, crate::error::KinDbError> {
        let frame = Self::decode_frame(data, false)?;
        Self::decode_root_hash_trailer_unverified(data, frame.checksum_end)
    }
}

impl From<GraphSnapshot> for LocateGraphSnapshot {
    fn from(value: GraphSnapshot) -> Self {
        Self {
            version: value.version,
            entities: value.entities.into_iter().collect(),
            relations: value.relations.into_iter().collect(),
            changes: value.changes.into_iter().collect(),
            shallow_files: value.shallow_files,
            file_layouts: value.file_layouts,
            structured_artifacts: value.structured_artifacts,
            opaque_artifacts: value.opaque_artifacts,
            resolved_tree: value.resolved_tree,
        }
    }
}

impl From<LocateGraphSnapshot> for GraphSnapshot {
    fn from(value: LocateGraphSnapshot) -> Self {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.version = value.version;
        snapshot.entities = value.entities.into_iter().collect();
        snapshot.relations = value.relations.into_iter().collect();
        snapshot.changes = value.changes.into_iter().collect();
        snapshot.shallow_files = value.shallow_files;
        snapshot.file_layouts = value.file_layouts;
        snapshot.structured_artifacts = value.structured_artifacts;
        snapshot.opaque_artifacts = value.opaque_artifacts;
        snapshot.resolved_tree = value.resolved_tree;
        snapshot
    }
}

impl<'de> Deserialize<'de> for LocateGraphSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LocateGraphSnapshotVisitor;

        impl<'de> Visitor<'de> for LocateGraphSnapshotVisitor {
            type Value = LocateGraphSnapshot;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("GraphSnapshot sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let version = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let entities = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let relations = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let FilteredLocateRelationMap(relations) = relations;

                let _: IgnoredAny = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let _: IgnoredAny = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;

                let changes = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;

                for index in 6..25 {
                    let _: IgnoredAny = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }

                let shallow_files = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(25, &self))?;
                let file_layouts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(26, &self))?;
                let structured_artifacts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(27, &self))?;
                let opaque_artifacts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(28, &self))?;

                let resolved_tree = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(29, &self))?;

                for index in 30..34 {
                    let _: IgnoredAny = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }

                Ok(LocateGraphSnapshot {
                    version,
                    entities,
                    relations,
                    changes,
                    shallow_files,
                    file_layouts,
                    structured_artifacts,
                    opaque_artifacts,
                    resolved_tree,
                })
            }
        }

        deserializer.deserialize_seq(LocateGraphSnapshotVisitor)
    }
}

struct SnapshotFrame<'a> {
    version: u32,
    body: &'a [u8],
    body_checksum: Option<[u8; 32]>,
    checksum_end: usize,
}

// ---------------------------------------------------------------------------
// BorrowedGraphSnapshot — zero-clone serializable view over live graph stores
// ---------------------------------------------------------------------------

/// A borrowed view over live graph stores that serializes identically to
/// [`GraphSnapshot`].  By holding references to the existing in-memory data
/// (hashbrown maps + vecs), we avoid the ~18 GB clone that `to_snapshot()`
/// materialises for large graphs.
///
/// The `Serialize` impl manually writes 34 fields in the same positional
/// order as the derive(Serialize) on `GraphSnapshot`, so the resulting
/// msgpack is byte-for-byte compatible with the owned version.
pub struct BorrowedGraphSnapshot<'a> {
    // EntityData fields
    pub entities: &'a hashbrown::HashMap<EntityId, Entity>,
    pub relations: &'a hashbrown::HashMap<RelationId, Relation>,
    pub outgoing: &'a hashbrown::HashMap<EntityId, Vec<RelationId>>,
    pub incoming: &'a hashbrown::HashMap<EntityId, Vec<RelationId>>,
    pub resolved_tree: &'a ResolvedTree,
    pub shallow_files: &'a hashbrown::HashMap<FilePathId, ShallowTrackedFile>,
    pub file_layouts: &'a hashbrown::HashMap<FilePathId, FileLayout>,
    pub structured_artifacts: &'a hashbrown::HashMap<FilePathId, StructuredArtifact>,
    pub opaque_artifacts: &'a hashbrown::HashMap<FilePathId, OpaqueArtifact>,
    // ChangeData fields
    pub changes: &'a hashbrown::HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: &'a hashbrown::HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub branches: &'a hashbrown::HashMap<BranchName, Branch>,
    // WorkData fields
    pub work_items: &'a hashbrown::HashMap<WorkId, WorkItem>,
    pub annotations: &'a hashbrown::HashMap<AnnotationId, Annotation>,
    pub work_links: &'a Vec<WorkLink>,
    // ReviewData fields
    pub reviews: &'a hashbrown::HashMap<ReviewId, Review>,
    pub review_decisions: &'a hashbrown::HashMap<ReviewId, Vec<ReviewDecision>>,
    pub review_notes: &'a hashbrown::HashMap<ReviewNoteId, ReviewNote>,
    pub review_discussions: &'a hashbrown::HashMap<ReviewDiscussionId, ReviewDiscussion>,
    pub review_assignments: &'a hashbrown::HashMap<ReviewId, Vec<ReviewAssignment>>,
    // VerificationData fields
    pub test_cases: &'a hashbrown::HashMap<TestId, TestCase>,
    pub assertions: &'a hashbrown::HashMap<AssertionId, Assertion>,
    pub verification_runs: &'a hashbrown::HashMap<VerificationRunId, VerificationRun>,
    pub mock_hints: &'a Vec<MockHint>,
    pub contracts: &'a hashbrown::HashMap<ContractId, Contract>,
    // ProvenanceData fields
    pub actors: &'a hashbrown::HashMap<ActorId, Actor>,
    pub delegations: &'a Vec<Delegation>,
    pub approvals: &'a Vec<Approval>,
    pub audit_events: &'a Vec<AuditEvent>,
    // SessionData fields
    pub sessions: &'a hashbrown::HashMap<SessionId, AgentSession>,
    pub intents: &'a hashbrown::HashMap<IntentId, Intent>,
    pub downstream_warnings: &'a Vec<(IntentId, EntityId, String)>,
    pub entity_revisions: &'a hashbrown::HashMap<EntityId, Vec<EntityRevision>>,
}

impl<'a> Serialize for BorrowedGraphSnapshot<'a> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // Must produce exactly 34 fields in the same order as GraphSnapshot's
        // derive(Serialize).  rmp_serde serializes structs as arrays, so
        // position (not name) determines the mapping.
        let mut state = serializer.serialize_struct("GraphSnapshot", 34)?;

        // 1. version
        state.serialize_field("version", &GraphSnapshot::CURRENT_VERSION)?;
        // 2. entities  (hashbrown::HashMap → map)
        state.serialize_field("entities", self.entities)?;
        // 3. relations
        state.serialize_field("relations", self.relations)?;
        // 4. outgoing
        state.serialize_field("outgoing", self.outgoing)?;
        // 5. incoming
        state.serialize_field("incoming", self.incoming)?;
        // 6. changes
        state.serialize_field("changes", self.changes)?;
        // 7. change_children
        state.serialize_field("change_children", self.change_children)?;
        // 8. branches
        state.serialize_field("branches", self.branches)?;
        // 9. work_items
        state.serialize_field("work_items", self.work_items)?;
        // 10. annotations
        state.serialize_field("annotations", self.annotations)?;
        // 11. work_links
        state.serialize_field("work_links", self.work_links)?;
        // 12. reviews
        state.serialize_field("reviews", self.reviews)?;
        // 13. review_decisions
        state.serialize_field("review_decisions", self.review_decisions)?;
        // 14. review_notes  (HashMap values → seq)
        state.serialize_field("review_notes", &HashMapValuesAsSeq(self.review_notes))?;
        // 15. review_discussions  (HashMap values → seq)
        state.serialize_field(
            "review_discussions",
            &HashMapValuesAsSeq(self.review_discussions),
        )?;
        // 16. review_assignments
        state.serialize_field("review_assignments", self.review_assignments)?;
        // 17. test_cases
        state.serialize_field("test_cases", self.test_cases)?;
        // 18. assertions
        state.serialize_field("assertions", self.assertions)?;
        // 19. verification_runs
        state.serialize_field("verification_runs", self.verification_runs)?;
        // 20. mock_hints
        state.serialize_field("mock_hints", self.mock_hints)?;
        // 21. contracts
        state.serialize_field("contracts", self.contracts)?;
        // 22. actors
        state.serialize_field("actors", self.actors)?;
        // 23. delegations
        state.serialize_field("delegations", self.delegations)?;
        // 24. approvals
        state.serialize_field("approvals", self.approvals)?;
        // 25. audit_events
        state.serialize_field("audit_events", self.audit_events)?;
        // 26. shallow_files  (HashMap values → seq)
        state.serialize_field("shallow_files", &HashMapValuesAsSeq(self.shallow_files))?;
        // 27. file_layouts  (HashMap values → seq)
        state.serialize_field("file_layouts", &HashMapValuesAsSeq(self.file_layouts))?;
        // 28. structured_artifacts  (HashMap values → seq)
        state.serialize_field(
            "structured_artifacts",
            &HashMapValuesAsSeq(self.structured_artifacts),
        )?;
        // 29. opaque_artifacts  (HashMap values → seq)
        state.serialize_field(
            "opaque_artifacts",
            &HashMapValuesAsSeq(self.opaque_artifacts),
        )?;
        // 30. resolved_tree
        state.serialize_field("resolved_tree", self.resolved_tree)?;
        // 31. sessions
        state.serialize_field("sessions", self.sessions)?;
        // 32. intents
        state.serialize_field("intents", self.intents)?;
        // 33. downstream_warnings
        state.serialize_field("downstream_warnings", self.downstream_warnings)?;
        // 34. entity_revisions
        state.serialize_field("entity_revisions", self.entity_revisions)?;
        state.end()
    }
}

impl<'a> BorrowedGraphSnapshot<'a> {
    /// Serialize to the on-disk binary format (KNDB header + msgpack body + checksum).
    ///
    /// Produces bytes identical in structure to [`GraphSnapshot::to_bytes`] but
    /// without ever materialising an owned [`GraphSnapshot`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(None)
    }

    pub fn to_bytes_with_persisted_root_hash(
        &self,
        root_hash: [u8; 32],
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(Some(root_hash))
    }

    fn to_bytes_inner(
        &self,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        let body = rmp_serde::to_vec(self).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("serialization failed: {e}"))
        })?;

        let trailer_len = persisted_root_hash
            .map(|_| GraphSnapshot::ROOT_HASH_TRAILER_LEN)
            .unwrap_or(0);
        let mut buf =
            Vec::with_capacity(16 + body.len() + GraphSnapshot::CHECKSUM_LEN + trailer_len);
        buf.extend_from_slice(&GraphSnapshot::MAGIC);
        buf.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);

        let body_checksum: [u8; 32] = Sha256::digest(&body).into();
        buf.extend_from_slice(&body_checksum);
        if let Some(root_hash) = persisted_root_hash {
            GraphSnapshot::append_root_hash_trailer(&mut buf, body_checksum, root_hash);
        }

        Ok(buf)
    }
}

/// Helper that serializes a `hashbrown::HashMap`'s values as a sequence
/// (matching the `Vec<V>` fields in [`GraphSnapshot`]'s on-disk format).
struct HashMapValuesAsSeq<'a, K, V>(&'a hashbrown::HashMap<K, V>);

impl<K, V: Serialize> Serialize for HashMapValuesAsSeq<'_, K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.values())
    }
}

fn graph_node_exists(
    node: GraphNodeId,
    entity_ids: &HashSet<EntityId>,
    artifact_ids: &HashSet<ArtifactId>,
    test_ids: &HashSet<TestId>,
    contract_ids: &HashSet<ContractId>,
    work_ids: &HashSet<WorkId>,
    run_ids: &HashSet<VerificationRunId>,
) -> bool {
    match node {
        GraphNodeId::Entity(id) => entity_ids.contains(&id),
        GraphNodeId::Artifact(id) => artifact_ids.contains(&id),
        GraphNodeId::Test(id) => test_ids.contains(&id),
        GraphNodeId::Contract(id) => contract_ids.contains(&id),
        GraphNodeId::Work(id) => work_ids.contains(&id),
        GraphNodeId::VerificationRun(id) => run_ids.contains(&id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (found by fuzzing): a snapshot header whose body_len is near
    /// usize::MAX must be rejected with an error, never wrap `16 + body_len`
    /// and panic on the body slice.
    #[test]
    fn from_bytes_rejects_overflowing_body_len_without_panic() {
        let mut data = Vec::new();
        data.extend_from_slice(&GraphSnapshot::MAGIC);
        data.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        data.extend_from_slice(&u64::MAX.to_le_bytes()); // absurd body_len
        data.extend_from_slice(&[0u8; 16]); // some trailing bytes
        let result = GraphSnapshot::from_bytes(&data);
        assert!(
            result.is_err(),
            "overflowing body_len must error, not panic"
        );
    }

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
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

    fn seal_change(mut change: SemanticChange) -> SemanticChange {
        change.id =
            kin_model::compute_semantic_change_id(&change).expect("valid semantic change fixture");
        change
    }

    fn encode_snapshot_without_admission_validation(snapshot: &GraphSnapshot) -> Vec<u8> {
        let body = rmp_serde::to_vec(snapshot).unwrap();
        let mut bytes = Vec::with_capacity(16 + body.len() + GraphSnapshot::CHECKSUM_LEN);
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));
        bytes
    }

    fn test_relation(src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn locate_snapshot_decode_preserves_locate_domains_only() {
        let caller = test_entity("caller");
        let callee = test_entity("callee");
        let relation = test_relation(caller.id, callee.id);
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([9; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added(caller.clone())],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        });

        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities.insert(caller.id, caller.clone());
        snapshot.entities.insert(callee.id, callee.clone());
        snapshot.relations.insert(relation.id, relation.clone());
        snapshot.outgoing.insert(caller.id, vec![relation.id]);
        snapshot.incoming.insert(callee.id, vec![relation.id]);
        snapshot.changes.insert(change.id, change.clone());
        let file_id = FilePathId::new("src/main.rs");
        let assigned_artifact_id = ArtifactId::new();
        snapshot.shallow_files.push(ShallowTrackedFile {
            file_id: file_id.clone(),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Some(Hash256::from_bytes([2; 32])),
            declaration_names: vec!["caller".into(), "callee".into()],
            import_paths: Vec::new(),
        });
        snapshot.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            assigned_artifact_id,
            RepoPath::from_utf8(&file_id.0).unwrap(),
            TreeEntry::blob(Hash256::from_bytes([1; 32]), false),
        )])
        .unwrap();

        let persisted_root_hash = [7; 32];
        let bytes = snapshot
            .to_bytes_with_persisted_root_hash(persisted_root_hash)
            .unwrap();
        let (locate_snapshot, decoded_root_hash) =
            LocateGraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap();

        assert_eq!(decoded_root_hash, Some(persisted_root_hash));
        assert_eq!(locate_snapshot.entities.len(), 2);
        assert_eq!(locate_snapshot.relations.len(), 1);
        assert_eq!(locate_snapshot.changes.len(), 1);
        assert_eq!(locate_snapshot.shallow_files.len(), 1);
        assert_eq!(
            locate_snapshot
                .resolved_tree
                .artifact_id_at_path(&RepoPath::from_utf8(&file_id.0).unwrap()),
            Some(assigned_artifact_id)
        );

        let decoded: GraphSnapshot = locate_snapshot.into();
        assert_eq!(decoded.entities.len(), 2);
        assert_eq!(decoded.relations.len(), 1);
        assert_eq!(decoded.changes.len(), 1);
        assert_eq!(
            decoded
                .resolved_tree
                .artifact_id_at_path(&RepoPath::from_utf8(&file_id.0).unwrap()),
            Some(assigned_artifact_id)
        );
        assert!(decoded.outgoing.is_empty());
        assert!(decoded.incoming.is_empty());
        assert!(decoded.work_items.is_empty());
        assert!(decoded.reviews.is_empty());
    }

    #[test]
    fn compact_empty_snapshot_is_clean() {
        let mut snap = GraphSnapshot::empty();
        let stats = snap.compact();
        assert!(stats.is_clean());
        assert_eq!(stats.total_removed(), 0);
        assert_eq!(stats.entities_before, 0);
        assert_eq!(stats.relations_before, 0);
    }

    #[test]
    fn snapshot_deserialization_rejects_duplicate_artifact_identity_assignments() {
        let snapshot = GraphSnapshot::empty();
        let artifact_id = ArtifactId::new();
        let mut encoded = serde_json::to_value(snapshot).unwrap();
        encoded["resolved_tree"] = serde_json::json!({
            "artifacts": [
                ResolvedArtifact::new(
                    artifact_id,
                    RepoPath::from_utf8("compose.yaml").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([1; 32]), false),
                ),
                ResolvedArtifact::new(
                    artifact_id,
                    RepoPath::from_utf8("Cargo.lock").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([2; 32]), false),
                ),
            ]
        });

        let error = serde_json::from_value::<GraphSnapshot>(encoded).unwrap_err();
        assert!(error.to_string().contains("more than once"));
    }

    #[test]
    fn snapshot_rejects_semantic_enrichment_without_tree_admission() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.structured_artifacts.push(StructuredArtifact {
            file_id: FilePathId::new("compose.yaml"),
            kind: ArtifactKind::ComposeFile,
            content_hash: Hash256::from_bytes([7; 32]),
            text_preview: Some("services:".into()),
        });

        let error = snapshot.to_bytes().unwrap_err();

        assert!(error
            .to_string()
            .contains("without admitted repository identity"));
    }

    #[test]
    fn compact_removes_orphaned_relations() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("alive");
        let e2 = test_entity("dead"); // will not be in entities
        let rel = test_relation(e1.id, e2.id);

        snap.entities.insert(e1.id, e1.clone());
        // e2 is NOT inserted — making the relation orphaned
        snap.relations.insert(rel.id, rel.clone());
        snap.outgoing.insert(e1.id, vec![rel.id]);
        snap.incoming.insert(e2.id, vec![rel.id]);

        let stats = snap.compact();
        assert_eq!(stats.orphaned_relations_removed, 1);
        assert!(snap.relations.is_empty());
        assert!(snap.outgoing.is_empty()); // cleaned because relation was removed
        assert!(snap.incoming.is_empty()); // cleaned because e2 doesn't exist
        assert!(!stats.is_clean());
    }

    #[test]
    fn compact_preserves_valid_relations() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = test_relation(e1.id, e2.id);

        snap.entities.insert(e1.id, e1.clone());
        snap.entities.insert(e2.id, e2.clone());
        snap.relations.insert(rel.id, rel.clone());
        snap.outgoing.insert(e1.id, vec![rel.id]);
        snap.incoming.insert(e2.id, vec![rel.id]);

        let stats = snap.compact();
        assert!(stats.is_clean());
        assert_eq!(snap.relations.len(), 1);
        assert_eq!(snap.outgoing.len(), 1);
        assert_eq!(snap.incoming.len(), 1);
    }

    #[test]
    fn compact_preserves_artifact_relations_with_persisted_artifact_ids() {
        let mut snap = GraphSnapshot::empty();
        let generated_path = FilePathId::new("single_include/nlohmann/json.hpp");
        let source_path = FilePathId::new("include/nlohmann/detail/exceptions.hpp");
        let generated_id = ArtifactId::new();
        let source_id = ArtifactId::new();

        for file_id in [&generated_path, &source_path] {
            snap.file_layouts.push(FileLayout {
                file_id: file_id.clone(),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
                parse_completeness: ParseCompleteness::Full,
            });
        }
        snap.resolved_tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                generated_id,
                RepoPath::from_utf8(&generated_path.0).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([1; 32]), false),
            ),
            ResolvedArtifact::new(
                source_id,
                RepoPath::from_utf8(&source_path.0).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([2; 32]), false),
            ),
        ])
        .unwrap();

        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::DerivedFrom,
            src: GraphNodeId::Artifact(generated_id),
            dst: GraphNodeId::Artifact(source_id),
            confidence: 0.9,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        snap.relations.insert(relation.id, relation);

        let stats = snap.compact();
        assert_eq!(stats.orphaned_relations_removed, 0);
        assert_eq!(snap.relations.len(), 1);
    }

    #[test]
    fn compact_removes_orphaned_mock_hints() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("target");
        snap.entities.insert(e1.id, e1.clone());

        let dead_test = TestId::new();
        snap.mock_hints.push(MockHint {
            hint_id: MockHintId::new(),
            test_id: dead_test,
            dependency_scope: WorkScope::Entity(e1.id),
            strategy: MockStrategy::Stub,
        });

        let stats = snap.compact();
        assert_eq!(stats.orphaned_mock_hints_removed, 1);
        assert!(snap.mock_hints.is_empty());
    }

    #[test]
    fn compact_removes_orphaned_downstream_warnings() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("warned");
        snap.entities.insert(e1.id, e1.clone());
        let dead_intent = IntentId::new();

        snap.downstream_warnings
            .push((dead_intent, e1.id, "stale warning".into()));

        let stats = snap.compact();
        assert_eq!(stats.orphaned_downstream_warnings_removed, 1);
        assert!(snap.downstream_warnings.is_empty());
    }

    #[test]
    fn compact_removes_orphaned_approvals() {
        let mut snap = GraphSnapshot::empty();

        let dead_change = SemanticChangeId::from_hash(Hash256::from_bytes([99; 32]));
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "tester".into(),
            external_refs: vec![],
        };
        snap.actors.insert(actor.actor_id, actor.clone());

        snap.approvals.push(Approval {
            approval_id: ApprovalId::new(),
            change_id: dead_change,
            approver: actor.actor_id,
            decision: ApprovalDecision::Approved,
            reason: "looks good".into(),
            timestamp: Timestamp::now(),
        });

        let stats = snap.compact();
        assert_eq!(stats.orphaned_approvals_removed, 1);
        assert!(snap.approvals.is_empty());
    }

    #[test]
    fn compact_removes_orphaned_delegations() {
        let mut snap = GraphSnapshot::empty();

        let dead_actor = ActorId::new();
        let live_actor = ActorId::new();
        snap.actors.insert(
            live_actor,
            Actor {
                actor_id: live_actor,
                kind: ActorKind::Human,
                display_name: "live".into(),
                external_refs: vec![],
            },
        );

        snap.delegations.push(Delegation {
            delegation_id: DelegationId::new(),
            principal: live_actor,
            delegate: dead_actor, // doesn't exist
            scope: vec![],
            started_at: Timestamp::now(),
            ended_at: None,
        });

        let stats = snap.compact();
        assert_eq!(stats.orphaned_delegations_removed, 1);
        assert!(snap.delegations.is_empty());
    }

    #[test]
    fn compact_stats_total_removed() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("live");
        snap.entities.insert(e1.id, e1.clone());
        let dead_entity = EntityId::new();

        // Add multiple types of orphaned data
        let rel = test_relation(e1.id, dead_entity);
        snap.relations.insert(rel.id, rel);

        let dead_intent = IntentId::new();
        snap.downstream_warnings
            .push((dead_intent, e1.id, "orphan".into()));

        let stats = snap.compact();
        assert!(stats.total_removed() >= 2);
        assert!(!stats.is_clean());
    }

    #[test]
    fn compact_roundtrip_produces_identical_bytes() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("a");
        let e2 = test_entity("b");
        let rel = test_relation(e1.id, e2.id);

        snap.entities.insert(e1.id, e1.clone());
        snap.entities.insert(e2.id, e2.clone());
        snap.relations.insert(rel.id, rel.clone());
        snap.outgoing.insert(e1.id, vec![rel.id]);
        snap.incoming.insert(e2.id, vec![rel.id]);

        // Compact a clean snapshot — should be idempotent
        snap.compact();
        let bytes1 = snap.to_bytes().unwrap();

        snap.compact();
        let bytes2 = snap.to_bytes().unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn to_bytes_rejects_noncurrent_body_version() {
        let mut snap = GraphSnapshot::empty();
        let e = test_entity("fast_path");
        snap.entities.insert(e.id, e);

        assert_eq!(snap.version, GraphSnapshot::CURRENT_VERSION);
        assert!(snap.to_bytes().is_ok());

        snap.version = 1;
        let error = snap.to_bytes().unwrap_err();
        assert!(error.to_string().contains("exactly v10"));
    }

    #[test]
    fn roundtrip_empty_snapshot() {
        let snap = GraphSnapshot::empty();

        let bytes = snap.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.entities.is_empty());
    }

    #[test]
    fn roundtrip_preserves_executable_symlink_and_unsupported_paths() {
        let mut snapshot = GraphSnapshot::empty();
        let executable = TreeEntry::blob(Hash256::from_bytes([0x41; 32]), true);
        let symlink = TreeEntry::symlink(Hash256::from_bytes([0x42; 32]));
        let opaque = TreeEntry::blob(Hash256::from_bytes([0x43; 32]), false);
        snapshot.resolved_tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("scripts/deploy").unwrap(),
                executable,
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("current-config").unwrap(),
                symlink,
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("assets/model.unsupported").unwrap(),
                opaque,
            ),
        ])
        .unwrap();

        let loaded = GraphSnapshot::from_bytes(&snapshot.to_bytes().unwrap()).unwrap();

        assert_eq!(
            loaded
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("scripts/deploy").unwrap())
                .map(|artifact| artifact.entry),
            Some(executable)
        );
        assert_eq!(
            loaded
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("current-config").unwrap())
                .map(|artifact| artifact.entry),
            Some(symlink)
        );
        assert_eq!(
            loaded
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("assets/model.unsupported").unwrap())
                .map(|artifact| artifact.entry),
            Some(opaque)
        );
    }

    #[test]
    fn current_snapshot_requires_every_persisted_field() {
        let encoded = serde_json::to_value(GraphSnapshot::empty()).unwrap();
        let fields: Vec<String> = encoded
            .as_object()
            .expect("snapshot serializes as a map")
            .keys()
            .cloned()
            .collect();

        for field in fields {
            let mut missing = encoded.clone();
            missing
                .as_object_mut()
                .expect("snapshot serializes as a map")
                .remove(&field);

            let error = serde_json::from_value::<GraphSnapshot>(missing).unwrap_err();
            assert!(
                error.to_string().contains(&field),
                "missing {field} should fail explicitly: {error}"
            );
        }
    }

    #[test]
    fn current_snapshot_rejects_unknown_persisted_fields() {
        let mut encoded = serde_json::to_value(GraphSnapshot::empty()).unwrap();
        encoded
            .as_object_mut()
            .expect("snapshot serializes as a map")
            .insert("working_tree".to_string(), serde_json::json!([]));

        let error = serde_json::from_value::<GraphSnapshot>(encoded).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `working_tree`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn current_version_checksum_is_appended() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Header: 4 magic + 4 version + 8 body_len = 16
        let body_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        // Total should be header + body + 32-byte checksum
        assert_eq!(bytes.len(), 16 + body_len + GraphSnapshot::CHECKSUM_LEN);

        // Version in header should match the current format version.
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn snapshot_decode_rejects_corrupted_semantic_change_identity() {
        let mut snapshot = GraphSnapshot::empty();
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x91; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "valid before corruption".into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        });
        snapshot.changes.insert(change.id, change.clone());
        snapshot
            .changes
            .get_mut(&change.id)
            .unwrap()
            .message
            .push_str(" after id was sealed");

        let bytes = encode_snapshot_without_admission_validation(&snapshot);
        let error = GraphSnapshot::from_bytes(&bytes)
            .expect_err("checksum-valid snapshot corruption must fail identity validation");
        assert!(error.to_string().contains("recomputes to"));

        let error = GraphSnapshot::from_bytes_with_persisted_root_hash_unverified(&bytes)
            .expect_err("the mmap checksum shortcut must still validate change identity");
        assert!(error.to_string().contains("recomputes to"));
    }

    #[test]
    fn current_version_roundtrips_persisted_root_hash_trailer() {
        let mut snap = GraphSnapshot::empty();
        let entity = test_entity("persisted-root");
        snap.entities.insert(entity.id, entity);
        let root_hash = crate::storage::merkle::compute_graph_root_hash(&snap);

        let bytes = snap.to_bytes_with_persisted_root_hash(root_hash).unwrap();
        let body_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        assert_eq!(
            bytes.len(),
            16 + body_len + GraphSnapshot::CHECKSUM_LEN + GraphSnapshot::ROOT_HASH_TRAILER_LEN
        );

        let (loaded, persisted_root_hash) =
            GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap();
        assert_eq!(persisted_root_hash, Some(root_hash));
        assert_eq!(loaded.entities.len(), 1);
    }

    #[test]
    fn current_version_unverified_load_reads_persisted_root_hash_trailer() {
        let mut snap = GraphSnapshot::empty();
        let entity = test_entity("persisted-root-unverified");
        snap.entities.insert(entity.id, entity);
        let root_hash = crate::storage::merkle::compute_graph_root_hash(&snap);

        let (loaded, persisted_root_hash) =
            GraphSnapshot::from_bytes_with_persisted_root_hash_unverified(
                &snap.to_bytes_with_persisted_root_hash(root_hash).unwrap(),
            )
            .unwrap();
        assert_eq!(persisted_root_hash, Some(root_hash));
        assert_eq!(loaded.entities.len(), 1);
    }

    #[test]
    fn corrupted_persisted_root_hash_trailer_is_rejected() {
        let snap = GraphSnapshot::empty();
        let root_hash = crate::storage::merkle::compute_graph_root_hash(&snap);
        let mut bytes = snap.to_bytes_with_persisted_root_hash(root_hash).unwrap();
        let trailer_digest_offset = bytes.len() - 1;
        bytes[trailer_digest_offset] ^= 0xFF;

        let err = GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("root-hash trailer mismatch") || msg.contains("corrupted"),
            "expected root-hash trailer error, got: {msg}"
        );
    }

    #[test]
    fn current_version_corrupted_body_detected() {
        let snap = GraphSnapshot::empty();
        let mut bytes = snap.to_bytes().unwrap();

        // Corrupt a byte in the body (after the 16-byte header)
        if bytes.len() > 20 {
            bytes[20] ^= 0xFF;
        }

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("checksum mismatch") || msg.contains("corrupted"),
            "expected checksum error, got: {msg}"
        );
    }

    #[test]
    fn current_version_truncated_checksum_detected() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Truncate the last 10 bytes (partial checksum)
        let truncated = &bytes[..bytes.len() - 10];

        let err = GraphSnapshot::from_bytes(truncated).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing checksum"),
            "expected missing checksum error, got: {msg}"
        );
    }

    #[test]
    fn rejects_v2_snapshot_without_inventing_tree_modes() {
        let snap = GraphSnapshot::empty();
        let mut snapshot = snap.clone();
        snapshot.version = 2;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);

        let error = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            error,
            crate::KinDbError::IncompatibleSnapshotVersion { found: 2, .. }
        ));
    }

    /// A snapshot written by an older Kin (schema predating the supported
    /// range) must fail fast with an explicit, actionable error naming the
    /// version gap and remediation — never a panic/crash during load.
    #[test]
    fn old_schema_snapshot_fails_fast_with_actionable_error() {
        // Build a well-formed KNDB frame whose format version predates the
        // minimum supported version (stand-in for a pre-versioning 0.1.x graph).
        let stale_version = GraphSnapshot::MIN_SUPPORTED_VERSION - 1;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&stale_version.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes()); // empty body

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::KinDbError::IncompatibleSnapshotVersion { found, .. }
                    if found == stale_version
            ),
            "expected IncompatibleSnapshotVersion, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("older than"),
            "missing version-gap wording: {msg}"
        );
        assert!(
            msg.contains(&format!(
                "versions {} through {}",
                GraphSnapshot::MIN_SUPPORTED_VERSION,
                GraphSnapshot::CURRENT_VERSION
            )),
            "missing supported-range wording: {msg}"
        );
        assert!(
            msg.contains("reinitialize") && msg.contains("exact file modes"),
            "missing exact-tree remediation: {msg}"
        );
    }

    /// A snapshot written by a newer Kin must also fail fast with a typed,
    /// actionable error (upgrade guidance) rather than crashing.
    #[test]
    fn future_schema_snapshot_fails_fast_with_actionable_error() {
        let future_version = GraphSnapshot::CURRENT_VERSION + 1;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&future_version.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::KinDbError::IncompatibleSnapshotVersion { found, .. }
                    if found == future_version
            ),
            "expected IncompatibleSnapshotVersion, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("newer than"),
            "missing version-gap wording: {msg}"
        );
        assert!(
            msg.contains("upgrade Kin"),
            "missing upgrade remediation: {msg}"
        );
    }

    #[test]
    fn rejects_current_layout_body_with_v3_envelope() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.version = 3;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));

        let error = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            error,
            crate::KinDbError::IncompatibleSnapshotVersion { found: 3, .. }
        ));
    }

    #[test]
    fn snapshot_roundtrips_file_layouts() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.admit_artifact_for_test(
            "src/lib.rs".to_string(),
            crate::types::regular_tree_entry(1),
        );
        snapshot.file_layouts.push(FileLayout {
            file_id: FilePathId::new("src/lib.rs"),
            parse_completeness: ParseCompleteness::Partial("1 parse error range(s)".into()),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::Trivia { byte_range: 0..42 }],
        });

        let bytes = snapshot.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.file_layouts.len(), 1);
        assert_eq!(
            loaded.file_layouts[0].parse_completeness,
            ParseCompleteness::Partial("1 parse error range(s)".into())
        );
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(GraphSnapshot::from_bytes(&data).is_err());
    }
}
