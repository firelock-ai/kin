// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::HashMap as FastHashMap;
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

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
    /// Test coverage entries removed (non-existent test or entity/contract/work).
    pub orphaned_test_coverage_removed: usize,
    /// Verification run references removed (non-existent run, entity, or work).
    pub orphaned_verification_refs_removed: usize,
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
            + self.orphaned_test_coverage_removed
            + self.orphaned_verification_refs_removed
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
pub struct GraphSnapshot {
    pub version: u32,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub outgoing: HashMap<EntityId, Vec<RelationId>>,
    pub incoming: HashMap<EntityId, Vec<RelationId>>,
    pub changes: HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub branches: HashMap<BranchName, Branch>,
    #[serde(default)]
    pub work_items: HashMap<WorkId, WorkItem>,
    #[serde(default)]
    pub annotations: HashMap<AnnotationId, Annotation>,
    #[serde(default)]
    pub work_links: Vec<WorkLink>,
    #[serde(default)]
    pub reviews: HashMap<ReviewId, Review>,
    #[serde(default)]
    pub review_decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    #[serde(default)]
    pub review_notes: Vec<ReviewNote>,
    #[serde(default)]
    pub review_discussions: Vec<ReviewDiscussion>,
    #[serde(default)]
    pub review_assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
    #[serde(default)]
    pub test_cases: HashMap<TestId, TestCase>,
    #[serde(default)]
    pub assertions: HashMap<AssertionId, Assertion>,
    #[serde(default)]
    pub verification_runs: HashMap<VerificationRunId, VerificationRun>,
    #[serde(default)]
    pub test_covers_entity: Vec<(TestId, EntityId)>,
    #[serde(default)]
    pub test_covers_contract: Vec<(TestId, ContractId)>,
    #[serde(default)]
    pub test_verifies_work: Vec<(TestId, WorkId)>,
    #[serde(default)]
    pub run_proves_entity: Vec<(VerificationRunId, EntityId)>,
    #[serde(default)]
    pub run_proves_work: Vec<(VerificationRunId, WorkId)>,
    #[serde(default)]
    pub mock_hints: Vec<MockHint>,
    #[serde(default)]
    pub contracts: HashMap<ContractId, Contract>,
    #[serde(default)]
    pub actors: HashMap<ActorId, Actor>,
    #[serde(default)]
    pub delegations: Vec<Delegation>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default)]
    pub audit_events: Vec<AuditEvent>,
    #[serde(default)]
    pub shallow_files: Vec<ShallowTrackedFile>,
    #[serde(default)]
    pub file_layouts: Vec<FileLayout>,
    #[serde(default)]
    pub structured_artifacts: Vec<StructuredArtifact>,
    #[serde(default)]
    pub opaque_artifacts: Vec<OpaqueArtifact>,
    #[serde(default)]
    pub file_hashes: HashMap<String, [u8; 32]>,
    #[serde(default)]
    pub sessions: HashMap<SessionId, AgentSession>,
    #[serde(default)]
    pub intents: HashMap<IntentId, Intent>,
    #[serde(default)]
    pub downstream_warnings: Vec<(IntentId, EntityId, String)>,
    #[serde(default)]
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
}

fn relation_kind_used_by_locate(kind: RelationKind) -> bool {
    matches!(
        kind,
        RelationKind::Calls
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
    pub const CURRENT_VERSION: u32 = 7;

    /// Magic bytes for the file header: "KNDB"
    pub const MAGIC: [u8; 4] = *b"KNDB";

    /// Size of the checksum appended to v3+ snapshots.
    pub const CHECKSUM_LEN: usize = 32;

    /// Optional trailer magic that binds a persisted graph root hash to the
    /// already-verified snapshot body checksum without changing the v6 body
    /// layout. Older readers ignore these trailing bytes.
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
            test_covers_entity: Vec::new(),
            test_covers_contract: Vec::new(),
            test_verifies_work: Vec::new(),
            run_proves_entity: Vec::new(),
            run_proves_work: Vec::new(),
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
            file_hashes: HashMap::new(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
            entity_revisions: HashMap::new(),
        }
    }

    /// Compact the snapshot by removing orphaned data.
    ///
    /// Performs garbage collection across all cross-referenced collections:
    /// - Relations whose src or dst entity no longer exists
    /// - Outgoing/incoming edge lists referencing non-existent entities or relations
    /// - Test coverage entries for non-existent tests, entities, contracts, or work items
    /// - Verification run references for non-existent runs, entities, or work items
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
            .shallow_files
            .iter()
            .map(|file| ArtifactId::from_file_id(&file.file_id))
            .chain(
                self.structured_artifacts
                    .iter()
                    .map(|artifact| ArtifactId::from_file_id(&artifact.file_id)),
            )
            .chain(
                self.opaque_artifacts
                    .iter()
                    .map(|artifact| ArtifactId::from_file_id(&artifact.file_id)),
            )
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

        // 4. Clean legacy test coverage entries
        let mut coverage_removed = 0usize;
        let before = self.test_covers_entity.len();
        self.test_covers_entity
            .retain(|(tid, eid)| test_ids.contains(tid) && entity_ids.contains(eid));
        coverage_removed += before - self.test_covers_entity.len();

        let before = self.test_covers_contract.len();
        self.test_covers_contract
            .retain(|(tid, cid)| test_ids.contains(tid) && contract_ids.contains(cid));
        coverage_removed += before - self.test_covers_contract.len();

        let before = self.test_verifies_work.len();
        self.test_verifies_work
            .retain(|(tid, wid)| test_ids.contains(tid) && work_ids.contains(wid));
        coverage_removed += before - self.test_verifies_work.len();
        stats.orphaned_test_coverage_removed = coverage_removed;

        // 5. Clean legacy verification run references
        let mut vr_removed = 0usize;
        let before = self.run_proves_entity.len();
        self.run_proves_entity
            .retain(|(rid, eid)| run_ids.contains(rid) && entity_ids.contains(eid));
        vr_removed += before - self.run_proves_entity.len();

        let before = self.run_proves_work.len();
        self.run_proves_work
            .retain(|(rid, wid)| run_ids.contains(rid) && work_ids.contains(wid));
        vr_removed += before - self.run_proves_work.len();
        stats.orphaned_verification_refs_removed = vr_removed;

        // 6. Clean mock hints for non-existent tests
        let before = self.mock_hints.len();
        self.mock_hints
            .retain(|hint| test_ids.contains(&hint.test_id));
        stats.orphaned_mock_hints_removed = before - self.mock_hints.len();

        // 7. Clean downstream warnings for non-existent intents or entities
        let intent_ids: HashSet<IntentId> = self.intents.keys().copied().collect();
        let before = self.downstream_warnings.len();
        self.downstream_warnings
            .retain(|(iid, eid, _)| intent_ids.contains(iid) && entity_ids.contains(eid));
        stats.orphaned_downstream_warnings_removed = before - self.downstream_warnings.len();

        // 8. Clean approvals for non-existent changes
        let change_ids: HashSet<SemanticChangeId> = self.changes.keys().copied().collect();
        let before = self.approvals.len();
        self.approvals.retain(|a| change_ids.contains(&a.change_id));
        stats.orphaned_approvals_removed = before - self.approvals.len();

        // 9. Clean delegations for non-existent actors
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
        let body = if self.version == Self::CURRENT_VERSION {
            // Fast path: version matches, serialize directly without cloning.
            // This saves ~200MB+ of peak memory for graphs with >500K entities.
            rmp_serde::to_vec(self).map_err(|e| {
                crate::error::KinDbError::StorageError(format!("serialization failed: {e}"))
            })?
        } else {
            // Slow path: version mismatch, must clone and update version.
            let mut snapshot = self.clone();
            snapshot.version = Self::CURRENT_VERSION;
            rmp_serde::to_vec(&snapshot).map_err(|e| {
                crate::error::KinDbError::StorageError(format!("serialization failed: {e}"))
            })?
        };

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
    /// - v1/v2: no checksum
    /// - v3+: checksum verified; returns error on mismatch
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
            1 => {
                let legacy: GraphSnapshotV1 = rmp_serde::from_slice(frame.body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })?;
                legacy.into()
            }
            2 => rmp_serde::from_slice(frame.body).map_err(|e| {
                crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
            })?,
            3 => Self::decode_v3_snapshot(frame.body)?,
            4 => Self::decode_v4_snapshot(frame.body)?,
            5 => {
                let migrated = super::migration::migrate(frame.body, 5, Self::CURRENT_VERSION)?;
                Self::decode_current_snapshot(&migrated)?
            }
            6 => {
                let migrated = super::migration::migrate(frame.body, 6, Self::CURRENT_VERSION)?;
                Self::decode_current_snapshot(&migrated)?
            }
            7 => Self::decode_current_snapshot(frame.body)?,
            _ => unreachable!("decode_frame validates supported versions"),
        };

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
        if data.len() < 16 + body_len {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot file truncated: body extends past end of data".to_string(),
            ));
        }
        let body = &data[16..16 + body_len];

        match version {
            1 | 2 => Ok(SnapshotFrame {
                version,
                body,
                body_checksum: None,
                checksum_end: 16 + body_len,
            }),
            3 => {
                let checksum_end = Self::require_checksum_slot(data, body_len, "v3")?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, "v3")?)
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
            4 => {
                let checksum_end = Self::require_checksum_slot(data, body_len, "v4")?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, "v4")?)
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
            5 => {
                let checksum_end = Self::require_checksum_slot(data, body_len, "v5")?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, "v5")?)
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
            6 => {
                let checksum_end = Self::require_checksum_slot(data, body_len, "v6")?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, "v6")?)
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
            7 => {
                let checksum_end = Self::require_checksum_slot(data, body_len, "v7")?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, "v7")?)
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
            _ => Err(crate::error::KinDbError::StorageError(format!(
                "unsupported format version: {version} (expected 1 through {})",
                Self::CURRENT_VERSION
            ))),
        }
    }

    fn decode_current_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.decode_current_snapshot").entered();
        rmp_serde::from_slice(body).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
        })
    }

    fn decode_v3_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        match Self::decode_current_snapshot(body) {
            Ok(snapshot) => Ok(snapshot),
            Err(current_err) => {
                let legacy: GraphSnapshotV3Legacy = rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!(
                        "deserialization failed: {e}; current-layout decode also failed: {current_err}"
                    ))
                })?;
                Ok(legacy.into())
            }
        }
    }

    fn decode_v4_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        match Self::decode_current_snapshot(body) {
            Ok(snapshot) => Ok(snapshot),
            Err(current_err) => {
                let legacy: GraphSnapshotV4Legacy = rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!(
                        "deserialization failed: {e}; current-layout decode also failed: {current_err}"
                    ))
                })?;
                Ok(legacy.into())
            }
        }
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
        let checksum_start = 16 + body_len;
        let checksum_end = checksum_start + Self::CHECKSUM_LEN;
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
            6 => {
                let migrated =
                    super::migration::migrate(frame.body, 6, GraphSnapshot::CURRENT_VERSION)?;
                GraphSnapshot::decode_current_snapshot(&migrated)?.into()
            }
            7 => Self::decode_current_snapshot(frame.body)?,
            1 => {
                let legacy: GraphSnapshotV1 = rmp_serde::from_slice(frame.body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })?;
                GraphSnapshot::from(legacy).into()
            }
            2 => {
                let snapshot: GraphSnapshot = rmp_serde::from_slice(frame.body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })?;
                snapshot.into()
            }
            3 => GraphSnapshot::decode_v3_snapshot(frame.body)?.into(),
            4 => GraphSnapshot::decode_v4_snapshot(frame.body)?.into(),
            5 => {
                let migrated =
                    super::migration::migrate(frame.body, 5, GraphSnapshot::CURRENT_VERSION)?;
                GraphSnapshot::decode_current_snapshot(&migrated)?.into()
            }
            _ => unreachable!("decode_frame validates supported versions"),
        };

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

                for index in 6..30 {
                    let _: IgnoredAny = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }

                let shallow_files = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(30, &self))?;
                let file_layouts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(31, &self))?;
                let structured_artifacts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(32, &self))?;
                let opaque_artifacts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(33, &self))?;

                while let Some(_) = seq.next_element::<IgnoredAny>()? {}

                Ok(LocateGraphSnapshot {
                    version,
                    entities,
                    relations,
                    changes,
                    shallow_files,
                    file_layouts,
                    structured_artifacts,
                    opaque_artifacts,
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
/// The `Serialize` impl manually writes 39 fields in the same positional
/// order as the derive(Serialize) on `GraphSnapshot`, so the resulting
/// msgpack is byte-for-byte compatible with the owned version.
pub struct BorrowedGraphSnapshot<'a> {
    // EntityData fields
    pub entities: &'a hashbrown::HashMap<EntityId, Entity>,
    pub relations: &'a hashbrown::HashMap<RelationId, Relation>,
    pub outgoing: &'a hashbrown::HashMap<EntityId, Vec<RelationId>>,
    pub incoming: &'a hashbrown::HashMap<EntityId, Vec<RelationId>>,
    pub file_hashes: &'a hashbrown::HashMap<String, [u8; 32]>,
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
        // Must produce exactly 39 fields in the same order as GraphSnapshot's
        // derive(Serialize).  rmp_serde serializes structs as arrays, so
        // position (not name) determines the mapping.
        let mut state = serializer.serialize_struct("GraphSnapshot", 39)?;

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
        // 20-24. coverage vecs — empty in to_snapshot()
        let empty_tid_eid: &[(TestId, EntityId)] = &[];
        let empty_tid_cid: &[(TestId, ContractId)] = &[];
        let empty_tid_wid: &[(TestId, WorkId)] = &[];
        let empty_rid_eid: &[(VerificationRunId, EntityId)] = &[];
        let empty_rid_wid: &[(VerificationRunId, WorkId)] = &[];
        state.serialize_field("test_covers_entity", empty_tid_eid)?;
        state.serialize_field("test_covers_contract", empty_tid_cid)?;
        state.serialize_field("test_verifies_work", empty_tid_wid)?;
        state.serialize_field("run_proves_entity", empty_rid_eid)?;
        state.serialize_field("run_proves_work", empty_rid_wid)?;
        // 25. mock_hints
        state.serialize_field("mock_hints", self.mock_hints)?;
        // 26. contracts
        state.serialize_field("contracts", self.contracts)?;
        // 27. actors
        state.serialize_field("actors", self.actors)?;
        // 28. delegations
        state.serialize_field("delegations", self.delegations)?;
        // 29. approvals
        state.serialize_field("approvals", self.approvals)?;
        // 30. audit_events
        state.serialize_field("audit_events", self.audit_events)?;
        // 31. shallow_files  (HashMap values → seq)
        state.serialize_field("shallow_files", &HashMapValuesAsSeq(self.shallow_files))?;
        // 32. file_layouts  (HashMap values → seq)
        state.serialize_field("file_layouts", &HashMapValuesAsSeq(self.file_layouts))?;
        // 33. structured_artifacts  (HashMap values → seq)
        state.serialize_field(
            "structured_artifacts",
            &HashMapValuesAsSeq(self.structured_artifacts),
        )?;
        // 34. opaque_artifacts  (HashMap values → seq)
        state.serialize_field(
            "opaque_artifacts",
            &HashMapValuesAsSeq(self.opaque_artifacts),
        )?;
        // 35. file_hashes
        state.serialize_field("file_hashes", self.file_hashes)?;
        // 36. sessions
        state.serialize_field("sessions", self.sessions)?;
        // 37. intents
        state.serialize_field("intents", self.intents)?;
        // 38. downstream_warnings
        state.serialize_field("downstream_warnings", self.downstream_warnings)?;
        // 39. entity_revisions
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

#[derive(Debug, Serialize, Deserialize)]
struct GraphSnapshotV1 {
    version: u32,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, LegacyEntityRelation>,
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    incoming: HashMap<EntityId, Vec<RelationId>>,
    changes: HashMap<SemanticChangeId, SemanticChange>,
    change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    branches: HashMap<BranchName, Branch>,
}

impl From<GraphSnapshotV1> for GraphSnapshot {
    fn from(value: GraphSnapshotV1) -> Self {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = value.entities;
        snapshot.relations = value
            .relations
            .into_iter()
            .map(|(relation_id, relation)| (relation_id, relation.into()))
            .collect();
        snapshot.outgoing = value.outgoing;
        snapshot.incoming = value.incoming;
        snapshot.changes = value.changes;
        snapshot.change_children = value.change_children;
        snapshot.branches = value.branches;
        snapshot
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LegacyEntityRelation {
    pub(crate) id: RelationId,
    pub(crate) kind: RelationKind,
    pub(crate) src: EntityId,
    pub(crate) dst: EntityId,
    pub(crate) confidence: f32,
    pub(crate) origin: RelationOrigin,
    pub(crate) created_in: Option<SemanticChangeId>,
    #[serde(default)]
    pub(crate) import_source: Option<String>,
}

impl From<LegacyEntityRelation> for Relation {
    fn from(value: LegacyEntityRelation) -> Self {
        Self {
            id: value.id,
            kind: value.kind,
            src: GraphNodeId::Entity(value.src),
            dst: GraphNodeId::Entity(value.dst),
            confidence: value.confidence,
            origin: value.origin,
            created_in: value.created_in,
            import_source: value.import_source,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GraphSnapshotV3Legacy {
    version: u32,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, LegacyEntityRelation>,
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    incoming: HashMap<EntityId, Vec<RelationId>>,
    changes: HashMap<SemanticChangeId, SemanticChange>,
    change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    branches: HashMap<BranchName, Branch>,
    #[serde(default)]
    work_items: HashMap<WorkId, WorkItem>,
    #[serde(default)]
    annotations: HashMap<AnnotationId, Annotation>,
    #[serde(default)]
    work_links: Vec<WorkLink>,
    #[serde(default)]
    test_cases: HashMap<TestId, TestCase>,
    #[serde(default)]
    assertions: HashMap<AssertionId, Assertion>,
    #[serde(default)]
    verification_runs: HashMap<VerificationRunId, VerificationRun>,
    #[serde(default)]
    test_covers_entity: Vec<(TestId, EntityId)>,
    #[serde(default)]
    test_covers_contract: Vec<(TestId, ContractId)>,
    #[serde(default)]
    test_verifies_work: Vec<(TestId, WorkId)>,
    #[serde(default)]
    run_proves_entity: Vec<(VerificationRunId, EntityId)>,
    #[serde(default)]
    run_proves_work: Vec<(VerificationRunId, WorkId)>,
    #[serde(default)]
    mock_hints: Vec<MockHint>,
    #[serde(default)]
    contracts: HashMap<ContractId, Contract>,
    #[serde(default)]
    actors: HashMap<ActorId, Actor>,
    #[serde(default)]
    delegations: Vec<Delegation>,
    #[serde(default)]
    approvals: Vec<Approval>,
    #[serde(default)]
    audit_events: Vec<AuditEvent>,
    #[serde(default)]
    shallow_files: Vec<ShallowTrackedFile>,
    #[serde(default)]
    structured_artifacts: Vec<StructuredArtifact>,
    #[serde(default)]
    opaque_artifacts: Vec<OpaqueArtifact>,
    #[serde(default)]
    file_hashes: HashMap<String, [u8; 32]>,
    #[serde(default)]
    sessions: HashMap<SessionId, AgentSession>,
    #[serde(default)]
    intents: HashMap<IntentId, Intent>,
    #[serde(default)]
    downstream_warnings: Vec<(IntentId, EntityId, String)>,
}

impl From<GraphSnapshotV3Legacy> for GraphSnapshot {
    fn from(value: GraphSnapshotV3Legacy) -> Self {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = value.entities;
        snapshot.relations = value
            .relations
            .into_iter()
            .map(|(relation_id, relation)| (relation_id, relation.into()))
            .collect();
        snapshot.outgoing = value.outgoing;
        snapshot.incoming = value.incoming;
        snapshot.changes = value.changes;
        snapshot.change_children = value.change_children;
        snapshot.branches = value.branches;
        snapshot.work_items = value.work_items;
        snapshot.annotations = value.annotations;
        snapshot.work_links = value.work_links;
        snapshot.test_cases = value.test_cases;
        snapshot.assertions = value.assertions;
        snapshot.verification_runs = value.verification_runs;
        snapshot.test_covers_entity = value.test_covers_entity;
        snapshot.test_covers_contract = value.test_covers_contract;
        snapshot.test_verifies_work = value.test_verifies_work;
        snapshot.run_proves_entity = value.run_proves_entity;
        snapshot.run_proves_work = value.run_proves_work;
        snapshot.mock_hints = value.mock_hints;
        snapshot.contracts = value.contracts;
        snapshot.actors = value.actors;
        snapshot.delegations = value.delegations;
        snapshot.approvals = value.approvals;
        snapshot.audit_events = value.audit_events;
        snapshot.shallow_files = value.shallow_files;
        snapshot.structured_artifacts = value.structured_artifacts;
        snapshot.opaque_artifacts = value.opaque_artifacts;
        snapshot.file_hashes = value.file_hashes;
        snapshot.sessions = value.sessions;
        snapshot.intents = value.intents;
        snapshot.downstream_warnings = value.downstream_warnings;
        snapshot
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct GraphSnapshotV4Legacy {
    pub(crate) version: u32,
    pub(crate) entities: HashMap<EntityId, Entity>,
    pub(crate) relations: HashMap<RelationId, LegacyEntityRelation>,
    pub(crate) outgoing: HashMap<EntityId, Vec<RelationId>>,
    pub(crate) incoming: HashMap<EntityId, Vec<RelationId>>,
    pub(crate) changes: HashMap<SemanticChangeId, SemanticChange>,
    pub(crate) change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub(crate) branches: HashMap<BranchName, Branch>,
    #[serde(default)]
    pub(crate) work_items: HashMap<WorkId, WorkItem>,
    #[serde(default)]
    pub(crate) annotations: HashMap<AnnotationId, Annotation>,
    #[serde(default)]
    pub(crate) work_links: Vec<WorkLink>,
    #[serde(default)]
    pub(crate) reviews: HashMap<ReviewId, Review>,
    #[serde(default)]
    pub(crate) review_decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    #[serde(default)]
    pub(crate) review_notes: Vec<ReviewNote>,
    #[serde(default)]
    pub(crate) review_discussions: Vec<ReviewDiscussion>,
    #[serde(default)]
    pub(crate) review_assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
    #[serde(default)]
    pub(crate) test_cases: HashMap<TestId, TestCase>,
    #[serde(default)]
    pub(crate) assertions: HashMap<AssertionId, Assertion>,
    #[serde(default)]
    pub(crate) verification_runs: HashMap<VerificationRunId, VerificationRun>,
    #[serde(default)]
    pub(crate) test_covers_entity: Vec<(TestId, EntityId)>,
    #[serde(default)]
    pub(crate) test_covers_contract: Vec<(TestId, ContractId)>,
    #[serde(default)]
    pub(crate) test_verifies_work: Vec<(TestId, WorkId)>,
    #[serde(default)]
    pub(crate) run_proves_entity: Vec<(VerificationRunId, EntityId)>,
    #[serde(default)]
    pub(crate) run_proves_work: Vec<(VerificationRunId, WorkId)>,
    #[serde(default)]
    pub(crate) mock_hints: Vec<MockHint>,
    #[serde(default)]
    pub(crate) contracts: HashMap<ContractId, Contract>,
    #[serde(default)]
    pub(crate) actors: HashMap<ActorId, Actor>,
    #[serde(default)]
    pub(crate) delegations: Vec<Delegation>,
    #[serde(default)]
    pub(crate) approvals: Vec<Approval>,
    #[serde(default)]
    pub(crate) audit_events: Vec<AuditEvent>,
    #[serde(default)]
    pub(crate) shallow_files: Vec<ShallowTrackedFile>,
    #[serde(default)]
    pub(crate) file_layouts: Vec<FileLayout>,
    #[serde(default)]
    pub(crate) structured_artifacts: Vec<StructuredArtifact>,
    #[serde(default)]
    pub(crate) opaque_artifacts: Vec<OpaqueArtifact>,
    #[serde(default)]
    pub(crate) file_hashes: HashMap<String, [u8; 32]>,
    #[serde(default)]
    pub(crate) sessions: HashMap<SessionId, AgentSession>,
    #[serde(default)]
    pub(crate) intents: HashMap<IntentId, Intent>,
    #[serde(default)]
    pub(crate) downstream_warnings: Vec<(IntentId, EntityId, String)>,
}

impl From<GraphSnapshotV4Legacy> for GraphSnapshot {
    fn from(value: GraphSnapshotV4Legacy) -> Self {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = value.entities;
        snapshot.relations = value
            .relations
            .into_iter()
            .map(|(relation_id, relation)| (relation_id, relation.into()))
            .collect();
        snapshot.outgoing = value.outgoing;
        snapshot.incoming = value.incoming;
        snapshot.changes = value.changes;
        snapshot.change_children = value.change_children;
        snapshot.branches = value.branches;
        snapshot.work_items = value.work_items;
        snapshot.annotations = value.annotations;
        snapshot.work_links = value.work_links;
        snapshot.reviews = value.reviews;
        snapshot.review_decisions = value.review_decisions;
        snapshot.review_notes = value.review_notes;
        snapshot.review_discussions = value.review_discussions;
        snapshot.review_assignments = value.review_assignments;
        snapshot.test_cases = value.test_cases;
        snapshot.assertions = value.assertions;
        snapshot.verification_runs = value.verification_runs;
        snapshot.test_covers_entity = value.test_covers_entity;
        snapshot.test_covers_contract = value.test_covers_contract;
        snapshot.test_verifies_work = value.test_verifies_work;
        snapshot.run_proves_entity = value.run_proves_entity;
        snapshot.run_proves_work = value.run_proves_work;
        snapshot.mock_hints = value.mock_hints;
        snapshot.contracts = value.contracts;
        snapshot.actors = value.actors;
        snapshot.delegations = value.delegations;
        snapshot.approvals = value.approvals;
        snapshot.audit_events = value.audit_events;
        snapshot.shallow_files = value.shallow_files;
        snapshot.file_layouts = value.file_layouts;
        snapshot.structured_artifacts = value.structured_artifacts;
        snapshot.opaque_artifacts = value.opaque_artifacts;
        snapshot.file_hashes = value.file_hashes;
        snapshot.sessions = value.sessions;
        snapshot.intents = value.intents;
        snapshot.downstream_warnings = value.downstream_warnings;
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{EntityStore, VerificationStore};

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
        }
    }

    #[test]
    fn locate_snapshot_decode_preserves_locate_domains_only() {
        let caller = test_entity("caller");
        let callee = test_entity("callee");
        let relation = test_relation(caller.id, callee.id);
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([9; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added(caller.clone())],
            relation_deltas: Vec::new(),
            artifact_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        };

        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities.insert(caller.id, caller.clone());
        snapshot.entities.insert(callee.id, callee.clone());
        snapshot.relations.insert(relation.id, relation.clone());
        snapshot.outgoing.insert(caller.id, vec![relation.id]);
        snapshot.incoming.insert(callee.id, vec![relation.id]);
        snapshot.changes.insert(change.id, change.clone());
        snapshot.shallow_files.push(ShallowTrackedFile {
            file_id: FilePathId::new("src/main.rs"),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Some(Hash256::from_bytes([2; 32])),
            declaration_names: vec!["caller".into(), "callee".into()],
            import_paths: Vec::new(),
        });

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

        let decoded: GraphSnapshot = locate_snapshot.into();
        assert_eq!(decoded.entities.len(), 2);
        assert_eq!(decoded.relations.len(), 1);
        assert_eq!(decoded.changes.len(), 1);
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
    fn compact_removes_orphaned_test_coverage() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("covered");
        snap.entities.insert(e1.id, e1.clone());

        let dead_test = TestId::new();
        let live_test = TestId::new();
        snap.test_cases.insert(
            live_test,
            TestCase {
                test_id: live_test,
                name: "live_test".into(),
                language: "rust".into(),
                kind: TestKind::Unit,
                scopes: vec![],
                runner: TestRunner::Cargo,
                file_origin: None,
            },
        );

        // One valid coverage entry, one orphaned (dead_test doesn't exist)
        snap.test_covers_entity.push((live_test, e1.id));
        snap.test_covers_entity.push((dead_test, e1.id));

        let stats = snap.compact();
        assert_eq!(stats.orphaned_test_coverage_removed, 1);
        assert_eq!(snap.test_covers_entity.len(), 1);
        assert_eq!(snap.test_covers_entity[0].0, live_test);
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
    fn from_bytes_reads_v4_entity_relations_and_legacy_coverage() {
        let e1 = test_entity("covered");
        let e2 = test_entity("callee");
        let test_id = TestId::new();
        let relation_id = RelationId::new();
        let legacy = GraphSnapshotV4Legacy {
            version: 4,
            entities: HashMap::from([(e1.id, e1.clone()), (e2.id, e2.clone())]),
            relations: HashMap::from([(
                relation_id,
                LegacyEntityRelation {
                    id: relation_id,
                    kind: RelationKind::Calls,
                    src: e1.id,
                    dst: e2.id,
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                },
            )]),
            outgoing: HashMap::from([(e1.id, vec![relation_id])]),
            incoming: HashMap::from([(e2.id, vec![relation_id])]),
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
            test_cases: HashMap::from([(
                test_id,
                TestCase {
                    test_id,
                    name: "test_target".into(),
                    language: "rust".into(),
                    kind: TestKind::Unit,
                    scopes: vec![],
                    runner: TestRunner::Cargo,
                    file_origin: None,
                },
            )]),
            assertions: HashMap::new(),
            verification_runs: HashMap::new(),
            test_covers_entity: vec![(test_id, e1.id)],
            test_covers_contract: Vec::new(),
            test_verifies_work: Vec::new(),
            run_proves_entity: Vec::new(),
            run_proves_work: Vec::new(),
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
            file_hashes: HashMap::new(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
        };
        let body = rmp_serde::to_vec(&legacy).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));

        let snapshot = GraphSnapshot::from_bytes(&bytes).unwrap();
        let relation = snapshot.relations.get(&relation_id).unwrap();
        assert_eq!(relation.src, GraphNodeId::Entity(e1.id));
        assert_eq!(relation.dst, GraphNodeId::Entity(e2.id));
        assert_eq!(snapshot.test_covers_entity, vec![(test_id, e1.id)]);

        let graph = crate::InMemoryGraph::from_snapshot(snapshot);
        let tests = graph.get_tests_for_entity(&e1.id).unwrap();
        assert_eq!(tests.len(), 1);
        let traversal = graph
            .traverse(&GraphNodeId::Test(test_id), &[RelationKind::Covers], 1)
            .unwrap();
        assert!(traversal.nodes.contains(&GraphNodeId::Entity(e1.id)));
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

        let dead_test = TestId::new();
        snap.test_covers_entity.push((dead_test, e1.id));

        let dead_intent = IntentId::new();
        snap.downstream_warnings
            .push((dead_intent, e1.id, "orphan".into()));

        let stats = snap.compact();
        assert!(stats.total_removed() >= 3);
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
    fn to_bytes_fast_path_avoids_clone() {
        // Verify that the fast path (version == CURRENT_VERSION) produces
        // identical output to the slow path
        let mut snap = GraphSnapshot::empty();
        let e = test_entity("fast_path");
        snap.entities.insert(e.id, e);

        assert_eq!(snap.version, GraphSnapshot::CURRENT_VERSION);
        let fast_bytes = snap.to_bytes().unwrap();

        // Force slow path by changing version
        snap.version = 1;
        let slow_bytes = snap.to_bytes().unwrap();

        // Both should produce valid current-version output
        let fast_loaded = GraphSnapshot::from_bytes(&fast_bytes).unwrap();
        let slow_loaded = GraphSnapshot::from_bytes(&slow_bytes).unwrap();
        assert_eq!(fast_loaded.entities.len(), slow_loaded.entities.len());
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
    fn loads_v1_snapshot_with_new_fields_defaulted() {
        let legacy = GraphSnapshotV1 {
            version: 1,
            entities: HashMap::new(),
            relations: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            changes: HashMap::new(),
            change_children: HashMap::new(),
            branches: HashMap::new(),
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let body = rmp_serde::to_vec(&legacy).unwrap();
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);

        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.work_items.is_empty());
        assert!(loaded.shallow_files.is_empty());
        assert!(loaded.sessions.is_empty());
    }

    #[test]
    fn loads_v2_snapshot_without_checksum() {
        // v2 snapshots have no checksum — must still load
        let snap = GraphSnapshot::empty();
        let mut snapshot = snap.clone();
        snapshot.version = 2;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);

        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert!(loaded.entities.is_empty());
    }

    #[test]
    fn loads_legacy_v3_snapshot_from_before_review_fields() {
        let legacy = GraphSnapshotV3Legacy {
            version: 3,
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
            test_cases: HashMap::new(),
            assertions: HashMap::new(),
            verification_runs: HashMap::new(),
            test_covers_entity: Vec::new(),
            test_covers_contract: Vec::new(),
            test_verifies_work: Vec::new(),
            run_proves_entity: Vec::new(),
            run_proves_work: Vec::new(),
            mock_hints: Vec::new(),
            contracts: HashMap::new(),
            actors: HashMap::new(),
            delegations: Vec::new(),
            approvals: Vec::new(),
            audit_events: Vec::new(),
            shallow_files: Vec::new(),
            structured_artifacts: Vec::new(),
            opaque_artifacts: Vec::new(),
            file_hashes: HashMap::new(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
        };

        let body = rmp_serde::to_vec(&legacy).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));

        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.reviews.is_empty());
        assert!(loaded.review_decisions.is_empty());
        assert!(loaded.review_notes.is_empty());
        assert!(loaded.review_discussions.is_empty());
        assert!(loaded.review_assignments.is_empty());
    }

    #[test]
    fn loads_current_layout_v3_snapshot_and_upgrades_on_write() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.version = 3;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));

        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, 3);

        let rewritten = loaded.to_bytes().unwrap();
        let rewritten_version = u32::from_le_bytes(rewritten[4..8].try_into().unwrap());
        assert_eq!(rewritten_version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn snapshot_roundtrips_file_layouts() {
        let mut snapshot = GraphSnapshot::empty();
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
