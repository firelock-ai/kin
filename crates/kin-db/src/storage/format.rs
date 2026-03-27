// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

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
    pub file_hashes: HashMap<String, [u8; 32]>,
    #[serde(default)]
    pub sessions: HashMap<SessionId, AgentSession>,
    #[serde(default)]
    pub intents: HashMap<IntentId, Intent>,
    #[serde(default)]
    pub downstream_warnings: Vec<(IntentId, EntityId, String)>,
}

impl GraphSnapshot {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 3;

    /// Magic bytes for the file header: "KNDB"
    pub const MAGIC: [u8; 4] = *b"KNDB";

    /// Size of the SHA-256 checksum appended to v3+ snapshots.
    pub const CHECKSUM_LEN: usize = 32;

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
            file_hashes: HashMap::new(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
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

        // 1. Remove orphaned relations (src or dst entity missing)
        let before = self.relations.len();
        self.relations.retain(|_, rel| {
            entity_ids.contains(&rel.src) && entity_ids.contains(&rel.dst)
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

        // 4. Clean test coverage entries
        let test_ids: HashSet<TestId> = self.test_cases.keys().copied().collect();
        let contract_ids: HashSet<ContractId> = self.contracts.keys().copied().collect();
        let work_ids: HashSet<WorkId> = self.work_items.keys().copied().collect();

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

        // 5. Clean verification run references
        let run_ids: HashSet<VerificationRunId> =
            self.verification_runs.keys().copied().collect();
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
        self.approvals
            .retain(|a| change_ids.contains(&a.change_id));
        stats.orphaned_approvals_removed = before - self.approvals.len();

        // 9. Clean delegations for non-existent actors
        let actor_ids: HashSet<ActorId> = self.actors.keys().copied().collect();
        let before = self.delegations.len();
        self.delegations.retain(|d| {
            actor_ids.contains(&d.principal) && actor_ids.contains(&d.delegate)
        });
        stats.orphaned_delegations_removed = before - self.delegations.len();

        stats.relations_after = self.relations.len();
        stats
    }

    /// Serialize the snapshot to bytes with a header and SHA-256 checksum.
    ///
    /// Wire format (v3):
    ///   [4B magic] [4B version LE] [8B body_len LE] [body ...] [32B SHA-256]
    ///
    /// The SHA-256 is computed over the msgpack body only.
    ///
    /// For large graphs (>500K entities), this avoids cloning the entire
    /// snapshot by serializing directly when the version already matches.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
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

        // Pre-allocate: header (16B) + body + checksum (32B)
        let mut buf = Vec::with_capacity(16 + body.len() + Self::CHECKSUM_LEN);
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&Self::CURRENT_VERSION.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);

        // Append SHA-256 checksum of the body
        let hash = Sha256::digest(&body);
        buf.extend_from_slice(&hash);

        Ok(buf)
    }

    /// Deserialize a snapshot from bytes (with header validation).
    ///
    /// - v1/v2: no checksum (loaded with a warning for v2)
    /// - v3+: SHA-256 checksum verified; returns error on mismatch
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::KinDbError> {
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
            1 => {
                let legacy: GraphSnapshotV1 = rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })?;
                Ok(legacy.into())
            }
            2 => {
                // v2 snapshots have no checksum — load normally
                rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })
            }
            3 => {
                // v3: verify SHA-256 checksum after body
                let checksum_start = 16 + body_len;
                if data.len() < checksum_start + Self::CHECKSUM_LEN {
                    return Err(crate::error::KinDbError::StorageError(
                        "v3 snapshot missing SHA-256 checksum".to_string(),
                    ));
                }
                let stored_hash = &data[checksum_start..checksum_start + Self::CHECKSUM_LEN];
                let computed_hash = Sha256::digest(body);

                if stored_hash != computed_hash.as_slice() {
                    return Err(crate::error::KinDbError::StorageError(
                        "snapshot checksum mismatch: file is corrupted".to_string(),
                    ));
                }

                rmp_serde::from_slice(body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
                })
            }
            _ => Err(crate::error::KinDbError::StorageError(format!(
                "unsupported format version: {version} (expected 1, 2, or {})",
                Self::CURRENT_VERSION
            ))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GraphSnapshotV1 {
    version: u32,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
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
        snapshot.relations = value.relations;
        snapshot.outgoing = value.outgoing;
        snapshot.incoming = value.incoming;
        snapshot.changes = value.changes;
        snapshot.change_children = value.change_children;
        snapshot.branches = value.branches;
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        }
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
        snap.outgoing
            .insert(e1.id, vec![rel.id]);
        snap.incoming
            .insert(e2.id, vec![rel.id]);

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

        // Both should produce valid v3 output
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
    fn v3_checksum_is_appended() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Header: 4 magic + 4 version + 8 body_len = 16
        let body_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        // Total should be header + body + 32-byte SHA-256
        assert_eq!(bytes.len(), 16 + body_len + GraphSnapshot::CHECKSUM_LEN);

        // Version in header should be 3
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(version, 3);
    }

    #[test]
    fn v3_corrupted_body_detected() {
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
    fn v3_truncated_checksum_detected() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Truncate the last 10 bytes (partial checksum)
        let truncated = &bytes[..bytes.len() - 10];

        let err = GraphSnapshot::from_bytes(truncated).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing SHA-256 checksum"),
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
    fn invalid_magic_rejected() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(GraphSnapshot::from_bytes(&data).is_err());
    }
}
