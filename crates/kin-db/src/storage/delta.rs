// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph-level delta computation and application.
//!
//! A `GraphSnapshotDelta` captures the difference between two graph states,
//! enabling incremental sync instead of full snapshot transfer. Deltas are
//! computed by diffing two `GraphSnapshot` instances and can be applied to
//! a base snapshot to reconstruct the target state.
//!
//! Wire format (v1):
//!   [4B magic "KNDD"] [4B version LE] [8B body_len LE] [body ...] [32B SHA-256]
//!
//! The body is MessagePack-serialized `GraphSnapshotDelta`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::hash::Hash;

use crate::error::KinDbError;
use crate::storage::backend::Generation;
use crate::storage::format::GraphSnapshot;
use crate::types::*;

// ---------------------------------------------------------------------------
// Generic collection delta
// ---------------------------------------------------------------------------

/// Delta for a HashMap-based collection: added, modified, and removed entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionDelta<K, V> {
    pub added: Vec<(K, V)>,
    /// Modified entries carry only the new value (caller has the old from base).
    pub modified: Vec<(K, V)>,
    pub removed: Vec<K>,
}

impl<K, V> Default for CollectionDelta<K, V> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            modified: Vec::new(),
            removed: Vec::new(),
        }
    }
}

impl<K, V> CollectionDelta<K, V> {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }

    pub fn change_count(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }
}

/// Delta for a Vec-based collection (append-only or replace-all semantics).
/// We track added and removed items; for simplicity in ordered collections
/// we store full replacement when items are reordered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VecDelta<V> {
    pub added: Vec<V>,
    pub removed: Vec<V>,
}

impl<V> Default for VecDelta<V> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
        }
    }
}

impl<V> VecDelta<V> {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

// ---------------------------------------------------------------------------
// GraphSnapshotDelta
// ---------------------------------------------------------------------------

/// A delta between two `GraphSnapshot` states.
///
/// Contains granular changes for every collection in the snapshot. Applying
/// this delta to the base snapshot reconstructs the target snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshotDelta {
    /// The generation of the base snapshot this delta was computed from.
    pub base_generation: Generation,

    // Core graph
    pub entities: CollectionDelta<EntityId, Entity>,
    pub relations: CollectionDelta<RelationId, Relation>,
    pub outgoing: CollectionDelta<EntityId, Vec<RelationId>>,
    pub incoming: CollectionDelta<EntityId, Vec<RelationId>>,

    // Change history
    pub changes: CollectionDelta<SemanticChangeId, SemanticChange>,
    pub change_children: CollectionDelta<SemanticChangeId, Vec<SemanticChangeId>>,

    // Branches
    pub branches: CollectionDelta<BranchName, Branch>,

    // Work graph
    pub work_items: CollectionDelta<WorkId, WorkItem>,
    pub annotations: CollectionDelta<AnnotationId, Annotation>,
    pub work_links: VecDelta<WorkLink>,

    // Reviews
    pub reviews: CollectionDelta<ReviewId, Review>,
    pub review_decisions: CollectionDelta<ReviewId, Vec<ReviewDecision>>,
    pub review_notes: VecDelta<ReviewNote>,
    pub review_discussions: VecDelta<ReviewDiscussion>,
    pub review_assignments: CollectionDelta<ReviewId, Vec<ReviewAssignment>>,

    // Verification
    pub test_cases: CollectionDelta<TestId, TestCase>,
    pub assertions: CollectionDelta<AssertionId, Assertion>,
    pub verification_runs: CollectionDelta<VerificationRunId, VerificationRun>,
    pub test_covers_entity: VecDelta<(TestId, EntityId)>,
    pub test_covers_contract: VecDelta<(TestId, ContractId)>,
    pub test_verifies_work: VecDelta<(TestId, WorkId)>,
    pub run_proves_entity: VecDelta<(VerificationRunId, EntityId)>,
    pub run_proves_work: VecDelta<(VerificationRunId, WorkId)>,
    pub mock_hints: VecDelta<MockHint>,

    // Contracts
    pub contracts: CollectionDelta<ContractId, Contract>,

    // Provenance
    pub actors: CollectionDelta<ActorId, Actor>,
    pub delegations: VecDelta<Delegation>,
    pub approvals: VecDelta<Approval>,
    pub audit_events: VecDelta<AuditEvent>,

    // File tracking
    pub shallow_files: VecDelta<ShallowTrackedFile>,
    #[serde(default)]
    pub structured_artifacts: VecDelta<StructuredArtifact>,
    #[serde(default)]
    pub opaque_artifacts: VecDelta<OpaqueArtifact>,
    pub file_hashes: CollectionDelta<String, [u8; 32]>,

    // Sessions/intents
    pub sessions: CollectionDelta<SessionId, AgentSession>,
    pub intents: CollectionDelta<IntentId, Intent>,
    pub downstream_warnings: VecDelta<(IntentId, EntityId, String)>,
}

impl GraphSnapshotDelta {
    /// Magic bytes for the delta file header: "KNDD"
    pub const MAGIC: [u8; 4] = *b"KNDD";

    /// Current delta format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Size of the SHA-256 checksum appended to the wire format.
    pub const CHECKSUM_LEN: usize = 32;

    /// Returns true if this delta contains no changes.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
            && self.relations.is_empty()
            && self.outgoing.is_empty()
            && self.incoming.is_empty()
            && self.changes.is_empty()
            && self.change_children.is_empty()
            && self.branches.is_empty()
            && self.work_items.is_empty()
            && self.annotations.is_empty()
            && self.work_links.is_empty()
            && self.reviews.is_empty()
            && self.review_decisions.is_empty()
            && self.review_notes.is_empty()
            && self.review_discussions.is_empty()
            && self.review_assignments.is_empty()
            && self.test_cases.is_empty()
            && self.assertions.is_empty()
            && self.verification_runs.is_empty()
            && self.test_covers_entity.is_empty()
            && self.test_covers_contract.is_empty()
            && self.test_verifies_work.is_empty()
            && self.run_proves_entity.is_empty()
            && self.run_proves_work.is_empty()
            && self.mock_hints.is_empty()
            && self.contracts.is_empty()
            && self.actors.is_empty()
            && self.delegations.is_empty()
            && self.approvals.is_empty()
            && self.audit_events.is_empty()
            && self.shallow_files.is_empty()
            && self.structured_artifacts.is_empty()
            && self.opaque_artifacts.is_empty()
            && self.file_hashes.is_empty()
            && self.sessions.is_empty()
            && self.intents.is_empty()
            && self.downstream_warnings.is_empty()
    }

    /// Total number of individual changes across all collections.
    pub fn total_changes(&self) -> usize {
        self.entities.change_count()
            + self.relations.change_count()
            + self.changes.change_count()
            + self.branches.change_count()
            + self.work_items.change_count()
            + self.annotations.change_count()
            + self.reviews.change_count()
            + self.review_decisions.change_count()
            + self.review_assignments.change_count()
            + self.test_cases.change_count()
            + self.assertions.change_count()
            + self.verification_runs.change_count()
            + self.contracts.change_count()
            + self.actors.change_count()
            + self.file_hashes.change_count()
            + self.sessions.change_count()
            + self.intents.change_count()
    }

    /// Serialize the delta to bytes with header and SHA-256 checksum.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KinDbError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Self::MAGIC);
        buf.extend_from_slice(&Self::CURRENT_VERSION.to_le_bytes());
        let body = rmp_serde::to_vec(self)
            .map_err(|e| KinDbError::StorageError(format!("delta serialization failed: {e}")))?;
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);

        let hash = Sha256::digest(&body);
        buf.extend_from_slice(&hash);

        Ok(buf)
    }

    /// Deserialize a delta from bytes (with header and checksum validation).
    pub fn from_bytes(data: &[u8]) -> Result<Self, KinDbError> {
        if data.len() < 16 {
            return Err(KinDbError::StorageError(
                "delta file too small for header".to_string(),
            ));
        }

        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(KinDbError::StorageError(format!(
                "invalid delta magic bytes: expected KNDD, got {:?}",
                magic
            )));
        }

        let version = u32::from_le_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| KinDbError::SliceConversionError("version bytes".to_string()))?,
        );
        if version != Self::CURRENT_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported delta version: {version} (expected {})",
                Self::CURRENT_VERSION
            )));
        }

        let body_len = u64::from_le_bytes(
            data[8..16]
                .try_into()
                .map_err(|_| KinDbError::SliceConversionError("body_len bytes".to_string()))?,
        ) as usize;

        if data.len() < 16 + body_len + Self::CHECKSUM_LEN {
            return Err(KinDbError::StorageError("delta file truncated".to_string()));
        }

        let body = &data[16..16 + body_len];
        let stored_hash = &data[16 + body_len..16 + body_len + Self::CHECKSUM_LEN];
        let computed_hash = Sha256::digest(body);

        if stored_hash != computed_hash.as_slice() {
            return Err(KinDbError::StorageError(
                "delta checksum mismatch: file is corrupted".to_string(),
            ));
        }

        rmp_serde::from_slice(body)
            .map_err(|e| KinDbError::StorageError(format!("delta deserialization failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Delta computation
// ---------------------------------------------------------------------------

/// Compute the diff of two HashMaps using PartialEq for comparison.
fn diff_maps_eq<K, V>(old: &HashMap<K, V>, new: &HashMap<K, V>) -> CollectionDelta<K, V>
where
    K: Eq + Hash + Clone,
    V: PartialEq + Clone,
{
    let mut delta = CollectionDelta {
        added: Vec::new(),
        modified: Vec::new(),
        removed: Vec::new(),
    };

    for (key, new_val) in new {
        match old.get(key) {
            None => delta.added.push((key.clone(), new_val.clone())),
            Some(old_val) if old_val != new_val => {
                delta.modified.push((key.clone(), new_val.clone()));
            }
            _ => {} // unchanged
        }
    }

    for key in old.keys() {
        if !new.contains_key(key) {
            delta.removed.push(key.clone());
        }
    }

    delta
}

/// Compute the diff of two HashMaps using serialization for comparison.
///
/// Used for model types that don't implement PartialEq (Entity, Relation, etc.).
/// Serializes both values to MessagePack and compares bytes.
fn diff_maps<K, V>(old: &HashMap<K, V>, new: &HashMap<K, V>) -> CollectionDelta<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone + serde::Serialize,
{
    let mut delta = CollectionDelta {
        added: Vec::new(),
        modified: Vec::new(),
        removed: Vec::new(),
    };

    for (key, new_val) in new {
        match old.get(key) {
            None => delta.added.push((key.clone(), new_val.clone())),
            Some(old_val) => {
                // Compare by serialized form — avoids PartialEq requirement
                let old_bytes = rmp_serde::to_vec(old_val).unwrap_or_default();
                let new_bytes = rmp_serde::to_vec(new_val).unwrap_or_default();
                if old_bytes != new_bytes {
                    delta.modified.push((key.clone(), new_val.clone()));
                }
            }
        }
    }

    for key in old.keys() {
        if !new.contains_key(key) {
            delta.removed.push(key.clone());
        }
    }

    delta
}

/// Compute the diff of two Vecs using serialization for comparison.
///
/// Uses `HashSet` for the lookup side so the complexity is O(n+m)
/// instead of the previous O(n*m) `contains()` approach.
fn diff_vecs<V>(old: &[V], new: &[V]) -> VecDelta<V>
where
    V: Clone + serde::Serialize,
{
    use std::collections::HashSet;

    // Serialize each element for comparison
    let old_serialized: Vec<Vec<u8>> = old
        .iter()
        .map(|v| rmp_serde::to_vec(v).unwrap_or_default())
        .collect();
    let new_serialized: Vec<Vec<u8>> = new
        .iter()
        .map(|v| rmp_serde::to_vec(v).unwrap_or_default())
        .collect();

    let old_set: HashSet<&Vec<u8>> = old_serialized.iter().collect();
    let new_set: HashSet<&Vec<u8>> = new_serialized.iter().collect();

    let mut delta = VecDelta {
        added: Vec::new(),
        removed: Vec::new(),
    };

    for (i, new_bytes) in new_serialized.iter().enumerate() {
        if !old_set.contains(new_bytes) {
            delta.added.push(new[i].clone());
        }
    }

    for (i, old_bytes) in old_serialized.iter().enumerate() {
        if !new_set.contains(old_bytes) {
            delta.removed.push(old[i].clone());
        }
    }

    delta
}

/// Compute the delta between two graph snapshots.
///
/// The returned delta, when applied to `old`, produces a state equivalent to `new`.
pub fn compute_graph_delta(
    old: &GraphSnapshot,
    new: &GraphSnapshot,
    base_generation: Generation,
) -> GraphSnapshotDelta {
    GraphSnapshotDelta {
        base_generation,
        entities: diff_maps(&old.entities, &new.entities),
        relations: diff_maps(&old.relations, &new.relations),
        outgoing: diff_maps_eq(&old.outgoing, &new.outgoing),
        incoming: diff_maps_eq(&old.incoming, &new.incoming),
        changes: diff_maps(&old.changes, &new.changes),
        change_children: diff_maps_eq(&old.change_children, &new.change_children),
        branches: diff_maps(&old.branches, &new.branches),
        work_items: diff_maps(&old.work_items, &new.work_items),
        annotations: diff_maps(&old.annotations, &new.annotations),
        work_links: diff_vecs(&old.work_links, &new.work_links),
        reviews: diff_maps(&old.reviews, &new.reviews),
        review_decisions: diff_maps(&old.review_decisions, &new.review_decisions),
        review_notes: diff_vecs(&old.review_notes, &new.review_notes),
        review_discussions: diff_vecs(&old.review_discussions, &new.review_discussions),
        review_assignments: diff_maps(&old.review_assignments, &new.review_assignments),
        test_cases: diff_maps(&old.test_cases, &new.test_cases),
        assertions: diff_maps(&old.assertions, &new.assertions),
        verification_runs: diff_maps(&old.verification_runs, &new.verification_runs),
        test_covers_entity: diff_vecs(&old.test_covers_entity, &new.test_covers_entity),
        test_covers_contract: diff_vecs(&old.test_covers_contract, &new.test_covers_contract),
        test_verifies_work: diff_vecs(&old.test_verifies_work, &new.test_verifies_work),
        run_proves_entity: diff_vecs(&old.run_proves_entity, &new.run_proves_entity),
        run_proves_work: diff_vecs(&old.run_proves_work, &new.run_proves_work),
        mock_hints: diff_vecs(&old.mock_hints, &new.mock_hints),
        contracts: diff_maps(&old.contracts, &new.contracts),
        actors: diff_maps(&old.actors, &new.actors),
        delegations: diff_vecs(&old.delegations, &new.delegations),
        approvals: diff_vecs(&old.approvals, &new.approvals),
        audit_events: diff_vecs(&old.audit_events, &new.audit_events),
        shallow_files: diff_vecs(&old.shallow_files, &new.shallow_files),
        structured_artifacts: diff_vecs(&old.structured_artifacts, &new.structured_artifacts),
        opaque_artifacts: diff_vecs(&old.opaque_artifacts, &new.opaque_artifacts),
        file_hashes: diff_maps_eq(&old.file_hashes, &new.file_hashes),
        sessions: diff_maps(&old.sessions, &new.sessions),
        intents: diff_maps(&old.intents, &new.intents),
        downstream_warnings: diff_vecs(&old.downstream_warnings, &new.downstream_warnings),
    }
}

// ---------------------------------------------------------------------------
// Delta application
// ---------------------------------------------------------------------------

/// Apply a `CollectionDelta` to a HashMap, mutating it in place.
fn apply_map_delta<K, V>(map: &mut HashMap<K, V>, delta: &CollectionDelta<K, V>)
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    for key in &delta.removed {
        map.remove(key);
    }
    for (key, val) in &delta.added {
        map.insert(key.clone(), val.clone());
    }
    for (key, val) in &delta.modified {
        map.insert(key.clone(), val.clone());
    }
}

/// Apply a `VecDelta` to a Vec, mutating it in place.
///
/// Uses a `HashSet` for the removal lookup so retain is O(n) instead of O(n*m).
fn apply_vec_delta<V>(vec: &mut Vec<V>, delta: &VecDelta<V>)
where
    V: Clone + serde::Serialize,
{
    use std::collections::HashSet;

    let removed_set: HashSet<Vec<u8>> = delta
        .removed
        .iter()
        .map(|v| rmp_serde::to_vec(v).unwrap_or_default())
        .collect();
    vec.retain(|item| {
        let item_bytes = rmp_serde::to_vec(item).unwrap_or_default();
        !removed_set.contains(&item_bytes)
    });
    vec.extend(delta.added.iter().cloned());
}

/// Apply a `GraphSnapshotDelta` to a `GraphSnapshot`, mutating it in place.
///
/// After application, the snapshot is equivalent to the target state that
/// the delta was computed from.
pub fn apply_graph_delta(snapshot: &mut GraphSnapshot, delta: &GraphSnapshotDelta) {
    // Core graph
    apply_map_delta(&mut snapshot.entities, &delta.entities);
    apply_map_delta(&mut snapshot.relations, &delta.relations);
    apply_map_delta(&mut snapshot.outgoing, &delta.outgoing);
    apply_map_delta(&mut snapshot.incoming, &delta.incoming);

    // Change history
    apply_map_delta(&mut snapshot.changes, &delta.changes);
    apply_map_delta(&mut snapshot.change_children, &delta.change_children);

    // Branches
    apply_map_delta(&mut snapshot.branches, &delta.branches);

    // Work graph
    apply_map_delta(&mut snapshot.work_items, &delta.work_items);
    apply_map_delta(&mut snapshot.annotations, &delta.annotations);
    apply_vec_delta(&mut snapshot.work_links, &delta.work_links);

    // Reviews
    apply_map_delta(&mut snapshot.reviews, &delta.reviews);
    apply_map_delta(&mut snapshot.review_decisions, &delta.review_decisions);
    apply_vec_delta(&mut snapshot.review_notes, &delta.review_notes);
    apply_vec_delta(&mut snapshot.review_discussions, &delta.review_discussions);
    apply_map_delta(&mut snapshot.review_assignments, &delta.review_assignments);

    // Verification
    apply_map_delta(&mut snapshot.test_cases, &delta.test_cases);
    apply_map_delta(&mut snapshot.assertions, &delta.assertions);
    apply_map_delta(&mut snapshot.verification_runs, &delta.verification_runs);
    apply_vec_delta(&mut snapshot.test_covers_entity, &delta.test_covers_entity);
    apply_vec_delta(
        &mut snapshot.test_covers_contract,
        &delta.test_covers_contract,
    );
    apply_vec_delta(&mut snapshot.test_verifies_work, &delta.test_verifies_work);
    apply_vec_delta(&mut snapshot.run_proves_entity, &delta.run_proves_entity);
    apply_vec_delta(&mut snapshot.run_proves_work, &delta.run_proves_work);
    apply_vec_delta(&mut snapshot.mock_hints, &delta.mock_hints);

    // Contracts
    apply_map_delta(&mut snapshot.contracts, &delta.contracts);

    // Provenance
    apply_map_delta(&mut snapshot.actors, &delta.actors);
    apply_vec_delta(&mut snapshot.delegations, &delta.delegations);
    apply_vec_delta(&mut snapshot.approvals, &delta.approvals);
    apply_vec_delta(&mut snapshot.audit_events, &delta.audit_events);

    // File tracking
    apply_vec_delta(&mut snapshot.shallow_files, &delta.shallow_files);
    apply_vec_delta(
        &mut snapshot.structured_artifacts,
        &delta.structured_artifacts,
    );
    apply_vec_delta(&mut snapshot.opaque_artifacts, &delta.opaque_artifacts);
    apply_map_delta(&mut snapshot.file_hashes, &delta.file_hashes);

    // Sessions/intents
    apply_map_delta(&mut snapshot.sessions, &delta.sessions);
    apply_map_delta(&mut snapshot.intents, &delta.intents);
    apply_vec_delta(
        &mut snapshot.downstream_warnings,
        &delta.downstream_warnings,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers -----------------------------------------------------------

    fn make_entity(name: &str) -> (EntityId, Entity) {
        let id = EntityId::new();
        let entity = Entity {
            id,
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
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        (id, entity)
    }

    fn make_relation(src: EntityId, dst: EntityId) -> (RelationId, Relation) {
        let id = RelationId::new();
        let relation = Relation {
            id,
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        };
        (id, relation)
    }

    // -- diff_maps tests ---------------------------------------------------

    #[test]
    fn diff_maps_empty_both() {
        let old: HashMap<String, i32> = HashMap::new();
        let new: HashMap<String, i32> = HashMap::new();
        let delta = diff_maps(&old, &new);
        assert!(delta.is_empty());
    }

    #[test]
    fn diff_maps_all_added() {
        let old: HashMap<String, i32> = HashMap::new();
        let mut new = HashMap::new();
        new.insert("a".to_string(), 1);
        new.insert("b".to_string(), 2);

        let delta = diff_maps(&old, &new);
        assert_eq!(delta.added.len(), 2);
        assert!(delta.modified.is_empty());
        assert!(delta.removed.is_empty());
    }

    #[test]
    fn diff_maps_all_removed() {
        let mut old = HashMap::new();
        old.insert("a".to_string(), 1);
        old.insert("b".to_string(), 2);
        let new: HashMap<String, i32> = HashMap::new();

        let delta = diff_maps(&old, &new);
        assert!(delta.added.is_empty());
        assert!(delta.modified.is_empty());
        assert_eq!(delta.removed.len(), 2);
    }

    #[test]
    fn diff_maps_mixed_changes() {
        let mut old = HashMap::new();
        old.insert("unchanged".to_string(), 1);
        old.insert("modified".to_string(), 2);
        old.insert("removed".to_string(), 3);

        let mut new = HashMap::new();
        new.insert("unchanged".to_string(), 1);
        new.insert("modified".to_string(), 99);
        new.insert("added".to_string(), 4);

        let delta = diff_maps(&old, &new);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.modified.len(), 1);
        assert_eq!(delta.removed.len(), 1);
        assert_eq!(delta.change_count(), 3);
    }

    // -- diff_vecs tests ---------------------------------------------------

    #[test]
    fn diff_vecs_empty_both() {
        let old: Vec<i32> = vec![];
        let new: Vec<i32> = vec![];
        let delta = diff_vecs(&old, &new);
        assert!(delta.is_empty());
    }

    #[test]
    fn diff_vecs_added_and_removed() {
        let old = vec![1, 2, 3];
        let new = vec![2, 3, 4, 5];

        let delta = diff_vecs(&old, &new);
        assert_eq!(delta.added, vec![4, 5]);
        assert_eq!(delta.removed, vec![1]);
    }

    // -- apply_map_delta tests ---------------------------------------------

    #[test]
    fn apply_map_delta_roundtrip() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);

        let delta = CollectionDelta {
            added: vec![("c".to_string(), 3)],
            modified: vec![("b".to_string(), 99)],
            removed: vec!["a".to_string()],
        };

        apply_map_delta(&mut map, &delta);
        assert_eq!(map.get("a"), None);
        assert_eq!(map.get("b"), Some(&99));
        assert_eq!(map.get("c"), Some(&3));
    }

    // -- apply_vec_delta tests ---------------------------------------------

    #[test]
    fn apply_vec_delta_roundtrip() {
        let mut vec = vec![1, 2, 3];
        let delta = VecDelta {
            added: vec![4, 5],
            removed: vec![1],
        };

        apply_vec_delta(&mut vec, &delta);
        assert!(!vec.contains(&1));
        assert!(vec.contains(&2));
        assert!(vec.contains(&3));
        assert!(vec.contains(&4));
        assert!(vec.contains(&5));
    }

    // -- Full GraphSnapshot delta roundtrip --------------------------------

    #[test]
    fn compute_and_apply_entity_delta() {
        let mut old = GraphSnapshot::empty();
        let mut new = GraphSnapshot::empty();

        let (id_a, entity_a) = make_entity("fn_a");
        let (id_b, entity_b) = make_entity("fn_b");
        let (id_c, entity_c) = make_entity("fn_c");

        // old has fn_a and fn_b
        old.entities.insert(id_a, entity_a.clone());
        old.entities.insert(id_b, entity_b.clone());

        // new has fn_a (modified name) and fn_c (added), fn_b removed
        let mut entity_a_modified = entity_a.clone();
        entity_a_modified.name = "fn_a_v2".to_string();
        new.entities.insert(id_a, entity_a_modified.clone());
        new.entities.insert(id_c, entity_c.clone());

        let delta = compute_graph_delta(&old, &new, 1);

        assert_eq!(delta.entities.added.len(), 1); // fn_c
        assert_eq!(delta.entities.modified.len(), 1); // fn_a modified
        assert_eq!(delta.entities.removed.len(), 1); // fn_b removed

        // Apply delta to old → should match new
        let mut result = old.clone();
        apply_graph_delta(&mut result, &delta);

        assert_eq!(result.entities.len(), 2);
        assert_eq!(result.entities.get(&id_a).unwrap().name, "fn_a_v2");
        assert!(result.entities.contains_key(&id_c));
        assert!(!result.entities.contains_key(&id_b));
    }

    #[test]
    fn compute_and_apply_relation_delta() {
        let mut old = GraphSnapshot::empty();
        let mut new = GraphSnapshot::empty();

        let (id_a, entity_a) = make_entity("fn_a");
        let (id_b, entity_b) = make_entity("fn_b");

        // Both have the same entities
        old.entities.insert(id_a, entity_a.clone());
        old.entities.insert(id_b, entity_b.clone());
        new.entities.insert(id_a, entity_a.clone());
        new.entities.insert(id_b, entity_b.clone());

        // old has no relations, new has a Calls relation
        let (rel_id, relation) = make_relation(id_a, id_b);
        new.relations.insert(rel_id, relation.clone());
        new.outgoing.insert(id_a, vec![rel_id]);
        new.incoming.insert(id_b, vec![rel_id]);

        let delta = compute_graph_delta(&old, &new, 1);
        assert_eq!(delta.relations.added.len(), 1);

        let mut result = old.clone();
        apply_graph_delta(&mut result, &delta);
        assert_eq!(result.relations.len(), 1);
        assert!(result.relations.contains_key(&rel_id));
    }

    #[test]
    fn compute_and_apply_branch_delta() {
        let mut old = GraphSnapshot::empty();
        let mut new = GraphSnapshot::empty();

        let branch_name = BranchName::new("main");
        let old_branch = Branch {
            name: branch_name.clone(),
            head: SemanticChangeId(Hash256::from_bytes([1; 32])),
        };
        let new_branch = Branch {
            head: SemanticChangeId(Hash256::from_bytes([2; 32])),
            ..old_branch.clone()
        };

        old.branches.insert(branch_name.clone(), old_branch);
        new.branches.insert(branch_name.clone(), new_branch);

        let delta = compute_graph_delta(&old, &new, 1);
        assert_eq!(delta.branches.modified.len(), 1);

        let mut result = old.clone();
        apply_graph_delta(&mut result, &delta);
        assert_eq!(
            result.branches.get(&branch_name).unwrap().head,
            SemanticChangeId(Hash256::from_bytes([2; 32]))
        );
    }

    #[test]
    fn compute_and_apply_file_hash_delta() {
        let mut old = GraphSnapshot::empty();
        let mut new = GraphSnapshot::empty();

        old.file_hashes.insert("a.rs".to_string(), [1; 32]);
        old.file_hashes.insert("b.rs".to_string(), [2; 32]);

        new.file_hashes.insert("a.rs".to_string(), [1; 32]); // unchanged
        new.file_hashes.insert("b.rs".to_string(), [99; 32]); // modified
        new.file_hashes.insert("c.rs".to_string(), [3; 32]); // added

        let delta = compute_graph_delta(&old, &new, 1);
        assert_eq!(delta.file_hashes.added.len(), 1);
        assert_eq!(delta.file_hashes.modified.len(), 1);
        assert!(delta.file_hashes.removed.is_empty());

        let mut result = old.clone();
        apply_graph_delta(&mut result, &delta);
        assert_eq!(result.file_hashes.get("a.rs"), Some(&[1; 32]));
        assert_eq!(result.file_hashes.get("b.rs"), Some(&[99; 32]));
        assert_eq!(result.file_hashes.get("c.rs"), Some(&[3; 32]));
    }

    #[test]
    fn empty_delta_from_identical_snapshots() {
        let snap = GraphSnapshot::empty();
        let delta = compute_graph_delta(&snap, &snap, 0);
        assert!(delta.is_empty());
        assert_eq!(delta.total_changes(), 0);
    }

    #[test]
    fn delta_serialization_roundtrip() {
        let mut old = GraphSnapshot::empty();
        let new = GraphSnapshot::empty();

        let (id_a, entity_a) = make_entity("fn_a");
        old.entities.insert(id_a, entity_a.clone());
        // new is empty — entity_a is removed

        let delta = compute_graph_delta(&old, &new, 42);

        let bytes = delta.to_bytes().unwrap();
        let loaded = GraphSnapshotDelta::from_bytes(&bytes).unwrap();

        assert_eq!(loaded.base_generation, 42);
        assert_eq!(loaded.entities.removed.len(), 1);
        assert_eq!(loaded.entities.removed[0], id_a);
    }

    #[test]
    fn delta_corrupted_body_detected() {
        let delta = compute_graph_delta(&GraphSnapshot::empty(), &GraphSnapshot::empty(), 0);
        let mut bytes = delta.to_bytes().unwrap();

        // Corrupt a byte in the body
        if bytes.len() > 20 {
            bytes[20] ^= 0xFF;
        }

        let err = GraphSnapshotDelta::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn delta_invalid_magic_rejected() {
        let mut data = vec![0u8; 80];
        data[0..4].copy_from_slice(b"XXXX");
        let err = GraphSnapshotDelta::from_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("invalid delta magic"));
    }

    #[test]
    fn delta_smaller_than_full_snapshot() {
        let mut old = GraphSnapshot::empty();
        let mut new = GraphSnapshot::empty();

        // Populate both with 100 entities
        for i in 0..100 {
            let (id, entity) = make_entity(&format!("fn_{i}"));
            old.entities.insert(id, entity.clone());
            new.entities.insert(id, entity);
        }

        // Modify just one entity in new
        let (mod_id, mod_entity) = make_entity("fn_modified");
        new.entities.insert(mod_id, mod_entity.clone());

        let full_bytes = new.to_bytes().unwrap();
        let delta = compute_graph_delta(&old, &new, 1);
        let delta_bytes = delta.to_bytes().unwrap();

        // Delta should be significantly smaller than full snapshot
        assert!(
            delta_bytes.len() < full_bytes.len(),
            "delta ({} bytes) should be smaller than full snapshot ({} bytes)",
            delta_bytes.len(),
            full_bytes.len()
        );
    }

    #[test]
    fn full_roundtrip_compute_serialize_deserialize_apply() {
        let mut old = GraphSnapshot::empty();
        let mut new = GraphSnapshot::empty();

        // Build a non-trivial old state
        let (id_a, entity_a) = make_entity("fn_a");
        let (id_b, entity_b) = make_entity("fn_b");
        let (rel_id, relation) = make_relation(id_a, id_b);

        old.entities.insert(id_a, entity_a.clone());
        old.entities.insert(id_b, entity_b.clone());
        old.relations.insert(rel_id, relation.clone());
        old.outgoing.insert(id_a, vec![rel_id]);
        old.incoming.insert(id_b, vec![rel_id]);
        old.file_hashes.insert("src/lib.rs".to_string(), [1; 32]);
        old.structured_artifacts.push(StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([7; 32]),
            text_preview: Some("build".into()),
        });

        // Build a modified new state
        let mut entity_a_v2 = entity_a.clone();
        entity_a_v2.name = "fn_a_v2".to_string();
        let (id_c, entity_c) = make_entity("fn_c");
        let (rel2_id, relation2) = make_relation(id_a, id_c);

        new.entities.insert(id_a, entity_a_v2);
        new.entities.insert(id_c, entity_c);
        // fn_b and its relation removed
        new.relations.insert(rel2_id, relation2);
        new.outgoing.insert(id_a, vec![rel2_id]);
        new.incoming.insert(id_c, vec![rel2_id]);
        new.file_hashes.insert("src/lib.rs".to_string(), [2; 32]);
        new.file_hashes.insert("src/new.rs".to_string(), [3; 32]);
        new.structured_artifacts.push(StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([8; 32]),
            text_preview: Some("build test".into()),
        });
        new.opaque_artifacts.push(OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([9; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        });

        // Compute → serialize → deserialize → apply
        let delta = compute_graph_delta(&old, &new, 5);
        let bytes = delta.to_bytes().unwrap();
        let loaded_delta = GraphSnapshotDelta::from_bytes(&bytes).unwrap();

        let mut result = old.clone();
        apply_graph_delta(&mut result, &loaded_delta);

        // Verify result matches new
        assert_eq!(result.entities.len(), new.entities.len());
        assert_eq!(result.entities.get(&id_a).unwrap().name, "fn_a_v2");
        assert!(result.entities.contains_key(&id_c));
        assert!(!result.entities.contains_key(&id_b));
        assert_eq!(result.relations.len(), new.relations.len());
        assert!(result.relations.contains_key(&rel2_id));
        assert!(!result.relations.contains_key(&rel_id));
        assert_eq!(result.file_hashes.len(), 2);
        assert_eq!(result.file_hashes.get("src/lib.rs"), Some(&[2; 32]));
        assert_eq!(result.file_hashes.get("src/new.rs"), Some(&[3; 32]));
        assert_eq!(result.structured_artifacts.len(), 1);
        assert_eq!(
            result.structured_artifacts[0].content_hash,
            Hash256::from_bytes([8; 32])
        );
        assert_eq!(result.opaque_artifacts.len(), 1);
    }
}
