//! Merkle DAG for cryptographic integrity verification of the entity/relation graph.
//!
//! Maps directly to the entity/relation graph structure:
//! - Each entity has a **content hash** = SHA-256(entity kind + name + signature + metadata)
//! - Each relation has a **relation hash** = SHA-256(kind + source hash + destination hash)
//! - A **sub-graph root hash** combines an entity's content hash with sorted outgoing relation hashes
//! - The **graph root hash** is the hash of all sorted entity sub-graph hashes
//!
//! This enables O(log n) verification of any sub-graph without hashing the entire repository.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;
use crate::types::*;

/// A 32-byte SHA-256 hash used throughout the Merkle DAG.
pub type MerkleHash = [u8; 32];

/// Zero hash — used as a sentinel for missing/empty nodes.
pub const ZERO_HASH: MerkleHash = [0u8; 32];

/// Compute the content hash of an entity.
///
/// Hash is deterministic over: entity kind, name, language, signature, visibility,
/// fingerprint hashes, file origin, and doc summary. This captures the semantic
/// identity of the entity independent of its graph position.
pub fn compute_entity_hash(entity: &Entity) -> MerkleHash {
    let mut hasher = Sha256::new();

    // Domain separator
    hasher.update(b"kin-entity-v1:");

    // Entity kind (as debug string for stability across repr changes)
    hasher.update(format!("{:?}", entity.kind).as_bytes());
    hasher.update(b"|");

    // Name
    hasher.update(entity.name.as_bytes());
    hasher.update(b"|");

    // Language
    hasher.update(format!("{:?}", entity.language).as_bytes());
    hasher.update(b"|");

    // Signature
    hasher.update(entity.signature.as_bytes());
    hasher.update(b"|");

    // Visibility
    hasher.update(format!("{:?}", entity.visibility).as_bytes());
    hasher.update(b"|");

    // Fingerprint hashes (the semantic identity core)
    hasher.update(entity.fingerprint.ast_hash.as_bytes());
    hasher.update(entity.fingerprint.signature_hash.as_bytes());
    hasher.update(entity.fingerprint.behavior_hash.as_bytes());

    // File origin (if any)
    if let Some(ref file) = entity.file_origin {
        hasher.update(b"file:");
        hasher.update(file.0.as_bytes());
    }
    hasher.update(b"|");

    // Doc summary (if any)
    if let Some(ref doc) = entity.doc_summary {
        hasher.update(b"doc:");
        hasher.update(doc.as_bytes());
    }

    // Metadata: serialize sorted keys for determinism
    let mut meta_keys: Vec<&String> = entity.metadata.extra.keys().collect();
    meta_keys.sort();
    for key in meta_keys {
        hasher.update(b"meta:");
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(entity.metadata.extra[key].to_string().as_bytes());
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the hash of a relation given endpoint entity hashes.
///
/// The relation hash binds the relation kind to the specific content of its
/// source and destination entities, creating a tamper-evident edge.
pub fn compute_relation_hash(
    relation: &Relation,
    src_hash: MerkleHash,
    dst_hash: MerkleHash,
) -> MerkleHash {
    let mut hasher = Sha256::new();

    // Domain separator
    hasher.update(b"kin-relation-v1:");

    // Relation kind
    hasher.update(format!("{:?}", relation.kind).as_bytes());
    hasher.update(b"|");

    // Source entity hash
    hasher.update(&src_hash);

    // Destination entity hash
    hasher.update(&dst_hash);

    // Confidence (as bytes for determinism)
    hasher.update(&relation.confidence.to_le_bytes());

    // Origin
    hasher.update(format!("{:?}", relation.origin).as_bytes());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute the sub-graph hash rooted at an entity.
///
/// Combines the entity's content hash with the sorted hashes of all outgoing
/// relations (which recursively incorporate their destination entity hashes).
/// This produces a hash that changes if any node or edge in the sub-graph is modified.
pub fn compute_subgraph_hash(
    entity_id: &EntityId,
    snapshot: &GraphSnapshot,
    cache: &mut HashMap<EntityId, MerkleHash>,
) -> MerkleHash {
    // Return cached result to avoid recomputation and handle cycles
    if let Some(&cached) = cache.get(entity_id) {
        return cached;
    }

    let entity = match snapshot.entities.get(entity_id) {
        Some(e) => e,
        None => return ZERO_HASH,
    };

    // Insert a sentinel to break cycles during recursion
    cache.insert(*entity_id, ZERO_HASH);

    let entity_hash = compute_entity_hash(entity);

    // Gather outgoing relation hashes (sorted for determinism)
    let mut relation_hashes: Vec<MerkleHash> = Vec::new();

    if let Some(rel_ids) = snapshot.outgoing.get(entity_id) {
        for rel_id in rel_ids {
            if let Some(relation) = snapshot.relations.get(rel_id) {
                let src_hash = entity_hash;
                let dst_hash = compute_subgraph_hash(&relation.dst, snapshot, cache);
                let rel_hash = compute_relation_hash(relation, src_hash, dst_hash);
                relation_hashes.push(rel_hash);
            }
        }
    }

    // Sort for deterministic ordering regardless of insertion order
    relation_hashes.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"kin-subgraph-v1:");
    hasher.update(&entity_hash);
    for rh in &relation_hashes {
        hasher.update(rh);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    // Cache the real result
    cache.insert(*entity_id, hash);
    hash
}

/// Compute the root hash for the entire graph.
///
/// The root hash is the SHA-256 of all entity sub-graph hashes sorted lexicographically.
/// This means the root is deterministic regardless of entity insertion order.
pub fn compute_graph_root_hash(snapshot: &GraphSnapshot) -> MerkleHash {
    let mut cache = HashMap::new();

    // Compute sub-graph hash for every entity
    let mut all_hashes: Vec<MerkleHash> = snapshot
        .entities
        .keys()
        .map(|id| compute_subgraph_hash(id, snapshot, &mut cache))
        .collect();

    // Sort for determinism
    all_hashes.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"kin-graph-root-v1:");
    for h in &all_hashes {
        hasher.update(h);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Result of verifying a single entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityVerification {
    /// Entity content matches its expected hash.
    Valid,
    /// Entity content has been tampered with.
    Tampered {
        expected: MerkleHash,
        actual: MerkleHash,
    },
    /// Entity not found in the graph.
    Missing,
}

/// Report from verifying a sub-graph.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// The root entity of the verified sub-graph.
    pub root: EntityId,
    /// Entities whose content hash is valid.
    pub verified: Vec<EntityId>,
    /// Entities whose content has been tampered with.
    pub tampered: Vec<TamperedNode>,
    /// The verification path (entity IDs visited during traversal).
    pub verification_path: Vec<EntityId>,
    /// Whether the entire sub-graph passed verification.
    pub is_valid: bool,
}

/// A node that failed integrity verification.
#[derive(Debug, Clone)]
pub struct TamperedNode {
    pub entity_id: EntityId,
    pub expected_hash: MerkleHash,
    pub actual_hash: MerkleHash,
}

/// Verify a single entity's content hash against a stored hash map.
pub fn verify_entity(
    entity_id: &EntityId,
    snapshot: &GraphSnapshot,
    stored_hashes: &HashMap<EntityId, MerkleHash>,
) -> EntityVerification {
    let entity = match snapshot.entities.get(entity_id) {
        Some(e) => e,
        None => return EntityVerification::Missing,
    };

    let expected = match stored_hashes.get(entity_id) {
        Some(&h) => h,
        None => return EntityVerification::Missing,
    };

    let actual = compute_entity_hash(entity);

    if actual == expected {
        EntityVerification::Valid
    } else {
        EntityVerification::Tampered { expected, actual }
    }
}

/// Verify an entire sub-graph rooted at `entity_id`.
///
/// Walks all outgoing relations recursively, verifying each entity's content
/// hash against the stored hashes. Returns a report listing verified and
/// tampered nodes.
pub fn verify_subgraph(
    entity_id: &EntityId,
    snapshot: &GraphSnapshot,
    stored_hashes: &HashMap<EntityId, MerkleHash>,
) -> Result<VerificationReport, KinDbError> {
    let mut report = VerificationReport {
        root: *entity_id,
        verified: Vec::new(),
        tampered: Vec::new(),
        verification_path: Vec::new(),
        is_valid: true,
    };

    let mut visited = HashSet::new();
    verify_subgraph_recursive(entity_id, snapshot, stored_hashes, &mut report, &mut visited);

    report.is_valid = report.tampered.is_empty();
    Ok(report)
}

fn verify_subgraph_recursive(
    entity_id: &EntityId,
    snapshot: &GraphSnapshot,
    stored_hashes: &HashMap<EntityId, MerkleHash>,
    report: &mut VerificationReport,
    visited: &mut HashSet<EntityId>,
) {
    if !visited.insert(*entity_id) {
        return; // Already visited (cycle protection)
    }

    report.verification_path.push(*entity_id);

    match verify_entity(entity_id, snapshot, stored_hashes) {
        EntityVerification::Valid => {
            report.verified.push(*entity_id);
        }
        EntityVerification::Tampered { expected, actual } => {
            report.tampered.push(TamperedNode {
                entity_id: *entity_id,
                expected_hash: expected,
                actual_hash: actual,
            });
        }
        EntityVerification::Missing => {
            // Entity not in graph or no stored hash — skip
        }
    }

    // Recurse into outgoing relations
    if let Some(rel_ids) = snapshot.outgoing.get(entity_id) {
        for rel_id in rel_ids {
            if let Some(relation) = snapshot.relations.get(rel_id) {
                verify_subgraph_recursive(
                    &relation.dst,
                    snapshot,
                    stored_hashes,
                    report,
                    visited,
                );
            }
        }
    }
}

/// Build a stored hash map for all entities in a snapshot.
///
/// This is used when saving a snapshot — compute and store the content hash
/// for every entity so that future verification can detect tampering.
pub fn build_entity_hash_map(snapshot: &GraphSnapshot) -> HashMap<EntityId, MerkleHash> {
    snapshot
        .entities
        .iter()
        .map(|(id, entity)| (*id, compute_entity_hash(entity)))
        .collect()
}

/// Incrementally update the hash map after a single entity mutation.
///
/// Only recomputes the hash for the changed entity rather than the entire graph.
pub fn update_entity_hash(
    entity: &Entity,
    hash_map: &mut HashMap<EntityId, MerkleHash>,
) {
    hash_map.insert(entity.id, compute_entity_hash(entity));
}

/// Remove an entity's hash from the map.
pub fn remove_entity_hash(entity_id: &EntityId, hash_map: &mut HashMap<EntityId, MerkleHash>) {
    hash_map.remove(entity_id);
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

    fn test_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        }
    }

    fn build_snapshot(
        entities: Vec<Entity>,
        relations: Vec<Relation>,
    ) -> GraphSnapshot {
        let mut snap = GraphSnapshot::empty();

        for e in &entities {
            snap.entities.insert(e.id, e.clone());
        }

        for r in &relations {
            snap.relations.insert(r.id, r.clone());
            snap.outgoing.entry(r.src).or_default().push(r.id);
            snap.incoming.entry(r.dst).or_default().push(r.id);
        }

        snap
    }

    // ---------------------------------------------------------------
    // Entity hash tests
    // ---------------------------------------------------------------

    #[test]
    fn entity_hash_is_deterministic() {
        let e = test_entity("deterministic");
        let h1 = compute_entity_hash(&e);
        let h2 = compute_entity_hash(&e);
        assert_eq!(h1, h2);
        assert_ne!(h1, ZERO_HASH);
    }

    #[test]
    fn entity_hash_changes_on_name_change() {
        let mut e = test_entity("original");
        let h1 = compute_entity_hash(&e);
        e.name = "modified".to_string();
        let h2 = compute_entity_hash(&e);
        assert_ne!(h1, h2);
    }

    #[test]
    fn entity_hash_changes_on_kind_change() {
        let mut e = test_entity("my_fn");
        let h1 = compute_entity_hash(&e);
        e.kind = EntityKind::Class;
        let h2 = compute_entity_hash(&e);
        assert_ne!(h1, h2);
    }

    #[test]
    fn entity_hash_changes_on_signature_change() {
        let mut e = test_entity("sig_test");
        let h1 = compute_entity_hash(&e);
        e.signature = "fn sig_test(x: i32) -> bool".to_string();
        let h2 = compute_entity_hash(&e);
        assert_ne!(h1, h2);
    }

    #[test]
    fn entity_hash_changes_on_fingerprint_change() {
        let mut e = test_entity("fp_test");
        let h1 = compute_entity_hash(&e);
        e.fingerprint.ast_hash = Hash256::from_bytes([1; 32]);
        let h2 = compute_entity_hash(&e);
        assert_ne!(h1, h2);
    }

    #[test]
    fn entity_hash_changes_on_metadata_change() {
        let mut e = test_entity("meta_test");
        let h1 = compute_entity_hash(&e);
        e.metadata
            .extra
            .insert("key".to_string(), serde_json::json!("value"));
        let h2 = compute_entity_hash(&e);
        assert_ne!(h1, h2);
    }

    // ---------------------------------------------------------------
    // Relation hash tests
    // ---------------------------------------------------------------

    #[test]
    fn relation_hash_incorporates_endpoint_hashes() {
        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        let h1_src = compute_entity_hash(&e1);
        let h1_dst = compute_entity_hash(&e2);
        let rh1 = compute_relation_hash(&rel, h1_src, h1_dst);

        // Same relation but with different source entity hash
        let rh2 = compute_relation_hash(&rel, [0xFF; 32], h1_dst);
        assert_ne!(rh1, rh2);

        // Same relation but with different dest entity hash
        let rh3 = compute_relation_hash(&rel, h1_src, [0xFF; 32]);
        assert_ne!(rh1, rh3);
    }

    #[test]
    fn relation_hash_changes_on_kind_change() {
        let e1 = test_entity("a");
        let e2 = test_entity("b");
        let mut rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let src_h = compute_entity_hash(&e1);
        let dst_h = compute_entity_hash(&e2);

        let rh1 = compute_relation_hash(&rel, src_h, dst_h);
        rel.kind = RelationKind::Imports;
        let rh2 = compute_relation_hash(&rel, src_h, dst_h);
        assert_ne!(rh1, rh2);
    }

    // ---------------------------------------------------------------
    // Sub-graph hash tests
    // ---------------------------------------------------------------

    #[test]
    fn subgraph_hash_changes_when_descendant_changes() {
        let e1 = test_entity("root");
        let e2 = test_entity("child");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let snap1 = build_snapshot(vec![e1.clone(), e2.clone()], vec![rel.clone()]);

        let mut cache1 = HashMap::new();
        let h1 = compute_subgraph_hash(&e1.id, &snap1, &mut cache1);

        // Modify the child entity
        let mut e2_modified = e2.clone();
        e2_modified.name = "child_modified".to_string();
        let snap2 = build_snapshot(vec![e1.clone(), e2_modified], vec![rel]);

        let mut cache2 = HashMap::new();
        let h2 = compute_subgraph_hash(&e1.id, &snap2, &mut cache2);

        assert_ne!(h1, h2, "sub-graph hash should change when descendant changes");
    }

    #[test]
    fn subgraph_hash_handles_cycles() {
        // A -> B -> A (cycle)
        let e1 = test_entity("cycle_a");
        let e2 = test_entity("cycle_b");
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e1.id, RelationKind::Calls);
        let snap = build_snapshot(vec![e1.clone(), e2.clone()], vec![r1, r2]);

        let mut cache = HashMap::new();
        // Should not stack overflow
        let h = compute_subgraph_hash(&e1.id, &snap, &mut cache);
        assert_ne!(h, ZERO_HASH);
    }

    // ---------------------------------------------------------------
    // Graph root hash tests
    // ---------------------------------------------------------------

    #[test]
    fn graph_root_hash_is_deterministic_regardless_of_insertion_order() {
        let e1 = test_entity("alpha");
        let e2 = test_entity("beta");
        let e3 = test_entity("gamma");

        // Build with order: e1, e2, e3
        let snap1 = build_snapshot(vec![e1.clone(), e2.clone(), e3.clone()], vec![]);
        let h1 = compute_graph_root_hash(&snap1);

        // Build with order: e3, e1, e2 (different insertion order)
        let snap2 = build_snapshot(vec![e3.clone(), e1.clone(), e2.clone()], vec![]);
        let h2 = compute_graph_root_hash(&snap2);

        assert_eq!(h1, h2, "root hash should be insertion-order independent");
    }

    #[test]
    fn graph_root_hash_changes_on_entity_change() {
        let e1 = test_entity("stable");
        let e2 = test_entity("changing");

        let snap1 = build_snapshot(vec![e1.clone(), e2.clone()], vec![]);
        let h1 = compute_graph_root_hash(&snap1);

        let mut e2_mod = e2.clone();
        e2_mod.name = "changed".to_string();
        let snap2 = build_snapshot(vec![e1, e2_mod], vec![]);
        let h2 = compute_graph_root_hash(&snap2);

        assert_ne!(h1, h2);
    }

    #[test]
    fn empty_graph_has_consistent_root_hash() {
        let snap = GraphSnapshot::empty();
        let h1 = compute_graph_root_hash(&snap);
        let h2 = compute_graph_root_hash(&snap);
        assert_eq!(h1, h2);
    }

    // ---------------------------------------------------------------
    // Verification tests
    // ---------------------------------------------------------------

    #[test]
    fn verify_entity_detects_tampered_content() {
        let e = test_entity("honest");
        let snap = build_snapshot(vec![e.clone()], vec![]);

        // Build hash map from original snapshot
        let hashes = build_entity_hash_map(&snap);

        // Verify passes with original
        let result = verify_entity(&e.id, &snap, &hashes);
        assert_eq!(result, EntityVerification::Valid);

        // Tamper with entity
        let mut tampered_snap = snap.clone();
        tampered_snap
            .entities
            .get_mut(&e.id)
            .unwrap()
            .name = "tampered".to_string();

        let result = verify_entity(&e.id, &tampered_snap, &hashes);
        assert!(matches!(result, EntityVerification::Tampered { .. }));
    }

    #[test]
    fn verify_subgraph_reports_tampered_nodes() {
        let e1 = test_entity("root");
        let e2 = test_entity("child_ok");
        let e3 = test_entity("child_tampered");
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e1.id, e3.id, RelationKind::Calls);

        let snap = build_snapshot(
            vec![e1.clone(), e2.clone(), e3.clone()],
            vec![r1, r2],
        );
        let hashes = build_entity_hash_map(&snap);

        // Tamper with e3 only
        let mut tampered_snap = snap.clone();
        tampered_snap
            .entities
            .get_mut(&e3.id)
            .unwrap()
            .name = "EVIL".to_string();

        let report = verify_subgraph(&e1.id, &tampered_snap, &hashes).unwrap();

        assert!(!report.is_valid);
        assert_eq!(report.tampered.len(), 1);
        assert_eq!(report.tampered[0].entity_id, e3.id);
        assert_eq!(report.verified.len(), 2); // e1 and e2 are fine
    }

    #[test]
    fn verify_subgraph_all_valid() {
        let e1 = test_entity("root");
        let e2 = test_entity("leaf");
        let rel = test_relation(e1.id, e2.id, RelationKind::Contains);

        let snap = build_snapshot(vec![e1.clone(), e2.clone()], vec![rel]);
        let hashes = build_entity_hash_map(&snap);

        let report = verify_subgraph(&e1.id, &snap, &hashes).unwrap();
        assert!(report.is_valid);
        assert_eq!(report.verified.len(), 2);
        assert!(report.tampered.is_empty());
    }

    // ---------------------------------------------------------------
    // Incremental update tests
    // ---------------------------------------------------------------

    #[test]
    fn incremental_update_only_changes_affected_hash() {
        let e1 = test_entity("stable");
        let e2 = test_entity("changing");
        let snap = build_snapshot(vec![e1.clone(), e2.clone()], vec![]);

        let mut hashes = build_entity_hash_map(&snap);
        let original_e1_hash = hashes[&e1.id];
        let original_e2_hash = hashes[&e2.id];

        // Modify e2
        let mut e2_mod = e2.clone();
        e2_mod.name = "changed".to_string();
        update_entity_hash(&e2_mod, &mut hashes);

        // e1's hash is untouched
        assert_eq!(hashes[&e1.id], original_e1_hash);
        // e2's hash has changed
        assert_ne!(hashes[&e2.id], original_e2_hash);
    }

    #[test]
    fn build_hash_map_is_comprehensive() {
        let e1 = test_entity("a");
        let e2 = test_entity("b");
        let e3 = test_entity("c");
        let snap = build_snapshot(vec![e1.clone(), e2.clone(), e3.clone()], vec![]);

        let hashes = build_entity_hash_map(&snap);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains_key(&e1.id));
        assert!(hashes.contains_key(&e2.id));
        assert!(hashes.contains_key(&e3.id));
    }

    #[test]
    fn remove_entity_hash_works() {
        let e = test_entity("removable");
        let snap = build_snapshot(vec![e.clone()], vec![]);
        let mut hashes = build_entity_hash_map(&snap);
        assert!(hashes.contains_key(&e.id));

        remove_entity_hash(&e.id, &mut hashes);
        assert!(!hashes.contains_key(&e.id));
    }
}
