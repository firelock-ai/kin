// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

/// Trait abstracting read-only access to the entity/relation graph for Merkle
/// hash computation.  Implemented for both [`GraphSnapshot`] (owned, on-disk
/// format) and borrowed live-graph stores so that `compute_graph_root_hash` can
/// run without materialising a full snapshot clone.
pub trait GraphHashSource {
    fn hash_entity(&self, id: &EntityId) -> Option<&Entity>;
    fn hash_relation(&self, id: &RelationId) -> Option<&Relation>;
    fn hash_outgoing(&self, id: &EntityId) -> Option<&[RelationId]>;
    fn hash_entity_ids(&self) -> Vec<EntityId>;
}

impl GraphHashSource for GraphSnapshot {
    fn hash_entity(&self, id: &EntityId) -> Option<&Entity> {
        self.entities.get(id)
    }
    fn hash_relation(&self, id: &RelationId) -> Option<&Relation> {
        self.relations.get(id)
    }
    fn hash_outgoing(&self, id: &EntityId) -> Option<&[RelationId]> {
        self.outgoing.get(id).map(|v| v.as_slice())
    }
    fn hash_entity_ids(&self) -> Vec<EntityId> {
        self.entities.keys().copied().collect()
    }
}

/// Persistent cache of per-entity content hashes.
///
/// Avoids recomputing SHA-256 for every entity on each
/// `compute_graph_root_hash` call. Callers should update this cache
/// incrementally via [`MerkleCache::entity_upserted`] and
/// [`MerkleCache::entity_removed`] whenever the graph mutates.
#[derive(Debug, Clone, Default)]
pub struct MerkleCache {
    /// Cached content hash for each entity, keyed by EntityId.
    entity_hashes: HashMap<EntityId, MerkleHash>,
}

impl MerkleCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm the cache from an existing snapshot (bulk build).
    pub fn from_snapshot(snapshot: &GraphSnapshot) -> Self {
        let entity_hashes = snapshot
            .entities
            .iter()
            .map(|(id, entity)| (*id, compute_entity_hash(entity)))
            .collect();
        Self { entity_hashes }
    }

    /// Update the cached hash for a single entity (upsert).
    pub fn entity_upserted(&mut self, entity: &Entity) {
        self.entity_hashes
            .insert(entity.id, compute_entity_hash(entity));
    }

    /// Remove a cached entity hash.
    pub fn entity_removed(&mut self, entity_id: &EntityId) {
        self.entity_hashes.remove(entity_id);
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entity_hashes.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entity_hashes.is_empty()
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entity_hashes.clear();
    }
}

/// A 32-byte SHA-256 hash used throughout the Merkle DAG.
pub type MerkleHash = [u8; 32];

/// Zero hash — used as a sentinel for missing/empty nodes.
pub const ZERO_HASH: MerkleHash = [0u8; 32];

fn compute_non_entity_node_hash(node: &GraphNodeId) -> MerkleHash {
    match node {
        GraphNodeId::Entity(_) => ZERO_HASH, // caller handles entities via cache
        GraphNodeId::Artifact(id) => hash_tagged_node("artifact", &id.0.to_string()),
        GraphNodeId::Test(id) => hash_tagged_node("test", &id.to_string()),
        GraphNodeId::Contract(id) => hash_tagged_node("contract", &id.to_string()),
        GraphNodeId::Work(id) => hash_tagged_node("work", &id.to_string()),
        GraphNodeId::VerificationRun(id) => hash_tagged_node("verification_run", &id.to_string()),
    }
}

fn compute_graph_node_hash_generic(
    node: &GraphNodeId,
    source: &impl GraphHashSource,
    cache: &mut HashMap<EntityId, MerkleHash>,
) -> MerkleHash {
    match node {
        GraphNodeId::Entity(entity_id) => {
            compute_subgraph_hash_generic(entity_id, source, cache, None)
        }
        GraphNodeId::Artifact(artifact_id) => {
            hash_tagged_node("artifact", &artifact_id.0.to_string())
        }
        GraphNodeId::Test(test_id) => hash_tagged_node("test", &test_id.to_string()),
        GraphNodeId::Contract(contract_id) => {
            hash_tagged_node("contract", &contract_id.to_string())
        }
        GraphNodeId::Work(work_id) => hash_tagged_node("work", &work_id.to_string()),
        GraphNodeId::VerificationRun(run_id) => {
            hash_tagged_node("verification_run", &run_id.to_string())
        }
    }
}

fn hash_tagged_node(tag: &str, value: &str) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-node-v1:");
    hasher.update(tag.as_bytes());
    hasher.update(b"|");
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

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
    hasher.update(src_hash);

    // Destination entity hash
    hasher.update(dst_hash);

    // Confidence (as bytes for determinism)
    hasher.update(relation.confidence.to_le_bytes());

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
///
/// If a [`MerkleCache`] is provided, per-entity content hashes are looked up
/// from the cache instead of being recomputed. The subgraph traversal cache
/// (`cache` parameter) still prevents redundant graph walks within a single
/// root-hash computation.
pub fn compute_subgraph_hash(
    entity_id: &EntityId,
    snapshot: &GraphSnapshot,
    cache: &mut HashMap<EntityId, MerkleHash>,
) -> MerkleHash {
    compute_subgraph_hash_generic(entity_id, snapshot, cache, None)
}

/// Like [`compute_subgraph_hash`] but accepts an optional [`MerkleCache`]
/// for reusing pre-computed entity content hashes.
pub fn compute_subgraph_hash_with(
    entity_id: &EntityId,
    snapshot: &GraphSnapshot,
    cache: &mut HashMap<EntityId, MerkleHash>,
    merkle_cache: Option<&mut MerkleCache>,
) -> MerkleHash {
    compute_subgraph_hash_generic(entity_id, snapshot, cache, merkle_cache)
}

/// Generic sub-graph hash computation over any [`GraphHashSource`].
///
/// Uses an iterative work-stack instead of recursive descent to avoid
/// stack overflow on deep entity chains (20K+ entities with long call
/// chains easily exceed the default 2 MB thread stack).
pub fn compute_subgraph_hash_generic(
    root_id: &EntityId,
    source: &impl GraphHashSource,
    cache: &mut HashMap<EntityId, MerkleHash>,
    merkle_cache: Option<&mut MerkleCache>,
) -> MerkleHash {
    if let Some(&cached) = cache.get(root_id) {
        return cached;
    }

    // Phase 1: iterative DFS to discover all reachable entity IDs and
    // compute per-entity content hashes (no recursion needed).
    let mut visit_stack: Vec<EntityId> = vec![*root_id];
    let mut topo_order: Vec<EntityId> = Vec::new();

    while let Some(eid) = visit_stack.pop() {
        if cache.contains_key(&eid) {
            continue;
        }
        let Some(entity) = source.hash_entity(&eid) else {
            cache.insert(eid, ZERO_HASH);
            continue;
        };
        // Sentinel breaks cycles — any back-edge sees ZERO_HASH.
        cache.insert(eid, ZERO_HASH);
        topo_order.push(eid);

        // Pre-compute entity content hash (cheap, no graph walk).
        let ehash = match &merkle_cache {
            Some(mc) => mc
                .entity_hashes
                .get(&eid)
                .copied()
                .unwrap_or_else(|| compute_entity_hash(entity)),
            None => compute_entity_hash(entity),
        };
        // Stash entity hash in a tagged sentinel so Phase 2 can retrieve it.
        // We'll overwrite the cache entry in Phase 2 with the real subgraph
        // hash. For now, store the entity hash in the upper bits won't work
        // (it's the same type). Instead, keep a side map.
        // Actually, we just recompute the entity hash in Phase 2 — it's fast
        // (no allocation, just SHA-256 of a few fields).
        let _ = ehash; // used below

        if let Some(rel_ids) = source.hash_outgoing(&eid) {
            for rel_id in rel_ids {
                if let Some(relation) = source.hash_relation(rel_id) {
                    if let GraphNodeId::Entity(dst_eid) = &relation.dst {
                        if !cache.contains_key(dst_eid) {
                            visit_stack.push(*dst_eid);
                        }
                    }
                }
            }
        }
    }

    // Phase 2: compute subgraph hashes in reverse discovery order (leaves
    // first). By the time we process a node, all its outgoing entity
    // targets already have their final hash in the cache.
    for eid in topo_order.iter().rev() {
        let Some(entity) = source.hash_entity(eid) else {
            continue;
        };
        let entity_hash = match &merkle_cache {
            Some(mc) => mc
                .entity_hashes
                .get(eid)
                .copied()
                .unwrap_or_else(|| compute_entity_hash(entity)),
            None => compute_entity_hash(entity),
        };

        let mut relation_hashes: Vec<MerkleHash> = Vec::new();
        if let Some(rel_ids) = source.hash_outgoing(eid) {
            for rel_id in rel_ids {
                if let Some(relation) = source.hash_relation(rel_id) {
                    let src_hash = entity_hash;
                    let dst_hash = match &relation.dst {
                        GraphNodeId::Entity(dst_eid) => {
                            cache.get(dst_eid).copied().unwrap_or(ZERO_HASH)
                        }
                        other => compute_non_entity_node_hash(other),
                    };
                    let rel_hash = compute_relation_hash(relation, src_hash, dst_hash);
                    relation_hashes.push(rel_hash);
                }
            }
        }
        relation_hashes.sort();

        let mut hasher = Sha256::new();
        hasher.update(b"kin-subgraph-v1:");
        hasher.update(entity_hash);
        for rh in &relation_hashes {
            hasher.update(rh);
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        cache.insert(*eid, hash);
    }

    cache.get(root_id).copied().unwrap_or(ZERO_HASH)
}

/// Compute the root hash for the entire graph.
///
/// The root hash is the SHA-256 of all entity sub-graph hashes sorted lexicographically.
/// This means the root is deterministic regardless of entity insertion order.
pub fn compute_graph_root_hash(snapshot: &GraphSnapshot) -> MerkleHash {
    compute_root_hash_generic(snapshot, None)
}

/// Like [`compute_graph_root_hash`] but accepts an optional [`MerkleCache`].
///
/// When a `MerkleCache` is provided, per-entity content hashes are reused
/// instead of being recomputed from scratch. The subgraph and root hashes
/// are still freshly computed (they depend on the relation topology) but the
/// expensive entity-level SHA-256 is cached.
pub fn compute_graph_root_hash_with(
    snapshot: &GraphSnapshot,
    merkle_cache: Option<&mut MerkleCache>,
) -> MerkleHash {
    compute_root_hash_generic(snapshot, merkle_cache)
}

/// Generic root hash computation over any [`GraphHashSource`].
pub fn compute_root_hash_generic(
    source: &impl GraphHashSource,
    mut merkle_cache: Option<&mut MerkleCache>,
) -> MerkleHash {
    let mut subgraph_cache = HashMap::new();
    let mut entity_ids = source.hash_entity_ids();
    entity_ids.sort_by_key(|entity_id| *entity_id.0.as_bytes());

    // Compute sub-graph hash for every entity
    let mut all_hashes: Vec<MerkleHash> = entity_ids
        .iter()
        .map(|id| {
            compute_subgraph_hash_generic(
                id,
                source,
                &mut subgraph_cache,
                merkle_cache.as_deref_mut(),
            )
        })
        .collect();

    // Sort for determinism
    all_hashes.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"kin-graph-root-v1:");
    for h in &all_hashes {
        hasher.update(h);
    }

    // Back-fill the MerkleCache with any entity hashes we computed during traversal
    if let Some(ref mut mc) = merkle_cache {
        for id in &entity_ids {
            if let Some(entity) = source.hash_entity(id) {
                mc.entity_hashes
                    .entry(*id)
                    .or_insert_with(|| compute_entity_hash(entity));
            }
        }
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute a full repo-truth hash covering ALL first-class truth domains.
///
/// Unlike [`compute_graph_root_hash`] which only covers entities and relations
/// (and remains the entity-integrity primitive), this hash includes every
/// domain in the snapshot: work items, work links, audit events, sessions,
/// intents, artifacts, branches, reviews, tests, contracts, and verification.
///
/// Use this for bootstrap acceptance, optimistic concurrency, and cache
/// validation — anywhere "has repo truth changed?" is the question.
pub fn compute_repo_truth_hash(snapshot: &GraphSnapshot) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-repo-truth-v1:");

    let entity_root = compute_graph_root_hash(snapshot);
    hasher.update(entity_root);

    hash_domain_count(&mut hasher, "work_items", snapshot.work_items.len());
    let mut work_ids: Vec<_> = snapshot.work_items.keys().collect();
    work_ids.sort_by_key(|id| id.0.as_bytes());
    for id in &work_ids {
        hasher.update(id.0.as_bytes());
        if let Some(item) = snapshot.work_items.get(id) {
            hasher.update(format!("{}", item.status).as_bytes());
            hasher.update(item.title.as_bytes());
        }
    }

    hash_domain_count(&mut hasher, "work_links", snapshot.work_links.len());
    hash_domain_count(&mut hasher, "audit_events", snapshot.audit_events.len());
    for ev in &snapshot.audit_events {
        hasher.update(ev.action.as_bytes());
        hasher.update(ev.timestamp.0.to_rfc3339().as_bytes());
    }

    hash_domain_count(&mut hasher, "sessions", snapshot.sessions.len());
    let mut sess_ids: Vec<_> = snapshot.sessions.keys().collect();
    sess_ids.sort_by_key(|id| id.0.as_bytes());
    for id in &sess_ids {
        hasher.update(id.0.as_bytes());
    }

    hash_domain_count(&mut hasher, "intents", snapshot.intents.len());
    let mut intent_ids: Vec<_> = snapshot.intents.keys().collect();
    intent_ids.sort_by_key(|id| id.0.as_bytes());
    for id in &intent_ids {
        hasher.update(id.0.as_bytes());
    }

    hash_domain_count(&mut hasher, "branches", snapshot.branches.len());
    hash_domain_count(&mut hasher, "changes", snapshot.changes.len());
    hash_domain_count(&mut hasher, "contracts", snapshot.contracts.len());
    hash_domain_count(&mut hasher, "test_cases", snapshot.test_cases.len());
    hash_domain_count(
        &mut hasher,
        "verification_runs",
        snapshot.verification_runs.len(),
    );
    hash_domain_count(&mut hasher, "reviews", snapshot.reviews.len());
    hash_domain_count(&mut hasher, "annotations", snapshot.annotations.len());
    hash_domain_count(
        &mut hasher,
        "artifacts_structured",
        snapshot.structured_artifacts.len(),
    );
    hash_domain_count(
        &mut hasher,
        "artifacts_opaque",
        snapshot.opaque_artifacts.len(),
    );

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn hash_domain_count(hasher: &mut Sha256, domain: &str, count: usize) {
    hasher.update(domain.as_bytes());
    hasher.update(&(count as u64).to_le_bytes());
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
    verify_subgraph_recursive(
        entity_id,
        snapshot,
        stored_hashes,
        &mut report,
        &mut visited,
    );

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
                if let Some(dst_entity_id) = relation.dst.as_entity() {
                    verify_subgraph_recursive(
                        &dst_entity_id,
                        snapshot,
                        stored_hashes,
                        report,
                        visited,
                    );
                }
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
pub fn update_entity_hash(entity: &Entity, hash_map: &mut HashMap<EntityId, MerkleHash>) {
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
            role: EntityRole::Source,
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
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        }
    }

    fn build_snapshot(entities: Vec<Entity>, relations: Vec<Relation>) -> GraphSnapshot {
        let mut snap = GraphSnapshot::empty();

        for e in &entities {
            snap.entities.insert(e.id, e.clone());
        }

        for r in &relations {
            snap.relations.insert(r.id, r.clone());
            if let Some(src) = r.src.as_entity() {
                snap.outgoing.entry(src).or_default().push(r.id);
            }
            if let Some(dst) = r.dst.as_entity() {
                snap.incoming.entry(dst).or_default().push(r.id);
            }
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

        assert_ne!(
            h1, h2,
            "sub-graph hash should change when descendant changes"
        );
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
    fn graph_root_hash_is_deterministic_for_cycles_regardless_of_insertion_order() {
        let e1 = test_entity("alpha");
        let e2 = test_entity("beta");
        let e3 = test_entity("gamma");
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e1.id, RelationKind::Calls);
        let r3 = test_relation(e2.id, e3.id, RelationKind::Calls);

        let snap1 = build_snapshot(
            vec![e1.clone(), e2.clone(), e3.clone()],
            vec![r1.clone(), r2.clone(), r3.clone()],
        );
        let h1 = compute_graph_root_hash(&snap1);

        let snap2 = build_snapshot(vec![e3.clone(), e1.clone(), e2.clone()], vec![r3, r2, r1]);
        let h2 = compute_graph_root_hash(&snap2);

        assert_eq!(h1, h2, "root hash should stay stable for cyclic graphs");
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
        tampered_snap.entities.get_mut(&e.id).unwrap().name = "tampered".to_string();

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

        let snap = build_snapshot(vec![e1.clone(), e2.clone(), e3.clone()], vec![r1, r2]);
        let hashes = build_entity_hash_map(&snap);

        // Tamper with e3 only
        let mut tampered_snap = snap.clone();
        tampered_snap.entities.get_mut(&e3.id).unwrap().name = "EVIL".to_string();

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

    // ---------------------------------------------------------------
    // MerkleCache tests
    // ---------------------------------------------------------------

    #[test]
    fn merkle_cache_produces_same_root_hash() {
        let e1 = test_entity("cached_a");
        let e2 = test_entity("cached_b");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let snap = build_snapshot(vec![e1.clone(), e2.clone()], vec![rel]);

        let h_without = compute_graph_root_hash(&snap);

        let mut mc = MerkleCache::from_snapshot(&snap);
        let h_with = compute_graph_root_hash_with(&snap, Some(&mut mc));

        assert_eq!(h_without, h_with, "cached root hash must match uncached");
    }

    #[test]
    fn merkle_cache_incremental_update() {
        let e1 = test_entity("inc_a");
        let mut e2 = test_entity("inc_b");
        let snap1 = build_snapshot(vec![e1.clone(), e2.clone()], vec![]);

        let mut mc = MerkleCache::from_snapshot(&snap1);
        assert_eq!(mc.len(), 2);

        // Modify e2 and update the cache incrementally
        e2.name = "inc_b_modified".to_string();
        mc.entity_upserted(&e2);

        let snap2 = build_snapshot(vec![e1, e2], vec![]);
        let h_cached = compute_graph_root_hash_with(&snap2, Some(&mut mc));
        let h_fresh = compute_graph_root_hash(&snap2);

        assert_eq!(
            h_cached, h_fresh,
            "incrementally-updated cache must match fresh computation"
        );
    }

    #[test]
    fn merkle_cache_entity_removed() {
        let e1 = test_entity("rm_a");
        let e2 = test_entity("rm_b");
        let snap = build_snapshot(vec![e1.clone(), e2.clone()], vec![]);

        let mut mc = MerkleCache::from_snapshot(&snap);
        assert_eq!(mc.len(), 2);

        mc.entity_removed(&e2.id);
        assert_eq!(mc.len(), 1);

        // Cache still works after removal (will recompute missing entity on demand)
        let snap2 = build_snapshot(vec![e1], vec![]);
        let h_cached = compute_graph_root_hash_with(&snap2, Some(&mut mc));
        let h_fresh = compute_graph_root_hash(&snap2);
        assert_eq!(h_cached, h_fresh);
    }
}
