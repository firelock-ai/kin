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

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::KinDbError;
use crate::storage::format::{GraphSnapshot, LocateGraphSnapshot};
use crate::types::*;

/// Trait abstracting read-only access to the entity/relation graph for Merkle
/// hash computation.  Implemented for both [`GraphSnapshot`] (owned, on-disk
/// format) and borrowed live-graph stores so that `compute_graph_root_hash` can
/// run without materialising a full snapshot clone.
pub trait GraphHashSource {
    fn hash_entity(&self, id: &EntityId) -> Option<&Entity>;
    fn hash_relation(&self, id: &RelationId) -> Option<&Relation>;
    fn hash_outgoing(&self, id: &EntityId) -> Option<&[RelationId]>;
    fn hash_incoming(&self, id: &EntityId) -> Option<&[RelationId]>;
    fn hash_entity_ids(&self) -> Vec<EntityId>;
    /// Number of entities in the source. Used to size the incremental-vs-full
    /// refresh decision without materialising the full id list.
    fn hash_entity_count(&self) -> usize {
        self.hash_entity_ids().len()
    }
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
    fn hash_incoming(&self, id: &EntityId) -> Option<&[RelationId]> {
        self.incoming.get(id).map(|v| v.as_slice())
    }
    fn hash_entity_ids(&self) -> Vec<EntityId> {
        self.entities.keys().copied().collect()
    }
    fn hash_entity_count(&self) -> usize {
        self.entities.len()
    }
}

/// Maintained Merkle state for the live entity/relation graph.
///
/// This preserves the exact root semantics of [`compute_graph_root_hash`] while
/// allowing live graphs to update the root from mutation seeds. The root hash
/// itself is still the SHA-256 stream over all sorted subgraph hashes; because
/// that legacy digest is intentionally unchanged, refreshing the root folds the
/// cached subgraph-hash multiset rather than walking or rehashing the full
/// graph.
#[derive(Debug, Clone)]
pub struct MerkleCache {
    /// Cached content hash for each entity, keyed by EntityId.
    entity_hashes: HashMap<EntityId, MerkleHash>,
    /// Cached subgraph hash for each entity, keyed by EntityId.
    subgraph_hashes: HashMap<EntityId, MerkleHash>,
    /// Multiset of current subgraph hashes, sorted for root folding.
    root_hashes: BTreeMap<MerkleHash, usize>,
    /// Current root hash for the live graph state.
    root_hash: MerkleHash,
}

impl Default for MerkleCache {
    fn default() -> Self {
        Self {
            entity_hashes: HashMap::new(),
            subgraph_hashes: HashMap::new(),
            root_hashes: BTreeMap::new(),
            root_hash: compute_root_from_sorted_hashes(std::iter::empty()),
        }
    }
}

impl MerkleCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm the cache from an existing snapshot (bulk build).
    pub fn from_snapshot(snapshot: &GraphSnapshot) -> Self {
        Self::from_source(snapshot)
    }

    /// Warm the cache from any graph hash source (bulk build/cold open).
    ///
    /// This is an O(entities + relations) batch build. Per-entity content hashes
    /// are order-independent, so they are computed in parallel across the rayon
    /// pool; the subgraph and root folds stay sequential over a fixed sorted
    /// order so the cycle-breaking traversal — and therefore the root — remains
    /// bit-identical to [`compute_graph_root_hash`].
    pub fn from_source(source: &impl GraphHashSource) -> Self {
        let mut cache = Self::new();
        let mut entity_ids = source.hash_entity_ids();
        entity_ids.sort_by_key(|entity_id| *entity_id.0.as_bytes());

        // Phase 1 (parallel, order-free): every entity's content hash is an
        // independent SHA-256 over its own fields. Collecting into a keyed map
        // makes the result independent of completion order.
        let entities_to_hash: Vec<(EntityId, &Entity)> = entity_ids
            .iter()
            .filter_map(|entity_id| source.hash_entity(entity_id).map(|e| (*entity_id, e)))
            .collect();
        cache.entity_hashes = entities_to_hash
            .par_iter()
            .map(|(entity_id, entity)| (*entity_id, compute_entity_hash(entity)))
            .collect();

        // Phase 2 (sequential): subgraph hashes share a traversal cache and
        // break cycles at whichever node the sorted DFS reaches first, so the
        // fixed sorted order is load-bearing for determinism.
        let mut subgraph_cache = HashMap::new();
        for entity_id in entity_ids {
            let subgraph_hash = compute_subgraph_hash_generic(
                &entity_id,
                source,
                &mut subgraph_cache,
                Some(&mut cache),
            );
            cache.set_subgraph_hash(entity_id, Some(subgraph_hash));
        }
        cache.root_hash = cache.compute_root_from_multiset();
        cache
    }

    /// Current graph root hash.
    pub fn root_hash(&self) -> MerkleHash {
        self.root_hash
    }

    /// Update the cached hash for a single entity (upsert).
    pub fn entity_upserted(&mut self, entity: &Entity) {
        self.entity_hashes
            .insert(entity.id, compute_entity_hash(entity));
    }

    /// Remove a cached entity hash.
    pub fn entity_removed(&mut self, entity_id: &EntityId) {
        self.entity_hashes.remove(entity_id);
        self.set_subgraph_hash(*entity_id, None);
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
        self.subgraph_hashes.clear();
        self.root_hashes.clear();
        self.root_hash = compute_root_from_sorted_hashes(std::iter::empty());
    }

    /// Rebuild the maintained state from a source and return the fresh root.
    pub fn rebuild_from_source(&mut self, source: &impl GraphHashSource) -> MerkleHash {
        *self = Self::from_source(source);
        self.root_hash
    }

    /// Refresh the root after mutation seeds changed.
    ///
    /// The dirty set is the touched entity component (see
    /// [`collect_touched_entity_component`]): the frozen subgraph algorithm's
    /// cycle handling makes per-mutation refresh inherently O(component), so the
    /// way to keep bulk ingestion linear is to refresh once over many
    /// accumulated seeds rather than once per mutation.
    ///
    /// When the work covers a large fraction of the graph — the initial bulk
    /// load touches nearly every entity — a single [`Self::from_source`] batch
    /// build is both simpler and faster (its per-entity hashing runs in
    /// parallel), so we fall back to it. The two fast-path checks bound the cost
    /// at O(entities + relations): the first skips the component walk when the
    /// seeds alone already dominate the graph, the second catches the case where
    /// the walked component does.
    pub fn refresh_affected<I>(&mut self, source: &impl GraphHashSource, seeds: I) -> MerkleHash
    where
        I: IntoIterator<Item = EntityId>,
    {
        let entity_count = source.hash_entity_count();
        let seeds: Vec<EntityId> = seeds.into_iter().collect();
        if seeds.len().saturating_mul(2) >= entity_count && entity_count > 0 {
            return self.rebuild_from_source(source);
        }

        let dirty = collect_touched_entity_component(source, seeds);
        if dirty.is_empty() {
            return self.root_hash;
        }

        if dirty.len().saturating_mul(2) >= entity_count {
            return self.rebuild_from_source(source);
        }

        for entity_id in &dirty {
            self.set_subgraph_hash(*entity_id, None);
            match source.hash_entity(entity_id) {
                Some(entity) => self.entity_upserted(entity),
                None => {
                    self.entity_hashes.remove(entity_id);
                }
            }
        }

        let dirty_set: HashSet<EntityId> = dirty.iter().copied().collect();
        let mut subgraph_cache: HashMap<EntityId, MerkleHash> = self
            .subgraph_hashes
            .iter()
            .filter_map(|(entity_id, hash)| {
                if dirty_set.contains(entity_id) {
                    None
                } else {
                    Some((*entity_id, *hash))
                }
            })
            .collect();
        for entity_id in dirty {
            if source.hash_entity(&entity_id).is_some() {
                let hash = compute_subgraph_hash_generic(
                    &entity_id,
                    source,
                    &mut subgraph_cache,
                    Some(self),
                );
                self.set_subgraph_hash(entity_id, Some(hash));
            }
        }

        self.root_hash = self.compute_root_from_multiset();
        self.root_hash
    }

    fn set_subgraph_hash(&mut self, entity_id: EntityId, hash: Option<MerkleHash>) {
        if let Some(old_hash) = self.subgraph_hashes.remove(&entity_id) {
            decrement_hash_multiset(&mut self.root_hashes, old_hash);
        }
        if let Some(hash) = hash {
            self.subgraph_hashes.insert(entity_id, hash);
            *self.root_hashes.entry(hash).or_insert(0) += 1;
        }
    }

    fn compute_root_from_multiset(&self) -> MerkleHash {
        compute_root_from_sorted_hashes(
            self.root_hashes
                .iter()
                .flat_map(|(hash, count)| std::iter::repeat_n(*hash, *count)),
        )
    }
}

fn decrement_hash_multiset(multiset: &mut BTreeMap<MerkleHash, usize>, hash: MerkleHash) {
    match multiset.get_mut(&hash) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            multiset.remove(&hash);
        }
        None => {}
    }
}

fn compute_root_from_sorted_hashes<I>(hashes: I) -> MerkleHash
where
    I: IntoIterator<Item = MerkleHash>,
{
    let mut hasher = Sha256::new();
    hasher.update(b"kin-graph-root-v1:");
    for hash in hashes {
        hasher.update(hash);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Collect the touched entity component: the seeds plus every entity weakly
/// connected to them through relations (walked in both directions).
///
/// A narrower reverse-reachability closure (ancestors only) would be tempting —
/// a subgraph hash folds in only the entity's forward-reachable set, so naively
/// only ancestors of a changed entity should move. But the frozen subgraph
/// algorithm breaks cycles with a `ZERO_HASH` sentinel at whichever node a
/// shared, globally-sorted DFS reaches first. Adding or removing any node can
/// shift that entry point, which rewrites the subgraph hashes of every node in
/// the affected cycle — including pure descendants that cannot reach the change.
/// Reproducing bit-identical roots therefore requires recomputing the whole
/// connected component whose traversal context can change.
fn collect_touched_entity_component<I>(source: &impl GraphHashSource, seeds: I) -> Vec<EntityId>
where
    I: IntoIterator<Item = EntityId>,
{
    let mut dirty = HashSet::new();
    let mut stack = Vec::new();
    for seed in seeds {
        if dirty.insert(seed) {
            stack.push(seed);
        }
    }

    while let Some(entity_id) = stack.pop() {
        if let Some(relation_ids) = source.hash_incoming(&entity_id) {
            for relation_id in relation_ids {
                let Some(relation) = source.hash_relation(relation_id) else {
                    continue;
                };
                let Some(src_id) = relation.src.as_entity() else {
                    continue;
                };
                if dirty.insert(src_id) {
                    stack.push(src_id);
                }
            }
        }
        if let Some(relation_ids) = source.hash_outgoing(&entity_id) {
            for relation_id in relation_ids {
                let Some(relation) = source.hash_relation(relation_id) else {
                    continue;
                };
                let Some(dst_id) = relation.dst.as_entity() else {
                    continue;
                };
                if dirty.insert(dst_id) {
                    stack.push(dst_id);
                }
            }
        }
    }

    let mut dirty: Vec<EntityId> = dirty.into_iter().collect();
    dirty.sort_by_key(|entity_id| *entity_id.0.as_bytes());
    dirty
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
        GraphNodeId::ExternalReference(id) => {
            hash_tagged_node("external_reference", &id.to_string())
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
            // Discover destinations in a deterministic (id-sorted) order. The
            // adjacency slice order is not guaranteed across runs, and the DFS
            // discovery order decides which edge of a cycle becomes the
            // ZERO_HASH back-edge — so an unsorted push would make cyclic
            // subgraph hashes (and thus the graph root) depend on adjacency
            // insertion order rather than on graph content alone.
            let mut next: Vec<EntityId> = Vec::new();
            for rel_id in rel_ids {
                if let Some(relation) = source.hash_relation(rel_id) {
                    if let GraphNodeId::Entity(dst_eid) = &relation.dst {
                        if !cache.contains_key(dst_eid) {
                            next.push(*dst_eid);
                        }
                    }
                }
            }
            next.sort_unstable_by_key(|e| *e.0.as_bytes());
            visit_stack.extend(next);
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
    #[cfg(test)]
    root_hash_passes::record();
    compute_root_hash_generic(snapshot, None)
}

/// Test-only census of whole-graph Merkle root passes.
///
/// A root pass walks every entity in the snapshot, so an open path that takes
/// two of them does twice the work it needs to. The count is the load-independent
/// evidence for that: it holds whatever the store size or the machine is.
///
/// The counter is thread-local because the test binary runs tests in parallel and
/// a shared counter would make any assertion on it a race. Every pass counted here
/// runs on the thread that called it — [`compute_root_hash_generic`] walks entities
/// serially — so a test observes exactly the passes it caused.
#[cfg(test)]
pub(crate) mod root_hash_passes {
    use std::cell::Cell;

    thread_local! {
        static PASSES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        PASSES.with(|passes| passes.set(passes.get() + 1));
    }

    /// Start counting from zero on this thread.
    pub(crate) fn reset() {
        PASSES.with(|passes| passes.set(0));
    }

    /// Passes taken on this thread since the last [`reset`].
    pub(crate) fn count() -> u64 {
        PASSES.with(Cell::get)
    }
}

/// Versioned authority for every graph domain that can change locate, lexical,
/// or vector retrieval results.
///
/// The legacy graph root intentionally covers only entity/relation topology.
/// It is therefore not a safe sidecar identity for exact repository-tree or
/// artifact enrichment changes. This digest binds those domains as well while
/// remaining substantially cheaper than cloning and hashing a full snapshot.
pub const RETRIEVAL_AUTHORITY_HASH_VERSION: u32 = 2;

const RETRIEVAL_AUTHORITY_DOMAIN: &[u8] = b"kin-retrieval-authority-v2:";

/// Compute the retrieval-sidecar authority for an owned snapshot.
pub fn compute_retrieval_authority_hash(snapshot: &GraphSnapshot) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(RETRIEVAL_AUTHORITY_DOMAIN);
    hasher.update(RETRIEVAL_AUTHORITY_HASH_VERSION.to_le_bytes());
    hasher.update(compute_graph_root_hash(snapshot));

    hash_map_domain(&mut hasher, "retrieval_entities", &snapshot.entities);
    hash_map_domain(&mut hasher, "retrieval_relations", &snapshot.relations);
    hash_map_domain(&mut hasher, "retrieval_changes", &snapshot.changes);
    hash_map_domain(
        &mut hasher,
        "retrieval_external_references",
        &snapshot.external_references,
    );
    hash_map_domain(
        &mut hasher,
        "retrieval_entity_revisions",
        &snapshot.entity_revisions,
    );

    let shallow: Vec<_> = snapshot
        .shallow_files
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_shallow_files", &shallow);
    let layouts: Vec<_> = snapshot
        .file_layouts
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_file_layouts", &layouts);
    let structured: Vec<_> = snapshot
        .structured_artifacts
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_structured_artifacts", &structured);
    let opaque: Vec<_> = snapshot
        .opaque_artifacts
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_opaque_artifacts", &opaque);

    let resolved: Vec<_> = snapshot.resolved_tree.artifacts().collect();
    hash_domain_elements(&mut hasher, "retrieval_resolved_tree", &resolved);
    finalize_sha256(hasher)
}

/// Compute the retrieval authority for the locate-only projection without
/// materialising a second owned `GraphSnapshot`.
pub(crate) fn compute_locate_retrieval_authority_hash(
    snapshot: &LocateGraphSnapshot,
    graph_root_hash: MerkleHash,
) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(RETRIEVAL_AUTHORITY_DOMAIN);
    hasher.update(RETRIEVAL_AUTHORITY_HASH_VERSION.to_le_bytes());
    hasher.update(graph_root_hash);

    hash_domain_elements(
        &mut hasher,
        "retrieval_entities",
        &snapshot.entities.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_relations",
        &snapshot.relations.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_changes",
        &snapshot.changes.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_external_references",
        &snapshot.external_references.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_entity_revisions",
        &snapshot.entity_revisions.iter().collect::<Vec<_>>(),
    );

    let shallow: Vec<_> = snapshot
        .shallow_files
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_shallow_files", &shallow);
    let layouts: Vec<_> = snapshot
        .file_layouts
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_file_layouts", &layouts);
    let structured: Vec<_> = snapshot
        .structured_artifacts
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_structured_artifacts", &structured);
    let opaque: Vec<_> = snapshot
        .opaque_artifacts
        .iter()
        .map(|value| (&value.file_id, value))
        .collect();
    hash_domain_elements(&mut hasher, "retrieval_opaque_artifacts", &opaque);

    let resolved: Vec<_> = snapshot.resolved_tree.artifacts().collect();
    hash_domain_elements(&mut hasher, "retrieval_resolved_tree", &resolved);
    finalize_sha256(hasher)
}

/// Compute the same retrieval authority directly over live hashbrown stores.
///
/// This is the zero-clone persistence path used while graph read guards are
/// held. Keep it byte-equivalent to [`compute_retrieval_authority_hash`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_live_retrieval_authority_hash(
    graph_root_hash: MerkleHash,
    entities: &hashbrown::HashMap<EntityId, Entity>,
    relations: &hashbrown::HashMap<RelationId, Relation>,
    changes: &HashMap<SemanticChangeId, SemanticChange>,
    entity_revisions: &hashbrown::HashMap<EntityId, Vec<EntityRevision>>,
    external_references: &hashbrown::HashMap<ExternalReferenceId, ExternalReference>,
    resolved_tree: &ResolvedTree,
    shallow_files: &hashbrown::HashMap<FilePathId, ShallowTrackedFile>,
    file_layouts: &hashbrown::HashMap<FilePathId, FileLayout>,
    structured_artifacts: &hashbrown::HashMap<FilePathId, StructuredArtifact>,
    opaque_artifacts: &hashbrown::HashMap<FilePathId, OpaqueArtifact>,
) -> MerkleHash {
    let mut hasher = Sha256::new();
    hasher.update(RETRIEVAL_AUTHORITY_DOMAIN);
    hasher.update(RETRIEVAL_AUTHORITY_HASH_VERSION.to_le_bytes());
    hasher.update(graph_root_hash);

    hash_domain_elements(
        &mut hasher,
        "retrieval_entities",
        &entities.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_relations",
        &relations.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_changes",
        &changes.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_external_references",
        &external_references.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_entity_revisions",
        &entity_revisions.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_shallow_files",
        &shallow_files.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_file_layouts",
        &file_layouts.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_structured_artifacts",
        &structured_artifacts.iter().collect::<Vec<_>>(),
    );
    hash_domain_elements(
        &mut hasher,
        "retrieval_opaque_artifacts",
        &opaque_artifacts.iter().collect::<Vec<_>>(),
    );
    let resolved: Vec<_> = resolved_tree.artifacts().collect();
    hash_domain_elements(&mut hasher, "retrieval_resolved_tree", &resolved);
    finalize_sha256(hasher)
}

fn finalize_sha256(hasher: Sha256) -> MerkleHash {
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
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

    compute_root_from_sorted_hashes(all_hashes)
}

/// Encoding version of [`compute_repo_truth_hash`].
///
/// Version 1 covered most domains by cardinality only, so histories that
/// disagreed about every delta but agreed on change count hashed identically.
/// Version 2 hashes the full canonical content of every covered domain.
///
/// Bump this whenever the covered domain set or the encoding changes. Callers
/// that persist a truth hash should persist [`RepoTruthHash`] instead of a bare
/// digest so a format upgrade is distinguishable from an actual change in repo
/// truth.
pub const REPO_TRUTH_HASH_VERSION: u32 = 5;

/// Domain separator for the repo-truth digest. Carries the encoding version so
/// a v1 digest can never be mistaken for a v2 digest of the same snapshot.
const REPO_TRUTH_DOMAIN: &[u8] = b"kin-repo-truth-v5:";

/// A repo-truth digest tagged with the encoding version that produced it.
///
/// Persist this rather than a bare [`MerkleHash`]: on upgrade, a stored value
/// whose `version` differs from [`REPO_TRUTH_HASH_VERSION`] is *stale format*,
/// not evidence that repo truth changed, and the correct response is to
/// recompute rather than to raise a truth-drift alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoTruthHash {
    /// Encoding version that produced `hash`.
    pub version: u32,
    /// The digest itself.
    pub hash: MerkleHash,
}

impl RepoTruthHash {
    /// Compute the current-version repo-truth hash for `snapshot`.
    pub fn compute(snapshot: &GraphSnapshot) -> Self {
        Self {
            version: REPO_TRUTH_HASH_VERSION,
            hash: compute_repo_truth_hash(snapshot),
        }
    }

    /// Whether this digest was produced by the current encoding.
    ///
    /// A `false` here means the stored value cannot be compared against a
    /// freshly computed one; recompute instead of reporting drift.
    pub fn is_current_version(&self) -> bool {
        self.version == REPO_TRUTH_HASH_VERSION
    }

    /// Whether two digests are comparable *and* equal.
    ///
    /// Digests from different encoding versions are never equal, even if the
    /// raw bytes were to collide.
    pub fn matches(&self, other: &Self) -> bool {
        self.version == other.version && self.hash == other.hash
    }
}

/// Compute a full repo-truth hash covering ALL first-class truth domains.
///
/// Unlike [`compute_graph_root_hash`] — which covers entity content and
/// outgoing-relation topology only, and remains the entity-integrity primitive
/// with unchanged semantics — this hash folds that root in and then adds the
/// canonical *content* of every other snapshot domain: the change DAG (ids,
/// parents, message, author, timestamp, and all entity/relation/artifact
/// deltas), work, reviews, tests, contracts, verification,
/// provenance, sessions, intents, files, and artifacts.
///
/// Use this for bootstrap acceptance, optimistic concurrency, and cache
/// validation — anywhere "has repo truth changed?" is the question. It is a
/// full-snapshot digest, O(total truth), so it belongs at acceptance and
/// validation checkpoints rather than in a per-operation polling loop.
///
/// Determinism guarantees:
/// - every domain is reduced to a sorted multiset of per-element digests, so
///   the result never depends on `HashMap` iteration order, on `Vec` order for
///   collections that are materialised from maps, or on insertion order;
/// - each element is hashed through a canonical JSON encoding with sorted
///   object keys, type tags, and length prefixes, so distinct field layouts
///   cannot collide by concatenation.
///
/// Deliberately *not* covered, because each is a derived index over data that
/// is already hashed in full and none of them has a canonical element order —
/// including them would produce spurious mismatches on an unchanged repo:
/// - `outgoing` / `incoming`: adjacency indexes over `relations`;
/// - `change_children`: inverse index over `changes[].parents`;
/// - `entity_revisions`: re-derived from `changes` whenever it is empty.
pub fn compute_repo_truth_hash(snapshot: &GraphSnapshot) -> MerkleHash {
    // Exhaustive destructuring is the coverage guard: adding a domain to
    // `GraphSnapshot` breaks this build until the new field is either hashed or
    // explicitly bound to `_` with a reason. A silently uncovered domain is the
    // exact failure this digest exists to prevent.
    let GraphSnapshot {
        version,
        entities,
        relations,
        // Adjacency indexes rebuilt from `relations` on load, with no canonical
        // element order of their own.
        outgoing: _,
        incoming: _,
        changes,
        // Inverse index over `changes[].parents`.
        change_children: _,
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
        // Re-derived from `changes` whenever it is empty, so a load can
        // legitimately populate it on an otherwise unchanged repo.
        entity_revisions: _,
        repository_authority,
        external_references,
        // A resolution of `changes` at one change, derived from data this
        // digest already hashes in full, and legitimately present on one
        // replica of a repository and absent on another without either being
        // wrong. Hashing it would report two identical repositories as
        // different the moment one of them wrote a section, which is the exact
        // spurious mismatch the four bindings above exist to avoid.
        materialized_graph: _,
    } = snapshot;

    let mut hasher = Sha256::new();
    hasher.update(REPO_TRUTH_DOMAIN);

    hash_domain_count(&mut hasher, "snapshot_version", *version as usize);

    // Fold in the dedicated entity/relation primitive so repo truth strictly
    // dominates the graph root, then cover entity and relation records in full:
    // the graph root intentionally omits fields such as span, role, lineage and
    // `created_in` that are still part of repo truth.
    hasher.update(compute_graph_root_hash(snapshot));

    hash_map_domain(&mut hasher, "entities", entities);
    hash_map_domain(&mut hasher, "relations", relations);
    hash_map_domain(&mut hasher, "external_references", external_references);

    hash_map_domain(&mut hasher, "changes", changes);
    hash_map_domain(&mut hasher, "work_items", work_items);
    hash_map_domain(&mut hasher, "annotations", annotations);
    hash_vec_domain(&mut hasher, "work_links", work_links);

    hash_map_domain(&mut hasher, "reviews", reviews);
    hash_map_domain(&mut hasher, "review_decisions", review_decisions);
    hash_vec_domain(&mut hasher, "review_notes", review_notes);
    hash_vec_domain(&mut hasher, "review_discussions", review_discussions);
    hash_map_domain(&mut hasher, "review_assignments", review_assignments);

    hash_map_domain(&mut hasher, "test_cases", test_cases);
    hash_map_domain(&mut hasher, "assertions", assertions);
    hash_map_domain(&mut hasher, "verification_runs", verification_runs);
    hash_vec_domain(&mut hasher, "mock_hints", mock_hints);
    hash_map_domain(&mut hasher, "contracts", contracts);

    hash_map_domain(&mut hasher, "actors", actors);
    hash_vec_domain(&mut hasher, "delegations", delegations);
    hash_vec_domain(&mut hasher, "approvals", approvals);
    hash_vec_domain(&mut hasher, "audit_events", audit_events);

    hash_vec_domain(&mut hasher, "shallow_files", shallow_files);
    hash_vec_domain(&mut hasher, "file_layouts", file_layouts);
    hash_vec_domain(&mut hasher, "artifacts_structured", structured_artifacts);
    hash_vec_domain(&mut hasher, "artifacts_opaque", opaque_artifacts);
    let resolved_artifacts: Vec<_> = resolved_tree.artifacts().cloned().collect();
    hash_vec_domain(&mut hasher, "resolved_tree", &resolved_artifacts);

    hash_map_domain(&mut hasher, "sessions", sessions);
    hash_map_domain(&mut hasher, "intents", intents);
    hash_vec_domain(&mut hasher, "downstream_warnings", downstream_warnings);
    if let Some(repository_authority) = repository_authority {
        hash_domain_elements(
            &mut hasher,
            "repository_authority",
            std::slice::from_ref(repository_authority),
        );
    } else {
        hash_domain_count(&mut hasher, "repository_authority", 0);
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Write a domain tag and a cardinality. The tag is length-prefixed so no two
/// domain-name/count pairs can produce the same byte run by concatenation.
fn hash_domain_count(hasher: &mut Sha256, domain: &str, count: usize) {
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((count as u64).to_le_bytes());
}

/// Fold a keyed domain in. Each `(key, value)` pair is hashed as a unit, so the
/// key-to-value binding is covered, and the pair digests are sorted so the
/// result is independent of map iteration order.
fn hash_map_domain<K, V>(hasher: &mut Sha256, domain: &str, map: &HashMap<K, V>)
where
    K: serde::Serialize + Sync,
    V: serde::Serialize + Sync,
{
    let entries: Vec<(&K, &V)> = map.iter().collect();
    hash_domain_elements(hasher, domain, &entries);
}

/// Fold an unkeyed domain in.
///
/// Element digests are sorted rather than hashed in slice order: several of
/// these vectors are materialised from maps (`shallow_files`, `file_layouts`,
/// `structured_artifacts`, `opaque_artifacts`, `review_notes`,
/// `review_discussions` are all built with `into_values()`), so their slice
/// order is not stable across processes. Sorting trades detection of a pure
/// reordering — which is not repo truth for these domains — for a digest that
/// is stable everywhere.
fn hash_vec_domain<T>(hasher: &mut Sha256, domain: &str, items: &[T])
where
    T: serde::Serialize + Sync,
{
    hash_domain_elements(hasher, domain, items);
}

fn hash_domain_elements<T>(hasher: &mut Sha256, domain: &str, elements: &[T])
where
    T: serde::Serialize + Sync,
{
    let mut element_hashes: Vec<MerkleHash> = elements
        .par_iter()
        .map(|element| canonical_element_hash(domain, element))
        .collect();
    element_hashes.sort_unstable();

    hash_domain_count(hasher, domain, element_hashes.len());
    for element_hash in &element_hashes {
        hasher.update(element_hash);
    }
}

/// Canonical content digest for one element of a truth domain.
///
/// The element is projected to a `serde_json::Value` and hashed through
/// [`hash_canonical_json`], which sorts object keys and length-prefixes every
/// scalar. That covers every serialised field without a hand-maintained field
/// list, so a domain type gaining a field cannot silently fall out of coverage.
fn canonical_element_hash<T>(domain: &str, element: &T) -> MerkleHash
where
    T: serde::Serialize + ?Sized,
{
    let mut hasher = Sha256::new();
    hasher.update(b"kin-truth-element-v1:");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());

    match serde_json::to_value(element) {
        Ok(value) => {
            hasher.update([JSON_TAG_OK]);
            hash_canonical_json(&mut hasher, &value);
        }
        Err(err) => {
            // An element that cannot be projected must still perturb the digest
            // deterministically rather than be silently skipped. No domain type
            // currently reaches this branch; the
            // `repo_truth_elements_project_to_canonical_json` test guards that.
            hasher.update([JSON_TAG_UNENCODABLE]);
            let message = err.to_string();
            hasher.update((message.len() as u64).to_le_bytes());
            hasher.update(message.as_bytes());
        }
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

const JSON_TAG_NULL: u8 = 0;
const JSON_TAG_BOOL: u8 = 1;
const JSON_TAG_NUMBER: u8 = 2;
const JSON_TAG_STRING: u8 = 3;
const JSON_TAG_ARRAY: u8 = 4;
const JSON_TAG_OBJECT: u8 = 5;
const JSON_TAG_OK: u8 = 0xC0;
const JSON_TAG_UNENCODABLE: u8 = 0xEE;

/// Hash a JSON value canonically.
///
/// Every node is prefixed with a type tag and every variable-length payload
/// with its byte length, so no two structurally different values can produce
/// the same byte stream by concatenation. Object keys are sorted, which is what
/// makes a `HashMap`-backed field (entity metadata, for one) hash identically
/// across processes.
fn hash_canonical_json(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => hasher.update([JSON_TAG_NULL]),
        serde_json::Value::Bool(b) => {
            hasher.update([JSON_TAG_BOOL]);
            hasher.update([u8::from(*b)]);
        }
        serde_json::Value::Number(n) => {
            // `Number`'s textual form is the only representation shared by all
            // three internal variants (u64/i64/f64); ryu/itoa make it stable
            // across platforms.
            hasher.update([JSON_TAG_NUMBER]);
            let text = n.to_string();
            hasher.update((text.len() as u64).to_le_bytes());
            hasher.update(text.as_bytes());
        }
        serde_json::Value::String(s) => {
            hasher.update([JSON_TAG_STRING]);
            hasher.update((s.len() as u64).to_le_bytes());
            hasher.update(s.as_bytes());
        }
        serde_json::Value::Array(items) => {
            hasher.update([JSON_TAG_ARRAY]);
            hasher.update((items.len() as u64).to_le_bytes());
            for item in items {
                hash_canonical_json(hasher, item);
            }
        }
        serde_json::Value::Object(map) => {
            hasher.update([JSON_TAG_OBJECT]);
            hasher.update((map.len() as u64).to_le_bytes());
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            for key in keys {
                hasher.update((key.len() as u64).to_le_bytes());
                hasher.update(key.as_bytes());
                match map.get(key) {
                    Some(child) => hash_canonical_json(hasher, child),
                    None => hasher.update([JSON_TAG_NULL]),
                }
            }
        }
    }
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
    use rand::{rngs::StdRng, RngExt, SeedableRng};

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
            evidence: Vec::new(),
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
    fn graph_root_hash_is_independent_of_adjacency_order_with_branching_cycle() {
        // e1 points to BOTH members of a cycle (e2 <-> e3). The DFS discovery
        // order of e2 vs e3 — and therefore which edge becomes the ZERO_HASH
        // back-edge — must depend only on graph content, never on e1's
        // adjacency (outgoing edge) order. Fixed ids make the fixture
        // order-sensitive deterministically.
        let mut e1 = test_entity("alpha");
        let mut e2 = test_entity("beta");
        let mut e3 = test_entity("gamma");
        e1.id = EntityId(uuid::Uuid::from_u128(1));
        e2.id = EntityId(uuid::Uuid::from_u128(2));
        e3.id = EntityId(uuid::Uuid::from_u128(3));

        let r_a = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r_b = test_relation(e1.id, e3.id, RelationKind::Calls);
        let r_c = test_relation(e2.id, e3.id, RelationKind::Calls);
        let r_d = test_relation(e3.id, e2.id, RelationKind::Calls);

        let ents = vec![e1, e2, e3];
        // snap1 discovers e1's out-edges as [e2, e3]; snap2 as [e3, e2].
        let snap1 = build_snapshot(
            ents.clone(),
            vec![r_a.clone(), r_b.clone(), r_c.clone(), r_d.clone()],
        );
        let snap2 = build_snapshot(ents, vec![r_b, r_a, r_c, r_d]);

        assert_eq!(
            compute_graph_root_hash(&snap1),
            compute_graph_root_hash(&snap2),
            "graph root must not depend on adjacency (outgoing edge) order"
        );
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

    #[test]
    fn merkle_cache_incremental_root_matches_full_recompute_across_random_mutations() {
        let mut rng = StdRng::seed_from_u64(0xF1955);
        let mut entities: Vec<Entity> = (0..12)
            .map(|index| {
                let mut entity = test_entity(&format!("entity_{index}"));
                entity.id = EntityId(uuid::Uuid::from_u128(index as u128 + 1));
                entity
            })
            .collect();
        let mut relations = Vec::new();

        // Include cycles up front so the incremental path must terminate and
        // preserve the same ZERO_HASH back-edge semantics as the cold path.
        for (src_index, dst_index) in [(0usize, 1usize), (1, 2), (2, 0), (3, 4), (4, 3)] {
            relations.push(test_relation(
                entities[src_index].id,
                entities[dst_index].id,
                RelationKind::Calls,
            ));
        }
        for _ in 0..18 {
            let src_index = rng.random_range(0..entities.len());
            let dst_index = rng.random_range(0..entities.len());
            if src_index != dst_index {
                relations.push(test_relation(
                    entities[src_index].id,
                    entities[dst_index].id,
                    RelationKind::References,
                ));
            }
        }

        let mut snapshot = build_snapshot(entities.clone(), relations.clone());
        let mut cache = MerkleCache::from_snapshot(&snapshot);
        assert_eq!(cache.root_hash(), compute_graph_root_hash(&snapshot));

        for step in 0..80 {
            let mut seeds = Vec::new();
            let op = match rng.random_range(0..4) {
                0 if !entities.is_empty() => {
                    let index = rng.random_range(0..entities.len());
                    entities[index].name = format!("entity_{index}_mutated_{step}");
                    entities[index].signature = format!("fn entity_{index}_mutated_{step}()");
                    seeds.push(entities[index].id);
                    format!("mutate entity index {index}")
                }
                1 if entities.len() > 3 => {
                    let index = rng.random_range(0..entities.len());
                    let removed = entities.remove(index);
                    for relation in &relations {
                        if relation.src.as_entity() == Some(removed.id)
                            || relation.dst.as_entity() == Some(removed.id)
                        {
                            if let Some(src) = relation.src.as_entity() {
                                seeds.push(src);
                            }
                        }
                    }
                    relations.retain(|relation| {
                        relation.src.as_entity() != Some(removed.id)
                            && relation.dst.as_entity() != Some(removed.id)
                    });
                    seeds.push(removed.id);
                    format!("delete entity index {index}")
                }
                2 if entities.len() > 1 => {
                    let src_index = rng.random_range(0..entities.len());
                    let mut dst_index = rng.random_range(0..entities.len());
                    if src_index == dst_index {
                        dst_index = (dst_index + 1) % entities.len();
                    }
                    let relation = test_relation(
                        entities[src_index].id,
                        entities[dst_index].id,
                        if step % 2 == 0 {
                            RelationKind::Calls
                        } else {
                            RelationKind::Imports
                        },
                    );
                    seeds.push(entities[src_index].id);
                    relations.push(relation);
                    format!("add relation {src_index}->{dst_index}")
                }
                _ if !relations.is_empty() => {
                    let index = rng.random_range(0..relations.len());
                    let relation = relations.remove(index);
                    seeds.extend(relation.src.as_entity());
                    seeds.extend(relation.dst.as_entity());
                    format!("remove relation index {index}")
                }
                _ => "noop".to_string(),
            };

            snapshot = build_snapshot(entities.clone(), relations.clone());
            cache.refresh_affected(&snapshot, seeds);
            assert_eq!(
                cache.root_hash(),
                compute_graph_root_hash(&snapshot),
                "incremental root diverged from cold recompute at step {step}: {op}"
            );
        }
    }

    /// Build a sizeable graph with a forward chain plus periodic back-edges, so
    /// it has many overlapping cycles — the case where the parallel batch build
    /// and the frozen cold path must still agree bit-for-bit.
    fn large_cyclic_snapshot(n: u128) -> (Vec<Entity>, GraphSnapshot) {
        let entities: Vec<Entity> = (0..n)
            .map(|i| {
                let mut entity = test_entity(&format!("entity_{i}"));
                entity.id = EntityId(uuid::Uuid::from_u128(i + 1));
                entity
            })
            .collect();
        let mut relations = Vec::new();
        for window in entities.windows(2) {
            relations.push(test_relation(
                window[0].id,
                window[1].id,
                RelationKind::Calls,
            ));
        }
        for i in (0..n as usize).step_by(7) {
            let dst = i / 2;
            if dst < i {
                relations.push(test_relation(
                    entities[i].id,
                    entities[dst].id,
                    RelationKind::References,
                ));
            }
        }
        let snapshot = build_snapshot(entities.clone(), relations);
        (entities, snapshot)
    }

    #[test]
    fn from_source_is_deterministic_and_matches_cold_on_large_graph() {
        let (_entities, snapshot) = large_cyclic_snapshot(4_000);
        let cold = compute_graph_root_hash(&snapshot);

        // The per-entity hashing in from_source runs across the rayon pool; the
        // root must not depend on completion order.
        let build1 = MerkleCache::from_source(&snapshot);
        let build2 = MerkleCache::from_source(&snapshot);

        assert_eq!(
            build1.root_hash(),
            cold,
            "parallel batch build must equal the frozen cold root"
        );
        assert_eq!(build2.root_hash(), cold);
        assert_eq!(
            build1.root_hash(),
            build2.root_hash(),
            "batch build must be deterministic across runs"
        );
    }

    #[test]
    fn refresh_affected_bulk_then_incremental_match_cold_on_large_graph() {
        let (mut entities, mut snapshot) = large_cyclic_snapshot(2_000);
        let mut cache = MerkleCache::from_snapshot(&snapshot);
        assert_eq!(cache.root_hash(), compute_graph_root_hash(&snapshot));

        // Mutate nearly every entity and refresh with a bulk seed set: this
        // exercises the seeds-dominate fast path (a single batch rebuild) and
        // must still reconcile to the frozen cold root.
        for entity in entities.iter_mut() {
            entity.signature = format!("{}::v2", entity.signature);
        }
        let relations: Vec<Relation> = snapshot.relations.values().cloned().collect();
        let seeds: Vec<EntityId> = entities.iter().map(|entity| entity.id).collect();
        snapshot = build_snapshot(entities.clone(), relations.clone());
        cache.refresh_affected(&snapshot, seeds);
        assert_eq!(
            cache.root_hash(),
            compute_graph_root_hash(&snapshot),
            "bulk refresh diverged from cold recompute"
        );

        // A subsequent small mutation must still reconcile to cold via the
        // incremental component path.
        entities[1].name = "renamed_entity".to_string();
        snapshot = build_snapshot(entities.clone(), relations);
        cache.refresh_affected(&snapshot, std::iter::once(entities[1].id));
        assert_eq!(
            cache.root_hash(),
            compute_graph_root_hash(&snapshot),
            "incremental refresh after bulk diverged from cold recompute"
        );
    }

    // ---------------------------------------------------------------
    // Repo truth hash tests
    // ---------------------------------------------------------------

    fn fixed_timestamp(seconds: i64) -> Timestamp {
        Timestamp(
            chrono::DateTime::from_timestamp(seconds, 0).expect("timestamp within supported range"),
        )
    }

    fn test_change(id_byte: u8, message: &str, entity_deltas: Vec<EntityDelta>) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([id_byte; 32])),
            parents: Vec::new(),
            timestamp: fixed_timestamp(1_700_000_000),
            author: AuthorId("tester".to_string()),
            message: message.to_string(),
            entity_deltas,
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        change.id =
            kin_model::compute_semantic_change_id(&change).expect("valid semantic change fixture");
        change
    }

    fn reseal_change(change: &mut SemanticChange) {
        change.id =
            kin_model::compute_semantic_change_id(change).expect("valid semantic change fixture");
    }

    fn snapshot_with_changes(changes: Vec<SemanticChange>) -> GraphSnapshot {
        let mut snapshot = GraphSnapshot::empty();
        for change in changes {
            snapshot.changes.insert(change.id, change);
        }
        snapshot
    }

    /// The regression this primitive was blind to: identical head snapshot,
    /// Identical change count, but the history disagrees about what the change
    /// actually did. Full-payload change identity and the repo-truth digest must
    /// both change.
    #[test]
    fn repo_truth_hash_detects_rewritten_entity_delta() {
        let original = test_entity("resolver_target");
        let mut rewritten = original.clone();
        rewritten.signature = "fn resolver_target(shadowed: bool)".to_string();

        let before = snapshot_with_changes(vec![test_change(
            0x11,
            "add resolver target",
            vec![EntityDelta::Added { new: original }],
        )]);
        let after = snapshot_with_changes(vec![test_change(
            0x11,
            "add resolver target",
            vec![EntityDelta::Added { new: rewritten }],
        )]);

        assert_eq!(
            before.changes.len(),
            after.changes.len(),
            "the two histories must have equal cardinality for this test to mean anything"
        );
        assert_ne!(
            before.changes.keys().next(),
            after.changes.keys().next(),
            "rewritten payloads must mint different semantic change ids"
        );
        assert_eq!(
            compute_graph_root_hash(&before),
            compute_graph_root_hash(&after),
            "the head snapshot is identical; only history disagrees"
        );
        assert_ne!(
            compute_repo_truth_hash(&before),
            compute_repo_truth_hash(&after),
            "a rewritten entity delta must change the repo truth hash"
        );
    }

    #[test]
    fn repo_truth_hash_detects_rewritten_change_parents() {
        let mut before_change = test_change(0x21, "commit", Vec::new());
        let mut after_change = before_change.clone();
        before_change.parents = vec![SemanticChangeId::from_hash(Hash256::from_bytes([0xA0; 32]))];
        after_change.parents = vec![SemanticChangeId::from_hash(Hash256::from_bytes([0xB0; 32]))];
        reseal_change(&mut before_change);
        reseal_change(&mut after_change);

        assert_ne!(
            compute_repo_truth_hash(&snapshot_with_changes(vec![before_change])),
            compute_repo_truth_hash(&snapshot_with_changes(vec![after_change])),
            "a rewritten parent edge must change the repo truth hash"
        );
    }

    #[test]
    fn repo_truth_hash_detects_rewritten_change_message() {
        assert_ne!(
            compute_repo_truth_hash(&snapshot_with_changes(vec![test_change(
                0x31,
                "original message",
                Vec::new()
            )])),
            compute_repo_truth_hash(&snapshot_with_changes(vec![test_change(
                0x31,
                "rewritten message",
                Vec::new()
            )])),
            "a rewritten commit message must change the repo truth hash"
        );
    }

    #[test]
    fn repo_truth_hash_is_independent_of_change_insertion_order() {
        let changes = vec![
            test_change(
                0x41,
                "first",
                vec![EntityDelta::Added {
                    new: test_entity("a"),
                }],
            ),
            test_change(
                0x42,
                "second",
                vec![EntityDelta::Added {
                    new: test_entity("b"),
                }],
            ),
            test_change(
                0x43,
                "third",
                vec![EntityDelta::Added {
                    new: test_entity("c"),
                }],
            ),
        ];
        let mut reversed = changes.clone();
        reversed.reverse();

        assert_eq!(
            compute_repo_truth_hash(&snapshot_with_changes(changes)),
            compute_repo_truth_hash(&snapshot_with_changes(reversed)),
            "insertion order must not affect the repo truth hash"
        );
    }

    #[test]
    fn repo_truth_hash_changes_when_a_change_is_added_or_removed() {
        let base = vec![test_change(0x51, "first", Vec::new())];
        let mut extended = base.clone();
        extended.push(test_change(0x52, "second", Vec::new()));

        let base_hash = compute_repo_truth_hash(&snapshot_with_changes(base.clone()));
        let extended_hash = compute_repo_truth_hash(&snapshot_with_changes(extended.clone()));
        assert_ne!(
            base_hash, extended_hash,
            "adding a change must change the repo truth hash"
        );

        let mut shortened = extended;
        shortened.pop();
        assert_eq!(
            compute_repo_truth_hash(&snapshot_with_changes(shortened)),
            base_hash,
            "removing the added change must restore the original hash"
        );
    }

    #[test]
    fn repo_truth_hash_is_stable_across_repeated_computation() {
        let entity_a = test_entity("stable_a");
        let entity_b = test_entity("stable_b");
        let relation = test_relation(entity_a.id, entity_b.id, RelationKind::Calls);
        let mut snapshot = build_snapshot(
            vec![entity_a.clone(), entity_b.clone()],
            vec![relation.clone()],
        );
        for change in [
            test_change(0x61, "one", vec![EntityDelta::Added { new: entity_a }]),
            test_change(0x62, "two", vec![EntityDelta::Added { new: entity_b }]),
        ] {
            snapshot.changes.insert(change.id, change);
        }

        let first = compute_repo_truth_hash(&snapshot);
        for _ in 0..8 {
            assert_eq!(
                first,
                compute_repo_truth_hash(&snapshot),
                "repeated computation over one snapshot must be bit-identical"
            );
        }
        assert_ne!(first, ZERO_HASH);
    }

    /// Entity metadata is a `HashMap`, so a digest that walked it in native
    /// order would drift between processes. The canonical encoding sorts keys.
    #[test]
    fn repo_truth_hash_is_independent_of_metadata_insertion_order() {
        let mut forward = test_entity("meta_order");
        for key in ["alpha", "beta", "gamma", "delta"] {
            forward
                .metadata
                .extra
                .insert(key.to_string(), serde_json::json!(key));
        }
        let mut reverse = test_entity("meta_order");
        reverse.id = forward.id;
        for key in ["delta", "gamma", "beta", "alpha"] {
            reverse
                .metadata
                .extra
                .insert(key.to_string(), serde_json::json!(key));
        }

        assert_eq!(
            compute_repo_truth_hash(&snapshot_with_changes(vec![test_change(
                0x71,
                "meta",
                vec![EntityDelta::Added { new: forward }]
            )])),
            compute_repo_truth_hash(&snapshot_with_changes(vec![test_change(
                0x71,
                "meta",
                vec![EntityDelta::Added { new: reverse }]
            )])),
            "metadata key insertion order must not affect the repo truth hash"
        );
    }

    /// Fields the graph root deliberately omits are still repo truth.
    #[test]
    fn repo_truth_hash_covers_entity_fields_outside_the_graph_root() {
        let entity = test_entity("provenance_carrier");
        let mut with_origin = entity.clone();
        with_origin.created_in = Some(SemanticChangeId::from_hash(Hash256::from_bytes([0xC1; 32])));

        let before = build_snapshot(vec![entity], Vec::new());
        let after = build_snapshot(vec![with_origin], Vec::new());

        assert_eq!(
            compute_graph_root_hash(&before),
            compute_graph_root_hash(&after),
            "graph root semantics are unchanged: it does not cover created_in"
        );
        assert_ne!(
            compute_repo_truth_hash(&before),
            compute_repo_truth_hash(&after),
            "repo truth must cover entity provenance the graph root omits"
        );
    }

    #[test]
    fn repo_truth_hash_is_version_tagged() {
        let snapshot = snapshot_with_changes(vec![test_change(0x81, "tagged", Vec::new())]);
        let tagged = RepoTruthHash::compute(&snapshot);

        assert_eq!(tagged.version, REPO_TRUTH_HASH_VERSION);
        assert_eq!(tagged.hash, compute_repo_truth_hash(&snapshot));
        assert!(tagged.is_current_version());
        assert!(tagged.matches(&RepoTruthHash::compute(&snapshot)));

        let stale = RepoTruthHash {
            version: REPO_TRUTH_HASH_VERSION - 1,
            hash: tagged.hash,
        };
        assert!(!stale.is_current_version());
        assert!(
            !tagged.matches(&stale),
            "same bytes from a different encoding version must not compare equal"
        );

        let round_tripped: RepoTruthHash =
            serde_json::from_str(&serde_json::to_string(&tagged).unwrap()).unwrap();
        assert_eq!(round_tripped, tagged);
    }

    #[test]
    fn repo_truth_hash_covers_tree_mode_and_symlink_kind() {
        let hash = Hash256::from_bytes([0x5a; 32]);
        let mut regular = GraphSnapshot::empty();
        regular.admit_artifact_for_test("tool".to_string(), TreeEntry::blob(hash, false));
        let regular_root = compute_repo_truth_hash(&regular);

        let mut executable = regular.clone();
        executable.admit_artifact_for_test("tool".to_string(), TreeEntry::blob(hash, true));
        let executable_root = compute_repo_truth_hash(&executable);

        let mut symlink = regular.clone();
        symlink.admit_artifact_for_test("tool".to_string(), TreeEntry::symlink(hash));
        let symlink_root = compute_repo_truth_hash(&symlink);

        assert_ne!(regular_root, executable_root);
        assert_ne!(regular_root, symlink_root);
        assert_ne!(executable_root, symlink_root);
    }

    #[test]
    fn repo_truth_hash_covers_artifact_identity_path_and_gitlink_target() {
        let artifact_id = ArtifactId::new();
        let other_id = ArtifactId::new();
        let path = RepoPath::from_utf8("vendor/dependency").unwrap();
        let moved_path = RepoPath::from_utf8("third_party/dependency").unwrap();
        let target = GitObjectId::sha1([1; 20]);
        let other_target = GitObjectId::sha1([2; 20]);

        let snapshot = |id, path: RepoPath, target| {
            let mut snapshot = GraphSnapshot::empty();
            snapshot.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
                id,
                path,
                TreeEntry::gitlink(target),
            )])
            .unwrap();
            snapshot
        };
        let baseline = compute_repo_truth_hash(&snapshot(artifact_id, path.clone(), target));
        let identity_changed = compute_repo_truth_hash(&snapshot(other_id, path.clone(), target));
        let path_changed = compute_repo_truth_hash(&snapshot(artifact_id, moved_path, target));
        let target_changed = compute_repo_truth_hash(&snapshot(artifact_id, path, other_target));

        assert_ne!(baseline, identity_changed);
        assert_ne!(baseline, path_changed);
        assert_ne!(baseline, target_changed);
    }

    #[test]
    fn repo_truth_hash_is_independent_of_resolved_tree_insertion_order() {
        let left = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("a").unwrap(),
            crate::types::regular_tree_entry(1),
        );
        let right = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("b").unwrap(),
            crate::types::regular_tree_entry(2),
        );
        let mut first = GraphSnapshot::empty();
        first.resolved_tree = ResolvedTree::from_artifacts([left.clone(), right.clone()]).unwrap();
        let mut second = GraphSnapshot::empty();
        second.resolved_tree = ResolvedTree::from_artifacts([right, left]).unwrap();

        assert_eq!(
            compute_repo_truth_hash(&first),
            compute_repo_truth_hash(&second)
        );
    }

    #[test]
    fn retrieval_authority_changes_when_exact_tree_or_artifact_facets_change() {
        let empty = GraphSnapshot::empty();
        let mut tree_only = GraphSnapshot::empty();
        let artifact_id = ArtifactId::new();
        tree_only.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            RepoPath::from_utf8("compose.yaml").unwrap(),
            crate::types::regular_tree_entry(1),
        )])
        .unwrap();

        assert_eq!(
            compute_graph_root_hash(&empty),
            compute_graph_root_hash(&tree_only),
            "the entity/relation root deliberately does not cover exact tree truth"
        );
        assert_ne!(
            compute_retrieval_authority_hash(&empty),
            compute_retrieval_authority_hash(&tree_only),
            "retrieval sidecars must be invalidated by exact tree changes"
        );

        let mut with_facet = tree_only.clone();
        with_facet.structured_artifacts.push(StructuredArtifact {
            file_id: FilePathId::new("compose.yaml"),
            kind: ArtifactKind::ComposeFile,
            content_hash: Hash256::from_bytes([2; 32]),
            text_preview: Some("services:".into()),
        });
        assert_ne!(
            compute_retrieval_authority_hash(&tree_only),
            compute_retrieval_authority_hash(&with_facet),
            "artifact retrieval documents must participate in sidecar authority"
        );
    }

    #[test]
    fn retrieval_and_repo_truth_bind_external_reference_records() {
        let empty = GraphSnapshot::empty();
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let mut with_reference = GraphSnapshot::empty();
        with_reference
            .external_references
            .insert(reference.id, reference);

        assert_eq!(
            compute_graph_root_hash(&empty),
            compute_graph_root_hash(&with_reference),
            "the legacy entity/relation root deliberately omits unconnected records"
        );
        assert_ne!(
            compute_retrieval_authority_hash(&empty),
            compute_retrieval_authority_hash(&with_reference),
            "retrieval sidecars must bind immutable external coordinates"
        );
        assert_ne!(
            compute_repo_truth_hash(&empty),
            compute_repo_truth_hash(&with_reference),
            "repo truth must bind immutable external coordinates"
        );
    }

    #[test]
    fn owned_locate_and_live_retrieval_authorities_are_byte_equivalent() {
        let mut snapshot = GraphSnapshot::empty();
        let artifact_id = ArtifactId::new();
        snapshot.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            RepoPath::from_utf8("Dockerfile").unwrap(),
            crate::types::regular_tree_entry(3),
        )])
        .unwrap();
        snapshot.opaque_artifacts.push(OpaqueArtifact {
            file_id: FilePathId::new("Dockerfile"),
            content_hash: Hash256::from_bytes([3; 32]),
            mime_type: Some("text/plain".into()),
            text_preview: Some("FROM scratch".into()),
        });
        let entity = test_entity("container_entry");
        snapshot.entities.insert(entity.id, entity);
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        snapshot.external_references.insert(reference.id, reference);

        let graph_root_hash = compute_graph_root_hash(&snapshot);
        let owned = compute_retrieval_authority_hash(&snapshot);
        let locate = LocateGraphSnapshot::from(snapshot.clone());
        assert_eq!(
            owned,
            compute_locate_retrieval_authority_hash(&locate, graph_root_hash)
        );

        let entities = snapshot
            .entities
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let relations = snapshot
            .relations
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let changes = snapshot
            .changes
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let revisions = snapshot
            .entity_revisions
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let shallow = snapshot
            .shallow_files
            .iter()
            .map(|value| (value.file_id.clone(), value.clone()))
            .collect();
        let layouts = snapshot
            .file_layouts
            .iter()
            .map(|value| (value.file_id.clone(), value.clone()))
            .collect();
        let structured = snapshot
            .structured_artifacts
            .iter()
            .map(|value| (value.file_id.clone(), value.clone()))
            .collect();
        let opaque = snapshot
            .opaque_artifacts
            .iter()
            .map(|value| (value.file_id.clone(), value.clone()))
            .collect();
        let external_references = snapshot
            .external_references
            .iter()
            .map(|(id, reference)| (*id, reference.clone()))
            .collect();
        assert_eq!(
            owned,
            compute_live_retrieval_authority_hash(
                graph_root_hash,
                &entities,
                &relations,
                &changes,
                &revisions,
                &external_references,
                &snapshot.resolved_tree,
                &shallow,
                &layouts,
                &structured,
                &opaque,
            )
        );
    }

    fn map_elements_encode<K, V>(map: &HashMap<K, V>) -> bool
    where
        K: serde::Serialize,
        V: serde::Serialize,
    {
        // Mirrors `hash_map_domain`: the entry is projected as a `(key, value)`
        // tuple, never as a JSON map. Keyed domains such as `changes` are keyed
        // by `Hash256`-backed newtypes, which serialise as byte arrays and are
        // therefore rejected in JSON key position — projecting the map directly
        // would push every one of those domains onto the unencodable branch.
        map.iter()
            .all(|(key, value)| serde_json::to_value((key, value)).is_ok())
    }

    fn vec_elements_encode<T: serde::Serialize>(items: &[T]) -> bool {
        items.iter().all(|item| serde_json::to_value(item).is_ok())
    }

    fn resolved_tree_elements_encode(tree: &ResolvedTree) -> bool {
        tree.artifacts()
            .all(|artifact| serde_json::to_value(artifact).is_ok())
    }

    /// Guards the `JSON_TAG_UNENCODABLE` branch in [`canonical_element_hash`]:
    /// if a domain element ever stops projecting to JSON, its content silently
    /// degrades to an error-string digest instead of being covered. Fail here
    /// instead. Domains left empty by this fixture are checked vacuously; the
    /// populated ones are the ones with non-trivial key and value types.
    #[test]
    fn repo_truth_elements_project_to_canonical_json() {
        let entity = test_entity("encodable");
        let other = test_entity("encodable_other");
        let modified_old = test_entity("encodable_modified_old");
        let mut modified_new = modified_old.clone();
        modified_new.name = "encodable_modified_new".to_string();
        let relation = test_relation(entity.id, other.id, RelationKind::Calls);
        let mut snapshot =
            build_snapshot(vec![entity.clone(), other.clone()], vec![relation.clone()]);
        let change = test_change(
            0x91,
            "encodable change",
            vec![
                EntityDelta::Added {
                    new: entity.clone(),
                },
                EntityDelta::Modified {
                    old: modified_old,
                    new: modified_new,
                },
                EntityDelta::Removed { old: other.clone() },
            ],
        );
        snapshot.changes.insert(change.id, change);
        snapshot.admit_artifact_for_test(
            "src/main.rs".to_string(),
            crate::types::regular_tree_entry(7),
        );

        for (domain, encodes) in [
            ("entities", map_elements_encode(&snapshot.entities)),
            ("relations", map_elements_encode(&snapshot.relations)),
            ("changes", map_elements_encode(&snapshot.changes)),
            ("work_items", map_elements_encode(&snapshot.work_items)),
            ("annotations", map_elements_encode(&snapshot.annotations)),
            ("work_links", vec_elements_encode(&snapshot.work_links)),
            ("reviews", map_elements_encode(&snapshot.reviews)),
            (
                "review_decisions",
                map_elements_encode(&snapshot.review_decisions),
            ),
            ("review_notes", vec_elements_encode(&snapshot.review_notes)),
            (
                "review_discussions",
                vec_elements_encode(&snapshot.review_discussions),
            ),
            (
                "review_assignments",
                map_elements_encode(&snapshot.review_assignments),
            ),
            ("test_cases", map_elements_encode(&snapshot.test_cases)),
            ("assertions", map_elements_encode(&snapshot.assertions)),
            (
                "verification_runs",
                map_elements_encode(&snapshot.verification_runs),
            ),
            ("mock_hints", vec_elements_encode(&snapshot.mock_hints)),
            ("contracts", map_elements_encode(&snapshot.contracts)),
            ("actors", map_elements_encode(&snapshot.actors)),
            ("delegations", vec_elements_encode(&snapshot.delegations)),
            ("approvals", vec_elements_encode(&snapshot.approvals)),
            ("audit_events", vec_elements_encode(&snapshot.audit_events)),
            (
                "shallow_files",
                vec_elements_encode(&snapshot.shallow_files),
            ),
            ("file_layouts", vec_elements_encode(&snapshot.file_layouts)),
            (
                "artifacts_structured",
                vec_elements_encode(&snapshot.structured_artifacts),
            ),
            (
                "artifacts_opaque",
                vec_elements_encode(&snapshot.opaque_artifacts),
            ),
            (
                "resolved_tree",
                resolved_tree_elements_encode(&snapshot.resolved_tree),
            ),
            ("sessions", map_elements_encode(&snapshot.sessions)),
            ("intents", map_elements_encode(&snapshot.intents)),
            (
                "downstream_warnings",
                vec_elements_encode(&snapshot.downstream_warnings),
            ),
        ] {
            assert!(
                encodes,
                "domain '{domain}' must project to canonical JSON, otherwise its content \
                 silently drops out of the repo truth hash"
            );
        }

        assert_ne!(compute_repo_truth_hash(&snapshot), ZERO_HASH);
    }
}
