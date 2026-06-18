// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(feature = "embeddings", feature = "vector"))]
use std::sync::Arc;

#[cfg(feature = "embeddings")]
use crate::embed::CodeEmbedder;
use crate::error::KinDbError;
use crate::search::{
    opaque_artifact_fields, shallow_file_fields, structured_artifact_fields, TextIndex,
};
use crate::storage::format::LocateGraphSnapshot;
use crate::storage::merkle::{
    compute_graph_root_hash, compute_root_hash_generic, GraphHashSource, MerkleCache,
};
use crate::storage::{CollectionDelta, Generation, GraphSnapshot, GraphSnapshotDelta, VecDelta};
use crate::store::{
    ChangeStore, EntityStore, GraphStore, ProvenanceStore, ReviewStore, SessionStore,
    VerificationStore, WorkStore,
};
use crate::types::*;
#[cfg(feature = "vector")]
use crate::vector::VectorIndex;

use super::index::IndexSet;
use super::traverse;

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn default_embedding_batch_size() -> usize {
    std::env::var("KIN_EMBED_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|threads| (threads.get() * 16).clamp(64, 192))
                .unwrap_or(128)
        })
}

const TEXT_INDEX_IMPORT_SOURCE_WEIGHT: f32 = 1.4;
const TEXT_INDEX_NEIGHBOR_NAME_WEIGHT: f32 = 1.0;
#[cfg(all(feature = "embeddings", feature = "vector"))]
const MAX_EMBED_CONTEXT_VALUES_PER_LABEL: usize = 3;
const PHASE9_RELATION_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x6a5a6d56593e4f4fb6f6f2e1de3d4f99);

fn coverage_percent(indexed: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (indexed as f64 / total as f64) * 100.0
}

fn build_artifact_indexes_from_paths<I>(
    paths: I,
) -> (
    HashMap<FilePathId, ArtifactId>,
    HashMap<ArtifactId, FilePathId>,
)
where
    I: IntoIterator<Item = FilePathId>,
{
    let mut artifact_index = HashMap::new();
    let mut artifact_reverse = HashMap::new();
    for path in paths {
        let id = ArtifactId::seed_from_file_id(&path);
        artifact_index.entry(path.clone()).or_insert(id);
        artifact_reverse.entry(id).or_insert(path);
    }
    (artifact_index, artifact_reverse)
}

fn reverse_artifact_index(
    artifact_index: &HashMap<FilePathId, ArtifactId>,
) -> HashMap<ArtifactId, FilePathId> {
    let mut artifact_reverse = HashMap::new();
    for (path, id) in artifact_index {
        artifact_reverse.entry(*id).or_insert_with(|| path.clone());
    }
    artifact_reverse
}

fn topologically_order_changes<I>(changes: I) -> Vec<SemanticChange>
where
    I: IntoIterator<Item = (SemanticChangeId, SemanticChange)>,
{
    let changes: HashMap<SemanticChangeId, SemanticChange> = changes.into_iter().collect();

    let mut ids = changes.keys().copied().collect::<Vec<_>>();
    ids.sort_by_key(|id| id.to_string());

    let mut visited = HashSet::new();
    let mut ordered = Vec::with_capacity(ids.len());
    enum Frame {
        Visit(SemanticChangeId),
        Emit(SemanticChange),
    }
    for id in ids {
        let mut stack = vec![Frame::Visit(id)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Visit(change_id) => {
                    if !visited.insert(change_id) {
                        continue;
                    }
                    let Some(change) = changes.get(&change_id) else {
                        continue;
                    };
                    stack.push(Frame::Emit(change.clone()));
                    for parent in change.parents.iter().rev() {
                        stack.push(Frame::Visit(*parent));
                    }
                }
                Frame::Emit(change) => ordered.push(change),
            }
        }
    }
    ordered
}

fn entity_matches_revision(left: &Entity, right: &Entity) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.name == right.name
        && left.language == right.language
        && left.fingerprint.ast_hash == right.fingerprint.ast_hash
        && left.fingerprint.signature_hash == right.fingerprint.signature_hash
        && left.fingerprint.behavior_hash == right.fingerprint.behavior_hash
        && left.file_origin == right.file_origin
        && left.span == right.span
        && left.signature == right.signature
        && left.visibility == right.visibility
        && left.role == right.role
        && left.doc_summary == right.doc_summary
        && left.metadata.extra == right.metadata.extra
        && left.lineage_parent == right.lineage_parent
}

fn lookup_entity_revision_id(
    revisions: &HashMap<EntityId, Vec<EntityRevision>>,
    entity: &Entity,
) -> Option<EntityRevisionId> {
    revisions
        .get(&entity.id)
        .and_then(|entries| {
            entries
                .iter()
                .rev()
                .find(|revision| entity_matches_revision(&revision.entity, entity))
        })
        .map(|revision| revision.revision_id)
}

/// Whether `entity`'s content matches the most recent recorded revision for its
/// id. Re-importing unchanged content (re-init mints a fresh change id, so the
/// deltas arrive again) must not append a redundant revision generation — that
/// is what bloated the graph and the vector index across re-init cycles.
fn entity_unchanged_since_last_revision(ent: &EntityData, entity: &Entity) -> bool {
    ent.entity_revisions
        .get(&entity.id)
        .and_then(|revs| revs.last())
        .is_some_and(|last| entity_matches_revision(&last.entity, entity))
}

fn append_entity_revisions(ent: &mut EntityData, change: &SemanticChange) {
    for delta in &change.entity_deltas {
        match delta {
            EntityDelta::Added(entity) => {
                if entity_unchanged_since_last_revision(ent, entity) {
                    continue;
                }
                ent.entity_revisions
                    .entry(entity.id)
                    .or_default()
                    .push(EntityRevision::new(entity.clone(), change.id, None));
            }
            EntityDelta::Modified { old, new } => {
                if entity_unchanged_since_last_revision(ent, new) {
                    continue;
                }
                let previous_revision = lookup_entity_revision_id(&ent.entity_revisions, old);
                ent.entity_revisions
                    .entry(new.id)
                    .or_default()
                    .push(EntityRevision::new(
                        new.clone(),
                        change.id,
                        previous_revision,
                    ));
            }
            EntityDelta::Removed(_) => {}
        }
    }
}

/// The most recent (HEAD) revision id of every entity's revision chain.
///
/// `append_entity_revisions` pushes each new generation to the end of the
/// chain, so `revs.last()` is the live revision. Superseded generations are
/// intentionally excluded: the vector index tracks at most one revision vector
/// per live entity. A superseded generation that a live re-embed leaves behind
/// is an orphan to reclaim — not retrieval truth that semantic search should
/// return as a second hit for the same entity. This is the single authority for
/// "which revision keys are current", shared by the prune target and the
/// embedding-queue backfill so the two never disagree (a disagreement would make
/// the backfill re-embed a key the prune immediately evicts, churning forever).
#[cfg(feature = "vector")]
fn latest_revision_ids(ent: &EntityData) -> impl Iterator<Item = EntityRevisionId> + '_ {
    ent.entity_revisions
        .values()
        .filter_map(|revs| revs.last().map(|rev| rev.revision_id))
}

fn entity_ids_for_relation(relation: &Relation) -> Vec<EntityId> {
    [relation.src.as_entity(), relation.dst.as_entity()]
        .into_iter()
        .flatten()
        .collect()
}

fn relation_is_entity_only(relation: &Relation) -> bool {
    relation.src.as_entity().is_some() && relation.dst.as_entity().is_some()
}

fn entity_neighbor_for_relation(relation: &Relation, entity_id: &EntityId) -> Option<EntityId> {
    let current = GraphNodeId::Entity(*entity_id);
    if relation.src == current {
        relation.dst.as_entity()
    } else if relation.dst == current {
        relation.src.as_entity()
    } else {
        None
    }
}

fn collect_entity_refresh_targets(ent: &EntityData, seed_ids: &[EntityId]) -> Vec<EntityId> {
    let mut targets = HashSet::new();

    for entity_id in seed_ids {
        if ent.entities.contains_key(entity_id) {
            targets.insert(*entity_id);
        }

        for relation_id in ent.outgoing.get(entity_id).into_iter().flatten() {
            let Some(relation) = ent.relations.get(relation_id) else {
                continue;
            };
            let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
                continue;
            };
            if ent.entities.contains_key(&neighbor_id) {
                targets.insert(neighbor_id);
            }
        }

        for relation_id in ent.incoming.get(entity_id).into_iter().flatten() {
            let Some(relation) = ent.relations.get(relation_id) else {
                continue;
            };
            let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
                continue;
            };
            if ent.entities.contains_key(&neighbor_id) {
                targets.insert(neighbor_id);
            }
        }
    }

    targets.into_iter().collect()
}

fn insert_relation_indexes(ent: &mut EntityData, relation: &Relation) {
    ent.node_outgoing
        .entry(relation.src)
        .or_default()
        .push(relation.id);
    ent.node_incoming
        .entry(relation.dst)
        .or_default()
        .push(relation.id);
    if let Some(src) = relation.src.as_entity() {
        ent.outgoing.entry(src).or_default().push(relation.id);
    }
    if let Some(dst) = relation.dst.as_entity() {
        ent.incoming.entry(dst).or_default().push(relation.id);
    }
}

fn remove_relation_indexes(ent: &mut EntityData, relation: &Relation) {
    if let Some(out) = ent.node_outgoing.get_mut(&relation.src) {
        out.retain(|rid| *rid != relation.id);
        if out.is_empty() {
            ent.node_outgoing.remove(&relation.src);
        }
    }
    if let Some(inc) = ent.node_incoming.get_mut(&relation.dst) {
        inc.retain(|rid| *rid != relation.id);
        if inc.is_empty() {
            ent.node_incoming.remove(&relation.dst);
        }
    }
    if let Some(src) = relation.src.as_entity() {
        if let Some(out) = ent.outgoing.get_mut(&src) {
            out.retain(|rid| *rid != relation.id);
            if out.is_empty() {
                ent.outgoing.remove(&src);
            }
        }
    }
    if let Some(dst) = relation.dst.as_entity() {
        if let Some(inc) = ent.incoming.get_mut(&dst) {
            inc.retain(|rid| *rid != relation.id);
            if inc.is_empty() {
                ent.incoming.remove(&dst);
            }
        }
    }
}

fn build_relation_indexes(
    relations: &HashMap<RelationId, Relation>,
) -> (
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
) {
    let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
    let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
    let mut node_outgoing: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();
    let mut node_incoming: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();

    for relation in relations.values() {
        node_outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        node_incoming
            .entry(relation.dst)
            .or_default()
            .push(relation.id);
        if let Some(src) = relation.src.as_entity() {
            outgoing.entry(src).or_default().push(relation.id);
        }
        if let Some(dst) = relation.dst.as_entity() {
            incoming.entry(dst).or_default().push(relation.id);
        }
    }

    (outgoing, incoming, node_outgoing, node_incoming)
}

/// Whether a snapshot load reused the persisted entity-level adjacency or had
/// to rebuild it from `relations` (FIR-853).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdjacencyReuse {
    /// The persisted `outgoing`/`incoming` maps were consistent with
    /// `relations` and were moved into the graph as-is (no rebuild).
    Reused,
    /// The persisted adjacency was missing or inconsistent, so the entity-level
    /// maps were rebuilt from `relations`.
    Rebuilt,
}

/// Build the relation adjacency indexes for a freshly loaded snapshot, reusing
/// the persisted entity-level `outgoing`/`incoming` maps when they are
/// consistent with `relations` (FIR-853).
///
/// The snapshot persists the entity-level adjacency (`outgoing`/`incoming`) but
/// historically `from_snapshot_inner` threw it away and rebuilt all four
/// adjacency maps from `relations` on every boot. This helper instead:
///
///   1. Always derives the node-level maps (`node_outgoing`/`node_incoming`)
///      from `relations` — those are keyed by `GraphNodeId` and are NOT
///      persisted, so they cannot be reused.
///   2. In that same single pass, tallies how many entity-keyed edges
///      `relations` implies.
///   3. If the persisted `outgoing`/`incoming` edge tallies match, the
///      persisted maps are trusted and moved in without reallocating or
///      re-hashing every entity key — the boot-time win. Otherwise (old
///      snapshot with no persisted adjacency, or an inconsistent one) the
///      entity-level maps are rebuilt from `relations` so a stale/missing
///      persisted adjacency can never yield an inconsistent in-memory graph.
///
/// Trust boundary: the snapshot body is SHA-256 checksum-verified before this
/// runs (see `GraphSnapshot::from_bytes`), and the writer maintains these maps
/// in lockstep with `relations`, so an edge-count match is a sound validity
/// signal — corruption is caught upstream and a writer that desynced the maps
/// would already have corrupted the live graph before saving.
pub(crate) fn build_relation_indexes_with_reuse(
    relations: &HashMap<RelationId, Relation>,
    persisted_outgoing: HashMap<EntityId, Vec<RelationId>>,
    persisted_incoming: HashMap<EntityId, Vec<RelationId>>,
) -> (
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
    AdjacencyReuse,
) {
    let mut node_outgoing: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();
    let mut node_incoming: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();
    let mut expected_outgoing_edges: usize = 0;
    let mut expected_incoming_edges: usize = 0;

    for relation in relations.values() {
        node_outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        node_incoming
            .entry(relation.dst)
            .or_default()
            .push(relation.id);
        if relation.src.as_entity().is_some() {
            expected_outgoing_edges += 1;
        }
        if relation.dst.as_entity().is_some() {
            expected_incoming_edges += 1;
        }
    }

    let persisted_outgoing_edges: usize = persisted_outgoing.values().map(Vec::len).sum();
    let persisted_incoming_edges: usize = persisted_incoming.values().map(Vec::len).sum();

    if persisted_outgoing_edges == expected_outgoing_edges
        && persisted_incoming_edges == expected_incoming_edges
    {
        // Persisted entity-level adjacency is consistent with the loaded
        // relations — reuse it directly instead of rebuilding.
        (
            persisted_outgoing,
            persisted_incoming,
            node_outgoing,
            node_incoming,
            AdjacencyReuse::Reused,
        )
    } else {
        // Stale / missing / inconsistent persisted adjacency — rebuild the
        // entity-level maps from relations so the in-memory graph is correct.
        let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        for relation in relations.values() {
            if let Some(src) = relation.src.as_entity() {
                outgoing.entry(src).or_default().push(relation.id);
            }
            if let Some(dst) = relation.dst.as_entity() {
                incoming.entry(dst).or_default().push(relation.id);
            }
        }
        (
            outgoing,
            incoming,
            node_outgoing,
            node_incoming,
            AdjacencyReuse::Rebuilt,
        )
    }
}

fn verification_relation_id(kind: RelationKind, src: GraphNodeId, dst: GraphNodeId) -> RelationId {
    let payload = format!("{kind:?}|{src}|{dst}");
    RelationId(uuid::Uuid::new_v5(
        &PHASE9_RELATION_NAMESPACE,
        payload.as_bytes(),
    ))
}

fn verification_relation(kind: RelationKind, src: GraphNodeId, dst: GraphNodeId) -> Relation {
    Relation {
        id: verification_relation_id(kind, src, dst),
        kind,
        src,
        dst,
        confidence: 1.0,
        origin: RelationOrigin::Inferred,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    }
}

fn migrate_legacy_verification_relations(snapshot: &mut GraphSnapshot) {
    let mut seen: HashSet<(RelationKind, GraphNodeId, GraphNodeId)> = snapshot
        .relations
        .values()
        .map(|relation| (relation.kind, relation.src, relation.dst))
        .collect();

    for (test_id, entity_id) in snapshot.test_covers_entity.drain(..) {
        let src = GraphNodeId::Test(test_id);
        let dst = GraphNodeId::Entity(entity_id);
        if seen.insert((RelationKind::Covers, src, dst)) {
            let relation = verification_relation(RelationKind::Covers, src, dst);
            snapshot.relations.insert(relation.id, relation);
        }
    }
    for (test_id, contract_id) in snapshot.test_covers_contract.drain(..) {
        let src = GraphNodeId::Test(test_id);
        let dst = GraphNodeId::Contract(contract_id);
        if seen.insert((RelationKind::Covers, src, dst)) {
            let relation = verification_relation(RelationKind::Covers, src, dst);
            snapshot.relations.insert(relation.id, relation);
        }
    }
    for (test_id, work_id) in snapshot.test_verifies_work.drain(..) {
        let src = GraphNodeId::Test(test_id);
        let dst = GraphNodeId::Work(work_id);
        if seen.insert((RelationKind::Covers, src, dst)) {
            let relation = verification_relation(RelationKind::Covers, src, dst);
            snapshot.relations.insert(relation.id, relation);
        }
    }
    for (run_id, entity_id) in snapshot.run_proves_entity.drain(..) {
        let src = GraphNodeId::VerificationRun(run_id);
        let dst = GraphNodeId::Entity(entity_id);
        if seen.insert((RelationKind::DerivedFrom, src, dst)) {
            let relation = verification_relation(RelationKind::DerivedFrom, src, dst);
            snapshot.relations.insert(relation.id, relation);
        }
    }
    for (run_id, work_id) in snapshot.run_proves_work.drain(..) {
        let src = GraphNodeId::VerificationRun(run_id);
        let dst = GraphNodeId::Work(work_id);
        if seen.insert((RelationKind::DerivedFrom, src, dst)) {
            let relation = verification_relation(RelationKind::DerivedFrom, src, dst);
            snapshot.relations.insert(relation.id, relation);
        }
    }
}

// ---------------------------------------------------------------------------
// Embedding status
// ---------------------------------------------------------------------------

/// Progress of the background embedding pipeline.
///
/// `pending` reports outstanding embedding work, defined as
/// `max(queue_length, total - indexed)`. `total` covers retrievable graph
/// objects that participate in semantic embedding: current entities,
/// historical entity revisions, and current artifacts. This deliberately covers
/// both queued-but-unembedded work and unindexed objects that have not yet been
/// queued (the latter is the steady state after loading a graph whose embedding
/// queues do not persist across restarts). Coverage gates that only inspect this
/// field stay correct without also reading `indexed` and `total`. Callers that
/// need the raw runtime queue length specifically should use
/// [`InMemoryGraph::pending_embeddings`] and
/// [`InMemoryGraph::pending_artifact_embeddings`] instead.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmbeddingStatus {
    /// Outstanding embedding work: `max(queue_length, total - indexed)`.
    pub pending: usize,
    /// Retrievable graph objects currently in the HNSW vector index.
    pub indexed: usize,
    /// Total retrievable graph objects that require embeddings.
    pub total: usize,
}

/// Graph-owned object resolved from a retrieval key.
#[derive(Debug, Clone)]
pub enum ResolvedRetrievalItem {
    Entity(Entity),
    ShallowFile(ShallowTrackedFile),
    StructuredArtifact(StructuredArtifact),
    OpaqueArtifact(OpaqueArtifact),
}

impl ResolvedRetrievalItem {
    pub fn file_path(&self) -> Option<FilePathId> {
        match self {
            Self::Entity(entity) => entity.file_origin.clone(),
            Self::ShallowFile(file) => Some(file.file_id.clone()),
            Self::StructuredArtifact(artifact) => Some(artifact.file_id.clone()),
            Self::OpaqueArtifact(artifact) => Some(artifact.file_id.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain sub-stores
// ---------------------------------------------------------------------------

/// Core entity/relation graph data.
#[derive(Clone)]
struct EntityData {
    entities: HashMap<EntityId, Entity>,
    entity_revisions: HashMap<EntityId, Vec<EntityRevision>>,
    relations: HashMap<RelationId, Relation>,
    /// Entity → outgoing relation IDs (entity's dependencies).
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    /// Entity → incoming relation IDs (entity's callers/dependents).
    incoming: HashMap<EntityId, Vec<RelationId>>,
    /// Mixed-node outgoing adjacency used by Phase 9 traversal.
    node_outgoing: HashMap<GraphNodeId, Vec<RelationId>>,
    /// Mixed-node incoming adjacency used by Phase 9 traversal.
    node_incoming: HashMap<GraphNodeId, Vec<RelationId>>,
    /// Secondary indexes for fast lookup.
    indexes: IndexSet,
    /// Incremental indexing: file path → SHA-256 content hash.
    file_hashes: HashMap<String, [u8; 32]>,
    /// Shallow file tracking (C2 tier).
    shallow_files: HashMap<FilePathId, ShallowTrackedFile>,
    /// Persisted file layouts for projection.
    file_layouts: HashMap<FilePathId, FileLayout>,
    /// Structured artifact tracking (C1 tier).
    structured_artifacts: HashMap<FilePathId, StructuredArtifact>,
    /// Opaque artifact tracking (C0 tier).
    opaque_artifacts: HashMap<FilePathId, OpaqueArtifact>,
    /// Forward: FilePathId → ArtifactId (O(1) lookup)
    artifact_index: HashMap<FilePathId, ArtifactId>,
    /// Reverse: ArtifactId → FilePathId (O(1) reverse lookup)
    artifact_reverse: HashMap<ArtifactId, FilePathId>,
}

impl GraphHashSource for EntityData {
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

/// Semantic change DAG + branches.
#[derive(Clone)]
struct ChangeData {
    changes: HashMap<SemanticChangeId, SemanticChange>,
    /// Parent → children in the change DAG.
    change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    branches: HashMap<BranchName, Branch>,
}

/// Work items, annotations, links.
#[derive(Clone)]
struct WorkData {
    work_items: HashMap<WorkId, WorkItem>,
    annotations: HashMap<AnnotationId, Annotation>,
    work_links: Vec<WorkLink>,
}

/// Reviews, decisions, notes, discussions, assignments.
#[derive(Clone)]
struct ReviewData {
    reviews: HashMap<ReviewId, Review>,
    review_decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    review_notes: HashMap<ReviewNoteId, ReviewNote>,
    review_discussions: HashMap<ReviewDiscussionId, ReviewDiscussion>,
    review_assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
}

/// Verification: tests, coverage, contracts.
#[derive(Clone)]
struct VerificationData {
    test_cases: HashMap<TestId, TestCase>,
    assertions: HashMap<AssertionId, Assertion>,
    verification_runs: HashMap<VerificationRunId, VerificationRun>,
    mock_hints: Vec<MockHint>,
    contracts: HashMap<ContractId, Contract>,
}

/// Provenance: actors, delegations, approvals, audit.
#[derive(Clone)]
struct ProvenanceData {
    actors: HashMap<ActorId, Actor>,
    delegations: Vec<Delegation>,
    approvals: Vec<Approval>,
    audit_events: Vec<AuditEvent>,
}

/// Session/intent state (daemon).
#[derive(Clone)]
struct SessionData {
    sessions: HashMap<SessionId, AgentSession>,
    intents: HashMap<IntentId, Intent>,
    downstream_warnings: Vec<(IntentId, EntityId, String)>,
}

#[derive(Debug)]
struct PendingGraphDelta {
    delta: GraphSnapshotDelta,
}

impl Default for PendingGraphDelta {
    fn default() -> Self {
        Self {
            delta: GraphSnapshotDelta::empty(0),
        }
    }
}

fn delta_map_upsert<K, V>(delta: &mut CollectionDelta<K, V>, key: K, value: V)
where
    K: Eq + Clone,
    V: Clone,
{
    delta.removed.retain(|removed| removed != &key);
    if let Some((_, existing)) = delta
        .added
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing = value;
        return;
    }
    if let Some((_, existing)) = delta
        .modified
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing = value;
        return;
    }
    delta.modified.push((key, value));
}

fn delta_map_remove<K, V>(delta: &mut CollectionDelta<K, V>, key: K)
where
    K: Eq + Clone,
{
    delta.added.retain(|(existing_key, _)| existing_key != &key);
    delta
        .modified
        .retain(|(existing_key, _)| existing_key != &key);
    if !delta.removed.iter().any(|removed| removed == &key) {
        delta.removed.push(key);
    }
}

fn delta_values_equal<V>(left: &V, right: &V) -> bool
where
    V: serde::Serialize,
{
    match (rmp_serde::to_vec(left), rmp_serde::to_vec(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn delta_vec_upsert_by_key<K, V, F>(delta: &mut VecDelta<V>, old: Option<V>, new: V, key_of: F)
where
    K: Eq,
    V: Clone + serde::Serialize,
    F: Fn(&V) -> K,
{
    let new_key = key_of(&new);
    delta.added.retain(|existing| key_of(existing) != new_key);

    let mut restored_base = false;
    delta.removed.retain(|removed| {
        if key_of(removed) != new_key {
            return true;
        }
        if delta_values_equal(removed, &new) {
            restored_base = true;
            false
        } else {
            true
        }
    });
    if restored_base {
        return;
    }

    if let Some(old) = old {
        if delta_values_equal(&old, &new) {
            return;
        }
        if !delta
            .removed
            .iter()
            .any(|removed| key_of(removed) == new_key)
        {
            delta.removed.push(old);
        }
    }
    delta.added.push(new);
}

fn delta_vec_remove_by_key<K, V, F>(delta: &mut VecDelta<V>, old: Option<V>, key: K, key_of: F)
where
    K: Eq,
    V: Clone,
    F: Fn(&V) -> K,
{
    let mut had_pending_add = false;
    delta.added.retain(|existing| {
        if key_of(existing) == key {
            had_pending_add = true;
            false
        } else {
            true
        }
    });
    if had_pending_add {
        return;
    }
    if let Some(old) = old {
        if !delta.removed.iter().any(|removed| key_of(removed) == key) {
            delta.removed.push(old);
        }
    }
}

fn record_edge_list_delta(pending: &mut PendingGraphDelta, ent: &EntityData, entity_id: EntityId) {
    match ent.outgoing.get(&entity_id).cloned() {
        Some(outgoing) => delta_map_upsert(&mut pending.delta.outgoing, entity_id, outgoing),
        None => delta_map_remove(&mut pending.delta.outgoing, entity_id),
    }
    match ent.incoming.get(&entity_id).cloned() {
        Some(incoming) => delta_map_upsert(&mut pending.delta.incoming, entity_id, incoming),
        None => delta_map_remove(&mut pending.delta.incoming, entity_id),
    }
}

fn record_relation_edge_delta(
    pending: &mut PendingGraphDelta,
    ent: &EntityData,
    relation: &Relation,
) {
    if let Some(src) = relation.src.as_entity() {
        record_edge_list_delta(pending, ent, src);
    }
    if let Some(dst) = relation.dst.as_entity() {
        record_edge_list_delta(pending, ent, dst);
    }
}

// ---------------------------------------------------------------------------
// Embedding queue — deterministic priority ordering
// ---------------------------------------------------------------------------

/// Recency class of a queued embedding item. Lower variants embed earlier.
///
/// `ChangedThisSync` covers entities/artifacts invalidated by a live graph
/// mutation (the incremental sync path: upsert/commit/relation edits).
/// `Backfill` covers bulk and "missing" re-queues (load-time backfill,
/// `queue_all_*`, `queue_missing_*`, manual bulk import). Declaration order is
/// the sort order, so a live change always outranks a backfill item.
///
/// The recency class is a deterministic property of *which producer enqueued
/// the item*, not of enqueue timing or map iteration order, so it never
/// reintroduces per-process nondeterminism into batch composition.
#[cfg(feature = "vector")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum EmbedRecency {
    /// Invalidated by a live graph mutation this sync — embed first.
    ChangedThisSync,
    /// Bulk / missing backfill — embed after changed-this-sync work.
    Backfill,
}

/// Deduplicating embedding work queue keyed by `K`.
///
/// Replaces the previous bare `HashSet<K>`: it still deduplicates (one embed
/// per key regardless of how many times it is enqueued) but additionally
/// records each key's [`EmbedRecency`] so the drain path can order work
/// deterministically by priority. The map's own iteration order is never
/// observed for batch composition — the drain always sorts by a total order —
/// so batch contents are identical across processes regardless of the
/// per-process HashMap seed.
#[cfg(feature = "vector")]
struct RecencyQueue<K: Eq + std::hash::Hash + Copy> {
    items: hashbrown::HashMap<K, EmbedRecency>,
}

#[cfg(feature = "vector")]
impl<K: Eq + std::hash::Hash + Copy> Default for RecencyQueue<K> {
    fn default() -> Self {
        Self {
            items: hashbrown::HashMap::new(),
        }
    }
}

#[cfg(feature = "vector")]
impl<K: Eq + std::hash::Hash + Copy> RecencyQueue<K> {
    /// Enqueue `key`, deduplicating. If the key is already queued, keep the
    /// higher-priority (lower) recency so a live change is never demoted to
    /// backfill by a subsequent bulk re-queue.
    fn insert(&mut self, key: K, recency: EmbedRecency) {
        self.items
            .entry(key)
            .and_modify(|cur| {
                if recency < *cur {
                    *cur = recency;
                }
            })
            .or_insert(recency);
    }

    /// Remove a key from the queue (e.g., when its entity is deleted).
    fn remove(&mut self, key: &K) -> bool {
        self.items.remove(key).is_some()
    }

    /// HashSet-style membership facade (used by tests; kept for parity with the
    /// previous queue type so call sites read identically).
    #[allow(dead_code)]
    fn contains(&self, key: &K) -> bool {
        self.items.contains_key(key)
    }

    #[allow(dead_code)]
    fn clear(&mut self) {
        self.items.clear();
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Remove and return every `(key, recency)` pair. Iteration order is
    /// unspecified; callers MUST sort deterministically before using the result.
    fn drain_all(&mut self) -> Vec<(K, EmbedRecency)> {
        self.items.drain().collect()
    }
}

// Embedding priority tiers. Lower tiers embed first, giving agents useful
// semantic coverage on the entities that matter (public API surface, then the
// rest of the live source) before historical revisions, tests, and generated
// code. The buckets are derived only from facts the graph already records
// (visibility / role / kind) — no new analysis pass.
#[cfg(feature = "vector")]
mod embed_tier {
    /// Public API contract surface (endpoints, interfaces, traits, schemas).
    pub const PUBLIC_API: u8 = 0;
    /// Other public source symbols.
    pub const PUBLIC_SOURCE: u8 = 1;
    /// Crate-visible source symbols.
    pub const CRATE_SOURCE: u8 = 2;
    /// Internal source symbols.
    pub const INTERNAL_SOURCE: u8 = 3;
    /// Private source symbols.
    pub const PRIVATE_SOURCE: u8 = 4;
    /// Historical (non-HEAD) entity revisions — embed after all live HEAD source.
    pub const REVISION: u8 = 5;
    /// Test code.
    pub const TEST: u8 = 6;
    /// Documentation entities.
    pub const DOCS: u8 = 7;
    /// Generated / vendored / external code and non-entity keys.
    pub const OTHER: u8 = 8;
}

/// Classify a HEAD entity into an [`embed_tier`] bucket from its visibility,
/// role, and kind. Public API surface ranks first; non-source roles last.
#[cfg(feature = "vector")]
fn entity_embed_tier(entity: &Entity) -> u8 {
    // Role dominates: non-source code always ranks after live source code.
    match entity.role {
        EntityRole::Test => return embed_tier::TEST,
        EntityRole::Docs => return embed_tier::DOCS,
        EntityRole::Generated | EntityRole::Vendored | EntityRole::External => {
            return embed_tier::OTHER
        }
        EntityRole::Source => {}
    }
    // A source-roled entity that is structurally a test still ranks as test.
    if matches!(entity.kind, EntityKind::Test) {
        return embed_tier::TEST;
    }
    let is_api_surface = matches!(
        entity.kind,
        EntityKind::ApiEndpoint
            | EntityKind::EventContract
            | EntityKind::Schema
            | EntityKind::Interface
            | EntityKind::TraitDef
    );
    match entity.visibility {
        Visibility::Public if is_api_surface => embed_tier::PUBLIC_API,
        Visibility::Public => embed_tier::PUBLIC_SOURCE,
        Visibility::Crate => embed_tier::CRATE_SOURCE,
        Visibility::Internal => embed_tier::INTERNAL_SOURCE,
        Visibility::Private => embed_tier::PRIVATE_SOURCE,
    }
}

/// Map an entity's incoming-relation degree (dependent/caller count, the cheap
/// centrality proxy the graph already maintains) to an ascending sort rank, so
/// that *higher* in-degree sorts *earlier*.
#[cfg(feature = "vector")]
fn embed_centrality_rank(in_degree: usize) -> u32 {
    u32::MAX - (in_degree.min(u32::MAX as usize) as u32)
}

/// Deterministic priority sort key for a queued embedding item. Sorts ascending
/// — the smallest key embeds first. Fields in precedence order:
/// 1. `tier` — semantic-importance bucket (public API ... generated; see [`embed_tier`])
/// 2. `recency` — changed-this-sync before bulk backfill
/// 3. `centrality_rank` — higher in-degree (more dependents) first
/// 4. `key` — `RetrievalKey` total order, the stable tiebreak on id
///
/// Because every field is a pure function of queue contents + current graph
/// state (and `key` is unique per queued item), the resulting order is a
/// deterministic total order — identical across processes regardless of how the
/// items were inserted.
#[cfg(feature = "vector")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EmbedSortKey {
    tier: u8,
    recency: EmbedRecency,
    centrality_rank: u32,
    key: RetrievalKey,
}

/// Compute the [`EmbedSortKey`] for a queued entity key against current graph
/// state. HEAD entities draw tier and centrality from their own graph facts;
/// historical revisions trail live HEAD source at a fixed revision tier;
/// artifact keys (not normally present in the entity queue) sort last.
///
/// PERF: this is O(1) per key — two `HashMap` point lookups (`entities` and
/// `incoming`) plus `Vec::len`, and a constant-time `entity_embed_tier` match.
/// No graph traversal happens here, so building keys for an init backfill of
/// 20K–50K entities is O(n) and the surrounding drain sort is O(n log n).
#[cfg(feature = "vector")]
fn embed_sort_key_for(ent: &EntityData, key: RetrievalKey, recency: EmbedRecency) -> EmbedSortKey {
    let (tier, centrality_rank) = match key {
        RetrievalKey::Entity(id) => {
            let tier = ent
                .entities
                .get(&id)
                .map(entity_embed_tier)
                .unwrap_or(embed_tier::OTHER);
            // In-degree (dependents) is a direct adjacency-list length lookup —
            // O(1), no edge walk.
            let in_degree = ent.incoming.get(&id).map(|rels| rels.len()).unwrap_or(0);
            (tier, embed_centrality_rank(in_degree))
        }
        RetrievalKey::EntityRevision(_) => (embed_tier::REVISION, embed_centrality_rank(0)),
        RetrievalKey::Artifact(_) | RetrievalKey::ArtifactRevision(_) => {
            (embed_tier::OTHER, embed_centrality_rank(0))
        }
    };
    EmbedSortKey {
        tier,
        recency,
        centrality_rank,
        key,
    }
}

// ---------------------------------------------------------------------------
// InMemoryGraph — sharded by domain
// ---------------------------------------------------------------------------

/// In-memory graph engine with O(1) entity/relation lookup and secondary indexes.
///
/// Data is sharded into domain-specific sub-stores, each behind its own
/// `RwLock`. This allows independent domains (e.g., session heartbeats vs
/// entity queries) to proceed without contending on the same lock.
///
/// **Lock ordering** (to prevent deadlocks when acquiring multiple locks):
/// entities → changes → work → reviews → verification → provenance → sessions
/// Deferred Merkle refresh state: dirty seeds accumulated since the last root
/// reconciliation. See [`InMemoryGraph::flush_merkle`].
#[derive(Default)]
struct PendingMerkle {
    dirty: bool,
    seeds: HashSet<EntityId>,
}

/// Counts how many times a deferred Merkle refresh actually ran. Used by tests
/// to prove that a burst of single-entity mutations collapses into one batch
/// reconciliation instead of one O(component) refresh per mutation.
#[cfg(test)]
static MERKLE_FLUSH_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub struct InMemoryGraph {
    /// Core entity/relation graph.
    entities: RwLock<EntityData>,
    /// Semantic change DAG + branches.
    changes: RwLock<ChangeData>,
    /// Work items, annotations, links.
    work: RwLock<WorkData>,
    /// Reviews, decisions, notes, discussions, assignments.
    reviews: RwLock<ReviewData>,
    /// Verification: tests, coverage, contracts.
    verification: RwLock<VerificationData>,
    /// Provenance: actors, delegations, approvals, audit.
    provenance: RwLock<ProvenanceData>,
    /// Session/intent state (already transient).
    sessions: RwLock<SessionData>,
    /// Optional full-text search index for ranked search queries.
    text_index: Option<TextIndex>,
    /// Merkle state for the entity/relation graph, reconciled lazily.
    merkle: parking_lot::RwLock<MerkleCache>,
    /// Deferred Merkle refresh state. Each mutation records its touched entities
    /// here; the root is reconciled against the live graph the next time it is
    /// read. The frozen subgraph hash makes a single refresh inherently
    /// O(component), so deferring keeps bulk ingestion to one batch Merkle build
    /// rather than one O(component) refresh per upsert.
    merkle_pending: parking_lot::Mutex<PendingMerkle>,
    /// Mutation-time delta journal for O(change) persistence flushes between commits.
    pending_delta: parking_lot::Mutex<PendingGraphDelta>,
    /// True when a mutation touched a domain not yet covered by the O(change) journal.
    full_snapshot_required: AtomicBool,
    /// True when the text index has uncommitted writes (upsert/remove without commit).
    text_dirty: AtomicBool,
    /// True when relation-derived text fields are stale and a full rebuild is
    /// needed before the next persist. Set by `upsert_relations_batch` to avoid
    /// 20K+ individual Tantivy upserts during bulk relation insertion.
    text_full_rebuild_required: AtomicBool,
    /// Code embedding model, lazily initialized on first embed call.
    #[cfg(feature = "embeddings")]
    embedder: parking_lot::Mutex<Option<Arc<CodeEmbedder>>>,
    /// HNSW vector index for semantic similarity search, lazily initialized.
    #[cfg(feature = "vector")]
    vector_index: parking_lot::Mutex<Option<Arc<VectorIndex>>>,
    /// Queue of entity keys that need embedding. Populated on upsert, drained
    /// by background workers or explicit `process_embedding_queue` calls.
    /// A [`RecencyQueue`] deduplicates (an entity modified twice only needs one
    /// embed) and records recency so the drain path can order work
    /// deterministically by priority (public-API/high-centrality and
    /// changed-this-sync entities first).
    #[cfg(feature = "vector")]
    embedding_queue: parking_lot::Mutex<RecencyQueue<RetrievalKey>>,
    /// Queue of artifact IDs that need embedding. This keeps artifact re-embed
    /// work targeted instead of forcing a full artifact pass on every embed run.
    #[cfg(feature = "vector")]
    artifact_embedding_queue: parking_lot::Mutex<RecencyQueue<ArtifactId>>,
}

impl InMemoryGraph {
    /// Create a new empty in-memory graph (RAM-only text index).
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Create a new empty in-memory graph with a persistent text index at
    /// the given directory path. The directory is created if it does not exist.
    pub fn with_text_index(text_index_path: PathBuf) -> Self {
        Self::build(Some(text_index_path))
    }

    fn build(text_index_path: Option<PathBuf>) -> Self {
        let text_index = match text_index_path.as_ref() {
            Some(p) => match TextIndex::open(Some(p)) {
                Ok(index) => Some(index),
                Err(err) => {
                    tracing::warn!(
                        "failed to open persistent text index at {}: {err}",
                        p.display()
                    );
                    TextIndex::new().ok()
                }
            },
            None => TextIndex::new().ok(),
        };
        let graph = Self {
            entities: RwLock::new(EntityData {
                entities: HashMap::new(),
                entity_revisions: HashMap::new(),
                relations: HashMap::new(),
                outgoing: HashMap::new(),
                incoming: HashMap::new(),
                node_outgoing: HashMap::new(),
                node_incoming: HashMap::new(),
                indexes: IndexSet::new(),
                file_hashes: HashMap::new(),
                shallow_files: HashMap::new(),
                file_layouts: HashMap::new(),
                structured_artifacts: HashMap::new(),
                opaque_artifacts: HashMap::new(),
                artifact_index: HashMap::new(),
                artifact_reverse: HashMap::new(),
            }),
            changes: RwLock::new(ChangeData {
                changes: HashMap::new(),
                change_children: HashMap::new(),
                branches: HashMap::new(),
            }),
            work: RwLock::new(WorkData {
                work_items: HashMap::new(),
                annotations: HashMap::new(),
                work_links: Vec::new(),
            }),
            reviews: RwLock::new(ReviewData {
                reviews: HashMap::new(),
                review_decisions: HashMap::new(),
                review_notes: HashMap::new(),
                review_discussions: HashMap::new(),
                review_assignments: HashMap::new(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: HashMap::new(),
                assertions: HashMap::new(),
                verification_runs: HashMap::new(),
                mock_hints: Vec::new(),
                contracts: HashMap::new(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: HashMap::new(),
                delegations: Vec::new(),
                approvals: Vec::new(),
                audit_events: Vec::new(),
            }),
            sessions: RwLock::new(SessionData {
                sessions: HashMap::new(),
                intents: HashMap::new(),
                downstream_warnings: Vec::new(),
            }),
            text_index,
            merkle: parking_lot::RwLock::new(MerkleCache::new()),
            merkle_pending: parking_lot::Mutex::new(PendingMerkle::default()),
            pending_delta: parking_lot::Mutex::new(PendingGraphDelta::default()),
            full_snapshot_required: AtomicBool::new(false),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
        };

        graph
    }

    /// Restore a graph from a snapshot (RAM-only text index).
    pub fn from_snapshot(mut snapshot: GraphSnapshot) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        let expected_root_hash = compute_graph_root_hash(&snapshot);
        Self::from_snapshot_inner(snapshot, None, expected_root_hash, false, false)
    }

    /// Restore a graph from a snapshot (RAM-only text index) with a precomputed
    /// graph root hash.
    pub fn from_snapshot_with_root_hash(
        mut snapshot: GraphSnapshot,
        expected_root_hash: [u8; 32],
    ) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        Self::from_snapshot_inner(snapshot, None, expected_root_hash, false, false)
    }

    /// Restore a graph from a snapshot without constructing any text index.
    ///
    /// This is intended for graph-only workflows such as warm-cache diffing
    /// where entity/file truth is needed but lexical retrieval is not.
    pub fn from_snapshot_without_text_index_with_root_hash(
        mut snapshot: GraphSnapshot,
        expected_root_hash: [u8; 32],
    ) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        Self::from_snapshot_inner(snapshot, None, expected_root_hash, false, true)
    }

    /// Restore a graph from a snapshot with a persistent text index at the
    /// given directory path.
    pub fn from_snapshot_with_text_index(
        mut snapshot: GraphSnapshot,
        text_index_path: PathBuf,
    ) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        let expected_root_hash = compute_graph_root_hash(&snapshot);
        Self::from_snapshot_inner(
            snapshot,
            Some(text_index_path),
            expected_root_hash,
            false,
            false,
        )
    }

    /// Restore a graph from a snapshot with a persistent text index loaded in
    /// read-only mode.
    pub fn from_snapshot_with_text_index_read_only(
        mut snapshot: GraphSnapshot,
        text_index_path: PathBuf,
    ) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        let expected_root_hash = compute_graph_root_hash(&snapshot);
        Self::from_snapshot_inner(
            snapshot,
            Some(text_index_path),
            expected_root_hash,
            true,
            false,
        )
    }

    /// Restore a graph from a snapshot with a persistent text index and a
    /// precomputed graph root hash.
    pub fn from_snapshot_with_text_index_and_root_hash(
        mut snapshot: GraphSnapshot,
        text_index_path: PathBuf,
        expected_root_hash: [u8; 32],
    ) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        Self::from_snapshot_inner(
            snapshot,
            Some(text_index_path),
            expected_root_hash,
            false,
            false,
        )
    }

    /// Restore a graph from a snapshot with a persistent text index loaded in
    /// read-only mode and a precomputed graph root hash.
    pub fn from_snapshot_with_text_index_and_root_hash_read_only(
        mut snapshot: GraphSnapshot,
        text_index_path: PathBuf,
        expected_root_hash: [u8; 32],
    ) -> Self {
        migrate_legacy_verification_relations(&mut snapshot);
        Self::from_snapshot_inner(
            snapshot,
            Some(text_index_path),
            expected_root_hash,
            true,
            false,
        )
    }

    /// Restore a read-only graph from a lightweight locate snapshot.
    ///
    /// This avoids reconstructing an intermediate full `GraphSnapshot` just to
    /// immediately collect the same entity/relation maps into the in-memory
    /// graph stores again.
    pub(crate) fn from_locate_snapshot_read_only(
        snapshot: LocateGraphSnapshot,
        text_index_path: Option<PathBuf>,
        expected_root_hash: [u8; 32],
    ) -> Self {
        Self::from_locate_snapshot_inner(snapshot, text_index_path, expected_root_hash, true)
    }

    fn from_snapshot_inner(
        snapshot: GraphSnapshot,
        text_index_path: Option<PathBuf>,
        expected_root_hash: [u8; 32],
        read_only: bool,
        skip_text_index: bool,
    ) -> Self {
        let GraphSnapshot {
            version: _,
            entities,
            relations,
            outgoing: persisted_outgoing,
            incoming: persisted_incoming,
            changes,
            change_children,
            branches,
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
            test_covers_entity: _,
            test_covers_contract: _,
            test_verifies_work: _,
            run_proves_entity: _,
            run_proves_work: _,
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
            file_hashes,
            sessions,
            intents,
            downstream_warnings,
            entity_revisions,
            entity_tombstones: _,
            relation_tombstones: _,
            change_order: _,
            artifact_index,
        } = snapshot;
        let entity_revisions: HashMap<EntityId, Vec<EntityRevision>> =
            if entity_revisions.is_empty() && !changes.is_empty() {
                kin_model::graph::derive_entity_revisions_from_changes(topologically_order_changes(
                    changes.iter().map(|(id, change)| (*id, change.clone())),
                ))
                .into_iter()
                .collect()
            } else {
                entity_revisions.into_iter().collect()
            };
        let _span = tracing::info_span!(
            "kindb.graph.from_snapshot",
            entities = entities.len(),
            relations = relations.len(),
            persistent_text_index = text_index_path.is_some(),
            read_only = read_only,
            skip_text_index = skip_text_index
        )
        .entered();
        let relations: HashMap<RelationId, Relation> = relations.into_iter().collect();
        let persisted_outgoing: HashMap<EntityId, Vec<RelationId>> =
            persisted_outgoing.into_iter().collect();
        let persisted_incoming: HashMap<EntityId, Vec<RelationId>> =
            persisted_incoming.into_iter().collect();
        let (outgoing, incoming, node_outgoing, node_incoming) = {
            let _span =
                tracing::info_span!("kindb.graph.from_snapshot.build_relation_indexes").entered();
            // FIR-853: reuse the persisted entity-level adjacency when it is
            // consistent with the loaded relations rather than discarding and
            // rebuilding it on every boot. Node-level maps are always derived
            // (they are not persisted).
            let (outgoing, incoming, node_outgoing, node_incoming, reuse) =
                build_relation_indexes_with_reuse(
                    &relations,
                    persisted_outgoing,
                    persisted_incoming,
                );
            tracing::debug!(
                adjacency_reuse = ?reuse,
                "kindb.graph.from_snapshot.adjacency"
            );
            (outgoing, incoming, node_outgoing, node_incoming)
        };
        let text_index = if skip_text_index {
            None
        } else {
            let _span = tracing::info_span!(
                "kindb.graph.from_snapshot.open_text_index",
                persistent_text_index = text_index_path.is_some()
            )
            .entered();
            match text_index_path.as_ref() {
                Some(p) => match if read_only {
                    TextIndex::open_read_only(Some(p))
                } else {
                    TextIndex::open(Some(p))
                } {
                    Ok(index) => Some(index),
                    Err(err) => {
                        tracing::warn!(
                            "failed to open persistent text index at {}: {err}",
                            p.display()
                        );
                        TextIndex::new().ok()
                    }
                },
                None => TextIndex::new().ok(),
            }
        };
        let text_index_current = text_index
            .as_ref()
            .and_then(TextIndex::graph_root_hash)
            .map(|hash| hash == expected_root_hash)
            .unwrap_or(false);
        let text_index_entity_coverage_current = if text_index_current {
            text_index
                .as_ref()
                .map(|index| {
                    entities.keys().all(|entity_id| {
                        index.contains_retrievable(&RetrievalKey::Entity(*entity_id))
                    })
                })
                .unwrap_or(false)
        } else {
            false
        };

        // Build secondary indexes in parallel using rayon.
        // Each chunk produces a partial IndexSet which we merge sequentially.
        // This is ~2-4x faster than a sequential loop for graphs >10K entities.
        let entity_vec: Vec<&Entity> = entities.values().collect();
        let indexes = {
            let _span =
                tracing::info_span!("kindb.graph.from_snapshot.build_entity_indexes").entered();
            if entity_vec.len() > 1024 {
                let chunk_indexes: Vec<IndexSet> = entity_vec
                    .par_chunks(4096)
                    .map(|chunk| {
                        let mut partial = IndexSet::new();
                        for entity in chunk {
                            partial.insert(
                                entity.id,
                                &entity.name,
                                entity.file_origin.as_ref(),
                                entity.kind,
                            );
                        }
                        partial
                    })
                    .collect();
                let mut merged = IndexSet::new();
                for partial in chunk_indexes {
                    merged.merge(partial);
                }
                merged
            } else {
                let mut indexes = IndexSet::new();
                for entity in &entity_vec {
                    indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }
                indexes
            }
        };

        let shallow_files: HashMap<FilePathId, ShallowTrackedFile> = shallow_files
            .into_iter()
            .map(|sf| (sf.file_id.clone(), sf))
            .collect();
        let file_layouts: HashMap<FilePathId, FileLayout> = file_layouts
            .into_iter()
            .map(|layout| (layout.file_id.clone(), layout))
            .collect();
        let structured_artifacts: HashMap<FilePathId, StructuredArtifact> = structured_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let opaque_artifacts: HashMap<FilePathId, OpaqueArtifact> = opaque_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let persisted_artifact_index: HashMap<FilePathId, ArtifactId> =
            artifact_index.into_iter().collect();
        let (artifact_index, artifact_reverse) = if persisted_artifact_index.is_empty() {
            build_artifact_indexes_from_paths(
                shallow_files
                    .keys()
                    .chain(file_layouts.keys())
                    .chain(structured_artifacts.keys())
                    .chain(opaque_artifacts.keys())
                    .cloned(),
            )
        } else {
            let artifact_reverse = reverse_artifact_index(&persisted_artifact_index);
            (persisted_artifact_index, artifact_reverse)
        };

        let entity_data = EntityData {
            entities: entities.into_iter().collect(),
            entity_revisions,
            relations,
            outgoing,
            incoming,
            node_outgoing,
            node_incoming,
            indexes,
            file_hashes: file_hashes.into_iter().collect(),
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            artifact_index,
            artifact_reverse,
        };
        let merkle = MerkleCache::from_source(&entity_data);

        let graph = Self {
            entities: RwLock::new(entity_data),
            changes: RwLock::new(ChangeData {
                changes: changes.into_iter().collect(),
                change_children: change_children.into_iter().collect(),
                branches: branches.into_iter().collect(),
            }),
            work: RwLock::new(WorkData {
                work_items: work_items.into_iter().collect(),
                annotations: annotations.into_iter().collect(),
                work_links,
            }),
            reviews: RwLock::new(ReviewData {
                reviews: reviews.into_iter().collect(),
                review_decisions: review_decisions.into_iter().collect(),
                review_notes: review_notes.into_iter().map(|n| (n.note_id, n)).collect(),
                review_discussions: review_discussions
                    .into_iter()
                    .map(|d| (d.discussion_id, d))
                    .collect(),
                review_assignments: review_assignments.into_iter().collect(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: test_cases.into_iter().collect(),
                assertions: assertions.into_iter().collect(),
                verification_runs: verification_runs.into_iter().collect(),
                mock_hints,
                contracts: contracts.into_iter().collect(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: actors.into_iter().collect(),
                delegations,
                approvals,
                audit_events,
            }),
            sessions: RwLock::new(SessionData {
                sessions: sessions.into_iter().collect(),
                intents: intents.into_iter().collect(),
                downstream_warnings,
            }),
            text_index,
            merkle: parking_lot::RwLock::new(merkle),
            merkle_pending: parking_lot::Mutex::new(PendingMerkle::default()),
            pending_delta: parking_lot::Mutex::new(PendingGraphDelta::default()),
            full_snapshot_required: AtomicBool::new(false),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
        };

        if !skip_text_index && (!text_index_current || !text_index_entity_coverage_current) {
            graph.rebuild_text_index_with_root_hash(expected_root_hash);
        }

        graph
    }

    fn from_locate_snapshot_inner(
        snapshot: LocateGraphSnapshot,
        text_index_path: Option<PathBuf>,
        expected_root_hash: [u8; 32],
        read_only: bool,
    ) -> Self {
        let LocateGraphSnapshot {
            version: _,
            entities,
            relations,
            changes,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            artifact_index,
        } = snapshot;
        let _span = tracing::info_span!(
            "kindb.graph.from_locate_snapshot",
            entities = entities.len(),
            relations = relations.len(),
            persistent_text_index = text_index_path.is_some(),
            read_only = read_only
        )
        .entered();
        let (outgoing, incoming, node_outgoing, node_incoming) = {
            let _span =
                tracing::info_span!("kindb.graph.from_locate_snapshot.build_relation_indexes")
                    .entered();
            build_relation_indexes(&relations)
        };
        let text_index = {
            let _span = tracing::info_span!(
                "kindb.graph.from_locate_snapshot.open_text_index",
                persistent_text_index = text_index_path.is_some()
            )
            .entered();
            match text_index_path.as_ref() {
                Some(p) => match if read_only {
                    TextIndex::open_read_only(Some(p))
                } else {
                    TextIndex::open(Some(p))
                } {
                    Ok(index) => Some(index),
                    Err(err) => {
                        tracing::warn!(
                            "failed to open persistent text index at {}: {err}",
                            p.display()
                        );
                        TextIndex::new().ok()
                    }
                },
                None => TextIndex::new().ok(),
            }
        };
        let text_index_current = text_index
            .as_ref()
            .and_then(TextIndex::graph_root_hash)
            .map(|hash| hash == expected_root_hash)
            .unwrap_or(false);

        let entity_vec: Vec<&Entity> = entities.values().collect();
        let indexes = {
            let _span =
                tracing::info_span!("kindb.graph.from_locate_snapshot.build_entity_indexes")
                    .entered();
            if entity_vec.len() > 1024 {
                let chunk_indexes: Vec<IndexSet> = entity_vec
                    .par_chunks(4096)
                    .map(|chunk| {
                        let mut partial = IndexSet::new();
                        for entity in chunk {
                            partial.insert(
                                entity.id,
                                &entity.name,
                                entity.file_origin.as_ref(),
                                entity.kind,
                            );
                        }
                        partial
                    })
                    .collect();
                let mut merged = IndexSet::new();
                for partial in chunk_indexes {
                    merged.merge(partial);
                }
                merged
            } else {
                let mut indexes = IndexSet::new();
                for entity in &entity_vec {
                    indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }
                indexes
            }
        };

        let shallow_files: HashMap<FilePathId, ShallowTrackedFile> = shallow_files
            .into_iter()
            .map(|sf| (sf.file_id.clone(), sf))
            .collect();
        let file_layouts: HashMap<FilePathId, FileLayout> = file_layouts
            .into_iter()
            .map(|layout| (layout.file_id.clone(), layout))
            .collect();
        let structured_artifacts: HashMap<FilePathId, StructuredArtifact> = structured_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let opaque_artifacts: HashMap<FilePathId, OpaqueArtifact> = opaque_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let persisted_artifact_index: HashMap<FilePathId, ArtifactId> =
            artifact_index.into_iter().collect();
        let (artifact_index, artifact_reverse) = if persisted_artifact_index.is_empty() {
            build_artifact_indexes_from_paths(
                shallow_files
                    .keys()
                    .chain(file_layouts.keys())
                    .chain(structured_artifacts.keys())
                    .chain(opaque_artifacts.keys())
                    .cloned(),
            )
        } else {
            let artifact_reverse = reverse_artifact_index(&persisted_artifact_index);
            (persisted_artifact_index, artifact_reverse)
        };

        let entity_data = EntityData {
            entities,
            entity_revisions: kin_model::graph::derive_entity_revisions_from_changes(
                topologically_order_changes(
                    changes.iter().map(|(id, change)| (*id, change.clone())),
                ),
            )
            .into_iter()
            .collect(),
            relations,
            outgoing,
            incoming,
            node_outgoing,
            node_incoming,
            indexes,
            file_hashes: HashMap::new(),
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            artifact_index,
            artifact_reverse,
        };
        let merkle = MerkleCache::from_source(&entity_data);

        let graph = Self {
            entities: RwLock::new(entity_data),
            changes: RwLock::new(ChangeData {
                changes,
                change_children: HashMap::new(),
                branches: HashMap::new(),
            }),
            work: RwLock::new(WorkData {
                work_items: HashMap::new(),
                annotations: HashMap::new(),
                work_links: Vec::new(),
            }),
            reviews: RwLock::new(ReviewData {
                reviews: HashMap::new(),
                review_decisions: HashMap::new(),
                review_notes: HashMap::new(),
                review_discussions: HashMap::new(),
                review_assignments: HashMap::new(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: HashMap::new(),
                assertions: HashMap::new(),
                verification_runs: HashMap::new(),
                mock_hints: Vec::new(),
                contracts: HashMap::new(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: HashMap::new(),
                delegations: Vec::new(),
                approvals: Vec::new(),
                audit_events: Vec::new(),
            }),
            sessions: RwLock::new(SessionData {
                sessions: HashMap::new(),
                intents: HashMap::new(),
                downstream_warnings: Vec::new(),
            }),
            text_index,
            merkle: parking_lot::RwLock::new(merkle),
            merkle_pending: parking_lot::Mutex::new(PendingMerkle::default()),
            pending_delta: parking_lot::Mutex::new(PendingGraphDelta::default()),
            full_snapshot_required: AtomicBool::new(false),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
        };

        if !text_index_current {
            graph.rebuild_text_index_with_root_hash(expected_root_hash);
        }

        graph
    }

    fn rebuild_text_index_with_root_hash(&self, root_hash: [u8; 32]) {
        let _span = tracing::info_span!("kindb.graph.rebuild_text_index_with_root_hash").entered();
        let Some(ref ti) = self.text_index else {
            return;
        };

        let docs: Vec<(RetrievalKey, Vec<(String, f32)>)> = {
            let ent = self.entities.read();
            let _span = tracing::info_span!(
                "kindb.graph.rebuild_text_index.collect",
                entities = ent.entities.len(),
                shallow_files = ent.shallow_files.len(),
                structured_artifacts = ent.structured_artifacts.len(),
                opaque_artifacts = ent.opaque_artifacts.len()
            )
            .entered();
            let entity_docs = ent.entities.values().map(|entity| {
                let extra = collect_text_index_extra_fields(&ent, &entity.id);
                let fields = if extra.is_empty() {
                    crate::search::entity_fields(entity)
                } else {
                    crate::search::entity_fields_with_extra(entity, &extra)
                };
                (RetrievalKey::Entity(entity.id), fields)
            });
            let artifact_docs = collect_artifact_text_index_docs(&ent);
            entity_docs.chain(artifact_docs).collect()
        };

        {
            let _span = tracing::info_span!(
                "kindb.graph.rebuild_text_index.bulk_rebuild",
                docs = docs.len()
            )
            .entered();
            let _ = ti.rebuild_all_owned(docs);
        }

        {
            let _span = tracing::info_span!("kindb.graph.rebuild_text_index.commit").entered();
            ti.set_graph_root_hash(root_hash);
            let _ = ti.commit();
        }
        self.text_dirty.store(false, Ordering::Release);
        self.text_full_rebuild_required
            .store(false, Ordering::Release);
    }

    #[inline]
    pub(crate) fn snapshot_root_hash_hint(&self) -> Option<[u8; 32]> {
        Some(self.compute_root_hash())
    }

    /// Current graph-root hash for the live entity/relation graph.
    ///
    /// This is the value a persisted vector-index sidecar must match before it
    /// can be trusted as graph-owned truth. Exposed so out-of-process callers
    /// (the daemon) can validate a sidecar against the live graph via
    /// [`SnapshotManager::load_vector_index_into_graph_if_valid`] instead of
    /// force-loading it unchecked.
    #[inline]
    pub fn snapshot_root_hash(&self) -> Option<[u8; 32]> {
        Some(self.compute_root_hash())
    }

    /// Record entities whose Merkle hashes are now stale.
    ///
    /// This only journals the touched seeds; the root is reconciled lazily by
    /// [`Self::flush_merkle`] on the next read. Deferring is what keeps bulk
    /// ingestion linear — thousands of single-relation upserts collapse into one
    /// batch Merkle build instead of one O(component) refresh apiece.
    #[inline]
    fn refresh_merkle_for_entities<I>(&self, _ent: &EntityData, seeds: I)
    where
        I: IntoIterator<Item = EntityId>,
    {
        let mut pending = self.merkle_pending.lock();
        pending.seeds.extend(seeds);
        pending.dirty = true;
    }

    /// Reconcile the deferred Merkle root against the live graph.
    ///
    /// Callers that read the root must run this first while holding a guard on
    /// `self.entities` (read or write) so the graph cannot mutate mid-refresh.
    /// `ent` is that already-held guard, passed in to avoid re-locking.
    fn flush_merkle(&self, ent: &EntityData) {
        let seeds = {
            let mut pending = self.merkle_pending.lock();
            if !pending.dirty {
                return;
            }
            pending.dirty = false;
            std::mem::take(&mut pending.seeds)
        };
        self.merkle.write().refresh_affected(ent, seeds);
        #[cfg(test)]
        MERKLE_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn has_pending_delta(&self) -> bool {
        !self.pending_delta.lock().delta.is_empty()
    }

    pub fn take_pending_delta(&self, base_generation: Generation) -> Option<GraphSnapshotDelta> {
        let mut pending = self.pending_delta.lock();
        if pending.delta.is_empty() {
            return None;
        }
        let mut delta = GraphSnapshotDelta::empty(base_generation);
        std::mem::swap(&mut pending.delta, &mut delta);
        delta.base_generation = base_generation;
        Some(delta)
    }

    pub fn clear_pending_delta(&self) {
        self.pending_delta.lock().delta = GraphSnapshotDelta::empty(0);
    }

    pub fn pending_delta_snapshot(
        &self,
        base_generation: Generation,
    ) -> Option<GraphSnapshotDelta> {
        let pending = self.pending_delta.lock();
        if pending.delta.is_empty() {
            return None;
        }
        let mut delta = pending.delta.clone();
        delta.base_generation = base_generation;
        Some(delta)
    }

    pub fn full_snapshot_required(&self) -> bool {
        self.full_snapshot_required.load(Ordering::Acquire)
    }

    pub fn clear_full_snapshot_required(&self) {
        self.full_snapshot_required.store(false, Ordering::Release);
    }

    fn require_full_snapshot(&self) {
        self.full_snapshot_required.store(true, Ordering::Release);
    }

    fn record_entity_delta_upsert(&self, entity: Entity) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.entities, entity.id, entity);
    }

    fn record_entity_delta_remove(&self, entity_id: EntityId) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.entities, entity_id);
        delta_map_remove(&mut pending.delta.entity_revisions, entity_id);
    }

    fn record_entity_revisions_delta_upsert(
        &self,
        entity_id: EntityId,
        revisions: Vec<EntityRevision>,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.entity_revisions, entity_id, revisions);
    }

    fn record_change_delta_upsert(&self, change: SemanticChange) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.changes, change.id, change);
    }

    fn record_change_children_delta_upsert(
        &self,
        change_id: SemanticChangeId,
        children: Vec<SemanticChangeId>,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.change_children, change_id, children);
    }

    fn record_branch_delta_upsert(&self, branch: Branch) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.branches, branch.name.clone(), branch);
    }

    fn record_branch_delta_remove(&self, name: BranchName) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.branches, name);
    }

    fn record_relation_delta_upsert(&self, ent: &EntityData, relation: Relation) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.relations, relation.id, relation.clone());
        record_relation_edge_delta(&mut pending, ent, &relation);
    }

    fn record_relation_delta_remove(&self, ent: &EntityData, relation: &Relation) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.relations, relation.id);
        record_relation_edge_delta(&mut pending, ent, relation);
    }

    fn record_file_hash_delta_upsert(&self, path: String, hash: [u8; 32]) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.file_hashes, path, hash);
    }

    fn record_file_hash_delta_remove(&self, path: String) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.file_hashes, path);
    }

    fn record_artifact_index_delta_upsert(&self, path: FilePathId, artifact_id: ArtifactId) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.artifact_index, path, artifact_id);
    }

    fn record_artifact_index_delta_remove(&self, path: FilePathId) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.artifact_index, path);
    }

    fn record_shallow_file_delta_upsert(
        &self,
        old: Option<ShallowTrackedFile>,
        new: ShallowTrackedFile,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(&mut pending.delta.shallow_files, old, new, |file| {
            file.file_id.clone()
        });
    }

    fn record_shallow_file_delta_remove(
        &self,
        old: Option<ShallowTrackedFile>,
        file_id: FilePathId,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(&mut pending.delta.shallow_files, old, file_id, |file| {
            file.file_id.clone()
        });
    }

    fn record_file_layout_delta_upsert(&self, old: Option<FileLayout>, new: FileLayout) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(&mut pending.delta.file_layouts, old, new, |layout| {
            layout.file_id.clone()
        });
    }

    fn record_file_layout_delta_remove(&self, old: Option<FileLayout>, file_id: FilePathId) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(&mut pending.delta.file_layouts, old, file_id, |layout| {
            layout.file_id.clone()
        });
    }

    fn record_structured_artifact_delta_upsert(
        &self,
        old: Option<StructuredArtifact>,
        new: StructuredArtifact,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(
            &mut pending.delta.structured_artifacts,
            old,
            new,
            |artifact| artifact.file_id.clone(),
        );
    }

    fn record_structured_artifact_delta_remove(
        &self,
        old: Option<StructuredArtifact>,
        file_id: FilePathId,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(
            &mut pending.delta.structured_artifacts,
            old,
            file_id,
            |artifact| artifact.file_id.clone(),
        );
    }

    fn record_opaque_artifact_delta_upsert(
        &self,
        old: Option<OpaqueArtifact>,
        new: OpaqueArtifact,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(&mut pending.delta.opaque_artifacts, old, new, |artifact| {
            artifact.file_id.clone()
        });
    }

    fn record_opaque_artifact_delta_remove(
        &self,
        old: Option<OpaqueArtifact>,
        file_id: FilePathId,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(
            &mut pending.delta.opaque_artifacts,
            old,
            file_id,
            |artifact| artifact.file_id.clone(),
        );
    }

    fn refresh_text_index_for_entities(&self, entity_ids: &[EntityId]) {
        let Some(ref ti) = self.text_index else {
            return;
        };

        let docs: Vec<(Entity, Vec<(String, f32)>)> = {
            let ent = self.entities.read();
            entity_ids
                .iter()
                .filter_map(|entity_id| {
                    ent.entities.get(entity_id).map(|entity| {
                        (
                            entity.clone(),
                            collect_text_index_extra_fields(&ent, entity_id),
                        )
                    })
                })
                .collect()
        };

        for (entity, extra_fields) in docs {
            let _ = ti.upsert_with_extra_fields(&entity, &extra_fields);
        }
        if !entity_ids.is_empty() {
            self.text_dirty.store(true, Ordering::Release);
        }
    }

    fn upsert_retrievable_text_index(
        &self,
        key: RetrievalKey,
        fields: &[(String, f32)],
    ) -> Result<(), KinDbError> {
        let Some(ref ti) = self.text_index else {
            return Ok(());
        };

        let field_refs: Vec<(&str, f32)> = fields
            .iter()
            .map(|(text, weight)| (text.as_str(), *weight))
            .collect();
        ti.upsert_retrievable(key, &field_refs)?;
        self.text_dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn remove_retrievable_text_index(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        let Some(ref ti) = self.text_index else {
            return Ok(());
        };

        ti.remove_retrievable(key)?;
        self.text_dirty.store(true, Ordering::Release);
        Ok(())
    }

    #[cfg(feature = "vector")]
    fn remove_retrievable_vector(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        if let Some(ref vi) = *self.vector_index.lock() {
            vi.remove_retrievable(key)?;
        }
        Ok(())
    }

    #[cfg(not(feature = "vector"))]
    fn remove_retrievable_vector(&self, _key: &RetrievalKey) -> Result<(), KinDbError> {
        Ok(())
    }

    #[cfg(feature = "vector")]
    fn invalidate_entities_for_embedding(&self, entity_ids: &[EntityId]) -> Result<(), KinDbError> {
        if entity_ids.is_empty() {
            return Ok(());
        }

        // Dedup, then SORT before removal. The removal order feeds the vector
        // index's free-list, and a `HashSet` iterates in per-process-random
        // order — so an unsorted remove sequence makes the HNSW slot history
        // (and thus live-search results) vary run to run. Sorting fixes the
        // remove/enqueue order deterministically.
        let mut unique_ids: Vec<EntityId> = entity_ids
            .iter()
            .copied()
            .collect::<HashSet<EntityId>>()
            .into_iter()
            .collect();
        unique_ids.sort();
        for entity_id in &unique_ids {
            self.remove_retrievable_vector(&RetrievalKey::Entity(*entity_id))?;
        }
        // Live mutation path: these entities changed this sync, so enqueue them
        // as `ChangedThisSync` (the highest recency tier) rather than backfill.
        let mut queue = self.embedding_queue.lock();
        for entity_id in &unique_ids {
            queue.insert(
                RetrievalKey::Entity(*entity_id),
                EmbedRecency::ChangedThisSync,
            );
        }
        Ok(())
    }

    #[cfg(not(feature = "vector"))]
    fn invalidate_entities_for_embedding(
        &self,
        _entity_ids: &[EntityId],
    ) -> Result<(), KinDbError> {
        Ok(())
    }

    #[cfg(feature = "vector")]
    fn invalidate_artifact_for_embedding(&self, artifact_id: ArtifactId) -> Result<(), KinDbError> {
        self.remove_retrievable_vector(&RetrievalKey::Artifact(artifact_id))?;
        // Live mutation path: changed-this-sync recency.
        self.artifact_embedding_queue
            .lock()
            .insert(artifact_id, EmbedRecency::ChangedThisSync);
        Ok(())
    }

    #[cfg(not(feature = "vector"))]
    fn invalidate_artifact_for_embedding(
        &self,
        _artifact_id: ArtifactId,
    ) -> Result<(), KinDbError> {
        Ok(())
    }

    /// Serialize the live graph directly to snapshot bytes + Merkle root hash,
    /// without cloning the sub-stores.  Acquires read guards on all stores,
    /// computes the root hash from the live EntityData, creates a
    /// [`BorrowedGraphSnapshot`] for serialization, then drops the guards.
    ///
    /// Returns `(serialized_bytes, root_hash)`.
    pub fn serialize_snapshot_borrowed(
        &self,
    ) -> Result<(Vec<u8>, crate::storage::merkle::MerkleHash), KinDbError> {
        self.serialize_snapshot_borrowed_with_hash(None)
    }

    /// Like [`serialize_snapshot_borrowed`] but accepts a pre-computed root
    /// hash.  When `Some`, the expensive Merkle DAG traversal is skipped.
    pub fn serialize_snapshot_borrowed_with_hash(
        &self,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<(Vec<u8>, crate::storage::merkle::MerkleHash), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.graph.serialize_snapshot_borrowed_with_hash",
            precomputed_hash = precomputed_hash.is_some()
        )
        .entered();
        use crate::storage::format::BorrowedGraphSnapshot;

        let t0 = std::time::Instant::now();
        let ent = self.entities.read();
        let chg = self.changes.read();
        let wrk = self.work.read();
        let rev = self.reviews.read();
        let ver = self.verification.read();
        let prv = self.provenance.read();
        let ses = self.sessions.read();
        let t_lock = t0.elapsed();

        let t1 = std::time::Instant::now();
        let graph_root_hash = {
            let _span =
                tracing::info_span!("kindb.graph.serialize_snapshot.compute_root_hash").entered();
            self.flush_merkle(&ent);
            let current = self.merkle.read().root_hash();
            precomputed_hash
                .filter(|hash| *hash == current)
                .unwrap_or(current)
        };
        let t_hash = t1.elapsed();

        let t2 = std::time::Instant::now();
        let bytes = {
            let _span = tracing::info_span!("kindb.graph.serialize_snapshot.encode").entered();
            let borrowed = BorrowedGraphSnapshot {
                entities: &ent.entities,
                entity_revisions: &ent.entity_revisions,
                relations: &ent.relations,
                outgoing: &ent.outgoing,
                incoming: &ent.incoming,
                file_hashes: &ent.file_hashes,
                shallow_files: &ent.shallow_files,
                file_layouts: &ent.file_layouts,
                structured_artifacts: &ent.structured_artifacts,
                opaque_artifacts: &ent.opaque_artifacts,
                changes: &chg.changes,
                change_children: &chg.change_children,
                branches: &chg.branches,
                work_items: &wrk.work_items,
                annotations: &wrk.annotations,
                work_links: &wrk.work_links,
                reviews: &rev.reviews,
                review_decisions: &rev.review_decisions,
                review_notes: &rev.review_notes,
                review_discussions: &rev.review_discussions,
                review_assignments: &rev.review_assignments,
                test_cases: &ver.test_cases,
                assertions: &ver.assertions,
                verification_runs: &ver.verification_runs,
                mock_hints: &ver.mock_hints,
                contracts: &ver.contracts,
                actors: &prv.actors,
                delegations: &prv.delegations,
                approvals: &prv.approvals,
                audit_events: &prv.audit_events,
                sessions: &ses.sessions,
                intents: &ses.intents,
                downstream_warnings: &ses.downstream_warnings,
            };
            borrowed.to_bytes_with_persisted_root_hash(graph_root_hash)?
        };
        let t_serialize = t2.elapsed();

        eprintln!(
            "[save-timer] lock={:.1}ms  root_hash={:.1}ms  serialize={:.1}ms  bytes={}",
            t_lock.as_secs_f64() * 1000.0,
            t_hash.as_secs_f64() * 1000.0,
            t_serialize.as_secs_f64() * 1000.0,
            bytes.len(),
        );

        Ok((bytes, graph_root_hash))
    }

    /// O(1) lookup: file path → graph-assigned ArtifactId
    pub fn artifact_id_for_path(&self, path: &FilePathId) -> Option<ArtifactId> {
        self.entities.read().artifact_index.get(path).copied()
    }

    /// O(1) reverse lookup: ArtifactId → file path
    pub fn path_for_artifact_id(&self, id: &ArtifactId) -> Option<FilePathId> {
        self.entities.read().artifact_reverse.get(id).cloned()
    }

    /// Idempotent: returns existing ID if tracked, else assigns new one.
    /// For migration, uses from_path() deterministic derivation so existing
    /// graph edges remain valid.
    pub fn ensure_artifact_id(&self, path: &FilePathId) -> ArtifactId {
        let mut ent = self.entities.write();
        if let Some(id) = ent.artifact_index.get(path) {
            *id
        } else {
            let new_id = ArtifactId::seed_from_path(&path.0);
            ent.artifact_index.insert(path.clone(), new_id);
            ent.artifact_reverse.insert(new_id, path.clone());
            self.record_artifact_index_delta_upsert(path.clone(), new_id);
            new_id
        }
    }

    /// Move artifact identity across paths (file rename).
    pub fn rename_artifact(
        &self,
        old_path: &FilePathId,
        new_path: &FilePathId,
    ) -> Option<ArtifactId> {
        let mut ent = self.entities.write();
        let id = ent.artifact_index.remove(old_path)?;
        ent.artifact_index.insert(new_path.clone(), id);
        ent.artifact_reverse.insert(id, new_path.clone());
        self.record_artifact_index_delta_remove(old_path.clone());
        self.record_artifact_index_delta_upsert(new_path.clone(), id);
        Some(id)
    }

    /// Return all entity→entity edges in a single lock acquisition.
    ///
    /// Each entry is `(src_entity_id, relation_kind, dst_entity_id, confidence)`.
    /// Used by [`ReadIndex::from_graph`] to avoid 20K+ per-entity lock acquisitions.
    pub fn list_all_entity_edges(&self) -> Vec<(EntityId, RelationKind, EntityId, f32)> {
        let ent = self.entities.read();
        let mut edges = Vec::with_capacity(ent.relations.len());
        for rel in ent.relations.values() {
            if let (Some(src), Some(dst)) = (rel.src.as_entity(), rel.dst.as_entity()) {
                edges.push((src, rel.kind, dst, rel.confidence));
            }
        }
        edges
    }

    pub fn to_snapshot(&self) -> GraphSnapshot {
        // Clone each sub-store under its own read lock, then drop the lock
        // immediately. Lock ordering: entities → changes → work → reviews
        // → verification → provenance → sessions.
        let ent = self.entities.read().clone();
        let chg = self.changes.read().clone();
        let wrk = self.work.read().clone();
        let rev = self.reviews.read().clone();
        let ver = self.verification.read().clone();
        let prv = self.provenance.read().clone();
        let ses = self.sessions.read().clone();

        GraphSnapshot {
            version: GraphSnapshot::CURRENT_VERSION,
            entities: ent.entities.into_iter().collect(),
            entity_revisions: ent.entity_revisions.into_iter().collect(),
            relations: ent.relations.into_iter().collect(),
            outgoing: ent.outgoing.into_iter().collect(),
            incoming: ent.incoming.into_iter().collect(),
            file_hashes: ent.file_hashes.into_iter().collect(),
            shallow_files: ent.shallow_files.into_values().collect(),
            file_layouts: ent.file_layouts.into_values().collect(),
            structured_artifacts: ent.structured_artifacts.into_values().collect(),
            opaque_artifacts: ent.opaque_artifacts.into_values().collect(),
            changes: chg.changes.into_iter().collect(),
            change_children: chg.change_children.into_iter().collect(),
            branches: chg.branches.into_iter().collect(),
            work_items: wrk.work_items.into_iter().collect(),
            annotations: wrk.annotations.into_iter().collect(),
            work_links: wrk.work_links,
            reviews: rev.reviews.into_iter().collect(),
            review_decisions: rev.review_decisions.into_iter().collect(),
            review_notes: rev.review_notes.into_values().collect(),
            review_discussions: rev.review_discussions.into_values().collect(),
            review_assignments: rev.review_assignments.into_iter().collect(),
            test_cases: ver.test_cases.into_iter().collect(),
            assertions: ver.assertions.into_iter().collect(),
            verification_runs: ver.verification_runs.into_iter().collect(),
            test_covers_entity: Vec::new(),
            test_covers_contract: Vec::new(),
            test_verifies_work: Vec::new(),
            run_proves_entity: Vec::new(),
            run_proves_work: Vec::new(),
            mock_hints: ver.mock_hints,
            contracts: ver.contracts.into_iter().collect(),
            actors: prv.actors.into_iter().collect(),
            delegations: prv.delegations,
            approvals: prv.approvals,
            audit_events: prv.audit_events,
            sessions: ses.sessions.into_iter().collect(),
            intents: ses.intents.into_iter().collect(),
            downstream_warnings: ses.downstream_warnings,
            entity_tombstones: std::collections::HashMap::new(),
            relation_tombstones: std::collections::HashMap::new(),
            change_order: std::collections::HashMap::new(),
            artifact_index: ent.artifact_index.into_iter().collect(),
        }
    }

    /// Compute the Merkle root hash directly from the live entity stores,
    /// without materialising a full `GraphSnapshot`.
    pub fn compute_root_hash(&self) -> crate::storage::merkle::MerkleHash {
        let ent = self.entities.read();
        self.flush_merkle(&ent);
        self.merkle.read().root_hash()
    }

    /// Recompute the canonical Merkle root hash directly from the live entity
    /// stores. This is the cold verification reference and does not replace the
    /// continuously-maintained live root.
    pub fn recompute_root_hash(&self) -> crate::storage::merkle::MerkleHash {
        let ent = self.entities.read();
        compute_root_hash_generic(&*ent, None)
    }

    /// Number of entities in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.read().entities.len()
    }

    /// Number of relations in the graph.
    pub fn relation_count(&self) -> usize {
        self.entities.read().relations.len()
    }

    /// Return incoming and outgoing relations for any graph node.
    ///
    /// The `EntityStore` relation APIs intentionally expose entity-only edges.
    /// Locate and graph-native diagnostics also need artifact/module edges such
    /// as file includes, so they use this concrete mixed-node accessor.
    pub fn get_all_relations_for_node(
        &self,
        node: &GraphNodeId,
    ) -> Result<Vec<Relation>, KinDbError> {
        let ent = self.entities.read();
        let mut result = Vec::new();
        let mut seen = hashbrown::HashSet::new();

        if let Some(edge_ids) = ent.node_outgoing.get(node) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        if let Some(edge_ids) = ent.node_incoming.get(node) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    /// Number of graph-owned non-entity retrievables.
    pub fn artifact_count(&self) -> usize {
        let ent = self.entities.read();
        ent.shallow_files.len() + ent.structured_artifacts.len() + ent.opaque_artifacts.len()
    }

    /// Collect comprehensive graph statistics for observability.
    pub fn graph_stats(&self) -> GraphStats {
        let ent = self.entities.read();
        let work = self.work.read();
        let reviews = self.reviews.read();
        let verification = self.verification.read();
        let sessions = self.sessions.read();
        let total_entities = ent.entities.len();
        let total_relations = ent.relations.len();
        let text_indexed_entity_count = self
            .text_index
            .as_ref()
            .map(|index| {
                ent.entities
                    .keys()
                    .filter(|entity_id| {
                        index.contains_retrievable(&RetrievalKey::Entity(**entity_id))
                    })
                    .count()
            })
            .unwrap_or(0);
        let embedding_status = self.embedding_status();
        #[cfg(feature = "vector")]
        let indexed_embedding_count = self
            .vector_index
            .lock()
            .as_ref()
            .map(|index| {
                ent.entities
                    .keys()
                    .filter(|entity_id| index.contains(entity_id))
                    .count()
            })
            .unwrap_or(0);
        #[cfg(not(feature = "vector"))]
        let indexed_embedding_count = 0usize;
        #[cfg(feature = "vector")]
        let pending_embedding_count = embedding_status
            .pending
            .max(total_entities.saturating_sub(indexed_embedding_count));
        #[cfg(not(feature = "vector"))]
        let pending_embedding_count = embedding_status.pending;

        let mut entity_counts = std::collections::HashMap::new();
        for entity in ent.entities.values() {
            *entity_counts
                .entry(format!("{:?}", entity.kind))
                .or_insert(0) += 1;
        }

        let mut relation_counts = std::collections::HashMap::new();
        for relation in ent.relations.values() {
            *relation_counts
                .entry(format!("{:?}", relation.kind))
                .or_insert(0) += 1;
        }

        let mut parse_completeness_counts = std::collections::HashMap::new();
        for layout in ent.file_layouts.values() {
            *parse_completeness_counts
                .entry(layout.parse_completeness.bucket().to_string())
                .or_insert(0) += 1;
        }

        let mut role_counts = std::collections::HashMap::new();
        for entity in ent.entities.values() {
            *role_counts.entry(format!("{:?}", entity.role)).or_insert(0) += 1;
        }

        GraphStats {
            total_entities,
            total_relations,
            entity_counts,
            relation_counts,
            parse_completeness_counts,
            shallow_file_count: ent.shallow_files.len(),
            file_layout_count: ent.file_layouts.len(),
            structured_artifact_count: ent.structured_artifacts.len(),
            opaque_artifact_count: ent.opaque_artifacts.len(),
            file_hash_count: ent.file_hashes.len(),
            text_indexed_entity_count,
            text_index_coverage_percent: coverage_percent(
                text_indexed_entity_count,
                total_entities,
            ),
            indexed_embedding_count,
            pending_embedding_count,
            embedding_coverage_percent: coverage_percent(indexed_embedding_count, total_entities),
            work_item_count: work.work_items.len(),
            test_case_count: verification.test_cases.len(),
            review_count: reviews.reviews.len(),
            session_count: sessions.sessions.len(),
            role_counts,
        }
    }

    /// Commit any pending text index writes and reload the reader.
    ///
    /// `upsert_entity` and `remove_entity` stage text index changes but defer
    /// the (expensive) tantivy commit. Callers should invoke this after a batch
    /// of writes so that subsequent `fuzzy_search` calls see the latest data.
    /// Calling this when the index is clean is a no-op.
    pub fn flush_text_index(&self) -> Result<(), KinDbError> {
        let _span = tracing::info_span!("kindb.flush_text_index").entered();
        // If a full rebuild was requested (e.g., after bulk relation insert),
        // do it now before committing. This regenerates all relation-derived
        // text fields in one pass instead of per-entity updates.
        if self
            .text_full_rebuild_required
            .swap(false, Ordering::AcqRel)
        {
            // Use a zero root hash — persist_text_index_with_root_hash sets the
            // real one. This just ensures the text content is rebuilt.
            self.rebuild_text_index_with_root_hash([0u8; 32]);
            return Ok(());
        }
        if self.text_dirty.swap(false, Ordering::AcqRel) {
            if let Some(ref ti) = self.text_index {
                ti.commit()?;
            }
        }
        Ok(())
    }

    pub fn persist_text_index_with_root_hash(
        &self,
        graph_root_hash: [u8; 32],
    ) -> Result<(), KinDbError> {
        // If relation-derived fields are stale, do a full rebuild first.
        // This is set by upsert_relations_batch to amortize the cost of
        // 20K+ individual Tantivy upserts into one full rebuild at persist time.
        if self
            .text_full_rebuild_required
            .swap(false, Ordering::AcqRel)
        {
            self.rebuild_text_index_with_root_hash(graph_root_hash);
            return Ok(());
        }

        if let Some(ref ti) = self.text_index {
            let root_hash_changed = ti.graph_root_hash() != Some(graph_root_hash);
            ti.set_graph_root_hash(graph_root_hash);
            if root_hash_changed {
                return ti.commit();
            }
            if !self.text_dirty.load(Ordering::Acquire)
                && !self.text_full_rebuild_required.load(Ordering::Acquire)
            {
                return Ok(());
            }
        }
        self.flush_text_index()
    }

    /// Full-text search across entity names, signatures, and file paths.
    ///
    /// Returns up to `limit` matching `(RetrievalKey, score)` pairs ranked by
    /// tantivy BM25 relevance. Returns an empty vec when no text index is
    /// available (e.g. the graph was built without one).
    pub fn text_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.text_search",
            query = %query,
            limit = limit
        )
        .entered();
        match self.text_index {
            Some(ref ti) => ti.fuzzy_search(query, limit),
            None => Ok(Vec::new()),
        }
    }

    /// Document frequency of `term` in the text index (its rarest token's
    /// posting count), for IDF-style term-discrimination weighting by callers.
    /// Returns 0 when there is no text index or the term is unindexed.
    pub fn text_doc_frequency(&self, term: &str) -> usize {
        match self.text_index {
            Some(ref ti) => ti.doc_frequency(term),
            None => 0,
        }
    }

    /// Number of documents currently visible to text search (the N for IDF).
    /// Returns 0 when there is no text index.
    pub fn text_document_count(&self) -> usize {
        match self.text_index {
            Some(ref ti) => ti.live_document_count(),
            None => 0,
        }
    }

    pub fn resolve_retrieval_key(&self, key: &RetrievalKey) -> Option<ResolvedRetrievalItem> {
        let ent = self.entities.read();
        match key {
            RetrievalKey::Entity(entity_id) => ent
                .entities
                .get(entity_id)
                .cloned()
                .map(ResolvedRetrievalItem::Entity),
            RetrievalKey::EntityRevision(rev_id) => ent
                .entity_revisions
                .values()
                .flat_map(|revisions| revisions.iter())
                .find(|rev| rev.revision_id == *rev_id)
                .map(|rev| ResolvedRetrievalItem::Entity(rev.entity.clone())),
            RetrievalKey::Artifact(artifact_id) => {
                let file_path = ent.artifact_reverse.get(artifact_id)?;
                ent.shallow_files
                    .get(file_path)
                    .cloned()
                    .map(ResolvedRetrievalItem::ShallowFile)
                    .or_else(|| {
                        ent.structured_artifacts
                            .get(file_path)
                            .cloned()
                            .map(ResolvedRetrievalItem::StructuredArtifact)
                    })
                    .or_else(|| {
                        ent.opaque_artifacts
                            .get(file_path)
                            .cloned()
                            .map(ResolvedRetrievalItem::OpaqueArtifact)
                    })
            }
            RetrievalKey::ArtifactRevision(rev_id) => {
                let chg = self.changes.read();
                for change in chg.changes.values() {
                    for delta in &change.artifact_deltas {
                        if let Some(hash) = delta.new_hash {
                            let derived_id = ArtifactRevisionId::for_artifact_change(
                                &delta.file_id,
                                &change.id,
                                &hash,
                            );
                            if derived_id == *rev_id {
                                return Some(ResolvedRetrievalItem::ShallowFile(
                                    ShallowTrackedFile {
                                        file_id: delta.file_id.clone(),
                                        language_hint: String::new(),
                                        declaration_count: 0,
                                        import_count: 0,
                                        syntax_hash: hash,
                                        signature_hash: None,
                                        declaration_names: vec![],
                                        import_paths: vec![],
                                    },
                                ));
                            }
                        }
                    }
                }
                None
            }
        }
    }

    /// Get or lazily initialize the code embedder.
    ///
    /// Downloads the model from HuggingFace on first call (~270 MB).
    /// Subsequent calls return the cached instance.
    #[cfg(feature = "embeddings")]
    fn get_embedder(&self) -> Result<Arc<CodeEmbedder>, KinDbError> {
        let mut guard = self.embedder.lock();
        if let Some(ref e) = *guard {
            return Ok(Arc::clone(e));
        }
        let embedder = Arc::new(CodeEmbedder::new()?);
        *guard = Some(Arc::clone(&embedder));
        Ok(embedder)
    }

    /// Get or lazily initialize the HNSW vector index, self-healing a
    /// stale-dimension index in the process.
    ///
    /// This is the single sanctioned entry point to the in-memory vector index:
    /// the embed worker, semantic search, and every other caller reach it only
    /// through here. That is what lets the dimension-mismatch recovery be
    /// **exactly once**. When a persisted index of the wrong dimension is loaded
    /// against the live embedder (e.g. an older 384-dim `graph.kvec` vs a
    /// 768-dim model), the detect → reset → recreate steps all run under a
    /// single `vector_index` lock acquisition, so a racing caller can never
    /// observe the stale index and fire its own reset + full requeue. The old
    /// drop-the-guard-then-reset pattern allowed exactly that race, churning the
    /// embedding queue and pinning CPU; keeping the reset atomic is the kin-db
    /// side of the embed-worker dimension-loop contract.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn get_vector_index(&self) -> Result<Arc<VectorIndex>, KinDbError> {
        let embedder = self.get_embedder()?;
        let mut guard = self.vector_index.lock();

        let mut did_reset = false;
        if let Some(ref vi) = *guard {
            if vi.dimensions() == embedder.dimensions() {
                return Ok(Arc::clone(vi));
            }
            tracing::warn!(
                "LOUD WARNING: Vector index dimensions ({}) do not match embedder dimensions ({})! Resetting and re-queueing missing.",
                vi.dimensions(),
                embedder.dimensions()
            );
            // Inline reset under the held guard. Do NOT call
            // `self.reset_vector_index()` here: it re-locks `self.vector_index`
            // and would deadlock. Clearing in place keeps the swap atomic.
            *guard = None;
            did_reset = true;
        }

        let vi = Arc::new(VectorIndex::new(embedder.dimensions())?);
        *guard = Some(Arc::clone(&vi));
        drop(guard);

        if did_reset {
            // `queue_missing_*` lock `embedding_queue` + `entities` (never
            // `vector_index`), so they are safe to call now that the guard is
            // released. The fresh empty index reports every entity/artifact as
            // missing, re-queueing a full rebuild at the live embedder
            // dimension — and this runs once, only on the resetting caller.
            self.queue_missing_for_embedding();
            self.queue_missing_artifacts_for_embedding();
        }

        Ok(vi)
    }

    /// Embed specific entities and insert their vectors into the HNSW index.
    ///
    /// Called by explicit embedding flows when the vector index needs to be
    /// built or refreshed in-process.
    ///
    /// Returns the number of entities embedded.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn embed_entities(&self, entity_ids: &[EntityId]) -> Result<usize, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embed_entities", entity_ids = entity_ids.len()).entered();
        use crate::embed::format_graph_entity_text_with_context;

        if entity_ids.is_empty() {
            return Ok(0);
        }

        let embedder = self.get_embedder()?;
        let vi = self.get_vector_index()?;

        // Collect text representations under read lock, then drop before inference.
        let entity_data: Vec<(EntityId, String)> = {
            let ent = self.entities.read();
            entity_ids
                .iter()
                .filter_map(|id| {
                    ent.entities.get(id).map(|e| {
                        let context_lines = collect_embedding_context_lines(&ent, id);
                        let text = format_graph_entity_text_with_context(e, &context_lines);
                        (e.id, text)
                    })
                })
                .collect()
        };

        if entity_data.is_empty() {
            return Ok(0);
        }

        let batch_size = default_embedding_batch_size();
        let mut count = 0;
        for chunk in entity_data.chunks(batch_size) {
            let texts: Vec<String> = chunk.iter().map(|(_, t)| t.clone()).collect();
            let vectors = embedder.embed_batch(&texts)?;
            for ((id, _), vec) in chunk.iter().zip(vectors.iter()) {
                vi.upsert(*id, vec)?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Batch-embed all entities in the graph.
    ///
    /// Convenience method that embeds every entity. Useful for initial
    /// indexing or rebuilding the vector index from scratch.
    ///
    /// Returns the number of entities embedded.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn build_embeddings(&self) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!("kindb.build_embeddings").entered();
        let mut all_ids: Vec<EntityId> = {
            let ent = self.entities.read();
            ent.entities.keys().copied().collect()
        };
        // `entities.keys()` iterates in per-process HashMap order; embedding (and
        // therefore inserting into the order-sensitive HNSW) in that order builds a
        // different graph each run. Sort so a from-scratch build is byte-identical
        // across processes. (The incremental daemon path drains via the globally
        // sorted `EmbedSortKey`; this is the from-scratch/backfill convenience.)
        all_ids.sort_unstable();
        self.embed_entities(&all_ids)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn build_embeddings(&self) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Embed arbitrary retrieval documents and upsert them into the vector index.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn embed_retrievable_texts(
        &self,
        docs: &[(RetrievalKey, String)],
        batch_size: usize,
    ) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.embed_retrievable_texts",
            docs = docs.len(),
            batch_size = batch_size
        )
        .entered();
        if docs.is_empty() {
            return Ok(0);
        }

        let embedder = self.get_embedder()?;
        let vi = self.get_vector_index()?;
        let batch_size = batch_size.max(1);
        let mut count = 0usize;

        for chunk in docs.chunks(batch_size) {
            let texts: Vec<String> = chunk.iter().map(|(_, text)| text.clone()).collect();
            let vectors = embedder.embed_batch(&texts)?;
            for ((key, _), vector) in chunk.iter().zip(vectors.iter()) {
                vi.upsert_retrievable(*key, vector)?;
                count += 1;
            }
        }

        Ok(count)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn embed_retrievable_texts(
        &self,
        _docs: &[(RetrievalKey, String)],
        _batch_size: usize,
    ) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Load a persisted HNSW vector index from disk.
    ///
    /// Dimensions are read from the file — no embedder needed. This means
    /// semantic search works even when `embeddings` feature is off, as long
    /// as a pre-built index exists on disk.
    #[cfg(feature = "vector")]
    pub fn load_vector_index(&self, path: &std::path::Path) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.load_vector_index",
            path = %path.display()
        )
        .entered();
        if !path.exists() {
            return Ok(0);
        }

        let loaded = VectorIndex::load_from_disk(path)?;
        let count = loaded.len();
        *self.vector_index.lock() = Some(Arc::new(loaded));
        Ok(count)
    }

    /// Load a persisted index, rejecting it ONLY if it positively declares a
    /// model/graph identity incompatible with `expected` (a legacy unstamped
    /// index is grandfathered and still loads).
    ///
    /// Unlike [`InMemoryGraph::load_vector_index`], an incompatible or unreadable
    /// index is NOT installed and does NOT error — it returns
    /// [`VectorIndexLoad::Incompatible`] so the caller can archive + rebuild
    /// instead of crash-looping or serving silently-wrong neighbors. The in-memory
    /// index is left untouched on incompatibility.
    #[cfg(feature = "vector")]
    pub fn load_vector_index_compatible(
        &self,
        path: &std::path::Path,
        expected: &crate::vector::IndexDescriptor,
    ) -> crate::vector::VectorIndexLoad {
        use crate::vector::{IndexLoadOutcome, VectorIndexLoad};
        match VectorIndex::load_compatible_grandfathered(path, expected) {
            IndexLoadOutcome::Loaded(index) => {
                let count = index.len();
                *self.vector_index.lock() = Some(Arc::new(index));
                VectorIndexLoad::Loaded(count)
            }
            IndexLoadOutcome::Incompatible(reason) => VectorIndexLoad::Incompatible(reason),
        }
    }

    #[cfg(feature = "vector")]
    pub fn save_vector_index(&self, path: &std::path::Path) -> Result<(), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.save_vector_index",
            path = %path.display()
        )
        .entered();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create vector index directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Only a graph that holds a populated index in memory writes the
        // sidecar. An in-memory `None` means the index was never loaded for
        // this graph (e.g. it was skipped as stale on reopen) — it does NOT
        // mean the repo has no vectors. Deleting the on-disk sidecar here would
        // silently destroy graph-owned truth that a later embed pass or a
        // matching reopen could have reused, so an unloaded index leaves the
        // persisted sidecar untouched. A genuinely stale sidecar is rejected on
        // load by `load_vector_index_if_valid` (root-hash check) and rebuilt
        // from the embedding queue, never by a destructive write here.
        if let Some(ref index) = *self.vector_index.lock() {
            index.save(path)?;
        }

        Ok(())
    }

    /// Stamp the in-memory vector index's self-description (embedding model
    /// identity + graph provenance) so the next `save_vector_index` persists it
    /// into the `.kvec`. A later load can then prove the stored vectors were
    /// produced by the expected model/graph and refuse silently-wrong neighbors,
    /// independently of the sidecar metadata. No-op when no index is loaded.
    #[cfg(feature = "vector")]
    pub fn stamp_vector_index_descriptor(&self, descriptor: crate::vector::IndexDescriptor) {
        if let Some(ref index) = *self.vector_index.lock() {
            index.set_descriptor(descriptor);
        }
    }

    #[cfg(feature = "embeddings")]
    pub fn share_embedder_from(&self, source: &InMemoryGraph) {
        let source_embedder = source.embedder.lock().clone();
        if let Some(e) = source_embedder {
            *self.embedder.lock() = Some(e);
        }
    }

    /// Returns `(dimensions, indexed_count)` for the loaded vector index, or
    /// `None` when no index is loaded for this graph. Available with the
    /// `vector` feature alone — it reads index metadata and needs no embedder.
    #[cfg(feature = "vector")]
    pub fn vector_index_stats(&self) -> Option<(usize, usize)> {
        self.vector_index
            .lock()
            .as_ref()
            .map(|index| (index.dimensions(), index.len()))
    }

    /// Semantic similarity search across all embedded entities.
    ///
    /// Embeds the query text using the code embedding model, then searches
    /// the HNSW vector index for the nearest neighbours.
    ///
    /// Returns up to `limit` `(RetrievalKey, distance)` pairs sorted by similarity.
    /// Returns an empty vec when embeddings are not yet built or features
    /// are disabled.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.semantic_search",
            query = %query,
            limit = limit
        )
        .entered();

        // An unpopulated vector index is a valid graph state, not an error:
        // `kin init` only queues embeddings, so the index can legitimately be
        // missing or empty until an explicit embed pass runs. Degrade to an
        // empty result here (callers fall back to text search) instead of
        // loading the embedder and failing. A populated index that then fails
        // to embed/search the query still surfaces the error via `?`.
        let vi = match &*self.vector_index.lock() {
            Some(vi) if !vi.is_empty() => Arc::clone(vi),
            _ => return Ok(Vec::new()),
        };

        let embedder = self.get_embedder()?;
        let vector = embedder.embed_text(query)?;
        vi.search_similar(&vector, limit)
    }

    /// Semantic similarity search (stub when features are disabled).
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn semantic_search(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        Ok(Vec::new())
    }

    /// Batched semantic similarity search across all embedded entities.
    ///
    /// Embeds all query texts in a single `embed_batch` call (one forward pass)
    /// instead of N separate `embed_text` calls, then searches the HNSW vector
    /// index for each resulting vector.
    ///
    /// Returns one `Vec<(RetrievalKey, distance)>` per query, in input order.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search_batch(
        &self,
        queries: &[&str],
        limit: usize,
    ) -> Result<Vec<Vec<(RetrievalKey, f32)>>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.semantic_search_batch",
            num_queries = queries.len(),
            limit = limit
        )
        .entered();

        if queries.is_empty() {
            return Ok(Vec::new());
        }

        // Mirror `semantic_search`: an empty/unpopulated index degrades to one
        // empty result per query rather than loading the embedder and failing.
        let vi = match &*self.vector_index.lock() {
            Some(vi) if !vi.is_empty() => Arc::clone(vi),
            _ => return Ok(vec![Vec::new(); queries.len()]),
        };

        let embedder = self.get_embedder()?;

        let texts: Vec<String> = queries.iter().map(|q| q.to_string()).collect();
        let vectors = embedder.embed_query_batch(&texts)?;

        let mut results = Vec::with_capacity(vectors.len());
        for vector in &vectors {
            results.push(vi.search_similar(vector, limit)?);
        }
        Ok(results)
    }

    /// Batched semantic similarity search with a predicate filter.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search_batch_filtered<P>(
        &self,
        queries: &[&str],
        limit: usize,
        predicate: P,
    ) -> Result<Vec<Vec<(RetrievalKey, f32)>>, KinDbError>
    where
        P: Fn(&RetrievalKey) -> bool,
    {
        let _span = tracing::info_span!(
            "kindb.semantic_search_batch_filtered",
            num_queries = queries.len(),
            limit = limit
        )
        .entered();

        if queries.is_empty() {
            return Ok(Vec::new());
        }

        let vi = match &*self.vector_index.lock() {
            Some(vi) if !vi.is_empty() => Arc::clone(vi),
            _ => return Ok(vec![Vec::new(); queries.len()]),
        };

        let embedder = self.get_embedder()?;

        let texts: Vec<String> = queries.iter().map(|q| q.to_string()).collect();
        let vectors = embedder.embed_query_batch(&texts)?;

        let mut results = Vec::with_capacity(vectors.len());
        for vector in &vectors {
            results.push(vi.search_similar_filtered(vector, limit, &predicate)?);
        }
        Ok(results)
    }

    /// Batched semantic similarity search (stub when features are disabled).
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn semantic_search_batch(
        &self,
        queries: &[&str],
        _limit: usize,
    ) -> Result<Vec<Vec<(RetrievalKey, f32)>>, KinDbError> {
        Ok(vec![Vec::new(); queries.len()])
    }

    // -----------------------------------------------------------------------
    // Embedding queue — progressive, non-blocking embedding pipeline
    // -----------------------------------------------------------------------

    /// Number of entities waiting to be embedded.
    #[cfg(feature = "vector")]
    pub fn pending_embeddings(&self) -> usize {
        self.embedding_queue.lock().len()
    }

    /// Number of entities waiting to be embedded (stub).
    #[cfg(not(feature = "vector"))]
    pub fn pending_embeddings(&self) -> usize {
        0
    }

    /// Number of artifacts waiting to be embedded.
    #[cfg(feature = "vector")]
    pub fn pending_artifact_embeddings(&self) -> usize {
        self.artifact_embedding_queue.lock().len()
    }

    /// Number of artifacts waiting to be embedded (stub).
    #[cfg(not(feature = "vector"))]
    pub fn pending_artifact_embeddings(&self) -> usize {
        0
    }

    /// Manually queue entity IDs for embedding (e.g., after bulk import).
    #[cfg(feature = "vector")]
    pub fn queue_for_embedding(&self, ids: &[EntityId]) {
        let mut queue = self.embedding_queue.lock();
        for id in ids {
            queue.insert(RetrievalKey::Entity(*id), EmbedRecency::Backfill);
        }
    }

    /// Manually queue retrieval keys for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_keys_for_embedding(&self, keys: &[RetrievalKey]) {
        let mut queue = self.embedding_queue.lock();
        for key in keys {
            queue.insert(*key, EmbedRecency::Backfill);
        }
    }

    /// Manually queue artifact IDs for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_artifacts_for_embedding(&self, ids: &[ArtifactId]) {
        let mut queue = self.artifact_embedding_queue.lock();
        for id in ids {
            queue.insert(*id, EmbedRecency::Backfill);
        }
    }

    /// Queue every entity in the graph for a from-scratch embedding pass: the
    /// HEAD revision of each entity plus every current HEAD entity.
    ///
    /// Only the latest revision of each entity is queued — superseded
    /// generations are not retrieval truth and would be evicted by
    /// `prune_orphaned_vectors`, so embedding them on a rebuild is pure waste
    /// (and reintroduces the doubled-vector state this convergence fixes,
    /// FIR-937). This matches the target set of `graph_truth_retrievable_keys`.
    #[cfg(feature = "vector")]
    pub fn queue_all_for_embedding(&self) {
        let mut queue = self.embedding_queue.lock();
        let ent = self.entities.read();

        // Queue the HEAD revision of each entity.
        for key in latest_revision_ids(&ent).map(RetrievalKey::EntityRevision) {
            queue.insert(key, EmbedRecency::Backfill);
        }

        // Queue all current HEAD entities
        for id in ent.entities.keys() {
            queue.insert(RetrievalKey::Entity(*id), EmbedRecency::Backfill);
        }
    }

    /// Queue all graph-owned artifacts for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_all_artifacts_for_embedding(&self) {
        let ids = {
            let ent = self.entities.read();
            collect_artifact_ids(&ent)
        };
        self.queue_artifacts_for_embedding(&ids);
    }

    #[cfg(not(feature = "vector"))]
    pub fn queue_all_artifacts_for_embedding(&self) {}

    /// Queue only entities and revisions that do not already have vectors in the current index.
    #[cfg(feature = "vector")]
    pub fn queue_missing_for_embedding(&self) {
        let vector_index = self.vector_index.lock().clone();
        let mut queue = self.embedding_queue.lock();
        let ent = self.entities.read();

        // Queue only the missing HEAD revision of each entity. Superseded
        // generations are deliberately NOT enqueued: they are not retrieval
        // truth (see `graph_truth_retrievable_keys`) and `prune_orphaned_vectors`
        // evicts them — enqueuing them would re-embed a key the prune removes on
        // the next pass, churning forever (FIR-937).
        for key in latest_revision_ids(&ent).map(RetrievalKey::EntityRevision) {
            let missing = vector_index
                .as_ref()
                .map(|vi| !vi.contains_retrievable(&key))
                .unwrap_or(true);
            if missing {
                queue.insert(key, EmbedRecency::Backfill);
            }
        }

        // Queue missing HEAD entities
        for id in ent.entities.keys() {
            let key = RetrievalKey::Entity(*id);
            let missing = vector_index
                .as_ref()
                .map(|vi| !vi.contains_retrievable(&key))
                .unwrap_or(true);
            if missing {
                queue.insert(key, EmbedRecency::Backfill);
            }
        }
    }

    /// Propagate vectors from already-embedded revisions to later revisions with
    /// identical entity fingerprints, avoiding redundant GPU inference.
    ///
    /// Many consecutive revisions of the same entity share identical content —
    /// they were "modified" only because a neighbouring entity changed in the
    /// same commit, causing span/line-number shifts. When
    /// `(ast_hash, signature_hash, behavior_hash)` all match between a revision
    /// that already has a vector and one that does not, we can safely copy the
    /// vector instead of re-embedding.
    ///
    /// Returns the number of vectors propagated.
    #[cfg(feature = "vector")]
    pub fn propagate_revision_vectors(&self) -> usize {
        let _span = tracing::info_span!("kindb.propagate_revision_vectors").entered();

        // Clone the Arc out of the Mutex so we don't hold the lock during the
        // (potentially large) iteration.
        let vi = match self.vector_index.lock().clone() {
            Some(vi) => vi,
            None => return 0,
        };

        let ent = self.entities.read();

        // Build a global revision-id → EntityRevision lookup so we can resolve
        // `previous_revision: Option<EntityRevisionId>` cheaply.
        let mut rev_by_id: hashbrown::HashMap<EntityRevisionId, &EntityRevision> =
            hashbrown::HashMap::new();
        for revisions in ent.entity_revisions.values() {
            for rev in revisions {
                rev_by_id.insert(rev.revision_id, rev);
            }
        }

        let mut propagated: usize = 0;

        // Iterate revision chains in a deterministic order. `entity_revisions` is
        // a HashMap, so `.values()` visits chains in per-process order; because
        // each propagated vector is upserted into the order-sensitive HNSW, that
        // would make the built index (and the persisted `.kvec`) differ run to
        // run. Sort by the owning entity id so insertion order is reproducible.
        // Eligibility itself is order-independent — it depends only on fingerprints
        // and the fully-built `rev_by_id` lookup, plus the per-chain `last_vectored`
        // cursor — never on which chain ran first.
        let mut chain_owner_ids: Vec<EntityId> = ent.entity_revisions.keys().copied().collect();
        chain_owner_ids.sort_unstable();
        for owner_id in &chain_owner_ids {
            let revisions = &ent.entity_revisions[owner_id];
            // Walk the chronological revision list. Track the most recent
            // revision id that is known to have a vector (either because it was
            // already in the index, or because we just propagated one to it).
            let mut last_vectored: Option<EntityRevisionId> = None;

            for rev in revisions {
                let key = RetrievalKey::EntityRevision(rev.revision_id);

                if vi.contains_retrievable(&key) {
                    // Already embedded — remember it as a potential source.
                    last_vectored = Some(rev.revision_id);
                    continue;
                }

                // Missing vector. Try to propagate from `previous_revision` if
                // the fingerprints match.
                if let Some(prev_id) = &rev.previous_revision {
                    if let Some(prev_rev) = rev_by_id.get(prev_id) {
                        if prev_rev.entity.fingerprint.ast_hash == rev.entity.fingerprint.ast_hash
                            && prev_rev.entity.fingerprint.signature_hash
                                == rev.entity.fingerprint.signature_hash
                            && prev_rev.entity.fingerprint.behavior_hash
                                == rev.entity.fingerprint.behavior_hash
                        {
                            let source_key = RetrievalKey::EntityRevision(*prev_id);
                            if let Some(vector) = vi.get_retrievable(&source_key) {
                                let _ = vi.upsert_retrievable(key, &vector);
                                propagated += 1;
                                last_vectored = Some(rev.revision_id);
                                continue;
                            }
                        }
                    }
                }

                // Fallback: try the last vectored revision in the same entity's
                // chronological list (covers cases where `previous_revision` is
                // None but the prior sibling has an identical fingerprint).
                if let Some(source_id) = last_vectored {
                    if let Some(source_rev) = rev_by_id.get(&source_id) {
                        if source_rev.entity.fingerprint.ast_hash == rev.entity.fingerprint.ast_hash
                            && source_rev.entity.fingerprint.signature_hash
                                == rev.entity.fingerprint.signature_hash
                            && source_rev.entity.fingerprint.behavior_hash
                                == rev.entity.fingerprint.behavior_hash
                        {
                            let source_key = RetrievalKey::EntityRevision(source_id);
                            if let Some(vector) = vi.get_retrievable(&source_key) {
                                let _ = vi.upsert_retrievable(key, &vector);
                                propagated += 1;
                                last_vectored = Some(rev.revision_id);
                                continue;
                            }
                        }
                    }
                }

                // No propagation possible — this revision stays un-vectored and
                // will be picked up by the normal embedding queue.
            }
        }

        tracing::info!(
            propagated = propagated,
            "propagate_revision_vectors complete"
        );
        propagated
    }

    /// Propagate revision vectors (stub when vector feature is disabled).
    #[cfg(not(feature = "vector"))]
    pub fn propagate_revision_vectors(&self) -> usize {
        0
    }

    /// Queue only artifacts that do not already have vectors in the current index.
    #[cfg(feature = "vector")]
    pub fn queue_missing_artifacts_for_embedding(&self) {
        let vector_index = self.vector_index.lock().clone();
        let ids: Vec<ArtifactId> = {
            let ent = self.entities.read();
            collect_artifact_ids(&ent)
                .into_iter()
                .filter(|id| {
                    let key = RetrievalKey::Artifact(*id);
                    vector_index
                        .as_ref()
                        .map(|vi| !vi.contains_retrievable(&key))
                        .unwrap_or(true)
                })
                .collect()
        };
        self.queue_artifacts_for_embedding(&ids);
    }

    #[cfg(not(feature = "vector"))]
    pub fn queue_missing_artifacts_for_embedding(&self) {}

    /// Drop the in-memory vector index so the next embedding pass rebuilds it
    /// from scratch at the CURRENT embedder dimension.
    ///
    /// This is the migration path for a repo whose persisted index was built at
    /// a different embedding dimension (e.g. an older 384-dim model) than the
    /// model now in use (768-dim). A normal embed pass reuses the loaded index
    /// and upserts fail with a dimension mismatch; clearing the in-memory index
    /// lets `queue_missing_for_embedding` re-queue every entity/artifact (the
    /// emptied index reports nothing as indexed) and `get_vector_index` lazily
    /// recreate the index sized to the live embedder.
    ///
    /// The on-disk sidecar is intentionally left untouched here: the per-batch
    /// persist that follows a rebuild overwrites it with the freshly-sized
    /// index, so there is no window where graph-owned vector truth is destroyed
    /// before its replacement exists.
    #[cfg(feature = "vector")]
    pub fn reset_vector_index(&self) {
        let _span = tracing::info_span!("kindb.reset_vector_index").entered();
        *self.vector_index.lock() = None;
    }

    #[cfg(not(feature = "vector"))]
    pub fn reset_vector_index(&self) {}

    /// Share another graph's vector index by cloning its `Arc`. The scoped
    /// graph can then search the HEAD index directly; callers filter results
    /// for scope membership (stable-key filtering in locate already does this).
    #[cfg(feature = "vector")]
    pub fn share_vector_index_from(&self, source: &InMemoryGraph) {
        let src_guard = source.vector_index.lock();
        if let Some(ref vi) = *src_guard {
            *self.vector_index.lock() = Some(Arc::clone(vi));
        }
    }

    #[cfg(not(feature = "vector"))]
    pub fn share_vector_index_from(&self, _source: &InMemoryGraph) {}

    /// Drain up to `batch_size` keys from the entity embedding queue in a
    /// deterministic order, leaving the remainder queued.
    ///
    /// This is the single ordering authority for entity embedding batches. The
    /// returned order is a pure function of the queued work (and, once the
    /// priority-signals layer lands, graph state); it never observes the
    /// queue's HashMap iteration order, so two processes that queued the same
    /// work drain identical batches in the identical order. That determinism is
    /// what removes the per-process batch-composition variance behind the embed
    /// determinism bug.
    #[cfg(feature = "vector")]
    fn drain_embedding_batch(&self, batch_size: usize) -> Vec<(RetrievalKey, EmbedRecency)> {
        let batch_size = batch_size.max(1);
        let drained = {
            let mut queue = self.embedding_queue.lock();
            queue.drain_all()
        };
        if drained.is_empty() {
            return Vec::new();
        }

        // Compute a deterministic priority sort key for each item from current
        // graph state (tier → recency → centrality → id), then order ascending
        // so the smallest — highest-priority — item embeds first. The sort is
        // GLOBAL over the entire drained queue and happens BEFORE the caller
        // chunks the returned batch for inference, so priority is never merely
        // per-chunk. (O(n) key build + O(n log n) sort; see `embed_sort_key_for`
        // for the per-key O(1) bound.)
        let mut keyed: Vec<(EmbedSortKey, RetrievalKey, EmbedRecency)> = {
            let ent = self.entities.read();
            drained
                .into_iter()
                .map(|(key, recency)| (embed_sort_key_for(&ent, key, recency), key, recency))
                .collect()
        };
        keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let take = batch_size.min(keyed.len());
        let leftover = keyed.split_off(take);
        if !leftover.is_empty() {
            let mut queue = self.embedding_queue.lock();
            for (_, key, recency) in leftover {
                queue.insert(key, recency);
            }
        }
        keyed
            .into_iter()
            .map(|(_, key, recency)| (key, recency))
            .collect()
    }

    /// Drain up to `batch_size` artifact IDs from the artifact embedding queue
    /// in a deterministic order, leaving the remainder queued.
    ///
    /// Mirrors [`InMemoryGraph::drain_embedding_batch`] for artifacts. This
    /// replaces the previous raw `HashSet::iter()` drain, whose per-process
    /// iteration order made artifact batch composition nondeterministic.
    #[cfg(feature = "vector")]
    fn drain_artifact_embedding_batch(&self, batch_size: usize) -> Vec<(ArtifactId, EmbedRecency)> {
        let batch_size = batch_size.max(1);
        let mut all = {
            let mut queue = self.artifact_embedding_queue.lock();
            queue.drain_all()
        };
        if all.is_empty() {
            return Vec::new();
        }

        // Deterministic total order: recency first (changed-this-sync before
        // backfill), then the artifact id as the stable tiebreak. (Artifacts
        // carry less semantic structure than entities, so recency + id is the
        // honest priority signal available without extra lookups.)
        all.sort_unstable_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

        let take = batch_size.min(all.len());
        let leftover = all.split_off(take);
        if !leftover.is_empty() {
            let mut queue = self.artifact_embedding_queue.lock();
            for (id, recency) in leftover {
                queue.insert(id, recency);
            }
        }
        all
    }

    /// Drain the current pending embedding queue in batches.
    ///
    /// This is the graph-first incremental path: graph mutations enqueue
    /// changed entities, and callers process only that pending work.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_all_pending_embeddings(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_all_pending_embeddings",
            batch_size = batch_size
        )
        .entered();
        let mut total = 0usize;
        let initial_pending = self.pending_embeddings();
        let start_time = std::time::Instant::now();
        loop {
            let pending = self.pending_embeddings();
            if pending == 0 {
                break;
            }
            let processed = self.process_embedding_queue(batch_size)?;
            if processed == 0 {
                break;
            }
            total += processed;
            if initial_pending > 0 {
                let percent = (total * 100) / initial_pending;
                eprint!(
                    "\r  Embedding Entities: [{}/{}] {}% | {:.1}s",
                    total,
                    initial_pending,
                    percent,
                    start_time.elapsed().as_secs_f64()
                );
            }
        }
        if initial_pending > 0 {
            eprintln!();
        }
        // Drain complete — reconcile the index to graph truth so superseded
        // revision generations do not survive the pass.
        self.prune_orphaned_vectors();
        Ok(total)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_all_pending_embeddings(&self, _batch_size: usize) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Drain the current pending artifact embedding queue in batches.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_all_pending_artifact_embeddings(
        &self,
        batch_size: usize,
    ) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_all_pending_artifact_embeddings",
            batch_size = batch_size
        )
        .entered();
        let mut total = 0usize;
        let initial_pending = self.pending_artifact_embeddings();
        let start_time = std::time::Instant::now();
        loop {
            let pending = self.pending_artifact_embeddings();
            if pending == 0 {
                break;
            }
            let processed = self.process_artifact_embedding_queue(batch_size)?;
            if processed == 0 {
                break;
            }
            total += processed;
            if initial_pending > 0 {
                let percent = (total * 100) / initial_pending;
                eprint!(
                    "\r  Embedding Artifacts: [{}/{}] {}% | {:.1}s",
                    total,
                    initial_pending,
                    percent,
                    start_time.elapsed().as_secs_f64()
                );
            }
        }
        if initial_pending > 0 {
            eprintln!();
        }
        Ok(total)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_all_pending_artifact_embeddings(
        &self,
        _batch_size: usize,
    ) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Process up to `batch_size` items from the embedding queue.
    ///
    /// Drains keys from the queue, generates embeddings via the
    /// CodeEmbedder, and inserts them into the HNSW VectorIndex.
    /// Returns the number of items successfully embedded.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_embedding_queue(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span =
            tracing::info_span!("kindb.process_embedding_queue", batch_size = batch_size).entered();
        use crate::embed::format_graph_entity_text;
        use crate::embed::format_graph_entity_text_with_context;

        let batch_size = batch_size.max(1);

        // Drain a deterministic, priority-ordered batch. `drain_embedding_batch`
        // is the single ordering authority: it sorts queued work by a stable
        // total order, so batch composition depends only on queue contents and
        // graph state — never on map iteration order — and is identical across
        // processes.
        let batch = self.drain_embedding_batch(batch_size);
        if batch.is_empty() {
            return Ok(0);
        }

        // Preserve each key's recency so an error-requeue cannot silently demote
        // changed-this-sync work to backfill.
        let batch_recency: hashbrown::HashMap<RetrievalKey, EmbedRecency> =
            batch.iter().copied().collect();
        let batch_keys: Vec<RetrievalKey> = batch.iter().map(|(key, _)| *key).collect();

        let requeue = |keys: &[RetrievalKey]| {
            if keys.is_empty() {
                return;
            }
            let mut queue = self.embedding_queue.lock();
            for key in keys {
                let recency = batch_recency
                    .get(key)
                    .copied()
                    .unwrap_or(EmbedRecency::Backfill);
                queue.insert(*key, recency);
            }
        };

        // Collect text representations under read lock, then drop before inference.
        let mut entity_data: Vec<(RetrievalKey, String)> = Vec::with_capacity(batch_keys.len());
        {
            let ent = self.entities.read();

            // Build a lookup map for any EntityRevisionId in the batch
            let mut rev_ids = hashbrown::HashSet::new();
            for key in &batch_keys {
                if let RetrievalKey::EntityRevision(rev_id) = key {
                    rev_ids.insert(*rev_id);
                }
            }

            let mut rev_lookup = hashbrown::HashMap::new();
            if !rev_ids.is_empty() {
                'outer: for revisions_vec in ent.entity_revisions.values() {
                    for rev in revisions_vec {
                        if rev_ids.contains(&rev.revision_id) {
                            rev_lookup.insert(rev.revision_id, rev.clone());
                            if rev_lookup.len() == rev_ids.len() {
                                break 'outer;
                            }
                        }
                    }
                }
            }

            for key in &batch_keys {
                match key {
                    RetrievalKey::Entity(entity_id) => {
                        if let Some(e) = ent.entities.get(entity_id) {
                            let context_lines = collect_embedding_context_lines(&ent, entity_id);
                            entity_data.push((
                                *key,
                                format_graph_entity_text_with_context(e, &context_lines),
                            ));
                        }
                    }
                    RetrievalKey::EntityRevision(rev_id) => {
                        if let Some(rev) = rev_lookup.get(rev_id) {
                            entity_data.push((*key, format_graph_entity_text(&rev.entity)));
                        }
                    }
                    _ => {}
                }
            }
        }

        if entity_data.is_empty() {
            return Ok(0);
        }

        let embedder = match self.get_embedder() {
            Ok(embedder) => embedder,
            Err(err) => {
                requeue(&batch_keys);
                return Err(err);
            }
        };
        let vi = match self.get_vector_index() {
            Ok(index) => index,
            Err(err) => {
                requeue(&batch_keys);
                return Err(err);
            }
        };

        let embed_batch_size = batch_size.max(1);
        let mut count = 0;
        for (chunk_idx, chunk) in entity_data.chunks(embed_batch_size).enumerate() {
            let texts: Vec<String> = chunk.iter().map(|(_, t)| t.clone()).collect();
            let vectors = match embedder.embed_batch(&texts) {
                Ok(vectors) => vectors,
                Err(err) => {
                    let start_idx = (chunk_idx * embed_batch_size).min(entity_data.len());
                    let remaining_keys: Vec<RetrievalKey> = entity_data[start_idx..]
                        .iter()
                        .map(|(key, _)| *key)
                        .collect();
                    requeue(&remaining_keys);
                    return Err(err);
                }
            };
            for (item_idx, ((key, _), vec)) in chunk.iter().zip(vectors.iter()).enumerate() {
                if let Err(err) = vi.upsert_retrievable(*key, vec) {
                    let mut remaining_keys: Vec<RetrievalKey> = chunk[item_idx..]
                        .iter()
                        .map(|(rest_key, _)| *rest_key)
                        .collect();

                    let next_chunk_start =
                        ((chunk_idx + 1) * embed_batch_size).min(entity_data.len());
                    remaining_keys.extend(
                        entity_data[next_chunk_start..]
                            .iter()
                            .map(|(rest_key, _)| *rest_key),
                    );
                    requeue(&remaining_keys);
                    return Err(err);
                }
                count += 1;
            }
        }

        // Live retire: when this batch drains the entity queue, a re-embed that
        // appended a new revision (and embedded its key) has left the entity's
        // prior revision vector behind. Reconcile the index to graph truth so the
        // superseded generation is retired now, instead of accumulating until the
        // next daemon boot's load-time reclaim. Gated on the queue being empty so
        // a multi-batch backfill prunes once at the end (O(index) per drain, not
        // per batch) rather than rescanning the whole index after every chunk.
        if count > 0 && self.embedding_queue.lock().is_empty() {
            self.prune_orphaned_vectors();
        }

        Ok(count)
    }

    /// Process embedding queue (stub when features are disabled).
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_embedding_queue(&self, _batch_size: usize) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Process up to `batch_size` artifacts from the embedding queue.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_artifact_embedding_queue(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_artifact_embedding_queue",
            batch_size = batch_size
        )
        .entered();

        let batch_size = batch_size.max(1);

        // Deterministic, dedup-preserving drain (single ordering authority).
        let batch = self.drain_artifact_embedding_batch(batch_size);
        if batch.is_empty() {
            return Ok(0);
        }

        // Preserve each id's recency so an error-requeue cannot demote
        // changed-this-sync work to backfill.
        let batch_recency: hashbrown::HashMap<ArtifactId, EmbedRecency> =
            batch.iter().copied().collect();
        let ids: Vec<ArtifactId> = batch.iter().map(|(id, _)| *id).collect();

        let requeue = |ids: &[ArtifactId]| {
            if ids.is_empty() {
                return;
            }
            let mut queue = self.artifact_embedding_queue.lock();
            for id in ids {
                let recency = batch_recency
                    .get(id)
                    .copied()
                    .unwrap_or(EmbedRecency::Backfill);
                queue.insert(*id, recency);
            }
        };

        let docs: Vec<(ArtifactId, RetrievalKey, String)> = {
            let ent = self.entities.read();
            ids.iter()
                .filter_map(|artifact_id| {
                    artifact_embedding_doc(&ent, artifact_id)
                        .map(|(key, text)| (*artifact_id, key, text))
                })
                .collect()
        };

        if docs.is_empty() {
            return Ok(0);
        }

        let embedder = match self.get_embedder() {
            Ok(embedder) => embedder,
            Err(err) => {
                requeue(&ids);
                return Err(err);
            }
        };
        let vi = match self.get_vector_index() {
            Ok(index) => index,
            Err(err) => {
                requeue(&ids);
                return Err(err);
            }
        };

        let embed_batch_size = batch_size.max(1);
        let mut count = 0usize;
        for (chunk_idx, chunk) in docs.chunks(embed_batch_size).enumerate() {
            let texts: Vec<String> = chunk.iter().map(|(_, _, text)| text.clone()).collect();
            let vectors = match embedder.embed_batch(&texts) {
                Ok(vectors) => vectors,
                Err(err) => {
                    let remaining_ids: Vec<ArtifactId> = docs[chunk_idx * embed_batch_size..]
                        .iter()
                        .map(|(artifact_id, _, _)| *artifact_id)
                        .collect();
                    requeue(&remaining_ids);
                    return Err(err);
                }
            };

            for (item_idx, ((_, key, _), vector)) in chunk.iter().zip(vectors.iter()).enumerate() {
                if let Err(err) = vi.upsert_retrievable(*key, vector) {
                    let mut remaining_ids: Vec<ArtifactId> = chunk[item_idx..]
                        .iter()
                        .map(|(artifact_id, _, _)| *artifact_id)
                        .collect();
                    remaining_ids.extend(
                        docs[(chunk_idx + 1) * embed_batch_size..]
                            .iter()
                            .map(|(artifact_id, _, _)| *artifact_id),
                    );
                    requeue(&remaining_ids);
                    return Err(err);
                }
                count += 1;
            }
        }

        Ok(count)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_artifact_embedding_queue(
        &self,
        _batch_size: usize,
    ) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Every retrieval key that participates in semantic embedding under the
    /// CURRENT graph truth: the LATEST revision of each entity, all HEAD
    /// entities, and all graph-owned artifacts. This is the authoritative target
    /// set the vector index should converge to — a key in the index but absent
    /// here is a stale generation that must be evicted.
    ///
    /// Only the latest revision per entity is admitted (not every historical
    /// generation). The live `reconcile → re-embed` path appends a new
    /// `EntityRevision` each time an entity's content changes; admitting every
    /// generation as truth made `prune_orphaned_vectors` keep the superseded
    /// vectors forever (they are still "referenced" by the revision history), so
    /// each entity accumulated one vector per edit and `semantic_locate`
    /// returned it once per generation. Pinning truth to the head revision lets
    /// the existing prune reclaim those superseded generations, leaving one
    /// revision vector per live entity (FIR-937).
    #[cfg(feature = "vector")]
    fn graph_truth_retrievable_keys(&self) -> hashbrown::HashSet<RetrievalKey> {
        let ent = self.entities.read();
        let mut keys = hashbrown::HashSet::new();
        keys.extend(latest_revision_ids(&ent).map(RetrievalKey::EntityRevision));
        keys.extend(ent.entities.keys().map(|id| RetrievalKey::Entity(*id)));
        keys.extend(
            collect_artifact_ids(&ent)
                .into_iter()
                .map(RetrievalKey::Artifact),
        );
        keys
    }

    /// Evict vectors whose keys no longer exist in graph truth (generation
    /// eviction).
    ///
    /// Two sources feed generation accumulation, both reclaimed here:
    ///
    /// - Re-init mints fresh `SemanticChangeId`s, so every entity gets a
    ///   brand-new `EntityRevision` key each cycle. The prior generation's
    ///   revision keys — orphaned the moment the graph dropped them — keep their
    ///   vectors and the persisted sidecar carries them forward.
    /// - The live `reconcile → re-embed` path appends a new `EntityRevision`
    ///   each time an entity's content changes while its earlier generation
    ///   stays in the revision history. The superseded vector lingers because the
    ///   old revision is still "referenced"; truth (`graph_truth_retrievable_keys`)
    ///   admits only the head revision, so it falls out here (FIR-937).
    ///
    /// Across re-init/re-embed cycles the index otherwise accumulates
    /// generations that all compete in ANN retrieval and return the same entity
    /// once per generation.
    ///
    /// This reconciles the index back to graph truth: any indexed key not in the
    /// current retrievable set is removed. Returns the number of vectors evicted.
    /// Idempotent and cheap when the index is already clean.
    #[cfg(feature = "vector")]
    pub fn prune_orphaned_vectors(&self) -> usize {
        let _span = tracing::info_span!("kindb.prune_orphaned_vectors").entered();

        let vi = match self.vector_index.lock().clone() {
            Some(vi) => vi,
            None => return 0,
        };

        let truth = self.graph_truth_retrievable_keys();
        let mut orphans: Vec<RetrievalKey> = vi
            .retrievable_keys()
            .into_iter()
            .filter(|key| !truth.contains(key))
            .collect();
        // `retrievable_keys()` returns keys in the index's per-process HashMap
        // order. Evicting in that order makes the resulting `free_list` push order
        // (and thus the slot a later re-embed reuses) vary across daemon boots,
        // which perturbs approximate-kNN neighbors at the candidate-set boundary.
        // Sort by the key's total order so eviction — and the index state it
        // leaves behind — is identical regardless of the map seed.
        orphans.sort_unstable();

        let mut evicted = 0usize;
        for key in &orphans {
            if vi.remove_retrievable(key).is_ok() {
                evicted += 1;
            }
        }

        if evicted > 0 {
            tracing::info!(evicted, "pruned orphaned vectors from index");
        }
        evicted
    }

    /// Prune orphaned vectors (stub when vector feature is disabled).
    #[cfg(not(feature = "vector"))]
    pub fn prune_orphaned_vectors(&self) -> usize {
        0
    }

    /// Get the current embedding status.
    ///
    /// The returned `pending` field is `max(queue_length, total - indexed)` so
    /// that coverage gates remain correct when entities exist that have not
    /// yet been queued for embedding (the steady state after loading a graph
    /// whose embedding queue does not persist across restarts).
    pub fn embedding_status(&self) -> EmbeddingStatus {
        #[cfg(feature = "vector")]
        let (queue_len, indexed, total) = {
            let queue_len =
                self.embedding_queue.lock().len() + self.artifact_embedding_queue.lock().len();
            let retrievable_keys = self.graph_truth_retrievable_keys();
            let total = retrievable_keys.len();
            let indexed = self
                .vector_index
                .lock()
                .as_ref()
                .map(|vi| {
                    retrievable_keys
                        .iter()
                        .filter(|key| vi.contains_retrievable(key))
                        .count()
                })
                .unwrap_or(0);
            (queue_len, indexed, total)
        };
        #[cfg(not(feature = "vector"))]
        let (queue_len, indexed, total) = (0usize, 0usize, self.entity_count());

        let pending = queue_len.max(total.saturating_sub(indexed));
        EmbeddingStatus {
            pending,
            indexed,
            total,
        }
    }

    /// Batch-upsert multiple entities under a single write lock.
    ///
    /// This avoids the per-entity lock acquire/release overhead of calling
    /// `upsert_entity` in a loop. Index entries are updated incrementally
    /// for each entity (old entries removed, new entries inserted).
    pub fn batch_upsert_entities(&self, entities: &[Entity]) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let entity_ids: Vec<EntityId> = entities.iter().map(|entity| entity.id).collect();
        for entity in entities {
            if let Some(old) = ent.entities.remove(&entity.id) {
                // Delta optimization: skip index churn when indexed fields unchanged
                let name_changed = old.name != entity.name;
                let file_changed = old.file_origin != entity.file_origin;
                let kind_changed = old.kind != entity.kind;

                if name_changed || file_changed || kind_changed {
                    ent.indexes
                        .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                    ent.indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }
            } else {
                ent.indexes.insert(
                    entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }
            ent.entities.insert(entity.id, entity.clone());
        }
        for entity in entities {
            self.record_entity_delta_upsert(entity.clone());
        }
        let affected = collect_entity_refresh_targets(&ent, &entity_ids);
        self.refresh_merkle_for_entities(&ent, entity_ids.iter().copied());
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    /// Batch-remove multiple entities under a single write lock.
    ///
    /// Removes each entity and its connected relations in one lock
    /// acquisition, avoiding per-entity lock overhead.
    pub fn batch_remove_entities(&self, ids: &[EntityId]) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let removed_ids: HashSet<EntityId> = ids.iter().copied().collect();
        let mut affected_neighbors = HashSet::new();
        for id in ids {
            if let Some(outgoing) = ent.outgoing.get(id) {
                for rel_id in outgoing {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            if !removed_ids.contains(&neighbor) {
                                affected_neighbors.insert(neighbor);
                            }
                        }
                    }
                }
            }
            if let Some(incoming) = ent.incoming.get(id) {
                for rel_id in incoming {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            if !removed_ids.contains(&neighbor) {
                                affected_neighbors.insert(neighbor);
                            }
                        }
                    }
                }
            }

            if let Some(entity) = ent.entities.remove(id) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }
            let removed_relations = remove_relations_for_entity(&mut ent, id);
            self.record_entity_delta_remove(*id);
            for relation in &removed_relations {
                self.record_relation_delta_remove(&ent, relation);
            }
        }
        let merkle_seeds: Vec<EntityId> = removed_ids
            .iter()
            .copied()
            .chain(affected_neighbors.iter().copied())
            .collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);

        if let Some(ref ti) = self.text_index {
            for id in ids {
                let _ = ti.remove(id);
            }
            self.text_dirty.store(true, Ordering::Release);
        }

        // Remove vectors for deleted entities.
        #[cfg(feature = "vector")]
        {
            let mut queue = self.embedding_queue.lock();
            for id in ids {
                queue.remove(&RetrievalKey::Entity(*id));
            }
            drop(queue);

            if let Some(ref vi) = *self.vector_index.lock() {
                for id in ids {
                    let _ = vi.remove(id);
                }
            }
        }

        let affected_neighbors: Vec<EntityId> = affected_neighbors.into_iter().collect();
        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;

        Ok(())
    }

    // ---------------------------------------------------------------
    // Non-trait methods (needed by commit.rs, matching KuzuGraphStore)
    // ---------------------------------------------------------------

    /// Remove all outgoing relations for an entity.
    /// Called during re-linking after file re-parse.
    pub fn remove_outgoing_relations(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut affected = HashSet::new();
        if let Some(rel_ids) = ent.outgoing.remove(id) {
            for rel_id in &rel_ids {
                if let Some(rel) = ent.relations.remove(rel_id) {
                    affected.extend(entity_ids_for_relation(&rel));
                    remove_relation_indexes(&mut ent, &rel);
                    self.record_relation_delta_remove(&ent, &rel);
                }
            }
        }
        let affected: Vec<EntityId> = affected.into_iter().collect();
        self.refresh_merkle_for_entities(
            &ent,
            std::iter::once(*id).chain(affected.iter().copied()),
        );
        drop(ent);

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    /// Delete a shallow tracked file by file path.
    pub fn delete_shallow_file(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.artifact_id_for_path(file_id).unwrap_or_else(|| {
            let id = ArtifactId::seed_from_file_id(file_id);
            id
        });

        let mut ent = self.entities.write();
        let old = ent.shallow_files.remove(file_id);
        self.record_shallow_file_delta_remove(old, file_id.clone());
        if !ent.structured_artifacts.contains_key(file_id)
            && !ent.opaque_artifacts.contains_key(file_id)
        {
            ent.artifact_index.remove(file_id);
            ent.artifact_reverse.remove(&artifact_id);
            self.record_artifact_index_delta_remove(file_id.clone());
        }
        drop(ent);

        let key = RetrievalKey::Artifact(artifact_id);
        self.remove_retrievable_text_index(&key)?;
        self.remove_retrievable_vector(&key)?;
        #[cfg(feature = "vector")]
        {
            self.artifact_embedding_queue.lock().remove(&artifact_id);
        }
        Ok(())
    }

    /// Get a single shallow tracked file.
    pub fn get_shallow_file(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<ShallowTrackedFile>, KinDbError> {
        Ok(self.entities.read().shallow_files.get(file_id).cloned())
    }

    // -------------------------------------------------------------------
    // Session/intent management — additional methods beyond SessionStore
    // (Core CRUD is in `impl SessionStore for InMemoryGraph` below.)
    // -------------------------------------------------------------------

    pub fn hard_collisions_for_entity(
        &self,
        entity_id: &EntityId,
        exclude_intent: &IntentId,
    ) -> Result<Vec<Intent>, KinDbError> {
        Ok(self
            .sessions
            .read()
            .intents
            .values()
            .filter(|i| {
                i.intent_id != *exclude_intent
                    && i.scopes
                        .iter()
                        .any(|s| matches!(s, IntentScope::Entity(eid) if eid == entity_id))
                    && i.lock_type == LockType::Hard
            })
            .cloned()
            .collect())
    }
    pub fn locks_for_entity(&self, entity_id: &EntityId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self
            .sessions
            .read()
            .intents
            .values()
            .filter(|i| {
                i.scopes
                    .iter()
                    .any(|s| matches!(s, IntentScope::Entity(eid) if eid == entity_id))
                    && i.lock_type == LockType::Hard
            })
            .cloned()
            .collect())
    }
    pub fn downstream_warnings_for_entity(
        &self,
        entity_id: &EntityId,
    ) -> Result<Vec<Intent>, KinDbError> {
        let ses = self.sessions.read();
        let intent_ids: Vec<IntentId> = ses
            .downstream_warnings
            .iter()
            .filter(|(_, eid, _)| eid == entity_id)
            .map(|(iid, _, _)| *iid)
            .collect();
        Ok(intent_ids
            .iter()
            .filter_map(|iid| ses.intents.get(iid).cloned())
            .collect())
    }
    pub fn create_downstream_warning(
        &self,
        intent_id: &IntentId,
        entity_id: &EntityId,
        reason: &str,
    ) -> Result<(), KinDbError> {
        self.sessions.write().downstream_warnings.push((
            *intent_id,
            *entity_id,
            reason.to_string(),
        ));
        self.require_full_snapshot();
        Ok(())
    }

    // -------------------------------------------------------------------
    // Incremental indexing helpers
    // -------------------------------------------------------------------

    /// Record the content hash for a file.
    pub fn set_file_hash(&self, path: &str, hash: [u8; 32]) {
        self.entities
            .write()
            .file_hashes
            .insert(path.to_string(), hash);
        self.record_file_hash_delta_upsert(path.to_string(), hash);
    }

    /// Get the recorded hash for a file.
    pub fn get_file_hash(&self, path: &str) -> Option<[u8; 32]> {
        self.entities.read().file_hashes.get(path).copied()
    }

    /// Remove all entities and their outgoing relations for entities in a given file.
    ///
    /// Incoming relations from OTHER files pointing to removed entities are kept
    /// (they become dangling but will be fixed during the cross-file linking phase).
    ///
    /// Returns the removed entity IDs.
    pub fn remove_entities_for_file(&self, path: &str) -> Vec<EntityId> {
        let mut ent = self.entities.write();

        // Find all entity IDs in this file via the file index.
        let entity_ids: Vec<EntityId> = ent.indexes.by_file(path).to_vec();

        if entity_ids.is_empty() {
            ent.file_hashes.remove(path);
            self.record_file_hash_delta_remove(path.to_string());
            return Vec::new();
        }

        let entity_set: hashbrown::HashSet<EntityId> = entity_ids.iter().copied().collect();
        let mut merkle_seeds: HashSet<EntityId> = entity_ids.iter().copied().collect();

        for &eid in &entity_ids {
            // Remove the entity itself.
            if let Some(entity) = ent.entities.remove(&eid) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
                self.record_entity_delta_remove(eid);
            }

            // Remove all outgoing relations from this entity.
            if let Some(out_rids) = ent.outgoing.remove(&eid) {
                for rid in &out_rids {
                    if let Some(rel) = ent.relations.remove(rid) {
                        remove_relation_indexes(&mut ent, &rel);
                        self.record_relation_delta_remove(&ent, &rel);
                    }
                }
            }

            // Remove incoming relations that originate from entities in the SAME file
            // (they were already removed above as outgoing from another entity in
            // entity_ids). For incoming relations from OTHER files, keep them as
            // dangling. We only need to clean up the incoming vec for this entity.
            if let Some(inc_rids) = ent.incoming.remove(&eid) {
                {
                    let mut pending = self.pending_delta.lock();
                    delta_map_remove(&mut pending.delta.incoming, eid);
                }
                for rid in &inc_rids {
                    // If the relation still exists, it's from an external file — keep it
                    // in the relations map but just remove from this entity's incoming vec
                    // (which we already did by removing the key). However we also need to
                    // check if the source is in the same file set — if so the relation
                    // was already removed above.
                    if let Some(rel) = ent.relations.get(rid) {
                        if let Some(src) = rel.src.as_entity() {
                            if entity_set.contains(&src) {
                                // Already removed as outgoing above — this is a leftover ref.
                                // The relation is already gone from ent.relations via the
                                // outgoing removal pass.
                            } else {
                                merkle_seeds.insert(src);
                            }
                        }
                        // If src is NOT in entity_set, this is a cross-file incoming
                        // relation. Keep the relation in ent.relations (dangling dst).
                    }
                }
            }
        }

        // Also remove the file hash entry.
        ent.file_hashes.remove(path);
        self.record_file_hash_delta_remove(path.to_string());
        self.refresh_merkle_for_entities(&ent, merkle_seeds);

        entity_ids
    }

    /// Get all file paths that have recorded content hashes.
    pub fn indexed_file_paths(&self) -> Vec<String> {
        self.entities.read().file_hashes.keys().cloned().collect()
    }

    /// Get file paths that have at least one entity (function, class, etc.).
    /// Unlike `indexed_file_paths` which returns every tracked file (including
    /// build artifacts, configs, etc.), this returns only files the parser
    /// extracted semantic entities from — the graph-native authority on what
    /// constitutes source code.
    pub fn entity_bearing_file_paths(&self) -> Vec<String> {
        self.entities.read().indexes.file.keys().cloned().collect()
    }
}

impl Default for InMemoryGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InMemoryGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ent = self.entities.read();
        let chg = self.changes.read();
        f.debug_struct("InMemoryGraph")
            .field("entities", &ent.entities.len())
            .field("relations", &ent.relations.len())
            .field("changes", &chg.changes.len())
            .field("branches", &chg.branches.len())
            .finish()
    }
}

/// Remove all relations connected to an entity, cleaning up both sides of each edge.
///
/// This is a shared helper used by `remove_entity` and `remove_entities_for_file`
/// to ensure relations are fully cleaned up (no dangling entries in `ent.relations`,
/// `ent.outgoing`, or `ent.incoming`).
fn remove_relations_for_entity(ent: &mut EntityData, entity_id: &EntityId) -> Vec<Relation> {
    // Collect all relation IDs from both directions
    let mut relation_ids = Vec::new();
    if let Some(outgoing) = ent.outgoing.get(entity_id) {
        relation_ids.extend(outgoing.iter().cloned());
    }
    if let Some(incoming) = ent.incoming.get(entity_id) {
        relation_ids.extend(incoming.iter().cloned());
    }

    // Remove each relation and clean up the other side's edge list
    let mut removed = Vec::new();
    for rel_id in &relation_ids {
        if let Some(rel) = ent.relations.remove(rel_id) {
            remove_relation_indexes(ent, &rel);
            removed.push(rel);
        }
    }

    // Remove the entity's own edge lists
    ent.outgoing.remove(entity_id);
    ent.incoming.remove(entity_id);
    removed
}

fn collect_artifact_text_index_docs<'a>(
    ent: &'a EntityData,
) -> impl Iterator<Item = (RetrievalKey, Vec<(String, f32)>)> + 'a {
    ent.shallow_files
        .values()
        .map(|file| {
            let id = ent
                .artifact_index
                .get(&file.file_id)
                .copied()
                .unwrap_or_else(|| ArtifactId::seed_from_file_id(&file.file_id));
            (RetrievalKey::Artifact(id), shallow_file_fields(file))
        })
        .chain(ent.structured_artifacts.values().map(|artifact| {
            let id = ent
                .artifact_index
                .get(&artifact.file_id)
                .copied()
                .unwrap_or_else(|| ArtifactId::seed_from_file_id(&artifact.file_id));
            (
                RetrievalKey::Artifact(id),
                structured_artifact_fields(artifact),
            )
        }))
        .chain(ent.opaque_artifacts.values().map(|artifact| {
            let id = ent
                .artifact_index
                .get(&artifact.file_id)
                .copied()
                .unwrap_or_else(|| ArtifactId::seed_from_file_id(&artifact.file_id));
            (RetrievalKey::Artifact(id), opaque_artifact_fields(artifact))
        }))
}

#[cfg(feature = "vector")]
fn collect_artifact_ids(ent: &EntityData) -> Vec<ArtifactId> {
    let mut ids = Vec::with_capacity(
        ent.shallow_files.len() + ent.structured_artifacts.len() + ent.opaque_artifacts.len(),
    );

    for file_id in ent.shallow_files.keys() {
        if let Some(id) = ent.artifact_index.get(file_id) {
            ids.push(*id);
        }
    }
    for file_id in ent.structured_artifacts.keys() {
        if let Some(id) = ent.artifact_index.get(file_id) {
            ids.push(*id);
        }
    }
    for file_id in ent.opaque_artifacts.keys() {
        if let Some(id) = ent.artifact_index.get(file_id) {
            ids.push(*id);
        }
    }

    ids
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn artifact_embedding_doc(
    ent: &EntityData,
    artifact_id: &ArtifactId,
) -> Option<(RetrievalKey, String)> {
    let file_path = ent.artifact_reverse.get(artifact_id)?;

    if let Some(file) = ent.shallow_files.get(file_path) {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_shallow_text(file),
        ));
    }

    if let Some(artifact) = ent.structured_artifacts.get(file_path) {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_artifact_text(artifact),
        ));
    }

    if let Some(artifact) = ent.opaque_artifacts.get(file_path) {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_opaque_text(artifact),
        ));
    }

    None
}

fn collect_text_index_extra_fields(ent: &EntityData, entity_id: &EntityId) -> Vec<(String, f32)> {
    let mut fields = Vec::new();
    // Deduplicate by (tag, text) without allocating format strings.
    let mut seen_imports: HashSet<&str> = HashSet::new();
    let mut seen_neighbors: HashSet<&str> = HashSet::new();

    collect_relation_text_fields(
        ent,
        ent.outgoing.get(entity_id).into_iter().flatten(),
        entity_id,
        &mut seen_imports,
        &mut seen_neighbors,
        &mut fields,
    );
    collect_relation_text_fields(
        ent,
        ent.incoming.get(entity_id).into_iter().flatten(),
        entity_id,
        &mut seen_imports,
        &mut seen_neighbors,
        &mut fields,
    );

    fields
}

fn collect_relation_text_fields<'a>(
    ent: &'a EntityData,
    relation_ids: impl Iterator<Item = &'a RelationId>,
    entity_id: &EntityId,
    seen_imports: &mut HashSet<&'a str>,
    seen_neighbors: &mut HashSet<&'a str>,
    fields: &mut Vec<(String, f32)>,
) {
    for relation_id in relation_ids {
        let Some(relation) = ent.relations.get(relation_id) else {
            continue;
        };
        if relation.kind == RelationKind::Contains {
            continue;
        }

        if let Some(import_source) = relation.import_source.as_deref() {
            let import_source = import_source.trim();
            if !import_source.is_empty() && seen_imports.insert(import_source) {
                fields.push((import_source.to_string(), TEXT_INDEX_IMPORT_SOURCE_WEIGHT));
            }
        }

        let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
            continue;
        };
        let Some(neighbor) = ent.entities.get(&neighbor_id) else {
            continue;
        };
        let neighbor_name = neighbor.name.trim();
        if !neighbor_name.is_empty() && seen_neighbors.insert(neighbor_name) {
            fields.push((neighbor_name.to_string(), TEXT_INDEX_NEIGHBOR_NAME_WEIGHT));
        }
    }
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn collect_embedding_context_lines(ent: &EntityData, entity_id: &EntityId) -> Vec<String> {
    let mut candidates: Vec<(&'static str, String, f32)> = Vec::new();

    collect_relation_embedding_context(
        ent,
        ent.outgoing.get(entity_id).into_iter().flatten(),
        entity_id,
        true,
        &mut candidates,
    );

    candidates.sort_by(|a, b| {
        b.2.total_cmp(&a.2)
            .then_with(|| a.0.cmp(b.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut seen = HashSet::new();
    let mut per_label: HashMap<&'static str, usize> = HashMap::new();
    let mut lines = Vec::new();

    for (label, value, _) in candidates {
        let dedupe_key = format!("{label}\u{0}{value}");
        if !seen.insert(dedupe_key) {
            continue;
        }

        let count = per_label.entry(label).or_insert(0);
        if *count >= MAX_EMBED_CONTEXT_VALUES_PER_LABEL {
            continue;
        }
        *count += 1;
        lines.push(format!("{label}: {value}"));
    }

    lines
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn collect_relation_embedding_context<'a>(
    ent: &EntityData,
    relation_ids: impl Iterator<Item = &'a RelationId>,
    entity_id: &EntityId,
    outgoing: bool,
    candidates: &mut Vec<(&'static str, String, f32)>,
) {
    for relation_id in relation_ids {
        let Some(relation) = ent.relations.get(relation_id) else {
            continue;
        };
        if relation.kind == RelationKind::Contains {
            continue;
        }

        let base_score = relation.confidence.max(0.0);

        if let Some(import_source) = relation.import_source.as_deref() {
            let import_source = import_source.trim();
            if !import_source.is_empty() {
                push_embedding_context_value(
                    candidates,
                    "import_source",
                    import_source,
                    base_score + 0.2,
                );
            }
        }

        let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
            continue;
        };
        let Some(neighbor) = ent.entities.get(&neighbor_id) else {
            continue;
        };
        let neighbor_name = neighbor.name.trim();
        if neighbor_name.is_empty() {
            continue;
        }

        push_embedding_context_value(
            candidates,
            relation_embedding_label(relation.kind, outgoing),
            neighbor_name,
            base_score,
        );
    }
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn push_embedding_context_value(
    candidates: &mut Vec<(&'static str, String, f32)>,
    label: &'static str,
    value: &str,
    score: f32,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    candidates.push((label, value.to_string(), score));
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn relation_embedding_label(kind: RelationKind, outgoing: bool) -> &'static str {
    match (kind, outgoing) {
        (RelationKind::Calls, true) => "calls",
        (RelationKind::Calls, false) => "called_by",
        (RelationKind::Imports, true) => "imports",
        (RelationKind::Imports, false) => "imported_by",
        (RelationKind::Includes, true) => "includes",
        (RelationKind::Includes, false) => "included_by",
        (RelationKind::References, true) => "references",
        (RelationKind::References, false) => "referenced_by",
        (RelationKind::UsesMacro, true) => "uses_macro",
        (RelationKind::UsesMacro, false) => "macro_used_by",
        (RelationKind::Implements, true) => "implements",
        (RelationKind::Implements, false) => "implemented_by",
        (RelationKind::Extends, true) => "extends",
        (RelationKind::Extends, false) => "extended_by",
        (RelationKind::Tests, true) => "tests",
        (RelationKind::Tests, false) => "tested_by",
        (RelationKind::DependsOn, true) => "depends_on",
        (RelationKind::DependsOn, false) => "depended_on_by",
        (RelationKind::CoChanges, true) => "co_changes",
        (RelationKind::CoChanges, false) => "co_changed_with",
        (RelationKind::DefinesContract, true) => "defines_contract",
        (RelationKind::DefinesContract, false) => "defined_by",
        (RelationKind::ConsumesContract, true) => "consumes_contract",
        (RelationKind::ConsumesContract, false) => "consumed_by",
        (RelationKind::EmitsEvent, true) => "emits_event",
        (RelationKind::EmitsEvent, false) => "emitted_by",
        (RelationKind::OwnedBy, true) => "owned_by",
        (RelationKind::OwnedBy, false) => "owns",
        (RelationKind::DocumentedBy, true) => "documented_by",
        (RelationKind::DocumentedBy, false) => "documents",
        (RelationKind::Covers, true) => "covers",
        (RelationKind::Covers, false) => "covered_by",
        (RelationKind::DerivedFrom, true) => "derived_from",
        (RelationKind::DerivedFrom, false) => "derives",
        (RelationKind::OwnedByFile, true) => "owned_by_file",
        (RelationKind::OwnedByFile, false) => "owns_file",
        (RelationKind::Contains, _) => "contains",
        (RelationKind::Overrides, true) => "overrides",
        (RelationKind::Overrides, false) => "overridden_by",
        (RelationKind::Instantiates, true) => "instantiates",
        (RelationKind::Instantiates, false) => "instantiated_by",
        (RelationKind::UsesType, true) => "uses_type",
        (RelationKind::UsesType, false) => "type_used_by",
        (RelationKind::SubscribesTo, true) => "subscribes_to",
        (RelationKind::SubscribesTo, false) => "subscribed_by",
        (RelationKind::SendsMessage, true) => "sends_message",
        (RelationKind::SendsMessage, false) => "message_from",
        (RelationKind::Spawns, true) => "spawns",
        (RelationKind::Spawns, false) => "spawned_by",
    }
}

impl EntityStore for InMemoryGraph {
    type Error = KinDbError;

    // Graph-assigned artifact identity: generic `GraphStore` consumers resolve a
    // path to its graph-owned `ArtifactId` through this override (delegates to the
    // inherent O(1) artifact-index lookup) rather than re-deriving from the path.
    fn artifact_id_for_path(&self, path: &FilePathId) -> Option<ArtifactId> {
        InMemoryGraph::artifact_id_for_path(self, path)
    }

    // -----------------------------------------------------------------------
    // Read operations — entities lock only
    // -----------------------------------------------------------------------

    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, KinDbError> {
        let _span = tracing::info_span!("kindb.get_entity").entered();
        Ok(self.entities.read().entities.get(id).cloned())
    }

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, KinDbError> {
        let ent = self.entities.read();
        let mut result = Vec::new();

        if let Some(edge_ids) = ent.outgoing.get(id) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if relation_is_entity_only(rel)
                        && (kinds.is_empty() || kinds.contains(&rel.kind))
                    {
                        result.push(rel.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    fn get_all_relations_for_entity(&self, id: &EntityId) -> Result<Vec<Relation>, KinDbError> {
        let _span = tracing::info_span!("kindb.get_all_relations_for_entity").entered();
        let ent = self.entities.read();
        let mut result = Vec::new();
        let mut seen = hashbrown::HashSet::new();

        // Outgoing
        if let Some(edge_ids) = ent.outgoing.get(id) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if relation_is_entity_only(rel) && seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        // Incoming
        if let Some(edge_ids) = ent.incoming.get(id) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if relation_is_entity_only(rel) && seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, KinDbError> {
        let ent = self.entities.read();
        Ok(traverse::downstream_impact(
            id,
            max_depth,
            &ent.entities,
            &ent.incoming,
            &ent.relations,
        ))
    }

    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let _span =
            tracing::info_span!("kindb.get_dependency_neighborhood", depth = depth).entered();
        let ent = self.entities.read();
        Ok(traverse::bfs_neighborhood(
            id,
            depth,
            &ent.entities,
            &ent.relations,
            &ent.outgoing,
        ))
    }

    fn expand_neighborhood(
        &self,
        entity_ids: &[EntityId],
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.expand_neighborhood",
            seeds = entity_ids.len(),
            edge_kinds = edge_kinds.len(),
            depth = depth
        )
        .entered();
        let ent = self.entities.read();
        Ok(traverse::expand_neighborhood(
            entity_ids,
            edge_kinds,
            depth,
            &ent.entities,
            &ent.relations,
            &ent.outgoing,
            &ent.incoming,
        ))
    }

    fn traverse(
        &self,
        start: &GraphNodeId,
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let ent = self.entities.read();
        Ok(traverse::traverse(
            start,
            edge_kinds,
            depth,
            &ent.entities,
            &ent.relations,
            &ent.node_outgoing,
            &ent.node_incoming,
        ))
    }

    fn find_dead_code(&self) -> Result<Vec<Entity>, KinDbError> {
        let ent = self.entities.read();
        Ok(traverse::find_dead_code(
            &ent.entities,
            &ent.incoming,
            &ent.relations,
        ))
    }

    fn has_incoming_relation_kinds(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
        exclude_same_file: bool,
    ) -> Result<bool, KinDbError> {
        let ent = self.entities.read();
        let entity = match ent.entities.get(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        Ok(traverse::has_incoming_of_kinds(
            id,
            entity,
            kinds,
            exclude_same_file,
            &ent.incoming,
            &ent.relations,
            &ent.entities,
        ))
    }

    fn query_entities(&self, filter: &EntityFilter) -> Result<Vec<Entity>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.query_entities",
            has_file = filter.file_path.is_some(),
            has_name = filter.name_pattern.is_some(),
            has_kinds = filter.kinds.as_ref().map(|kinds| kinds.len()).unwrap_or(0)
        )
        .entered();
        let ent = self.entities.read();

        // Only the name-pattern lookup produces a meaningful, deterministic
        // candidate order (exact matches ahead of token matches, id-sorted
        // within each group). The file/kind/all branches iterate hash sets in
        // arbitrary order, so their candidate order must NOT leak into the
        // result order — those fall back to a pure id-sort below.
        let candidate_order_is_ranked;
        let candidate_ids: Vec<EntityId> = if let Some(ref fp) = filter.file_path {
            candidate_order_is_ranked = false;
            ent.indexes.by_file(&fp.0).to_vec()
        } else if let Some(ref pattern) = filter.name_pattern {
            candidate_order_is_ranked = true;
            ent.indexes.by_name_pattern(pattern)
        } else if let Some(ref kinds) = filter.kinds {
            candidate_order_is_ranked = false;
            if kinds.len() == 1 {
                ent.indexes.by_kind(kinds[0]).to_vec()
            } else {
                ent.entities.keys().copied().collect()
            }
        } else {
            candidate_order_is_ranked = false;
            ent.entities.keys().copied().collect()
        };

        // Capture each id's rank position so the relevance order from the index
        // lookup survives the parallel filter below instead of being discarded.
        let rank: HashMap<EntityId, usize> = if candidate_order_is_ranked {
            candidate_ids
                .iter()
                .enumerate()
                .map(|(pos, eid)| (*eid, pos))
                .collect()
        } else {
            HashMap::new()
        };

        let mut results: Vec<Entity> = candidate_ids
            .par_iter()
            .filter_map(|eid| {
                ent.entities.get(eid).and_then(|entity| {
                    if matches_filter(entity, filter) {
                        Some(entity.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Sort by rank ascending (position 0 = best match), then by entity id
        // as a total tie-break. When candidate order is not ranked the rank map
        // is empty, so every entity shares the same rank and the result is a
        // pure id-sort. Either way the id tie-break makes the order fully
        // deterministic regardless of hash iteration or rayon scheduling.
        results.sort_by(|a, b| {
            let ra = rank.get(&a.id).copied().unwrap_or(usize::MAX);
            let rb = rank.get(&b.id).copied().unwrap_or(usize::MAX);
            ra.cmp(&rb).then_with(|| a.id.cmp(&b.id))
        });
        Ok(results)
    }

    fn list_all_entities(&self) -> Result<Vec<Entity>, KinDbError> {
        Ok(self
            .entities
            .read()
            .entities
            .par_values()
            .cloned()
            .collect())
    }

    // -----------------------------------------------------------------------
    // Write operations — entities lock only
    // -----------------------------------------------------------------------

    fn upsert_entity(&self, entity: &Entity) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();

        // Delta index update: only touch indexes when indexed fields change.
        if let Some(old) = ent.entities.remove(&entity.id) {
            let name_changed = old.name != entity.name;
            let file_changed = old.file_origin != entity.file_origin;
            let kind_changed = old.kind != entity.kind;

            if name_changed || file_changed || kind_changed {
                ent.indexes
                    .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                ent.indexes.insert(
                    entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }
        } else {
            // New entity — insert into indexes
            ent.indexes.insert(
                entity.id,
                &entity.name,
                entity.file_origin.as_ref(),
                entity.kind,
            );
        }

        ent.entities.insert(entity.id, entity.clone());
        let affected = collect_entity_refresh_targets(&ent, &[entity.id]);
        self.record_entity_delta_upsert(entity.clone());
        self.refresh_merkle_for_entities(&ent, std::iter::once(entity.id));
        drop(ent); // Release write lock before text index + embedding work.

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    fn upsert_relation(&self, relation: &Relation) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut affected = HashSet::new();
        let mut merkle_seeds = Vec::new();

        // Remove old edge entries if updating
        if let Some(old) = ent.relations.remove(&relation.id) {
            affected.extend(entity_ids_for_relation(&old));
            merkle_seeds.extend(entity_ids_for_relation(&old));
            remove_relation_indexes(&mut ent, &old);
            self.record_relation_delta_remove(&ent, &old);
        }

        // Insert new edge entries
        insert_relation_indexes(&mut ent, relation);
        ent.relations.insert(relation.id, relation.clone());
        self.record_relation_delta_upsert(&ent, relation.clone());
        affected.extend(entity_ids_for_relation(relation));
        merkle_seeds.extend(entity_ids_for_relation(relation));
        let affected: Vec<EntityId> = affected.into_iter().collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    fn remove_entity(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();

        let mut affected_neighbors = Vec::new();

        if let Some(entity) = ent.entities.remove(id) {
            ent.indexes.remove(
                &entity.id,
                &entity.name,
                entity.file_origin.as_ref(),
                entity.kind,
            );
            // Keep text index in sync (commit is deferred — call flush_text_index())
            if let Some(ref ti) = self.text_index {
                let _ = ti.remove(id);
                self.text_dirty.store(true, Ordering::Release);
            }

            if let Some(outgoing) = ent.outgoing.get(id) {
                for rel_id in outgoing {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            affected_neighbors.push(neighbor);
                        }
                    }
                }
            }
            if let Some(incoming) = ent.incoming.get(id) {
                for rel_id in incoming {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            affected_neighbors.push(neighbor);
                        }
                    }
                }
            }
        }

        // Clean up all connected relations and edge maps
        let removed_relations = remove_relations_for_entity(&mut ent, id);
        self.record_entity_delta_remove(*id);
        for relation in &removed_relations {
            self.record_relation_delta_remove(&ent, relation);
        }
        let merkle_seeds: Vec<EntityId> = std::iter::once(*id)
            .chain(affected_neighbors.iter().copied())
            .collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);

        // Remove vector for deleted entity.
        #[cfg(feature = "vector")]
        {
            self.embedding_queue
                .lock()
                .remove(&RetrievalKey::Entity(*id));
            if let Some(ref vi) = *self.vector_index.lock() {
                let _ = vi.remove(id);
            }
        }

        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;

        Ok(())
    }

    fn remove_entities_batch(&self, ids: &[EntityId]) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let id_set: hashbrown::HashSet<EntityId> = ids.iter().copied().collect();
        let mut affected_neighbors = Vec::new();

        for id in ids {
            if let Some(entity) = ent.entities.remove(id) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );

                if let Some(outgoing) = ent.outgoing.get(id) {
                    for rel_id in outgoing {
                        if let Some(rel) = ent.relations.get(rel_id) {
                            if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                                if !id_set.contains(&neighbor) {
                                    affected_neighbors.push(neighbor);
                                }
                            }
                        }
                    }
                }
                if let Some(incoming) = ent.incoming.get(id) {
                    for rel_id in incoming {
                        if let Some(rel) = ent.relations.get(rel_id) {
                            if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                                if !id_set.contains(&neighbor) {
                                    affected_neighbors.push(neighbor);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clean up all connected relations and edge maps
        for id in ids {
            let removed_relations = remove_relations_for_entity(&mut ent, id);
            self.record_entity_delta_remove(*id);
            for relation in &removed_relations {
                self.record_relation_delta_remove(&ent, relation);
            }
        }
        let merkle_seeds: Vec<EntityId> = ids
            .iter()
            .copied()
            .chain(affected_neighbors.iter().copied())
            .collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);

        // Keep text index in sync (commit is deferred — call flush_text_index())
        if let Some(ref ti) = self.text_index {
            let _ = ti.remove_batch(ids)?;
            self.text_dirty.store(true, Ordering::Release);
        }

        // Remove vectors for deleted entities.
        #[cfg(feature = "vector")]
        {
            let mut eq = self.embedding_queue.lock();
            for id in ids {
                eq.remove(&RetrievalKey::Entity(*id));
            }
            if let Some(ref vi) = *self.vector_index.lock() {
                let _ = vi.remove_batch(ids)?;
            }
        }

        affected_neighbors.sort_unstable();
        affected_neighbors.dedup();

        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;

        Ok(())
    }

    fn remove_relation(&self, id: &RelationId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut affected = Vec::new();

        if let Some(rel) = ent.relations.remove(id) {
            affected.extend(entity_ids_for_relation(&rel));
            let merkle_seeds = entity_ids_for_relation(&rel);
            remove_relation_indexes(&mut ent, &rel);
            self.record_relation_delta_remove(&ent, &rel);
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
        }

        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    fn upsert_shallow_file(&self, shallow: &ShallowTrackedFile) -> Result<(), KinDbError> {
        let artifact_id = self.ensure_artifact_id(&shallow.file_id);
        let old = self
            .entities
            .write()
            .shallow_files
            .insert(shallow.file_id.clone(), shallow.clone());
        self.record_shallow_file_delta_upsert(old, shallow.clone());
        let key = RetrievalKey::Artifact(artifact_id);
        let fields = shallow_file_fields(shallow);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(artifact_id)?;
        Ok(())
    }

    fn list_shallow_files(&self) -> Result<Vec<ShallowTrackedFile>, KinDbError> {
        Ok(self
            .entities
            .read()
            .shallow_files
            .values()
            .cloned()
            .collect())
    }

    fn get_shallow_file(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<ShallowTrackedFile>, KinDbError> {
        Ok(self.entities.read().shallow_files.get(file_id).cloned())
    }

    fn upsert_structured_artifact(&self, artifact: &StructuredArtifact) -> Result<(), KinDbError> {
        let artifact_id = self.ensure_artifact_id(&artifact.file_id);
        let old = self
            .entities
            .write()
            .structured_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
        self.record_structured_artifact_delta_upsert(old, artifact.clone());
        let key = RetrievalKey::Artifact(artifact_id);
        let fields = structured_artifact_fields(artifact);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(artifact_id)?;
        Ok(())
    }

    fn list_structured_artifacts(&self) -> Result<Vec<StructuredArtifact>, KinDbError> {
        Ok(self
            .entities
            .read()
            .structured_artifacts
            .values()
            .cloned()
            .collect())
    }

    fn get_structured_artifact(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<StructuredArtifact>, KinDbError> {
        Ok(self
            .entities
            .read()
            .structured_artifacts
            .get(file_id)
            .cloned())
    }

    fn delete_structured_artifact(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.artifact_id_for_path(file_id).unwrap_or_else(|| {
            let id = ArtifactId::seed_from_file_id(file_id);
            id
        });

        let mut ent = self.entities.write();
        let old = ent.structured_artifacts.remove(file_id);
        self.record_structured_artifact_delta_remove(old, file_id.clone());
        // Only remove the index if there are no other artifact types using this path
        if !ent.shallow_files.contains_key(file_id) && !ent.opaque_artifacts.contains_key(file_id) {
            ent.artifact_index.remove(file_id);
            ent.artifact_reverse.remove(&artifact_id);
            self.record_artifact_index_delta_remove(file_id.clone());
        }
        drop(ent);

        let key = RetrievalKey::Artifact(artifact_id);
        self.remove_retrievable_text_index(&key)?;
        self.remove_retrievable_vector(&key)?;
        #[cfg(feature = "vector")]
        {
            self.artifact_embedding_queue.lock().remove(&artifact_id);
        }
        Ok(())
    }

    fn upsert_opaque_artifact(&self, artifact: &OpaqueArtifact) -> Result<(), KinDbError> {
        let artifact_id = self.ensure_artifact_id(&artifact.file_id);
        let old = self
            .entities
            .write()
            .opaque_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
        self.record_opaque_artifact_delta_upsert(old, artifact.clone());
        let key = RetrievalKey::Artifact(artifact_id);
        let fields = opaque_artifact_fields(artifact);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(artifact_id)?;
        Ok(())
    }

    fn list_opaque_artifacts(&self) -> Result<Vec<OpaqueArtifact>, KinDbError> {
        Ok(self
            .entities
            .read()
            .opaque_artifacts
            .values()
            .cloned()
            .collect())
    }

    fn get_opaque_artifact(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<OpaqueArtifact>, KinDbError> {
        Ok(self.entities.read().opaque_artifacts.get(file_id).cloned())
    }

    fn delete_opaque_artifact(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.artifact_id_for_path(file_id).unwrap_or_else(|| {
            let id = ArtifactId::seed_from_file_id(file_id);
            id
        });

        let mut ent = self.entities.write();
        let old = ent.opaque_artifacts.remove(file_id);
        self.record_opaque_artifact_delta_remove(old, file_id.clone());
        // Only remove the index if there are no other artifact types using this path
        if !ent.shallow_files.contains_key(file_id)
            && !ent.structured_artifacts.contains_key(file_id)
        {
            ent.artifact_index.remove(file_id);
            ent.artifact_reverse.remove(&artifact_id);
            self.record_artifact_index_delta_remove(file_id.clone());
        }
        drop(ent);

        let key = RetrievalKey::Artifact(artifact_id);
        self.remove_retrievable_text_index(&key)?;
        self.remove_retrievable_vector(&key)?;
        #[cfg(feature = "vector")]
        {
            self.artifact_embedding_queue.lock().remove(&artifact_id);
        }
        Ok(())
    }

    fn upsert_file_layout(&self, layout: &FileLayout) -> Result<(), KinDbError> {
        self.ensure_artifact_id(&layout.file_id);
        let old = self
            .entities
            .write()
            .file_layouts
            .insert(layout.file_id.clone(), layout.clone());
        self.record_file_layout_delta_upsert(old, layout.clone());
        Ok(())
    }

    fn get_file_layout(&self, file_id: &FilePathId) -> Result<Option<FileLayout>, KinDbError> {
        Ok(self.entities.read().file_layouts.get(file_id).cloned())
    }

    fn list_file_layouts(&self) -> Result<Vec<FileLayout>, KinDbError> {
        Ok(self
            .entities
            .read()
            .file_layouts
            .values()
            .cloned()
            .collect())
    }

    fn get_file_hash(&self, file_id: &FilePathId) -> Result<Option<Hash256>, KinDbError> {
        Ok(self
            .entities
            .read()
            .file_hashes
            .get(&file_id.0)
            .copied()
            .map(Hash256::from_bytes))
    }

    fn delete_file_layout(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.artifact_id_for_path(file_id).unwrap_or_else(|| {
            let id = ArtifactId::seed_from_file_id(file_id);
            id
        });

        let mut ent = self.entities.write();
        let old = ent.file_layouts.remove(file_id);
        self.record_file_layout_delta_remove(old, file_id.clone());
        if !ent.shallow_files.contains_key(file_id)
            && !ent.structured_artifacts.contains_key(file_id)
            && !ent.opaque_artifacts.contains_key(file_id)
        {
            ent.artifact_index.remove(file_id);
            ent.artifact_reverse.remove(&artifact_id);
            self.record_artifact_index_delta_remove(file_id.clone());
        }
        Ok(())
    }

    fn apply_transaction_delta(&self, delta: &TransactionDelta) -> Result<(), KinDbError> {
        let mut affected = HashSet::new();
        let mut deleted_entities = Vec::new();
        let mut merkle_seeds = HashSet::new();

        {
            let mut ent = self.entities.write();

            // 1. Process entity deltas
            for ent_delta in &delta.entity_deltas {
                match ent_delta {
                    EntityDelta::Added(entity) | EntityDelta::Modified { new: entity, .. } => {
                        if let Some(old) = ent.entities.remove(&entity.id) {
                            let name_changed = old.name != entity.name;
                            let file_changed = old.file_origin != entity.file_origin;
                            let kind_changed = old.kind != entity.kind;

                            if name_changed || file_changed || kind_changed {
                                ent.indexes.remove(
                                    &old.id,
                                    &old.name,
                                    old.file_origin.as_ref(),
                                    old.kind,
                                );
                                ent.indexes.insert(
                                    entity.id,
                                    &entity.name,
                                    entity.file_origin.as_ref(),
                                    entity.kind,
                                );
                            }
                        } else {
                            ent.indexes.insert(
                                entity.id,
                                &entity.name,
                                entity.file_origin.as_ref(),
                                entity.kind,
                            );
                        }

                        ent.entities.insert(entity.id, entity.clone());
                        self.record_entity_delta_upsert(entity.clone());
                        affected.insert(entity.id);
                        merkle_seeds.insert(entity.id);
                    }
                    EntityDelta::Removed(id) => {
                        deleted_entities.push(*id);
                        merkle_seeds.insert(*id);
                        if let Some(entity) = ent.entities.remove(id) {
                            ent.indexes.remove(
                                &entity.id,
                                &entity.name,
                                entity.file_origin.as_ref(),
                                entity.kind,
                            );
                            if let Some(ref ti) = self.text_index {
                                let _ = ti.remove(id);
                                self.text_dirty.store(true, Ordering::Release);
                            }

                            if let Some(outgoing) = ent.outgoing.get(id) {
                                for rel_id in outgoing {
                                    if let Some(rel) = ent.relations.get(rel_id) {
                                        if let Some(neighbor) =
                                            entity_neighbor_for_relation(rel, id)
                                        {
                                            affected.insert(neighbor);
                                            merkle_seeds.insert(neighbor);
                                        }
                                    }
                                }
                            }
                            if let Some(incoming) = ent.incoming.get(id) {
                                for rel_id in incoming {
                                    if let Some(rel) = ent.relations.get(rel_id) {
                                        if let Some(neighbor) =
                                            entity_neighbor_for_relation(rel, id)
                                        {
                                            affected.insert(neighbor);
                                            merkle_seeds.insert(neighbor);
                                        }
                                    }
                                }
                            }
                        }
                        let removed_relations = remove_relations_for_entity(&mut ent, id);
                        self.record_entity_delta_remove(*id);
                        for relation in &removed_relations {
                            self.record_relation_delta_remove(&ent, relation);
                        }
                    }
                }
            }

            // 2. Process relation deltas
            for rel_delta in &delta.relation_deltas {
                match rel_delta {
                    RelationDelta::Added(relation) => {
                        if let Some(old) = ent.relations.remove(&relation.id) {
                            affected.extend(entity_ids_for_relation(&old));
                            merkle_seeds.extend(entity_ids_for_relation(&old));
                            remove_relation_indexes(&mut ent, &old);
                            self.record_relation_delta_remove(&ent, &old);
                        }
                        insert_relation_indexes(&mut ent, relation);
                        ent.relations.insert(relation.id, relation.clone());
                        self.record_relation_delta_upsert(&ent, relation.clone());
                        affected.extend(entity_ids_for_relation(relation));
                        merkle_seeds.extend(entity_ids_for_relation(relation));
                    }
                    RelationDelta::Removed(id) => {
                        if let Some(rel) = ent.relations.remove(id) {
                            affected.extend(entity_ids_for_relation(&rel));
                            merkle_seeds.extend(entity_ids_for_relation(&rel));
                            remove_relation_indexes(&mut ent, &rel);
                            self.record_relation_delta_remove(&ent, &rel);
                        }
                    }
                }
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds.iter().copied());
        }

        // 3. Clean up deleted entities from the embedding queue / vector index
        #[cfg(feature = "vector")]
        {
            let mut eq = self.embedding_queue.lock();
            let vi_lock = self.vector_index.lock();
            for id in &deleted_entities {
                eq.remove(&RetrievalKey::Entity(*id));
                if let Some(ref vi) = *vi_lock {
                    let _ = vi.remove(id);
                }
            }
        }

        // 4. Invalidate / refresh text index & embeddings for affected entities
        let affected_list: Vec<EntityId> = affected.into_iter().collect();
        if !affected_list.is_empty() {
            self.refresh_text_index_for_entities(&affected_list);
            self.invalidate_entities_for_embedding(&affected_list)?;
        }

        Ok(())
    }

    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<(), KinDbError> {
        if entities.is_empty() {
            return Ok(());
        }

        let affected = {
            let mut ent = self.entities.write();
            let mut all_affected = Vec::with_capacity(entities.len());

            for entity in entities {
                if let Some(old) = ent.entities.remove(&entity.id) {
                    let name_changed = old.name != entity.name;
                    let file_changed = old.file_origin != entity.file_origin;
                    let kind_changed = old.kind != entity.kind;

                    if name_changed || file_changed || kind_changed {
                        ent.indexes
                            .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                        ent.indexes.insert(
                            entity.id,
                            &entity.name,
                            entity.file_origin.as_ref(),
                            entity.kind,
                        );
                    }
                } else {
                    ent.indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }

                ent.entities.insert(entity.id, entity.clone());
                self.record_entity_delta_upsert(entity.clone());
                all_affected.push(entity.id);
            }

            let affected = collect_entity_refresh_targets(&ent, &all_affected);
            self.refresh_merkle_for_entities(&ent, all_affected.iter().copied());
            affected
        };

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    fn upsert_relations_batch(&self, relations: &[Relation]) -> Result<(), KinDbError> {
        if relations.is_empty() {
            return Ok(());
        }

        {
            let mut ent = self.entities.write();
            let mut merkle_seeds = Vec::new();

            ent.relations.reserve(relations.len());
            for relation in relations {
                if let Some(old) = ent.relations.remove(&relation.id) {
                    merkle_seeds.extend(entity_ids_for_relation(&old));
                    remove_relation_indexes(&mut ent, &old);
                    self.record_relation_delta_remove(&ent, &old);
                }

                insert_relation_indexes(&mut ent, relation);
                ent.relations.insert(relation.id, relation.clone());
                self.record_relation_delta_upsert(&ent, relation.clone());
                merkle_seeds.extend(entity_ids_for_relation(relation));
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
        }

        // Relation-derived text fields are now stale for affected entities,
        // but doing 20K+ individual Tantivy upserts is too expensive during
        // bulk init. Instead, mark that a full rebuild is required — this will
        // be honored by persist_text_index_with_root_hash before saving.
        self.text_full_rebuild_required
            .store(true, Ordering::Release);

        Ok(())
    }

    fn replace_relations_of_kind(
        &self,
        kind: RelationKind,
        new_relations: Vec<Relation>,
    ) -> Result<(), KinDbError> {
        // Short-circuit: if no new relations and none of this kind exist, skip everything.
        if new_relations.is_empty() {
            let ent = self.entities.read();
            let has_existing = ent.relations.values().any(|r| r.kind == kind);
            if !has_existing {
                return Ok(());
            }
            drop(ent);
        }

        // Step 1: Off-lock — pre-build the new relations map with exact capacity
        let mut new_map: HashMap<RelationId, Relation> =
            HashMap::with_capacity(new_relations.len());
        for rel in new_relations {
            new_map.insert(rel.id, rel);
        }

        // Step 2: Single write lock — retain non-kind + insert new + rebuild indexes
        {
            let mut ent = self.entities.write();
            let mut merkle_seeds = Vec::new();

            // Remove all relations of this kind — O(N) scan, no per-relation index work
            let removed_relations: Vec<Relation> = ent
                .relations
                .values()
                .filter(|rel| rel.kind == kind)
                .cloned()
                .collect();
            let removed = removed_relations.len();
            ent.relations.retain(|_, rel| rel.kind != kind);

            if removed == 0 && new_map.is_empty() {
                return Ok(());
            }
            for relation in &removed_relations {
                merkle_seeds.extend(entity_ids_for_relation(relation));
            }

            // Reserve and insert new relations
            ent.relations.reserve(new_map.len());
            for (id, rel) in new_map {
                merkle_seeds.extend(entity_ids_for_relation(&rel));
                ent.relations.insert(id, rel);
            }

            // Rebuild ALL adjacency indexes from scratch — O(R) total
            // Much faster than incremental remove+insert (O(R * degree) due to Vec::retain)
            let (outgoing, incoming, node_outgoing, node_incoming) =
                build_relation_indexes(&ent.relations);
            ent.outgoing = outgoing;
            ent.incoming = incoming;
            ent.node_outgoing = node_outgoing;
            ent.node_incoming = node_incoming;
            for relation in &removed_relations {
                self.record_relation_delta_remove(&ent, relation);
            }
            for relation in ent.relations.values().filter(|rel| rel.kind == kind) {
                self.record_relation_delta_upsert(&ent, relation.clone());
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
        }

        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        Ok(())
    }

    fn remove_relations_batch(&self, ids: &[&RelationId]) -> Result<(), KinDbError> {
        if ids.is_empty() {
            return Ok(());
        }

        {
            let mut ent = self.entities.write();
            let mut merkle_seeds = Vec::new();

            for id in ids {
                if let Some(rel) = ent.relations.remove(*id) {
                    merkle_seeds.extend(entity_ids_for_relation(&rel));
                    remove_relation_indexes(&mut ent, &rel);
                    self.record_relation_delta_remove(&ent, &rel);
                }
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
        }

        // Defer text index rebuild like upsert_relations_batch.
        self.text_full_rebuild_required
            .store(true, Ordering::Release);

        Ok(())
    }
}

impl ChangeStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Change DAG — changes lock only
    // -----------------------------------------------------------------------

    fn get_entity_history(&self, id: &EntityId) -> Result<Vec<SemanticChange>, KinDbError> {
        let chg = self.changes.read();
        // Find all changes that mention this entity in their deltas
        let mut history: Vec<SemanticChange> = chg
            .changes
            .values()
            .filter(|change| {
                change.entity_deltas.iter().any(|delta| match delta {
                    EntityDelta::Added(e) => e.id == *id,
                    EntityDelta::Modified { old, new } => old.id == *id || new.id == *id,
                    EntityDelta::Removed(eid) => eid == id,
                })
            })
            .cloned()
            .collect();
        // Sort by timestamp ascending
        history.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(history)
    }

    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> Result<Vec<SemanticChangeId>, KinDbError> {
        let chg = self.changes.read();

        // Collect all ancestors of `a`
        let mut ancestors_a: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*a];
        while let Some(cid) = stack.pop() {
            if ancestors_a.insert(cid) {
                if let Some(change) = chg.changes.get(&cid) {
                    stack.extend_from_slice(&change.parents);
                }
            }
        }

        // Walk ancestors of `b` with depth tracking, find common ancestors
        let mut bases: Vec<(SemanticChangeId, u32)> = Vec::new();
        let mut visited: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((*b, 0u32));
        while let Some((cid, depth)) = queue.pop_front() {
            if !visited.insert(cid) {
                continue;
            }
            if ancestors_a.contains(&cid) {
                bases.push((cid, depth));
                // Don't traverse further past a merge base
                continue;
            }
            if let Some(change) = chg.changes.get(&cid) {
                for parent in &change.parents {
                    queue.push_back((*parent, depth + 1));
                }
            }
        }

        // Return only the lowest-depth (nearest) common ancestors
        if let Some(min_depth) = bases.iter().map(|(_, d)| *d).min() {
            Ok(bases
                .into_iter()
                .filter(|(_, d)| *d == min_depth)
                .map(|(cid, _)| cid)
                .collect())
        } else {
            Ok(Vec::new())
        }
    }

    fn create_change(&self, change: &SemanticChange) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        append_entity_revisions(&mut ent, change);
        let revision_updates: Vec<(EntityId, Vec<EntityRevision>)> = change
            .entity_deltas
            .iter()
            .map(|delta| match delta {
                EntityDelta::Added(entity) | EntityDelta::Modified { new: entity, .. } => entity.id,
                EntityDelta::Removed(id) => *id,
            })
            .filter_map(|entity_id| {
                ent.entity_revisions
                    .get(&entity_id)
                    .cloned()
                    .map(|revisions| (entity_id, revisions))
            })
            .collect();
        for (entity_id, revisions) in revision_updates {
            self.record_entity_revisions_delta_upsert(entity_id, revisions);
        }
        drop(ent);

        let mut chg = self.changes.write();

        // Register in parent → children index
        for parent in &change.parents {
            let children = chg.change_children.entry(*parent).or_default();
            children.push(change.id);
            self.record_change_children_delta_upsert(*parent, children.clone());
        }

        chg.changes.insert(change.id, change.clone());
        self.record_change_delta_upsert(change.clone());
        Ok(())
    }

    fn get_change(&self, id: &SemanticChangeId) -> Result<Option<SemanticChange>, KinDbError> {
        Ok(self.changes.read().changes.get(id).cloned())
    }

    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> Result<Vec<SemanticChange>, KinDbError> {
        let chg = self.changes.read();

        // Walk backwards from head collecting changes until we hit base
        let mut result = Vec::new();
        let mut visited: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*head];

        while let Some(cid) = stack.pop() {
            if cid == *base || !visited.insert(cid) {
                continue;
            }
            if let Some(change) = chg.changes.get(&cid) {
                result.push(change.clone());
                stack.extend_from_slice(&change.parents);
            }
        }

        // Reverse so oldest-first
        result.reverse();
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Branch operations — changes lock only
    // -----------------------------------------------------------------------

    fn get_branch(&self, name: &BranchName) -> Result<Option<Branch>, KinDbError> {
        Ok(self.changes.read().branches.get(name).cloned())
    }

    fn create_branch(&self, branch: &Branch) -> Result<(), KinDbError> {
        let mut chg = self.changes.write();
        if chg.branches.contains_key(&branch.name) {
            return Err(KinDbError::DuplicateEntity(format!(
                "branch '{}' already exists",
                branch.name
            )));
        }
        chg.branches.insert(branch.name.clone(), branch.clone());
        self.record_branch_delta_upsert(branch.clone());
        Ok(())
    }

    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> Result<(), KinDbError> {
        let mut chg = self.changes.write();
        match chg.branches.get_mut(name) {
            Some(branch) => {
                branch.head = *new_head;
                self.record_branch_delta_upsert(branch.clone());
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("branch '{}'", name))),
        }
    }

    fn delete_branch(&self, name: &BranchName) -> Result<(), KinDbError> {
        self.changes.write().branches.remove(name);
        self.record_branch_delta_remove(name.clone());
        Ok(())
    }

    fn list_branches(&self) -> Result<Vec<Branch>, KinDbError> {
        Ok(self.changes.read().branches.values().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// Memory re-anchor — rename-durable annotation recall (Track B)
// ---------------------------------------------------------------------------

/// How a recalled annotation matched the queried entity. Carried in the recall
/// payload so an agent knows the epistemic basis of the memory it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallMatchBasis {
    /// The annotation is scoped directly to this entity's current id.
    Id,
    /// Re-anchored by fingerprint: the annotation's original scoped entity no
    /// longer resolves (renamed/removed) and its anchor matches this entity.
    FingerprintReanchor,
    /// Fingerprint collision: the anchor matches, but the annotation's scoped
    /// entity is a DIFFERENT entity that is still live (shared/duplicated
    /// fingerprint, e.g. templated code). Excluded from recall by default.
    FingerprintCollision,
}

/// An annotation recalled for an entity, tagged with the epistemic signal an
/// agent needs: how it matched and how stale its anchor is relative to the
/// entity's current fingerprint.
#[derive(Debug, Clone)]
pub struct RecalledAnnotation {
    pub annotation: Annotation,
    pub match_basis: RecallMatchBasis,
    pub staleness: StalenessState,
    /// Whether the matched/owning entity shares the queried entity's file.
    /// Always true for an `Id` match; false (unknown) for a re-anchor whose
    /// original entity is gone.
    pub same_file: bool,
    /// Whether the matched/owning entity shares the queried entity's kind.
    pub same_kind: bool,
}

/// Options controlling [`InMemoryGraph::recall_for_entity_with`].
#[derive(Debug, Clone, Default)]
pub struct RecallOptions {
    /// Include `Stale` matches (anchor structurally diverged). Off by default.
    pub include_stale: bool,
    /// Include `FingerprintCollision` matches — memory owned by a *different*
    /// live entity that shares the fingerprint. Off by default so recall never
    /// silently hands an agent another entity's memory.
    pub include_fingerprint_collisions: bool,
}

/// Staleness of an anchor relative to an entity's current fingerprint.
fn anchor_staleness(anchor: &SemanticAnchor, fp: &SemanticFingerprint) -> StalenessState {
    let ast_match = anchor.ast_hash == fp.ast_hash;
    let sig_match = anchor.signature_hash == fp.signature_hash;
    if ast_match && sig_match {
        StalenessState::Fresh
    } else if ast_match {
        // Structure unchanged, signature changed — the memory may still apply.
        StalenessState::Suspect
    } else {
        StalenessState::Stale
    }
}

fn recall_basis_rank(b: RecallMatchBasis) -> u8 {
    match b {
        RecallMatchBasis::Id => 0,
        RecallMatchBasis::FingerprintReanchor => 1,
        RecallMatchBasis::FingerprintCollision => 2,
    }
}

fn recall_staleness_rank(s: StalenessState) -> u8 {
    match s {
        StalenessState::Fresh => 0,
        StalenessState::Suspect => 1,
        StalenessState::Stale => 2,
    }
}

impl InMemoryGraph {
    /// Capture a rename-durable [`SemanticAnchor`] for an annotation from the
    /// first live entity scope it carries.
    ///
    /// An annotation deposited on `WorkScope::Entity(id)` is anchored to that id,
    /// but the id derives from (file, name, kind, line) — so a rename mints a new
    /// id and orphans the deposit. The entity's `SemanticFingerprint`
    /// (`ast_hash` + `signature_hash`) is rename-invariant (a pure rename changes
    /// only `name`), so recording it at deposit time lets recall re-anchor the
    /// memory by fingerprint after a rename. Returns `None` when no entity scope
    /// resolves to a live entity.
    fn capture_entity_anchor(&self, scopes: &[WorkScope]) -> Option<SemanticAnchor> {
        let ent = self.entities.read();
        scopes.iter().find_map(|scope| match scope {
            WorkScope::Entity(id) => ent.entities.get(id).map(|e| SemanticAnchor {
                ast_hash: e.fingerprint.ast_hash,
                signature_hash: e.fingerprint.signature_hash,
            }),
            _ => None,
        })
    }

    /// Recall annotations ("memory deposits") for an entity, re-anchoring across
    /// renames. Uses default [`RecallOptions`] (exclude `Stale` and fingerprint
    /// collisions).
    pub fn recall_for_entity(&self, entity_id: &EntityId) -> Vec<RecalledAnnotation> {
        self.recall_for_entity_with(entity_id, &RecallOptions::default())
    }

    /// Recall annotations for an entity by id OR by rename-durable fingerprint
    /// anchor, each tagged with its [`RecallMatchBasis`] and [`StalenessState`].
    ///
    /// An annotation matches when it is scoped to `entity_id` (basis `Id`), or
    /// when its `anchored_fingerprint` structurally matches the entity's current
    /// fingerprint (`ast_hash` equal). A fingerprint match is a
    /// `FingerprintReanchor` when the annotation's original scoped entity no
    /// longer resolves (a rename), or a `FingerprintCollision` when that scope
    /// still points at a different live entity (duplicated/templated code that
    /// happens to share a fingerprint). Collisions and `Stale` matches are
    /// excluded unless requested in `opts`.
    ///
    /// Results are returned in a deterministic total order: match basis
    /// (`Id` < re-anchor < collision), then staleness (fresh first), then
    /// same-file and same-kind preference, then annotation id.
    pub fn recall_for_entity_with(
        &self,
        entity_id: &EntityId,
        opts: &RecallOptions,
    ) -> Vec<RecalledAnnotation> {
        let ent = self.entities.read();
        let target = match ent.entities.get(entity_id) {
            Some(e) => e,
            None => return Vec::new(),
        };
        let target_fp = target.fingerprint.clone();
        let target_file = target.file_origin.clone();
        let target_kind = target.kind;

        let wrk = self.work.read();
        let mut out: Vec<RecalledAnnotation> = Vec::new();
        for ann in wrk.annotations.values() {
            let id_match = ann
                .scopes
                .iter()
                .any(|s| matches!(s, WorkScope::Entity(e) if e == entity_id));

            if id_match {
                // Staleness from the deposit-time anchor vs the current
                // fingerprint; without an anchor we cannot tell, so treat Fresh.
                let staleness = ann
                    .anchored_fingerprint
                    .as_ref()
                    .map(|a| anchor_staleness(a, &target_fp))
                    .unwrap_or(StalenessState::Fresh);
                if staleness == StalenessState::Stale && !opts.include_stale {
                    continue;
                }
                out.push(RecalledAnnotation {
                    annotation: ann.clone(),
                    match_basis: RecallMatchBasis::Id,
                    staleness,
                    same_file: true,
                    same_kind: true,
                });
                continue;
            }

            // Fingerprint re-anchor / collision: require a structural ast match.
            let anchor = match &ann.anchored_fingerprint {
                Some(a) if a.ast_hash == target_fp.ast_hash => a,
                _ => continue,
            };
            let staleness = anchor_staleness(anchor, &target_fp); // Fresh or Suspect

            // Does any entity scope still resolve to a LIVE entity != target?
            // If so this fingerprint match belongs to that living entity
            // (collision); otherwise the original is gone → a rename re-anchor.
            let owner = ann.scopes.iter().find_map(|s| match s {
                WorkScope::Entity(sid) if sid != entity_id => ent.entities.get(sid),
                _ => None,
            });

            let (match_basis, same_file, same_kind) = match owner {
                Some(o) => (
                    RecallMatchBasis::FingerprintCollision,
                    o.file_origin == target_file,
                    o.kind == target_kind,
                ),
                // Original entity gone — its file/kind are unknown, so we cannot
                // claim same-file/same-kind.
                None => (RecallMatchBasis::FingerprintReanchor, false, false),
            };

            if match_basis == RecallMatchBasis::FingerprintCollision
                && !opts.include_fingerprint_collisions
            {
                continue;
            }
            if staleness == StalenessState::Stale && !opts.include_stale {
                continue;
            }
            out.push(RecalledAnnotation {
                annotation: ann.clone(),
                match_basis,
                staleness,
                same_file,
                same_kind,
            });
        }

        // Deterministic total order: basis → staleness → same-file → same-kind →
        // annotation id. Prefers exact-id, fresh, same-file/same-kind memory.
        out.sort_by(|a, b| {
            recall_basis_rank(a.match_basis)
                .cmp(&recall_basis_rank(b.match_basis))
                .then(recall_staleness_rank(a.staleness).cmp(&recall_staleness_rank(b.staleness)))
                .then((!a.same_file).cmp(&(!b.same_file)))
                .then((!a.same_kind).cmp(&(!b.same_kind)))
                .then(
                    a.annotation
                        .annotation_id
                        .0
                        .cmp(&b.annotation.annotation_id.0),
                )
        });
        out
    }

    /// Actively re-scope orphaned annotations onto their renamed entity.
    ///
    /// For each annotation that has a fingerprint anchor but whose entity scopes
    /// no longer resolve to any live entity (the original was renamed/removed),
    /// find live entities whose fingerprint matches the anchor. When there is
    /// EXACTLY ONE such entity (an unambiguous rename target) append
    /// `WorkScope::Entity(new_id)` so future recall is an O(1) exact-id match.
    /// Ambiguous anchors (a fingerprint shared by several live entities —
    /// duplicated/templated code) are left untouched and continue to resolve via
    /// lazy fingerprint recall, so this never mis-anchors memory to the wrong
    /// duplicate. Returns the number of annotations re-scoped. Idempotent.
    ///
    /// This is the OPTIONAL active-detection path. kin-db never invokes it on its
    /// own (it is inert by default); the reconcile/sync path (kin-side) calls it
    /// behind a default-off flag after applying a graph diff.
    pub fn reanchor_orphaned_annotations(&self) -> usize {
        // Lock order: entities (read) BEFORE work (write).
        let ent = self.entities.read();
        let mut by_fp: HashMap<(Hash256, Hash256), Vec<EntityId>> = HashMap::new();
        for (id, e) in &ent.entities {
            by_fp
                .entry((e.fingerprint.ast_hash, e.fingerprint.signature_hash))
                .or_default()
                .push(*id);
        }

        let mut wrk = self.work.write();
        let mut count = 0usize;
        for ann in wrk.annotations.values_mut() {
            let anchor = match &ann.anchored_fingerprint {
                Some(a) => a,
                None => continue,
            };
            // Skip annotations already anchored to a live entity (not orphaned).
            let has_live_scope = ann
                .scopes
                .iter()
                .any(|s| matches!(s, WorkScope::Entity(id) if ent.entities.contains_key(id)));
            if has_live_scope {
                continue;
            }
            // Re-scope only on an UNAMBIGUOUS single fingerprint match.
            if let Some(ids) = by_fp.get(&(anchor.ast_hash, anchor.signature_hash)) {
                if ids.len() == 1 {
                    let new_id = ids[0];
                    let already = ann
                        .scopes
                        .iter()
                        .any(|s| matches!(s, WorkScope::Entity(id) if *id == new_id));
                    if !already {
                        ann.scopes.push(WorkScope::Entity(new_id));
                        count += 1;
                    }
                }
            }
        }
        count
    }
}

impl WorkStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Work graph operations (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_work_item(&self, item: &WorkItem) -> Result<(), KinDbError> {
        self.work
            .write()
            .work_items
            .insert(item.work_id, item.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_work_item(&self, id: &WorkId) -> Result<Option<WorkItem>, KinDbError> {
        Ok(self.work.read().work_items.get(id).cloned())
    }

    fn list_work_items(&self, filter: &WorkFilter) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let results = wrk
            .work_items
            .values()
            .filter(|item| {
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&item.kind) {
                        return false;
                    }
                }
                if let Some(ref statuses) = filter.statuses {
                    if !statuses.contains(&item.status) {
                        return false;
                    }
                }
                if let Some(ref scope) = filter.scope {
                    if !item.scopes.contains(scope) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_work_status(&self, id: &WorkId, status: WorkStatus) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        match wrk.work_items.get_mut(id) {
            Some(item) => {
                item.status = status;
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("work item '{}'", id))),
        }
    }

    fn delete_work_item(&self, id: &WorkId) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        wrk.work_items.remove(id);
        // Also remove associated links
        wrk.work_links.retain(|link| match link {
            WorkLink::Affects { work_id, .. } => work_id != id,
            WorkLink::DecomposesTo { parent, child } => parent != id && child != id,
            WorkLink::BlockedBy { blocked, blocker } => blocked != id && blocker != id,
            WorkLink::Implements { work_id, .. } => work_id != id,
            _ => true,
        });
        self.require_full_snapshot();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Annotation operations (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_annotation(&self, ann: &Annotation) -> Result<(), KinDbError> {
        let mut ann = ann.clone();
        // Capture the rename-durable fingerprint anchor at deposit time when the
        // caller did not supply one (Track B memory re-anchor). Acquires the
        // entities read lock first, then the work write lock — never both at
        // once — respecting the entities → work lock order.
        if ann.anchored_fingerprint.is_none() {
            ann.anchored_fingerprint = self.capture_entity_anchor(&ann.scopes);
        }
        self.work.write().annotations.insert(ann.annotation_id, ann);
        self.require_full_snapshot();
        Ok(())
    }

    fn get_annotation(&self, id: &AnnotationId) -> Result<Option<Annotation>, KinDbError> {
        Ok(self.work.read().annotations.get(id).cloned())
    }

    fn list_annotations(&self, filter: &AnnotationFilter) -> Result<Vec<Annotation>, KinDbError> {
        let wrk = self.work.read();
        let results = wrk
            .annotations
            .values()
            .filter(|ann| {
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&ann.kind) {
                        return false;
                    }
                }
                if let Some(ref scopes) = filter.scopes {
                    if !ann.scopes.iter().any(|s| scopes.contains(s)) {
                        return false;
                    }
                }
                if !filter.include_stale && ann.staleness == StalenessState::Stale {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_annotation_staleness(
        &self,
        id: &AnnotationId,
        staleness: StalenessState,
    ) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        match wrk.annotations.get_mut(id) {
            Some(ann) => {
                ann.staleness = staleness;
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("annotation '{}'", id))),
        }
    }

    fn delete_annotation(&self, id: &AnnotationId) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        wrk.annotations.remove(id);
        // Remove associated links
        wrk.work_links.retain(|link| match link {
            WorkLink::AttachedTo { annotation_id, .. } => annotation_id != id,
            WorkLink::Supersedes { new_id, old_id } => new_id != id && old_id != id,
            _ => true,
        });
        self.require_full_snapshot();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Work graph relationships (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        // Avoid duplicates
        if !wrk.work_links.contains(link) {
            wrk.work_links.push(link.clone());
            self.require_full_snapshot();
        }
        Ok(())
    }

    fn delete_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        self.work.write().work_links.retain(|l| l != link);
        self.require_full_snapshot();
        Ok(())
    }

    fn get_work_for_scope(&self, scope: &WorkScope) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        // Find work IDs that affect this scope
        let work_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::Affects { work_id, scope: s } if s == scope => Some(*work_id),
                _ => None,
            })
            .collect();
        // Also include items whose scopes contain this scope directly
        let mut results: Vec<WorkItem> = wrk
            .work_items
            .values()
            .filter(|item| item.scopes.contains(scope) || work_ids.contains(&item.work_id))
            .cloned()
            .collect();
        results.dedup_by_key(|item| item.work_id);
        Ok(results)
    }

    fn get_annotations_for_scope(&self, scope: &WorkScope) -> Result<Vec<Annotation>, KinDbError> {
        let wrk = self.work.read();
        let results = wrk
            .annotations
            .values()
            .filter(|ann| ann.scopes.contains(scope))
            .cloned()
            .collect();
        Ok(results)
    }

    fn get_child_work_items(&self, parent: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let child_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::DecomposesTo { parent: p, child } if p == parent => Some(*child),
                _ => None,
            })
            .collect();
        let results = child_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_parent_work_items(&self, child: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let parent_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::DecomposesTo { parent, child: c } if c == child => Some(*parent),
                _ => None,
            })
            .collect();
        let results = parent_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_blockers(&self, work_id: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let blocker_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::BlockedBy { blocked, blocker } if blocked == work_id => Some(*blocker),
                _ => None,
            })
            .collect();
        let results = blocker_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_blocked_work_items(&self, work_id: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let blocked_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::BlockedBy { blocked, blocker } if blocker == work_id => Some(*blocked),
                _ => None,
            })
            .collect();
        let results = blocked_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_implementors(&self, work_id: &WorkId) -> Result<Vec<WorkScope>, KinDbError> {
        let wrk = self.work.read();
        let scopes = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::Implements {
                    scope,
                    work_id: wid,
                } if wid == work_id => Some(scope.clone()),
                _ => None,
            })
            .collect();
        Ok(scopes)
    }

    fn get_annotations_for_work_item(
        &self,
        work_id: &WorkId,
    ) -> Result<Vec<Annotation>, KinDbError> {
        let wrk = self.work.read();
        let annotation_ids: Vec<AnnotationId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::AttachedTo {
                    annotation_id,
                    target: AnnotationTarget::Work(id),
                } if id == work_id => Some(*annotation_id),
                _ => None,
            })
            .collect();
        let results = annotation_ids
            .iter()
            .filter_map(|id| wrk.annotations.get(id).cloned())
            .collect();
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// ReviewStore implementation
// ---------------------------------------------------------------------------

impl ReviewStore for InMemoryGraph {
    type Error = KinDbError;

    fn create_review(&self, review: &Review) -> Result<(), KinDbError> {
        self.reviews
            .write()
            .reviews
            .insert(review.review_id, review.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review(&self, id: &ReviewId) -> Result<Option<Review>, KinDbError> {
        Ok(self.reviews.read().reviews.get(id).cloned())
    }

    fn list_reviews(&self, filter: &ReviewFilter) -> Result<Vec<Review>, KinDbError> {
        let rev = self.reviews.read();
        let results = rev
            .reviews
            .values()
            .filter(|r| {
                if let Some(ref states) = filter.states {
                    if !states.contains(&r.state) {
                        return false;
                    }
                }
                if let Some(ref reviewer_name) = filter.reviewer {
                    // Check if this reviewer has an assignment for this review
                    if let Some(assignments) = rev.review_assignments.get(&r.review_id) {
                        if !assignments
                            .iter()
                            .any(|a| a.reviewer.name == *reviewer_name)
                        {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_review_state(
        &self,
        id: &ReviewId,
        state: ReviewDecisionState,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        match rev.reviews.get_mut(id) {
            Some(review) => {
                review.state = state;
                review.updated_at = Timestamp::now();
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("review '{}'", id))),
        }
    }

    fn delete_review(&self, id: &ReviewId) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        rev.reviews.remove(id);
        rev.review_decisions.remove(id);
        rev.review_assignments.remove(id);
        // Remove notes belonging to this review
        rev.review_notes.retain(|_, note| note.review_id != *id);
        // Remove discussions belonging to this review
        rev.review_discussions
            .retain(|_, disc| disc.review_id != *id);
        self.require_full_snapshot();
        Ok(())
    }

    fn add_review_decision(
        &self,
        id: &ReviewId,
        decision: &ReviewDecision,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(id) {
            return Err(KinDbError::NotFound(format!("review '{}'", id)));
        }
        rev.review_decisions
            .entry(*id)
            .or_default()
            .push(decision.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_decisions(&self, id: &ReviewId) -> Result<Vec<ReviewDecision>, KinDbError> {
        Ok(self
            .reviews
            .read()
            .review_decisions
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    fn add_review_note(&self, note: &ReviewNote) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(&note.review_id) {
            return Err(KinDbError::NotFound(format!("review '{}'", note.review_id)));
        }
        rev.review_notes.insert(note.note_id, note.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_notes(&self, id: &ReviewId) -> Result<Vec<ReviewNote>, KinDbError> {
        let rev = self.reviews.read();
        let results = rev
            .review_notes
            .values()
            .filter(|note| note.review_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn delete_review_note(&self, note_id: &ReviewNoteId) -> Result<(), KinDbError> {
        self.reviews.write().review_notes.remove(note_id);
        self.require_full_snapshot();
        Ok(())
    }

    fn create_review_discussion(&self, discussion: &ReviewDiscussion) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(&discussion.review_id) {
            return Err(KinDbError::NotFound(format!(
                "review '{}'",
                discussion.review_id
            )));
        }
        rev.review_discussions
            .insert(discussion.discussion_id, discussion.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_discussions(&self, id: &ReviewId) -> Result<Vec<ReviewDiscussion>, KinDbError> {
        let rev = self.reviews.read();
        let results = rev
            .review_discussions
            .values()
            .filter(|disc| disc.review_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn add_discussion_comment(
        &self,
        id: &ReviewDiscussionId,
        comment: &ReviewComment,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        match rev.review_discussions.get_mut(id) {
            Some(disc) => {
                disc.comments.push(comment.clone());
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("review discussion '{}'", id))),
        }
    }

    fn set_discussion_state(
        &self,
        id: &ReviewDiscussionId,
        state: ReviewDiscussionState,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        match rev.review_discussions.get_mut(id) {
            Some(disc) => {
                disc.state = state;
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("review discussion '{}'", id))),
        }
    }

    fn assign_reviewer(&self, assignment: &ReviewAssignment) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(&assignment.review_id) {
            return Err(KinDbError::NotFound(format!(
                "review '{}'",
                assignment.review_id
            )));
        }
        rev.review_assignments
            .entry(assignment.review_id)
            .or_default()
            .push(assignment.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_assignments(&self, id: &ReviewId) -> Result<Vec<ReviewAssignment>, KinDbError> {
        Ok(self
            .reviews
            .read()
            .review_assignments
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    fn remove_reviewer(&self, review_id: &ReviewId, reviewer: &str) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if let Some(assignments) = rev.review_assignments.get_mut(review_id) {
            assignments.retain(|a| a.reviewer.name != reviewer);
        }
        self.require_full_snapshot();
        Ok(())
    }
}

impl VerificationStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Verification graph operations (Phase 9) — verification + entities locks
    // -----------------------------------------------------------------------

    fn create_test_case(&self, test: &TestCase) -> Result<(), KinDbError> {
        let entity_scopes: Vec<EntityId> = {
            let ent = self.entities.read();
            let mut seen = HashSet::new();
            test.scopes
                .iter()
                .filter_map(|scope| match scope {
                    WorkScope::Entity(entity_id)
                        if ent.entities.contains_key(entity_id) && seen.insert(*entity_id) =>
                    {
                        Some(*entity_id)
                    }
                    _ => None,
                })
                .collect()
        };
        let mut ver = self.verification.write();
        ver.test_cases.insert(test.test_id, test.clone());
        drop(ver);
        if !entity_scopes.is_empty() {
            let relations: Vec<Relation> = entity_scopes
                .into_iter()
                .map(|entity_id| {
                    verification_relation(
                        RelationKind::Covers,
                        GraphNodeId::Test(test.test_id),
                        GraphNodeId::Entity(entity_id),
                    )
                })
                .collect();
            self.upsert_relations_batch(&relations)?;
        }
        self.require_full_snapshot();
        Ok(())
    }

    fn get_test_case(&self, id: &TestId) -> Result<Option<TestCase>, KinDbError> {
        Ok(self.verification.read().test_cases.get(id).cloned())
    }

    fn get_tests_for_entity(&self, id: &EntityId) -> Result<Vec<TestCase>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Entity(*id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::Covers, GraphNodeId::Test(test_id)) => Some(test_id),
                _ => None,
            })
            .filter(|test_id| seen.insert(*test_id))
            .filter_map(|test_id| ver.test_cases.get(&test_id).cloned())
            .collect())
    }

    fn delete_test_case(&self, id: &TestId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut ver = self.verification.write();
        ver.test_cases.remove(id);
        ver.mock_hints.retain(|h| h.test_id != *id);
        let node = GraphNodeId::Test(*id);
        let mut relation_ids = Vec::new();
        if let Some(outgoing) = ent.node_outgoing.get(&node) {
            relation_ids.extend(outgoing.iter().copied());
        }
        if let Some(incoming) = ent.node_incoming.get(&node) {
            relation_ids.extend(incoming.iter().copied());
        }
        relation_ids.sort_unstable_by_key(|relation_id| relation_id.0);
        relation_ids.dedup();
        for relation_id in relation_ids {
            if let Some(relation) = ent.relations.remove(&relation_id) {
                remove_relation_indexes(&mut ent, &relation);
            }
        }
        self.require_full_snapshot();
        Ok(())
    }

    fn create_assertion(&self, assertion: &Assertion) -> Result<(), KinDbError> {
        self.verification
            .write()
            .assertions
            .insert(assertion.assertion_id, assertion.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_assertion(&self, id: &AssertionId) -> Result<Option<Assertion>, KinDbError> {
        Ok(self.verification.read().assertions.get(id).cloned())
    }

    fn get_coverage_summary(&self) -> Result<CoverageSummary, KinDbError> {
        // Lock ordering: entities → verification
        let ent = self.entities.read();
        let total = ent.entities.len();
        let covered_ids: std::collections::HashSet<EntityId> = ent
            .relations
            .values()
            .filter_map(
                |relation| match (relation.kind, relation.src, relation.dst) {
                    (
                        RelationKind::Covers,
                        GraphNodeId::Test(_),
                        GraphNodeId::Entity(entity_id),
                    ) => Some(entity_id),
                    _ => None,
                },
            )
            .collect();
        let covered = covered_ids.len();
        let ratio = if total > 0 {
            covered as f64 / total as f64
        } else {
            0.0
        };
        let missing: Vec<EntityId> = ent
            .entities
            .keys()
            .filter(|id| !covered_ids.contains(id))
            .copied()
            .collect();
        Ok(CoverageSummary {
            total_entities: total,
            covered_entities: covered,
            coverage_ratio: ratio,
            missing_proof: missing,
        })
    }

    // -----------------------------------------------------------------------
    // Verification runs (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn create_verification_run(&self, run: &VerificationRun) -> Result<(), KinDbError> {
        self.verification
            .write()
            .verification_runs
            .insert(run.run_id, run.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_verification_run(
        &self,
        id: &VerificationRunId,
    ) -> Result<Option<VerificationRun>, KinDbError> {
        Ok(self.verification.read().verification_runs.get(id).cloned())
    }

    fn list_runs_for_test(&self, test_id: &TestId) -> Result<Vec<VerificationRun>, KinDbError> {
        let ver = self.verification.read();
        let results = ver
            .verification_runs
            .values()
            .filter(|run| run.test_ids.contains(test_id))
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Test ↔ scope linking (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn create_test_covers_entity(
        &self,
        test_id: &TestId,
        entity_id: &EntityId,
    ) -> Result<(), KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let test_exists = ver.test_cases.contains_key(test_id);
        let entity_exists = ent.entities.contains_key(entity_id);
        drop(ver);
        drop(ent);
        if !test_exists || !entity_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::Covers,
            GraphNodeId::Test(*test_id),
            GraphNodeId::Entity(*entity_id),
        ))
    }

    fn create_test_covers_contract(
        &self,
        test_id: &TestId,
        contract_id: &ContractId,
    ) -> Result<(), KinDbError> {
        let ver = self.verification.read();
        let test_exists = ver.test_cases.contains_key(test_id);
        let contract_exists = ver.contracts.contains_key(contract_id);
        drop(ver);
        if !test_exists || !contract_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::Covers,
            GraphNodeId::Test(*test_id),
            GraphNodeId::Contract(*contract_id),
        ))
    }

    fn create_test_verifies_work(
        &self,
        test_id: &TestId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        let wrk = self.work.read();
        let ver = self.verification.read();
        let test_exists = ver.test_cases.contains_key(test_id);
        let work_exists = wrk.work_items.contains_key(work_id);
        drop(ver);
        drop(wrk);
        if !test_exists || !work_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::Covers,
            GraphNodeId::Test(*test_id),
            GraphNodeId::Work(*work_id),
        ))
    }

    fn get_tests_covering_contract(
        &self,
        contract_id: &ContractId,
    ) -> Result<Vec<TestCase>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Contract(*contract_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::Covers, GraphNodeId::Test(test_id)) => Some(test_id),
                _ => None,
            })
            .filter(|test_id| seen.insert(*test_id))
            .filter_map(|test_id| ver.test_cases.get(&test_id).cloned())
            .collect())
    }

    fn get_tests_verifying_work(&self, work_id: &WorkId) -> Result<Vec<TestCase>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Work(*work_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::Covers, GraphNodeId::Test(test_id)) => Some(test_id),
                _ => None,
            })
            .filter(|test_id| seen.insert(*test_id))
            .filter_map(|test_id| ver.test_cases.get(&test_id).cloned())
            .collect())
    }

    // -----------------------------------------------------------------------
    // Mock hints (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn create_mock_hint(&self, hint: &MockHint) -> Result<(), KinDbError> {
        self.verification.write().mock_hints.push(hint.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_mock_hints_for_test(&self, test_id: &TestId) -> Result<Vec<MockHint>, KinDbError> {
        let ver = self.verification.read();
        let results = ver
            .mock_hints
            .iter()
            .filter(|h| h.test_id == *test_id)
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Verification run → proof links (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn link_run_proves_entity(
        &self,
        run_id: &VerificationRunId,
        entity_id: &EntityId,
    ) -> Result<(), KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let run_exists = ver.verification_runs.contains_key(run_id);
        let entity_exists = ent.entities.contains_key(entity_id);
        drop(ver);
        drop(ent);
        if !run_exists || !entity_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::DerivedFrom,
            GraphNodeId::VerificationRun(*run_id),
            GraphNodeId::Entity(*entity_id),
        ))
    }

    fn link_run_proves_work(
        &self,
        run_id: &VerificationRunId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        let wrk = self.work.read();
        let ver = self.verification.read();
        let run_exists = ver.verification_runs.contains_key(run_id);
        let work_exists = wrk.work_items.contains_key(work_id);
        drop(ver);
        drop(wrk);
        if !run_exists || !work_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::DerivedFrom,
            GraphNodeId::VerificationRun(*run_id),
            GraphNodeId::Work(*work_id),
        ))
    }

    fn list_runs_proving_entity(
        &self,
        entity_id: &EntityId,
    ) -> Result<Vec<VerificationRun>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Entity(*entity_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::DerivedFrom, GraphNodeId::VerificationRun(run_id)) => Some(run_id),
                _ => None,
            })
            .filter(|run_id| seen.insert(*run_id))
            .filter_map(|run_id| ver.verification_runs.get(&run_id).cloned())
            .collect())
    }

    fn list_runs_proving_work(&self, work_id: &WorkId) -> Result<Vec<VerificationRun>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Work(*work_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::DerivedFrom, GraphNodeId::VerificationRun(run_id)) => Some(run_id),
                _ => None,
            })
            .filter(|run_id| seen.insert(*run_id))
            .filter_map(|run_id| ver.verification_runs.get(&run_id).cloned())
            .collect())
    }

    // -----------------------------------------------------------------------
    // Contract CRUD — verification lock only
    // -----------------------------------------------------------------------

    fn create_contract(&self, contract: &Contract) -> Result<(), KinDbError> {
        // Contract uses EntityId for its `id` field but the trait keys by ContractId.
        // We derive a ContractId from the contract's EntityId for storage.
        let key = ContractId(contract.id.0);
        self.verification
            .write()
            .contracts
            .insert(key, contract.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, KinDbError> {
        Ok(self.verification.read().contracts.get(id).cloned())
    }

    fn list_contracts(&self) -> Result<Vec<Contract>, KinDbError> {
        Ok(self
            .verification
            .read()
            .contracts
            .values()
            .cloned()
            .collect())
    }

    // -----------------------------------------------------------------------
    // Contract coverage (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn get_contract_coverage_summary(&self) -> Result<ContractCoverageSummary, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let total = ver.contracts.len();
        let covered_ids: std::collections::HashSet<ContractId> = ent
            .relations
            .values()
            .filter_map(
                |relation| match (relation.kind, relation.src, relation.dst) {
                    (
                        RelationKind::Covers,
                        GraphNodeId::Test(_),
                        GraphNodeId::Contract(contract_id),
                    ) => Some(contract_id),
                    _ => None,
                },
            )
            .collect();
        let covered = ver
            .contracts
            .keys()
            .filter(|cid| covered_ids.contains(cid))
            .count();
        let ratio = if total > 0 {
            covered as f64 / total as f64
        } else {
            0.0
        };
        let uncovered: Vec<ContractId> = ver
            .contracts
            .keys()
            .filter(|cid| !covered_ids.contains(cid))
            .copied()
            .collect();
        Ok(ContractCoverageSummary {
            total_contracts: total,
            covered_contracts: covered,
            coverage_ratio: ratio,
            uncovered_contract_ids: uncovered,
        })
    }
}

impl ProvenanceStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Provenance operations (Phase 10) — provenance lock only
    // -----------------------------------------------------------------------

    fn create_actor(&self, actor: &Actor) -> Result<(), KinDbError> {
        self.provenance
            .write()
            .actors
            .insert(actor.actor_id, actor.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_actor(&self, id: &ActorId) -> Result<Option<Actor>, KinDbError> {
        Ok(self.provenance.read().actors.get(id).cloned())
    }

    fn list_actors(&self) -> Result<Vec<Actor>, KinDbError> {
        Ok(self.provenance.read().actors.values().cloned().collect())
    }

    fn create_delegation(&self, delegation: &Delegation) -> Result<(), KinDbError> {
        self.provenance.write().delegations.push(delegation.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_delegations_for_actor(&self, id: &ActorId) -> Result<Vec<Delegation>, KinDbError> {
        let prv = self.provenance.read();
        let results = prv
            .delegations
            .iter()
            .filter(|d| d.principal == *id || d.delegate == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn create_approval(&self, approval: &Approval) -> Result<(), KinDbError> {
        self.provenance.write().approvals.push(approval.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_approvals_for_change(&self, id: &SemanticChangeId) -> Result<Vec<Approval>, KinDbError> {
        let prv = self.provenance.read();
        let results = prv
            .approvals
            .iter()
            .filter(|a| a.change_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn record_audit_event(&self, event: &AuditEvent) -> Result<(), KinDbError> {
        self.provenance.write().audit_events.push(event.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn query_audit_events(
        &self,
        actor_id: Option<&ActorId>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, KinDbError> {
        let prv = self.provenance.read();
        let results: Vec<AuditEvent> = prv
            .audit_events
            .iter()
            .rev()
            .filter(|e| {
                if let Some(aid) = actor_id {
                    e.actor_id == *aid
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(results)
    }
}

impl SessionStore for InMemoryGraph {
    type Error = KinDbError;

    fn upsert_session(&self, session: &AgentSession) -> Result<(), KinDbError> {
        self.sessions
            .write()
            .sessions
            .insert(session.session_id, session.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_session(&self, session_id: &SessionId) -> Result<Option<AgentSession>, KinDbError> {
        Ok(self.sessions.read().sessions.get(session_id).cloned())
    }

    fn delete_session(&self, session_id: &SessionId) -> Result<(), KinDbError> {
        self.sessions.write().sessions.remove(session_id);
        self.require_full_snapshot();
        Ok(())
    }

    fn list_sessions(&self) -> Result<Vec<AgentSession>, KinDbError> {
        Ok(self.sessions.read().sessions.values().cloned().collect())
    }

    fn update_heartbeat(
        &self,
        session_id: &SessionId,
        heartbeat: &crate::types::Timestamp,
    ) -> Result<(), KinDbError> {
        if let Some(session) = self.sessions.write().sessions.get_mut(session_id) {
            session.last_heartbeat = heartbeat.clone();
            self.require_full_snapshot();
        }
        Ok(())
    }

    fn register_intent(&self, intent: &Intent) -> Result<(), KinDbError> {
        self.sessions
            .write()
            .intents
            .insert(intent.intent_id, intent.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_intent(&self, intent_id: &IntentId) -> Result<Option<Intent>, KinDbError> {
        Ok(self.sessions.read().intents.get(intent_id).cloned())
    }

    fn delete_intent(&self, intent_id: &IntentId) -> Result<(), KinDbError> {
        self.sessions.write().intents.remove(intent_id);
        self.require_full_snapshot();
        Ok(())
    }

    fn list_intents_for_session(&self, session_id: &SessionId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self
            .sessions
            .read()
            .intents
            .values()
            .filter(|i| i.session_id == *session_id)
            .cloned()
            .collect())
    }

    fn list_all_intents(&self) -> Result<Vec<Intent>, KinDbError> {
        Ok(self.sessions.read().intents.values().cloned().collect())
    }
}

impl GraphStore for InMemoryGraph {
    type Error = KinDbError;
}

/// Check whether an entity matches all filter criteria.
fn matches_filter(entity: &Entity, filter: &EntityFilter) -> bool {
    if let Some(ref kinds) = filter.kinds {
        if !kinds.contains(&entity.kind) {
            return false;
        }
    }

    if let Some(ref langs) = filter.languages {
        if !langs.contains(&entity.language) {
            return false;
        }
    }

    if let Some(ref pattern) = filter.name_pattern {
        let pat = pattern.to_lowercase();
        let name = entity.name.to_lowercase();
        if let Some(suffix) = pat.strip_prefix('*') {
            if !name.ends_with(suffix) {
                return false;
            }
        } else if let Some(prefix) = pat.strip_suffix('*') {
            if !name.starts_with(prefix) {
                return false;
            }
        } else if !name.contains(&pat) {
            return false;
        }
    }

    if let Some(ref fp) = filter.file_path {
        match &entity.file_origin {
            Some(origin) if origin == fp => {}
            _ => return false,
        }
    }

    if let Some(ref roles) = filter.roles {
        if !roles.contains(&entity.role) {
            return false;
        }
    }

    true
}

impl RetrievalKeyFileResolver for InMemoryGraph {
    fn file_path_for_retrieval_key(&self, key: RetrievalKey) -> Option<FilePathId> {
        self.resolve_retrieval_key(&key)
            .and_then(|item| item.file_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn test_vector_index_dimension_mismatch_auto_recovery() {
        let graph = InMemoryGraph::new();
        // Setup a vector index with a mismatching dimension (e.g. 100)
        let mismatched_vi = Arc::new(VectorIndex::new(100).unwrap());
        *graph.vector_index.lock() = Some(mismatched_vi);

        // Add some entities so we can verify they get queued for embedding
        let entity = test_entity("foo", "src/main.rs");
        graph.upsert_entities_batch(&[entity]).unwrap();

        // Clear the queue so we can verify the auto-recovery queues missing items
        graph.embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);

        // Fetch the vector index, which should trigger recovery because the embedder has a different dimension
        let vi = graph.get_vector_index().unwrap();

        // Dimensions should match the embedder now
        let embedder = graph.get_embedder().unwrap();
        assert_eq!(vi.dimensions(), embedder.dimensions());

        // The entity should be queued for embedding now
        assert_eq!(graph.pending_embeddings(), 1);
    }

    fn test_entity(name: &str, file: &str) -> Entity {
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
            file_origin: Some(FilePathId::new(file)),
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

    /// Once the graph is one connected component, adding relations one at a time
    /// (as test-materialization does) must not refresh the Merkle root per
    /// upsert — that is O(component) each, i.e. O(N^2) over the burst. Deferral
    /// collapses the whole burst into a single batch Merkle build at the next
    /// root read.
    #[test]
    fn single_relation_upserts_defer_to_one_batch_merkle() {
        let graph = InMemoryGraph::new();
        let n: usize = 12_000;
        let entities: Vec<Entity> = (0..n as u128)
            .map(|i| test_entity_with_id(i + 1, &format!("entity_{i}")))
            .collect();
        graph.batch_upsert_entities(&entities).unwrap();

        // Chain every entity so the whole graph is one weakly-connected
        // component — this is what makes a per-mutation refresh touch the entire
        // graph in the buggy path.
        let chain: Vec<Relation> = entities
            .windows(2)
            .map(|window| test_relation(window[0].id, window[1].id, RelationKind::Calls))
            .collect();
        graph.upsert_relations_batch(&chain).unwrap();

        MERKLE_FLUSH_COUNT.store(0, Ordering::Relaxed);
        let start = std::time::Instant::now();
        // Thousands of single-relation upserts, exactly like
        // materialize_discovered_tests' per-test `upsert_relation` loop.
        for i in 0..3_000usize {
            let src = entities[i % n].id;
            let dst = entities[(i * 7 + 1) % n].id;
            graph
                .upsert_relation(&test_relation(src, dst, RelationKind::Tests))
                .unwrap();
        }

        // Nothing has read the root, so not one refresh should have run.
        assert_eq!(
            MERKLE_FLUSH_COUNT.load(Ordering::Relaxed),
            0,
            "single-entity upserts must defer Merkle work, not refresh eagerly"
        );

        // The first root read reconciles everything in exactly one batch build.
        let root = graph.compute_root_hash();
        let elapsed = start.elapsed();
        assert_eq!(
            MERKLE_FLUSH_COUNT.load(Ordering::Relaxed),
            1,
            "reconciliation must be a single batch refresh, not one per mutation"
        );
        assert_eq!(
            root,
            compute_graph_root_hash(&graph.to_snapshot()),
            "deferred root must equal the cold frozen root"
        );
        // The old O(N^2) path is minutes for this size; deferral is well under
        // this generous bound.
        assert!(
            elapsed.as_secs() < 30,
            "3000 single-relation upserts + reconcile took {elapsed:?} — non-linear regression"
        );
    }

    // ----------------------------------------------------------------------
    // FIR-853: boot-time adjacency reuse
    // ----------------------------------------------------------------------

    /// When the persisted entity-level adjacency is consistent with relations,
    /// the loader reuses it as-is instead of recomputing from relations.
    #[test]
    fn adjacency_reuse_when_persisted_consistent() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let rel = test_relation(e1, e2, RelationKind::Calls);
        let rid = rel.id;
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid, rel);

        // The exact adjacency a correct writer would persist.
        let mut persisted_outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_outgoing.insert(e1, vec![rid]);
        let mut persisted_incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_incoming.insert(e2, vec![rid]);

        let (outgoing, incoming, node_outgoing, node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, persisted_outgoing, persisted_incoming);

        assert_eq!(reuse, AdjacencyReuse::Reused);
        assert_eq!(outgoing.get(&e1), Some(&vec![rid]));
        assert_eq!(incoming.get(&e2), Some(&vec![rid]));
        // Node-level maps are never persisted, so they are always derived.
        assert_eq!(
            node_outgoing.get(&GraphNodeId::Entity(e1)),
            Some(&vec![rid])
        );
        assert_eq!(
            node_incoming.get(&GraphNodeId::Entity(e2)),
            Some(&vec![rid])
        );
    }

    /// Definitive "reuse, not recompute" proof: feed a persisted adjacency that
    /// is edge-count-consistent but maps the edge to DIFFERENT entities than the
    /// relations imply. A recompute would derive the correct mapping; reuse
    /// returns the persisted (deliberately divergent) mapping verbatim.
    #[test]
    fn adjacency_reuse_returns_persisted_not_recomputed() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let decoy_src = EntityId::new();
        let decoy_dst = EntityId::new();
        let rel = test_relation(e1, e2, RelationKind::Calls);
        let rid = rel.id;
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid, rel);

        // Same edge COUNT (1 outgoing, 1 incoming) but mapped to decoy entities.
        let mut persisted_outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_outgoing.insert(decoy_src, vec![rid]);
        let mut persisted_incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_incoming.insert(decoy_dst, vec![rid]);

        let (outgoing, incoming, _node_outgoing, _node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, persisted_outgoing, persisted_incoming);

        assert_eq!(reuse, AdjacencyReuse::Reused);
        // Reused verbatim — the decoy mapping survives, proving no recompute ran.
        assert_eq!(outgoing.get(&decoy_src), Some(&vec![rid]));
        assert!(outgoing.get(&e1).is_none());
        assert_eq!(incoming.get(&decoy_dst), Some(&vec![rid]));
        assert!(incoming.get(&e2).is_none());
    }

    /// An empty persisted adjacency (e.g. an older snapshot that never wrote it)
    /// alongside real relations must be rebuilt, never trusted.
    #[test]
    fn adjacency_rebuild_when_persisted_empty() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();
        let r1 = test_relation(e1, e2, RelationKind::Calls);
        let r2 = test_relation(e2, e3, RelationKind::Contains);
        let (rid1, rid2) = (r1.id, r2.id);
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid1, r1);
        relations.insert(rid2, r2);

        let (outgoing, incoming, _node_outgoing, _node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, HashMap::new(), HashMap::new());

        assert_eq!(reuse, AdjacencyReuse::Rebuilt);
        assert_eq!(outgoing.get(&e1), Some(&vec![rid1]));
        assert_eq!(outgoing.get(&e2), Some(&vec![rid2]));
        assert_eq!(incoming.get(&e2), Some(&vec![rid1]));
        assert_eq!(incoming.get(&e3), Some(&vec![rid2]));
    }

    /// A persisted adjacency whose edge tally disagrees with relations is
    /// inconsistent and must be rebuilt rather than reused.
    #[test]
    fn adjacency_rebuild_when_persisted_inconsistent() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let r1 = test_relation(e1, e2, RelationKind::Calls);
        let r2 = test_relation(e2, e1, RelationKind::Calls);
        let (rid1, rid2) = (r1.id, r2.id);
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid1, r1);
        relations.insert(rid2, r2);

        // Persisted outgoing only records ONE of the two outgoing edges → tally
        // mismatch (1 != 2) forces a rebuild.
        let mut persisted_outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_outgoing.insert(e1, vec![rid1]);
        let mut persisted_incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_incoming.insert(e2, vec![rid1]);
        persisted_incoming.insert(e1, vec![rid2]);

        let (outgoing, incoming, _node_outgoing, _node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, persisted_outgoing, persisted_incoming);

        assert_eq!(reuse, AdjacencyReuse::Rebuilt);
        // Rebuilt correctly from relations: both edges present on both sides.
        assert_eq!(outgoing.get(&e1), Some(&vec![rid1]));
        assert_eq!(outgoing.get(&e2), Some(&vec![rid2]));
        assert_eq!(incoming.get(&e2), Some(&vec![rid1]));
        assert_eq!(incoming.get(&e1), Some(&vec![rid2]));
    }

    /// Empty relations + empty persisted adjacency is the trivial consistent
    /// case and counts as a (no-op) reuse.
    #[test]
    fn adjacency_reuse_when_graph_empty() {
        let relations: HashMap<RelationId, Relation> = HashMap::new();
        let (outgoing, incoming, node_outgoing, node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, HashMap::new(), HashMap::new());
        assert_eq!(reuse, AdjacencyReuse::Reused);
        assert!(outgoing.is_empty());
        assert!(incoming.is_empty());
        assert!(node_outgoing.is_empty());
        assert!(node_incoming.is_empty());
    }

    /// End-to-end boot path: a snapshot carrying persisted adjacency loads into a
    /// graph whose neighbor queries match the relations (the reuse branch must
    /// produce a correct in-memory graph, not just a fast one).
    #[test]
    fn from_snapshot_with_persisted_adjacency_resolves_neighbors() {
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let rid = rel.id;

        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities.insert(e1.id, e1.clone());
        snapshot.entities.insert(e2.id, e2.clone());
        snapshot.relations.insert(rid, rel);
        // Persist a CONSISTENT entity-level adjacency so the reuse branch runs.
        snapshot.outgoing.insert(e1.id, vec![rid]);
        snapshot.incoming.insert(e2.id, vec![rid]);

        let graph = InMemoryGraph::from_snapshot(snapshot);
        assert_eq!(graph.relation_count(), 1);
        // Reads the (reused) entity-level `outgoing` adjacency.
        let outgoing = graph.get_relations(&e1.id, &[]).unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].id, rid);
        assert_eq!(outgoing[0].dst, GraphNodeId::Entity(e2.id));
    }

    #[test]
    fn upsert_and_get_entity() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        let fetched = graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "foo");
        assert_eq!(graph.entity_count(), 1);
    }

    #[test]
    fn upsert_entity_overwrites() {
        let graph = InMemoryGraph::new();
        let mut entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        entity.name = "bar".to_string();
        graph.upsert_entity(&entity).unwrap();

        let fetched = graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "bar");
        assert_eq!(graph.entity_count(), 1);
    }

    #[test]
    fn remove_entity_cleans_up() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        graph.remove_entity(&id).unwrap();

        assert!(graph.get_entity(&id).unwrap().is_none());
        assert_eq!(graph.entity_count(), 0);
    }

    #[test]
    fn remove_entity_cleans_up_relations_both_sides() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let e3 = test_entity("other", "c.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        // e1 → e2 (outgoing from e1, incoming to e2)
        let rel1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        // e3 → e2 (outgoing from e3, incoming to e2)
        let rel2 = test_relation(e3.id, e2.id, RelationKind::Calls);
        // e2 → e3 (outgoing from e2, incoming to e3)
        let rel3 = test_relation(e2.id, e3.id, RelationKind::Contains);

        graph.upsert_relation(&rel1).unwrap();
        graph.upsert_relation(&rel2).unwrap();
        graph.upsert_relation(&rel3).unwrap();

        assert_eq!(graph.relation_count(), 3);

        // Remove e2 — should clean up all 3 relations and both sides' edge vecs
        graph.remove_entity(&e2.id).unwrap();

        // e2 is gone
        assert!(graph.get_entity(&e2.id).unwrap().is_none());

        // All 3 relations should be removed from the relations map
        assert_eq!(
            graph.relation_count(),
            0,
            "all relations touching e2 should be removed"
        );

        // e1 should have no outgoing relations left (rel1 was e1→e2)
        let e1_rels = graph.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert!(
            e1_rels.is_empty(),
            "e1 should have no outgoing calls after e2 removed"
        );

        // e3 should have no outgoing relations left (rel2 was e3→e2)
        let e3_out = graph.get_relations(&e3.id, &[RelationKind::Calls]).unwrap();
        assert!(
            e3_out.is_empty(),
            "e3 should have no outgoing calls after e2 removed"
        );

        // e3 should have no incoming relations left (rel3 was e2→e3)
        let e3_all = graph.get_all_relations_for_entity(&e3.id).unwrap();
        assert!(
            e3_all.is_empty(),
            "e3 should have no relations after e2 removed"
        );
    }

    #[test]
    fn upsert_and_get_relations() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        // Outgoing from e1
        let rels = graph.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dst, GraphNodeId::Entity(e2.id));

        // All relations for e2 (incoming)
        let rels = graph.get_all_relations_for_entity(&e2.id).unwrap();
        assert_eq!(rels.len(), 1);
    }

    #[test]
    fn remove_relation() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let rid = rel.id;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.remove_relation(&rid).unwrap();

        assert!(graph.get_relations(&e1.id, &[]).unwrap().is_empty());
        assert_eq!(graph.relation_count(), 0);
    }

    #[test]
    fn merkle_root_stays_current_across_live_entity_relation_mutations() {
        fn assert_current(graph: &InMemoryGraph) {
            assert_eq!(
                graph.snapshot_root_hash(),
                Some(compute_graph_root_hash(&graph.to_snapshot())),
                "maintained live root must match cold recompute"
            );
        }

        let graph = InMemoryGraph::new();
        assert_current(&graph);

        let mut root = test_entity("root", "a.rs");
        let child = test_entity("child", "b.rs");
        let leaf = test_entity("leaf", "c.rs");
        graph.upsert_entity(&root).unwrap();
        graph.upsert_entity(&child).unwrap();
        graph.upsert_entity(&leaf).unwrap();
        assert_current(&graph);

        let root_to_child = test_relation(root.id, child.id, RelationKind::Calls);
        let child_to_leaf = test_relation(child.id, leaf.id, RelationKind::Calls);
        let leaf_to_root = test_relation(leaf.id, root.id, RelationKind::References);
        graph.upsert_relation(&root_to_child).unwrap();
        graph.upsert_relation(&child_to_leaf).unwrap();
        graph.upsert_relation(&leaf_to_root).unwrap();
        assert_current(&graph);

        root.name = "root_changed".to_string();
        root.signature = "fn root_changed()".to_string();
        graph.upsert_entity(&root).unwrap();
        assert_current(&graph);

        graph.remove_relation(&child_to_leaf.id).unwrap();
        assert_current(&graph);

        graph.remove_entity(&leaf.id).unwrap();
        assert_current(&graph);
    }

    #[test]
    fn relation_context_feeds_text_search() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let caller = test_entity("router", "src/router.rs");
        let callee = test_entity("parseExtensionRegistry", "src/extensions.rs");
        let mut rel = test_relation(caller.id, callee.id, RelationKind::Calls);
        rel.import_source = Some("pkg.extensions.registry".into());

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.flush_text_index().unwrap();

        let import_hits = graph.text_search("extensions registry", 10).unwrap();
        assert!(
            import_hits
                .iter()
                .any(|(key, _)| *key == RetrievalKey::from(caller.id)),
            "caller should become searchable by import-source context"
        );

        let neighbor_hits = graph.text_search("parseExtensionRegistry", 10).unwrap();
        assert!(
            neighbor_hits
                .iter()
                .any(|(key, _)| *key == RetrievalKey::from(caller.id)),
            "caller should become searchable by direct graph neighbor names"
        );
    }

    #[test]
    fn removing_relation_retracts_relation_context_from_text_search() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let caller = test_entity("router", "src/router.rs");
        let callee = test_entity("handler", "src/handler.rs");
        let mut rel = test_relation(caller.id, callee.id, RelationKind::Calls);
        rel.import_source = Some("acme.internal.registry".into());
        let rel_id = rel.id;

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.flush_text_index().unwrap();
        assert!(
            !graph
                .text_search("internal registry", 10)
                .unwrap()
                .is_empty(),
            "relation context should be searchable before removal"
        );

        graph.remove_relation(&rel_id).unwrap();
        graph.flush_text_index().unwrap();
        assert!(
            graph
                .text_search("internal registry", 10)
                .unwrap()
                .is_empty(),
            "relation context should disappear after removal"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn embedding_context_includes_relation_labels_and_import_sources() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("router", "src/router.rs");
        let callee = test_entity("parseExtensionRegistry", "src/extensions.rs");
        let owner = test_entity("ExtensionManager", "src/manager.rs");

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&owner).unwrap();

        let mut calls = test_relation(caller.id, callee.id, RelationKind::Calls);
        calls.import_source = Some("pkg.extensions.registry".into());
        let owned_by = test_relation(caller.id, owner.id, RelationKind::OwnedBy);

        graph.upsert_relation(&calls).unwrap();
        graph.upsert_relation(&owned_by).unwrap();

        let context = {
            let ent = graph.entities.read();
            collect_embedding_context_lines(&ent, &caller.id)
        };

        assert!(
            context
                .iter()
                .any(|line| line == "calls: parseExtensionRegistry"),
            "outgoing relation labels should be preserved in embedding text"
        );
        assert!(
            context
                .iter()
                .any(|line| line == "owned_by: ExtensionManager"),
            "graph neighborhood names should be preserved in embedding text"
        );
        assert!(
            context
                .iter()
                .any(|line| line == "import_source: pkg.extensions.registry"),
            "import provenance should be preserved in embedding text"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn embedding_context_includes_cochange_relation_labels() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("router", "src/router.rs");
        let peer = test_entity("registry", "src/registry.rs");

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&peer).unwrap();

        let cochange = test_relation(caller.id, peer.id, RelationKind::CoChanges);
        graph.upsert_relation(&cochange).unwrap();

        let context = {
            let ent = graph.entities.read();
            collect_embedding_context_lines(&ent, &caller.id)
        };

        assert!(
            context.iter().any(|line| line == "co_changes: registry"),
            "co-change labels should be preserved in embedding text"
        );
    }

    /// An unpopulated vector index is a valid graph state (`kin init` only
    /// queues embeddings), so semantic search degrades to an empty result and
    /// lets callers fall back to text search. Crucially it must NOT load the
    /// embedder — if it did, this test would attempt a model download. A fast,
    /// network-free `Ok(empty)` proves the degrade path avoids the fail-fast
    /// that made `kin search --semantic` error 100% of the time on a fresh repo.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn semantic_search_on_unpopulated_index_degrades_to_empty() {
        let graph = InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("router", "src/router.rs"))
            .unwrap();

        let results = graph
            .semantic_search("anything", 10)
            .expect("unpopulated semantic search must degrade, not error");
        assert!(
            results.is_empty(),
            "unpopulated index should yield no semantic hits"
        );

        let batch = graph
            .semantic_search_batch(&["a", "b"], 10)
            .expect("unpopulated batch semantic search must degrade, not error");
        assert_eq!(
            batch.len(),
            2,
            "batch search must return one (empty) result per query"
        );
        assert!(batch.iter().all(|hits| hits.is_empty()));
    }

    #[test]
    fn query_by_kind() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("func1", "a.rs");
        let mut e2 = test_entity("MyClass", "b.rs");
        e2.kind = EntityKind::Class;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            kinds: Some(vec![EntityKind::Function]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "func1");
    }

    #[test]
    fn query_by_name_pattern() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("getUser", "a.rs");
        let e2 = test_entity("getPost", "a.rs");
        let e3 = test_entity("deleteUser", "a.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("get*".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn snapshot_restore_rebuilds_text_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut snapshot = GraphSnapshot::empty();
        let mut entity = test_entity("parseExtensionRegistry", "src/extensions.rs");
        entity.doc_summary = Some("Parses the extension registry configuration".into());
        let entity_id = entity.id;
        snapshot.entities.insert(entity.id, entity);
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([9; 32]),
            text_preview: Some("build install".into()),
        };
        let artifact_file_id = artifact.file_id.clone();
        snapshot.structured_artifacts.push(artifact);

        let graph =
            InMemoryGraph::from_snapshot_with_text_index(snapshot, dir.path().join("text-index"));

        // Identity is graph-assigned: read the id the graph minted on restore.
        let artifact_key = RetrievalKey::Artifact(
            graph
                .artifact_id_for_path(&artifact_file_id)
                .expect("restored artifact must have a graph-assigned id"),
        );

        let hits = graph.text_search("extension registry", 10).unwrap();
        assert!(
            hits.iter()
                .any(|(key, _)| *key == RetrievalKey::from(entity_id)),
            "snapshot restore should make entities immediately searchable"
        );

        let artifact_hits = graph.text_search("build install", 10).unwrap();
        assert!(
            artifact_hits.iter().any(|(key, _)| *key == artifact_key),
            "snapshot restore should rebuild artifact text documents too"
        );
    }

    #[test]
    fn text_search_and_resolution_support_artifact_keys() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([9; 32]),
            text_preview: Some("build install".into()),
        };
        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.flush_text_index().unwrap();

        // Identity is graph-assigned by the upsert: read it back from the index.
        let artifact_key = RetrievalKey::Artifact(
            graph
                .artifact_id_for_path(&artifact.file_id)
                .expect("upserted artifact must have a graph-assigned id"),
        );

        let hits = graph.text_search("build install", 10).unwrap();
        assert!(hits.iter().any(|(key, _)| *key == artifact_key));

        let resolved = graph.resolve_retrieval_key(&artifact_key).unwrap();
        match resolved {
            ResolvedRetrievalItem::StructuredArtifact(found) => {
                assert_eq!(found.file_id.0, "Makefile");
            }
            other => panic!("expected structured artifact, got {other:?}"),
        }

        assert_eq!(
            graph.file_path_for_retrieval_key(artifact_key),
            Some(FilePathId::new("Makefile"))
        );
    }

    #[test]
    fn deleting_artifact_removes_text_search_hit() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([7; 32]),
            text_preview: Some("build clean".into()),
        };
        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.flush_text_index().unwrap();

        // Identity is graph-assigned by the upsert: capture it before deletion.
        let artifact_key = RetrievalKey::Artifact(
            graph
                .artifact_id_for_path(&artifact.file_id)
                .expect("upserted artifact must have a graph-assigned id"),
        );
        assert!(graph
            .text_search("build clean", 10)
            .unwrap()
            .iter()
            .any(|(key, _)| *key == artifact_key));

        graph.delete_structured_artifact(&artifact.file_id).unwrap();
        graph.flush_text_index().unwrap();

        assert!(!graph
            .text_search("build clean", 10)
            .unwrap()
            .iter()
            .any(|(key, _)| *key == artifact_key));
    }

    #[test]
    fn query_by_file() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "src/main.rs");
        let e2 = test_entity("b", "src/lib.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            file_path: Some(FilePathId::new("src/main.rs")),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "a");
    }

    #[test]
    fn mixed_language_query_and_coverage_remain_truthful() {
        let graph = InMemoryGraph::new();
        let rust_entity = test_entity("compileRust", "src/lib.rs");
        let mut ts_entity = test_entity("renderTs", "web/app.ts");
        let mut py_entity = test_entity("trainPy", "tools/train.py");

        ts_entity.language = LanguageId::TypeScript;
        py_entity.language = LanguageId::Python;

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let names: std::collections::HashSet<_> =
            results.iter().map(|entity| entity.name.as_str()).collect();

        assert_eq!(results.len(), 2);
        assert!(names.contains("compileRust"));
        assert!(names.contains("renderTs"));
        assert!(!names.contains("trainPy"));

        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_render_ts".into(),
            language: "typescript".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Jest,
            file_origin: Some(FilePathId::new("web/app.test.ts")),
        };

        graph.create_test_case(&test_case).unwrap();
        graph
            .create_test_covers_entity(&test_case.test_id, &ts_entity.id)
            .unwrap();

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 3);
        assert_eq!(summary.covered_entities, 1);
    }

    #[test]
    fn downstream_impact() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("core_fn", "a.rs");
        let e2 = test_entity("caller", "b.rs");
        let rel = test_relation(e2.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let impact = graph.get_downstream_impact(&e1.id, 10).unwrap();
        assert_eq!(impact.len(), 1);
        assert_eq!(impact[0].id, e2.id);
    }

    #[test]
    fn dependency_neighborhood() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");
        let e3 = test_entity("c", "c.rs");
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e3.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_relation(&r1).unwrap();
        graph.upsert_relation(&r2).unwrap();

        let sg = graph.get_dependency_neighborhood(&e1.id, 2).unwrap();
        assert_eq!(sg.entities.len(), 3);
        assert_eq!(sg.relations.len(), 2);
    }

    #[test]
    fn expand_neighborhood_filters_edge_kinds_bidirectionally() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("anchor", "b.rs");
        let e3 = test_entity("importer", "c.rs");
        let e4 = test_entity("peer", "d.rs");
        let calls = test_relation(e1.id, e2.id, RelationKind::Calls);
        let imports = test_relation(e3.id, e2.id, RelationKind::Imports);
        let cochange = test_relation(e2.id, e4.id, RelationKind::CoChanges);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_entity(&e4).unwrap();
        graph.upsert_relation(&calls).unwrap();
        graph.upsert_relation(&imports).unwrap();
        graph.upsert_relation(&cochange).unwrap();

        let sg = graph
            .expand_neighborhood(&[e2.id], &[RelationKind::Calls, RelationKind::CoChanges], 1)
            .unwrap();

        assert_eq!(sg.entities.len(), 3);
        assert!(sg.entities.contains_key(&e1.id));
        assert!(sg.entities.contains_key(&e2.id));
        assert!(sg.entities.contains_key(&e4.id));
        assert!(!sg.entities.contains_key(&e3.id));
        assert_eq!(sg.relations.len(), 2);
        assert!(sg.relations.iter().any(|rel| rel.id == calls.id));
        assert!(sg.relations.iter().any(|rel| rel.id == cochange.id));
        assert!(!sg.relations.iter().any(|rel| rel.id == imports.id));
    }

    #[test]
    fn dead_code_detection() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("used", "a.rs");
        let e2 = test_entity("unused", "b.rs");
        let e3 = test_entity("caller", "c.rs");
        let rel = test_relation(e3.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dead = graph.find_dead_code().unwrap();
        let dead_names: Vec<&str> = dead.iter().map(|e| e.name.as_str()).collect();
        assert!(dead_names.contains(&"unused"));
        assert!(dead_names.contains(&"caller"));
        assert!(!dead_names.contains(&"used"));
    }

    #[test]
    fn has_incoming_relation_kinds() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("target", "a.rs");
        let e2 = test_entity("caller", "b.rs");
        let rel = test_relation(e2.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        assert!(graph
            .has_incoming_relation_kinds(&e1.id, &[RelationKind::Calls], false)
            .unwrap());
        assert!(!graph
            .has_incoming_relation_kinds(&e1.id, &[RelationKind::Imports], false)
            .unwrap());
    }

    #[test]
    fn branch_operations() {
        let graph = InMemoryGraph::new();
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]));
        let branch = Branch {
            name: BranchName::new("main"),
            head: change_id,
        };

        graph.create_branch(&branch).unwrap();
        let fetched = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
        assert_eq!(fetched.name.0, "main");

        let new_head = SemanticChangeId::from_hash(Hash256::from_bytes([2; 32]));
        graph
            .update_branch_head(&BranchName::new("main"), &new_head)
            .unwrap();
        let updated = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
        assert_eq!(updated.head, new_head);

        let branches = graph.list_branches().unwrap();
        assert_eq!(branches.len(), 1);

        graph.delete_branch(&BranchName::new("main")).unwrap();
        assert!(graph
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn change_dag_operations() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]));
        let genesis = SemanticChange {
            id: genesis_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "genesis".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&genesis).unwrap();

        let child_id = SemanticChangeId::from_hash(Hash256::from_bytes([2; 32]));
        let child = SemanticChange {
            id: child_id,
            parents: vec![genesis_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "child".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&child).unwrap();

        let fetched = graph.get_change(&child_id).unwrap().unwrap();
        assert_eq!(fetched.message, "child");

        let since = graph.get_changes_since(&genesis_id, &child_id).unwrap();
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].message, "child");
    }

    #[test]
    fn resolve_entity_at_replays_entity_deltas_for_target_head() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x33; 32]);

        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let at_add = graph
            .resolve_entity_at(&entity_v1.id, &add_id)
            .unwrap()
            .unwrap();
        assert_eq!(at_add.signature, entity_v1.signature);

        let at_modify = graph
            .resolve_entity_at(&entity_v1.id, &modify_id)
            .unwrap()
            .unwrap();
        assert_eq!(at_modify.signature, entity_v2.signature);
    }

    #[test]
    fn get_entity_revisions_at_tracks_revision_lineage_for_target_head() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x34; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x35; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x36; 32]);

        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x37; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let revisions = graph
            .get_entity_revisions_at(&entity_v1.id, &modify_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].entity.signature, entity_v1.signature);
        assert_eq!(revisions[0].ended_by, Some(modify_id));
        assert_eq!(revisions[1].entity.signature, entity_v2.signature);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert_eq!(revisions[1].ended_by, None);
    }

    #[test]
    fn create_change_persists_entity_revision_lineage_in_snapshots() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x71; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x72; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x73; 32]);
        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x74; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2,
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let snapshot = graph.to_snapshot();
        let revisions = snapshot
            .entity_revisions
            .get(&entity_v1.id)
            .expect("entity revision chain should be persisted");
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[1].introduced_by, modify_id);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
    }

    #[test]
    fn from_snapshot_backfills_entity_revisions_from_change_history() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x75; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x76; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x77; 32]);
        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x78; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2,
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut snapshot = graph.to_snapshot();
        snapshot.entity_revisions.clear();

        let reloaded = InMemoryGraph::from_snapshot(snapshot);
        let repaired = reloaded.to_snapshot();
        let revisions = repaired
            .entity_revisions
            .get(&entity_v1.id)
            .expect("reload should rebuild entity revision chain");
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[1].introduced_by, modify_id);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
    }

    #[test]
    fn get_relation_revisions_at_replays_relation_lifecycle() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x38; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let caller = test_entity("caller", "src/lib.rs");
        let callee = test_entity("callee", "src/lib.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x39; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add graph".to_string(),
                entity_deltas: vec![
                    EntityDelta::Added(caller.clone()),
                    EntityDelta::Added(callee.clone()),
                ],
                relation_deltas: vec![RelationDelta::Added(rel.clone())],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x3a; 32]));
        graph
            .create_change(&SemanticChange {
                id: remove_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove relation".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![RelationDelta::Removed(rel.id)],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let revisions = graph
            .get_relation_revisions_at(&rel.id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].relation_id, rel.id);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[0].ended_by, Some(remove_id));
    }

    #[test]
    fn resolve_graph_at_replays_entities_and_relations() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let caller = test_entity("caller", "src/lib.rs");
        let callee = test_entity("callee", "src/lib.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add graph".to_string(),
                entity_deltas: vec![
                    EntityDelta::Added(caller.clone()),
                    EntityDelta::Added(callee.clone()),
                ],
                relation_deltas: vec![RelationDelta::Added(rel.clone())],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x43; 32]));
        graph
            .create_change(&SemanticChange {
                id: remove_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove callee".to_string(),
                entity_deltas: vec![EntityDelta::Removed(callee.id)],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let added_state = graph.resolve_graph_at(&add_id).unwrap();
        assert_eq!(added_state.entities.len(), 2);
        assert_eq!(added_state.relations.len(), 1);

        let removed_state = graph.resolve_graph_at(&remove_id).unwrap();
        assert!(removed_state.entities.contains_key(&caller.id));
        assert!(!removed_state.entities.contains_key(&callee.id));
        assert!(
            removed_state.relations.is_empty(),
            "dangling relations should be pruned when an entity is removed"
        );
    }

    #[test]
    fn resolve_graph_at_replays_file_tree_into_resolved_state() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let file_id = FilePathId::new("docs/config.json");
        let content_hash = Hash256::from_bytes([0x45; 32]);
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x46; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(content_hash),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let state = graph.resolve_graph_at(&add_id).unwrap();
        assert_eq!(state.file_tree.get(&file_id), Some(&content_hash));
    }

    #[test]
    fn get_entity_history_at_filters_to_reachable_changes() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x51; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity = test_entity("foo", "src/lib.rs");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x52; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut main_entity = entity.clone();
        main_entity.signature = "fn foo_main()".to_string();
        let main_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x53; 32]));
        graph
            .create_change(&SemanticChange {
                id: main_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "main change".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity.clone(),
                    new: main_entity,
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut feature_entity = entity.clone();
        feature_entity.signature = "fn foo_feature()".to_string();
        let feature_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x54; 32]));
        graph
            .create_change(&SemanticChange {
                id: feature_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "feature change".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity.clone(),
                    new: feature_entity,
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let history = graph.get_entity_history_at(&entity.id, &main_id).unwrap();
        let messages: Vec<_> = history.into_iter().map(|change| change.message).collect();
        assert_eq!(
            messages,
            vec!["add foo".to_string(), "main change".to_string()]
        );
    }

    #[test]
    fn get_entity_revisions_at_tracks_supersession_and_removal() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x56; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_v1.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x57; 32]);

        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x58; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x59; 32]));
        graph
            .create_change(&SemanticChange {
                id: remove_id,
                parents: vec![modify_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove foo".to_string(),
                entity_deltas: vec![EntityDelta::Removed(entity_v1.id)],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let revisions = graph
            .get_entity_revisions_at(&entity_v1.id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[0].ended_by, Some(modify_id));
        assert_eq!(revisions[1].introduced_by, modify_id);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert_eq!(revisions[1].ended_by, Some(remove_id));
        assert!(graph
            .resolve_entity_revision_at(&entity_v1.id, &remove_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_relation_revisions_at_tracks_add_remove_cycles() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x5a; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let caller = test_entity("caller", "src/lib.rs");
        let callee = test_entity("callee", "src/lib.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x5b; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add relation".to_string(),
                entity_deltas: vec![
                    EntityDelta::Added(caller.clone()),
                    EntityDelta::Added(callee.clone()),
                ],
                relation_deltas: vec![RelationDelta::Added(rel.clone())],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x5c; 32]));
        graph
            .create_change(&SemanticChange {
                id: remove_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove relation".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![RelationDelta::Removed(rel.id)],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let revisions = graph
            .get_relation_revisions_at(&rel.id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[0].ended_by, Some(remove_id));
        assert!(graph
            .resolve_relation_revision_at(&rel.id, &remove_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_artifact_revisions_at_tracks_current_and_removed_content() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x66; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let file_id = FilePathId::new("docs/config.json");
        let v1 = Hash256::from_bytes([0x67; 32]);
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x68; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(v1),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let v2 = Hash256::from_bytes([0x69; 32]);
        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x6a; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(v1),
                    new_hash: Some(v2),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x6b; 32]));
        graph
            .create_change(&SemanticChange {
                id: remove_id,
                parents: vec![modify_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Removed,
                    old_hash: Some(v2),
                    new_hash: None,
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let revisions = graph
            .get_artifact_revisions_at(&file_id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].content_hash, v1);
        assert_eq!(revisions[0].ended_by, Some(modify_id));
        assert_eq!(revisions[1].content_hash, v2);
        assert_eq!(revisions[1].ended_by, Some(remove_id));
        assert!(graph
            .resolve_artifact_revision_at(&file_id, &remove_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_file_tree_at_replays_artifact_deltas_for_target_head() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let file_id = FilePathId::new("docs/config.json");
        let v1 = Hash256::from_bytes([0x62; 32]);
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x63; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(v1),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let v2 = Hash256::from_bytes([0x64; 32]);
        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x65; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(v1),
                    new_hash: Some(v2),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let at_add = graph.resolve_file_tree_at(&add_id).unwrap();
        assert_eq!(at_add.get(&file_id), Some(&v1));

        let at_modify = graph.resolve_file_tree_at(&modify_id).unwrap();
        assert_eq!(at_modify.get(&file_id), Some(&v2));
    }

    #[test]
    fn get_artifact_revisions_at_replays_file_history() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x66; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let file_id = FilePathId::new("docs/config.json");
        let v1 = Hash256::from_bytes([0x67; 32]);
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x68; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(v1),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let v2 = Hash256::from_bytes([0x69; 32]);
        let modify_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x6a; 32]));
        graph
            .create_change(&SemanticChange {
                id: modify_id,
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: file_id.clone(),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(v1),
                    new_hash: Some(v2),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let revisions = graph
            .get_artifact_revisions_at(&file_id, &modify_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].content_hash, v1);
        assert_eq!(revisions[0].ended_by, Some(modify_id));
        assert_eq!(revisions[1].content_hash, v2);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert_eq!(revisions[1].ended_by, None);
    }

    #[test]
    fn list_all_entities() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let all = graph.list_all_entities().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn concurrent_read_access() {
        use std::sync::Arc;
        use std::thread;

        let graph = Arc::new(InMemoryGraph::new());
        let e = test_entity("concurrent", "a.rs");
        let id = e.id;
        graph.upsert_entity(&e).unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let g = Arc::clone(&graph);
                thread::spawn(move || g.get_entity(&id).unwrap().unwrap().name)
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), "concurrent");
        }
    }

    #[test]
    fn work_item_crud() {
        let graph = InMemoryGraph::new();
        let item = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Feature,
            title: "Add login".into(),
            description: "OAuth login".into(),
            status: WorkStatus::Proposed,
            priority: Priority::High,
            scopes: vec![],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("alice"),
            created_at: Timestamp::now(),
        };
        let id = item.work_id;

        graph.create_work_item(&item).unwrap();
        let fetched = graph.get_work_item(&id).unwrap().unwrap();
        assert_eq!(fetched.title, "Add login");

        graph
            .update_work_status(&id, WorkStatus::InProgress)
            .unwrap();
        let updated = graph.get_work_item(&id).unwrap().unwrap();
        assert_eq!(updated.status, WorkStatus::InProgress);

        graph.delete_work_item(&id).unwrap();
        assert!(graph.get_work_item(&id).unwrap().is_none());
    }

    #[test]
    fn annotation_crud() {
        let graph = InMemoryGraph::new();
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Warning,
            body: "Deprecated API".into(),
            scopes: vec![],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("bob"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        let id = ann.annotation_id;

        graph.create_annotation(&ann).unwrap();
        let fetched = graph.get_annotation(&id).unwrap().unwrap();
        assert_eq!(fetched.body, "Deprecated API");

        graph
            .update_annotation_staleness(&id, StalenessState::Stale)
            .unwrap();
        let updated = graph.get_annotation(&id).unwrap().unwrap();
        assert_eq!(updated.staleness, StalenessState::Stale);

        graph.delete_annotation(&id).unwrap();
        assert!(graph.get_annotation(&id).unwrap().is_none());
    }

    #[test]
    fn test_case_and_coverage() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("target_fn", "src/lib.rs");
        let eid = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let tc = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        let tid = tc.test_id;

        graph.create_test_case(&tc).unwrap();
        graph.create_test_covers_entity(&tid, &eid).unwrap();

        let tests = graph.get_tests_for_entity(&eid).unwrap();
        assert_eq!(tests.len(), 1);

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 1);
        assert_eq!(summary.covered_entities, 1);
    }

    #[test]
    fn create_test_case_batches_entity_scope_cover_relations() {
        let graph = InMemoryGraph::new();
        let entity_a = test_entity("target_a", "src/lib.rs");
        let entity_b = test_entity("target_b", "src/lib.rs");
        graph.upsert_entity(&entity_a).unwrap();
        graph.upsert_entity(&entity_b).unwrap();

        let tc = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![
                WorkScope::Entity(entity_a.id),
                WorkScope::Entity(entity_b.id),
                WorkScope::Entity(entity_a.id),
            ],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        let tid = tc.test_id;

        graph.create_test_case(&tc).unwrap();

        let tests_a = graph.get_tests_for_entity(&entity_a.id).unwrap();
        let tests_b = graph.get_tests_for_entity(&entity_b.id).unwrap();
        assert_eq!(tests_a.len(), 1);
        assert_eq!(tests_b.len(), 1);
        assert_eq!(tests_a[0].test_id, tid);
        assert_eq!(tests_b[0].test_id, tid);
    }

    #[test]
    fn traverse_crosses_verification_and_entity_edges() {
        let graph = InMemoryGraph::new();
        let covered = test_entity("target_fn", "src/lib.rs");
        let callee = test_entity("helper_fn", "src/lib.rs");
        graph.upsert_entity(&covered).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(covered.id, callee.id, RelationKind::Calls))
            .unwrap();

        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        graph.create_test_case(&test_case).unwrap();
        graph
            .create_test_covers_entity(&test_case.test_id, &covered.id)
            .unwrap();

        let traversal = graph
            .traverse(&GraphNodeId::Test(test_case.test_id), &[], 2)
            .unwrap();

        assert!(traversal
            .nodes
            .contains(&GraphNodeId::Test(test_case.test_id)));
        assert!(traversal.nodes.contains(&GraphNodeId::Entity(covered.id)));
        assert!(traversal.nodes.contains(&GraphNodeId::Entity(callee.id)));
        assert_eq!(traversal.entities.len(), 2);
        assert!(traversal
            .relations
            .iter()
            .any(|relation| relation.kind == RelationKind::Covers));
        assert!(traversal
            .relations
            .iter()
            .any(|relation| relation.kind == RelationKind::Calls));
    }

    #[test]
    fn actor_and_audit() {
        let graph = InMemoryGraph::new();
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "Alice".into(),
            external_refs: vec![],
        };
        let aid = actor.actor_id;

        graph.create_actor(&actor).unwrap();
        let fetched = graph.get_actor(&aid).unwrap().unwrap();
        assert_eq!(fetched.display_name, "Alice");

        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: aid,
            action: "commit".into(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: None,
        };
        graph.record_audit_event(&event).unwrap();

        let events = graph.query_audit_events(Some(&aid), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "commit");
    }

    #[test]
    fn shallow_file_tracking() {
        let graph = InMemoryGraph::new();
        let sf = ShallowTrackedFile {
            file_id: FilePathId::new("lib.c"),
            language_hint: "c".into(),
            declaration_count: 5,
            import_count: 3,
            syntax_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: None,
            declaration_names: vec!["decode".into()],
            import_paths: vec!["zstd.h".into()],
        };

        graph.upsert_shallow_file(&sf).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 5);
        let fetched = graph.get_shallow_file(&sf.file_id).unwrap().unwrap();
        assert_eq!(fetched.file_id, sf.file_id);
        assert_eq!(fetched.declaration_count, sf.declaration_count);
        assert_eq!(fetched.language_hint, sf.language_hint);

        // Upsert replaces
        let sf2 = ShallowTrackedFile {
            declaration_count: 10,
            ..sf.clone()
        };
        graph.upsert_shallow_file(&sf2).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 10);
        let fetched = graph.get_shallow_file(&sf2.file_id).unwrap().unwrap();
        assert_eq!(fetched.file_id, sf2.file_id);
        assert_eq!(fetched.declaration_count, sf2.declaration_count);
    }

    #[test]
    fn artifact_tracking() {
        let graph = InMemoryGraph::new();
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0xbb; 32]),
            text_preview: Some("build test".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([0xcc; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };

        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();

        let structured_files = graph.list_structured_artifacts().unwrap();
        let opaque_files = graph.list_opaque_artifacts().unwrap();
        assert_eq!(structured_files.len(), 1);
        assert_eq!(structured_files[0].kind, ArtifactKind::Makefile);
        assert_eq!(opaque_files.len(), 1);
        assert_eq!(opaque_files[0].mime_type.as_deref(), Some("image/svg+xml"));
        let fetched_structured = graph
            .get_structured_artifact(&structured.file_id)
            .unwrap()
            .unwrap();
        assert_eq!(fetched_structured.file_id, structured.file_id);
        assert_eq!(fetched_structured.kind, structured.kind);
        assert_eq!(fetched_structured.text_preview, structured.text_preview);
        let fetched_opaque = graph.get_opaque_artifact(&opaque.file_id).unwrap().unwrap();
        assert_eq!(fetched_opaque.file_id, opaque.file_id);
        assert_eq!(fetched_opaque.mime_type, opaque.mime_type);
        assert_eq!(fetched_opaque.text_preview, opaque.text_preview);
        assert!(graph
            .get_structured_artifact(&FilePathId::new("missing.file"))
            .unwrap()
            .is_none());

        graph
            .delete_structured_artifact(&structured.file_id)
            .unwrap();
        graph.delete_opaque_artifact(&opaque.file_id).unwrap();
        assert!(graph.list_structured_artifacts().unwrap().is_empty());
        assert!(graph.list_opaque_artifacts().unwrap().is_empty());
    }

    #[cfg(feature = "vector")]
    #[test]
    fn artifact_embedding_queue_tracks_shallow_structured_and_opaque_artifacts() {
        let graph = InMemoryGraph::new();
        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("src/lib.rs"),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 1,
            syntax_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Some(Hash256::from_bytes([0x12; 32])),
            declaration_names: vec!["run".into()],
            import_paths: vec!["std::fmt".into()],
        };
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x13; 32]),
            text_preview: Some("build test".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([0x14; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };

        graph.upsert_shallow_file(&shallow).unwrap();
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();

        // Identity is graph-assigned by the upserts above: read it back.
        let shallow_id = graph.artifact_id_for_path(&shallow.file_id).unwrap();
        let structured_id = graph.artifact_id_for_path(&structured.file_id).unwrap();
        let opaque_id = graph.artifact_id_for_path(&opaque.file_id).unwrap();

        {
            let queue = graph.artifact_embedding_queue.lock();
            assert!(queue.contains(&shallow_id));
            assert!(queue.contains(&structured_id));
            assert!(queue.contains(&opaque_id));
            assert_eq!(queue.len(), 3);
        }

        graph.delete_shallow_file(&shallow.file_id).unwrap();
        graph
            .delete_structured_artifact(&structured.file_id)
            .unwrap();
        graph.delete_opaque_artifact(&opaque.file_id).unwrap();

        let queue = graph.artifact_embedding_queue.lock();
        assert!(queue.is_empty());
    }

    #[test]
    fn file_layout_tracking() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("src/lib.rs");
        let layout = FileLayout {
            file_id: file_id.clone(),
            parse_completeness: ParseCompleteness::Partial("1 parse error range(s)".into()),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::Trivia { byte_range: 0..12 }],
        };

        graph.upsert_file_layout(&layout).unwrap();
        let fetched = graph.get_file_layout(&file_id).unwrap().unwrap();
        assert_eq!(fetched.parse_completeness, layout.parse_completeness);
        assert_eq!(graph.list_file_layouts().unwrap().len(), 1);
        assert!(
            graph.artifact_id_for_path(&file_id).is_some(),
            "source file layouts must register graph artifact IDs for artifact relations"
        );

        graph.delete_file_layout(&file_id).unwrap();
        assert!(graph.get_file_layout(&file_id).unwrap().is_none());
        assert!(
            graph.artifact_id_for_path(&file_id).is_none(),
            "deleting the last file-surface owner should remove the artifact index entry"
        );
    }

    #[test]
    fn delta_index_skips_unchanged_fields() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("myFunc", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();

        // Upsert same entity with only non-indexed field changes (signature)
        let mut updated = entity.clone();
        updated.signature = "fn myFunc() -> bool".to_string();
        graph.upsert_entity(&updated).unwrap();

        // Index should still work correctly
        let ent = graph.entities.read();
        assert_eq!(ent.indexes.by_name_pattern("myfunc"), vec![id]);
        assert_eq!(ent.indexes.by_file("src/main.rs"), vec![id]);
        assert_eq!(ent.indexes.by_kind(EntityKind::Function), vec![id]);
        drop(ent);

        // Now change an indexed field (name)
        let mut renamed = updated.clone();
        renamed.name = "renamedFunc".to_string();
        graph.upsert_entity(&renamed).unwrap();

        let ent = graph.entities.read();
        assert!(ent.indexes.by_name_pattern("myfunc").is_empty());
        assert_eq!(ent.indexes.by_name_pattern("renamedfunc"), vec![id]);
        // File index should still have the entity
        assert_eq!(ent.indexes.by_file("src/main.rs"), vec![id]);
        drop(ent);

        // Change file_origin
        let mut moved = renamed.clone();
        moved.file_origin = Some(FilePathId::new("src/other.rs"));
        graph.upsert_entity(&moved).unwrap();

        let ent = graph.entities.read();
        assert!(ent.indexes.by_file("src/main.rs").is_empty());
        assert_eq!(ent.indexes.by_file("src/other.rs"), vec![id]);
        drop(ent);

        // Change kind
        let mut retyped = moved.clone();
        retyped.kind = EntityKind::Class;
        graph.upsert_entity(&retyped).unwrap();

        let ent = graph.entities.read();
        assert!(ent.indexes.by_kind(EntityKind::Function).is_empty());
        assert_eq!(ent.indexes.by_kind(EntityKind::Class), vec![id]);
    }

    #[test]
    fn delta_index_benchmark_unchanged_vs_changed() {
        // Populate a graph with 1000 entities
        let graph = InMemoryGraph::new();
        let mut entities = Vec::with_capacity(1000);
        for i in 0..1000 {
            let e = test_entity(&format!("entity_{i}"), &format!("src/mod_{}.rs", i / 50));
            graph.upsert_entity(&e).unwrap();
            entities.push(e);
        }

        // Benchmark: upsert all 1000 entities with only non-indexed changes (signature)
        let start = std::time::Instant::now();
        for e in &entities {
            let mut updated = e.clone();
            updated.signature = format!("fn {}() -> bool", e.name);
            graph.upsert_entity(&updated).unwrap();
        }
        let unchanged_elapsed = start.elapsed();

        // Benchmark: upsert all 1000 entities with indexed field change (name)
        let start = std::time::Instant::now();
        for (i, e) in entities.iter().enumerate() {
            let mut updated = e.clone();
            updated.name = format!("renamed_{i}");
            graph.upsert_entity(&updated).unwrap();
        }
        let changed_elapsed = start.elapsed();

        // The unchanged path should be faster since it skips index remove+insert.
        // We don't assert a specific ratio (hardware-dependent) but verify correctness.
        eprintln!(
            "Delta index benchmark (1000 entities): unchanged={:?}, changed={:?}, ratio={:.2}x",
            unchanged_elapsed,
            changed_elapsed,
            changed_elapsed.as_nanos() as f64 / unchanged_elapsed.as_nanos().max(1) as f64,
        );

        // Verify indexes are still correct after all mutations
        let ent = graph.entities.read();
        assert_eq!(ent.indexes.by_name_pattern("renamed_0").len(), 1);
        assert!(ent.indexes.by_name_pattern("entity_0").is_empty());
    }

    // -----------------------------------------------------------------------
    // Embedding queue tests
    // -----------------------------------------------------------------------

    #[test]
    fn upsert_queues_entity_for_embedding() {
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");
        graph.upsert_entity(&e).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending + status.indexed, 1);
        }
        #[cfg(not(feature = "vector"))]
        assert_eq!(graph.pending_embeddings(), 0);
    }

    #[test]
    fn batch_upsert_queues_entities_for_embedding() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");

        graph.batch_upsert_entities(&[e1, e2]).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending + status.indexed, 2);
        }
    }

    #[test]
    fn embedding_queue_deduplicates() {
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");

        // Upsert the same entity twice — should only be queued once
        graph.upsert_entity(&e).unwrap();
        graph.upsert_entity(&e).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending + status.indexed, 1);
        }
    }

    #[test]
    fn remove_entity_clears_embedding_queue() {
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");
        graph.upsert_entity(&e).unwrap();
        graph.remove_entity(&e.id).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending, 0);
            assert_eq!(status.indexed, 0);
        }
    }

    #[test]
    fn batch_remove_entities_clear_embedding_queue() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph
            .batch_upsert_entities(&[e1.clone(), e2.clone()])
            .unwrap();
        graph.batch_remove_entities(&[e1.id, e2.id]).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending, 0);
            assert_eq!(status.indexed, 0);
        }
    }

    #[test]
    fn queue_all_for_embedding() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        // Clear the queue (it was populated by upserts)
        #[cfg(feature = "vector")]
        {
            graph.embedding_queue.lock().clear();
            assert_eq!(graph.pending_embeddings(), 0);

            // Now queue all
            graph.queue_all_for_embedding();
            assert_eq!(graph.pending_embeddings(), 2);
        }
    }

    #[cfg(feature = "vector")]
    #[test]
    fn queue_missing_for_embedding_only_enqueues_unindexed_entities() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.queue_missing_for_embedding();
        assert_eq!(graph.pending_embeddings(), 1);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn reset_vector_index_requeues_every_entity_for_rebuild() {
        // Simulates the stale-dimension migration: a repo arrives with a loaded
        // index that already covers every entity, so a normal pass would queue
        // nothing. Resetting must drop the index and let a full re-queue happen
        // so the rebuild produces a fresh index at the live embedder dimension.
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.upsert(e2.id, &[0.0, 1.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        // Precondition: index is loaded and reports full coverage, so the
        // incremental path would queue nothing.
        assert!(graph.vector_index.lock().is_some());
        assert_eq!(graph.embedding_status().indexed, 2);
        graph.embedding_queue.lock().clear();
        graph.queue_missing_for_embedding();
        assert_eq!(
            graph.pending_embeddings(),
            0,
            "fully-indexed graph should queue nothing without a reset"
        );

        // Reset drops the in-memory index; a full re-queue now covers all entities.
        graph.reset_vector_index();
        assert!(graph.vector_index.lock().is_none());
        assert_eq!(graph.embedding_status().indexed, 0);
        graph.queue_missing_for_embedding();
        assert_eq!(
            graph.pending_embeddings(),
            2,
            "reset must re-queue every entity for a clean dimension rebuild"
        );
    }

    /// Add `entities` to the graph under a fresh change id, recording one
    /// `EntityRevision` per entity (mirrors `kin init`, whose change id is seeded
    /// with a timestamp so every re-init mints new revision keys).
    #[cfg(feature = "vector")]
    fn apply_init_change(graph: &InMemoryGraph, change_byte: u8, entities: &[Entity]) {
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([change_byte; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "init".to_string(),
            entity_deltas: entities
                .iter()
                .map(|e| EntityDelta::Added(e.clone()))
                .collect(),
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&change).unwrap();
        graph.batch_upsert_entities(entities).unwrap();
    }

    /// Synthetically "embed" every current graph-truth retrievable key by
    /// upserting a unit vector — exercises the index lifecycle without a GPU or
    /// the `embeddings` feature (so it cannot reach `get_vector_index`).
    #[cfg(feature = "vector")]
    fn embed_all_retrievable(graph: &InMemoryGraph) {
        {
            let mut guard = graph.vector_index.lock();
            if guard.is_none() {
                *guard = Some(Arc::new(VectorIndex::new(2).unwrap()));
            }
        }
        let vi = graph.vector_index.lock().clone().unwrap();
        for key in graph.graph_truth_retrievable_keys() {
            vi.upsert_retrievable(key, &[1.0, 0.0]).unwrap();
        }
    }

    /// Gate for #21: across init → embed → re-init → re-embed the vector index
    /// must converge to the true target count, not accumulate stale revision
    /// generations.
    ///
    /// Production re-init builds a FRESH graph under a new change id, so every
    /// entity gets a brand-new `EntityRevision` key. The prior generation's
    /// revision vectors survive only in the persisted sidecar; once that sidecar
    /// is loaded into the new graph they are orphans relative to current truth.
    /// `prune_orphaned_vectors` reconciles the index back to graph truth.
    #[cfg(feature = "vector")]
    #[test]
    fn reembed_after_reinit_converges_to_true_target_count() {
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        let entities = [e1, e2];
        let dir = tempfile::TempDir::new().unwrap();
        let sidecar = dir.path().join("vectors.kvec");

        // init (generation 1) → embed → persist sidecar
        let gen1 = InMemoryGraph::new();
        apply_init_change(&gen1, 0x01, &entities);
        let target = gen1.graph_truth_retrievable_keys().len();
        // 2 HEAD entities + 2 revisions (generation 1).
        assert_eq!(target, 4);
        embed_all_retrievable(&gen1);
        assert_eq!(gen1.vector_index_stats().unwrap().1, target);
        gen1.save_vector_index(&sidecar).unwrap();

        // re-init: a fresh graph under a NEW change id. Generation-1 revision
        // keys exist only in the sidecar now, not in this graph's truth.
        let gen2 = InMemoryGraph::new();
        apply_init_change(&gen2, 0x02, &entities);
        let target_after = gen2.graph_truth_retrievable_keys().len();
        assert_eq!(target_after, 4);

        // Reopen reuses the persisted sidecar (entity content unchanged → root
        // hash matches), dragging the generation-1 revision vectors back in.
        let loaded = gen2.load_vector_index(&sidecar).unwrap();
        assert_eq!(
            loaded, target,
            "sidecar carries the full generation-1 index"
        );

        // Re-embed the current generation. Its HEAD-entity keys replace, but the
        // generation-2 revision keys are new — so without eviction the index now
        // holds BOTH generations' revision vectors (stale-generation bloat).
        embed_all_retrievable(&gen2);
        let before_prune = gen2.vector_index_stats().unwrap().1;
        assert!(
            before_prune > target_after,
            "expected stale-generation accumulation before pruning ({before_prune} vs {target_after})"
        );

        // GATE: eviction reconciles the index to graph truth.
        let evicted = gen2.prune_orphaned_vectors();
        assert_eq!(evicted, before_prune - target_after);
        assert_eq!(
            gen2.vector_index_stats().unwrap().1,
            target_after,
            "index must equal the true target count after re-embed + prune"
        );

        // Idempotent: a clean index prunes nothing.
        assert_eq!(gen2.prune_orphaned_vectors(), 0);
    }

    /// Source-level convergence: re-importing unchanged content must not append a
    /// redundant revision generation, regardless of whether the re-init reused
    /// the same change id (same-second) or minted a fresh one. A genuine content
    /// change still records a new revision.
    #[cfg(feature = "vector")]
    #[test]
    fn reinit_over_unchanged_content_records_no_new_revision() {
        let e1 = test_entity("foo", "src/a.rs");
        let entities = [e1.clone()];
        let graph = InMemoryGraph::new();

        let rev_count = |g: &InMemoryGraph| -> usize {
            let ent = g.entities.read();
            ent.entity_revisions.values().map(|v| v.len()).sum()
        };

        apply_init_change(&graph, 0x01, &entities);
        assert_eq!(rev_count(&graph), 1);
        assert_eq!(graph.graph_truth_retrievable_keys().len(), 2);

        // Same change id (same-second re-init) — no new revision.
        apply_init_change(&graph, 0x01, &entities);
        assert_eq!(rev_count(&graph), 1, "same-id re-init must not duplicate");

        // Fresh change id (re-init seconds later) — still unchanged content, so
        // still no new generation.
        apply_init_change(&graph, 0x02, &entities);
        assert_eq!(rev_count(&graph), 1, "fresh-id re-init must converge");
        assert_eq!(graph.graph_truth_retrievable_keys().len(), 2);

        // A genuine content change DOES record a new revision.
        let mut changed = e1;
        changed.signature = "fn foo(x: i32)".to_string();
        changed.fingerprint.signature_hash = Hash256::from_bytes([7; 32]);
        apply_init_change(&graph, 0x03, &[changed]);
        assert_eq!(rev_count(&graph), 2, "real change must record a revision");
    }

    /// Build entity `e1` with a two-generation revision chain (revision 1
    /// superseded by revision 2, both retained in history) and return its
    /// (old, new) revision ids.
    #[cfg(feature = "vector")]
    fn two_revision_entity(
        graph: &InMemoryGraph,
        e1: &Entity,
    ) -> (EntityRevisionId, EntityRevisionId) {
        apply_init_change(graph, 0x01, std::slice::from_ref(e1));
        let mut changed = e1.clone();
        changed.signature = "fn foo(x: i32)".to_string();
        changed.fingerprint.signature_hash = Hash256::from_bytes([7; 32]);
        apply_init_change(graph, 0x02, &[changed]);

        let ent = graph.entities.read();
        let chain = ent
            .entity_revisions
            .get(&e1.id)
            .expect("entity must have a revision chain");
        assert_eq!(chain.len(), 2, "entity must hold an old + new revision");
        let pair = (chain[0].revision_id, chain[1].revision_id);
        assert_ne!(pair.0, pair.1, "the two generations must be distinct keys");
        pair
    }

    /// FIR-937 (live re-embed retire): a re-embed that appends a new revision
    /// for an entity must leave exactly ONE vector for that entity — the new
    /// revision's. The superseded generation is still referenced by the entity's
    /// revision history, so before the fix `prune_orphaned_vectors` (whose truth
    /// admitted every generation) kept BOTH vectors and `semantic_locate`
    /// returned the entity twice with two distinct cosine scores. Discriminating:
    /// FAILS on the old all-revisions truth (evicts 0), PASSES on head-only truth.
    #[cfg(feature = "vector")]
    #[test]
    fn live_reembed_retires_superseded_revision_vector() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let (rev_old, rev_new) = two_revision_entity(&graph, &e1);

        // The doubled state a live re-embed leaves behind: revision 1's vector
        // (indexed earlier) AND revision 2's vector (the re-embed) both live,
        // each a DISTINCT vector under the SAME entity.
        let vi = VectorIndex::new(2).unwrap();
        let vec_old = [1.0f32, 0.0];
        let vec_new = [0.0f32, 1.0];
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_old), &vec_old)
            .unwrap();
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_new), &vec_new)
            .unwrap();
        vi.upsert(e1.id, &vec_new).unwrap(); // HEAD entity key (kept by truth)
        *graph.vector_index.lock() = Some(Arc::new(vi));

        let evicted = graph.prune_orphaned_vectors();
        assert_eq!(
            evicted, 1,
            "exactly the superseded revision-1 vector must be retired"
        );

        let vi = graph.vector_index.lock().clone().unwrap();
        assert!(
            vi.get_retrievable(&RetrievalKey::EntityRevision(rev_old))
                .is_none(),
            "superseded revision-1 vector must be gone"
        );
        assert_eq!(
            vi.get_retrievable(&RetrievalKey::EntityRevision(rev_new)),
            Some(vec_new.to_vec()),
            "head revision-2 vector must survive unchanged"
        );
        assert!(
            vi.contains(&e1.id),
            "HEAD entity vector is current truth and must remain"
        );
        // Idempotent once converged.
        assert_eq!(graph.prune_orphaned_vectors(), 0);
    }

    /// FIR-937 (load-time reclaim): an index already doubled on disk (tonight's
    /// persisted state — both revision generations of an entity) self-heals when
    /// reopened. Mirrors `load_vector_index_if_valid`'s load-then-prune sequence.
    /// Discriminating: the reclaim evicts 0 on the old truth, 1 on the fix.
    #[cfg(feature = "vector")]
    #[test]
    fn load_time_reclaim_heals_doubled_persisted_revision_index() {
        let e1 = test_entity("foo", "src/a.rs");
        let dir = tempfile::TempDir::new().unwrap();
        let sidecar = dir.path().join("vectors.kvec");

        // Persist a sidecar holding BOTH revision generations + the HEAD entity.
        let (rev_old, rev_new) = {
            let graph = InMemoryGraph::new();
            let (rev_old, rev_new) = two_revision_entity(&graph, &e1);
            let vi = VectorIndex::new(2).unwrap();
            vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_old), &[1.0, 0.0])
                .unwrap();
            vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_new), &[0.0, 1.0])
                .unwrap();
            vi.upsert(e1.id, &[0.0, 1.0]).unwrap();
            vi.save(&sidecar).unwrap();
            (rev_old, rev_new)
        };

        // A fresh graph at the SAME revision history reopens the doubled sidecar.
        // Revision ids are hash(entity_id, change_id) — deterministic across
        // graphs — so the persisted revision keys match this graph's history.
        let graph = InMemoryGraph::new();
        let (rev_old2, rev_new2) = two_revision_entity(&graph, &e1);
        assert_eq!((rev_old, rev_new), (rev_old2, rev_new2));

        let loaded = graph.load_vector_index(&sidecar).unwrap();
        assert_eq!(
            loaded, 3,
            "sidecar carries both revisions + the head entity"
        );

        let evicted = graph.prune_orphaned_vectors();
        assert_eq!(
            evicted, 1,
            "load-time reclaim retires the superseded revision"
        );

        let vi = graph.vector_index.lock().clone().unwrap();
        assert!(vi
            .get_retrievable(&RetrievalKey::EntityRevision(rev_old))
            .is_none());
        assert!(vi
            .get_retrievable(&RetrievalKey::EntityRevision(rev_new))
            .is_some());
    }

    #[cfg(feature = "vector")]
    #[test]
    fn queue_missing_for_embedding_only_enqueues_unindexed_artifacts() {
        let graph = InMemoryGraph::new();
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x21; 32]),
            text_preview: Some("build".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([0x22; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        // Identity is graph-assigned by the upsert above: read it back so the
        // pre-seeded vector index entry matches what the graph will look for.
        let structured_key =
            RetrievalKey::Artifact(graph.artifact_id_for_path(&structured.file_id).unwrap());
        index
            .upsert_retrievable(structured_key, &[1.0, 0.0])
            .unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.artifact_embedding_queue.lock().clear();
        graph.queue_missing_artifacts_for_embedding();

        let opaque_id = graph.artifact_id_for_path(&opaque.file_id).unwrap();
        let queue = graph.artifact_embedding_queue.lock();
        assert_eq!(queue.len(), 1);
        assert!(queue.contains(&opaque_id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn upserting_entity_queues_neighbors_for_reembedding() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("caller", "src/a.rs");
        let callee = test_entity("callee", "src/b.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(caller.id, &[1.0, 0.0]).unwrap();
        index.upsert(callee.id, &[0.0, 1.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();

        let mut renamed = callee.clone();
        renamed.name = "callee_v2".into();
        graph.upsert_entity(&renamed).unwrap();

        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(caller.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee.id)));
        drop(queue);

        let vector_index = graph.vector_index.lock();
        let vi = vector_index.as_ref().unwrap();
        assert!(!vi.contains(&caller.id));
        assert!(!vi.contains(&callee.id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn remove_relation_queues_affected_entities_for_reembedding() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("caller", "src/a.rs");
        let callee = test_entity("callee", "src/b.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(caller.id, &[1.0, 0.0]).unwrap();
        index.upsert(callee.id, &[0.0, 1.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.remove_relation(&rel.id).unwrap();

        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(caller.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee.id)));
        drop(queue);

        let vector_index = graph.vector_index.lock();
        let vi = vector_index.as_ref().unwrap();
        assert!(!vi.contains(&caller.id));
        assert!(!vi.contains(&callee.id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn remove_outgoing_relations_queues_affected_entities_for_reembedding() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("caller", "src/a.rs");
        let callee_a = test_entity("callee_a", "src/b.rs");
        let callee_b = test_entity("callee_b", "src/c.rs");
        let rel_a = test_relation(caller.id, callee_a.id, RelationKind::Calls);
        let rel_b = test_relation(caller.id, callee_b.id, RelationKind::Calls);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee_a).unwrap();
        graph.upsert_entity(&callee_b).unwrap();
        graph.upsert_relation(&rel_a).unwrap();
        graph.upsert_relation(&rel_b).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(caller.id, &[1.0, 0.0]).unwrap();
        index.upsert(callee_a.id, &[0.0, 1.0]).unwrap();
        index.upsert(callee_b.id, &[0.5, 0.5]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.remove_outgoing_relations(&caller.id).unwrap();

        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(caller.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee_a.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee_b.id)));
        drop(queue);

        let vector_index = graph.vector_index.lock();
        let vi = vector_index.as_ref().unwrap();
        assert!(!vi.contains(&caller.id));
        assert!(!vi.contains(&callee_a.id));
        assert!(!vi.contains(&callee_b.id));
        assert!(graph
            .get_relations(&caller.id, &[RelationKind::Calls])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn embedding_status_reflects_state() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let status = graph.embedding_status();
        assert_eq!(status.total, 2);
        assert_eq!(status.indexed, 0);
        #[cfg(feature = "vector")]
        assert_eq!(status.pending, 2);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_pending_covers_unindexed_when_queue_drained() {
        // Reproduces the operational case where a graph is reopened with some
        // entities already in the vector index but the embedding queue is
        // empty because it does not persist across restarts. Before this
        // regression test landed, `embedding_status().pending` returned the
        // raw queue length, so a coverage gate that inspected `pending`
        // alone saw zero outstanding work even though entities remained
        // unindexed. See SP-17 in the methodology paper.
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        let e3 = test_entity("baz", "src/c.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);

        let status = graph.embedding_status();
        assert_eq!(status.total, 3);
        assert_eq!(status.indexed, 1);
        assert_eq!(
            status.pending, 2,
            "pending must report outstanding work, not raw queue length"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_counts_unindexed_artifacts_when_queue_drained() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        graph.upsert_entity(&e1).unwrap();
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x45; 32]),
            text_preview: Some("build".into()),
        };
        graph.upsert_structured_artifact(&artifact).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.artifact_embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);
        assert_eq!(graph.pending_artifact_embeddings(), 0);

        let status = graph.embedding_status();
        assert_eq!(status.total, 2);
        assert_eq!(status.indexed, 1);
        assert_eq!(
            status.pending, 1,
            "pending must include unindexed artifacts even after queue state is lost"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_ignores_source_artifact_identities_without_embedding_docs() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/lib.rs");
        graph.upsert_entity(&e1).unwrap();

        // Source files can have graph-native artifact identities for relations
        // and projection, but only shallow/structured/opaque artifact records
        // have document text that the artifact embedder can vectorize.
        graph.ensure_artifact_id(&FilePathId::new("src/lib.rs"));

        let status = graph.embedding_status();
        assert_eq!(status.total, 1);
        assert_eq!(status.indexed, 0);
        assert_eq!(status.pending, 1);

        graph.artifact_embedding_queue.lock().clear();
        graph.queue_missing_artifacts_for_embedding();
        assert!(
            graph.artifact_embedding_queue.lock().is_empty(),
            "source-only artifact identities must not become unprocessable pending vectors"
        );
    }

    #[test]
    fn process_embedding_queue_without_embeddings_is_noop() {
        // With just "vector" feature (no "embeddings"), process should return 0
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");
        graph.upsert_entity(&e).unwrap();

        // This should be Ok(0) regardless of feature flags
        let result = graph.process_embedding_queue(64);
        assert!(result.is_ok());
    }

    #[test]
    fn graph_stats_counts_entities_and_relations() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));

        // Insert two functions and one class
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        let mut e3 = test_entity("MyClass", "src/c.rs");
        e3.kind = EntityKind::Class;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        // Insert a Calls relation and a CoChanges relation
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e3.id, RelationKind::CoChanges);
        graph.upsert_relation(&r1).unwrap();
        graph.upsert_relation(&r2).unwrap();

        // Add a shallow file
        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("README.md"),
            language_hint: "markdown".into(),
            declaration_count: 1,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([0; 32]),
            signature_hash: None,
            declaration_names: vec!["README".into()],
            import_paths: vec![],
        };
        graph.upsert_shallow_file(&shallow).unwrap();

        let layout = FileLayout {
            file_id: FilePathId::new("src/a.rs"),
            parse_completeness: ParseCompleteness::Partial("1 parse error range(s)".into()),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::Trivia { byte_range: 0..8 }],
        };
        graph.upsert_file_layout(&layout).unwrap();

        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([2; 32]),
            text_preview: Some("build test".into()),
        };
        graph.upsert_structured_artifact(&structured).unwrap();

        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([3; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };
        graph.upsert_opaque_artifact(&opaque).unwrap();

        // Set a file hash
        graph.set_file_hash("src/a.rs", [1u8; 32]);
        graph.flush_text_index().unwrap();

        #[cfg(feature = "vector")]
        {
            let vector_path = dir.path().join("vectors.hnsw");
            let index = crate::vector::VectorIndex::new(4).unwrap();
            index.upsert(e1.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            index.save(&vector_path).unwrap();
            graph.load_vector_index(&vector_path).unwrap();
        }

        let stats = graph.graph_stats();

        assert_eq!(stats.total_entities, 3);
        assert_eq!(stats.total_relations, 2);
        assert_eq!(stats.entity_counts.get("Function"), Some(&2));
        assert_eq!(stats.entity_counts.get("Class"), Some(&1));
        assert_eq!(stats.relation_counts.get("Calls"), Some(&1));
        assert_eq!(stats.relation_counts.get("CoChanges"), Some(&1));
        assert_eq!(stats.file_layout_count, 1);
        assert_eq!(stats.parse_completeness_counts.get("partial"), Some(&1));
        assert_eq!(stats.shallow_file_count, 1);
        assert_eq!(stats.structured_artifact_count, 1);
        assert_eq!(stats.opaque_artifact_count, 1);
        assert_eq!(stats.file_hash_count, 1);
        assert_eq!(stats.text_indexed_entity_count, 3);
        assert!((stats.text_index_coverage_percent - 100.0).abs() < f64::EPSILON);
        #[cfg(feature = "vector")]
        assert_eq!(stats.indexed_embedding_count, 1);
        #[cfg(not(feature = "vector"))]
        assert_eq!(stats.indexed_embedding_count, 0);
        #[cfg(feature = "vector")]
        assert_eq!(stats.pending_embedding_count, 6);
        #[cfg(not(feature = "vector"))]
        assert_eq!(stats.pending_embedding_count, 0);
        #[cfg(feature = "vector")]
        assert!((stats.embedding_coverage_percent - 33.33333333333333).abs() < 0.001);
        #[cfg(not(feature = "vector"))]
        assert!((stats.embedding_coverage_percent - 0.0).abs() < f64::EPSILON);
        assert_eq!(stats.work_item_count, 0);
        assert_eq!(stats.test_case_count, 0);
        assert_eq!(stats.review_count, 0);
        assert_eq!(stats.session_count, 0);
        assert_eq!(stats.role_counts.get("Source"), Some(&3));
    }

    #[test]
    fn resolve_graph_at_handles_deep_linear_history_iteratively() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x5b; 32]));
        graph
            .create_change(&SemanticChange {
                id: genesis_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let mut previous = genesis_id;
        let mut head = genesis_id;
        for idx in 0..3_000u16 {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&(idx + 1).to_be_bytes());
            let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));
            graph
                .create_change(&SemanticChange {
                    id,
                    parents: vec![previous],
                    timestamp: Timestamp::now(),
                    author: AuthorId::new("test"),
                    message: format!("change {idx}"),
                    entity_deltas: vec![],
                    relation_deltas: vec![],
                    artifact_deltas: vec![],
                    projected_files: vec![],
                    spec_link: None,
                    evidence: vec![],
                    risk_summary: None,
                    authored_on: None,
                })
                .unwrap();
            previous = id;
            head = id;
        }

        let state = graph.resolve_graph_at(&head).unwrap();
        assert!(state.entities.is_empty());
        assert!(state.relations.is_empty());
        assert!(state.file_tree.is_empty());
    }

    fn test_entity_with_id(id_seed: u128, name: &str) -> Entity {
        Entity {
            id: EntityId(uuid::Uuid::from_u128(id_seed)),
            ..test_entity(name, "src/main.rs")
        }
    }

    #[test]
    fn query_entities_preserves_name_rank() {
        // An exact name match must rank ahead of a token/substring match, even
        // when the exact match has the larger entity id (so a bare id-sort
        // would put it last).
        let graph = InMemoryGraph::new();
        let exact = test_entity_with_id(0xff, "parse");
        let token = test_entity_with_id(0x01, "parseTableFromHtml");
        graph.upsert_entity(&exact).unwrap();
        graph.upsert_entity(&token).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("parse".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let names: Vec<&str> = results.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["parse", "parseTableFromHtml"],
            "exact name match should outrank token match regardless of id"
        );
    }

    #[test]
    fn query_entities_tie_break_is_id_ascending() {
        // Entities at the same rank (all exact name matches) are ordered by id
        // ascending as the total tie-break.
        let graph = InMemoryGraph::new();
        let hi = test_entity_with_id(0x30, "dup");
        let lo = test_entity_with_id(0x10, "dup");
        let mid = test_entity_with_id(0x20, "dup");
        // Insert out of id order.
        graph.upsert_entity(&hi).unwrap();
        graph.upsert_entity(&lo).unwrap();
        graph.upsert_entity(&mid).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("dup".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let ids: Vec<EntityId> = results.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![lo.id, mid.id, hi.id]);
    }

    #[test]
    fn query_entities_deterministic_across_calls() {
        // Same query against the same graph must produce a byte-identical
        // ordering on every call — no HashMap-iteration-order leakage.
        let graph = InMemoryGraph::new();
        for i in 0..32u128 {
            graph
                .upsert_entity(&test_entity_with_id(0x1000 + i, "handler"))
                .unwrap();
        }

        let filter = EntityFilter {
            name_pattern: Some("handler".to_string()),
            ..Default::default()
        };
        let first: Vec<EntityId> = graph
            .query_entities(&filter)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        for _ in 0..8 {
            let again: Vec<EntityId> = graph
                .query_entities(&filter)
                .unwrap()
                .iter()
                .map(|e| e.id)
                .collect();
            assert_eq!(again, first, "query_entities order must be deterministic");
        }
    }

    #[test]
    fn query_entities_non_name_queries_stay_id_sorted() {
        // File and kind queries draw candidates from hash sets in arbitrary
        // order. Their result order must remain a deterministic id-sort and
        // must not be perturbed by the name-rank path.
        let graph = InMemoryGraph::new();
        let ids: Vec<EntityId> = (0..24u128)
            .map(|i| {
                let e = test_entity_with_id(0x900 + i, &format!("fn_{i}"));
                graph.upsert_entity(&e).unwrap();
                e.id
            })
            .collect();
        let mut expected = ids.clone();
        expected.sort();

        let by_file = EntityFilter {
            file_path: Some(FilePathId::new("src/main.rs")),
            ..Default::default()
        };
        let file_ids: Vec<EntityId> = graph
            .query_entities(&by_file)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(file_ids, expected, "file query must be id-sorted");

        let by_kind = EntityFilter {
            kinds: Some(vec![EntityKind::Function]),
            ..Default::default()
        };
        let kind_ids: Vec<EntityId> = graph
            .query_entities(&by_kind)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(kind_ids, expected, "kind query must be id-sorted");
    }

    // -----------------------------------------------------------------------
    // Deterministic priority embedding queue (5.8/R5)
    // -----------------------------------------------------------------------

    #[cfg(feature = "vector")]
    #[test]
    fn recency_queue_dedups_and_keeps_highest_priority_recency() {
        let key = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(1)));

        let mut q: RecencyQueue<RetrievalKey> = RecencyQueue::default();
        q.insert(key, EmbedRecency::Backfill);
        q.insert(key, EmbedRecency::Backfill);
        assert_eq!(q.len(), 1, "duplicate inserts must dedup to one entry");

        // Re-queuing as a live change upgrades recency (lower value wins).
        q.insert(key, EmbedRecency::ChangedThisSync);
        assert_eq!(q.len(), 1);
        assert_eq!(q.drain_all(), vec![(key, EmbedRecency::ChangedThisSync)]);

        // A later backfill must NOT downgrade an existing live-change entry.
        let mut q2: RecencyQueue<RetrievalKey> = RecencyQueue::default();
        q2.insert(key, EmbedRecency::ChangedThisSync);
        q2.insert(key, EmbedRecency::Backfill);
        assert_eq!(q2.drain_all(), vec![(key, EmbedRecency::ChangedThisSync)]);
    }

    /// Pin the INTENDED tier lattice (semantics, not implementation): a refactor
    /// that silently inverts any rung must fail here. Canonical order, earliest
    /// embed first:
    ///   PUBLIC_API < PUBLIC_SOURCE < CRATE_SOURCE < INTERNAL_SOURCE
    ///   < PRIVATE_SOURCE < REVISION < TEST < DOCS < OTHER
    #[cfg(feature = "vector")]
    #[test]
    fn entity_embed_tier_lattice_is_pinned_public_api_first_generated_last() {
        let with = |vis: Visibility, role: EntityRole, kind: EntityKind| -> Entity {
            let mut e = test_entity("e", "src/lib.rs");
            e.visibility = vis;
            e.role = role;
            e.kind = kind;
            e
        };

        // Public API contract surface (each API kind, when Public).
        for kind in [
            EntityKind::ApiEndpoint,
            EntityKind::EventContract,
            EntityKind::Schema,
            EntityKind::Interface,
            EntityKind::TraitDef,
        ] {
            assert_eq!(
                entity_embed_tier(&with(Visibility::Public, EntityRole::Source, kind)),
                embed_tier::PUBLIC_API,
                "{kind:?} @ Public must be the public-API tier"
            );
        }

        // Source code by visibility (non-API kinds).
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::PUBLIC_SOURCE
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Crate,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::CRATE_SOURCE
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Internal,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::INTERNAL_SOURCE
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Private,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::PRIVATE_SOURCE
        );

        // Non-source roles trail all live source, regardless of visibility.
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Test,
                EntityKind::Function
            )),
            embed_tier::TEST
        );
        // A source-roled but structurally-test entity is still a test.
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Source,
                EntityKind::Test
            )),
            embed_tier::TEST
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Docs,
                EntityKind::DocumentNode
            )),
            embed_tier::DOCS
        );
        for role in [
            EntityRole::Generated,
            EntityRole::Vendored,
            EntityRole::External,
        ] {
            assert_eq!(
                entity_embed_tier(&with(Visibility::Public, role, EntityKind::Function)),
                embed_tier::OTHER,
                "{role:?} must be the trailing tier even when Public"
            );
        }

        // The full lattice is strictly ordered, earliest-embed first. REVISION
        // is not produced by entity_embed_tier (it is assigned to historical
        // revision keys in embed_sort_key_for) but is pinned in the chain so the
        // overall ordering contract is encoded in one place.
        assert!(
            embed_tier::PUBLIC_API < embed_tier::PUBLIC_SOURCE
                && embed_tier::PUBLIC_SOURCE < embed_tier::CRATE_SOURCE
                && embed_tier::CRATE_SOURCE < embed_tier::INTERNAL_SOURCE
                && embed_tier::INTERNAL_SOURCE < embed_tier::PRIVATE_SOURCE
                && embed_tier::PRIVATE_SOURCE < embed_tier::REVISION
                && embed_tier::REVISION < embed_tier::TEST
                && embed_tier::TEST < embed_tier::DOCS
                && embed_tier::DOCS < embed_tier::OTHER,
            "tier lattice must stay strictly ordered public-API → generated"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embed_sort_key_precedence_is_tier_recency_centrality_id() {
        let k_lo = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(1)));
        let k_hi = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(2)));

        // Tier dominates recency and centrality.
        let better_tier = EmbedSortKey {
            tier: 0,
            recency: EmbedRecency::Backfill,
            centrality_rank: u32::MAX,
            key: k_hi,
        };
        let worse_tier = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::ChangedThisSync,
            centrality_rank: 0,
            key: k_lo,
        };
        assert!(better_tier < worse_tier);

        // Within a tier, recency dominates centrality.
        let changed = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::ChangedThisSync,
            centrality_rank: u32::MAX,
            key: k_hi,
        };
        let backfill = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: 0,
            key: k_lo,
        };
        assert!(changed < backfill);

        // Within tier+recency, higher in-degree (lower rank) embeds first.
        let high_centrality = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(10),
            key: k_hi,
        };
        let low_centrality = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(0),
            key: k_lo,
        };
        assert!(high_centrality < low_centrality);

        // All else equal, the key id is the stable tiebreak.
        let id_lo = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(0),
            key: k_lo,
        };
        let id_hi = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(0),
            key: k_hi,
        };
        assert!(id_lo < id_hi);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_is_stable_across_insertion_orders() {
        // Same three entities, two different insertion orders -> identical drain.
        let mut alpha = test_entity_with_id(0x10, "alpha");
        alpha.visibility = Visibility::Private; // tier PRIVATE_SOURCE
        let mut beta = test_entity_with_id(0x20, "beta");
        beta.kind = EntityKind::Interface; // tier PUBLIC_API
        let gamma = test_entity_with_id(0x30, "gamma"); // tier PUBLIC_SOURCE

        let g1 = InMemoryGraph::new();
        for e in [&alpha, &beta, &gamma] {
            g1.upsert_entity(e).unwrap();
        }
        let g2 = InMemoryGraph::new();
        for e in [&gamma, &alpha, &beta] {
            g2.upsert_entity(e).unwrap();
        }

        let keys = |drained: Vec<(RetrievalKey, EmbedRecency)>| -> Vec<RetrievalKey> {
            drained.into_iter().map(|(k, _)| k).collect()
        };
        let order1 = keys(g1.drain_embedding_batch(100));
        let order2 = keys(g2.drain_embedding_batch(100));
        assert_eq!(
            order1, order2,
            "drain order must be independent of insertion / map-seed order"
        );

        // And it is the priority order: public API, then public source, then private.
        assert_eq!(
            order1,
            vec![
                RetrievalKey::Entity(beta.id),
                RetrievalKey::Entity(gamma.id),
                RetrievalKey::Entity(alpha.id),
            ]
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_prioritizes_high_centrality_within_tier() {
        let g = InMemoryGraph::new();
        let hub = test_entity_with_id(0x60, "hub");
        let leaf = test_entity_with_id(0x61, "leaf");
        g.upsert_entity(&hub).unwrap();
        g.upsert_entity(&leaf).unwrap();

        // Give hub three incoming relations (in-degree 3); leaf stays at 0.
        for i in 0..3u128 {
            let dep = test_entity_with_id(0x70 + i, "dep");
            g.upsert_entity(&dep).unwrap();
            g.upsert_relation(&test_relation(dep.id, hub.id, RelationKind::Calls))
                .unwrap();
        }

        let order: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let pos = |id| {
            order
                .iter()
                .position(|k| *k == RetrievalKey::Entity(id))
                .unwrap()
        };
        // Same tier + recency; hub's higher in-degree must place it before leaf.
        assert!(
            pos(hub.id) < pos(leaf.id),
            "higher-centrality entity must embed earlier within a tier"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_orders_changed_this_sync_before_backfill() {
        let g = InMemoryGraph::new();
        // a.id < b.id, so an id-only sort would put `a` first; recency must flip it.
        let a = test_entity_with_id(0x40, "aaa");
        let b = test_entity_with_id(0x41, "bbb");
        g.upsert_entity(&a).unwrap();
        g.upsert_entity(&b).unwrap();

        g.embedding_queue.lock().clear();
        g.queue_for_embedding(&[a.id]); // a -> Backfill
        g.upsert_entity(&b).unwrap(); // b -> ChangedThisSync (live invalidate path)

        let order: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            order,
            vec![RetrievalKey::Entity(b.id), RetrievalKey::Entity(a.id)],
            "changed-this-sync must embed before backfill despite a lower id"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_respects_batch_size_and_requeues_leftover() {
        let g = InMemoryGraph::new();
        let mut api = test_entity_with_id(0x80, "api");
        api.kind = EntityKind::Interface; // tier PUBLIC_API
        let pubfn = test_entity_with_id(0x81, "pubfn"); // tier PUBLIC_SOURCE
        let mut privfn = test_entity_with_id(0x82, "privfn");
        privfn.visibility = Visibility::Private; // tier PRIVATE_SOURCE
        g.upsert_entity(&privfn).unwrap();
        g.upsert_entity(&pubfn).unwrap();
        g.upsert_entity(&api).unwrap();

        // Batch of 1 -> only the highest-priority item (the API surface).
        let first = g.drain_embedding_batch(1);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, RetrievalKey::Entity(api.id));
        assert_eq!(g.pending_embeddings(), 2, "leftover must be requeued");

        // Next drain continues in priority order.
        let rest: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            rest,
            vec![
                RetrievalKey::Entity(pubfn.id),
                RetrievalKey::Entity(privfn.id)
            ]
        );
        assert_eq!(g.pending_embeddings(), 0);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_artifact_embedding_batch_is_deterministic_and_recency_first() {
        let g = InMemoryGraph::new();
        // Pure queue-ordering test: ids are arbitrary distinct graph-assigned
        // values, not tied to any tracked path, so mint them directly.
        let id1 = ArtifactId::new();
        let id2 = ArtifactId::new();
        let id3 = ArtifactId::new();

        {
            let mut q = g.artifact_embedding_queue.lock();
            // Scrambled insertion order, mixed recency.
            q.insert(id3, EmbedRecency::Backfill);
            q.insert(id1, EmbedRecency::ChangedThisSync);
            q.insert(id2, EmbedRecency::Backfill);
            // Duplicate insert must dedup.
            q.insert(id2, EmbedRecency::Backfill);
        }
        assert_eq!(g.pending_artifact_embeddings(), 3);

        let order: Vec<ArtifactId> = g
            .drain_artifact_embedding_batch(100)
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        // Changed-this-sync first, then backfill ids in ascending id order.
        let mut backfill = vec![id2, id3];
        backfill.sort();
        let mut expected = vec![id1];
        expected.extend(backfill);
        assert_eq!(order, expected);
    }

    /// Rider 1: the live invalidate (re-enqueue) path must UPGRADE an item
    /// already queued as Backfill to ChangedThisSync — a max-priority insert,
    /// never first-writer-wins — and must not duplicate it.
    #[cfg(feature = "vector")]
    #[test]
    fn invalidate_path_upgrades_queued_backfill_to_changed_this_sync() {
        let g = InMemoryGraph::new();
        // peer has the LOWER id, target the HIGHER id. Same tier + centrality.
        // If recency were ignored, the id tiebreak alone would order [peer, target];
        // an upgrade of `target` to ChangedThisSync must flip that to [target, peer].
        let peer = test_entity_with_id(0x90, "peer");
        let target = test_entity_with_id(0x91, "target");
        g.upsert_entity(&peer).unwrap();
        g.upsert_entity(&target).unwrap();

        // Establish a known baseline: both queued as Backfill.
        g.embedding_queue.lock().clear();
        g.queue_for_embedding(&[peer.id, target.id]);
        assert_eq!(g.pending_embeddings(), 2);

        // Live mutation re-enqueues `target` via the invalidate path.
        g.upsert_entity(&target).unwrap();
        assert_eq!(
            g.pending_embeddings(),
            2,
            "re-enqueue must upgrade in place, not add a duplicate"
        );

        let order: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            order,
            vec![
                RetrievalKey::Entity(target.id),
                RetrievalKey::Entity(peer.id)
            ],
            "invalidate path must UPGRADE backfill→changed-this-sync (max policy), \
             flipping the id-tiebreak order"
        );
    }

    // -----------------------------------------------------------------------
    // Memory re-anchor — rename-durable annotation recall (Track B)
    // -----------------------------------------------------------------------

    #[test]
    fn deposit_captures_entity_fingerprint_anchor() {
        let graph = InMemoryGraph::new();
        let mut e = test_entity("foo", "src/lib.rs");
        e.fingerprint.ast_hash = Hash256::from_bytes([7; 32]);
        e.fingerprint.signature_hash = Hash256::from_bytes([9; 32]);
        graph.upsert_entity(&e).unwrap();

        // Deposit with no anchor — the store must capture the entity fingerprint.
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Instruction,
            body: "remember the invariant".into(),
            scopes: vec![WorkScope::Entity(e.id)],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("alice"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        graph.create_annotation(&ann).unwrap();
        let anchor = graph
            .get_annotation(&ann.annotation_id)
            .unwrap()
            .unwrap()
            .anchored_fingerprint
            .expect("deposit must capture the entity fingerprint anchor");
        assert_eq!(anchor.ast_hash, Hash256::from_bytes([7; 32]));
        assert_eq!(anchor.signature_hash, Hash256::from_bytes([9; 32]));

        // A caller-supplied anchor must be preserved, not overwritten.
        let custom = SemanticAnchor {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
        };
        let ann2 = Annotation {
            annotation_id: AnnotationId::new(),
            anchored_fingerprint: Some(custom.clone()),
            ..ann.clone()
        };
        graph.create_annotation(&ann2).unwrap();
        assert_eq!(
            graph
                .get_annotation(&ann2.annotation_id)
                .unwrap()
                .unwrap()
                .anchored_fingerprint,
            Some(custom),
            "caller-supplied anchor must be preserved"
        );

        // No entity scope → no anchor captured.
        let ann3 = Annotation {
            annotation_id: AnnotationId::new(),
            scopes: vec![WorkScope::Artifact(FilePathId::new("src/lib.rs"))],
            anchored_fingerprint: None,
            ..ann.clone()
        };
        graph.create_annotation(&ann3).unwrap();
        assert!(graph
            .get_annotation(&ann3.annotation_id)
            .unwrap()
            .unwrap()
            .anchored_fingerprint
            .is_none());
    }

    /// Deposit an annotation on a scope (anchor captured by `create_annotation`).
    fn deposit_on(graph: &InMemoryGraph, ann_seed: u128, scope: WorkScope) -> AnnotationId {
        let id = AnnotationId(uuid::Uuid::from_u128(ann_seed));
        let ann = Annotation {
            annotation_id: id,
            kind: AnnotationKind::Instruction,
            body: "remembered detail".into(),
            scopes: vec![scope],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("t"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        graph.create_annotation(&ann).unwrap();
        id
    }

    fn entity_with_fp(seed: u128, name: &str, file: &str, ast: u8, sig: u8) -> Entity {
        let mut e = test_entity_with_id(seed, name);
        e.file_origin = Some(FilePathId::new(file));
        e.fingerprint.ast_hash = Hash256::from_bytes([ast; 32]);
        e.fingerprint.signature_hash = Hash256::from_bytes([sig; 32]);
        e
    }

    #[test]
    fn recall_by_exact_id_is_fresh() {
        let graph = InMemoryGraph::new();
        let e = entity_with_fp(0x100, "foo", "src/a.rs", 1, 2);
        graph.upsert_entity(&e).unwrap();
        deposit_on(&graph, 0xa1, WorkScope::Entity(e.id));

        let recalled = graph.recall_for_entity(&e.id);
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].match_basis, RecallMatchBasis::Id);
        assert_eq!(recalled[0].staleness, StalenessState::Fresh);
    }

    #[test]
    fn recall_reanchors_across_rename() {
        let graph = InMemoryGraph::new();
        let old = entity_with_fp(0x200, "oldName", "src/a.rs", 5, 6);
        graph.upsert_entity(&old).unwrap();
        deposit_on(&graph, 0xb1, WorkScope::Entity(old.id)); // anchor = (5, 6)

        // Rename: the old entity is removed and a new entity (different id, same
        // file/kind/fingerprint, different name) takes its place.
        graph.remove_entity(&old.id).unwrap();
        let new = entity_with_fp(0x201, "newName", "src/a.rs", 5, 6);
        graph.upsert_entity(&new).unwrap();

        // Recall by the NEW id re-anchors the orphaned memory by fingerprint.
        let recalled = graph.recall_for_entity(&new.id);
        assert_eq!(recalled.len(), 1);
        assert_eq!(
            recalled[0].annotation.annotation_id,
            AnnotationId(uuid::Uuid::from_u128(0xb1))
        );
        assert_eq!(
            recalled[0].match_basis,
            RecallMatchBasis::FingerprintReanchor
        );
        assert_eq!(recalled[0].staleness, StalenessState::Fresh);

        // The old (now-removed) id resolves to nothing.
        assert!(graph.recall_for_entity(&old.id).is_empty());
    }

    #[test]
    fn recall_staleness_tiers_by_signature_then_ast_change() {
        let graph = InMemoryGraph::new();
        let e = entity_with_fp(0x300, "f", "src/a.rs", 3, 4);
        graph.upsert_entity(&e).unwrap();
        deposit_on(&graph, 0xc1, WorkScope::Entity(e.id)); // anchor = (3, 4)

        // Signature changes (ast unchanged) → Suspect, still recalled by default.
        graph
            .upsert_entity(&entity_with_fp(0x300, "f", "src/a.rs", 3, 44))
            .unwrap();
        let r = graph.recall_for_entity(&e.id);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].staleness, StalenessState::Suspect);

        // AST changes too → Stale: excluded by default, included on request.
        graph
            .upsert_entity(&entity_with_fp(0x300, "f", "src/a.rs", 33, 44))
            .unwrap();
        assert!(
            graph.recall_for_entity(&e.id).is_empty(),
            "Stale matches are excluded by default"
        );
        let r_all = graph.recall_for_entity_with(
            &e.id,
            &RecallOptions {
                include_stale: true,
                ..Default::default()
            },
        );
        assert_eq!(r_all.len(), 1);
        assert_eq!(r_all[0].staleness, StalenessState::Stale);
    }

    #[test]
    fn recall_excludes_fingerprint_collisions_by_default() {
        let graph = InMemoryGraph::new();
        // Two DIFFERENT live entities sharing a fingerprint (duplicated code).
        let x = entity_with_fp(0x400, "x", "src/x.rs", 8, 8);
        let y = entity_with_fp(0x401, "y", "src/y.rs", 8, 8);
        graph.upsert_entity(&x).unwrap();
        graph.upsert_entity(&y).unwrap();
        deposit_on(&graph, 0xd1, WorkScope::Entity(y.id)); // memory on Y

        // Recall for X: Y is still live, so its memory is a collision — excluded.
        assert!(
            graph.recall_for_entity(&x.id).is_empty(),
            "another live entity's memory must not surface by default"
        );

        // Opt-in surfaces it, tagged as a cross-file collision.
        let r = graph.recall_for_entity_with(
            &x.id,
            &RecallOptions {
                include_fingerprint_collisions: true,
                ..Default::default()
            },
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].match_basis, RecallMatchBasis::FingerprintCollision);
        assert!(!r[0].same_file, "Y is in a different file than X");

        // Y itself recalls its own memory as an exact-id match.
        let ry = graph.recall_for_entity(&y.id);
        assert_eq!(ry.len(), 1);
        assert_eq!(ry[0].match_basis, RecallMatchBasis::Id);
    }

    #[test]
    fn reanchor_orphaned_annotations_rescopes_unique_rename() {
        let graph = InMemoryGraph::new();
        let old = entity_with_fp(0x500, "oldName", "src/a.rs", 5, 6);
        graph.upsert_entity(&old).unwrap();
        deposit_on(&graph, 0xe1, WorkScope::Entity(old.id));

        // Rename to a single new entity sharing the fingerprint.
        graph.remove_entity(&old.id).unwrap();
        let new = entity_with_fp(0x501, "newName", "src/a.rs", 5, 6);
        graph.upsert_entity(&new).unwrap();

        // Before active re-scope, recall resolves only via fingerprint re-anchor.
        assert_eq!(
            graph.recall_for_entity(&new.id)[0].match_basis,
            RecallMatchBasis::FingerprintReanchor
        );

        // Active re-scope appends the new entity scope (unambiguous match).
        assert_eq!(graph.reanchor_orphaned_annotations(), 1);
        let recalled = graph.recall_for_entity(&new.id);
        assert_eq!(recalled.len(), 1);
        assert_eq!(
            recalled[0].match_basis,
            RecallMatchBasis::Id,
            "after re-scope the memory is an exact-id match"
        );

        // Idempotent: a second pass changes nothing.
        assert_eq!(graph.reanchor_orphaned_annotations(), 0);
    }

    #[test]
    fn reanchor_skips_ambiguous_fingerprint() {
        let graph = InMemoryGraph::new();
        let old = entity_with_fp(0x600, "oldName", "src/a.rs", 7, 7);
        graph.upsert_entity(&old).unwrap();
        deposit_on(&graph, 0xf1, WorkScope::Entity(old.id));
        graph.remove_entity(&old.id).unwrap();

        // Two live entities now share the orphaned anchor's fingerprint.
        graph
            .upsert_entity(&entity_with_fp(0x601, "candA", "src/a.rs", 7, 7))
            .unwrap();
        graph
            .upsert_entity(&entity_with_fp(0x602, "candB", "src/b.rs", 7, 7))
            .unwrap();

        // Ambiguous → must NOT commit a re-scope (could mis-anchor to a duplicate).
        assert_eq!(graph.reanchor_orphaned_annotations(), 0);
        let ann = graph
            .get_annotation(&AnnotationId(uuid::Uuid::from_u128(0xf1)))
            .unwrap()
            .unwrap();
        assert_eq!(
            ann.scopes,
            vec![WorkScope::Entity(old.id)],
            "ambiguous anchors are left for lazy fingerprint recall, not committed"
        );
    }

    // -----------------------------------------------------------------------
    // Vector index self-description / dimension recovery (R2/R9, #10c)
    // -----------------------------------------------------------------------

    #[cfg(feature = "vector")]
    #[test]
    fn save_vector_index_persists_stamped_descriptor() {
        use crate::vector::{IndexDescriptor, IndexLoadOutcome};

        let graph = InMemoryGraph::new();
        let vi = crate::VectorIndex::new(2).unwrap();
        vi.upsert(EntityId::new(), &[1.0, 0.0]).unwrap();
        *graph.vector_index.lock() = Some(std::sync::Arc::new(vi));

        graph.stamp_vector_index_descriptor(IndexDescriptor {
            model_id: Some("model-A@1".into()),
            graph_root: Some("root-1".into()),
        });

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("g.kvec");
        graph.save_vector_index(&path).unwrap();

        // The persisted .kvec proves its own model/graph identity on load.
        assert!(matches!(
            crate::VectorIndex::load_compatible(
                &path,
                &IndexDescriptor {
                    model_id: Some("model-A@1".into()),
                    graph_root: Some("root-1".into()),
                },
            ),
            IndexLoadOutcome::Loaded(_)
        ));
        // A same-dimension model swap is caught from the stamp alone.
        assert!(matches!(
            crate::VectorIndex::load_compatible(
                &path,
                &IndexDescriptor {
                    model_id: Some("model-B@1".into()),
                    graph_root: Some("root-1".into()),
                },
            ),
            IndexLoadOutcome::Incompatible(_)
        ));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn load_vector_index_compatible_rejects_swap_without_installing() {
        use crate::vector::{IndexDescriptor, VectorIndexLoad};

        // Persist a stamped index (model-A).
        let writer = InMemoryGraph::new();
        let vi = crate::VectorIndex::new(2).unwrap();
        vi.upsert(EntityId::new(), &[1.0, 0.0]).unwrap();
        *writer.vector_index.lock() = Some(std::sync::Arc::new(vi));
        writer.stamp_vector_index_descriptor(IndexDescriptor {
            model_id: Some("model-A@1".into()),
            graph_root: Some("root-1".into()),
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("g.kvec");
        writer.save_vector_index(&path).unwrap();

        // A model-B expectation is rejected and NOT installed (no silent garbage).
        let graph = InMemoryGraph::new();
        let out = graph.load_vector_index_compatible(
            &path,
            &IndexDescriptor {
                model_id: Some("model-B@1".into()),
                graph_root: Some("root-1".into()),
            },
        );
        assert!(matches!(out, VectorIndexLoad::Incompatible(_)));
        assert!(
            graph.vector_index.lock().is_none(),
            "an incompatible index must never be installed"
        );

        // The matching expectation installs it.
        let out2 = graph.load_vector_index_compatible(
            &path,
            &IndexDescriptor {
                model_id: Some("model-A@1".into()),
                graph_root: Some("root-1".into()),
            },
        );
        assert!(matches!(out2, VectorIndexLoad::Loaded(1)));
        assert!(graph.vector_index.lock().is_some());
    }
}
