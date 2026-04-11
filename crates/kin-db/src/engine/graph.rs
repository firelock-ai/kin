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
use crate::storage::merkle::{compute_graph_root_hash, compute_root_hash_generic, GraphHashSource};
use crate::storage::GraphSnapshot;
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

fn append_entity_revisions(ent: &mut EntityData, change: &SemanticChange) {
    for delta in &change.entity_deltas {
        match delta {
            EntityDelta::Added(entity) => {
                ent.entity_revisions
                    .entry(entity.id)
                    .or_default()
                    .push(EntityRevision::new(entity.clone(), change.id, None));
            }
            EntityDelta::Modified { old, new } => {
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
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmbeddingStatus {
    /// Entities queued but not yet embedded.
    pub pending: usize,
    /// Entities currently in the HNSW vector index.
    pub indexed: usize,
    /// Total entities in the graph.
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
    fn hash_entity_ids(&self) -> Vec<EntityId> {
        self.entities.keys().copied().collect()
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
    /// Cached Merkle root hash for the current graph state.
    snapshot_root_hash: parking_lot::RwLock<Option<[u8; 32]>>,
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
    /// Queue of entity IDs that need embedding. Populated on upsert, drained
    /// by background workers or explicit `process_embedding_queue` calls.
    /// Using HashSet to deduplicate (an entity modified twice only needs one embed).
    #[cfg(feature = "vector")]
    embedding_queue: parking_lot::Mutex<hashbrown::HashSet<EntityId>>,
    /// Queue of artifact IDs that need embedding. This keeps artifact re-embed
    /// work targeted instead of forcing a full artifact pass on every embed run.
    #[cfg(feature = "vector")]
    artifact_embedding_queue: parking_lot::Mutex<hashbrown::HashSet<ArtifactId>>,
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
            snapshot_root_hash: parking_lot::RwLock::new(None),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
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
            outgoing: _,
            incoming: _,
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
        let (outgoing, incoming, node_outgoing, node_incoming) = {
            let _span =
                tracing::info_span!("kindb.graph.from_snapshot.build_relation_indexes").entered();
            build_relation_indexes(&relations)
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

        let graph = Self {
            entities: RwLock::new(EntityData {
                entities: entities.into_iter().collect(),
                entity_revisions,
                relations,
                outgoing,
                incoming,
                node_outgoing,
                node_incoming,
                indexes,
                file_hashes: file_hashes.into_iter().collect(),
                shallow_files: shallow_files
                    .into_iter()
                    .map(|sf| (sf.file_id.clone(), sf))
                    .collect(),
                file_layouts: file_layouts
                    .into_iter()
                    .map(|layout| (layout.file_id.clone(), layout))
                    .collect(),
                structured_artifacts: structured_artifacts
                    .into_iter()
                    .map(|artifact| (artifact.file_id.clone(), artifact))
                    .collect(),
                opaque_artifacts: opaque_artifacts
                    .into_iter()
                    .map(|artifact| (artifact.file_id.clone(), artifact))
                    .collect(),
            }),
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
            snapshot_root_hash: parking_lot::RwLock::new(None),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
        };

        if !skip_text_index && !text_index_current {
            graph.rebuild_text_index_with_root_hash(expected_root_hash);
        }

        graph.record_snapshot_root_hash(expected_root_hash);
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

        let graph = Self {
            entities: RwLock::new(EntityData {
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
                shallow_files: shallow_files
                    .into_iter()
                    .map(|sf| (sf.file_id.clone(), sf))
                    .collect(),
                file_layouts: file_layouts
                    .into_iter()
                    .map(|layout| (layout.file_id.clone(), layout))
                    .collect(),
                structured_artifacts: structured_artifacts
                    .into_iter()
                    .map(|artifact| (artifact.file_id.clone(), artifact))
                    .collect(),
                opaque_artifacts: opaque_artifacts
                    .into_iter()
                    .map(|artifact| (artifact.file_id.clone(), artifact))
                    .collect(),
            }),
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
            snapshot_root_hash: parking_lot::RwLock::new(None),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
        };

        if !text_index_current {
            graph.rebuild_text_index_with_root_hash(expected_root_hash);
        }

        graph.record_snapshot_root_hash(expected_root_hash);
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
        *self.snapshot_root_hash.read()
    }

    #[inline]
    pub(crate) fn record_snapshot_root_hash(&self, root_hash: [u8; 32]) {
        *self.snapshot_root_hash.write() = Some(root_hash);
    }

    #[inline]
    fn invalidate_snapshot_root_hash(&self) {
        *self.snapshot_root_hash.write() = None;
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

        let unique_ids: HashSet<EntityId> = entity_ids.iter().copied().collect();
        for entity_id in &unique_ids {
            self.remove_retrievable_vector(&RetrievalKey::Entity(*entity_id))?;
        }
        let ids: Vec<EntityId> = unique_ids.into_iter().collect();
        self.queue_for_embedding(&ids);
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
        self.artifact_embedding_queue.lock().insert(artifact_id);
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
            precomputed_hash.unwrap_or_else(|| compute_root_hash_generic(&*ent, None))
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

        self.record_snapshot_root_hash(graph_root_hash);

        eprintln!(
            "[save-timer] lock={:.1}ms  root_hash={:.1}ms  serialize={:.1}ms  bytes={}",
            t_lock.as_secs_f64() * 1000.0,
            t_hash.as_secs_f64() * 1000.0,
            t_serialize.as_secs_f64() * 1000.0,
            bytes.len(),
        );

        Ok((bytes, graph_root_hash))
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
        }
    }

    /// Compute the Merkle root hash directly from the live entity stores,
    /// without materialising a full `GraphSnapshot`.
    pub fn compute_root_hash(&self) -> crate::storage::merkle::MerkleHash {
        if let Some(root_hash) = self.snapshot_root_hash_hint() {
            return root_hash;
        }
        let ent = self.entities.read();
        let root_hash = compute_root_hash_generic(&*ent, None);
        self.record_snapshot_root_hash(root_hash);
        root_hash
    }

    /// Number of entities in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.read().entities.len()
    }

    /// Number of relations in the graph.
    pub fn relation_count(&self) -> usize {
        self.entities.read().relations.len()
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
            pending_embedding_count: embedding_status.pending,
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
            self.record_snapshot_root_hash(graph_root_hash);
            return Ok(());
        }

        if let Some(ref ti) = self.text_index {
            let root_hash_changed = ti.graph_root_hash() != Some(graph_root_hash);
            ti.set_graph_root_hash(graph_root_hash);
            self.record_snapshot_root_hash(graph_root_hash);
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

    pub fn resolve_retrieval_key(&self, key: &RetrievalKey) -> Option<ResolvedRetrievalItem> {
        let ent = self.entities.read();
        match key {
            RetrievalKey::Entity(entity_id) => ent
                .entities
                .get(entity_id)
                .cloned()
                .map(ResolvedRetrievalItem::Entity),
            RetrievalKey::Artifact(artifact_id) => ent
                .shallow_files
                .values()
                .find(|file| ArtifactId::from_file_id(&file.file_id) == *artifact_id)
                .cloned()
                .map(ResolvedRetrievalItem::ShallowFile)
                .or_else(|| {
                    ent.structured_artifacts
                        .values()
                        .find(|artifact| {
                            ArtifactId::from_file_id(&artifact.file_id) == *artifact_id
                        })
                        .cloned()
                        .map(ResolvedRetrievalItem::StructuredArtifact)
                })
                .or_else(|| {
                    ent.opaque_artifacts
                        .values()
                        .find(|artifact| {
                            ArtifactId::from_file_id(&artifact.file_id) == *artifact_id
                        })
                        .cloned()
                        .map(ResolvedRetrievalItem::OpaqueArtifact)
                }),
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

    /// Get or lazily initialize the HNSW vector index.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn get_vector_index(&self) -> Result<Arc<VectorIndex>, KinDbError> {
        let mut guard = self.vector_index.lock();
        if let Some(ref vi) = *guard {
            return Ok(Arc::clone(vi));
        }
        let embedder = self.get_embedder()?;
        let vi = Arc::new(VectorIndex::new(embedder.dimensions())?);
        *guard = Some(Arc::clone(&vi));
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
        let all_ids: Vec<EntityId> = {
            let ent = self.entities.read();
            ent.entities.keys().copied().collect()
        };
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

        if let Some(ref index) = *self.vector_index.lock() {
            index.save(path)?;
        } else if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to remove stale vector index {}: {e}",
                    path.display()
                ))
            })?;
        }

        Ok(())
    }

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
        let embedder = self.get_embedder()?;
        let vi = self.get_vector_index()?;
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
            queue.insert(*id);
        }
    }

    /// Manually queue artifact IDs for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_artifacts_for_embedding(&self, ids: &[ArtifactId]) {
        let mut queue = self.artifact_embedding_queue.lock();
        for id in ids {
            queue.insert(*id);
        }
    }

    /// Queue ALL entities in the graph for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_all_for_embedding(&self) {
        let ids: Vec<EntityId> = {
            let ent = self.entities.read();
            ent.entities.keys().copied().collect()
        };
        let mut queue = self.embedding_queue.lock();
        for id in ids {
            queue.insert(id);
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

    /// Queue only entities that do not already have vectors in the current index.
    #[cfg(feature = "vector")]
    pub fn queue_missing_for_embedding(&self) {
        let vector_index = self.vector_index.lock().clone();
        let ids: Vec<EntityId> = {
            let ent = self.entities.read();
            ent.entities
                .keys()
                .copied()
                .filter(|id| {
                    vector_index
                        .as_ref()
                        .map(|vi| !vi.contains(id))
                        .unwrap_or(true)
                })
                .collect()
        };
        self.queue_for_embedding(&ids);
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
        }
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

    /// Process up to `batch_size` entities from the embedding queue.
    ///
    /// Drains entity IDs from the queue, generates embeddings via the
    /// CodeEmbedder, and inserts them into the HNSW VectorIndex.
    /// Returns the number of entities successfully embedded.
    ///
    /// This is the main entry point for both:
    /// - Daemon background worker (called periodically)
    /// - CLI `kin embed` command (called in a loop until queue is empty)
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_embedding_queue(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span =
            tracing::info_span!("kindb.process_embedding_queue", batch_size = batch_size).entered();
        use crate::embed::format_graph_entity_text_with_context;

        let batch_size = batch_size.max(1);

        let requeue = |ids: &[EntityId]| {
            if ids.is_empty() {
                return;
            }
            let mut queue = self.embedding_queue.lock();
            for id in ids {
                queue.insert(*id);
            }
        };

        // Drain up to batch_size IDs from the queue.
        let ids: Vec<EntityId> = {
            let mut queue = self.embedding_queue.lock();
            let mut drained = Vec::with_capacity(batch_size.min(queue.len()));
            let mut iter = queue.iter().copied();
            for _ in 0..batch_size {
                if let Some(id) = iter.next() {
                    drained.push(id);
                } else {
                    break;
                }
            }
            for id in &drained {
                queue.remove(id);
            }
            drained
        };

        if ids.is_empty() {
            return Ok(0);
        }

        // Collect text representations under read lock, then drop before inference.
        let entity_data: Vec<(EntityId, String)> = {
            let ent = self.entities.read();
            ids.iter()
                .filter_map(|id| {
                    ent.entities.get(id).map(|e| {
                        let context_lines = collect_embedding_context_lines(&ent, id);
                        (
                            *id,
                            format_graph_entity_text_with_context(e, &context_lines),
                        )
                    })
                })
                .collect()
        };

        if entity_data.is_empty() {
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
        let mut count = 0;
        for (chunk_idx, chunk) in entity_data.chunks(embed_batch_size).enumerate() {
            let texts: Vec<String> = chunk.iter().map(|(_, t)| t.clone()).collect();
            let vectors = match embedder.embed_batch(&texts) {
                Ok(vectors) => vectors,
                Err(err) => {
                    let remaining_ids: Vec<EntityId> = entity_data[chunk_idx * embed_batch_size..]
                        .iter()
                        .map(|(id, _)| *id)
                        .collect();
                    requeue(&remaining_ids);
                    return Err(err);
                }
            };
            for (item_idx, ((id, _), vec)) in chunk.iter().zip(vectors.iter()).enumerate() {
                if let Err(err) = vi.upsert(*id, vec) {
                    let mut remaining_ids: Vec<EntityId> = chunk[item_idx..]
                        .iter()
                        .map(|(rest_id, _)| *rest_id)
                        .collect();
                    remaining_ids.extend(
                        entity_data[(chunk_idx + 1) * embed_batch_size..]
                            .iter()
                            .map(|(rest_id, _)| *rest_id),
                    );
                    requeue(&remaining_ids);
                    return Err(err);
                }
                count += 1;
            }
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

        let requeue = |ids: &[ArtifactId]| {
            if ids.is_empty() {
                return;
            }
            let mut queue = self.artifact_embedding_queue.lock();
            for id in ids {
                queue.insert(*id);
            }
        };

        let ids: Vec<ArtifactId> = {
            let mut queue = self.artifact_embedding_queue.lock();
            let mut drained = Vec::with_capacity(batch_size.min(queue.len()));
            let mut iter = queue.iter().copied();
            for _ in 0..batch_size {
                if let Some(id) = iter.next() {
                    drained.push(id);
                } else {
                    break;
                }
            }
            for id in &drained {
                queue.remove(id);
            }
            drained
        };

        if ids.is_empty() {
            return Ok(0);
        }

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

    /// Get the current embedding status.
    pub fn embedding_status(&self) -> EmbeddingStatus {
        #[cfg(feature = "vector")]
        let (pending, indexed) = {
            let pending = self.embedding_queue.lock().len();
            let indexed = {
                let ent = self.entities.read();
                self.vector_index
                    .lock()
                    .as_ref()
                    .map(|vi| ent.entities.keys().filter(|id| vi.contains(id)).count())
                    .unwrap_or(0)
            };
            (pending, indexed)
        };
        #[cfg(not(feature = "vector"))]
        let (pending, indexed) = (0, 0);

        let total = self.entity_count();
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
        let affected = collect_entity_refresh_targets(&ent, &entity_ids);
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        self.invalidate_snapshot_root_hash();

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
            remove_relations_for_entity(&mut ent, id);
        }
        drop(ent);

        if let Some(ref ti) = self.text_index {
            for id in ids {
                let _ = ti.remove(id);
            }
            self.text_dirty.store(true, Ordering::Release);
        }
        self.invalidate_snapshot_root_hash();

        // Remove vectors for deleted entities.
        #[cfg(feature = "vector")]
        {
            let mut queue = self.embedding_queue.lock();
            for id in ids {
                queue.remove(id);
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
        self.invalidate_snapshot_root_hash();

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
                }
            }
        }
        let affected: Vec<EntityId> = affected.into_iter().collect();
        drop(ent);

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    /// Delete a shallow tracked file by file path.
    pub fn delete_shallow_file(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        self.entities.write().shallow_files.remove(file_id);
        let artifact_id = ArtifactId::from_file_id(file_id);
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
            return Vec::new();
        }

        let entity_set: hashbrown::HashSet<EntityId> = entity_ids.iter().copied().collect();

        for &eid in &entity_ids {
            // Remove the entity itself.
            if let Some(entity) = ent.entities.remove(&eid) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }

            // Remove all outgoing relations from this entity.
            if let Some(out_rids) = ent.outgoing.remove(&eid) {
                for rid in &out_rids {
                    if let Some(rel) = ent.relations.remove(rid) {
                        remove_relation_indexes(&mut ent, &rel);
                    }
                }
            }

            // Remove incoming relations that originate from entities in the SAME file
            // (they were already removed above as outgoing from another entity in
            // entity_ids). For incoming relations from OTHER files, keep them as
            // dangling. We only need to clean up the incoming vec for this entity.
            if let Some(inc_rids) = ent.incoming.remove(&eid) {
                for rid in &inc_rids {
                    // If the relation still exists, it's from an external file — keep it
                    // in the relations map but just remove from this entity's incoming vec
                    // (which we already did by removing the key). However we also need to
                    // check if the source is in the same file set — if so the relation
                    // was already removed above.
                    if let Some(rel) = ent.relations.get(rid) {
                        if rel
                            .src
                            .as_entity()
                            .is_some_and(|src| entity_set.contains(&src))
                        {
                            // Already removed as outgoing above — this is a leftover ref.
                            // The relation is already gone from ent.relations via the
                            // outgoing removal pass.
                        }
                        // If src is NOT in entity_set, this is a cross-file incoming
                        // relation. Keep the relation in ent.relations (dangling dst).
                    }
                }
            }
        }

        // Also remove the file hash entry.
        ent.file_hashes.remove(path);
        self.invalidate_snapshot_root_hash();

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
fn remove_relations_for_entity(ent: &mut EntityData, entity_id: &EntityId) {
    // Collect all relation IDs from both directions
    let mut relation_ids = Vec::new();
    if let Some(outgoing) = ent.outgoing.get(entity_id) {
        relation_ids.extend(outgoing.iter().cloned());
    }
    if let Some(incoming) = ent.incoming.get(entity_id) {
        relation_ids.extend(incoming.iter().cloned());
    }

    // Remove each relation and clean up the other side's edge list
    for rel_id in &relation_ids {
        if let Some(rel) = ent.relations.remove(rel_id) {
            remove_relation_indexes(ent, &rel);
        }
    }

    // Remove the entity's own edge lists
    ent.outgoing.remove(entity_id);
    ent.incoming.remove(entity_id);
}

fn collect_artifact_text_index_docs<'a>(
    ent: &'a EntityData,
) -> impl Iterator<Item = (RetrievalKey, Vec<(String, f32)>)> + 'a {
    ent.shallow_files
        .values()
        .map(|file| {
            (
                RetrievalKey::Artifact(ArtifactId::from_file_id(&file.file_id)),
                shallow_file_fields(file),
            )
        })
        .chain(ent.structured_artifacts.values().map(|artifact| {
            (
                RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id)),
                structured_artifact_fields(artifact),
            )
        }))
        .chain(ent.opaque_artifacts.values().map(|artifact| {
            (
                RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id)),
                opaque_artifact_fields(artifact),
            )
        }))
}

#[cfg(feature = "vector")]
fn collect_artifact_ids(ent: &EntityData) -> Vec<ArtifactId> {
    let mut ids = Vec::with_capacity(
        ent.shallow_files.len() + ent.structured_artifacts.len() + ent.opaque_artifacts.len(),
    );
    ids.extend(
        ent.shallow_files
            .values()
            .map(|file| ArtifactId::from_file_id(&file.file_id)),
    );
    ids.extend(
        ent.structured_artifacts
            .values()
            .map(|artifact| ArtifactId::from_file_id(&artifact.file_id)),
    );
    ids.extend(
        ent.opaque_artifacts
            .values()
            .map(|artifact| ArtifactId::from_file_id(&artifact.file_id)),
    );
    ids
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn artifact_embedding_doc(
    ent: &EntityData,
    artifact_id: &ArtifactId,
) -> Option<(RetrievalKey, String)> {
    if let Some(file) = ent
        .shallow_files
        .values()
        .find(|file| ArtifactId::from_file_id(&file.file_id) == *artifact_id)
    {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_shallow_text(file),
        ));
    }

    if let Some(artifact) = ent
        .structured_artifacts
        .values()
        .find(|artifact| ArtifactId::from_file_id(&artifact.file_id) == *artifact_id)
    {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_artifact_text(artifact),
        ));
    }

    ent.opaque_artifacts
        .values()
        .find(|artifact| ArtifactId::from_file_id(&artifact.file_id) == *artifact_id)
        .map(|artifact| {
            (
                RetrievalKey::Artifact(*artifact_id),
                crate::embed::format_opaque_text(artifact),
            )
        })
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
        (RelationKind::References, true) => "references",
        (RelationKind::References, false) => "referenced_by",
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

        let candidate_ids: Vec<EntityId> = if let Some(ref fp) = filter.file_path {
            ent.indexes.by_file(&fp.0).to_vec()
        } else if let Some(ref pattern) = filter.name_pattern {
            ent.indexes.by_name_pattern(pattern)
        } else if let Some(ref kinds) = filter.kinds {
            if kinds.len() == 1 {
                ent.indexes.by_kind(kinds[0]).to_vec()
            } else {
                ent.entities.keys().copied().collect()
            }
        } else {
            ent.entities.keys().copied().collect()
        };

        let results: Vec<Entity> = candidate_ids
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
        drop(ent); // Release write lock before text index + embedding work.

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        self.invalidate_snapshot_root_hash();

        Ok(())
    }

    fn upsert_relation(&self, relation: &Relation) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut affected = HashSet::new();

        // Remove old edge entries if updating
        if let Some(old) = ent.relations.remove(&relation.id) {
            affected.extend(entity_ids_for_relation(&old));
            remove_relation_indexes(&mut ent, &old);
        }

        // Insert new edge entries
        insert_relation_indexes(&mut ent, relation);
        ent.relations.insert(relation.id, relation.clone());
        affected.extend(entity_ids_for_relation(relation));
        let affected: Vec<EntityId> = affected.into_iter().collect();
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        self.invalidate_snapshot_root_hash();
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
        remove_relations_for_entity(&mut ent, id);
        drop(ent);

        // Remove vector for deleted entity.
        #[cfg(feature = "vector")]
        {
            self.embedding_queue.lock().remove(id);
            if let Some(ref vi) = *self.vector_index.lock() {
                let _ = vi.remove(id);
            }
        }

        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;
        self.invalidate_snapshot_root_hash();

        Ok(())
    }

    fn remove_relation(&self, id: &RelationId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut affected = Vec::new();

        if let Some(rel) = ent.relations.remove(id) {
            affected.extend(entity_ids_for_relation(&rel));
            remove_relation_indexes(&mut ent, &rel);
        }

        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        self.invalidate_snapshot_root_hash();
        Ok(())
    }

    fn upsert_shallow_file(&self, shallow: &ShallowTrackedFile) -> Result<(), KinDbError> {
        self.entities
            .write()
            .shallow_files
            .insert(shallow.file_id.clone(), shallow.clone());
        let key = RetrievalKey::Artifact(ArtifactId::from_file_id(&shallow.file_id));
        let fields = shallow_file_fields(shallow);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(ArtifactId::from_file_id(&shallow.file_id))?;
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
        self.entities
            .write()
            .structured_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
        let key = RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id));
        let fields = structured_artifact_fields(artifact);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(ArtifactId::from_file_id(&artifact.file_id))?;
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
        self.entities.write().structured_artifacts.remove(file_id);
        let artifact_id = ArtifactId::from_file_id(file_id);
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
        self.entities
            .write()
            .opaque_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
        let key = RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id));
        let fields = opaque_artifact_fields(artifact);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(ArtifactId::from_file_id(&artifact.file_id))?;
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
        self.entities.write().opaque_artifacts.remove(file_id);
        let artifact_id = ArtifactId::from_file_id(file_id);
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
        self.entities
            .write()
            .file_layouts
            .insert(layout.file_id.clone(), layout.clone());
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
        self.entities.write().file_layouts.remove(file_id);
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
                all_affected.push(entity.id);
            }

            collect_entity_refresh_targets(&ent, &all_affected)
        };

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        self.invalidate_snapshot_root_hash();

        Ok(())
    }

    fn upsert_relations_batch(&self, relations: &[Relation]) -> Result<(), KinDbError> {
        if relations.is_empty() {
            return Ok(());
        }

        {
            let mut ent = self.entities.write();

            ent.relations.reserve(relations.len());
            for relation in relations {
                if let Some(old) = ent.relations.remove(&relation.id) {
                    remove_relation_indexes(&mut ent, &old);
                }

                insert_relation_indexes(&mut ent, relation);
                ent.relations.insert(relation.id, relation.clone());
            }
        }

        // Relation-derived text fields are now stale for affected entities,
        // but doing 20K+ individual Tantivy upserts is too expensive during
        // bulk init. Instead, mark that a full rebuild is required — this will
        // be honored by persist_text_index_with_root_hash before saving.
        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_snapshot_root_hash();

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

            // Remove all relations of this kind — O(N) scan, no per-relation index work
            let before = ent.relations.len();
            ent.relations.retain(|_, rel| rel.kind != kind);
            let removed = before - ent.relations.len();

            if removed == 0 && new_map.is_empty() {
                return Ok(());
            }

            // Reserve and insert new relations
            ent.relations.reserve(new_map.len());
            for (id, rel) in new_map {
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
        }

        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_snapshot_root_hash();
        Ok(())
    }

    fn remove_relations_batch(&self, ids: &[&RelationId]) -> Result<(), KinDbError> {
        if ids.is_empty() {
            return Ok(());
        }

        {
            let mut ent = self.entities.write();

            for id in ids {
                if let Some(rel) = ent.relations.remove(*id) {
                    remove_relation_indexes(&mut ent, &rel);
                }
            }
        }

        // Defer text index rebuild like upsert_relations_batch.
        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_snapshot_root_hash();

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
        drop(ent);

        let mut chg = self.changes.write();

        // Register in parent → children index
        for parent in &change.parents {
            chg.change_children
                .entry(*parent)
                .or_default()
                .push(change.id);
        }

        chg.changes.insert(change.id, change.clone());
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
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("branch '{}'", name))),
        }
    }

    fn delete_branch(&self, name: &BranchName) -> Result<(), KinDbError> {
        self.changes.write().branches.remove(name);
        Ok(())
    }

    fn list_branches(&self) -> Result<Vec<Branch>, KinDbError> {
        Ok(self.changes.read().branches.values().cloned().collect())
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
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Annotation operations (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_annotation(&self, ann: &Annotation) -> Result<(), KinDbError> {
        self.work
            .write()
            .annotations
            .insert(ann.annotation_id, ann.clone());
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
        }
        Ok(())
    }

    fn delete_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        self.work.write().work_links.retain(|l| l != link);
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
        self.invalidate_snapshot_root_hash();
        Ok(())
    }

    fn create_assertion(&self, assertion: &Assertion) -> Result<(), KinDbError> {
        self.verification
            .write()
            .assertions
            .insert(assertion.assertion_id, assertion.clone());
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
        Ok(())
    }

    fn get_session(&self, session_id: &SessionId) -> Result<Option<AgentSession>, KinDbError> {
        Ok(self.sessions.read().sessions.get(session_id).cloned())
    }

    fn delete_session(&self, session_id: &SessionId) -> Result<(), KinDbError> {
        self.sessions.write().sessions.remove(session_id);
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
        }
        Ok(())
    }

    fn register_intent(&self, intent: &Intent) -> Result<(), KinDbError> {
        self.sessions
            .write()
            .intents
            .insert(intent.intent_id, intent.clone());
        Ok(())
    }

    fn get_intent(&self, intent_id: &IntentId) -> Result<Option<Intent>, KinDbError> {
        Ok(self.sessions.read().intents.get(intent_id).cloned())
    }

    fn delete_intent(&self, intent_id: &IntentId) -> Result<(), KinDbError> {
        self.sessions.write().intents.remove(intent_id);
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
        }
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
        let artifact_key = RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id));
        snapshot.structured_artifacts.push(artifact);

        let graph =
            InMemoryGraph::from_snapshot_with_text_index(snapshot, dir.path().join("text-index"));

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
        let artifact_key = RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id));

        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.flush_text_index().unwrap();

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
        let artifact_key = RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id));

        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.flush_text_index().unwrap();
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

        let shallow_id = ArtifactId::from_file_id(&shallow.file_id);
        let structured_id = ArtifactId::from_file_id(&structured.file_id);
        let opaque_id = ArtifactId::from_file_id(&opaque.file_id);

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

        graph.delete_file_layout(&file_id).unwrap();
        assert!(graph.get_file_layout(&file_id).unwrap().is_none());
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
        let structured_key = RetrievalKey::Artifact(ArtifactId::from_file_id(&structured.file_id));
        index
            .upsert_retrievable(structured_key, &[1.0, 0.0])
            .unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.artifact_embedding_queue.lock().clear();
        graph.queue_missing_artifacts_for_embedding();

        let opaque_id = ArtifactId::from_file_id(&opaque.file_id);
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
        assert!(queue.contains(&caller.id));
        assert!(queue.contains(&callee.id));
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
        assert!(queue.contains(&caller.id));
        assert!(queue.contains(&callee.id));
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
        assert!(queue.contains(&caller.id));
        assert!(queue.contains(&callee_a.id));
        assert!(queue.contains(&callee_b.id));
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
        assert_eq!(stats.pending_embedding_count, 3);
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
}
