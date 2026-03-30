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
use crate::search::TextIndex;
use crate::storage::merkle::compute_graph_root_hash;
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

fn coverage_percent(indexed: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (indexed as f64 / total as f64) * 100.0
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

// ---------------------------------------------------------------------------
// Domain sub-stores
// ---------------------------------------------------------------------------

/// Core entity/relation graph data.
#[derive(Clone)]
struct EntityData {
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
    /// Entity → outgoing relation IDs (entity's dependencies).
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    /// Entity → incoming relation IDs (entity's callers/dependents).
    incoming: HashMap<EntityId, Vec<RelationId>>,
    /// Secondary indexes for fast lookup.
    indexes: IndexSet,
    /// Incremental indexing: file path → SHA-256 content hash.
    file_hashes: HashMap<String, [u8; 32]>,
    /// Shallow file tracking (C2 tier).
    shallow_files: HashMap<FilePathId, ShallowTrackedFile>,
    /// Structured artifact tracking (C1 tier).
    structured_artifacts: HashMap<FilePathId, StructuredArtifact>,
    /// Opaque artifact tracking (C0 tier).
    opaque_artifacts: HashMap<FilePathId, OpaqueArtifact>,
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
    test_covers_entity: hashbrown::HashSet<(TestId, EntityId)>,
    test_covers_contract: hashbrown::HashSet<(TestId, ContractId)>,
    test_verifies_work: hashbrown::HashSet<(TestId, WorkId)>,
    run_proves_entity: hashbrown::HashSet<(VerificationRunId, EntityId)>,
    run_proves_work: hashbrown::HashSet<(VerificationRunId, WorkId)>,
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
    /// True when the text index has uncommitted writes (upsert/remove without commit).
    text_dirty: AtomicBool,
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
                relations: HashMap::new(),
                outgoing: HashMap::new(),
                incoming: HashMap::new(),
                indexes: IndexSet::new(),
                file_hashes: HashMap::new(),
                shallow_files: HashMap::new(),
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
                test_covers_entity: hashbrown::HashSet::new(),
                test_covers_contract: hashbrown::HashSet::new(),
                test_verifies_work: hashbrown::HashSet::new(),
                run_proves_entity: hashbrown::HashSet::new(),
                run_proves_work: hashbrown::HashSet::new(),
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
            text_dirty: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
        };

        graph
    }

    /// Restore a graph from a snapshot (RAM-only text index).
    pub fn from_snapshot(snapshot: GraphSnapshot) -> Self {
        let expected_root_hash = compute_graph_root_hash(&snapshot);
        Self::from_snapshot_inner(snapshot, None, expected_root_hash, false)
    }

    /// Restore a graph from a snapshot (RAM-only text index) with a precomputed
    /// graph root hash.
    pub fn from_snapshot_with_root_hash(
        snapshot: GraphSnapshot,
        expected_root_hash: [u8; 32],
    ) -> Self {
        Self::from_snapshot_inner(snapshot, None, expected_root_hash, false)
    }

    /// Restore a graph from a snapshot with a persistent text index at the
    /// given directory path.
    pub fn from_snapshot_with_text_index(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
    ) -> Self {
        let expected_root_hash = compute_graph_root_hash(&snapshot);
        Self::from_snapshot_inner(snapshot, Some(text_index_path), expected_root_hash, false)
    }

    /// Restore a graph from a snapshot with a persistent text index loaded in
    /// read-only mode.
    pub fn from_snapshot_with_text_index_read_only(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
    ) -> Self {
        let expected_root_hash = compute_graph_root_hash(&snapshot);
        Self::from_snapshot_inner(snapshot, Some(text_index_path), expected_root_hash, true)
    }

    /// Restore a graph from a snapshot with a persistent text index and a
    /// precomputed graph root hash.
    pub fn from_snapshot_with_text_index_and_root_hash(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
        expected_root_hash: [u8; 32],
    ) -> Self {
        Self::from_snapshot_inner(snapshot, Some(text_index_path), expected_root_hash, false)
    }

    /// Restore a graph from a snapshot with a persistent text index loaded in
    /// read-only mode and a precomputed graph root hash.
    pub fn from_snapshot_with_text_index_and_root_hash_read_only(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
        expected_root_hash: [u8; 32],
    ) -> Self {
        Self::from_snapshot_inner(snapshot, Some(text_index_path), expected_root_hash, true)
    }

    fn from_snapshot_inner(
        snapshot: GraphSnapshot,
        text_index_path: Option<PathBuf>,
        expected_root_hash: [u8; 32],
        read_only: bool,
    ) -> Self {
        let text_index = match text_index_path.as_ref() {
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
        };
        let text_index_current = text_index
            .as_ref()
            .and_then(TextIndex::graph_root_hash)
            .map(|hash| hash == expected_root_hash)
            .unwrap_or(false);

        // Build secondary indexes in parallel using rayon.
        // Each chunk produces a partial IndexSet which we merge sequentially.
        // This is ~2-4x faster than a sequential loop for graphs >10K entities.
        let entity_vec: Vec<&Entity> = snapshot.entities.values().collect();
        let indexes = if entity_vec.len() > 1024 {
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
        };

        let graph = Self {
            entities: RwLock::new(EntityData {
                entities: snapshot.entities.into_iter().collect(),
                relations: snapshot.relations.into_iter().collect(),
                outgoing: snapshot.outgoing.into_iter().collect(),
                incoming: snapshot.incoming.into_iter().collect(),
                indexes,
                file_hashes: snapshot.file_hashes.into_iter().collect(),
                shallow_files: snapshot
                    .shallow_files
                    .into_iter()
                    .map(|sf| (sf.file_id.clone(), sf))
                    .collect(),
                structured_artifacts: snapshot
                    .structured_artifacts
                    .into_iter()
                    .map(|artifact| (artifact.file_id.clone(), artifact))
                    .collect(),
                opaque_artifacts: snapshot
                    .opaque_artifacts
                    .into_iter()
                    .map(|artifact| (artifact.file_id.clone(), artifact))
                    .collect(),
            }),
            changes: RwLock::new(ChangeData {
                changes: snapshot.changes.into_iter().collect(),
                change_children: snapshot.change_children.into_iter().collect(),
                branches: snapshot.branches.into_iter().collect(),
            }),
            work: RwLock::new(WorkData {
                work_items: snapshot.work_items.into_iter().collect(),
                annotations: snapshot.annotations.into_iter().collect(),
                work_links: snapshot.work_links,
            }),
            reviews: RwLock::new(ReviewData {
                reviews: snapshot.reviews.into_iter().collect(),
                review_decisions: snapshot.review_decisions.into_iter().collect(),
                review_notes: snapshot
                    .review_notes
                    .into_iter()
                    .map(|n| (n.note_id, n))
                    .collect(),
                review_discussions: snapshot
                    .review_discussions
                    .into_iter()
                    .map(|d| (d.discussion_id, d))
                    .collect(),
                review_assignments: snapshot.review_assignments.into_iter().collect(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: snapshot.test_cases.into_iter().collect(),
                assertions: snapshot.assertions.into_iter().collect(),
                verification_runs: snapshot.verification_runs.into_iter().collect(),
                test_covers_entity: snapshot.test_covers_entity.into_iter().collect(),
                test_covers_contract: snapshot.test_covers_contract.into_iter().collect(),
                test_verifies_work: snapshot.test_verifies_work.into_iter().collect(),
                run_proves_entity: snapshot.run_proves_entity.into_iter().collect(),
                run_proves_work: snapshot.run_proves_work.into_iter().collect(),
                mock_hints: snapshot.mock_hints,
                contracts: snapshot.contracts.into_iter().collect(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: snapshot.actors.into_iter().collect(),
                delegations: snapshot.delegations,
                approvals: snapshot.approvals,
                audit_events: snapshot.audit_events,
            }),
            sessions: RwLock::new(SessionData {
                sessions: snapshot.sessions.into_iter().collect(),
                intents: snapshot.intents.into_iter().collect(),
                downstream_warnings: snapshot.downstream_warnings,
            }),
            text_index,
            text_dirty: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(hashbrown::HashSet::new()),
        };

        if !text_index_current {
            graph.rebuild_text_index_with_root_hash(expected_root_hash);
        }

        graph
    }

    fn rebuild_text_index_with_root_hash(&self, root_hash: [u8; 32]) {
        let Some(ref ti) = self.text_index else {
            return;
        };

        let docs: Vec<(Entity, Vec<(String, f32)>)> = {
            let ent = self.entities.read();
            ent.entities
                .values()
                .map(|entity| {
                    (
                        entity.clone(),
                        collect_text_index_extra_fields(&ent, &entity.id),
                    )
                })
                .collect()
        };

        for (entity, extra_fields) in docs {
            let _ = ti.upsert_with_extra_fields(&entity, &extra_fields);
        }
        ti.set_graph_root_hash(root_hash);
        let _ = ti.commit();
        self.text_dirty.store(false, Ordering::Release);
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
            relations: ent.relations.into_iter().collect(),
            outgoing: ent.outgoing.into_iter().collect(),
            incoming: ent.incoming.into_iter().collect(),
            file_hashes: ent.file_hashes.into_iter().collect(),
            shallow_files: ent.shallow_files.into_values().collect(),
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
            test_covers_entity: ver.test_covers_entity.into_iter().collect(),
            test_covers_contract: ver.test_covers_contract.into_iter().collect(),
            test_verifies_work: ver.test_verifies_work.into_iter().collect(),
            run_proves_entity: ver.run_proves_entity.into_iter().collect(),
            run_proves_work: ver.run_proves_work.into_iter().collect(),
            mock_hints: ver.mock_hints,
            contracts: ver.contracts.into_iter().collect(),
            actors: prv.actors.into_iter().collect(),
            delegations: prv.delegations,
            approvals: prv.approvals,
            audit_events: prv.audit_events,
            sessions: ses.sessions.into_iter().collect(),
            intents: ses.intents.into_iter().collect(),
            downstream_warnings: ses.downstream_warnings,
        }
    }

    /// Number of entities in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.read().entities.len()
    }

    /// Number of relations in the graph.
    pub fn relation_count(&self) -> usize {
        self.entities.read().relations.len()
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
            .map(|index| index.live_document_count())
            .unwrap_or(0);
        let embedding_status = self.embedding_status();

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

        GraphStats {
            total_entities,
            total_relations,
            entity_counts,
            relation_counts,
            shallow_file_count: ent.shallow_files.len(),
            structured_artifact_count: ent.structured_artifacts.len(),
            opaque_artifact_count: ent.opaque_artifacts.len(),
            file_hash_count: ent.file_hashes.len(),
            text_indexed_entity_count,
            text_index_coverage_percent: coverage_percent(
                text_indexed_entity_count,
                total_entities,
            ),
            indexed_embedding_count: embedding_status.indexed,
            pending_embedding_count: embedding_status.pending,
            embedding_coverage_percent: coverage_percent(embedding_status.indexed, total_entities),
            work_item_count: work.work_items.len(),
            test_case_count: verification.test_cases.len(),
            review_count: reviews.reviews.len(),
            session_count: sessions.sessions.len(),
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
        if let Some(ref ti) = self.text_index {
            let root_hash_changed = ti.graph_root_hash() != Some(graph_root_hash);
            ti.set_graph_root_hash(graph_root_hash);
            if root_hash_changed {
                return ti.commit();
            }
        }
        self.flush_text_index()
    }

    /// Full-text search across entity names, signatures, and file paths.
    ///
    /// Returns up to `limit` matching `(EntityId, score)` pairs ranked by
    /// tantivy BM25 relevance. Returns an empty vec when no text index is
    /// available (e.g. the graph was built without one).
    pub fn text_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
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
    /// Returns up to `limit` `(EntityId, distance)` pairs sorted by similarity.
    /// Returns an empty vec when embeddings are not yet built or features
    /// are disabled.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
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
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
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

    /// Manually queue entity IDs for embedding (e.g., after bulk import).
    #[cfg(feature = "vector")]
    pub fn queue_for_embedding(&self, ids: &[EntityId]) {
        let mut queue = self.embedding_queue.lock();
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

    /// Get the current embedding status.
    pub fn embedding_status(&self) -> EmbeddingStatus {
        #[cfg(feature = "vector")]
        let (pending, indexed) = {
            let pending = self.embedding_queue.lock().len();
            let indexed = self
                .vector_index
                .lock()
                .as_ref()
                .map(|vi| vi.len())
                .unwrap_or(0);
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
        drop(ent);

        if let Some(ref ti) = self.text_index {
            for entity in entities {
                let _ = ti.upsert(entity);
            }
            self.text_dirty.store(true, Ordering::Release);
        }

        // Queue entities for embedding. Bulk import/commit paths explicitly
        // build embeddings later, and long-lived daemon sessions drain this
        // queue in the background.
        #[cfg(feature = "vector")]
        {
            let mut queue = self.embedding_queue.lock();
            for entity in entities {
                queue.insert(entity.id);
            }
        }

        Ok(())
    }

    /// Batch-remove multiple entities under a single write lock.
    ///
    /// Removes each entity and its connected relations in one lock
    /// acquisition, avoiding per-entity lock overhead.
    pub fn batch_remove_entities(&self, ids: &[EntityId]) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        for id in ids {
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

        Ok(())
    }

    // ---------------------------------------------------------------
    // Non-trait methods (needed by commit.rs, matching KuzuGraphStore)
    // ---------------------------------------------------------------

    /// Remove all outgoing relations for an entity.
    /// Called during re-linking after file re-parse.
    pub fn remove_outgoing_relations(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        if let Some(rel_ids) = ent.outgoing.remove(id) {
            for rel_id in &rel_ids {
                if let Some(rel) = ent.relations.remove(rel_id) {
                    // Also remove from incoming side
                    if let Some(inc) = ent.incoming.get_mut(&rel.dst) {
                        inc.retain(|r| r != rel_id);
                    }
                }
            }
        }
        Ok(())
    }

    /// Delete a shallow tracked file by file path.
    pub fn delete_shallow_file(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        self.entities.write().shallow_files.remove(file_id);
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
                        // Clean up the incoming side of the destination entity.
                        if let Some(inc) = ent.incoming.get_mut(&rel.dst) {
                            inc.retain(|r| r != rid);
                            if inc.is_empty() {
                                ent.incoming.remove(&rel.dst);
                            }
                        }
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
                        if entity_set.contains(&rel.src) {
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

        entity_ids
    }

    /// Get all file paths that have recorded content hashes.
    pub fn indexed_file_paths(&self) -> Vec<String> {
        self.entities.read().file_hashes.keys().cloned().collect()
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
            // Clean up the OTHER entity's outgoing list
            if &rel.src != entity_id {
                if let Some(out) = ent.outgoing.get_mut(&rel.src) {
                    out.retain(|id| id != rel_id);
                }
            }
            // Clean up the OTHER entity's incoming list
            if &rel.dst != entity_id {
                if let Some(inc) = ent.incoming.get_mut(&rel.dst) {
                    inc.retain(|id| id != rel_id);
                }
            }
        }
    }

    // Remove the entity's own edge lists
    ent.outgoing.remove(entity_id);
    ent.incoming.remove(entity_id);
}

fn collect_text_index_extra_fields(ent: &EntityData, entity_id: &EntityId) -> Vec<(String, f32)> {
    let mut fields = Vec::new();
    let mut seen = HashSet::new();

    collect_relation_text_fields(
        ent,
        ent.outgoing.get(entity_id).into_iter().flatten(),
        entity_id,
        &mut seen,
        &mut fields,
    );
    collect_relation_text_fields(
        ent,
        ent.incoming.get(entity_id).into_iter().flatten(),
        entity_id,
        &mut seen,
        &mut fields,
    );

    fields
}

fn collect_relation_text_fields<'a>(
    ent: &EntityData,
    relation_ids: impl Iterator<Item = &'a RelationId>,
    entity_id: &EntityId,
    seen: &mut HashSet<String>,
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
            if !import_source.is_empty() && seen.insert(format!("import:{import_source}")) {
                fields.push((import_source.to_string(), TEXT_INDEX_IMPORT_SOURCE_WEIGHT));
            }
        }

        let neighbor_id = if relation.src == *entity_id {
            relation.dst
        } else {
            relation.src
        };
        let Some(neighbor) = ent.entities.get(&neighbor_id) else {
            continue;
        };
        let neighbor_name = neighbor.name.trim();
        if !neighbor_name.is_empty() && seen.insert(format!("neighbor:{neighbor_name}")) {
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

        let neighbor_id = if relation.src == *entity_id {
            relation.dst
        } else {
            relation.src
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
        (RelationKind::Contains, _) => "contains",
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
                    if kinds.is_empty() || kinds.contains(&rel.kind) {
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
                    if seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        // Incoming
        if let Some(edge_ids) = ent.incoming.get(id) {
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
        drop(ent); // Release write lock before text index + embedding work.

        self.refresh_text_index_for_entities(&[entity.id]);

        // Queue the entity for embedding. Interactive daemon sessions can
        // drain this asynchronously; explicit CLI flows rebuild via `kin embed`.
        #[cfg(feature = "vector")]
        {
            self.embedding_queue.lock().insert(entity.id);
        }

        Ok(())
    }

    fn upsert_relation(&self, relation: &Relation) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();

        // Remove old edge entries if updating
        if let Some(old) = ent.relations.remove(&relation.id) {
            if let Some(out) = ent.outgoing.get_mut(&old.src) {
                out.retain(|r| *r != relation.id);
            }
            if let Some(inc) = ent.incoming.get_mut(&old.dst) {
                inc.retain(|r| *r != relation.id);
            }
        }

        // Insert new edge entries
        ent.outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        ent.incoming
            .entry(relation.dst)
            .or_default()
            .push(relation.id);

        ent.relations.insert(relation.id, relation.clone());
        let affected = [relation.src, relation.dst];
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
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
                        affected_neighbors.push(rel.dst);
                    }
                }
            }
            if let Some(incoming) = ent.incoming.get(id) {
                for rel_id in incoming {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        affected_neighbors.push(rel.src);
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

        Ok(())
    }

    fn remove_relation(&self, id: &RelationId) -> Result<(), KinDbError> {
        let mut ent = self.entities.write();
        let mut affected = Vec::new();

        if let Some(rel) = ent.relations.remove(id) {
            affected.push(rel.src);
            affected.push(rel.dst);
            if let Some(out) = ent.outgoing.get_mut(&rel.src) {
                out.retain(|r| *r != *id);
            }
            if let Some(inc) = ent.incoming.get_mut(&rel.dst) {
                inc.retain(|r| *r != *id);
            }
        }

        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        Ok(())
    }

    fn upsert_shallow_file(&self, shallow: &ShallowTrackedFile) -> Result<(), KinDbError> {
        self.entities
            .write()
            .shallow_files
            .insert(shallow.file_id.clone(), shallow.clone());
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

    fn upsert_structured_artifact(&self, artifact: &StructuredArtifact) -> Result<(), KinDbError> {
        self.entities
            .write()
            .structured_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
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

    fn delete_structured_artifact(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        self.entities.write().structured_artifacts.remove(file_id);
        Ok(())
    }

    fn upsert_opaque_artifact(&self, artifact: &OpaqueArtifact) -> Result<(), KinDbError> {
        self.entities
            .write()
            .opaque_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
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

    fn delete_opaque_artifact(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        self.entities.write().opaque_artifacts.remove(file_id);
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
        // Lock ordering: entities → verification
        let ent = self.entities.read();
        let mut ver = self.verification.write();
        // Auto-create coverage edges from entity scopes (matches KuzuGraphStore behavior).
        for scope in &test.scopes {
            if let WorkScope::Entity(eid) = scope {
                if ent.entities.contains_key(eid) {
                    ver.test_covers_entity.insert((test.test_id, *eid));
                }
            }
        }
        ver.test_cases.insert(test.test_id, test.clone());
        Ok(())
    }

    fn get_test_case(&self, id: &TestId) -> Result<Option<TestCase>, KinDbError> {
        Ok(self.verification.read().test_cases.get(id).cloned())
    }

    fn get_tests_for_entity(&self, id: &EntityId) -> Result<Vec<TestCase>, KinDbError> {
        let ver = self.verification.read();
        let test_ids: Vec<TestId> = ver
            .test_covers_entity
            .iter()
            .filter_map(|(tid, eid)| if eid == id { Some(*tid) } else { None })
            .collect();
        let results = test_ids
            .iter()
            .filter_map(|tid| ver.test_cases.get(tid).cloned())
            .collect();
        Ok(results)
    }

    fn delete_test_case(&self, id: &TestId) -> Result<(), KinDbError> {
        let mut ver = self.verification.write();
        ver.test_cases.remove(id);
        ver.test_covers_entity.retain(|(tid, _)| tid != id);
        ver.test_covers_contract.retain(|(tid, _)| tid != id);
        ver.test_verifies_work.retain(|(tid, _)| tid != id);
        ver.mock_hints.retain(|h| h.test_id != *id);
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
        let ver = self.verification.read();
        let total = ent.entities.len();
        let covered_ids: std::collections::HashSet<EntityId> =
            ver.test_covers_entity.iter().map(|(_, eid)| *eid).collect();
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
        self.verification
            .write()
            .test_covers_entity
            .insert((*test_id, *entity_id));
        Ok(())
    }

    fn create_test_covers_contract(
        &self,
        test_id: &TestId,
        contract_id: &ContractId,
    ) -> Result<(), KinDbError> {
        self.verification
            .write()
            .test_covers_contract
            .insert((*test_id, *contract_id));
        Ok(())
    }

    fn create_test_verifies_work(
        &self,
        test_id: &TestId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        self.verification
            .write()
            .test_verifies_work
            .insert((*test_id, *work_id));
        Ok(())
    }

    fn get_tests_covering_contract(
        &self,
        contract_id: &ContractId,
    ) -> Result<Vec<TestCase>, KinDbError> {
        let ver = self.verification.read();
        let test_ids: Vec<TestId> = ver
            .test_covers_contract
            .iter()
            .filter_map(
                |(tid, cid)| {
                    if cid == contract_id {
                        Some(*tid)
                    } else {
                        None
                    }
                },
            )
            .collect();
        let results = test_ids
            .iter()
            .filter_map(|tid| ver.test_cases.get(tid).cloned())
            .collect();
        Ok(results)
    }

    fn get_tests_verifying_work(&self, work_id: &WorkId) -> Result<Vec<TestCase>, KinDbError> {
        let ver = self.verification.read();
        let test_ids: Vec<TestId> = ver
            .test_verifies_work
            .iter()
            .filter_map(|(tid, wid)| if wid == work_id { Some(*tid) } else { None })
            .collect();
        let results = test_ids
            .iter()
            .filter_map(|tid| ver.test_cases.get(tid).cloned())
            .collect();
        Ok(results)
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
        self.verification
            .write()
            .run_proves_entity
            .insert((*run_id, *entity_id));
        Ok(())
    }

    fn link_run_proves_work(
        &self,
        run_id: &VerificationRunId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        self.verification
            .write()
            .run_proves_work
            .insert((*run_id, *work_id));
        Ok(())
    }

    fn list_runs_proving_entity(
        &self,
        entity_id: &EntityId,
    ) -> Result<Vec<VerificationRun>, KinDbError> {
        let ver = self.verification.read();
        let results = ver
            .run_proves_entity
            .iter()
            .filter_map(|(run_id, linked_entity_id)| {
                if linked_entity_id == entity_id {
                    ver.verification_runs.get(run_id).cloned()
                } else {
                    None
                }
            })
            .collect();
        Ok(results)
    }

    fn list_runs_proving_work(&self, work_id: &WorkId) -> Result<Vec<VerificationRun>, KinDbError> {
        let ver = self.verification.read();
        let results = ver
            .run_proves_work
            .iter()
            .filter_map(|(run_id, linked_work_id)| {
                if linked_work_id == work_id {
                    ver.verification_runs.get(run_id).cloned()
                } else {
                    None
                }
            })
            .collect();
        Ok(results)
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
        let ver = self.verification.read();
        let total = ver.contracts.len();
        let covered_ids: std::collections::HashSet<ContractId> = ver
            .test_covers_contract
            .iter()
            .map(|(_, cid)| *cid)
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

    true
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
        assert_eq!(rels[0].dst, e2.id);

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
                .any(|(entity_id, _)| *entity_id == caller.id),
            "caller should become searchable by import-source context"
        );

        let neighbor_hits = graph.text_search("parseExtensionRegistry", 10).unwrap();
        assert!(
            neighbor_hits
                .iter()
                .any(|(entity_id, _)| *entity_id == caller.id),
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

        let graph =
            InMemoryGraph::from_snapshot_with_text_index(snapshot, dir.path().join("text-index"));

        let hits = graph.text_search("extension registry", 10).unwrap();
        assert!(
            hits.iter().any(|(hit_id, _)| *hit_id == entity_id),
            "snapshot restore should make entities immediately searchable"
        );
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

        // Upsert replaces
        let sf2 = ShallowTrackedFile {
            declaration_count: 10,
            ..sf.clone()
        };
        graph.upsert_shallow_file(&sf2).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 10);
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

        graph
            .delete_structured_artifact(&structured.file_id)
            .unwrap();
        graph.delete_opaque_artifact(&opaque.file_id).unwrap();
        assert!(graph.list_structured_artifacts().unwrap().is_empty());
        assert!(graph.list_opaque_artifacts().unwrap().is_empty());
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

        // Insert a Calls relation
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        graph.upsert_relation(&r1).unwrap();

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
        assert_eq!(stats.total_relations, 1);
        assert_eq!(stats.entity_counts.get("Function"), Some(&2));
        assert_eq!(stats.entity_counts.get("Class"), Some(&1));
        assert_eq!(stats.relation_counts.get("Calls"), Some(&1));
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
    }
}
