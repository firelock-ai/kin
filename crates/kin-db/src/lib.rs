// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod admission;
pub mod embed;
pub mod engine;
pub mod error;
pub mod retrieval;
pub mod search;
pub mod storage;
pub mod store;
pub mod types;
#[cfg(feature = "vector")]
pub mod vector;

pub use embed::{
    CodeEmbedder, EmbeddingProducer, EmbeddingProducerSet, ProducedEmbeddingBatch,
    VectorProducerProvenance,
};
#[cfg(feature = "vector")]
pub use engine::VectorSalvageStats;
pub use engine::{
    EmbeddingStatus, InMemoryGraph, PersistenceEpoch, ProducedSemanticSearch,
    ProducedSemanticSearchBatch, ResolvedRetrievalItem,
};
pub use error::{KinDbError, Result};
pub use kin_search::TEXT_INDEX_FORMAT_VERSION;
pub use retrieval::{unified_retrieve, RetrievalCandidate, RetrievalQuery};
pub use search::{resolve_roles, ScoredHit, TextIndex};
pub use storage::format::{
    CompactionStats, GraphSnapshot, MaterializedGraphRefusal, MaterializedGraphSection,
    WorkspaceGraphFacts, MATERIALIZED_GRAPH_SCHEMA_VERSION,
};
#[cfg(feature = "gcs")]
pub use storage::GcsBackend;
pub use storage::ReadIndex;
pub use storage::SnapshotManager;
pub use storage::{
    apply_graph_delta, compute_graph_delta, CollectionDelta, GraphSnapshotDelta, VecDelta,
};
pub use storage::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_repo_truth_hash, compute_subgraph_hash, remove_entity_hash, update_entity_hash,
    verify_entity, verify_subgraph, EntityVerification, MerkleHash, RepoTruthHash, TamperedNode,
    VerificationReport, REPO_TRUTH_HASH_VERSION, ZERO_HASH,
};
pub use storage::{
    load_recovered_snapshot, AuthorityPayloadStats, GcsFullAuthorityEnvelopeCompatibility,
    Generation, LocalFileBackend, LocalNamespaceIdentityFault, LocalNamespaceProbe, PersistedDelta,
    PersistedVectorArtifact, RecoveredSnapshot, SnapshotAuthority, SnapshotCursor,
    SnapshotRecoveryState, SnapshotSaveOutcome, SourceBlobValidationRequest, SourceBlobWriteBatch,
    StorageBackend, VectorArtifact, VectorArtifactBinding, VectorArtifactCursor,
    VectorArtifactLoadOutcome, VectorArtifactSaveOutcome, VectorRepositoryIdentity,
    VerifiedSourceBlob, VerifiedSourceBlobBatch, GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY,
    GENERATION_INIT, MAX_SOURCE_BLOB_BYTES, MAX_VECTOR_ARTIFACT_BYTES,
    MAX_VECTOR_ARTIFACT_METADATA_BYTES,
};
#[cfg(feature = "vector")]
pub use storage::{
    read_hosted_vector_artifact_actual_producers, validate_hosted_vector_artifact_inner,
    validate_hosted_vector_artifact_inner_for_producers,
    validate_hosted_vector_artifact_inner_with_producers, VECTOR_INDEX_METADATA_VERSION,
};
pub use storage::{
    AuthorityCommitDecision, AuthorityPublication, AuthorityReadLease, DurableAuthorityPersistence,
    PersistOutcome, VersionedAuthorityState,
};
pub use storage::{
    AuthorityEnvelopeSnapshot, ChangeAdmissionPolicy, LocalRepositoryAuthorityFreeze,
    PersistedRepositoryAuthority, RepositoryAuthorityManager, RepositoryAuthorityMetadata,
    RepositoryAuthorityState, WorkspaceAdmissionSnapshot,
};
pub use storage::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
pub use storage::{VectorSidecarDisposition, VectorSidecarLoadOutcome};
pub use store::{
    ChangeStore, EntityStore, GraphStore, ProvenanceStore, SessionStore, VerificationStore,
    WorkStore,
};
pub use types::*;
#[cfg(feature = "vector")]
pub use vector::{IndexDescriptor, VectorIndex, VectorIndexLoad};
