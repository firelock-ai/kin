// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod authority;
pub mod authority_frame;
pub mod backend;
pub(crate) mod body_walk;
pub(crate) mod canonical_hash;
pub mod change_map;
pub(crate) mod change_validation;
pub mod delta;
pub mod format;
#[cfg(feature = "gcs")]
pub mod gcs;
mod gcs_compatibility;
pub(crate) mod history_replay;
pub mod index;
mod local_journal;
pub mod merkle;
mod mmap;
#[cfg(feature = "vector")]
pub(crate) use local_journal::sync_parent_directory;
#[cfg(feature = "vector")]
pub(crate) use mmap::open_regular_nofollow;
#[cfg(feature = "embeddings")]
pub(crate) use mmap::read_regular_bounded;
pub mod repository;
mod snapshot;
#[cfg(feature = "sql")]
pub mod sql;
pub mod tiered;

pub use authority::{
    AuthorityCommitDecision, AuthorityPublication, AuthorityReadLease, DurableAuthorityPersistence,
    PersistOutcome, VersionedAuthorityState,
};
pub use authority_frame::AuthorityFrame;
pub use backend::{
    load_recovered_snapshot, AuthorityPayloadStats, Generation, LocalFileBackend,
    LocalNamespaceIdentityFault, LocalNamespaceProbe, PersistedDelta, PersistedVectorArtifact,
    PreparedWorkspaceGraphArtifact, RecoveredSnapshot, SnapshotAuthority, SnapshotCursor,
    SnapshotRecoveryState, SnapshotSaveOutcome, SourceBlobValidationRequest, SourceBlobWriteBatch,
    StorageBackend, VectorArtifact, VectorArtifactBinding, VectorArtifactCursor,
    VectorArtifactLoadOutcome, VectorArtifactSaveOutcome, VectorRepositoryIdentity,
    VerifiedSourceBlob, VerifiedSourceBlobBatch, GENERATION_INIT, MAX_SOURCE_BLOB_BYTES,
    MAX_VECTOR_ARTIFACT_BYTES, MAX_VECTOR_ARTIFACT_METADATA_BYTES,
};
pub use change_map::{ChangeMap, ChangeMapInner};
pub use delta::{
    apply_graph_delta, compute_graph_delta, CollectionDelta, GraphSnapshotDelta, VecDelta,
};
pub use format::{
    AuthorityEnvelopeSnapshot, CompactionStats, GraphSnapshot, MaterializedGraphRefusal,
    MaterializedGraphSection, WorkspaceGraphFacts, MATERIALIZED_GRAPH_SCHEMA_VERSION,
};
#[cfg(feature = "gcs")]
pub use gcs::GcsBackend;
pub use gcs_compatibility::{
    GcsFullAuthorityEnvelopeCompatibility, GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY,
};
pub use index::ReadIndex;
pub use merkle::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_repo_truth_hash, compute_retrieval_authority_hash, compute_subgraph_hash,
    remove_entity_hash, update_entity_hash, verify_entity, verify_subgraph, EntityVerification,
    MerkleHash, RepoTruthHash, TamperedNode, VerificationReport, REPO_TRUTH_HASH_VERSION,
    RETRIEVAL_AUTHORITY_HASH_VERSION, ZERO_HASH,
};
pub use repository::{
    ChangeAdmissionPolicy, LocalRepositoryAuthorityFreeze, MaterializedGraphSectionOutcome,
    PersistedRepositoryAuthority, PreparedWorkspaceGraphStats, RepositoryAuthorityManager,
    RepositoryAuthorityMetadata, RepositoryAuthorityState, WorkspaceAdmissionSnapshot,
    PREPARED_WORKSPACE_GRAPH_VERSION,
};
#[cfg(feature = "vector")]
pub use snapshot::{
    read_hosted_vector_artifact_actual_producers, validate_hosted_vector_artifact_inner,
    validate_hosted_vector_artifact_inner_for_producers,
    validate_hosted_vector_artifact_inner_with_producers, VECTOR_INDEX_METADATA_VERSION,
};
pub use snapshot::{SnapshotManager, VectorSidecarDisposition, VectorSidecarLoadOutcome};
#[cfg(feature = "sql")]
pub use sql::SqliteBackend;
pub use tiered::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
