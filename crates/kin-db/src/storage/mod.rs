// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod authority;
pub mod backend;
pub(crate) mod change_validation;
pub mod delta;
pub mod format;
#[cfg(feature = "gcs")]
pub mod gcs;
pub(crate) mod history_replay;
pub mod index;
mod local_journal;
pub mod merkle;
mod mmap;
pub mod repository;
mod snapshot;
#[cfg(feature = "sql")]
pub mod sql;
pub mod tiered;

pub use authority::{
    AuthorityCommitDecision, AuthorityPublication, AuthorityReadLease, DurableAuthorityPersistence,
    PersistOutcome, VersionedAuthorityState,
};
pub use backend::{
    load_recovered_snapshot, AuthorityPayloadStats, Generation, LocalFileBackend,
    LocalNamespaceIdentityFault, LocalNamespaceProbe, PersistedDelta,
    PreparedWorkspaceGraphArtifact, RecoveredSnapshot, SnapshotAuthority, SnapshotCursor,
    SnapshotRecoveryState, SnapshotSaveOutcome, SourceBlobValidationRequest, SourceBlobWriteBatch,
    StorageBackend, VerifiedSourceBlob, VerifiedSourceBlobBatch, GENERATION_INIT,
    MAX_SOURCE_BLOB_BYTES,
};
pub use delta::{
    apply_graph_delta, compute_graph_delta, CollectionDelta, GraphSnapshotDelta, VecDelta,
};
pub use format::{CompactionStats, GraphSnapshot};
#[cfg(feature = "gcs")]
pub use gcs::GcsBackend;
pub use index::ReadIndex;
pub use merkle::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_repo_truth_hash, compute_retrieval_authority_hash, compute_subgraph_hash,
    remove_entity_hash, update_entity_hash, verify_entity, verify_subgraph, EntityVerification,
    MerkleHash, RepoTruthHash, TamperedNode, VerificationReport, REPO_TRUTH_HASH_VERSION,
    RETRIEVAL_AUTHORITY_HASH_VERSION, ZERO_HASH,
};
pub use repository::{
    ChangeAdmissionPolicy, LocalRepositoryAuthorityFreeze, PersistedRepositoryAuthority,
    PreparedWorkspaceGraphStats, RepositoryAuthorityManager, RepositoryAuthorityState,
    WorkspaceAdmissionSnapshot, PREPARED_WORKSPACE_GRAPH_VERSION,
};
pub use snapshot::SnapshotManager;
#[cfg(feature = "vector")]
pub use snapshot::VECTOR_INDEX_METADATA_VERSION;
#[cfg(feature = "sql")]
pub use sql::SqliteBackend;
pub use tiered::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
