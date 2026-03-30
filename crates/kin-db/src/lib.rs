// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

pub use embed::CodeEmbedder;
pub use engine::{EmbeddingStatus, InMemoryGraph, ResolvedRetrievalItem};
pub use error::{KinDbError, Result};
pub use retrieval::{unified_retrieve, RetrievalCandidate, RetrievalQuery};
pub use search::TextIndex;
pub use storage::format::{CompactionStats, GraphSnapshot};
#[cfg(feature = "gcs")]
pub use storage::GcsBackend;
pub use storage::ReadIndex;
pub use storage::SnapshotManager;
pub use storage::{
    apply_graph_delta, compute_graph_delta, CollectionDelta, GraphSnapshotDelta, VecDelta,
};
pub use storage::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_subgraph_hash, remove_entity_hash, update_entity_hash, verify_entity, verify_subgraph,
    EntityVerification, MerkleHash, TamperedNode, VerificationReport, ZERO_HASH,
};
pub use storage::{Generation, LocalFileBackend, StorageBackend, GENERATION_INIT};
pub use storage::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
#[cfg(feature = "vector")]
pub use storage::VECTOR_INDEX_METADATA_VERSION;
pub use store::{
    ChangeStore, EntityStore, GraphStore, ProvenanceStore, SessionStore, VerificationStore,
    WorkStore,
};
pub use kin_search::TEXT_INDEX_FORMAT_VERSION;
pub use types::*;
#[cfg(feature = "vector")]
pub use vector::VectorIndex;
