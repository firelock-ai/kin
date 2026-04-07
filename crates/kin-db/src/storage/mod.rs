// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod backend;
pub mod delta;
pub mod format;
#[cfg(feature = "gcs")]
pub mod gcs;
pub mod index;
pub mod merkle;
pub mod migration;
mod mmap;
mod snapshot;
#[cfg(feature = "sql")]
pub mod sql;
pub mod tiered;

pub use backend::{Generation, LocalFileBackend, StorageBackend, GENERATION_INIT};
pub use delta::{
    apply_graph_delta, compute_graph_delta, CollectionDelta, GraphSnapshotDelta, VecDelta,
};
pub use format::{CompactionStats, GraphSnapshot};
#[cfg(feature = "gcs")]
pub use gcs::GcsBackend;
pub use index::ReadIndex;
pub use merkle::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_repo_truth_hash, compute_subgraph_hash, remove_entity_hash, update_entity_hash,
    verify_entity, verify_subgraph, EntityVerification, MerkleHash, TamperedNode,
    VerificationReport, ZERO_HASH,
};
pub use snapshot::SnapshotManager;
#[cfg(feature = "vector")]
pub use snapshot::VECTOR_INDEX_METADATA_VERSION;
#[cfg(feature = "sql")]
pub use sql::SqliteBackend;
pub use tiered::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
