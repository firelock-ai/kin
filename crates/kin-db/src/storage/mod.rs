// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod backend;
pub mod format;
#[cfg(feature = "gcs")]
pub mod gcs;
pub mod index;
pub mod merkle;
mod mmap;
mod snapshot;
pub mod tiered;

pub use backend::{Generation, LocalFileBackend, StorageBackend, GENERATION_INIT};
pub use format::GraphSnapshot;
#[cfg(feature = "gcs")]
pub use gcs::GcsBackend;
pub use index::ReadIndex;
pub use merkle::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_subgraph_hash, remove_entity_hash, update_entity_hash, verify_entity, verify_subgraph,
    EntityVerification, MerkleHash, TamperedNode, VerificationReport, ZERO_HASH,
};
pub use snapshot::SnapshotManager;
pub use tiered::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
