// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod embed;
pub mod engine;
pub mod error;
pub mod search;
pub mod storage;
pub mod store;
pub mod types;
#[cfg(feature = "vector")]
pub mod vector;

pub use embed::CodeEmbedder;
pub use engine::InMemoryGraph;
pub use error::{KinDbError, Result};
pub use search::TextIndex;
pub use storage::ReadIndex;
pub use storage::SnapshotManager;
pub use storage::{
    build_entity_hash_map, compute_entity_hash, compute_graph_root_hash, compute_relation_hash,
    compute_subgraph_hash, remove_entity_hash, update_entity_hash, verify_entity, verify_subgraph,
    EntityVerification, MerkleHash, TamperedNode, VerificationReport, ZERO_HASH,
};
pub use storage::{LoadStrategy, SystemMemInfo, TieredConfig, TieredGraph};
pub use store::GraphStore;
pub use types::*;
#[cfg(feature = "vector")]
pub use vector::VectorIndex;
