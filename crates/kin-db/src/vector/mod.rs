// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod hnsw;

pub use hnsw::{IndexLoadOutcome, VectorIndex};
pub use kin_vector::IndexDescriptor;

/// Result of installing a persisted index into a graph via
/// [`crate::InMemoryGraph::load_vector_index_compatible`].
pub enum VectorIndexLoad {
    /// The on-disk index proved compatible and was installed; carries the count.
    Loaded(usize),
    /// The index was incompatible/unreadable and was NOT installed; carries the
    /// reason for the recovery notice. The graph's in-memory index is unchanged.
    Incompatible(String),
}
