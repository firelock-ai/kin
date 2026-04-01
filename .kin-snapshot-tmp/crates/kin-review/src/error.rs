// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::ids::SemanticChangeId;

/// Errors that can occur during semantic review.
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("semantic change not found: {0}")]
    ChangeNotFound(SemanticChangeId),

    #[error("entity not found: {0}")]
    EntityNotFound(kin_model::ids::EntityId),

    #[error("graph store error: {0}")]
    GraphStore(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("no changes between base and head")]
    NoChanges,

    #[error("review error: {0}")]
    Other(String),
}

impl ReviewError {
    /// Wrap an arbitrary graph store error.
    pub fn graph<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        ReviewError::GraphStore(Box::new(err))
    }
}
