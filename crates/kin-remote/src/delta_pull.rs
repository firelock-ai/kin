// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Delta pull mechanism: fetches semantic deltas from the remote.
//!
//! The `DeltaPuller` trait defines the interface for pulling changes from
//! KinLab. Implementations can use REST, gRPC, or any other transport.
//! Pulling the same delta twice is idempotent — the same result is returned
//! without side effects.

use crate::sync_types::SemanticDelta;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PullError {
    #[error("entity not found: {0}")]
    EntityNotFound(String),
    #[error("remote unavailable: {0}")]
    RemoteUnavailable(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

// ---------------------------------------------------------------------------
// DeltaPuller trait
// ---------------------------------------------------------------------------

/// Trait for pulling semantic deltas from a remote. Implementations should be
/// idempotent: pulling the same delta twice returns the same result.
pub trait DeltaPuller: Send + Sync {
    /// Fetch the full semantic delta for a specific entity.
    fn pull_delta(&self, entity_id: &str) -> Result<SemanticDelta, PullError>;

    /// Batch pull all deltas since a given timestamp.
    fn pull_deltas_since(&self, since: DateTime<Utc>) -> Result<Vec<SemanticDelta>, PullError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation (for testing and local development)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct InMemoryDeltaPuller {
    deltas: HashMap<String, SemanticDelta>,
}

impl InMemoryDeltaPuller {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a delta for testing.
    pub fn insert(&mut self, delta: SemanticDelta) {
        self.deltas.insert(delta.entity_id.clone(), delta);
    }

    /// Remove a delta (for testing).
    pub fn remove(&mut self, entity_id: &str) -> Option<SemanticDelta> {
        self.deltas.remove(entity_id)
    }

    pub fn len(&self) -> usize {
        self.deltas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
    }
}

impl DeltaPuller for InMemoryDeltaPuller {
    fn pull_delta(&self, entity_id: &str) -> Result<SemanticDelta, PullError> {
        self.deltas
            .get(entity_id)
            .cloned()
            .ok_or_else(|| PullError::EntityNotFound(entity_id.to_owned()))
    }

    fn pull_deltas_since(&self, since: DateTime<Utc>) -> Result<Vec<SemanticDelta>, PullError> {
        let mut results: Vec<SemanticDelta> = self
            .deltas
            .values()
            .filter(|d| d.timestamp > since)
            .cloned()
            .collect();
        results.sort_by_key(|d| d.timestamp);
        Ok(results)
    }
}
