// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod graph;
pub mod incremental;
mod index;
mod traverse;

#[cfg(feature = "vector")]
pub use graph::VectorSalvageStats;
pub use graph::{
    EmbeddingStatus, EnrichmentContextStatus, EnrichmentStatusError, EnrichmentStatusFacts,
    FileEnrichmentStatus, InMemoryGraph, PersistenceEpoch, ProducedSemanticSearch,
    ProducedSemanticSearchBatch, ResolvedRetrievalItem, SourceDerivationFacts,
    SourceDerivationLimit, SourceDerivationLimits, SourceDerivationUnavailable,
    SourceEntityBinding, SourceLayoutFact, SourceOpaqueFact, SourceReservedRelation,
};
pub use incremental::{compute_diff, IncrementalDiff};
