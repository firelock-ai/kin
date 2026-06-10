// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Full graph statistics for observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    /// Entity counts keyed by EntityKind debug name (e.g. "Function", "Class").
    pub entity_counts: HashMap<String, usize>,
    /// Relation counts keyed by RelationKind debug name (e.g. "Calls", "Imports").
    pub relation_counts: HashMap<String, usize>,
    /// Parse completeness counts keyed by layout completeness bucket.
    pub parse_completeness_counts: HashMap<String, usize>,
    /// Number of shallow-tracked files (C2 tier).
    pub shallow_file_count: usize,
    /// Number of structured artifacts (C1 tier).
    pub structured_artifact_count: usize,
    /// Number of opaque artifacts (C0 tier).
    pub opaque_artifact_count: usize,
    /// Number of persisted file layouts.
    pub file_layout_count: usize,
    /// Number of file content hashes recorded.
    pub file_hash_count: usize,
    /// Number of entities currently visible in the committed text index.
    pub text_indexed_entity_count: usize,
    /// Text index coverage relative to total entities.
    pub text_index_coverage_percent: f64,
    /// Number of entities currently present in the vector index.
    pub indexed_embedding_count: usize,
    /// Number of entities queued for embedding but not yet indexed.
    pub pending_embedding_count: usize,
    /// Embedding coverage relative to total entities.
    pub embedding_coverage_percent: f64,
    /// Number of work items.
    pub work_item_count: usize,
    /// Number of test cases.
    pub test_case_count: usize,
    /// Number of reviews.
    pub review_count: usize,
    /// Number of agent sessions.
    pub session_count: usize,
    /// Total entity count across all kinds.
    pub total_entities: usize,
    /// Total relation count across all kinds.
    pub total_relations: usize,
    /// Entity counts keyed by EntityRole debug name (e.g. "Source", "Test").
    #[serde(default)]
    pub role_counts: HashMap<String, usize>,
}
