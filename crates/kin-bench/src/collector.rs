// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::time::Instant;

use chrono::Utc;
use kin_model::entity::EntityKind;
use kin_model::graph::GraphStore;
use kin_model::relation::RelationKind;

use crate::error::{BenchError, Result};
use crate::metrics::*;

/// Collects benchmark metrics from the graph store.
pub struct MetricCollector;

impl MetricCollector {
    /// Measure dependency coverage: what fraction of entities have at least
    /// one outgoing DependsOn/Calls/Imports relation.
    pub fn collect_dependency_coverage<G: GraphStore>(store: &G) -> Result<DependencyCoverage> {
        let all_entities = store
            .list_all_entities()
            .map_err(|e| BenchError::Graph(e.to_string()))?;

        let total = all_entities.len() as u64;
        let mut with_deps = 0u64;

        for entity in &all_entities {
            let rels = store
                .get_relations(
                    &entity.id,
                    &[
                        RelationKind::DependsOn,
                        RelationKind::Calls,
                        RelationKind::Imports,
                    ],
                )
                .map_err(|e| BenchError::Graph(e.to_string()))?;

            if !rels.is_empty() {
                with_deps += 1;
            }
        }

        let coverage_pct = if total == 0 {
            0.0
        } else {
            (with_deps as f64 / total as f64) * 100.0
        };

        Ok(DependencyCoverage {
            total_entities: total,
            entities_with_deps: with_deps,
            coverage_pct,
        })
    }

    /// Measure dead code detection by querying the graph.
    pub fn collect_dead_code_stats<G: GraphStore>(store: &G) -> Result<DeadCodeAccuracy> {
        let dead = store
            .find_dead_code()
            .map_err(|e| BenchError::Graph(e.to_string()))?;

        Ok(DeadCodeAccuracy {
            detected_dead: dead.len() as u64,
            confirmed_dead: 0, // requires ground truth; placeholder
            false_positives: 0,
        })
    }

    /// Measure token savings: compare total entity count/complexity vs
    /// naive file token estimate.
    pub fn collect_token_savings<G: GraphStore>(
        store: &G,
        avg_tokens_per_file: u64,
        avg_tokens_per_entity: u64,
    ) -> Result<TokenSavings> {
        let all_entities = store
            .list_all_entities()
            .map_err(|e| BenchError::Graph(e.to_string()))?;

        // Count unique files
        let file_count = {
            let mut files = std::collections::HashSet::new();
            for e in &all_entities {
                if let Some(ref f) = e.file_origin {
                    files.insert(f.clone());
                }
            }
            files.len() as u64
        };

        let entity_count = all_entities.len() as u64;
        let naive_tokens = file_count * avg_tokens_per_file;
        let semantic_tokens = entity_count * avg_tokens_per_entity;

        let tokens_saved = naive_tokens.saturating_sub(semantic_tokens);
        let savings_pct = if naive_tokens == 0 {
            0.0
        } else {
            (tokens_saved as f64 / naive_tokens as f64) * 100.0
        };

        Ok(TokenSavings {
            naive_file_tokens: naive_tokens,
            semantic_tokens,
            tokens_saved,
            savings_pct,
        })
    }

    /// Measure token-to-logic ratio: tokens used per semantic entity.
    pub fn collect_token_to_logic_ratio<G: GraphStore>(
        store: &G,
        total_tokens: u64,
    ) -> Result<TokenToLogicRatio> {
        let all_entities = store
            .list_all_entities()
            .map_err(|e| BenchError::Graph(e.to_string()))?;

        let entity_count = all_entities.len() as u64;
        let ratio = if entity_count == 0 {
            0.0
        } else {
            total_tokens as f64 / entity_count as f64
        };

        Ok(TokenToLogicRatio {
            total_tokens,
            total_entities: entity_count,
            ratio,
        })
    }

    /// Count entities by kind — useful for dashboard summaries.
    pub fn count_entities_by_kind<G: GraphStore>(store: &G) -> Result<Vec<(EntityKind, u64)>> {
        let all_entities = store
            .list_all_entities()
            .map_err(|e| BenchError::Graph(e.to_string()))?;

        let mut counts = std::collections::HashMap::new();
        for e in &all_entities {
            *counts.entry(e.kind).or_insert(0u64) += 1;
        }

        let mut result: Vec<_> = counts.into_iter().collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(result)
    }

    /// Count test coverage: fraction of non-test entities that have a
    /// Tests relation pointing at them.
    pub fn collect_test_coverage<G: GraphStore>(store: &G) -> Result<DependencyCoverage> {
        let all_entities = store
            .list_all_entities()
            .map_err(|e| BenchError::Graph(e.to_string()))?;

        let non_test: Vec<_> = all_entities
            .iter()
            .filter(|e| e.kind != EntityKind::Test)
            .collect();

        let total = non_test.len() as u64;
        let mut covered = 0u64;

        for entity in &non_test {
            let rels = store
                .get_relations(&entity.id, &[RelationKind::Tests])
                .map_err(|e| BenchError::Graph(e.to_string()))?;

            if !rels.is_empty() {
                covered += 1;
            }
        }

        let coverage_pct = if total == 0 {
            0.0
        } else {
            (covered as f64 / total as f64) * 100.0
        };

        Ok(DependencyCoverage {
            total_entities: total,
            entities_with_deps: covered,
            coverage_pct,
        })
    }

    /// Time an operation and return a metric. This is a utility for
    /// wrapping any measurable operation.
    pub fn time_operation<F, T>(name: &str, category: MetricCategory, f: F) -> (T, Metric)
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();

        let metric = Metric {
            name: name.to_string(),
            category,
            value: MetricValue::Duration(DurationMs::from_std(elapsed)),
            unit: "ms".to_string(),
            timestamp: Utc::now(),
            labels: vec![],
        };

        (result, metric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_operation_captures_duration() {
        let (result, metric) =
            MetricCollector::time_operation("test_op", MetricCategory::DeveloperVelocity, || 42);
        assert_eq!(result, 42);
        assert_eq!(metric.name, "test_op");
        assert_eq!(metric.category, MetricCategory::DeveloperVelocity);
        assert_eq!(metric.unit, "ms");
    }
}
