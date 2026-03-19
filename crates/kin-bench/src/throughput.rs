//! Throughput benchmarks for graph operations.
//!
//! Measures operations-per-second for common graph queries.

use std::time::Instant;

use kin_model::graph::EntityFilter;
use kin_model::GraphStore;

use crate::error::{BenchError, Result};
use crate::metrics::ThroughputMetric;

/// Run a throughput benchmark for entity lookup by ID.
///
/// Retrieves a sample of entity IDs, then repeatedly looks them up for
/// `iterations` total lookups, cycling through the sample.
pub fn bench_entity_lookup<G: GraphStore>(graph: &G, iterations: usize) -> Result<ThroughputMetric> {
    let entities = graph
        .list_all_entities()
        .map_err(|e| BenchError::Graph(e.to_string()))?;

    if entities.is_empty() {
        return Ok(ThroughputMetric {
            ops_per_sec: 0.0,
            total_duration_ms: 0.0,
            iterations: 0,
            operation: "entity_lookup".into(),
        });
    }

    let ids: Vec<_> = entities.iter().map(|e| e.id).collect();
    let start = Instant::now();
    for i in 0..iterations {
        let id = &ids[i % ids.len()];
        let _ = graph
            .get_entity(id)
            .map_err(|e| BenchError::Graph(e.to_string()))?;
    }
    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    Ok(ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: "entity_lookup".into(),
    })
}

/// Run a throughput benchmark for entity query by name pattern.
///
/// Queries entities with various name prefixes for `iterations` total queries.
pub fn bench_query_by_name<G: GraphStore>(
    graph: &G,
    iterations: usize,
) -> Result<ThroughputMetric> {
    let patterns = ["a", "b", "c", "get", "set", "new", "fn", "test", "main"];
    let start = Instant::now();
    for i in 0..iterations {
        let pattern = patterns[i % patterns.len()];
        let filter = EntityFilter {
            name_pattern: Some(pattern.to_string()),
            ..Default::default()
        };
        let _ = graph
            .query_entities(&filter)
            .map_err(|e| BenchError::Graph(e.to_string()))?;
    }
    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    Ok(ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: "query_by_name".into(),
    })
}

/// Run a throughput benchmark for downstream impact traversal.
///
/// Retrieves entity IDs and repeatedly calls `get_downstream_impact`.
pub fn bench_downstream_impact<G: GraphStore>(
    graph: &G,
    iterations: usize,
) -> Result<ThroughputMetric> {
    let entities = graph
        .list_all_entities()
        .map_err(|e| BenchError::Graph(e.to_string()))?;

    if entities.is_empty() {
        return Ok(ThroughputMetric {
            ops_per_sec: 0.0,
            total_duration_ms: 0.0,
            iterations: 0,
            operation: "downstream_impact".into(),
        });
    }

    let ids: Vec<_> = entities.iter().map(|e| e.id).collect();
    let start = Instant::now();
    for i in 0..iterations {
        let id = &ids[i % ids.len()];
        let _ = graph
            .get_downstream_impact(id, 3)
            .map_err(|e| BenchError::Graph(e.to_string()))?;
    }
    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    Ok(ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: "downstream_impact".into(),
    })
}

/// Run a throughput benchmark for dependency neighborhood queries.
///
/// Retrieves entity IDs and repeatedly calls `get_dependency_neighborhood`.
pub fn bench_dependency_neighborhood<G: GraphStore>(
    graph: &G,
    iterations: usize,
) -> Result<ThroughputMetric> {
    let entities = graph
        .list_all_entities()
        .map_err(|e| BenchError::Graph(e.to_string()))?;

    if entities.is_empty() {
        return Ok(ThroughputMetric {
            ops_per_sec: 0.0,
            total_duration_ms: 0.0,
            iterations: 0,
            operation: "dependency_neighborhood".into(),
        });
    }

    let ids: Vec<_> = entities.iter().map(|e| e.id).collect();
    let start = Instant::now();
    for i in 0..iterations {
        let id = &ids[i % ids.len()];
        let _ = graph
            .get_dependency_neighborhood(id, 2)
            .map_err(|e| BenchError::Graph(e.to_string()))?;
    }
    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    Ok(ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: "dependency_neighborhood".into(),
    })
}

/// Run all throughput benchmarks and return results.
pub fn bench_all_throughput<G: GraphStore>(
    graph: &G,
    iterations_per_op: usize,
) -> Result<Vec<ThroughputMetric>> {
    Ok(vec![
        bench_entity_lookup(graph, iterations_per_op)?,
        bench_query_by_name(graph, iterations_per_op)?,
        bench_downstream_impact(graph, iterations_per_op)?,
        bench_dependency_neighborhood(graph, iterations_per_op)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throughput_metric_ops_per_sec_calculation() {
        // If 1000 iterations took 500ms, that's 2000 ops/sec
        let m = ThroughputMetric {
            ops_per_sec: 2000.0,
            total_duration_ms: 500.0,
            iterations: 1000,
            operation: "test_op".into(),
        };
        assert!((m.ops_per_sec - 2000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn throughput_metric_serialization() {
        let m = ThroughputMetric {
            ops_per_sec: 1500.5,
            total_duration_ms: 666.0,
            iterations: 1000,
            operation: "entity_lookup".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation, "entity_lookup");
        assert_eq!(parsed.iterations, 1000);
    }
}
