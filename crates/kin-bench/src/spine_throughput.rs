// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Performance benchmarks for kin-spine at scale (100+ repos).
//!
//! Measures operations-per-second and latency percentiles for spine
//! operations with synthetic multi-repo workloads. Designed to validate
//! that the federation layer scales to large organizations.

use std::time::Instant;

use kin_model::{EntityId, EntityKind, FingerprintAlgorithm, Hash256, SemanticFingerprint};
use kin_spine::{
    federated_impact, CrossRepoEdge, EntityEntry, RepoEndpoint, RoutingTable, SpineIndex,
};

use crate::metrics::{LatencyPercentiles, MemoryMetric, ThroughputMetric};

/// Scale tier for benchmark workloads.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum SpineScale {
    /// 10 repos, ~50 entities each — baseline for unit-test-level runs.
    Small,
    /// 100 repos, ~100 entities each — target for CI.
    Medium,
    /// 250 repos, ~200 entities each — production-scale stress test.
    Large,
    /// 500 repos, ~500 entities each — extreme-scale validation.
    ExtraLarge,
}

impl SpineScale {
    pub fn repo_count(&self) -> usize {
        match self {
            SpineScale::Small => 10,
            SpineScale::Medium => 100,
            SpineScale::Large => 250,
            SpineScale::ExtraLarge => 500,
        }
    }

    pub fn entities_per_repo(&self) -> usize {
        match self {
            SpineScale::Small => 50,
            SpineScale::Medium => 100,
            SpineScale::Large => 200,
            SpineScale::ExtraLarge => 500,
        }
    }

    /// Cross-repo edges as fraction of total entities (realistic density).
    pub fn edge_density(&self) -> f64 {
        match self {
            SpineScale::Small => 0.05,
            SpineScale::Medium => 0.03,
            SpineScale::Large => 0.02,
            SpineScale::ExtraLarge => 0.015,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SpineScale::Small => "small_10",
            SpineScale::Medium => "medium_100",
            SpineScale::Large => "large_250",
            SpineScale::ExtraLarge => "xlarge_500",
        }
    }
}

/// Full result of a spine scale benchmark run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpineBenchmarkResult {
    pub scale: String,
    pub repo_count: usize,
    pub total_entities: usize,
    pub total_edges: usize,
    pub registration: ThroughputMetric,
    pub resolve_by_name: ThroughputMetric,
    pub resolve_with_fingerprint: ThroughputMetric,
    pub edge_lookup: ThroughputMetric,
    pub federated_bfs: ThroughputMetric,
    pub routing_lookup: ThroughputMetric,
    pub registration_latency: Option<LatencyPercentiles>,
    pub resolve_latency: Option<LatencyPercentiles>,
    pub bfs_latency: Option<LatencyPercentiles>,
    pub memory_after_load: Option<MemoryMetric>,
}

// ---------------------------------------------------------------------------
// Synthetic data generation
// ---------------------------------------------------------------------------

static ENTITY_KINDS: &[EntityKind] = &[
    EntityKind::Function,
    EntityKind::Class,
    EntityKind::Interface,
    EntityKind::TraitDef,
    EntityKind::Module,
    EntityKind::Method,
    EntityKind::EnumDef,
    EntityKind::Constant,
];

fn synthetic_fingerprint(seed: u64) -> SemanticFingerprint {
    let mut ast = [0u8; 32];
    let mut sig = [0u8; 32];
    let mut beh = [0u8; 32];
    let bytes = seed.to_le_bytes();
    ast[..8].copy_from_slice(&bytes);
    sig[..8].copy_from_slice(&(seed.wrapping_mul(31)).to_le_bytes());
    beh[..8].copy_from_slice(&(seed.wrapping_mul(97)).to_le_bytes());
    SemanticFingerprint {
        ast_hash: Hash256::from_bytes(ast),
        signature_hash: Hash256::from_bytes(sig),
        behavior_hash: Hash256::from_bytes(beh),
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        stability_score: 1.0,
    }
}

fn synthetic_entry(repo: &str, entity_index: usize) -> EntityEntry {
    let kind = ENTITY_KINDS[entity_index % ENTITY_KINDS.len()];
    let name = format!("entity_{entity_index}");
    EntityEntry {
        repo_id: repo.to_string(),
        entity_id: EntityId::new(),
        name,
        kind,
        signature: format!("fn entity_{entity_index}()"),
        fingerprint: synthetic_fingerprint(entity_index as u64),
        file_path: Some(format!("src/mod_{}.rs", entity_index / 10)),
    }
}

/// Names that appear in multiple repos, simulating common patterns
/// like Config, Error, init, parse, etc.
static COMMON_NAMES: &[&str] = &[
    "Config", "Error", "init", "parse", "new", "run", "build",
    "validate", "process", "handle", "create", "delete", "update",
    "get", "set", "list", "find", "search", "connect", "close",
];

fn synthetic_common_entry(repo: &str, common_index: usize) -> EntityEntry {
    let name = COMMON_NAMES[common_index % COMMON_NAMES.len()];
    let kind = if common_index % 3 == 0 {
        EntityKind::Class
    } else {
        EntityKind::Function
    };
    EntityEntry {
        repo_id: repo.to_string(),
        entity_id: EntityId::new(),
        name: name.to_string(),
        kind,
        signature: format!("fn {name}()"),
        fingerprint: synthetic_fingerprint((common_index as u64).wrapping_mul(7919)),
        file_path: Some("src/lib.rs".to_string()),
    }
}

/// Build a populated SpineIndex at the given scale.
/// Returns the index, a flat vec of all entries, and the cross-repo edges added.
fn build_spine_at_scale(
    scale: SpineScale,
) -> (SpineIndex, Vec<EntityEntry>, Vec<CrossRepoEdge>) {
    let index = SpineIndex::new();
    let repo_count = scale.repo_count();
    let per_repo = scale.entities_per_repo();
    let mut all_entries: Vec<EntityEntry> = Vec::with_capacity(repo_count * per_repo);

    for r in 0..repo_count {
        let repo_name = format!("repo-{r:04}");
        let mut entries: Vec<EntityEntry> = Vec::with_capacity(per_repo);

        // Most entities are unique to this repo
        let unique_count = per_repo.saturating_sub(COMMON_NAMES.len());
        for e in 0..unique_count {
            entries.push(synthetic_entry(&repo_name, r * 10000 + e));
        }

        // Add common-name entities (Config, Error, etc.) to every repo
        for c in 0..COMMON_NAMES.len().min(per_repo) {
            entries.push(synthetic_common_entry(&repo_name, c));
        }

        all_entries.extend(entries.clone());
        index.register_repo(&repo_name, entries, &format!("hash-{r:04}"));
    }

    // Add cross-repo edges at the configured density
    let total_entities = all_entries.len();
    let edge_count = (total_entities as f64 * scale.edge_density()) as usize;
    let mut edges = Vec::with_capacity(edge_count);

    // Deterministic pseudo-random edge generation using linear congruential generator
    let mut lcg_state: u64 = 42;
    let lcg_step = |state: &mut u64| -> usize {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*state >> 16) as usize
    };

    for _ in 0..edge_count {
        let src_idx = lcg_step(&mut lcg_state) % total_entities;
        let dst_idx = lcg_step(&mut lcg_state) % total_entities;
        if all_entries[src_idx].repo_id == all_entries[dst_idx].repo_id {
            continue; // skip intra-repo edges
        }
        let edge = CrossRepoEdge {
            src_repo: all_entries[src_idx].repo_id.clone(),
            src_entity: all_entries[src_idx].entity_id,
            dst_repo: all_entries[dst_idx].repo_id.clone(),
            dst_entity: all_entries[dst_idx].entity_id,
            confidence: 0.85,
        };
        edges.push(edge.clone());
        index.add_cross_repo_edge(edge);
    }

    (index, all_entries, edges)
}

// ---------------------------------------------------------------------------
// Individual benchmark functions
// ---------------------------------------------------------------------------

/// Benchmark: register_repo throughput (measures index ingestion speed).
pub fn bench_spine_registration(scale: SpineScale, iterations: usize) -> ThroughputMetric {
    let per_repo = scale.entities_per_repo();
    let start = Instant::now();

    for i in 0..iterations {
        let index = SpineIndex::new();
        let repo_name = format!("bench-repo-{i}");
        let entries: Vec<EntityEntry> = (0..per_repo)
            .map(|e| synthetic_entry(&repo_name, i * 10000 + e))
            .collect();
        index.register_repo(&repo_name, entries, &format!("hash-{i}"));
    }

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: format!("spine_register_repo_{}", scale.label()),
    }
}

/// Benchmark: resolve by name across 100+ repos.
pub fn bench_spine_resolve_by_name(
    index: &SpineIndex,
    scale: SpineScale,
    iterations: usize,
) -> ThroughputMetric {
    let start = Instant::now();

    for i in 0..iterations {
        let name = COMMON_NAMES[i % COMMON_NAMES.len()];
        let kind = if i % 3 == 0 {
            Some(EntityKind::Class)
        } else {
            Some(EntityKind::Function)
        };
        let _ = index.resolve(name, kind, None);
    }

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: format!("spine_resolve_name_{}", scale.label()),
    }
}

/// Benchmark: resolve with fingerprint disambiguation.
pub fn bench_spine_resolve_with_fingerprint(
    index: &SpineIndex,
    scale: SpineScale,
    iterations: usize,
) -> ThroughputMetric {
    let start = Instant::now();

    for i in 0..iterations {
        let name = COMMON_NAMES[i % COMMON_NAMES.len()];
        let fp = synthetic_fingerprint(i as u64);
        let _ = index.resolve(name, Some(EntityKind::Function), Some(&fp));
    }

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: format!("spine_resolve_fingerprint_{}", scale.label()),
    }
}

/// Benchmark: cross_repo_edges_for lookup at scale.
pub fn bench_spine_edge_lookup(
    index: &SpineIndex,
    entries: &[EntityEntry],
    scale: SpineScale,
    iterations: usize,
) -> ThroughputMetric {
    if entries.is_empty() {
        return ThroughputMetric {
            ops_per_sec: 0.0,
            total_duration_ms: 0.0,
            iterations: 0,
            operation: format!("spine_edge_lookup_{}", scale.label()),
        };
    }

    let start = Instant::now();

    for i in 0..iterations {
        let entry = &entries[i % entries.len()];
        let _ = index.cross_repo_edges_for(&entry.repo_id, &entry.entity_id);
    }

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: format!("spine_edge_lookup_{}", scale.label()),
    }
}

/// Benchmark: federated_impact BFS traversal at scale.
pub fn bench_spine_federated_bfs(
    index: &SpineIndex,
    entries: &[EntityEntry],
    scale: SpineScale,
    iterations: usize,
    max_depth: u32,
) -> ThroughputMetric {
    if entries.is_empty() {
        return ThroughputMetric {
            ops_per_sec: 0.0,
            total_duration_ms: 0.0,
            iterations: 0,
            operation: format!("spine_federated_bfs_{}", scale.label()),
        };
    }

    let start = Instant::now();

    for i in 0..iterations {
        let entry = &entries[i % entries.len()];
        let _ = federated_impact(index, &entry.repo_id, &entry.entity_id, max_depth);
    }

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: format!("spine_federated_bfs_{}", scale.label()),
    }
}

/// Benchmark: routing table lookup at scale.
pub fn bench_spine_routing(
    scale: SpineScale,
    iterations: usize,
) -> ThroughputMetric {
    let repo_count = scale.repo_count();
    let endpoint_count = (repo_count / 10).max(1);
    let table = RoutingTable::new();

    // Distribute repos across endpoints
    for ep in 0..endpoint_count {
        let repos: Vec<String> = (0..repo_count)
            .filter(|r| r % endpoint_count == ep)
            .map(|r| format!("repo-{r:04}"))
            .collect();
        table.register_endpoint(RepoEndpoint {
            url: format!("http://daemon-{ep}:4219"),
            repos,
            healthy: true,
            last_check: None,
        });
    }

    let start = Instant::now();

    for i in 0..iterations {
        let repo_id = format!("repo-{:04}", i % repo_count);
        let _ = table.route(&repo_id);
    }

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    ThroughputMetric {
        ops_per_sec: if duration_ms > 0.0 {
            iterations as f64 / (duration_ms / 1000.0)
        } else {
            0.0
        },
        total_duration_ms: duration_ms,
        iterations,
        operation: format!("spine_routing_{}", scale.label()),
    }
}

// ---------------------------------------------------------------------------
// Latency percentile collection
// ---------------------------------------------------------------------------

/// Collect per-operation latency samples for registration.
pub fn collect_registration_latencies(scale: SpineScale, samples: usize) -> Option<LatencyPercentiles> {
    let per_repo = scale.entities_per_repo();
    let mut durations = Vec::with_capacity(samples);

    for i in 0..samples {
        let index = SpineIndex::new();
        let repo_name = format!("lat-repo-{i}");
        let entries: Vec<EntityEntry> = (0..per_repo)
            .map(|e| synthetic_entry(&repo_name, i * 10000 + e))
            .collect();

        let t0 = Instant::now();
        index.register_repo(&repo_name, entries, &format!("hash-{i}"));
        durations.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    LatencyPercentiles::from_samples(&durations)
}

/// Collect per-operation latency samples for resolve.
pub fn collect_resolve_latencies(
    index: &SpineIndex,
    samples: usize,
) -> Option<LatencyPercentiles> {
    let mut durations = Vec::with_capacity(samples);

    for i in 0..samples {
        let name = COMMON_NAMES[i % COMMON_NAMES.len()];
        let fp = synthetic_fingerprint(i as u64);

        let t0 = Instant::now();
        let _ = index.resolve(name, Some(EntityKind::Function), Some(&fp));
        durations.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    LatencyPercentiles::from_samples(&durations)
}

/// Collect per-operation latency samples for federated BFS.
pub fn collect_bfs_latencies(
    index: &SpineIndex,
    entries: &[EntityEntry],
    max_depth: u32,
    samples: usize,
) -> Option<LatencyPercentiles> {
    if entries.is_empty() {
        return None;
    }

    let mut durations = Vec::with_capacity(samples);

    for i in 0..samples {
        let entry = &entries[i % entries.len()];
        let t0 = Instant::now();
        let _ = federated_impact(index, &entry.repo_id, &entry.entity_id, max_depth);
        durations.push(t0.elapsed().as_secs_f64() * 1000.0);
    }

    LatencyPercentiles::from_samples(&durations)
}

// ---------------------------------------------------------------------------
// Full benchmark suite
// ---------------------------------------------------------------------------

/// Run the complete spine benchmark suite at a given scale.
///
/// Default iterations: 1000 for throughput, 200 for latency percentiles.
pub fn bench_spine_at_scale(
    scale: SpineScale,
    iterations: usize,
) -> SpineBenchmarkResult {
    let latency_samples = (iterations / 5).max(50);

    // Build the spine and measure memory
    let rss_before = MemoryMetric::current_rss_kb();
    let (index, entries, edges) = build_spine_at_scale(scale);
    let rss_after = MemoryMetric::current_rss_kb();

    let memory = Some(MemoryMetric {
        rss_before_kb: rss_before,
        rss_after_kb: rss_after,
        rss_delta_kb: rss_after as i64 - rss_before as i64,
        peak_kb: rss_after,
    });

    // Throughput benchmarks
    let registration = bench_spine_registration(scale, iterations);
    let resolve_by_name = bench_spine_resolve_by_name(&index, scale, iterations);
    let resolve_with_fingerprint =
        bench_spine_resolve_with_fingerprint(&index, scale, iterations);
    let edge_lookup = bench_spine_edge_lookup(&index, &entries, scale, iterations);
    let federated_bfs = bench_spine_federated_bfs(&index, &entries, scale, iterations, 5);
    let routing_lookup = bench_spine_routing(scale, iterations);

    // Latency percentiles
    let registration_latency = collect_registration_latencies(scale, latency_samples);
    let resolve_latency = collect_resolve_latencies(&index, latency_samples);
    let bfs_latency = collect_bfs_latencies(&index, &entries, 5, latency_samples);

    SpineBenchmarkResult {
        scale: scale.label().to_string(),
        repo_count: index.repo_count(),
        total_entities: index.entity_count(),
        total_edges: index.edge_count(),
        registration,
        resolve_by_name,
        resolve_with_fingerprint,
        edge_lookup,
        federated_bfs,
        routing_lookup,
        registration_latency,
        resolve_latency,
        bfs_latency,
        memory_after_load: memory,
    }
}

/// Run spine benchmarks at all scales. Returns results indexed by scale label.
pub fn bench_spine_all_scales(iterations_per_scale: usize) -> Vec<SpineBenchmarkResult> {
    vec![
        bench_spine_at_scale(SpineScale::Small, iterations_per_scale),
        bench_spine_at_scale(SpineScale::Medium, iterations_per_scale),
        bench_spine_at_scale(SpineScale::Large, iterations_per_scale),
        bench_spine_at_scale(SpineScale::ExtraLarge, iterations_per_scale),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_spine_small_scale() {
        let (index, entries, edges) = build_spine_at_scale(SpineScale::Small);
        assert_eq!(index.repo_count(), 10);
        assert!(index.entity_count() > 0);
        assert!(!entries.is_empty());
        // Small scale: 10 repos × 50 entities = 500 entities, 5% density → ~25 edges
        assert!(
            edges.len() > 0,
            "should have cross-repo edges at small scale"
        );
    }

    #[test]
    fn build_spine_medium_scale() {
        let (index, entries, _edges) = build_spine_at_scale(SpineScale::Medium);
        assert_eq!(index.repo_count(), 100);
        // 100 repos × 100 entities = 10,000 total entities
        assert!(
            index.entity_count() >= 9_000,
            "medium scale should have ~10k entities, got {}",
            index.entity_count()
        );
        assert!(entries.len() >= 9_000);
    }

    #[test]
    fn spine_registration_throughput() {
        let result = bench_spine_registration(SpineScale::Small, 100);
        assert_eq!(result.iterations, 100);
        assert!(result.ops_per_sec > 0.0);
        assert!(result.total_duration_ms > 0.0);
    }

    #[test]
    fn spine_resolve_throughput() {
        let (index, _, _) = build_spine_at_scale(SpineScale::Small);
        let result = bench_spine_resolve_by_name(&index, SpineScale::Small, 100);
        assert_eq!(result.iterations, 100);
        assert!(result.ops_per_sec > 0.0);
    }

    #[test]
    fn spine_resolve_with_fingerprint_throughput() {
        let (index, _, _) = build_spine_at_scale(SpineScale::Small);
        let result = bench_spine_resolve_with_fingerprint(&index, SpineScale::Small, 100);
        assert_eq!(result.iterations, 100);
        assert!(result.ops_per_sec > 0.0);
    }

    #[test]
    fn spine_edge_lookup_throughput() {
        let (index, entries, _) = build_spine_at_scale(SpineScale::Small);
        let result = bench_spine_edge_lookup(&index, &entries, SpineScale::Small, 100);
        assert_eq!(result.iterations, 100);
        assert!(result.ops_per_sec > 0.0);
    }

    #[test]
    fn spine_federated_bfs_throughput() {
        let (index, entries, _) = build_spine_at_scale(SpineScale::Small);
        let result = bench_spine_federated_bfs(&index, &entries, SpineScale::Small, 50, 3);
        assert_eq!(result.iterations, 50);
        assert!(result.ops_per_sec > 0.0);
    }

    #[test]
    fn spine_routing_throughput() {
        let result = bench_spine_routing(SpineScale::Medium, 1000);
        assert_eq!(result.iterations, 1000);
        assert!(result.ops_per_sec > 0.0);
    }

    #[test]
    fn spine_latency_percentiles_registration() {
        let p = collect_registration_latencies(SpineScale::Small, 20).unwrap();
        assert_eq!(p.count, 20);
        assert!(p.p50 > 0.0);
        assert!(p.p99 >= p.p50);
    }

    #[test]
    fn spine_latency_percentiles_resolve() {
        let (index, _, _) = build_spine_at_scale(SpineScale::Small);
        let p = collect_resolve_latencies(&index, 20).unwrap();
        assert_eq!(p.count, 20);
        assert!(p.p99 >= p.p50);
    }

    #[test]
    fn spine_latency_percentiles_bfs() {
        let (index, entries, _) = build_spine_at_scale(SpineScale::Small);
        let p = collect_bfs_latencies(&index, &entries, 3, 20).unwrap();
        assert_eq!(p.count, 20);
        assert!(p.p99 >= p.p50);
    }

    #[test]
    fn full_benchmark_suite_small() {
        let result = bench_spine_at_scale(SpineScale::Small, 50);
        assert_eq!(result.repo_count, 10);
        assert!(result.total_entities > 0);
        assert!(result.registration.ops_per_sec > 0.0);
        assert!(result.resolve_by_name.ops_per_sec > 0.0);
        assert!(result.federated_bfs.ops_per_sec > 0.0);
        assert!(result.routing_lookup.ops_per_sec > 0.0);
        assert!(result.registration_latency.is_some());
        assert!(result.resolve_latency.is_some());
        assert!(result.bfs_latency.is_some());
        assert!(result.memory_after_load.is_some());
    }

    #[test]
    fn full_benchmark_at_100_repos() {
        // The core target: 100+ repos
        let result = bench_spine_at_scale(SpineScale::Medium, 100);
        assert!(
            result.repo_count >= 100,
            "medium scale must be 100+ repos, got {}",
            result.repo_count
        );
        assert!(
            result.total_entities >= 9_000,
            "should have ~10k entities at 100 repos"
        );
        assert!(
            result.total_edges > 0,
            "should have cross-repo edges"
        );

        // Sanity: operations should be fast enough to complete
        assert!(result.registration.total_duration_ms < 30_000.0);
        assert!(result.resolve_by_name.total_duration_ms < 30_000.0);
        assert!(result.federated_bfs.total_duration_ms < 30_000.0);
    }

    #[test]
    fn common_name_disambiguation_at_scale() {
        // Verify that resolving "Config" across 100 repos returns all repos
        let (index, _, _) = build_spine_at_scale(SpineScale::Medium);
        let results = index.resolve("Config", Some(EntityKind::Class), None);

        // Every repo registers a "Config" class
        assert!(
            results.len() >= 90,
            "Config should resolve across most repos, got {} matches",
            results.len()
        );

        // Verify fingerprint disambiguation narrows results
        let fp = synthetic_fingerprint(0); // matches common_index=0 pattern
        let ranked = index.resolve("Config", Some(EntityKind::Class), Some(&fp));
        assert_eq!(ranked.len(), results.len()); // same count, different order
    }

    #[test]
    fn serialization_roundtrip() {
        let result = bench_spine_at_scale(SpineScale::Small, 10);
        let json = serde_json::to_string_pretty(&result).unwrap();
        let parsed: SpineBenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scale, result.scale);
        assert_eq!(parsed.repo_count, result.repo_count);
        assert_eq!(parsed.total_entities, result.total_entities);
    }
}
