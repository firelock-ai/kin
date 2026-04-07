// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Scale benchmarks for kin-db at 100K, 500K, and 1M entities.
//!
//! Run with: `cargo test -p kin-db --test scale_bench -- --ignored --nocapture`
//!
//! These are integration tests marked `#[ignore]` so they don't run in CI.
//! Each test generates a synthetic graph, measures key operations, and prints results.

use std::time::Instant;

use kin_db::InMemoryGraph;
use kin_model::{
    entity::*, graph::EntityFilter, graph::EntityStore, ids::*, relation::*, Hash256,
    SemanticFingerprint,
};

fn test_fingerprint() -> SemanticFingerprint {
    SemanticFingerprint {
        ast_hash: Hash256::from_bytes([0; 32]),
        signature_hash: Hash256::from_bytes([0; 32]),
        behavior_hash: Hash256::from_bytes([0; 32]),
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        stability_score: 1.0,
    }
}

/// Generate a synthetic graph with `n` entities and `rels_per_entity` outgoing relations.
///
/// Builds a GraphSnapshot directly (no locking) then hydrates via from_snapshot().
/// This is ~100x faster than calling upsert_entity/upsert_relation one at a time,
/// and matches how real graphs are loaded (deserialize → from_snapshot).
fn generate_graph(n: usize, rels_per_entity: usize) -> InMemoryGraph {
    use std::collections::HashMap;

    // Build entities in a plain HashMap (no locking, no indexing overhead)
    let mut entities = HashMap::with_capacity(n);
    let mut entity_ids = Vec::with_capacity(n);

    for i in 0..n {
        let id = EntityId::new();
        entities.insert(
            id,
            Entity {
                id,
                kind: match i % 5 {
                    0 => EntityKind::Function,
                    1 => EntityKind::Class,
                    2 => EntityKind::Method,
                    3 => EntityKind::Interface,
                    _ => EntityKind::Module,
                },
                name: format!("entity_{i}"),
                language: LanguageId::Rust,
                fingerprint: test_fingerprint(),
                file_origin: Some(FilePathId::new(format!("src/mod_{}.rs", i / 50))),
                span: Some(SourceSpan {
                    file: FilePathId::new(format!("src/mod_{}.rs", i / 50)),
                    start_byte: (i % 50) * 200,
                    end_byte: (i % 50) * 200 + 180,
                    start_line: (i % 50) as u32 * 10,
                    start_col: 0,
                    end_line: (i % 50) as u32 * 10 + 9,
                    end_col: 0,
                }),
                signature: format!("fn entity_{i}() -> Result<()>"),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            },
        );
        entity_ids.push(id);
    }

    // Build relations in a plain HashMap
    let mut relations = HashMap::with_capacity(n * rels_per_entity);
    let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::with_capacity(n);
    let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::with_capacity(n);

    for (i, src_id) in entity_ids.iter().enumerate() {
        for r in 0..rels_per_entity {
            let dst_idx = (i * 7 + r * 13 + 1) % n;
            if dst_idx == i {
                continue;
            }
            let rel_id = RelationId::new();
            let dst_id = entity_ids[dst_idx];
            relations.insert(
                rel_id,
                Relation {
                    id: rel_id,
                    kind: match r % 3 {
                        0 => RelationKind::Calls,
                        1 => RelationKind::Imports,
                        _ => RelationKind::References,
                    },
                    src: GraphNodeId::Entity(*src_id),
                    dst: GraphNodeId::Entity(dst_id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                },
            );
            outgoing.entry(*src_id).or_default().push(rel_id);
            incoming.entry(dst_id).or_default().push(rel_id);
        }
    }

    // Build snapshot and hydrate — this builds indexes in one pass, no locking
    let snapshot = kin_db::GraphSnapshot {
        version: kin_db::GraphSnapshot::CURRENT_VERSION,
        entities,
        entity_revisions: HashMap::new(),
        relations,
        outgoing,
        incoming,
        changes: HashMap::new(),
        change_children: HashMap::new(),
        branches: HashMap::new(),
        work_items: HashMap::new(),
        annotations: HashMap::new(),
        work_links: Vec::new(),
        reviews: HashMap::new(),
        review_decisions: HashMap::new(),
        review_notes: Vec::new(),
        review_discussions: Vec::new(),
        review_assignments: HashMap::new(),
        test_cases: HashMap::new(),
        assertions: HashMap::new(),
        verification_runs: HashMap::new(),
        test_covers_entity: Vec::new(),
        test_covers_contract: Vec::new(),
        test_verifies_work: Vec::new(),
        run_proves_entity: Vec::new(),
        run_proves_work: Vec::new(),
        mock_hints: Vec::new(),
        contracts: HashMap::new(),
        actors: HashMap::new(),
        delegations: Vec::new(),
        approvals: Vec::new(),
        audit_events: Vec::new(),
        shallow_files: Vec::new(),
        file_layouts: Vec::new(),
        structured_artifacts: Vec::new(),
        opaque_artifacts: Vec::new(),
        file_hashes: HashMap::new(),
        sessions: HashMap::new(),
        intents: HashMap::new(),
        downstream_warnings: Vec::new(),
        entity_revisions: HashMap::new(),
    };

    InMemoryGraph::from_snapshot(snapshot)
}

fn bench_entity_lookup(graph: &InMemoryGraph, entity_ids: &[EntityId], label: &str) {
    let iterations = 10_000;
    let start = Instant::now();
    for i in 0..iterations {
        let id = &entity_ids[i % entity_ids.len()];
        let _ = graph.get_entity(id).unwrap();
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iterations as u32;
    println!("  {label} entity lookup: {per_op:?}/op ({iterations} iterations in {elapsed:?})");
}

fn bench_query_by_file(graph: &InMemoryGraph, label: &str) {
    let filter = EntityFilter {
        file_path: Some(FilePathId::new("src/mod_0.rs")),
        ..Default::default()
    };
    let start = Instant::now();
    let results = graph.query_entities(&filter).unwrap();
    let elapsed = start.elapsed();
    println!(
        "  {label} query by file: {elapsed:?} ({} entities returned)",
        results.len()
    );
}

fn bench_bfs_neighborhood(graph: &InMemoryGraph, start_id: &EntityId, label: &str) {
    let start = Instant::now();
    let subgraph = graph.get_dependency_neighborhood(start_id, 3).unwrap();
    let elapsed = start.elapsed();
    println!(
        "  {label} 3-hop BFS: {elapsed:?} ({} entities, {} relations)",
        subgraph.entities.len(),
        subgraph.relations.len()
    );
}

fn bench_impact(graph: &InMemoryGraph, start_id: &EntityId, label: &str) {
    let start = Instant::now();
    let impacted = graph.get_downstream_impact(start_id, 5).unwrap();
    let elapsed = start.elapsed();
    println!(
        "  {label} impact (depth 5): {elapsed:?} ({} impacted entities)",
        impacted.len()
    );
}

fn bench_dead_code(graph: &InMemoryGraph, label: &str) {
    let start = Instant::now();
    let dead = graph.find_dead_code().unwrap();
    let elapsed = start.elapsed();
    println!(
        "  {label} dead code detection: {elapsed:?} ({} dead entities)",
        dead.len()
    );
}

fn bench_serialization(graph: &InMemoryGraph, label: &str) {
    let start = Instant::now();
    let snapshot = graph.to_snapshot();
    let ser_elapsed = start.elapsed();

    let start = Instant::now();
    let bytes = snapshot.to_bytes().unwrap();
    let encode_elapsed = start.elapsed();

    let start = Instant::now();
    let _loaded = kin_db::GraphSnapshot::from_bytes(&bytes).unwrap();
    let decode_elapsed = start.elapsed();

    let size_mb = bytes.len() as f64 / 1_048_576.0;
    println!("  {label} serialize (to_snapshot): {ser_elapsed:?}");
    println!("  {label} encode (to_bytes): {encode_elapsed:?} ({size_mb:.1} MB)");
    println!("  {label} decode (from_bytes): {decode_elapsed:?}");
}

fn bench_memory(graph: &InMemoryGraph, label: &str) {
    let snapshot = graph.to_snapshot();
    let bytes = snapshot.to_bytes().unwrap();
    let disk_mb = bytes.len() as f64 / 1_048_576.0;

    // Estimate in-memory size: entity count * ~200 bytes + relation count * ~100 bytes + index overhead
    let entity_count = graph.entity_count();
    let estimated_mem_mb =
        (entity_count as f64 * 200.0 + (entity_count as f64 * 5.0) * 100.0) / 1_048_576.0;
    let ratio = estimated_mem_mb / disk_mb;

    println!("  {label} entities: {entity_count}");
    println!("  {label} disk size: {disk_mb:.1} MB");
    println!("  {label} estimated memory: {estimated_mem_mb:.0} MB");
    println!("  {label} memory/disk ratio: {ratio:.1}x");
}

fn run_bench_suite(n: usize, rels_per_entity: usize) {
    let label = format!("{n}");
    println!("\n=== {n} entities, {rels_per_entity} rels/entity ===");

    let gen_start = Instant::now();
    let graph = generate_graph(n, rels_per_entity);
    let gen_elapsed = gen_start.elapsed();
    println!("  Generated in {gen_elapsed:?}");

    // Collect entity IDs for lookup bench
    let filter = EntityFilter::default();
    let all = graph.query_entities(&filter).unwrap();
    let entity_ids: Vec<EntityId> = all.iter().map(|e| e.id).collect();

    bench_entity_lookup(&graph, &entity_ids, &label);
    bench_query_by_file(&graph, &label);
    bench_bfs_neighborhood(&graph, &entity_ids[0], &label);
    bench_impact(&graph, &entity_ids[0], &label);
    bench_dead_code(&graph, &label);
    bench_incremental_upsert(&graph, &label);
    bench_serialization(&graph, &label);
    bench_memory(&graph, &label);
}

fn bench_incremental_upsert(graph: &InMemoryGraph, label: &str) {
    // Measure single-entity upsert throughput (incremental index update)
    let n = 1000;
    let entities: Vec<Entity> = (0..n)
        .map(|i| Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: format!("bench_incr_{i}"),
            language: LanguageId::Rust,
            fingerprint: test_fingerprint(),
            file_origin: Some(FilePathId::new(format!("bench/incr_{}.rs", i / 10))),
            span: None,
            signature: format!("fn bench_incr_{i}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        })
        .collect();

    // Single upserts (lock per entity)
    let start = Instant::now();
    for e in &entities {
        graph.upsert_entity(e).unwrap();
    }
    let single_elapsed = start.elapsed();
    let single_per_op = single_elapsed / n as u32;

    // Remove them for fair comparison
    for e in &entities {
        graph.remove_entity(&e.id).unwrap();
    }

    // Batch upserts (single lock acquisition)
    let start = Instant::now();
    graph.batch_upsert_entities(&entities).unwrap();
    let batch_elapsed = start.elapsed();
    let batch_per_op = batch_elapsed / n as u32;

    let speedup = single_elapsed.as_nanos() as f64 / batch_elapsed.as_nanos().max(1) as f64;

    println!("  {label} incremental upsert ({n} entities):");
    println!("    single: {single_per_op:?}/op ({single_elapsed:?} total)");
    println!("    batch:  {batch_per_op:?}/op ({batch_elapsed:?} total)");
    println!("    speedup: {speedup:.1}x");

    // Remove them again
    let ids: Vec<EntityId> = entities.iter().map(|e| e.id).collect();
    graph.batch_remove_entities(&ids).unwrap();
}

fn bench_snapshot_index_build(n: usize, label: &str) {
    // Measure from_snapshot index build time (the parallelized path)
    use std::collections::HashMap;

    let mut entities = HashMap::with_capacity(n);
    for i in 0..n {
        let id = EntityId::new();
        entities.insert(
            id,
            Entity {
                id,
                kind: match i % 5 {
                    0 => EntityKind::Function,
                    1 => EntityKind::Class,
                    2 => EntityKind::Method,
                    3 => EntityKind::Interface,
                    _ => EntityKind::Module,
                },
                name: format!("entity_{i}"),
                language: LanguageId::Rust,
                fingerprint: test_fingerprint(),
                file_origin: Some(FilePathId::new(format!("src/mod_{}.rs", i / 50))),
                span: None,
                signature: format!("fn entity_{i}()"),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            },
        );
    }

    let snapshot = kin_db::GraphSnapshot {
        version: kin_db::GraphSnapshot::CURRENT_VERSION,
        entities,
        entity_revisions: HashMap::new(),
        relations: HashMap::new(),
        outgoing: HashMap::new(),
        incoming: HashMap::new(),
        changes: HashMap::new(),
        change_children: HashMap::new(),
        branches: HashMap::new(),
        work_items: HashMap::new(),
        annotations: HashMap::new(),
        work_links: Vec::new(),
        reviews: HashMap::new(),
        review_decisions: HashMap::new(),
        review_notes: Vec::new(),
        review_discussions: Vec::new(),
        review_assignments: HashMap::new(),
        test_cases: HashMap::new(),
        assertions: HashMap::new(),
        verification_runs: HashMap::new(),
        test_covers_entity: Vec::new(),
        test_covers_contract: Vec::new(),
        test_verifies_work: Vec::new(),
        run_proves_entity: Vec::new(),
        run_proves_work: Vec::new(),
        mock_hints: Vec::new(),
        contracts: HashMap::new(),
        actors: HashMap::new(),
        delegations: Vec::new(),
        approvals: Vec::new(),
        audit_events: Vec::new(),
        shallow_files: Vec::new(),
        file_layouts: Vec::new(),
        structured_artifacts: Vec::new(),
        opaque_artifacts: Vec::new(),
        file_hashes: HashMap::new(),
        sessions: HashMap::new(),
        intents: HashMap::new(),
        downstream_warnings: Vec::new(),
        entity_revisions: HashMap::new(),
    };

    let start = Instant::now();
    let _graph = InMemoryGraph::from_snapshot(snapshot);
    let elapsed = start.elapsed();
    println!("  {label} from_snapshot ({n} entities): {elapsed:?}");
}

/// Benchmark delta indexing: unchanged indexed fields (skip index churn) vs changed fields.
fn bench_delta_index(graph: &InMemoryGraph, label: &str) {
    use kin_model::entity::*;
    use kin_model::ids::*;

    // Build 1000 test entities and insert them
    let n = 1000;
    let entities: Vec<Entity> = (0..n)
        .map(|i| Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: format!("delta_entity_{i}"),
            language: LanguageId::Rust,
            fingerprint: test_fingerprint(),
            file_origin: Some(FilePathId::new(format!("delta/mod_{}.rs", i / 10))),
            span: None,
            signature: format!("fn delta_entity_{i}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        })
        .collect();
    graph.batch_upsert_entities(&entities).unwrap();

    // Upsert with UNCHANGED indexed fields (only signature changes) — should skip index work
    let unchanged: Vec<Entity> = entities
        .iter()
        .map(|e| {
            let mut u = e.clone();
            u.signature = format!("fn {}() -> bool", e.name);
            u
        })
        .collect();
    let start = Instant::now();
    graph.batch_upsert_entities(&unchanged).unwrap();
    let unchanged_elapsed = start.elapsed();

    // Upsert with CHANGED indexed fields (name changes) — must update indexes
    let changed: Vec<Entity> = entities
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mut u = e.clone();
            u.name = format!("delta_renamed_{i}");
            u
        })
        .collect();
    let start = Instant::now();
    graph.batch_upsert_entities(&changed).unwrap();
    let changed_elapsed = start.elapsed();

    let speedup = changed_elapsed.as_nanos() as f64 / unchanged_elapsed.as_nanos().max(1) as f64;
    println!("  {label} delta index ({n} entities):");
    println!("    unchanged indexed fields: {unchanged_elapsed:?}");
    println!("    changed indexed fields:   {changed_elapsed:?}");
    println!("    speedup (skip ratio):     {speedup:.1}x");

    // Cleanup
    let ids: Vec<EntityId> = entities.iter().map(|e| e.id).collect();
    graph.batch_remove_entities(&ids).unwrap();
}

#[test]
#[ignore]
fn bench_incremental_indexing() {
    println!("\n=== Incremental indexing benchmarks ===");

    // Snapshot index build at various scales
    bench_snapshot_index_build(10_000, "10K");
    bench_snapshot_index_build(50_000, "50K");
    bench_snapshot_index_build(100_000, "100K");

    // Single vs batch upsert on a pre-populated graph
    let graph = generate_graph(10_000, 3);
    bench_incremental_upsert(&graph, "10K-base");
    bench_delta_index(&graph, "10K-base");

    let graph = generate_graph(100_000, 3);
    bench_incremental_upsert(&graph, "100K-base");
    bench_delta_index(&graph, "100K-base");
}

#[test]
#[ignore]
fn bench_100k() {
    run_bench_suite(100_000, 5);
}

#[test]
#[ignore]
fn bench_500k() {
    run_bench_suite(500_000, 5);
}

#[test]
#[ignore]
fn bench_1m() {
    run_bench_suite(1_000_000, 5);
}
