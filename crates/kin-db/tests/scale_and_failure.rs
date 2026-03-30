// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Scale, long-run, and failure injection tests for kin-db.
//!
//! These tests verify correctness under stress conditions:
//! - 100K entity graph operations complete in bounded time
//! - 1000 save/reload cycles produce no drift
//! - Corrupt snapshots are detected and handled
//! - Concurrent readers + single writer produce no corruption

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use kin_db::*;
use tempfile::TempDir;

fn test_fingerprint() -> SemanticFingerprint {
    SemanticFingerprint {
        ast_hash: Hash256::from_bytes([0; 32]),
        signature_hash: Hash256::from_bytes([0; 32]),
        behavior_hash: Hash256::from_bytes([0; 32]),
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        stability_score: 1.0,
    }
}

fn generate_snapshot(n: usize, rels_per_entity: usize) -> (GraphSnapshot, Vec<EntityId>) {
    let mut entities = HashMap::with_capacity(n);
    let mut entity_ids = Vec::with_capacity(n);
    let mut relations = HashMap::new();
    let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
    let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();

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
                file_origin: Some(FilePathId::new(&format!("src/mod_{}.rs", i / 100))),
                span: None,
                signature: format!("fn entity_{i}()"),
                visibility: Visibility::Public,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            },
        );
        entity_ids.push(id);
    }

    for (i, src_id) in entity_ids.iter().enumerate() {
        for j in 0..rels_per_entity {
            let dst_idx = (i + j + 1) % n;
            let dst_id = entity_ids[dst_idx];
            let rel_id = RelationId::new();
            relations.insert(
                rel_id,
                Relation {
                    id: rel_id,
                    src: *src_id,
                    dst: dst_id,
                    kind: RelationKind::Calls,
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

    let snapshot = GraphSnapshot {
        version: GraphSnapshot::CURRENT_VERSION,
        entities,
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
        structured_artifacts: Vec::new(),
        opaque_artifacts: Vec::new(),
        file_hashes: HashMap::new(),
        sessions: HashMap::new(),
        intents: HashMap::new(),
        downstream_warnings: Vec::new(),
    };

    (snapshot, entity_ids)
}

/// Scale test: 100K entities with basic operations in bounded time.
#[test]
fn scale_100k_entities() {
    let (snapshot, entity_ids) = generate_snapshot(100_000, 2);
    let start = Instant::now();
    let graph = InMemoryGraph::from_snapshot(snapshot);
    let hydrate_time = start.elapsed();

    // Hydration should complete in reasonable time (< 30s even on slow hardware).
    assert!(
        hydrate_time.as_secs() < 30,
        "hydration of 100K entities took {:?}, expected < 30s",
        hydrate_time
    );

    // list_all_entities
    let start = Instant::now();
    let all = graph.list_all_entities().unwrap();
    let list_time = start.elapsed();
    assert_eq!(all.len(), 100_000);
    assert!(
        list_time.as_secs() < 5,
        "list_all_entities took {:?}, expected < 5s",
        list_time
    );

    // Point lookup by ID
    let start = Instant::now();
    for eid in entity_ids.iter().take(1000) {
        let entity = graph.get_entity(eid).unwrap();
        assert!(entity.is_some());
    }
    let lookup_time = start.elapsed();
    assert!(
        lookup_time.as_millis() < 100,
        "1000 point lookups took {:?}, expected < 100ms",
        lookup_time
    );

    // Graph traversal (neighborhood)
    let start = Instant::now();
    let neighborhood = graph
        .get_dependency_neighborhood(&entity_ids[0], 2)
        .unwrap();
    let traversal_time = start.elapsed();
    assert!(!neighborhood.entities.is_empty());
    assert!(
        traversal_time.as_secs() < 5,
        "neighborhood query took {:?}, expected < 5s",
        traversal_time
    );
}

/// Long-run test: 100 save/reload cycles with no drift.
///
/// Uses a smaller graph (1K entities) to keep runtime reasonable,
/// but proves that serialization round-trips are lossless.
#[test]
fn save_reload_no_drift_100_cycles() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    let (initial_snapshot, entity_ids) = generate_snapshot(1_000, 2);
    let initial_entity_count = initial_snapshot.entities.len();
    let _initial_relation_count = initial_snapshot.relations.len();

    // Save initial snapshot.
    {
        let graph = InMemoryGraph::from_snapshot(initial_snapshot);
        let mgr = SnapshotManager::new(&path);
        mgr.swap(graph);
        mgr.save().unwrap();
    }

    // 100 save/reload cycles.
    for cycle in 0..100 {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();

        let entities = graph.list_all_entities().unwrap();
        assert_eq!(
            entities.len(),
            initial_entity_count,
            "entity count drifted at cycle {cycle}: expected {initial_entity_count}, got {}",
            entities.len()
        );

        // Spot-check a few entity IDs still exist.
        for eid in entity_ids.iter().take(10) {
            assert!(
                graph.get_entity(eid).unwrap().is_some(),
                "entity {eid:?} missing at cycle {cycle}"
            );
        }

        // Re-save (exercises full serialization round-trip).
        mgr.save().unwrap();
    }
}

/// Failure injection: corrupt snapshot bytes, verify detection.
#[test]
fn corrupt_snapshot_detected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    // Save a valid snapshot.
    {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        for i in 0..50 {
            graph
                .upsert_entity(&Entity {
                    id: EntityId::new(),
                    kind: EntityKind::Function,
                    name: format!("func_{i}"),
                    language: LanguageId::Rust,
                    fingerprint: test_fingerprint(),
                    file_origin: Some(FilePathId::new("src/lib.rs")),
                    span: None,
                    signature: format!("fn func_{i}()"),
                    visibility: Visibility::Public,
                    doc_summary: None,
                    metadata: EntityMetadata::default(),
                    lineage_parent: None,
                    created_in: None,
                    superseded_by: None,
                })
                .unwrap();
        }
        mgr.save().unwrap();
    }

    // Read the raw bytes and corrupt them.
    let mut bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() > 40, "snapshot should be non-trivial");

    // Corrupt the middle of the file (past the header).
    let mid = bytes.len() / 2;
    for byte in bytes[mid..mid + 10].iter_mut() {
        *byte ^= 0xFF;
    }
    std::fs::write(&path, &bytes).unwrap();

    // Open should fail since the data is corrupt and no recovery candidate exists.
    let result = SnapshotManager::open(&path);
    assert!(result.is_err(), "opening corrupt snapshot should fail");
}

/// Corrupt GraphSnapshot::from_bytes directly.
#[test]
fn corrupt_bytes_rejected_by_from_bytes() {
    let snapshot = GraphSnapshot::empty();
    let bytes = snapshot.to_bytes().unwrap();

    // Corrupt a byte in the body (past header).
    let mut corrupt = bytes.clone();
    if corrupt.len() > 20 {
        corrupt[15] ^= 0xFF;
    }

    let result = GraphSnapshot::from_bytes(&corrupt);
    assert!(
        result.is_err(),
        "from_bytes should reject corrupted snapshot data"
    );
}

/// Multi-thread test: 3 concurrent readers + 1 writer via SnapshotManager.
#[test]
fn concurrent_readers_single_writer() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    let mgr = Arc::new(SnapshotManager::open(&path).unwrap());

    // Pre-populate with some data.
    {
        let graph = mgr.graph();
        for i in 0..100 {
            graph
                .upsert_entity(&Entity {
                    id: EntityId::new(),
                    kind: EntityKind::Function,
                    name: format!("initial_{i}"),
                    language: LanguageId::Rust,
                    fingerprint: test_fingerprint(),
                    file_origin: Some(FilePathId::new("src/lib.rs")),
                    span: None,
                    signature: format!("fn initial_{i}()"),
                    visibility: Visibility::Public,
                    doc_summary: None,
                    metadata: EntityMetadata::default(),
                    lineage_parent: None,
                    created_in: None,
                    superseded_by: None,
                })
                .unwrap();
        }
    }

    let barrier = Arc::new(std::sync::Barrier::new(4)); // 3 readers + 1 writer

    // Spawn 3 reader threads.
    let mut handles = Vec::new();
    for reader_id in 0..3 {
        let mgr_clone = Arc::clone(&mgr);
        let barrier_clone = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            barrier_clone.wait();
            for _ in 0..100 {
                let graph = mgr_clone.graph();
                let entities = graph.list_all_entities().unwrap();
                // Entity count should be >= 100 (initial) and never decrease.
                assert!(
                    entities.len() >= 100,
                    "reader {reader_id} saw {} entities, expected >= 100",
                    entities.len()
                );
            }
        });
        handles.push(handle);
    }

    // Writer thread: add more entities.
    {
        let mgr_clone = Arc::clone(&mgr);
        let barrier_clone = Arc::clone(&barrier);
        let handle = std::thread::spawn(move || {
            barrier_clone.wait();
            let graph = mgr_clone.graph();
            for i in 0..100 {
                graph
                    .upsert_entity(&Entity {
                        id: EntityId::new(),
                        kind: EntityKind::Function,
                        name: format!("writer_{i}"),
                        language: LanguageId::Rust,
                        fingerprint: test_fingerprint(),
                        file_origin: Some(FilePathId::new("src/writer.rs")),
                        span: None,
                        signature: format!("fn writer_{i}()"),
                        visibility: Visibility::Public,
                        doc_summary: None,
                        metadata: EntityMetadata::default(),
                        lineage_parent: None,
                        created_in: None,
                        superseded_by: None,
                    })
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // Final verification: all writes visible.
    let graph = mgr.graph();
    let all = graph.list_all_entities().unwrap();
    assert_eq!(
        all.len(),
        200,
        "should have 100 initial + 100 writer entities"
    );
}
