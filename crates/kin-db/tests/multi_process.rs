// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Multi-process concurrency tests for SnapshotManager.
//!
//! These tests verify that:
//! 1. Two processes cannot corrupt the snapshot via concurrent opens (flock).
//! 2. The generation marker correctly detects stale state.

use kin_db::*;
use tempfile::TempDir;

fn test_entity(name: &str) -> Entity {
    Entity {
        id: EntityId::new(),
        kind: EntityKind::Function,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new("src/lib.rs")),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

#[test]
fn flock_prevents_concurrent_open() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    // First open succeeds and holds the lock.
    let mgr1 = SnapshotManager::open(&path).unwrap();
    let graph = mgr1.graph();
    graph.upsert_entity(&test_entity("first")).unwrap();
    mgr1.save().unwrap();

    // Second open on the same path should fail with LockError.
    let result = SnapshotManager::open(&path);
    let err_msg = match result {
        Ok(_) => panic!("second open should fail while first holds lock"),
        Err(e) => e.to_string(),
    };
    assert!(
        err_msg.contains("lock") || err_msg.contains("Lock"),
        "error should mention lock contention, got: {err_msg}"
    );

    // After dropping the first manager, the lock is released.
    drop(mgr1);
    let mgr2 = SnapshotManager::open(&path).unwrap();
    let graph2 = mgr2.graph();
    let entities = graph2.list_all_entities().unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].name, "first");
}

#[test]
fn generation_staleness_detection() {
    let dir = TempDir::new().unwrap();
    let base_path = dir.path().join("repo1");
    std::fs::create_dir_all(&base_path).unwrap();

    let backend = LocalFileBackend::new(&base_path);

    // First save: generation goes from INIT to something > 0.
    let snapshot = GraphSnapshot::empty();
    let bytes = snapshot.to_bytes().unwrap();
    let gen1 = backend
        .save_snapshot("test", &bytes, GENERATION_INIT)
        .unwrap();
    assert!(gen1 > GENERATION_INIT, "first save should advance generation");

    // Second save with correct expected generation succeeds.
    let gen2 = backend.save_snapshot("test", &bytes, gen1).unwrap();
    assert!(gen2 > gen1, "second save should advance generation");

    // Third save with stale generation (gen1 instead of gen2) should fail.
    let result = backend.save_snapshot("test", &bytes, gen1);
    assert!(
        result.is_err(),
        "save with stale generation should fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("generation") || err_msg.contains("stale") || err_msg.contains("mismatch"),
        "error should mention generation staleness, got: {err_msg}"
    );
}

#[test]
fn snapshot_data_survives_lock_release_and_reacquire() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    // Write data with first manager.
    {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        for i in 0..100 {
            graph
                .upsert_entity(&test_entity(&format!("entity_{i}")))
                .unwrap();
        }
        mgr.save().unwrap();
    }
    // Lock released on drop.

    // Reopen and verify all data is intact.
    {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        let entities = graph.list_all_entities().unwrap();
        assert_eq!(entities.len(), 100);
    }
}

#[test]
fn rcu_swap_does_not_corrupt_concurrent_readers() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");
    let mgr = SnapshotManager::open(&path).unwrap();

    // Write initial data.
    let graph_v1 = mgr.graph();
    let e1 = test_entity("version_1");
    let e1_id = e1.id;
    graph_v1.upsert_entity(&e1).unwrap();

    // Take a reader snapshot.
    let reader_ref = mgr.graph();

    // Swap to a completely new graph.
    let new_graph = InMemoryGraph::new();
    let e2 = test_entity("version_2");
    let e2_id = e2.id;
    new_graph.upsert_entity(&e2).unwrap();
    mgr.swap(new_graph);

    // Old reader still sees v1 data.
    assert!(reader_ref.get_entity(&e1_id).unwrap().is_some());
    assert!(reader_ref.get_entity(&e2_id).unwrap().is_none());

    // New reader sees v2 data.
    let current = mgr.graph();
    assert!(current.get_entity(&e2_id).unwrap().is_some());
    assert!(current.get_entity(&e1_id).unwrap().is_none());
}

#[test]
fn delta_round_trip_preserves_data() {
    let dir = TempDir::new().unwrap();
    let base_path = dir.path().join("repo_delta");
    std::fs::create_dir_all(&base_path).unwrap();

    let backend = LocalFileBackend::new(&base_path);

    // Save initial snapshot with one entity.
    let mut snapshot = GraphSnapshot::empty();
    let e1 = test_entity("delta_base");
    snapshot.entities.insert(e1.id, e1.clone());
    let bytes = snapshot.to_bytes().unwrap();
    let gen1 = backend
        .save_snapshot("test", &bytes, GENERATION_INIT)
        .unwrap();

    // Create a modified snapshot with an additional entity.
    let mut snapshot2 = snapshot.clone();
    let e2 = test_entity("delta_added");
    snapshot2.entities.insert(e2.id, e2.clone());

    // Compute and save a delta.
    let delta = compute_graph_delta(&snapshot, &snapshot2, gen1);
    let delta_bytes = delta.to_bytes().unwrap();
    let gen2 = backend.save_delta("test", &delta_bytes, gen1).unwrap();
    assert!(gen2 > gen1);

    // Load deltas since gen1 and apply.
    let deltas = backend.load_deltas_since("test", gen1).unwrap();
    assert_eq!(deltas.len(), 1);

    let loaded_delta = GraphSnapshotDelta::from_bytes(&deltas[0].0).unwrap();
    let mut applied = snapshot.clone();
    apply_graph_delta(&mut applied, &loaded_delta);

    assert_eq!(applied.entities.len(), 2);
    assert!(applied.entities.contains_key(&e1.id));
    assert!(applied.entities.contains_key(&e2.id));
}
