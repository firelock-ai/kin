// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Artifact coordination tests.
//!
//! Verifies that all persisted artifacts stay mutually consistent after
//! save/load cycles, and that crash recovery produces a valid graph.
//!
//! ## Persisted artifacts (SnapshotManager path):
//!
//! | Artifact | Path | Purpose |
//! |----------|------|---------|
//! | Main snapshot | `graph.kndb` | MessagePack-serialized GraphSnapshot |
//! | Lock file | `graph.lock` | flock sentinel for exclusive process access |
//! | Recovery candidate | `graph.tmp` | In-flight write; promoted to graph.kndb on success |
//! | Recovery marker | `graph.tmp.meta` | SHA-256 + byte length of graph.tmp for crash validation |
//!
//! ## Persisted artifacts (StorageBackend/LocalFileBackend path):
//!
//! | Artifact | Path | Purpose |
//! |----------|------|---------|
//! | Main snapshot | `{repo}/graph.kndb` | MessagePack-serialized GraphSnapshot |
//! | Generation counter | `{repo}/graph.kndb.gen` | Monotonic u64 for CAS writes |
//! | Delta files | `{repo}/deltas/{gen:020}.kndd` | Incremental diffs from base snapshot |
//! | Overlay state | `{repo}/overlays/{session}.bin` | Session preemption recovery |
//! | Lock file | `{repo}/.lock` | flock for StorageBackend CAS |
//!
//! ## Vector index artifacts (VectorIndex):
//!
//! | Artifact | Path | Purpose |
//! |----------|------|---------|
//! | HNSW index | `*.usearch` | usearch HNSW graph for semantic similarity |
//! | Key map sidecar | `*.keys.bin` | EntityId <-> u64 key mapping for usearch |
//! | Recovery marker | `*.usearch.tmp.meta` | SHA-256 for crash recovery of vector index |

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

fn make_relation(src: EntityId, dst: EntityId) -> Relation {
    Relation {
        id: RelationId::new(),
        src,
        dst,
        kind: RelationKind::Calls,
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
    }
}

/// After N save/load cycles, the graph should be identical.
#[test]
fn save_load_cycles_preserve_data() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    let mut entity_ids = Vec::new();
    let mut relation_ids = Vec::new();

    // Build up a graph over 10 save/load cycles.
    for cycle in 0..10 {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();

        // Add new entities each cycle.
        for i in 0..10 {
            let e = test_entity(&format!("cycle_{cycle}_entity_{i}"));
            entity_ids.push(e.id);
            graph.upsert_entity(&e).unwrap();
        }

        // Add relations between some entities.
        if entity_ids.len() >= 2 {
            let src = entity_ids[entity_ids.len() - 2];
            let dst = entity_ids[entity_ids.len() - 1];
            let rel = make_relation(src, dst);
            relation_ids.push(rel.id);
            graph.upsert_relation(&rel).unwrap();
        }

        mgr.save().unwrap();
    }

    // Final load: verify all data present.
    let mgr = SnapshotManager::open(&path).unwrap();
    let graph = mgr.graph();

    let all_entities = graph.list_all_entities().unwrap();
    assert_eq!(
        all_entities.len(),
        100,
        "should have 10 entities * 10 cycles = 100"
    );

    for eid in &entity_ids {
        assert!(
            graph.get_entity(eid).unwrap().is_some(),
            "entity {eid:?} should exist after reload"
        );
    }
}

/// Snapshot + generation + deltas should all agree after operations.
#[test]
fn backend_artifacts_stay_consistent() {
    let dir = TempDir::new().unwrap();
    let base_path = dir.path().join("backend_test");
    std::fs::create_dir_all(&base_path).unwrap();
    let backend = LocalFileBackend::new(&base_path);

    // Save initial snapshot.
    let mut snapshot = GraphSnapshot::empty();
    let e1 = test_entity("base_entity");
    snapshot.entities.insert(e1.id, e1.clone());
    let bytes = snapshot.to_bytes().unwrap();
    let gen1 = backend
        .save_snapshot("repo1", &bytes, GENERATION_INIT)
        .unwrap();

    // Save a delta.
    let mut snapshot2 = snapshot.clone();
    let e2 = test_entity("delta_entity");
    snapshot2.entities.insert(e2.id, e2.clone());
    let delta = compute_graph_delta(&snapshot, &snapshot2, gen1);
    let delta_bytes = delta.to_bytes().unwrap();
    let _gen2 = backend.save_delta("repo1", &delta_bytes, gen1).unwrap();

    // Load and reconstruct: snapshot + delta should equal snapshot2.
    let (loaded_bytes, loaded_gen) = backend.load_snapshot("repo1").unwrap().unwrap();
    // Note: save_delta advances the shared generation counter, so loaded_gen
    // may be > gen1. The snapshot bytes are still from gen1's save, but the
    // generation file reflects the latest write (including deltas).
    assert!(loaded_gen >= gen1, "loaded gen should be >= gen1");

    let mut loaded_snapshot = GraphSnapshot::from_bytes(&loaded_bytes).unwrap();
    let deltas = backend.load_deltas_since("repo1", gen1).unwrap();
    assert_eq!(deltas.len(), 1);

    let loaded_delta = GraphSnapshotDelta::from_bytes(&deltas[0].0).unwrap();
    apply_graph_delta(&mut loaded_snapshot, &loaded_delta);

    assert_eq!(loaded_snapshot.entities.len(), 2);
    assert!(loaded_snapshot.entities.contains_key(&e1.id));
    assert!(loaded_snapshot.entities.contains_key(&e2.id));

    // Compact: should merge delta into snapshot.
    let compacted_gen = backend.compact_deltas("repo1").unwrap();
    assert!(compacted_gen > gen1);

    let (final_bytes, _) = backend.load_snapshot("repo1").unwrap().unwrap();
    let final_snapshot = GraphSnapshot::from_bytes(&final_bytes).unwrap();
    assert_eq!(final_snapshot.entities.len(), 2);

    let remaining_deltas = backend.load_deltas_since("repo1", GENERATION_INIT).unwrap();
    assert!(
        remaining_deltas.is_empty(),
        "deltas should be cleared after compaction"
    );
}

/// Simulate a crash mid-write by leaving a .tmp + .tmp.meta but no primary.
/// Verify recovery produces the correct graph.
#[test]
fn crash_recovery_from_valid_tmp() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    // Create a graph and save it normally first.
    {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        let e1 = test_entity("original");
        graph.upsert_entity(&e1).unwrap();
        mgr.save().unwrap();
    }

    // Now simulate a crash: write a new snapshot to .tmp with marker,
    // but delete the primary (as if rename hadn't happened yet).
    let new_entity = test_entity("crash_recovery");
    let new_entity_id = new_entity.id;
    {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        graph.upsert_entity(&new_entity).unwrap();
        // Manually write recovery candidate without promoting.
        let snapshot = graph.to_snapshot();
        let bytes = snapshot.to_bytes().unwrap();

        let tmp_path = path.with_extension("tmp");
        let marker_path = path.with_extension("tmp.meta");

        // Write tmp file.
        std::fs::write(&tmp_path, &bytes).unwrap();

        // Write marker with correct checksum.
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).into()
        };
        let marker = serde_json::json!({
            "version": 1,
            "byte_len": bytes.len() as u64,
            "sha256": digest,
        });
        std::fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        drop(mgr);

        // Delete the primary to simulate crash before rename.
        std::fs::remove_file(&path).unwrap();
    }

    // Recovery: open should detect missing primary, find valid .tmp, and recover.
    let recovered_mgr = SnapshotManager::open(&path).unwrap();
    let graph = recovered_mgr.graph();

    // The recovered graph should contain the new entity.
    let fetched = graph.get_entity(&new_entity_id).unwrap();
    assert!(
        fetched.is_some(),
        "crash-recovered graph should contain the entity written before crash"
    );
    assert_eq!(fetched.unwrap().name, "crash_recovery");

    // The primary should now exist (promoted from .tmp).
    assert!(path.exists(), "primary snapshot should be restored");
    assert!(
        !path.with_extension("tmp").exists(),
        "recovery .tmp should be consumed"
    );
}

/// Corrupt snapshot with no valid recovery candidate should fail gracefully.
#[test]
fn corrupt_snapshot_no_recovery_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    // Save a valid snapshot.
    {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        graph
            .upsert_entity(&test_entity("will_be_corrupted"))
            .unwrap();
        mgr.save().unwrap();
    }

    // Corrupt it.
    let mut bytes = std::fs::read(&path).unwrap();
    for byte in bytes.iter_mut().take(20) {
        *byte ^= 0xFF;
    }
    std::fs::write(&path, bytes).unwrap();

    // Open should fail (corrupt primary, no recovery candidate).
    let result = SnapshotManager::open(&path);
    assert!(
        result.is_err(),
        "opening corrupt snapshot without recovery candidate should fail"
    );
}

/// Overlay save/load round-trip.
#[test]
fn overlay_round_trip() {
    let dir = TempDir::new().unwrap();
    let base_path = dir.path().join("overlay_test");
    std::fs::create_dir_all(&base_path).unwrap();
    let backend = LocalFileBackend::new(&base_path);

    // Save initial snapshot so the repo directory exists.
    let snapshot = GraphSnapshot::empty();
    let bytes = snapshot.to_bytes().unwrap();
    backend
        .save_snapshot("repo1", &bytes, GENERATION_INIT)
        .unwrap();

    // Save an overlay.
    let overlay_data = b"serialized overlay state";
    backend
        .save_overlay("repo1", "session-123", overlay_data)
        .unwrap();

    // Load it back.
    let loaded = backend
        .load_overlay("repo1", "session-123")
        .unwrap()
        .unwrap();
    assert_eq!(loaded, overlay_data);

    // Delete it.
    backend.delete_overlay("repo1", "session-123").unwrap();
    let gone = backend.load_overlay("repo1", "session-123").unwrap();
    assert!(gone.is_none());
}
