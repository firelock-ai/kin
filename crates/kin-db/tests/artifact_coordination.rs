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
//! | Authority | `graph.kndb.authority.json` | Atomic committed snapshot base/head generations and graph root |
//! | Versioned snapshot | `graph.kndb.snapshots/{gen:020}.kndb` | Immutable committed GraphSnapshot base |
//! | Compatibility projection | `graph.kndb` | Canonical projection for legacy readers; not recovery authority |
//! | Delta journal | `graph.kndb.deltas/{gen:020}.kndd` | Contiguous committed changes after the snapshot base |
//! | Lock file | `graph.lock` | flock sentinel for exclusive process access |
//! | Recovery candidate | `graph.kndb.tmp` | In-flight compatibility projection write |
//! | Recovery marker | `graph.kndb.tmp.meta` | SHA-256 + byte length of graph.kndb.tmp for crash validation |
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
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn authoritative_snapshot_path(snapshot_path: &Path) -> PathBuf {
    let authority_path = append_suffix(snapshot_path, ".authority.json");
    let authority: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();
    let snapshot_file = authority
        .get("snapshot_file")
        .and_then(serde_json::Value::as_str)
        .expect("authority must name its immutable snapshot");
    append_suffix(snapshot_path, ".snapshots").join(snapshot_file)
}

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
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new("src/lib.rs")),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
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
        src: GraphNodeId::Entity(src),
        dst: GraphNodeId::Entity(dst),
        kind: RelationKind::Calls,
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
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
    // The tuple generation must describe these exact base bytes. The
    // acknowledged journal head is available through load_snapshot_authority.
    assert_eq!(loaded_gen, gen1);

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

/// A compatibility-projection write that crashes before the authority commit
/// must not replace the last committed graph truth.
#[test]
fn crash_before_authority_commit_keeps_old_snapshot_truth() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kindb").join("graph.kndb");

    // Create a graph and save it normally first.
    let original_entity_id = {
        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        let e1 = test_entity("original");
        let e1_id = e1.id;
        graph.upsert_entity(&e1).unwrap();
        mgr.save().unwrap();
        e1_id
    };

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

        // Append the suffix to the full path (graph.kndb.tmp /
        // graph.kndb.tmp.meta), matching the production recovery_tmp_path
        // derivation so reopen recovery finds these files.
        let mut tmp_name = std::ffi::OsString::from(path.as_os_str());
        tmp_name.push(".tmp");
        let tmp_path = std::path::PathBuf::from(tmp_name);
        let mut marker_name = std::ffi::OsString::from(path.as_os_str());
        marker_name.push(".tmp.meta");
        let marker_path = std::path::PathBuf::from(marker_name);

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

    // Recovery reads committed authority, not the uncommitted compatibility
    // candidate, then heals the canonical projection from immutable truth.
    let recovered_mgr = SnapshotManager::open(&path).unwrap();
    let graph = recovered_mgr.graph();

    assert!(
        graph.get_entity(&original_entity_id).unwrap().is_some(),
        "last committed entity should survive the interrupted write"
    );
    assert!(
        graph.get_entity(&new_entity_id).unwrap().is_none(),
        "uncommitted compatibility candidate must not override authority"
    );

    // The compatibility projection should be restored from authority and the
    // stale recovery candidate consumed.
    assert!(path.exists(), "compatibility projection should be restored");
    assert!(
        !append_suffix(&path, ".tmp").exists(),
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

    // Corrupt the immutable snapshot named by authority. Corrupting only the
    // compatibility projection cannot affect committed graph truth.
    let authoritative_path = authoritative_snapshot_path(&path);
    let mut bytes = std::fs::read(&authoritative_path).unwrap();
    for byte in bytes.iter_mut().take(20) {
        *byte ^= 0xFF;
    }
    std::fs::write(&authoritative_path, bytes).unwrap();

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
