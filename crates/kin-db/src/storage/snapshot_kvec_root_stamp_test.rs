//! Regression: the kvec sidecar's `graph_root_hash` must be the
//! continuously-maintained current graph root.
//!
//! Included as a child module of `storage::snapshot` (rather than an external
//! `tests/` integration test) because reading the module-private sidecar helpers
//! is not reachable from an out-of-crate test.

#![cfg(feature = "vector")]

use super::*;
use crate::storage::merkle::compute_graph_root_hash;
use crate::store::EntityStore;
use crate::types::*;
use crate::VectorIndex;
use tempfile::TempDir;

fn stamp_test_entity(name: &str) -> Entity {
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
        file_origin: Some(FilePathId::new("src/main.rs")),
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

/// The kvec sidecar is stamped with the continuously-maintained graph root.
#[test]
fn kvec_stamp_uses_continuously_maintained_root() {
    let dir = TempDir::new().unwrap();
    let snapshot_path = dir.path().join("graph.kndb");
    let metadata_path = vector_index_metadata_path_for(&snapshot_path);
    let vector_path = vector_index_path_for(&snapshot_path);

    let mgr = SnapshotManager::new(&snapshot_path);
    let graph = mgr.graph();
    let entity = stamp_test_entity("stamp_owner");
    graph.upsert_entity(&entity).unwrap();

    let vectors = VectorIndex::new(4).unwrap();
    vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
    vectors.save(&vector_path).unwrap();
    graph.load_vector_index(&vector_path).unwrap();

    mgr.save().unwrap();

    let canonical = compute_graph_root_hash(&graph.to_snapshot());
    assert_eq!(
        graph.snapshot_root_hash_hint(),
        Some(canonical),
        "maintained root must stay current before vector stamp"
    );

    SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None).unwrap();

    let metadata = read_vector_index_metadata(&metadata_path)
        .unwrap()
        .expect("kvec metadata should be written");

    assert_eq!(
        metadata.graph_root_hash,
        hex::encode(canonical),
        "sidecar must stamp the maintained current root"
    );
}

/// Two graphs built with identical entity content stamp identical sidecar roots.
/// This is the cross-instance root-hash identity property prepared-state reuse
/// depends on.
#[test]
fn kvec_stamp_is_prep_invariant() {
    fn stamp_one(dir: &TempDir, file: &str) -> String {
        let snapshot_path = dir.path().join(file);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        // Fixed id/content so both "preps" are byte-identical graph truth.
        let mut entity = stamp_test_entity("prep_invariant_owner");
        entity.id = EntityId(uuid::Uuid::from_u128(
            0x5151_5151_5151_5151_5151_5151_5151_5151,
        ));
        graph.upsert_entity(&entity).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        mgr.save().unwrap();

        SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None).unwrap();

        read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("kvec metadata should be written")
            .graph_root_hash
    }

    let dir = TempDir::new().unwrap();
    let prep_a = stamp_one(&dir, "prep_a.kndb");
    let prep_b = stamp_one(&dir, "prep_b.kndb");

    assert_eq!(
        prep_a, prep_b,
        "identical graph content must stamp identical sidecar roots regardless of cached hint"
    );
}
