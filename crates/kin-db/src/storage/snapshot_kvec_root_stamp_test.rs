//! FIR-930 regression: the kvec sidecar's `graph_root_hash` must be the
//! canonical root recomputed from current graph content at the stamp site, NOT
//! whatever value happens to be cached in `snapshot_root_hash_hint()`.
//!
//! Included as a child module of `storage::snapshot` (rather than an external
//! `tests/` integration test) because faithfully reproducing the bug requires
//! poisoning the `pub(crate)` hint and reading the module-private sidecar
//! helpers — neither is reachable from an out-of-crate test.

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

/// A stale/wrong `snapshot_root_hash_hint()` must be ignored: the kvec sidecar
/// is stamped with the canonical recompute. Pre-FIR-930 this stamped the
/// poisoned hint, so the sidecar's root no longer matched graph truth (and
/// diverged across otherwise-identical preps).
#[test]
fn kvec_stamp_ignores_stale_root_hash_hint() {
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

    // A real save records the canonical root into the hint.
    mgr.save().unwrap();

    let canonical = compute_graph_root_hash(&graph.to_snapshot());

    // Poison the cached hint with a value that is NOT the canonical root, then
    // persist the sidecar. With the bug, this poisoned value would be stamped.
    let poison = [0xABu8; 32];
    assert_ne!(poison, canonical, "poison must differ from canonical root");
    graph.record_snapshot_root_hash(poison);
    assert_eq!(
        graph.snapshot_root_hash_hint(),
        Some(poison),
        "hint should be poisoned going into the stamp"
    );

    SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None).unwrap();

    let metadata = read_vector_index_metadata(&metadata_path)
        .unwrap()
        .expect("kvec metadata should be written");

    assert_eq!(
        metadata.graph_root_hash,
        hex::encode(canonical),
        "sidecar must stamp the canonical recomputed root, not the cached hint"
    );
    assert_ne!(
        metadata.graph_root_hash,
        hex::encode(poison),
        "sidecar must not stamp the stale/poisoned hint value"
    );
}

/// The canonical recompute is prep-invariant: two graphs built with identical
/// entity content stamp identical sidecar roots even when their cached hints
/// were poisoned to different values. This is the property the FIR-814 identity
/// experiment (ROOT_HASH_MATCH=0/26) actually needed.
#[test]
fn kvec_stamp_is_prep_invariant_under_divergent_hints() {
    fn stamp_one(dir: &TempDir, file: &str, hint: [u8; 32]) -> String {
        let snapshot_path = dir.path().join(file);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        // Fixed id/content so both "preps" are byte-identical graph truth.
        let mut entity = stamp_test_entity("prep_invariant_owner");
        entity.id = EntityId(uuid::Uuid::from_u128(0x5151_5151_5151_5151_5151_5151_5151_5151));
        graph.upsert_entity(&entity).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        mgr.save().unwrap();

        // Diverge the cached hints across the two preps.
        graph.record_snapshot_root_hash(hint);
        SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None).unwrap();

        read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("kvec metadata should be written")
            .graph_root_hash
    }

    let dir = TempDir::new().unwrap();
    let prep_a = stamp_one(&dir, "prep_a.kndb", [0x11u8; 32]);
    let prep_b = stamp_one(&dir, "prep_b.kndb", [0x22u8; 32]);

    assert_eq!(
        prep_a, prep_b,
        "identical graph content must stamp identical sidecar roots regardless of cached hint"
    );
}
