// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a persist that does not install leaves on disk.
//!
//! This is the cost of streaming a snapshot frame rather than buffering it. The
//! bytes are now written before the gates that decide whether to install them,
//! so every path that ends without installing owns a file the size of the
//! store. A path that neither installs nor discards one leaks a whole store to
//! disk per persist, which on a kernel-scale repository is tens of gigabytes
//! per refused save (FIR-3064).
//!
//! No memory guard can see this. `snapshot_persist_memory.rs` measures the live
//! heap and would read a leaked file as a clean run, and it is its own test
//! binary with a process-global counting allocator, so this cannot live beside
//! it: a second test running there is measured into its peak. Adding this one
//! to that file took its ceiling from 0.04 copies to 0.61 and failed it, which
//! is the file's own doc comment being right.
//!
//! Two arms, because there are two shapes of not-installing and they leave by
//! different doors. An identical re-save at a superseded cursor takes the
//! idempotent-retry branch and returns early; a DIFFERENT snapshot at the same
//! cursor gets past that branch and is refused by the generation check. Both
//! stage a frame first.

use kin_db::{
    GraphSnapshot, LocalFileBackend, SnapshotCursor, SnapshotSaveOutcome, StorageBackend,
};
use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
    Hash256, LanguageId, SemanticFingerprint, Visibility,
};

/// Enough entities that a leaked staging file would be an obvious one.
const ENTITIES: usize = 2_000;

/// Bytes of documentation body per entity, so the snapshot has real mass.
const ENTITY_PAYLOAD_BYTES: usize = 2_048;

/// Any history validator version. The write path branches on `Some` versus
/// `None`, never on the number: `Some` means the caller already proved storage
/// admission, which is the conversion's path and the one this guards.
const ANY_HISTORY_VALIDATOR: u32 = 1;

fn measurement_entity(index: usize) -> Entity {
    let path = format!("src/module_{index}.rs");
    let name = format!("kin_{index}");
    let byte = (index % 251) as u8;
    Entity {
        id: EntityId::from_content(&path, &name, "function", 1),
        kind: EntityKind::Function,
        name: name.clone(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([byte; 32]),
            signature_hash: Hash256::from_bytes([byte.wrapping_add(1); 32]),
            behavior_hash: Hash256::from_bytes([byte.wrapping_add(2); 32]),
            equivalence_hash: Hash256::from_bytes([byte.wrapping_add(3); 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new(&path)),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: Some(format!("{name} ").repeat(ENTITY_PAYLOAD_BYTES / 8)),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn measurement_snapshot() -> GraphSnapshot {
    let mut snapshot = GraphSnapshot::empty();
    for index in 0..ENTITIES {
        let entity = measurement_entity(index);
        snapshot.entities.insert(entity.id, entity);
    }
    snapshot
}

/// A persist that does not install must leave nothing repository-sized behind.
///
/// The listing is controlled before it is trusted: the installed `.kndb` must
/// be visible in it, because a wrong directory lists nothing and would read
/// as clean.
#[test]
fn a_persist_that_does_not_install_leaves_no_staged_frame_behind() {
    let snapshot = measurement_snapshot();
    let directory = tempfile::tempdir().expect("scratch store");
    let backend = LocalFileBackend::new(directory.path());

    let mut produce = |out: &mut dyn std::io::Write| {
        snapshot
            .stream_to(out)
            .map(|shape| (shape.byte_len, shape.sha256))
    };
    match backend.save_snapshot_streamed(
        "hygiene",
        &mut produce,
        SnapshotCursor::INITIAL,
        Some(ANY_HISTORY_VALIDATOR),
    ) {
        SnapshotSaveOutcome::Committed { .. } => {}
        other => panic!("the first persist must commit, got {other:?}"),
    }

    let surface = directory.path().join("hygiene").join("snapshots");
    let listing = || -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&surface)
            .expect("the snapshot surface exists")
            .map(|entry| {
                entry
                    .expect("a readable surface entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    };
    let staged = |names: &[String]| -> Vec<String> {
        names
            .iter()
            .filter(|name| name.contains(".candidate-"))
            .cloned()
            .collect()
    };

    let after_install = listing();
    // The control on the listing itself. A path that pointed at the wrong
    // directory would return an empty vector and every assertion below would
    // pass on nothing.
    assert!(
        after_install.iter().any(|name| name.ends_with(".kndb")),
        "the surface must hold the installed snapshot, or this looked in the wrong place: \
         {after_install:?}"
    );
    assert!(
        staged(&after_install).is_empty(),
        "a committed persist left a staged frame behind: {after_install:?}"
    );

    // Arm one: the same snapshot at a cursor the store has moved past. Its
    // digest matches the record, so the idempotent-retry branch returns Ok
    // early, after the frame has already been staged.
    let mut same = |out: &mut dyn std::io::Write| {
        snapshot
            .stream_to(out)
            .map(|shape| (shape.byte_len, shape.sha256))
    };
    let retried = backend.save_snapshot_streamed(
        "hygiene",
        &mut same,
        SnapshotCursor::INITIAL,
        Some(ANY_HISTORY_VALIDATOR),
    );
    let after_retry = listing();
    assert!(
        staged(&after_retry).is_empty(),
        "an idempotent retry left a staged frame behind, one whole store of disk per retry: \
         {after_retry:?} (outcome {retried:?})"
    );

    // Arm two: a different snapshot at the same superseded cursor. The digest
    // no longer matches, so this one reaches the generation check and is
    // refused, again after staging.
    let mut smaller = GraphSnapshot::empty();
    for index in 0..(ENTITIES / 2) {
        let entity = measurement_entity(index);
        smaller.entities.insert(entity.id, entity);
    }
    let mut different = |out: &mut dyn std::io::Write| {
        smaller
            .stream_to(out)
            .map(|shape| (shape.byte_len, shape.sha256))
    };
    let refused = backend.save_snapshot_streamed(
        "hygiene",
        &mut different,
        SnapshotCursor::INITIAL,
        Some(ANY_HISTORY_VALIDATOR),
    );
    assert!(
        !matches!(refused, SnapshotSaveOutcome::Committed { .. }),
        "a different snapshot at a superseded cursor must not commit, got {refused:?}"
    );
    let after_refusal = listing();
    assert!(
        after_refusal.iter().any(|name| name.ends_with(".kndb")),
        "the installed snapshot must survive a refused save: {after_refusal:?}"
    );
    assert!(
        staged(&after_refusal).is_empty(),
        "a refused persist left a staged frame behind, one whole store of disk per refusal: \
         {after_refusal:?}"
    );

    println!(
        "surface after install {after_install:?}\nafter retry {after_retry:?}\nafter refusal \
         {after_refusal:?}"
    );
}
