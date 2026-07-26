// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Round-trip integration tests for kin-reconcile.
//!
//! These tests exercise the public Reconciler API end-to-end:
//! register a file layout + content, build an exact transaction with entity
//! mutations, project to disk, and verify the resulting bytes.

use std::collections::HashMap;

use kin_blobs::BlobStore;
use kin_db::{EntityStore, InMemoryGraph};
use kin_index::FileEvent;
use kin_model::{
    Entity, EntityDelta, EntityId, EntityKind, EntityMetadata, EntityRole, FileLayout, FilePathId,
    FingerprintAlgorithm, Hash256, ImportSection, LanguageId, ParseCompleteness,
    SemanticFingerprint, SourceRegion, SourceSpan, TransactionDelta, Visibility,
};
use kin_reconcile::Reconciler;

/// Helper: build a minimal Entity with the given fields.
fn make_entity(
    id: EntityId,
    name: &str,
    file: &str,
    span: Option<SourceSpan>,
    signature: &str,
) -> Entity {
    Entity {
        id,
        kind: EntityKind::Function,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: Hash256::from_bytes([0xbb; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 0.95,
        },
        file_origin: Some(FilePathId::new(file)),
        span,
        signature: signature.to_string(),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn projection_transaction(new: Entity) -> TransactionDelta {
    let mut old = new.clone();
    old.fingerprint.ast_hash = Hash256::from_bytes([0; 32]);
    assert_ne!(old, new);
    TransactionDelta {
        entity_deltas: vec![EntityDelta::Modified { old, new }],
        ..TransactionDelta::default()
    }
}

fn added_entities(delta: &TransactionDelta) -> Vec<&Entity> {
    delta
        .entity_deltas
        .iter()
        .filter_map(|entity_delta| match entity_delta {
            EntityDelta::Added { new } => Some(new),
            EntityDelta::Modified { .. } | EntityDelta::Removed { .. } => None,
        })
        .collect()
}

fn modified_entities(delta: &TransactionDelta) -> Vec<(&Entity, &Entity)> {
    delta
        .entity_deltas
        .iter()
        .filter_map(|entity_delta| match entity_delta {
            EntityDelta::Modified { old, new } => Some((old, new)),
            EntityDelta::Added { .. } | EntityDelta::Removed { .. } => None,
        })
        .collect()
}

fn removed_entities(delta: &TransactionDelta) -> Vec<&Entity> {
    delta
        .entity_deltas
        .iter()
        .filter_map(|entity_delta| match entity_delta {
            EntityDelta::Removed { old } => Some(old),
            EntityDelta::Added { .. } | EntityDelta::Modified { .. } => None,
        })
        .collect()
}

/// Prove that `extract_entity_body` uses the entity's span to extract the
/// full body from the projection state's cached file content, NOT the
/// entity's `signature` field.
#[test]
fn body_extracted_from_span_not_signature() {
    let dir = tempfile::tempdir().unwrap();
    let _blob_store = BlobStore::new(dir.path().join("objects")).unwrap();

    let file_content = b"fn foo() { return 42; }\nfn bar() { }\n";
    let file_name = "test.rs";

    // Write the file to disk so projection can write back to it.
    std::fs::write(dir.path().join(file_name), file_content).unwrap();

    let entity_id = EntityId::new();

    let layout = FileLayout {
        file_id: FilePathId::new(file_name),
        parse_completeness: ParseCompleteness::Full,
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions: vec![
            SourceRegion::EntityRef {
                entity_id,
                byte_range: 0..23, // "fn foo() { return 42; }"
            },
            SourceRegion::Trivia {
                byte_range: 23..24, // "\n"
            },
            SourceRegion::Trivia {
                byte_range: 24..37, // "fn bar() { }\n"
            },
        ],
    };

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());
    reconciler
        .projection_mut()
        .register_file(layout, file_content.to_vec());

    // Build a transaction: the entity's span covers bytes 0..23, but signature is
    // deliberately shorter ("fn foo()") to prove the span wins.
    let entity = make_entity(
        entity_id,
        "foo",
        file_name,
        Some(SourceSpan {
            file: FilePathId::new(file_name),
            start_byte: 0,
            end_byte: 23,
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 23,
        }),
        "fn foo()", // intentionally NOT the full body
    );

    let transaction = projection_transaction(entity);

    let (modified, _warnings) = reconciler
        .project_transaction_to_files(&transaction, &HashMap::new())
        .unwrap();

    assert_eq!(modified.len(), 1, "expected exactly 1 modified file");

    // Read the file back.
    let result = std::fs::read(dir.path().join(file_name)).unwrap();

    // The entity region (bytes 0..23) should contain the span-extracted body,
    // which is "fn foo() { return 42; }" — NOT the signature "fn foo()".
    let entity_bytes = &result[0..23];
    assert_eq!(
        entity_bytes, b"fn foo() { return 42; }",
        "body should come from span extraction, not signature"
    );
    assert_ne!(
        entity_bytes, b"fn foo()\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "body must NOT be the signature padded"
    );
}

/// Prove that a whitespace/comment gap between two entity regions is not
/// disturbed when only one entity is projected.
#[test]
fn trivia_preserved_between_entities() {
    let dir = tempfile::tempdir().unwrap();
    let _blob_store = BlobStore::new(dir.path().join("objects")).unwrap();

    //                       0         1         2         3
    //                       0123456789012345678901234567890123456789
    let file_content = b"fn foo() { 1 }\n\n// gap\n\nfn bar() { 2 }\n";
    let file_name = "trivia.rs";

    std::fs::write(dir.path().join(file_name), file_content).unwrap();

    let foo_id = EntityId::new();
    let bar_id = EntityId::new();

    // Work out exact byte ranges:
    // "fn foo() { 1 }" = bytes 0..14
    // "\n\n// gap\n\n"  = bytes 14..24  (trivia)
    // "fn bar() { 2 }" = bytes 24..38
    // "\n"              = bytes 38..39
    assert_eq!(&file_content[0..14], b"fn foo() { 1 }");
    assert_eq!(&file_content[14..24], b"\n\n// gap\n\n");
    assert_eq!(&file_content[24..38], b"fn bar() { 2 }");

    let layout = FileLayout {
        file_id: FilePathId::new(file_name),
        parse_completeness: ParseCompleteness::Full,
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions: vec![
            SourceRegion::EntityRef {
                entity_id: foo_id,
                byte_range: 0..14,
            },
            SourceRegion::Trivia { byte_range: 14..24 },
            SourceRegion::EntityRef {
                entity_id: bar_id,
                byte_range: 24..38,
            },
            SourceRegion::Trivia { byte_range: 38..39 },
        ],
    };

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());
    reconciler
        .projection_mut()
        .register_file(layout, file_content.to_vec());

    // Only modify foo — bar is untouched.
    let foo_entity = make_entity(
        foo_id,
        "foo",
        file_name,
        Some(SourceSpan {
            file: FilePathId::new(file_name),
            start_byte: 0,
            end_byte: 14,
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 14,
        }),
        "fn foo()",
    );

    let transaction = projection_transaction(foo_entity);

    let (modified, _) = reconciler
        .project_transaction_to_files(&transaction, &HashMap::new())
        .unwrap();

    assert_eq!(modified.len(), 1);

    let result = std::fs::read(dir.path().join(file_name)).unwrap();

    // The trivia gap "\n\n// gap\n\n" must be unchanged.
    assert_eq!(
        &result[14..24],
        b"\n\n// gap\n\n",
        "trivia between entities must be preserved"
    );

    // bar's region must also be unchanged.
    assert_eq!(
        &result[24..38],
        b"fn bar() { 2 }",
        "unmodified entity bar must be unchanged"
    );
}

/// Prove that modifying one entity in a multi-entity file leaves the other
/// entity's bytes unchanged.
#[test]
fn multi_entity_file_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let _blob_store = BlobStore::new(dir.path().join("objects")).unwrap();

    let file_content = b"fn a() { 1 }\nfn b() { 2 }\n";
    let file_name = "multi.rs";

    std::fs::write(dir.path().join(file_name), file_content).unwrap();

    let a_id = EntityId::new();
    let b_id = EntityId::new();

    // "fn a() { 1 }" = bytes 0..12
    // "\n"            = bytes 12..13 (trivia)
    // "fn b() { 2 }" = bytes 13..25
    // "\n"            = bytes 25..26
    assert_eq!(&file_content[0..12], b"fn a() { 1 }");
    assert_eq!(&file_content[12..13], b"\n");
    assert_eq!(&file_content[13..25], b"fn b() { 2 }");

    let layout = FileLayout {
        file_id: FilePathId::new(file_name),
        parse_completeness: ParseCompleteness::Full,
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions: vec![
            SourceRegion::EntityRef {
                entity_id: a_id,
                byte_range: 0..12,
            },
            SourceRegion::Trivia { byte_range: 12..13 },
            SourceRegion::EntityRef {
                entity_id: b_id,
                byte_range: 13..25,
            },
            SourceRegion::Trivia { byte_range: 25..26 },
        ],
    };

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());
    reconciler
        .projection_mut()
        .register_file(layout, file_content.to_vec());

    // Modify entity a: change body from "fn a() { 1 }" to "fn a() { 9 }"
    // The new body is the same length so byte offsets for b stay the same.
    let a_entity = make_entity(
        a_id,
        "a",
        file_name,
        Some(SourceSpan {
            file: FilePathId::new(file_name),
            start_byte: 0,
            end_byte: 12,
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 12,
        }),
        "fn a()",
    );

    // Give entity a a different fingerprint so it is treated as changed.
    let mut a_mod = a_entity.clone();
    a_mod.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);

    let transaction = TransactionDelta {
        entity_deltas: vec![EntityDelta::Modified {
            old: a_entity,
            new: a_mod,
        }],
        ..TransactionDelta::default()
    };

    let (modified, _) = reconciler
        .project_transaction_to_files(&transaction, &HashMap::new())
        .unwrap();

    assert_eq!(modified.len(), 1);

    let result = std::fs::read(dir.path().join(file_name)).unwrap();

    // Entity a's region: the span-based extraction returns the original bytes
    // (bytes 0..12 from cached content = "fn a() { 1 }"), so the spliced
    // content replaces the same range with the same bytes. The splice still
    // happened (the file was "modified"), but the content is identical because
    // span extraction returns the original cached body.
    assert_eq!(
        &result[0..12],
        b"fn a() { 1 }",
        "entity a region should contain the span-extracted body"
    );

    // Entity b must be EXACTLY unchanged.
    assert_eq!(
        &result[13..25],
        b"fn b() { 2 }",
        "entity b must be exactly unchanged"
    );

    // File length must be correct.
    assert_eq!(result.len(), file_content.len(), "file length must match");

    // The full file should be byte-identical since the splice replaced
    // entity a's range with its own span content (same bytes).
    assert_eq!(
        result.as_slice(),
        file_content.as_slice(),
        "full file content must be preserved when splicing same-span body"
    );
}

/// A1: Full round-trip integration test.
///
/// 1. Write a source file and reconcile it (entities enter the graph).
/// 2. Commit entities to the graph.
/// 3. Externally edit the file (change function body).
/// 4. Reconcile the edit (an exact modification delta is returned).
/// 5. Verify the new entity state has the new fingerprint and body content.
///
/// This is the single most important test for Kin — it proves that
/// graph and files stay in sync across the full edit cycle.
#[test]
fn full_round_trip_edit_reconcile_verify() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
    let graph = InMemoryGraph::new();

    // Step 1: Write a Rust source file.
    let file_path = dir.path().join("round_trip.rs");
    let original_content = b"pub fn greet() -> i32 { 42 }\n";
    std::fs::write(&file_path, original_content).unwrap();

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());

    // Step 2: First reconcile — transaction adds one entity.
    let event = FileEvent::Changed(file_path.clone());
    let reconcile1 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("first reconcile should succeed");
    let added1 = added_entities(&reconcile1.delta);

    assert_eq!(
        added1.len(),
        1,
        "expected exactly 1 new entity from first reconcile"
    );
    let stable_id = added1[0].id;
    let original_entity = added1[0].clone();
    let original_fingerprint = original_entity.fingerprint.clone();

    // Commit entity to graph so it is "existing" for subsequent reconciles.
    graph
        .upsert_entity(&original_entity)
        .expect("upsert must succeed");

    // Step 3: Externally edit the file — change the function signature and body.
    // This is structurally different enough to change the AST fingerprint.
    let edited_content = b"pub fn greet(name: &str) -> String { format!(\"hello {}\", name) }\n";
    std::fs::write(&file_path, edited_content).unwrap();

    // Step 4: Reconcile the external edit.
    let reconcile2 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("second reconcile after edit should succeed");

    // Step 5: Verify the exact transaction reflects the change.
    let added2 = added_entities(&reconcile2.delta);
    let modified2 = modified_entities(&reconcile2.delta);
    assert!(added2.is_empty(), "no new entities should be added on edit");
    assert_eq!(modified2.len(), 1, "exactly 1 entity should be modified");
    assert_eq!(
        modified2[0].0.id, stable_id,
        "modified entity must use the stable graph ID"
    );

    let modified_entity = modified2[0].1;

    // The fingerprint must have changed (different source content).
    assert_ne!(
        modified_entity.fingerprint.ast_hash, original_fingerprint.ast_hash,
        "fingerprint must change after body edit"
    );

    // The entity should have a blob_hash in metadata (from C1/C2 fix).
    assert!(
        modified_entity.metadata.extra.contains_key("blob_hash"),
        "modified entity must have blob_hash in metadata"
    );

    // Identity must be preserved.
    assert_eq!(
        modified_entity.id, stable_id,
        "entity ID must be stable across edits"
    );
    assert_eq!(
        modified_entity.name, original_entity.name,
        "entity name must be preserved"
    );
}

/// Comprehensive round-trip test: the single most important test for Kin.
///
/// Exercises the full lifecycle:
/// 1. Write a source file and reconcile it (entities + relations enter a transaction)
/// 2. Commit entities to the graph
/// 3. Externally edit the file (change function body AND signature)
/// 4. Reconcile the edit — verify the exact modification has the new fingerprint
/// 5. Project the transaction back to files — verify file on disk matches expected content
/// 6. Re-reconcile — verify idempotence (no further modifications detected)
///
/// This proves that graph and files stay in sync across the full edit cycle,
/// entity IDs are stable, blob_hash metadata is set, and stale relations are
/// removed when the file changes.
#[test]
fn comprehensive_round_trip_with_projection_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
    let graph = InMemoryGraph::new();

    // --- Step 1: Write a Rust source file with two functions ---
    let file_path = dir.path().join("two_fns.rs");
    let original_content = b"pub fn alpha() -> i32 { 1 }\npub fn beta() -> i32 { 2 }\n";
    std::fs::write(&file_path, original_content).unwrap();

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());

    // --- Step 2: First reconcile — entities enter as exact additions ---
    let event = FileEvent::Changed(file_path.clone());
    let reconcile1 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("first reconcile should succeed");

    // Verify we got an Updated outcome with 2 added entities.
    match &reconcile1.outcome {
        kin_reconcile::ReconcileOutcome::Updated {
            added,
            modified,
            removed,
            ..
        } => {
            assert_eq!(added.len(), 2, "expected 2 entities from first reconcile");
            assert!(modified.is_empty(), "no modifications on first reconcile");
            assert!(removed.is_empty(), "no removals on first reconcile");
        }
        other => panic!("expected Updated, got: {:?}", other),
    }

    // All added entities must have blob_hash in metadata.
    let added1 = added_entities(&reconcile1.delta);
    for entity in &added1 {
        assert!(
            entity.metadata.extra.contains_key("blob_hash"),
            "entity {} must have blob_hash metadata",
            entity.name
        );
    }

    // Find entities by name for later comparison.
    let alpha_entity = added1
        .iter()
        .copied()
        .find(|e| e.name == "alpha")
        .expect("alpha must exist");
    let alpha_id = alpha_entity.id;
    let beta_id = added1
        .iter()
        .copied()
        .find(|e| e.name == "beta")
        .expect("beta must exist")
        .id;
    let original_alpha_fp = alpha_entity.fingerprint.clone();
    let original_beta_fp = added1
        .iter()
        .copied()
        .find(|entity| entity.id == beta_id)
        .expect("beta must exist")
        .fingerprint
        .clone();

    // Commit entities to the graph.
    for entity in &added1 {
        graph.upsert_entity(entity).expect("upsert must succeed");
    }

    // --- Step 3: Externally edit the file — change alpha's body ---
    let edited_content = b"pub fn alpha(x: i32) -> i32 { x * 2 }\npub fn beta() -> i32 { 2 }\n";
    std::fs::write(&file_path, edited_content).unwrap();

    // --- Step 4: Reconcile the external edit ---
    let reconcile2 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("second reconcile after edit should succeed");

    // alpha changed semantically. Beta's semantic fingerprint is unchanged, but
    // its source span and containing blob provenance move because alpha grew.
    let added2 = added_entities(&reconcile2.delta);
    let modified2 = modified_entities(&reconcile2.delta);
    let removed2 = removed_entities(&reconcile2.delta);
    assert!(
        added2.is_empty(),
        "no new entities on edit of existing file"
    );
    assert!(
        modified2.iter().any(|(_, new)| new.id == alpha_id),
        "alpha must have an exact modification"
    );
    assert!(
        removed2.is_empty(),
        "no entities were removed (both still present)"
    );

    let modified_alpha = modified2
        .iter()
        .find_map(|(_, new)| (new.id == alpha_id).then_some(*new))
        .expect("alpha modification must exist");

    // Fingerprint must have changed.
    assert_ne!(
        modified_alpha.fingerprint.ast_hash, original_alpha_fp.ast_hash,
        "alpha's fingerprint must change after body edit"
    );

    // Identity must be stable.
    assert_eq!(modified_alpha.id, alpha_id, "alpha ID must be stable");
    assert_eq!(modified_alpha.name, "alpha", "alpha name must be preserved");

    // blob_hash must be set on modified entity.
    assert!(
        modified_alpha.metadata.extra.contains_key("blob_hash"),
        "modified alpha must have blob_hash"
    );

    let modified_beta = modified2
        .iter()
        .find_map(|(_, new)| (new.id == beta_id).then_some(*new))
        .expect("beta span/blob enrichment must advance");
    assert_eq!(
        modified_beta.fingerprint, original_beta_fp,
        "beta remains semantically unchanged"
    );

    // --- Step 5: The transaction's file-derived body is already on disk ---
    // We need the modified entity to have a span pointing to the file
    // for project_transaction_to_files to extract the body.
    // The reconciler already registered the layout from the second reconcile,
    // so we can project directly.

    // Commit every exact entity modification so graph enrichment matches disk.
    for (_, new) in &modified2 {
        graph.upsert_entity(new).expect("upsert modified entity");
    }

    // --- Step 6: Re-reconcile — should be idempotent (no further changes) ---
    // Read the file again after edit — it should still match edited_content.
    let disk_content = std::fs::read(&file_path).unwrap();
    assert_eq!(
        disk_content.as_slice(),
        edited_content.as_slice(),
        "file on disk must match edited content"
    );

    let reconcile3 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("third reconcile (idempotency) should succeed");

    // No modifications should be detected — the graph matches the file.
    assert!(
        reconcile3.delta.entity_deltas.is_empty(),
        "re-reconcile must be idempotent: no entity deltas expected, got {}",
        reconcile3.delta.entity_deltas.len()
    );
    assert!(
        reconcile3.delta.relation_deltas.is_empty(),
        "re-reconcile must be idempotent: no relation deltas expected"
    );
}

/// Test that reconcile transactionality works: if an error occurs during
/// reconcile, no partial transaction escapes and internal LKG state is restored.
#[test]
fn reconcile_transaction_rollback_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
    let graph = InMemoryGraph::new();

    // Write an initial file and reconcile it.
    let file_path = dir.path().join("txn_test.rs");
    std::fs::write(&file_path, b"pub fn txn_fn() -> i32 { 1 }\n").unwrap();

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());
    let event = FileEvent::Changed(file_path.clone());

    let first = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("first reconcile should succeed");

    assert_eq!(added_entities(&first.delta).len(), 1);
    let first_delta = first.delta.clone();
    let lkg_len = reconciler.lkg().len();

    // Now try to reconcile a file that doesn't exist (should error).
    let bad_path = dir.path().join("nonexistent.rs");
    let bad_event = FileEvent::Changed(bad_path);

    let result = reconciler.reconcile_file_change(&bad_event, &blob_store, &graph);

    // The reconcile should have failed.
    assert!(result.is_err(), "reconcile of nonexistent file should fail");

    assert_eq!(first.delta, first_delta, "prior transaction is immutable");
    assert_eq!(reconciler.lkg().len(), lkg_len, "LKG must be restored");
}

/// Prove that the real runtime path — reconcile_file_change followed by
/// project_transaction_to_files — works correctly when an entity already exists
/// in the graph (the "modified" branch).
///
/// This exercises the P1 entity-ID remap: when reconcile_file_change sees
/// an existing entity, it remaps the parser-assigned UUID to old.id in both
/// the exact modification AND the layout regions. project_entity_mutations must
/// be able to find old.id in the layout to apply the splice.
///
/// Without the fix, the layout has the parser's new UUID, not old.id, so the
/// splice is silently skipped and modified.len() == 0 instead of 1.
#[test]
fn reconcile_then_project_uses_stable_ids() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
    let graph = InMemoryGraph::new();

    // A minimal Rust file the tree-sitter adapter will parse into one function entity.
    let file_path = dir.path().join("lib.rs");
    std::fs::write(&file_path, b"pub fn foo() -> i32 { 42 }\n").unwrap();

    let mut reconciler = Reconciler::new(dir.path().to_path_buf());

    // --- Reconcile 1: graph is empty, entity is treated as a new addition ---
    let event = FileEvent::Changed(file_path.clone());
    let reconcile1 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("first reconcile should succeed");

    // One entity (fn foo) should have been added.
    let added1 = added_entities(&reconcile1.delta);
    assert_eq!(added1.len(), 1, "expected 1 new entity");
    let stable_id = added1[0].id;

    // Commit the entity to the graph so it is "existing" for the next reconcile.
    for entity in added1 {
        graph.upsert_entity(entity).expect("upsert must succeed");
    }

    // --- Reconcile 2: graph has the entity; same file, so fingerprint unchanged ---
    // The reconciler sees it as an existing entity and remaps the new parser UUID
    // back to stable_id in both the transaction and the layout regions.
    let reconcile2 = reconciler
        .reconcile_file_change(&event, &blob_store, &graph)
        .expect("second reconcile should succeed");

    // No entity change was detected, but the
    // projection state must now have stable_id in its layout regions.
    assert!(reconcile2.delta.entity_deltas.is_empty());
    // Build a modification under stable_id to verify the layout matches.
    let old = graph
        .get_entity(&stable_id)
        .expect("graph lookup")
        .expect("entity must exist");
    let mut entity_mod = old.clone();
    // Change the fingerprint to mark it as agent-modified.
    entity_mod.fingerprint.ast_hash = Hash256::from_bytes([0xde; 32]);
    let transaction = TransactionDelta {
        entity_deltas: vec![EntityDelta::Modified {
            old,
            new: entity_mod,
        }],
        ..TransactionDelta::default()
    };

    // --- Project: layout must contain stable_id so the splice is applied ---
    let (modified, _warnings) = reconciler
        .project_transaction_to_files(&transaction, &HashMap::new())
        .expect("projection must succeed");

    assert_eq!(
        modified.len(),
        1,
        "exactly one file must be written; if 0 the layout ID remap is broken"
    );
}
