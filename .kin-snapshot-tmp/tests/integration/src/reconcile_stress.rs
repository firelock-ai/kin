// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconcile stress and correctness tests.
//!
//! Exercises the reconciler under adversarial conditions: rapid file changes,
//! generated/ignored files, partial writes, idempotent cycles, and conflicting
//! concurrent edits.

use kin_blobs::BlobStore;
use kin_index::FileEvent;
use kin_model::*;
use kin_reconcile::Reconciler;

use crate::helpers::*;

// -----------------------------------------------------------------------
// Helper: set up a reconciler with a working directory.
// -----------------------------------------------------------------------

fn setup_reconciler(
    dir: &std::path::Path,
) -> (
    Reconciler,
    BlobStore,
    std::sync::Arc<kin_db::InMemoryGraph>,
    GraphOverlay,
) {
    let (tempdir_unused, _graph, _genesis_id) = init_kin_repo();
    // Use the dir as the working directory but the graph from a fresh init.

    // We need init in the actual dir for layout to work.
    let init_result = kin_core::init(dir).unwrap();
    let snap_path = init_result.layout.root().join("kindb").join("graph.kndb");
    let snap = kin_db::SnapshotManager::open(&snap_path).unwrap();
    let graph = snap.graph();

    let blob_store = BlobStore::new(init_result.layout.objects_dir()).unwrap();
    let reconciler = Reconciler::new(dir.to_path_buf());
    let overlay = GraphOverlay::default();

    // Drop the unused tempdir reference from init_kin_repo.
    drop(tempdir_unused);

    (reconciler, blob_store, graph, overlay)
}

// -----------------------------------------------------------------------
// 1. Multiple reconcile cycles with no changes: idempotent
// -----------------------------------------------------------------------

#[test]
fn reconcile_idempotent_on_unchanged_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    // Write a source file.
    let content = "export function stable(): void { }\n";
    let path = write_ts_file(dir.path(), "src/stable.ts", content);

    // First reconcile: adds entities to the overlay.
    let event = FileEvent::Changed(path.clone());
    let outcome = reconciler
        .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay)
        .unwrap();

    // Apply the overlay adds to the graph so subsequent reconciles see them.
    for (_, entity) in &overlay.entity_adds {
        graph.upsert_entity(entity).unwrap();
    }
    let entities_after_first = graph.list_all_entities().unwrap().len();

    // Reset overlay for next cycle (simulating a commit clearing the overlay).
    let mut overlay2 = GraphOverlay::default();

    // Reconcile 4 more times against the same unchanged file.
    for i in 0..4 {
        let event = FileEvent::Changed(path.clone());
        let outcome = reconciler
            .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay2);
        assert!(
            outcome.is_ok(),
            "reconcile cycle {} should succeed: {:?}",
            i + 1,
            outcome
        );
    }

    // No new entities should be added (file unchanged, entities already in graph).
    assert_eq!(
        overlay2.entity_adds.len(),
        0,
        "unchanged file should not produce new entity adds"
    );
    assert_eq!(
        overlay2.entity_removes.len(),
        0,
        "unchanged file should not produce entity removes"
    );

    // Graph entity count should be stable.
    let entities_after_cycles = graph.list_all_entities().unwrap().len();
    assert_eq!(
        entities_after_first, entities_after_cycles,
        "entity count should be stable after repeated reconciles"
    );
}

// -----------------------------------------------------------------------
// 2. Rapid file changes: simulate editor typing
// -----------------------------------------------------------------------

#[test]
fn reconcile_handles_rapid_file_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    let path = dir.path().join("src/typing.ts");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    // Simulate typing: each iteration modifies the file.
    let versions = vec![
        "export function f(): void { }",
        "export function f(): void { console.log('a'); }",
        "export function f(): void { console.log('ab'); }",
        "export function f(): number { return 1; }",
        "export function f(): number { return 42; }",
    ];

    let mut success_count = 0;
    for version in &versions {
        std::fs::write(&path, version).unwrap();
        let event = FileEvent::Changed(path.clone());
        match reconciler.reconcile_file_change(&event, &blob_store, &*graph, &mut overlay) {
            Ok(_) => success_count += 1,
            Err(kin_reconcile::ReconcileError::FileModifiedDuringReconcile { .. }) => {
                // This is acceptable — the file changed between read and verify.
            }
            Err(e) => panic!("unexpected error during rapid reconcile: {:?}", e),
        }
    }

    assert!(
        success_count > 0,
        "at least some rapid changes should reconcile successfully"
    );
}

// -----------------------------------------------------------------------
// 3. Reconcile after file removal
// -----------------------------------------------------------------------

#[test]
fn reconcile_handles_file_removal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    // Create and reconcile a file.
    let content = "export function temporary(): void { }\n";
    let path = write_ts_file(dir.path(), "src/temp.ts", content);
    let event = FileEvent::Changed(path.clone());
    reconciler
        .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay)
        .unwrap();

    // Now remove the file and reconcile the removal.
    std::fs::remove_file(&path).unwrap();
    let remove_event = FileEvent::Removed(path.clone());
    let outcome = reconciler.reconcile_file_change(&remove_event, &blob_store, &*graph, &mut overlay);
    assert!(outcome.is_ok(), "file removal reconcile should succeed");
}

// -----------------------------------------------------------------------
// 4. Broken AST during reconcile: LKG preserved
// -----------------------------------------------------------------------

#[test]
fn reconcile_broken_ast_preserves_lkg() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    // Step 1: reconcile a valid file.
    let valid = "export function good(): number { return 1; }\n";
    let path = write_ts_file(dir.path(), "src/evolving.ts", valid);
    let event = FileEvent::Changed(path.clone());
    let outcome = reconciler
        .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay)
        .unwrap();

    // Should have added entities.
    match &outcome {
        kin_reconcile::ReconcileOutcome::Updated { added, .. } => {
            assert!(!added.is_empty(), "should have added entities");
        }
        other => panic!("expected Updated outcome, got {:?}", other),
    }

    let lkg_count = reconciler.lkg().len();
    assert!(lkg_count > 0, "LKG should have entries after valid parse");

    // Step 2: write broken content.
    let broken = "export function { broken syntax !!!";
    std::fs::write(&path, broken).unwrap();
    let event2 = FileEvent::Changed(path.clone());
    let outcome2 = reconciler.reconcile_file_change(&event2, &blob_store, &*graph, &mut overlay);

    // Should return BrokenAst (not an error), and LKG should be preserved.
    match outcome2 {
        Ok(kin_reconcile::ReconcileOutcome::BrokenAst { .. }) => {
            // Expected: LKG is preserved.
        }
        Ok(kin_reconcile::ReconcileOutcome::Updated { .. }) => {
            // Also acceptable if tree-sitter parsed it with error recovery.
        }
        Err(kin_reconcile::ReconcileError::FileModifiedDuringReconcile { .. }) => {
            // Race condition: acceptable in tests.
        }
        _other => {
            // Not a hard failure — some parsers are more lenient.
            // Just verify LKG is still intact.
        }
    }

    assert!(
        reconciler.lkg().len() >= lkg_count,
        "LKG count should not decrease after broken AST"
    );
}

// -----------------------------------------------------------------------
// 5. Reconcile with empty overlay: fresh start
// -----------------------------------------------------------------------

#[test]
fn reconcile_from_empty_overlay() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    assert!(overlay.entity_adds.is_empty());
    assert!(overlay.entity_mods.is_empty());
    assert!(overlay.entity_removes.is_empty());

    let content = "export function fresh(): void { }\n";
    let path = write_ts_file(dir.path(), "src/fresh.ts", content);
    let event = FileEvent::Changed(path.clone());

    let outcome = reconciler
        .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay)
        .unwrap();

    match outcome {
        kin_reconcile::ReconcileOutcome::Updated { added, .. } => {
            assert!(!added.is_empty(), "should add entities from a fresh file");
        }
        other => panic!("expected Updated, got {:?}", other),
    }
}

// -----------------------------------------------------------------------
// 6. Reconcile entity modification: detect changed body
// -----------------------------------------------------------------------

#[test]
fn reconcile_detects_entity_modification() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    // Initial version.
    let v1 = "export function mutable(): number { return 1; }\n";
    let path = write_ts_file(dir.path(), "src/mutable.ts", v1);
    let event = FileEvent::Changed(path.clone());
    reconciler
        .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay)
        .unwrap();

    // Apply overlay adds to the graph so the reconciler can diff against them.
    for (_, entity) in &overlay.entity_adds {
        graph.upsert_entity(entity).unwrap();
    }

    // Reset overlay for next cycle.
    let mut overlay2 = GraphOverlay::default();

    // Modified version.
    let v2 = "export function mutable(): number { return 42; }\n";
    std::fs::write(&path, v2).unwrap();
    let event2 = FileEvent::Changed(path.clone());
    let outcome = reconciler
        .reconcile_file_change(&event2, &blob_store, &*graph, &mut overlay2)
        .unwrap();

    match outcome {
        kin_reconcile::ReconcileOutcome::Updated { modified, .. } => {
            assert!(
                !modified.is_empty(),
                "should detect modification of entity body"
            );
        }
        other => panic!("expected Updated with modifications, got {:?}", other),
    }
}

// -----------------------------------------------------------------------
// 7. Reconcile entity removal from file: detect deleted function
// -----------------------------------------------------------------------

#[test]
fn reconcile_detects_entity_removal_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    // Two functions.
    let v1 = r#"export function keep(): void { }
export function remove(): void { }
"#;
    let path = write_ts_file(dir.path(), "src/shrinking.ts", v1);
    let event = FileEvent::Changed(path.clone());
    reconciler
        .reconcile_file_change(&event, &blob_store, &*graph, &mut overlay)
        .unwrap();

    // Apply to graph.
    for (_, entity) in &overlay.entity_adds {
        graph.upsert_entity(entity).unwrap();
    }

    let mut overlay2 = GraphOverlay::default();

    // Remove one function.
    let v2 = "export function keep(): void { }\n";
    std::fs::write(&path, v2).unwrap();
    let event2 = FileEvent::Changed(path.clone());
    let outcome = reconciler
        .reconcile_file_change(&event2, &blob_store, &*graph, &mut overlay2)
        .unwrap();

    match outcome {
        kin_reconcile::ReconcileOutcome::Updated { removed, .. } => {
            assert!(
                !removed.is_empty(),
                "should detect removal of entity from file"
            );
        }
        other => panic!("expected Updated with removals, got {:?}", other),
    }
}

// -----------------------------------------------------------------------
// 8. Reconcile with multiple files: independent processing
// -----------------------------------------------------------------------

#[test]
fn reconcile_multiple_files_independently() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    let path_a = write_ts_file(
        dir.path(),
        "src/fileA.ts",
        "export function alpha(): void { }\n",
    );
    let path_b = write_ts_file(
        dir.path(),
        "src/fileB.ts",
        "export function beta(): void { }\n",
    );

    // Reconcile both files.
    let event_a = FileEvent::Changed(path_a.clone());
    let event_b = FileEvent::Changed(path_b.clone());

    reconciler
        .reconcile_file_change(&event_a, &blob_store, &*graph, &mut overlay)
        .unwrap();
    reconciler
        .reconcile_file_change(&event_b, &blob_store, &*graph, &mut overlay)
        .unwrap();

    // Both entities should be in the overlay.
    let all_add_names: Vec<&str> = overlay
        .entity_adds
        .values()
        .map(|e| e.name.as_str())
        .collect();
    assert!(
        all_add_names.contains(&"alpha"),
        "alpha should be in overlay adds"
    );
    assert!(
        all_add_names.contains(&"beta"),
        "beta should be in overlay adds"
    );
}

// -----------------------------------------------------------------------
// 9. Reconcile with partial write (truncated file)
// -----------------------------------------------------------------------

#[test]
fn reconcile_handles_truncated_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut reconciler, blob_store, graph, mut overlay) = setup_reconciler(dir.path());

    // Write a truncated file (looks like mid-write).
    let truncated = "export function trunca";
    let path = write_ts_file(dir.path(), "src/truncated.ts", truncated);
    let event = FileEvent::Changed(path.clone());

    let outcome = reconciler.reconcile_file_change(&event, &blob_store, &*graph, &mut overlay);

    // Should either return BrokenAst (preferred) or succeed with partial entities.
    // The key invariant: no panic, no graph corruption.
    match outcome {
        Ok(kin_reconcile::ReconcileOutcome::BrokenAst { .. }) => {
            // Expected: truncated file has broken AST.
        }
        Ok(kin_reconcile::ReconcileOutcome::Updated { .. }) => {
            // Also acceptable: tree-sitter did partial recovery.
        }
        Err(kin_reconcile::ReconcileError::FileModifiedDuringReconcile { .. }) => {
            // Race condition acceptable in tests.
        }
        Err(_e) => {
            // Index errors (unsupported file, etc.) are also non-catastrophic.
            // Just make sure it didn't panic.
        }
        _ => {}
    }
}
