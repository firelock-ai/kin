// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Phase 11 acceptance tests: mutation workflow parity.
//!
//! These tests prove the end-to-end mutation workflow:
//! create workspace -> edit files -> reconcile/re-index -> verify graph updated.

use kin_blobs::BlobStore;
use kin_cli::commands::reconcile::reconcile_session_dir;
use kin_db::SnapshotManager;
use kin_index::IndexedAny;
use kin_model::graph::GraphStore;
use kin_runtime::workspace::{MaterializeStrategy, MaterializedWorkspace};

use crate::helpers::*;

// ---------------------------------------------------------------------------
// 42. Edit source file, re-index, verify entity updated in graph
// ---------------------------------------------------------------------------

#[test]
fn test_edit_source_reconcile() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();

    // Write initial TypeScript file with one function.
    let ts_content = r#"
export function greet(name: string): string {
    return `Hello, ${name}!`;
}
"#;
    let ts_path = write_ts_file(dir.path(), "src/hello.ts", ts_content);

    // Index the file — entities should appear.
    let result = indexer
        .index_and_apply(&ts_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(
        result.entities_upserted > 0,
        "initial index should upsert entities"
    );

    let entities_before = graph.list_all_entities().unwrap();
    let greet_before = entities_before
        .iter()
        .find(|e| e.name.contains("greet"))
        .expect("greet entity should exist after initial index");
    let greet_fingerprint_before = greet_before.fingerprint.clone();

    // Edit the file — change the function body (semantic change).
    let ts_content_edited = r#"
export function greet(name: string): string {
    return `Hi there, ${name}! Welcome!`;
}

export function farewell(name: string): string {
    return `Goodbye, ${name}!`;
}
"#;
    write_ts_file(dir.path(), "src/hello.ts", ts_content_edited);

    // Re-index the same file.
    let result2 = indexer
        .index_and_apply(&ts_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(
        result2.entities_upserted > 0,
        "re-index after edit should upsert entities"
    );

    // Verify graph now has both greet and farewell.
    let entities_after = graph.list_all_entities().unwrap();
    let names: Vec<&str> = entities_after.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("farewell")),
        "new function 'farewell' should appear in graph, got: {:?}",
        names
    );

    // The greet entity should still exist (modified, not removed).
    let greet_after = entities_after
        .iter()
        .find(|e| e.name.contains("greet"))
        .expect("greet entity should still exist after edit");

    // Fingerprint should have changed because the body changed.
    assert_ne!(
        greet_after.fingerprint.behavior_hash, greet_fingerprint_before.behavior_hash,
        "greet's behavior_hash should change after body edit"
    );
}

// ---------------------------------------------------------------------------
// 43. Create a brand new file, index, verify new entities appear
// ---------------------------------------------------------------------------

#[test]
fn test_create_file_reconcile() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();

    // Graph should start empty (no user entities).
    let entities_before = graph.list_all_entities().unwrap();
    assert!(
        entities_before.is_empty(),
        "graph should start with no entities"
    );

    // Create a brand new TypeScript file with multiple functions.
    let ts_content = r#"
export function add(a: number, b: number): number {
    return a + b;
}

export function subtract(a: number, b: number): number {
    return a - b;
}

export class MathUtils {
    multiply(a: number, b: number): number {
        return a * b;
    }
}
"#;
    let ts_path = write_ts_file(dir.path(), "src/math.ts", ts_content);

    // Index the new file.
    let result = indexer
        .index_and_apply(&ts_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(
        result.entities_upserted > 0,
        "indexing new file should upsert entities"
    );

    // Verify entities appeared in graph.
    let entities_after = graph.list_all_entities().unwrap();
    assert!(
        entities_after.len() >= 3,
        "expected at least 3 entities (add, subtract, MathUtils), got {}",
        entities_after.len()
    );

    let names: Vec<&str> = entities_after.iter().map(|e| e.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n.contains("add")),
        "expected 'add' entity, got: {:?}",
        names
    );
    assert!(
        names.iter().any(|n| n.contains("subtract")),
        "expected 'subtract' entity, got: {:?}",
        names
    );
}

// ---------------------------------------------------------------------------
// 44. Delete a source file, re-index as removal, verify entities gone
// ---------------------------------------------------------------------------

#[test]
fn test_delete_file_reconcile() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();

    // Create and index a TypeScript file.
    let ts_content = r#"
export function doWork(): void {
    console.log("working");
}

export function cleanup(): void {
    console.log("cleaning up");
}
"#;
    let ts_path = write_ts_file(dir.path(), "src/worker.ts", ts_content);

    let result = indexer
        .index_and_apply(&ts_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(result.entities_upserted > 0);

    // Verify entities exist.
    let entities_before = graph.list_all_entities().unwrap();
    assert!(
        !entities_before.is_empty(),
        "entities should exist before deletion"
    );

    // Delete the file from disk.
    std::fs::remove_file(&ts_path).unwrap();

    // Handle removal via the indexer.
    let removal_result = indexer.handle_removal(&ts_path, graph.as_ref()).unwrap();
    assert!(
        removal_result.entities_removed > 0,
        "removal should remove entities, got {} removed",
        removal_result.entities_removed
    );

    // Verify entities are gone from graph.
    let entities_after = graph.list_all_entities().unwrap();

    // Filter to only entities from the deleted file.
    let worker_entities: Vec<_> = entities_after
        .iter()
        .filter(|e| {
            e.file_origin
                .as_ref()
                .map(|f| f.to_string().contains("worker.ts"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        worker_entities.is_empty(),
        "entities from deleted file should be removed from graph, still found: {:?}",
        worker_entities.iter().map(|e| &e.name).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// 45. Edit a README (non-code file), re-index, verify opaque artifact hash changes
// ---------------------------------------------------------------------------

#[test]
fn test_edit_readme_round_trips_as_opaque_artifact() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = kin_index::IndexPipeline::new();

    // Write initial README.
    let readme_content = "# My Project\n\nThis is a test project.\n";
    let readme_path = dir.path().join("README.md");
    std::fs::write(&readme_path, readme_content).unwrap();

    let first_hash = match pipeline.index_any_file(&readme_path, &blob_store).unwrap() {
        IndexedAny::OpaqueArtifact(artifact) => {
            assert_eq!(
                artifact.file_id.0,
                readme_path.display().to_string(),
                "README should round-trip with its tracked path",
            );
            assert_eq!(
                artifact.mime_type.as_deref(),
                Some("text/md"),
                "README should stay classified as a markdown opaque artifact",
            );
            artifact.content_hash
        }
        other => panic!("README should index as an opaque artifact, got: {other:?}"),
    };

    assert!(
        graph.list_all_entities().unwrap().is_empty(),
        "non-code README indexing should not invent semantic entities",
    );

    // Edit the README.
    let readme_edited = "# My Project\n\nUpdated description with more details.\n\n## Features\n- Fast\n- Reliable\n";
    std::fs::write(&readme_path, readme_edited).unwrap();

    let second_hash = match pipeline.index_any_file(&readme_path, &blob_store).unwrap() {
        IndexedAny::OpaqueArtifact(artifact) => artifact.content_hash,
        other => panic!("edited README should stay an opaque artifact, got: {other:?}"),
    };

    assert_ne!(
        first_hash, second_hash,
        "editing a README should produce a new tracked content hash",
    );
}

// ---------------------------------------------------------------------------
// 46. Session reconcile: create a new doc file, verify it persists predictably
// ---------------------------------------------------------------------------

#[test]
fn test_session_reconcile_adds_doc_file() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let session_dir = layout.root().join("runs/session-doc-add");

    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("README.md"),
        "# Session-created Doc\n\nThis file should survive reconcile.\n",
    )
    .unwrap();

    let summary = reconcile_session_dir(&layout, &session_dir).unwrap();
    assert_eq!(summary.change_count, 1);
    assert_eq!(summary.files_indexed, 0);
    assert_eq!(summary.total_upserted, 0);
    assert_eq!(summary.total_removed, 0);
    assert_eq!(summary.changes, vec![("added".into(), "README.md".into())]);

    let persisted = std::fs::read_to_string(dir.path().join("README.md")).unwrap();
    assert!(
        persisted.contains("Session-created Doc"),
        "reconcile should copy new doc files back into the source tree"
    );

    let snapshot = SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
    let graph = snapshot.graph();
    assert_eq!(
        graph.entity_count(),
        0,
        "adding a doc file through session reconcile should not invent semantic entities",
    );
}

// ---------------------------------------------------------------------------
// 47. Session reconcile: delete a doc file, verify it is removed predictably
// ---------------------------------------------------------------------------

#[test]
fn test_session_reconcile_deletes_doc_file() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let session_dir = layout.root().join("runs/session-doc-delete");

    std::fs::write(
        dir.path().join("README.md"),
        "# Existing Doc\n\nThis file should be deleted through reconcile.\n",
    )
    .unwrap();
    std::fs::create_dir_all(&session_dir).unwrap();

    let summary = reconcile_session_dir(&layout, &session_dir).unwrap();
    assert_eq!(summary.change_count, 1);
    assert_eq!(summary.files_indexed, 0);
    assert_eq!(summary.total_upserted, 0);
    assert_eq!(summary.total_removed, 0);
    assert_eq!(
        summary.changes,
        vec![("deleted".into(), "README.md".into())]
    );

    assert!(
        !dir.path().join("README.md").exists(),
        "reconcile should remove deleted doc files from the source tree",
    );

    let snapshot = SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
    let graph = snapshot.graph();
    assert_eq!(
        graph.entity_count(),
        0,
        "deleting a doc file through session reconcile should leave semantic state unchanged",
    );
}

// ---------------------------------------------------------------------------
// 48. Session reconcile: rename a source file, verify remove + add semantics
// ---------------------------------------------------------------------------

#[test]
fn test_session_reconcile_renames_source_file() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();
    let source_path = write_rust_file(
        dir.path(),
        "src/legacy.rs",
        "pub fn renamed_from_session() -> &'static str { \"ok\" }\n",
    );

    let initial = indexer
        .index_and_apply(&source_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(initial.entities_upserted > 0);

    let session_dir = layout.root().join("runs/session-rename-source");
    std::fs::create_dir_all(session_dir.join("src")).unwrap();
    std::fs::write(
        session_dir.join("src/renamed.rs"),
        "pub fn renamed_from_session() -> &'static str { \"ok\" }\n",
    )
    .unwrap();

    let summary = reconcile_session_dir(&layout, &session_dir).unwrap();
    assert_eq!(summary.change_count, 2);
    assert!(
        summary
            .changes
            .contains(&("added".into(), "src/renamed.rs".into())),
        "reconcile should detect the new path in session workspace"
    );
    assert!(
        summary
            .changes
            .contains(&("deleted".into(), "src/legacy.rs".into())),
        "reconcile should detect removal of the old path from source"
    );
    assert!(
        summary.files_indexed >= 1,
        "rename reconcile should re-index the added file"
    );
    assert!(
        summary.total_upserted >= 1,
        "rename reconcile should update semantic state for the renamed file"
    );

    assert!(
        !dir.path().join("src/legacy.rs").exists(),
        "old source path should be removed after reconcile"
    );
    assert!(
        dir.path().join("src/renamed.rs").exists(),
        "new source path should be present after reconcile"
    );

    let snapshot = SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
    let graph = snapshot.graph();
    let entities = graph.list_all_entities().unwrap();
    let renamed_entities: Vec<_> = entities
        .iter()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .map(|origin| origin.to_string().contains("src/renamed.rs"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !renamed_entities.is_empty(),
        "reconcile should move surviving entities onto the renamed file path"
    );
    assert!(
        entities.iter().all(|entity| {
            !entity
                .file_origin
                .as_ref()
                .map(|origin| origin.to_string().contains("src/legacy.rs"))
                .unwrap_or(false)
        }),
        "no surviving entity should still point at the deleted path"
    );
}

// ---------------------------------------------------------------------------
// 49. Session reconcile: generated artifacts do not poison source updates
// ---------------------------------------------------------------------------

#[test]
fn test_session_reconcile_ignores_generated_artifacts() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();
    let source_path = write_ts_file(
        dir.path(),
        "src/service.ts",
        "export function status(): string {\n    return \"ok\";\n}\n",
    );

    let initial = indexer
        .index_and_apply(&source_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(initial.entities_upserted > 0);
    let before_entities = graph.list_all_entities().unwrap();
    let status_before = before_entities
        .iter()
        .find(|entity| entity.name.contains("status"))
        .expect("status entity should exist before session reconcile");
    let behavior_hash_before = status_before.fingerprint.behavior_hash;

    let session_dir = layout.root().join("runs/session-generated-artifacts");
    std::fs::create_dir_all(session_dir.join("src")).unwrap();
    std::fs::create_dir_all(session_dir.join("target")).unwrap();
    std::fs::create_dir_all(session_dir.join("node_modules/pkg")).unwrap();
    std::fs::create_dir_all(session_dir.join("build")).unwrap();
    std::fs::write(
        session_dir.join("src/service.ts"),
        "export function status(): string {\n    return \"ready\";\n}\n",
    )
    .unwrap();
    std::fs::write(session_dir.join("target/output.log"), "compiled output").unwrap();
    std::fs::write(
        session_dir.join("node_modules/pkg/index.js"),
        "module.exports = 'ignore me';\n",
    )
    .unwrap();
    std::fs::write(session_dir.join("build/report.txt"), "generated report").unwrap();

    let summary = reconcile_session_dir(&layout, &session_dir).unwrap();
    assert_eq!(summary.change_count, 1);
    assert_eq!(summary.files_indexed, 1);
    assert_eq!(
        summary.changes,
        vec![("modified".into(), "src/service.ts".into())]
    );

    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/service.ts")).unwrap(),
        "export function status(): string {\n    return \"ready\";\n}\n",
        "reconcile should apply the intended source edit",
    );
    assert!(
        !dir.path().join("target").exists(),
        "target output should not be copied back into the source tree"
    );
    assert!(
        !dir.path().join("node_modules").exists(),
        "node_modules content should not be copied back into the source tree"
    );
    assert!(
        !dir.path().join("build").exists(),
        "build output should not be copied back into the source tree"
    );

    let snapshot = SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
    let graph = snapshot.graph();
    let after_entities = graph.list_all_entities().unwrap();
    let status_after = after_entities
        .iter()
        .find(|entity| entity.name.contains("status"))
        .expect("status entity should still exist after reconcile");
    assert_ne!(
        status_after.fingerprint.behavior_hash, behavior_hash_before,
        "source edits should still update semantic state when generated artifacts are present",
    );
}

// ---------------------------------------------------------------------------
// 50. Session loop: edit -> test -> fix -> reconcile
// ---------------------------------------------------------------------------

#[test]
fn test_session_edit_test_fix_reconcile_loop() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();
    let source_path = write_rust_file(
        dir.path(),
        "src/lib.rs",
        "pub fn status() -> &'static str {\n    \"broken\"\n}\n",
    );
    let check_script = dir.path().join("check.sh");
    std::fs::write(&check_script, "#!/bin/sh\ngrep -q '\"fixed\"' src/lib.rs\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&check_script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&check_script, permissions).unwrap();
    }

    let initial = indexer
        .index_and_apply(&source_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(initial.entities_upserted > 0);
    let before_entities = graph.list_all_entities().unwrap();
    let status_before = before_entities
        .iter()
        .find(|entity| entity.name.contains("status"))
        .expect("status entity should exist before fix loop");
    let behavior_hash_before = status_before.fingerprint.behavior_hash;

    let session_dir = layout.root().join("runs/session-test-fix-loop");
    std::fs::create_dir_all(session_dir.join("src")).unwrap();
    std::fs::write(
        session_dir.join("src/lib.rs"),
        "pub fn status() -> &'static str {\n    \"broken\"\n}\n",
    )
    .unwrap();
    std::fs::write(
        session_dir.join("check.sh"),
        "#!/bin/sh\ngrep -q '\"fixed\"' src/lib.rs\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(session_dir.join("check.sh"))
            .unwrap()
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(session_dir.join("check.sh"), permissions).unwrap();
    }

    let failing = std::process::Command::new("sh")
        .arg("check.sh")
        .current_dir(&session_dir)
        .output()
        .unwrap();
    assert!(
        !failing.status.success(),
        "repo-local check should fail before the session fix"
    );

    std::fs::write(
        session_dir.join("src/lib.rs"),
        "pub fn status() -> &'static str {\n    \"fixed\"\n}\n",
    )
    .unwrap();

    let passing = std::process::Command::new("sh")
        .arg("check.sh")
        .current_dir(&session_dir)
        .output()
        .unwrap();
    assert!(
        passing.status.success(),
        "repo-local check should pass after the session fix"
    );

    let summary = reconcile_session_dir(&layout, &session_dir).unwrap();
    assert_eq!(summary.change_count, 1);
    assert_eq!(summary.files_indexed, 1);
    assert_eq!(
        summary.changes,
        vec![("modified".into(), "src/lib.rs".into())]
    );

    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/lib.rs")).unwrap(),
        "pub fn status() -> &'static str {\n    \"fixed\"\n}\n",
        "reconcile should persist the fixed source back to the repo"
    );

    let snapshot = SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
    let graph = snapshot.graph();
    let after_entities = graph.list_all_entities().unwrap();
    let status_after = after_entities
        .iter()
        .find(|entity| entity.name.contains("status"))
        .expect("status entity should still exist after reconcile");
    assert_ne!(
        status_after.fingerprint.behavior_hash, behavior_hash_before,
        "the successful fix should update semantic state after reconcile",
    );
}

// ---------------------------------------------------------------------------
// 51. Full round-trip works in compat and native modes
// ---------------------------------------------------------------------------

#[test]
fn test_session_round_trip_in_compat_mode() {
    assert_round_trip_in_mode(kin_core::RepoMode::Compat);
}

#[test]
fn test_session_round_trip_in_native_mode() {
    assert_round_trip_in_mode(kin_core::RepoMode::Native);
}

fn assert_round_trip_in_mode(mode: kin_core::RepoMode) {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    kin_core::write_repo_mode(&layout, mode).unwrap();

    let source_root = kin_core::source_dir(&layout);
    std::fs::create_dir_all(source_root.join("src")).unwrap();

    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();
    let source_path = write_rust_file(
        &source_root,
        "src/mode_round_trip.rs",
        "pub fn mode_value() -> &'static str {\n    \"before\"\n}\n",
    );
    let initial = indexer
        .index_and_apply(&source_path, &blob_store, graph.as_ref())
        .unwrap();
    assert!(initial.entities_upserted > 0);

    let before_entities = graph.list_all_entities().unwrap();
    let before = before_entities
        .iter()
        .find(|entity| entity.name.contains("mode_value"))
        .expect("mode_value entity should exist before mode round trip");
    let behavior_hash_before = before.fingerprint.behavior_hash;

    let session_dir = layout
        .root()
        .join("runs")
        .join(format!("session-round-trip-{}", mode.as_str()));
    let workspace = MaterializedWorkspace::create(
        &source_root,
        &session_dir,
        Some(MaterializeStrategy::Copy),
        None,
    )
    .unwrap();

    std::fs::write(
        workspace.root.join("src/mode_round_trip.rs"),
        "pub fn mode_value() -> &'static str {\n    \"after\"\n}\n",
    )
    .unwrap();

    let summary = reconcile_session_dir(&layout, &session_dir).unwrap();
    assert_eq!(summary.change_count, 1);
    assert_eq!(summary.files_indexed, 1);
    assert_eq!(
        summary.changes,
        vec![("modified".into(), "src/mode_round_trip.rs".into())]
    );

    assert_eq!(
        std::fs::read_to_string(source_root.join("src/mode_round_trip.rs")).unwrap(),
        "pub fn mode_value() -> &'static str {\n    \"after\"\n}\n",
        "round trip should persist the edited file back into the mode-specific source root",
    );

    if mode == kin_core::RepoMode::Native {
        assert!(
            !dir.path().join("src/mode_round_trip.rs").exists(),
            "native mode should keep source files under .kin/source-root rather than repo root",
        );
    }

    let snapshot = SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
    let graph = snapshot.graph();
    let after_entities = graph.list_all_entities().unwrap();
    let after = after_entities
        .iter()
        .find(|entity| entity.name.contains("mode_value"))
        .expect("mode_value entity should still exist after round trip");
    assert_ne!(
        after.fingerprint.behavior_hash, behavior_hash_before,
        "round trip should update semantic state in both modes",
    );
}

// ---------------------------------------------------------------------------
// 52. Exec in materialized workspace: verify command runs successfully
// ---------------------------------------------------------------------------

#[test]
fn test_exec_in_workspace() {
    let (dir, _graph, _genesis_id) = init_kin_repo();

    // Write a file that the command can interact with.
    std::fs::write(dir.path().join("data.txt"), "hello from kin").unwrap();

    // Execute a command in a materialized workspace.
    let config = kin_runtime::exec::MaterializeConfig::default();
    let result = kin_runtime::exec::exec_in_workspace(dir.path(), "cat data.txt", &config).unwrap();

    assert_eq!(result.exit_code, 0, "command should succeed");
    assert!(
        result.stdout.contains("hello from kin"),
        "stdout should contain file contents, got: {:?}",
        result.stdout
    );

    // The workspace path should be different from the source.
    assert_ne!(
        result.workspace_path,
        dir.path(),
        "workspace should be a separate directory"
    );

    // Clean up.
    kin_runtime::exec::cleanup_workspace(&result.workspace_path).unwrap();
}

// ---------------------------------------------------------------------------
// 53. Full round-trip: create -> index -> edit -> re-index -> verify identity
// ---------------------------------------------------------------------------

#[test]
fn test_full_mutation_round_trip() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let indexer = kin_index::Indexer::new();

    // Step 1: Create and index a Rust file.
    let rs_content = r#"
pub fn process(input: &str) -> String {
    input.to_uppercase()
}
"#;
    let rs_path = write_rust_file(dir.path(), "src/lib.rs", rs_content);
    indexer
        .index_and_apply(&rs_path, &blob_store, graph.as_ref())
        .unwrap();

    let entities_v1 = graph.list_all_entities().unwrap();
    assert!(
        !entities_v1.is_empty(),
        "should have entities after v1 index"
    );

    // Step 2: Edit the file — add a second function.
    let rs_content_v2 = r#"
pub fn process(input: &str) -> String {
    input.to_uppercase()
}

pub fn validate(input: &str) -> bool {
    !input.is_empty()
}
"#;
    write_rust_file(dir.path(), "src/lib.rs", rs_content_v2);
    indexer
        .index_and_apply(&rs_path, &blob_store, graph.as_ref())
        .unwrap();

    let entities_v2 = graph.list_all_entities().unwrap();
    assert!(
        entities_v2.len() > entities_v1.len(),
        "should have more entities after adding a function (v1={}, v2={})",
        entities_v1.len(),
        entities_v2.len()
    );

    // Step 3: Remove the original function, keep only validate.
    let rs_content_v3 = r#"
pub fn validate(input: &str) -> bool {
    !input.is_empty()
}
"#;
    write_rust_file(dir.path(), "src/lib.rs", rs_content_v3);
    indexer
        .index_and_apply(&rs_path, &blob_store, graph.as_ref())
        .unwrap();

    let entities_v3 = graph.list_all_entities().unwrap();
    let names_v3: Vec<&str> = entities_v3.iter().map(|e| e.name.as_str()).collect();

    // 'process' should be gone, 'validate' should remain.
    assert!(
        !names_v3.iter().any(|n| n.contains("process")),
        "removed function 'process' should be gone from graph, got: {:?}",
        names_v3
    );
    assert!(
        names_v3.iter().any(|n| n.contains("validate")),
        "'validate' should still be in graph, got: {:?}",
        names_v3
    );
}
