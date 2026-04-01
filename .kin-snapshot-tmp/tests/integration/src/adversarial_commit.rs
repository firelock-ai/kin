// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Adversarial commit-path tests.
//!
//! These tests verify that the commit pipeline handles edge cases gracefully:
//! broken ASTs, empty files, binary content, extreme paths, unicode names,
//! and mixed add+remove operations.

use kin_blobs::BlobStore;
use kin_index::{FileClassification, FileClassifier, IndexPipeline};
use kin_model::*;

use crate::helpers::*;

// -----------------------------------------------------------------------
// 1. Broken AST: syntax errors should not corrupt the graph
// -----------------------------------------------------------------------

#[test]
fn commit_with_broken_ast_does_not_corrupt_graph() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // First, index a valid file so the graph has entities.
    let valid_ts = r#"export function greet(name: string): string {
    return `Hello, ${name}!`;
}
"#;
    let valid_path = write_ts_file(dir.path(), "src/greet.ts", valid_ts);
    let indexed = pipeline.index_file(&valid_path, &blob_store).unwrap();
    assert!(matches!(indexed.parse_state, ParseState::Valid));
    for entity in &indexed.entities {
        graph.upsert_entity(entity).unwrap();
    }
    let entity_count_before = graph.list_all_entities().unwrap().len();
    assert!(entity_count_before > 0, "should have entities from valid file");

    // Now write a file with broken syntax.
    let broken_ts = r#"export function broken( {
    // Missing closing paren and brace
    return 42
"#;
    let broken_path = write_ts_file(dir.path(), "src/broken.ts", broken_ts);
    let broken_result = pipeline.index_file(&broken_path, &blob_store).unwrap();

    // The pipeline should produce an Incomplete parse state.
    assert!(
        matches!(broken_result.parse_state, ParseState::Incomplete { .. }),
        "broken AST should produce Incomplete parse state, got {:?}",
        broken_result.parse_state
    );

    // Apply using the overlay — LKG enforcement should skip the broken file.
    let apply_result = kin_index::apply_to_graph(&*graph, &broken_result).unwrap();
    assert!(
        apply_result.skipped_lkg,
        "broken AST should be skipped (LKG preserved)"
    );

    // Verify original entities are still intact.
    let entity_count_after = graph.list_all_entities().unwrap().len();
    assert_eq!(
        entity_count_before, entity_count_after,
        "entity count should not change after broken AST commit attempt"
    );
}

// -----------------------------------------------------------------------
// 2. Empty file: should not panic
// -----------------------------------------------------------------------

#[test]
fn commit_with_empty_file_does_not_panic() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Write an empty TypeScript file.
    let empty_path = write_ts_file(dir.path(), "src/empty.ts", "");
    let result = pipeline.index_file(&empty_path, &blob_store).unwrap();

    // Should produce zero entities but not panic.
    assert_eq!(result.entities.len(), 0, "empty file should produce zero entities");
    assert!(
        matches!(result.parse_state, ParseState::Valid),
        "empty file should parse as valid (empty AST)"
    );
}

#[test]
fn commit_with_whitespace_only_file_does_not_panic() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    let ws_path = write_ts_file(dir.path(), "src/whitespace.ts", "   \n\n   \n  \t  \n");
    let result = pipeline.index_file(&ws_path, &blob_store).unwrap();
    assert_eq!(result.entities.len(), 0);
}

// -----------------------------------------------------------------------
// 3. Binary file: should classify as artifact, not parse
// -----------------------------------------------------------------------

#[test]
fn binary_file_classified_as_opaque_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let binary_path = dir.path().join("image.png");
    // Write some binary content (PNG header + garbage).
    let binary_content: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG header
        0x00, 0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03,
    ];
    std::fs::write(&binary_path, &binary_content).unwrap();

    let classification = FileClassifier::classify(&binary_path);
    assert!(
        matches!(classification, FileClassification::OpaqueArtifact { .. }),
        "binary file should be classified as OpaqueArtifact, got {:?}",
        classification
    );
}

#[test]
fn binary_file_in_source_dir_indexed_as_opaque() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Write a binary file with a non-source extension.
    let binary_path = dir.path().join("src/data.bin");
    std::fs::create_dir_all(binary_path.parent().unwrap()).unwrap();
    std::fs::write(&binary_path, &[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]).unwrap();

    let result = pipeline.index_any_file(&binary_path, &blob_store).unwrap();
    assert!(
        matches!(result, kin_index::IndexedAny::OpaqueArtifact(_)),
        "binary file should be indexed as OpaqueArtifact"
    );
}

// -----------------------------------------------------------------------
// 4. Long file names / deep paths
// -----------------------------------------------------------------------

#[test]
fn commit_with_long_file_name() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Create a file with a very long name (200+ characters).
    let long_name = format!("src/{}.ts", "a".repeat(200));
    let content = "export function longNameFile(): void { }";
    let path = write_ts_file(dir.path(), &long_name, content);

    let result = pipeline.index_file(&path, &blob_store).unwrap();
    assert!(
        !result.entities.is_empty(),
        "should extract entities from file with long name"
    );
}

#[test]
fn commit_with_deeply_nested_path() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Create a deeply nested file (10 levels).
    let deep_path = "a/b/c/d/e/f/g/h/i/j/deep.ts";
    let content = "export function deeplyNested(): number { return 42; }";
    let path = write_ts_file(dir.path(), deep_path, content);

    let result = pipeline.index_file(&path, &blob_store).unwrap();
    assert!(
        !result.entities.is_empty(),
        "should extract entities from deeply nested file"
    );
    assert_eq!(result.entities[0].name, "deeplyNested");
}

// -----------------------------------------------------------------------
// 5. Unicode in entity names
// -----------------------------------------------------------------------

#[test]
fn commit_with_unicode_entity_names() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Python allows unicode identifiers.
    let py_content = r#"def grüße(name):
    return f"Hallo, {name}!"

def 挨拶(名前):
    return f"こんにちは、{名前}！"
"#;
    let py_path = dir.path().join("src/unicode.py");
    std::fs::create_dir_all(py_path.parent().unwrap()).unwrap();
    std::fs::write(&py_path, py_content).unwrap();

    let result = pipeline.index_file(&py_path, &blob_store).unwrap();

    // Should parse without panic. The exact entities depend on tree-sitter
    // support for unicode identifiers, but at minimum it should not crash.
    assert!(
        matches!(result.parse_state, ParseState::Valid | ParseState::Incomplete { .. }),
        "unicode file should parse without panic"
    );

    // If entities were extracted, verify they can be stored in the graph.
    for entity in &result.entities {
        graph.upsert_entity(entity).unwrap();
    }
}

#[test]
fn commit_with_unicode_file_path() {
    let (dir, _graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // File with unicode in path name.
    let path = dir.path().join("src/données/traitement.py");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "def process():\n    return 1\n").unwrap();

    let result = pipeline.index_file(&path, &blob_store).unwrap();
    assert_eq!(result.entities.len(), 1);
    assert_eq!(result.entities[0].name, "process");
}

// -----------------------------------------------------------------------
// 6. Files added and removed in same commit
// -----------------------------------------------------------------------

#[test]
fn add_and_remove_files_in_same_index_cycle() {
    let (dir, graph, genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Step 1: Index an initial file using relative path normalization.
    let initial_content = "export function original(): void { }";
    let initial_path = write_ts_file(dir.path(), "src/original.ts", initial_content);
    let indexed = pipeline.index_file_relative(&initial_path, &blob_store, dir.path()).unwrap();
    for entity in &indexed.entities {
        graph.upsert_entity(entity).unwrap();
    }
    let original_entity_id = indexed.entities[0].id;
    let original_file_id = indexed.file_id.clone();

    // Verify entity exists.
    let original = graph.get_entity(&original_entity_id).unwrap();
    assert!(original.is_some(), "original entity should exist");

    // Step 2: Remove the file.
    std::fs::remove_file(&initial_path).unwrap();
    let removal_result = kin_index::apply_file_removal(&*graph, &original_file_id).unwrap();
    assert_eq!(removal_result.entities_removed, 1);

    // Step 3: Add a new file in the same cycle.
    let new_content = "export function replacement(): string { return 'new'; }";
    let new_path = write_ts_file(dir.path(), "src/replacement.ts", new_content);
    let new_indexed = pipeline.index_file(&new_path, &blob_store).unwrap();
    for entity in &new_indexed.entities {
        graph.upsert_entity(entity).unwrap();
    }

    // Verify: old entity gone, new entity present.
    let old_entity = graph.get_entity(&original_entity_id).unwrap();
    assert!(old_entity.is_none(), "original entity should be removed");

    let all_entities = graph.list_all_entities().unwrap();
    let new_names: Vec<&str> = all_entities.iter().map(|e| e.name.as_str()).collect();
    assert!(
        new_names.contains(&"replacement"),
        "new entity should be present, got {:?}",
        new_names
    );
    assert!(
        !new_names.contains(&"original"),
        "original entity should not be present"
    );
}

// -----------------------------------------------------------------------
// 7. Parse failure mid-batch does not leave partial entities
// -----------------------------------------------------------------------

#[test]
fn partial_parse_failure_does_not_leave_stale_entities() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Index a valid file first.
    let valid_content = "export function stable(): void { }";
    let valid_path = write_ts_file(dir.path(), "src/stable.ts", valid_content);
    let valid_indexed = pipeline.index_file(&valid_path, &blob_store).unwrap();
    for entity in &valid_indexed.entities {
        graph.upsert_entity(entity).unwrap();
    }

    let count_before = graph.list_all_entities().unwrap().len();

    // Try to index a broken file — LKG should prevent graph corruption.
    let broken_content = "export function { broken syntax here !!!";
    let broken_path = write_ts_file(dir.path(), "src/broken.ts", broken_content);
    let broken_indexed = pipeline.index_file(&broken_path, &blob_store).unwrap();

    if matches!(broken_indexed.parse_state, ParseState::Incomplete { .. }) {
        let apply_result = kin_index::apply_to_graph(&*graph, &broken_indexed).unwrap();
        assert!(apply_result.skipped_lkg, "broken parse should be skipped");
    }

    // Entity count should not have changed.
    let count_after = graph.list_all_entities().unwrap().len();
    assert_eq!(
        count_before, count_after,
        "entity count should be stable after partial failure"
    );
}

// -----------------------------------------------------------------------
// 8. File with no extension: should not crash the pipeline
// -----------------------------------------------------------------------

#[test]
fn file_with_no_extension_classified_as_opaque() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Makefile.bak");
    std::fs::write(&path, "all:\n\t@echo hello\n").unwrap();

    // No extension should be handled gracefully.
    let no_ext_path = dir.path().join("CHANGES");
    std::fs::write(&no_ext_path, "v1.0 - initial release\n").unwrap();

    let classification = FileClassifier::classify(&no_ext_path);
    assert!(
        matches!(classification, FileClassification::OpaqueArtifact { .. }),
        "file with no extension should be opaque"
    );
}

// -----------------------------------------------------------------------
// 9. Very large entity count in a single file
// -----------------------------------------------------------------------

#[test]
fn commit_with_many_entities_in_single_file() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let blob_store = BlobStore::new(layout.objects_dir()).unwrap();
    let pipeline = IndexPipeline::new();

    // Generate a TypeScript file with 100 functions.
    let mut content = String::new();
    for i in 0..100 {
        content.push_str(&format!(
            "export function func_{i}(): number {{ return {i}; }}\n\n"
        ));
    }
    let path = write_ts_file(dir.path(), "src/many_functions.ts", &content);

    let result = pipeline.index_file(&path, &blob_store).unwrap();
    assert!(
        matches!(result.parse_state, ParseState::Valid),
        "large file should parse as valid"
    );
    assert!(
        result.entities.len() >= 50,
        "should extract many entities, got {}",
        result.entities.len()
    );

    // Store all in graph.
    for entity in &result.entities {
        graph.upsert_entity(entity).unwrap();
    }

    let all = graph.list_all_entities().unwrap();
    assert!(
        all.len() >= 50,
        "graph should contain many entities, got {}",
        all.len()
    );
}
