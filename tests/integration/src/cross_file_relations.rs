// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration tests for cross-file relation extraction and linking.
//!
//! These tests verify end-to-end functionality:
//! 1. TypeScript parser extracts calls and imports
//! 2. Indexing pipeline collects unresolved cross-file relations
//! 3. CrossFileLinker resolves calls by name matching

use kin_blobs::BlobStore;
use kin_index::{link_cross_file, FileParseData, IndexPipeline};
use kin_model::*;
use kin_parser::ExtractedRelation;

use crate::helpers::*;

// -----------------------------------------------------------------------
// Cross-File Call Relations
// -----------------------------------------------------------------------

#[test]
fn extract_cross_file_calls_in_typescript() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    // Write utils.ts with a helper function
    let utils_path = dir.path().join("utils.ts");
    std::fs::write(
        &utils_path,
        r#"export function formatMessage(msg: string): string {
    return msg.toUpperCase();
}"#,
    )
    .unwrap();

    // Write main.ts that calls the helper
    let main_path = dir.path().join("main.ts");
    std::fs::write(
        &main_path,
        r#"import { formatMessage } from './utils';

export function sayHello(name: string): void {
    const message = formatMessage(`Hello ${name}`);
    console.log(message);
}"#,
    )
    .unwrap();

    // Index both files
    let utils_indexed = pipeline.index_file(&utils_path, &blob_store).unwrap();
    let main_indexed = pipeline.index_file(&main_path, &blob_store).unwrap();

    // utils.ts should have the formatMessage entity
    assert_eq!(utils_indexed.entities.len(), 1);
    assert_eq!(utils_indexed.entities[0].name, "formatMessage");

    // main.ts should have sayHello and an import
    assert_eq!(main_indexed.entities.len(), 1);
    assert_eq!(main_indexed.entities[0].name, "sayHello");

    // Verify that the call to formatMessage is unresolved (cross-file)
    assert!(!main_indexed.unresolved_relations.is_empty());

    // Find the Calls relation to formatMessage
    let calls = main_indexed
        .unresolved_relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.dst_name.contains("format"))
        .collect::<Vec<_>>();
    assert!(
        !calls.is_empty(),
        "Should have unresolved call to formatMessage"
    );
}

#[test]
fn link_cross_file_calls_after_indexing() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    // Write utils.ts
    let utils_path = dir.path().join("utils.ts");
    std::fs::write(
        &utils_path,
        r#"export function helperFunc(): void {
    console.log("Helper");
}"#,
    )
    .unwrap();

    // Write main.ts that calls helper
    let main_path = dir.path().join("main.ts");
    std::fs::write(
        &main_path,
        r#"export function mainFunc(): void {
    helperFunc();
}"#,
    )
    .unwrap();

    // Index and store both files
    let utils_idx = pipeline.index_file(&utils_path, &blob_store).unwrap();
    let main_idx = pipeline.index_file(&main_path, &blob_store).unwrap();

    // Store entities in graph
    for entity in &utils_idx.entities {
        graph.upsert_entity(entity).unwrap();
    }
    for entity in &main_idx.entities {
        graph.upsert_entity(entity).unwrap();
    }

    // Store resolved relations
    for relation in &utils_idx.relations {
        graph.upsert_relation(relation).unwrap();
    }
    for relation in &main_idx.relations {
        graph.upsert_relation(relation).unwrap();
    }

    // Build FileParseData from indexed results for cross-file linking.
    // Reconstruct ExtractedRelations from unresolved relations so the linker
    // can match them across files.
    let files: Vec<FileParseData> = vec![
        FileParseData {
            file_path: utils_idx.file_id.0.clone(),
            parse_completeness: kin_model::ParseCompleteness::Full,
            entities: utils_idx.entities.clone(),
            relations: vec![],
            imports: vec![],
        },
        FileParseData {
            file_path: main_idx.file_id.0.clone(),
            parse_completeness: kin_model::ParseCompleteness::Full,
            entities: main_idx.entities.clone(),
            relations: main_idx
                .unresolved_relations
                .iter()
                .map(|u| ExtractedRelation {
                    call_shape: None,
                    kind: u.kind,
                    src_name: main_idx
                        .entities
                        .iter()
                        .find(|e| e.id == u.src_entity_id)
                        .map(|e| e.name.clone())
                        .unwrap_or_default(),
                    dst_name: u.dst_name.clone(),
                    import_source: None,
                })
                .collect(),
            imports: vec![],
        },
    ];

    let resolved = link_cross_file(&files);

    assert!(
        !resolved.is_empty(),
        "Should have resolved at least one cross-file call"
    );

    // All resolved should be Calls relations
    assert!(
        resolved.iter().all(|r| r.kind == RelationKind::Calls),
        "All resolved relations should be Calls"
    );
}

// -----------------------------------------------------------------------
// Partial Resolution Tracking
// -----------------------------------------------------------------------

#[test]
fn track_partially_resolved_relations() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    // Create two files where one function calls another
    let utils_path = dir.path().join("utils.ts");
    std::fs::write(
        &utils_path,
        r#"export function utilsFunc(): void {
    console.log("Utils");
}"#,
    )
    .unwrap();

    let main_path = dir.path().join("main.ts");
    std::fs::write(
        &main_path,
        r#"export function mainFunc(): void {
    utilsFunc();
}"#,
    )
    .unwrap();

    // Index both files
    let utils_idx = pipeline.index_file(&utils_path, &blob_store).unwrap();
    let main_idx = pipeline.index_file(&main_path, &blob_store).unwrap();

    // Store all entities in graph
    for entity in &utils_idx.entities {
        graph.upsert_entity(entity).unwrap();
    }
    for entity in &main_idx.entities {
        graph.upsert_entity(entity).unwrap();
    }

    // Main file should have unresolved relations (calls to utilsFunc from utils.ts)
    assert!(
        !main_idx.unresolved_relations.is_empty(),
        "Should have unresolved relations from cross-file calls"
    );

    // All unresolved should have the calling function's EntityId
    for unresolved in &main_idx.unresolved_relations {
        assert_ne!(
            unresolved.src_entity_id,
            EntityId::default(),
            "Should have resolved src entity ID"
        );
        assert!(!unresolved.dst_name.is_empty(), "Should have dst name");
    }
}

// -----------------------------------------------------------------------
// End-to-End Multi-File Scenario
// -----------------------------------------------------------------------

#[test]
fn end_to_end_multi_file_cross_file_relations() {
    let (dir, graph, _genesis_id) = init_kin_repo();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    // Create a small TypeScript project
    //
    // math.ts:
    //   - multiply(a, b)
    //   - divide(a, b)
    //
    // calculator.ts:
    //   - calculate() calls multiply and divide
    //
    // main.ts:
    //   - run() calls calculate

    let math_path = dir.path().join("math.ts");
    std::fs::write(
        &math_path,
        r#"export function multiply(a: number, b: number): number {
    return a * b;
}

export function divide(a: number, b: number): number {
    return a / b;
}"#,
    )
    .unwrap();

    let calc_path = dir.path().join("calculator.ts");
    std::fs::write(
        &calc_path,
        r#"export function calculate(x: number, y: number): number {
    const product = multiply(x, y);
    const quotient = divide(x, y);
    return product + quotient;
}"#,
    )
    .unwrap();

    let main_path = dir.path().join("main.ts");
    std::fs::write(
        &main_path,
        r#"export function run(): void {
    const result = calculate(10, 2);
    console.log(result);
}"#,
    )
    .unwrap();

    // Index all files
    let math_indexed = pipeline.index_file(&math_path, &blob_store).unwrap();
    let calc_indexed = pipeline.index_file(&calc_path, &blob_store).unwrap();
    let main_indexed = pipeline.index_file(&main_path, &blob_store).unwrap();

    // Store all entities
    for idx in [&math_indexed, &calc_indexed, &main_indexed] {
        for entity in &idx.entities {
            graph.upsert_entity(entity).unwrap();
        }
    }

    // Store resolved relations
    for idx in [&math_indexed, &calc_indexed, &main_indexed] {
        for relation in &idx.relations {
            graph.upsert_relation(relation).unwrap();
        }
    }

    // Build FileParseData from indexed results for cross-file linking.
    let indexed_files = [&math_indexed, &calc_indexed, &main_indexed];
    let file_parse_data: Vec<FileParseData> = indexed_files
        .iter()
        .map(|idx| FileParseData {
            file_path: idx.file_id.0.clone(),
            parse_completeness: kin_model::ParseCompleteness::Full,
            entities: idx.entities.clone(),
            relations: idx
                .unresolved_relations
                .iter()
                .map(|u| ExtractedRelation {
                    call_shape: None,
                    kind: u.kind,
                    src_name: idx
                        .entities
                        .iter()
                        .find(|e| e.id == u.src_entity_id)
                        .map(|e| e.name.clone())
                        .unwrap_or_default(),
                    dst_name: u.dst_name.clone(),
                    import_source: None,
                })
                .collect(),
            imports: vec![],
        })
        .collect();

    let resolved = link_cross_file(&file_parse_data);

    // Verify we have resolved outcomes for the cross-file calls:
    // - calculate() calls multiply and divide
    // - run() calls calculate
    assert!(
        resolved.len() >= 2,
        "Should resolve at least 2 cross-file calls (got {})",
        resolved.len()
    );

    // All should be Calls relations
    assert!(
        resolved.iter().all(|r| r.kind == RelationKind::Calls),
        "All resolved relations should be Calls"
    );

    // All should have reasonable confidence from linker
    assert!(
        resolved.iter().all(|r| r.confidence >= 0.5),
        "All should have reasonable confidence from linker"
    );
}
