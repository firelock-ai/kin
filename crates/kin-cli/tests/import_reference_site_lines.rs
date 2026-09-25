// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `find_references` names the line an import's NAME is written on.
//!
//! The Study 07 control asked honojs/hono who imports `DEFAULT_STYLE_ID` and
//! got `src/helper/css/index.ts:17` beside `:19`, and `src/jsx/dom/css.ts:13`
//! beside `:15`. Lines 17 and 13 are bare `import {` lines. They carry no
//! occurrence of the name, so a reader cannot read them, jump to them, or
//! rewrite them, and a row that reports both makes the caller check which of
//! the two is real.
//!
//! The cause was one line in the linker: an entity-level import edge cited
//! `FileImport::site`, the whole statement, for every specifier under it.
//! `reference_lines` is served from `RelationEvidence::source_span`
//! (`kin_mcp::handlers::common::relation_reference_lines`), so the statement's
//! first line is exactly what came back.
//!
//! This grades the whole chain on a multi-line TypeScript import: adapter
//! records the specifier's own node, linker cites it, MCP reports it. It runs
//! on BOTH ingest arms, because they are separate code paths that have
//! diverged before: `resolve_cross_file` is the batch arm a `kin init` walks,
//! and `link_cross_file_incremental_with_completeness` is the arm a live
//! reconcile takes on each save.

use std::collections::HashMap;

use kin_db::InMemoryGraph;
use kin_index::linker::{ArtifactIdentityMap, IncrementalLinker};
use kin_index::{
    link_cross_file_incremental_with_completeness, FileParseCompletenessMap, FileParseData,
    IndexPipeline,
};
use kin_model::{
    ArtifactId, Entity, EntityKind, EntityStore, FilePathId, Hash256, LocatedEntry, Relation,
    RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};

const DEFS_PATH: &str = "defs.ts";
const DEFS_SOURCE: &str = "export const DEFAULT_STYLE_ID = 'kin-style'\n";

const CALLER_PATH: &str = "caller.ts";
/// 1: `import {`, 2: the specifier, 3: `} from './defs'`, 6: the use site.
///
/// The name is written on exactly one import line and the statement opens on a
/// different one, which is what makes a row reporting line 1 distinguishable
/// from a row reporting line 2. A second specifier follows it so a builder that
/// gives every specifier under one statement the same span is caught too.
const CALLER_SOURCE: &str = "import {\n\
                             \x20 DEFAULT_STYLE_ID,\n\
                             \x20 OTHER_STYLE_ID,\n\
                             } from './defs'\n\
                             \n\
                             export function render(): string {\n\
                             \x20 return DEFAULT_STYLE_ID + OTHER_STYLE_ID\n\
                             }\n";

/// The 1-based line each name is written on, read off the fixture itself so
/// editing the source cannot leave the expectation behind.
fn line_of(needle: &str) -> u32 {
    CALLER_SOURCE
        .lines()
        .enumerate()
        .find(|(_, line)| line.trim_start().starts_with(needle))
        .map(|(index, _)| index as u32 + 1)
        .unwrap_or_else(|| panic!("the fixture must write {needle:?} at the start of a line"))
}

/// One file's parse, kept in the shape both linker arms take.
struct IndexedFixtureFile {
    parse: FileParseData,
    entities: Vec<Entity>,
    same_file_relations: Vec<Relation>,
    artifact_id: ArtifactId,
    blob_hash: Hash256,
}

fn index_files() -> Vec<IndexedFixtureFile> {
    let pipeline = IndexPipeline::new();
    [
        (
            DEFS_PATH,
            format!("{DEFS_SOURCE}export const OTHER_STYLE_ID = 'kin-other'\n"),
        ),
        (CALLER_PATH, CALLER_SOURCE.to_string()),
    ]
    .into_iter()
    .map(|(path, source)| {
        let blob_hash = kin_blobs::digest(source.as_bytes());
        let indexed = pipeline
            .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), blob_hash)
            .unwrap_or_else(|error| panic!("index {path}: {error}"))
            .indexed_file;
        IndexedFixtureFile {
            parse: FileParseData {
                file_path: path.to_string(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            },
            entities: indexed.entities,
            same_file_relations: indexed.relations,
            artifact_id: ArtifactId::new(),
            blob_hash,
        }
    })
    .collect()
}

fn completeness_of(files: &[IndexedFixtureFile]) -> FileParseCompletenessMap {
    files
        .iter()
        .map(|file| {
            (
                file.parse.file_path.clone(),
                kin_model::ParseCompleteness::Full,
            )
        })
        .collect()
}

/// The batch arm, which is what a `kin init` walk runs.
fn link_batch(files: &[IndexedFixtureFile]) -> Vec<Relation> {
    let pipeline = IndexPipeline::new();
    let mut artifact_ids = ArtifactIdentityMap::new();
    for file in files {
        artifact_ids.insert(file.parse.file_path.clone(), file.artifact_id);
    }
    let parses: Vec<FileParseData> = files.iter().map(|file| file.parse.clone()).collect();
    pipeline
        .resolve_cross_file(&parses, &artifact_ids)
        .expect("batch cross-file linking")
}

/// The live arm, which is what `kin_reconcile::cross_file` drives on each save.
fn link_incremental(files: &[IndexedFixtureFile]) -> Vec<Relation> {
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.parse.file_path, file.artifact_id, &file.entities);
    }
    let completeness = completeness_of(files);
    let batch: Vec<FileParseData> = files.iter().map(|file| file.parse.clone()).collect();
    link_cross_file_incremental_with_completeness(&batch, &linker, &completeness)
        .expect("incremental cross-file linking")
}

/// The graph both surfaces are asked, with every entity span deliberately
/// removed.
///
/// That is the non-vacuity control. With no entity span in the graph there is
/// no definition line for a row to have copied, so any line it carries can only
/// have come from the relation's own evidence.
fn graph_with(files: &[IndexedFixtureFile], linked: &[Relation]) -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    for file in files {
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: file.artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(&file.parse.file_path).expect("fixture path is utf-8"),
                        TreeEntry::blob(file.blob_hash, false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .expect("admit fixture artifact");
    }
    for file in files {
        for entity in &file.entities {
            let mut entity = entity.clone();
            entity.span = None;
            graph.upsert_entity(&entity).unwrap();
        }
        for relation in &file.same_file_relations {
            graph.upsert_relation(relation).unwrap();
        }
    }
    for relation in linked {
        graph.upsert_relation(relation).unwrap();
    }
    graph
}

async fn find_import_references(graph: &InMemoryGraph, target: &Entity) -> serde_json::Value {
    let args = HashMap::from([
        (
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        ),
        ("relation_kinds".to_string(), serde_json::json!(["imports"])),
    ]);
    let response = kin_mcp::handlers::entities::handle_find_references(&args, graph, None)
        .await
        .expect("find_references");
    let kin_mcp::types::ContentBlock::Text { text } = response.content.first().unwrap();
    serde_json::from_str(text).expect("find_references body is json")
}

#[tokio::test]
async fn an_import_row_names_the_specifier_line_not_the_statement_line() {
    let specifier_line = line_of("DEFAULT_STYLE_ID,");
    let statement_line = line_of("import {");
    assert_ne!(
        specifier_line, statement_line,
        "the fixture must put the name on a line of its own or it grades nothing"
    );

    for (arm, link) in [
        (
            "batch",
            link_batch as fn(&[IndexedFixtureFile]) -> Vec<Relation>,
        ),
        ("incremental", link_incremental),
    ] {
        let files = index_files();
        let linked = link(&files);
        let graph = graph_with(&files, &linked);

        let target = files
            .iter()
            .flat_map(|file| file.entities.iter())
            .find(|entity| entity.name == "DEFAULT_STYLE_ID")
            .unwrap_or_else(|| panic!("{arm}: no `DEFAULT_STYLE_ID` entity"))
            .clone();

        // The importing file's module surface, which is the entity an
        // entity-level import edge is sourced at.
        let importer = files
            .iter()
            .find(|file| file.parse.file_path == CALLER_PATH)
            .expect("the caller file")
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Module)
            .unwrap_or_else(|| panic!("{arm}: the caller file has no module entity"))
            .clone();

        let body = find_import_references(&graph, &target).await;
        let rows = body["references"]
            .as_array()
            .unwrap_or_else(|| panic!("{arm}: `references` array: {body:#}"));
        let row = rows
            .iter()
            .find(|row| row["name"] == serde_json::json!(importer.name))
            .unwrap_or_else(|| {
                panic!(
                    "{arm}: no import row for the caller's module `{}`: {body:#}",
                    importer.name
                )
            });

        assert_eq!(
            row["reference_lines"],
            serde_json::json!([specifier_line]),
            "{arm}: the row must name line {specifier_line}, where `DEFAULT_STYLE_ID` is \
             written, and nothing else: {row:#}"
        );
        assert!(
            !row["reference_lines"]
                .as_array()
                .expect("reference_lines is an array")
                .contains(&serde_json::json!(statement_line)),
            "{arm}: line {statement_line} carries a bare `import {{` and no occurrence of the \
             name; reporting it is the defect: {row:#}"
        );
        assert_eq!(
            row["reference_line_count"],
            serde_json::json!(1),
            "{arm}: one specifier binds the name once: {row:#}"
        );
        assert_eq!(
            row["reference_lines_absent_reason"],
            serde_json::Value::Null,
            "{arm}: a row that HAS a site must claim no absence: {row:#}"
        );
        // Non-vacuity: the fixture strips entity spans, so the number above
        // came from the relation's evidence or from nowhere.
        assert_eq!(
            row["start_line"],
            serde_json::Value::Null,
            "{arm}: the fixture removes entity spans on purpose: {row:#}"
        );
    }
}

/// The falsification, as a standing guard.
///
/// Reverting the linker to cite `FileImport::site` makes both rows above
/// report line 1, the bare `import {`. This says that outright, over every
/// import row the fixture produces on both arms, so the regression is caught
/// by a case whose name says what went wrong rather than by an equality that
/// happens to move.
#[tokio::test]
async fn no_import_row_ever_names_the_statement_line() {
    let statement_line = line_of("import {");

    for (arm, link) in [
        (
            "batch",
            link_batch as fn(&[IndexedFixtureFile]) -> Vec<Relation>,
        ),
        ("incremental", link_incremental),
    ] {
        let files = index_files();
        let linked = link(&files);
        let graph = graph_with(&files, &linked);

        let mut checked = 0_usize;
        for name in ["DEFAULT_STYLE_ID", "OTHER_STYLE_ID"] {
            let target = files
                .iter()
                .flat_map(|file| file.entities.iter())
                .find(|entity| entity.name == name)
                .unwrap_or_else(|| panic!("{arm}: no `{name}` entity"))
                .clone();
            let body = find_import_references(&graph, &target).await;
            for row in body["references"]
                .as_array()
                .unwrap_or_else(|| panic!("{arm}: `references` array: {body:#}"))
            {
                let lines = row["reference_lines"]
                    .as_array()
                    .expect("reference_lines is an array");
                assert!(
                    !lines.contains(&serde_json::json!(statement_line)),
                    "{arm}: the row for `{name}` names line {statement_line}, which carries a \
                     bare `import {{` and no occurrence of any imported name: {row:#}"
                );
                checked += lines.len();
            }
        }
        assert!(
            checked > 0,
            "{arm}: no line was checked at all, which is what this guard looks like when the \
             fixture stops producing import rows"
        );
    }
}

/// A single-line import still reports its own line.
///
/// The fix moves an edge's evidence off the statement and onto the specifier.
/// On a one-line import the two sit on the same line, so this is the case that
/// would break silently if the specifier span were recorded against the wrong
/// node or dropped.
#[tokio::test]
async fn a_single_line_import_reports_the_line_it_is_written_on() {
    const SINGLE_LINE_CALLER: &str = "import { DEFAULT_STYLE_ID } from './defs'\n\
                                      \n\
                                      export function render(): string {\n\
                                      \x20 return DEFAULT_STYLE_ID\n\
                                      }\n";

    let pipeline = IndexPipeline::new();
    let defs_source = format!("{DEFS_SOURCE}export const OTHER_STYLE_ID = 'kin-other'\n");
    let files: Vec<IndexedFixtureFile> = [
        (DEFS_PATH, defs_source.as_str()),
        (CALLER_PATH, SINGLE_LINE_CALLER),
    ]
    .into_iter()
    .map(|(path, source)| {
        let blob_hash = kin_blobs::digest(source.as_bytes());
        let indexed = pipeline
            .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), blob_hash)
            .unwrap_or_else(|error| panic!("index {path}: {error}"))
            .indexed_file;
        IndexedFixtureFile {
            parse: FileParseData {
                file_path: path.to_string(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            },
            entities: indexed.entities,
            same_file_relations: indexed.relations,
            artifact_id: ArtifactId::new(),
            blob_hash,
        }
    })
    .collect();

    let linked = link_batch(&files);
    let graph = graph_with(&files, &linked);
    let target = files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == "DEFAULT_STYLE_ID")
        .expect("no `DEFAULT_STYLE_ID` entity")
        .clone();
    let importer = files
        .iter()
        .find(|file| file.parse.file_path == CALLER_PATH)
        .expect("the caller file")
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Module)
        .expect("the caller file has no module entity")
        .clone();

    let body = find_import_references(&graph, &target).await;
    let row = body["references"]
        .as_array()
        .unwrap_or_else(|| panic!("`references` array: {body:#}"))
        .iter()
        .find(|row| row["name"] == serde_json::json!(importer.name))
        .unwrap_or_else(|| panic!("no import row for `{}`: {body:#}", importer.name));

    assert_eq!(
        row["reference_lines"],
        serde_json::json!([1]),
        "the whole import is written on line 1, so the specifier's line is line 1: {row:#}"
    );
}

/// Two specifiers under one statement do not collapse onto one line.
///
/// A builder that cites the statement for every specifier passes any check that
/// looks at a single name, because a one-specifier import's statement line and
/// specifier line can be made to agree. Asking the SECOND name of the same
/// statement is what separates "cites the specifier" from "cites the
/// statement".
#[tokio::test]
async fn the_second_specifier_of_one_statement_reports_its_own_line() {
    let second_line = line_of("OTHER_STYLE_ID,");
    let first_line = line_of("DEFAULT_STYLE_ID,");
    assert_ne!(first_line, second_line);

    let files = index_files();
    let linked = link_batch(&files);
    let graph = graph_with(&files, &linked);

    let target = files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == "OTHER_STYLE_ID")
        .expect("no `OTHER_STYLE_ID` entity")
        .clone();
    let importer = files
        .iter()
        .find(|file| file.parse.file_path == CALLER_PATH)
        .expect("the caller file")
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::Module)
        .expect("the caller file has no module entity")
        .clone();

    let body = find_import_references(&graph, &target).await;
    let rows = body["references"]
        .as_array()
        .unwrap_or_else(|| panic!("`references` array: {body:#}"));
    let row = rows
        .iter()
        .find(|row| row["name"] == serde_json::json!(importer.name))
        .unwrap_or_else(|| panic!("no import row for `{}`: {body:#}", importer.name));

    assert_eq!(
        row["reference_lines"],
        serde_json::json!([second_line]),
        "the second specifier is written on line {second_line}, not on line {first_line} and \
         not on the statement's: {row:#}"
    );
}
