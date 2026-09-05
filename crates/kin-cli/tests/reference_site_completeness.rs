// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A reference answer that claims its site list is complete must actually hold
//! every site.
//!
//! `find_references` answered express's `setCharset` with three referencing
//! entities, `reference_sites: 3`, `known_reference_sites: 3`,
//! `reference_sites_complete: true` and verdict `certified`, while
//! `test/utils.js` alone calls it on lines 50, 54, 58, 62 and 66. That file
//! holds exactly one entity, so it was not a per-entity split. Two things
//! produced it, and only the second is fixed here:
//!
//! 1. The site list really was short. The JavaScript adapter reaches
//!    `extract_calls_from_context` only from named-declaration arms of
//!    `extract_js_node` (`kin-parser/src/languages/javascript.rs:1489`), so a
//!    module-level statement records no call edge, and express's tests are
//!    `describe`/`it` at module level. The row that did come back came from
//!    language-server enrichment, which keeps
//!    `CallHierarchyOutgoingCall.from_ranges.first()` and drops the rest
//!    (kin-lsp `src/enrichment.rs:292`). Both are scoped follow-ups.
//! 2. The answer CERTIFIED that short list. `reference_sites_complete` asked
//!    only whether every returned row carried at least one line, which a row
//!    holding one of five satisfies, so a reader could not tell an undercount
//!    from a small repository.
//!
//! So this asserts the invariant rather than either number: an answer either
//! lists every site, or does not claim its site set is complete. It goes red on
//! the flag this fixes and stays green when the two producers above are fixed,
//! because then the five lines are all there.

use std::collections::HashMap;

use kin_db::InMemoryGraph;
use kin_index::linker::{ArtifactIdentityMap, IncrementalLinker};
use kin_index::{
    link_cross_file_incremental_with_completeness, FileParseCompletenessMap, FileParseData,
    IndexPipeline,
};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry, Relation,
    RelationEvidence, RelationId, RelationKind, RelationOrigin, RepoPath, SourceSpan,
    TransactionDelta, TreeDelta, TreeEntry,
};

/// The definition every fixture calls. Written as a plain declaration so the
/// adapter yields a `setCharset` function entity to point `find_references` at.
const DEFS: &str = "function setCharset(type, charset) {\n\
                    \x20 return charset ? type : type;\n\
                    }\n\
                    \n\
                    module.exports = { setCharset };\n";

/// express's `test/utils.js` in miniature: one module entity, five calls at
/// module level, each inside an `it(...)` callback, each on its own line.
const MODULE_LEVEL_CALLER: &str = "var utils = require('../lib/utils');\n\
                                   \n\
                                   describe('the charset helper', function () {\n\
                                   \x20 it('a', function () {\n\
                                   \x20   utils.setCharset();\n\
                                   \x20 });\n\
                                   \n\
                                   \x20 it('b', function () {\n\
                                   \x20   utils.setCharset('text/html');\n\
                                   \x20 });\n\
                                   \n\
                                   \x20 it('c', function () {\n\
                                   \x20   utils.setCharset('text/plain');\n\
                                   \x20 });\n\
                                   \n\
                                   \x20 it('d', function () {\n\
                                   \x20   utils.setCharset('text/xml');\n\
                                   \x20 });\n\
                                   \n\
                                   \x20 it('e', function () {\n\
                                   \x20   utils.setCharset('text/css');\n\
                                   \x20 });\n\
                                   });\n";

/// The same five calls inside a named function, which is the shape the adapter
/// does extract. The positive control: here the graph holds every site, so the
/// answer must both list all five and certify them.
const FUNCTION_LEVEL_CALLER: &str = "var utils = require('../lib/utils');\n\
                                     \n\
                                     function run() {\n\
                                     \x20 utils.setCharset();\n\
                                     \x20 utils.setCharset('text/html');\n\
                                     \x20 utils.setCharset('text/plain');\n\
                                     \x20 utils.setCharset('text/xml');\n\
                                     \x20 utils.setCharset('text/css');\n\
                                     }\n";

const DEFS_PATH: &str = "lib/utils.js";
const CALLER_PATH: &str = "test/utils.js";

/// The 1-based lines the calls are written on, read off the fixture source so
/// editing the fixture cannot leave the expectation behind.
fn call_site_lines(source: &str) -> Vec<u32> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("utils.setCharset("))
        .map(|(index, _)| index as u32 + 1)
        .collect()
}

struct IndexedFile {
    parse: FileParseData,
    entities: Vec<Entity>,
    same_file_relations: Vec<Relation>,
    artifact_id: ArtifactId,
}

fn index_files(caller_source: &str) -> Vec<IndexedFile> {
    let pipeline = IndexPipeline::new();
    [(DEFS_PATH, DEFS), (CALLER_PATH, caller_source)]
        .into_iter()
        .map(|(path, source)| {
            // The file's real content digest, per file, not a shared zero hash.
            // The daemon checks that the digest matches the bytes it indexed, so
            // a placeholder here is a fixture that stops resembling the product
            // the moment that check tightens.
            let blob_hash = kin_blobs::digest(source.as_bytes());
            let indexed = pipeline
                .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), blob_hash)
                .unwrap_or_else(|error| panic!("index {path}: {error}"))
                .indexed_file;
            IndexedFile {
                parse: FileParseData {
                    file_path: path.to_string(),
                    entities: indexed.entities.clone(),
                    relations: indexed.extracted_relations,
                    imports: indexed.imports,
                },
                entities: indexed.entities,
                same_file_relations: indexed.relations,
                artifact_id: ArtifactId::new(),
            }
        })
        .collect()
}

fn link(files: &[IndexedFile]) -> Vec<Relation> {
    let pipeline = IndexPipeline::new();
    let mut artifact_ids = ArtifactIdentityMap::new();
    for file in files {
        artifact_ids.insert(file.parse.file_path.clone(), file.artifact_id);
    }
    let parses: Vec<FileParseData> = files.iter().map(|file| file.parse.clone()).collect();
    pipeline
        .resolve_cross_file(&parses, &artifact_ids)
        .expect("cross-file linking")
}

/// The graph both fixtures are asked, with every entity span removed.
///
/// The non-vacuity control: with no definition line in the graph, any line a
/// reference row reports can only have come from a relation's own evidence.
fn graph_with(files: &[IndexedFile], linked: &[Relation]) -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    for file in files {
        let mut seed = [0u8; 32];
        for (slot, byte) in seed.iter_mut().zip(file.parse.file_path.as_bytes()) {
            *slot = *byte;
        }
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: file.artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(&file.parse.file_path).expect("fixture path is utf-8"),
                        TreeEntry::blob(Hash256::from_bytes(seed), false),
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

fn entity_in<'a>(files: &'a [IndexedFile], path: &str, name: &str) -> &'a Entity {
    files
        .iter()
        .find(|file| file.parse.file_path == path)
        .unwrap_or_else(|| panic!("indexed file {path}"))
        .entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("entity `{name}` in {path}"))
}

async fn find_references(graph: &InMemoryGraph, target: &Entity) -> serde_json::Value {
    let args = HashMap::from([(
        "entity_id".to_string(),
        serde_json::json!(target.id.to_string()),
    )]);
    let response = kin_mcp::handlers::entities::handle_find_references(&args, graph, None)
        .await
        .expect("find_references");
    let kin_mcp::types::ContentBlock::Text { text } = response.content.first().unwrap();
    serde_json::from_str(text).expect("find_references body is json")
}

/// The edge language-server enrichment writes for this caller: one relation for
/// the whole (caller, callee, kind) pair, carrying exactly one site whatever the
/// file holds.
///
/// Built here rather than by running a language server, because the collapse is
/// in what kin-lsp stores, not in what the server answered: `enrich_entity_calls`
/// keeps `call.from_ranges.first()` (kin-lsp `src/enrichment.rs:292`), so this is
/// the shape the graph receives.
fn language_server_call_edge(caller: &Entity, target: &Entity, first_site_line: u32) -> Relation {
    Relation {
        id: RelationId::new(),
        kind: RelationKind::Calls,
        src: GraphNodeId::Entity(caller.id),
        dst: GraphNodeId::Entity(target.id),
        confidence: 0.95,
        origin: RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: vec![RelationEvidence {
            source_span: Some(SourceSpan {
                file: FilePathId::new(CALLER_PATH),
                start_byte: 0,
                end_byte: 1,
                // The graph convention is 0-based; the surface adds one.
                start_line: first_site_line - 1,
                start_col: 0,
                end_line: first_site_line - 1,
                end_col: 1,
            }),
            parser_rule: Some("lsp_call_hierarchy".to_string()),
            ..RelationEvidence::default()
        }],
    }
}

/// The express shape: five call sites in one file with one entity, reachable
/// only through the enrichment edge. The answer must not certify its site set.
#[tokio::test]
async fn a_module_level_caller_reached_only_by_enrichment_does_not_certify_its_sites() {
    let sites = call_site_lines(MODULE_LEVEL_CALLER);
    assert_eq!(
        sites.len(),
        5,
        "the fixture must write five calls on five lines or it does not reproduce GAP-A"
    );

    let files = index_files(MODULE_LEVEL_CALLER);
    let linked = link(&files);
    let graph = graph_with(&files, &linked);

    let target = entity_in(&files, DEFS_PATH, "setCharset").clone();
    let caller = entity_in(&files, CALLER_PATH, "utils").clone();
    graph
        .upsert_relation(&language_server_call_edge(&caller, &target, sites[0]))
        .unwrap();

    let body = find_references(&graph, &target).await;
    let rows = body["references"]
        .as_array()
        .unwrap_or_else(|| panic!("references array: {body:#}"));
    let row = rows
        .iter()
        .find(|row| row["file_path"] == CALLER_PATH)
        .unwrap_or_else(|| panic!("no row for {CALLER_PATH}: {body:#}"));

    let reported: Vec<u32> = row["reference_lines"]
        .as_array()
        .unwrap_or_else(|| panic!("reference_lines array: {row:#}"))
        .iter()
        .map(|line| line.as_u64().expect("a site line is a number") as u32)
        .collect();

    // The invariant, stated once: every site, or no claim of completeness.
    if reported != sites {
        assert_eq!(
            body["counts"]["reference_sites_complete"],
            serde_json::json!(false),
            "the row reports {reported:?} of the five sites at {sites:?}, so the answer must \
             not claim its site set is complete: {body:#}"
        );
        assert_eq!(
            body["counts"]["reference_sites"],
            serde_json::Value::Null,
            "a site total that is only a floor is not emitted as a number: {body:#}"
        );
        assert_eq!(
            row["reference_lines_partial_reason"], "language_server_edge",
            "a row whose sites are a floor must name why: {row:#}"
        );
    }

    // Non-vacuity: the fixture removes entity spans, so any line above came from
    // relation evidence rather than from a definition line.
    assert_eq!(
        row["start_line"],
        serde_json::Value::Null,
        "the fixture removes entity spans on purpose: {row:#}"
    );
    assert!(
        !reported.is_empty(),
        "the enrichment edge carries one site, so the row must not be empty: {row:#}"
    );
}

/// The positive control, and the reason this is not a fix that marks every
/// answer uncertain: the same five calls inside a named function are all
/// recorded by the adapter, and that answer both lists them and certifies them.
#[tokio::test]
async fn a_function_level_caller_lists_every_site_and_certifies_them() {
    let sites = call_site_lines(FUNCTION_LEVEL_CALLER);
    assert_eq!(sites.len(), 5, "the control must also write five calls");

    let files = index_files(FUNCTION_LEVEL_CALLER);
    let linked = link(&files);
    let graph = graph_with(&files, &linked);

    let target = entity_in(&files, DEFS_PATH, "setCharset").clone();
    let body = find_references(&graph, &target).await;
    let rows = body["references"]
        .as_array()
        .unwrap_or_else(|| panic!("references array: {body:#}"));
    let row = rows
        .iter()
        .find(|row| row["name"] == "run")
        .unwrap_or_else(|| panic!("no row for caller `run`: {body:#}"));

    assert_eq!(
        row["reference_lines"],
        serde_json::json!(sites),
        "the adapter records each call site, so every one must be reported: {row:#}"
    );
    assert_eq!(row["reference_line_count"], 5);
    assert_eq!(
        row["reference_lines_partial_reason"],
        serde_json::Value::Null,
        "a parsed row holds every site the parse saw: {row:#}"
    );
    assert_eq!(
        body["counts"]["reference_sites_complete"],
        serde_json::json!(true),
        "a complete site set must still be able to say complete: {body:#}"
    );
}

/// The linker's own incompleteness marker floors the row, and the sites it did
/// record all survive.
///
/// Producer-backed rather than hand-stamped: the completeness map is the
/// linker's input, so passing `ParseCompleteness::Partial` for the caller file
/// makes `call_shape_evidence` emit `call_shape_incomplete_parse_v1` and
/// `relation_evidence` write each call site's span ONTO that marker record.
/// Every byte of the evidence under test is what the real linker produced.
///
/// The shape is the one an origin check cannot see: five real, correct lines
/// beside the producer's own statement that the parse it read them from was not
/// exhaustive. Listing all five and still refusing to certify is the honest
/// answer, and it is what this asserts.
#[tokio::test]
async fn a_recovered_parse_floors_the_row_while_keeping_every_site_it_recorded() {
    let sites = call_site_lines(FUNCTION_LEVEL_CALLER);
    assert_eq!(sites.len(), 5, "the fixture must write five calls");

    let files = index_files(FUNCTION_LEVEL_CALLER);
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.parse.file_path, file.artifact_id, &file.entities);
    }
    // The one input that changes: this file's parse was recovered, not full.
    let completeness: FileParseCompletenessMap = files
        .iter()
        .map(|file| {
            let state = if file.parse.file_path == CALLER_PATH {
                kin_model::ParseCompleteness::Partial("fixture: recovered parse".to_string())
            } else {
                kin_model::ParseCompleteness::Full
            };
            (file.parse.file_path.clone(), state)
        })
        .collect();
    let batch: Vec<FileParseData> = files.iter().map(|file| file.parse.clone()).collect();
    let linked = link_cross_file_incremental_with_completeness(&batch, &linker, &completeness)
        .expect("incremental cross-file linking");
    let graph = graph_with(&files, &linked);

    let target = entity_in(&files, DEFS_PATH, "setCharset").clone();
    let body = find_references(&graph, &target).await;
    let rows = body["references"]
        .as_array()
        .unwrap_or_else(|| panic!("references array: {body:#}"));
    let row = rows
        .iter()
        .find(|row| row["name"] == "run")
        .unwrap_or_else(|| panic!("no row for caller `run`: {body:#}"));

    // Non-vacuity for the fixture itself: if the marker never reached the graph
    // this asserts nothing, so the evidence is read back from the linker's own
    // output rather than assumed.
    let marked = linked.iter().any(|relation| {
        relation.evidence.iter().any(|evidence| {
            evidence.parser_rule.as_deref()
                == Some(kin_index::linker::CALL_SHAPE_EVIDENCE_INCOMPLETE_PARSE_V1)
                && evidence.source_span.is_some()
        })
    });
    assert!(
        marked,
        "the linker must have stamped the incomplete-parse marker onto a spanned record, or \
         this fixture proves nothing"
    );

    assert_eq!(
        row["reference_lines"],
        serde_json::json!(sites),
        "every site the recovered parse did record must still be reported: {row:#}"
    );
    assert_eq!(
        row["reference_lines_partial_reason"], "incomplete_call_evidence",
        "the linker said the parse was short, so the answer must not certify: {row:#}"
    );
    assert_eq!(
        body["counts"]["reference_sites"],
        serde_json::Value::Null,
        "a site total over incomplete evidence is not a number: {body:#}"
    );
    assert_eq!(
        body["counts"]["reference_sites_complete"],
        serde_json::json!(false),
        "{body:#}"
    );
}
