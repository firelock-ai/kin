// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A reference row must say WHERE the reference is, not only who made it.
//!
//! `find_references` served `reference_lines` from
//! `RelationEvidence::source_span` from the day the field existed, and no
//! producer ever set it: `kin_parser::ExtractedRelation` carried no span, so an
//! adapter that had the call node in hand could not hand its position to the
//! resolver. Every row on every language came back with an empty
//! `reference_lines` and `reference_lines_absent_reason: "no_evidence_span"`,
//! which is why a stranger asking "who calls this, and where" got entities and
//! files from Kin and then ran grep for the lines (FIR-1825).
//!
//! This asserts the whole chain on the two languages that lost those A/B tasks:
//! adapter records the call site, linker turns it into a span under the
//! caller's file, MCP and CLI both report it. It runs on BOTH ingest arms,
//! because they are separate code paths that have diverged before (kin#870):
//! `resolve_cross_file` is the batch arm a `kin init` walks, and
//! `link_cross_file_incremental_with_completeness` is the arm a live reconcile
//! takes on each save.

use std::collections::HashMap;

use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_db::InMemoryGraph;
use kin_index::linker::{ArtifactIdentityMap, IncrementalLinker};
use kin_index::{
    link_cross_file_incremental_with_completeness, FileParseCompletenessMap, FileParseData,
    IndexPipeline,
};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, Hash256, LocatedEntry, Relation, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};

/// A caller file that reaches `compute` twice, at lines the fixture states
/// outright, plus a definition file. The two sites are on different lines so a
/// row reporting one of them is distinguishable from a row reporting both, and
/// neither is the caller's own definition line, so a surface that quietly
/// reports `start_line` instead of the sites fails.
struct Fixture {
    language: &'static str,
    defs_path: &'static str,
    defs_source: &'static str,
    caller_path: &'static str,
    caller_source: &'static str,
    /// Entity name of the function doing the calling.
    caller_name: &'static str,
    /// The call as it is written, used to derive the expected site lines from
    /// the fixture source itself rather than from a hand-counted constant.
    call_text: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "Python",
        defs_path: "defs.py",
        defs_source: "def compute():\n    return 1\n",
        caller_path: "caller.py",
        // 1: import, 2: blank, 3: def run, 4: first call, 5: blank, 6: second call
        caller_source: "from defs import compute\n\
                        \n\
                        def run():\n\
                        \x20   first = compute()\n\
                        \n\
                        \x20   return first + compute()\n",
        caller_name: "run",
        call_text: "compute()",
    },
    Fixture {
        language: "JavaScript",
        defs_path: "defs.js",
        defs_source: "export function compute() { return 1; }\n",
        caller_path: "caller.js",
        // 1: import, 2: blank, 3: export function run, 4: first call, 5: blank,
        // 6: second call
        caller_source: "import { compute } from \"./defs\";\n\
                        \n\
                        export function run() {\n\
                        \x20 const first = compute();\n\
                        \n\
                        \x20 return first + compute();\n\
                        }\n",
        caller_name: "run",
        call_text: "compute()",
    },
];

impl Fixture {
    /// The 1-based caller-file lines the calls are written on, read off the
    /// fixture source. Deriving them here rather than pinning two constants
    /// means editing the fixture cannot leave the expectation behind, and the
    /// oracle is independent of anything the graph produced.
    fn expected_sites(&self) -> Vec<u32> {
        self.caller_source
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(self.call_text))
            .map(|(index, _)| index as u32 + 1)
            .collect()
    }
}

/// One file's parse, kept in the shape both linker arms take.
struct IndexedFixtureFile {
    parse: FileParseData,
    entities: Vec<Entity>,
    same_file_relations: Vec<Relation>,
    artifact_id: ArtifactId,
}

fn index_files(fixture: &Fixture) -> Vec<IndexedFixtureFile> {
    let pipeline = IndexPipeline::new();
    let blob_hash = kin_blobs::Hash256::from_bytes([0u8; 32]);
    [
        (fixture.defs_path, fixture.defs_source),
        (fixture.caller_path, fixture.caller_source),
    ]
    .into_iter()
    .map(|(path, source)| {
        let indexed = pipeline
            .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), blob_hash)
            .unwrap_or_else(|error| panic!("{} index {path}: {error}", fixture.language))
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

/// The batch arm: every file parsed, then one cross-file resolution over all of
/// them. This is what a `kin init` walk runs.
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

/// The live arm: the linker learns each file as it is saved, then resolves the
/// one file that changed against what it already knows. This is the path
/// `kin_reconcile::cross_file` drives on every save.
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
/// That is the non-vacuity control, and it is a stronger one than comparing the
/// sites against a definition line: with no entity span in the graph there is no
/// definition line to report at all, so any line a reference row carries can
/// only have come from the relation's own evidence. It also keeps the fixture
/// off the body-projection path, which would want committed blobs this test
/// never writes.
fn graph_with(files: &[IndexedFixtureFile], linked: &[Relation]) -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    // Admit each fixture file's artifact before any relation names it. The
    // linker roots reference edges at the file's artifact, so a graph that
    // never admitted one holds edges no persist gate would accept, and kin-db
    // refuses them at the write. A transaction carrying a `TreeDelta::Added`
    // is the product's own admission path.
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

async fn find_references(graph: &InMemoryGraph, target: &Entity) -> serde_json::Value {
    let args = HashMap::from([
        (
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        ),
        ("relation_kinds".to_string(), serde_json::json!(["calls"])),
    ]);
    let response = kin_mcp::handlers::entities::handle_find_references(&args, graph, None)
        .await
        .expect("find_references");
    let kin_mcp::types::ContentBlock::Text { text } = response.content.first().unwrap();
    serde_json::from_str(text).expect("find_references body is json")
}

/// Every resolved Python and JavaScript reference row carries the caller-file
/// lines of the reference sites, on both ingest arms, and the CLI prints the
/// same lines the MCP row carries.
#[tokio::test]
async fn python_and_javascript_reference_rows_carry_call_site_lines_on_both_ingest_arms() {
    for fixture in FIXTURES {
        for (arm, link) in [
            (
                "batch",
                link_batch as fn(&[IndexedFixtureFile]) -> Vec<Relation>,
            ),
            ("incremental", link_incremental),
        ] {
            let files = index_files(fixture);
            let linked = link(&files);
            let graph = graph_with(&files, &linked);

            let target = files[0]
                .entities
                .iter()
                .find(|entity| entity.name == "compute")
                .unwrap_or_else(|| panic!("{} {arm}: compute entity", fixture.language))
                .clone();

            let body = find_references(&graph, &target).await;
            let rows = body["references"].as_array().unwrap_or_else(|| {
                panic!("{} {arm}: references array: {body:#}", fixture.language)
            });
            let row = rows
                .iter()
                .find(|row| row["name"] == fixture.caller_name)
                .unwrap_or_else(|| {
                    panic!(
                        "{} {arm}: no row for caller `{}`: {body:#}",
                        fixture.language, fixture.caller_name
                    )
                });

            let expected_sites = fixture.expected_sites();
            assert_eq!(
                expected_sites.len(),
                2,
                "{}: the fixture must write the call on two lines for the site list to be \
                 distinguishable from a single position",
                fixture.language,
            );
            assert_eq!(
                row["reference_lines"],
                serde_json::json!(expected_sites),
                "{} {arm}: the row must name the lines the calls are written on: {row:#}",
                fixture.language,
            );
            assert_eq!(
                row["reference_line_count"], 2,
                "{} {arm}: two calls are two sites: {row:#}",
                fixture.language,
            );
            assert_eq!(
                row["reference_lines_absent_reason"],
                serde_json::Value::Null,
                "{} {arm}: a row that HAS sites must claim no absence: {row:#}",
                fixture.language,
            );
            // Non-vacuity: the graph holds no entity span, so the row has no
            // definition line to have copied. Every number above came from the
            // relation's evidence or from nowhere.
            assert_eq!(
                row["start_line"],
                serde_json::Value::Null,
                "{} {arm}: the fixture removes entity spans on purpose: {row:#}",
                fixture.language,
            );
            assert_eq!(
                body["counts"]["reference_sites_complete"],
                serde_json::json!(true),
                "{} {arm}: every returned row has sites, so the answer must say so: \
                 {body:#}",
                fixture.language,
            );

            let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
            let cli = build_refs_response(
                &layout,
                &graph,
                &RefsRequest {
                    entity: target.id.to_string(),
                    kind: "calls".to_string(),
                },
                &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
                    "initialized": true, "graph_loaded": true,
                    "graph_entity_count": 4, "graph_generation": 1,
                })),
            )
            .expect("kin refs");
            let cli_text = cli.lines.join("\n");
            let expected_label = format!("sites {},{}", expected_sites[0], expected_sites[1]);
            assert!(
                cli_text.contains(&expected_label),
                "{} {arm}: `kin refs` must print the same sites the MCP row carries \
                 (`{expected_label}`): {cli_text}",
                fixture.language,
            );
            assert!(
                !cli_text.contains("sites none"),
                "{} {arm}: no row may report an absent site set here: {cli_text}",
                fixture.language,
            );
        }
    }
}
