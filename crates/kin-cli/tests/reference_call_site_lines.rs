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
//! This asserts the whole chain, language by language: adapter records the call
//! site, linker turns it into a span under the caller's file, MCP and CLI both
//! report it. A language joins the table when its adapter starts recording
//! sites, and the per-language census in `kin-index` is what names the ones
//! that have not. It runs on BOTH ingest arms,
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
    /// Entity name of the function being called. Qualified in the languages
    /// whose adapter owns a member by its container, bare in the ones that do
    /// not, because the row under test is the one the graph really holds.
    target_name: &'static str,
    caller_path: &'static str,
    caller_source: &'static str,
    /// Entity name of the function doing the calling.
    caller_name: &'static str,
    /// The array in the `find_references` body this fixture's row is in.
    ///
    /// `references` for every language whose call the linker can bind to one
    /// destination. `candidates` for Ruby, whose methods are owned by a class
    /// and whose bare call therefore reaches a same-name method the reference
    /// site does not settle: the answer withholds that row from the counted
    /// references on purpose, carries it beside them in the same row shape, and
    /// says so in `degradations`. The site chain this file grades is the same
    /// either way, and reading only `references` would leave the one language
    /// that cannot produce one ungraded.
    rows_field: &'static str,
    /// The call as it is written, used to derive the expected site lines from
    /// the fixture source itself rather than from a hand-counted constant.
    call_text: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "Python",
        defs_path: "defs.py",
        defs_source: "def compute():\n    return 1\n",
        target_name: "compute",
        caller_path: "caller.py",
        // 1: import, 2: blank, 3: def run, 4: first call, 5: blank, 6: second call
        caller_source: "from defs import compute\n\
                        \n\
                        def run():\n\
                        \x20   first = compute()\n\
                        \n\
                        \x20   return first + compute()\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        language: "JavaScript",
        defs_path: "defs.js",
        defs_source: "export function compute() { return 1; }\n",
        target_name: "compute",
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
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // Go is here because it was the language this whole chain was broken
        // on: its adapter recorded no site for a call, so the linker had no
        // span to store and every row came back with no evidence span. Against
        // the Go compiler on the gh CLI repository that cost a third of the
        // reference rows a language-server tier returned, and all of the rows a
        // parser-only tier returned.
        language: "Go",
        defs_path: "defs.go",
        defs_source: "package fixture\n\nfunc compute() int {\n\treturn 1\n}\n",
        target_name: "compute",
        caller_path: "caller.go",
        // 1: package, 2: blank, 3: func run, 4: first call, 5: blank,
        // 6: second call, 7: close
        caller_source: "package fixture\n\
                        \n\
                        func run() int {\n\
                        \x20   first := compute()\n\
                        \n\
                        \x20   return first + compute()\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // Rust is here because Kin is written in it, so every demo and every
        // agent session run against Kin's own tree read reference rows that
        // named a caller and no line. Its adapter recorded no site for a call
        // expression and none for a call written inside a macro body.
        language: "Rust",
        defs_path: "defs.rs",
        defs_source: "pub fn compute() -> u32 {\n    1\n}\n",
        target_name: "compute",
        caller_path: "caller.rs",
        // 1: pub fn run, 2: first call, 3: blank, 4: second call, 5: close
        caller_source: "pub fn run() -> u32 {\n\
                        \x20   let first = compute();\n\
                        \n\
                        \x20   first + compute()\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // Java, whose adapter records the invocation now. The target sits in the
        // caller's own class for the reason the lookup below spells out.
        language: "Java",
        defs_path: "Other.java",
        defs_source: "class Other {\n\
                      \x20 int noop() { return 0; }\n\
                      }\n",
        target_name: "Same.compute",
        caller_path: "Same.java",
        // 1: class, 2: static compute, 3: int run, 4: first call, 5: blank,
        // 6: second call, 7: close run, 8: close class
        caller_source: "class Same {\n\
                        \x20 static int compute() { return 1; }\n\
                        \x20 int run() {\n\
                        \x20   int first = compute();\n\
                        \n\
                        \x20   return first + compute();\n\
                        \x20 }\n\
                        }\n",
        caller_name: "Same.run",
        // The trailing semicolon keeps the definition line, which writes
        // `compute() {`, out of the derived expectation.
        rows_field: "references",
        call_text: "compute();",
    },
    Fixture {
        // C, whose adapter records the call expression now.
        language: "C",
        defs_path: "defs.c",
        defs_source: "int compute(void) { return 1; }\n",
        target_name: "compute",
        caller_path: "caller.c",
        // 1: int run, 2: first call, 3: blank, 4: second call, 5: close
        caller_source: "int run(void) {\n\
                        \x20   int first = compute();\n\
                        \n\
                        \x20   return first + compute();\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // C++, whose adapter records the call expression now.
        language: "Cpp",
        defs_path: "defs.cpp",
        defs_source: "int compute() { return 1; }\n",
        target_name: "compute",
        caller_path: "caller.cpp",
        // 1: int run, 2: first call, 3: blank, 4: second call, 5: close
        caller_source: "int run() {\n\
                        \x20   int first = compute();\n\
                        \n\
                        \x20   return first + compute();\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // C#, whose adapter records the invocation now. The target sits in the
        // caller's own class for the same reason Java's does.
        language: "CSharp",
        defs_path: "Other.cs",
        defs_source: "namespace N { class Other {\n\
                      \x20 public int Noop() { return 0; }\n\
                      } }\n",
        target_name: "N.Same.Compute",
        caller_path: "Same.cs",
        // 1: namespace and class, 2: static Compute, 3: public int Run,
        // 4: first call, 5: blank, 6: second call, 7: close Run,
        // 8: close class and namespace
        caller_source: "namespace N { class Same {\n\
                        \x20 public static int Compute() { return 1; }\n\
                        \x20 public int Run() {\n\
                        \x20   var first = Compute();\n\
                        \n\
                        \x20   return first + Compute();\n\
                        \x20 }\n\
                        } }\n",
        caller_name: "N.Same.Run",
        // The trailing semicolon keeps the definition line out, as above.
        rows_field: "references",
        call_text: "Compute();",
    },
    Fixture {
        // Ruby, whose adapter records the call now. Its row is a candidate
        // rather than a counted reference, for the reason `rows_field` names.
        //
        // The first call is written on the right of an assignment, which the
        // adapter's `assignment` arm used to walk past without extracting
        // anything, so this fixture reported one site where its source writes
        // two. That arm recurses now and the fixture asserts both.
        language: "Ruby",
        defs_path: "defs.rb",
        defs_source: "class Defs\n\
                      \x20 def compute\n\
                      \x20   1\n\
                      \x20 end\n\
                      end\n",
        target_name: "Defs.compute",
        caller_path: "caller.rb",
        // 1: class, 2: def run, 3: first call, 4: blank, 5: second call,
        // 6: end run, 7: end class
        caller_source: "class Caller\n\
                        \x20 def run\n\
                        \x20   first = compute()\n\
                        \n\
                        \x20   first + compute()\n\
                        \x20 end\n\
                        end\n",
        caller_name: "Caller.run",
        rows_field: "candidates",
        call_text: "compute()",
    },
    Fixture {
        // PHP, whose adapter records the call expression now.
        language: "Php",
        defs_path: "defs.php",
        defs_source: "<?php\n\
                      function compute() { return 1; }\n",
        target_name: "compute",
        caller_path: "caller.php",
        // 1: open tag, 2: function run, 3: first call, 4: blank,
        // 5: second call, 6: close
        caller_source: "<?php\n\
                        function run() {\n\
                        \x20   $first = compute();\n\
                        \n\
                        \x20   return $first + compute();\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // Kotlin, whose adapter records the call expression now.
        language: "Kotlin",
        defs_path: "defs.kt",
        defs_source: "fun compute(): Int { return 1 }\n",
        target_name: "compute",
        caller_path: "caller.kt",
        // 1: fun run, 2: first call, 3: blank, 4: second call, 5: close
        caller_source: "fun run(): Int {\n\
                        \x20   val first = compute()\n\
                        \n\
                        \x20   return first + compute()\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
        call_text: "compute()",
    },
    Fixture {
        // Swift, whose adapter records the call expression now.
        //
        // The second call is written inside a `return`, which tree-sitter-swift
        // binds to the whole operator expression around it, so the adapter used
        // to extract no call there and this fixture reported one site where its
        // source writes two. The callee is read off the operator's right
        // operand now and the fixture asserts both.
        language: "Swift",
        defs_path: "defs.swift",
        defs_source: "func compute() -> Int { return 1 }\n",
        target_name: "compute",
        caller_path: "caller.swift",
        // 1: func run, 2: first call, 3: blank, 4: second call, 5: close
        caller_source: "func run() -> Int {\n\
                        \x20   let first = compute()\n\
                        \n\
                        \x20   return first + compute()\n\
                        }\n",
        caller_name: "run",
        rows_field: "references",
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
    /// This file's real content digest, carried so the tree entry admitting the
    /// artifact names the same bytes the index was given. `kin_model::Hash256`
    /// is a re-export of `kin_blobs::Hash256`, so one value serves both.
    blob_hash: Hash256,
}

fn index_files(fixture: &Fixture) -> Vec<IndexedFixtureFile> {
    let pipeline = IndexPipeline::new();
    [
        (fixture.defs_path, fixture.defs_source),
        (fixture.caller_path, fixture.caller_source),
    ]
    .into_iter()
    .map(|(path, source)| {
        // The file's real content digest, per file, not a shared zero hash. The
        // daemon checks that the digest matches the bytes it indexed, so a
        // placeholder is a fixture that stops resembling the product the moment
        // that check tightens. The same value goes into the tree entry below.
        let blob_hash = kin_blobs::digest(source.as_bytes());
        let indexed = pipeline
            .index_file_content_with_tests(
                &FilePathId::new(path),
                source.as_bytes(),
                kin_blobs::digest(source.as_bytes()),
            )
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
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: file.artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(&file.parse.file_path).expect("fixture path is utf-8"),
                        // The file's own content digest, the same one the index
                        // was given. It was the path bytes padded with zeros,
                        // which is a value no blob store would ever hold.
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

/// Every resolved reference row carries the caller-file lines of the reference
/// sites, on both ingest arms, and the CLI prints the same lines the MCP row
/// carries.
#[tokio::test]
async fn reference_rows_carry_call_site_lines_on_both_ingest_arms() {
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

            // Across both files, not just the definition file.
            //
            // A language whose members are owned by a container only produces a
            // counted reference row when the call sits inside that container:
            // `find_references` withholds a bare cross-class call as a
            // receiver-name candidate, because nothing at the reference site
            // settles the receiver's type, and that is the right answer. So the
            // Java and C# fixtures put the target beside its caller and keep a
            // second file for the linker arms to walk, and the lookup follows
            // the target rather than assuming which file holds it.
            let target = files
                .iter()
                .flat_map(|file| file.entities.iter())
                .find(|entity| entity.name == fixture.target_name)
                .unwrap_or_else(|| {
                    panic!(
                        "{} {arm}: no `{}` entity",
                        fixture.language, fixture.target_name
                    )
                })
                .clone();

            let body = find_references(&graph, &target).await;
            let rows = body[fixture.rows_field].as_array().unwrap_or_else(|| {
                panic!(
                    "{} {arm}: `{}` array: {body:#}",
                    fixture.language, fixture.rows_field
                )
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
            if fixture.rows_field == "references" {
                assert_eq!(
                    body["counts"]["reference_sites_complete"],
                    serde_json::json!(true),
                    "{} {arm}: every returned row has sites, so the answer must say so: \
                     {body:#}",
                    fixture.language,
                );
            }

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
