// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A Go struct field is addressable by its owner-qualified name and
//! `find_references` on it answers with real reference sites.
//!
//! Found while revising the reference-resolution paper against cli/cli: a
//! struct field could not be addressed as `Owner.Field` at all (no such
//! entity existed), so asking for its references answered with the
//! referencing FUNCTIONS and no line sites — an answer that cannot be graded
//! or acted on. This fixture is the shape of that gap through the real Go
//! parser and the real cross-file linker: a struct declared in one file, two
//! functions in a second file that read the field, and a third function in
//! that same file that writes it.
//!
//! This response fixture covers cross-file sites. Same-file selectors,
//! free-global decoys, and incremental relinking are covered by
//! kin-index's go_field_reference_resolution suite.

use std::collections::HashMap;

use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{
    ArtifactId, Entity, EntityKind, EntityStore, FilePathId, LocatedEntry, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};
use kin_parser::{GoAdapter, LanguageAdapter};

/// The struct's own file: one field, no accessor.
const TASK_GO: &str = "package task\n\
                       \n\
                       // Task tracks one unit of work.\n\
                       type Task struct {\n\
                       \tName string\n\
                       }\n";

/// Two reads (`Describe`, `Summarize`) and one write (`Rename`), all in a
/// file other than the struct's own.
const ACCESS_GO: &str = "package task\n\
                         \n\
                         import \"fmt\"\n\
                         \n\
                         func Describe(t *Task) {\n\
                         \tfmt.Println(t.Name)\n\
                         }\n\
                         \n\
                         func Summarize(t *Task) string {\n\
                         \treturn t.Name\n\
                         }\n\
                         \n\
                         func Rename(t *Task, next string) {\n\
                         \tt.Name = next\n\
                         }\n";

const FILES: [(&str, &str); 2] = [("task.go", TASK_GO), ("access.go", ACCESS_GO)];

fn parse_go(file_path: &str, source: &str) -> FileParseData {
    let adapter = GoAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse the Go fixture");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|entity| entity.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

struct Fixture {
    files: Vec<FileParseData>,
    graph: InMemoryGraph,
}

fn fixture() -> Fixture {
    let files: Vec<FileParseData> = FILES
        .iter()
        .map(|(path, source)| parse_go(path, source))
        .collect();
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifact_ids).expect("link the fixture");

    let graph = InMemoryGraph::new();
    // Admit each fixture file's artifact before any entity or relation names
    // it. `handle_find_references` refuses with a repository-authority gap
    // on a graph that holds edges no persist gate would ever have accepted;
    // a `TreeDelta::Added` transaction is the product's own admission path,
    // the same one `reference_call_site_lines.rs` uses for this reason.
    for (path, source) in FILES {
        let artifact_id = artifact_ids[path];
        let blob_hash = kin_blobs::digest(source.as_bytes());
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(path).expect("fixture path is utf-8"),
                        TreeEntry::blob(blob_hash, false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .expect("admit fixture artifact");
    }
    // Every entity span is dropped on the graph's own copy — `fixture.files`
    // below keeps the real ones — for the same non-vacuity reason
    // `reference_call_site_lines.rs` drops them: with no entity span in the
    // graph, `find_references` cannot resolve a caller-file line for any
    // row by quietly reading the entity's declaration, and the body-
    // projection path a span would open wants committed blobs this test
    // never writes, which is exactly the repository-authority binding this
    // in-memory fixture has none of. Any site the assertions below see can
    // only have come from the relation's own evidence.
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        let mut entity = entity.clone();
        entity.span = None;
        graph.upsert_entity(&entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    Fixture { files, graph }
}

/// The 1-based lines `needle` is written on, read off the fixture source
/// itself so the expectation cannot drift from what the fixture actually
/// writes.
fn lines_containing(source: &str, needle: &str) -> Vec<u32> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(needle))
        .map(|(index, _)| index as u32 + 1)
        .collect()
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

/// The 1-based file lines the collector keys a served row's sites by, matched
/// by the caller's entity id.
///
/// The wire addresses each site inside its caller and never by a file line,
/// and this fixture strips entity spans, so a served site cannot say where it
/// is. The exact lines are pinned here instead, at the collector the row is
/// served from.
fn collected_lines(graph: &InMemoryGraph, target: &Entity, served: &serde_json::Value) -> Vec<u32> {
    kin_mcp::handlers::common::collect_graph_reference_rows(
        graph,
        &target.id,
        &kin_mcp::handlers::common::default_reference_kinds(),
        None,
    )
    .expect("collect reference rows")
    .into_iter()
    .find(|row| row.entity_id.as_deref() == served["entity_id"].as_str())
    .unwrap_or_else(|| panic!("the collector holds no row for the served one: {served:#?}"))
    .reference_lines
}

/// The same call, addressed by name instead of by raw entity id — the way a
/// person or an agent actually asks for it, and the design's own bar:
/// "addressable by its owner-qualified name".
async fn find_references_by_query(graph: &InMemoryGraph, query: &str) -> serde_json::Value {
    let args = HashMap::from([("query".to_string(), serde_json::json!(query))]);
    let response = kin_mcp::handlers::entities::handle_find_references(&args, graph, None)
        .await
        .expect("find_references");
    let kin_mcp::types::ContentBlock::Text { text } = response.content.first().unwrap();
    serde_json::from_str(text).expect("find_references body is json")
}

/// Ingestion mints the field as an owner-qualified entity, the way a method
/// is already `Owner.Method`.
#[test]
fn ingestion_mints_the_field_as_an_owner_qualified_entity() {
    let fixture = fixture();
    let field = fixture
        .files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == "Task.Name")
        .expect("Task.Name must be a graph entity");
    assert_eq!(field.kind, EntityKind::Field);
    assert_eq!(
        field.file_origin.as_ref().map(|f| f.0.as_str()),
        Some("task.go"),
        "the field's declaration site is where it is written, not where it is used"
    );
}

/// `find_references` on the field returns all three sites — two reads, one
/// write — each with a line and a resolution label, through the store's MCP
/// handler and the CLI's own `kin refs` surface.
#[tokio::test]
async fn find_references_on_the_field_returns_read_and_write_sites_with_lines() {
    let fixture = fixture();
    let graph = &fixture.graph;
    let target = fixture
        .files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == "Task.Name")
        .expect("Task.Name must be a graph entity")
        .clone();

    let body = find_references(graph, &target).await;
    // Receiver-name candidates are held at every requested floor: the
    // member spelling and occurrence site do not establish its owner type.
    assert_eq!(
        body["references"],
        serde_json::json!([]),
        "every site here resolves through the receiver fan-out tier, which is always held: \
         {body:#?}"
    );
    let refs = body["candidates"]
        .as_array()
        .unwrap_or_else(|| panic!("no `candidates` array in the find_references body: {body:#?}"));
    assert_eq!(
        body["counts"]["receiver_name_candidates"], 3,
        "all three sites are counted as receiver-name candidates: {body:#?}"
    );
    let degradations = body["degradations"].as_array().cloned().unwrap_or_default();
    assert!(
        degradations
            .iter()
            .any(|entry| entry["reason"] == "receiver_name_candidates"),
        "the answer must disclose why the sites are candidates rather than references, so a \
         caller with no grep can still trust the count: {body:#?}"
    );

    let by_caller: HashMap<&str, &serde_json::Value> = refs
        .iter()
        .map(|row| (row["name"].as_str().unwrap(), row))
        .collect();

    let describe_lines = lines_containing(ACCESS_GO, "fmt.Println(t.Name)");
    let summarize_lines = lines_containing(ACCESS_GO, "return t.Name");
    let rename_lines = lines_containing(ACCESS_GO, "t.Name = next");
    for (caller, expected_lines) in [
        ("Describe", &describe_lines),
        ("Summarize", &summarize_lines),
        ("Rename", &rename_lines),
    ] {
        let row = by_caller
            .get(caller)
            .unwrap_or_else(|| panic!("no reference row for `{caller}`: {refs:#?}"));
        // The wire serves each site inside its caller, and a spanless caller
        // cannot place one, so the exact line is pinned at the collector.
        assert_eq!(
            &collected_lines(graph, &target, row),
            expected_lines,
            "{caller}'s row must carry the line its access is written on: {row:#?}"
        );
        assert_eq!(
            (*row)["site_count"],
            serde_json::json!(expected_lines.len()),
            "{caller}'s row serves one site per access: {row:#?}"
        );
        let sites = (*row)["sites"]
            .as_array()
            .unwrap_or_else(|| panic!("{caller}'s row has a `sites` array: {row:#?}"));
        assert_eq!(sites.len(), expected_lines.len(), "{row:#?}");
        for site in sites {
            assert_eq!(site["line_in_entity"], serde_json::Value::Null, "{row:#?}");
            assert_eq!(
                site["callee_unavailable"], "caller_has_no_span",
                "the fixture removes entity spans on purpose: {row:#?}"
            );
        }
        for retired in ["file_path", "start_line", "reference_lines"] {
            assert!(
                (*row).get(retired).is_none(),
                "{caller}'s row carries no `{retired}`: {row:#?}"
            );
        }
        assert_eq!(
            (*row)["projection"]["path"],
            "access.go",
            "{caller}'s row is labelled with the file it is projected into: {row:#?}"
        );
        assert_eq!(
            (*row)["sites_absent_reason"],
            serde_json::Value::Null,
            "{caller}'s row has a site, so it must claim no absence: {row:#?}"
        );
        // Without a language server, a Go field access resolves through the
        // same bare-name fan-out tier a Go method call already does —
        // `name_only`, per that tier's own confidence. A store-level answer
        // is never expected to certify more than the parser proved.
        assert_eq!(
            (*row)["resolution"],
            "name_only",
            "{caller}'s row must carry the resolution label a caller with no grep depends on: \
             {row:#?}"
        );
    }

    assert_eq!(
        refs.len(),
        3,
        "exactly the two reads and the one write, nothing else: {refs:#?}"
    );

    // The same three sites, through `kin refs` — the CLI surface a person
    // actually runs, not just the MCP body an agent reads.
    let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
    let cli = build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: target.id.to_string(),
            kind: "all".to_string(),
        },
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 6, "graph_generation": 1,
        })),
    )
    .expect("kin refs");
    let cli_text = cli.lines.join("\n");
    for caller in ["Describe", "Summarize", "Rename"] {
        assert!(
            cli_text.contains(caller),
            "`kin refs` must name {caller} among the field's references: {cli_text}"
        );
    }
}

/// The design's own bar: the field is addressable by its owner-qualified
/// name, not only by the raw entity id every other assertion in this file
/// already has in hand. A person or an agent asking `find_references` for
/// `Task.Name`, or running `kin refs Task.Name`, must resolve to the same
/// entity the id-addressed calls above do — the same way `Owner.Method`
/// already resolves for a method.
#[tokio::test]
async fn the_field_resolves_by_its_owner_qualified_name() {
    let fixture = fixture();
    let graph = &fixture.graph;
    let target = fixture
        .files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == "Task.Name")
        .expect("Task.Name must be a graph entity");

    let body = find_references_by_query(graph, "Task.Name").await;
    assert_eq!(
        body["candidates"]
            .as_array()
            .map(|rows| rows.len())
            .unwrap_or(0),
        3,
        "querying by `Task.Name` must resolve to the field and answer with its three \
         sites, the same as querying by id: {body:#?}"
    );

    let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
    let cli = build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: "Task.Name".to_string(),
            kind: "all".to_string(),
        },
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 6, "graph_generation": 1,
        })),
    )
    .expect("kin refs Task.Name");
    assert!(cli.error.is_none(), "{:?}", cli.lines);
    let cli_text = cli.lines.join("\n");
    assert!(
        cli_text.contains(&target.id.to_string()) || cli_text.contains("Task.Name"),
        "`kin refs Task.Name` must resolve to the field entity: {cli_text}"
    );
    for caller in ["Describe", "Summarize", "Rename"] {
        assert!(
            cli_text.contains(caller),
            "`kin refs Task.Name` must name {caller}: {cli_text}"
        );
    }
}

/// The receiver fan-out ground is held at every floor, field or method: a
/// bare-name match is a candidate whatever a caller asked for, so even
/// `min_resolution: "name_only"` — which does widen the SEPARATE `name_only`
/// ceiling a store's stronger rows can impose on a focal — leaves these three
/// sites in `candidates`. Mirrors
/// `a_receiver_name_row_is_a_candidate_and_never_a_counted_reference`'s own
/// control for a method call resolved through the identical tier.
#[tokio::test]
async fn min_resolution_name_only_does_not_promote_the_receiver_fan_out() {
    let fixture = fixture();
    let graph = &fixture.graph;
    let target = fixture
        .files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == "Task.Name")
        .expect("Task.Name must be a graph entity");

    let args = HashMap::from([
        (
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        ),
        ("min_resolution".to_string(), serde_json::json!("name_only")),
    ]);
    let response = kin_mcp::handlers::entities::handle_find_references(&args, graph, None)
        .await
        .expect("find_references");
    let kin_mcp::types::ContentBlock::Text { text } = response.content.first().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).expect("json body");

    assert_eq!(
        body["references"],
        serde_json::json!([]),
        "the fan-out ground holds these sites even at the widest floor: {body:#?}"
    );
    assert_eq!(
        body["candidates"]
            .as_array()
            .map(Vec::len)
            .unwrap_or_default(),
        3,
        "all three sites still read as candidates: {body:#?}"
    );
    assert_eq!(
        body["counts"]["receiver_name_candidates"], 3,
        "the fan-out is held at every floor: {body:#?}"
    );
}
