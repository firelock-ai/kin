// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A local variable that shares a function's name is not a reference to it.
//!
//! Measured on cli/cli v2.101.0, where the repository holds exactly one
//! `func requestBody` and `kin refs requestBody` answered "referenced by 17
//! entities". Sixteen of those were local variables called `requestBody` in
//! packages that never import the one the function lives in: every one a
//! `References` edge at `name_only`, every one inside the count the answer led
//! with. One row, a `Calls` at `type_resolved`, was the real caller.
//!
//! It matters most for the reader who cannot check it. `kin agent`'s own system
//! prompt tells the model Kin is its only way to look at the repository and
//! gives it no grep, so sixteen fabricated cross-package references are sixteen
//! things it has no way to falsify.
//!
//! The fixture is the same shape in Go, through the real Go parser and the real
//! cross-file linker: one package defining the function and calling it, one
//! package with a local variable of that name and no import of the first.

use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityStore, FilePathId};
use kin_parser::{GoAdapter, LanguageAdapter};

/// The package that owns the function, and the one caller that really calls it.
const RERUN_GO: &str = r#"package rerun

func requestBody(id string) string {
	return "{\"job\":\"" + id + "\"}"
}

func rerunJob(id string) string {
	return requestBody(id)
}
"#;

/// Another package, with no import of `rerun`, whose functions each declare a
/// local variable called `requestBody`. Nothing here references the function.
const API_GO: &str = r#"package api

func apiRun(body string) string {
	requestBody := body + "\n"
	return requestBody
}

func createGist(body string) string {
	requestBody := "gist:" + body
	return requestBody
}
"#;

const FILES: [(&str, &str); 2] = [
    ("pkg/cmd/run/rerun/rerun.go", RERUN_GO),
    ("pkg/cmd/api/api.go", API_GO),
];

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

fn fixture_graph() -> InMemoryGraph {
    let files: Vec<FileParseData> = FILES
        .iter()
        .map(|(path, source)| parse_go(path, source))
        .collect();
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifact_ids).expect("link the fixture");
    let graph = InMemoryGraph::new();
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    graph
}

fn healthy_envelope() -> kin_mcp::Envelope {
    kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
        "initialized": true,
        "graph_loaded": true,
        "graph_entity_count": 10,
        "graph_generation": 1,
    }))
}

fn refs_lines(graph: &InMemoryGraph, entity: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let response = build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: entity.to_string(),
            kind: "all".to_string(),
        },
        &healthy_envelope(),
    )
    .expect("refs response");
    assert!(response.error.is_none(), "{:?}", response.lines);
    response.lines
}

/// The count the answer leads with holds only the caller that is one, and the
/// same-named locals are listed under their own heading with their own count.
#[test]
fn a_same_named_local_is_not_counted_as_a_reference_to_the_function() {
    let graph = fixture_graph();

    // The fixture's positive control, and the fact the whole defect rests on:
    // the graph holds exactly one entity called `requestBody`. The locals are
    // not entities at all, so every extra row in the answer below is an edge
    // the linker drew from an identifier that merely carries the name.
    let named: Vec<Entity> = graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("requestBody".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name == "requestBody")
        .collect();
    assert_eq!(named.len(), 1, "one definition in the fixture: {named:?}");

    let lines = refs_lines(&graph, "requestBody");
    let joined = lines.join("\n");

    // The control this test would be worthless without: the fixture has to
    // actually produce the bad edge. If the linker stopped emitting it, the
    // assertions below would pass against an answer with no rows at all.
    assert!(
        joined.contains("apiRun"),
        "the fixture must reproduce the same-name edge: {joined}"
    );

    let headline = lines
        .iter()
        .find(|line| line.starts_with("referenced by "))
        .unwrap_or_else(|| panic!("no count line in {lines:?}"));
    assert_eq!(
        headline, "referenced by 1 entities, plus 2 unconfirmed candidates not in that count:",
        "only the real caller is counted, and the held rows are named on the same line: {joined}"
    );

    // The one counted row is the caller that really calls it.
    let counted: Vec<&String> = lines
        .iter()
        .skip_while(|line| !line.starts_with("referenced by "))
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .collect();
    assert_eq!(counted.len(), 1, "{counted:?}");
    assert!(
        counted[0].contains("rerunJob") && counted[0].contains("[Calls]"),
        "the counted row is the call: {}",
        counted[0]
    );

    // The locals are disclosed rather than dropped, under a heading that says
    // what they are, so nothing the graph holds disappears from the answer.
    let heading = lines
        .iter()
        .find(|line| line.contains("name-only match"))
        .unwrap_or_else(|| panic!("no name-only heading in {lines:?}"));
    assert!(
        heading.starts_with("2 name-only matches not counted above"),
        "{heading}"
    );
    assert!(
        heading.contains("local variable or a parameter of the same name"),
        "the heading has to say what these rows are: {heading}"
    );
    for local in ["apiRun", "createGist"] {
        let row = lines
            .iter()
            .find(|line| line.trim_start().starts_with(local))
            .unwrap_or_else(|| panic!("{local} is not listed in {lines:?}"));
        assert!(row.contains("(name_only)"), "{row}");
    }

    // A caller with no grep has only the tier to go on, so the answer says what
    // the tiers mean rather than assuming it knows.
    let legend = lines
        .iter()
        .find(|line| line.starts_with("note: the tag after each row"))
        .unwrap_or_else(|| panic!("no resolution legend in {lines:?}"));
    for tier in ["type_resolved", "import_scoped", "name_only"] {
        assert!(
            legend.contains(tier),
            "the legend must name {tier}: {legend}"
        );
    }
}

/// The control: a name the graph resolves properly keeps its count and prints
/// no legend, so the change above narrows the wrong answer and not every answer.
#[test]
fn a_resolved_caller_is_still_counted_and_carries_no_name_only_note() {
    let graph = fixture_graph();
    let lines = refs_lines(&graph, "rerunJob");
    let joined = lines.join("\n");
    assert!(
        joined.contains("No incoming") || joined.contains("No resolved incoming"),
        "nothing calls rerunJob in the fixture: {joined}"
    );
    assert!(
        !joined.contains("name-only match"),
        "an answer with no name-only row prints no name-only heading: {joined}"
    );

    // And the counted side of the requestBody answer is a real, proven call,
    // so the rule held out the rows it should and kept the row it should.
    let lines = refs_lines(&graph, "requestBody");
    let counted = lines
        .iter()
        .find(|line| line.trim_start().starts_with("rerunJob"))
        .unwrap_or_else(|| panic!("the real caller is missing from {lines:?}"));
    assert!(
        !counted.contains("(name_only)"),
        "the real caller resolved past a name match: {counted}"
    );
}
