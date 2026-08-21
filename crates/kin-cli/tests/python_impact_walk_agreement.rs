// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Acceptance reproduction for FIR-2478, on the fixture shape that filed it.
//!
//! A small multi-module Python library: a `BaseAdapter` transport contract, an
//! `HTTPAdapter` that overrides it, a `Session` that calls the adapter, a
//! module-level API on top of the session, and a pytest suite. That shape puts
//! three declarations of the member name `send` in the graph, gives the
//! contract method a containing class and an overriding implementation, and
//! nothing else.
//!
//! Two defects lived on one command over exactly this shape. `kin impact
//! BaseAdapter.send --json` answered with a prose count of ten beside an empty
//! ranked candidate array, because one walk filtered to impact edges and the
//! other walked containment too. And `kin impact send --json` reported a name
//! the graph holds three times as not found, with an empty candidate list,
//! because a structured caller retained the exact-name matches during
//! resolution and the candidate snapshot was taken after that retain.
//!
//! The fixture runs through the real Python adapter and the real cross-file
//! linker into a real `InMemoryGraph`, which is the shape `kin init` produces
//! over an existing tree.

use kin_cli::commands::impact::{build_impact_response, ImpactRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityStore, FilePathId};
use kin_parser::{LanguageAdapter, PythonAdapter};

const ADAPTERS_PY: &str = r#""""Transport adapters."""


class BaseAdapter:
    """The transport contract."""

    def __init__(self):
        super().__init__()

    def send(self, request, stream=False):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    """The default transport."""

    def __init__(self, pool_connections=10):
        super().__init__()
        self.pool_connections = pool_connections

    def send(self, request, stream=False):
        return self.build_response(request)

    def build_response(self, request):
        return {"request": request}

    def close(self):
        self.pool_connections = 0
"#;

const SESSIONS_PY: &str = r#""""Sessions."""

from adapters import HTTPAdapter


class Session:
    def __init__(self):
        self.adapter = HTTPAdapter()

    def send(self, request):
        return self.adapter.send(request)

    def request(self, method, url):
        return self.send({"method": method, "url": url})

    def get(self, url):
        return self.request("GET", url)

    def post(self, url):
        return self.request("POST", url)

    def put(self, url):
        return self.request("PUT", url)

    def patch(self, url):
        return self.request("PATCH", url)

    def delete(self, url):
        return self.request("DELETE", url)

    def head(self, url):
        return self.request("HEAD", url)

    def options(self, url):
        return self.request("OPTIONS", url)
"#;

const API_PY: &str = r#""""Module level API."""

from sessions import Session


def request(method, url):
    session = Session()
    return session.request(method, url)


def get(url):
    return request("GET", url)


def dispatch(prepared):
    session = Session()
    return session.send(prepared)
"#;

const TEST_ADAPTERS_PY: &str = r#"from adapters import HTTPAdapter


def test_http_adapter_send():
    adapter = HTTPAdapter()
    assert adapter.send({"url": "http://example.invalid"})


def test_http_adapter_close():
    adapter = HTTPAdapter()
    adapter.close()
"#;

fn parse_py(file_path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("fixture parses");
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("fixture extracts");
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

fn project() -> (InMemoryGraph, Vec<FileParseData>) {
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py("sessions.py", SESSIONS_PY),
        parse_py("api.py", API_PY),
        parse_py("tests/test_adapters.py", TEST_ADAPTERS_PY),
    ];
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifact_ids).expect("link fixture");
    let graph = InMemoryGraph::new();
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    (graph, files)
}

fn envelope() -> kin_mcp::Envelope {
    kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
        "initialized": true,
        "graph_loaded": true,
        "graph_entity_count": 40,
        "graph_generation": 1,
    }))
}

/// The names the grouped listing puts under a hop header.
fn listed_names(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| line.strip_prefix("    - "))
        .filter_map(|row| row.split(" (").next())
        .map(str::to_string)
        .collect()
}

async fn impact(
    graph: &InMemoryGraph,
    entity: &str,
    file: Option<&str>,
) -> kin_cli::commands::impact::ImpactResponse {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    build_impact_response(
        &layout,
        graph,
        &ImpactRequest {
            entity: entity.to_string(),
            depth: 3,
            file: file.map(str::to_string),
            kind: None,
            signature: None,
            require_unique: true,
        },
        &envelope(),
    )
    .await
    .expect("impact response")
}

/// Defect 1, on the entity that filed it: the abstract transport contract.
///
/// Its only inbound edges are its containing class and the override. Before the
/// two walks shared one relation policy the listing reached the class at hop 1
/// under a "direct callers" header and everything the class contains behind it,
/// while the ranked report carried the override alone.
#[tokio::test]
async fn one_payload_gives_one_answer_for_the_transport_contract() {
    let (graph, _files) = project();
    let response = impact(&graph, "BaseAdapter.send", None).await;

    assert_eq!(response.resolution, "resolved");
    let ranked = response.ranked.as_ref().expect("ranked report");
    let listed = listed_names(&response.lines);
    assert_eq!(
        listed.len(),
        ranked.candidates.len(),
        "one payload may not carry two counts: lines {:?} ranked {:?}",
        listed,
        ranked
            .candidates
            .iter()
            .map(|c| c.identity.name.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        !listed.is_empty(),
        "control: the override is a real impact edge, so agreement here is not two empty sets"
    );
    assert!(
        !listed.contains(&"BaseAdapter".to_string()),
        "a containing class is not a caller of its own method: {:?}",
        response.lines
    );
    assert!(
        listed.contains(&"HTTPAdapter.send".to_string()),
        "the overriding implementation is what a change to the contract reaches: {:?}",
        response.lines
    );
    let rendered = response.lines.join("\n");
    assert!(
        rendered.contains(&format!("{} local entities", ranked.candidates.len())),
        "the printed count is the count of the ranked set: {rendered}"
    );
}

/// The positive control the ticket names: the implementation side must keep
/// answering with its dependents, and its two walks must agree too.
#[tokio::test]
async fn the_implementation_side_keeps_its_dependents() {
    let (graph, _files) = project();
    let response = impact(&graph, "HTTPAdapter.send", None).await;

    assert_eq!(response.resolution, "resolved");
    let ranked = response.ranked.as_ref().expect("ranked report");
    let listed = listed_names(&response.lines);
    assert_eq!(
        listed.len(),
        ranked.candidates.len(),
        "lines {:?} ranked {}",
        listed,
        ranked.candidates.len()
    );
    for expected in ["Session.send", "Session.request", "test_http_adapter_send"] {
        assert!(
            listed.contains(&expected.to_string()),
            "{expected} calls into this adapter and must still be reported: {:?}",
            response.lines
        );
    }
    assert!(
        !listed.contains(&"HTTPAdapter".to_string()),
        "the containing class is still not a caller: {:?}",
        response.lines
    );
}

/// Defect 2: a bare member name is ambiguous, never absent.
#[tokio::test]
async fn a_bare_member_name_reports_its_declarations_rather_than_not_found() {
    let (graph, _files) = project();
    let response = impact(&graph, "send", None).await;

    assert_eq!(
        response.resolution, "ambiguous",
        "the graph holds this name: {:?}",
        response.lines
    );
    let named: Vec<&str> = response
        .query
        .name_candidates
        .iter()
        .map(|candidate| candidate.name.as_str())
        .collect();
    for expected in ["BaseAdapter.send", "HTTPAdapter.send", "Session.send"] {
        assert!(
            named.contains(&expected),
            "{expected} is a declaration of this name and must be offered: {named:?}"
        );
    }
    assert_eq!(
        response.query.match_count,
        response.query.name_candidates.len(),
        "the count is the resolved set, not zero: {:?}",
        response.query
    );
    let rendered = response.lines.join("\n");
    assert!(
        !rendered.contains("not found") && !rendered.contains("check the spelling"),
        "the name is in the graph, so it must not be reported as missing: {rendered}"
    );
}

/// Defect 2, second half: the remediation the text surface prints has to work.
#[tokio::test]
async fn a_file_qualifier_narrows_a_bare_member_name_to_that_file() {
    let (graph, _files) = project();
    let response = impact(&graph, "send", Some("adapters.py")).await;

    assert_eq!(
        response.resolution, "ambiguous",
        "following the printed remedy must narrow the set, never empty it: {:?}",
        response.lines
    );
    let rendered = response.lines.join("\n");
    assert!(
        rendered.contains("BaseAdapter.send") && rendered.contains("HTTPAdapter.send"),
        "both declarations in adapters.py are named: {rendered}"
    );
    assert!(
        !rendered.contains("Session.send"),
        "the declaration in the other file is excluded: {rendered}"
    );
    assert_eq!(
        response.query.match_count, 2,
        "the qualifier narrowed rather than emptied: {rendered}"
    );
}
