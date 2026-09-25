// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One rule for a bare member name, on every surface that accepts a name.
//!
//! The graph names a member by its owner: `Scaffold.get` in Python,
//! `Server.Handle` in Go, `Router.route` in TypeScript. A caller usually holds
//! only the bare name, and before this rule no surface agreed on what it meant.
//! On pallets/flask, `kin refs get` refused it as a partial name,
//! `get_entity_source(entity_id: "get")` returned the body of the tutorial's
//! `get_db`, `kin context route` built a pack around the `T_route` type
//! variable, and a benchmark arm that looked for the bare name among
//! `list_file_entities` rows resolved 53 of 102 subjects.
//!
//! The rule: a bare name reaches every entity whose member segment is exactly
//! that name, once at least one of them has an owner. One such entity answers
//! directly. Several are listed with their owner-qualified names and ids and
//! none is chosen, except by `kin refs` and `find_references`, which answer for
//! each in its own section. Each fixture runs through the real language adapter
//! and the real cross-file linker, and every assertion about the CLI is paired
//! with the same question asked of the MCP handlers over the same graph.

use std::collections::HashMap;

use kin_cli::commands::impact::{build_impact_response, ImpactRequest};
use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_cli::commands::trace::{build_trace_json_response, TraceRequest};
use kin_cli::entity_identity::{resolve_entity, IdentityQualifiers, NameMatch};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, Hash256, LocatedEntry, RepoPath, TransactionDelta,
    TreeDelta, TreeEntry,
};
use kin_parser::{GoAdapter, LanguageAdapter, PythonAdapter, RustAdapter, TypeScriptAdapter};

const SCAFFOLD_PY: &str = r#"class Scaffold:
    def get(self, rule):
        return self.route(rule)

    def route(self, rule):
        return rule
"#;

const CTX_PY: &str = r#"class _AppCtxGlobals:
    def get(self, name, default=None):
        return default
"#;

const DB_PY: &str = r#"def get_db():
    return {}
"#;

const VIEWS_PY: &str = r#"from scaffold import Scaffold
from ctx import _AppCtxGlobals


def index():
    app = Scaffold()
    app.route("/")
    g = _AppCtxGlobals()
    return g.get("user")
"#;

const SERVER_GO: &str = r#"package server

type Server struct{}

func (s *Server) Handle() string { return "server" }

func (s *Server) Close() {}

type Client struct{}

func (c *Client) Handle() string { return "client" }

func Run() string {
	s := &Server{}
	s.Close()
	return s.Handle()
}
"#;

const ROUTER_TS: &str = r#"export class Router {
  route(path: string): string {
    return path;
  }

  get(path: string): string {
    return this.route(path);
  }
}

export class Cache {
  get(key: string): string {
    return key;
  }
}

export function getRouter(): Router {
  return new Router();
}
"#;

fn parse<A: LanguageAdapter>(adapter: &A, file_path: &str, source: &str) -> FileParseData {
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

/// Admit one artifact per file through the repository tree, the path the
/// product uses, then link and store the fixture.
fn graph_of(files: Vec<FileParseData>) -> InMemoryGraph {
    graph_of_spans(files, true)
}

/// [`graph_of`], optionally storing every entity without its span. The spans
/// are dropped only after linking, so the linker sees the parse it always does.
fn graph_of_spans(files: Vec<FileParseData>, keep_spans: bool) -> InMemoryGraph {
    let graph = InMemoryGraph::new();
    let mut artifact_ids = HashMap::new();
    for file in &files {
        let artifact_id = ArtifactId::new();
        let mut seed = [0u8; 32];
        for (slot, byte) in seed.iter_mut().zip(file.file_path.as_bytes()) {
            *slot = *byte;
        }
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(&file.file_path).expect("fixture path is utf-8"),
                        TreeEntry::blob(Hash256::from_bytes(seed), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .expect("admit fixture artifact");
        artifact_ids.insert(file.file_path.clone(), artifact_id);
    }
    let relations = link_cross_file(&files, &artifact_ids).expect("link fixture");
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        let mut entity = entity.clone();
        if !keep_spans {
            entity.span = None;
        }
        graph.upsert_entity(&entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    graph
}

fn python_files() -> Vec<FileParseData> {
    vec![
        parse(&PythonAdapter, "src/app/scaffold.py", SCAFFOLD_PY),
        parse(&PythonAdapter, "src/app/ctx.py", CTX_PY),
        parse(&PythonAdapter, "src/app/db.py", DB_PY),
        parse(&PythonAdapter, "src/app/views.py", VIEWS_PY),
    ]
}

fn python_graph() -> InMemoryGraph {
    graph_of(python_files())
}

/// The same fixture with every entity span removed. A reference row whose
/// span is present is checked against the source bytes, which needs a pinned
/// repository authority this in-process harness does not have; resolution
/// reads names and ids only, so it answers the same either way.
fn python_graph_without_spans() -> InMemoryGraph {
    graph_of_spans(python_files(), false)
}

fn envelope() -> kin_mcp::Envelope {
    kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
        "initialized": true,
        "graph_loaded": true,
        "graph_entity_count": 20,
        "graph_generation": 1,
    }))
}

fn layout() -> (tempfile::TempDir, kin_core::KinLayout) {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    (dir, layout)
}

fn refs(graph: &InMemoryGraph, entity: &str) -> kin_cli::commands::refs::RefsResponse {
    let (_dir, layout) = layout();
    build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: entity.to_string(),
            kind: "all".to_string(),
        },
        &envelope(),
    )
    .expect("refs response")
}

fn names(entities: &[Entity]) -> Vec<&str> {
    entities.iter().map(|entity| entity.name.as_str()).collect()
}

fn args(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect()
}

fn json(result: &kin_mcp::ToolCallResult) -> serde_json::Value {
    let kin_mcp::types::ContentBlock::Text { text } = result.content.first().expect("content");
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::json!({ "text": text }))
}

/// The CLI resolver: a lone owner's member answers, and a member name two
/// owners share is refused with both, never with the substring cousin.
#[test]
fn the_cli_resolver_reaches_owner_members_by_their_bare_name() {
    let graph = python_graph();

    let lone = resolve_entity(&graph, "route", &IdentityQualifiers::default()).unwrap();
    assert_eq!(lone.name_match, NameMatch::Member);
    assert_eq!(names(&lone.candidates), vec!["Scaffold.route"]);
    assert!(!lone.needs_a_pin());

    let shared = resolve_entity(&graph, "get", &IdentityQualifiers::default()).unwrap();
    assert!(shared.shares_member_name());
    assert!(shared.needs_a_pin());
    let mut reached = names(&shared.candidates);
    reached.sort_unstable();
    assert_eq!(
        reached,
        vec!["Scaffold.get", "_AppCtxGlobals.get"],
        "every owner's member and not `get_db`, which only contains the name"
    );

    let refusal = kin_cli::entity_identity::pin_request_lines(&graph, &shared).join("\n");
    assert!(
        refusal.contains("2 members of different owners carry it"),
        "{refusal}"
    );
    assert!(
        refusal.contains("_AppCtxGlobals.get") && refusal.contains("Scaffold.get"),
        "{refusal}"
    );
    assert!(!refusal.contains("get_db"), "{refusal}");
    for candidate in &shared.candidates {
        assert!(
            refusal.contains(&candidate.id.to_string()),
            "each row carries the id that addresses it: {refusal}"
        );
    }

    // A file pin narrows a shared member name to the one owner in that file.
    let pinned = resolve_entity(
        &graph,
        "get",
        &IdentityQualifiers {
            file: Some("src/app/ctx.py".to_string()),
            ..IdentityQualifiers::default()
        },
    )
    .unwrap();
    assert_eq!(names(&pinned.candidates), vec!["_AppCtxGlobals.get"]);
    assert!(!pinned.needs_a_pin());
}

/// `kin refs` answers a lone member directly and a shared one once per owner,
/// the CLI half of `find_references`' sectioned reply, and both surfaces reach
/// the same entities for the same name.
#[tokio::test]
async fn kin_refs_and_find_references_answer_a_bare_member_name_alike() {
    let graph = python_graph_without_spans();

    let lone = refs(&graph, "route");
    assert!(lone.error.is_none(), "{:?}", lone.lines);
    assert!(
        lone.lines[0].starts_with("References to 'route' -> Scaffold.route"),
        "{:?}",
        lone.lines
    );

    let shared = refs(&graph, "get");
    assert!(shared.error.is_none(), "{:?}", shared.lines);
    let rendered = shared.lines.join("\n");
    assert!(
        rendered.contains("2 members of different owners carry it"),
        "{rendered}"
    );
    assert!(
        rendered.contains("== _AppCtxGlobals.get (method)")
            && rendered.contains("== Scaffold.get (method)"),
        "one section per owner: {rendered}"
    );
    assert!(!rendered.contains("get_db"), "{rendered}");

    let mcp = json(
        &kin_mcp::handlers::entities::handle_find_references(
            &args(&[("query", serde_json::json!("route"))]),
            &graph,
            None,
        )
        .await
        .unwrap(),
    );
    assert_eq!(mcp["focal_entity"]["name"], "Scaffold.route", "{mcp}");

    let mcp = json(
        &kin_mcp::handlers::entities::handle_find_references(
            &args(&[("query", serde_json::json!("get"))]),
            &graph,
            None,
        )
        .await
        .unwrap(),
    );
    let sectioned: Vec<&str> = mcp["candidates_by_owner"]
        .as_array()
        .unwrap_or_else(|| panic!("sectioned: {mcp}"))
        .iter()
        .map(|section| section["owner_qualified_name"].as_str().unwrap())
        .collect();
    let cli_order: Vec<&str> = shared
        .lines
        .iter()
        .filter_map(|line| line.strip_prefix("== "))
        .map(|line| line.split(' ').next().unwrap())
        .collect();
    assert_eq!(
        sectioned, cli_order,
        "the CLI and MCP section the same owners in the same order"
    );
}

/// Every single-answer surface refuses a shared member name with the same
/// candidates, and accepts a lone one.
#[test]
fn single_answer_surfaces_list_a_shared_member_name_and_take_a_lone_one() {
    let graph = python_graph();
    let expected = resolve_entity(&graph, "get", &IdentityQualifiers::default()).unwrap();
    let mut expected_ids: Vec<String> = expected
        .candidates
        .iter()
        .map(|entity| entity.id.to_string())
        .collect();
    expected_ids.sort_unstable();

    let ids_of = |body: &serde_json::Value| {
        let mut ids: Vec<String> = body["candidates"]
            .as_array()
            .unwrap_or_else(|| panic!("candidates: {body}"))
            .iter()
            .map(|row| row["entity_id"].as_str().unwrap().to_string())
            .collect();
        ids.sort_unstable();
        ids
    };

    let source = json(
        &kin_mcp::handlers::entities::handle_get_entity_source(
            &args(&[("entity_id", serde_json::json!("get"))]),
            &graph,
            None,
        )
        .unwrap(),
    );
    assert_eq!(source["ambiguous_focal"], true, "{source}");
    assert_eq!(ids_of(&source), expected_ids);
    assert!(source.get("body").is_none(), "{source}");

    let flow = json(
        &kin_mcp::handlers::entities::handle_trace_data_flow(
            &args(&[("focal", serde_json::json!("get"))]),
            &graph,
        )
        .unwrap(),
    );
    assert_eq!(ids_of(&flow), expected_ids, "{flow}");

    let (_dir, layout) = layout();
    let trace = build_trace_json_response(
        &layout,
        &graph,
        &TraceRequest {
            entity: "get".to_string(),
            json: true,
            compact: false,
            budget: "8k".to_string(),
            assistant: None,
            max_lines: 40,
            nearby_limit: 4,
            transitive_limit: 2,
            file: None,
            kind: None,
        },
    )
    .unwrap();
    let refusal = trace.error.expect("kin trace refuses a shared member name");
    assert!(
        refusal.contains("_AppCtxGlobals.get") && refusal.contains("Scaffold.get"),
        "{refusal}"
    );

    let lone = build_trace_json_response(
        &layout,
        &graph,
        &TraceRequest {
            entity: "route".to_string(),
            json: true,
            compact: false,
            budget: "8k".to_string(),
            assistant: None,
            max_lines: 40,
            nearby_limit: 4,
            transitive_limit: 2,
            file: None,
            kind: None,
        },
    )
    .unwrap();
    assert!(lone.error.is_none(), "{:?}", lone.lines);
    assert_eq!(
        lone.entities.first().map(|entity| entity.name.as_str()),
        Some("Scaffold.route")
    );
}

/// `kin xref` resolves its own way and used to take the best-ranked substring
/// match; a shared member name is now refused with the owners' members.
#[tokio::test]
async fn kin_xref_lists_a_shared_member_name() {
    let graph = python_graph();
    let response = kin_cli::commands::xref::build_xref_response(
        &graph,
        &kin_cli::commands::xref::XrefRequest {
            entity: "get".to_string(),
        },
        "fixture",
        "root",
        None,
    )
    .await
    .expect("xref response");
    let refusal = response
        .error
        .expect("a shared member name names no entity");
    assert!(
        refusal.contains("_AppCtxGlobals.get") && refusal.contains("Scaffold.get"),
        "{refusal}"
    );
    assert!(!refusal.contains("get_db"), "{refusal}");
}

/// A structured `kin impact` caller asking for one entity takes a lone member
/// the way it takes an exact name, and is refused with the owners otherwise.
#[tokio::test]
async fn kin_impact_takes_a_lone_member_and_lists_shared_ones() {
    let graph = python_graph();
    let (_dir, layout) = layout();
    let impact = |entity: &'static str| {
        let layout = &layout;
        let graph = &graph;
        async move {
            build_impact_response(
                layout,
                graph,
                &ImpactRequest {
                    entity: entity.to_string(),
                    depth: 2,
                    file: None,
                    kind: None,
                    signature: None,
                    require_unique: true,
                    dispatch_candidates: false,
                },
                &envelope(),
            )
            .await
            .expect("impact response")
        }
    };

    let lone = impact("route").await;
    assert_eq!(lone.resolution, "resolved", "{:?}", lone.lines);
    assert!(lone.lines[0].contains("Scaffold.route"), "{:?}", lone.lines);

    let shared = impact("get").await;
    assert_eq!(shared.resolution, "ambiguous", "{:?}", shared.lines);
    let rendered = shared.lines.join("\n");
    assert!(
        rendered.contains("2 members of different owners carry it"),
        "{rendered}"
    );
}

/// `list_file_entities` rows carry the bare member name, so the bare-name
/// lookup the benchmark arm makes against a file finds the member.
#[test]
fn list_file_entities_rows_carry_the_member_name() {
    let graph = python_graph();
    let result = kin_mcp::handlers::file_entities::handle_list_file_entities(
        &args(&[("path", serde_json::json!("src/app/scaffold.py"))]),
        &graph,
        kin_mcp::working_copy::WorkingCopySurface::NotApplicable,
    )
    .unwrap();
    let body = json(&result);
    let by_member: Vec<(&str, &str)> = body["entities"]
        .as_array()
        .unwrap_or_else(|| panic!("entities: {body}"))
        .iter()
        .filter(|row| row["member_name"] == "get")
        .map(|row| {
            (
                row["name"].as_str().unwrap(),
                row["owner"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(by_member, vec![("Scaffold.get", "Scaffold")], "{body}");
}

/// The pallets/flask shape the name index hid: two `Blueprint` classes whose
/// names match `blueprint` whole once case is folded, and more names carrying
/// the `blueprint` token than the index keeps. The plain pattern returns only
/// the classes, so a rule read off it never saw `Request.blueprint`.
#[test]
fn a_member_the_name_index_hides_is_still_reached() {
    let tests: String = (0..40)
        .map(|index| format!("def test_blueprint_{index}():\n    pass\n\n\n"))
        .collect();
    let graph =
        graph_of_spans(
            vec![
            parse(&PythonAdapter, "src/flask/blueprints.py", "class Blueprint:\n    pass\n"),
            parse(
                &PythonAdapter,
                "src/flask/sansio/blueprints.py",
                "class Blueprint:\n    pass\n",
            ),
            parse(
                &PythonAdapter,
                "src/flask/wrappers.py",
                "class Request:\n    @property\n    def blueprint(self):\n        return None\n",
            ),
            parse(&PythonAdapter, "tests/test_blueprints.py", &tests),
        ],
            false,
        );

    let plain = graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("blueprint".to_string()),
            ..Default::default()
        })
        .unwrap();
    assert!(
        plain
            .iter()
            .all(|entity| entity.name != "Request.blueprint"),
        "control: the name index must hide the member for this test to mean anything: {:?}",
        names(&plain)
    );

    let resolved = resolve_entity(&graph, "blueprint", &IdentityQualifiers::default()).unwrap();
    assert_eq!(resolved.name_match, NameMatch::Member);
    assert_eq!(names(&resolved.candidates), vec!["Request.blueprint"]);

    let answer = refs(&graph, "blueprint");
    assert!(
        answer.lines[0].starts_with("References to 'blueprint' -> Request.blueprint"),
        "{:?}",
        answer.lines
    );
}

/// An exact whole name is its own first tier. A module function named `get`
/// beside the method `Session.get` is what `get` names, on the CLI and over
/// MCP alike, and the method is not pooled into a shared member answer.
#[tokio::test]
async fn an_exact_name_answers_ahead_of_a_member_on_every_surface() {
    let graph = graph_of_spans(
        vec![
            parse(
                &PythonAdapter,
                "src/app/sessions.py",
                "class Session:\n    def get(self, url):\n        return url\n",
            ),
            parse(
                &PythonAdapter,
                "src/app/api.py",
                "def get(url):\n    return url\n",
            ),
        ],
        false,
    );

    let resolved = resolve_entity(&graph, "get", &IdentityQualifiers::default()).unwrap();
    assert_eq!(resolved.name_match, NameMatch::Exact);
    assert_eq!(names(&resolved.candidates), vec!["get"]);

    let answer = refs(&graph, "get");
    assert!(answer.error.is_none(), "{:?}", answer.lines);
    assert!(
        answer.lines[0].starts_with("References to 'get' -> get "),
        "{:?}",
        answer.lines
    );

    let mcp = json(
        &kin_mcp::handlers::entities::handle_find_references(
            &args(&[("query", serde_json::json!("get"))]),
            &graph,
            None,
        )
        .await
        .unwrap(),
    );
    assert!(mcp.get("candidates_by_owner").is_none(), "{mcp}");
    assert_eq!(mcp["focal_entity"]["name"], "get", "{mcp}");
}

/// A Rust struct and an enum variant of the same name: the struct answers, and
/// the variant is reachable by its bare name only where nothing is named it
/// exactly.
#[test]
fn a_rust_variant_never_pools_with_the_struct_of_its_name() {
    let graph = graph_of(vec![parse(
        &RustAdapter,
        "src/graph.rs",
        "pub struct Entity;\n\npub enum GraphNodeId {\n    Entity(u32),\n    Artifact(u32),\n}\n",
    )]);
    let exact = resolve_entity(&graph, "Entity", &IdentityQualifiers::default()).unwrap();
    assert_eq!(exact.name_match, NameMatch::Exact);
    assert_eq!(names(&exact.candidates), vec!["Entity"]);

    let variant = resolve_entity(&graph, "Artifact", &IdentityQualifiers::default()).unwrap();
    assert_eq!(variant.name_match, NameMatch::Member);
    assert_eq!(names(&variant.candidates), vec!["GraphNodeId::Artifact"]);
}

/// A Go struct field is a member by kind, so its bare name reaches it when
/// nothing is named it exactly.
#[test]
fn a_go_field_is_reached_by_its_bare_name() {
    let graph = graph_of(vec![parse(
        &GoAdapter,
        "internal/users/user.go",
        "package users\n\ntype User struct {\n\tName string\n}\n",
    )]);
    let field = resolve_entity(&graph, "Name", &IdentityQualifiers::default()).unwrap();
    assert_eq!(field.name_match, NameMatch::Member);
    assert_eq!(names(&field.candidates), vec!["User.Name"]);
}

/// `kin context` and the daemon's `get_context_pack` route resolve focals
/// through the same shared member rule: a shared name has candidates and no
/// focal, and a lone member is a focal.
#[test]
fn context_focals_follow_the_shared_member_rule() {
    let graph = python_graph();
    let shared = kin_cli::commands::context::shared_member_focal_candidates(&graph, "get").unwrap();
    let mut shared: Vec<String> = shared
        .expect("a shared member name has candidates")
        .into_iter()
        .map(|entity| entity.name)
        .collect();
    shared.sort();
    assert_eq!(shared, vec!["Scaffold.get", "_AppCtxGlobals.get"]);
    assert!(
        kin_cli::commands::context::resolve_focal_for_mcp(&graph, "get")
            .unwrap()
            .is_none()
    );

    let lone = kin_cli::commands::context::resolve_focal_for_mcp(&graph, "route")
        .unwrap()
        .expect("a lone member is a focal");
    let expected = resolve_entity(&graph, "route", &IdentityQualifiers::default()).unwrap();
    assert_eq!(
        lone["entity_id"],
        serde_json::json!(expected.candidates[0].id.to_string())
    );
}

/// A walk's authority over an empty store, enough for a walk that reads no
/// bodies.
fn empty_authority() -> (
    tempfile::TempDir,
    kin_cli::commands::repository_authority::RequestRepositoryAuthority,
) {
    let temp = tempfile::tempdir().unwrap();
    let kin_root = temp.path().join(".kin");
    std::fs::create_dir_all(kin_root.join("objects")).unwrap();
    let layout = kin_core::KinLayout::new(kin_root);
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_parts(
        kin_model::RepositoryId::new("bare-member-name-test").unwrap(),
        kin_model::WorkspaceId::new(),
        std::sync::Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
    );
    (
        temp,
        kin_cli::commands::repository_authority::RequestRepositoryAuthority::pinned(binding),
    )
}

fn walk(
    graph: &InMemoryGraph,
    focal: &str,
    target: Option<&str>,
) -> anyhow::Result<kin_cli::commands::trace_data_flow::TraceDataFlowResponse> {
    let (_temp, authority) = empty_authority();
    kin_cli::commands::trace_data_flow::build_trace_data_flow_response(
        &authority,
        graph,
        &kin_cli::commands::trace_data_flow::TraceDataFlowRequest {
            focal: focal.to_string(),
            depth: None,
            direction: None,
            limit_per_step: None,
            include_body: Some(false),
            max_response_chars: None,
            include_type_edges: None,
            target: target.map(str::to_string),
        },
    )
}

/// The CLI walker behind the daemon's `trace_data_flow` route refuses a member
/// name several owners share with every candidate, typed so the MCP route
/// answers with the shared candidates reply rather than a walk from one of them.
#[test]
fn the_cli_walker_refuses_a_shared_member_focal_with_every_candidate() {
    let graph = python_graph();
    let error = walk(&graph, "get", None).expect_err("a shared member name is no focal");
    let shared = error
        .downcast_ref::<kin_cli::commands::trace_data_flow::SharedMemberFocal>()
        .unwrap_or_else(|| panic!("typed for the MCP route: {error}"));
    let mut named: Vec<&str> = shared.candidates.iter().map(|e| e.name.as_str()).collect();
    named.sort_unstable();
    assert_eq!(named, vec!["Scaffold.get", "_AppCtxGlobals.get"]);
    let text = shared.lines.join("\n");
    assert!(!text.contains("get_db"), "{text}");
    for candidate in &shared.candidates {
        assert!(text.contains(&candidate.id.to_string()), "{text}");
    }
}

/// A shared member name given as the walk's `target` is disclosed with every
/// candidate by id, and the walk still answers from its focal.
#[test]
fn the_cli_walker_discloses_a_shared_member_target_by_id() {
    let graph = python_graph();
    let expected = resolve_entity(&graph, "get", &IdentityQualifiers::default()).unwrap();
    let response = walk(&graph, "index", Some("get")).expect("the walk answers from its focal");
    let disclosed = response
        .degradations
        .iter()
        .find(|entry| entry.reason == "target_ambiguous")
        .unwrap_or_else(|| panic!("{:?}", response.degradations));
    for candidate in &expected.candidates {
        assert!(
            disclosed.detail.contains(&candidate.id.to_string()),
            "{}",
            disclosed.detail
        );
    }
    assert!(response
        .degradations
        .iter()
        .all(|entry| entry.reason != "target_not_resolved"));
}

/// Go names a method by its receiver type, so the same rule applies there.
#[tokio::test]
async fn a_go_method_is_reached_by_its_bare_name() {
    let graph = graph_of(vec![parse(
        &GoAdapter,
        "internal/server/server.go",
        SERVER_GO,
    )]);

    let lone = resolve_entity(&graph, "Close", &IdentityQualifiers::default()).unwrap();
    assert_eq!(names(&lone.candidates), vec!["Server.Close"]);
    assert!(!lone.needs_a_pin());

    let shared = resolve_entity(&graph, "Handle", &IdentityQualifiers::default()).unwrap();
    assert!(shared.shares_member_name());
    let mut reached = names(&shared.candidates);
    reached.sort_unstable();
    assert_eq!(reached, vec!["Client.Handle", "Server.Handle"]);

    let mcp = json(
        &kin_mcp::handlers::entities::handle_find_references(
            &args(&[("query", serde_json::json!("Handle"))]),
            &graph,
            None,
        )
        .await
        .unwrap(),
    );
    assert_eq!(mcp["candidate_count"], 2, "{mcp}");
}

/// TypeScript names a class member by its class, so the same rule applies
/// there, and a function whose name only starts with the member name is not
/// one of its candidates.
#[test]
fn a_typescript_member_is_reached_by_its_bare_name() {
    let graph = graph_of(vec![parse(&TypeScriptAdapter, "src/router.ts", ROUTER_TS)]);

    let lone = resolve_entity(&graph, "route", &IdentityQualifiers::default()).unwrap();
    assert_eq!(names(&lone.candidates), vec!["Router.route"]);

    let shared = resolve_entity(&graph, "get", &IdentityQualifiers::default()).unwrap();
    assert!(shared.shares_member_name());
    let mut reached = names(&shared.candidates);
    reached.sort_unstable();
    assert_eq!(reached, vec!["Cache.get", "Router.get"]);
}
