// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end cover for the answers `kin refs` and `kin impact` give on a type
//! declaration whose members live in other files.
//!
//! The fixture is the shape `anyhow` has: `pub struct Error` is declared in
//! `src/lib.rs`, its `impl` blocks are split across `src/lib.rs` and
//! `src/error.rs`, callers reach the members rather than the type, and a
//! same-named private declaration sits in a `tests/ui` fixture. Run through the
//! real Rust parser and the real cross-file linker, that produces a graph where
//! the type declaration owns no incoming Calls/Imports/References edge at all,
//! while its members own several.
//!
//! Both commands used to answer that with a bare empty line, which reads as
//! "nothing depends on this type" when the graph plainly says otherwise. These
//! tests pin the honest answer instead, and pin that a genuinely unreferenced
//! entity still gets the plain empty one.

use kin_cli::commands::impact::{build_impact_response, ImpactRequest};
use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityStore, FilePathId};
use kin_parser::{LanguageAdapter, RustAdapter};

const LIB_RS: &str = r#"mod error;
mod user;

pub struct Error {
    code: u32,
}

impl Error {
    pub fn msg(code: u32) -> Self {
        Error { code }
    }
}
"#;

const ERROR_RS: &str = r#"use crate::Error;

impl Error {
    pub fn chain(&self) -> u32 {
        self.code
    }
}
"#;

const USER_RS: &str = r#"use crate::Error;

pub fn build() -> Error {
    Error::msg(1)
}

pub fn read(e: &Error) -> u32 {
    e.chain()
}
"#;

const UI_RS: &str = r#"struct Error;

fn main() {
    let _ = Error;
}
"#;

fn parse_rs(file_path: &str, source: &str) -> FileParseData {
    let adapter = RustAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse fixture");
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

/// The fixture repository, ingested through the real parser and linker.
pub fn anyhow_shaped_graph() -> InMemoryGraph {
    let files = vec![
        parse_rs("src/lib.rs", LIB_RS),
        parse_rs("src/error.rs", ERROR_RS),
        parse_rs("src/user.rs", USER_RS),
        parse_rs("tests/ui/no-impl.rs", UI_RS),
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
    graph
}

fn layout() -> (tempfile::TempDir, kin_core::KinLayout) {
    let dir = tempfile::tempdir().unwrap();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    (dir, layout)
}

fn refs_lines(graph: &InMemoryGraph, entity: &str) -> String {
    let (_dir, layout) = layout();
    build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: entity.to_string(),
            kind: "all".to_string(),
        },
        // Substrate sound, so the FIR-2524 absence qualifier answers on coverage
        // rather than on the envelope. These cases assert refs CONTENT.
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 2,
            "graph_generation": 1,
        })),
    )
    .expect("refs response")
    .lines
    .join("\n")
}

async fn impact_lines(graph: &InMemoryGraph, entity: &str, file: Option<&str>) -> String {
    let (_dir, layout) = layout();
    build_impact_response(
        &layout,
        graph,
        &ImpactRequest {
            entity: entity.to_string(),
            depth: 3,
            file: file.map(ToOwned::to_owned),
            kind: None,
            signature: None,
            require_unique: false,
        },
        // Substrate sound, so the FIR-2524 absence qualifier answers on coverage
        // rather than on the envelope. These cases assert impact CONTENT.
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 2,
            "graph_generation": 1,
        })),
    )
    .await
    .expect("impact response")
    .lines
    .join("\n")
}

/// The premise every assertion below rests on: the linker really does leave the
/// type declaration with no incoming reference edge, while its members carry
/// them. Without this the tests could pass for the wrong reason.
#[test]
fn fixture_premise_declaration_owns_no_incoming_edges_but_members_do() {
    let graph = anyhow_shaped_graph();
    let declaration = graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("Error".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| {
            entity.name == "Error"
                && entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some("src/lib.rs")
        })
        .expect("Error declared in src/lib.rs");

    let incoming: Vec<_> = graph
        .get_all_relations_for_entity(&declaration.id)
        .unwrap()
        .into_iter()
        .filter(|relation| {
            relation.dst == kin_model::GraphNodeId::Entity(declaration.id)
                && matches!(
                    relation.kind,
                    kin_model::RelationKind::Calls
                        | kin_model::RelationKind::Imports
                        | kin_model::RelationKind::References
                )
        })
        .collect();
    assert!(
        incoming.is_empty(),
        "fixture premise: the declaration must own no incoming reference edge, got {incoming:?}"
    );

    for member in ["Error::msg", "Error::chain"] {
        let entity = graph
            .query_entities(&kin_model::EntityFilter {
                name_pattern: Some(member.to_string()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == member)
            .unwrap_or_else(|| panic!("{member} in the fixture graph"));
        let callers = graph
            .get_all_relations_for_entity(&entity.id)
            .unwrap()
            .into_iter()
            .filter(|relation| relation.dst == kin_model::GraphNodeId::Entity(entity.id))
            .count();
        assert!(
            callers > 0,
            "fixture premise: {member} must carry incoming edges"
        );
    }
}

/// Why the listing is gathered by name and not by the containment edge.
///
/// The Rust extractor emits a `Contains` for both `impl` blocks, but the linker
/// keys containment against a declaration in the same file, and `src/error.rs`
/// declares none. So the cross-file edge is dropped and the declaration is left
/// owning exactly one outgoing `Contains`, to its same-file member. Collecting
/// members from edges alone would therefore lose `Error::chain`, which is the
/// member this whole answer exists to surface.
///
/// If this reddens because the declaration now owns an edge to `Error::chain`,
/// the graph gap is closed and the collector should move to edges, where a
/// declaration's members can be told from a same-named declaration's.
#[test]
fn fixture_premise_containment_reaches_only_the_same_file_member() {
    let graph = anyhow_shaped_graph();
    let declaration = graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("Error".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| {
            entity.name == "Error"
                && entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some("src/lib.rs")
        })
        .expect("Error declared in src/lib.rs");

    let contained: Vec<String> = graph
        .get_all_relations_for_entity(&declaration.id)
        .unwrap()
        .into_iter()
        .filter(|relation| {
            relation.kind == kin_model::RelationKind::Contains
                && relation.src == kin_model::GraphNodeId::Entity(declaration.id)
        })
        .filter_map(|relation| relation.dst.as_entity())
        .filter_map(|id| graph.get_entity(&id).unwrap())
        .map(|entity| entity.name)
        .collect();

    assert_eq!(
        contained,
        vec!["Error::msg".to_string()],
        "containment must reach the same-file member and not the cross-file one"
    );
}

#[test]
fn refs_on_a_declaration_names_the_members_that_carry_references() {
    let graph = anyhow_shaped_graph();
    let joined = refs_lines(&graph, "Error");

    assert!(
        joined.contains("No incoming"),
        "the empty signal itself must be preserved: {joined}"
    );
    assert!(
        joined.contains("Error::msg") && joined.contains("src/lib.rs"),
        "must name the member that carries references, with its file: {joined}"
    );
    assert!(
        joined.contains("Error::chain") && joined.contains("src/error.rs"),
        "must name a member declared in another file, with its file: {joined}"
    );
    assert!(
        joined.contains("kin refs Error::"),
        "must offer a runnable next command: {joined}"
    );
}

/// The count in the note and the count the suggested command prints are read
/// through one collector, so they cannot drift apart. A note advertising three
/// referencing entities beside a command that then lists one is worse than no
/// note at all.
#[test]
fn the_member_count_in_the_note_is_the_count_its_suggested_command_prints() {
    let graph = anyhow_shaped_graph();
    let note = refs_lines(&graph, "Error");
    let advertised = note
        .lines()
        .find(|line| line.trim_start().starts_with("Error::msg @"))
        .expect("the note lists Error::msg");
    assert!(
        advertised.contains("[1 referencing entity]"),
        "note line: {advertised}"
    );

    let member = refs_lines(&graph, "Error::msg");
    assert!(
        member.contains("referenced by 1 entities:"),
        "the suggested command must report the advertised count: {member}"
    );
}

#[test]
fn refs_on_a_declaration_names_the_other_identities_sharing_the_name() {
    let graph = anyhow_shaped_graph();
    let joined = refs_lines(&graph, "Error");
    assert!(
        joined.contains("tests/ui/no-impl.rs"),
        "must name the same-named identity it did not choose: {joined}"
    );
}

/// The falsification the ticket asks for: an entity that genuinely has no
/// incoming references, no members, and no same-named sibling must still get the
/// plain empty answer. If this reddens, the honest-empty note has become
/// unconditional and stopped carrying information.
#[test]
fn genuinely_unreferenced_entity_still_gets_the_plain_empty_answer() {
    let graph = anyhow_shaped_graph();
    let joined = refs_lines(&graph, "read");
    assert!(
        joined.contains("No incoming"),
        "must report the empty result: {joined}"
    );
    assert_eq!(
        joined.lines().count(),
        2,
        "an entity with nothing further to report gets exactly the header and the empty line: {joined}"
    );
}

#[tokio::test]
async fn impact_on_a_declaration_names_the_members_that_carry_impact() {
    let graph = anyhow_shaped_graph();
    let joined = impact_lines(&graph, "Error", None).await;

    assert!(
        joined.contains("Error::msg") || joined.contains("Error::chain"),
        "must name the members whose dependents exist: {joined}"
    );
    assert!(
        joined.contains("kin impact Error::"),
        "must offer a runnable next command: {joined}"
    );
    assert!(
        joined.contains("tests/ui/no-impl.rs"),
        "the ambiguity note must name the identity it did not choose: {joined}"
    );
}

#[tokio::test]
async fn impact_on_a_genuinely_isolated_entity_still_reports_plain_empty() {
    let graph = anyhow_shaped_graph();
    let joined = impact_lines(&graph, "read", None).await;
    assert!(
        joined.contains("No local downstream impact found"),
        "must report the empty result: {joined}"
    );
    assert!(
        !joined.contains("try:"),
        "nothing further to offer means no next-step note: {joined}"
    );
}

/// `--file` narrows the candidates the ordinary lookup already found.
/// When it narrows them to none, the answer must say the filter matched nothing
/// and name what the name itself resolves to. Claiming the entity is absent from
/// the graph is false: the unfiltered lookup just found it.
#[tokio::test]
async fn impact_file_qualifier_that_matches_nothing_reports_a_filter_miss() {
    let graph = anyhow_shaped_graph();
    let joined = impact_lines(&graph, "Error", Some("src/error.rs")).await;

    assert!(
        !joined.contains("not found in this repo's graph"),
        "must not claim the entity is absent when the name resolves: {joined}"
    );
    assert!(
        joined.contains("src/error.rs"),
        "must name the qualifier that matched nothing: {joined}"
    );
    assert!(
        joined.contains("src/lib.rs") && joined.contains("tests/ui/no-impl.rs"),
        "must name the identities the unfiltered lookup does find: {joined}"
    );
}

/// A name that really is absent must still get the not-found answer, so the
/// filter-miss wording above cannot be reached by simply never reporting a miss.
#[tokio::test]
async fn absent_name_still_reports_not_found() {
    let graph = anyhow_shaped_graph();
    let joined = impact_lines(&graph, "NoSuchSymbol", Some("src/error.rs")).await;
    assert!(
        joined.contains("not found in this repo's graph"),
        "a genuinely absent name keeps the not-found answer: {joined}"
    );
}

/// The listing is gathered by name qualification, and the graph does not tie a
/// declaration to members declared in another file, so the wording has to claim
/// a shared name and not ownership.
///
/// `tests/ui/no-impl.rs` declares a unit `struct Error;` that owns nothing at
/// all, and qualifying an ordinary command to it is reachable from the CLI.
/// Telling that declaration it owns `Error::msg` and `Error::chain`, which
/// belong to the `Error` in `src/lib.rs`, is the same answer that is true of
/// nothing and wrong about the repository, pointed the other way.
#[tokio::test]
async fn a_memberless_declaration_is_not_told_it_owns_the_other_declarations_members() {
    let graph = anyhow_shaped_graph();
    let joined = impact_lines(&graph, "Error", Some("tests/ui/no-impl.rs")).await;

    assert!(
        joined.contains("Error::msg") || joined.contains("Error::chain"),
        "the entities the name qualifies are still worth naming: {joined}"
    );
    assert!(
        !joined.contains("member"),
        "a declaration that owns no members must not be told it has them: {joined}"
    );
    assert!(
        joined.contains("named 'Error::*'"),
        "the listing must say it is scoped by name: {joined}"
    );
}

/// The same claim on the `refs` surface. Resolution by name prefers the
/// `src/lib.rs` identity, so the memberless one is reached by id, which is a
/// spelling `kin refs` accepts.
#[test]
fn refs_scopes_the_listing_by_name_rather_than_claiming_ownership() {
    let graph = anyhow_shaped_graph();
    let memberless = graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("Error".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| {
            entity.name == "Error"
                && entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some("tests/ui/no-impl.rs")
        })
        .expect("the unit struct Error in tests/ui/no-impl.rs");

    let joined = refs_lines(&graph, &memberless.id.0.to_string());
    assert!(
        joined.contains("Error::msg") && joined.contains("Error::chain"),
        "the entities the name qualifies are still worth naming: {joined}"
    );
    assert!(
        !joined.contains("member"),
        "a declaration that owns no members must not be told it has them: {joined}"
    );
    assert!(
        joined.contains("named 'Error::*'"),
        "the listing must say it is scoped by name: {joined}"
    );
}
