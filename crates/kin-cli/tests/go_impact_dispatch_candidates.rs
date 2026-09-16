// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin impact` on a Go method only a dynamic dispatch reaches.
//!
//! The same fixture shape `kin-index/tests/go_interface_dispatch_candidates.rs`
//! asserts the computation on, carried through the command that answers "what
//! breaks if I change this". That question is the one a dispatch candidate is
//! most dangerous to get wrong in both directions, so the rows are listed under
//! their own count, with the interface method each came through named, and the
//! impacted total does not move.
//!
//! One thing this fixture is NOT is a graph where the concrete method has no
//! dependents. These files are linked by the real cross-file linker with no
//! language server, and `sink.Write(payload)` arrives with the bare callee name
//! `Write`, so the bare-name fan-out binds it to every same-named method in
//! another file. The walk therefore hands `emit` to `Buffer.Write` and to
//! `Counter.Write` alike and is wrong about one of them. That is the contrast
//! `the_bare_name_walk_reaches_both_types_and_only_one_earns_a_candidate`
//! asserts, and it is a better argument for the section than an empty walk
//! would have been. An earlier version of this file asserted the empty walk and
//! was wrong about its own fixture.

use kin_cli::commands::impact::{build_impact_response, ImpactRequest, ImpactResponse};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use std::collections::HashMap;

use kin_model::{
    ArtifactId, Entity, EntityFilter, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry,
    Relation, RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_parser::{GoAdapter, LanguageAdapter};

const CONTRACT: &str = r#"
package gh

type Writer interface {
	Write(p []byte) (int, error)
	Close() error
}
"#;

const BUFFER: &str = r#"
package buf

type Buffer struct {
	data []byte
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *Buffer) Close() error {
	return nil
}
"#;

const COUNTER: &str = r#"
package count

type Counter struct {
	n int
}

func (c *Counter) Write(p []byte) (int, error) {
	c.n += len(p)
	return len(p), nil
}
"#;

const CALLER: &str = r#"
package app

func emit(sink Writer, payload []byte) error {
	if _, err := sink.Write(payload); err != nil {
		return err
	}
	return sink.Close()
}
"#;

fn admit_file_artifacts(
    graph: &InMemoryGraph,
    files: &[FileParseData],
) -> HashMap<String, ArtifactId> {
    let mut artifact_ids = HashMap::new();
    for file in files {
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
    artifact_ids
}

fn parse_go(file_path: &str, source: &str) -> FileParseData {
    let adapter = GoAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("fixture parses");
    let file_id = FilePathId::new(file_path.to_string());
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

fn entity_named(graph: &InMemoryGraph, name: &str) -> Entity {
    graph
        .query_entities(&EntityFilter::default())
        .expect("the store answers")
        .into_iter()
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("the graph holds an entity named {name}"))
}

/// The graph a repository with a Go language server has.
///
/// The one edge added by hand is the call site's own resolution: `sink.Write(p)`
/// reaches the graph with the bare callee name and gopls is what binds it to
/// the interface's method object, which is what the Go type checker does too.
/// Stated here rather than simulated so the assumption stays visible.
fn project() -> InMemoryGraph {
    let files = vec![
        parse_go("internal/gh/contract.go", CONTRACT),
        parse_go("internal/buf/buffer.go", BUFFER),
        parse_go("internal/count/counter.go", COUNTER),
        parse_go("cmd/app/emit.go", CALLER),
    ];
    let graph = InMemoryGraph::new();
    let artifact_ids = admit_file_artifacts(&graph, &files);
    let relations = link_cross_file(&files, &artifact_ids).expect("link fixture");
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }

    let emit = entity_named(&graph, "emit");
    for contract_method in ["Writer.Write", "Writer.Close"] {
        let spec = entity_named(&graph, contract_method);
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(emit.id),
                dst: GraphNodeId::Entity(spec.id),
                confidence: 1.0,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .expect("the call edge lands");
    }
    graph
}

fn envelope() -> kin_mcp::Envelope {
    kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
        "initialized": true,
        "graph_loaded": true,
        "graph_entity_count": 20,
        "graph_generation": 1,
    }))
}

async fn impact(graph: &InMemoryGraph, entity: &str, dispatch: bool) -> ImpactResponse {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    build_impact_response(
        &layout,
        graph,
        &ImpactRequest {
            entity: entity.to_string(),
            depth: 3,
            file: None,
            kind: None,
            signature: None,
            require_unique: false,
            dispatch_candidates: dispatch,
        },
        &envelope(),
    )
    .await
    .expect("impact response")
}

fn dispatch_rows(response: &ImpactResponse) -> Vec<&String> {
    response
        .lines
        .iter()
        .filter(|line| line.contains("(dispatch_candidate)"))
        .collect()
}

fn headline(response: &ImpactResponse) -> Option<&String> {
    response
        .lines
        .iter()
        .find(|line| line.contains("interface-dispatch candidate"))
}

/// The section stays out of the answer until it is asked for.
#[tokio::test]
async fn no_dispatch_section_appears_without_the_flag() {
    let graph = project();
    let response = impact(&graph, "Buffer.Write", false).await;

    assert_eq!(response.resolution, "resolved");
    let rendered = response.lines.join("\n");
    assert!(
        headline(&response).is_none() && dispatch_rows(&response).is_empty(),
        "the section must not appear unless it was asked for: {rendered}"
    );
}

/// Why a dispatch candidate is worth computing even where the walk already
/// names a dependent.
///
/// `sink.Write(payload)` reaches the linker with the bare callee name `Write`,
/// and with no language server the bare-name fan-out binds it to EVERY
/// same-named method in another file at
/// `kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE`. So the impact walk
/// hands `emit` to `Buffer.Write` and to `Counter.Write` alike, and it is wrong
/// about exactly one of them: `Counter` has no `Close` and satisfies no
/// contract the call site names.
///
/// The dispatch computation tells them apart, because it is grounded in the
/// method set rather than in the leaf name. This test is the contrast, and it
/// is the reason the section is worth reading next to the walk rather than
/// instead of it.
#[tokio::test]
async fn the_bare_name_walk_reaches_both_types_and_only_one_earns_a_candidate() {
    let graph = project();

    let buffer_walk = impact(&graph, "Buffer.Write", false).await;
    let counter_walk = impact(&graph, "Counter.Write", false).await;
    let names = |response: &ImpactResponse| -> Vec<String> {
        response
            .lines
            .iter()
            .filter_map(|line| line.strip_prefix("    - "))
            .filter_map(|row| row.split(" (").next())
            .map(str::to_string)
            .collect()
    };
    assert!(
        names(&buffer_walk).contains(&"emit".to_string()),
        "the fan-out reaches the satisfying type: {:?}",
        buffer_walk.lines
    );
    assert!(
        names(&counter_walk).contains(&"emit".to_string()),
        "and reaches the one that satisfies nothing, which is the guess: {:?}",
        counter_walk.lines
    );

    let buffer = impact(&graph, "Buffer.Write", true).await;
    let counter = impact(&graph, "Counter.Write", true).await;
    assert_eq!(
        dispatch_rows(&buffer).len(),
        1,
        "Buffer satisfies Writer, so the call through it is a candidate: {:?}",
        buffer.lines
    );
    assert!(
        dispatch_rows(&counter).is_empty(),
        "Counter satisfies nothing, so it earns none: {:?}",
        counter.lines
    );
}

#[tokio::test]
async fn the_flag_lists_the_call_site_written_against_the_interface() {
    let graph = project();
    let response = impact(&graph, "Buffer.Write", true).await;

    let rows = dispatch_rows(&response);
    assert_eq!(
        rows.len(),
        1,
        "the caller written against Writer is the one candidate: {:?}",
        response.lines
    );
    assert!(
        rows[0].contains("emit") && rows[0].contains("via Writer.Write"),
        "the row names the caller and the interface method it came through: {}",
        rows[0]
    );

    let headline = headline(&response).expect("a headline beside the rows");
    assert!(
        headline.contains("not counted above") && headline.contains("possible and unproven"),
        "the count and the claim travel together, in the wording kin refs uses: {headline}"
    );
}

/// The whole reason this rides beside the walk rather than inside it. `kin
/// impact` answers what breaks, and a maybe must not move that number.
#[tokio::test]
async fn the_impacted_total_is_identical_with_and_without_the_flag() {
    let graph = project();
    let plain = impact(&graph, "Buffer.Write", false).await;
    let with_candidates = impact(&graph, "Buffer.Write", true).await;

    let walk_lines = |response: &ImpactResponse| -> Vec<String> {
        response
            .lines
            .iter()
            .filter(|line| {
                !line.contains("interface-dispatch") && !line.contains("dispatch_candidate")
            })
            .cloned()
            .collect()
    };
    assert_eq!(
        walk_lines(&plain),
        walk_lines(&with_candidates),
        "the flag may only add its own section; every other line must be byte-identical"
    );
}

/// The control. `Counter` has `Write` and no `Close`, so it satisfies no
/// contract the call site names, and a method-name match alone must not carry
/// it into an impact answer.
#[tokio::test]
async fn a_type_that_misses_one_contract_method_gets_no_candidates() {
    let graph = project();
    let response = impact(&graph, "Counter.Write", true).await;

    assert!(
        dispatch_rows(&response).is_empty(),
        "Counter has no Close: {:?}",
        response.lines
    );
    let headline = headline(&response).expect("the section is answered at zero too");
    assert!(
        headline.contains("satisfies no interface this graph holds"),
        "a reader deciding whether the method is dead is told why the list is empty: {headline}"
    );
}

/// Asked for and answered even when the focal is the wrong shape entirely, for
/// the same reason: a section that appears only when it has rows is one no
/// reader learns to look for.
#[tokio::test]
async fn a_non_go_method_focal_says_why_it_has_no_candidates() {
    let graph = project();
    let response = impact(&graph, "Buffer", true).await;

    let headline = headline(&response).expect("the section is answered for any focal");
    assert!(
        headline.contains("computed for Go methods"),
        "the reason names the rule rather than leaving an empty list: {headline}"
    );
}
