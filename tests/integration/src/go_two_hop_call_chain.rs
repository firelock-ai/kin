// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A two-hop Go call chain across two packages, through the real parser, the
//! real linker and the real context builder.
//!
//! The chain is the one a caller asks `kin trace` for: `apiRun` in package
//! `api` calls `HttpRequest` in package `httptransport`, which calls
//! `roundTrip` beside it. Both hops are ordinary cross-file `Calls` edges and
//! the graph holds both.
//!
//! On `cli/cli` v2.101.0 the graph held exactly this shape for
//! `apiRun -Calls-> httpRequest` at `pkg/cmd/api/api.go:434`, `kin path` walked
//! it forward in one hop, and `kin trace apiRun` named `httpRequest` zero times
//! while naming four cross-package entities the focal does not call. The
//! dependency section was ordered by a neighbourhood-wide relation weight that
//! cannot tell a call the focal makes from a call made two hops away, every
//! candidate tied at the `Calls` weight, the tie fell through to a uuid, and
//! the row landed 33rd of 39 with `--nearby 12` printing the first twelve.
//!
//! So this grades the three facts a trace of that shape rests on: the focal's
//! own call is in the section, the section leads with the calls the focal
//! makes, and the second hop is reachable the same way from the first.

use std::collections::HashMap;

use kin_context::{
    build_context_pack, focal_dependency_edges, ContextOptions, FocalEdge, FocalEdgeDirection,
    NO_FOCAL_EDGE_RANK,
};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityId, EntityStore, FilePathId, RelationKind, TokenBudget};
use kin_parser::{GoAdapter, LanguageAdapter};

const API_GO: &str = r#"package api

import (
	"fmt"

	"github.com/example/gh/internal/httptransport"
)

func apiRun(path string) error {
	params, err := parseFields(path)
	if err != nil {
		return err
	}
	resp, err := httptransport.HttpRequest(path, params)
	if err != nil {
		return err
	}
	return processResponse(resp)
}

func parseFields(path string) (string, error) {
	return path, nil
}

func processResponse(body string) error {
	fmt.Println(body)
	return nil
}
"#;

const TRANSPORT_GO: &str = r#"package httptransport

func HttpRequest(path string, params string) (string, error) {
	return roundTrip(path + params)
}

func roundTrip(request string) (string, error) {
	return request, nil
}
"#;

fn parse(file_path: &str, source: &str) -> FileParseData {
    let adapter = GoAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter
        .parse(bytes)
        .expect("the Go adapter parses the fixture");
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("the Go adapter extracts the fixture");
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

fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| {
            let known: Vec<&str> = files
                .iter()
                .flat_map(|f| f.entities.iter())
                .map(|e| e.name.as_str())
                .collect();
            panic!("entity `{name}` in `{file}` not found; the fixture holds {known:?}")
        })
        .id
}

/// Parse both packages, link them, and load the result into a graph.
fn linked_graph() -> (InMemoryGraph, Vec<FileParseData>) {
    let files = vec![
        parse("pkg/cmd/api/api.go", API_GO),
        parse("internal/httptransport/transport.go", TRANSPORT_GO),
    ];
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity");

    let store = InMemoryGraph::new();
    for file in &files {
        for entity in &file.entities {
            store.upsert_entity(entity).expect("fixture entity");
        }
    }
    // Entity-to-entity edges only. The linker also emits artifact-level import
    // edges, and this fixture admits entities directly rather than through a
    // repository tree transaction, so an artifact endpoint has no admitted
    // artifact to point at. The dependency section reads only entity-to-entity
    // edges anyway, which is what `relation_is_entity_only` gates in the store.
    for relation in &relations {
        if relation.src.as_entity().is_none() || relation.dst.as_entity().is_none() {
            continue;
        }
        store.upsert_relation(relation).expect("fixture relation");
    }
    (store, files)
}

/// Names in one pack's dependency section, in the order the section holds them.
fn dependency_names(store: &InMemoryGraph, focal: &EntityId, budget: TokenBudget) -> Vec<String> {
    let pack = build_context_pack(
        store,
        focal,
        &ContextOptions {
            budget,
            ..ContextOptions::default()
        },
    )
    .expect("the builder answers for a focal the graph holds");
    pack.dependency_signatures
        .iter()
        .map(|entry| {
            store
                .get_entity(&entry.entity_id)
                .expect("graph read")
                .expect("a pack row names an entity the graph holds")
                .name
        })
        .collect()
}

#[test]
fn a_two_hop_go_call_chain_is_named_hop_by_hop() {
    let (store, files) = linked_graph();
    let api_run = entity_id(&files, "pkg/cmd/api/api.go", "apiRun");
    let http_request = entity_id(&files, "internal/httptransport/transport.go", "HttpRequest");
    let round_trip = entity_id(&files, "internal/httptransport/transport.go", "roundTrip");

    // The control. A fixture whose parser or linker produced no cross-package
    // call would grade the builder on an edge that was never there, and would
    // read exactly like the builder losing one.
    let api_edges = focal_dependency_edges(
        &api_run,
        &store
            .get_all_relations_for_entity(&api_run)
            .expect("graph read"),
    );
    assert_eq!(
        api_edges.get(&http_request).copied(),
        Some(FocalEdge {
            kind: RelationKind::Calls,
            direction: FocalEdgeDirection::Outgoing,
        }),
        "the fixture must hold the cross-package call; fix the fixture, not the assertion"
    );

    let transport_edges = focal_dependency_edges(
        &http_request,
        &store
            .get_all_relations_for_entity(&http_request)
            .expect("graph read"),
    );
    assert_eq!(
        transport_edges.get(&round_trip).copied(),
        Some(FocalEdge {
            kind: RelationKind::Calls,
            direction: FocalEdgeDirection::Outgoing,
        }),
        "the fixture must hold the second hop; fix the fixture, not the assertion"
    );

    let hop_one = dependency_names(&store, &api_run, TokenBudget::Large32k);
    assert!(
        hop_one.contains(&"HttpRequest".to_string()),
        "hop one is missing from the section: {hop_one:?}"
    );

    let hop_two = dependency_names(&store, &http_request, TokenBudget::Large32k);
    assert!(
        hop_two.contains(&"roundTrip".to_string()),
        "hop two is missing from the section: {hop_two:?}"
    );
}

#[test]
fn the_section_leads_with_the_calls_the_focal_makes() {
    let (store, files) = linked_graph();
    let api_run = entity_id(&files, "pkg/cmd/api/api.go", "apiRun");
    let relations = store
        .get_all_relations_for_entity(&api_run)
        .expect("graph read");
    let edges = focal_dependency_edges(&api_run, &relations);

    // Every call the focal makes, straight from the graph, with no ranking in
    // the way. This is the set the section may not lose rows from.
    let calls: Vec<EntityId> = edges
        .iter()
        .filter(|(_, edge)| edge.is_outgoing_call())
        .map(|(id, _)| *id)
        .collect();
    assert!(
        calls.len() >= 3,
        "the fixture must give the focal several callees or the ordering is untested: {}",
        calls.len()
    );

    let pack = build_context_pack(
        &store,
        &api_run,
        &ContextOptions {
            budget: TokenBudget::Large32k,
            ..ContextOptions::default()
        },
    )
    .expect("the builder answers for a focal the graph holds");
    let rows: Vec<EntityId> = pack
        .dependency_signatures
        .iter()
        .map(|entry| entry.entity_id)
        .collect();

    for call in &calls {
        assert!(
            rows.contains(call),
            "the section dropped a call the graph holds: {:?}",
            store.get_entity(call).ok().flatten().map(|e| e.name)
        );
    }

    // No row that is not a call the focal makes may sit above one that is. The
    // old order interleaved them by a weight every candidate tied on, so the
    // rank the caller's limit cut against was a uuid.
    let mut seen_non_call = None;
    for id in &rows {
        let is_call = edges.get(id).is_some_and(FocalEdge::is_outgoing_call);
        match (&seen_non_call, is_call) {
            (Some(earlier), true) => panic!(
                "a call sorted below a row that is not one: {:?} came after {:?}",
                store.get_entity(id).ok().flatten().map(|e| e.name),
                store.get_entity(earlier).ok().flatten().map(|e| e.name),
            ),
            (None, false) => seen_non_call = Some(*id),
            _ => {}
        }
    }

    // A row the focal holds no edge to ranks below every row it does, whatever
    // relation weight the neighbourhood gave it.
    let stranger = EntityId::new();
    assert_eq!(
        kin_context::focal_edge_rank(&edges, &stranger),
        NO_FOCAL_EDGE_RANK
    );
    assert_eq!(
        kin_context::focal_edge_rank(
            &edges,
            &entity_id(&files, "internal/httptransport/transport.go", "HttpRequest")
        ),
        0
    );
}
