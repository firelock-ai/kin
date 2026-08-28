// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FIR-2828, the reading half. Does the arrival gate's arithmetic actually run
//! on a store built by the product's own path?
//!
//! `kin_mcp::caller_arrival` decides whether an empty reference list may be read
//! as the whole truth by subtracting a family file's resolved `Calls` edges from
//! the call sites the parser read there. Before this fixture existed, that
//! subtraction had never happened on a real Python store: the extractor withheld
//! the parse-side count from any file whose call extraction it could not fully
//! represent, so every family file landed in the gate's absent-count branch and
//! a file whose every call became an edge was indistinguishable from one holding
//! calls the graph never saw.
//!
//! The fixture is built so the two are distinguishable only if the arithmetic
//! runs. Both family files reach the focal's file through a direct-name import,
//! so both hold an `Imports` edge and both land in the family. `clean.py`
//! resolves every call it writes. `messy.py` writes one more through a subscript
//! callee the extractor cannot name, so its call sites and its edges differ by
//! exactly one. A gate reading a count taken off the emitted relations rather
//! than off the file's call sites certifies `messy.py` too.

use std::collections::HashMap;

use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData, IndexPipeline};
use kin_mcp::caller_arrival::{observe_caller_arrival, ArrivalState};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, Hash256, LocatedEntry, RelationKind, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};

const STORE_PY: &str = r#"def open_db():
    return {}


def note_body(db, note_id):
    return ""
"#;

/// Two call sites, and the linker records an edge for both. The receiver call
/// is what made the extractor withhold this file's count.
const CLEAN_PY: &str = r#"from notepkg import store
from notepkg.store import note_body


def summarize(note_id):
    db = store.open_db()
    return note_body(db, note_id)
"#;

/// Three call sites, two edges. `handlers["render"](body)` has no name the
/// extractor can bind, so it produces no relation at all.
const MESSY_PY: &str = r#"from notepkg import store
from notepkg.store import note_body


def summarize_messy(note_id, handlers):
    db = store.open_db()
    body = note_body(db, note_id)
    return handlers["render"](body)
"#;

/// The same family shape as `messy.py` with the unnameable call removed, so the
/// control differs from the subject in exactly one call site.
const SECOND_CLEAN_PY: &str = r#"from notepkg import store
from notepkg.store import note_body


def summarize_again(note_id):
    db = store.open_db()
    return note_body(db, note_id)
"#;

fn parse(path: &str, source: &str) -> (FileParseData, Vec<Entity>) {
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(path),
            source.as_bytes(),
            kin_blobs::Hash256::from_bytes([5; 32]),
        )
        .unwrap_or_else(|error| panic!("indexing {path} failed: {error}"))
        .indexed_file;
    (
        FileParseData {
            file_path: path.to_string(),
            entities: indexed.entities.clone(),
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        },
        indexed.entities,
    )
}

/// Admit one artifact per parsed file, the way a persist gate requires, and
/// return the identity map the linker takes.
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

fn project(sources: &[(&str, &str)]) -> (InMemoryGraph, Vec<Entity>) {
    let parsed: Vec<(FileParseData, Vec<Entity>)> = sources
        .iter()
        .map(|(path, source)| parse(path, source))
        .collect();
    let files: Vec<FileParseData> = parsed.iter().map(|(file, _)| file.clone()).collect();
    let entities: Vec<Entity> = parsed
        .iter()
        .flat_map(|(_, entities)| entities.iter().cloned())
        .collect();

    let graph = InMemoryGraph::new();
    let artifact_ids = admit_file_artifacts(&graph, &files);
    let relations = link_cross_file(&files, &artifact_ids).expect("link fixture");
    for entity in &entities {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    (graph, entities)
}

fn focal(entities: &[Entity], name: &str, file: &str) -> Entity {
    entities
        .iter()
        .find(|entity| {
            entity.name == name && entity.file_origin.as_ref().is_some_and(|f| f.0 == file)
        })
        .unwrap_or_else(|| panic!("fixture entity `{name}` in {file} not found"))
        .clone()
}

/// Resolved `Calls` edges leaving one file, counted the way the gate counts
/// them, so the fixture cannot drift into proving something else.
fn resolved_call_edges(graph: &InMemoryGraph, entities: &[Entity], file: &str) -> u64 {
    let mut total: u64 = 0;
    for entity in entities
        .iter()
        .filter(|entity| entity.file_origin.as_ref().is_some_and(|f| f.0 == file))
    {
        let relations = graph
            .get_all_relations_for_entity(&entity.id)
            .expect("relations read");
        total += relations
            .iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(entity.id)
            })
            .count() as u64;
    }
    total
}

/// The finding, in one reading. The gate must name the file holding a call the
/// graph never saw, and must not name the file whose calls all became edges.
#[test]
fn the_gate_names_only_the_family_file_holding_an_unresolved_call() {
    let (graph, entities) = project(&[
        ("notepkg/__init__.py", ""),
        ("notepkg/store.py", STORE_PY),
        ("notepkg/clean.py", CLEAN_PY),
        ("notepkg/messy.py", MESSY_PY),
    ]);
    let note_body = focal(&entities, "note_body", "notepkg/store.py");

    // The fixture's own premises, asserted before the verdict is read. Without
    // these a family that collapsed to nothing would certify and read as a pass.
    let arrival = observe_caller_arrival(&graph, &note_body);
    assert_eq!(
        arrival.family_files, 2,
        "both importers must reach the family, or the verdict below is about a different set"
    );
    assert_eq!(
        arrival.family_measured, 2,
        "and both must carry a parse-side count, which is the whole point of this ticket"
    );
    assert_eq!(
        resolved_call_edges(&graph, &entities, "notepkg/clean.py"),
        2,
        "the control file's two calls must both become edges, or it is not a clean control"
    );
    assert_eq!(
        resolved_call_edges(&graph, &entities, "notepkg/messy.py"),
        2,
        "and the subject file must resolve the same two, so the only difference between them \
         is the call site that produced no relation"
    );

    assert_eq!(
        arrival.state,
        ArrivalState::Unaccounted,
        "a family file holding a call the graph never saw must stop certification"
    );
    let named: Vec<&str> = arrival
        .unaccounted
        .iter()
        .map(|file| file.file.as_str())
        .collect();
    assert_eq!(
        named,
        vec!["notepkg/messy.py"],
        "and only that file: naming the clean sibling too is the blanket refusal this gate \
         exists to avoid"
    );
    let row = &arrival.unaccounted[0];
    assert_eq!(
        (
            row.parsed_call_sites,
            row.resolved_call_edges,
            row.unaccounted_call_sites
        ),
        (Some(3), 2, Some(1)),
        "and the row must carry the arithmetic it rests on, not a bare refusal"
    );
}

/// The control that keeps the gate from being a blanket refusal over every
/// Python family. Replace the one unnameable call with a sibling that resolves
/// everything, and the same focal certifies.
#[test]
fn a_family_whose_every_call_resolved_still_certifies() {
    let (graph, entities) = project(&[
        ("notepkg/__init__.py", ""),
        ("notepkg/store.py", STORE_PY),
        ("notepkg/clean.py", CLEAN_PY),
        ("notepkg/second.py", SECOND_CLEAN_PY),
    ]);
    let note_body = focal(&entities, "note_body", "notepkg/store.py");

    let arrival = observe_caller_arrival(&graph, &note_body);
    assert_eq!(
        arrival.family_files, 2,
        "the control must have the same family size as the subject"
    );
    assert_eq!(arrival.family_measured, 2, "and the same measured coverage");
    assert_eq!(
        arrival.state,
        ArrivalState::Accounted,
        "a family whose every call site became an edge must certify: {:?}",
        arrival.unaccounted
    );
    assert!(
        arrival.unaccounted.is_empty(),
        "and name nothing: {:?}",
        arrival.unaccounted
    );
}
