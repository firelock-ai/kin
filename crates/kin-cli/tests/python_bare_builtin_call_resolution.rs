// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Acceptance reproduction for the fabricated cross-module call edge a bare
//! Python builtin used to mint (FIR-2400).
//!
//! The fixture is the shape the isolated stranger run hit: a parsing module
//! that reads a file with the builtin `open`, and a storage module it never
//! imports whose `NoteStore` exposes an `open` classmethod. The bare name
//! reached the linker's bare-name index, matched the one entity in the graph
//! carrying it, and `trace_data_flow` from `ingest_directory` walked a whole
//! subtree of a module `parsing.py` cannot see, `default_db_path` included.
//!
//! Everything here runs through the real Python adapter, the real cross-file
//! linker, and a real `InMemoryGraph`, which is what `kin init` builds over an
//! existing tree. The positive controls sit in the same fixture on purpose: the
//! receiver call `NoteStore.open(path)` in `cli.py` must still resolve, so a
//! gate that simply deleted the entity from the graph would fail this file.

use std::sync::Arc;

use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_cli::commands::repository_authority::RequestRepositoryAuthority;
use kin_cli::commands::trace_data_flow::{
    build_trace_data_flow_response, TraceDataFlowRequest, TraceDirection,
};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityStore, FilePathId};
use kin_parser::{LanguageAdapter, PythonAdapter};

/// `parse_file` reads with the builtin `open` and imports nothing from storage.
/// This is the call site the ticket names, verbatim in shape.
const PARSING_PY: &str = r##""""Note parsing."""

import os
import re

TAG_RE = re.compile(r"#(\w+)")


def parse_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    return {"name": os.path.basename(path), "tags": TAG_RE.findall(text)}
"##;

/// `NoteStore.open` is a classmethod, which no bare-name call can invoke, and
/// `default_db_path` is reachable from it. In the measured response those were
/// steps 8 and 16.
const STORAGE_PY: &str = r#""""Note storage."""

import os


def default_db_path(root):
    return os.path.join(root, "notes.json")


class NoteStore:
    def __init__(self, path):
        self.path = path
        self.notes = {}

    @classmethod
    def open(cls, path):
        return cls(default_db_path(path))

    def upsert_note(self, note):
        self.notes[note["name"]] = note
        return note

    def prune_except(self, keep):
        self.notes = {k: v for k, v in self.notes.items() if k in keep}
        return self.notes
"#;

/// The focal. It never calls `NoteStore.open`, so the only route from here to
/// the storage module's classmethod is through `parse_file`'s builtin call.
const INGEST_PY: &str = r#""""Directory ingest."""

import os

from parsing import parse_file


def ingest_directory(path, store):
    for name in os.listdir(path):
        note = parse_file(os.path.join(path, name))
        store.upsert_note(note)
    return store
"#;

/// The positive control for the receiver path: this file imports the class and
/// calls the classmethod through it, which must still resolve.
const CLI_PY: &str = r#""""Command line interface."""

from ingest import ingest_directory
from storage import NoteStore


def open_store(path):
    return NoteStore.open(path)


def main(path):
    store = open_store(path)
    return ingest_directory(path, store)
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

fn notekeeper_project() -> (InMemoryGraph, Vec<FileParseData>) {
    let files = vec![
        parse_py("cli.py", CLI_PY),
        parse_py("ingest.py", INGEST_PY),
        parse_py("parsing.py", PARSING_PY),
        parse_py("storage.py", STORAGE_PY),
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

fn entity_id(files: &[FileParseData], name: &str) -> String {
    files
        .iter()
        .flat_map(|file| file.entities.iter())
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("fixture entity `{name}` not found"))
        .id
        .0
        .to_string()
}

fn absent_binding() -> kin_core::LocalRepositoryAuthorityBinding {
    let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
    kin_core::LocalRepositoryAuthorityBinding::from_parts(
        kin_model::RepositoryId::new("absent-python-bare-builtin").unwrap(),
        kin_model::WorkspaceId::new(),
        Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
    )
}

/// Every entity name `trace_data_flow` reports when it walks callees from
/// `focal`, at the ticket's own depth and direction.
fn callee_chain(graph: &InMemoryGraph, files: &[FileParseData], focal: &str) -> Vec<String> {
    let response = build_trace_data_flow_response(
        &RequestRepositoryAuthority::pinned(absent_binding()),
        graph,
        &TraceDataFlowRequest {
            focal: entity_id(files, focal),
            depth: Some(3),
            direction: Some(TraceDirection::Calls),
            limit_per_step: Some(25),
            include_body: Some(false),
            max_response_chars: None,
            include_type_edges: None,
        },
    )
    .expect("trace fixture");
    response
        .chain
        .iter()
        .map(|step| step.entity.entity_name.clone())
        .collect()
}

/// The defect, reproduced and closed. `ingest_directory` reaches `parse_file`,
/// and `parse_file` opens a file. Before the fix that builtin call carried the
/// trace into `NoteStore.open` and on to `default_db_path`, in a module
/// `parsing.py` neither imports nor names.
#[test]
fn tracing_calls_never_crosses_a_builtin_open_into_the_storage_module() {
    let (graph, files) = notekeeper_project();
    let chain = callee_chain(&graph, &files, "ingest_directory");

    assert!(
        chain.iter().any(|name| name == "parse_file"),
        "the real cross-module call must still be walked, got {chain:?}"
    );
    assert!(
        !chain.iter().any(|name| name == "NoteStore.open"),
        "a builtin `open` must not carry the trace into NoteStore.open, got {chain:?}"
    );
    assert!(
        !chain.iter().any(|name| name == "default_db_path"),
        "nothing under the fabricated edge may be reached, got {chain:?}"
    );
}

/// The receiver path this fix must leave working. `cli.py` imports the class
/// and calls the classmethod through it, so the same two entities the previous
/// test refuses are exactly what this trace must reach.
#[test]
fn tracing_calls_from_an_importing_caller_still_reaches_the_classmethod() {
    let (graph, files) = notekeeper_project();
    let chain = callee_chain(&graph, &files, "open_store");

    assert!(
        chain.iter().any(|name| name == "NoteStore.open"),
        "`NoteStore.open(path)` in a file importing NoteStore must resolve, got {chain:?}"
    );
    assert!(
        chain.iter().any(|name| name == "default_db_path"),
        "the classmethod's own callee must still be reached, got {chain:?}"
    );
}

/// `find_references` and `trace_data_flow` read the same edges, so the two must
/// agree about who calls `NoteStore.open`: `open_store` does, `parse_file` never
/// did.
#[test]
fn find_references_on_the_classmethod_lists_the_importing_caller_and_not_the_parser() {
    let (graph, files) = notekeeper_project();
    let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
    let response = build_refs_response(
        &layout,
        &graph,
        &RefsRequest {
            entity: entity_id(&files, "NoteStore.open"),
            kind: "all".to_string(),
        },
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 4, "graph_generation": 1,
        })),
    )
    .expect("refs fixture");
    let listing = response.lines.join("\n");

    assert!(
        listing.contains("open_store"),
        "the importing caller must be listed, got:\n{listing}"
    );
    assert!(
        !listing.contains("parse_file"),
        "a bare builtin `open` must not appear as a caller, got:\n{listing}"
    );
}
