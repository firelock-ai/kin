// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Acceptance reproduction for the value-reference edge class, on the fixture
//! shape that produced seven false dead-code rows.
//!
//! A small multi-module Python project: an argparse CLI whose subcommands are
//! wired by name (`ingest.set_defaults(func=cmd_ingest)`), a module constant
//! read inside a function in its own file (`WIKI_RE`), and a second constant
//! imported cross-file and read through an attribute (`TAG_RE.pattern`). Every
//! one of those symbols is referenced as a VALUE and never called, which is
//! exactly the class the Python adapter did not extract. `kin dead-code` listed
//! all seven beside the two genuinely unused helpers, so a reader who trusted
//! the list would have deleted a working CLI.
//!
//! The fixture runs through the real Python adapter and the real cross-file
//! linker into a real `InMemoryGraph`, which is the shape `kin init` produces
//! over an existing tree.

use kin_cli::commands::dead_code::build_dead_code_response;
use kin_cli::commands::refs::{build_bulk_refs_response, BulkRefsRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use std::collections::HashMap;

use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, Hash256, LocatedEntry, RepoPath, TransactionDelta,
    TreeDelta, TreeEntry,
};
use kin_parser::{LanguageAdapter, PythonAdapter};

/// Admit one artifact per parsed file into the graph's repository tree, and
/// return the identity map the linker takes.
///
/// This fixture used to mint an `ArtifactId` per file and admit none of them.
/// That builds a store that could never exist: every persist gate refuses a
/// relation whose artifact endpoint the resolved tree does not carry, so the
/// graph these tests assembled was one no snapshot would have accepted, and
/// kin-db now refuses the same edge at the write. Admitting through a
/// transaction carrying a `TreeDelta::Added` is the path the product itself
/// uses, so the fixture now describes a repository that could really hold what
/// it is asserting about.
fn admit_file_artifacts(
    graph: &InMemoryGraph,
    files: &[FileParseData],
) -> HashMap<String, ArtifactId> {
    let mut artifact_ids = HashMap::new();
    for file in files {
        let artifact_id = ArtifactId::new();
        // Nothing here reads blob content; the artifact only has to exist at
        // this path. Deriving the hash from the path keeps the fixture
        // deterministic without pulling in a hasher.
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

const PARSING_PY: &str = r##""""Note parsing helpers."""

import re

TAG_RE = re.compile(r"#(\w+)")
WIKI_RE = re.compile(r"\[\[([^\]]+)\]\]")


def extract_tags(text):
    return sorted({m.lower() for m in TAG_RE.findall(text)})


def extract_links(text):
    return [m.split("|")[0] for m in WIKI_RE.findall(text)]


def unused_helper(text):
    return text.strip()
"##;

const STORAGE_PY: &str = r#""""Note storage."""

import json

from parsing import extract_links, extract_tags


class NoteStore:
    def __init__(self, path):
        self.path = path
        self.notes = {}

    def ingest(self, name, text):
        self.notes[name] = {
            "tags": extract_tags(text),
            "links": extract_links(text),
        }
        return self.notes[name]

    def search(self, term):
        return [n for n in self.notes if term in n]
"#;

const LINKGRAPH_PY: &str = r#""""Link graph queries."""


def backlinks(notes, target):
    return [n for n, body in notes.items() if target in body["links"]]


def orphans(notes):
    return [n for n, body in notes.items() if not body["links"]]


def isolated_helper(notes):
    return len(notes)
"#;

const CLI_PY: &str = r#""""Command line interface."""

import argparse

from linkgraph import backlinks, orphans
from parsing import TAG_RE
from storage import NoteStore


def cmd_ingest(args):
    store = NoteStore(args.path)
    return store.ingest(args.name, args.text)


def cmd_tags(args):
    store = NoteStore(args.path)
    return store.notes.get(args.name, {}).get("tags", [])


def cmd_orphans(args):
    store = NoteStore(args.path)
    return orphans(store.notes)


def cmd_backlinks(args):
    store = NoteStore(args.path)
    return backlinks(store.notes, args.name)


def cmd_search(args):
    store = NoteStore(args.path)
    return store.search(args.term)


def build_parser():
    parser = argparse.ArgumentParser(epilog="tags: %s" % TAG_RE.pattern)
    sub = parser.add_subparsers()
    ingest = sub.add_parser("ingest")
    ingest.set_defaults(func=cmd_ingest)
    tags = sub.add_parser("tags")
    tags.set_defaults(func=cmd_tags)
    orph = sub.add_parser("orphans")
    orph.set_defaults(func=cmd_orphans)
    back = sub.add_parser("backlinks")
    back.set_defaults(func=cmd_backlinks)
    search = sub.add_parser("search")
    search.set_defaults(func=cmd_search)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)
"#;

/// The pytest suite. `main` is imported here and read as a value, never
/// called, so before this edge class existed the entry point itself was on the
/// delete list.
const TEST_CLI_PY: &str = r#"from cli import main


def test_ingest_then_backlinks():
    assert main is not None


def test_search_and_tags():
    assert main is not None
"#;

/// The five subcommand handlers, wired only by `set_defaults(func=NAME)`.
const WIRED_BY_VALUE: [&str; 5] = [
    "cmd_backlinks",
    "cmd_ingest",
    "cmd_orphans",
    "cmd_search",
    "cmd_tags",
];

/// The two constants: one read inside its own file, one also read cross-file.
const CONSTANTS_READ_AS_VALUES: [&str; 2] = ["TAG_RE", "WIKI_RE"];

/// The only genuinely unused symbols in the fixture.
const GENUINELY_DEAD: [&str; 2] = ["isolated_helper", "unused_helper"];

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

fn notes_project() -> (InMemoryGraph, Vec<FileParseData>) {
    let files = vec![
        parse_py("cli.py", CLI_PY),
        parse_py("parsing.py", PARSING_PY),
        parse_py("storage.py", STORAGE_PY),
        parse_py("linkgraph.py", LINKGRAPH_PY),
        parse_py("tests/test_cli.py", TEST_CLI_PY),
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

/// Which of `names` the reference collector finds an inbound edge for, read
/// through `kin refs --bulk` over the Calls + Imports + References triple. That
/// is the same collector, over the same kinds, that the dead-code scan consults
/// before it puts a row on a delete list.
fn names_with_references(
    graph: &InMemoryGraph,
    files: &[FileParseData],
    names: &[&str],
) -> Vec<String> {
    let request = BulkRefsRequest {
        entity_ids: names.iter().map(|name| entity_id(files, name)).collect(),
        kind: "all".to_string(),
        compact: true,
    };
    let response = build_bulk_refs_response(graph, &request).expect("bulk refs");
    let mut found = Vec::new();
    for (name, result) in names.iter().zip(response.results.iter()) {
        let count = result
            .get("reference_count")
            .and_then(|value| value.as_u64())
            .unwrap_or_else(|| panic!("bulk refs row for `{name}` carries no reference_count"));
        if count > 0 {
            found.push((*name).to_string());
        }
    }
    found
}

#[test]
fn every_symbol_wired_by_value_now_owns_an_inbound_reference() {
    // The defect, reproduced and closed. Each of these seven is referenced as a
    // value and never called, so before the value-reference edge class existed
    // every one of them reported zero inbound edges of any kind.
    let (graph, files) = notes_project();
    let mut expected: Vec<String> = WIRED_BY_VALUE
        .iter()
        .chain(CONSTANTS_READ_AS_VALUES.iter())
        .map(|name| (*name).to_string())
        .collect();
    expected.sort();

    let mut probed: Vec<&str> = WIRED_BY_VALUE.to_vec();
    probed.extend(CONSTANTS_READ_AS_VALUES);
    let mut found = names_with_references(&graph, &files, &probed);
    found.sort();

    assert_eq!(
        found, expected,
        "every symbol used as a value must own an inbound reference edge"
    );
}

#[test]
fn a_symbol_with_no_reference_of_any_kind_is_still_reported() {
    // The opposite direction. An edge class that rescued everything would be
    // just as wrong as one that rescued nothing.
    let (graph, files) = notes_project();
    let found = names_with_references(&graph, &files, &GENUINELY_DEAD);
    assert!(
        found.is_empty(),
        "genuinely unused helpers must keep reporting no references, got {found:?}"
    );
}

#[test]
fn the_cross_file_constant_leaves_the_dead_code_list() {
    // `TAG_RE` is imported into cli.py and read there as `TAG_RE.pattern`. That
    // is the one false row the whole-repo scan can retire on its own, because
    // its candidate generator asks only whether an inbound edge crosses a file
    // boundary. The same-file rows below need the scan to consult the reference
    // collector as well, which is what kin#866 wires in.
    let (graph, _files) = notes_project();
    let response = build_dead_code_response(
        None,
        &graph,
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 4, "graph_generation": 1,
        })),
    )
    .expect("dead-code scan");
    let listed = listed_names(&response.lines);

    assert!(
        !listed.contains(&"TAG_RE".to_string()),
        "TAG_RE is read cross-file in cli.py, got {listed:?}"
    );
    for name in GENUINELY_DEAD {
        assert!(
            listed.contains(&name.to_string()),
            "`{name}` is genuinely unused and must stay listed, got {listed:?}"
        );
    }
}

#[test]
fn the_dead_code_list_holds_only_rows_the_collector_cannot_rescue() {
    // The acceptance statement, expressed against what this graph can prove:
    // every row the whole-repo scan still prints either is genuinely dead, or
    // is rescued the moment the scan reads the reference collector. Nothing
    // else survives, and no genuinely dead symbol is hidden.
    let (graph, files) = notes_project();
    let response = build_dead_code_response(
        None,
        &graph,
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 4, "graph_generation": 1,
        })),
    )
    .expect("dead-code scan");
    let listed = listed_names(&response.lines);

    let listed_refs: Vec<&str> = listed.iter().map(String::as_str).collect();
    let rescued = names_with_references(&graph, &files, &listed_refs);

    let mut unrescued: Vec<String> = listed
        .iter()
        .filter(|name| !rescued.contains(name))
        .cloned()
        .collect();
    unrescued.sort();
    assert_eq!(
        unrescued,
        GENUINELY_DEAD.map(String::from).to_vec(),
        "only the genuinely unused helpers may survive the reference collector"
    );
}

/// The entity names a dead-code response listed, read off its rendered rows.
fn listed_names(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let row = line.strip_prefix("  ")?;
            let (name, rest) = row.split_once(" (")?;
            rest.contains(") - ").then(|| name.to_string())
        })
        .collect()
}
