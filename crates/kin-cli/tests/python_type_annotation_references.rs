// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Acceptance reproduction for the type-annotation edge class, on the shape a
//! stranger's Python project produced.
//!
//! `parsing.py` defines `ParsedNote` and `WikiLink`. `storage.py` imports
//! `ParsedNote` and never calls it: it appears as a parameter type, as a return
//! type, and as a dataclass field type, and `WikiLink` appears only as the
//! element type `ParsedNote` is built from. Because the adapter emitted no edge
//! of any class for an annotation, `find_references("ParsedNote")` answered with
//! the one caller in its own file and `find_references("WikiLink")` missed
//! `ParsedNote` entirely, so a reader who renamed `ParsedNote` on that answer
//! would have left `storage.py` holding the old name in three places.
//!
//! Everything here runs through the real Python adapter, the real cross-file
//! linker, and the collector `find_references` itself calls over the relation
//! kinds it defaults to.

use std::collections::{BTreeSet, HashMap};

use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_cli::commands::rename::{plan_rename, RenameRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file_with_completeness, FileParseData};
use kin_mcp::handlers::common::default_reference_kinds;
use kin_model::{
    ArtifactId, AuthorId, Entity, EntityId, EntityStore, FileLayout, FilePathId, GraphNodeId,
    Hash256, ImportSection, OperationId, ParseCompleteness, RepoPath, ResolvedArtifact,
    ResolvedTree, TreeEntry,
};
use kin_parser::{LanguageAdapter, PythonAdapter};

/// The defining module. Neither class is ever called.
const PARSING_PY: &str = r#""""Note parsing."""


class WikiLink:
    pass


class ParsedNote:
    pass
"#;

/// The consuming module. `ParsedNote` is named three times and called zero
/// times; `WikiLink` is named once, as the element type of a field.
const STORAGE_PY: &str = r#""""Note storage."""

from typing import Optional, Tuple

from parsing import ParsedNote, WikiLink


class NoteRow:
    note: Optional[ParsedNote] = None
    links: Tuple[WikiLink, ...] = ()


def upsert_note(note: ParsedNote, mtime: Optional[float] = None) -> int:
    return 1


def latest() -> ParsedNote:
    raise NotImplementedError
"#;

/// A third module with no consumer at all, so a fix that rescued everything
/// would be caught as surely as one that rescued nothing.
const ORPHAN_PY: &str = r#""""Nothing depends on this."""


class OrphanRecord:
    pass
"#;

fn parse_py(file_path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("fixture parses");
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("fixture extracts");
    assert!(
        matches!(
            ParseCompleteness::from_parse_state(&output.parse_state),
            ParseCompleteness::Full
        ),
        "fixture {file_path} must parse cleanly"
    );
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

/// Link the parsed files into a persisted graph the way ingest does, with the
/// resolved tree, file layouts and coverage certificates a rename plan reads.
fn link_into_graph(
    files: Vec<FileParseData>,
    bodies: &HashMap<String, String>,
) -> (Vec<FileParseData>, InMemoryGraph) {
    let completeness = files
        .iter()
        .map(|file| (file.file_path.clone(), ParseCompleteness::Full))
        .collect();
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file_with_completeness(&files, &artifact_ids, &completeness)
        .expect("every fixture file has an artifact identity");

    let mut admitted = artifact_ids.iter().collect::<Vec<_>>();
    admitted.sort_by(|(left, _), (right, _)| left.cmp(right));
    // Real content digests, because repository CAS verifies the body a rename
    // plan loads against the digest the tree names.
    let resolved_tree =
        ResolvedTree::from_artifacts(admitted.into_iter().map(|(path, artifact_id)| {
            let body = bodies
                .get(path.as_str())
                .unwrap_or_else(|| panic!("fixture body for {path} was not supplied"));
            ResolvedArtifact::new(
                *artifact_id,
                RepoPath::from_utf8(path).expect("valid fixture repository path"),
                TreeEntry::blob(
                    Hash256::from_bytes(kin_blobs::digest(body.as_bytes()).0),
                    false,
                ),
            )
        }))
        .expect("unique admitted fixture artifacts");
    let mut snapshot = kin_db::GraphSnapshot::empty();
    snapshot.resolved_tree = resolved_tree;
    let graph = InMemoryGraph::from_snapshot(snapshot).expect("open admitted fixture graph");
    for file in &files {
        graph
            .upsert_file_layout(&FileLayout {
                file_id: FilePathId::new(&file.file_path),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
            })
            .expect("upsert file layout");
        for entity in &file.entities {
            graph.upsert_entity(entity).expect("upsert entity");
        }
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    (files, graph)
}

/// Path to body, the same map the fixture parses from and a rename plan loads
/// from, so no digest can disagree with what was indexed.
fn bodies(files: &[(&str, &str)]) -> HashMap<String, String> {
    files
        .iter()
        .map(|(path, body)| ((*path).to_string(), (*body).to_string()))
        .collect()
}

fn notes_project() -> (Vec<FileParseData>, InMemoryGraph) {
    let sources = [
        ("storage.py", STORAGE_PY),
        ("parsing.py", PARSING_PY),
        ("orphan.py", ORPHAN_PY),
    ];
    let bodies = bodies(&sources);
    let parsed = sources
        .iter()
        .map(|(path, body)| parse_py(path, body))
        .collect();
    link_into_graph(parsed, &bodies)
}

fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("fixture entity `{name}` in `{file}` not found"))
        .id
}

/// The consumers `find_references` reports for one entity, as `(file, name)`.
///
/// Read off the graph under
/// [`kin_mcp::handlers::common::default_reference_kinds`] itself, which is the
/// Calls + Imports + References triple the MCP handler filters its collector
/// on and the same triple `kin refs --kind all` and the dead-code scan use.
/// Importing that function rather than restating the three kinds is the point:
/// if `References` ever left the default set, this helper would stop finding
/// the annotated consumers instead of quietly asserting a stale copy.
///
/// The handler adds body projection on top, which needs a live repository
/// authority binding a parsed-in-memory fixture does not have. Which edges pass
/// the kind filter is what decides whether a consumer is reported at all, and
/// that is what this reads.
fn find_references(graph: &InMemoryGraph, target: EntityId) -> BTreeSet<(String, String)> {
    let kinds = default_reference_kinds();
    graph
        .get_all_relations_for_entity(&target)
        .expect("inbound relations")
        .into_iter()
        .filter(|rel| rel.dst == GraphNodeId::Entity(target) && kinds.contains(&rel.kind))
        .filter_map(|rel| rel.src.as_entity())
        .filter_map(|source_id| {
            graph
                .get_entity(&source_id)
                .expect("referencing entity")
                .map(|entity| {
                    (
                        entity
                            .file_origin
                            .map(|file| file.0)
                            .unwrap_or_else(|| "<graph-only>".to_string()),
                        entity.name,
                    )
                })
        })
        .collect()
}

/// The rendered `kin refs --kind all` answer for one entity, which is the CLI
/// half of the same reference collector.
fn refs_lines(graph: &InMemoryGraph, entity: &str) -> String {
    let dir = tempfile::tempdir().expect("temp repository root");
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: entity.to_string(),
            kind: "all".to_string(),
        },
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 4, "graph_generation": 1,
        })),
    )
    .expect("refs response")
    .lines
    .join("\n")
}

#[test]
fn find_references_lists_every_consumer_that_only_annotates() {
    // The defect, reproduced and closed. Each of these three names `ParsedNote`
    // in an annotation and nowhere else, so before annotations carried an edge
    // every one of them was invisible here.
    let (files, graph) = notes_project();
    let found = find_references(&graph, entity_id(&files, "parsing.py", "ParsedNote"));

    for consumer in ["upsert_note", "latest", "NoteRow"] {
        assert!(
            found.contains(&("storage.py".to_string(), consumer.to_string())),
            "`{consumer}` annotates ParsedNote and must be listed, got {found:?}"
        );
    }

    // And the same answer through the rendered CLI surface, so the edge is
    // proven to reach a shipped command rather than only the relation table.
    let lines = refs_lines(&graph, "ParsedNote");
    for consumer in ["upsert_note", "latest", "NoteRow"] {
        assert!(
            lines.contains(consumer),
            "`kin refs ParsedNote` must name `{consumer}`, got:\n{lines}"
        );
    }
}

#[test]
fn find_references_on_an_element_type_reaches_the_class_built_from_it() {
    // The second half of the reported miss. `WikiLink` is named only as the
    // element type of `NoteRow.links`, which is why the context pack for the
    // annotated class carried no dependency on it.
    let (files, graph) = notes_project();
    let found = find_references(&graph, entity_id(&files, "parsing.py", "WikiLink"));

    assert!(
        found.contains(&("storage.py".to_string(), "NoteRow".to_string())),
        "the class whose field type is WikiLink must be listed, got {found:?}"
    );
}

#[test]
fn a_class_nothing_annotates_still_reports_no_references() {
    // The opposite direction. An edge class that rescued every type would be as
    // wrong as one that rescued none.
    let (files, graph) = notes_project();
    let found = find_references(&graph, entity_id(&files, "orphan.py", "OrphanRecord"));

    assert!(
        found.is_empty(),
        "an unreferenced class must keep reporting nothing, got {found:?}"
    );
}

/// The rename fixture reaches the class through a MODULE import
/// (`import parsing` then `parsing.ParsedNote`) rather than a named one.
/// `plan_rename` refuses outright while a graph source imports the target by
/// name, because artifact-level Python import edges carry no exact source span,
/// so the named-import shape cannot reach the planner at all today. The module
/// import puts the only `ParsedNote` token in `storage.py` inside the annotated
/// function, which is exactly the site this fix made visible.
const RENAME_PARSING_PY: &str = "class ParsedNote:\n    pass\n";
const RENAME_STORAGE_PY: &str =
    "import parsing\n\n\ndef upsert_note(note: parsing.ParsedNote) -> int:\n    return 1\n";

#[test]
fn the_rename_plan_names_the_consumer_that_only_annotates() {
    let sources = [
        ("storage.py", RENAME_STORAGE_PY),
        ("parsing.py", RENAME_PARSING_PY),
    ];
    let bodies = bodies(&sources);
    let parsed = sources
        .iter()
        .map(|(path, body)| parse_py(path, body))
        .collect();
    let (_files, graph) = link_into_graph(parsed, &bodies);

    let plan = plan_rename(
        &graph,
        &RenameRequest {
            symbol: "ParsedNote".to_string(),
            new_name: "NoteRecord".to_string(),
            file: Some("parsing.py".to_string()),
            line: None,
            column: None,
            json: true,
            operation_id: OperationId::new(),
            actor: AuthorId::new("fir2399-annotation-test"),
        },
        |path, _hash| {
            let path = path.as_utf8().expect("fixture paths are UTF-8");
            bodies
                .get(path)
                .map(|body| body.as_bytes().to_vec())
                .ok_or_else(|| anyhow::anyhow!("missing fixture body {path}"))
        },
    )
    .expect("rename plans over the annotated consumer");

    let edited: BTreeSet<&str> = plan.edits.iter().map(|edit| edit.file.0.as_str()).collect();
    assert!(
        edited.contains("storage.py"),
        "the annotated consumer's file must be edited, got {edited:?}"
    );

    let annotation_edit = plan
        .edits
        .iter()
        .find(|edit| edit.file.0 == "storage.py")
        .expect("an edit inside the annotated consumer");
    assert_eq!(
        annotation_edit.reason, "graph-reference:references",
        "the consumer must be reached by a graph reference edge, not by a name sweep"
    );
    assert_eq!(annotation_edit.old_text, "ParsedNote");
    assert_eq!(annotation_edit.new_text, "NoteRecord");
    assert_eq!(
        annotation_edit.start_line, 4,
        "the edit must land on the annotated signature"
    );
}
