// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file resolution of Python type annotations, through the real parser
//! and the real linker.
//!
//! A class named only in an annotation now carries a `References` edge out of
//! extraction. These tests pin that such an edge crosses a file boundary
//! through the SAME tiers a call does, so an annotated consumer binds on import
//! evidence rather than by name alone. Confidence is asserted rather than merely
//! the edge, because the blind cross-file name tier reaches the same entity at
//! 0.7 in a single-definition fixture and an edge alone cannot tell the two
//! apart.

use std::collections::HashMap;

use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, GraphNodeId, Relation, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};

/// Confidence the linker records when a relation resolves through the referring
/// file's own import declaration (tier (b) of `linker::resolve_one_file`).
const IMPORT_RESOLVED_CONFIDENCE: f32 = 0.95;

/// Confidence for a member reached through a namespace/module import
/// (`import parsing` then `parsing.ParsedNote`, tier (b2)).
const MODULE_MEMBER_CONFIDENCE: f32 = 0.9;

fn parse_py(path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let file_id = FilePathId::new(path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("fixture parses");
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("fixture extracts");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn link(files: &[FileParseData]) -> Vec<Relation> {
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file(files, &artifact_ids).expect("every fixture file has an artifact identity")
}

fn entity_id_in(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn reference_confidence(relations: &[Relation], src: EntityId, dst: EntityId) -> Option<f32> {
    relations
        .iter()
        .find(|rel| {
            rel.kind == RelationKind::References
                && rel.src == GraphNodeId::Entity(src)
                && rel.dst == GraphNodeId::Entity(dst)
        })
        .map(|rel| rel.confidence)
}

/// The defining module. `ParsedNote` is a class; nothing here calls it.
const PARSING_PY: &str = r#""""Note parsing."""


class WikiLink:
    pass


class ParsedNote:
    pass
"#;

/// The consuming module. It imports `ParsedNote` and names it ONLY in
/// annotations: a parameter type, a return type, and a dataclass field type.
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

fn two_file_project() -> Vec<FileParseData> {
    vec![
        parse_py("storage.py", STORAGE_PY),
        parse_py("parsing.py", PARSING_PY),
    ]
}

#[test]
fn a_parameter_annotation_binds_across_the_file_boundary_through_its_import() {
    let files = two_file_project();
    let relations = link(&files);

    assert_eq!(
        reference_confidence(
            &relations,
            entity_id_in(&files, "storage.py", "upsert_note"),
            entity_id_in(&files, "parsing.py", "ParsedNote"),
        ),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the parameter annotation must bind through its import, not the blind name tier"
    );
}

#[test]
fn a_return_annotation_binds_across_the_file_boundary_through_its_import() {
    let files = two_file_project();
    let relations = link(&files);

    assert_eq!(
        reference_confidence(
            &relations,
            entity_id_in(&files, "storage.py", "latest"),
            entity_id_in(&files, "parsing.py", "ParsedNote"),
        ),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the return annotation must bind through its import"
    );
}

#[test]
fn a_field_annotation_binds_across_the_file_boundary_through_its_import() {
    // Both fields, so the plain wrapper (`Optional[ParsedNote]`) and the
    // variadic one (`Tuple[WikiLink, ...]`) are each proven rather than one
    // standing in for the other.
    let files = two_file_project();
    let relations = link(&files);
    let row = entity_id_in(&files, "storage.py", "NoteRow");

    assert_eq!(
        reference_confidence(
            &relations,
            row,
            entity_id_in(&files, "parsing.py", "ParsedNote"),
        ),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the `Optional[ParsedNote]` field must bind through its import"
    );
    assert_eq!(
        reference_confidence(
            &relations,
            row,
            entity_id_in(&files, "parsing.py", "WikiLink"),
        ),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the `Tuple[WikiLink, ...]` field must bind through its import"
    );
}

#[test]
fn an_annotation_does_not_bind_to_a_same_named_class_in_an_unimported_module() {
    // The precision half, and the falsifier for the import gate. Two modules
    // define `ParsedNote`; only one is imported. Name alone cannot choose, so
    // the import must, and the twin must gain nothing. Drop the
    // defined-or-imported filter in `emit_python_value_references` and this is
    // the assertion that fails.
    let mut files = two_file_project();
    files.push(parse_py("legacy.py", "class ParsedNote:\n    pass\n"));
    let relations = link(&files);

    let consumer = entity_id_in(&files, "storage.py", "upsert_note");
    assert_eq!(
        reference_confidence(
            &relations,
            consumer,
            entity_id_in(&files, "parsing.py", "ParsedNote"),
        ),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the imported definition binds"
    );
    assert_eq!(
        reference_confidence(
            &relations,
            consumer,
            entity_id_in(&files, "legacy.py", "ParsedNote"),
        ),
        None,
        "the same-named class in an unimported module must gain no reference"
    );
}

#[test]
fn a_dotted_annotation_binds_through_the_module_import() {
    let files = vec![
        parse_py(
            "storage.py",
            "import parsing\n\n\ndef upsert_note(note: parsing.ParsedNote) -> int:\n    return 1\n",
        ),
        parse_py("parsing.py", PARSING_PY),
    ];
    let relations = link(&files);

    assert_eq!(
        reference_confidence(
            &relations,
            entity_id_in(&files, "storage.py", "upsert_note"),
            entity_id_in(&files, "parsing.py", "ParsedNote"),
        ),
        Some(MODULE_MEMBER_CONFIDENCE),
        "`parsing.ParsedNote` must bind through the module import"
    );
}

#[test]
fn an_annotation_resolves_exactly_as_the_same_call_would() {
    // Requirement: annotations go through the SAME tiers as calls, so the same
    // name in the same file must reach the same target at the same confidence.
    // Parity is what proves no separate rule was invented for type positions.
    let annotated = vec![
        parse_py(
            "storage.py",
            "from parsing import ParsedNote\n\n\ndef upsert_note(note: ParsedNote) -> int:\n    return 1\n",
        ),
        parse_py("parsing.py", PARSING_PY),
    ];
    let calling = vec![
        parse_py(
            "storage.py",
            "from parsing import ParsedNote\n\n\ndef upsert_note(note) -> int:\n    ParsedNote()\n    return 1\n",
        ),
        parse_py("parsing.py", PARSING_PY),
    ];

    let annotation_edge = reference_confidence(
        &link(&annotated),
        entity_id_in(&annotated, "storage.py", "upsert_note"),
        entity_id_in(&annotated, "parsing.py", "ParsedNote"),
    );
    let call_relations = link(&calling);
    let caller = entity_id_in(&calling, "storage.py", "upsert_note");
    let callee = entity_id_in(&calling, "parsing.py", "ParsedNote");
    let call_edge = call_relations
        .iter()
        .find(|rel| {
            rel.kind == RelationKind::Calls
                && rel.src == GraphNodeId::Entity(caller)
                && rel.dst == GraphNodeId::Entity(callee)
        })
        .map(|rel| rel.confidence);

    assert_eq!(
        annotation_edge, call_edge,
        "an annotation and the identical call must resolve alike"
    );
    assert_eq!(
        annotation_edge,
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "and both bind on the import tier"
    );
}
