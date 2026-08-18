// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file resolution of Python value references, through the real parser
//! and the real linker.
//!
//! A symbol used as a value rather than called now carries a `References` edge
//! out of extraction. These tests pin that such an edge resolves through the
//! SAME tiers a call does, so a value reference crossing a file boundary binds
//! with import evidence rather than by name alone. Confidence is asserted, not
//! merely the edge: the blind cross-file name fallback reaches the same entity
//! at 0.7 in a single-definition fixture, so an edge alone cannot tell import
//! resolution from a lucky name match.

use std::collections::HashMap;

use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, GraphNodeId, Relation, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};

/// Confidence the linker records when a relation resolves through the
/// referring file's own import declaration (tier (b) of
/// `linker::resolve_one_file`).
const IMPORT_RESOLVED_CONFIDENCE: f32 = 0.95;

/// Confidence for a member reached through a namespace/module import
/// (`import parsing` then `parsing.TAG_RE`, tier (b2)).
const MODULE_MEMBER_CONFIDENCE: f32 = 0.9;

/// Confidence for the blind cross-file exact-name fallback (tier (c)). An edge
/// at this tier proves only that one entity of that name exists somewhere.
const NAME_ONLY_CONFIDENCE: f32 = 0.7;

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

#[test]
fn a_value_reference_to_an_imported_constant_binds_through_the_import() {
    let files = vec![
        parse_py(
            "cli.py",
            "from parsing import TAG_RE\n\n\ndef build_parser():\n    return TAG_RE.pattern\n",
        ),
        parse_py(
            "parsing.py",
            "TAG_RE = compile(\"#\")\n\n\ndef extract_tags(text):\n    return TAG_RE.findall(text)\n",
        ),
    ];
    let relations = link(&files);

    let reader = entity_id_in(&files, "cli.py", "build_parser");
    let constant = entity_id_in(&files, "parsing.py", "TAG_RE");
    assert_eq!(
        reference_confidence(&relations, reader, constant),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the value reference must bind through its import, not the blind name fallback"
    );
}

#[test]
fn a_value_reference_reached_through_a_module_import_binds_to_that_module() {
    let files = vec![
        parse_py(
            "cli.py",
            "import parsing\n\n\ndef build_parser():\n    return parsing.TAG_RE\n",
        ),
        parse_py("parsing.py", "TAG_RE = compile(\"#\")\n"),
    ];
    let relations = link(&files);

    let reader = entity_id_in(&files, "cli.py", "build_parser");
    let constant = entity_id_in(&files, "parsing.py", "TAG_RE");
    assert_eq!(
        reference_confidence(&relations, reader, constant),
        Some(MODULE_MEMBER_CONFIDENCE),
        "`parsing.TAG_RE` must bind through the module import"
    );
}

#[test]
fn an_imported_value_reference_does_not_bind_to_a_same_named_twin() {
    // The precision half. Two files define TAG_RE; only one is imported. Name
    // alone cannot choose, so the import must, and the twin must gain nothing.
    let files = vec![
        parse_py(
            "cli.py",
            "from parsing import TAG_RE\n\n\ndef build_parser():\n    return TAG_RE.pattern\n",
        ),
        parse_py("parsing.py", "TAG_RE = compile(\"#\")\n"),
        parse_py("legacy.py", "TAG_RE = compile(\"@\")\n"),
    ];
    let relations = link(&files);

    let reader = entity_id_in(&files, "cli.py", "build_parser");
    let real = entity_id_in(&files, "parsing.py", "TAG_RE");
    let twin = entity_id_in(&files, "legacy.py", "TAG_RE");
    assert_eq!(
        reference_confidence(&relations, reader, real),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the imported definition binds"
    );
    assert_eq!(
        reference_confidence(&relations, reader, twin),
        None,
        "the same-named twin in an unimported file must gain no reference"
    );
}

#[test]
fn a_same_file_value_reference_resolves_without_the_linker() {
    // The argparse shape sits entirely inside one file, so it never reaches a
    // cross-file tier. It must still arrive fully resolved.
    let files = vec![parse_py(
        "cli.py",
        "def cmd_ingest(args):\n    return 1\n\n\ndef main():\n    ingest.set_defaults(func=cmd_ingest)\n",
    )];
    let relations = link(&files);

    let caller = entity_id_in(&files, "cli.py", "main");
    let handler = entity_id_in(&files, "cli.py", "cmd_ingest");
    assert_eq!(
        reference_confidence(&relations, caller, handler),
        Some(1.0),
        "a same-file value reference is parsed evidence, not inference"
    );
}

#[test]
fn a_value_reference_resolves_exactly_as_the_same_call_would() {
    // Requirement: value references go through the SAME tiers as calls, so they
    // must reach the same target at the same confidence. Asserting parity
    // rather than an absolute rule is what keeps this honest, because a bare
    // unresolved module name (`requests`) is deliberately left to the
    // name-global tiers rather than orphaned, for calls and references alike.
    let referencing = vec![
        parse_py(
            "cli.py",
            "from requests import Session\n\n\ndef build():\n    return Session\n",
        ),
        parse_py("vendor.py", "def Session():\n    return 1\n"),
    ];
    let calling = vec![
        parse_py(
            "cli.py",
            "from requests import Session\n\n\ndef build():\n    return Session()\n",
        ),
        parse_py("vendor.py", "def Session():\n    return 1\n"),
    ];

    let reference_edge = reference_confidence(
        &link(&referencing),
        entity_id_in(&referencing, "cli.py", "build"),
        entity_id_in(&referencing, "vendor.py", "Session"),
    );
    let call_relations = link(&calling);
    let caller = entity_id_in(&calling, "cli.py", "build");
    let callee = entity_id_in(&calling, "vendor.py", "Session");
    let call_edge = call_relations
        .iter()
        .find(|rel| {
            rel.kind == RelationKind::Calls
                && rel.src == GraphNodeId::Entity(caller)
                && rel.dst == GraphNodeId::Entity(callee)
        })
        .map(|rel| rel.confidence);

    assert_eq!(
        reference_edge, call_edge,
        "a value reference and the identical call must resolve alike"
    );
    assert_eq!(
        reference_edge,
        Some(NAME_ONLY_CONFIDENCE),
        "and both land on the blind name tier for an unresolved bare module name"
    );
}

#[test]
fn an_unimported_same_named_entity_still_reaches_the_name_fallback() {
    // Recall control. A file-local entity referenced as a value keeps binding
    // through the ordinary tiers; this pins that the new edge class did not
    // acquire a stricter rule than a call has.
    let files = vec![
        parse_py(
            "cli.py",
            "def helper():\n    return 1\n\n\ndef run():\n    return helper\n",
        ),
        parse_py("other.py", "def unrelated():\n    return 2\n"),
    ];
    let relations = link(&files);

    let caller = entity_id_in(&files, "cli.py", "run");
    let helper = entity_id_in(&files, "cli.py", "helper");
    assert_eq!(
        reference_confidence(&relations, caller, helper),
        Some(1.0),
        "the same-file definition wins outright"
    );
    let unrelated = entity_id_in(&files, "other.py", "unrelated");
    assert_eq!(
        reference_confidence(&relations, caller, unrelated),
        None,
        "and nothing else in the repository is reached"
    );
}
