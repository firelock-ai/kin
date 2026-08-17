// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file linking of Python and JavaScript imports through the real parser.
//!
//! Python module paths are dotted (`app.parsing`, `.parsing`), not path-shaped,
//! so the linker's generic module resolution never mapped them onto a repo file:
//! Python graphs carried no artifact-level `Imports` edge at all, and every
//! imported call fell through to the blind name fallback, which drops the edge
//! the moment two modules define the same name. These tests drive real adapters
//! into the real linker and pin both halves: the import edge exists, the call
//! binds to the module it was imported from, and an unimported ambiguous name
//! still resolves to nothing rather than to a guess.

use std::collections::{HashMap, HashSet};

use kin_index::{link_cross_file as link_cross_file_with_identities, FileParseData};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, GraphNodeId, Relation, RelationKind};
use kin_parser::{JavaScriptAdapter, LanguageAdapter, PythonAdapter};

fn parse_with(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> FileParseData {
    let file_id = FilePathId::new(path);
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("fixture parses");
    let output = adapter.extract(&tree, bytes, &file_id).expect("fixture extracts");
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

type ArtifactIds = HashMap<String, ArtifactId>;

/// Link and return both the relations and the identity map, so artifact-level
/// import edges can be asserted by path rather than by opaque identity.
fn link_with_identities(files: &[FileParseData]) -> (Vec<Relation>, ArtifactIds) {
    let artifact_ids: ArtifactIds = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity");
    (relations, artifact_ids)
}

fn link(files: &[FileParseData]) -> Vec<Relation> {
    link_with_identities(files).0
}

fn artifact_import_paths(
    relations: &[Relation],
    artifact_ids: &ArtifactIds,
) -> HashSet<(String, String)> {
    let path_of = |node: &GraphNodeId| -> Option<String> {
        match node {
            GraphNodeId::Artifact(id) => artifact_ids
                .iter()
                .find(|(_, candidate)| *candidate == id)
                .map(|(path, _)| path.clone()),
            _ => None,
        }
    };
    relations
        .iter()
        .filter(|rel| rel.kind == RelationKind::Imports)
        .filter_map(|rel| Some((path_of(&rel.src)?, path_of(&rel.dst)?)))
        .collect()
}

fn entity_id_in(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn call_confidence(relations: &[Relation], src: EntityId, dst: EntityId) -> Option<f32> {
    relations
        .iter()
        .find(|rel| {
            rel.kind == RelationKind::Calls
                && rel.src == GraphNodeId::Entity(src)
                && rel.dst == GraphNodeId::Entity(dst)
        })
        .map(|rel| rel.confidence)
}

fn parsing_module(path: &str) -> FileParseData {
    parse_with(
        &PythonAdapter,
        path,
        "def parse_note(path):\n    return {}\n",
    )
}

/// Confidence the linker records when a call resolves through the importing
/// file's own import declaration (tier (b) of `linker::resolve_one_file`).
///
/// Asserting the confidence, not merely the edge, is what keeps these tests
/// falsifiable: the blind cross-file name fallback reaches the same entity at
/// 0.7 in the single-definition fixtures, so an edge alone cannot tell import
/// resolution apart from a lucky name match.
const IMPORT_RESOLVED_CONFIDENCE: f32 = 0.95;

#[test]
fn flat_python_absolute_import_produces_an_artifact_import_edge() {
    let files = vec![
        parse_with(
            &PythonAdapter,
            "storage.py",
            "from parsing import parse_note\n\n\nclass Database:\n    def ingest_note(self, path):\n        return parse_note(path)\n",
        ),
        parsing_module("parsing.py"),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids)
            .contains(&("storage.py".to_string(), "parsing.py".to_string())),
        "`from parsing import parse_note` must produce storage.py -> parsing.py Imports"
    );

    let caller = entity_id_in(&files, "storage.py", "Database.ingest_note");
    let callee = entity_id_in(&files, "parsing.py", "parse_note");
    assert_eq!(
        call_confidence(&relations, caller, callee),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the call must bind through its import, not through the blind name fallback"
    );
}

#[test]
fn python_package_relative_import_resolves_to_the_sibling_module() {
    let files = vec![
        parse_with(
            &PythonAdapter,
            "app/storage.py",
            "from .parsing import parse_note\n\n\ndef ingest_note(path):\n    return parse_note(path)\n",
        ),
        parsing_module("app/parsing.py"),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids)
            .contains(&("app/storage.py".to_string(), "app/parsing.py".to_string())),
        "`from .parsing import ...` names the importer's own package, not a path segment"
    );
    let caller = entity_id_in(&files, "app/storage.py", "ingest_note");
    let callee = entity_id_in(&files, "app/parsing.py", "parse_note");
    assert_eq!(
        call_confidence(&relations, caller, callee),
        Some(IMPORT_RESOLVED_CONFIDENCE)
    );
}

#[test]
fn python_dotted_package_import_resolves_through_the_repo_root() {
    let files = vec![
        parse_with(
            &PythonAdapter,
            "app/storage.py",
            "from app.parsing import parse_note\n\n\ndef ingest_note(path):\n    return parse_note(path)\n",
        ),
        parsing_module("app/parsing.py"),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids)
            .contains(&("app/storage.py".to_string(), "app/parsing.py".to_string())),
        "a dotted absolute import resolves against the repository root"
    );
}

#[test]
fn python_package_import_resolves_to_its_init_module() {
    let files = vec![
        parse_with(
            &PythonAdapter,
            "app/storage.py",
            "from app.parsing import parse_note\n\n\ndef ingest_note(path):\n    return parse_note(path)\n",
        ),
        parsing_module("app/parsing/__init__.py"),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids).contains(&(
            "app/storage.py".to_string(),
            "app/parsing/__init__.py".to_string()
        )),
        "a package import resolves to the package's __init__ module"
    );
}

#[test]
fn python_src_layout_absolute_import_resolves() {
    let files = vec![
        parse_with(
            &PythonAdapter,
            "src/app/storage.py",
            "from app.parsing import parse_note\n\n\ndef ingest_note(path):\n    return parse_note(path)\n",
        ),
        parsing_module("src/app/parsing.py"),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids).contains(&(
            "src/app/storage.py".to_string(),
            "src/app/parsing.py".to_string()
        )),
        "a src/ layout is a source root a repository-local import resolves against"
    );
}

#[test]
fn a_third_party_python_import_resolves_to_nothing_local() {
    let files = vec![
        parse_with(
            &PythonAdapter,
            "storage.py",
            "from requests import get\n\n\ndef fetch(url):\n    return get(url)\n",
        ),
        parsing_module("parsing.py"),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids).is_empty(),
        "an import that names no repo-local module must not resolve to one"
    );
}

#[test]
fn an_import_bound_call_binds_to_the_imported_module_not_the_same_named_twin() {
    // `parse_note` is defined twice. The import says which one this call means;
    // before import resolution the name bucket was ambiguous and the call was
    // recorded as an unresolvable external reference instead.
    let files = vec![
        parse_with(
            &PythonAdapter,
            "storage.py",
            "from parsing import parse_note\n\n\ndef ingest_note(path):\n    return parse_note(path)\n",
        ),
        parsing_module("parsing.py"),
        parse_with(
            &PythonAdapter,
            "legacy.py",
            "def parse_note(path):\n    return None\n",
        ),
    ];
    let relations = link(&files);

    let caller = entity_id_in(&files, "storage.py", "ingest_note");
    let imported = entity_id_in(&files, "parsing.py", "parse_note");
    let twin = entity_id_in(&files, "legacy.py", "parse_note");

    assert_eq!(
        call_confidence(&relations, caller, imported),
        Some(IMPORT_RESOLVED_CONFIDENCE),
        "the imported definition is the one this call reaches"
    );
    assert!(
        call_confidence(&relations, caller, twin).is_none(),
        "the same-named definition in an unimported module must not be linked"
    );
}

#[test]
fn an_unimported_ambiguous_name_is_left_unresolved() {
    // No import binds `parse_note` here, and two modules define it. Nothing in
    // the source says which one runs, so the linker must emit no call edge to
    // either rather than pick one.
    let files = vec![
        parse_with(
            &PythonAdapter,
            "storage.py",
            "def ingest_note(path):\n    return parse_note(path)\n",
        ),
        parsing_module("parsing.py"),
        parse_with(
            &PythonAdapter,
            "legacy.py",
            "def parse_note(path):\n    return None\n",
        ),
    ];
    let relations = link(&files);

    let caller = entity_id_in(&files, "storage.py", "ingest_note");
    for module in ["parsing.py", "legacy.py"] {
        let candidate = entity_id_in(&files, module, "parse_note");
        assert!(
            call_confidence(&relations, caller, candidate).is_none(),
            "an ambiguous unimported name must not be bound to {module}"
        );
    }
}

#[test]
fn javascript_relative_import_produces_an_artifact_import_edge() {
    let files = vec![
        parse_with(
            &JavaScriptAdapter,
            "storage.js",
            "import { parseNote } from './parsing.js';\nexport function ingestNote(p) { return parseNote(p); }\n",
        ),
        parse_with(
            &JavaScriptAdapter,
            "parsing.js",
            "export function parseNote(p) { return {}; }\n",
        ),
    ];
    let (relations, artifact_ids) = link_with_identities(&files);

    assert!(
        artifact_import_paths(&relations, &artifact_ids)
            .contains(&("storage.js".to_string(), "parsing.js".to_string())),
        "a relative JavaScript import produces storage.js -> parsing.js Imports"
    );

    let caller = entity_id_in(&files, "storage.js", "ingestNote");
    let callee = entity_id_in(&files, "parsing.js", "parseNote");
    assert!(
        call_confidence(&relations, caller, callee).is_some(),
        "the imported call resolves across the file boundary"
    );
}

#[test]
fn javascript_same_named_twin_does_not_steal_an_imported_call() {
    let files = vec![
        parse_with(
            &JavaScriptAdapter,
            "storage.js",
            "import { parseNote } from './parsing.js';\nexport function ingestNote(p) { return parseNote(p); }\n",
        ),
        parse_with(
            &JavaScriptAdapter,
            "parsing.js",
            "export function parseNote(p) { return {}; }\n",
        ),
        parse_with(
            &JavaScriptAdapter,
            "legacy.js",
            "export function parseNote(p) { return null; }\n",
        ),
    ];
    let relations = link(&files);

    let caller = entity_id_in(&files, "storage.js", "ingestNote");
    let imported = entity_id_in(&files, "parsing.js", "parseNote");
    let twin = entity_id_in(&files, "legacy.js", "parseNote");
    assert!(call_confidence(&relations, caller, imported).is_some());
    assert!(
        call_confidence(&relations, caller, twin).is_none(),
        "the unimported twin must not be linked"
    );
}
