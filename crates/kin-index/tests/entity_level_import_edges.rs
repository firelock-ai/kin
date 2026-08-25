// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Entity-level import edges, the class `find_references` can actually read.
//!
//! `find_references` opens its walk with `rel.src.as_entity()` and skips
//! anything that is not an entity, so an artifact-to-artifact import edge is
//! invisible to it however well the specifier resolved. These tests pin the
//! shapes that must produce an entity-rooted `Imports` edge, and they pin, out
//! loud, the shapes that still do not.
//!
//! Every fixture here is a shape taken from the census over real corpora, not
//! an invented minimal case, because a fixture simple enough to pass by
//! accident proves nothing about the repositories this has to work on.

use std::collections::HashMap;

use kin_index::{link_cross_file, FileParseData};
use kin_model::{ArtifactId, Entity, EntityKind, FilePathId, GraphNodeId, RelationKind};
use kin_parser::{JavaScriptAdapter, LanguageAdapter, PythonAdapter};

fn parse_with(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> FileParseData {
    let file_id = FilePathId::new(path);
    let bytes = src.as_bytes();
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

fn py(path: &str, src: &str) -> FileParseData {
    parse_with(&PythonAdapter, path, src)
}

fn js(path: &str, src: &str) -> FileParseData {
    parse_with(&JavaScriptAdapter, path, src)
}

fn link(files: &[FileParseData]) -> Vec<kin_model::Relation> {
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file(files, &artifact_ids).expect("fixture links")
}

/// Entity-rooted `Imports` edges as `(src entity name, dst entity name)`.
///
/// Reading names rather than ids is what makes a failure legible: an assertion
/// that reports `[]` against an expected pair says which pair is missing.
fn entity_import_pairs(files: &[FileParseData]) -> Vec<(String, String)> {
    let relations = link(files);
    let name_of: HashMap<_, _> = files
        .iter()
        .flat_map(|f| f.entities.iter())
        .map(|e| (e.id, e.name.clone()))
        .collect();
    let mut out: Vec<(String, String)> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Imports)
        .filter_map(|r| match (r.src, r.dst) {
            (GraphNodeId::Entity(s), GraphNodeId::Entity(d)) => {
                Some((name_of.get(&s)?.clone(), name_of.get(&d)?.clone()))
            }
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn has_module_entity(file: &FileParseData) -> bool {
    file.entities.iter().any(|e| e.kind == EntityKind::Module)
}

// ---------------------------------------------------------------------------
// Parser-level extraction, verified rather than assumed.
// ---------------------------------------------------------------------------

/// `import x as z` must produce an import declaration.
///
/// Reported as a code reading; this asserts it against the real adapter, so the
/// claim is measured rather than inferred.
#[test]
fn python_aliased_plain_import_produces_an_import_declaration() {
    let file = py("app/main.py", "import helpers as h\n");
    let specifiers: Vec<&str> = file
        .imports
        .iter()
        .map(|i| i.module_path.as_str())
        .collect();
    assert!(
        specifiers.contains(&"helpers"),
        "`import helpers as h` recorded no import naming `helpers`; got {specifiers:?}"
    );
}

/// `import a, b` must record both modules, not just the first.
#[test]
fn python_multi_module_import_records_every_module() {
    let file = py("app/main.py", "import alpha, beta\n");
    let mut modules: Vec<&str> = file
        .imports
        .iter()
        .map(|i| i.module_path.as_str())
        .collect();
    modules.sort();
    assert_eq!(
        modules,
        vec!["alpha", "beta"],
        "`import alpha, beta` did not record both modules"
    );
}

// ---------------------------------------------------------------------------
// The shapes that must reach find_references.
// ---------------------------------------------------------------------------

/// The census's dominant resolvable Python shape: a relative from-import naming
/// a symbol the target defines. 504 of fastapi's specifiers are this shape.
#[test]
fn python_relative_from_import_binds_the_named_symbol_at_entity_level() {
    let files = vec![
        py(
            "app/routing.py",
            "class APIRouter:\n    def add(self):\n        return 1\n",
        ),
        py(
            "app/main.py",
            "from .routing import APIRouter\n\n\ndef build():\n    return APIRouter()\n",
        ),
    ];
    assert!(
        has_module_entity(&files[1]),
        "precondition: the importing file must carry a module entity to source the edge"
    );
    let pairs = entity_import_pairs(&files);
    assert!(
        pairs.iter().any(|(_, dst)| dst == "APIRouter"),
        "no entity-level Imports edge reached `APIRouter`; got {pairs:?}"
    );
}

/// An absolute from-import across a package, the second most common Python
/// shape in the census.
#[test]
fn python_absolute_from_import_binds_the_named_symbol_at_entity_level() {
    let files = vec![
        py("fastapi/applications.py", "class FastAPI:\n    pass\n"),
        py(
            "docs_src/tutorial001.py",
            "from fastapi.applications import FastAPI\n\n\napp = FastAPI()\n",
        ),
    ];
    let pairs = entity_import_pairs(&files);
    assert!(
        pairs.iter().any(|(_, dst)| dst == "FastAPI"),
        "no entity-level Imports edge reached `FastAPI`; got {pairs:?}"
    );
}

/// An aliased from-import must bind the ORIGINAL name, since that is the entity
/// the target defines. Binding the alias would point the edge at nothing.
#[test]
fn python_aliased_from_import_binds_the_original_name() {
    let files = vec![
        py("app/routing.py", "class APIRouter:\n    pass\n"),
        py(
            "app/main.py",
            "from .routing import APIRouter as Router\n\n\ndef build():\n    return Router()\n",
        ),
    ];
    let pairs = entity_import_pairs(&files);
    assert!(
        pairs.iter().any(|(_, dst)| dst == "APIRouter"),
        "aliased import did not bind the original name `APIRouter`; got {pairs:?}"
    );
}

/// An import naming a symbol the target does not define must produce no
/// entity-level edge. Without this the fix could pass every test above by
/// emitting an edge for every specifier regardless of whether it resolved.
#[test]
fn python_import_of_an_undefined_name_produces_no_entity_edge() {
    let files = vec![
        py("app/routing.py", "class APIRouter:\n    pass\n"),
        py("app/main.py", "from .routing import NotDefinedHere\n"),
    ];
    let pairs = entity_import_pairs(&files);
    assert!(
        !pairs.iter().any(|(_, dst)| dst == "NotDefinedHere"),
        "invented an entity-level edge for a name the target does not define; got {pairs:?}"
    );
}

// ---------------------------------------------------------------------------
// The gap that remains, asserted so the suite reports it rather than implying
// completeness.
// ---------------------------------------------------------------------------

/// A non-index JavaScript file carries no module entity, so it cannot source an
/// entity-level import edge however well its specifier resolved.
///
/// This test asserts the CURRENT limitation on purpose. It is the honest record
/// that JavaScript is not fixed, and it is written to fail loudly the day the
/// JavaScript adapter starts emitting module entities for ordinary files, so
/// nobody has to remember to come back and check.
#[test]
fn javascript_non_index_file_still_sources_no_entity_import_edge() {
    let files = vec![
        js("lib/router.js", "function Router() {}\nmodule.exports = Router;\n"),
        js(
            "lib/application.js",
            "var Router = require('./router');\nfunction use() { return Router(); }\nmodule.exports = use;\n",
        ),
    ];
    assert!(
        !has_module_entity(&files[1]),
        "lib/application.js now carries a module entity; the JavaScript adapter changed, \
         so the entity-level import edge for non-index files is now buildable and this \
         limitation test should be replaced by a positive assertion"
    );
    let pairs = entity_import_pairs(&files);
    assert!(
        pairs.is_empty(),
        "a non-index JavaScript file sourced an entity-level import edge; got {pairs:?}"
    );
}

/// An `index.js` in an ordinary directory DOES carry a module entity, so its
/// whole-module require has both endpoints available. This is the shape behind
/// the census's 29-of-141 reading on express, where every one of the 29 is an
/// `examples/<name>/index.js`.
#[test]
fn javascript_index_file_in_a_named_directory_carries_a_module_entity() {
    let file = js(
        "examples/auth/index.js",
        "module.exports = require('./router');\n",
    );
    assert!(
        has_module_entity(&file),
        "an index.js in a named directory carried no module entity"
    );
}

/// An `index.js` sitting directly in `lib/` or `src/` carries NO module entity,
/// because `extract_module_name_from_path` refuses those two directory names
/// outright.
///
/// This is the sharper half of the JavaScript gap and it is worth pinning
/// separately: the exclusion lands on exactly the directories a real library
/// keeps its code in, so express's own `lib/` is unreachable at entity level
/// twice over, once for not being an index file and once for the directory
/// name. Asserted as the current limitation, and written to fail the day the
/// rule changes.
#[test]
fn javascript_index_file_directly_under_lib_or_src_carries_no_module_entity() {
    for path in ["lib/index.js", "src/index.js"] {
        let file = js(path, "module.exports = require('./router');\n");
        assert!(
            !has_module_entity(&file),
            "{path} now carries a module entity; the JavaScript adapter's src/lib \
             exclusion changed and this limitation test should become a positive one"
        );
    }
}
