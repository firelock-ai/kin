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
use kin_parser::{JavaScriptAdapter, LanguageAdapter, PythonAdapter, TypeScriptAdapter};

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

fn ts(path: &str, src: &str) -> FileParseData {
    parse_with(&TypeScriptAdapter, path, src)
}

/// The module entity's name, or `None`.
///
/// The presence check alone would pass on a module named anything at all, and
/// the name is half of what FIR-2675 decides: an index file takes its
/// directory's name and every other file takes its own stem.
fn module_entity_name(file: &FileParseData) -> Option<&str> {
    file.entities
        .iter()
        .find(|e| e.kind == EntityKind::Module)
        .map(|e| e.name.as_str())
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
/// FIR-2675 turned this from a limitation into the behaviour. It was written to
/// fail the day the JavaScript adapter started emitting module entities for
/// ordinary files, and that is this change; the assertion is inverted rather
/// than deleted, so the record of what moved stays in the file.
#[test]
fn javascript_non_index_file_sources_an_entity_import_edge() {
    let files = vec![
        js("lib/router.js", "function Router() {}\nmodule.exports = Router;\n"),
        js(
            "lib/application.js",
            "var Router = require('./router');\nfunction use() { return Router(); }\nmodule.exports = use;\n",
        ),
    ];
    assert_eq!(
        module_entity_name(&files[1]),
        Some("application"),
        "a non-index file takes its own stem, the way a Python module does"
    );
    // The edge lands on the MODULE, not on the function inside it, and that is
    // the right target rather than a near miss. `require('./router')` names the
    // whole module; `module.exports = Router` is what makes the two the same
    // object at runtime, and the graph should say what the source said. Python
    // already behaves this way for `import routing`, which is why this port
    // mirrors it rather than inventing a rule. Before this change `lib/router.js`
    // had no module entity at all, so the edge existed for nothing to land on.
    let pairs = entity_import_pairs(&files);
    assert!(
        pairs.contains(&("application".to_string(), "router".to_string())),
        "lib/application.js must source an entity-level import edge to the router module; \
         got {pairs:?}"
    );
}

/// A NAMED import still reaches the named entity rather than the module.
///
/// The test above pins that a whole-module require names the module. This pins
/// the other half, because a port that made every import land on a module would
/// satisfy that one while destroying the specifier-level answer `find_references`
/// is built on.
#[test]
fn a_named_javascript_import_binds_the_named_entity_not_the_module() {
    let files = vec![
        js("lib/router.js", "export function Router() {}\n"),
        js(
            "lib/application.js",
            "import { Router } from './router';\nexport function use() { return Router(); }\n",
        ),
    ];
    let pairs = entity_import_pairs(&files);
    assert!(
        pairs.contains(&("application".to_string(), "Router".to_string())),
        "a named import must bind the named entity; got {pairs:?}"
    );
}

// ---------------------------------------------------------------------------
// The artifact edge is unchanged. Asserted, not assumed.
// ---------------------------------------------------------------------------

/// The artifact-to-artifact import edge must survive the entity-level one
/// exactly as it was: same endpoints, same confidence, same parser rule.
///
/// Every consumer reading artifact import edges today, including the coverage
/// line and the include graph, reads them unchanged. This is an assertion
/// rather than an assumption because "I only added something" is precisely the
/// claim that is cheap to make and expensive to be wrong about.
#[test]
fn the_artifact_import_edge_is_unchanged_by_the_entity_edge() {
    let files = vec![
        py("app/routing.py", "class APIRouter:\n    pass\n"),
        py("app/main.py", "from .routing import APIRouter\n"),
    ];
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifact_ids).expect("fixture links");

    let src = GraphNodeId::Artifact(artifact_ids["app/main.py"]);
    let dst = GraphNodeId::Artifact(artifact_ids["app/routing.py"]);
    let artifact_edges: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Imports && r.src == src && r.dst == dst)
        .collect();

    assert_eq!(
        artifact_edges.len(),
        1,
        "expected exactly one artifact import edge from main.py to routing.py, got {}",
        artifact_edges.len()
    );
    let edge = artifact_edges[0];
    assert_eq!(edge.confidence, 1.0, "artifact edge confidence changed");
    assert_eq!(
        edge.evidence.first().and_then(|e| e.parser_rule.as_deref()),
        Some("import_declaration"),
        "artifact edge parser rule changed"
    );
    assert_eq!(
        edge.evidence
            .first()
            .and_then(|e| e.resolved_path.as_deref()),
        Some("app/routing.py"),
        "artifact edge resolved path changed"
    );

    // And the entity edge sits beside it rather than replacing it.
    assert!(
        !entity_import_pairs(&files).is_empty(),
        "the entity edge should exist alongside the artifact edge, not instead of it"
    );
}

/// The two edges must carry different relation ids, or the caller's dedup would
/// drop one of them and which one it dropped would depend on iteration order.
#[test]
fn the_artifact_and_entity_import_edges_have_distinct_ids() {
    let files = vec![
        py("app/routing.py", "class APIRouter:\n    pass\n"),
        py("app/main.py", "from .routing import APIRouter\n"),
    ];
    let relations = link(&files);
    let import_ids: Vec<_> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Imports)
        .map(|r| r.id)
        .collect();
    let unique: std::collections::HashSet<_> = import_ids.iter().collect();
    assert_eq!(
        import_ids.len(),
        unique.len(),
        "two import edges collided on one relation id: {import_ids:?}"
    );
    assert!(
        import_ids.len() >= 2,
        "expected both an artifact and an entity import edge, got {}",
        import_ids.len()
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

/// An `index.js` directly in `lib/` or `src/` now carries a module entity too.
///
/// The old rule refused those two directory names outright, which landed on
/// exactly the directories a real library keeps its code in: express's own
/// `lib/` was unreachable at entity level twice over, once for not being an
/// index file and once for the directory name. Python carries no such blocklist
/// and neither does this any more, so `lib/index.js` is named `lib`, which is
/// what `require('./lib')` calls it.
#[test]
fn javascript_index_file_directly_under_lib_or_src_carries_a_module_entity() {
    for (path, expected) in [("lib/index.js", "lib"), ("src/index.js", "src")] {
        let file = js(path, "module.exports = require('./router');\n");
        assert_eq!(
            module_entity_name(&file),
            Some(expected),
            "{path} must carry a module entity named after its directory"
        );
    }
}

/// A root-level `index.js` still carries nothing, and that is deliberate.
///
/// An index file is named after the directory it indexes, and a file at the
/// repository root has no such directory. It produced nothing before this change
/// and produces nothing after it, so the port did not quietly widen into a case
/// with no sensible name.
#[test]
fn a_root_level_index_file_carries_no_module_entity() {
    let file = js("index.js", "module.exports = require('./lib/router');\n");
    assert_eq!(module_entity_name(&file), None);
}

/// TypeScript had NO module-entity test at all before this change, so this is
/// added rather than converted. The two adapters carried byte-identical copies
/// of the rule and drifted anyway, which is why they now share one helper.
#[test]
fn typescript_files_carry_module_entities_by_the_same_rule_as_javascript() {
    for (path, expected) in [
        ("lib/application.ts", Some("application")),
        ("components/Button.tsx", Some("Button")),
        ("packages/mui-base/src/useSelect/index.ts", Some("useSelect")),
        ("lib/index.ts", Some("lib")),
        ("index.ts", None),
    ] {
        let file = ts(path, "export function use() { return 1; }\n");
        assert_eq!(
            module_entity_name(&file),
            expected,
            "TypeScript module identity for {path}"
        );
    }
}

/// A `.d.ts` declaration file is named `foo`, not `foo.d`.
///
/// This is the drift the shared helper exists to stop: the old
/// `is_ts_index_file` never matched `index.d.ts`, and stripping only `.ts` from
/// `foo.d.ts` leaves a name no source ever writes. It is a separate test from
/// the table above because it is the one case where suffix ORDER decides the
/// answer.
#[test]
fn a_typescript_declaration_file_is_named_without_its_d_segment() {
    assert_eq!(
        module_entity_name(&ts("types/express.d.ts", "export declare const x: number;\n")),
        Some("express")
    );
}

/// A path carrying none of the language's suffixes emits nothing.
///
/// This mirrors `python_module_identity`'s `.strip_suffix(".py").unwrap_or("")`
/// exactly, and it is the guard that matters most: `round_trip_fuzz.rs` passes
/// an extension-less `FilePathId`, and a module entity there would span the
/// whole file and swallow every other entity in the region.
#[test]
fn an_extension_less_path_emits_no_module_entity() {
    assert_eq!(module_entity_name(&js("some/fixture", "function a() {}\n")), None);
    assert_eq!(module_entity_name(&ts("some/fixture", "function a() {}\n")), None);
}
