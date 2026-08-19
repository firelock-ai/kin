// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! JavaScript import and `require` specifier resolution, through the real
//! parser and the real cross-file linker.
//!
//! A CommonJS module is a file, so a resolved `require('./router')` is an
//! ARTIFACT-to-artifact `Imports` edge rather than an entity-to-entity one.
//! These tests assert on that edge directly, because it is the resolution.
//!
//! The fixtures mirror express, which is the corpus the gap was found on:
//! `index.js` requires `./lib/express`, `lib/express.js` requires `./router`
//! (a directory whose entry is `lib/router/index.js`), and an example nested
//! two directories deep requires `../..`, the repository root.

use kin_index::{link_cross_file as link_cross_file_with_identities, FileParseData};
use kin_model::{ArtifactId, Entity, FilePathId, GraphNodeId, Relation, RelationKind};
use kin_parser::{JavaScriptAdapter, LanguageAdapter, TypeScriptAdapter};
use std::collections::HashMap;

fn parse_with(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> FileParseData {
    let file_id = FilePathId::new(path);
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
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

struct Linked {
    relations: Vec<Relation>,
    artifact_ids: HashMap<String, ArtifactId>,
    files: Vec<FileParseData>,
}

impl Linked {
    fn imports_from(&self, importer: &str) -> Vec<&str> {
        let Some(src) = self.artifact_ids.get(importer) else {
            return Vec::new();
        };
        let mut targets: Vec<&str> = self
            .relations
            .iter()
            .filter(|relation| {
                matches!(
                    relation.kind,
                    RelationKind::Imports | RelationKind::Includes
                ) && relation.src == GraphNodeId::Artifact(*src)
            })
            .filter_map(|relation| {
                self.artifact_ids.iter().find_map(|(path, id)| {
                    (relation.dst == GraphNodeId::Artifact(*id)).then_some(path.as_str())
                })
            })
            .collect();
        targets.sort();
        targets
    }

    fn import_edge_count(&self) -> usize {
        self.relations
            .iter()
            .filter(|relation| {
                matches!(
                    relation.kind,
                    RelationKind::Imports | RelationKind::Includes
                )
            })
            .count()
    }

    fn entity_id(&self, file: &str, name: &str) -> kin_model::EntityId {
        self.files
            .iter()
            .flat_map(|f| f.entities.iter())
            .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
            .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
            .id
    }

    fn has_call(&self, src: kin_model::EntityId, dst: kin_model::EntityId) -> bool {
        self.relations.iter().any(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src == GraphNodeId::Entity(src)
                && relation.dst == GraphNodeId::Entity(dst)
        })
    }
}

fn link(files: Vec<FileParseData>) -> Linked {
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file_with_identities(&files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity");
    Linked {
        relations,
        artifact_ids,
        files,
    }
}

fn js(path: &str, src: &str) -> FileParseData {
    parse_with(&JavaScriptAdapter, path, src)
}

/// The express shape: a relative `require` of a file, of a directory whose
/// entry is `index.js`, and a bare specifier that names an npm package.
#[test]
fn relative_requires_resolve_and_a_bare_package_specifier_does_not() {
    let linked = link(vec![
        js("index.js", "module.exports = require('./lib/express');\n"),
        js(
            "lib/express.js",
            "var mixin = require('merge-descriptors');\nvar proto = require('./application');\nvar Router = require('./router');\nfunction createApplication() { return mixin({}, proto, false); }\nmodule.exports = createApplication;\n",
        ),
        js(
            "lib/application.js",
            "var Router = require('./router');\nvar app = module.exports = {};\n",
        ),
        js("lib/router/index.js", "function Router() {}\nmodule.exports = Router;\n"),
    ]);

    assert_eq!(linked.imports_from("index.js"), vec!["lib/express.js"]);
    assert_eq!(
        linked.imports_from("lib/express.js"),
        vec!["lib/application.js", "lib/router/index.js"],
        "`./router` names the directory whose entry is lib/router/index.js, and \
         `merge-descriptors` names a package this repository does not hold"
    );
    assert_eq!(
        linked.imports_from("lib/application.js"),
        vec!["lib/router/index.js"]
    );
}

/// `require('../..')` from a nested directory names the repository root.
/// Joining an index filename onto the empty resolved prefix produced
/// `/index.js`, which is absolute and matches no repo-relative path, so 96 of
/// express's 157 relative specifiers resolved to nothing.
#[test]
fn a_relative_specifier_that_names_the_repository_root_resolves_to_its_index() {
    let linked = link(vec![
        js("index.js", "module.exports = require('./lib/express');\n"),
        js(
            "lib/express.js",
            "function createApplication() {}\nmodule.exports = createApplication;\n",
        ),
        js(
            "examples/auth/index.js",
            "var express = require('../..');\nvar app = express();\n",
        ),
        js(
            "examples/mvc/lib/boot.js",
            "var express = require('../../..');\nfunction boot() { return express; }\n",
        ),
    ]);

    assert_eq!(
        linked.imports_from("examples/auth/index.js"),
        vec!["index.js"],
        "`../..` from examples/auth names the repository root"
    );
    assert_eq!(
        linked.imports_from("examples/mvc/lib/boot.js"),
        vec!["index.js"],
        "one more level up is still the repository root"
    );
}

/// A trailing slash is Node's directory form of the same specifier.
#[test]
fn a_trailing_slash_specifier_resolves_to_the_directory_index() {
    let linked = link(vec![
        js(
            "src/app.js",
            "const router = require('./router/');\nfunction run() { return router; }\n",
        ),
        js("src/router/index.js", "module.exports = {};\n"),
    ]);
    assert_eq!(
        linked.imports_from("src/app.js"),
        vec!["src/router/index.js"]
    );
}

/// `.mjs` and `.cjs` are module extensions Node completes exactly as it
/// completes `.js`. Leaving them out made every ECMAScript-module file in a
/// repository unreachable through a relative specifier.
#[test]
fn ecmascript_module_extensions_complete_like_js() {
    let linked = link(vec![
        js(
            "src/a.js",
            "const m = require('./deep/mod');\nfunction go() { return m; }\n",
        ),
        js(
            "src/deep/mod.mjs",
            "export function thing() { return 1; }\n",
        ),
    ]);
    assert_eq!(linked.imports_from("src/a.js"), vec!["src/deep/mod.mjs"]);

    let linked = link(vec![
        js(
            "src/a.js",
            "const m = require('./legacy');\nfunction go() { return m; }\n",
        ),
        js("src/legacy.cjs", "module.exports = {};\n"),
    ]);
    assert_eq!(linked.imports_from("src/a.js"), vec!["src/legacy.cjs"]);

    let linked = link(vec![
        js(
            "src/a.js",
            "const m = require('./pkg');\nfunction go() { return m; }\n",
        ),
        js("src/pkg/index.mjs", "export const value = 1;\n"),
    ]);
    assert_eq!(linked.imports_from("src/a.js"), vec!["src/pkg/index.mjs"]);
}

/// Node ESM requires the extension in the specifier, and a TypeScript package
/// built for NodeNext writes `./util.js` in source whose file on disk is
/// `util.ts`. The specifier names the emitted artifact; the repository holds
/// the input.
#[test]
fn a_specifier_naming_emitted_javascript_resolves_to_the_typescript_source() {
    let linked = link(vec![
        js(
            "src/a.mjs",
            "import { helper } from './util.js';\nexport function run() { return helper(); }\n",
        ),
        parse_with(
            &TypeScriptAdapter,
            "src/util.ts",
            "export function helper() { return 1; }\n",
        ),
    ]);
    assert_eq!(linked.imports_from("src/a.mjs"), vec!["src/util.ts"]);
}

/// A bare specifier naming a package this repository does not hold stays
/// unresolved. A fabricated edge is worse than a missing one.
#[test]
fn a_package_this_repository_does_not_hold_produces_no_edge() {
    let linked = link(vec![
        js(
            "lib/view.js",
            "var path = require('path');\nvar debug = require('debug')('express:view');\nfunction View() {}\nmodule.exports = View;\n",
        ),
        js("lib/utils.js", "exports.etag = function etag() { return 1; };\n"),
    ]);
    assert_eq!(
        linked.import_edge_count(),
        0,
        "neither `path` nor `debug` is a module this repository owns"
    );
}

/// `const { a, b } = require('./m')` binds each destructured key to `m`'s
/// export, so a later `a()` is a call into `m`. This is the shape express uses
/// throughout, and it is what makes `find_references` on an export reach its
/// consumers rather than stopping at the file boundary.
#[test]
fn a_destructured_require_binds_each_name_to_the_module_it_came_from() {
    let linked = link(vec![
        js(
            "lib/response.js",
            "const { etag, wetag } = require('./utils');\nfunction sendfile(body) { return etag(body) + wetag(body); }\n",
        ),
        js(
            "lib/utils.js",
            "exports.etag = function etag() { return 1; };\nexports.wetag = function wetag() { return 2; };\n",
        ),
    ]);

    let sendfile = linked.entity_id("lib/response.js", "sendfile");
    let etag = linked.entity_id("lib/utils.js", "etag");
    let wetag = linked.entity_id("lib/utils.js", "wetag");
    assert!(
        linked.has_call(sendfile, etag),
        "`etag()` came from `./utils` and must link there"
    );
    assert!(
        linked.has_call(sendfile, wetag),
        "`wetag()` came from the same destructuring and must link there too"
    );
    assert_eq!(
        linked.imports_from("lib/response.js"),
        vec!["lib/utils.js"],
        "the destructuring is one import statement of one module"
    );
}

/// A renamed destructured key keeps its ORIGINAL name as the resolution target,
/// so the local alias does not have to exist in the imported module.
#[test]
fn a_renamed_destructured_key_resolves_to_the_exported_name() {
    let linked = link(vec![
        js(
            "lib/response.js",
            "const { etag: makeEtag } = require('./utils');\nfunction send(body) { return makeEtag(body); }\n",
        ),
        js("lib/utils.js", "exports.etag = function etag() { return 1; };\n"),
    ]);
    let send = linked.entity_id("lib/response.js", "send");
    let etag = linked.entity_id("lib/utils.js", "etag");
    assert!(
        linked.has_call(send, etag),
        "`makeEtag` is `etag` under another name"
    );
}

/// `require('.')` from a file that IS its directory's index resolves back to
/// the importer. A module does not import itself.
#[test]
fn a_specifier_that_resolves_to_the_importing_file_produces_no_edge() {
    let linked = link(vec![
        js(
            "lib/index.js",
            "const self = require('.');\nfunction run() { return self; }\n",
        ),
        js("lib/other.js", "module.exports = {};\n"),
    ]);
    assert_eq!(
        linked.import_edge_count(),
        0,
        "a self-loop is not a resolved import"
    );
}
