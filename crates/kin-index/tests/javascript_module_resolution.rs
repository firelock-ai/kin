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

use kin_index::{
    link_cross_file as link_cross_file_with_identities, link_cross_file_incremental, FileParseData,
    IncrementalLinker,
};
use kin_model::{ArtifactId, Entity, EntityKind, FilePathId, GraphNodeId, Relation, RelationKind};
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

// ---- Default exports: which entity in the target file a default import means ----

/// `core/lib.js` names its module `lib` and its default export `defaultCallee`,
/// so the two identities are distinguishable by name. A file whose default
/// export is named for the file, which is the common JS idiom and is what
/// axios's `lib/core/settle.js` does, puts both under one name and makes the
/// mistake invisible from the outside.
const CALLEE_LIB: &str = r#"export default function defaultCallee(response) {
  return response;
}

export function namedCallee(response) {
  return response;
}
"#;

const TOP_CALLER: &str = r#"import defaultCallee from '../core/lib.js';
import { namedCallee } from '../core/lib.js';

export function topAdapter(config) {
  return new Promise(function dispatch(resolve, reject) {
    request.on('done', function onDone(response) {
      defaultCallee(response);
      namedCallee(response);
    });
  });
}
"#;

/// The positive control, kept as its own test rather than as the first
/// assertion of the one below it.
///
/// A control that shares a test with its subject cannot be OBSERVED to hold
/// while the subject fails: the run reports one verdict for both, and reading
/// it as "the control held" is reading the panic message rather than the
/// result. Split out, it prints its own `ok` line in every falsification arm.
///
/// `namedCallee` is called on the line below the `defaultCallee` call the next
/// test is about, in the same body at the same depth. It resolved before this
/// change and it must go on resolving.
#[test]
fn a_named_imported_callee_resolves_from_the_same_nested_call_site() {
    let linked = link(vec![
        js("core/lib.js", CALLEE_LIB),
        js("adapters/top.js", TOP_CALLER),
    ]);
    assert!(
        linked.has_call(
            linked.entity_id("adapters/top.js", "topAdapter"),
            linked.entity_id("core/lib.js", "namedCallee")
        ),
        "a named-imported callee three function levels down inside a promise \
         executor inside an event callback resolves, which is what says nesting \
         depth is not the mechanism in the two tests below"
    );
}

/// The default import is the subject: it landed on `lib`, the Module entity for
/// the callee's own file, because the resolver returned the first Public entity
/// in that file and a Module spans the whole file, so it sorts first.
#[test]
fn a_default_imported_callee_binds_to_the_declaration_not_the_files_module() {
    let linked = link(vec![
        js("core/lib.js", CALLEE_LIB),
        js("adapters/top.js", TOP_CALLER),
    ]);

    let caller = linked.entity_id("adapters/top.js", "topAdapter");
    let default_callee = linked.entity_id("core/lib.js", "defaultCallee");
    let callee_module = linked.entity_id("core/lib.js", "lib");

    assert!(
        linked.has_call(caller, default_callee),
        "a default-imported callee must reach the function it names"
    );
    assert!(
        !linked.has_call(caller, callee_module),
        "the callee file's Module entity is not its default export"
    );
}

/// Both halves of FIR-3357 in one assertion, from the shape axios is written
/// in: the call sits inside `export default <expression>`, which the parser
/// walked past, and its callee is default-imported, which the linker bound to
/// the wrong node. Either defect alone makes this red.
#[test]
fn a_default_export_expressions_body_reaches_a_default_imported_callee() {
    let nested = r#"import defaultCallee from '../core/lib.js';

const isSupported = true;

export default isSupported &&
  function nestedAdapter(config) {
    return new Promise(function dispatch(resolve, reject) {
      request.on('done', function onDone(response) {
        defaultCallee(response);
      });
    });
  };
"#;
    let linked = link(vec![
        js("core/lib.js", CALLEE_LIB),
        js("adapters/nested.js", nested),
    ]);

    let caller = linked.entity_id("adapters/nested.js", "default");
    let default_callee = linked.entity_id("core/lib.js", "defaultCallee");
    assert!(
        linked.has_call(caller, default_callee),
        "the adapter body under `export default <expression>` calls \
         `defaultCallee`, and the graph must hold that edge"
    );
}

/// axios's `lib/helpers/buildURL.js` shape: the file exports a helper BEFORE
/// its default export.
///
/// This is the case that says the fallback must decline rather than guess.
/// Skipping only the file's Module still left "the first exported entity",
/// which here is `encode` at the top of the file rather than `buildUrl` below
/// it, and on the real repository all three of `buildURL`'s call sites landed
/// on `encode`: the wrong function in the right file. Declining hands the call
/// to the pinned-import tier, which looks the caller's own binding name up
/// inside the pinned file.
#[test]
fn a_default_export_below_a_named_one_is_not_confused_with_it() {
    let linked = link(vec![
        js(
            "helpers/url.js",
            r#"export function encode(val) {
  return val;
}

export default function buildUrl(url, params) {
  return encode(url) + params;
}
"#,
        ),
        js(
            "core/axios.js",
            r#"import buildUrl from '../helpers/url.js';

export function getUri(config) {
  return buildUrl(config.url, config.params);
}
"#,
        ),
    ]);

    let caller = linked.entity_id("core/axios.js", "getUri");
    assert!(
        linked.has_call(caller, linked.entity_id("helpers/url.js", "buildUrl")),
        "the default-imported callee is `buildUrl`, the file's default export"
    );
    assert!(
        !linked.has_call(caller, linked.entity_id("helpers/url.js", "encode")),
        "`encode` is exported first and is not the default export; binding to it \
         is worse than binding to nothing, because it reads as a real answer"
    );
}

/// The file that leaves the fallback no choice: one exported declaration and
/// nothing else, which is axios's `lib/core/settle.js` and the common shape.
/// Here the fallback does answer, and it must answer with the declaration
/// rather than with the file's own module.
#[test]
fn a_lone_default_export_still_resolves_through_the_fallback() {
    // The file is `settler.js` and the declaration is `settle`, so the module
    // and the function carry different names and the assertion below can tell
    // which of the two the call reached. axios's own file is `settle.js`, where
    // they collide and the mistake is invisible from outside.
    let linked = link(vec![
        js(
            "core/settler.js",
            r#"export default function settle(response) {
  return response;
}
"#,
        ),
        js(
            "adapters/only.js",
            r#"import settle from '../core/settler.js';

export function send(response) {
  return settle(response);
}
"#,
        ),
    ]);

    let caller = linked.entity_id("adapters/only.js", "send");
    assert!(
        linked.has_call(caller, linked.entity_id("core/settler.js", "settle")),
        "one exported declaration leaves no ambiguity, so the fallback answers"
    );
    assert!(
        !linked.has_call(caller, linked.entity_id("core/settler.js", "settler")),
        "and it answers with the declaration, not with the file's own module"
    );
}

/// The incremental linker reads the entity list in the order its caller hands
/// it over, and the batch linker sorts by span. Both must answer this the same
/// way, so the rule is keyed on the entity's KIND rather than on where it
/// happens to sit in a list.
///
/// The module is moved to the front here on purpose. In the order the JavaScript
/// adapter emits today it sits last, so an order-reading resolver gets the right
/// answer by luck and a test that used the emission order could not fail.
#[test]
fn the_incremental_linker_skips_the_module_whatever_order_it_was_given() {
    let mut callee = js("core/lib.js", CALLEE_LIB);
    callee
        .entities
        .sort_by_key(|entity| entity.kind != EntityKind::Module);
    assert_eq!(
        callee.entities.first().map(|entity| entity.kind),
        Some(EntityKind::Module),
        "the fixture must hand the module over first, or this test proves nothing"
    );
    let caller = js("adapters/top.js", TOP_CALLER);

    let mut linker = IncrementalLinker::new();
    let files = vec![callee, caller];
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    let relations = link_cross_file_incremental(&files, &linker).expect("incremental link");

    let id = |file: &str, name: &str| {
        files
            .iter()
            .flat_map(|f| f.entities.iter())
            .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
            .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
            .id
    };
    let has_call = |src, dst| {
        relations.iter().any(|r| {
            r.kind == RelationKind::Calls
                && r.src == GraphNodeId::Entity(src)
                && r.dst == GraphNodeId::Entity(dst)
        })
    };

    assert!(
        has_call(
            id("adapters/top.js", "topAdapter"),
            id("core/lib.js", "defaultCallee")
        ),
        "the incremental linker must reach the declaration too"
    );
    assert!(
        !has_call(
            id("adapters/top.js", "topAdapter"),
            id("core/lib.js", "lib")
        ),
        "and must not park the call on the callee file's module"
    );
}
