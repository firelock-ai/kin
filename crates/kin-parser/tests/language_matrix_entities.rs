// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language entity-extraction matrix.
//!
//! For every language with a full adapter, asserts that functions, methods, and
//! classes/types are extracted with non-empty canonical signatures, and that a
//! multi-line declaration collapses to the same signature string as its
//! single-line form (the shared `declaration_signature` contract exercised by
//! `cpp_multiline_declarator_keeps_signature_string`).
//!
//! Signatures come from the shared `declaration_signature`, which cuts before a
//! node's `body` field, or before a plainly-kinded body child (Kotlin's
//! `function_body`/`class_body`) when the grammar exposes no such field. The
//! `#[ignore]`d tests at the bottom pin the cells where that contract is not met
//! today (Ruby: an empty-body method keeps a trailing `end`) plus the shared
//! trailing-comma wart.

use kin_model::{EntityKind, FilePathId};
use kin_parser::{
    CAdapter, CSharpAdapter, CppAdapter, ExtractedEntity, GoAdapter, JavaAdapter,
    JavaScriptAdapter, KotlinAdapter, LanguageAdapter, ParseOutput, PhpAdapter, PythonAdapter,
    RubyAdapter, RustAdapter, SwiftAdapter, TypeScriptAdapter,
};

fn extract(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> ParseOutput {
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    adapter
        .extract(&tree, bytes, &FilePathId::new(path))
        .expect("extract should succeed")
}

fn entity<'a>(out: &'a ParseOutput, kind: EntityKind, name: &str) -> &'a ExtractedEntity {
    out.entities
        .iter()
        .find(|e| e.kind == kind && e.name == name)
        .unwrap_or_else(|| {
            panic!(
                "no {kind:?} named {name:?}; have: {:?}",
                out.entities
                    .iter()
                    .map(|e| (e.kind, e.name.as_str()))
                    .collect::<Vec<_>>()
            )
        })
}

/// A callable entity must have a non-empty signature that names it, shows its
/// parameter list, and does not leak its body (`{`).
fn assert_clean_callable_sig(e: &ExtractedEntity, simple_name: &str) {
    assert!(!e.signature.is_empty(), "empty signature for {}", e.name);
    assert!(
        e.signature.contains(simple_name),
        "signature {:?} should name {:?}",
        e.signature,
        simple_name
    );
    assert!(
        e.signature.contains('('),
        "signature {:?} should carry a parameter list",
        e.signature
    );
    assert!(
        !e.signature.contains('{'),
        "signature {:?} must not leak the body",
        e.signature
    );
}

fn sig_of(adapter: &dyn LanguageAdapter, path: &str, src: &str, name: &str) -> String {
    extract(adapter, path, src)
        .entities
        .into_iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("entity {name:?} not found"))
        .signature
}

/// Assert a pure line-wrap of a declaration (no added tokens) collapses to the
/// same signature string as its single-line form.
fn assert_multiline_stable(
    adapter: &dyn LanguageAdapter,
    path: &str,
    single: &str,
    multi: &str,
    name: &str,
) {
    let a = sig_of(adapter, path, single, name);
    let b = sig_of(adapter, path, multi, name);
    assert_eq!(a, b, "line-wrapping must not change the signature ({name})");
    assert!(!a.is_empty(), "signature must be non-empty ({name})");
}

// ---------------------------------------------------------------------------
// Entity extraction — one test per language.
// ---------------------------------------------------------------------------

#[test]
fn typescript_entities() {
    let out = extract(
        &TypeScriptAdapter,
        "s.ts",
        "export function plain(): number { return 1; }\nclass Service {\n  run(): void {}\n}\ninterface Greeter { greet(): string; }\ntype Id = string;\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::Interface, "Greeter")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::TypeAlias, "Id")
        .signature
        .is_empty());
    assert_multiline_stable(
        &TypeScriptAdapter,
        "s.ts",
        "function total(a: number, b: number): number { return a + b; }",
        "function total(\n  a: number,\n  b: number\n): number { return a + b; }",
        "total",
    );
}

#[test]
fn javascript_entities() {
    let out = extract(
        &JavaScriptAdapter,
        "s.js",
        "export function plain() { return 1; }\nclass Service {\n  run() {}\n}\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &JavaScriptAdapter,
        "s.js",
        "function total(a, b) { return a + b; }",
        "function total(\n  a,\n  b\n) { return a + b; }",
        "total",
    );
}

#[test]
fn python_entities() {
    let out = extract(
        &PythonAdapter,
        "s.py",
        "def plain():\n    return 1\n\nclass Service:\n    def run(self):\n        pass\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &PythonAdapter,
        "s.py",
        "def total(a, b):\n    return a + b\n",
        "def total(\n    a,\n    b):\n    return a + b\n",
        "total",
    );
}

#[test]
fn go_entities() {
    let out = extract(
        &GoAdapter,
        "s.go",
        "package main\n\nfunc plain() {}\n\ntype Server struct{}\n\nfunc (s *Server) Run() {}\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Server.Run"), "Run");
    assert!(!entity(&out, EntityKind::Class, "Server")
        .signature
        .is_empty());
    assert_multiline_stable(
        &GoAdapter,
        "s.go",
        "package main\nfunc total(a int, b int) int { return a + b }\n",
        "package main\nfunc total(\n    a int,\n    b int) int { return a + b }\n",
        "total",
    );
}

#[test]
fn java_entities() {
    let out = extract(
        &JavaAdapter,
        "S.java",
        "class Service {\n    void run() {}\n}\ninterface Greeter { String greet(); }\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::Interface, "Greeter")
        .signature
        .is_empty());
    assert_multiline_stable(
        &JavaAdapter,
        "S.java",
        "class C { int total(int a, int b) { return a + b; } }",
        "class C { int total(\n    int a,\n    int b\n) { return a + b; } }",
        "C.total",
    );
}

#[test]
fn rust_entities() {
    let out = extract(
        &RustAdapter,
        "s.rs",
        "fn plain() -> i32 { 1 }\n\nstruct Service;\n\nimpl Service {\n    fn run(&self) {}\n}\ntrait Greeter { fn greet(&self) -> String; }\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service::run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::TraitDef, "Greeter")
        .signature
        .is_empty());
    assert_multiline_stable(
        &RustAdapter,
        "s.rs",
        "fn total(a: i32, b: i32) -> i32 { a + b }",
        "fn total(\n    a: i32,\n    b: i32) -> i32 { a + b }",
        "total",
    );
}

#[test]
fn c_entities() {
    let out = extract(
        &CAdapter,
        "s.c",
        "int plain() { return 1; }\nvoid run() {}\nstruct Point { int x; int y; };\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Point")
        .signature
        .is_empty());
    assert_multiline_stable(
        &CAdapter,
        "s.c",
        "int total(int a, int b) { return a + b; }",
        "int total(\n    int a,\n    int b\n) { return a + b; }",
        "total",
    );
}

#[test]
fn cpp_entities() {
    let out = extract(
        &CppAdapter,
        "s.cpp",
        "int plain() { return 1; }\nclass Service {\npublic:\n    void run() {}\n};\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service::run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &CppAdapter,
        "s.cpp",
        "int total(int a, int b) { return a + b; }",
        "int total(\n    int a,\n    int b\n) { return a + b; }",
        "total",
    );
}

#[test]
fn csharp_entities() {
    let out = extract(
        &CSharpAdapter,
        "S.cs",
        "namespace Demo {\n    class Service {\n        void Run() {}\n    }\n}\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Demo.Service.Run"), "Run");
    assert!(!entity(&out, EntityKind::Class, "Demo.Service")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::Module, "Demo")
        .signature
        .is_empty());
    assert_multiline_stable(
        &CSharpAdapter,
        "S.cs",
        "namespace N { class C { int Total(int a, int b) { return a + b; } } }",
        "namespace N { class C { int Total(\n    int a,\n    int b\n) { return a + b; } } }",
        "N.C.Total",
    );
}

#[test]
fn ruby_entities() {
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "class Service\n    def run\n        work\n    end\nend\n",
    );
    // A method with a body gets a clean `def run` signature.
    assert_clean_callable_sig_ruby(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &RubyAdapter,
        "s.rb",
        "class C\n    def total(a, b)\n        a + b\n    end\nend\n",
        "class C\n    def total(\n        a,\n        b)\n        a + b\n    end\nend\n",
        "C.total",
    );
}

/// Ruby signatures have no parameter parens for a paren-less `def`, so the
/// generic paren assertion does not apply; only name + non-empty + no body.
fn assert_clean_callable_sig_ruby(e: &ExtractedEntity, simple_name: &str) {
    assert!(!e.signature.is_empty(), "empty signature for {}", e.name);
    assert!(
        e.signature.contains(simple_name),
        "signature {:?} should name {:?}",
        e.signature,
        simple_name
    );
    assert!(
        !e.signature.contains('{'),
        "signature {:?} must not leak a brace body",
        e.signature
    );
}

#[test]
fn php_entities() {
    let out = extract(
        &PhpAdapter,
        "s.php",
        "<?php\nfunction plain() { return 1; }\nclass Service {\n    public function run() {}\n}\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &PhpAdapter,
        "s.php",
        "<?php\nfunction total($a, $b) { return $a + $b; }\n",
        "<?php\nfunction total(\n    $a,\n    $b\n) { return $a + $b; }\n",
        "total",
    );
}

#[test]
fn swift_entities() {
    let out = extract(
        &SwiftAdapter,
        "s.swift",
        "func plain() -> Int { return 1 }\nclass Service {\n    func run() {}\n}\n",
    );
    assert_clean_callable_sig(entity(&out, EntityKind::Function, "plain"), "plain");
    assert_clean_callable_sig(entity(&out, EntityKind::Method, "Service.run"), "run");
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &SwiftAdapter,
        "s.swift",
        "func total(a: Int, b: Int) -> Int { return a + b }",
        "func total(\n    a: Int,\n    b: Int\n) -> Int { return a + b }",
        "total",
    );
}

#[test]
fn kotlin_entities_extract_with_nonempty_signatures() {
    // Kotlin entities are extracted with the right kinds and names, and the
    // multi-line form is stable. The *quality* gap (body in signature) is pinned
    // separately below.
    let out = extract(
        &KotlinAdapter,
        "s.kt",
        "fun plain(): Int { return 1 }\nclass Service {\n    fun run() {}\n}\n",
    );
    assert!(!entity(&out, EntityKind::Function, "plain")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::Method, "Service.run")
        .signature
        .is_empty());
    assert!(!entity(&out, EntityKind::Class, "Service")
        .signature
        .is_empty());
    assert_multiline_stable(
        &KotlinAdapter,
        "s.kt",
        "fun total(a: Int, b: Int): Int { return a + b }",
        "fun total(\n    a: Int,\n    b: Int\n): Int { return a + b }",
        "total",
    );
}

// ---------------------------------------------------------------------------
// Pinned gaps (RED/YELLOW cells) — executable, #[ignore]d with the observed
// behavior named on the reason line.
// ---------------------------------------------------------------------------

#[test]
fn kotlin_signature_should_exclude_body() {
    let sig = sig_of(
        &KotlinAdapter,
        "s.kt",
        "fun total(a: Int, b: Int): Int {\n    return a + b\n}\n",
        "total",
    );
    assert!(
        !sig.contains('{'),
        "Kotlin signature should exclude the body, got {sig:?}"
    );
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript relational shape.
//
// A `kin init` of express on 0.5.36 produced 613 entities and 211 relations:
// 0.34 per entity, no Contains, no Extends, no Method or Class kind, and 451 of
// the 613 entities Constants. Python on a comparable repo produced 2.64
// relations per entity. The two fixtures below carry every JavaScript shape
// that gap came from, and assert edge DENSITY as well as presence so a
// regression that halves the relational graph fails rather than passing on a
// surviving sample.
// ---------------------------------------------------------------------------

/// Every relational JavaScript shape in one file: an ES class with methods and
/// a base, a constructor with a prototype method, a receiver-object method, a
/// namespace object literal, a const-bound arrow, a CommonJS export and an ESM
/// export.
const RELATIONAL_JS: &str = r#"
import { helper } from './helper';
const format = require('./format');

export class Service extends Base {
  run() { return format(helper(this.id)); }
  stop() { return format(helper(this.id)); }
}

function View(name) { this.name = normalize(trim(name)); }
View.prototype.lookup = function lookup(n) { return format(helper(n)); };

res.status = function status(code) { return format(validate(code)); };
res.set = res.header = function header(field) { return format(trim(field)); };

const utils = {
  parse(input) { return format(helper(input)); },
  print: (x) => format(trim(x)),
};

const build = (spec) => format(normalize(spec));

module.exports = { boot() { return format(helper(0)); } };

export const NAME = 'service';
"#;

/// The TypeScript mirror of [`RELATIONAL_JS`]. The two adapters share the
/// CommonJS import surface, the receiver-assignment forms and the
/// object-literal method extraction, so a divergence here means one adapter
/// answers a question about the same source differently from the other.
const RELATIONAL_TS: &str = r#"
import { helper } from './helper';
const format = require('./format');

export class Service extends Base {
  run(): number { return format(helper(this.id)); }
  stop(): number { return format(helper(this.id)); }
}

function View(name: string) { this.name = normalize(trim(name)); }
View.prototype.lookup = function lookup(n: string) { return format(helper(n)); };

res.status = function status(code: number) { return format(validate(code)); };
res.set = res.header = function header(field: string) { return format(trim(field)); };

const utils = {
  parse(input: string) { return format(helper(input)); },
  print: (x: string) => format(trim(x)),
};

const build = (spec: string) => format(normalize(spec));

module.exports = { boot() { return format(helper(0)); } };

export const NAME = 'service';
"#;

/// Assert the relational contract both adapters must satisfy on their fixture.
fn assert_relational_shape(out: &ParseOutput, lang: &str) {
    let named: Vec<(EntityKind, &str)> = out
        .entities
        .iter()
        .map(|e| (e.kind, e.name.as_str()))
        .collect();
    let expected = [
        // ES class, its methods, and the constructor-plus-prototype form.
        // Both are classes with methods, and the graph must not tell them apart.
        (EntityKind::Class, "Service"),
        (EntityKind::Method, "Service.run"),
        (EntityKind::Method, "Service.stop"),
        (EntityKind::Class, "View"),
        (EntityKind::Method, "View.lookup"),
        // A receiver object owns what is assigned to it, and a chained
        // assignment defines every target on the chain.
        (EntityKind::Class, "res"),
        (EntityKind::Method, "res.status"),
        (EntityKind::Method, "res.set"),
        (EntityKind::Method, "res.header"),
        // A namespace object literal owns its function properties.
        (EntityKind::Class, "utils"),
        (EntityKind::Method, "utils.parse"),
        (EntityKind::Method, "utils.print"),
        // A const-bound arrow is a Function, never a Constant.
        (EntityKind::Function, "build"),
        // `module.exports = { ... }` exports one function per property.
        (EntityKind::Function, "boot"),
        // A scalar named export stays a Constant.
        (EntityKind::Constant, "NAME"),
    ];
    for want in expected {
        assert!(
            named.contains(&want),
            "{lang}: missing {want:?}; have {named:?}"
        );
    }

    let contains: std::collections::BTreeSet<(&str, &str)> = out
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Contains)
        .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
        .collect();
    for want in [
        ("Service", "Service.run"),
        ("Service", "Service.stop"),
        ("View", "View.lookup"),
        ("res", "res.status"),
        ("res", "res.set"),
        ("res", "res.header"),
        ("utils", "utils.parse"),
        ("utils", "utils.print"),
    ] {
        assert!(
            contains.contains(&want),
            "{lang}: missing Contains {want:?}; have {contains:?}"
        );
    }

    let extends: Vec<(&str, &str)> = out
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Extends)
        .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
        .collect();
    assert_eq!(extends, vec![("Service", "Base")], "{lang}: Extends");

    // Both the ESM `import` and the CommonJS `require` reach the import
    // surface; cross-file resolution has no binding to work with otherwise.
    let modules: std::collections::BTreeSet<&str> =
        out.imports.iter().map(|i| i.module_path.as_str()).collect();
    assert!(
        modules.contains("./helper") && modules.contains("./format"),
        "{lang}: expected both ESM and CommonJS imports, got {modules:?}"
    );
    // A require binding is a dependency line, not an entity.
    assert!(
        !named.iter().any(|(_, n)| *n == "format"),
        "{lang}: require binding must not become an entity; have {named:?}"
    );

    // Density, not just presence: express measured 0.34 relations per entity
    // against Python's 2.64. Asserting the ratio is what makes a regression
    // that halves the edge count fail on a fixture that still contains every
    // expected name.
    //
    // The file's own Module entity is excluded from the denominator, and the
    // exclusion is the point rather than a convenience. Since FIR-2675 every
    // JS/TS file carries one, and it is deliberately not a container: Python's
    // module is not one either, and making it one would put every top-level
    // entity inside it, which `top_level_entities` in the round-trip fuzz reads
    // as one whole-file region and collapses. So the module is a node this
    // fixture's relational shape says nothing about, and counting it in the
    // denominator measured the port rather than the edges. Left in, it dropped
    // this fixture from 2.07 to 1.94 while not one relation had changed.
    let counted: Vec<_> = out
        .entities
        .iter()
        .filter(|e| e.kind != EntityKind::Module)
        .collect();
    let density = out.relations.len() as f64 / counted.len() as f64;
    assert!(
        density >= 2.0,
        "{lang}: {} relations over {} non-module entities is {density:.2} per entity, \
         below the 2.0 floor this fixture must clear",
        out.relations.len(),
        counted.len()
    );
}

#[test]
fn javascript_relational_shape() {
    assert_relational_shape(
        &extract(&JavaScriptAdapter, "service.js", RELATIONAL_JS),
        "javascript",
    );
}

#[test]
fn typescript_relational_shape() {
    assert_relational_shape(
        &extract(&TypeScriptAdapter, "service.ts", RELATIONAL_TS),
        "typescript",
    );
}

// ---------------------------------------------------------------------------
// The CommonJS export surface.
//
// express's `lib/utils.js` exports nine names. Six are function literals and
// three are call results, and the three produced no entity at all: not an
// unresolved reference the absence machinery could hedge about, but nothing to
// hedge about. An export sweep run from the graph returned six and reported
// nothing missing.
// ---------------------------------------------------------------------------

/// The shape of express's `lib/utils.js`: require bindings at the top, then
/// nine exports whose right-hand sides are a call on a required module, two
/// factory calls, a member access, an identifier, a re-exported dependency and
/// three function literals.
const EXPORT_SURFACE_JS: &str = r#"
var { METHODS } = require('node:http');
var etag = require('etag');
var bodyParser = require('body-parser');

exports.methods = METHODS.map((method) => method.toLowerCase());
exports.etag = createETagGenerator({ weak: false });
exports.wetag = createETagGenerator({ weak: true });
exports.json = bodyParser.json;
exports.Router = Router;
exports.static = require('serve-static');
exports.normalizeType = function(type) { return acceptParams(type); };
exports.compileETag = function(val) { return wrap(val); };
exports.compileQueryParser = function compileQueryParser(val) { return wrap(val); };
"#;

/// The TypeScript mirror. Both adapters share `extract_js_assignment_function`,
/// so a divergence here means one of them answers a question about the same
/// CommonJS source differently from the other.
const EXPORT_SURFACE_TS: &str = r#"
var { METHODS } = require('node:http');
var etag = require('etag');
var bodyParser = require('body-parser');

exports.methods = METHODS.map((method: string) => method.toLowerCase());
exports.etag = createETagGenerator({ weak: false });
exports.wetag = createETagGenerator({ weak: true });
exports.json = bodyParser.json;
exports.Router = Router;
exports.static = require('serve-static');
exports.normalizeType = function(type: string) { return acceptParams(type); };
exports.compileETag = function(val: string) { return wrap(val); };
exports.compileQueryParser = function compileQueryParser(val: string) { return wrap(val); };
"#;

/// Every name a CommonJS module exports must be reachable from the graph, and
/// its kind must say what it is.
fn assert_export_surface(out: &ParseOutput, lang: &str) {
    let named: Vec<(EntityKind, &str)> = out
        .entities
        .iter()
        .map(|e| (e.kind, e.name.as_str()))
        .collect();

    // A call result, a member access and a bare identifier are exports as much
    // as a function literal is. Each is a value, so each is kinded Constant.
    for want in [
        (EntityKind::Constant, "methods"),
        (EntityKind::Constant, "etag"),
        (EntityKind::Constant, "wetag"),
        (EntityKind::Constant, "json"),
        (EntityKind::Constant, "Router"),
        (EntityKind::Function, "normalizeType"),
        (EntityKind::Function, "compileETag"),
        (EntityKind::Function, "compileQueryParser"),
    ] {
        assert!(
            named.contains(&want),
            "{lang}: missing export {want:?}; have {named:?}"
        );
    }

    // Every one of them is public; an export sweep keys on that.
    for e in &out.entities {
        assert_eq!(
            e.visibility,
            kin_model::Visibility::Public,
            "{lang}: export {:?} should be public",
            e.name
        );
    }

    // `exports.static = require('serve-static')` is a re-exported dependency.
    // It reaches the graph as an import specifier under that name, so a
    // constant beside it would count the same dependency line twice.
    assert!(
        !named.iter().any(|(_, n)| *n == "static"),
        "{lang}: a require re-export must stay an import; have {named:?}"
    );
    let static_specifiers: Vec<&str> = out
        .imports
        .iter()
        .filter(|i| i.module_path == "serve-static")
        .flat_map(|i| i.specifiers.iter().map(|s| s.local_name.as_str()))
        .collect();
    assert_eq!(
        static_specifiers,
        vec!["static"],
        "{lang}: serve-static should bind one specifier"
    );

    // The factory a call-result export is built from is the edge that makes it
    // reachable from the code that produces it.
    let calls: Vec<(&str, &str)> = out
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
        .collect();
    for want in [
        ("etag", "createETagGenerator"),
        ("wetag", "createETagGenerator"),
        ("methods", "map"),
    ] {
        assert!(
            calls.contains(&want),
            "{lang}: missing Calls {want:?}; have {calls:?}"
        );
    }

    // Nine exports in, nine reachable out. Reverting the rule that admits a
    // non-function right-hand side drops this to six.
    let exported = [
        "methods",
        "etag",
        "wetag",
        "json",
        "Router",
        "static",
        "normalizeType",
        "compileETag",
        "compileQueryParser",
    ];
    let reachable = exported
        .iter()
        .filter(|name| {
            named.iter().any(|(_, n)| n == *name)
                || out
                    .imports
                    .iter()
                    .any(|i| i.specifiers.iter().any(|s| s.local_name == **name))
        })
        .count();
    assert_eq!(
        reachable,
        exported.len(),
        "{lang}: {reachable} of {} exports reachable; have {named:?}",
        exported.len()
    );
}

#[test]
fn javascript_commonjs_export_surface() {
    assert_export_surface(
        &extract(&JavaScriptAdapter, "utils.js", EXPORT_SURFACE_JS),
        "javascript",
    );
}

#[test]
fn typescript_commonjs_export_surface() {
    assert_export_surface(
        &extract(&TypeScriptAdapter, "utils.ts", EXPORT_SURFACE_TS),
        "typescript",
    );
}

/// `export const X = f(...)` is the ESM form of the same export. It already
/// produced an entity, and this pins that, so the CommonJS rule and the ESM
/// path cannot drift into different answers about the same export.
#[test]
fn esm_export_const_from_a_call_result_is_a_constant() {
    let src = "export const etag = createETagGenerator({ weak: false });";
    for (lang, out) in [
        ("javascript", extract(&JavaScriptAdapter, "utils.js", src)),
        ("typescript", extract(&TypeScriptAdapter, "utils.ts", src)),
    ] {
        let named: Vec<(EntityKind, &str)> = out
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert!(
            named.contains(&(EntityKind::Constant, "etag")),
            "{lang}: ESM call-result export missing; have {named:?}"
        );
    }
}

#[test]
#[ignore = "YELLOW: Ruby empty-body method keeps a trailing `end` in the signature (`def helper end`) because there is no `body` field to cut before"]
fn ruby_empty_body_method_signature_should_exclude_end() {
    let sig = sig_of(
        &RubyAdapter,
        "s.rb",
        "class C\n    def helper\n    end\nend\n",
        "C.helper",
    );
    assert_eq!(sig, "def helper", "got {sig:?}");
}

#[test]
#[ignore = "YELLOW: shared declaration_signature does not collapse a trailing `,)` — a multi-line param list with a trailing comma yields `total(a, b,)` vs single-line `total(a, b)`. Affects every trailing-comma grammar (Rust/Python/Go/TS/JS/Kotlin/Swift)"]
fn trailing_comma_multiline_signature_should_match_single_line() {
    // Representative sample across three grammars; the wart is in the shared
    // signature canonicalizer, so any trailing-comma language reproduces it.
    let rust = |s: &str| sig_of(&RustAdapter, "s.rs", s, "total");
    assert_eq!(
        rust("fn total(a: i32, b: i32) -> i32 { a + b }"),
        rust("fn total(a: i32, b: i32,) -> i32 { a + b }"),
    );
    let py = |s: &str| sig_of(&PythonAdapter, "s.py", s, "total");
    assert_eq!(
        py("def total(a, b):\n    return a + b\n"),
        py("def total(a, b,):\n    return a + b\n"),
    );
    let go = |s: &str| sig_of(&GoAdapter, "s.go", s, "total");
    assert_eq!(
        go("package main\nfunc total(a int, b int) int { return a + b }\n"),
        go("package main\nfunc total(a int, b int,) int { return a + b }\n"),
    );
}
