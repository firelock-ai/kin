// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language entity-extraction matrix (FIR-1313).
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
