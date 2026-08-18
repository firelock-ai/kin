// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language call-relation matrix.
//!
//! Three probes per language: (1) a plain same-file call emits a `Calls` edge
//! whose `dst_name` is a simple, index-matchable identifier; (2) a method call
//! on an object emits the rightmost name (never the dotted `obj.method` form);
//! (3) handlers wired as values/callbacks — whatever the language idiomatically
//! uses — probed for what the adapter *actually* emits.
//!
//! GREEN cells are locked as regression tests, including the rightmost-name
//! narrowing of dotted method calls in every adapter. Rust's `self.` call is
//! the deliberate exception: the receiver is settled by the syntax, so it is
//! folded into an owner-qualified `Type::method` destination rather than left
//! as a bare leaf. That destination is still simple and index-matchable, which
//! is the property this matrix exists to lock. Several callback shapes
//! are not wired to edges; those cells are written and `#[ignore]`d with the
//! observed behavior named on the reason line.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{
    CAdapter, CSharpAdapter, CppAdapter, ExtractedRelation, GoAdapter, JavaAdapter,
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

fn rels_of(out: &ParseOutput, kind: RelationKind) -> Vec<&ExtractedRelation> {
    out.relations.iter().filter(|r| r.kind == kind).collect()
}

fn has_edge(out: &ParseOutput, kind: RelationKind, src: &str, dst: &str) -> bool {
    out.relations
        .iter()
        .any(|r| r.kind == kind && r.src_name == src && r.dst_name == dst)
}

fn no_dotted_call_dst(out: &ParseOutput) {
    let dotted: Vec<&str> = rels_of(out, RelationKind::Calls)
        .iter()
        .map(|r| r.dst_name.as_str())
        .filter(|n| n.contains('.'))
        .collect();
    assert!(
        dotted.is_empty(),
        "Calls dst_names must be simple identifiers, got dotted: {dotted:?}"
    );
}

// ---------------------------------------------------------------------------
// (1) plain same-file call -> simple dst_name  [GREEN, all languages]
// ---------------------------------------------------------------------------

#[test]
fn typescript_plain_call_emits_simple_name() {
    let out = extract(
        &TypeScriptAdapter,
        "s.ts",
        "function caller() { target(); }\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn javascript_plain_call_emits_simple_name() {
    let out = extract(
        &JavaScriptAdapter,
        "s.js",
        "function caller() { target(); }\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn python_plain_call_emits_simple_name() {
    let out = extract(&PythonAdapter, "s.py", "def caller():\n    target()\n");
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn go_plain_call_emits_simple_name() {
    let out = extract(
        &GoAdapter,
        "s.go",
        "package main\nfunc caller() { target() }\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn java_plain_call_emits_simple_name() {
    let out = extract(
        &JavaAdapter,
        "S.java",
        "class C { void caller() { target(); } void target() {} }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "C.caller", "target"));
}

#[test]
fn rust_plain_call_emits_simple_name() {
    let out = extract(&RustAdapter, "s.rs", "fn caller() { target(); }\n");
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn c_plain_call_emits_simple_name() {
    let out = extract(&CAdapter, "s.c", "void caller() { target(); }\n");
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn cpp_plain_call_emits_simple_name() {
    let out = extract(&CppAdapter, "s.cpp", "void caller() { target(); }\n");
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn csharp_plain_call_emits_simple_name() {
    let out = extract(
        &CSharpAdapter,
        "S.cs",
        "namespace N { class C { void Caller() { Target(); } void Target() {} } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "N.C.Caller", "Target"));
}

#[test]
fn ruby_parenthesized_call_emits_simple_name() {
    // Ruby needs parentheses (or a receiver) for the extractor to see a `call`
    // node; the paren-less form is pinned in the ignored section below.
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "class C\n    def caller\n        target()\n    end\nend\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "C.caller", "target"));
}

#[test]
fn php_plain_call_emits_simple_name() {
    let out = extract(
        &PhpAdapter,
        "s.php",
        "<?php\nfunction caller() { target(); }\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn kotlin_plain_call_emits_simple_name() {
    let out = extract(&KotlinAdapter, "s.kt", "fun caller() { target() }\n");
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

#[test]
fn swift_plain_call_emits_simple_name() {
    let out = extract(&SwiftAdapter, "s.swift", "func caller() { target() }\n");
    assert!(has_edge(&out, RelationKind::Calls, "caller", "target"));
}

// ---------------------------------------------------------------------------
// (2) method call on an object -> rightmost name  [GREEN where narrowed]
// ---------------------------------------------------------------------------

#[test]
fn typescript_method_call_emits_rightmost_name() {
    let out = extract(
        &TypeScriptAdapter,
        "s.ts",
        "class S { run() { obj.execute(); } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn javascript_method_call_emits_rightmost_name() {
    let out = extract(
        &JavaScriptAdapter,
        "s.js",
        "class S { run() { obj.execute(); } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn python_method_call_emits_rightmost_name() {
    let out = extract(
        &PythonAdapter,
        "s.py",
        "class S:\n    def run(self):\n        obj.execute()\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn go_selector_call_emits_rightmost_name() {
    let out = extract(
        &GoAdapter,
        "s.go",
        "package main\nimport \"fmt\"\nfunc run() { fmt.Println(\"x\") }\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "run", "Println"));
    no_dotted_call_dst(&out);
}

/// Rust is the one cell in this matrix that does not narrow to the bare
/// rightmost name, because `self` settles the receiver. Inside `impl S`,
/// `self.helper()` can only reach `S`'s own `helper`, and `S::helper` is the
/// exact key that method entity is stored under, so folding the receiver into
/// the callee resolves the call to its definition. The bare leaf is what let a
/// `self.` call match every same-named method in the repository. The matrix
/// invariant that matters is unchanged: the destination is still simple and
/// index-matchable, and still never the dotted `self.helper` form. FIR-1581.
#[test]
fn rust_self_method_call_folds_the_receiver_into_the_owner() {
    let out = extract(
        &RustAdapter,
        "s.rs",
        "struct S;\nimpl S {\n    fn run(&self) { self.helper(); }\n    fn helper(&self) {}\n}\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S::run", "S::helper"));
    assert!(
        !has_edge(&out, RelationKind::Calls, "S::run", "helper"),
        "the bare leaf is what made a `self.` call ambiguous across crates"
    );
    no_dotted_call_dst(&out);
}

#[test]
fn cpp_method_call_emits_rightmost_name() {
    let out = extract(
        &CppAdapter,
        "s.cpp",
        "class S {\npublic:\n    void run() { obj.execute(); }\n};\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S::run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn ruby_receiver_call_emits_rightmost_name() {
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "class S\n    def run\n        obj.execute\n    end\nend\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn php_method_call_emits_rightmost_name() {
    let out = extract(
        &PhpAdapter,
        "s.php",
        "<?php\nclass S {\n    public function run() { $obj->execute(); }\n}\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn kotlin_method_call_emits_rightmost_name() {
    let out = extract(
        &KotlinAdapter,
        "s.kt",
        "class S {\n    fun run() { obj.execute() }\n}\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn swift_method_call_emits_rightmost_name() {
    let out = extract(
        &SwiftAdapter,
        "s.swift",
        "class S {\n    func run() { obj.execute() }\n}\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "execute"));
    no_dotted_call_dst(&out);
}

// ---------------------------------------------------------------------------
// (3) value-position / callback handlers — what the adapter ACTUALLY emits.
// ---------------------------------------------------------------------------

#[test]
fn go_function_value_argument_emits_reference() {
    // Go and Python turn a bare function passed as a value into a graph edge:
    // `register(plain)` yields a References edge to `plain`. TypeScript, Java
    // and Ruby still do not, which is what the ignored cases below record.
    let out = extract(
        &GoAdapter,
        "s.go",
        "package main\nfunc plain() {}\nfunc run() { register(plain) }\n",
    );
    assert!(
        has_edge(&out, RelationKind::References, "run", "plain"),
        "expected References run -> plain, got {:?}",
        out.relations
            .iter()
            .map(|r| (r.kind, r.src_name.as_str(), r.dst_name.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn python_function_value_argument_emits_reference() {
    // The argparse shape: `set_defaults(func=cmd_ingest)` never calls
    // `cmd_ingest`, so the References edge is the only one it can own.
    let out = extract(
        &PythonAdapter,
        "s.py",
        "def plain():\n    return 1\n\ndef run():\n    register(func=plain)\n",
    );
    assert!(
        has_edge(&out, RelationKind::References, "run", "plain"),
        "expected References run -> plain, got {:?}",
        out.relations
            .iter()
            .map(|r| (r.kind, r.src_name.as_str(), r.dst_name.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn csharp_object_creation_emits_reference() {
    let out = extract(
        &CSharpAdapter,
        "S.cs",
        "namespace N { class C { void Run() { var w = new Widget(); } } }",
    );
    assert!(has_edge(
        &out,
        RelationKind::References,
        "N.C.Run",
        "Widget"
    ));
}

#[test]
fn kotlin_lambda_body_calls_are_captured() {
    // A handler wired as a trailing lambda: the calls *inside* the lambda body
    // attribute to the enclosing method.
    let out = extract(
        &KotlinAdapter,
        "s.kt",
        "class S {\n    fun run() { register { handle() } }\n}\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "register"));
    assert!(has_edge(&out, RelationKind::Calls, "S.run", "handle"));
}

#[test]
fn java_lambda_body_calls_are_captured() {
    let out = extract(
        &JavaAdapter,
        "S.java",
        "class C { void run() { list.forEach(x -> handle(x)); } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "C.run", "handle"));
}

#[test]
fn ruby_block_body_calls_are_captured() {
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "class C\n    def run\n        items.each { |x| handle(x) }\n    end\nend\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "C.run", "handle"));
}

#[test]
fn typescript_arrow_body_calls_are_captured() {
    let out = extract(
        &TypeScriptAdapter,
        "s.ts",
        "function run() { arr.forEach(x => handle(x)); }\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "run", "handle"));
}

// ---------------------------------------------------------------------------
// Pinned gaps (RED/YELLOW) — executable, #[ignore]d with observed behavior.
// ---------------------------------------------------------------------------

#[test]
fn java_method_call_should_narrow_to_rightmost_name() {
    let out = extract(
        &JavaAdapter,
        "S.java",
        "class C { void run() { obj.execute(); } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "C.run", "execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn csharp_method_call_should_narrow_to_rightmost_name() {
    let out = extract(
        &CSharpAdapter,
        "S.cs",
        "namespace N { class C { void Run() { obj.Execute(); } } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "N.C.Run", "Execute"));
    no_dotted_call_dst(&out);
}

#[test]
fn csharp_static_qualified_call_should_narrow_to_rightmost_name() {
    let out = extract(
        &CSharpAdapter,
        "S.cs",
        "namespace N { class C { void Run() { Console.WriteLine(\"x\"); } } }",
    );
    assert!(has_edge(&out, RelationKind::Calls, "N.C.Run", "WriteLine"));
    no_dotted_call_dst(&out);
}

#[test]
#[ignore = "YELLOW: Ruby drops a paren-less, receiver-less call — bare `target` parses as an identifier, not a `call` node, so no Calls edge is emitted"]
fn ruby_parenless_call_should_be_emitted() {
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "class C\n    def caller\n        target\n    end\nend\n",
    );
    assert!(has_edge(&out, RelationKind::Calls, "C.caller", "target"));
}

#[test]
#[ignore = "YELLOW: a bare function passed as a JS/TS callback value (`register(plain)`) emits no edge to `plain` — only the receiving call `register` is recorded"]
fn typescript_callback_value_should_emit_reference() {
    let out = extract(
        &TypeScriptAdapter,
        "s.ts",
        "function plain() {}\nfunction run() { register(plain); }\n",
    );
    assert!(
        has_edge(&out, RelationKind::References, "run", "plain")
            || has_edge(&out, RelationKind::Calls, "run", "plain"),
        "expected an edge run -> plain for the callback value"
    );
}

#[test]
#[ignore = "YELLOW: a Java method reference (`this::helper`) passed as a value emits no edge to `helper`"]
fn java_method_reference_should_emit_edge() {
    let out = extract(
        &JavaAdapter,
        "S.java",
        "class C { void run() { register(this::helper); } void helper() {} }",
    );
    assert!(
        has_edge(&out, RelationKind::References, "C.run", "helper")
            || has_edge(&out, RelationKind::Calls, "C.run", "helper"),
        "expected an edge C.run -> helper for the method reference"
    );
}

#[test]
#[ignore = "YELLOW: a Ruby symbol callback (`register(:helper)`) emits no edge to `helper` — the symbol argument is not resolved to a reference"]
fn ruby_symbol_callback_should_emit_reference() {
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "class C\n    def run\n        register(:helper)\n    end\n    def helper\n    end\nend\n",
    );
    assert!(
        has_edge(&out, RelationKind::References, "C.run", "helper")
            || has_edge(&out, RelationKind::Calls, "C.run", "helper"),
        "expected an edge C.run -> helper for the symbol callback"
    );
}
