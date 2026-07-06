// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression net for Python call-resolution.
//!
//! Python is the only call-extracting adapter that previously had no dedicated
//! call-resolution test, even though every other one (Go, JS/TS, Kotlin, Swift,
//! C++ qualified-name) does. This file closes that gap.
//!
//! Python narrows attribute callees to their **leaf name at extraction time**,
//! with one deliberate exception. `module.func()`, `obj.method()`, and
//! `self.member.save()` all emit a `Calls` edge whose `dst_name` is the trailing
//! identifier (`func`, `method`, `save`) — their receiver's type is unknowable
//! at parse time. But `self.m()` / `cls.m()` dispatch through the *enclosing
//! class*, so they emit the class-qualified form (`Service.validate`): that
//! qualifier is what lets the linker resolve an inherited method through the
//! class's Extends chain instead of fanning out on the bare name. Because the
//! parser hands the linker either a simple name or a `Class.method` key that
//! matches how method entities are named, name-based cross-file resolution
//! stays aligned with the entity keyspace. These tests are the regression net
//! for both halves of that contract.
//!
//! Same-file extraction (entities + `Calls` `dst_name`s) is asserted here. The
//! cross-file dimension of the matrix — the same three call shapes resolving to
//! an entity in another file through the real linker — lives in
//! `kin-index/tests/python_call_resolution.rs`, since cross-file linking is a
//! kin-index responsibility.
//!
//! Matrix (same-file arm):
//!   * bare call (`target()`), with and without an import binding
//!   * module-attribute call (`module.func()`) — narrowed to `func`
//!   * method call on an instance (`obj.method()`) — narrowed to `method`
//!   * nesting recursion: calls inside nested `def`s and inside class methods
//!     attribute to the innermost *enclosing function entity* (nested `def`s
//!     produce no entity of their own, so their calls roll up to the method or
//!     top-level function that encloses them).

use kin_model::{EntityKind, FilePathId, RelationKind};
use kin_parser::{ExtractedRelation, LanguageAdapter, ParseOutput, PythonAdapter};

fn extract(source: &str) -> ParseOutput {
    let adapter = PythonAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    let file_id = FilePathId::new("test/calls.py");
    adapter
        .extract(&tree, bytes, &file_id)
        .expect("extract should succeed")
}

fn calls(output: &ParseOutput) -> Vec<&ExtractedRelation> {
    output
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect()
}

fn calls_named<'a>(output: &'a ParseOutput, name: &str) -> Vec<&'a ExtractedRelation> {
    calls(output)
        .into_iter()
        .filter(|r| r.dst_name == name)
        .collect()
}

fn has_entity(output: &ParseOutput, kind: EntityKind, name: &str) -> bool {
    output
        .entities
        .iter()
        .any(|e| e.kind == kind && e.name == name)
}

const CALLS_FIXTURE: &[u8] = include_bytes!("../../../tests/adapter-fixtures/python/calls.py");

// ---- bare calls ----

#[test]
fn bare_call_emits_identifier_name() {
    let output = extract("def target():\n    pass\n\ndef caller():\n    target()\n");
    let hits = calls_named(&output, "target");
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one Calls edge named 'target', got {:?}",
        calls(&output)
    );
    assert_eq!(hits[0].src_name, "caller");
    assert!(
        hits[0].import_source.is_none(),
        "a locally-defined callee carries no import source, got {:?}",
        hits[0].import_source
    );
    assert!(has_entity(&output, EntityKind::Function, "caller"));
    assert!(has_entity(&output, EntityKind::Function, "target"));
}

#[test]
fn bare_call_with_import_carries_import_source() {
    // `from helpers import compute` binds the simple name `compute`, so the
    // extractor annotates the `compute()` edge with its module of origin.
    let output = extract("from helpers import compute\n\ndef caller():\n    compute()\n");
    let hits = calls_named(&output, "compute");
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one Calls edge named 'compute', got {:?}",
        calls(&output)
    );
    assert_eq!(hits[0].src_name, "caller");
    assert_eq!(
        hits[0].import_source.as_deref(),
        Some("helpers"),
        "an imported bare callee carries its import path as import_source"
    );
}

// ---- module-attribute calls ----

#[test]
fn module_attribute_call_narrows_to_leaf_name() {
    // `mathlib.compute()` narrows to the leaf `compute`. The dotted form must
    // never survive, and because narrowing drops the `mathlib` binding the leaf
    // name is not an imported name, so it carries no import_source.
    let output = extract("import mathlib\n\ndef caller():\n    mathlib.compute()\n");
    let hits = calls_named(&output, "compute");
    assert_eq!(
        hits.len(),
        1,
        "expected leaf-name edge 'compute' (not 'mathlib.compute'), got {:?}",
        calls(&output)
    );
    assert_eq!(hits[0].src_name, "caller");
    assert!(
        hits[0].import_source.is_none(),
        "leaf name is not the imported binding `mathlib`, so no import_source"
    );
    assert!(
        !calls(&output).iter().any(|r| r.dst_name.contains('.')),
        "dotted form must not appear as a Calls dst_name, got {:?}",
        calls(&output)
    );
}

// ---- method calls on an instance ----

#[test]
fn method_call_on_instance_narrows_to_leaf_name() {
    let output = extract(
        "class Service:\n    def run(self):\n        pass\n\ndef driver():\n    svc = Service()\n    svc.run()\n",
    );
    let run_hits = calls_named(&output, "run");
    assert!(
        run_hits.iter().any(|r| r.src_name == "driver"),
        "expected driver -> run (from `svc.run()`), got {:?}",
        calls(&output)
    );
    // Constructor call `Service()` is a plain identifier callee.
    assert!(
        calls_named(&output, "Service")
            .iter()
            .any(|r| r.src_name == "driver"),
        "expected driver -> Service (constructor), got {:?}",
        calls(&output)
    );
    assert!(
        !calls(&output).iter().any(|r| r.dst_name.contains('.')),
        "no Calls dst_name may be dotted (e.g. 'svc.run'), got {:?}",
        calls(&output)
    );
    assert!(has_entity(&output, EntityKind::Method, "Service.run"));
}

// ---- nesting recursion ----

#[test]
fn nested_def_calls_attribute_to_innermost_enclosing_function() {
    // `inner` is a nested def and gets no entity of its own, so the innermost
    // enclosing *entity* for both `leaf()` and `inner()` is `outer`.
    let output = extract("def outer():\n    def inner():\n        leaf()\n    inner()\n");

    assert!(has_entity(&output, EntityKind::Function, "outer"));
    assert!(
        !has_entity(&output, EntityKind::Function, "inner"),
        "a nested def must not produce its own function entity"
    );

    assert!(
        calls_named(&output, "leaf")
            .iter()
            .all(|r| r.src_name == "outer"),
        "call inside the nested def must attribute to the enclosing entity `outer`, got {:?}",
        calls(&output)
    );
    assert!(
        !calls_named(&output, "leaf").is_empty(),
        "the call inside the nested def must not be dropped, got {:?}",
        calls(&output)
    );
    assert!(
        calls_named(&output, "inner")
            .iter()
            .any(|r| r.src_name == "outer"),
        "the call to the nested def itself attributes to `outer`, got {:?}",
        calls(&output)
    );
    assert!(
        !calls(&output).iter().any(|r| r.src_name == "inner"),
        "no call may attribute to the entity-less nested def `inner`, got {:?}",
        calls(&output)
    );
}

#[test]
fn class_method_nested_def_calls_attribute_to_method_entity() {
    // A class method that wraps a nested def: both the method's own call and the
    // call inside the nested def roll up to the method entity `Holder.method`.
    let output = extract(
        "class Holder:\n    def method(self):\n        def nested():\n            deep()\n        nested()\n",
    );

    assert!(has_entity(&output, EntityKind::Method, "Holder.method"));
    assert!(
        !has_entity(&output, EntityKind::Function, "nested"),
        "a nested def inside a method must not produce its own entity"
    );

    assert!(
        calls_named(&output, "deep")
            .iter()
            .all(|r| r.src_name == "Holder.method"),
        "call inside the method's nested def attributes to `Holder.method`, got {:?}",
        calls(&output)
    );
    assert!(
        !calls_named(&output, "deep").is_empty(),
        "the deeply-nested call must not be dropped, got {:?}",
        calls(&output)
    );
    assert!(
        calls_named(&output, "nested")
            .iter()
            .any(|r| r.src_name == "Holder.method"),
        "the method's call to its nested def attributes to `Holder.method`, got {:?}",
        calls(&output)
    );
}

// ---- self/cls receivers: class-qualified dst_name ----

#[test]
fn self_call_emits_class_qualified_dst() {
    let output = extract(
        "class Command:\n    def handle(self):\n        self.validate()\n        cls_free()\n",
    );
    assert!(
        calls_named(&output, "Command.validate")
            .iter()
            .any(|r| r.src_name == "Command.handle"),
        "self.validate() inside Command must emit the class-qualified dst \
         'Command.validate' so the linker can walk the Extends chain, got {:?}",
        calls(&output)
    );
    assert!(
        calls_named(&output, "validate").is_empty(),
        "the bare form must not be emitted alongside the qualified one, got {:?}",
        calls(&output)
    );
}

// ---- fixture: dst_names are leaf identifiers, except self/cls dispatch ----

#[test]
fn fixture_calls_are_all_leaf_names() {
    let adapter = PythonAdapter;
    let tree = adapter.parse(CALLS_FIXTURE).expect("parse fixture");
    let file_id = FilePathId::new("adapter-fixtures/python/calls.py");
    let output = adapter
        .extract(&tree, CALLS_FIXTURE, &file_id)
        .expect("extract fixture");
    let call_edges = calls(&output);

    // Regression invariant: attribute/method callees are narrowed unless the
    // receiver is `self`/`cls`, whose dispatch class is known — those emit the
    // `Class.method` form. Any other dotted dst_name means the narrowing broke.
    let dotted: Vec<&str> = call_edges
        .iter()
        .map(|r| r.dst_name.as_str())
        .filter(|n| n.contains('.') && *n != "Service.validate")
        .collect();
    assert!(
        dotted.is_empty(),
        "Calls dst_names must be simple identifiers (or self/cls-qualified \
         Class.method), but got dotted: {:?}",
        dotted
    );

    // Every call shape in the matrix is represented.
    for expected in &[
        "handler",          // bare call in plain()
        "add_url_rule",     // attribute call on a local (app.add_url_rule)
        "query",            // chained attribute call (db.session.query())
        "save",             // attribute call on an instance member (self.store.save)
        "Service.validate", // self-call (self.validate) — class-qualified
        "Store",            // constructor call
        "route",            // decorator call @app.route(...)
        "requires_auth",    // bare decorator @requires_auth
    ] {
        assert!(
            call_edges.iter().any(|r| r.dst_name == *expected),
            "fixture should produce a Calls edge to '{}', got {:?}",
            expected,
            call_edges.iter().map(|r| &r.dst_name).collect::<Vec<_>>()
        );
    }

    // Spot-check source attribution for representative shapes.
    assert!(
        call_edges
            .iter()
            .any(|r| r.src_name == "plain" && r.dst_name == "handler"),
        "expected plain -> handler"
    );
    assert!(
        call_edges
            .iter()
            .any(|r| r.src_name == "Service.process" && r.dst_name == "save"),
        "expected Service.process -> save (from self.store.save)"
    );
    assert!(
        call_edges
            .iter()
            .any(|r| r.src_name == "home" && r.dst_name == "route"),
        "expected home -> route (from the @app.route decorator)"
    );
}
