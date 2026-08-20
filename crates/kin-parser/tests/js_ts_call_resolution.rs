// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression tests for the JS/TS dotted-callee bug, and for the one dotted
//! form that is deliberately kept.
//!
//! Prior behavior: `a.b()` emitted a `Calls` edge with `dst_name = "a.b"`,
//! raw source text that never matched any entity in the graph. `dst_name` is
//! the simple method name ("b") for every receiver whose type the syntax does
//! not settle, which is what these tests pin.
//!
//! The exception is a call through the method's OWN owner: `this.m()`, or
//! `Owner.m()` written inside `Owner`. That one is recorded as `Owner.m`,
//! matching how the Python adapter pins `self.m()` to its class. It is a
//! resolved receiver rather than raw source text, and it is load-bearing:
//! every linker tier that matches a bare method leaf considers cross-file
//! candidates only, so a bare `m` can never reach a same-file `Owner.m`.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{
    ExtractedRelation, JavaScriptAdapter, LanguageAdapter, ParseOutput, TypeScriptAdapter,
};

fn fixture_path(lang: &str, file: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    format!(
        "{}/tests/adapter-fixtures/{}/{}",
        workspace_root.display(),
        lang,
        file
    )
}

fn parse_fixture(adapter: &dyn LanguageAdapter, lang: &str, file: &str) -> ParseOutput {
    let path = fixture_path(lang, file);
    let source = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let tree = adapter.parse(&source).expect("parse");
    adapter
        .extract(&tree, &source, &FilePathId::new("test/calls"))
        .expect("extract")
}

fn calls(output: &ParseOutput) -> Vec<&ExtractedRelation> {
    output
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect()
}

fn dst_names(output: &ParseOutput) -> Vec<&str> {
    calls(output).iter().map(|r| r.dst_name.as_str()).collect()
}

// ---- JavaScript ----

#[test]
fn js_plain_call_resolves_identifier() {
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    assert!(
        dst_names(&output).contains(&"bare"),
        "plain() should produce a Calls edge to `bare`, got {:?}",
        dst_names(&output)
    );
}

#[test]
fn js_member_call_resolves_to_property_name() {
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let names = dst_names(&output);
    assert!(
        names.contains(&"log"),
        "member() should produce a Calls edge to `log`, got {:?}",
        names
    );
}

#[test]
fn js_chained_call_emits_each_rightmost_identifier() {
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let names = dst_names(&output);
    assert!(
        names.contains(&"b") && names.contains(&"c"),
        "chained `a.b().c()` should emit calls to both `b` and `c`, got {:?}",
        names
    );
}

#[test]
fn js_optional_chain_resolves_to_property_name() {
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let names = dst_names(&output);
    assert!(
        names.contains(&"maybe"),
        "optional chain `obj?.maybe()` should emit call to `maybe`, got {:?}",
        names
    );
}

#[test]
fn js_this_call_is_pinned_to_its_own_class() {
    // `this.sayHi()` inside `Greeter.greet` names a method of `Greeter`, and
    // the syntax settles that: `this` is the receiver the method was called
    // on. Recording it as `Greeter.sayHi` is what lets the linker's same-file
    // tier bind it, since every bare-leaf tier skips the calling file.
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let names = dst_names(&output);
    assert!(
        names.contains(&"Greeter.sayHi"),
        "`this.sayHi()` in `Greeter` should emit call to `Greeter.sayHi`, got {:?}",
        names
    );
    // A receiver-less call in the same body is a free function and stays bare.
    assert!(
        names.contains(&"helperCall"),
        "`helperCall()` should stay a bare name, got {:?}",
        names
    );
}

#[test]
fn js_dotted_dst_names_only_ever_name_the_enclosing_owner() {
    // The bug this file was written for: emitting raw source text like
    // `a.b` or `console.log` as a callee, which matches no entity. That is
    // still forbidden. A dotted callee is admissible only when its owner half
    // is the enclosing owner, which is a resolved receiver rather than text.
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let dotted: Vec<&ExtractedRelation> = calls(&output)
        .into_iter()
        .filter(|r| r.dst_name.contains('.'))
        .collect();
    for rel in &dotted {
        let owner = rel.dst_name.split('.').next().unwrap_or_default();
        assert_eq!(
            Some(owner),
            rel.src_name.split('.').next(),
            "dotted callee {:?} must be owned by the same entity as its caller {:?}",
            rel.dst_name,
            rel.src_name
        );
    }
    let names = dst_names(&output);
    for bare in ["log", "b", "c", "maybe"] {
        assert!(
            names.contains(&bare),
            "foreign receiver call should stay bare `{bare}`, got {names:?}"
        );
    }
}

// ---- TypeScript ----

#[test]
fn ts_plain_call_resolves_identifier() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    assert!(
        dst_names(&output).contains(&"bare"),
        "plain() should produce a Calls edge to `bare`, got {:?}",
        dst_names(&output)
    );
}

#[test]
fn ts_member_call_resolves_to_property_name() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let names = dst_names(&output);
    assert!(
        names.contains(&"log"),
        "member() should produce a Calls edge to `log`, got {:?}",
        names
    );
}

#[test]
fn ts_chained_call_emits_each_rightmost_identifier() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let names = dst_names(&output);
    assert!(
        names.contains(&"b") && names.contains(&"c"),
        "chained `a.b().c()` should emit calls to both `b` and `c`, got {:?}",
        names
    );
}

#[test]
fn ts_optional_chain_resolves_to_property_name() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let names = dst_names(&output);
    assert!(
        names.contains(&"maybe"),
        "optional chain `obj?.maybe()` should emit call to `maybe`, got {:?}",
        names
    );
}

#[test]
fn ts_this_call_is_pinned_to_its_own_class() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let names = dst_names(&output);
    assert!(
        names.contains(&"Greeter.sayHi"),
        "`this.sayHi()` in `Greeter` should emit call to `Greeter.sayHi`, got {:?}",
        names
    );
    assert!(
        names.contains(&"helperCall"),
        "`helperCall()` should stay a bare name, got {:?}",
        names
    );
}

#[test]
fn ts_dotted_dst_names_only_ever_name_the_enclosing_owner() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let dotted: Vec<&ExtractedRelation> = calls(&output)
        .into_iter()
        .filter(|r| r.dst_name.contains('.'))
        .collect();
    for rel in &dotted {
        let owner = rel.dst_name.split('.').next().unwrap_or_default();
        assert_eq!(
            Some(owner),
            rel.src_name.split('.').next(),
            "dotted callee {:?} must be owned by the same entity as its caller {:?}",
            rel.dst_name,
            rel.src_name
        );
    }
    let names = dst_names(&output);
    for bare in ["log", "b", "c", "maybe"] {
        assert!(
            names.contains(&bare),
            "foreign receiver call should stay bare `{bare}`, got {names:?}"
        );
    }
}

// ---- Receivers ----
//
// A member call also records the expression it was written on. Without it the
// linker has only the bare leaf, and matching that leaf against every
// same-named symbol in the repository is what bound `JSON.stringify` to
// express's own `stringify` and `http.createServer` to a test's own
// `createServer`. The receiver is what separates a call through an imported
// module from a call through a value nothing here types.

fn receiver_for<'a>(output: &'a ParseOutput, dst: &str) -> Option<&'a str> {
    calls(output)
        .into_iter()
        .find(|r| r.dst_name == dst)
        .unwrap_or_else(|| panic!("no Calls edge to `{dst}` in {:?}", dst_names(output)))
        .receiver
        .as_deref()
}

fn receivers_for<'a>(output: &'a ParseOutput, dst: &str) -> Vec<Option<&'a str>> {
    calls(output)
        .into_iter()
        .filter(|r| r.dst_name == dst)
        .map(|r| r.receiver.as_deref())
        .collect()
}

#[test]
fn js_member_call_records_the_receiver_it_was_written_on() {
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    assert_eq!(
        receiver_for(&output, "log"),
        Some("console"),
        "`console.log(...)` must record `console` as its receiver"
    );
    assert_eq!(
        receiver_for(&output, "handle"),
        Some("this.router"),
        "`this.router.handle(...)` must record the whole property chain, \
         which is the only thing that says the destination is not here"
    );
    assert_eq!(
        receiver_for(&output, "b"),
        Some("a"),
        "`a.b()` must record `a` as its receiver"
    );
    assert_eq!(
        receiver_for(&output, "maybe"),
        Some("obj"),
        "an optional chain is still a member call and still has a receiver"
    );
}

#[test]
fn js_owner_folded_and_bare_calls_record_no_receiver() {
    // The owner is already in the callee name, so repeating it as a receiver
    // would make the linker skip the same-file tier that name exists to reach.
    // This is the same split the Python adapter makes for `self`/`cls`.
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    assert_eq!(
        receiver_for(&output, "Greeter.sayHi"),
        None,
        "`this.sayHi()` is recorded owner-qualified, so it carries no receiver"
    );
    assert_eq!(
        receiver_for(&output, "Application.own"),
        None,
        "`this.own()` is recorded owner-qualified, so it carries no receiver"
    );
    assert_eq!(
        receiver_for(&output, "helperCall"),
        None,
        "a bare call has no receiver to record"
    );
    assert_eq!(
        receiver_for(&output, "bare"),
        None,
        "a bare call has no receiver to record"
    );
}

#[test]
fn js_receiver_that_is_not_a_name_chain_is_declined() {
    // The field's consumers read it as a name: the linker splits it at the
    // first `.` and asks the file's imports about that root. A call, a
    // subscript or a parenthesized expression answers nothing, and recording
    // its raw text would put source formatting into an identifier position.
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    assert_eq!(
        receiver_for(&output, "c"),
        None,
        "`a.b().c()` is written on a call, which names no binding"
    );
    let run_receivers = receivers_for(&output, "run");
    assert_eq!(
        run_receivers.len(),
        2,
        "the fixture writes `run` on a subscript and on a call, got {run_receivers:?}"
    );
    assert!(
        run_receivers.iter().all(Option::is_none),
        "neither `deps[0]` nor `make()` names a binding, got {run_receivers:?}"
    );
}

#[test]
fn ts_member_calls_record_receivers_through_the_same_constructor() {
    // TypeScript has no call extractor of its own: `typescript.rs` imports
    // `extract_calls_from_context` from the JavaScript adapter. This pins that,
    // so a change made for JavaScript cannot silently leave TypeScript behind.
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    assert_eq!(
        receiver_for(&output, "log"),
        Some("console"),
        "`console.log(...)` must record `console` as its receiver"
    );
    assert_eq!(
        receiver_for(&output, "handle"),
        Some("this.router"),
        "`this.router.handle(...)` must record the whole property chain"
    );
    assert_eq!(
        receiver_for(&output, "Application.own"),
        None,
        "an owner-folded call carries no receiver in TypeScript either"
    );
    assert_eq!(
        receiver_for(&output, "c"),
        None,
        "`a.b().c()` is written on a call, which names no binding"
    );
}
