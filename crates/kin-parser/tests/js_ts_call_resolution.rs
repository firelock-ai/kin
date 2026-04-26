// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression tests for the JS/TS dotted-callee bug.
//!
//! Prior behavior: `a.b()` emitted a `Calls` edge with `dst_name = "a.b"`,
//! which never matched any entity in the graph. These tests assert the
//! fixed behavior — `dst_name` is the simple method name ("b").

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
fn js_this_prefix_stripped_on_identifier_callee() {
    // `this.sayHi()` is a member_expression (object=this, property=sayHi) and
    // resolves to `sayHi`. This test also guards the identifier-branch
    // `strip_prefix("this.")` path in case the grammar surfaces the whole
    // thing as an identifier.
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let names = dst_names(&output);
    assert!(
        names.contains(&"sayHi"),
        "`this.sayHi()` should emit call to `sayHi`, got {:?}",
        names
    );
}

#[test]
fn js_no_dotted_dst_names() {
    let output = parse_fixture(&JavaScriptAdapter, "javascript", "calls.js");
    let dotted: Vec<&ExtractedRelation> = calls(&output)
        .into_iter()
        .filter(|r| r.dst_name.contains('.'))
        .collect();
    assert!(
        dotted.is_empty(),
        "no Calls edge should have a dotted dst_name; found {:?}",
        dotted.iter().map(|r| &r.dst_name).collect::<Vec<_>>()
    );
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
fn ts_this_prefix_stripped_on_identifier_callee() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let names = dst_names(&output);
    assert!(
        names.contains(&"sayHi"),
        "`this.sayHi()` should emit call to `sayHi`, got {:?}",
        names
    );
}

#[test]
fn ts_no_dotted_dst_names() {
    let output = parse_fixture(&TypeScriptAdapter, "typescript", "calls.ts");
    let dotted: Vec<&ExtractedRelation> = calls(&output)
        .into_iter()
        .filter(|r| r.dst_name.contains('.'))
        .collect();
    assert!(
        dotted.is_empty(),
        "no Calls edge should have a dotted dst_name; found {:?}",
        dotted.iter().map(|r| &r.dst_name).collect::<Vec<_>>()
    );
}
