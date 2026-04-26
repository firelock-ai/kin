// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression tests for the kotlin + swift dotted-callee fix.
//!
//! Before the fix, `obj.method()` produced a Calls edge with
//! `dst_name = "obj.method"`. After, it must be `"method"` so cross-file
//! resolution matches the simple name of the target function.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{ExtractedRelation, KotlinAdapter, LanguageAdapter, SwiftAdapter};

fn kotlin_calls(source: &[u8]) -> Vec<ExtractedRelation> {
    let adapter = KotlinAdapter;
    let tree = adapter.parse(source).unwrap();
    let file_id = FilePathId::new("fixture.kt");
    let output = adapter.extract(&tree, source, &file_id).unwrap();
    output
        .relations
        .into_iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect()
}

fn swift_calls(source: &[u8]) -> Vec<ExtractedRelation> {
    let adapter = SwiftAdapter;
    let tree = adapter.parse(source).unwrap();
    let file_id = FilePathId::new("fixture.swift");
    let output = adapter.extract(&tree, source, &file_id).unwrap();
    output
        .relations
        .into_iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect()
}

const KOTLIN_FIXTURE: &[u8] =
    include_bytes!("../../../tests/adapter-fixtures/kotlin/calls.kt");

const SWIFT_FIXTURE: &[u8] =
    include_bytes!("../../../tests/adapter-fixtures/swift/calls.swift");

#[test]
fn kotlin_plain_call_emits_simple_name() {
    let calls = kotlin_calls(KOTLIN_FIXTURE);
    assert!(
        calls
            .iter()
            .any(|c| c.src_name == "Service.plainCall" && c.dst_name == "helper"),
        "expected Service.plainCall -> helper, got {:?}",
        calls
    );
}

#[test]
fn kotlin_member_call_emits_trailing_identifier() {
    let calls = kotlin_calls(KOTLIN_FIXTURE);
    assert!(
        calls
            .iter()
            .any(|c| c.src_name == "Service.memberCall" && c.dst_name == "run"),
        "expected Service.memberCall -> run, got {:?}",
        calls
    );
}

#[test]
fn kotlin_chained_call_emits_both_simple_names() {
    let calls = kotlin_calls(KOTLIN_FIXTURE);
    let dst_names: Vec<&str> = calls
        .iter()
        .filter(|c| c.src_name == "Service.chainedCall")
        .map(|c| c.dst_name.as_str())
        .collect();
    assert!(
        dst_names.contains(&"adapter"),
        "expected chainedCall -> adapter, got {:?}",
        dst_names
    );
    assert!(
        dst_names.contains(&"execute"),
        "expected chainedCall -> execute, got {:?}",
        dst_names
    );
}

#[test]
fn kotlin_safe_call_emits_simple_name() {
    let calls = kotlin_calls(KOTLIN_FIXTURE);
    assert!(
        calls
            .iter()
            .any(|c| c.src_name == "Service.safeCall" && c.dst_name == "run"),
        "expected Service.safeCall -> run for `maybe?.run()`, got {:?}",
        calls
    );
}

#[test]
fn kotlin_call_dst_names_never_contain_dots() {
    let calls = kotlin_calls(KOTLIN_FIXTURE);
    let dotted: Vec<&str> = calls
        .iter()
        .map(|c| c.dst_name.as_str())
        .filter(|n| n.contains('.'))
        .collect();
    assert!(
        dotted.is_empty(),
        "Calls dst_names must be simple identifiers, but got dotted: {:?}",
        dotted
    );
}

#[test]
fn swift_plain_call_emits_simple_name() {
    let calls = swift_calls(SWIFT_FIXTURE);
    assert!(
        calls
            .iter()
            .any(|c| c.src_name == "Service.plainCall" && c.dst_name == "helper"),
        "expected Service.plainCall -> helper, got {:?}",
        calls
    );
}

#[test]
fn swift_member_call_emits_trailing_identifier() {
    let calls = swift_calls(SWIFT_FIXTURE);
    assert!(
        calls
            .iter()
            .any(|c| c.src_name == "Service.memberCall" && c.dst_name == "run"),
        "expected Service.memberCall -> run, got {:?}",
        calls
    );
}

#[test]
fn swift_chained_call_emits_both_simple_names() {
    let calls = swift_calls(SWIFT_FIXTURE);
    let dst_names: Vec<&str> = calls
        .iter()
        .filter(|c| c.src_name == "Service.chainedCall")
        .map(|c| c.dst_name.as_str())
        .collect();
    assert!(
        dst_names.contains(&"adapter"),
        "expected chainedCall -> adapter, got {:?}",
        dst_names
    );
    assert!(
        dst_names.contains(&"execute"),
        "expected chainedCall -> execute, got {:?}",
        dst_names
    );
}

#[test]
fn swift_self_call_strips_self_prefix() {
    let calls = swift_calls(SWIFT_FIXTURE);
    assert!(
        calls
            .iter()
            .any(|c| c.src_name == "Service.selfCall" && c.dst_name == "helper"),
        "expected Service.selfCall -> helper (no `self.` prefix), got {:?}",
        calls
    );
}

#[test]
fn swift_call_dst_names_never_contain_dots() {
    let calls = swift_calls(SWIFT_FIXTURE);
    let dotted: Vec<&str> = calls
        .iter()
        .map(|c| c.dst_name.as_str())
        .filter(|n| n.contains('.'))
        .collect();
    assert!(
        dotted.is_empty(),
        "Calls dst_names must be simple identifiers, but got dotted: {:?}",
        dotted
    );
}
