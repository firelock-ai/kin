// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression tests for Go call-resolution.
//!
//! Verifies that `selector_expression` callees like `fmt.Println(x)` and
//! `s.Run()` emit Calls edges keyed on the *simple* rightmost name
//! (`Println`, `Run`) rather than the full dotted form. Dotted dst_names
//! break name-based edge resolution elsewhere in the graph.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{ExtractedRelation, GoAdapter, LanguageAdapter};

fn parse_and_extract(source: &str) -> Vec<ExtractedRelation> {
    let adapter = GoAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    let file_id = FilePathId("test/calls.go".to_string());
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("extract should succeed");
    output.relations
}

fn calls_named<'a>(rels: &'a [ExtractedRelation], name: &str) -> Vec<&'a ExtractedRelation> {
    rels.iter()
        .filter(|r| r.kind == RelationKind::Calls && r.dst_name == name)
        .collect()
}

fn load_fixture() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let path = workspace_root.join("tests/adapter-fixtures/go/calls.go");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e))
}

#[test]
fn plain_call_emits_simple_name() {
    let source = r#"
package main

func target() {}

func caller() {
    target()
}
"#;
    let rels = parse_and_extract(source);
    let hits = calls_named(&rels, "target");
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one Calls edge named 'target', got {} in {:?}",
        hits.len(),
        rels
    );
    assert_eq!(hits[0].src_name, "caller");
}

#[test]
fn package_call_emits_rightmost_name_with_import_source() {
    let source = r#"
package main

import "fmt"

func caller() {
    fmt.Println("hi")
}
"#;
    let rels = parse_and_extract(source);
    let hits = calls_named(&rels, "Println");
    assert_eq!(
        hits.len(),
        1,
        "expected simple-name edge 'Println' (not 'fmt.Println'), got {:?}",
        rels
    );
    assert_eq!(
        hits[0].import_source.as_deref(),
        Some("fmt"),
        "package-qualified call should carry its import path as import_source"
    );
    assert!(
        !rels.iter().any(|r| r.dst_name == "fmt.Println"),
        "dotted form 'fmt.Println' must not appear as a dst_name"
    );
}

#[test]
fn receiver_method_call_emits_simple_name() {
    let source = r#"
package main

type Server struct{}

func (s *Server) Run() {}

func driver() {
    s := &Server{}
    s.Run()
}
"#;
    let rels = parse_and_extract(source);
    let hits = calls_named(&rels, "Run");
    assert!(
        !hits.is_empty(),
        "expected at least one Calls edge named 'Run', got {:?}",
        rels
    );
    assert!(
        hits.iter().any(|r| r.src_name == "driver"),
        "driver() should call Run"
    );
}

#[test]
fn chained_call_emits_each_rightmost_name() {
    let source = r#"
package main

type T struct{}

func (t *T) B() *T { return t }

func (t *T) C() {}

func make() *T { return &T{} }

func driver() {
    make().B().C()
}
"#;
    let rels = parse_and_extract(source);
    assert!(
        !calls_named(&rels, "B").is_empty(),
        "expected 'B' in chain, got {:?}",
        rels
    );
    assert!(
        !calls_named(&rels, "C").is_empty(),
        "expected 'C' in chain, got {:?}",
        rels
    );
    // Regression: no dotted forms, even from a chain where the inner
    // operand is itself a call_expression.
    for rel in &rels {
        if rel.kind == RelationKind::Calls {
            assert!(
                !rel.dst_name.contains('.'),
                "Calls dst_name must not contain '.', saw {:?}",
                rel
            );
        }
    }
}

#[test]
fn fixture_calls_produces_simple_names_only() {
    let source = load_fixture();
    let rels = parse_and_extract(&source);

    let calls: Vec<&ExtractedRelation> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect();

    assert!(
        !calls.iter().any(|c| c.dst_name.contains('.')),
        "regression: Calls dst_name must never contain '.' — saw {:?}",
        calls
            .iter()
            .filter(|c| c.dst_name.contains('.'))
            .collect::<Vec<_>>()
    );

    for expected in &["plain", "Println", "Run", "B", "C"] {
        assert!(
            calls.iter().any(|c| c.dst_name == *expected),
            "fixture should produce Calls edge with dst_name '{}' — got {:?}",
            expected,
            calls.iter().map(|c| &c.dst_name).collect::<Vec<_>>()
        );
    }

    let println = calls
        .iter()
        .find(|c| c.dst_name == "Println")
        .expect("Println edge present");
    assert_eq!(
        println.import_source.as_deref(),
        Some("fmt"),
        "fmt.Println should carry import_source 'fmt'"
    );
}
