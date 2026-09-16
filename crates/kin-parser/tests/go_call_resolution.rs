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

/// The 0-based rows of the lines that satisfy `matches`, read off the fixture
/// source so editing the fixture cannot leave the expectation behind.
fn rows_where(source: &str, matches: impl Fn(&str) -> bool) -> Vec<u32> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| matches(line))
        .map(|(row, _)| row as u32)
        .collect()
}

/// The 0-based rows a relation's site names, sorted.
fn site_rows(rels: &[ExtractedRelation], kind: RelationKind, dst: &str, src: &str) -> Vec<u32> {
    let mut rows: Vec<u32> = rels
        .iter()
        .filter(|r| r.kind == kind && r.dst_name == dst && r.src_name == src)
        .map(|r| {
            r.site
                .as_ref()
                .unwrap_or_else(|| panic!("{kind:?} edge {src} -> {dst} carries no site: {r:?}"))
                .start_line
        })
        .collect();
    rows.sort_unstable();
    rows
}

/// Every Go call and value read names the position its syntax sits at, and two
/// reads of one name keep two positions.
///
/// The adapter emitted all of them with `site: None`, so the linker had no
/// position to put on the relation's evidence and every surface that reports
/// reference lines reported the edge as having no evidence span instead. The
/// per-context dedup then kept only the first read of a name, so even a site
/// recorded later could not have described the others.
#[test]
fn calls_and_value_reads_carry_the_position_they_were_read_at() {
    // 1 package, 2 blank, 3 var, 4 blank, 5 func caller, 6 call, 7 call,
    // 8 read, 9 read, 10 close, 11 blank, 12 func work.
    let source = "package main\n\
                  \n\
                  var limit = 1\n\
                  \n\
                  func caller() int {\n\
                  \x20   work()\n\
                  \x20   work()\n\
                  \x20   first := limit\n\
                  \x20   return first + limit\n\
                  }\n\
                  \n\
                  func work() {}\n";
    let rels = parse_and_extract(source);

    // The two calls, which are written on two lines so a site list reporting
    // one of them is distinguishable from one reporting both. `func work() {}`
    // is excluded by the exact match on the trimmed line, so the declaration
    // cannot stand in for a call site.
    let call_rows = rows_where(source, |line| line.trim() == "work()");
    assert_eq!(call_rows.len(), 2, "the fixture writes two calls");
    assert_eq!(
        site_rows(&rels, RelationKind::Calls, "work", "caller"),
        call_rows,
        "each Calls edge must name the call expression it came from: {rels:?}"
    );

    // The two reads of the package-level variable. Its declaration is excluded,
    // so a site copied from the declaration would not match either.
    let read_rows = rows_where(source, |line| {
        line.contains("limit") && !line.trim_start().starts_with("var ")
    });
    assert_eq!(read_rows.len(), 2, "the fixture writes two reads");
    assert_eq!(
        site_rows(&rels, RelationKind::References, "limit", "caller"),
        read_rows,
        "a name read twice in one body must contribute both positions: {rels:?}"
    );

    // No edge of a kind that describes a position may arrive without one.
    for rel in &rels {
        if matches!(
            rel.kind,
            RelationKind::Calls
                | RelationKind::References
                | RelationKind::SendsMessage
                | RelationKind::Spawns
        ) {
            assert!(
                rel.site.is_some(),
                "{:?} edge must carry a site: {rel:?}",
                rel.kind
            );
        }
    }
}

/// The same claim over the checked-in Go fixture, so a shape this file does not
/// spell out cannot reintroduce a siteless edge.
#[test]
fn fixture_calls_all_carry_a_site() {
    let source = load_fixture();
    let rels = parse_and_extract(&source);
    let calls: Vec<&ExtractedRelation> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect();
    assert!(!calls.is_empty(), "the fixture must produce Calls edges");
    let siteless: Vec<&&ExtractedRelation> = calls.iter().filter(|c| c.site.is_none()).collect();
    assert!(
        siteless.is_empty(),
        "every Calls edge must name its call expression, these do not: {siteless:?}"
    );
}
