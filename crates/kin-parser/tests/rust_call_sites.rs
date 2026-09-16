// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every Rust call edge names the position its syntax sits at.
//!
//! The adapter built every `Calls` edge with `site: None`, so the linker had no
//! position to put on the relation's evidence and every surface that reports
//! reference lines reported the edge as having no evidence span instead. Kin is
//! written in Rust, so that is the language every demo and every agent session
//! run against Kin's own tree was reading.
//!
//! Two shapes, because the adapter extracts calls two ways. A `call_expression`
//! is a node, and its site is that node. A call written inside a macro body is
//! not: tree-sitter leaves a macro's arguments as a flat token run, so the
//! adapter reconstructs the call from sibling tokens and the site has to be
//! built from the run's first and last token.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{ExtractedRelation, LanguageAdapter, RustAdapter};

fn parse_and_extract(source: &str) -> Vec<ExtractedRelation> {
    let adapter = RustAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    adapter
        .extract(&tree, bytes, &FilePathId::new("test/calls.rs"))
        .expect("extract should succeed")
        .relations
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

/// The 0-based rows the matching relations' sites name, sorted.
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

/// A call written as a call expression names the expression's own position, and
/// two calls of one name keep two positions.
#[test]
fn call_expressions_carry_the_position_they_were_written_at() {
    // 1 fn caller, 2 call, 3 blank, 4 call, 5 close, 6 blank, 7 fn work.
    let source = "pub fn caller() -> u32 {\n\
                  \x20   let first = work();\n\
                  \n\
                  \x20   first + work()\n\
                  }\n\
                  \n\
                  pub fn work() -> u32 { 1 }\n";
    let rels = parse_and_extract(source);

    // The two calls, on two lines, so a site list reporting one of them is
    // distinguishable from one reporting both. The declaration line is excluded
    // by requiring the call to be preceded by something other than `fn `, so a
    // site copied from the definition would not match.
    let call_rows = rows_where(source, |line| {
        line.contains("work()") && !line.contains("fn work")
    });
    assert_eq!(call_rows.len(), 2, "the fixture writes two calls");
    assert_eq!(
        site_rows(&rels, RelationKind::Calls, "work", "caller"),
        call_rows,
        "each Calls edge must name the call expression it came from: {rels:?}"
    );
}

/// A call written inside a macro body names the token run it was read from.
///
/// The adapter reconstructs these from sibling tokens because tree-sitter does
/// not parse a macro's arguments into expressions, so this is the one call
/// shape whose site cannot come from a single node.
#[test]
fn calls_inside_a_macro_body_carry_the_token_run_they_were_read_from() {
    // 1 fn caller, 2 macro call, 3 close, 4 blank, 5 fn total.
    let source = "pub fn caller() -> String {\n\
                  \x20   format!(\"{}\", total(2))\n\
                  }\n\
                  \n\
                  pub fn total(value: u32) -> u32 { value }\n";
    let rels = parse_and_extract(source);

    let macro_rows = rows_where(source, |line| line.contains("format!"));
    assert_eq!(macro_rows.len(), 1, "the fixture writes one macro call");
    assert_eq!(
        site_rows(&rels, RelationKind::Calls, "total", "caller"),
        macro_rows,
        "a call reconstructed from a macro's token run must still name its \
         position: {rels:?}"
    );

    let site = rels
        .iter()
        .find(|r| r.kind == RelationKind::Calls && r.dst_name == "total")
        .and_then(|r| r.site.as_ref())
        .expect("the macro-body call carries a site");
    assert_eq!(
        &source[site.start_byte..site.end_byte],
        "total(2)",
        "the site must cover the call as written, from its first token through \
         the close of its argument group"
    );
}

/// No Rust call edge arrives without a site, over a body that mixes the shapes
/// this file spells out with the ones it does not.
#[test]
fn every_call_edge_carries_a_site() {
    let source = "pub struct Widget;\n\
                  \n\
                  impl Widget {\n\
                  \x20   pub fn render(&self) -> u32 {\n\
                  \x20       let base = helper();\n\
                  \x20       let scaled = self.scale(base);\n\
                  \x20       println!(\"{}\", helper());\n\
                  \x20       scaled + crate::billing::total(base)\n\
                  \x20   }\n\
                  \n\
                  \x20   fn scale(&self, value: u32) -> u32 { value * 2 }\n\
                  }\n\
                  \n\
                  pub fn helper() -> u32 { 1 }\n";
    let rels = parse_and_extract(source);
    let calls: Vec<&ExtractedRelation> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::Calls)
        .collect();
    assert!(calls.len() >= 4, "the fixture must produce calls: {rels:?}");
    let siteless: Vec<&&ExtractedRelation> = calls.iter().filter(|c| c.site.is_none()).collect();
    assert!(
        siteless.is_empty(),
        "every Calls edge must name the syntax it came from, these do not: {siteless:?}"
    );
    for call in &calls {
        let site = call.site.as_ref().expect("checked above");
        assert!(
            site.end_byte > site.start_byte && site.end_byte <= source.len(),
            "a site must name a non-empty range inside the file: {call:?}"
        );
    }
}
