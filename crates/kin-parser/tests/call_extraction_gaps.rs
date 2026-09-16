// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Calls the adapters used to drop on the floor.
//!
//! These are not site gaps. The edge was never built, so no span could describe
//! it and no reference row could report it: `kin refs` answered that nobody
//! called a function the source calls, and the answer looked clean. Both were
//! found by a reference-line fixture that came back with one site where its
//! source writes two, and both fixtures in that suite were written around the
//! gap until this closed it.
//!
//! Each case asserts the edge exists AND names its position, because an edge
//! recorded without a site is the defect the reference-line suite exists to
//! catch and this file must not reintroduce it.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{ExtractedRelation, LanguageAdapter, RubyAdapter, SwiftAdapter};

fn extract(adapter: &dyn LanguageAdapter, path: &str, source: &str) -> Vec<ExtractedRelation> {
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    adapter
        .extract(&tree, bytes, &FilePathId::new(path))
        .expect("extract should succeed")
        .relations
}

/// The 0-based rows the matching call edges' sites name, sorted.
fn call_site_rows(rels: &[ExtractedRelation], dst: &str, src: &str) -> Vec<u32> {
    let mut rows: Vec<u32> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.dst_name == dst && r.src_name == src)
        .map(|r| {
            r.site
                .as_ref()
                .unwrap_or_else(|| panic!("call edge {src} -> {dst} carries no site: {r:?}"))
                .start_line
        })
        .collect();
    rows.sort_unstable();
    rows
}

/// A Ruby call on the right of an assignment is a call.
///
/// `extract_ruby_node`'s assignment arm read the left side for a constant and
/// returned without walking what it assigns, so `first = compute()` produced no
/// edge at all while a bare `compute()` on its own line produced one. Every
/// other arm of that walk recurses.
#[test]
fn a_ruby_call_on_the_right_of_an_assignment_is_extracted() {
    // 1 class, 2 def run, 3 assignment call, 4 operator assignment call,
    // 5 bare call, 6 end, 7 end.
    let source = "class Caller\n\
                  \x20 def run\n\
                  \x20   first = compute()\n\
                  \x20   first += compute()\n\
                  \x20   compute()\n\
                  \x20 end\n\
                  end\n";
    let rels = extract(&RubyAdapter, "caller.rb", source);
    assert_eq!(
        call_site_rows(&rels, "compute", "Caller.run"),
        vec![2, 3, 4],
        "all three calls are calls, and each names the line it is written on: {rels:?}"
    );
}

/// A Ruby constant assignment still yields its entity while the walk descends.
///
/// The arm's own job is to record `LIMIT = 5` as a constant owned by its
/// container. Making it recurse must not cost that.
#[test]
fn a_ruby_constant_assignment_keeps_its_entity() {
    let source = "class Caller\n\
                  \x20 LIMIT = 5\n\
                  end\n";
    let adapter = RubyAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    let output = adapter
        .extract(&tree, bytes, &FilePathId::new("caller.rb"))
        .expect("extract should succeed");
    assert!(
        output
            .entities
            .iter()
            .any(|entity| entity.name == "Caller.LIMIT"),
        "the constant must survive the walk: {:?}",
        output.entities
    );
}

/// A Swift call written inside a `return` is a call.
///
/// A reference-line fixture whose second call was `return first + compute()`
/// reported only the line of the first, so the return's call reached no edge.
#[test]
fn a_swift_call_inside_a_return_is_extracted() {
    // 1 func run, 2 binding call, 3 return call, 4 close.
    let source = "func run() -> Int {\n\
                  \x20   let first = compute()\n\
                  \x20   return first + compute()\n\
                  }\n";
    let rels = extract(&SwiftAdapter, "caller.swift", source);
    assert_eq!(
        call_site_rows(&rels, "compute", "run"),
        vec![1, 2],
        "both calls are calls, and each names the line it is written on: {rels:?}"
    );
}
