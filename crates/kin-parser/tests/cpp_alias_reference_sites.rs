// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A C++ type alias names where it read the type it aliases.
//!
//! The alias's `References` edges carried no position, so a reference row on a
//! type came back with no evidence span. The names come from two places and
//! only one of them has nodes: a node walk over the declaration, and a text
//! pass that lexes the alias's own source for names the walk does not reach. A
//! name the walk read carries the bytes it read. A name only the text pass
//! produced stays spanless, because pointing at the whole declaration would be
//! a wrong line rather than a missing one.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{CppAdapter, ExtractedRelation, LanguageAdapter};

fn extract(source: &str) -> Vec<ExtractedRelation> {
    let adapter = CppAdapter;
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    adapter
        .extract(&tree, bytes, &FilePathId::new("alias.cpp"))
        .expect("extract should succeed")
        .relations
}

fn reference_site<'a>(
    rels: &[ExtractedRelation],
    source: &'a str,
    dst: &str,
) -> Option<(u32, &'a str)> {
    rels.iter()
        .filter(|r| r.kind == RelationKind::References && r.dst_name == dst)
        .find_map(|r| {
            r.site
                .as_ref()
                .map(|site| (site.start_line, &source[site.start_byte..site.end_byte]))
        })
}

/// The alias's reference to a plain type names the identifier it read.
#[test]
fn an_alias_names_the_type_identifier_it_read() {
    // 0 class, 1 blank, 2 using.
    let source = "class Widget {};\n\
                  \n\
                  using Alias = Widget;\n";
    let rels = extract(source);
    assert_eq!(
        reference_site(&rels, source, "Widget"),
        Some((2, "Widget")),
        "the site must cover the type name as written: {rels:?}"
    );
}

/// A templated alias still names a position, on the alias's own line and over
/// bytes that mention the type.
///
/// This one is deliberately weaker than the test above. tree-sitter gives the
/// name and the argument list different shapes depending on how the type is
/// written, so pinning the exact extent here would pin the grammar rather than
/// the property: what a reference row needs is a line inside the declaration
/// that really mentions the type.
#[test]
fn a_templated_alias_still_names_a_position_over_the_type_it_read() {
    // 0 class, 1 blank, 2 using.
    let source = "template <class T> class Holder {};\n\
                  \n\
                  using Held = Holder<int>;\n";
    let rels = extract(source);
    let referenced: Vec<&ExtractedRelation> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::References && r.src_name == "Held")
        .collect();
    assert!(
        !referenced.is_empty(),
        "the alias must reference the type it holds: {rels:?}"
    );
    for relation in &referenced {
        let site = relation.site.as_ref().unwrap_or_else(|| {
            panic!("the node walk read this name, so it has a site: {relation:?}")
        });
        assert_eq!(
            site.start_line, 2,
            "the site sits on the alias: {relation:?}"
        );
        assert!(
            source[site.start_byte..site.end_byte].contains(&relation.dst_name),
            "the site must cover bytes that mention the type: {relation:?}"
        );
    }
}
