// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A macro use names the line it is written on.
//!
//! `UsesMacro` is the edge `kin refs` answers with when the thing being asked
//! about is a macro, and it carried no position at all: every row came back
//! with no evidence span while the identifier the adapter read was right there.
//! Call edges were fixed first because they are the common case; these are the
//! same defect on the edge kind beside them.

use kin_model::{FilePathId, RelationKind};
use kin_parser::{CAdapter, CppAdapter, ExtractedRelation, LanguageAdapter};

fn extract(adapter: &dyn LanguageAdapter, path: &str, source: &str) -> Vec<ExtractedRelation> {
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    adapter
        .extract(&tree, bytes, &FilePathId::new(path))
        .expect("extract should succeed")
        .relations
}

/// The 0-based rows the matching macro-use edges' sites name, sorted, with the
/// text each site covers beside it so a span that names the wrong bytes fails
/// rather than a span that merely names a plausible row.
fn macro_use_sites<'a>(
    rels: &[ExtractedRelation],
    source: &'a str,
    dst: &str,
    src: &str,
) -> Vec<(u32, &'a str)> {
    let mut sites: Vec<(u32, &str)> = rels
        .iter()
        .filter(|r| r.kind == RelationKind::UsesMacro && r.dst_name == dst && r.src_name == src)
        .map(|r| {
            let site = r
                .site
                .as_ref()
                .unwrap_or_else(|| panic!("macro use {src} -> {dst} carries no site: {r:?}"));
            (site.start_line, &source[site.start_byte..site.end_byte])
        })
        .collect();
    sites.sort_unstable();
    sites
}

/// A C macro read twice in one function names both positions.
#[test]
fn c_macro_uses_name_the_identifier_they_were_read_at() {
    // 0 define, 1 blank, 2 int run, 3 first use, 4 blank, 5 second use, 6 close.
    let source = "#define LIMIT 10\n\
                  \n\
                  int run(void) {\n\
                  \x20   int first = LIMIT;\n\
                  \n\
                  \x20   return first + LIMIT;\n\
                  }\n";
    let rels = extract(&CAdapter, "limits.c", source);
    assert_eq!(
        macro_use_sites(&rels, source, "LIMIT", "run"),
        vec![(3, "LIMIT"), (5, "LIMIT")],
        "each use names the identifier it was read at: {rels:?}"
    );
}

/// A C++ macro read twice in one function names both positions.
#[test]
fn cpp_macro_uses_name_the_identifier_they_were_read_at() {
    // 0 define, 1 blank, 2 int run, 3 first use, 4 blank, 5 second use,
    // 6 close.
    let source = "#define LIMIT 10\n\
                  \n\
                  int run() {\n\
                  \x20   int first = LIMIT;\n\
                  \n\
                  \x20   return first + LIMIT;\n\
                  }\n";
    let rels = extract(&CppAdapter, "limits.cpp", source);
    assert_eq!(
        macro_use_sites(&rels, source, "LIMIT", "run"),
        vec![(3, "LIMIT"), (5, "LIMIT")],
        "each use names the identifier it was read at: {rels:?}"
    );
}

/// A C++ macro used INSIDE another macro's body names the identifier, not the
/// whole replacement list.
///
/// tree-sitter leaves a replacement list as one opaque node, so this is the one
/// use with no node of its own: its extent is derived from the value node's
/// start and the text before it. The span therefore has to be checked against
/// the bytes it covers, not only against its row, which is what would catch a
/// site that pointed at the whole body.
#[test]
fn a_cpp_macro_used_inside_a_macro_body_names_the_identifier() {
    // 0 define INNER, 1 blank, 2 define OUTER, whose body uses INNER.
    let source = "#define INNER 1\n\
                  \n\
                  #define OUTER (INNER + INNER)\n";
    let rels = extract(&CppAdapter, "macros.cpp", source);
    assert_eq!(
        macro_use_sites(&rels, source, "INNER", "OUTER"),
        vec![(2, "INNER")],
        "the site must cover the identifier inside the replacement list: {rels:?}"
    );
}
