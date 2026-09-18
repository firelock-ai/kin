// SPDX-License-Identifier: MIT

//! The two constructs this fork exists for, and the behaviour it must not move.
//!
//! Everything under `grammar/` is generated, so a re-vendor that drops a patch
//! leaves no diff a reader would notice. These tests are that diff: each one
//! fails against unmodified tree-sitter-typescript 0.23.2 and passes here.
//!
//! The controls matter as much as the repairs. Patch 0001 confines itself to
//! object type member boundaries precisely so that a `<` on the next line keeps
//! continuing an expression everywhere else, and only a test of the untouched
//! cases can show the confinement held.

use tree_sitter::{Parser, Tree};

fn parse(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&kin_grammar_typescript::LANGUAGE_TYPESCRIPT.into())
        .expect("load the TypeScript grammar");
    parser.parse(source, None).expect("parse")
}

fn parse_tsx(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&kin_grammar_typescript::LANGUAGE_TSX.into())
        .expect("load the TSX grammar");
    parser.parse(source, None).expect("parse")
}

#[track_caller]
fn assert_clean(tree: &Tree, source: &str) {
    assert!(
        !tree.root_node().has_error(),
        "grammar rejected source the TypeScript compiler accepts:\n{source}\n{}",
        tree.root_node().to_sexp()
    );
}

/// The top-level named children, which is what an `ERROR` node takes away: it
/// swallows the declarations after it rather than stopping at the construct it
/// could not read.
fn top_level_kinds(tree: &Tree) -> Vec<String> {
    let mut cursor = tree.walk();
    tree.root_node()
        .named_children(&mut cursor)
        .map(|n| n.kind().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Patch 0001: a member not terminated by `;` or `,`, followed by a member
// beginning with `<`.
// ---------------------------------------------------------------------------

#[test]
fn interface_member_ends_before_a_generic_call_signature() {
    let source = "interface I {\n  p: string\n  <T>(): void\n}\n";
    assert_clean(&parse(source), source);
}

#[test]
fn an_object_type_literal_ends_a_member_the_same_way() {
    let source = "type I = {\n  p: string\n  <T>(): void\n}\n";
    assert_clean(&parse(source), source);
}

/// The damage this patch exists to stop, stated as what the tree looks like. On
/// this fixture unmodified 0.23.2 leaves a fourth top-level child, an `ERROR`,
/// and what that node covers is lost. How far it reaches is the file's business:
/// here it stops at the closing brace, on `honojs/hono`'s
/// `src/helper/factory/index.ts` it runs from line 26 to the end of all 375, and
/// on `src/types.ts` it covers the file from line 1 to line 2,779.
#[test]
fn a_member_boundary_leaves_no_error_node_behind() {
    let source = concat!(
        "interface I {\n",
        "  p: string\n",
        "  <T>(): void\n",
        "}\n",
        "export function after(): number {\n  return 1;\n}\n",
        "export class Later {}\n",
    );
    let tree = parse(source);
    assert_clean(&tree, source);
    assert_eq!(
        top_level_kinds(&tree),
        vec![
            "interface_declaration",
            "export_statement",
            "export_statement"
        ],
        "an ERROR node must not sit between the declarations"
    );
}

/// Every separator that already worked has to keep working, because the patch
/// adds a way for a member to end and removes none.
#[test]
fn the_separators_that_already_ended_a_member_still_do() {
    for source in [
        "interface I {\n  p: string;\n  <T>(): void\n}\n",
        "interface I {\n  p: string,\n  <T>(): void\n}\n",
        "interface I {\n  p: string\n  (): void\n}\n",
        "interface I {\n  p: string\n  m<T>(): void\n}\n",
        "interface I {\n  <T>(): void\n}\n",
        "interface I {\n  p: string\n  q: number\n}\n",
    ] {
        assert_clean(&parse(source), source);
    }
}

/// A union or intersection type written across lines still continues, because
/// the patch changed the `<` case and nothing else. Without this the same
/// reasoning applied to `|` would split `A | B` into two members.
#[test]
fn a_type_spanning_lines_still_continues() {
    let source = "interface I {\n  p: string\n    | number\n  q: A\n    & B\n}\n";
    assert_clean(&parse(source), source);
}

// ---------------------------------------------------------------------------
// Confinement. These are not constructs the patch repairs; they are constructs
// it must leave exactly as it found them. A `<` after a newline continues the
// line everywhere except between object type members, and the probe token is
// what keeps that true.
// ---------------------------------------------------------------------------

#[test]
fn a_less_than_still_continues_an_expression() {
    for source in [
        "const a = 1\nconst b = a\n< 2\n",
        "declare function f<T>(x: T): T\nconst r = f\n<number>(1)\n",
    ] {
        assert_clean(&parse(source), source);
    }
}

/// Outside an object type a `<` on the next line still reads as type arguments,
/// which is what unmodified 0.23.2 does. A scanner-wide change would have split
/// this into `type A = B` and a stray `<number>`, and it is the only thing the
/// cruder version of this patch got wrong.
#[test]
fn a_type_argument_list_on_the_next_line_is_untouched() {
    let source = "type B<T> = T\ntype A = B\n<number>\n";
    let tree = parse(source);
    assert_clean(&tree, source);
    assert_eq!(
        top_level_kinds(&tree),
        vec!["type_alias_declaration", "type_alias_declaration"],
        "`B` and `<number>` must still read as one generic type"
    );
}

#[test]
fn tsx_reads_an_element_after_a_newline_as_before() {
    let source = "const el = <div />\nconst other = 1\n";
    assert_clean(&parse_tsx(source), source);
}

// ---------------------------------------------------------------------------
// Patch 0002: type-only export star, valid since TypeScript 5.0.
// ---------------------------------------------------------------------------

#[test]
fn type_only_export_star_parses() {
    for source in [
        "export type * from './x'\n",
        "export type * as NS from './x'\n",
    ] {
        assert_clean(&parse(source), source);
    }
}

/// Defect B's `ERROR` is one token wide and the parser resynchronises at the
/// next statement, so the declaration after it survives either way. What the
/// patch buys is the file reading as valid rather than as damaged, and the
/// re-export being a re-export rather than a token inside an error.
#[test]
fn a_type_only_export_star_reads_as_a_re_export() {
    let source = "export type * from './x'\nexport const after = 1\n";
    let tree = parse(source);
    assert_clean(&tree, source);
    assert_eq!(
        top_level_kinds(&tree),
        vec!["export_statement", "export_statement"],
        "the re-export must be an export statement"
    );
}

#[test]
fn the_export_forms_that_already_parsed_still_do() {
    for source in [
        "export type { A } from './x'\n",
        "export type { A }\n",
        "export * from './x'\n",
        "export * as NS from './x'\n",
        "import type * as NS from './x'\n",
    ] {
        assert_clean(&parse(source), source);
    }
}
