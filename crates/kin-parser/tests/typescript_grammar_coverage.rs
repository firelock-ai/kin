// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the two vendored grammar patches are worth at the extraction surface.
//!
//! `kin-grammar-typescript`'s own tests pin the parse. These pin the thing the
//! parse was for: a construct the TypeScript compiler accepts must not leave the
//! file half read, and must not cost the declarations around it.
//!
//! The two costs are not the same size, and the tests say so rather than
//! flattening them. Measured on `honojs/hono` at `098e1191`, over the 188
//! non-test TypeScript files the proof draws from:
//!
//! - Both defects together took 8 files from `Valid` to `Incomplete`. Those
//!   files hold 5,016 of the tree's 25,979 lines, 19.3 percent.
//! - Of those 25,979 lines, an `ERROR` node covered 3,181 before and covers none
//!   after.
//! - Entities went from 2,623 to 2,670, and every one of the 47 is Defect A's.
//!   `src/types.ts` alone went from 25 to 63, `src/helper/factory/index.ts` from
//!   3 to 12.
//! - Defect B moved no entity and no import on this tree. Its `ERROR` is one
//!   token wide, tree-sitter resynchronises at the next statement, and the
//!   re-export is still recovered. What it cost was the file's parse state,
//!   which is what a reader of `ParseState` is told about the file.
//!
//! So `a_generic_call_signature_recovers_a_member` is the test that fails before
//! on a missing entity. The rest fail before on `parse_state`, which is the
//! honest shape of each defect rather than the loudest claim available.

use kin_model::{EntityKind, FilePathId, ParseState};
use kin_parser::{LanguageAdapter, ParseOutput, TypeScriptAdapter};

fn extract(path: &str, src: &str) -> ParseOutput {
    let bytes = src.as_bytes();
    let tree = TypeScriptAdapter
        .parse(bytes)
        .expect("parse should succeed");
    TypeScriptAdapter
        .extract(&tree, bytes, &FilePathId::new(path))
        .expect("extract should succeed")
}

#[track_caller]
fn assert_parsed_whole(out: &ParseOutput, source: &str) {
    match &out.parse_state {
        ParseState::Valid => {}
        other => panic!("the grammar left part of this file unread, {other:?}:\n{source}"),
    }
}

#[track_caller]
fn assert_holds(out: &ParseOutput, kind: EntityKind, name: &str) {
    assert!(
        out.entities
            .iter()
            .any(|e| e.kind == kind && e.name == name),
        "no {kind:?} named {name:?}; have: {:?}",
        out.entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Defect A: a member not terminated by `;` or `,`, followed by a member
// beginning with `<`.
// ---------------------------------------------------------------------------

/// The entity the defect costs. A member after the generic call signature is
/// inside the `ERROR`, so it is not extracted and the interface does not contain
/// it, which is `src/types.ts` in miniature: extraction there stopped where
/// `HandlerInterface` began and the file yielded 25 entities for 52 top-level
/// declarations.
///
/// The call signature itself carries no name and is not an entity either way, by
/// the same cut the class arm makes.
#[test]
fn a_generic_call_signature_recovers_a_member() {
    let source = concat!(
        "export interface I {\n",
        "  p: string\n",
        "  <T>(): void\n",
        "  q: number\n",
        "}\n",
        "export function afterFunction(): number {\n  return 1;\n}\n",
    );
    let out = extract("defect_a.ts", source);
    assert_parsed_whole(&out, source);

    assert_holds(&out, EntityKind::Interface, "I");
    assert_holds(&out, EntityKind::Method, "I.p");
    assert_holds(&out, EntityKind::Method, "I.q");
    assert_holds(&out, EntityKind::Function, "afterFunction");
    assert!(
        out.relations
            .iter()
            .any(|r| r.src_name == "I" && r.dst_name == "I.q"),
        "the interface must contain the member after the call signature; have: {:?}",
        out.relations
            .iter()
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect::<Vec<_>>()
    );
}

/// The minimised reproduction itself, three lines, which `tsc` accepts.
#[test]
fn the_minimised_reproduction_reads_whole() {
    let source = "export interface I {\n  p: string\n  <T>(): void\n}\n";
    let out = extract("minimal_a.ts", source);
    assert_parsed_whole(&out, source);
    assert_holds(&out, EntityKind::Interface, "I");
    assert_holds(&out, EntityKind::Method, "I.p");
}

/// The same boundary inside an object type literal, which is the form
/// `src/types.ts` carries.
#[test]
fn an_object_type_literal_member_boundary_reads_whole() {
    let source = concat!(
        "export type Callable = {\n",
        "  p: string\n",
        "  <T>(): void\n",
        "  q: number\n",
        "}\n",
        "export function afterFunction(): number {\n  return 1;\n}\n",
    );
    let out = extract("defect_a_object_type.ts", source);
    assert_parsed_whole(&out, source);
    assert_holds(&out, EntityKind::TypeAlias, "Callable");
    assert_holds(&out, EntityKind::Function, "afterFunction");
}

// ---------------------------------------------------------------------------
// Defect B: type-only export star, valid since TypeScript 5.0. On `honojs/hono`
// it sat on line 112 of `src/jsx/index.ts` and line 169 of
// `src/jsx/dom/index.ts`, and left both files `Incomplete`.
// ---------------------------------------------------------------------------

/// A file whose only fault is a type-only export star is a fully read file, so
/// its parse state has to say so. The re-export edge survives either way and the
/// test asserts it stays, because a fix that read the file by dropping the edge
/// would be a worse answer than the defect.
#[test]
fn a_type_only_export_star_leaves_the_file_valid() {
    let source = concat!(
        "export type * from './types';\n",
        "export type * as Namespaced from './other';\n",
        "export function afterFunction(): number {\n  return 1;\n}\n",
        "export class AfterClass {}\n",
    );
    let out = extract("defect_b.ts", source);
    assert_parsed_whole(&out, source);
    assert_holds(&out, EntityKind::Function, "afterFunction");
    assert_holds(&out, EntityKind::Class, "AfterClass");

    let modules: Vec<&str> = out.imports.iter().map(|i| i.module_path.as_str()).collect();
    assert!(
        modules.contains(&"./types") && modules.contains(&"./other"),
        "both re-exports must still be recorded; have: {modules:?}"
    );
}

// ---------------------------------------------------------------------------
// Both dialects.
// ---------------------------------------------------------------------------

/// A `.tsx` file reaches the same grammar through the TSX dialect, and the Flow
/// repair path in the JavaScript adapter reaches it too, so both patches have to
/// hold on TSX rather than on the non-JSX dialect alone. They are generated from
/// one `define-grammar.js`, and this is the test that says so.
#[test]
fn the_tsx_dialect_carries_both_repairs() {
    let source = concat!(
        "export type * from './types';\n",
        "export interface I {\n",
        "  p: string\n",
        "  <T>(): void\n",
        "  q: number\n",
        "}\n",
        "export function afterFunction(): number {\n  return 1;\n}\n",
    );
    let bytes = source.as_bytes();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&kin_grammar_typescript::LANGUAGE_TSX.into())
        .expect("load the TSX grammar");
    let tree = parser.parse(bytes, None).expect("parse");
    assert!(
        !tree.root_node().has_error(),
        "the TSX dialect rejected source the TypeScript compiler accepts:\n{source}"
    );
    let out = TypeScriptAdapter
        .extract(&tree, bytes, &FilePathId::new("defect.tsx"))
        .expect("extract should succeed");
    assert_holds(&out, EntityKind::Interface, "I");
    assert_holds(&out, EntityKind::Method, "I.q");
    assert_holds(&out, EntityKind::Function, "afterFunction");
}
