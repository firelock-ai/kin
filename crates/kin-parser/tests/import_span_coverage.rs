// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every language's import carries a REAL span.
//!
//! `FileImport::site` is a required field, so no adapter can forget it: the
//! compiler names every construction site that omits one. That closes the
//! "forgot an adapter" case completely and closes nothing else, because a
//! required field can still be satisfied with a lie. `(0, 0)` compiles. A span
//! over the wrong bytes compiles. This suite is the half a compile error cannot
//! reach.
//!
//! It is driven from `ALL_LANGUAGE_IDS` through a wildcard-free match, not from
//! a hand-written list of cases. That matters here more than usual: the
//! existing import fixture table in `adapter_conformance.rs` is such a list and
//! it covers thirteen of fourteen languages, silently omitting HCL, so nothing
//! asserted HCL carried a `FileImport` at all. A suite that enumerates its own
//! subjects by hand cannot report the subject it forgot.

use kin_model::{FilePathId, LanguageId};
use kin_parser::{AdapterRegistry, ALL_LANGUAGE_IDS};

/// Source that imports something, for every language.
///
/// The match has **no wildcard arm**. Adding a `LanguageId` variant fails to
/// compile here, which is the point: a new language arrives with a fixture or
/// it does not arrive. Do not add `_ => ...`; it would turn this suite into one
/// that cannot fail.
fn fixture_for(id: LanguageId) -> (&'static str, &'static [u8]) {
    match id {
        LanguageId::Python => ("py", b"import os\nfrom pathlib import Path\n"),
        LanguageId::JavaScript => ("js", b"import util from './util.js';\n"),
        LanguageId::TypeScript => ("ts", b"import { util } from './util';\n"),
        LanguageId::Go => ("go", b"package main\nimport \"fmt\"\n"),
        LanguageId::Rust => ("rs", b"use crate::util::run;\n"),
        LanguageId::Java => ("java", b"import java.util.List;\npublic class Foo { }\n"),
        LanguageId::C => ("c", b"#include <stdio.h>\nint main(void) { return 0; }\n"),
        LanguageId::Cpp => ("cpp", b"#include <vector>\nint main() { return 0; }\n"),
        LanguageId::CSharp => ("cs", b"using System;\npublic class Foo { }\n"),
        LanguageId::Ruby => ("rb", b"require 'json'\nclass Foo\nend\n"),
        // `use`, not `require`. PHP's `require`/`include` produces no
        // FileImport at all, a known gap pinned by an ignored case in
        // language_matrix_imports.rs; a fixture using it would fail here for a
        // reason that has nothing to do with spans.
        LanguageId::Php => ("php", b"<?php\nuse Foo\\Bar;\nclass Baz { }\n"),
        LanguageId::Swift => ("swift", b"import Foundation\nclass Foo { }\n"),
        LanguageId::Kotlin => ("kt", b"import foo.Bar\nclass Baz { }\n"),
        // HCL's import is a module block's `source` attribute, and this is the
        // language the hand-written table in adapter_conformance.rs omitted.
        LanguageId::Hcl => ("tf", b"module \"vpc\" {\n  source = \"./modules/vpc\"\n}\n"),
    }
}

/// The last identifier-ish segment of a module path, for checking the span
/// points at bytes that actually mention what was imported.
///
/// Adapters normalise module paths differently (`./util.js` against `util`,
/// `Foo\Bar` against `Bar`), so comparing the whole path would fail on
/// normalisation rather than on a wrong span. The final segment survives every
/// normalisation this workspace does and is still specific enough that a `(0,
/// 0)` span or a span over the wrong statement does not contain it.
fn tail_segment(module_path: &str) -> String {
    module_path
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '<' || c == '>')
        .rsplit(['/', '.', '\\', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(module_path)
        .to_string()
}

#[test]
fn every_language_carries_a_real_import_span() {
    let registry = AdapterRegistry::new();
    let mut checked = 0_usize;

    for id in ALL_LANGUAGE_IDS.iter().copied() {
        let (ext, source) = fixture_for(id);
        let adapter = registry
            .get_by_language(id)
            .unwrap_or_else(|| panic!("{id}: no adapter registered"));
        let tree = adapter
            .parse(source)
            .unwrap_or_else(|err| panic!("{id}: parse failed: {err}"));
        let file_id = FilePathId(format!("test/import_span_fixture.{ext}"));
        let output = adapter
            .extract(&tree, source, &file_id)
            .unwrap_or_else(|err| panic!("{id}: extract failed: {err}"));

        assert!(
            !output.imports.is_empty(),
            "{id}: the fixture imports something but the adapter produced no FileImport, \
             so this language's span cannot be checked at all"
        );

        for import in &output.imports {
            let site = &import.site;

            assert!(
                site.end_byte > site.start_byte,
                "{id}: import {:?} carries an empty span {}..{}; a required field satisfied \
                 with (0, 0) is the lie this suite exists to catch",
                import.module_path,
                site.start_byte,
                site.end_byte
            );
            assert!(
                site.end_byte <= source.len(),
                "{id}: import {:?} spans {}..{} but the file is {} bytes",
                import.module_path,
                site.start_byte,
                site.end_byte,
                source.len()
            );
            // Not "line >= 1". Both span builders in this crate write
            // tree-sitter's `start_position().row` straight through, and that
            // row is 0-based, so an import on the first line correctly reports
            // 0. Asserting 1-based here failed on TypeScript and the assertion
            // was wrong, not the code.
            //
            // What IS worth asserting is that the line agrees with the bytes.
            // A fabricated span can carry any line number it likes; one derived
            // from the same node cannot disagree with its own offset.
            let newlines_before = source[..site.start_byte]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count() as u32;
            assert_eq!(
                site.start_line, newlines_before,
                "{id}: import {:?} reports line {} but sits after {} newline(s); the line and \
                 the byte offset come from one node and cannot disagree",
                import.module_path, site.start_line, newlines_before
            );

            let text = String::from_utf8_lossy(&source[site.start_byte..site.end_byte]);
            let tail = tail_segment(&import.module_path);
            assert!(
                text.contains(&tail),
                "{id}: import {:?} points at {:?}, which does not mention {:?}; the span is \
                 real but it is over the wrong bytes",
                import.module_path,
                text,
                tail
            );
            checked += 1;
        }
    }

    assert_eq!(
        checked > 0,
        true,
        "no imports were checked at all, which is what this suite looks like when the fixtures \
         stop producing imports"
    );
}
