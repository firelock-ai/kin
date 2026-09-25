// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! An import's evidence names the line the IMPORTED NAME is written on.
//!
//! `import_span_coverage.rs` proves every language's `FileImport` carries a
//! real span. A real span can still be the wrong one. An entity-level import
//! edge is minted per specifier, and it cited `FileImport::site`, which is the
//! whole statement, so every specifier of
//!
//! ```text
//! import {
//!   DEFAULT_STYLE_ID,
//! } from './common'
//! ```
//!
//! reported the line carrying the bare `import {`. `find_references` answered
//! with that line beside the real one, and the reader cannot act on it: there
//! is no occurrence of the name there to read, to jump to, or to rewrite.
//!
//! Driven from `ALL_LANGUAGE_IDS` through a wildcard-free match, for the same
//! reason the span suite is: a new `LanguageId` variant fails to compile here
//! until someone decides what its imports anchor on. Do not add `_ => ...`.

use kin_model::{FilePathId, LanguageId};
use kin_parser::{AdapterRegistry, ALL_LANGUAGE_IDS};

/// What an import statement in this language gives an edge to point at.
enum Anchor {
    /// The grammar gives the adapter a node for the imported name, so the edge
    /// cites that name's own line and column range.
    Named {
        /// The local name the adapter records for it.
        specifier: &'static str,
        /// 0-based line the name is written on.
        line: u32,
    },
    /// The language binds a name the file never writes down, so there is no
    /// specifier node to record and the statement's span is the only evidence
    /// there is. The reason is recorded rather than the language being skipped.
    Unwritten {
        #[allow(dead_code)]
        reason: &'static str,
    },
}

struct Fixture {
    ext: &'static str,
    source: &'static str,
    /// 0-based line the `FileImport`'s own span opens on. It stays available
    /// for a statement-level reader, so it is asserted rather than assumed.
    statement_line: u32,
    /// 0-based line of a multi-line construct's opening delimiter, where the
    /// grammar has one that is NOT the statement span's first line. Go's
    /// `FileImport` unit is the `import_spec` inside the group, so the group's
    /// `import (` line is never either span's first line and is asserted
    /// against directly.
    group_line: Option<u32>,
    anchor: Anchor,
}

/// Every language's import, written across lines wherever its grammar allows
/// the imported name to sit on a line of its own.
///
/// The match has **no wildcard arm**, on purpose. See the module docs.
fn fixture_for(id: LanguageId) -> Fixture {
    match id {
        LanguageId::Python => Fixture {
            ext: "py",
            source: "from pathlib import (\n    Path,\n)\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "Path",
                line: 1,
            },
        },
        LanguageId::TypeScript => Fixture {
            ext: "ts",
            source: "import {\n  util,\n} from './util';\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "util",
                line: 1,
            },
        },
        LanguageId::JavaScript => Fixture {
            ext: "js",
            source: "import {\n  util,\n} from './util.js';\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "util",
                line: 1,
            },
        },
        // Go's `FileImport` unit is the `import_spec`, one per line inside a
        // grouped `import ( ... )`, so the statement span already sits on the
        // spec's line. What has to hold is that neither span reports the
        // group's opening `import (` line, which is `group_line` below.
        LanguageId::Go => Fixture {
            ext: "go",
            source: "package main\n\nimport (\n\t\"fmt\"\n)\n",
            statement_line: 3,
            group_line: Some(2),
            anchor: Anchor::Named {
                specifier: "fmt",
                line: 3,
            },
        },
        LanguageId::Rust => Fixture {
            ext: "rs",
            source: "use crate::util::{\n    run,\n};\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "run",
                line: 1,
            },
        },
        LanguageId::Java => Fixture {
            ext: "java",
            source: "import java.util.\n    List;\npublic class Foo { }\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "List",
                line: 1,
            },
        },
        LanguageId::Kotlin => Fixture {
            ext: "kt",
            source: "import foo.\n    Bar\nclass Baz { }\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "Bar",
                line: 1,
            },
        },
        LanguageId::Php => Fixture {
            ext: "php",
            source: "<?php\nuse\n    Foo\\Bar;\nclass Baz { }\n",
            statement_line: 1,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "Bar",
                line: 2,
            },
        },
        LanguageId::CSharp => Fixture {
            ext: "cs",
            source: "using\n    System;\npublic class Foo { }\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "System",
                line: 1,
            },
        },
        // Swift terminates a statement at the newline, so `import` and the
        // module name cannot be split across lines at all. The specifier is
        // still anchored on its own node, which is what gives the edge a
        // column range over the module name instead of over the keyword.
        LanguageId::Swift => Fixture {
            ext: "swift",
            source: "import Foundation\nclass Foo { }\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Named {
                specifier: "Foundation",
                line: 0,
            },
        },
        LanguageId::C => Fixture {
            ext: "c",
            source: "#include <stdio.h>\nint main(void) { return 0; }\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Unwritten {
                reason: "an #include binds every name the header declares and writes none of them",
            },
        },
        LanguageId::Cpp => Fixture {
            ext: "cpp",
            source: "#include <vector>\nint main() { return 0; }\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Unwritten {
                reason: "an #include binds every name the header declares and writes none of them",
            },
        },
        LanguageId::Ruby => Fixture {
            ext: "rb",
            source: "require 'json'\nclass Foo\nend\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Unwritten {
                reason: "require names its module through a string literal, not a bound identifier",
            },
        },
        LanguageId::Hcl => Fixture {
            ext: "tf",
            source: "module \"vpc\" {\n  source = \"./modules/vpc\"\n}\n",
            statement_line: 0,
            group_line: None,
            anchor: Anchor::Unwritten {
                reason: "an HCL import is a module block's source attribute; the name is the label",
            },
        },
    }
}

#[test]
fn every_language_anchors_an_import_on_the_line_that_carries_the_name() {
    let registry = AdapterRegistry::new();

    for id in ALL_LANGUAGE_IDS.iter().copied() {
        let fixture = fixture_for(id);
        let source = fixture.source.as_bytes();
        let adapter = registry
            .get_by_language(id)
            .unwrap_or_else(|| panic!("{id}: no adapter registered"));
        let tree = adapter
            .parse(source)
            .unwrap_or_else(|err| panic!("{id}: parse failed: {err}"));
        let file_id = FilePathId(format!("test/import_anchor_fixture.{}", fixture.ext));
        let output = adapter
            .extract(&tree, source, &file_id)
            .unwrap_or_else(|err| panic!("{id}: extract failed: {err}"));

        assert!(
            !output.imports.is_empty(),
            "{id}: the fixture imports something but the adapter produced no FileImport"
        );

        match fixture.anchor {
            Anchor::Named { specifier, line } => {
                let (import, spec) = output
                    .imports
                    .iter()
                    .find_map(|import| {
                        import
                            .specifiers
                            .iter()
                            .find(|spec| spec.local_name == specifier)
                            .map(|spec| (import, spec))
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "{id}: no specifier named {specifier:?}; the adapter recorded {:?}",
                            output
                                .imports
                                .iter()
                                .flat_map(|import| import.specifiers.iter())
                                .map(|spec| spec.local_name.as_str())
                                .collect::<Vec<_>>()
                        )
                    });

                let site = spec.site.as_ref().unwrap_or_else(|| {
                    panic!(
                        "{id}: specifier {specifier:?} carries no site of its own, so every edge \
                         minted from it falls back to the import statement's span"
                    )
                });

                assert_eq!(
                    site.start_line, line,
                    "{id}: specifier {specifier:?} is written on line {line} but its site reports \
                     line {}",
                    site.start_line
                );

                // A fabricated span can carry any line it likes; one derived
                // from the specifier's own node cannot disagree with its own
                // byte offset.
                let newlines_before = source[..site.start_byte]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count() as u32;
                assert_eq!(
                    site.start_line, newlines_before,
                    "{id}: specifier {specifier:?} reports line {} but sits after {newlines_before} \
                     newline(s)",
                    site.start_line
                );

                let text = String::from_utf8_lossy(&source[site.start_byte..site.end_byte]);
                assert!(
                    text.contains(specifier),
                    "{id}: specifier {specifier:?} points at {text:?}, which does not mention it; \
                     the span is real but it is over the wrong bytes"
                );

                assert_eq!(
                    import.evidence_site(spec).start_line,
                    line,
                    "{id}: the edge builders read `evidence_site`, and it did not return the \
                     specifier's own span"
                );

                // The statement's span is still there for a statement-level
                // reader. Losing it would break `kin rename`, which needs an
                // exact source span on the evidence to plan an edit at all.
                assert_eq!(
                    import.site.start_line, fixture.statement_line,
                    "{id}: the FileImport's statement span moved off line {}",
                    fixture.statement_line
                );

                if let Some(group_line) = fixture.group_line {
                    assert_ne!(
                        site.start_line, group_line,
                        "{id}: specifier {specifier:?} reports the line the group opens on, which \
                         carries no name at all"
                    );
                }
            }
            Anchor::Unwritten { .. } => {
                for import in &output.imports {
                    for spec in &import.specifiers {
                        assert!(
                            spec.site.is_none(),
                            "{id}: specifier {:?} recorded a site, but this language's fixture \
                             says its imports bind a name the file never writes; either the \
                             adapter changed or this fixture is stale",
                            spec.local_name
                        );
                        assert_eq!(
                            import.evidence_site(spec).start_byte,
                            import.site.start_byte,
                            "{id}: an unwritten specifier must fall back to the statement's span"
                        );
                    }
                }
            }
        }
    }
}

/// The defect exactly as the Study 07 control found it, in the language it was
/// found in: a named specifier two lines below the `import {` that opens the
/// statement, reported on its own line and not on the opening one.
#[test]
fn a_multi_line_typescript_import_does_not_report_the_opening_line() {
    let registry = AdapterRegistry::new();
    let source = b"import { css } from '../css/index'\nimport {\n  DEFAULT_STYLE_ID,\n  SomethingElse,\n} from './common'\n";
    let adapter = registry
        .get_by_language(LanguageId::TypeScript)
        .expect("typescript adapter");
    let tree = adapter.parse(source).expect("parse");
    let file_id = FilePathId::new("src/jsx/dom/css.ts");
    let output = adapter.extract(&tree, source, &file_id).expect("extract");

    let import = output
        .imports
        .iter()
        .find(|import| import.module_path == "./common")
        .expect("the ./common import");

    assert_eq!(
        import.site.start_line, 1,
        "the statement opens on the bare `import {{` line"
    );

    let anchors: Vec<(&str, u32)> = import
        .specifiers
        .iter()
        .map(|spec| {
            (
                spec.local_name.as_str(),
                import.evidence_site(spec).start_line,
            )
        })
        .collect();

    assert_eq!(
        anchors,
        vec![("DEFAULT_STYLE_ID", 2), ("SomethingElse", 3)],
        "each specifier is evidenced by the line that carries it, never by the statement's"
    );
}
