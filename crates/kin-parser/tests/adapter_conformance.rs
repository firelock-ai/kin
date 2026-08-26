// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Adapter Conformance Suite
//!
//! Every `LanguageAdapter` implementation MUST pass these tests.
//! When adding a new language adapter, add it to the `all_adapters()` list
//! and provide fixture files in `tests/adapter-fixtures/<language>/`.
//!
//! Conformance requirements:
//! 1. `language_id()` returns a valid `LanguageId`
//! 2. `file_extensions()` returns at least one extension
//! 3. `parse()` succeeds on valid source code
//! 4. `parse()` returns a tree (may have errors) on invalid source code
//! 5. `extract()` produces at least one entity from the basic fixture
//! 6. Extracted entities have non-empty names
//! 7. Extracted entities have valid fingerprints (non-zero hashes)
//! 8. Extracted entities have valid source spans
//! 9. `parse_state` is `Complete` or `Partial` (never panics)
//! 10. Deterministic: same input produces same output

use kin_model::{FilePathId, ParseState};
use kin_parser::{language_ordinal, ALL_LANGUAGE_IDS};
use kin_parser::{
    AdapterRegistry, CAdapter, CSharpAdapter, CppAdapter, GoAdapter, HclAdapter, JavaAdapter,
    JavaScriptAdapter, KotlinAdapter, LanguageAdapter, ParseOutput, PhpAdapter, PythonAdapter,
    RubyAdapter, RustAdapter, SwiftAdapter, TypeScriptAdapter,
};

/// Returns all registered adapters for conformance testing.
fn all_adapters() -> Vec<Box<dyn LanguageAdapter>> {
    vec![
        Box::new(TypeScriptAdapter),
        Box::new(JavaScriptAdapter),
        Box::new(PythonAdapter),
        Box::new(GoAdapter),
        Box::new(JavaAdapter),
        Box::new(RustAdapter),
        Box::new(CAdapter),
        Box::new(CppAdapter),
        Box::new(CSharpAdapter),
        Box::new(RubyAdapter),
        Box::new(PhpAdapter),
        Box::new(SwiftAdapter),
        Box::new(KotlinAdapter),
        Box::new(HclAdapter),
    ]
}

/// Fixture directory relative to workspace root.
fn fixture_path(lang: &str, file: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // CARGO_MANIFEST_DIR is .../crates/kin-parser, go up 2 levels to workspace root
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    format!(
        "{}/tests/adapter-fixtures/{}/{}",
        workspace_root.display(),
        lang,
        file
    )
}

fn load_fixture(lang: &str, file: &str) -> Vec<u8> {
    let path = fixture_path(lang, file);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path, e))
}

fn parse_fixture(adapter: &dyn LanguageAdapter, source: &[u8]) -> ParseOutput {
    let tree = adapter.parse(source).expect("parse should succeed");
    let file_id = FilePathId("test/fixture.ext".to_string());
    adapter
        .extract(&tree, source, &file_id)
        .expect("extract should succeed")
}

// ---- Conformance Requirement 1: language_id is valid ----

/// `all_adapters()` covers every `LanguageId`, and nothing else.
///
/// Every conformance test in this file iterates `all_adapters()`, a list
/// maintained by hand, and the module comment asks whoever adds an adapter to
/// remember it. An adapter missing from that list is not tested by ANY of them,
/// and the suite stays green while saying nothing about it. That is the same
/// shape as the registry guard this lane replaced (FIR-2704): a list checked
/// only against itself.
///
/// So the list is compared against `ALL_LANGUAGE_IDS`, whose companion
/// `language_ordinal` is a wildcard-free match and therefore a compile error
/// when a `LanguageId` variant is added. Both directions matter: a language
/// with no entry here is untested, and an entry for a language the enumeration
/// does not know means the two have drifted and every "all adapters" claim in
/// this file is measuring a different set than it reads.
#[test]
fn conformance_list_covers_every_language_id() {
    let mut listed: Vec<usize> = all_adapters()
        .iter()
        .map(|a| language_ordinal(a.language_id()))
        .collect();
    let mut expected: Vec<usize> = ALL_LANGUAGE_IDS
        .iter()
        .copied()
        .map(language_ordinal)
        .collect();
    listed.sort_unstable();
    expected.sort_unstable();

    let missing: Vec<usize> = expected
        .iter()
        .copied()
        .filter(|o| !listed.contains(o))
        .collect();
    assert!(
        missing.is_empty(),
        "these LanguageId ordinals are absent from all_adapters(), so every conformance test in \
         this file silently skips them: {missing:?}"
    );

    let extra: Vec<usize> = listed
        .iter()
        .copied()
        .filter(|o| !expected.contains(o))
        .collect();
    assert!(
        extra.is_empty(),
        "all_adapters() lists languages the enumeration does not know: {extra:?}"
    );

    assert_eq!(
        listed.len(),
        ALL_LANGUAGE_IDS.len(),
        "one language, one adapter entry; a duplicate hides a language behind another"
    );
}

#[test]
fn conformance_language_id_is_set() {
    for adapter in all_adapters() {
        let lang = adapter.language_id();
        // LanguageId is an enum — if it compiles, it's valid
        let _ = format!("{:?}", lang);
    }
}

// ---- Conformance Requirement 2: file_extensions non-empty ----

#[test]
fn conformance_file_extensions_non_empty() {
    for adapter in all_adapters() {
        let exts = adapter.file_extensions();
        assert!(
            !exts.is_empty(),
            "Adapter {:?} must declare at least one file extension",
            adapter.language_id()
        );
        for ext in exts {
            assert!(
                !ext.is_empty(),
                "Extension must not be empty for {:?}",
                adapter.language_id()
            );
            assert!(
                !ext.starts_with('.'),
                "Extension '{}' must not start with dot for {:?}",
                ext,
                adapter.language_id()
            );
        }
    }
}

// ---- Conformance Requirement 3: parse succeeds on valid source ----

#[test]
fn conformance_parse_valid_source() {
    let cases: Vec<(&str, &[u8])> = vec![
        ("typescript", b"export function hello(): void {}"),
        ("javascript", b"function hello() {}"),
        ("python", b"def hello():\n    pass\n"),
        ("go", b"package main\nfunc Hello() {}"),
        ("java", b"public class Hello { public void greet() {} }"),
        ("rust", b"pub fn hello() {}"),
        ("c", b"int hello(void) { return 1; }"),
        ("cpp", b"class Hello {}; int greet() { return 1; }"),
        ("csharp", b"public class Hello { public void Greet() {} }"),
        ("ruby", b"class Hello\n  def greet\n  end\nend\n"),
        (
            "php",
            b"<?php\nclass Hello { public function greet() {} }\n" as &[u8],
        ),
        ("swift", b"class Hello { func greet() {} }"),
        ("kotlin", b"class Hello { fun greet() {} }"),
        (
            "hcl",
            b"resource \"aws_s3_bucket\" \"logs\" { bucket = \"logs\" }\n",
        ),
    ];

    let registry = AdapterRegistry::new();
    for (lang, source) in cases {
        let exts: Vec<&str> = match lang {
            "typescript" => vec!["ts"],
            "javascript" => vec!["js"],
            "python" => vec!["py"],
            "go" => vec!["go"],
            "java" => vec!["java"],
            "rust" => vec!["rs"],
            "c" => vec!["c"],
            "cpp" => vec!["cpp"],
            "csharp" => vec!["cs"],
            "ruby" => vec!["rb"],
            "php" => vec!["php"],
            "swift" => vec!["swift"],
            "kotlin" => vec!["kt"],
            "hcl" => vec!["tf"],
            _ => continue,
        };

        for ext in exts {
            if let Some(adapter) = registry.get_by_extension(ext) {
                let result = adapter.parse(source);
                assert!(
                    result.is_ok(),
                    "Parse failed for {} with ext {}: {:?}",
                    lang,
                    ext,
                    result.err()
                );
            }
        }
    }
}

#[test]
fn conformance_imports_are_file_imports_not_file_id_relations() {
    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, Box<dyn LanguageAdapter>, &str, &[u8])> = vec![
        (
            "python",
            Box::new(PythonAdapter),
            "py",
            b"import os\nfrom pathlib import Path\ndef f():\n    return Path('.')\n",
        ),
        (
            "javascript",
            Box::new(JavaScriptAdapter),
            "js",
            b"import util from './util.js';\nfunction f() { return util(); }\n",
        ),
        (
            "typescript",
            Box::new(TypeScriptAdapter),
            "ts",
            b"import { util } from './util';\nexport function f() { return util(); }\n",
        ),
        (
            "go",
            Box::new(GoAdapter),
            "go",
            b"package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"x\") }\n",
        ),
        (
            "rust",
            Box::new(RustAdapter),
            "rs",
            b"use crate::util::run;\npub fn f() { run(); }\n",
        ),
        (
            "kotlin",
            Box::new(KotlinAdapter),
            "kt",
            b"import foo.Bar\nclass Baz { fun f() = Bar() }\n",
        ),
        (
            "swift",
            Box::new(SwiftAdapter),
            "swift",
            b"import Foundation\nclass Foo { func f() {} }\n",
        ),
        (
            "c",
            Box::new(CAdapter),
            "c",
            b"#include <stdio.h>\nint main(void) { return 0; }\n",
        ),
        (
            "cpp",
            Box::new(CppAdapter),
            "cpp",
            b"#include <vector>\nint main() { return 0; }\n",
        ),
        (
            "java",
            Box::new(JavaAdapter),
            "java",
            b"import java.util.List;\npublic class Foo { List<String> names; }\n",
        ),
        (
            "csharp",
            Box::new(CSharpAdapter),
            "cs",
            b"using System;\npublic class Foo { }\n",
        ),
        (
            "ruby",
            Box::new(RubyAdapter),
            "rb",
            b"require 'json'\nclass Foo\nend\n",
        ),
        (
            "php",
            Box::new(PhpAdapter),
            "php",
            b"<?php\nuse Foo\\Bar;\nclass Baz { }\n",
        ),
    ];

    for (lang, adapter, ext, source) in cases {
        let tree = adapter
            .parse(source)
            .unwrap_or_else(|err| panic!("parse failed for {lang}: {err}"));
        let file_id = FilePathId(format!("test/import_fixture.{ext}"));
        let output = adapter
            .extract(&tree, source, &file_id)
            .unwrap_or_else(|err| panic!("extract failed for {lang}: {err}"));
        assert!(
            !output.imports.is_empty(),
            "{lang} import/include syntax should be carried as FileImport"
        );
        let file_source = file_id.to_string();
        assert!(
            output
                .relations
                .iter()
                .all(|relation| relation.src_name != file_source),
            "{lang} emitted a fake file-id relation source"
        );
    }
}

// ---- Conformance Requirement 4: parse handles invalid source ----

#[test]
fn conformance_parse_invalid_source_no_panic() {
    for adapter in all_adapters() {
        // Tree-sitter is error-tolerant: it should parse garbage without panicking
        let garbage = b"{{{{!!!! not valid in any language }}}}";
        let result = adapter.parse(garbage);
        // Should succeed (tree-sitter is lenient) or return a structured error
        // Either way, it must not panic
        let _ = result;
    }
}

// ---- Conformance Requirement 5: extract produces entities from fixture ----

#[test]
fn conformance_extract_basic_fixture_typescript() {
    let source = load_fixture("typescript", "basic.ts");
    let adapter = TypeScriptAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "TypeScript basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_python() {
    let source = load_fixture("python", "basic.py");
    let adapter = PythonAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Python basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_rust() {
    let source = load_fixture("rust", "basic.rs");
    let adapter = RustAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Rust basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_go() {
    let source = load_fixture("go", "basic.go");
    let adapter = GoAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Go basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_java() {
    let source = load_fixture("java", "Basic.java");
    let adapter = JavaAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Java basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_javascript() {
    let source = load_fixture("javascript", "basic.js");
    let adapter = JavaScriptAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "JavaScript basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_c() {
    let source = load_fixture("c", "basic.c");
    let adapter = CAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "C basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_cpp() {
    let source = load_fixture("cpp", "basic.cpp");
    let adapter = CppAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "C++ basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_swift() {
    let source = load_fixture("swift", "basic.swift");
    let adapter = SwiftAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Swift basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_kotlin() {
    let source = load_fixture("kotlin", "basic.kt");
    let adapter = KotlinAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Kotlin basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_hcl() {
    let source = load_fixture("hcl", "basic.tf");
    let adapter = HclAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "HCL basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_csharp() {
    let source = load_fixture("csharp", "Basic.cs");
    let adapter = CSharpAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "C# basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_ruby() {
    let source = load_fixture("ruby", "basic.rb");
    let adapter = RubyAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "Ruby basic fixture should produce entities"
    );
}

#[test]
fn conformance_extract_basic_fixture_php() {
    let source = load_fixture("php", "basic.php");
    let adapter = PhpAdapter;
    let output = parse_fixture(&adapter, &source);
    assert!(
        !output.entities.is_empty(),
        "PHP basic fixture should produce entities"
    );
}

// ---- Conformance Requirement 6: entity names non-empty ----

#[test]
fn conformance_entity_names_non_empty() {
    let fixtures: Vec<(&str, Box<dyn LanguageAdapter>)> = vec![
        ("typescript/basic.ts", Box::new(TypeScriptAdapter)),
        ("python/basic.py", Box::new(PythonAdapter)),
        ("rust/basic.rs", Box::new(RustAdapter)),
        ("go/basic.go", Box::new(GoAdapter)),
        ("java/Basic.java", Box::new(JavaAdapter)),
        ("javascript/basic.js", Box::new(JavaScriptAdapter)),
        ("c/basic.c", Box::new(CAdapter)),
        ("cpp/basic.cpp", Box::new(CppAdapter)),
        ("csharp/Basic.cs", Box::new(CSharpAdapter)),
        ("ruby/basic.rb", Box::new(RubyAdapter)),
        ("php/basic.php", Box::new(PhpAdapter)),
    ];

    for (fixture, adapter) in &fixtures {
        let parts: Vec<&str> = fixture.split('/').collect();
        let source = load_fixture(parts[0], parts[1]);
        let output = parse_fixture(adapter.as_ref(), &source);

        for entity in &output.entities {
            assert!(
                !entity.name.is_empty(),
                "Entity name must not be empty in {} ({:?})",
                fixture,
                adapter.language_id()
            );
        }
    }
}

// ---- Conformance Requirement 7: fingerprints are non-trivial ----

#[test]
fn conformance_fingerprints_non_zero() {
    let fixtures: Vec<(&str, Box<dyn LanguageAdapter>)> = vec![
        ("typescript/basic.ts", Box::new(TypeScriptAdapter)),
        ("python/basic.py", Box::new(PythonAdapter)),
        ("rust/basic.rs", Box::new(RustAdapter)),
        ("c/basic.c", Box::new(CAdapter)),
        ("cpp/basic.cpp", Box::new(CppAdapter)),
        ("csharp/Basic.cs", Box::new(CSharpAdapter)),
        ("ruby/basic.rb", Box::new(RubyAdapter)),
        ("php/basic.php", Box::new(PhpAdapter)),
    ];

    let zero_hash = kin_model::Hash256::from_bytes([0u8; 32]);

    for (fixture, adapter) in &fixtures {
        let parts: Vec<&str> = fixture.split('/').collect();
        let source = load_fixture(parts[0], parts[1]);
        let output = parse_fixture(adapter.as_ref(), &source);

        for entity in &output.entities {
            assert_ne!(
                entity.fingerprint.ast_hash, zero_hash,
                "AST hash must not be zero for '{}' in {}",
                entity.name, fixture
            );
            assert_ne!(
                entity.fingerprint.behavior_hash, zero_hash,
                "Behavior hash must not be zero for '{}' in {}",
                entity.name, fixture
            );
        }
    }
}

// ---- Conformance Requirement 8: source spans valid ----

#[test]
fn conformance_source_spans_valid() {
    let fixtures: Vec<(&str, Box<dyn LanguageAdapter>)> = vec![
        ("typescript/basic.ts", Box::new(TypeScriptAdapter)),
        ("python/basic.py", Box::new(PythonAdapter)),
        ("rust/basic.rs", Box::new(RustAdapter)),
        ("c/basic.c", Box::new(CAdapter)),
        ("cpp/basic.cpp", Box::new(CppAdapter)),
        ("csharp/Basic.cs", Box::new(CSharpAdapter)),
        ("ruby/basic.rb", Box::new(RubyAdapter)),
        ("php/basic.php", Box::new(PhpAdapter)),
    ];

    for (fixture, adapter) in &fixtures {
        let parts: Vec<&str> = fixture.split('/').collect();
        let source = load_fixture(parts[0], parts[1]);
        let output = parse_fixture(adapter.as_ref(), &source);

        for entity in &output.entities {
            assert!(
                entity.span.end_byte > entity.span.start_byte,
                "Span end must be after start for '{}' in {}",
                entity.name,
                fixture
            );
            assert!(
                entity.span.end_byte <= source.len(),
                "Span must not exceed source length for '{}' in {}",
                entity.name,
                fixture
            );
        }
    }
}

// ---- Conformance Requirement 9: parse_state is valid ----

#[test]
fn conformance_parse_state_valid() {
    let fixtures: Vec<(&str, Box<dyn LanguageAdapter>)> = vec![
        ("typescript/basic.ts", Box::new(TypeScriptAdapter)),
        ("python/basic.py", Box::new(PythonAdapter)),
        ("rust/basic.rs", Box::new(RustAdapter)),
        ("go/basic.go", Box::new(GoAdapter)),
        ("java/Basic.java", Box::new(JavaAdapter)),
        ("javascript/basic.js", Box::new(JavaScriptAdapter)),
        ("c/basic.c", Box::new(CAdapter)),
        ("cpp/basic.cpp", Box::new(CppAdapter)),
        ("csharp/Basic.cs", Box::new(CSharpAdapter)),
        ("ruby/basic.rb", Box::new(RubyAdapter)),
        ("php/basic.php", Box::new(PhpAdapter)),
    ];

    for (fixture, adapter) in &fixtures {
        let parts: Vec<&str> = fixture.split('/').collect();
        let source = load_fixture(parts[0], parts[1]);
        let output = parse_fixture(adapter.as_ref(), &source);

        // Must be Valid for well-formed fixtures
        assert!(
            matches!(output.parse_state, ParseState::Valid),
            "Parse state should be Valid for well-formed fixture {} (got {:?})",
            fixture,
            output.parse_state
        );
    }
}

// ---- Conformance Requirement 10: deterministic output ----

#[test]
fn conformance_deterministic_output() {
    let fixtures: Vec<(&str, Box<dyn LanguageAdapter>)> = vec![
        ("typescript/basic.ts", Box::new(TypeScriptAdapter)),
        ("python/basic.py", Box::new(PythonAdapter)),
        ("rust/basic.rs", Box::new(RustAdapter)),
        ("c/basic.c", Box::new(CAdapter)),
        ("cpp/basic.cpp", Box::new(CppAdapter)),
        ("csharp/Basic.cs", Box::new(CSharpAdapter)),
        ("ruby/basic.rb", Box::new(RubyAdapter)),
        ("php/basic.php", Box::new(PhpAdapter)),
    ];

    for (fixture, adapter) in &fixtures {
        let parts: Vec<&str> = fixture.split('/').collect();
        let source = load_fixture(parts[0], parts[1]);

        let output1 = parse_fixture(adapter.as_ref(), &source);
        let output2 = parse_fixture(adapter.as_ref(), &source);

        assert_eq!(
            output1.entities.len(),
            output2.entities.len(),
            "Entity count must be deterministic for {}",
            fixture
        );

        for (e1, e2) in output1.entities.iter().zip(output2.entities.iter()) {
            assert_eq!(
                e1.name, e2.name,
                "Entity names must be deterministic for {}",
                fixture
            );
            assert_eq!(
                e1.fingerprint.ast_hash, e2.fingerprint.ast_hash,
                "Fingerprint hashes must be deterministic for '{}' in {}",
                e1.name, fixture
            );
        }
    }
}

#[test]
fn invalid_utf8_declaration_ranges_never_panic() {
    let source = b"jj==\n\xff\xff";
    let registry = AdapterRegistry::new();
    let file_id = FilePathId::new("invalid_utf8");

    for language in registry.supported_languages() {
        let adapter = registry
            .get_by_language(language)
            .expect("supported language has an adapter");
        if let Ok(tree) = adapter.parse(source) {
            let _ = adapter.extract(&tree, source, &file_id);
        }
    }
}

#[test]
fn python_invalid_utf8_declarations_are_opaque_and_byte_distinct() {
    let sources: [&[u8]; 3] = [
        b"# coding: latin-1\ndef target(value=\"x  \xff y\"):\n    return value\n",
        b"# coding: latin-1\ndef target(value=\"x \xff y\"):\n    return value\n",
        b"# coding: latin-1\ndef target(value=\"x  \xfe y\"):\n    return value\n",
    ];
    let adapter = PythonAdapter;
    let file_id = FilePathId::new("invalid_utf8.py");
    let mut signatures = Vec::new();

    for source in sources {
        let tree = adapter.parse(source).expect("parse Latin-1 Python fixture");
        let output = adapter
            .extract(&tree, source, &file_id)
            .expect("extract Latin-1 Python fixture");
        assert!(
            matches!(output.parse_state, ParseState::Valid),
            "the safety regression must exercise tree-sitter's valid parse path"
        );
        let signature = output
            .entities
            .iter()
            .find(|entity| entity.name == "target")
            .expect("target entity")
            .signature
            .clone();
        assert!(
            signature.starts_with("non_utf8_hex:"),
            "invalid-UTF-8 declarations must stay outside semantic classifiers: {signature}"
        );
        signatures.push(signature);
    }

    assert_ne!(
        signatures[0], signatures[1],
        "semantic whitespace around an invalid byte must remain visible"
    );
    assert_ne!(
        signatures[0], signatures[2],
        "distinct invalid byte values must remain visible"
    );
}

// ---- Registry conformance ----

#[test]
fn conformance_registry_covers_all_extensions() {
    let registry = AdapterRegistry::new();

    let expected_extensions = vec![
        "ts", "tsx", "js", "jsx", "py", "go", "java", "rs", "c", "h", "cpp", "hpp", "cc", "cxx",
        "cs", "rb", "php",
    ];

    for ext in expected_extensions {
        assert!(
            registry.get_by_extension(ext).is_some(),
            "Registry must have an adapter for .{} files",
            ext
        );
    }
}

#[test]
fn conformance_registry_returns_none_for_unknown() {
    let registry = AdapterRegistry::new();
    assert!(registry.get_by_extension("xyz").is_none());
    assert!(registry.get_by_extension("").is_none());
}

// ---- Edge-case coverage: verify deeper extraction on realistic fixtures ----

#[test]
fn edge_case_go_extracts_interfaces_structs_methods_constants() {
    let adapter = GoAdapter;
    let source = load_fixture("go", "edge_cases.go");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| output.entities.iter().filter(|e| e.kind == kind).count();

    // Should extract: Shape (interface), Circle, Rectangle, LabeledShape (structs),
    // Color, ShapeList, ShapeFactory (type aliases)
    assert!(
        by_kind(kin_model::EntityKind::Interface) >= 1,
        "Go should extract Shape interface"
    );
    assert!(
        by_kind(kin_model::EntityKind::Class) >= 2,
        "Go should extract Circle and Rectangle structs"
    );
    // Should extract: Divide, SumAll, init (functions)
    assert!(
        by_kind(kin_model::EntityKind::Function) >= 2,
        "Go should extract standalone functions"
    );
    // Should extract receiver methods: Circle.Area, Circle.Perimeter, etc.
    assert!(
        by_kind(kin_model::EntityKind::Method) >= 6,
        "Go should extract methods with receivers"
    );
    // Should extract constants: Red (at minimum)
    assert!(
        by_kind(kin_model::EntityKind::Constant) >= 1,
        "Go should extract iota constants"
    );

    let names: Vec<&str> = output.entities.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"Shape"), "Should find interface Shape");
    assert!(names.contains(&"Circle"), "Should find struct Circle");
    assert!(names.contains(&"Divide"), "Should find func Divide");
    assert!(
        names.iter().any(|n| n.contains("Circle.Area")),
        "Should find method Circle.Area"
    );
}

#[test]
fn edge_case_rust_extracts_traits_enums_generics_impls() {
    let adapter = RustAdapter;
    let source = load_fixture("rust", "edge_cases.rs");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| output.entities.iter().filter(|e| e.kind == kind).count();

    // Should extract: Container (struct), Shape (enum), Processor (trait)
    assert!(
        by_kind(kin_model::EntityKind::Class) >= 1,
        "Rust should extract struct Container"
    );
    assert!(
        by_kind(kin_model::EntityKind::EnumDef) >= 1,
        "Rust should extract enum Shape"
    );
    assert!(
        by_kind(kin_model::EntityKind::TraitDef) >= 1,
        "Rust should extract trait Processor"
    );
    // Should extract: longest, serialize_map, fetch_data (functions)
    assert!(
        by_kind(kin_model::EntityKind::Function) >= 2,
        "Rust should extract standalone functions"
    );
    // Should extract: MAX_RETRIES (const), COUNTER (static)
    assert!(
        by_kind(kin_model::EntityKind::Constant) >= 1,
        "Rust should extract const items"
    );
    // Should extract Module: utils
    assert!(
        by_kind(kin_model::EntityKind::Module) >= 1,
        "Rust should extract mod items"
    );

    // Check trait impl relation: Container implements Display
    let impls: Vec<_> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Implements)
        .collect();
    // At minimum Container -> Display should be detected
    assert!(
        !impls.is_empty(),
        "Rust should detect trait impl relations, found none"
    );
}

#[test]
fn edge_case_python_extracts_decorators_inheritance_async() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "edge_cases.py");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| output.entities.iter().filter(|e| e.kind == kind).count();

    // Should extract: Shape, Circle, Rectangle, Drawable, DrawableCircle,
    // ShapeFactory, ShapeContext (classes)
    assert!(
        by_kind(kin_model::EntityKind::Class) >= 5,
        "Python should extract all class definitions including ABC, dataclass, Protocol"
    );
    // Should extract: fetch_shapes, sort_by_area, shape_areas (functions)
    assert!(
        by_kind(kin_model::EntityKind::Function) >= 2,
        "Python should extract standalone functions"
    );
    // Should extract methods: area, perimeter, description, unit, from_diameter, etc.
    assert!(
        by_kind(kin_model::EntityKind::Method) >= 5,
        "Python should extract methods from classes"
    );

    // Check inheritance: Circle extends Shape, DrawableCircle extends Circle
    let extends: Vec<_> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Extends)
        .collect();
    assert!(
        extends.len() >= 2,
        "Python should detect extends relations from inheritance, found {}",
        extends.len()
    );
}

#[test]
fn python_resolves_attribute_calls_as_method_name() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "calls.py");
    let output = parse_fixture(&adapter, &source);

    let call_dsts: Vec<&str> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .map(|r| r.dst_name.as_str())
        .collect();

    assert!(
        call_dsts.contains(&"add_url_rule"),
        "Python should resolve attribute call to bare method name, got dst_names: {:?}",
        call_dsts
    );
    assert!(
        !call_dsts.contains(&"app.add_url_rule"),
        "Python should NOT emit qualified attribute path as Calls dst, got dst_names: {:?}",
        call_dsts
    );
}

#[test]
fn python_self_calls_qualify_with_enclosing_class() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "calls.py");
    let output = parse_fixture(&adapter, &source);

    let call_dsts: Vec<&str> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .map(|r| r.dst_name.as_str())
        .collect();

    // A self-receiver dispatches through the enclosing class, so the callee is
    // emitted class-qualified — the key the linker's inheritance walk resolves.
    assert!(
        call_dsts.contains(&"Service.validate"),
        "Python should emit self.validate() as the class-qualified 'Service.validate', got: {:?}",
        call_dsts
    );
    assert!(
        !call_dsts.contains(&"self.validate"),
        "Python should NOT emit self-qualified path as Calls dst, got: {:?}",
        call_dsts
    );
}

#[test]
fn python_chained_calls_extract_method_names() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "calls.py");
    let output = parse_fixture(&adapter, &source);

    let call_dsts: Vec<&str> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .map(|r| r.dst_name.as_str())
        .collect();

    assert!(
        call_dsts.contains(&"query"),
        "Python should extract 'query' from chained call db.session.query(), got: {:?}",
        call_dsts
    );
    assert!(
        call_dsts.contains(&"all"),
        "Python should extract 'all' from chained call .all(), got: {:?}",
        call_dsts
    );
}

#[test]
fn python_decorator_emits_calls_edge_simple_name() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "calls.py");
    let output = parse_fixture(&adapter, &source);

    let calls: Vec<_> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .collect();

    assert!(
        calls.iter().any(|r| r.src_name == "protected" && r.dst_name == "requires_auth"),
        "Python should emit Calls edge from 'protected' to 'requires_auth' for @requires_auth, got: {:?}",
        calls.iter().map(|r| (r.src_name.as_str(), r.dst_name.as_str())).collect::<Vec<_>>()
    );
}

#[test]
fn python_decorator_extracts_attribute_name_not_dotted() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "calls.py");
    let output = parse_fixture(&adapter, &source);

    let calls: Vec<_> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .collect();

    assert!(
        calls
            .iter()
            .any(|r| r.src_name == "home" && r.dst_name == "route"),
        "Python should emit Calls edge from 'home' to bare 'route' for @app.route, got: {:?}",
        calls
            .iter()
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(
        !calls.iter().any(|r| r.dst_name == "app.route"),
        "Python should NOT emit 'app.route' as a Calls dst for decorator, got: {:?}",
        calls
            .iter()
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn python_stacked_decorators_all_emit_edges() {
    let adapter = PythonAdapter;
    let source = load_fixture("python", "calls.py");
    let output = parse_fixture(&adapter, &source);

    let api_calls: Vec<&str> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Calls && r.src_name == "api_endpoint")
        .map(|r| r.dst_name.as_str())
        .collect();

    assert!(
        api_calls.contains(&"route"),
        "Python stacked decorator @app.route should emit Calls edge from api_endpoint to 'route', got: {:?}",
        api_calls
    );
    assert!(
        api_calls.contains(&"requires_auth"),
        "Python stacked decorator @requires_auth should emit Calls edge from api_endpoint to 'requires_auth', got: {:?}",
        api_calls
    );
}

#[test]
fn edge_case_java_extracts_generics_enums_inner_classes() {
    let adapter = JavaAdapter;
    let source = load_fixture("java", "EdgeCases.java");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| output.entities.iter().filter(|e| e.kind == kind).count();

    // Should extract: Shape (interface), AbstractShape, Circle, Container, Processor (classes)
    assert!(
        by_kind(kin_model::EntityKind::Interface) >= 1,
        "Java should extract Shape interface"
    );
    assert!(
        by_kind(kin_model::EntityKind::Class) >= 3,
        "Java should extract concrete classes"
    );
    // Should extract: Color (enum)
    assert!(
        by_kind(kin_model::EntityKind::EnumDef) >= 1,
        "Java should extract enum Color"
    );
    // Should extract methods: area, perimeter, describe, getColor, getHex, etc.
    assert!(
        by_kind(kin_model::EntityKind::Method) >= 5,
        "Java should extract methods from classes and interfaces"
    );

    // Check implements and extends
    let implements: Vec<_> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Implements)
        .collect();
    assert!(
        !implements.is_empty(),
        "Java should detect implements relations"
    );

    let extends: Vec<_> = output
        .relations
        .iter()
        .filter(|r| r.kind == kin_model::RelationKind::Extends)
        .collect();
    assert!(!extends.is_empty(), "Java should detect extends relations");
}

#[test]
fn edge_case_typescript_extracts_generics_enums_namespaces() {
    let adapter = TypeScriptAdapter;
    let source = load_fixture("typescript", "edge_cases.ts");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| output.entities.iter().filter(|e| e.kind == kind).count();

    // Should extract: Repository (interface), BaseEntity, User, InMemoryRepository (classes)
    assert!(
        by_kind(kin_model::EntityKind::Interface) >= 1,
        "TS should extract generic interface Repository"
    );
    assert!(
        by_kind(kin_model::EntityKind::Class) >= 2,
        "TS should extract classes"
    );
    // Should extract: UserRole (enum)
    assert!(
        by_kind(kin_model::EntityKind::EnumDef) >= 1,
        "TS should extract string enum UserRole"
    );
    // Should extract: isAdmin, withRetry (functions)
    assert!(
        by_kind(kin_model::EntityKind::Function) >= 2,
        "TS should extract exported functions"
    );
}

#[test]
fn edge_case_javascript_extracts_generators_classes_closures() {
    let adapter = JavaScriptAdapter;
    let source = load_fixture("javascript", "edge_cases.js");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| output.entities.iter().filter(|e| e.kind == kind).count();

    // Should extract: Store (class)
    assert!(
        by_kind(kin_model::EntityKind::Class) >= 1,
        "JS should extract class Store"
    );
    // Should extract: range, fetchPages, createCounter, createApp (functions)
    assert!(
        by_kind(kin_model::EntityKind::Function) >= 2,
        "JS should extract function declarations including generators"
    );

    let names: Vec<&str> = output.entities.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"Store"), "Should find class Store");
}
