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
use kin_parser::{
    AdapterRegistry, GoAdapter, JavaAdapter, JavaScriptAdapter, LanguageAdapter, ParseOutput,
    PythonAdapter, RustAdapter, TypeScriptAdapter,
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

// ---- Registry conformance ----

#[test]
fn conformance_registry_covers_all_extensions() {
    let registry = AdapterRegistry::new();

    let expected_extensions = vec!["ts", "tsx", "js", "jsx", "py", "go", "java", "rs"];

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
