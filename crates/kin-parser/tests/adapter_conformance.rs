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
use kin_parser::{
    AdapterRegistry, CAdapter, CSharpAdapter, CppAdapter, GoAdapter, JavaAdapter,
    JavaScriptAdapter, LanguageAdapter, ParseOutput, PythonAdapter, RubyAdapter, RustAdapter,
    TypeScriptAdapter,
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
        ("c", b"int hello(void) { return 1; }"),
        ("cpp", b"class Hello {}; int greet() { return 1; }"),
        ("csharp", b"public class Hello { public void Greet() {} }"),
        ("ruby", b"class Hello\n  def greet\n  end\nend\n"),
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

    let expected_extensions = vec![
        "ts", "tsx", "js", "jsx", "py", "go", "java", "rs", "c", "h", "cpp", "hpp", "cc", "cxx",
        "cs", "rb",
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

    let by_kind = |kind| {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    };

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

    let by_kind = |kind| {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    };

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

    let by_kind = |kind| {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    };

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
fn edge_case_java_extracts_generics_enums_inner_classes() {
    let adapter = JavaAdapter;
    let source = load_fixture("java", "EdgeCases.java");
    let output = parse_fixture(&adapter, &source);

    let by_kind = |kind| {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    };

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

    let by_kind = |kind| {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    };

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

    let by_kind = |kind| {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .count()
    };

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
