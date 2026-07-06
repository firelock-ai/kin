// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression tests for fingerprint semantics.
//!
//! `compute_fingerprint` must produce identical fingerprints across
//! comment-only and formatting-only edits (comments are grammar `extra`
//! nodes; inter-token whitespace never reaches the tree), while staying
//! sensitive to token changes and to structure moves that reuse the same
//! token text. Raw-byte hashing violated this: a deleted comment or a
//! reformat registered as a behavior change and fed false "behavior of X
//! changed" evidence to review gates.

use kin_model::{FilePathId, Hash256};
use kin_parser::{
    CAdapter, CSharpAdapter, CppAdapter, GoAdapter, JavaAdapter, JavaScriptAdapter, KotlinAdapter,
    LanguageAdapter, PhpAdapter, PythonAdapter, RubyAdapter, RustAdapter, SwiftAdapter,
    TypeScriptAdapter,
};

fn entity_hashes(
    adapter: &dyn LanguageAdapter,
    source: &str,
    name: &str,
) -> (Hash256, Hash256, Hash256) {
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    let file_id = FilePathId(format!("test/fp.{}", adapter.file_extensions()[0]));
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("extract should succeed");
    let entity = output
        .entities
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| {
            panic!(
                "entity '{}' not found; have: {:?}",
                name,
                output.entities.iter().map(|e| &e.name).collect::<Vec<_>>()
            )
        });
    (
        entity.fingerprint.ast_hash,
        entity.fingerprint.signature_hash,
        entity.fingerprint.behavior_hash,
    )
}

#[test]
fn go_comment_only_edit_keeps_fingerprint() {
    let with_comment = r#"
package config

type AuthConfig struct{}

func (c *AuthConfig) HasEnvToken() bool {
    // This will check the token in the environment.
    // It mirrors the lookup order used at auth time.
    return len(envToken()) > 0
}
"#;
    let without_comment = r#"
package config

type AuthConfig struct{}

func (c *AuthConfig) HasEnvToken() bool {
    return len(envToken()) > 0
}
"#;
    let adapter = GoAdapter;
    let a = entity_hashes(&adapter, with_comment, "AuthConfig.HasEnvToken");
    let b = entity_hashes(&adapter, without_comment, "AuthConfig.HasEnvToken");
    assert_eq!(
        a, b,
        "comment-only edit must not change any fingerprint hash"
    );
}

#[test]
fn cpp_whitespace_only_edit_keeps_fingerprint() {
    let formatted = r#"
int add(int a, int b) {
    return a + b;
}
"#;
    let compact = r#"
int add(int a,int b){return a+b;}
"#;
    let adapter = CppAdapter;
    let a = entity_hashes(&adapter, formatted, "add");
    let b = entity_hashes(&adapter, compact, "add");
    assert_eq!(
        a, b,
        "whitespace-only edit must not change any fingerprint hash"
    );
}

#[test]
fn cpp_member_comment_keeps_class_fingerprint() {
    let with_comment = r#"
class Widget {
public:
    // Rebuilds the cached layout.
    void refresh();
    int size() const;
};
"#;
    let without_comment = r#"
class Widget {
public:
    void refresh();
    int size() const;
};
"#;
    let adapter = CppAdapter;
    let a = entity_hashes(&adapter, with_comment, "Widget");
    let b = entity_hashes(&adapter, without_comment, "Widget");
    assert_eq!(a, b, "member comment must not change the class fingerprint");
}

#[test]
fn rust_token_change_alters_behavior_hash_only() {
    let plus = "fn total(a: i32, b: i32) -> i32 { a + b }";
    let minus = "fn total(a: i32, b: i32) -> i32 { a - b }";
    let adapter = RustAdapter;
    let (ast_a, sig_a, beh_a) = entity_hashes(&adapter, plus, "total");
    let (ast_b, sig_b, beh_b) = entity_hashes(&adapter, minus, "total");
    assert_eq!(ast_a, ast_b, "operator swap keeps the AST shape");
    assert_eq!(sig_a, sig_b, "operator swap keeps the signature");
    assert_ne!(beh_a, beh_b, "operator swap must alter the behavior hash");
}

#[test]
fn rust_comment_only_edit_keeps_fingerprint() {
    let with_comment = r#"
fn total(a: i32, b: i32) -> i32 {
    // Sum the operands.
    a + b
}
"#;
    let without_comment = r#"
fn total(a: i32, b: i32) -> i32 {
    a + b
}
"#;
    let adapter = RustAdapter;
    let a = entity_hashes(&adapter, with_comment, "total");
    let b = entity_hashes(&adapter, without_comment, "total");
    assert_eq!(
        a, b,
        "comment-only edit must not change any fingerprint hash"
    );
}

#[test]
fn python_block_move_alters_behavior_hash() {
    let outside = r#"
def guard(x):
    if x:
        prepare()
    launch()
"#;
    let inside = r#"
def guard(x):
    if x:
        prepare()
        launch()
"#;
    let adapter = PythonAdapter;
    let (_, _, beh_a) = entity_hashes(&adapter, outside, "guard");
    let (_, _, beh_b) = entity_hashes(&adapter, inside, "guard");
    assert_ne!(
        beh_a, beh_b,
        "moving a statement between blocks reuses the same tokens but must alter the behavior hash"
    );
}

#[test]
fn cpp_multiline_declarator_keeps_signature_string() {
    let single_line = r#"
class ArgParser {
public:
    ArgParser( int argc, char* const argv[], Config& config )
    : m_mode( modeNone )
    {
        parse();
    }
};
"#;
    let multi_line = r#"
class ArgParser {
public:
    ArgParser
    (   int argc, char* const argv[], Config& config )
    :   m_mode( modeNone )
    {
        parse();
    }
};
"#;
    let adapter = CppAdapter;
    let sig = |src: &str| {
        let bytes = src.as_bytes();
        let tree = adapter.parse(bytes).expect("parse should succeed");
        let file_id = FilePathId("test/sig.hpp".to_string());
        let output = adapter
            .extract(&tree, bytes, &file_id)
            .expect("extract should succeed");
        output
            .entities
            .iter()
            .find(|e| e.name == "ArgParser::ArgParser")
            .map(|e| e.signature.clone())
            .expect("constructor entity")
    };
    let a = sig(single_line);
    let b = sig(multi_line);
    assert_eq!(
        a, b,
        "line wrapping must not change the extracted signature string"
    );
    assert!(
        a.contains("int argc"),
        "signature must carry the parameter list, got: {a}"
    );
    assert!(
        !a.contains("m_mode"),
        "member-initializer list must not leak into the signature, got: {a}"
    );
}

// ---------------------------------------------------------------------------
// Cosmetic-stability matrix (FIR-1313): extend the comment-only + whitespace-
// only invariant to every full-adapter language not covered above. Go, C++,
// Rust, and Python are already exercised earlier in this file; the block below
// adds TypeScript, JavaScript, Java, C, C#, Ruby, PHP, Kotlin, and Swift. All
// are GREEN — `compute_fingerprint` is shared and skips comment `extra` nodes
// and inter-token whitespace, so every adapter inherits the invariant.
// ---------------------------------------------------------------------------

/// A comment-only edit and a whitespace-only reformat must each leave all three
/// fingerprint hashes of `name` unchanged.
fn assert_cosmetic_stable(
    adapter: &dyn LanguageAdapter,
    name: &str,
    base: &str,
    comment_only: &str,
    whitespace_only: &str,
) {
    let b = entity_hashes(adapter, base, name);
    assert_eq!(
        b,
        entity_hashes(adapter, comment_only, name),
        "comment-only edit must not change any fingerprint hash ({name})"
    );
    assert_eq!(
        b,
        entity_hashes(adapter, whitespace_only, name),
        "whitespace-only edit must not change any fingerprint hash ({name})"
    );
}

#[test]
fn typescript_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &TypeScriptAdapter,
        "total",
        "function total(a: number, b: number): number { return a + b; }",
        "function total(a: number, b: number): number {\n  // sum them\n  return a + b;\n}",
        "function total(a:number,b:number):number{return a+b;}",
    );
}

#[test]
fn javascript_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &JavaScriptAdapter,
        "total",
        "function total(a, b) { return a + b; }",
        "function total(a, b) {\n  // sum them\n  return a + b;\n}",
        "function total(a,b){return a+b;}",
    );
}

#[test]
fn java_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &JavaAdapter,
        "C.total",
        "class C { int total(int a, int b) { return a + b; } }",
        "class C { int total(int a, int b) {\n    // sum them\n    return a + b; } }",
        "class C{int total(int a,int b){return a+b;}}",
    );
}

#[test]
fn c_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &CAdapter,
        "total",
        "int total(int a, int b) { return a + b; }",
        "int total(int a, int b) {\n    /* sum them */\n    return a + b;\n}",
        "int total(int a,int b){return a+b;}",
    );
}

#[test]
fn csharp_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &CSharpAdapter,
        "N.C.Total",
        "namespace N { class C { int Total(int a, int b) { return a + b; } } }",
        "namespace N { class C { int Total(int a, int b) {\n    // sum them\n    return a + b; } } }",
        "namespace N{class C{int Total(int a,int b){return a+b;}}}",
    );
}

#[test]
fn ruby_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &RubyAdapter,
        "C.total",
        "class C\n    def total(a, b)\n        a + b\n    end\nend\n",
        "class C\n    def total(a, b)\n        # sum them\n        a + b\n    end\nend\n",
        "class C\n  def total(a,b)\n    a + b\n  end\nend\n",
    );
}

#[test]
fn php_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &PhpAdapter,
        "total",
        "<?php\nfunction total($a, $b) { return $a + $b; }\n",
        "<?php\nfunction total($a, $b) {\n    // sum them\n    return $a + $b;\n}\n",
        "<?php\nfunction total($a,$b){return $a+$b;}\n",
    );
}

#[test]
fn kotlin_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &KotlinAdapter,
        "total",
        "fun total(a: Int, b: Int): Int { return a + b }",
        "fun total(a: Int, b: Int): Int {\n    // sum them\n    return a + b\n}",
        "fun total(a:Int,b:Int):Int{return a+b}",
    );
}

#[test]
fn swift_cosmetic_edits_keep_fingerprint() {
    assert_cosmetic_stable(
        &SwiftAdapter,
        "total",
        "func total(a: Int, b: Int) -> Int { return a + b }",
        "func total(a: Int, b: Int) -> Int {\n    // sum them\n    return a + b\n}",
        "func total(a:Int,b:Int)->Int{return a+b}",
    );
}
