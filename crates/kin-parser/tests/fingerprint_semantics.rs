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
use kin_parser::{CppAdapter, GoAdapter, LanguageAdapter, PythonAdapter, RustAdapter};

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
