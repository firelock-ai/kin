// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end ingest proof for the behavior-equivalence class.
//!
//! Drives the real indexing pipeline (parse -> extract -> attach) and asserts
//! that the graph-owned `SemanticFingerprint.equivalence_hash` is docstring-
//! insensitive but changes on a genuine behavior change. This is the ingest half
//! of the capability; the review-consumption half is covered by kin-review's
//! inline tests. The full corpus reproof (fresh graphs over the benign-60 rows)
//! is founder-gated and lives outside this crate.

use kin_index::IndexPipeline;
use kin_model::{FilePathId, Hash256};

fn zero() -> Hash256 {
    Hash256::from_bytes([0; 32])
}

/// Ingest `source` through the real pipeline and return the equivalence hash
/// attached to `entity`. The zero hash means "not computed".
fn ingest_equivalence_hash(source: &str, entity: &str, ext: &str) -> Hash256 {
    let pipeline = IndexPipeline::new();
    let file_id = FilePathId::new(format!("pkg/mod.{ext}"));
    let indexed = pipeline
        .index_file_content_with_tests(
            &file_id,
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .expect("indexing should succeed")
        .indexed_file;
    indexed
        .entities
        .iter()
        .find(|e| e.name == entity)
        .map(|e| e.fingerprint.equivalence_hash)
        .unwrap_or_else(|| panic!("entity '{entity}' not found"))
}

fn py(source: &str, entity: &str) -> Hash256 {
    ingest_equivalence_hash(source, entity, "py")
}

#[test]
fn ingest_attaches_equivalence_hash_to_python_entities() {
    let h = py("def f(a, b):\n    return a + b\n", "f");
    assert_ne!(
        h,
        zero(),
        "a Python entity must carry a computed behavior-equivalence hash after ingest"
    );
}

#[test]
fn ingest_hash_is_stable_across_function_docstring_edit() {
    // Mirrors sphinx 42841b7f69: a docstring-only edit is behavior-preserving.
    let with_doc =
        "def terminal_safe(s):\n    \"\"\"safely encode a string.\"\"\"\n    return s.encode('ascii')\n";
    let edited_doc =
        "def terminal_safe(s):\n    \"\"\"Safely encode a string.\"\"\"\n    return s.encode('ascii')\n";
    let no_doc = "def terminal_safe(s):\n    return s.encode('ascii')\n";
    let a = py(with_doc, "terminal_safe");
    assert_eq!(
        a,
        py(edited_doc, "terminal_safe"),
        "editing a docstring must not change the hash"
    );
    assert_eq!(
        a,
        py(no_doc, "terminal_safe"),
        "removing a docstring must not change the hash"
    );
}

#[test]
fn ingest_hash_is_stable_across_method_docstring_removal_in_class() {
    // Mirrors django 4f8bc75bc3: the class fingerprint must also be
    // docstring-insensitive when the docstring lives inside a method.
    let with_doc =
        "class WhereNode:\n    def clone(self):\n        \"\"\"Create a clone of the tree.\"\"\"\n        return self.copy()\n";
    let without_doc = "class WhereNode:\n    def clone(self):\n        return self.copy()\n";
    assert_eq!(
        py(with_doc, "WhereNode"),
        py(without_doc, "WhereNode"),
        "a docstring removed inside a method must not change the class hash"
    );
}

#[test]
fn ingest_hash_changes_on_real_behavior_change() {
    // Protected true positive: an operator change must alter the hash.
    assert_ne!(
        py("def total(a, b):\n    return a + b\n", "total"),
        py("def total(a, b):\n    return a - b\n", "total"),
        "an operator change must yield a different ingest-attached hash"
    );
}

#[test]
fn ingest_leaves_zero_sentinel_for_non_participating_language() {
    // JavaScript does not participate (bare strings can be directives), so the
    // hash stays the zero sentinel; the review layer then treats it as unknown
    // and never downgrades.
    let h = ingest_equivalence_hash("function f() { return work(); }", "f", "js");
    assert_eq!(
        h,
        zero(),
        "a non-participating language must keep the zero-hash sentinel"
    );
}
