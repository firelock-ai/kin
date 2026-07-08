// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end ingest proof for the behavior-equivalence class (FIR-1435).
//!
//! Drives the real indexing pipeline (parse -> extract -> attach) and asserts
//! that the graph-owned `EQUIVALENCE_CLASS_KEY` metadata is docstring-insensitive
//! but changes on a genuine behavior change. This is the ingest half of the
//! capability; the review-consumption half is covered by kin-review's inline
//! tests. The full corpus reproof (fresh graphs over the benign-60 rows) is
//! founder-gated and lives outside this crate.

use kin_index::{IndexPipeline, EQUIVALENCE_CLASS_KEY};
use kin_model::{FilePathId, Hash256};

/// Ingest `source` through the real pipeline and return the equivalence class
/// attached to `entity`, if any.
fn ingest_equivalence_class(source: &str, entity: &str) -> Option<String> {
    let pipeline = IndexPipeline::new();
    let file_id = FilePathId::new("pkg/mod.py");
    let indexed = pipeline
        .index_file_content_with_tests(&file_id, source.as_bytes(), Hash256::from_bytes([0; 32]))
        .expect("indexing should succeed")
        .indexed_file;
    indexed
        .entities
        .iter()
        .find(|e| e.name == entity)
        .and_then(|e| e.metadata.extra.get(EQUIVALENCE_CLASS_KEY))
        .and_then(|v| v.as_str().map(str::to_string))
}

#[test]
fn ingest_attaches_equivalence_class_to_python_entities() {
    let class =
        ingest_equivalence_class("def f(a, b):\n    return a + b\n", "f").expect("class attached");
    assert!(
        !class.is_empty(),
        "a Python entity must carry a behavior-equivalence class after ingest"
    );
}

#[test]
fn ingest_class_is_stable_across_function_docstring_edit() {
    // Mirrors sphinx 42841b7f69: a docstring-only edit is behavior-preserving.
    let with_doc =
        "def terminal_safe(s):\n    \"\"\"safely encode a string.\"\"\"\n    return s.encode('ascii')\n";
    let edited_doc =
        "def terminal_safe(s):\n    \"\"\"Safely encode a string.\"\"\"\n    return s.encode('ascii')\n";
    let no_doc = "def terminal_safe(s):\n    return s.encode('ascii')\n";
    let a = ingest_equivalence_class(with_doc, "terminal_safe").expect("class attached");
    let b = ingest_equivalence_class(edited_doc, "terminal_safe").expect("class attached");
    let c = ingest_equivalence_class(no_doc, "terminal_safe").expect("class attached");
    assert_eq!(a, b, "editing a docstring must not change the equivalence class");
    assert_eq!(a, c, "removing a docstring must not change the equivalence class");
}

#[test]
fn ingest_class_is_stable_across_method_docstring_removal_in_class() {
    // Mirrors django 4f8bc75bc3: the class fingerprint must also be
    // docstring-insensitive when the docstring lives inside a method.
    let with_doc =
        "class WhereNode:\n    def clone(self):\n        \"\"\"Create a clone of the tree.\"\"\"\n        return self.copy()\n";
    let without_doc =
        "class WhereNode:\n    def clone(self):\n        return self.copy()\n";
    let a = ingest_equivalence_class(with_doc, "WhereNode").expect("class attached");
    let b = ingest_equivalence_class(without_doc, "WhereNode").expect("class attached");
    assert_eq!(
        a, b,
        "a docstring removed inside a method must not change the class equivalence class"
    );
}

#[test]
fn ingest_class_changes_on_real_behavior_change() {
    // Protected true positive: an operator change must alter the class.
    let plus = ingest_equivalence_class("def total(a, b):\n    return a + b\n", "total")
        .expect("class attached");
    let minus = ingest_equivalence_class("def total(a, b):\n    return a - b\n", "total")
        .expect("class attached");
    assert_ne!(
        plus, minus,
        "an operator change must yield a different ingest-attached equivalence class"
    );
}

#[test]
fn ingest_does_not_attach_class_for_non_participating_language() {
    // JavaScript does not participate (bare strings can be directives), so no
    // class is attached — the review layer then treats it as unknown and never
    // downgrades.
    let class = ingest_equivalence_class_js("function f() { return work(); }", "f");
    assert!(
        class.is_none(),
        "a non-participating language must not carry an equivalence class"
    );
}

/// Ingest a JavaScript source and return the equivalence class, if any.
fn ingest_equivalence_class_js(source: &str, entity: &str) -> Option<String> {
    let pipeline = IndexPipeline::new();
    let file_id = FilePathId::new("pkg/mod.js");
    let indexed = pipeline
        .index_file_content_with_tests(&file_id, source.as_bytes(), Hash256::from_bytes([0; 32]))
        .expect("indexing should succeed")
        .indexed_file;
    indexed
        .entities
        .iter()
        .find(|e| e.name == entity)
        .and_then(|e| e.metadata.extra.get(EQUIVALENCE_CLASS_KEY))
        .and_then(|v| v.as_str().map(str::to_string))
}
