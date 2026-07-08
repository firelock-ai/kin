// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::ids::LanguageId;
use kin_model::{FingerprintAlgorithm, Hash256, SemanticFingerprint};
use sha2::{Digest, Sha256};
use tree_sitter::Node;

/// Metadata key under which the behavior-equivalence class of an entity is
/// stored on `Entity.metadata.extra`. Present only for entities whose language
/// participates in the equivalence relation; absent entries assert nothing.
pub const EQUIVALENCE_CLASS_KEY: &str = "kin.behavior_equivalence_class";

/// Compute a SemanticFingerprint from source text and a signature string.
///
/// This operates at the entity level (post-extraction), complementing the
/// tree-sitter node-level fingerprint in kin-parser. It normalizes the source
/// before hashing so that whitespace and comment changes do not alter the
/// fingerprint.
pub fn compute_entity_fingerprint(source: &str, signature: &str) -> SemanticFingerprint {
    let normalized = normalize_source(source);

    // AST hash: hash the normalized source (approximates structure without comments/whitespace)
    let ast_hash = hash_bytes(normalized.as_bytes());

    // Signature hash: hash just the signature line
    let signature_hash = hash_bytes(signature.as_bytes());

    // Behavior hash: hash the full source including whitespace (exact content)
    let behavior_hash = hash_bytes(source.as_bytes());

    SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash,
        signature_hash,
        behavior_hash,
        stability_score: compute_stability(source),
    }
}

/// Normalize source text by stripping comments, collapsing whitespace, and
/// removing blank lines. This makes the fingerprint stable across formatting
/// changes while still being sensitive to structural changes.
fn normalize_source(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut in_block_comment = false;

    for line in source.lines() {
        let trimmed = line.trim();

        // Handle block comments
        if in_block_comment {
            if let Some(pos) = trimmed.find("*/") {
                in_block_comment = false;
                let after = trimmed[pos + 2..].trim();
                if !after.is_empty() {
                    result.push_str(after);
                    result.push('\n');
                }
            }
            continue;
        }

        // Skip line comments
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // Handle start of block comment
        if let Some(pos) = trimmed.find("/*") {
            let before = trimmed[..pos].trim();
            if let Some(end_pos) = trimmed[pos..].find("*/") {
                // Single-line block comment: join before + after
                let after = trimmed[pos + end_pos + 2..].trim();
                let combined = match (before.is_empty(), after.is_empty()) {
                    (true, true) => String::new(),
                    (true, false) => after.to_string(),
                    (false, true) => before.to_string(),
                    (false, false) => format!("{} {}", before, after),
                };
                if !combined.is_empty() {
                    result.push_str(&combined);
                    result.push('\n');
                }
            } else {
                // Multi-line block comment starts here
                if !before.is_empty() {
                    result.push_str(before);
                    result.push('\n');
                }
                in_block_comment = true;
            }
            continue;
        }

        // Skip empty lines
        if trimmed.is_empty() {
            continue;
        }

        // Collapse internal whitespace
        let collapsed: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
        result.push_str(&collapsed);
        result.push('\n');
    }

    result
}

/// Compute a stability score based on source characteristics.
/// Longer, more complex entities get a slightly lower score since they are
/// more likely to change.
fn compute_stability(source: &str) -> f32 {
    let lines = source.lines().count();
    if lines <= 5 {
        1.0
    } else if lines <= 20 {
        0.9
    } else if lines <= 50 {
        0.8
    } else {
        0.7
    }
}

fn hash_bytes(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    finalize_hash(hasher)
}

fn finalize_hash(hasher: Sha256) -> Hash256 {
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256::from_bytes(bytes)
}

/// Behavior-equivalence hash of a parsed entity node.
///
/// Produces a canonical token-stream digest that is INSENSITIVE to comments,
/// formatting, and pure-no-op string statements (Python docstrings), but
/// SENSITIVE to every operator, constant, identifier, call target, literal
/// value, and structural move. Two entity bodies whose hashes are EQUAL are
/// behavior-equivalent under this bounded, conservative relation; UNEQUAL
/// hashes assert nothing (may or may not be equivalent).
///
/// Soundness contract — the protected-true-positive guarantee: a change to any
/// operator, constant, non-docstring literal, call target, identifier, or
/// statement ordering ALWAYS changes the hash. Only edits that provably cannot
/// alter runtime behavior — comments, whitespace, and no-op string statements —
/// are normalized away. `unprovable == not equivalent`.
///
/// This is the graph-owned complement to `kin_parser::compute_fingerprint`'s
/// `behavior_hash`, which is already comment- and whitespace-insensitive but
/// still changes on a docstring edit; the equivalence hash removes exactly that
/// residual, behavior-irrelevant sensitivity and nothing more.
pub fn behavior_equivalence_hash(node: &Node, source: &[u8], language: LanguageId) -> Hash256 {
    let mut hasher = Sha256::new();
    hash_equivalence_stream(node, source, language, &mut hasher);
    finalize_hash(hasher)
}

/// Whether a language participates in behavior-equivalence normalization. When
/// false, `behavior_equivalence_hash` is byte-for-byte the same digest as the
/// `behavior_hash` token stream, so the relation collapses to exact-body
/// equality — the safe default.
pub fn language_supports_equivalence(language: LanguageId) -> bool {
    // Conservative: only languages whose bare string statements are guaranteed
    // pure no-ops. Python docstrings qualify. JS/TS bare strings can be
    // directive prologues (`"use strict"`, `"use client"`) that change runtime
    // behavior, so they are intentionally excluded.
    matches!(language, LanguageId::Python)
}

/// Hash the semantic token stream of a subtree exactly as
/// `kin_parser::compute_fingerprint`'s behavior hash does — named-node
/// open/close markers plus every leaf token's kind and text, skipping `extra`
/// (comment) subtrees — with one added normalization: a pure-no-op string
/// statement (a Python docstring or any bare, non-interpolated string
/// expression statement) is dropped, because evaluating a string literal and
/// discarding it has no runtime effect.
fn hash_equivalence_stream(node: &Node, source: &[u8], language: LanguageId, hasher: &mut Sha256) {
    if node.is_extra() {
        return;
    }
    if is_pure_noop_string_statement(node, language) {
        return;
    }
    if node.child_count() == 0 {
        hasher.update(node.kind().as_bytes());
        hasher.update([0x1f]);
        hasher.update(node.utf8_text(source).unwrap_or("").as_bytes());
        hasher.update([0x1e]);
        return;
    }
    let named = node.is_named();
    if named {
        hasher.update(node.kind().as_bytes());
        hasher.update(b"(");
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        hash_equivalence_stream(&child, source, language, hasher);
    }
    if named {
        hasher.update(b")");
    }
}

/// True for a statement that evaluates a single string literal and discards the
/// result: a Python docstring, or any bare string-literal expression statement.
/// Such a statement has no observable runtime effect, so adding, removing, or
/// editing it is behavior-preserving.
///
/// Guards that keep this sound:
/// - restricted to languages whose bare string statements are pure no-ops
///   ([`language_supports_equivalence`]); every other language returns false,
/// - the statement's only named child must be a string (or a concatenation of
///   string literals), never an assignment/return/call that merely contains a
///   string, and
/// - interpolated strings (f-strings) are never treated as no-ops, because
///   their embedded expressions can have side effects.
fn is_pure_noop_string_statement(node: &Node, language: LanguageId) -> bool {
    if !language_supports_equivalence(language) {
        return false;
    }
    if node.kind() != "expression_statement" {
        return false;
    }
    let mut cursor = node.walk();
    let mut named_children = node
        .children(&mut cursor)
        .filter(|c| c.is_named() && !c.is_extra());
    let Some(only) = named_children.next() else {
        return false;
    };
    if named_children.next().is_some() {
        return false;
    }
    matches!(only.kind(), "string" | "concatenated_string") && !subtree_has_interpolation(&only)
}

/// Whether any node in the subtree is a string interpolation (f-string field).
fn subtree_has_interpolation(node: &Node) -> bool {
    if node.kind() == "interpolation" {
        return true;
    }
    let mut cursor = node.walk();
    let has = node
        .children(&mut cursor)
        .any(|child| subtree_has_interpolation(&child));
    has
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        assert_eq!(fp1.ast_hash, fp2.ast_hash);
        assert_eq!(fp1.signature_hash, fp2.signature_hash);
        assert_eq!(fp1.behavior_hash, fp2.behavior_hash);
    }

    #[test]
    fn whitespace_changes_do_not_affect_ast_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn  foo()  {  1  }", "fn foo()");
        assert_eq!(fp1.ast_hash, fp2.ast_hash);
        // But behavior hash differs since exact text changed
        assert_ne!(fp1.behavior_hash, fp2.behavior_hash);
    }

    #[test]
    fn comment_changes_do_not_affect_ast_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("// a comment\nfn foo() { 1 }", "fn foo()");
        assert_eq!(fp1.ast_hash, fp2.ast_hash);
    }

    #[test]
    fn different_signatures_produce_different_signature_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo(x: i32)");
        assert_ne!(fp1.signature_hash, fp2.signature_hash);
    }

    #[test]
    fn structural_change_affects_ast_hash() {
        let fp1 = compute_entity_fingerprint("fn foo() { 1 }", "fn foo()");
        let fp2 = compute_entity_fingerprint("fn foo() { bar(); 1 }", "fn foo()");
        assert_ne!(fp1.ast_hash, fp2.ast_hash);
    }

    #[test]
    fn stability_score_scales_with_size() {
        let small = compute_entity_fingerprint("fn x() { 1 }", "fn x()");
        let large_source = (0..60)
            .map(|i| format!("let x{i} = {i};"))
            .collect::<Vec<_>>()
            .join("\n");
        let large = compute_entity_fingerprint(&large_source, "fn big()");
        assert!(small.stability_score > large.stability_score);
    }

    #[test]
    fn normalize_strips_line_comments() {
        let result = normalize_source("// hello\nfn foo() {}\n// bye\n");
        assert_eq!(result, "fn foo() {}\n");
    }

    #[test]
    fn normalize_strips_block_comments() {
        let result = normalize_source("fn foo() /* comment */ {}\n");
        assert_eq!(result, "fn foo() {}\n");
    }

    #[test]
    fn normalize_strips_python_comments() {
        let result = normalize_source("# comment\ndef foo():\n    pass\n");
        assert_eq!(result, "def foo():\npass\n");
    }

    #[test]
    fn normalize_collapses_whitespace() {
        let result = normalize_source("fn   foo(  a:   i32  ) {}\n");
        assert_eq!(result, "fn foo( a: i32 ) {}\n");
    }
}

#[cfg(test)]
mod equivalence_tests {
    use super::behavior_equivalence_hash;
    use kin_model::{FilePathId, Hash256};
    use kin_parser::{
        JavaScriptAdapter, LanguageAdapter, PythonAdapter, RustAdapter, TypeScriptAdapter,
    };

    /// Behavior-equivalence hash of the named entity in `source`. Mirrors the
    /// real ingest path: parse, extract, then hash the entity's own AST node.
    fn equiv(adapter: &dyn LanguageAdapter, source: &str, name: &str) -> Hash256 {
        let bytes = source.as_bytes();
        let tree = adapter.parse(bytes).expect("parse should succeed");
        let file_id = FilePathId(format!("test/eq.{}", adapter.file_extensions()[0]));
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
        let span = &entity.span;
        let node = tree
            .root_node()
            .descendant_for_byte_range(span.start_byte, span.end_byte.saturating_sub(1))
            .expect("entity node should resolve from its span");
        behavior_equivalence_hash(&node, bytes, adapter.language_id())
    }

    // ---- Equivalence: behavior-preserving edits collapse to one class -------

    /// Removing a docstring (mirrors django 4f8bc75bc3 WhereNode.clone) is
    /// behavior-preserving: the method's equivalence class is unchanged.
    #[test]
    fn python_docstring_removal_is_equivalent() {
        let with_doc = "def clone(self):\n    \"\"\"Create a clone of the tree.\"\"\"\n    c = self.new()\n    return c\n";
        let without_doc = "def clone(self):\n    c = self.new()\n    return c\n";
        assert_eq!(
            equiv(&PythonAdapter, with_doc, "clone"),
            equiv(&PythonAdapter, without_doc, "clone"),
            "removing a docstring must not change the equivalence class"
        );
    }

    /// Editing docstring TEXT (mirrors sphinx 42841b7f69 terminal_safe casing
    /// `safely` -> `Safely`) is behavior-preserving.
    #[test]
    fn python_docstring_edit_is_equivalent() {
        let lower = "def terminal_safe(s):\n    \"\"\"safely encode a string.\"\"\"\n    return s.encode('ascii')\n";
        let upper = "def terminal_safe(s):\n    \"\"\"Safely encode a string.\"\"\"\n    return s.encode('ascii')\n";
        assert_eq!(
            equiv(&PythonAdapter, lower, "terminal_safe"),
            equiv(&PythonAdapter, upper, "terminal_safe"),
            "editing docstring text must not change the equivalence class"
        );
    }

    /// A method docstring removed inside a class leaves the CLASS equivalence
    /// class unchanged too (mirrors 4f8bc75bc3, whose row fires on both
    /// WhereNode and WhereNode.clone).
    #[test]
    fn python_class_method_docstring_removal_is_equivalent() {
        let with_doc = "class WhereNode:\n    def clone(self):\n        \"\"\"docs\"\"\"\n        return self.copy()\n";
        let without_doc = "class WhereNode:\n    def clone(self):\n        return self.copy()\n";
        assert_eq!(
            equiv(&PythonAdapter, with_doc, "WhereNode"),
            equiv(&PythonAdapter, without_doc, "WhereNode"),
            "a docstring removed inside a method must not change the class equivalence class"
        );
    }

    /// Comment-only and whitespace-only edits are already absorbed (comments are
    /// grammar `extra` nodes; whitespace never reaches the tree).
    #[test]
    fn python_comment_and_whitespace_are_equivalent() {
        let base = "def total(a, b):\n    return a + b\n";
        let commented = "def total(a, b):\n    # sum them\n    return a + b\n";
        let reformatted = "def total(a,b):\n        return a  +  b\n";
        let h = equiv(&PythonAdapter, base, "total");
        assert_eq!(h, equiv(&PythonAdapter, commented, "total"));
        assert_eq!(h, equiv(&PythonAdapter, reformatted, "total"));
    }

    // ---- Protected true positives: behavior changes must NEVER collapse -----

    /// Operator swap (`+` -> `-`) must change the equivalence class.
    #[test]
    fn python_operator_change_is_not_equivalent() {
        let plus = "def total(a, b):\n    return a + b\n";
        let minus = "def total(a, b):\n    return a - b\n";
        assert_ne!(
            equiv(&PythonAdapter, plus, "total"),
            equiv(&PythonAdapter, minus, "total"),
            "an operator change is a behavior change and must not be equivalent"
        );
    }

    /// Constant change must change the equivalence class.
    #[test]
    fn python_constant_change_is_not_equivalent() {
        let one = "def answer():\n    return 41\n";
        let two = "def answer():\n    return 42\n";
        assert_ne!(
            equiv(&PythonAdapter, one, "answer"),
            equiv(&PythonAdapter, two, "answer"),
            "a constant change is a behavior change and must not be equivalent"
        );
    }

    /// Adding a guard/raise (mirrors django f97a6123c0 and sphinx 883faaa568,
    /// the genuine behavior changes this fix must NOT flip) is not equivalent.
    #[test]
    fn python_added_raise_is_not_equivalent() {
        let before = "def safe_getattr(obj, name, *args):\n    return getattr(obj, name, *args)\n";
        let after = "def safe_getattr(obj, name, *args):\n    if len(args) > 1:\n        raise TypeError('too many')\n    return getattr(obj, name, *args)\n";
        assert_ne!(
            equiv(&PythonAdapter, before, "safe_getattr"),
            equiv(&PythonAdapter, after, "safe_getattr"),
            "adding a validation raise is a behavior change and must not be equivalent"
        );
    }

    /// A string used as a VALUE (not a bare statement) is behavior-relevant:
    /// changing an assigned/returned string literal must not be equivalent.
    #[test]
    fn python_string_value_change_is_not_equivalent() {
        let a = "def label():\n    x = \"alpha\"\n    return x\n";
        let b = "def label():\n    x = \"beta\"\n    return x\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "label"),
            equiv(&PythonAdapter, b, "label"),
            "a string assigned to a variable is a value, not a docstring, and must not be normalized"
        );
    }

    /// An f-string statement can have side effects in its interpolations, so it
    /// is never treated as a no-op: changing the interpolated call is a behavior
    /// change.
    #[test]
    fn python_fstring_statement_is_not_a_noop() {
        let a = "def emit():\n    f\"{log_a()}\"\n    return 1\n";
        let b = "def emit():\n    f\"{log_b()}\"\n    return 1\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "emit"),
            equiv(&PythonAdapter, b, "emit"),
            "an interpolated string statement has side effects and must not be normalized away"
        );
    }

    /// Statement reordering is a behavior change under this bounded relation —
    /// we do not attempt to prove commutativity.
    #[test]
    fn python_statement_reorder_is_not_equivalent() {
        let ab = "def run():\n    a()\n    b()\n";
        let ba = "def run():\n    b()\n    a()\n";
        assert_ne!(
            equiv(&PythonAdapter, ab, "run"),
            equiv(&PythonAdapter, ba, "run"),
            "statement reordering is not proven equivalent (conservative)"
        );
    }

    /// A JavaScript bare string statement is a directive prologue candidate
    /// (`\"use strict\"`), so JS never participates: adding it is NOT equivalent.
    /// This guards against the unsound generalization of Python's docstring rule.
    #[test]
    fn javascript_use_strict_is_not_normalized() {
        let without = "function f() { return work(); }";
        let with = "function f() { \"use strict\"; return work(); }";
        assert_ne!(
            equiv(&JavaScriptAdapter, without, "f"),
            equiv(&JavaScriptAdapter, with, "f"),
            "a JS bare string statement can be a directive and must not be normalized away"
        );
    }

    // ---- Conservative boundaries (documented Tier-2, currently NOT equal) ----

    /// A local-variable rename is NOT yet proven equivalent: alpha-renaming is a
    /// deliberately deferred (Tier-2) capability. Documents the conservative
    /// boundary so a future change that flips this is a conscious decision.
    #[test]
    fn python_local_rename_is_conservatively_not_equivalent() {
        let x = "def f(items):\n    total = 0\n    for it in items:\n        total += it\n    return total\n";
        let y =
            "def f(items):\n    acc = 0\n    for it in items:\n        acc += it\n    return acc\n";
        assert_ne!(
            equiv(&PythonAdapter, x, "f"),
            equiv(&PythonAdapter, y, "f"),
            "local alpha-rename is Tier-2 and must stay conservatively non-equivalent for now"
        );
    }

    /// A tuple->object access-path reshape WITHOUT the co-changed-container
    /// machinery (Tier-2, the svelte 432763a03e class) is conservatively NOT
    /// equivalent. The shape-transparency license only exists with the co-change
    /// analysis, which this graph-owned single-entity hash does not carry.
    #[test]
    fn typescript_access_reshape_is_conservatively_not_equivalent() {
        let tuple = "function get(o) { return o.pair[0] === a && o.pair[1].has(x); }";
        let object = "function get(o) { return o.rec.reaction === a && o.rec.sources.has(x); }";
        assert_ne!(
            equiv(&TypeScriptAdapter, tuple, "get"),
            equiv(&TypeScriptAdapter, object, "get"),
            "access-path reshape is Tier-2 and must stay conservatively non-equivalent for now"
        );
    }

    // ---- Determinism --------------------------------------------------------

    #[test]
    fn equivalence_hash_is_deterministic() {
        let src = "def clone(self):\n    \"\"\"docs\"\"\"\n    return self.copy()\n";
        assert_eq!(
            equiv(&PythonAdapter, src, "clone"),
            equiv(&PythonAdapter, src, "clone"),
            "the equivalence hash must be deterministic across runs"
        );
    }

    /// For a non-participating language with no comments or docstrings, the
    /// equivalence hash still discriminates real changes (it collapses to the
    /// behavior-hash token stream).
    #[test]
    fn rust_behavior_change_is_not_equivalent() {
        let plus = "fn total(a: i32, b: i32) -> i32 { a + b }";
        let minus = "fn total(a: i32, b: i32) -> i32 { a - b }";
        assert_ne!(
            equiv(&RustAdapter, plus, "total"),
            equiv(&RustAdapter, minus, "total"),
            "a Rust operator change must not be equivalent"
        );
    }
}
