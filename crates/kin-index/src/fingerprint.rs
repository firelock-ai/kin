// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::ids::LanguageId;
use kin_model::{FingerprintAlgorithm, Hash256, SemanticFingerprint};
use sha2::{Digest, Sha256};
use tree_sitter::Node;

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
        equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
    let ctx = EquivalenceContext::for_entity_file(node, source, language);
    hash_equivalence_stream(node, source, language, ctx, &mut hasher);
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
fn hash_equivalence_stream(
    node: &Node,
    source: &[u8],
    language: LanguageId,
    ctx: EquivalenceContext,
    hasher: &mut Sha256,
) {
    if node.is_extra() {
        return;
    }
    if is_pure_noop_string_statement(node, language) {
        return;
    }
    if is_pure_annotation_statement(node, language) {
        return;
    }
    if is_canonical_none_type(node, source, language, ctx) {
        hasher.update(CANONICAL_NONE_TYPE);
        return;
    }
    if language_supports_equivalence(language) && is_neutralizable_annotated_assignment(node) {
        // A valued PEP 526 annotated assignment `x: T = v` hashes as `x = v`: the
        // annotation and its `:` drop out (metadata-only), so an annotation-only
        // edit collapses to one class while any change to the assigned value still
        // differs. Applies only when the annotation is side-effect-free.
        hasher.update(node.kind().as_bytes());
        hasher.update(b"(");
        let annotation_id = node.child_by_field_name("type").map(|t| t.id());
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if Some(child.id()) == annotation_id || (!child.is_named() && child.kind() == ":") {
                continue;
            }
            hash_equivalence_stream(&child, source, language, ctx, hasher);
        }
        hasher.update(b")");
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
        hash_equivalence_stream(&child, source, language, ctx, hasher);
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

/// Canonical digest marker emitted in place of the interchangeable explicit
/// spellings of the `NoneType` singleton (`type(None)`, `types.NoneType`) so a
/// body differing only by that swap hashes identically. The `\x1d`
/// group-separator bytes cannot collide with any tree-sitter token text.
const CANONICAL_NONE_TYPE: &[u8] = b"\x1dcanon:none_type\x1d";

/// File-level facts that gate the `NoneType` canonicalization so it fires only
/// where the referenced names provably resolve to the Python stdlib. Computed
/// once per entity from its enclosing file's parse tree (imports + name
/// bindings) — graph-native, never a bare textual match. `Copy` so it threads
/// cheaply through the hash walk.
#[derive(Clone, Copy)]
struct EquivalenceContext {
    /// `type` is the un-shadowed builtin: no binding of `type` in the file.
    type_builtin_available: bool,
    /// `types` resolves to the stdlib module: `import types` present and `types`
    /// not otherwise bound.
    types_module_is_stdlib: bool,
    /// Bare `NoneType` resolves to the stdlib singleton: `from types import
    /// NoneType` present and `NoneType` not otherwise bound.
    bare_none_type_is_stdlib: bool,
}

impl EquivalenceContext {
    /// Every gate closed — the conservative default for non-participating
    /// languages, where no NoneType spelling is ever canonicalized.
    const CLOSED: Self = Self {
        type_builtin_available: false,
        types_module_is_stdlib: false,
        bare_none_type_is_stdlib: false,
    };

    /// Derive the context from the file that contains `node`: walk to the file
    /// root and scan its imports and name bindings once.
    fn for_entity_file(node: &Node, source: &[u8], language: LanguageId) -> Self {
        if !language_supports_equivalence(language) {
            return Self::CLOSED;
        }
        let mut root = *node;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        let mut scan = BindingScan::default();
        scan_name_bindings(&root, source, &mut scan);
        Self {
            type_builtin_available: !scan.type_shadowed,
            types_module_is_stdlib: scan.import_types && !scan.types_shadowed,
            bare_none_type_is_stdlib: scan.from_types_none_type && !scan.none_type_shadowed,
        }
    }
}

/// Accumulates the file-level import and shadowing facts for the three names
/// (`type`, `types`, `NoneType`) the NoneType canonicalization depends on.
#[derive(Default)]
struct BindingScan {
    import_types: bool,
    from_types_none_type: bool,
    type_shadowed: bool,
    types_shadowed: bool,
    none_type_shadowed: bool,
}

impl BindingScan {
    fn shadow(&mut self, name: &str) {
        match name {
            "type" => self.type_shadowed = true,
            "types" => self.types_shadowed = true,
            "NoneType" => self.none_type_shadowed = true,
            _ => {}
        }
    }
}

/// Walk the file recording the two stdlib imports and any local rebinding of the
/// three tracked names. Covers the realistic binding forms — import, class/def,
/// (augmented) assignment, parameters, `for`/`with`/`except`/walrus targets. A
/// tracked name bound by a rarer form (comprehension target, match capture) is
/// simply not observed here; because canonicalization also requires the positive
/// stdlib-import gate, an unobserved rebinding stays conservative.
fn scan_name_bindings(node: &Node, source: &[u8], scan: &mut BindingScan) {
    match node.kind() {
        "import_statement" => scan_import(node, source, scan),
        "import_from_statement" => scan_import_from(node, source, scan),
        "class_definition" | "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                scan.shadow(node_text(&name, source));
            }
        }
        "assignment" | "augmented_assignment" | "for_statement" => {
            if let Some(left) = node.child_by_field_name("left") {
                shadow_targets(&left, source, scan);
            }
        }
        "parameters" | "lambda_parameters" => shadow_parameters(node, source, scan),
        "named_expression" => {
            if let Some(name) = node.child_by_field_name("name") {
                scan.shadow(node_text(&name, source));
            }
        }
        "as_pattern" | "except_clause" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                shadow_targets(&alias, source, scan);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        scan_name_bindings(&child, source, scan);
    }
}

fn scan_import(node: &Node, source: &[u8], scan: &mut BindingScan) {
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        match name.kind() {
            "dotted_name" => match first_component(&name, source) {
                Some("types") => scan.import_types = true,
                Some(other) => scan.shadow(other),
                None => {}
            },
            "aliased_import" => {
                if let Some(alias) = name.child_by_field_name("alias") {
                    scan.shadow(node_text(&alias, source));
                }
            }
            _ => {}
        }
    }
}

fn scan_import_from(node: &Node, source: &[u8], scan: &mut BindingScan) {
    let module_is_types = node
        .child_by_field_name("module_name")
        .map(|m| m.kind() == "dotted_name" && node_text(&m, source) == "types")
        .unwrap_or(false);
    let mut wildcard_cursor = node.walk();
    let has_wildcard = node
        .children(&mut wildcard_cursor)
        .any(|c| c.kind() == "wildcard_import");
    if has_wildcard {
        // `from X import *` may bind any tracked name; stay conservative.
        scan.type_shadowed = true;
        scan.types_shadowed = true;
        scan.none_type_shadowed = true;
    }
    let mut cursor = node.walk();
    for name in node.children_by_field_name("name", &mut cursor) {
        match name.kind() {
            "dotted_name" => {
                let bound = node_text(&name, source);
                if module_is_types && bound == "NoneType" {
                    scan.from_types_none_type = true;
                } else {
                    scan.shadow(bound);
                }
            }
            "aliased_import" => {
                let orig = name
                    .child_by_field_name("name")
                    .map(|n| node_text(&n, source));
                let alias = name
                    .child_by_field_name("alias")
                    .map(|a| node_text(&a, source));
                if module_is_types && orig == Some("NoneType") && alias == Some("NoneType") {
                    scan.from_types_none_type = true;
                } else if let Some(alias) = alias {
                    scan.shadow(alias);
                }
            }
            _ => {}
        }
    }
}

/// Shadow every identifier bound by an assignment/loop/with/except target,
/// descending through tuple and list destructuring. Attribute and subscript
/// targets (`a.b = …`, `a[0] = …`) bind no bare name and are ignored.
fn shadow_targets(node: &Node, source: &[u8], scan: &mut BindingScan) {
    match node.kind() {
        "identifier" => scan.shadow(node_text(node, source)),
        "pattern_list"
        | "tuple_pattern"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "as_pattern_target" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                shadow_targets(&child, source, scan);
            }
        }
        _ => {}
    }
}

/// Shadow the NAME of each parameter (never its annotation or default, which are
/// read positions): a simple `identifier`, or the leading identifier of a typed,
/// defaulted, or splat parameter.
fn shadow_parameters(params: &Node, source: &[u8], scan: &mut BindingScan) {
    let mut cursor = params.walk();
    for param in params.children(&mut cursor) {
        match param.kind() {
            "identifier" => scan.shadow(node_text(&param, source)),
            "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
                let mut inner = param.walk();
                let name = param
                    .children(&mut inner)
                    .find(|c| c.kind() == "identifier");
                if let Some(id) = name {
                    scan.shadow(node_text(&id, source));
                }
            }
            "default_parameter" | "typed_default_parameter" => {
                if let Some(name) = param.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        scan.shadow(node_text(&name, source));
                    }
                }
            }
            _ => {}
        }
    }
}

/// First `identifier` component of a `dotted_name` (`a` in `a.b.c`).
fn first_component<'a>(dotted: &Node, source: &'a [u8]) -> Option<&'a str> {
    let mut cursor = dotted.walk();
    for child in dotted.children(&mut cursor) {
        if child.kind() == "identifier" {
            return Some(node_text(&child, source));
        }
    }
    None
}

/// True when `node` denotes the `NoneType` singleton in a spelling this file
/// proves resolves to the stdlib: `type(None)` (un-shadowed builtin `type`),
/// `types.NoneType` (stdlib `types` module), or bare `NoneType` (bound by
/// `from types import NoneType`). Python 3.10+ guarantees all three are the same
/// object, so folding them to one marker collapses exactly that swap. Every gate
/// is graph-derived from the file's imports and bindings; when a gate is closed
/// (name shadowed, or the import absent) the spelling is left untouched.
fn is_canonical_none_type(
    node: &Node,
    source: &[u8],
    language: LanguageId,
    ctx: EquivalenceContext,
) -> bool {
    if !language_supports_equivalence(language) {
        return false;
    }
    match node.kind() {
        "attribute" => ctx.types_module_is_stdlib && is_types_none_type_attribute(node, source),
        "call" => ctx.type_builtin_available && is_type_of_none_call(node, source),
        "identifier" => {
            ctx.bare_none_type_is_stdlib
                && node_text(node, source) == "NoneType"
                && is_value_reference_position(node)
        }
        _ => false,
    }
}

/// `types.NoneType` exactly: object identifier `types`, attribute `NoneType`.
fn is_types_none_type_attribute(node: &Node, source: &[u8]) -> bool {
    let object_is_types = node
        .child_by_field_name("object")
        .map(|o| o.kind() == "identifier" && node_text(&o, source) == "types")
        .unwrap_or(false);
    let attr_is_none_type = node
        .child_by_field_name("attribute")
        .map(|a| node_text(&a, source) == "NoneType")
        .unwrap_or(false);
    object_is_types && attr_is_none_type
}

/// `type(None)` exactly: a call to the bare `type` identifier with the single
/// argument `None`.
fn is_type_of_none_call(node: &Node, source: &[u8]) -> bool {
    let function_is_type = node
        .child_by_field_name("function")
        .map(|f| f.kind() == "identifier" && node_text(&f, source) == "type")
        .unwrap_or(false);
    if !function_is_type {
        return false;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let mut named = args
        .children(&mut cursor)
        .filter(|c| c.is_named() && !c.is_extra());
    let Some(only) = named.next() else {
        return false;
    };
    named.next().is_none() && only.kind() == "none"
}

/// True when a bare `NoneType` identifier is a value reference, not the member
/// side of an attribute access (`x.NoneType`) or a keyword-argument name
/// (`f(NoneType=…)`) — positions where the token is not the imported name.
fn is_value_reference_position(node: &Node) -> bool {
    let Some(parent) = node.parent() else {
        return true;
    };
    match parent.kind() {
        "attribute" => parent.child_by_field_name("attribute").map(|a| a.id()) != Some(node.id()),
        "keyword_argument" => parent.child_by_field_name("name").map(|n| n.id()) != Some(node.id()),
        _ => true,
    }
}

/// True for a bare PEP 526 variable annotation with no assigned value —
/// `name: T` — whose annotation `T` is a side-effect-free type expression. Such
/// a statement binds nothing; at function scope it is never evaluated, and at
/// class/module scope it only records an entry in `__annotations__`. Either way
/// it changes no runtime behavior, so adding, removing, or editing it is
/// behavior-preserving.
///
/// Guards that keep this sound:
/// - restricted to `language_supports_equivalence` languages (Python),
/// - the statement's only named child must be an `assignment` carrying a `type`
///   field and NO `right` field — an assigned value is behavior-relevant and is
///   never dropped, and
/// - the annotation must contain only side-effect-free type-expression nodes; a
///   `call` or other evaluable-with-effects form keeps the statement in the hash.
fn is_pure_annotation_statement(node: &Node, language: LanguageId) -> bool {
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
    let Some(assignment) = named_children.next() else {
        return false;
    };
    if named_children.next().is_some() || assignment.kind() != "assignment" {
        return false;
    }
    if assignment.child_by_field_name("right").is_some() {
        return false;
    }
    let Some(annotation) = assignment.child_by_field_name("type") else {
        return false;
    };
    is_side_effect_free_type_expr(&annotation)
}

/// True for a valued PEP 526 annotated assignment — `name: T = value` — whose
/// annotation `T` is a side-effect-free type expression. Its annotation may be
/// dropped from the hash (leaving `name = value`), because a type hint on an
/// assignment records only `__annotations__` metadata and never changes what the
/// assignment binds. The assigned value is retained, so any value change differs.
fn is_neutralizable_annotated_assignment(node: &Node) -> bool {
    if node.kind() != "assignment" || node.child_by_field_name("right").is_none() {
        return false;
    }
    match node.child_by_field_name("type") {
        Some(annotation) => is_side_effect_free_type_expr(&annotation),
        None => false,
    }
}

/// Whether a type-annotation subtree is free of runtime side effects: composed
/// only of identifiers, dotted/attribute names, subscripts (`List[int]`), unions
/// (`int | None`), tuples/lists of the same, string forward-references, and
/// literal atoms. Any `call` — or any node kind not on the allow-list — makes it
/// NOT side-effect-free, so an annotation that evaluates something with effects
/// is never dropped.
fn is_side_effect_free_type_expr(node: &Node) -> bool {
    match node.kind() {
        "identifier"
        | "dotted_name"
        | "none"
        | "true"
        | "false"
        | "string"
        | "concatenated_string"
        | "integer"
        | "float"
        | "ellipsis" => true,
        "type"
        | "constrained_type"
        | "generic_type"
        | "member_type"
        | "union_type"
        | "splat_type"
        | "type_parameter"
        | "attribute"
        | "subscript"
        | "binary_operator"
        | "unary_operator"
        | "tuple"
        | "list"
        | "slice"
        | "parenthesized_expression"
        | "expression_list" => {
            let mut cursor = node.walk();
            let all_free = node
                .children(&mut cursor)
                .filter(|c| c.is_named() && !c.is_extra())
                .all(|c| is_side_effect_free_type_expr(&c));
            all_free
        }
        _ => false,
    }
}

/// UTF-8 text of a node, or the empty string if it is not valid UTF-8.
fn node_text<'a>(node: &Node, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
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

    // ---- Type-identity: type(None) == types.NoneType (Python 3.10+) ---------
    // Each canonicalization is gated on the file proving the referenced name
    // resolves to the stdlib (import present, name un-shadowed).

    /// `type(None)` and `types.NoneType` are the same singleton at runtime, so a
    /// body swapping one explicit spelling for the other is behavior-preserving
    /// when `types` is the stdlib module (mirrors django fd21f82aa8's serializer).
    #[test]
    fn python_type_none_and_types_nonetype_are_equivalent() {
        let a = "def check(x):\n    return isinstance(x, (type(None), int))\n";
        let b = "import types\ndef check(x):\n    return isinstance(x, (types.NoneType, int))\n";
        assert_eq!(
            equiv(&PythonAdapter, a, "check"),
            equiv(&PythonAdapter, b, "check"),
            "type(None) and stdlib types.NoneType denote the same singleton and must be equivalent"
        );
    }

    /// The canonicalization holds for a standalone type reference too.
    #[test]
    fn python_type_none_standalone_is_equivalent() {
        let a = "def f():\n    t = type(None)\n    return t\n";
        let b = "import types\ndef f():\n    t = types.NoneType\n    return t\n";
        assert_eq!(equiv(&PythonAdapter, a, "f"), equiv(&PythonAdapter, b, "f"));
    }

    /// Bare `NoneType` bound by `from types import NoneType` is the stdlib
    /// singleton, so swapping `type(None)` for it is behavior-preserving (mirrors
    /// django fd21f82aa8's `SpatialReference`/`Index` isinstance checks).
    #[test]
    fn python_bare_nonetype_from_stdlib_import_is_equivalent() {
        let before = "def check(x):\n    return isinstance(x, (type(None), int))\n";
        let after =
            "from types import NoneType\ndef check(x):\n    return isinstance(x, (NoneType, int))\n";
        assert_eq!(
            equiv(&PythonAdapter, before, "check"),
            equiv(&PythonAdapter, after, "check"),
            "bare NoneType imported from stdlib types must fold to the same class as type(None)"
        );
    }

    /// GUARD: a co-located REAL type change is not masked by the None-type
    /// canonicalization — `int` -> `str` beside an unchanged `type(None)` stays
    /// a behavior change.
    #[test]
    fn python_type_none_canon_does_not_mask_sibling_type_change() {
        let a = "def check(x):\n    return isinstance(x, (type(None), int))\n";
        let b = "def check(x):\n    return isinstance(x, (type(None), str))\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "check"),
            equiv(&PythonAdapter, b, "check"),
            "a real sibling type change (int->str) must not be normalized away"
        );
    }

    /// GUARD: `type(None)` canonicalizes only for `None` — `type(0)` is a
    /// different type and must stay non-equivalent.
    #[test]
    fn python_type_of_other_value_is_not_canonicalized() {
        let a = "def f():\n    return type(None)\n";
        let b = "def f():\n    return type(0)\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "f"),
            equiv(&PythonAdapter, b, "f"),
            "type(0) is not the NoneType singleton and must not be canonicalized"
        );
    }

    /// GATE: `types.NoneType` is NOT canonicalized without `import types` — the
    /// file has not proven `types` is the stdlib module.
    #[test]
    fn python_types_nonetype_without_import_not_canonicalized() {
        let a = "def check(x):\n    return isinstance(x, (type(None), int))\n";
        let b = "def check(x):\n    return isinstance(x, (types.NoneType, int))\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "check"),
            equiv(&PythonAdapter, b, "check"),
            "types.NoneType without `import types` must stay conservatively non-equivalent"
        );
    }

    /// GATE: bare `NoneType` is NOT canonicalized without `from types import
    /// NoneType` — the name is not proven to bind the stdlib singleton.
    #[test]
    fn python_bare_nonetype_without_import_not_canonicalized() {
        let a = "def check(x):\n    return isinstance(x, (type(None), int))\n";
        let b = "def check(x):\n    return isinstance(x, (NoneType, int))\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "check"),
            equiv(&PythonAdapter, b, "check"),
            "bare NoneType with no stdlib import must stay conservatively non-equivalent"
        );
    }

    /// GATE: a file-local `class NoneType` shadows the import, so bare `NoneType`
    /// is NOT canonicalized even with `from types import NoneType` present.
    #[test]
    fn python_local_class_nonetype_blocks_canonicalization() {
        let a = "from types import NoneType\ndef check(x):\n    return isinstance(x, (type(None), int))\n";
        let b = "from types import NoneType\nclass NoneType:\n    pass\ndef check(x):\n    return isinstance(x, (NoneType, int))\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "check"),
            equiv(&PythonAdapter, b, "check"),
            "a local class NoneType shadows the stdlib import; bare NoneType must not canonicalize"
        );
    }

    /// GATE: a file-local rebinding `NoneType = ...` shadows the import, so bare
    /// `NoneType` is NOT canonicalized.
    #[test]
    fn python_local_rebind_nonetype_blocks_canonicalization() {
        let a = "from types import NoneType\ndef check(x):\n    return isinstance(x, (type(None), int))\n";
        let b = "from types import NoneType\nNoneType = object()\ndef check(x):\n    return isinstance(x, (NoneType, int))\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "check"),
            equiv(&PythonAdapter, b, "check"),
            "a local rebinding of NoneType shadows the stdlib import; bare NoneType must not canonicalize"
        );
    }

    /// GATE: a shadowed `type` (here a parameter) is not the builtin, so
    /// `type(None)` is NOT canonicalized.
    #[test]
    fn python_shadowed_type_blocks_type_none() {
        let a = "import types\ndef f(type):\n    return isinstance(f, (type(None), int))\n";
        let b = "import types\ndef f(type):\n    return isinstance(f, (types.NoneType, int))\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "f"),
            equiv(&PythonAdapter, b, "f"),
            "when `type` is shadowed, type(None) is not the builtin and must not canonicalize"
        );
    }

    // ---- Annotation-only body changes are behavior-preserving ---------------

    /// Adding a bare PEP 526 annotation statement inside a function body (mirrors
    /// sphinx d25c3ad241's `subtarget: Optional[str]`) changes no runtime
    /// behavior: it binds nothing and is never evaluated at function scope.
    #[test]
    fn python_added_bare_annotation_in_body_is_equivalent() {
        let without = "def f(warnings):\n    for w in warnings:\n        emit(w)\n";
        let with =
            "def f(warnings):\n    subtarget: Optional[str]\n    for w in warnings:\n        emit(w)\n";
        assert_eq!(
            equiv(&PythonAdapter, without, "f"),
            equiv(&PythonAdapter, with, "f"),
            "a bare local annotation is a no-op and must not change the equivalence class"
        );
    }

    /// Adding class-level attribute annotations (mirrors d25c3ad241's `Sphinx`
    /// `warningiserror: bool` / `_warncount: int`) records only `__annotations__`
    /// metadata and is behavior-preserving for the class.
    #[test]
    fn python_added_class_attribute_annotation_is_equivalent() {
        let without = "class Sphinx:\n    def __init__(self):\n        self.x = 1\n";
        let with = "class Sphinx:\n    warningiserror: bool\n    _warncount: int\n    def __init__(self):\n        self.x = 1\n";
        assert_eq!(
            equiv(&PythonAdapter, without, "Sphinx"),
            equiv(&PythonAdapter, with, "Sphinx"),
            "class attribute annotations are metadata-only and must not change the class equivalence class"
        );
    }

    /// Editing an annotation's TYPE (bare, no value) is behavior-preserving.
    #[test]
    fn python_bare_annotation_type_edit_is_equivalent() {
        let a = "class C:\n    x: int\n    def m(self):\n        return 1\n";
        let b = "class C:\n    x: str\n    def m(self):\n        return 1\n";
        assert_eq!(equiv(&PythonAdapter, a, "C"), equiv(&PythonAdapter, b, "C"));
    }

    /// GUARD: an annotation carrying a VALUE is a real assignment, never dropped
    /// — `x: int` (no value) vs `x: int = compute()` must be non-equivalent.
    #[test]
    fn python_annotated_assignment_with_value_is_not_equivalent() {
        let bare = "class C:\n    x: int\n    def m(self):\n        return 1\n";
        let valued = "class C:\n    x: int = compute()\n    def m(self):\n        return 1\n";
        assert_ne!(
            equiv(&PythonAdapter, bare, "C"),
            equiv(&PythonAdapter, valued, "C"),
            "an annotation with an assigned value is behavior-relevant and must not be dropped"
        );
    }

    /// GUARD: a bare annotation whose type expression is a CALL can have side
    /// effects at class/module scope and must not be dropped.
    #[test]
    fn python_bare_annotation_with_call_is_not_dropped() {
        let without = "class C:\n    def m(self):\n        return 1\n";
        let with = "class C:\n    x: make_type()\n    def m(self):\n        return 1\n";
        assert_ne!(
            equiv(&PythonAdapter, without, "C"),
            equiv(&PythonAdapter, with, "C"),
            "an annotation that evaluates a call is not side-effect-free and must stay in the hash"
        );
    }

    /// A valued annotated assignment whose ONLY delta is the annotation is
    /// behavior-preserving — the annotation is metadata; the bound value is
    /// unchanged (`x: int = 5` vs `x: str = 5`).
    #[test]
    fn python_annotated_assignment_annotation_only_is_equivalent() {
        let a = "class C:\n    x: int = 5\n    def m(self):\n        return 1\n";
        let b = "class C:\n    x: str = 5\n    def m(self):\n        return 1\n";
        assert_eq!(
            equiv(&PythonAdapter, a, "C"),
            equiv(&PythonAdapter, b, "C"),
            "an annotation-only edit on a valued assignment (value unchanged) must be equivalent"
        );
    }

    /// GUARD: the VALUE of a valued annotated assignment is behavior-relevant —
    /// `x: int = 5` vs `x: int = 6` must be non-equivalent even though the
    /// annotation is unchanged.
    #[test]
    fn python_annotated_assignment_value_change_is_not_equivalent() {
        let a = "class C:\n    x: int = 5\n    def m(self):\n        return 1\n";
        let b = "class C:\n    x: int = 6\n    def m(self):\n        return 1\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "C"),
            equiv(&PythonAdapter, b, "C"),
            "a change to the assigned value must never pass through the annotation-only path"
        );
    }

    // ---- Protected true positives stay non-equivalent -----

    /// Adding a narrowing conjunct to a
    /// predicate is a real domain change and must stay non-equivalent.
    #[test]
    fn python_added_narrowing_conjunct_is_not_equivalent() {
        let before = "def find(files):\n    return [f for f in files if f.is_md()]\n";
        let after =
            "def find(files):\n    return [f for f in files if f.is_md() and not f.is_symlink()]\n";
        assert_ne!(
            equiv(&PythonAdapter, before, "find"),
            equiv(&PythonAdapter, after, "find"),
            "an added narrowing conjunct (b9cacbc347 shape) is a behavior change"
        );
    }

    /// Protected-TP shape (b55526f4e8): removing a try/except fallback is a
    /// control-flow behavior change and must stay non-equivalent.
    #[test]
    fn python_removed_try_except_fallback_is_not_equivalent() {
        let with_fallback = "def parse(s):\n    try:\n        return strict(s)\n    except ValueError:\n        return fallback(s)\n";
        let without = "def parse(s):\n    return strict(s)\n";
        assert_ne!(
            equiv(&PythonAdapter, with_fallback, "parse"),
            equiv(&PythonAdapter, without, "parse"),
            "removing a try/except fallback (b55526f4e8 shape) is a behavior change"
        );
    }

    /// Protected-TP shape (f195c4ae87): adding an `__eq__` method converts
    /// identity equality to structural equality — a real semantic change the
    /// annotation-stripping normalization must never absorb.
    #[test]
    fn python_added_eq_method_is_not_equivalent() {
        let without = "class Op:\n    def __init__(self, op):\n        self.op = op\n";
        let with = "class Op:\n    def __init__(self, op):\n        self.op = op\n    def __eq__(self, other):\n        return self.op == other.op\n";
        assert_ne!(
            equiv(&PythonAdapter, without, "Op"),
            equiv(&PythonAdapter, with, "Op"),
            "adding __eq__ (f195c4ae87 shape) changes equality semantics"
        );
    }

    /// Protected-TP shape (f97a6123c0 / 883faaa568): an added `raise` guard is a
    /// behavior change even when a bare annotation is edited in the same body —
    /// annotation-stripping must be surgical and never absorb the raise.
    #[test]
    fn python_added_raise_beside_annotation_is_not_equivalent() {
        let before =
            "def safe(obj, name, *args):\n    result: object\n    return getattr(obj, name, *args)\n";
        let after = "def safe(obj, name, *args):\n    result: object\n    if len(args) > 1:\n        raise TypeError('too many')\n    return getattr(obj, name, *args)\n";
        assert_ne!(
            equiv(&PythonAdapter, before, "safe"),
            equiv(&PythonAdapter, after, "safe"),
            "an added raise guard (f97a6123c0 shape) must stay non-equivalent despite an edited annotation"
        );
    }

    /// A commutative operand reorder whose operand is a CALL is not proven
    /// side-effect-free (the svelte 432763a03e `set`/`get` shape): it is never
    /// canonicalized and stays non-equivalent.
    #[test]
    fn python_operand_reorder_with_call_is_not_equivalent() {
        let a = "def g(o, x):\n    return o.has(x) and o.ready == x\n";
        let b = "def g(o, x):\n    return o.ready == x and o.has(x)\n";
        assert_ne!(
            equiv(&PythonAdapter, a, "g"),
            equiv(&PythonAdapter, b, "g"),
            "reordering a boolean whose operand is a call is not proven equivalent (432763a03e shape)"
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

    /// The composed normalization pipeline is invariant to comments and
    /// whitespace even when every canonicalization fires at once: bare-annotation
    /// stripping, valued-annotation stripping, and NoneType folding together must
    /// yield one identical hash regardless of formatting.
    #[test]
    fn python_canonicalizations_are_formatting_deterministic() {
        let plain = "from types import NoneType\n\
             def check(x):\n    y: int\n    z: int = 5\n    return isinstance(x, (NoneType, int))\n";
        let noisy = "from types import NoneType\n\
             def check(x):  # trailing comment\n    # leading comment\n    y:    int\n    z: int =  5\n    return isinstance(x, ( NoneType , int ))\n";
        assert_eq!(
            equiv(&PythonAdapter, plain, "check"),
            equiv(&PythonAdapter, noisy, "check"),
            "the composed canonicalization pipeline must be formatting-invariant"
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
