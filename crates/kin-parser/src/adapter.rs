// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{
    FilePathId, FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan,
};
use sha2::{Digest, Sha256};
use tree_sitter::{Node, Parser, Tree};

use crate::error::{ParseError, Result};
use crate::extract::{ParseOutput, RelationSite};

/// Hint for incremental tree-sitter parse. Maps directly to tree_sitter::InputEdit.
#[derive(Debug, Clone)]
pub struct EditHint {
    pub start_byte: usize,
    pub old_end_byte: usize,
    pub new_end_byte: usize,
}

/// Trait that each language adapter implements.
pub trait LanguageAdapter: Send + Sync {
    /// Which language this adapter handles.
    fn language_id(&self) -> LanguageId;

    /// File extensions this adapter matches (e.g. `["ts", "tsx"]`).
    fn file_extensions(&self) -> &[&str];

    /// Parse source code into a tree-sitter Tree.
    fn parse(&self, source: &[u8]) -> Result<Tree>;

    /// Parse incrementally using a previous tree and edit hint.
    /// Default implementation ignores the hint and does a full re-parse.
    fn parse_incremental(&self, source: &[u8], old_tree: &Tree, edit: &EditHint) -> Result<Tree> {
        let _ = (old_tree, edit);
        self.parse(source)
    }

    /// Extract entities and relations from a parsed tree.
    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput>;
}

/// Compute a semantic fingerprint by hashing different aspects of a node.
///
/// All three hashes skip grammar `extra` nodes (comments), and the behavior
/// hash is built from the leaf-token stream rather than raw source bytes, so
/// comment-only and formatting-only edits produce identical fingerprints
/// while any token or structure change still alters the behavior hash.
pub fn compute_fingerprint(node: &Node, source: &[u8]) -> SemanticFingerprint {
    let mut ast_hasher = Sha256::new();
    hash_ast_shape(node, &mut ast_hasher);
    let ast_hash = finalize_hash(ast_hasher);

    let mut sig_hasher = Sha256::new();
    sig_hasher.update(node.kind().as_bytes());
    // Hash children kinds as a proxy for the signature shape
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() && !child.is_extra() {
            sig_hasher.update(child.kind().as_bytes());
        }
    }
    let signature_hash = finalize_hash(sig_hasher);

    let mut behavior_hasher = Sha256::new();
    hash_token_stream(node, source, &mut behavior_hasher);
    let behavior_hash = finalize_hash(behavior_hasher);

    SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash,
        signature_hash,
        behavior_hash,
        equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
        stability_score: 0.8,
    }
}

fn hash_ast_shape(node: &Node, hasher: &mut Sha256) {
    hasher.update(node.kind().as_bytes());
    hasher.update(b"(");
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() && !child.is_extra() {
            hash_ast_shape(&child, hasher);
        }
    }
    hasher.update(b")");
}

/// Hash the semantic token content of a subtree: named-node open/close
/// markers plus the kind and text of every leaf token, skipping `extra`
/// subtrees entirely. Inter-token whitespace never appears in the tree, so
/// the digest is stable across formatting and comment edits, while the
/// structural markers keep it sensitive to nesting moves that reuse the
/// same token text (e.g. a statement moving into an adjacent block).
fn hash_token_stream(node: &Node, source: &[u8], hasher: &mut Sha256) {
    if node.is_extra() {
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
        hash_token_stream(&child, source, hasher);
    }
    if named {
        hasher.update(b")");
    }
}

/// Formatting-canonical declaration text of a node, cut before its `body`
/// child and any C++ member-initializer list, falling back to the full node
/// text for body-less declarations. Grammars that expose the body as a
/// plainly-kinded child instead of a `body` field (e.g. Kotlin's
/// `function_body`/`class_body`) are cut at that child by kind. Line wrapping
/// and indentation outside literals must not leak into signatures, while
/// syntax-tree string/character/template literal ranges are copied byte-for-
/// byte because their whitespace is semantic data. A declaration containing
/// invalid UTF-8 is represented as an opaque, reversible byte string instead
/// of lossy text so distinct source contracts can never collapse together.
pub fn declaration_signature(node: &Node, source: &[u8]) -> String {
    let start = node.start_byte();
    let mut end = node.end_byte();
    if let Some(body) = node.child_by_field_name("body") {
        end = end.min(body.start_byte());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(
            child.kind(),
            "field_initializer_list" | "function_body" | "class_body" | "enum_class_body"
        ) {
            end = end.min(child.start_byte());
        }
    }
    let end = end.max(start);
    let source_slice = source.get(start..end).unwrap_or_default();
    let Ok(text) = std::str::from_utf8(source_slice) else {
        return opaque_non_utf8_signature(source_slice);
    };
    let mut literal_ranges = Vec::new();
    collect_literal_ranges(node, start, end, &mut literal_ranges);
    literal_ranges.retain(|(literal_start, literal_end)| {
        literal_start < literal_end
            && *literal_end <= text.len()
            && text.is_char_boundary(*literal_start)
            && text.is_char_boundary(*literal_end)
    });
    canonicalize_signature_spacing(text, &literal_ranges)
        .trim_end_matches(['{', ':'])
        .trim()
        .to_string()
}

/// Preserve every original byte while keeping invalid-UTF-8 declarations out
/// of language-specific signature classifiers. The prefix contains no source
/// syntax and the hexadecimal payload is injective, so callers can compare
/// signatures safely but cannot mistake the opaque value for a parsed `def`,
/// function, or method declaration.
fn opaque_non_utf8_signature(source: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut signature = String::with_capacity("non_utf8_hex:".len() + source.len() * 2);
    signature.push_str("non_utf8_hex:");
    for byte in source {
        signature.push(HEX[(byte >> 4) as usize] as char);
        signature.push(HEX[(byte & 0x0f) as usize] as char);
    }
    signature
}

/// Protect syntax-tree literal nodes from declaration whitespace
/// canonicalization. Literal source bytes are semantic data: collapsing
/// `"a  b"` to `"a b"`, or deleting a space before punctuation inside a
/// string, changes a Python default and can corrupt review classification.
fn collect_literal_ranges(
    node: &Node,
    signature_start: usize,
    signature_end: usize,
    ranges: &mut Vec<(usize, usize)>,
) {
    if node.end_byte() <= signature_start || node.start_byte() >= signature_end {
        return;
    }
    let kind = node.kind();
    if kind.contains("string")
        || kind.contains("char_literal")
        || kind.contains("character_literal")
        || kind.contains("template")
    {
        let start = node.start_byte().max(signature_start) - signature_start;
        let end = node.end_byte().min(signature_end) - signature_start;
        if start < end {
            ranges.push((start, end));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_literal_ranges(&child, signature_start, signature_end, ranges);
    }
}

/// Collapse declaration formatting and canonicalize punctuation while copying
/// literal ranges byte-for-byte. A line break at a token boundary
/// (`ArgParser\n(...)`) and its inline form (`ArgParser(...)`) remain identical,
/// but whitespace and punctuation inside strings are never rewritten.
fn canonicalize_signature_spacing(source: &str, literal_ranges: &[(usize, usize)]) -> String {
    let mut ranges = literal_ranges.to_vec();
    ranges.sort_unstable();
    let mut range_index = 0usize;
    let mut out = String::with_capacity(source.len());
    let mut pending_space = false;
    let mut i = 0usize;

    while i < source.len() {
        if let Some(&(start, end)) = ranges.get(range_index) {
            if i == start {
                if pending_space
                    && !matches!(out.chars().last(), Some('(') | Some('[') | Some('<') | None)
                {
                    out.push(' ');
                }
                out.push_str(&source[start..end]);
                pending_space = false;
                i = end;
                range_index += 1;
                continue;
            }
        }

        let ch = source[i..]
            .chars()
            .next()
            .expect("i is always a UTF-8 character boundary");
        if ch.is_whitespace() {
            pending_space = true;
            i += ch.len_utf8();
            continue;
        }

        match ch {
            '(' | ')' | ',' | '[' | ']' | ';' | '<' | '>' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(ch);
            }
            _ => {
                if pending_space
                    && !matches!(out.chars().last(), Some('(') | Some('[') | Some('<') | None)
                {
                    out.push(' ');
                }
                out.push(ch);
            }
        }
        pending_space = false;
        i += ch.len_utf8();
    }
    out
}

fn finalize_hash(hasher: Sha256) -> Hash256 {
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256::from_bytes(bytes)
}

/// Create a new tree-sitter parser for a given LanguageFn.
pub fn make_parser(language: &tree_sitter_language::LanguageFn) -> Result<Parser> {
    let mut parser = Parser::new();
    parser
        .set_language(&(*language).into())
        .map_err(|e| ParseError::LanguageLoad(e.to_string()))?;
    Ok(parser)
}

/// Build a SourceSpan from a tree-sitter Node.
pub fn span_from_node(node: &Node, file_id: &FilePathId) -> SourceSpan {
    let start = node.start_position();
    let end = node.end_position();
    SourceSpan {
        file: file_id.clone(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: start.row as u32,
        start_col: start.column as u32,
        end_line: end.row as u32,
        end_col: end.column as u32,
    }
}

/// The file-free site of a node, for a relation whose evidence is the syntax at
/// that node. Line and column are 0-based tree-sitter `Point` values, matching
/// [`span_from_node`]; the presentation seam converts once, at the surface.
pub fn site_from_node(node: &Node) -> RelationSite {
    let start = node.start_position();
    let end = node.end_position();
    RelationSite {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: start.row as u32,
        start_col: start.column as u32,
        end_line: end.row as u32,
        end_col: end.column as u32,
    }
}

/// Check whether a tree has parse errors and collect error ranges.
pub fn collect_error_ranges(tree: &Tree) -> Vec<(usize, usize)> {
    let mut errors = Vec::new();
    collect_errors_recursive(&tree.root_node(), &mut errors);
    errors
}

fn collect_errors_recursive(node: &Node, errors: &mut Vec<(usize, usize)>) {
    if node.is_error() || node.is_missing() {
        errors.push((node.start_byte(), node.end_byte()));
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_errors_recursive(&child, errors);
    }
}
