// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{
    FilePathId, FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan,
};
use sha2::{Digest, Sha256};
use tree_sitter::{Node, Parser, Tree};

use crate::error::{ParseError, Result};
use crate::extract::ParseOutput;

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

/// Whitespace-collapsed declaration text of a node, cut before its `body`
/// child and any C++ member-initializer list, falling back to the full node
/// text for body-less declarations. Line wrapping and indentation must not
/// leak into signatures: a multi-line declarator and its single-line
/// reformat are the same declaration, and a signature string that differs
/// only by formatting reads as a false signature change downstream.
pub fn declaration_signature(node: &Node, source: &[u8]) -> String {
    let start = node.start_byte();
    let mut end = node.end_byte();
    if let Some(body) = node.child_by_field_name("body") {
        end = end.min(body.start_byte());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "field_initializer_list" {
            end = end.min(child.start_byte());
        }
    }
    let end = end.max(start);
    let text = source
        .get(start..end)
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    canonicalize_signature_spacing(&collapsed)
        .trim_end_matches(['{', ':'])
        .trim()
        .to_string()
}

/// Canonicalize spacing around punctuation in a collapsed signature so that
/// a line break at a token boundary (`ArgParser\n(...)`) and its inline form
/// (`ArgParser(...)`) render identically: no space before `()[],;<>`, none
/// after an opening bracket.
fn canonicalize_signature_spacing(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '(' | ')' | ',' | '[' | ']' | ';' | '<' | '>' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(ch);
            }
            ' ' => {
                if !matches!(out.chars().last(), Some('(') | Some('[') | Some('<') | None) {
                    out.push(' ');
                }
            }
            c => out.push(c),
        }
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
