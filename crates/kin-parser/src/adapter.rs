// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{
    FilePathId, FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan,
};
use sha2::{Digest, Sha256};
use tree_sitter::{Node, Parser, Tree};

use crate::error::{ParseError, Result};
use crate::extract::ParseOutput;

/// Trait that each language adapter implements.
pub trait LanguageAdapter: Send + Sync {
    /// Which language this adapter handles.
    fn language_id(&self) -> LanguageId;

    /// File extensions this adapter matches (e.g. `["ts", "tsx"]`).
    fn file_extensions(&self) -> &[&str];

    /// Parse source code into a tree-sitter Tree.
    fn parse(&self, source: &[u8]) -> Result<Tree>;

    /// Extract entities and relations from a parsed tree.
    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput>;
}

/// Compute a semantic fingerprint by hashing different aspects of a node.
pub fn compute_fingerprint(node: &Node, source: &[u8]) -> SemanticFingerprint {
    let text = node.utf8_text(source).unwrap_or("");

    let mut ast_hasher = Sha256::new();
    hash_ast_shape(node, &mut ast_hasher);
    let ast_hash = finalize_hash(ast_hasher);

    let mut sig_hasher = Sha256::new();
    sig_hasher.update(node.kind().as_bytes());
    // Hash children kinds as a proxy for the signature shape
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            sig_hasher.update(child.kind().as_bytes());
        }
    }
    let signature_hash = finalize_hash(sig_hasher);

    let mut behavior_hasher = Sha256::new();
    behavior_hasher.update(text.as_bytes());
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
        if child.is_named() {
            hash_ast_shape(&child, hasher);
        }
    }
    hasher.update(b")");
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
