//! C2 Shallow Syntax extraction.
//!
//! Provides coarse, parser-backed declaration and import extraction for files
//! where Kin has a tree-sitter grammar but no full semantic adapter. This is
//! the C2 tier: better than opaque, weaker than full entity extraction.
//!
//! The generic shallow extractor walks top-level named AST nodes and classifies
//! them into declaration-like and import-like constructs without language-specific
//! logic. This gives stable file-level fingerprints and queryable declarations
//! without overstating semantic confidence.

use kin_model::{FilePathId, Hash256, ParseState};
use sha2::{Digest, Sha256};
use tree_sitter::Tree;

use crate::adapter::collect_error_ranges;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// C2 shallow parse output for a single file.
#[derive(Debug, Clone)]
pub struct ShallowFile {
    pub file_id: FilePathId,
    pub language_hint: Option<String>,
    pub parse_state: ParseState,
    pub declarations: Vec<ShallowDecl>,
    pub imports: Vec<ShallowImport>,
    pub fingerprint: ShallowFingerprint,
}

/// A top-level declaration detected by shallow parsing.
#[derive(Debug, Clone)]
pub struct ShallowDecl {
    pub kind: ShallowDeclKind,
    pub name: String,
    pub start_line: u32,
    pub end_line: u32,
}

/// Coarse classification of a shallow declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShallowDeclKind {
    FunctionLike,
    TypeLike,
    ModuleLike,
    ConstantLike,
    Unknown,
}

impl std::fmt::Display for ShallowDeclKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionLike => write!(f, "function"),
            Self::TypeLike => write!(f, "type"),
            Self::ModuleLike => write!(f, "module"),
            Self::ConstantLike => write!(f, "constant"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A shallow import detected in the file.
#[derive(Debug, Clone)]
pub struct ShallowImport {
    pub raw_path: String,
    pub alias: Option<String>,
    pub line: u32,
}

/// File-level fingerprint for change detection at C2 tier.
#[derive(Debug, Clone)]
pub struct ShallowFingerprint {
    /// Hash of the full syntax tree shape (AST node kinds).
    pub syntax_hash: Hash256,
    /// Hash of declaration names and kinds (coarse signature).
    pub signature_hash: Option<Hash256>,
}

// ---------------------------------------------------------------------------
// Generic shallow extractor
// ---------------------------------------------------------------------------

/// Extract shallow declarations and imports from a tree-sitter parse tree.
///
/// This walks top-level named children of the root node and classifies them
/// based on common tree-sitter node kind patterns shared across grammars.
/// It is parser-backed, not regex-based.
pub fn extract_shallow(
    tree: &Tree,
    source: &[u8],
    file_id: &FilePathId,
    language_hint: Option<&str>,
) -> ShallowFile {
    let root = tree.root_node();
    let errors = collect_error_ranges(tree);
    let parse_state = if errors.is_empty() {
        ParseState::Valid
    } else {
        ParseState::Incomplete {
            error_ranges: errors,
        }
    };

    let mut declarations = Vec::new();
    let mut imports = Vec::new();

    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if !child.is_named() {
            continue;
        }

        process_node(&child, source, &mut declarations, &mut imports);
    }

    let fingerprint = compute_shallow_fingerprint(tree, &declarations);

    ShallowFile {
        file_id: file_id.clone(),
        language_hint: language_hint.map(|s| s.to_string()),
        parse_state,
        declarations,
        imports,
        fingerprint,
    }
}

// ---------------------------------------------------------------------------
// Node classification helpers
// ---------------------------------------------------------------------------

/// Process a top-level AST node, extracting declarations and imports.
/// Unwraps wrapper nodes like `export_statement` to find the inner declaration.
fn process_node(
    node: &tree_sitter::Node,
    source: &[u8],
    declarations: &mut Vec<ShallowDecl>,
    imports: &mut Vec<ShallowImport>,
) {
    let kind_str = node.kind();

    // Unwrap export wrappers to find inner declarations
    if kind_str == "export_statement" || kind_str == "decorated_definition" {
        let mut inner_cursor = node.walk();
        for inner in node.children(&mut inner_cursor) {
            if inner.is_named() && inner.kind() != "decorator" {
                process_node(&inner, source, declarations, imports);
            }
        }
        return;
    }

    // Classify import-like nodes
    if is_import_like(kind_str) {
        if let Some(imp) = extract_import_node(node, source) {
            imports.push(imp);
        }
        return;
    }

    // Classify declaration-like nodes
    let decl_kind = classify_node_kind(kind_str);
    if let Some(name) = extract_node_name(node, source) {
        declarations.push(ShallowDecl {
            kind: decl_kind,
            name,
            start_line: node.start_position().row as u32,
            end_line: node.end_position().row as u32,
        });
    }
}

/// Node kinds that represent import/include statements across tree-sitter grammars.
fn is_import_like(kind: &str) -> bool {
    kind.contains("import")
        || kind.contains("use_declaration")
        || kind.contains("use_statement")
        || kind.contains("include")
        || kind.contains("require")
        || kind == "package_clause"
}

/// Classify a tree-sitter node kind into a ShallowDeclKind.
fn classify_node_kind(kind: &str) -> ShallowDeclKind {
    // Function-like
    if kind.contains("function")
        || kind.contains("method")
        || kind == "arrow_function"
        || kind == "fn_item"
        || kind == "function_item"
    {
        return ShallowDeclKind::FunctionLike;
    }

    // Type-like
    if kind.contains("class")
        || kind.contains("struct")
        || kind.contains("enum")
        || kind.contains("interface")
        || kind.contains("type_alias")
        || kind.contains("trait")
        || kind == "type_item"
    {
        return ShallowDeclKind::TypeLike;
    }

    // Module-like
    if kind.contains("module")
        || kind.contains("namespace")
        || kind == "mod_item"
        || kind == "package_declaration"
    {
        return ShallowDeclKind::ModuleLike;
    }

    // Constant-like
    if kind.contains("const")
        || kind.contains("static")
        || kind.contains("variable")
        || kind == "let_declaration"
        || kind == "lexical_declaration"
        || kind == "const_item"
        || kind == "static_item"
    {
        return ShallowDeclKind::ConstantLike;
    }

    ShallowDeclKind::Unknown
}

/// Try to extract the name of a declaration node.
///
/// Looks for common child node names: "name", "declarator", and first identifier.
fn extract_node_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Try named child "name"
    if let Some(name_node) = node.child_by_field_name("name") {
        return name_node.utf8_text(source).ok().map(|s| s.to_string());
    }

    // Try named child "declarator" (C-style), unwrapping nested declarators
    // e.g. function_definition -> function_declarator -> identifier
    if let Some(decl_node) = node.child_by_field_name("declarator") {
        // First check for a "name" field at this level
        if let Some(name_node) = decl_node.child_by_field_name("name") {
            return name_node.utf8_text(source).ok().map(|s| s.to_string());
        }
        // Recurse into nested declarator (C function_declarator -> declarator)
        if let Some(inner) = decl_node.child_by_field_name("declarator") {
            if inner.kind() == "identifier" {
                return inner.utf8_text(source).ok().map(|s| s.to_string());
            }
            if let Some(name_node) = inner.child_by_field_name("name") {
                return name_node.utf8_text(source).ok().map(|s| s.to_string());
            }
        }
        return decl_node.utf8_text(source).ok().map(|s| s.to_string());
    }

    // Fall back to first identifier child
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "type_identifier" {
            return child.utf8_text(source).ok().map(|s| s.to_string());
        }
    }

    None
}

/// Try to extract an import path from an import-like node.
fn extract_import_node(node: &tree_sitter::Node, source: &[u8]) -> Option<ShallowImport> {
    // Look for "source" or "path" field (common in JS/TS/Python grammars)
    let path_node = node
        .child_by_field_name("source")
        .or_else(|| node.child_by_field_name("path"))
        .or_else(|| node.child_by_field_name("module_name"));

    if let Some(pn) = path_node {
        let text = pn.utf8_text(source).ok()?;
        let raw_path = text.trim_matches(|c| c == '"' || c == '\'').to_string();
        return Some(ShallowImport {
            raw_path,
            alias: None,
            line: node.start_position().row as u32,
        });
    }

    // Look for "argument" field (Rust use_declaration)
    if let Some(arg_node) = node.child_by_field_name("argument") {
        let text = arg_node.utf8_text(source).ok()?;
        return Some(ShallowImport {
            raw_path: text.to_string(),
            alias: None,
            line: node.start_position().row as u32,
        });
    }

    // Fall back to first string literal or scoped identifier child
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" | "string_literal" => {
                let text = child.utf8_text(source).ok()?;
                return Some(ShallowImport {
                    raw_path: text.trim_matches(|c| c == '"' || c == '\'').to_string(),
                    alias: None,
                    line: node.start_position().row as u32,
                });
            }
            "scoped_identifier" | "use_list" | "scoped_use_list" | "dotted_name" | "identifier" => {
                let text = child.utf8_text(source).ok()?;
                return Some(ShallowImport {
                    raw_path: text.to_string(),
                    alias: None,
                    line: node.start_position().row as u32,
                });
            }
            _ => {}
        }
    }

    // Last resort: use the full node text as the import path
    let text = node.utf8_text(source).ok()?;
    Some(ShallowImport {
        raw_path: text.trim().to_string(),
        alias: None,
        line: node.start_position().row as u32,
    })
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

fn compute_shallow_fingerprint(tree: &Tree, declarations: &[ShallowDecl]) -> ShallowFingerprint {
    // syntax_hash: hash of the tree shape (top-level node kinds)
    let mut syntax_hasher = Sha256::new();
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.is_named() {
            syntax_hasher.update(child.kind().as_bytes());
            syntax_hasher.update(b"|");
        }
    }
    let syntax_result = syntax_hasher.finalize();
    let mut syntax_bytes = [0u8; 32];
    syntax_bytes.copy_from_slice(&syntax_result);

    // signature_hash: hash of declaration names + kinds
    let signature_hash = if declarations.is_empty() {
        None
    } else {
        let mut sig_hasher = Sha256::new();
        for decl in declarations {
            sig_hasher.update(format!("{}:{}", decl.kind, decl.name).as_bytes());
            sig_hasher.update(b"|");
        }
        let sig_result = sig_hasher.finalize();
        let mut sig_bytes = [0u8; 32];
        sig_bytes.copy_from_slice(&sig_result);
        Some(Hash256::from_bytes(sig_bytes))
    };

    ShallowFingerprint {
        syntax_hash: Hash256::from_bytes(syntax_bytes),
        signature_hash,
    }
}

// ---------------------------------------------------------------------------
// Grammar registry
// ---------------------------------------------------------------------------

/// Get the tree-sitter grammar for a C2 shallow syntax language.
///
/// Returns None if the grammar crate is not compiled in.
/// Add new grammar crates to expand C2 coverage.
pub fn get_shallow_grammar(language_hint: &str) -> Option<tree_sitter_language::LanguageFn> {
    match language_hint {
        "c" => Some(tree_sitter_c::LANGUAGE),
        // Future C2 grammars: "cpp", "ruby", "swift", "kotlin", etc.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Convenience: one-call C2 parse
// ---------------------------------------------------------------------------

/// Parse a file at C2 shallow tier, returning a ShallowFile if a grammar is available.
///
/// This combines grammar lookup, tree-sitter parsing, and shallow extraction
/// into a single call. Returns None if no grammar exists for the language hint
/// or if parsing fails.
pub fn parse_shallow_file(
    content: &[u8],
    file_id: &FilePathId,
    language_hint: &str,
) -> Option<ShallowFile> {
    let lang_fn = get_shallow_grammar(language_hint)?;
    let mut parser = crate::adapter::make_parser(&lang_fn).ok()?;
    let tree = parser.parse(content, None)?;
    Some(extract_shallow(
        &tree,
        content,
        file_id,
        Some(language_hint),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::make_parser;

    fn parse_and_extract(source: &str, lang: &tree_sitter_language::LanguageFn) -> ShallowFile {
        let mut parser = make_parser(lang).unwrap();
        let tree = parser.parse(source.as_bytes(), None).unwrap();
        let file_id = FilePathId::new("test.rs");
        extract_shallow(&tree, source.as_bytes(), &file_id, Some("rust"))
    }

    #[test]
    fn shallow_extracts_rust_functions() {
        let source = r#"
fn hello() {
    println!("hi");
}

fn world(x: i32) -> bool {
    true
}
"#;
        let result = parse_and_extract(source, &tree_sitter_rust::LANGUAGE);
        assert!(matches!(result.parse_state, ParseState::Valid));
        assert_eq!(result.declarations.len(), 2);
        assert_eq!(result.declarations[0].name, "hello");
        assert_eq!(result.declarations[0].kind, ShallowDeclKind::FunctionLike);
        assert_eq!(result.declarations[1].name, "world");
    }

    #[test]
    fn shallow_extracts_rust_structs() {
        let source = r#"
struct Foo {
    bar: i32,
}

enum Color {
    Red,
    Blue,
}
"#;
        let result = parse_and_extract(source, &tree_sitter_rust::LANGUAGE);
        assert_eq!(result.declarations.len(), 2);
        assert_eq!(result.declarations[0].name, "Foo");
        assert_eq!(result.declarations[0].kind, ShallowDeclKind::TypeLike);
        assert_eq!(result.declarations[1].name, "Color");
        assert_eq!(result.declarations[1].kind, ShallowDeclKind::TypeLike);
    }

    #[test]
    fn shallow_extracts_rust_use_statements() {
        let source = r#"
use std::collections::HashMap;
use crate::model::Entity;

fn main() {}
"#;
        let result = parse_and_extract(source, &tree_sitter_rust::LANGUAGE);
        assert!(result.imports.len() >= 2);
        assert_eq!(result.declarations.len(), 1);
    }

    #[test]
    fn shallow_extracts_python_functions() {
        let source = r#"
def greet(name):
    print(f"Hello, {name}")

class Animal:
    def speak(self):
        pass
"#;
        let result = parse_and_extract(source, &tree_sitter_python::LANGUAGE);
        assert!(result.declarations.len() >= 2);
        // Should find greet (function) and Animal (class)
        let names: Vec<&str> = result
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(names.contains(&"greet"));
        assert!(names.contains(&"Animal"));
    }

    #[test]
    fn shallow_extracts_typescript_declarations() {
        let source = r#"
import { foo } from './utils';

export function bar(): void {}

export interface Config {
    name: string;
}

const MAX = 100;
"#;
        let result = parse_and_extract(source, &tree_sitter_typescript::LANGUAGE_TSX);
        assert!(!result.imports.is_empty());
        assert!(result.declarations.len() >= 2);
    }

    #[test]
    fn shallow_fingerprint_changes_with_content() {
        let source1 = "fn foo() {}\nfn bar() {}";
        let source2 = "fn foo() {}\nfn baz() {}";

        let r1 = parse_and_extract(source1, &tree_sitter_rust::LANGUAGE);
        let r2 = parse_and_extract(source2, &tree_sitter_rust::LANGUAGE);

        // Syntax hash should be the same (same structure: two function_items)
        assert_eq!(r1.fingerprint.syntax_hash, r2.fingerprint.syntax_hash);

        // Signature hash should differ (different names)
        assert_ne!(r1.fingerprint.signature_hash, r2.fingerprint.signature_hash);
    }

    #[test]
    fn shallow_fingerprint_syntax_changes() {
        let source1 = "fn foo() {}";
        let source2 = "fn foo() {}\nstruct Bar {}";

        let r1 = parse_and_extract(source1, &tree_sitter_rust::LANGUAGE);
        let r2 = parse_and_extract(source2, &tree_sitter_rust::LANGUAGE);

        // Different top-level structure -> different syntax hash
        assert_ne!(r1.fingerprint.syntax_hash, r2.fingerprint.syntax_hash);
    }

    #[test]
    fn shallow_parse_state_incomplete_on_errors() {
        let source = "fn broken({{{}}}";
        let result = parse_and_extract(source, &tree_sitter_rust::LANGUAGE);
        assert!(matches!(result.parse_state, ParseState::Incomplete { .. }));
    }

    #[test]
    fn shallow_empty_file() {
        let source = "";
        let result = parse_and_extract(source, &tree_sitter_rust::LANGUAGE);
        assert!(matches!(result.parse_state, ParseState::Valid));
        assert!(result.declarations.is_empty());
        assert!(result.imports.is_empty());
        assert!(result.fingerprint.signature_hash.is_none());
    }

    #[test]
    fn shallow_go_function() {
        let source = r#"
package main

func hello() {
    fmt.Println("hi")
}
"#;
        let result = parse_and_extract(source, &tree_sitter_go::LANGUAGE);
        let names: Vec<&str> = result
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(names.contains(&"hello"));
    }

    #[test]
    fn get_shallow_grammar_c_returns_some() {
        assert!(get_shallow_grammar("c").is_some());
    }

    #[test]
    fn get_shallow_grammar_unknown_returns_none() {
        assert!(get_shallow_grammar("ruby").is_none());
    }

    #[test]
    fn shallow_c_function() {
        let source = r#"
#include <stdio.h>

void hello(void) {
    printf("hi\n");
}

int add(int a, int b) {
    return a + b;
}
"#;
        let mut parser = crate::adapter::make_parser(&tree_sitter_c::LANGUAGE).unwrap();
        let tree = parser.parse(source.as_bytes(), None).unwrap();
        let file_id = FilePathId::new("test.c");
        let result = extract_shallow(&tree, source.as_bytes(), &file_id, Some("c"));
        assert!(matches!(result.parse_state, ParseState::Valid));
        // Should find hello and add as declarations
        let names: Vec<&str> = result
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(
            names.contains(&"hello") || names.contains(&"add"),
            "Expected C function declarations, got: {:?}",
            names
        );
    }

    #[test]
    fn shallow_java_class() {
        let source = r#"
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
"#;
        let result = parse_and_extract(source, &tree_sitter_java::LANGUAGE);
        let names: Vec<&str> = result
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(names.contains(&"HelloWorld"));
    }
}
