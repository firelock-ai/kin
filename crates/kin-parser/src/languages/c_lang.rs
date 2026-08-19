// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, FileImport, ImportedName, ParseOutput};

pub struct CAdapter;

impl LanguageAdapter for CAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::C
    }

    fn file_extensions(&self) -> &[&str] {
        &["c", "h"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_c::LANGUAGE)?;
        parser
            .parse(source, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            })
    }

    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput> {
        let error_ranges = collect_error_ranges(tree);
        let parse_state = if error_ranges.is_empty() {
            ParseState::Valid
        } else {
            ParseState::Incomplete { error_ranges }
        };

        let mut entities = Vec::new();
        let mut relations = Vec::new();
        let mut imports = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_c_node(&child, source, file_id, &mut entities, &mut relations);
        }

        // Recursively extract all includes and ALL_CAPS macro usages across the whole file
        extract_includes_and_macros_recursive(&root, source, file_id, &mut imports, &mut relations);

        // Build import lookup: local_name -> module_path
        let import_map: std::collections::HashMap<&str, &str> = imports
            .iter()
            .flat_map(|imp| {
                imp.specifiers
                    .iter()
                    .map(move |spec| (spec.local_name.as_str(), imp.module_path.as_str()))
            })
            .collect();

        // Annotate Calls/References relations with import_source
        for rel in &mut relations {
            if matches!(
                rel.kind,
                kin_model::RelationKind::Calls | kin_model::RelationKind::References
            ) {
                if let Some(&module) = import_map.get(rel.dst_name.as_str()) {
                    rel.import_source = Some(module.to_string());
                }
            }
        }

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests: Vec::new(),
            parse_state,
        })
    }
}

fn extract_c_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = extract_function_name(node, source) {
                let vis = c_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                extract_calls_from_body(node, source, &name, relations);
            }
        }
        "declaration" => {
            extract_declaration(node, source, file_id, entities);
        }
        "type_definition" => {
            extract_type_definition(node, source, file_id, entities);
        }
        "struct_specifier" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Class,
                        name,
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        // A union is modeled as a Class, mirroring struct handling.
        "union_specifier" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Class,
                        name,
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        "enum_specifier" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::EnumDef,
                        name,
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        // Recurse into preprocessor conditional blocks (#ifdef, #ifndef, #if, etc.)
        // so that code inside header guards is still extracted.
        "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_c_node(&child, source, file_id, entities, relations);
            }
        }
        "preproc_def" | "preproc_function_def" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Macro,
                        name,
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        _ => {}
    }
}

/// Extract the function name from a `function_definition` node.
///
/// In tree-sitter-c, the name lives inside the `declarator` field which is
/// typically a `function_declarator` containing an `identifier`.
fn extract_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    find_identifier(&declarator, source)
}

/// Recursively search for the first `identifier` node in a subtree.
fn find_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        let text = node.utf8_text(source).unwrap_or("").to_string();
        if !text.is_empty() {
            return Some(text);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = find_identifier(&child, source) {
            return Some(name);
        }
    }
    None
}

/// Check whether a node or its children contain a function_declarator.
fn has_function_declarator(node: &tree_sitter::Node) -> bool {
    if node.kind() == "function_declarator" {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declarator" || has_function_declarator(&child) {
            return true;
        }
    }
    false
}

/// Extract entities from a top-level `declaration` node.
///
/// Handles: `const` declarations, `enum_specifier`, `struct_specifier`.
fn extract_declaration(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
) {
    let text = node.utf8_text(source).unwrap_or("");

    // Check for enum_specifier inside the declaration
    if let Some(enum_node) = find_child_of_kind(node, "enum_specifier") {
        if let Some(name_node) = enum_node.child_by_field_name("name") {
            let name = name_node.utf8_text(source).unwrap_or("").to_string();
            if !name.is_empty() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::EnumDef,
                    name,
                    signature: node_signature(node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                return;
            }
        }
    }

    // Check for struct_specifier inside the declaration
    if let Some(struct_node) = find_child_of_kind(node, "struct_specifier") {
        if let Some(name_node) = struct_node.child_by_field_name("name") {
            let name = name_node.utf8_text(source).unwrap_or("").to_string();
            if !name.is_empty() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name,
                    signature: node_signature(node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                return;
            }
        }
    }

    // Check for union_specifier inside the declaration (mirrors struct handling)
    if let Some(union_node) = find_child_of_kind(node, "union_specifier") {
        if let Some(name_node) = union_node.child_by_field_name("name") {
            let name = name_node.utf8_text(source).unwrap_or("").to_string();
            if !name.is_empty() {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name,
                    signature: node_signature(node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                return;
            }
        }
    }

    // Check for function declarations/prototypes (including macro-prefixed).
    // A declaration with a function_declarator descendant is a function prototype.
    if let Some(declarator) = node.child_by_field_name("declarator") {
        if has_function_declarator(&declarator) {
            if let Some(name) = find_identifier(&declarator, source) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name,
                    signature: node_signature(node, source),
                    visibility: c_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                return;
            }
        }
    }

    // Check for const-qualified variable declarations
    if text.contains("const ") || text.contains("const\t") {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(name) = find_identifier(&declarator, source) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Constant,
                    name,
                    signature: node_signature(node, source),
                    visibility: c_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
    }
}

/// Extract entities from a `type_definition` (typedef) node.
///
/// If the typedef wraps a struct_specifier or enum_specifier, extract the
/// appropriate entity kind. Otherwise treat it as a type alias.
fn extract_type_definition(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
) {
    // The typedef name is in the `declarator` field (the alias name).
    let typedef_name = node.child_by_field_name("declarator").and_then(|d| {
        let text = d.utf8_text(source).unwrap_or("").to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    });

    // Check if the typedef wraps a struct_specifier
    if let Some(struct_node) = find_child_of_kind(node, "struct_specifier") {
        // Prefer the typedef name, fall back to the struct tag name
        let name = typedef_name.clone().or_else(|| {
            struct_node.child_by_field_name("name").and_then(|n| {
                let t = n.utf8_text(source).unwrap_or("").to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            })
        });
        if let Some(name) = name {
            entities.push(ExtractedEntity {
                kind: EntityKind::Class,
                name,
                signature: node_signature(node, source),
                visibility: Visibility::Public,
                doc_summary: extract_preceding_comment(node, source),
                fingerprint: compute_fingerprint(node, source),
                span: span_from_node(node, file_id),
            });
            return;
        }
    }

    // Check if the typedef wraps an enum_specifier
    if let Some(enum_node) = find_child_of_kind(node, "enum_specifier") {
        let name = typedef_name.clone().or_else(|| {
            enum_node.child_by_field_name("name").and_then(|n| {
                let t = n.utf8_text(source).unwrap_or("").to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            })
        });
        if let Some(name) = name {
            entities.push(ExtractedEntity {
                kind: EntityKind::EnumDef,
                name,
                signature: node_signature(node, source),
                visibility: Visibility::Public,
                doc_summary: extract_preceding_comment(node, source),
                fingerprint: compute_fingerprint(node, source),
                span: span_from_node(node, file_id),
            });
            return;
        }
    }

    // Plain typedef (e.g., `typedef unsigned long size_t;`)
    if let Some(name) = typedef_name {
        entities.push(ExtractedEntity {
            kind: EntityKind::TypeAlias,
            name,
            signature: node_signature(node, source),
            visibility: Visibility::Public,
            doc_summary: extract_preceding_comment(node, source),
            fingerprint: compute_fingerprint(node, source),
            span: span_from_node(node, file_id),
        });
    }
}

/// Find the first direct child of a given kind (non-recursive).
fn find_child_of_kind<'a>(
    node: &tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let count = node.child_count();
    for i in 0..count {
        let Ok(child_index) = i.try_into() else {
            continue;
        };
        if let Some(child) = node.child(child_index) {
            if child.kind() == kind {
                return Some(child);
            }
        }
    }
    None
}

/// Determine visibility for a C declaration.
/// `static` → Private, everything else → Public.
fn c_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    // Check for `static` storage class specifier among direct children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" {
            let text = child.utf8_text(source).unwrap_or("");
            if text == "static" {
                return Visibility::Private;
            }
        }
    }
    Visibility::Public
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "comment" {
        let text = prev.utf8_text(source).ok()?;
        let cleaned = text
            .trim_start_matches("/*")
            .trim_end_matches("*/")
            .trim_start_matches("//")
            .trim()
            .to_string();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    } else {
        None
    }
}

/// Extract `#include` directive as an import relation and a `FileImport`.
fn extract_c_include(
    node: &tree_sitter::Node,
    source: &[u8],
    _file_id: &FilePathId,
    _relations: &mut Vec<ExtractedRelation>,
    imports: &mut Vec<FileImport>,
) {
    // The path child is either a `system_lib_string` (<stdio.h>) or
    // `string_literal` ("myheader.h").
    let path_node = node.child_by_field_name("path").or_else(|| {
        // Fallback: search children for the path token.
        // Use index-based iteration to avoid borrow-checker issues with cursor.
        let count = node.child_count();
        (0..count)
            .filter_map(|i| i.try_into().ok().and_then(|index| node.child(index)))
            .find(|c| c.kind() == "system_lib_string" || c.kind() == "string_literal")
    });

    if let Some(path_node) = path_node {
        let raw_path = path_node.utf8_text(source).unwrap_or("").to_string();
        let module_path = raw_path
            .trim_matches(|c| c == '"' || c == '<' || c == '>')
            .to_string();

        if !module_path.is_empty() {
            let local_name = module_path
                .rsplit('/')
                .next()
                .unwrap_or(&module_path)
                .to_string();

            imports.push(FileImport {
                module_path,
                specifiers: vec![ImportedName {
                    local_name,
                    original_name: Some("default".to_string()),
                    is_default: true,
                }],
            });
        }
    }
}

/// Recursively walk a function body to find `call_expression` nodes.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                let callee = function.utf8_text(source).unwrap_or("").to_string();
                if is_valid_callee(&callee) {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee,
                        import_source: None,
                    });
                }
            }
        }
        extract_calls_from_body(&child, source, context_name, relations);
    }
}

fn is_valid_callee(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.chars().all(|c| c.is_numeric())
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_function() {
        let adapter = CAdapter;
        let source = b"int add(int a, int b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "add");
        assert_eq!(funcs[0].visibility, Visibility::Public);
    }

    #[test]
    fn extract_static_function() {
        let adapter = CAdapter;
        let source = b"static int helper(void) { return 0; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "helper");
        assert_eq!(funcs[0].visibility, Visibility::Private);
    }

    #[test]
    fn extract_struct() {
        let adapter = CAdapter;
        let source = b"struct Point { int x; int y; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Point");
    }

    #[test]
    fn extract_typedef_struct() {
        let adapter = CAdapter;
        let source = b"typedef struct { int x; int y; } Vec2;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Vec2");
    }

    #[test]
    fn extract_enum() {
        let adapter = CAdapter;
        let source = b"enum Color { RED, GREEN, BLUE };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Color");
    }

    #[test]
    fn extract_typedef_alias() {
        let adapter = CAdapter;
        let source = b"typedef unsigned long size_t;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let aliases: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::TypeAlias)
            .collect();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].name, "size_t");
    }

    #[test]
    fn extract_includes_as_imports() {
        let adapter = CAdapter;
        let source = b"#include <stdio.h>\n#include \"myheader.h\"\nint main() { return 0; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 2);

        let stdio = output
            .imports
            .iter()
            .find(|i| i.module_path == "stdio.h")
            .expect("should have stdio.h import");
        assert_eq!(stdio.specifiers[0].local_name, "stdio.h");
        assert_eq!(
            stdio.specifiers[0].original_name.as_deref(),
            Some("default")
        );
        assert!(stdio.specifiers[0].is_default);

        let myheader = output
            .imports
            .iter()
            .find(|i| i.module_path == "myheader.h")
            .expect("should have myheader.h import");
        assert_eq!(myheader.specifiers[0].local_name, "myheader.h");

        assert!(
            output
                .relations
                .iter()
                .all(|r| r.kind != kin_model::RelationKind::Imports),
            "imports should be carried by FileImport, not fake file-sourced relations"
        );
    }

    #[test]
    fn extracts_lowercase_preprocessor_macro_definitions_without_use_noise() {
        let adapter = CAdapter;
        let source = b"#define private public\nstruct Secret { int value; };\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("secret.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macro_entity = output
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Macro && entity.name == "private")
            .expect("lowercase preprocessor definitions should remain graph-visible macros");
        assert!(
            macro_entity.signature.contains("#define private public"),
            "macro signature should preserve the source directive, got {:?}",
            macro_entity.signature
        );
        assert!(
            output.relations.iter().all(|relation| relation.kind
                != kin_model::RelationKind::UsesMacro
                || relation.dst_name != "private"),
            "lowercase identifiers should not be promoted to macro-use edges"
        );
    }

    #[test]
    fn extract_call_relations() {
        let adapter = CAdapter;
        let source = b"void greet() { printf(\"hello\"); helper(); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .collect();
        assert!(
            calls.len() >= 2,
            "expected at least 2 calls, got {}",
            calls.len()
        );
        let dst_names: Vec<&str> = calls.iter().map(|c| c.dst_name.as_str()).collect();
        assert!(dst_names.contains(&"printf"));
        assert!(dst_names.contains(&"helper"));
    }

    #[test]
    fn extract_multiple_entities() {
        let adapter = CAdapter;
        let source = br#"
#include <stdlib.h>

typedef struct {
    int x;
    int y;
} Point;

enum Direction { NORTH, SOUTH, EAST, WEST };

static int internal_helper(void) { return 42; }

int compute(Point p) { return internal_helper() + p.x; }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("multi.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let names: Vec<&str> = output.entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Point"), "missing Point, got: {:?}", names);
        assert!(
            names.contains(&"Direction"),
            "missing Direction, got: {:?}",
            names
        );
        assert!(
            names.contains(&"internal_helper"),
            "missing internal_helper, got: {:?}",
            names
        );
        assert!(
            names.contains(&"compute"),
            "missing compute, got: {:?}",
            names
        );

        // Verify visibility
        let helper = output
            .entities
            .iter()
            .find(|e| e.name == "internal_helper")
            .unwrap();
        assert_eq!(helper.visibility, Visibility::Private);

        let compute = output
            .entities
            .iter()
            .find(|e| e.name == "compute")
            .unwrap();
        assert_eq!(compute.visibility, Visibility::Public);

        // Verify call relation from compute -> internal_helper
        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls && r.src_name == "compute")
            .collect();
        assert!(
            calls.iter().any(|c| c.dst_name == "internal_helper"),
            "compute should call internal_helper, got: {:?}",
            calls
        );

        // Verify include import
        assert_eq!(output.imports.len(), 1);
        assert_eq!(output.imports[0].module_path, "stdlib.h");
    }

    #[test]
    fn extract_preprocessor_macros_as_entities() {
        let adapter = CAdapter;
        let source = br#"
#define JSON_DIAGNOSTICS 1
#define JSON_ASSERT(x) do { if (!(x)) abort(); } while (0)
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("include/nlohmann/detail/macro_scope.h");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macros: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Macro)
            .collect();
        let names: Vec<&str> = macros.iter().map(|e| e.name.as_str()).collect();

        assert!(names.contains(&"JSON_DIAGNOSTICS"), "macros={names:?}");
        assert!(names.contains(&"JSON_ASSERT"), "macros={names:?}");
    }

    #[test]
    fn extract_block_comment_doc_summary() {
        let adapter = CAdapter;
        let source = b"/* Adds two integers. */\nint add(int a, int b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "add")
            .expect("should find add");
        assert_eq!(func.doc_summary.as_deref(), Some("Adds two integers."));
    }

    #[test]
    fn extract_line_comment_doc_summary() {
        let adapter = CAdapter;
        let source = b"// Increments the counter.\nint inc(int x) { return x + 1; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "inc")
            .expect("should find inc");
        assert_eq!(func.doc_summary.as_deref(), Some("Increments the counter."));
    }

    #[test]
    fn no_comment_yields_none() {
        let adapter = CAdapter;
        let source = b"int bare(void) { return 0; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "bare")
            .expect("should find bare");
        assert!(func.doc_summary.is_none());
    }

    #[test]
    fn extract_macro_usages_with_enclosing_scope() {
        let adapter = CAdapter;
        let source = b"void my_func() { MY_MACRO(); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::UsesMacro && r.dst_name == "MY_MACRO")
            .collect();
        assert!(!calls.is_empty());
        for call in &calls {
            assert_eq!(call.src_name, "my_func");
        }
    }

    #[test]
    fn extract_union() {
        let adapter = CAdapter;
        let source = b"union Value { int i; float f; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let unions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(unions.len(), 1);
        assert_eq!(unions[0].name, "Value");
        assert_eq!(unions[0].visibility, Visibility::Public);
    }

    #[test]
    fn extract_union_declared_with_variable() {
        let adapter = CAdapter;
        let source = b"union Data { int i; float f; } shared;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let unions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(unions.len(), 1);
        assert_eq!(unions[0].name, "Data");
    }
}

fn find_enclosing_entity(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut scopes = Vec::new();
    let mut curr = *node;

    while let Some(parent) = curr.parent() {
        match parent.kind() {
            "function_definition" => {
                if let Some(name) = extract_function_name(&parent, source) {
                    scopes.push(name);
                }
            }
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    if let Ok(name_text) = name_node.utf8_text(source) {
                        let name = name_text.trim().to_string();
                        if !name.is_empty() {
                            scopes.push(name);
                        }
                    }
                }
            }
            _ => {}
        }
        curr = parent;
    }

    if scopes.is_empty() {
        None
    } else {
        scopes.reverse();
        Some(scopes.join("::"))
    }
}

fn extract_includes_and_macros_recursive(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &kin_model::FilePathId,
    imports: &mut Vec<crate::extract::FileImport>,
    relations: &mut Vec<crate::extract::ExtractedRelation>,
) {
    if node.kind() == "preproc_include" {
        extract_c_include(node, source, file_id, relations, imports);
    } else if matches!(
        node.kind(),
        "identifier" | "type_identifier" | "statement_identifier" | "field_identifier"
    ) {
        if let Ok(name) = node.utf8_text(source) {
            if is_all_caps_macro(name) {
                if let Some(src_name) = find_enclosing_entity(node, source) {
                    if src_name != name && !src_name.ends_with(&format!("::{}", name)) {
                        relations.push(crate::extract::ExtractedRelation {
                            site: None,
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::UsesMacro,
                            src_name,
                            dst_name: name.to_string(),
                            import_source: None,
                        });
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_includes_and_macros_recursive(&child, source, file_id, imports, relations);
    }
}

fn is_all_caps_macro(name: &str) -> bool {
    let mut has_upper = false;
    for c in name.chars() {
        if c.is_ascii_lowercase() {
            return false;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    has_upper && name.len() >= 3
}
