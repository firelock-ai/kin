// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    ExtractedEntity, ExtractedRelation, ExtractedTest, ExtractedTestKind, FileImport, ImportedName,
    ParseOutput,
};

pub struct SwiftAdapter;

impl LanguageAdapter for SwiftAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Swift
    }

    fn file_extensions(&self) -> &[&str] {
        &["swift"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_swift::LANGUAGE)?;
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
            extract_swift_node(&child, source, file_id, None, &mut entities, &mut relations);
            if child.kind() == "import_declaration" {
                if let Some(file_import) = extract_swift_import(&child, source) {
                    imports.push(file_import);
                }
            }
        }

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
                } else if let Some(prefix) = rel.dst_name.split('.').next() {
                    if let Some(&module) = import_map.get(prefix) {
                        rel.import_source = Some(module.to_string());
                    }
                }
            }
        }

        // Detect XCTest methods (func testXxx()) and @Test-annotated functions
        let mut tests = Vec::new();
        for ent in &entities {
            if ent.kind == EntityKind::Method && ent.name.contains('.') {
                let method_name = ent.name.rsplit('.').next().unwrap_or(&ent.name);
                if method_name.starts_with("test") {
                    tests.push(ExtractedTest {
                        name: ent.name.clone(),
                        kind: ExtractedTestKind::Unit,
                        runner: "xctest".to_string(),
                    });
                }
            }
        }

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests,
            parse_state,
        })
    }
}

fn extract_swift_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "class_declaration" => {
            // tree-sitter-swift uses class_declaration for class, struct, enum,
            // extension, and actor. The declaration_kind field distinguishes them.
            let decl_kind = node
                .child_by_field_name("declaration_kind")
                .map(|n| n.kind().to_string())
                .unwrap_or_default();

            if let Some(name_node) = node.child_by_field_name("name") {
                let name = extract_name_text(&name_node, source);
                if name.is_empty() {
                    return;
                }

                let entity_kind = match decl_kind.as_str() {
                    "class" => EntityKind::Class,
                    "struct" => EntityKind::Class,
                    "enum" => EntityKind::EnumDef,
                    "actor" => EntityKind::Class,
                    "extension" => {
                        // Extensions add methods to existing types; emit as Module
                        // and recurse into body with the extended type as context.
                        let body = find_child_by_kind(node, "class_body");
                        if let Some(ref body_node) = body {
                            let mut body_cursor = body_node.walk();
                            for member in body_node.children(&mut body_cursor) {
                                extract_swift_node(
                                    &member,
                                    source,
                                    file_id,
                                    Some(&name),
                                    entities,
                                    relations,
                                );
                            }
                        }
                        return;
                    }
                    _ => EntityKind::Class,
                };

                let vis = detect_swift_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: entity_kind,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Extract inheritance (superclass, protocol conformance)
                extract_inheritance(node, source, &name, relations);

                // Recurse into class/struct/enum body
                let body_kind = if decl_kind == "enum" {
                    "enum_class_body"
                } else {
                    "class_body"
                };
                if let Some(body_node) = find_child_by_kind(node, body_kind) {
                    let mut body_cursor = body_node.walk();
                    for member in body_node.children(&mut body_cursor) {
                        extract_swift_node(
                            &member,
                            source,
                            file_id,
                            Some(&name),
                            entities,
                            relations,
                        );
                    }
                }
            }
        }
        "protocol_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = extract_name_text(&name_node, source);
                if name.is_empty() {
                    return;
                }

                let vis = detect_swift_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Interface,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Protocol inheritance
                extract_inheritance(node, source, &name, relations);

                // Recurse into protocol body for method declarations
                if let Some(body_node) = find_child_by_kind(node, "protocol_body") {
                    let mut body_cursor = body_node.walk();
                    for member in body_node.children(&mut body_cursor) {
                        extract_swift_node(
                            &member,
                            source,
                            file_id,
                            Some(&name),
                            entities,
                            relations,
                        );
                    }
                }
            }
        }
        "function_declaration" | "protocol_function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let func_name = extract_name_text(&name_node, source);
                if func_name.is_empty() {
                    return;
                }

                let (kind, qualified) = if let Some(cls) = class_ctx {
                    (EntityKind::Method, format!("{}.{}", cls, func_name))
                } else {
                    (EntityKind::Function, func_name)
                };

                let vis = detect_swift_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                if let Some(cls) = class_ctx {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified.clone(),
                        import_source: None,
                    });
                }

                extract_calls_from_body(node, source, &qualified, relations);
            }
        }
        "init_declaration" => {
            let init_name = if let Some(cls) = class_ctx {
                format!("{}.init", cls)
            } else {
                "init".to_string()
            };

            entities.push(ExtractedEntity {
                kind: EntityKind::Method,
                name: init_name.clone(),
                signature: node_signature(node, source),
                visibility: detect_swift_visibility(node, source),
                doc_summary: extract_preceding_comment(node, source),
                fingerprint: compute_fingerprint(node, source),
                span: span_from_node(node, file_id),
            });

            if let Some(cls) = class_ctx {
                relations.push(ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: kin_model::RelationKind::Contains,
                    src_name: cls.to_string(),
                    dst_name: init_name.clone(),
                    import_source: None,
                });
            }

            extract_calls_from_body(node, source, &init_name, relations);
        }
        "deinit_declaration" => {
            if let Some(cls) = class_ctx {
                let deinit_name = format!("{}.deinit", cls);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: deinit_name.clone(),
                    signature: "deinit".to_string(),
                    visibility: Visibility::Internal,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                relations.push(ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: kin_model::RelationKind::Contains,
                    src_name: cls.to_string(),
                    dst_name: deinit_name,
                    import_source: None,
                });
            }
        }
        "property_declaration" | "protocol_property_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let prop_name = extract_pattern_name(&name_node, source);
                if prop_name.is_empty() {
                    return;
                }

                let is_constant = is_let_binding(&name_node, source);
                let qualified = if let Some(cls) = class_ctx {
                    format!("{}.{}", cls, prop_name)
                } else {
                    prop_name
                };

                let kind = if class_ctx.is_none() && is_constant {
                    EntityKind::Constant
                } else {
                    EntityKind::StaticVar
                };

                entities.push(ExtractedEntity {
                    kind,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_swift_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                if let Some(cls) = class_ctx {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified,
                        import_source: None,
                    });
                }
            }
        }
        "typealias_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = extract_name_text(&name_node, source);
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::TypeAlias,
                        name,
                        signature: node_signature(node, source),
                        visibility: detect_swift_visibility(node, source),
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        "enum_entry" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let case_name = extract_name_text(&name_node, source);
                if !case_name.is_empty() {
                    let qualified = if let Some(cls) = class_ctx {
                        format!("{}.{}", cls, case_name)
                    } else {
                        case_name
                    };

                    entities.push(ExtractedEntity {
                        kind: EntityKind::Constant,
                        name: qualified.clone(),
                        signature: node_signature(node, source),
                        visibility: detect_swift_visibility(node, source),
                        doc_summary: None,
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });

                    if let Some(cls) = class_ctx {
                        relations.push(ExtractedRelation {
                            site: None,
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::Contains,
                            src_name: cls.to_string(),
                            dst_name: qualified,
                            import_source: None,
                        });
                    }
                }
            }
        }
        "import_declaration" => {}
        _ => {}
    }
}

/// Extract the text name from a node, handling both simple_identifier
/// and type_identifier / user_type nodes.
fn extract_name_text(node: &tree_sitter::Node, source: &[u8]) -> String {
    match node.kind() {
        "simple_identifier" | "type_identifier" => node.utf8_text(source).unwrap_or("").to_string(),
        _ => {
            // For composite nodes (user_type, etc.), try to find the first
            // simple_identifier or type_identifier child.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "simple_identifier" || child.kind() == "type_identifier" {
                    return child.utf8_text(source).unwrap_or("").to_string();
                }
            }
            // Fallback: use the node's own text
            node.utf8_text(source).unwrap_or("").to_string()
        }
    }
}

/// Extract the bound variable name from a pattern node.
/// Swift property_declaration has name -> pattern -> value_binding_pattern -> bound_identifier.
fn extract_pattern_name(node: &tree_sitter::Node, source: &[u8]) -> String {
    // Direct simple_identifier
    if node.kind() == "simple_identifier" {
        return node.utf8_text(source).unwrap_or("").to_string();
    }

    // Look for bound_identifier field or simple_identifier children recursively
    if let Some(bound) = node.child_by_field_name("bound_identifier") {
        return extract_name_text(&bound, source);
    }

    // Walk children to find simple_identifier
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "simple_identifier" {
            return child.utf8_text(source).unwrap_or("").to_string();
        }
        let found = extract_pattern_name(&child, source);
        if !found.is_empty() {
            return found;
        }
    }

    String::new()
}

/// Check if a pattern node represents a let binding (constant).
fn is_let_binding(node: &tree_sitter::Node, source: &[u8]) -> bool {
    // Look for value_binding_pattern with mutability field = "let"
    if node.kind() == "value_binding_pattern" {
        if let Some(mutability) = node.child_by_field_name("mutability") {
            return mutability.utf8_text(source).unwrap_or("") == "let";
        }
    }
    // Check parent signature text as fallback
    if let Some(parent) = node.parent() {
        let text = parent.utf8_text(source).unwrap_or("");
        return text.trim_start().starts_with("let ");
    }
    false
}

/// Extract inheritance/conformance from a class, struct, enum, or protocol declaration.
fn extract_inheritance(
    node: &tree_sitter::Node,
    source: &[u8],
    type_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_constraints" || child.kind() == "inheritance_specifier" {
            extract_type_names_from_inheritance(&child, source, type_name, relations);
        }
    }
}

fn extract_type_names_from_inheritance(
    node: &tree_sitter::Node,
    source: &[u8],
    type_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "user_type" || child.kind() == "type_identifier" {
            let parent_name = extract_name_text(&child, source);
            if !parent_name.is_empty() && parent_name != type_name {
                // In Swift, the first item in the inheritance list for a class
                // could be either a superclass or a protocol. Without type resolution
                // we emit Implements (protocol conformance) for all, which is the
                // safer assumption.
                relations.push(ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: kin_model::RelationKind::Implements,
                    src_name: type_name.to_string(),
                    dst_name: parent_name,
                    import_source: None,
                });
            }
        }
        // Recurse for nested type nodes
        if child.kind() != "user_type" && child.kind() != "type_identifier" {
            extract_type_names_from_inheritance(&child, source, type_name, relations);
        }
    }
}

fn detect_swift_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for modifier in child.children(&mut mod_cursor) {
                if modifier.kind() == "visibility_modifier" {
                    let text = modifier.utf8_text(source).unwrap_or("");
                    return match text {
                        "public" | "open" => Visibility::Public,
                        "private" | "fileprivate" => Visibility::Private,
                        _ => Visibility::Internal,
                    };
                }
            }
        }
    }
    // Swift default visibility is internal
    Visibility::Internal
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "comment" || prev.kind() == "multiline_comment" {
        let text = prev.utf8_text(source).ok()?;
        let cleaned = text
            .lines()
            .map(|l| {
                l.trim_start_matches('/')
                    .trim_start_matches('*')
                    .trim_end_matches('*')
                    .trim_end_matches('/')
                    .trim()
            })
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    } else {
        None
    }
}

fn find_child_by_kind<'a>(
    node: &'a tree_sitter::Node,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    let result = node.children(&mut cursor).find(|c| c.kind() == kind);
    result
}

/// Recursively walk a function/method body to find call_expression nodes.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(callee) = extract_callee_name(&child, source) {
                if !callee.is_empty() {
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

/// Extract the callee name from a call_expression.
///
/// For navigation chains like `a.b.c()` tree-sitter-swift produces:
///   (call_expression
///     (navigation_expression
///       target: (navigation_expression
///         target: (simple_identifier "a")
///         suffix: (navigation_suffix suffix: (simple_identifier "b")))
///       suffix: (navigation_suffix suffix: (simple_identifier "c")))
///     (call_suffix ...))
/// We unwrap `suffix -> navigation_suffix -> suffix (simple_identifier)` so
/// `a.b.c()` maps to `"c"` and `obj.method()` maps to `"method"`. This mirrors
/// the Python attribute-call fix and keeps Calls edges keyed on simple names.
fn extract_callee_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "simple_identifier" => {
                let raw = child.utf8_text(source).unwrap_or("");
                let stripped = raw.strip_prefix("self.").unwrap_or(raw);
                return Some(stripped.to_string());
            }
            "navigation_expression" => {
                return extract_navigation_suffix_name(&child, source);
            }
            "call_suffix" | "value_arguments" | "lambda_literal" => continue,
            _ => {}
        }
    }
    None
}

/// Pull the rightmost identifier out of a tree-sitter-swift `navigation_expression`.
/// The `suffix` field holds a `navigation_suffix` whose own `suffix` field is the
/// trailing `simple_identifier` we want.
fn extract_navigation_suffix_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let nav_suffix = node.child_by_field_name("suffix")?;
    let ident = nav_suffix.child_by_field_name("suffix")?;
    let text = ident.utf8_text(source).unwrap_or("").to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Extract a structured import from a Swift import_declaration node.
/// Swift imports: `import Foundation`, `import class UIKit.UIView`
fn extract_swift_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let text = node.utf8_text(source).unwrap_or("").trim().to_string();
    // Strip "import" keyword and optional kind specifier (class, struct, func, etc.)
    let after_import = text.strip_prefix("import")?.trim();

    // Handle `import kind Module.Symbol` form
    let module_path = match after_import.split_whitespace().count() {
        0 => return None,
        1 => after_import.to_string(),
        _ => {
            // Skip the kind specifier (class, struct, func, enum, protocol, typealias, var, let)
            let parts: Vec<&str> = after_import.splitn(2, char::is_whitespace).collect();
            let kind_keywords = [
                "class",
                "struct",
                "func",
                "enum",
                "protocol",
                "typealias",
                "var",
                "let",
            ];
            if kind_keywords.contains(&parts[0]) {
                parts.get(1).unwrap_or(&"").trim().to_string()
            } else {
                after_import.to_string()
            }
        }
    };

    if module_path.is_empty() {
        return None;
    }

    // The local name is the last component (e.g., "Foundation" from "Foundation",
    // "UIView" from "UIKit.UIView")
    let local_name = module_path
        .rsplit('.')
        .next()
        .unwrap_or(&module_path)
        .to_string();

    Some(FileImport {
        site: crate::adapter::site_from_node(node),
        module_path,
        specifiers: vec![ImportedName {
            local_name,
            original_name: None,
            is_default: false,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_swift_function() {
        let adapter = SwiftAdapter;
        let source = b"func add(_ a: Int, _ b: Int) -> Int { return a + b }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("math.swift");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "add");
    }

    #[test]
    fn parse_swift_class() {
        let adapter = SwiftAdapter;
        let source = b"public class Dog {\n    var name: String = \"\"\n    func bark() { print(\"woof\") }\n}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Dog.swift");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Dog");
        assert_eq!(classes[0].visibility, Visibility::Public);
    }

    #[test]
    fn parse_swift_struct() {
        let adapter = SwiftAdapter;
        let source = b"struct Point {\n    let x: Double\n    let y: Double\n}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Point.swift");
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
    fn parse_swift_protocol() {
        let adapter = SwiftAdapter;
        let source = b"protocol Drawable {\n    func draw()\n}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Drawable.swift");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let protocols: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Interface)
            .collect();
        assert_eq!(protocols.len(), 1);
        assert_eq!(protocols[0].name, "Drawable");
    }

    #[test]
    fn parse_swift_enum() {
        let adapter = SwiftAdapter;
        let source =
            b"enum Direction {\n    case north\n    case south\n    case east\n    case west\n}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Direction.swift");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Direction");
    }

    #[test]
    fn parse_swift_imports() {
        let adapter = SwiftAdapter;
        let source = b"import Foundation\nimport UIKit\n\nfunc main() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.swift");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 2);

        let foundation = output
            .imports
            .iter()
            .find(|i| i.module_path == "Foundation")
            .unwrap();
        assert_eq!(foundation.specifiers[0].local_name, "Foundation");

        let uikit = output
            .imports
            .iter()
            .find(|i| i.module_path == "UIKit")
            .unwrap();
        assert_eq!(uikit.specifiers[0].local_name, "UIKit");
    }

    #[test]
    fn parse_swift_method_calls() {
        let adapter = SwiftAdapter;
        let source = b"func greet() {\n    print(\"hello\")\n    doWork()\n}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("greet.swift");
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
        assert!(dst_names.contains(&"print"));
        assert!(dst_names.contains(&"doWork"));
    }

    #[test]
    fn parse_swift_visibility() {
        let adapter = SwiftAdapter;
        let source =
            b"public func publicFunc() {}\nprivate func privateFunc() {}\nfunc internalFunc() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("vis.swift");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 3);

        let public_fn = funcs.iter().find(|f| f.name == "publicFunc").unwrap();
        assert_eq!(public_fn.visibility, Visibility::Public);

        let private_fn = funcs.iter().find(|f| f.name == "privateFunc").unwrap();
        assert_eq!(private_fn.visibility, Visibility::Private);

        let internal_fn = funcs.iter().find(|f| f.name == "internalFunc").unwrap();
        assert_eq!(internal_fn.visibility, Visibility::Internal);
    }
}
