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

pub struct JavaAdapter;

impl LanguageAdapter for JavaAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Java
    }

    fn file_extensions(&self) -> &[&str] {
        &["java"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_java::LANGUAGE)?;
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
            extract_java_node(&child, source, file_id, None, &mut entities, &mut relations);
            if child.kind() == "import_declaration" {
                if let Some(file_import) = extract_java_import(&child, source) {
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
            if matches!(rel.kind, kin_model::RelationKind::Calls | kin_model::RelationKind::References) {
                if let Some(&module) = import_map.get(rel.dst_name.as_str()) {
                    rel.import_source = Some(module.to_string());
                }
            }
        }

        // Detect @Test annotated methods (JUnit)
        let mut tests = Vec::new();
        extract_java_tests(&root, source, &mut tests);

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests,
            parse_state,
        })
    }
}

fn extract_java_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let vis = detect_java_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Extract superclass
                if let Some(sc) = node.child_by_field_name("superclass") {
                    let parent_name = sc.utf8_text(source).unwrap_or("").to_string();
                    if !parent_name.is_empty() {
                        relations.push(ExtractedRelation {
                            kind: kin_model::RelationKind::Extends,
                            src_name: name.clone(),
                            dst_name: parent_name,
                            import_source: None,
                        });
                    }
                }

                // Extract interfaces
                if let Some(ifaces) = node.child_by_field_name("interfaces") {
                    let mut iface_cursor = ifaces.walk();
                    for iface in ifaces.children(&mut iface_cursor) {
                        if iface.is_named() {
                            let iface_name = iface.utf8_text(source).unwrap_or("").to_string();
                            if !iface_name.is_empty() {
                                relations.push(ExtractedRelation {
                                    kind: kin_model::RelationKind::Implements,
                                    src_name: name.clone(),
                                    dst_name: iface_name,
                                    import_source: None,
                                });
                            }
                        }
                    }
                }

                // Recurse into class body
                if let Some(body) = node.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for member in body.children(&mut body_cursor) {
                        extract_java_node(
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
        "interface_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Interface,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_java_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "enum_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::EnumDef,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_java_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "method_declaration" | "constructor_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let method_name = name_node.utf8_text(source).unwrap_or("").to_string();
                let qualified = if let Some(cls) = class_ctx {
                    format!("{}.{}", cls, method_name)
                } else {
                    method_name
                };
                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_java_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                if let Some(cls) = class_ctx {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified.clone(),
                        import_source: None,
                    });
                }
                extract_calls_from_body(node, source, &qualified, relations);
            }
        }
        "field_declaration" => {
            // Extract constant fields (static final)
            let text = node.utf8_text(source).unwrap_or("");
            if text.contains("static") && text.contains("final") {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let name = name_node.utf8_text(source).unwrap_or("").to_string();
                            let qualified = if let Some(cls) = class_ctx {
                                format!("{}.{}", cls, name)
                            } else {
                                name
                            };
                            entities.push(ExtractedEntity {
                                kind: EntityKind::Constant,
                                name: qualified,
                                signature: node_signature(node, source),
                                visibility: detect_java_visibility(node, source),
                                doc_summary: None,
                                fingerprint: compute_fingerprint(node, source),
                                span: span_from_node(node, file_id),
                            });
                        }
                    }
                }
            }
        }
        "import_declaration" => {
            let text = node.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                relations.push(ExtractedRelation {
                    kind: kin_model::RelationKind::Imports,
                    src_name: file_id.to_string(),
                    dst_name: text,
                    import_source: None,
                });
            }
        }
        "program" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_java_node(&child, source, file_id, class_ctx, entities, relations);
            }
        }
        _ => {}
    }
}

fn detect_java_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    // Check for modifiers
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let text = child.utf8_text(source).unwrap_or("");
            if text.contains("public") {
                return Visibility::Public;
            } else if text.contains("private") {
                return Visibility::Private;
            } else if text.contains("protected") {
                return Visibility::Internal;
            }
        }
    }
    // Java default is package-private
    Visibility::Internal
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    let text = node.utf8_text(source).unwrap_or("");
    text.lines()
        .next()
        .unwrap_or(text)
        .trim_end_matches('{')
        .trim()
        .to_string()
}

fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "block_comment" || prev.kind() == "line_comment" {
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

/// Recursively walk a method body to find `method_invocation` nodes.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "method_invocation" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let callee = name_node.utf8_text(source).unwrap_or("").to_string();
                if !callee.is_empty() {
                    relations.push(ExtractedRelation {
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

/// Extract a structured import from a Java `import_declaration` node.
fn extract_java_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    // Find the scoped_identifier or identifier child
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "scoped_identifier" {
            let full_path = child.utf8_text(source).unwrap_or("").to_string();
            if full_path.is_empty() {
                return None;
            }
            // Split into module_path (everything before last dot) and local_name (last segment)
            if let Some(dot_pos) = full_path.rfind('.') {
                let module_path = full_path[..dot_pos].to_string();
                let local_name = full_path[dot_pos + 1..].to_string();
                return Some(FileImport {
                    module_path,
                    specifiers: vec![ImportedName {
                        local_name,
                        original_name: None,
                        is_default: false,
                    }],
                });
            } else {
                // No dot — entire path is the name
                return Some(FileImport {
                    module_path: String::new(),
                    specifiers: vec![ImportedName {
                        local_name: full_path,
                        original_name: None,
                        is_default: false,
                    }],
                });
            }
        }
    }
    None
}

/// Recursively detect @Test annotated methods in Java source.
fn extract_java_tests(node: &tree_sitter::Node, source: &[u8], tests: &mut Vec<ExtractedTest>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "method_declaration" {
            // Check for @Test annotation on preceding siblings or children
            if has_test_annotation(&child, source) {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    if !name.is_empty() {
                        tests.push(ExtractedTest {
                            name,
                            kind: ExtractedTestKind::Unit,
                            runner: "junit".to_string(),
                        });
                    }
                }
            }
        }
        // Recurse into class bodies, etc.
        extract_java_tests(&child, source, tests);
    }
}

/// Check if a method has an @Test annotation (marker_annotation or annotation).
fn has_test_annotation(node: &tree_sitter::Node, source: &[u8]) -> bool {
    // Check children (modifiers node contains annotations)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for m in child.children(&mut mod_cursor) {
                if m.kind() == "marker_annotation" || m.kind() == "annotation" {
                    let text = m.utf8_text(source).unwrap_or("");
                    if text.contains("Test") {
                        return true;
                    }
                }
            }
        }
        if child.kind() == "marker_annotation" || child.kind() == "annotation" {
            let text = child.utf8_text(source).unwrap_or("");
            if text.contains("Test") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_java_class() {
        let adapter = JavaAdapter;
        let source = b"public class Dog { public void bark() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Dog.java");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Dog");
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].name, "Dog.bark");
    }

    #[test]
    fn parse_java_interface() {
        let adapter = JavaAdapter;
        let source = b"public interface Runnable { void run(); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Runnable.java");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let ifaces: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Interface)
            .collect();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "Runnable");
    }

    #[test]
    fn parse_java_method_calls() {
        let adapter = JavaAdapter;
        let source =
            b"public class App { public void run() { System.out.println(\"hi\"); doWork(); } }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("App.java");
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
        assert!(dst_names.contains(&"println"));
        assert!(dst_names.contains(&"doWork"));
    }

    #[test]
    fn parse_java_imports() {
        let adapter = JavaAdapter;
        let source = b"import java.util.List;\nimport java.io.File;\n\npublic class App {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("App.java");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 2);

        let list_import = output
            .imports
            .iter()
            .find(|i| i.module_path == "java.util")
            .unwrap();
        assert_eq!(list_import.specifiers.len(), 1);
        assert_eq!(list_import.specifiers[0].local_name, "List");

        let file_import = output
            .imports
            .iter()
            .find(|i| i.module_path == "java.io")
            .unwrap();
        assert_eq!(file_import.specifiers.len(), 1);
        assert_eq!(file_import.specifiers[0].local_name, "File");
    }
}
