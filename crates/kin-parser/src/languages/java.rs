use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, ParseOutput};

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
        parser.parse(source, None).ok_or_else(|| {
            crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            }
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
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_java_node(&child, source, file_id, None, &mut entities, &mut relations);
        }

        Ok(ParseOutput {
            entities,
            relations,
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
                        dst_name: qualified,
                    });
                }
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
        if cleaned.is_empty() { None } else { Some(cleaned) }
    } else {
        None
    }
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
}
