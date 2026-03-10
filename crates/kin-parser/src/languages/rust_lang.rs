use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, ParseOutput};

pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Rust
    }

    fn file_extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_rust::LANGUAGE)?;
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
            extract_rust_node(&child, source, file_id, &mut entities, &mut relations);
        }

        Ok(ParseOutput {
            entities,
            relations,
            parse_state,
        })
    }
}

fn extract_rust_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "struct_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "enum_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::EnumDef,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "trait_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::TraitDef,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "type_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::TypeAlias,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "const_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Constant,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "static_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::StaticVar,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "impl_item" => {
            // Extract methods from impl blocks
            let type_name = node
                .child_by_field_name("type")
                .and_then(|t| Some(t.utf8_text(source).unwrap_or("").to_string()))
                .unwrap_or_default();

            // Check for trait impl
            let trait_name = node
                .child_by_field_name("trait")
                .and_then(|t| Some(t.utf8_text(source).unwrap_or("").to_string()));

            if let Some(ref trait_n) = trait_name {
                if !trait_n.is_empty() && !type_name.is_empty() {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Implements,
                        src_name: type_name.clone(),
                        dst_name: trait_n.clone(),
                    });
                }
            }

            if let Some(body) = node.child_by_field_name("body") {
                let mut body_cursor = body.walk();
                for member in body.children(&mut body_cursor) {
                    if member.kind() == "function_item" {
                        if let Some(name_node) = member.child_by_field_name("name") {
                            let method_name =
                                name_node.utf8_text(source).unwrap_or("").to_string();
                            let qualified = if type_name.is_empty() {
                                method_name
                            } else {
                                format!("{}::{}", type_name, method_name)
                            };
                            entities.push(ExtractedEntity {
                                kind: EntityKind::Method,
                                name: qualified.clone(),
                                signature: node_signature(&member, source),
                                visibility: detect_rust_visibility(&member, source),
                                doc_summary: extract_doc_comment(&member, source),
                                fingerprint: compute_fingerprint(&member, source),
                                span: span_from_node(&member, file_id),
                            });
                            if !type_name.is_empty() {
                                relations.push(ExtractedRelation {
                                    kind: kin_model::RelationKind::Contains,
                                    src_name: type_name.clone(),
                                    dst_name: qualified,
                                });
                            }
                        }
                    }
                }
            }
        }
        "mod_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Module,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "use_declaration" => {
            let text = node.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                relations.push(ExtractedRelation {
                    kind: kin_model::RelationKind::Imports,
                    src_name: file_id.to_string(),
                    dst_name: text,
                });
            }
        }
        _ => {}
    }
}

fn detect_rust_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            let text = child.utf8_text(source).unwrap_or("");
            if text.contains("pub(crate)") {
                return Visibility::Crate;
            } else if text.contains("pub(super)") || text.contains("pub(in") {
                return Visibility::Internal;
            } else if text == "pub" {
                return Visibility::Public;
            }
        }
    }
    Visibility::Private
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

fn extract_doc_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Collect preceding line_comment nodes that start with ///
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "line_comment" {
            let text = p.utf8_text(source).unwrap_or("");
            if text.starts_with("///") {
                comments.push(text.trim_start_matches('/').trim().to_string());
            } else {
                break;
            }
        } else {
            break;
        }
        prev = p.prev_sibling();
    }
    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rust_function() {
        let adapter = RustAdapter;
        let source = b"pub fn add(a: i32, b: i32) -> i32 { a + b }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
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
    fn parse_rust_struct_and_impl() {
        let adapter = RustAdapter;
        let source = br#"
pub struct Dog {
    name: String,
}

impl Dog {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub fn bark(&self) -> &str {
        "woof"
    }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("dog.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Dog");

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn parse_rust_trait() {
        let adapter = RustAdapter;
        let source = b"pub trait Animal { fn speak(&self) -> String; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("traits.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let traits: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::TraitDef)
            .collect();
        assert_eq!(traits.len(), 1);
        assert_eq!(traits[0].name, "Animal");
    }

    #[test]
    fn parse_rust_enum() {
        let adapter = RustAdapter;
        let source = b"pub enum Color { Red, Green, Blue }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("color.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Color");
    }
}
