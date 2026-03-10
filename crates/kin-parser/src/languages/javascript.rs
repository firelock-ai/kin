use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, ParseOutput};

pub struct JavaScriptAdapter;

impl LanguageAdapter for JavaScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::JavaScript
    }

    fn file_extensions(&self) -> &[&str] {
        &["js", "jsx", "mjs", "cjs"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_javascript::LANGUAGE)?;
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
            extract_js_node(&child, source, file_id, &mut entities, &mut relations);
        }

        Ok(ParseOutput {
            entities,
            relations,
            parse_state,
        })
    }
}

fn extract_js_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_declaration" | "function" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_js_visibility(node),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_js_visibility(node),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Recurse into class body
                if let Some(body) = node.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for member in body.children(&mut body_cursor) {
                        if member.kind() == "method_definition" {
                            if let Some(mn) = member.child_by_field_name("name") {
                                let method_name = mn.utf8_text(source).unwrap_or("").to_string();
                                let qualified = format!("{}.{}", name, method_name);
                                entities.push(ExtractedEntity {
                                    kind: EntityKind::Method,
                                    name: qualified.clone(),
                                    signature: node_signature(&member, source),
                                    visibility: Visibility::Public,
                                    doc_summary: extract_preceding_comment(&member, source),
                                    fingerprint: compute_fingerprint(&member, source),
                                    span: span_from_node(&member, file_id),
                                });
                                relations.push(ExtractedRelation {
                                    kind: kin_model::RelationKind::Contains,
                                    src_name: name.clone(),
                                    dst_name: qualified,
                                });
                            }
                        }
                    }
                }
            }
        }
        "export_statement" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_js_node(&child, source, file_id, entities, relations);
            }
        }
        "import_statement" => {
            if let Some(src_node) = node.child_by_field_name("source") {
                let module = src_node
                    .utf8_text(source)
                    .unwrap_or("")
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_string();
                if !module.is_empty() {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Imports,
                        src_name: file_id.to_string(),
                        dst_name: module,
                    });
                }
            }
        }
        _ => {}
    }
}

fn detect_js_visibility(node: &tree_sitter::Node) -> Visibility {
    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" {
            return Visibility::Public;
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

fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "comment" {
        let text = prev.utf8_text(source).ok()?;
        let cleaned = text
            .lines()
            .map(|l| l.trim_start_matches('/').trim_start_matches('*').trim())
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
    fn parse_javascript_function() {
        let adapter = JavaScriptAdapter;
        let source = b"function add(a, b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        assert_eq!(output.entities.len(), 1);
        assert_eq!(output.entities[0].name, "add");
        assert_eq!(output.entities[0].kind, EntityKind::Function);
    }

    #[test]
    fn parse_javascript_class() {
        let adapter = JavaScriptAdapter;
        let source = b"class Foo { bar() {} baz() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 2);
    }
}
