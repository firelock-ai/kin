use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, ParseOutput};

pub struct TypeScriptAdapter;

impl LanguageAdapter for TypeScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::TypeScript
    }

    fn file_extensions(&self) -> &[&str] {
        &["ts", "tsx"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT)?;
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
            extract_ts_node(&child, source, file_id, &mut entities, &mut relations);
        }

        Ok(ParseOutput {
            entities,
            relations,
            parse_state,
        })
    }
}

fn extract_ts_node(
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
                let sig = node_signature(node, source);
                let vis = detect_ts_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name,
                    signature: sig,
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let sig = node_signature(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name: name.clone(),
                    signature: sig,
                    visibility: detect_ts_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Extract heritage (extends/implements)
                extract_ts_heritage(node, source, &name, relations);

                // Recurse into class body for methods
                if let Some(body) = node.child_by_field_name("body") {
                    let mut cursor = body.walk();
                    for member in body.children(&mut cursor) {
                        extract_ts_class_member(
                            &member, source, file_id, &name, entities, relations,
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
                    visibility: detect_ts_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "type_alias_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::TypeAlias,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_ts_visibility(node, source),
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
                    visibility: detect_ts_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            // Check for `export const X = ...`
            let mut decl_cursor = node.walk();
            for declarator in node.children(&mut decl_cursor) {
                if declarator.kind() == "variable_declarator" {
                    if let Some(name_node) = declarator.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        entities.push(ExtractedEntity {
                            kind: EntityKind::Constant,
                            name,
                            signature: node_signature(node, source),
                            visibility: detect_ts_visibility(node, source),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(node, source),
                            span: span_from_node(node, file_id),
                        });
                    }
                }
            }
        }
        "export_statement" => {
            // Recurse into exported declaration
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_ts_node(&child, source, file_id, entities, relations);
            }
        }
        "import_statement" => {
            // Extract import relations
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

fn extract_ts_class_member(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_name: &str,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "method_definition" | "public_field_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let qualified = format!("{}.{}", class_name, name);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_ts_member_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                relations.push(ExtractedRelation {
                    kind: kin_model::RelationKind::Contains,
                    src_name: class_name.to_string(),
                    dst_name: qualified,
                });
            }
        }
        _ => {}
    }
}

fn extract_ts_heritage(
    node: &tree_sitter::Node,
    source: &[u8],
    class_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_heritage" {
            let mut heritage_cursor = child.walk();
            for clause in child.children(&mut heritage_cursor) {
                match clause.kind() {
                    "extends_clause" => {
                        if let Some(value) = clause.child(1) {
                            let parent = value.utf8_text(source).unwrap_or("").to_string();
                            if !parent.is_empty() {
                                relations.push(ExtractedRelation {
                                    kind: kin_model::RelationKind::Extends,
                                    src_name: class_name.to_string(),
                                    dst_name: parent,
                                });
                            }
                        }
                    }
                    "implements_clause" => {
                        let mut impl_cursor = clause.walk();
                        for iface in clause.children(&mut impl_cursor) {
                            if iface.is_named() && iface.kind() != "implements" {
                                let iface_name =
                                    iface.utf8_text(source).unwrap_or("").to_string();
                                if !iface_name.is_empty() {
                                    relations.push(ExtractedRelation {
                                        kind: kin_model::RelationKind::Implements,
                                        src_name: class_name.to_string(),
                                        dst_name: iface_name,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn detect_ts_visibility(node: &tree_sitter::Node, _source: &[u8]) -> Visibility {
    // Check if parent is an export statement
    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" {
            return Visibility::Public;
        }
    }
    Visibility::Private
}

fn detect_ts_member_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let text = node.utf8_text(source).unwrap_or("");
    if text.starts_with("private") || text.contains("private ") {
        Visibility::Private
    } else if text.starts_with("protected") || text.contains("protected ") {
        Visibility::Internal
    } else {
        Visibility::Public
    }
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    let text = node.utf8_text(source).unwrap_or("");
    // Take first line or up to opening brace
    let sig = text
        .lines()
        .next()
        .unwrap_or(text)
        .trim_end_matches('{')
        .trim();
    sig.to_string()
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
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typescript_function() {
        let adapter = TypeScriptAdapter;
        let source = b"export function greet(name: string): string { return `Hello ${name}`; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        assert!(!output.entities.is_empty());
        let func = &output.entities[0];
        assert_eq!(func.kind, EntityKind::Function);
        assert_eq!(func.name, "greet");
    }

    #[test]
    fn parse_typescript_class() {
        let adapter = TypeScriptAdapter;
        let source = br#"
export class Dog extends Animal implements Pet {
    name: string;
    bark(): void {}
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let class_entities: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(class_entities.len(), 1);
        assert_eq!(class_entities[0].name, "Dog");

        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert_eq!(extends.len(), 1);
        assert_eq!(extends[0].dst_name, "Animal");
    }

    #[test]
    fn detect_broken_ast() {
        let adapter = TypeScriptAdapter;
        let source = b"function foo( { return 1; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("broken.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Incomplete { .. }));
    }
}
