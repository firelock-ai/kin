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

pub struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Go
    }

    fn file_extensions(&self) -> &[&str] {
        &["go"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_go::LANGUAGE)?;
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
            extract_go_node(&child, source, file_id, &mut entities, &mut relations);
            if child.kind() == "import_declaration" {
                extract_go_imports(&child, source, &mut imports);
            }
        }

        // Detect Go test functions (func TestXxx(t *testing.T))
        let mut tests = Vec::new();
        for ent in &entities {
            if ent.kind == EntityKind::Function && ent.name.starts_with("Test") {
                tests.push(ExtractedTest {
                    name: ent.name.clone(),
                    kind: ExtractedTestKind::Unit,
                    runner: "go".to_string(),
                });
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

fn extract_go_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let vis = go_visibility(&name);
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
        "method_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let method_name = name_node.utf8_text(source).unwrap_or("").to_string();
                // Try to get receiver type
                let receiver_type = node
                    .child_by_field_name("receiver")
                    .and_then(|r| extract_receiver_type(&r, source))
                    .unwrap_or_default();

                let qualified = if receiver_type.is_empty() {
                    method_name.clone()
                } else {
                    format!("{}.{}", receiver_type, method_name)
                };

                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: go_visibility(&method_name),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                extract_calls_from_body(node, source, &qualified, relations);
            }
        }
        "type_declaration" => {
            let mut cursor = node.walk();
            for spec in node.children(&mut cursor) {
                if spec.kind() == "type_spec" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let type_node = spec.child_by_field_name("type");
                        let kind = match type_node.map(|t| t.kind()) {
                            Some("struct_type") => EntityKind::Class,
                            Some("interface_type") => EntityKind::Interface,
                            _ => EntityKind::TypeAlias,
                        };
                        entities.push(ExtractedEntity {
                            kind,
                            name,
                            signature: node_signature(&spec, source),
                            visibility: go_visibility(name_node.utf8_text(source).unwrap_or("")),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&spec, source),
                            span: span_from_node(&spec, file_id),
                        });
                    }
                }
            }
        }
        "const_declaration" | "var_declaration" => {
            let mut cursor = node.walk();
            for spec in node.children(&mut cursor) {
                if spec.kind() == "const_spec" || spec.kind() == "var_spec" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let kind = if node.kind() == "const_declaration" {
                            EntityKind::Constant
                        } else {
                            EntityKind::StaticVar
                        };
                        entities.push(ExtractedEntity {
                            kind,
                            name,
                            signature: node_signature(&spec, source),
                            visibility: go_visibility(name_node.utf8_text(source).unwrap_or("")),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&spec, source),
                            span: span_from_node(&spec, file_id),
                        });
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
        _ => {}
    }
}

fn extract_receiver_type(receiver: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = receiver.walk();
    let found = receiver.children(&mut cursor).find(|n| {
        n.kind() == "parameter_declaration"
            || n.kind() == "type_identifier"
            || n.kind() == "pointer_type"
    });
    found.and_then(|pd| find_type_identifier(&pd, source))
}

fn find_type_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() == "type_identifier" {
        return Some(node.utf8_text(source).unwrap_or("").to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = find_type_identifier(&child, source) {
            return Some(name);
        }
    }
    None
}

fn go_visibility(name: &str) -> Visibility {
    if name.chars().next().is_some_and(|c| c.is_uppercase()) {
        Visibility::Public
    } else {
        Visibility::Private
    }
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
        let cleaned = text.trim_start_matches('/').trim().to_string();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    } else {
        None
    }
}

/// Recursively walk a function/method body to find `call_expression` nodes.
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
                if is_valid_callee_name(&callee) {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee,
                    });
                }
            }
        }
        extract_calls_from_body(&child, source, context_name, relations);
    }
}

fn is_valid_callee_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.chars().all(|c| c.is_numeric())
}

/// Extract structured imports from a Go `import_declaration` node.
fn extract_go_imports(node: &tree_sitter::Node, source: &[u8], imports: &mut Vec<FileImport>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "import_spec" {
            if let Some(file_import) = extract_go_import_spec(&child, source) {
                imports.push(file_import);
            }
        } else if child.kind() == "import_spec_list" {
            let mut list_cursor = child.walk();
            for spec in child.children(&mut list_cursor) {
                if spec.kind() == "import_spec" {
                    if let Some(file_import) = extract_go_import_spec(&spec, source) {
                        imports.push(file_import);
                    }
                }
            }
        }
    }
}

/// Parse a single `import_spec` node into a `FileImport`.
fn extract_go_import_spec(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let path_node = node.child_by_field_name("path")?;
    let raw_path = path_node.utf8_text(source).unwrap_or("");
    let module_path = raw_path.trim_matches('"').to_string();
    if module_path.is_empty() {
        return None;
    }

    let alias = node.child_by_field_name("name").and_then(|n| {
        let t = n.utf8_text(source).unwrap_or("").to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    });

    // Default local name is the last path segment
    let default_local = module_path
        .rsplit('/')
        .next()
        .unwrap_or(&module_path)
        .to_string();

    let (local_name, original_name) = match alias {
        Some(a) => (a, Some(default_local)),
        None => (default_local, None),
    };

    Some(FileImport {
        module_path,
        specifiers: vec![ImportedName {
            local_name,
            original_name,
            is_default: false,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_function() {
        let adapter = GoAdapter;
        let source = b"package main\n\nfunc Add(a, b int) int { return a + b }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "Add");
        assert_eq!(funcs[0].visibility, Visibility::Public);
    }

    #[test]
    fn parse_go_struct() {
        let adapter = GoAdapter;
        let source = b"package main\n\ntype Dog struct {\n    Name string\n}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Dog");
    }

    #[test]
    fn parse_go_function_calls() {
        let adapter = GoAdapter;
        let source =
            b"package main\n\nimport \"fmt\"\n\nfunc Hello() { fmt.Println(\"hi\"); doStuff() }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.go");
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
        assert!(dst_names.contains(&"fmt.Println"));
        assert!(dst_names.contains(&"doStuff"));
    }

    #[test]
    fn parse_go_imports() {
        let adapter = GoAdapter;
        let source = b"package main\n\nimport (\n\t\"fmt\"\n\tm \"math\"\n)";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 2);

        let fmt_import = output
            .imports
            .iter()
            .find(|i| i.module_path == "fmt")
            .unwrap();
        assert_eq!(fmt_import.specifiers.len(), 1);
        assert_eq!(fmt_import.specifiers[0].local_name, "fmt");
        assert!(fmt_import.specifiers[0].original_name.is_none());

        let math_import = output
            .imports
            .iter()
            .find(|i| i.module_path == "math")
            .unwrap();
        assert_eq!(math_import.specifiers.len(), 1);
        assert_eq!(math_import.specifiers[0].local_name, "m");
        assert_eq!(
            math_import.specifiers[0].original_name.as_deref(),
            Some("math")
        );
    }
}
