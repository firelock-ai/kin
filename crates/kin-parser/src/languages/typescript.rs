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
        let mut tests = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_ts_node(&child, source, file_id, &mut entities, &mut relations);
            if let Some(import_like) = extract_ts_import_like(&child, source) {
                imports.push(import_like);
            }
            // Detect describe/it/test calls (Jest/Vitest/Mocha)
            extract_js_tests(&child, source, &mut tests);
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
                    name: name.clone(),
                    signature: sig,
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                // Extract calls within function body
                extract_calls_from_context(node, source, &name, relations);
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
            let mut decl_cursor = node.walk();
            for declarator in node.children(&mut decl_cursor) {
                if declarator.kind() == "variable_declarator" {
                    if let Some(name_node) = declarator.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let value_node = declarator.child_by_field_name("value");
                        let kind = if value_node.as_ref().is_some_and(is_ts_function_like_node) {
                            EntityKind::Function
                        } else {
                            EntityKind::Constant
                        };
                        entities.push(ExtractedEntity {
                            kind,
                            name,
                            signature: node_signature(&declarator, source),
                            visibility: detect_ts_visibility(node, source),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&declarator, source),
                            span: span_from_node(&declarator, file_id),
                        });
                        if let Some(value_node) = value_node.filter(is_ts_function_like_node) {
                            let context_name = name_node.utf8_text(source).unwrap_or("");
                            extract_calls_from_context(&value_node, source, context_name, relations);
                        }
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
                        import_source: None,
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
                    dst_name: qualified.clone(),
                    import_source: None,
                });
                // Extract calls within method body
                extract_calls_from_context(node, source, &qualified, relations);
            }
        }
        _ => {}
    }
}

fn is_ts_function_like_node(node: &tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "arrow_function" | "function" | "function_expression" | "generator_function"
    )
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
                                    import_source: None,
                                });
                            }
                        }
                    }
                    "implements_clause" => {
                        let mut impl_cursor = clause.walk();
                        for iface in clause.children(&mut impl_cursor) {
                            if iface.is_named() && iface.kind() != "implements" {
                                let iface_name = iface.utf8_text(source).unwrap_or("").to_string();
                                if !iface_name.is_empty() {
                                    relations.push(ExtractedRelation {
                                        kind: kin_model::RelationKind::Implements,
                                        src_name: class_name.to_string(),
                                        dst_name: iface_name,
                                        import_source: None,
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

/// Extract all function/method calls within a function/method body.
/// The `context_name` parameter is the name of the containing function or qualified method name.
/// This identifies cross-file references (unresolved function names from AST).
fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            // A call_expression has function (callee) as first child
            if let Some(function) = child.child(0) {
                let callee_name = function.utf8_text(source).unwrap_or("").to_string();
                // Only track identifiers and member accesses (filter out string/number literals)
                if is_valid_callee_name(&callee_name) {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                        import_source: None,
                    });
                }
            }
        }
        // Recurse into child nodes
        extract_calls_from_context(&child, source, context_name, relations);
    }
}

/// Check if a callee name is valid (not a literal, not empty).
fn is_valid_callee_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.starts_with('`')
        && !name.chars().all(|c| c.is_numeric())
}

/// Extract import-like file context from import and re-export statements.
fn extract_ts_import_like(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    match node.kind() {
        "import_statement" => extract_ts_import(node, source),
        "export_statement" => extract_ts_export_source(node, source),
        _ => None,
    }
}

/// Extract detailed import information from an import_statement node.
/// Returns FileImport with module path and list of imported names.
fn extract_ts_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut module_path = String::new();
    let mut specifiers = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" => {
                // Extract module path from string literal
                let text = child.utf8_text(source).unwrap_or("").to_string();
                module_path = text.trim_matches(|c| c == '\'' || c == '"').to_string();
            }
            "import_clause" => {
                // Extract specifiers from import_clause
                let mut clause_cursor = child.walk();
                for clause_child in child.children(&mut clause_cursor) {
                    match clause_child.kind() {
                        "named_imports" => {
                            extract_ts_named_imports(&clause_child, source, &mut specifiers);
                        }
                        "namespace_import" => {
                            if let Some(import_name) =
                                extract_namespace_import_name(&clause_child, source)
                            {
                                specifiers.push(import_name);
                            }
                        }
                        "import_specifier" => {
                            // Default import or single named import
                            if let Some(import_name) =
                                extract_single_import_name(&clause_child, source)
                            {
                                specifiers.push(import_name);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if module_path.is_empty() {
        return None;
    }

    Some(FileImport {
        module_path,
        specifiers,
    })
}

fn extract_ts_export_source(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut module_path = String::new();
    let mut specifiers = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" => {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                module_path = text.trim_matches(|c| c == '\'' || c == '"').to_string();
            }
            "export_clause" | "named_exports" => {
                extract_ts_export_specifiers(&child, source, &mut specifiers);
            }
            _ => {}
        }
    }

    if module_path.is_empty() {
        return None;
    }

    if specifiers.is_empty() {
        specifiers.push(ImportedName {
            local_name: "*".to_string(),
            original_name: Some("*".to_string()),
            is_default: false,
        });
    }

    Some(FileImport {
        module_path,
        specifiers,
    })
}

/// Extract a namespace import from `import * as util from "./util"`.
///
/// We encode namespace imports as `local_name = util` and `original_name = "*"`
/// so the linker can later resolve member calls like `util.finalizeIssue(...)`
/// to the `finalizeIssue` entity exported by that module.
fn extract_namespace_import_name(node: &tree_sitter::Node, source: &[u8]) -> Option<ImportedName> {
    let local_name = node
        .children(&mut node.walk())
        .find(|child| child.is_named())
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("")
        .to_string();

    if local_name.is_empty() {
        return None;
    }

    Some(ImportedName {
        local_name,
        original_name: Some("*".to_string()),
        is_default: false,
    })
}

/// Extract named imports from a named_imports node (e.g., `{ foo, bar as baz }`).
fn extract_ts_named_imports(
    node: &tree_sitter::Node,
    source: &[u8],
    specifiers: &mut Vec<ImportedName>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "import_specifier" {
            if let Some(import_name) = extract_single_import_name(&child, source) {
                specifiers.push(import_name);
            }
        }
    }
}

fn extract_ts_export_specifiers(
    node: &tree_sitter::Node,
    source: &[u8],
    specifiers: &mut Vec<ImportedName>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "export_specifier" => {
                if let Some(import_name) = extract_single_import_name(&child, source) {
                    specifiers.push(import_name);
                }
            }
            "identifier" => {
                let text = child.utf8_text(source).unwrap_or("").trim().to_string();
                if !text.is_empty() {
                    specifiers.push(ImportedName {
                        local_name: text.clone(),
                        original_name: None,
                        is_default: false,
                    });
                }
            }
            _ => {}
        }
    }
}

/// Extract a single imported name from an import_specifier node.
fn extract_single_import_name(node: &tree_sitter::Node, source: &[u8]) -> Option<ImportedName> {
    let mut local_name = String::new();
    let mut original_name = None;

    let mut cursor = node.walk();
    let mut child_index = 0;
    for child in node.children(&mut cursor) {
        if child.is_named() {
            let text = child.utf8_text(source).unwrap_or("").to_string();
            if child_index == 0 {
                // First identifier is the original name
                original_name = Some(text.clone());
                local_name = text;
            } else if child_index == 1 {
                // After "as" keyword, next identifier is the local name
                local_name = text;
            }
            child_index += 1;
        }
    }

    if local_name.is_empty() {
        return None;
    }

    // If original_name equals local_name, don't store it (not renamed)
    let final_original_name = if original_name.as_ref() == Some(&local_name) {
        None
    } else {
        original_name
    };

    Some(ImportedName {
        local_name,
        original_name: final_original_name,
        is_default: false,
    })
}

/// Detect Jest/Vitest/Mocha test calls: `test(...)`, `it(...)`, `describe(...)`.
fn extract_js_tests(node: &tree_sitter::Node, source: &[u8], tests: &mut Vec<ExtractedTest>) {
    if node.kind() == "expression_statement" || node.kind() == "call_expression" {
        let mut expr_cursor = node.walk();
        let call = if node.kind() == "expression_statement" {
            // expression_statement > call_expression
            node.children(&mut expr_cursor)
                .find(|c| c.kind() == "call_expression")
        } else {
            Some(*node)
        };
        if let Some(call_node) = call {
            if let Some(func) = call_node.child_by_field_name("function") {
                let func_name = func.utf8_text(source).unwrap_or("");
                if matches!(func_name, "test" | "it") {
                    // Extract the test name from first argument (string literal)
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        let mut cursor = args.walk();
                        for arg in args.children(&mut cursor) {
                            if arg.kind() == "string" || arg.kind() == "template_string" {
                                let name = arg
                                    .utf8_text(source)
                                    .unwrap_or("")
                                    .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                                    .to_string();
                                if !name.is_empty() {
                                    tests.push(ExtractedTest {
                                        name,
                                        kind: ExtractedTestKind::Unit,
                                        runner: "jest".to_string(),
                                    });
                                }
                                break;
                            }
                        }
                    }
                } else if func_name == "describe" {
                    // Recurse into describe block body to find nested it/test calls
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        let mut cursor = args.walk();
                        for arg in args.children(&mut cursor) {
                            if arg.kind() == "arrow_function" || arg.kind() == "function" {
                                if let Some(body) = arg.child_by_field_name("body") {
                                    let mut body_cursor = body.walk();
                                    for child in body.children(&mut body_cursor) {
                                        extract_js_tests(&child, source, tests);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Recurse for top-level statements that might contain tests
    if node.kind() == "program" || node.kind() == "statement_block" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_js_tests(&child, source, tests);
        }
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
        let func = output
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Function)
            .unwrap();
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

    #[test]
    fn parse_typescript_namespace_import() {
        let adapter = TypeScriptAdapter;
        let source =
            b"import * as util from './util';\nexport const run = () => util.finalizeIssue();";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "./util");
        assert_eq!(import.specifiers.len(), 1);
        assert_eq!(import.specifiers[0].local_name, "util");
        assert_eq!(import.specifiers[0].original_name.as_deref(), Some("*"));
    }

    #[test]
    fn parse_typescript_function_valued_const_as_function() {
        let adapter = TypeScriptAdapter;
        let source =
            b"export const createApp = (...args) => { hydrate(args); return mount(args); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected one function-valued const entity");
        assert_eq!(funcs[0].name, "createApp");

        let callees: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(callees.contains(&"hydrate"));
        assert!(callees.contains(&"mount"));
    }

    #[test]
    fn parse_typescript_reexport_source_as_import_context() {
        let adapter = TypeScriptAdapter;
        let source = b"export { hydrate } from './runtime-dom';\nexport * from '@vue/runtime-core';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 2);
        assert_eq!(output.imports[0].module_path, "./runtime-dom");
        assert!(output.imports[0]
            .specifiers
            .iter()
            .any(|spec| spec.local_name == "hydrate"));
        assert_eq!(output.imports[1].module_path, "@vue/runtime-core");
        assert!(output.imports[1]
            .specifiers
            .iter()
            .any(|spec| spec.local_name == "*"));
    }

}
