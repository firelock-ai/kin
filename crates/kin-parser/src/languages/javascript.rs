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
            extract_js_node(&child, source, file_id, &mut entities, &mut relations);
            // Extract imports at top level
            if child.kind() == "import_statement" {
                if let Some(import) = extract_js_import(&child, source) {
                    imports.push(import);
                }
            }
            // Extract CommonJS require() calls as imports
            if child.kind() == "lexical_declaration" || child.kind() == "variable_declaration" {
                if let Some(import) = extract_require_import(&child, source) {
                    imports.push(import);
                }
            }
            // Detect describe/it/test calls (Jest/Vitest/Mocha)
            extract_js_tests_from_node(&child, source, &mut tests);
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
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_js_visibility(node),
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
                                    dst_name: qualified.clone(),
                                });
                                // Extract calls within method body
                                extract_calls_from_context(&member, source, &qualified, relations);
                            }
                        }
                    }
                }
            }
        }
        "expression_statement" => {
            // Handle prototype method assignments: obj.method = function() {}
            // and module.exports = function name() {}
            extract_js_assignment_function(node, source, file_id, entities, relations);
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

/// Extract a usable entity name from the LHS of an assignment.
/// For `member_expression` like `app.init` or `module.exports`, returns the property name.
/// For plain `identifier`, returns it directly.
fn extract_assignment_lhs_name(lhs: &tree_sitter::Node, source: &[u8]) -> String {
    match lhs.kind() {
        "member_expression" => {
            // Use the property (rightmost) part: app.init → "init", module.exports → "module.exports"
            let obj_text = lhs
                .child_by_field_name("object")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            let prop_text = lhs
                .child_by_field_name("property")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            // For module.exports, keep the full name since it's the module entry point
            if obj_text == "module" && prop_text == "exports" {
                "module.exports".to_string()
            } else {
                // Use the property name (e.g., app.init → "init", proto.method → "method")
                prop_text.to_string()
            }
        }
        "identifier" => lhs.utf8_text(source).unwrap_or("").to_string(),
        _ => lhs.utf8_text(source).unwrap_or("").to_string(),
    }
}

/// Extract function entities from assignment expressions like `app.init = function() {}`.
fn extract_js_assignment_function(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    // Find the assignment_expression child
    let assign = {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.children(&mut cursor) {
            if child.kind() == "assignment_expression" {
                found = Some(child);
                break;
            }
        }
        found
    };
    let assign = match assign {
        Some(a) => a,
        None => return,
    };
    let lhs = match assign.child_by_field_name("left") {
        Some(l) => l,
        None => return,
    };
    let rhs = match assign.child_by_field_name("right") {
        Some(r) => r,
        None => return,
    };
    let rhs_kind = rhs.kind();
    let is_function_rhs = matches!(
        rhs_kind,
        "function_expression" | "function" | "arrow_function" | "generator_function"
    );
    if !is_function_rhs {
        return;
    }
    // Determine the entity name: prefer the function's own name, fall back to LHS property
    let name = if matches!(rhs_kind, "function_expression" | "function" | "generator_function") {
        rhs.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.to_string())
    } else {
        None
    };
    let name = name.unwrap_or_else(|| extract_assignment_lhs_name(&lhs, source));
    if name.is_empty() {
        return;
    }
    entities.push(ExtractedEntity {
        kind: EntityKind::Function,
        name: name.clone(),
        signature: node_signature(node, source),
        visibility: Visibility::Public,
        doc_summary: extract_preceding_comment(node, source),
        fingerprint: compute_fingerprint(node, source),
        span: span_from_node(node, file_id),
    });
    extract_calls_from_context(&rhs, source, &name, relations);
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
fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(function) = child.child(0) {
                let callee_name = function.utf8_text(source).unwrap_or("").to_string();
                if is_valid_callee_name(&callee_name) {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                    });
                }
            }
        }
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

/// Extract detailed import information from an import_statement node.
fn extract_js_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut module_path = String::new();
    let mut specifiers = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" => {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                module_path = text.trim_matches(|c| c == '\'' || c == '"').to_string();
            }
            "import_clause" => {
                let mut clause_cursor = child.walk();
                for clause_child in child.children(&mut clause_cursor) {
                    match clause_child.kind() {
                        "named_imports" => {
                            extract_js_named_imports(&clause_child, source, &mut specifiers);
                        }
                        "import_specifier" => {
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

/// Extract named imports from a named_imports node (e.g., `{ foo, bar as baz }`).
fn extract_js_named_imports(
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
                original_name = Some(text.clone());
                local_name = text;
            } else if child_index == 1 {
                local_name = text;
            }
            child_index += 1;
        }
    }

    if local_name.is_empty() {
        return None;
    }

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

/// Extract CommonJS require() call as a FileImport.
/// Handles patterns like `const foo = require('./bar')`.
fn extract_require_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    // Walk into variable_declarator children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            let var_name = child
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("")
                .to_string();

            // Check if the value is a call_expression with callee "require"
            if let Some(value) = child.child_by_field_name("value") {
                if value.kind() == "call_expression" {
                    if let Some(callee) = value.child(0) {
                        let callee_text = callee.utf8_text(source).unwrap_or("");
                        if callee_text == "require" {
                            // Extract the argument (module path)
                            if let Some(args) = value.child_by_field_name("arguments") {
                                let mut args_cursor = args.walk();
                                for arg in args.children(&mut args_cursor) {
                                    if arg.kind() == "string" {
                                        let module_path = arg
                                            .utf8_text(source)
                                            .unwrap_or("")
                                            .trim_matches(|c| c == '\'' || c == '"')
                                            .to_string();
                                        if !module_path.is_empty() && !var_name.is_empty() {
                                            return Some(FileImport {
                                                module_path,
                                                specifiers: vec![ImportedName {
                                                    local_name: var_name,
                                                    original_name: None,
                                                    is_default: true,
                                                }],
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Detect Jest/Vitest/Mocha test calls in JS: `test(...)`, `it(...)`, `describe(...)`.
fn extract_js_tests_from_node(
    node: &tree_sitter::Node,
    source: &[u8],
    tests: &mut Vec<ExtractedTest>,
) {
    if node.kind() == "expression_statement" || node.kind() == "call_expression" {
        let mut cursor = node.walk();
        let call = if node.kind() == "expression_statement" {
            node.children(&mut cursor)
                .find(|c| c.kind() == "call_expression")
        } else {
            Some(*node)
        };
        if let Some(call_node) = call {
            if let Some(func) = call_node.child_by_field_name("function") {
                let func_name = func.utf8_text(source).unwrap_or("");
                if matches!(func_name, "test" | "it") {
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
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        let mut cursor = args.walk();
                        for arg in args.children(&mut cursor) {
                            if arg.kind() == "arrow_function" || arg.kind() == "function" {
                                if let Some(body) = arg.child_by_field_name("body") {
                                    let mut body_cursor = body.walk();
                                    for child in body.children(&mut body_cursor) {
                                        extract_js_tests_from_node(&child, source, tests);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if node.kind() == "program" || node.kind() == "statement_block" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_js_tests_from_node(&child, source, tests);
        }
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

    #[test]
    fn parse_js_function_calls() {
        let adapter = JavaScriptAdapter;
        let source = b"function doWork(x) { console.log(x); helper(x); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
        let callees: Vec<&str> = calls.iter().map(|r| r.dst_name.as_str()).collect();
        assert!(callees.contains(&"console.log"), "missing console.log call");
        assert!(callees.contains(&"helper"), "missing helper call");
        // All calls should originate from doWork
        for c in &calls {
            assert_eq!(c.src_name, "doWork");
        }
    }

    #[test]
    fn parse_js_imports() {
        let adapter = JavaScriptAdapter;
        let source = b"import { foo, bar as baz } from './module';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "./module");
        assert_eq!(import.specifiers.len(), 2);
        // First specifier: foo (not renamed)
        assert_eq!(import.specifiers[0].local_name, "foo");
        assert!(import.specifiers[0].original_name.is_none());
        // Second specifier: bar as baz
        assert_eq!(import.specifiers[1].local_name, "baz");
        assert_eq!(import.specifiers[1].original_name.as_deref(), Some("bar"));
    }

    #[test]
    fn parse_js_require() {
        let adapter = JavaScriptAdapter;
        let source = b"const path = require('./utils/path');";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "./utils/path");
        assert_eq!(import.specifiers.len(), 1);
        assert_eq!(import.specifiers[0].local_name, "path");
        assert!(import.specifiers[0].is_default);
    }

    #[test]
    fn parse_js_prototype_method_named() {
        // app.init = function init() { ... }
        let adapter = JavaScriptAdapter;
        let source = b"app.init = function init() { console.log('starting'); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected 1 function, got {:?}", funcs);
        assert_eq!(funcs[0].name, "init");
    }

    #[test]
    fn parse_js_prototype_method_anonymous() {
        // res.status = function(code) { ... } — anonymous, use property name
        let adapter = JavaScriptAdapter;
        let source = b"res.status = function(code) { return this; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected 1 function, got {:?}", funcs);
        assert_eq!(funcs[0].name, "status");
    }

    #[test]
    fn parse_js_value_assignment_skipped() {
        // exports.Router = Router — value assignment, not a function → should NOT produce entity
        let adapter = JavaScriptAdapter;
        let source = b"exports.Router = Router;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(
            funcs.len(),
            0,
            "value assignments should not produce entities, got {:?}",
            funcs
        );
    }

    #[test]
    fn parse_js_module_exports_named() {
        // module.exports = function createApplication() { ... }
        let adapter = JavaScriptAdapter;
        let source = b"module.exports = function createApplication() { return app; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected 1 function, got {:?}", funcs);
        // Named function on RHS takes precedence
        assert_eq!(funcs[0].name, "createApplication");
    }

    #[test]
    fn parse_js_module_exports_anonymous() {
        // module.exports = function() { ... } — anonymous, falls back to "module.exports"
        let adapter = JavaScriptAdapter;
        let source = b"module.exports = function() { return app; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "module.exports");
    }

    #[test]
    fn parse_js_arrow_function_assignment() {
        // app.handler = (req, res) => { ... }
        let adapter = JavaScriptAdapter;
        let source = b"app.handler = (req, res) => { res.send('ok'); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected 1 function, got {:?}", funcs);
        assert_eq!(funcs[0].name, "handler");
    }
}
