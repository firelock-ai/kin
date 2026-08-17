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

        // Emit Module entity for index.js/index.jsx files (JS packages).
        // This makes the module searchable by its directory name, e.g.,
        // `src/plugin/customParseFormat/index.js` → entity "customParseFormat".
        if is_js_index_file(&file_id.0) {
            if let Some(module_name) = extract_module_name_from_path(&file_id.0) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Module,
                    name: module_name,
                    signature: format!("module {}", file_id.0),
                    visibility: Visibility::Public,
                    doc_summary: None,
                    fingerprint: compute_fingerprint(&root, source),
                    span: span_from_node(&root, file_id),
                });
            }
        }

        for child in root.children(&mut cursor) {
            extract_js_node(&child, source, file_id, &mut entities, &mut relations);
            if let Some(import_like) = extract_js_import_like(&child, source) {
                imports.push(import_like);
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

                // Extract Extends relation for class inheritance.
                // tree-sitter-javascript: class_declaration → class_heritage → identifier
                {
                    let mut heritage_cursor = node.walk();
                    for child in node.children(&mut heritage_cursor) {
                        if child.kind() == "class_heritage" {
                            // Inside class_heritage, find the named identifier (skip "extends" keyword)
                            let mut hc = child.walk();
                            for hchild in child.children(&mut hc) {
                                if hchild.is_named() && hchild.kind() == "identifier" {
                                    let parent_name =
                                        hchild.utf8_text(source).unwrap_or("").to_string();
                                    if !parent_name.is_empty() {
                                        relations.push(ExtractedRelation {
                                            receiver: None,
                                            call_shape: None,
                                            kind: kin_model::RelationKind::Extends,
                                            src_name: name.clone(),
                                            dst_name: parent_name,
                                            import_source: None,
                                        });
                                    }
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }

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
                                    receiver: None,
                                    call_shape: None,
                                    kind: kin_model::RelationKind::Contains,
                                    src_name: name.clone(),
                                    dst_name: qualified.clone(),
                                    import_source: None,
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
        "lexical_declaration" | "variable_declaration" => {
            let mut decl_cursor = node.walk();
            for declarator in node.children(&mut decl_cursor) {
                if declarator.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name_node) = declarator
                    .child_by_field_name("name")
                    .or_else(|| declarator.named_child(0))
                else {
                    continue;
                };
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let value_node = declarator.child_by_field_name("value");
                let is_function_like = value_node.as_ref().is_some_and(is_js_function_like_node);
                let kind = if is_function_like {
                    EntityKind::Function
                } else {
                    EntityKind::Constant
                };
                // Filter data-only constants: object/array literals, bare
                // identifiers, strings, etc. without function calls or
                // callbacks are noise (CSS theme tokens, locale strings,
                // config objects). Keeps constants initialized with call
                // expressions (React.forwardRef, styled, memo) or containing
                // arrow functions — these represent real code entities.
                if kind == EntityKind::Constant {
                    if let Some(ref value) = value_node {
                        // Keep named constants with a scalar literal value
                        // (e.g. `MAX_RETRIES = 5`) so trace tasks resolve
                        // through them. Object/array literals stay filtered
                        // even when named (avoids config-token bloat).
                        let rescue = is_named_constant(&name) && is_scalar_literal(value);
                        if is_data_only_js_value(value) && !rescue {
                            continue;
                        }
                    }
                }
                entities.push(ExtractedEntity {
                    kind,
                    name,
                    signature: node_signature(&declarator, source),
                    visibility: detect_js_visibility(node),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(&declarator, source),
                    span: span_from_node(&declarator, file_id),
                });
                if let Some(value_node) = value_node.filter(is_js_function_like_node) {
                    let context_name = name_node.utf8_text(source).unwrap_or("");
                    extract_calls_from_context(&value_node, source, context_name, relations);
                }
            }
        }
        "export_statement" => {
            let entities_before = entities.len();
            let mut cursor = node.walk();
            let mut has_default = false;
            for child in node.children(&mut cursor) {
                if child.kind() == "default" || child.utf8_text(source).unwrap_or("") == "default" {
                    has_default = true;
                }
                extract_js_node(&child, source, file_id, entities, relations);
            }
            // If this is a default export and recursion didn't create any entities,
            // create a synthetic "default" entity so the linker can resolve
            // `import Foo from './this-file'` to something.
            if has_default && entities.len() == entities_before {
                // Find the exported value (skip "export" and "default" keywords)
                let mut value_cursor = node.walk();
                let exported_value = node.children(&mut value_cursor).find(|child| {
                    child.is_named()
                        && !matches!(
                            child.kind(),
                            "export_clause" | "named_exports" | "decorator"
                        )
                });
                if let Some(val) = exported_value {
                    let name = "default".to_string();
                    let kind = match val.kind() {
                        "function"
                        | "function_expression"
                        | "arrow_function"
                        | "generator_function" => EntityKind::Function,
                        "class" | "class_declaration" => EntityKind::Class,
                        _ => EntityKind::Constant,
                    };
                    entities.push(ExtractedEntity {
                        kind,
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
        "import_statement" => {
            // Import handling is done via FileImport records (extract_js_import).
            // The linker creates Imports edges from FileImport specifiers.
        }
        _ => {}
    }
}

fn is_js_function_like_node(node: &tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "function_expression" | "function" | "arrow_function" | "generator_function"
    )
}

/// Returns true if `name` looks like a deliberately-named constant
/// (e.g. `MAX_RETRIES`, `API_URL`, `HTTP_TIMEOUT_ms`, `PROBE_BASE_d6177fd8`)
/// rather than an incidental local (`x`, `count`, `tmp`). Such constants are
/// kept even when their value is a data-only scalar so trace-computation tasks
/// can resolve through them. Detects an internal run of two uppercase letters
/// or an underscore immediately followed by an uppercase letter; a naive
/// all-uppercase rule would reject lowercase-hex-tagged names.
fn is_named_constant(name: &str) -> bool {
    let n = name.trim();
    if n.is_empty() {
        return false;
    }
    let has_upper_run = n
        .as_bytes()
        .windows(2)
        .any(|w| w[0].is_ascii_uppercase() && w[1].is_ascii_uppercase());
    let has_underscore_upper = n
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'_' && w[1].is_ascii_uppercase());
    has_upper_run || has_underscore_upper
}

/// Returns true if a value node is a scalar literal (number, string, boolean,
/// null/undefined). Used to scope the named-constant rescue to scalars so that
/// named object/array literals (theme tokens, config maps) stay filtered.
fn is_scalar_literal(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "number" | "string" | "true" | "false" | "null" | "undefined" => true,
        "parenthesized_expression" => node
            .child(1)
            .map(|inner| is_scalar_literal(&inner))
            .unwrap_or(false),
        _ => false,
    }
}

/// Returns true if a value node is a data-only constant that should be
/// filtered from entity extraction. Data-only values are object literals,
/// array literals, bare identifiers, and other non-functional patterns that
/// create noise in large repos like MUI (45K CSS theme tokens, locale objects).
///
/// Values containing function calls, arrow functions, or other executable
/// code are preserved — these represent meaningful code like React components
/// (e.g., `createSvgIcon(...)`, `styled('div')(...)`).
fn is_data_only_js_value(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        // Bare identifier re-exports: `const X = Y`
        "identifier" => true,
        // Member access re-exports: `const X = pkg.Y`
        "member_expression" => !js_subtree_contains_function_like(node),
        // Primitives
        "undefined" | "null" | "true" | "false" | "number" => true,
        // Short strings are trivial (includes quotes, so "ab" = 4 bytes)
        "string" => node.byte_range().len() <= 4,
        // Template literals without function calls
        "template_string" => !js_subtree_contains_function_like(node),
        // Object/array literals: only data if no function-like children
        "object" | "array" => !js_subtree_contains_function_like(node),
        // Parenthesized: unwrap
        "parenthesized_expression" => node
            .child(1)
            .map(|inner| is_data_only_js_value(&inner))
            .unwrap_or(false),
        _ => false,
    }
}

/// Returns true if any node in the subtree is a function-like expression
/// or a call expression. Used to distinguish data-only object/array literals
/// from meaningful code (React components, styled-components, etc.).
fn js_subtree_contains_function_like(node: &tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if is_js_function_like_node(&current) || current.kind() == "call_expression" {
            return true;
        }
        cursor.reset(current);
        if cursor.goto_first_child() {
            loop {
                stack.push(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    false
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
    let name = if matches!(
        rhs_kind,
        "function_expression" | "function" | "generator_function"
    ) {
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
    crate::adapter::declaration_signature(node, source)
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
///
/// For a `call_expression`, the `function` field is the callee. We unpack
/// `member_expression` callees to the rightmost identifier (`a.b()` -> `b`),
/// so graph edges key on the simple method name rather than the dotted
/// source text. `new X()` is a `new_expression` (not `call_expression`) and
/// is intentionally skipped here.
fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                let callee_name = match function.kind() {
                    "member_expression" => function
                        .child_by_field_name("property")
                        .map(|f| f.utf8_text(source).unwrap_or("").to_string())
                        .unwrap_or_default(),
                    "identifier" => {
                        let raw = function.utf8_text(source).unwrap_or("");
                        raw.strip_prefix("this.").unwrap_or(raw).to_string()
                    }
                    _ => String::new(),
                };
                if is_valid_callee_name(&callee_name) {
                    relations.push(ExtractedRelation {
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                        import_source: None,
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

/// Extract import-like file context from import and re-export statements.
fn extract_js_import_like(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    match node.kind() {
        "import_statement" => extract_js_import(node, source),
        "export_statement" => extract_js_export_source(node, source),
        _ => None,
    }
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
                        "identifier" => {
                            // Default import: `import Foo from 'bar'`
                            let text = clause_child.utf8_text(source).unwrap_or("").to_string();
                            if !text.is_empty() {
                                specifiers.push(ImportedName {
                                    local_name: text,
                                    original_name: Some("default".to_string()),
                                    is_default: true,
                                });
                            }
                        }
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

fn extract_js_export_source(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
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
                extract_js_export_specifiers(&child, source, &mut specifiers);
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

fn extract_js_export_specifiers(
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
                        local_name: text,
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

/// Check if a file is a JS index file (index.js, index.jsx, index.mjs, index.cjs).
fn is_js_index_file(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    matches!(
        basename,
        "index.js" | "index.jsx" | "index.mjs" | "index.cjs"
    )
}

/// Extract the module name from a file path for index files.
/// `src/plugin/customParseFormat/index.js` → `"customParseFormat"`
/// `themes/index.js` → `"themes"`
fn extract_module_name_from_path(path: &str) -> Option<String> {
    let without_basename = path.rsplit_once('/')?.0;
    let dir_name = without_basename
        .rsplit('/')
        .next()
        .unwrap_or(without_basename);
    if dir_name.is_empty() || dir_name == "src" || dir_name == "lib" {
        return None;
    }
    Some(dir_name.to_string())
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
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "add");
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
        // Member calls resolve to the rightmost identifier (`console.log` -> `log`).
        assert!(callees.contains(&"log"), "missing log call (console.log)");
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

    #[test]
    fn parse_js_uppercase_constant() {
        let adapter = JavaScriptAdapter;
        let source = b"export const PROBE_SECRET_abcd1234 = 'uuid';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            1,
            "expected 1 constant, got {:?}",
            constants
        );
        assert_eq!(constants[0].name, "PROBE_SECRET_abcd1234");
    }

    #[test]
    fn parse_js_function_valued_const_as_function() {
        let adapter = JavaScriptAdapter;
        let source = b"export const useAutocomplete = (props) => { helper(props); return props; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected one function-valued const entity");
        assert_eq!(funcs[0].name, "useAutocomplete");

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(calls.contains(&"helper"));
    }

    #[test]
    fn parse_js_reexport_source_as_import_context() {
        let adapter = JavaScriptAdapter;
        let source =
            b"export { hydrate } from './runtime-dom';\nexport * from '@vue/runtime-core';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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

    #[test]
    fn parse_js_class_extends() {
        let adapter = JavaScriptAdapter;
        let source = b"class Dog extends Animal { bark() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        // Should have Dog class and Dog.bark method
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Dog");

        // Should have Extends relation from Dog to Animal
        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert_eq!(
            extends.len(),
            1,
            "expected 1 Extends relation, got {:?}",
            extends
        );
        assert_eq!(extends[0].src_name, "Dog");
        assert_eq!(extends[0].dst_name, "Animal");
    }

    #[test]
    fn parse_js_exports_prop_function() {
        let adapter = JavaScriptAdapter;
        let source = b"exports.handler = function() { console.log('hi'); };";
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
            1,
            "expected 1 function from exports.handler, got {:?}",
            funcs
        );
        assert_eq!(funcs[0].name, "handler");
    }

    #[test]
    fn parse_js_default_import_specifier() {
        let adapter = JavaScriptAdapter;
        let source = b"import React from 'react';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "react");
        assert_eq!(import.specifiers.len(), 1);
        assert_eq!(import.specifiers[0].local_name, "React");
        assert_eq!(
            import.specifiers[0].original_name.as_deref(),
            Some("default")
        );
        assert!(import.specifiers[0].is_default);
    }

    #[test]
    fn parse_js_default_import_with_named() {
        let adapter = JavaScriptAdapter;
        let source = b"import dayjs, { Dayjs } from 'dayjs';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "dayjs");
        assert!(
            import.specifiers.len() >= 2,
            "expected at least 2 specifiers (default + named), got {}",
            import.specifiers.len()
        );
        let default_spec = import.specifiers.iter().find(|s| s.is_default);
        assert!(default_spec.is_some(), "missing default import specifier");
        assert_eq!(default_spec.unwrap().local_name, "dayjs");
    }

    #[test]
    fn parse_js_exported_data_only_object_filtered() {
        let adapter = JavaScriptAdapter;
        // Data-only object literals (theme tokens, configs) are filtered to
        // prevent constant explosion in repos like MUI.
        let source = b"export const themes = { dark: { bg: '#000' }, light: { bg: '#fff' } };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            0,
            "data-only exported object constants should be filtered"
        );
    }

    #[test]
    fn parse_js_exported_object_with_callback_kept() {
        let adapter = JavaScriptAdapter;
        // Object literals with function-like children are meaningful code
        let source = b"export const handlers = { onClick: () => console.log('click') };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            1,
            "object literals with callbacks should be kept"
        );
        assert_eq!(constants[0].name, "handlers");
    }

    #[test]
    fn parse_js_unexported_lowercase_const_skipped() {
        let adapter = JavaScriptAdapter;
        let source = b"const localHelper = { x: 1 };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            0,
            "unexported non-UPPER_SNAKE_CASE constants should be skipped"
        );
    }

    #[test]
    fn parse_js_export_default_anonymous_function() {
        let adapter = JavaScriptAdapter;
        let source = b"export default function() { return 42; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let defaults: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name == "default")
            .collect();
        assert_eq!(
            defaults.len(),
            1,
            "anonymous default export should create a 'default' entity"
        );
        assert_eq!(defaults[0].kind, EntityKind::Function);
        assert_eq!(defaults[0].visibility, Visibility::Public);
    }

    #[test]
    fn parse_js_export_default_identifier() {
        let adapter = JavaScriptAdapter;
        let source = b"const dayjs = function(d) { return d; };\nexport default dayjs;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        // Should have the named function AND a "default" entity
        let defaults: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name == "default")
            .collect();
        assert_eq!(
            defaults.len(),
            1,
            "export default <identifier> should create a 'default' entity"
        );
    }

    #[test]
    fn parse_js_module_entity_for_index_file() {
        let adapter = JavaScriptAdapter;
        let source = b"export { default } from './LoadingButton';";
        let tree = adapter.parse(source).unwrap();
        // Key: file_id path ends with /index.js and has a directory component
        let file_id = FilePathId::new("packages/mui-lab/src/LoadingButton/index.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(
            modules.len(),
            1,
            "index.js should create a Module entity named after its directory"
        );
        assert_eq!(modules[0].name, "LoadingButton");
    }

    #[test]
    fn keep_named_numeric_constant() {
        let adapter = JavaScriptAdapter;
        // A named numeric constant must be indexed so trace-computation tasks
        // can resolve through it — even though `13` is a data-only scalar.
        let source = b"export const PROBE_BASE_d6177fd8 = 13;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            1,
            "named numeric constant should be kept, got: {:?}",
            constants.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        assert_eq!(constants[0].name, "PROBE_BASE_d6177fd8");
    }

    #[test]
    fn keep_named_scalar_constants_drop_incidental_locals() {
        let adapter = JavaScriptAdapter;
        // Positive matrix: deliberately-named constants are kept even with
        // data-only scalar values. Negative matrix: incidental lowercase
        // locals with scalar values stay filtered (avoids entity-set bloat).
        let source = br#"
export const PROBE_BASE_d6177fd8 = 13;
export const MAX_RETRIES = 5;
export const API_URL = "x";
export const HTTP_TIMEOUT_ms = 30;
const x = 1;
const count = 0;
const total = 100;
const i = 0;
const tmp = 2;
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let names: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .map(|e| e.name.as_str())
            .collect();

        for kept in [
            "PROBE_BASE_d6177fd8",
            "MAX_RETRIES",
            "API_URL",
            "HTTP_TIMEOUT_ms",
        ] {
            assert!(
                names.contains(&kept),
                "named constant `{kept}` should be kept, got: {names:?}"
            );
        }
        for dropped in ["x", "count", "total", "i", "tmp"] {
            assert!(
                !names.contains(&dropped),
                "incidental local `{dropped}` should be dropped, got: {names:?}"
            );
        }
    }
}
