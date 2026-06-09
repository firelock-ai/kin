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

pub struct CppAdapter;

impl LanguageAdapter for CppAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Cpp
    }

    fn file_extensions(&self) -> &[&str] {
        &["cpp", "hpp", "cc", "cxx"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let preprocessed = preprocess_cpp_source(source);
        let mut parser = make_parser(&tree_sitter_cpp::LANGUAGE)?;
        parser
            .parse(&preprocessed, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            })
    }

    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput> {
        let preprocessed = preprocess_cpp_source(source);
        let source = &preprocessed;
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
            extract_cpp_node(
                &child,
                source,
                file_id,
                None,
                Visibility::Public, // file-scope default
                &mut entities,
                &mut relations,
            );
        }

        // Recursively extract all includes and ALL_CAPS macro usages across the whole file
        extract_includes_and_macros_recursive(&root, source, file_id, &mut imports, &mut relations);

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

        // Detect C++ test framework macros (Google Test, Catch2)
        let mut tests = Vec::new();
        extract_cpp_tests(&root, source, &mut tests);

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests,
            parse_state,
        })
    }
}

/// Recursively extract entities and relations from a C++ tree-sitter node.
///
/// `class_ctx` carries the enclosing class/struct name when recursing into class bodies.
/// `default_vis` carries the current access specifier context within a class body.
fn extract_cpp_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_ctx: Option<&str>,
    default_vis: Visibility,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_definition" => {
            // Could be a free function or a method inside a class body.
            let name = extract_function_name(node, source);
            if let Some(name) = name {
                let vis = if class_ctx.is_some() {
                    default_vis
                } else {
                    detect_file_scope_visibility(node, source)
                };

                let (kind, qualified) = if let Some(cls) = class_ctx {
                    (EntityKind::Method, format!("{}::{}", cls, name))
                } else {
                    (EntityKind::Function, name)
                };

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
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified.clone(),
                        import_source: None,
                    });
                }

                extract_calls_from_body(node, source, &qualified, relations);
            }
        }
        "declaration" => {
            // A declaration inside a class body could be a method declaration (prototype).
            // At file scope it could be a function prototype/definition or variable.
            if let Some(name) = extract_declaration_function_name(node, source) {
                if let Some(cls) = class_ctx {
                    // Inside a class: method declaration
                    let qualified = format!("{}::{}", cls, name);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Method,
                        name: qualified.clone(),
                        signature: node_signature(node, source),
                        visibility: default_vis,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified,
                        import_source: None,
                    });
                } else {
                    // File scope: function declaration/prototype (e.g. macro-prefixed)
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Function,
                        name,
                        signature: node_signature(node, source),
                        visibility: default_vis,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        "class_specifier" => {
            extract_class_or_struct(node, source, file_id, false, entities, relations);
        }
        "struct_specifier" => {
            extract_class_or_struct(node, source, file_id, true, entities, relations);
        }
        "enum_specifier" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::EnumDef,
                        name,
                        signature: node_signature(node, source),
                        visibility: if class_ctx.is_some() {
                            default_vis
                        } else {
                            Visibility::Public
                        },
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        "namespace_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Module,
                        name: name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
            // Recurse into namespace body
            if let Some(body) = node.child_by_field_name("body") {
                let mut body_cursor = body.walk();
                for member in body.children(&mut body_cursor) {
                    extract_cpp_node(
                        &member,
                        source,
                        file_id,
                        None,
                        Visibility::Public,
                        entities,
                        relations,
                    );
                }
            }
        }
        "type_definition" => {
            // typedef ... name;
            // The last named child before ';' is typically the alias name.
            let name = extract_typedef_name(node, source);
            if let Some(name) = name {
                entities.push(ExtractedEntity {
                    kind: EntityKind::TypeAlias,
                    name,
                    signature: node_signature(node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "template_declaration" => {
            // Unwrap the template and extract the inner declaration.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "class_specifier"
                    | "struct_specifier"
                    | "function_definition"
                    | "declaration" => {
                        extract_cpp_node(
                            &child,
                            source,
                            file_id,
                            class_ctx,
                            default_vis,
                            entities,
                            relations,
                        );
                    }
                    _ => {}
                }
            }
        }
        // Recurse into preprocessor conditional blocks (#ifdef, #ifndef, #if, etc.)
        // so that code inside header guards is still extracted.
        "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_cpp_node(
                    &child,
                    source,
                    file_id,
                    class_ctx,
                    default_vis,
                    entities,
                    relations,
                );
            }
        }
        "preproc_def" | "preproc_function_def" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Macro,
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
        _ => {}
    }
}

/// Extract a class or struct specifier.
fn extract_class_or_struct(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    is_struct: bool,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let name_node = match node.child_by_field_name("name") {
        Some(n) => n,
        None => return, // anonymous class/struct
    };
    let name = name_node.utf8_text(source).unwrap_or("").to_string();
    if name.is_empty() {
        return;
    }

    entities.push(ExtractedEntity {
        kind: EntityKind::Class,
        name: name.clone(),
        signature: node_signature(node, source),
        visibility: Visibility::Public,
        doc_summary: extract_preceding_comment(node, source),
        fingerprint: compute_fingerprint(node, source),
        span: span_from_node(node, file_id),
    });

    // Extract base classes from base_class_clause
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "base_class_clause" {
            extract_base_classes(&child, source, &name, relations);
        }
    }

    // Recurse into body (field_declaration_list)
    if let Some(body) = node.child_by_field_name("body") {
        // Default visibility: private for class, public for struct
        let mut current_vis = if is_struct {
            Visibility::Public
        } else {
            Visibility::Private
        };

        let mut body_cursor = body.walk();
        for member in body.children(&mut body_cursor) {
            match member.kind() {
                "access_specifier" => {
                    current_vis = parse_access_specifier(&member, source);
                }
                "function_definition" | "declaration" | "template_declaration" => {
                    extract_cpp_node(
                        &member,
                        source,
                        file_id,
                        Some(&name),
                        current_vis,
                        entities,
                        relations,
                    );
                }
                _ => {}
            }
        }
    }
}

/// Extract base class names from a `base_class_clause` and emit Extends relations.
fn extract_base_classes(
    node: &tree_sitter::Node,
    source: &[u8],
    class_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // The type_identifier or qualified_identifier nodes are the base class names.
        match child.kind() {
            "type_identifier" | "qualified_identifier" => {
                let base_name = child.utf8_text(source).unwrap_or("").to_string();
                if !base_name.is_empty() {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Extends,
                        src_name: class_name.to_string(),
                        dst_name: base_name,
                        import_source: None,
                    });
                }
            }
            _ => {
                // Recurse into child nodes (e.g., template_type with a type_identifier inside)
                extract_base_classes(&child, source, class_name, relations);
            }
        }
    }
}

/// Parse an `access_specifier` node and return the corresponding Visibility.
fn parse_access_specifier(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let text = node.utf8_text(source).unwrap_or("");
    if text.contains("public") {
        Visibility::Public
    } else if text.contains("protected") {
        Visibility::Internal
    } else {
        Visibility::Private
    }
}

/// Extract the function name from a `function_definition` node.
/// Handles `declarator > function_declarator > identifier|field_identifier|destructor_name`.
fn extract_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    extract_name_from_declarator(&declarator, source)
}

/// Recursively find the function name from a declarator chain.
fn extract_name_from_declarator(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "function_declarator" => {
            // The declarator field of a function_declarator is the name part.
            if let Some(inner) = node.child_by_field_name("declarator") {
                return extract_name_from_declarator(&inner, source);
            }
            // Fallback: look for identifier children.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "identifier" | "field_identifier" | "destructor_name" => {
                        let text = child.utf8_text(source).unwrap_or("").to_string();
                        if !text.is_empty() {
                            return Some(text);
                        }
                    }
                    "qualified_identifier" => {
                        let text = child.utf8_text(source).unwrap_or("").to_string();
                        if !text.is_empty() {
                            return Some(text);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        "identifier" | "field_identifier" | "destructor_name" => {
            let text = node.utf8_text(source).unwrap_or("").to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        "qualified_identifier" => {
            let text = node.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                return Some(text);
            }
            None
        }
        "pointer_declarator" | "reference_declarator" => {
            // Unwrap pointer/reference wrappers.
            if let Some(inner) = node.child_by_field_name("declarator") {
                return extract_name_from_declarator(&inner, source);
            }
            None
        }
        _ => {
            // Try child named "declarator" for any other wrapping node.
            if let Some(inner) = node.child_by_field_name("declarator") {
                return extract_name_from_declarator(&inner, source);
            }
            None
        }
    }
}

/// Extract function name from a `declaration` node (method prototype inside class body).
fn extract_declaration_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    // Check if this declaration has a function_declarator somewhere in the chain.
    if has_function_declarator(&declarator) {
        extract_name_from_declarator(&declarator, source)
    } else {
        None
    }
}

/// Check whether a node or its declarator children contain a function_declarator.
fn has_function_declarator(node: &tree_sitter::Node) -> bool {
    if node.kind() == "function_declarator" {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declarator" || has_function_declarator(&child) {
            return true;
        }
    }
    false
}

/// Extract the name from a `type_definition` (typedef).
fn extract_typedef_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // The declarator field holds the alias name.
    if let Some(decl) = node.child_by_field_name("declarator") {
        let text = decl.utf8_text(source).unwrap_or("").to_string();
        if !text.is_empty() {
            return Some(text);
        }
    }
    // Fallback: the type_identifier child is the alias name.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_identifier" {
            let text = child.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// Detect file-scope visibility. `static` functions are private; otherwise public.
fn detect_file_scope_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" {
            let text = child.utf8_text(source).unwrap_or("");
            if text == "static" {
                return Visibility::Private;
            }
        }
    }
    Visibility::Public
}

/// First line of the node text, trimmed of trailing `{`.
fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    let text = node.utf8_text(source).unwrap_or("");
    text.lines()
        .next()
        .unwrap_or(text)
        .trim_end_matches('{')
        .trim()
        .to_string()
}

/// Extract the preceding comment (// or /* ... */) as a doc summary.
fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "comment" {
        let text = prev.utf8_text(source).ok()?;
        // Strip block comment delimiters first, then process per-line.
        let stripped = text
            .strip_prefix("/**")
            .or_else(|| text.strip_prefix("/*"))
            .unwrap_or(text);
        let stripped = stripped.strip_suffix("*/").unwrap_or(stripped);
        let cleaned = stripped
            .lines()
            .map(|l| {
                l.trim_start_matches('/')
                    .trim_start_matches('*')
                    .trim_end_matches('/')
                    .trim_end_matches('*')
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
                let callee_name = match function.kind() {
                    "field_expression" => {
                        // obj.method() or obj->method()
                        function
                            .child_by_field_name("field")
                            .map(|f| f.utf8_text(source).unwrap_or("").to_string())
                            .unwrap_or_default()
                    }
                    _ => function.utf8_text(source).unwrap_or("").to_string(),
                };
                if is_valid_callee(&callee_name) {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                        import_source: None,
                    });
                }
            }
        }
        extract_calls_from_body(&child, source, context_name, relations);
    }
}

fn is_valid_callee(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.chars().all(|c| c.is_numeric())
}

fn find_enclosing_entity(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut scopes = Vec::new();
    let mut curr = *node;

    while let Some(parent) = curr.parent() {
        match parent.kind() {
            "function_definition" => {
                if let Some(name) = extract_function_name(&parent, source) {
                    scopes.push(name);
                }
            }
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    if let Ok(name_text) = name_node.utf8_text(source) {
                        let name = name_text.trim().to_string();
                        if !name.is_empty() {
                            scopes.push(name);
                        }
                    }
                }
            }
            _ => {}
        }
        curr = parent;
    }

    if scopes.is_empty() {
        None
    } else {
        scopes.reverse();
        Some(scopes.join("::"))
    }
}

fn extract_includes_and_macros_recursive(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    imports: &mut Vec<FileImport>,
    relations: &mut Vec<ExtractedRelation>,
) {
    if node.kind() == "preproc_include" {
        if let Some(file_import) = extract_include(node, source) {
            imports.push(file_import);
        }
    } else if matches!(
        node.kind(),
        "identifier" | "type_identifier" | "statement_identifier" | "field_identifier"
    ) {
        if let Some(name) = node.utf8_text(source).ok() {
            if is_all_caps_macro(name) {
                if let Some(src_name) = find_enclosing_entity(node, source) {
                    if src_name != name && !src_name.ends_with(&format!("::{}", name)) {
                        relations.push(ExtractedRelation {
                            kind: kin_model::RelationKind::UsesMacro,
                            src_name,
                            dst_name: name.to_string(),
                            import_source: None,
                        });
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_includes_and_macros_recursive(&child, source, file_id, imports, relations);
    }
}

fn is_all_caps_macro(name: &str) -> bool {
    // Only accept if there is at least one uppercase letter and NO lowercase letters.
    // Also must not be just numbers/symbols.
    let mut has_upper = false;
    for c in name.chars() {
        if c.is_ascii_lowercase() {
            return false;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    has_upper && name.len() >= 3 // avoid single-letter macros
}

/// Extract a `#include` directive into a `FileImport`.
fn extract_include(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    // The path child is either a system_lib_string (<foo>) or a string_literal ("foo").
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "system_lib_string" | "string_literal" => {
                let raw = child.utf8_text(source).unwrap_or("").to_string();
                // Strip < > or " "
                let path = raw
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .trim_start_matches('"')
                    .trim_end_matches('"')
                    .to_string();
                if path.is_empty() {
                    return None;
                }
                let local_name = path.rsplit('/').next().unwrap_or(&path).to_string();
                return Some(FileImport {
                    module_path: path,
                    specifiers: vec![ImportedName {
                        local_name,
                        original_name: Some("default".to_string()),
                        is_default: true,
                    }],
                });
            }
            _ => {}
        }
    }
    None
}

/// Recursively detect C++ test framework macros (Google Test, Catch2).
fn extract_cpp_tests(node: &tree_sitter::Node, source: &[u8], tests: &mut Vec<ExtractedTest>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        // Google Test: TEST(SuiteName, TestName) { ... }
        // tree-sitter-cpp parses these as function_definition nodes whose declarator
        // text starts with TEST(, TEST_F(, or TEST_P(.
        if kind == "function_definition" {
            let declarator_text = child
                .child_by_field_name("declarator")
                .and_then(|d| d.utf8_text(source).ok())
                .unwrap_or("");
            if declarator_text.starts_with("TEST(")
                || declarator_text.starts_with("TEST_F(")
                || declarator_text.starts_with("TEST_P(")
            {
                let suite = declarator_text
                    .split('(')
                    .nth(1)
                    .and_then(|s| s.split(',').next())
                    .map(|s| s.trim())
                    .unwrap_or(declarator_text);
                let test_name = declarator_text
                    .split(',')
                    .nth(1)
                    .map(|s| s.trim_matches(|c: char| c == ')' || c.is_whitespace()))
                    .unwrap_or("test");
                tests.push(ExtractedTest {
                    name: format!("{}::{}", suite, test_name),
                    kind: ExtractedTestKind::Unit,
                    runner: "gtest".to_string(),
                });
            }
        }
        // Catch2: TEST_CASE("name", "[tags]")
        let text = child.utf8_text(source).unwrap_or("");
        if text.starts_with("TEST_CASE") {
            if let Some(name) = text.split('"').nth(1) {
                tests.push(ExtractedTest {
                    name: name.to_string(),
                    kind: ExtractedTestKind::Unit,
                    runner: "catch2".to_string(),
                });
            }
        }
        extract_cpp_tests(&child, source, tests);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_class_with_methods() {
        let adapter = CppAdapter;
        let source = br#"
class Dog {
public:
    Dog() {}
    void bark() { printf("woof"); }
private:
    int age;
    void wag() {}
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("dog.cpp");
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
        assert!(
            methods.len() >= 2,
            "expected at least 2 methods, got {}",
            methods.len()
        );

        let method_names: Vec<&str> = methods.iter().map(|m| m.name.as_str()).collect();
        assert!(
            method_names.contains(&"Dog::bark"),
            "should find Dog::bark, got {:?}",
            method_names
        );

        // Check Contains relations
        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains && r.src_name == "Dog")
            .collect();
        assert!(
            contains.len() >= 2,
            "should have at least 2 Contains relations, got {}",
            contains.len()
        );
    }

    #[test]
    fn extract_namespace() {
        let adapter = CppAdapter;
        let source = br#"
namespace utils {
    void helper() {}
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("utils.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "utils");

        // The function inside should also be extracted
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "helper");
    }

    #[test]
    fn extract_inheritance() {
        let adapter = CppAdapter;
        let source = br#"
class Animal {
public:
    virtual void speak() {}
};

class Dog : public Animal {
public:
    void speak() override {}
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("animals.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert_eq!(extends.len(), 1);
        assert_eq!(extends[0].src_name, "Dog");
        assert_eq!(extends[0].dst_name, "Animal");
    }

    #[test]
    fn extract_free_function() {
        let adapter = CppAdapter;
        let source = b"int add(int a, int b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("math.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

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
    fn extract_includes_as_imports() {
        let adapter = CppAdapter;
        let source = br#"
#include <iostream>
#include "myheader.h"
#include <nlohmann/detail/input/binary_reader.hpp>

int main() { return 0; }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(
            output.imports.len(),
            3,
            "expected 2 imports, got {:?}",
            output.imports
        );

        let iostream = output
            .imports
            .iter()
            .find(|i| i.specifiers.iter().any(|s| s.local_name == "iostream"));
        assert!(iostream.is_some(), "should find iostream import");

        let myheader = output
            .imports
            .iter()
            .find(|i| i.specifiers.iter().any(|s| s.local_name == "myheader.h"));
        assert!(myheader.is_some(), "should find myheader.h import");
        assert_eq!(myheader.unwrap().module_path, "myheader.h");

        let binary_reader = output
            .imports
            .iter()
            .find(|i| i.module_path == "nlohmann/detail/input/binary_reader.hpp")
            .expect("should keep full include path");
        assert_eq!(binary_reader.specifiers[0].local_name, "binary_reader.hpp");
        assert_eq!(
            binary_reader.specifiers[0].original_name.as_deref(),
            Some("default")
        );
        assert!(binary_reader.specifiers[0].is_default);

        assert!(
            output
                .relations
                .iter()
                .all(|r| r.kind != kin_model::RelationKind::Imports),
            "imports should be carried by FileImport, not fake file-sourced relations"
        );
    }

    #[test]
    fn access_specifier_visibility() {
        let adapter = CppAdapter;
        let source = br#"
class Foo {
public:
    void pub_method() {}
private:
    void priv_method() {}
protected:
    void prot_method() {}
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("foo.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();

        let pub_m = methods.iter().find(|m| m.name == "Foo::pub_method");
        assert!(pub_m.is_some(), "should find pub_method");
        assert_eq!(pub_m.unwrap().visibility, Visibility::Public);

        let priv_m = methods.iter().find(|m| m.name == "Foo::priv_method");
        assert!(priv_m.is_some(), "should find priv_method");
        assert_eq!(priv_m.unwrap().visibility, Visibility::Private);

        let prot_m = methods.iter().find(|m| m.name == "Foo::prot_method");
        assert!(prot_m.is_some(), "should find prot_method");
        assert_eq!(prot_m.unwrap().visibility, Visibility::Internal);
    }

    #[test]
    fn extract_struct_default_public() {
        let adapter = CppAdapter;
        let source = br#"
struct Point {
    void print() {}
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("point.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Point");

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 1);
        // Struct members default to public
        assert_eq!(methods[0].visibility, Visibility::Public);
    }

    #[test]
    fn extract_enum() {
        let adapter = CppAdapter;
        let source = b"enum Color { Red, Green, Blue };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("color.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Color");
    }

    #[test]
    fn extract_function_calls() {
        let adapter = CppAdapter;
        let source = br#"
void process() {
    parse(data);
    obj.transform();
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("proc.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .collect();
        let dst_names: Vec<&str> = calls.iter().map(|c| c.dst_name.as_str()).collect();
        assert!(dst_names.contains(&"parse"), "should find call to parse()");
        assert!(
            dst_names.contains(&"transform"),
            "should find call to transform()"
        );
    }

    #[test]
    fn extract_static_function_private() {
        let adapter = CppAdapter;
        let source = b"static void internal_helper() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("helpers.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "internal_helper");
        assert_eq!(funcs[0].visibility, Visibility::Private);
    }

    #[test]
    fn extract_class_default_private() {
        let adapter = CppAdapter;
        let source = br#"
class Secret {
    void hidden() {}
public:
    void visible() {}
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("secret.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        let hidden = methods.iter().find(|m| m.name == "Secret::hidden");
        assert!(hidden.is_some());
        assert_eq!(hidden.unwrap().visibility, Visibility::Private);

        let visible = methods.iter().find(|m| m.name == "Secret::visible");
        assert!(visible.is_some());
        assert_eq!(visible.unwrap().visibility, Visibility::Public);
    }

    #[test]
    fn extract_doxygen_block_comment() {
        let adapter = CppAdapter;
        let source = br#"
/** Computes the sum of two integers. */
int add(int a, int b) { return a + b; }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("math.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "add")
            .expect("should find add");
        assert_eq!(
            func.doc_summary.as_deref(),
            Some("Computes the sum of two integers.")
        );
    }

    #[test]
    fn extract_line_comment_on_method() {
        let adapter = CppAdapter;
        let source = br#"
class Calc {
public:
    // Multiplies two numbers.
    int mul(int a, int b) { return a * b; }
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("calc.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let method = output
            .entities
            .iter()
            .find(|e| e.name == "Calc::mul")
            .expect("should find Calc::mul");
        assert_eq!(
            method.doc_summary.as_deref(),
            Some("Multiplies two numbers.")
        );
    }

    #[test]
    fn no_comment_yields_none_cpp() {
        let adapter = CppAdapter;
        let source = b"void bare() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("bare.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "bare")
            .expect("should find bare");
        assert!(func.doc_summary.is_none());
    }

    #[test]
    fn extract_preprocessor_macros_as_entities() {
        let adapter = CppAdapter;
        let source = br#"
#define NLOHMANN_JSON_NAMESPACE_BEGIN namespace nlohmann {
#define JSON_HEDLEY_NON_NULL(...) __attribute__((nonnull(__VA_ARGS__)))
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("include/nlohmann/detail/macro_scope.hpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macros: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Macro)
            .collect();
        let names: Vec<&str> = macros.iter().map(|e| e.name.as_str()).collect();

        assert!(
            names.contains(&"NLOHMANN_JSON_NAMESPACE_BEGIN"),
            "macros={names:?}"
        );
        assert!(names.contains(&"JSON_HEDLEY_NON_NULL"), "macros={names:?}");
    }

    #[test]
    fn extract_gtest_macro() {
        let adapter = CppAdapter;
        let source = br#"
TEST(MySuite, MyTest) {
    EXPECT_EQ(1, 1);
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert!(
            !output.tests.is_empty(),
            "should detect Google Test macro, got no tests"
        );
        let t = &output.tests[0];
        assert_eq!(t.name, "MySuite::MyTest");
        assert_eq!(t.runner, "gtest");
    }

    #[test]
    fn extract_macro_usages_with_enclosing_scope_cpp() {
        let adapter = CppAdapter;
        let source = br#"
namespace ns {
    class MyClass {
        void my_method() {
            MY_MACRO();
        }
    };
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls && r.dst_name == "MY_MACRO")
            .collect();
        assert!(!calls.is_empty());
        for call in &calls {
            assert_eq!(call.src_name, "MyClass::my_method");
        }
    }
}

fn preprocess_cpp_source(source: &[u8]) -> Vec<u8> {
    let mut s = source.to_vec();
    replace_namespace_macros(&mut s);
    s
}

fn replace_namespace_macros(source: &mut [u8]) {
    let begin_macro = b"NLOHMANN_JSON_NAMESPACE_BEGIN";
    let begin_repl = b"namespace nlohmann {         ";
    let end_macro = b"NLOHMANN_JSON_NAMESPACE_END";
    let end_repl = b"}                          ";

    replace_macro_safe(source, begin_macro, begin_repl);
    replace_macro_safe(source, end_macro, end_repl);
}

fn replace_macro_safe(source: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut i = 0;
    while i + from.len() <= source.len() {
        if &source[i..i + from.len()] == from {
            if is_preceded_by_define(source, i) {
                i += from.len();
            } else {
                source[i..i + from.len()].copy_from_slice(to);
                i += from.len();
            }
        } else {
            i += 1;
        }
    }
}

fn is_preceded_by_define(source: &[u8], idx: usize) -> bool {
    let mut p = idx;
    while p > 0 {
        p -= 1;
        let c = source[p];
        if c == b' ' || c == b'\t' {
            continue;
        }
        if c == b'\n' || c == b'\r' {
            return false;
        }
        if p >= 5 && &source[p-5..p+1] == b"define" {
            p -= 5;
            while p > 0 {
                p -= 1;
                let c2 = source[p];
                if c2 == b' ' || c2 == b'\t' {
                    continue;
                }
                if c2 == b'#' {
                    return true;
                }
                break;
            }
        }
        break;
    }
    false
}
