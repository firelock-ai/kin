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

pub struct KotlinAdapter;

impl LanguageAdapter for KotlinAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Kotlin
    }

    fn file_extensions(&self) -> &[&str] {
        &["kt", "kts"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_kotlin_ng::LANGUAGE)?;
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
            extract_kotlin_node(&child, source, file_id, None, &mut entities, &mut relations);
            // tree-sitter-kotlin-ng emits individual `import` nodes at root level
            // (no `import_list` wrapper)
            if child.kind() == "import" {
                if let Some(file_import) = extract_kotlin_import(&child, source) {
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
            if matches!(
                rel.kind,
                kin_model::RelationKind::Calls | kin_model::RelationKind::References
            ) {
                if let Some(&module) = import_map.get(rel.dst_name.as_str()) {
                    rel.import_source = Some(module.to_string());
                }
            }
        }

        // Detect @Test annotated functions (JUnit/KotlinTest)
        let mut tests = Vec::new();
        extract_kotlin_tests(&root, source, &mut tests);

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests,
            parse_state,
            parsed_call_sites: None,
        })
    }
}

fn extract_kotlin_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "class_declaration" => {
            // In kotlin-ng grammar, class_declaration covers both `class` and `interface`.
            // Distinguish by looking for the anonymous keyword child.
            let is_interface = has_keyword_child(node, "interface");
            let is_enum = has_modifier(node, source, "enum");

            if let Some(name) = find_named_child_text(node, "identifier", source) {
                if name.is_empty() {
                    return;
                }

                let entity_kind = if is_interface {
                    EntityKind::Interface
                } else if is_enum {
                    EntityKind::EnumDef
                } else {
                    EntityKind::Class
                };

                let vis = detect_kotlin_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: entity_kind,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Extract inheritance from delegation_specifier children
                extract_inheritance(node, source, &name, is_interface, relations);

                // Recurse into class_body or enum_class_body
                let mut body_cursor = node.walk();
                for child in node.children(&mut body_cursor) {
                    match child.kind() {
                        "class_body" => {
                            let mut inner = child.walk();
                            for member in child.children(&mut inner) {
                                extract_kotlin_node(
                                    &member,
                                    source,
                                    file_id,
                                    Some(&name),
                                    entities,
                                    relations,
                                );
                            }
                        }
                        "enum_class_body" => {
                            let mut inner = child.walk();
                            for member in child.children(&mut inner) {
                                if member.kind() == "enum_entry" {
                                    if let Some(entry_name) =
                                        find_child_text_by_kind(&member, "identifier", source)
                                    {
                                        let qualified = format!("{}.{}", name, entry_name);
                                        entities.push(ExtractedEntity {
                                            kind: EntityKind::Constant,
                                            name: qualified.clone(),
                                            signature: node_signature(&member, source),
                                            visibility: Visibility::Public,
                                            doc_summary: None,
                                            fingerprint: compute_fingerprint(&member, source),
                                            span: span_from_node(&member, file_id),
                                        });
                                        relations.push(ExtractedRelation {
                                            site: None,
                                            receiver: None,
                                            call_shape: None,
                                            kind: kin_model::RelationKind::Contains,
                                            src_name: name.clone(),
                                            dst_name: qualified,
                                            import_source: None,
                                        });
                                    }
                                } else {
                                    // Non-enum-entry members (functions, properties, etc.)
                                    extract_kotlin_node(
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
                        _ => {}
                    }
                }
            }
        }
        "object_declaration" => {
            if let Some(name) = find_named_child_text(node, "identifier", source) {
                if name.is_empty() {
                    return;
                }

                let vis = detect_kotlin_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Recurse into object body
                if let Some(body) = find_child_by_kind(node, "class_body") {
                    let mut inner = body.walk();
                    for member in body.children(&mut inner) {
                        extract_kotlin_node(
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
        "companion_object" => {
            // Companion objects: use the parent class as context or the companion name
            let companion_name = find_named_child_text(node, "identifier", source);
            let ctx_name = if let Some(ref cname) = companion_name {
                if let Some(cls) = class_ctx {
                    format!("{}.{}", cls, cname)
                } else {
                    cname.clone()
                }
            } else if let Some(cls) = class_ctx {
                format!("{}.Companion", cls)
            } else {
                "Companion".to_string()
            };

            if let Some(body) = find_child_by_kind(node, "class_body") {
                let mut inner = body.walk();
                for member in body.children(&mut inner) {
                    extract_kotlin_node(
                        &member,
                        source,
                        file_id,
                        Some(&ctx_name),
                        entities,
                        relations,
                    );
                }
            }
        }
        "function_declaration" => {
            if let Some(func_name) = find_named_child_text(node, "identifier", source) {
                if func_name.is_empty() {
                    return;
                }

                let (kind, qualified) = if let Some(cls) = class_ctx {
                    (EntityKind::Method, format!("{}.{}", cls, func_name))
                } else {
                    (EntityKind::Function, func_name)
                };

                let vis = detect_kotlin_visibility(node, source);
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
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified.clone(),
                        import_source: None,
                    });
                }

                extract_calls_from_body(node, source, &qualified, relations);
            }
        }
        "secondary_constructor" => {
            if let Some(cls) = class_ctx {
                let ctor_name = format!("{}.constructor", cls);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: ctor_name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_kotlin_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                relations.push(ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: kin_model::RelationKind::Contains,
                    src_name: cls.to_string(),
                    dst_name: ctor_name.clone(),
                    import_source: None,
                });
                extract_calls_from_body(node, source, &ctor_name, relations);
            }
        }
        "property_declaration" => {
            if let Some(prop_name) = find_variable_declaration_name(node, source) {
                if prop_name.is_empty() {
                    return;
                }

                let is_const = has_modifier(node, source, "const");
                let is_val = has_keyword_child(node, "val");

                let qualified = if let Some(cls) = class_ctx {
                    format!("{}.{}", cls, prop_name)
                } else {
                    prop_name
                };

                let kind = if class_ctx.is_none() && (is_const || is_val) {
                    EntityKind::Constant
                } else {
                    EntityKind::StaticVar
                };

                entities.push(ExtractedEntity {
                    kind,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_kotlin_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                if let Some(cls) = class_ctx {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: qualified,
                        import_source: None,
                    });
                }
            }
        }
        "type_alias" => {
            if let Some(name) = find_named_child_text(node, "identifier", source) {
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::TypeAlias,
                        name,
                        signature: node_signature(node, source),
                        visibility: detect_kotlin_visibility(node, source),
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

/// Check if a node has an anonymous keyword child with the given kind text.
fn has_keyword_child(node: &tree_sitter::Node, keyword: &str) -> bool {
    let mut cursor = node.walk();
    let result = node
        .children(&mut cursor)
        .any(|c| !c.is_named() && c.kind() == keyword);
    result
}

/// Check if a node has a specific modifier keyword (e.g., "enum", "data", "const").
/// In kotlin-ng, modifiers contain typed children like `class_modifier`, `property_modifier`,
/// `inheritance_modifier`, etc. whose text is the keyword.
fn has_modifier(node: &tree_sitter::Node, source: &[u8], modifier_keyword: &str) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for m in child.children(&mut mod_cursor) {
                let text = m.utf8_text(source).unwrap_or("");
                if text == modifier_keyword {
                    return true;
                }
            }
        }
    }
    false
}

/// Find the first child of a given kind and return its text.
fn find_child_text_by_kind(node: &tree_sitter::Node, kind: &str, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == kind {
            let text = child.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// Find the first **named** child of a given kind and return its text.
/// In kotlin-ng, `identifier` is a named node (unlike `simple_identifier` or `type_identifier`
/// which do not exist in this grammar). We use `child_by_field_name` when the grammar uses
/// a field like `name:`, falling back to kind-based search.
fn find_named_child_text(node: &tree_sitter::Node, kind: &str, source: &[u8]) -> Option<String> {
    // First try the "name" field which many kotlin-ng rules use
    if let Some(child) = node.child_by_field_name("name") {
        if child.kind() == kind {
            let text = child.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    // Also try the "type" field (used by type_alias)
    if let Some(child) = node.child_by_field_name("type") {
        if child.kind() == kind {
            let text = child.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    // Fallback to first named child matching the kind
    find_child_text_by_kind(node, kind, source)
}

/// Find the first child of a given kind.
fn find_child_by_kind<'a>(
    node: &'a tree_sitter::Node,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    let result = node.children(&mut cursor).find(|c| c.kind() == kind);
    result
}

/// Extract the variable name from a `variable_declaration` or `multi_variable_declaration`
/// inside a property_declaration.
/// In kotlin-ng, property_declaration contains `variable_declaration` which has an `identifier` child.
fn find_variable_declaration_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "multi_variable_declaration" || child.kind() == "variable_declaration" {
            return find_child_text_by_kind(&child, "identifier", source);
        }
    }
    None
}

fn detect_kotlin_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for m in child.children(&mut mod_cursor) {
                if m.kind() == "visibility_modifier" {
                    let text = m.utf8_text(source).unwrap_or("");
                    return match text {
                        "public" => Visibility::Public,
                        "private" => Visibility::Private,
                        "protected" => Visibility::Internal,
                        "internal" => Visibility::Internal,
                        _ => Visibility::Public,
                    };
                }
            }
        }
    }
    // Kotlin default visibility is public
    Visibility::Public
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_preceding_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if prev.kind() == "multiline_comment"
        || prev.kind() == "comment"
        || prev.kind() == "line_comment"
    {
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

/// Extract inheritance/implementation from delegation_specifiers.
/// In kotlin-ng: class_declaration > delegation_specifiers > delegation_specifier > ...
fn extract_inheritance(
    node: &tree_sitter::Node,
    source: &[u8],
    type_name: &str,
    is_interface: bool,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "delegation_specifiers" => {
                // Wrapper node containing delegation_specifier children
                let mut inner = child.walk();
                for spec in child.children(&mut inner) {
                    if spec.kind() == "delegation_specifier" {
                        extract_delegation_specifier(
                            &spec,
                            source,
                            type_name,
                            is_interface,
                            relations,
                        );
                    }
                }
            }
            "delegation_specifier" => {
                extract_delegation_specifier(&child, source, type_name, is_interface, relations);
            }
            _ => {}
        }
    }
}

fn extract_delegation_specifier(
    node: &tree_sitter::Node,
    source: &[u8],
    type_name: &str,
    is_interface: bool,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "constructor_invocation" => {
                if let Some(parent_name) = extract_user_type_name(&child, source) {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Extends,
                        src_name: type_name.to_string(),
                        dst_name: parent_name,
                        import_source: None,
                    });
                }
            }
            "user_type" => {
                let parent_name = extract_user_type_name(&child, source)
                    .unwrap_or_else(|| child.utf8_text(source).unwrap_or("").to_string());
                if !parent_name.is_empty() && parent_name != type_name {
                    let rel_kind = if is_interface {
                        kin_model::RelationKind::Extends
                    } else {
                        kin_model::RelationKind::Implements
                    };
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: rel_kind,
                        src_name: type_name.to_string(),
                        dst_name: parent_name,
                        import_source: None,
                    });
                }
            }
            _ => {}
        }
    }
}

/// Extract the type name from a user_type or constructor_invocation node.
fn extract_user_type_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Try to find user_type child first (for constructor_invocation)
    if let Some(ut) = find_child_by_kind(node, "user_type") {
        return extract_user_type_name(&ut, source);
    }
    // In kotlin-ng, user_type contains `identifier` nodes
    find_child_text_by_kind(node, "identifier", source)
}

/// Recursively walk a function body to find call_expression nodes.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(callee) = extract_callee_name(&child, source) {
                if !callee.is_empty() {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
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

/// Extract the callee name from a call_expression.
///
/// For navigation chains like `a.b.c()` the kotlin-ng grammar shape is:
///   (call_expression
///     (navigation_expression
///       (navigation_expression (identifier "a") (identifier "b"))
///       (identifier "c"))
///     (value_arguments))
/// We unwrap to the rightmost trailing identifier, so `a.b.c()` maps to `"c"`
/// and `obj?.foo()` maps to `"foo"`. This mirrors the Python attribute-call
/// fix and keeps Calls edges keyed on simple names.
fn extract_callee_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" | "simple_identifier" => {
                let raw = child.utf8_text(source).unwrap_or("");
                let stripped = raw.strip_prefix("this.").unwrap_or(raw);
                return Some(stripped.to_string());
            }
            "navigation_expression" => {
                return extract_trailing_identifier(&child, source);
            }
            "call_suffix" | "value_arguments" | "lambda_literal" | "annotated_lambda" => continue,
            _ => {}
        }
    }
    None
}

/// Walk a kotlin-ng `navigation_expression` to its rightmost `identifier` child.
/// The grammar nests chains left-associatively, so the trailing simple name is
/// always the last named `identifier` at the outermost level.
fn extract_trailing_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let mut last_ident: Option<String> = None;
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" || child.kind() == "simple_identifier" {
            last_ident = Some(child.utf8_text(source).unwrap_or("").to_string());
        }
    }
    last_ident.filter(|s| !s.is_empty())
}

/// Extract a structured import from a kotlin-ng `import` node.
///
/// Grammar shapes:
///   import kotlin.collections.List       => (import (qualified_identifier (identifier)x3))
///   import kotlin.collections.List as K  => (import (qualified_identifier (identifier)x3) (identifier))
///   import kotlin.collections.*           => (import (qualified_identifier (identifier)x2))
///                                            (wildcard detected by trailing `.*` in source text)
fn extract_kotlin_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let qi_node = find_child_by_kind(node, "qualified_identifier")?;
    let full_path = qi_node.utf8_text(source).unwrap_or("").to_string();
    if full_path.is_empty() {
        return None;
    }

    // Check for wildcard: source text of the import node ends with `.*`
    let node_text = node.utf8_text(source).unwrap_or("");
    let is_wildcard = node_text.trim().ends_with(".*");

    // Check for alias: an `identifier` child directly on the import node (not inside
    // qualified_identifier). The qualified_identifier holds the path; a second `identifier`
    // sibling is the alias.
    let alias = {
        let mut cursor = node.walk();
        let mut alias_text = None;
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                alias_text = Some(child.utf8_text(source).unwrap_or("").to_string());
                break;
            }
        }
        alias_text.filter(|s| !s.is_empty())
    };

    if is_wildcard {
        return Some(FileImport {
            site: crate::adapter::site_from_node(node),
            module_path: full_path,
            specifiers: vec![ImportedName {
                local_name: "*".to_string(),
                original_name: None,
                is_default: false,
            }],
        });
    }

    // Split qualified path into module_path and imported name
    if let Some(dot_pos) = full_path.rfind('.') {
        let module_path = full_path[..dot_pos].to_string();
        let original_name = full_path[dot_pos + 1..].to_string();
        let has_alias = alias.is_some();
        let local_name = alias.unwrap_or_else(|| original_name.clone());
        Some(FileImport {
            site: crate::adapter::site_from_node(node),
            module_path,
            specifiers: vec![ImportedName {
                local_name,
                original_name: if has_alias { Some(original_name) } else { None },
                is_default: false,
            }],
        })
    } else {
        let local_name = alias.unwrap_or_else(|| full_path.clone());
        Some(FileImport {
            site: crate::adapter::site_from_node(node),
            module_path: String::new(),
            specifiers: vec![ImportedName {
                local_name,
                original_name: None,
                is_default: false,
            }],
        })
    }
}

/// Recursively detect @Test annotated functions in Kotlin source.
fn extract_kotlin_tests(node: &tree_sitter::Node, source: &[u8], tests: &mut Vec<ExtractedTest>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declaration" && has_test_annotation(&child, source) {
            if let Some(name) = find_named_child_text(&child, "identifier", source) {
                if !name.is_empty() {
                    tests.push(ExtractedTest {
                        name,
                        kind: ExtractedTestKind::Unit,
                        runner: "junit".to_string(),
                    });
                }
            }
        }
        // Recurse into class bodies, etc.
        extract_kotlin_tests(&child, source, tests);
    }
}

/// Check if a function has an @Test annotation.
fn has_test_annotation(node: &tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for m in child.children(&mut mod_cursor) {
                if m.kind() == "annotation" || m.kind() == "single_annotation" {
                    let text = m.utf8_text(source).unwrap_or("");
                    if text.contains("Test") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kotlin_class() {
        let adapter = KotlinAdapter;
        let source = b"class Dog { fun bark() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Dog.kt");
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
    fn parse_kotlin_interface() {
        let adapter = KotlinAdapter;
        let source = b"interface Runnable { fun run() }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Runnable.kt");
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
    fn parse_kotlin_data_class() {
        let adapter = KotlinAdapter;
        let source = b"data class Point(val x: Int, val y: Int)";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Point.kt");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Point");
    }

    #[test]
    fn parse_kotlin_object() {
        let adapter = KotlinAdapter;
        let source = b"object Singleton { fun instance() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Singleton.kt");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let objects: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, "Singleton");
    }

    #[test]
    fn parse_kotlin_function() {
        let adapter = KotlinAdapter;
        let source = b"fun add(a: Int, b: Int): Int = a + b";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("math.kt");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "add");
    }

    #[test]
    fn parse_kotlin_method_calls() {
        let adapter = KotlinAdapter;
        let source = b"class App { fun run() { println(\"hi\"); doWork() } }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("App.kt");
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
    fn parse_kotlin_imports() {
        let adapter = KotlinAdapter;
        let source = b"import kotlin.collections.List\nimport java.io.File\n\nfun main() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("App.kt");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 2);

        let list_import = output
            .imports
            .iter()
            .find(|i| i.module_path == "kotlin.collections")
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

    #[test]
    fn parse_kotlin_visibility() {
        let adapter = KotlinAdapter;
        let source =
            b"public fun publicFunc() {}\nprivate fun privateFunc() {}\nfun defaultFunc() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("vis.kt");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 3);

        let public_fn = funcs.iter().find(|f| f.name == "publicFunc").unwrap();
        assert_eq!(public_fn.visibility, Visibility::Public);

        let private_fn = funcs.iter().find(|f| f.name == "privateFunc").unwrap();
        assert_eq!(private_fn.visibility, Visibility::Private);

        // Kotlin default visibility is public
        let default_fn = funcs.iter().find(|f| f.name == "defaultFunc").unwrap();
        assert_eq!(default_fn.visibility, Visibility::Public);
    }
}
