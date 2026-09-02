// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    CallArgShape, ExtractedEntity, ExtractedRelation, ExtractedTest, ExtractedTestKind, FileImport,
    ImportedName, ParseOutput,
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
            parsed_call_sites: None,
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
                        site: None,
                        receiver: None,
                        call_shape: None,
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
        // A union is modeled as a Class; its members default to public like a struct.
        "union_specifier" => {
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
            for name in typedef_alias_names(node, source) {
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
        "alias_declaration" => {
            if let Some((alias_name, referenced_types)) = extract_alias_declaration(node, source) {
                let scoped_alias = class_ctx
                    .map(|class_name| format!("{class_name}::{alias_name}"))
                    .unwrap_or_else(|| alias_name.clone());
                entities.push(ExtractedEntity {
                    kind: EntityKind::TypeAlias,
                    name: scoped_alias,
                    signature: node_signature(node, source),
                    visibility: default_vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                let src_name = class_ctx
                    .map(str::to_string)
                    .unwrap_or_else(|| alias_name.clone());
                for referenced_type in referenced_types {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::References,
                        src_name: src_name.clone(),
                        dst_name: referenced_type,
                        import_source: None,
                    });
                }
            }
        }
        "template_declaration" => {
            // Unwrap the template and extract the inner declaration.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "class_specifier"
                    | "struct_specifier"
                    | "union_specifier"
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
        //
        // `extern "C" { ... }` is a linkage_specification whose declaration_list body
        // holds the rest of the header. A header shared with C opens that brace inside
        // one `#ifdef __cplusplus` and closes it inside another, so tree-sitter puts
        // every declaration between them in the body rather than at the top level. An
        // ERROR node likewise keeps the well-formed subtrees error recovery salvaged.
        // Walk through all of them, or a header's entire public API stays invisible.
        "preproc_ifdef"
        | "preproc_if"
        | "preproc_else"
        | "preproc_elif"
        | "linkage_specification"
        | "declaration_list"
        | "ERROR" => {
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
                        name: name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });

                    // tree-sitter leaves a macro's replacement list as an opaque
                    // `preproc_arg`, so references made INSIDE a macro body are
                    // never walked as identifier nodes. Lex the body text and
                    // emit `UsesMacro` edges to the ALL_CAPS macros it expands to
                    // (e.g. Catch2's INTERNAL_CATCH_* chains), sourced from this
                    // macro. The macro's own name, its parameters, and reserved
                    // `__`-prefixed identifiers are excluded; the linker drops
                    // any target that resolves to no Macro entity.
                    if let Some(value_node) = node.child_by_field_name("value") {
                        let body = value_node.utf8_text(source).unwrap_or("");
                        let params = macro_parameter_names(node, source);
                        let mut seen = std::collections::HashSet::new();
                        for token in lex_identifiers(body) {
                            if token != name
                                && !token.starts_with("__")
                                && !params.contains(token)
                                && is_all_caps_macro(token)
                                && seen.insert(token.to_string())
                            {
                                relations.push(ExtractedRelation {
                                    site: None,
                                    receiver: None,
                                    call_shape: None,
                                    kind: kin_model::RelationKind::UsesMacro,
                                    src_name: name.clone(),
                                    dst_name: token.to_string(),
                                    import_source: None,
                                });
                            }
                        }
                    }
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
                "function_definition"
                | "declaration"
                | "alias_declaration"
                | "template_declaration" => {
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
                        site: None,
                        receiver: None,
                        call_shape: None,
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

/// How far to follow a declarator chain before giving up. Real C++ nests a handful of
/// pointers and parentheses; anything deeper is malformed input, not a name.
const MAX_DECLARATOR_DEPTH: usize = 16;

/// Resolve the name a typedef declarator introduces.
///
/// A typedef alias arrives wrapped in whatever declarator syntax names it: `IntVec`,
/// `*foo_p`, `arr_t[10]` or `(*Handler)(int, void *)`. Follow the chain down through
/// pointers, arrays, functions and parentheses to the name at the bottom, so a
/// function-pointer typedef is stored as `Handler` and not as the text of its
/// declarator, which no query can reach.
///
/// Deliberately separate from [`declarator_name`], which serves receiver-type
/// mapping: that one stops at an `identifier` and skips function declarators, while a
/// typedef's leaf is a `type_identifier` and its function-pointer form is exactly a
/// function declarator. Widening the shared helper would change what
/// `record_typed_declarators` records.
fn typedef_declarator_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut current = *node;
    for _ in 0..MAX_DECLARATOR_DEPTH {
        // A parenthesized declarator holds its inner declarator as an unnamed child.
        let next = current
            .child_by_field_name("declarator")
            .or_else(|| current.named_child(0));
        let Some(next) = next else {
            let text = current.utf8_text(source).unwrap_or("").trim().to_string();
            return if text.is_empty() { None } else { Some(text) };
        };
        current = next;
    }
    None
}

/// Collect every alias name a `type_definition` introduces.
///
/// One typedef can name several: `typedef struct Foo { ... } Foo, *FooPtr;` carries two
/// `declarator` fields, and reading only the first loses `FooPtr`.
///
/// A malformed typedef such as `typedef struct Foo;` parses with a MISSING, empty
/// `type_identifier` in the declarator field, so it yields no name and no entity. That
/// is deliberate: the alternative is an entity whose name is the empty string, which no
/// query can reach and which the adapter conformance suite refuses.
fn typedef_alias_names(node: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for i in 0..node.child_count() {
        let Ok(child_index) = i.try_into() else {
            continue;
        };
        if node.field_name_for_child(child_index) != Some("declarator") {
            continue;
        }
        let Some(child) = node.child(child_index) else {
            continue;
        };
        if let Some(name) = typedef_declarator_name(&child, source) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

fn extract_alias_declaration(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<(String, Vec<String>)> {
    let alias_name = node
        .child_by_field_name("name")
        .and_then(|child| child.utf8_text(source).ok())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .or_else(|| first_alias_type_identifier(node, source))?;

    let mut references =
        alias_rhs_type_references(node.utf8_text(source).unwrap_or(""), &alias_name);
    let mut skipped_alias = false;
    collect_alias_referenced_types(
        node,
        source,
        &alias_name,
        &mut skipped_alias,
        &mut references,
    );
    references.sort();
    references.dedup();
    Some((alias_name, references))
}

fn alias_rhs_type_references(alias_text: &str, alias_name: &str) -> Vec<String> {
    let Some((_, rhs)) = alias_text.split_once('=') else {
        return Vec::new();
    };
    let mut references = Vec::new();
    let mut token = String::new();
    for ch in rhs.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            token.push(ch);
        } else if !token.is_empty() {
            push_normalized_alias_reference(&token, alias_name, &mut references);
            token.clear();
        }
    }
    if !token.is_empty() {
        push_normalized_alias_reference(&token, alias_name, &mut references);
    }
    references
}

fn push_normalized_alias_reference(raw: &str, _alias_name: &str, references: &mut Vec<String>) {
    if let Some(name) = normalize_cpp_type_reference(raw) {
        if !is_unhelpful_cpp_type_reference(&name) {
            references.push(name);
        }
    }
}

fn first_alias_type_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_identifier" {
            let text = child.utf8_text(source).unwrap_or("").trim().to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn collect_alias_referenced_types(
    node: &tree_sitter::Node,
    source: &[u8],
    alias_name: &str,
    skipped_alias: &mut bool,
    references: &mut Vec<String>,
) {
    match node.kind() {
        "qualified_identifier" => {
            if let Some(name) = normalize_cpp_type_reference(node.utf8_text(source).unwrap_or("")) {
                if name != alias_name && !is_unhelpful_cpp_type_reference(&name) {
                    references.push(name);
                }
            }
            return;
        }
        "type_identifier" => {
            if let Some(name) = normalize_cpp_type_reference(node.utf8_text(source).unwrap_or("")) {
                if name == alias_name && !*skipped_alias {
                    *skipped_alias = true;
                    return;
                }
                if name != alias_name && !is_unhelpful_cpp_type_reference(&name) {
                    references.push(name);
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_alias_referenced_types(&child, source, alias_name, skipped_alias, references);
    }
}

fn normalize_cpp_type_reference(raw: &str) -> Option<String> {
    let before_template = raw.split('<').next().unwrap_or(raw);
    let trimmed = before_template
        .trim()
        .trim_start_matches("::")
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != ':');
    let name = trimmed
        .rsplit("::")
        .next()
        .unwrap_or(trimmed)
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn is_unhelpful_cpp_type_reference(name: &str) -> bool {
    matches!(
        name,
        "void"
            | "bool"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "auto"
            | "typename"
            | "class"
            | "struct"
    )
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
    crate::adapter::declaration_signature(node, source)
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

/// Strip template-argument lists from a callee path while preserving its
/// `::` structure: `ratio_string<Ratio>::symbol` → `ratio_string::symbol`.
/// Template args in a callee name defeat every name index downstream (the
/// suffix resolver rejects `<`/`>` outright), so the emitted reference must
/// carry the instantiation-free path. Operator names are kept verbatim —
/// their angle brackets are not template arguments.
fn strip_callee_template_args(raw: &str) -> String {
    if !raw.contains('<') || raw.contains("operator") {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut depth = 0usize;
    for ch in raw.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            c if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// Static receiver types visible inside one function/method body: local
/// variables and parameters (`var_types`), the enclosing class name for a
/// `this` receiver (`enclosing_class`), and the enclosing class's data members
/// (`member_types`). A `recv.method()` / `recv->method()` whose receiver type
/// resolves here is emitted as `Type::method`, so the linker binds it to that
/// class instead of fanning the call out to every same-named method.
#[derive(Default)]
struct ReceiverScope {
    enclosing_class: Option<String>,
    var_types: std::collections::HashMap<String, String>,
    member_types: std::collections::HashMap<String, String>,
}

impl ReceiverScope {
    fn owner_of(&self, receiver: &str) -> Option<&str> {
        self.var_types
            .get(receiver)
            .or_else(|| self.member_types.get(receiver))
            .map(String::as_str)
    }
}

/// Walk a function/method body and emit its `call_expression` edges. A method
/// call's receiver static type is resolved through the body's [`ReceiverScope`]
/// so a typed receiver binds to `Type::method`; an unresolvable receiver keeps
/// the bare rightmost name (the linker's ambiguous-fanout tier weighs those).
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut scope = ReceiverScope {
        enclosing_class: context_name
            .rsplit_once("::")
            .map(|(owner, _)| owner.to_string()),
        ..ReceiverScope::default()
    };
    collect_param_types(node, source, &mut scope.var_types);
    collect_local_var_types(node, source, &mut scope.var_types);
    collect_member_field_types(node, source, &mut scope.member_types);
    collect_scoped_calls(node, source, context_name, &scope, relations);
}

fn collect_scoped_calls(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    scope: &ReceiverScope,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                let dst_name = if function.kind() == "field_expression" {
                    let method = strip_callee_template_args(
                        function
                            .child_by_field_name("field")
                            .and_then(|f| f.utf8_text(source).ok())
                            .unwrap_or_default(),
                    );
                    match receiver_owner(&function, source, scope) {
                        Some(owner) if is_valid_callee(&method) => format!("{owner}::{method}"),
                        _ => method,
                    }
                } else {
                    strip_callee_template_args(function.utf8_text(source).unwrap_or(""))
                };
                if is_valid_callee(&dst_name) {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name,
                        import_source: None,
                        call_shape: cpp_call_shape(&child, source),
                    });
                }
            }
        }
        collect_scoped_calls(&child, source, context_name, scope, relations);
    }
}

/// The [`CallArgShape`] of a C++ `call_expression`. tree-sitter groups a call's
/// arguments into an `argument_list` whose named children are the argument
/// expressions, so the positional count is nesting-correct: `f(g(x), y)` is 2,
/// `f(Ptr<A, B>{})` is 1 (the template comma is inside one argument), `f()` is
/// 0. Interspersed comments are skipped. C++ has no keyword arguments, so
/// `keywords` is empty and `has_var_keyword` is always false; a pack expansion
/// (`args...`) sets `has_var_positional` so the linker treats the count as a
/// lower bound and prunes nothing. `None` when the call carries no argument
/// list, leaving the linker to bind that call shape-blind.
fn cpp_call_shape(call_expr: &tree_sitter::Node, source: &[u8]) -> Option<CallArgShape> {
    let arguments = call_expr.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut positional: u32 = 0;
    let mut has_var_positional = false;
    for arg in arguments.named_children(&mut cursor) {
        if arg.kind() == "comment" {
            continue;
        }
        positional += 1;
        if argument_is_pack_expansion(&arg, source) {
            has_var_positional = true;
        }
    }
    Some(CallArgShape {
        positional,
        keywords: Vec::new(),
        has_var_positional,
        has_var_keyword: false,
    })
}

/// Whether a call argument is a pack/splat expansion (`args...`,
/// `std::forward<T>(args)...`). tree-sitter can model the trailing `...` as its
/// own token rather than part of the argument node, so this keys on the
/// argument's text ending in `...` — the reliable surface signal, and
/// conservative: a missed pack only forgoes an optimization, a spurious hit only
/// widens the accepted arity, and neither drops a real edge.
fn argument_is_pack_expansion(arg: &tree_sitter::Node, source: &[u8]) -> bool {
    arg.utf8_text(source)
        .map(|text| text.trim_end().ends_with("..."))
        .unwrap_or(false)
}

/// Resolve a `field_expression` receiver to a class name: `this` binds to the
/// enclosing class; a bare identifier binds to its local/parameter type, then to
/// an enclosing-class member's type. Any other receiver shape (chained access,
/// call result, subscript) is left unresolved so the call keeps its bare name.
fn receiver_owner(
    field_expr: &tree_sitter::Node,
    source: &[u8],
    scope: &ReceiverScope,
) -> Option<String> {
    let receiver = field_expr.child_by_field_name("argument")?;
    match receiver.kind() {
        "this" => scope.enclosing_class.clone(),
        "identifier" => scope
            .owner_of(receiver.utf8_text(source).ok()?)
            .map(str::to_string),
        _ => None,
    }
}

/// Collect `name -> class type` for the parameters under a function declarator.
fn collect_param_types(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut std::collections::HashMap<String, String>,
) {
    if node.kind() == "parameter_list" {
        let mut cursor = node.walk();
        for param in node.children(&mut cursor) {
            if matches!(
                param.kind(),
                "parameter_declaration" | "optional_parameter_declaration"
            ) {
                record_typed_declarators(&param, source, out);
            }
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_param_types(&child, source, out);
    }
}

/// Collect `name -> class type` for every local `declaration` in a body.
fn collect_local_var_types(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut std::collections::HashMap<String, String>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "declaration" {
            record_typed_declarators(&child, source, out);
        }
        collect_local_var_types(&child, source, out);
    }
}

/// Collect `member -> class type` for the enclosing class's data members, found
/// by walking up to the nearest class/struct/union and reading its field list.
fn collect_member_field_types(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut std::collections::HashMap<String, String>,
) {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            if let Some(body) = ancestor.child_by_field_name("body") {
                let mut cursor = body.walk();
                for member in body.children(&mut cursor) {
                    if member.kind() == "field_declaration" {
                        record_typed_declarators(&member, source, out);
                    }
                }
            }
            return;
        }
        current = ancestor.parent();
    }
}

/// Map each of a declaration's named declarators to its class type. Function
/// declarators (method prototypes) carry no receiver type and are skipped, as
/// are non-class types (`int`, `auto`, ...).
fn record_typed_declarators(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut std::collections::HashMap<String, String>,
) {
    let Some(class_type) = node
        .child_by_field_name("type")
        .and_then(|t| type_class_name(&t, source))
    else {
        return;
    };
    let mut cursor = node.walk();
    for declarator in node.children_by_field_name("declarator", &mut cursor) {
        if declarator_is_function(&declarator) {
            continue;
        }
        if let Some(name) = declarator_name(&declarator, source) {
            out.entry(name).or_insert_with(|| class_type.clone());
        }
    }
}

/// Reduce a `type` node to the bare class name usable as an entity key: a plain
/// or template type yields its identifier, a qualified type its leaf; primitive
/// and inferred (`auto`) types yield nothing.
fn type_class_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => node.utf8_text(source).ok().map(str::to_string),
        "template_type" | "qualified_identifier" => node
            .child_by_field_name("name")
            .and_then(|n| type_class_name(&n, source)),
        _ => None,
    }
}

/// Descend a declarator through pointer/reference/array/init wrappers to the
/// declared identifier.
fn declarator_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => node.utf8_text(source).ok().map(str::to_string),
        "pointer_declarator" | "array_declarator" | "init_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|c| declarator_name(&c, source)),
        "reference_declarator" | "parenthesized_declarator" => node
            .named_child(0)
            .and_then(|c| declarator_name(&c, source)),
        _ => None,
    }
}

/// Whether a declarator declares a function (a method prototype), which has no
/// receiver type to record.
fn declarator_is_function(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "function_declarator" => true,
        "pointer_declarator"
        | "reference_declarator"
        | "init_declarator"
        | "array_declarator"
        | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .or_else(|| node.named_child(0))
            .map(|c| declarator_is_function(&c))
            .unwrap_or(false),
        _ => false,
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

#[allow(clippy::only_used_in_recursion)]
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
        if let Ok(name) = node.utf8_text(source) {
            if is_all_caps_macro(name) {
                if let Some(src_name) = find_enclosing_entity(node, source) {
                    if src_name != name && !src_name.ends_with(&format!("::{}", name)) {
                        relations.push(ExtractedRelation {
                            site: None,
                            receiver: None,
                            call_shape: None,
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

/// Collect the parameter names of a function-like macro (`#define M(a, b) ...`)
/// so they are not mistaken for referenced macros in the replacement list.
fn macro_parameter_names(
    node: &tree_sitter::Node,
    source: &[u8],
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut cursor = params.walk();
        for child in params.children(&mut cursor) {
            if child.kind() == "identifier" {
                if let Ok(text) = child.utf8_text(source) {
                    if !text.is_empty() {
                        names.insert(text.to_string());
                    }
                }
            }
        }
    }
    names
}

/// Lex identifier tokens from raw text, skipping the contents of string and
/// char literals so quoted words are never treated as identifiers. Used to
/// scan opaque macro-body text that tree-sitter does not tokenize.
fn lex_identifiers(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'"' | b'\'' => {
                let quote = c;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    let closed = bytes[i] == quote;
                    i += 1;
                    if closed {
                        break;
                    }
                }
            }
            _ if c == b'_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                if let Ok(tok) = std::str::from_utf8(&bytes[start..i]) {
                    tokens.push(tok);
                }
            }
            _ => {
                i += 1;
            }
        }
    }
    tokens
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
                    site: crate::adapter::site_from_node(node),
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

#[allow(clippy::items_after_test_module)]
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
    fn extracts_lowercase_preprocessor_macro_definitions_without_use_noise() {
        let adapter = CppAdapter;
        let source = br#"
#define private public
class Secret {
private:
    int value = 0;
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("secret.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macro_entity = output
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Macro && entity.name == "private")
            .expect("lowercase preprocessor definitions should remain graph-visible macros");
        assert!(
            macro_entity.signature.contains("#define private public"),
            "macro signature should preserve the source directive, got {:?}",
            macro_entity.signature
        );
        assert!(
            output.relations.iter().all(|relation| relation.kind
                != kin_model::RelationKind::UsesMacro
                || relation.dst_name != "private"),
            "lowercase identifiers should not be promoted to macro-use edges"
        );
    }

    #[test]
    fn alias_declarations_emit_references_to_rhs_types() {
        let adapter = CppAdapter;
        let source = br#"
template<typename BasicJsonType>
class basic_json {
private:
    using internal_iterator = ::nlohmann::detail::internal_iterator<BasicJsonType>;
    using iter_impl = ::nlohmann::detail::iter_impl<BasicJsonType>;
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("json.hpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let aliases: Vec<_> = output
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::TypeAlias)
            .map(|entity| entity.name.as_str())
            .collect();
        assert!(
            aliases.contains(&"basic_json::internal_iterator"),
            "class-local alias entity should be scoped, got {aliases:?}"
        );
        assert!(
            aliases.contains(&"basic_json::iter_impl"),
            "class-local alias entity should be scoped, got {aliases:?}"
        );

        let references: Vec<_> = output
            .relations
            .iter()
            .filter(|relation| {
                relation.kind == kin_model::RelationKind::References
                    && relation.src_name == "basic_json"
            })
            .map(|relation| relation.dst_name.as_str())
            .collect();
        assert!(
            references.contains(&"internal_iterator"),
            "alias RHS should reference internal_iterator, got {references:?}"
        );
        assert!(
            references.contains(&"iter_impl"),
            "alias RHS should reference iter_impl, got {references:?}"
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

    #[test]
    fn macro_body_references_emit_uses_macro_edges() {
        // Catch2-style macros expand to INTERNAL_CATCH_* chains. tree-sitter
        // leaves the replacement list as opaque text, so without lexing the body
        // these macro->macro references are lost and a behavioral revert made
        // inside a macro body is invisible to impact analysis.
        let adapter = CppAdapter;
        let source = br#"
#define CATCH_FLAG 1
#define INTERNAL_CATCH_TEST(expr, flag) do_check(expr, flag)
#define INTERNAL_CATCH_TESTCASE2(name) do_register(name)
#define INTERNAL_CATCH_TEST_CASE(...) INTERNAL_CATCH_TESTCASE2(__VA_ARGS__)
#define CATCH_REQUIRE(expr) INTERNAL_CATCH_TEST(expr, CATCH_FLAG)
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("catch.hpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let uses: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::UsesMacro)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();

        assert!(
            uses.contains(&("INTERNAL_CATCH_TEST_CASE", "INTERNAL_CATCH_TESTCASE2")),
            "a macro should reference the macro its body expands to, found: {uses:?}"
        );
        assert!(
            uses.contains(&("CATCH_REQUIRE", "INTERNAL_CATCH_TEST")),
            "CATCH_REQUIRE should reference INTERNAL_CATCH_TEST from its body, found: {uses:?}"
        );
        assert!(
            uses.contains(&("CATCH_REQUIRE", "CATCH_FLAG")),
            "CATCH_REQUIRE should reference the CATCH_FLAG token in its body, found: {uses:?}"
        );
        // `__VA_ARGS__` is a reserved builtin, not a repo macro.
        assert!(
            !uses.iter().any(|(_, dst)| *dst == "__VA_ARGS__"),
            "reserved __-prefixed identifiers must not be referenced, found: {uses:?}"
        );
        // `expr` is a macro parameter (and lowercase) — never a macro reference.
        assert!(
            !uses.iter().any(|(_, dst)| *dst == "expr"),
            "macro parameters must not be referenced, found: {uses:?}"
        );
        // A macro must never reference itself.
        assert!(
            !uses.iter().any(|(src, dst)| src == dst),
            "a macro must not reference itself, found: {uses:?}"
        );
    }

    #[test]
    fn macro_body_ignores_string_literal_contents() {
        // ALL_CAPS words inside a string literal are text, not macro references.
        let adapter = CppAdapter;
        let source = br#"
#define LOG_MESSAGE(x) emit("ERROR", x, OTHER_MACRO)
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("log.hpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let uses: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::UsesMacro)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();

        assert!(
            uses.contains(&("LOG_MESSAGE", "OTHER_MACRO")),
            "the bare macro token should be referenced, found: {uses:?}"
        );
        assert!(
            !uses.iter().any(|(_, dst)| *dst == "ERROR"),
            "ALL_CAPS words inside a string literal must not be referenced, found: {uses:?}"
        );
    }

    #[test]
    fn extract_union() {
        let adapter = CppAdapter;
        let source = b"union Value { int i; float f; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("value.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let unions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(unions.len(), 1);
        assert_eq!(unions[0].name, "Value");
    }

    #[test]
    fn extract_union_with_method() {
        let adapter = CppAdapter;
        let source = br#"
union Tagged {
    int as_int() { return 0; }
};
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("tagged.cpp");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let unions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(unions.len(), 1);
        assert_eq!(unions[0].name, "Tagged");

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].name, "Tagged::as_int");
        // Union members default to public, mirroring struct.
        assert_eq!(methods[0].visibility, Visibility::Public);

        assert!(output
            .relations
            .iter()
            .any(|r| r.kind == kin_model::RelationKind::Contains
                && r.src_name == "Tagged"
                && r.dst_name == "Tagged::as_int"));
    }

    /// A header shared with C: one `#ifdef __cplusplus` opens the `extern "C"` brace
    /// and a second one closes it, so tree-sitter puts the whole public API inside a
    /// single linkage_specification.
    const EXTERN_C_HEADER: &[u8] = br#"
#ifndef EXAMPLE_SHARED_H
#define EXAMPLE_SHARED_H

#ifdef __cplusplus
extern "C" {
#endif

#define EXAMPLE_MAX_BUF 4096

typedef void (*ExampleHandler)(int code, void *ctx);
typedef unsigned long example_size_t;

int example_open(const char *path);

#ifdef __cplusplus
}
#endif

#endif
"#;

    fn cpp_entities(source: &[u8], file: &str) -> Vec<ExtractedEntity> {
        let adapter = CppAdapter;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new(file);
        adapter.extract(&tree, source, &file_id).unwrap().entities
    }

    fn cpp_names_of(entities: &[ExtractedEntity], kind: EntityKind) -> Vec<String> {
        entities
            .iter()
            .filter(|entity| entity.kind == kind)
            .map(|entity| entity.name.clone())
            .collect()
    }

    #[test]
    fn extern_c_block_does_not_hide_the_public_api() {
        let entities = cpp_entities(EXTERN_C_HEADER, "shared.h");
        let aliases = cpp_names_of(&entities, EntityKind::TypeAlias);
        assert!(
            aliases.iter().any(|name| name == "ExampleHandler"),
            "{aliases:?}"
        );
        assert!(
            aliases.iter().any(|name| name == "example_size_t"),
            "{aliases:?}"
        );
        assert!(
            cpp_names_of(&entities, EntityKind::Function)
                .iter()
                .any(|name| name == "example_open"),
            "the prototype inside the extern C block was dropped"
        );
        assert!(
            cpp_names_of(&entities, EntityKind::Macro)
                .iter()
                .any(|name| name == "EXAMPLE_MAX_BUF"),
            "the macro inside the extern C block was dropped"
        );
    }

    #[test]
    fn function_pointer_typedef_is_named_by_its_identifier() {
        let entities = cpp_entities(
            b"typedef void (*Handler)(int, void*);\ntypedef void (Plain)(int);\n",
            "cb.hpp",
        );
        let aliases = cpp_names_of(&entities, EntityKind::TypeAlias);
        assert!(aliases.iter().any(|name| name == "Handler"), "{aliases:?}");
        assert!(aliases.iter().any(|name| name == "Plain"), "{aliases:?}");
        assert!(
            aliases.iter().all(|name| !name.contains('(')),
            "a raw declarator leaked into a name: {aliases:?}"
        );
    }

    #[test]
    fn a_typedef_records_every_alias_it_declares() {
        let entities = cpp_entities(b"typedef struct Node { int v; } Node, *NodePtr;", "n.hpp");
        let aliases = cpp_names_of(&entities, EntityKind::TypeAlias);
        assert!(
            aliases.iter().any(|name| name == "NodePtr"),
            "the second declarator was dropped: {aliases:?}"
        );
    }

    /// The same unbalanced-conditional shape that makes hiredis's libuv.h a single
    /// ERROR node in C does it in C++ too: a `#if` arm opens a function body, the
    /// `#else` arm opens a second signature, and one brace closes both.
    const UNBALANCED_CONDITIONAL_HEADER: &[u8] = br#"
#ifndef EXAMPLE_EVENTS_H
#define EXAMPLE_EVENTS_H

typedef struct Events { int n; } Events;

#if VERSION_MINOR < 11
static void onTimeout(void *t, int status) {
    (void)status;
#else
static void onTimeout(void *t) {
#endif
    (void)t;
}

static void onCleanup(void *p) { (void)p; }

#endif
"#;

    #[test]
    fn declarations_recovered_from_a_top_level_parse_error_are_kept() {
        let tree = CppAdapter.parse(UNBALANCED_CONDITIONAL_HEADER).unwrap();
        let root = tree.root_node();
        assert_eq!(
            (root.child_count(), root.child(0).map(|node| node.kind())),
            (1, Some("ERROR")),
            "the fixture must reproduce the single top-level ERROR node, or this test \
             proves nothing about error recovery"
        );

        let entities = cpp_entities(UNBALANCED_CONDITIONAL_HEADER, "events.hpp");
        assert!(
            cpp_names_of(&entities, EntityKind::TypeAlias)
                .iter()
                .any(|name| name == "Events"),
            "{:?}",
            cpp_names_of(&entities, EntityKind::TypeAlias)
        );
        assert!(
            cpp_names_of(&entities, EntityKind::Function)
                .iter()
                .any(|name| name == "onCleanup"),
            "{:?}",
            cpp_names_of(&entities, EntityKind::Function)
        );
    }

    #[test]
    fn a_malformed_typedef_yields_no_entity_rather_than_an_empty_name() {
        // Each of these parses with a MISSING, empty type_identifier in the declarator
        // field. Reading it without checking would put an unreachable, empty-named
        // entity in the graph.
        for source in [
            b"typedef struct Foo;".as_slice(),
            b"typedef int;".as_slice(),
            b"typedef struct { int a; };".as_slice(),
        ] {
            let entities = cpp_entities(source, "broken.hpp");
            assert!(
                entities.iter().all(|entity| !entity.name.trim().is_empty()),
                "an empty entity name leaked from {:?}",
                std::str::from_utf8(source).unwrap()
            );
            assert!(
                cpp_names_of(&entities, EntityKind::TypeAlias).is_empty(),
                "a malformed typedef should name nothing, got {:?}",
                cpp_names_of(&entities, EntityKind::TypeAlias)
            );
        }
    }

    #[test]
    fn a_plain_typedef_alias_keeps_its_name() {
        let entities = cpp_entities(b"typedef unsigned long my_size_t;", "t.hpp");
        assert_eq!(
            cpp_names_of(&entities, EntityKind::TypeAlias),
            vec!["my_size_t"]
        );
    }
}

/// Bounded lexical preprocessing before tree-sitter parsing.
///
/// Scope boundary — macro-GENERATED symbols are out of extraction scope:
/// `#define` definitions themselves ARE captured (as `EntityKind::Macro`),
/// and macro invocations are captured as call relations, but code a
/// function-like macro would EXPAND to (X-macros, Qt MOC, Boost.PP,
/// `DEFINE_*` registration patterns) is never expanded here and therefore
/// never becomes entities. Faithful expansion requires the full include
/// graph and compiler flags, which a per-file parse does not have; partial
/// heuristic expansion would fabricate entities at wrong spans. Retrieval
/// consequence: symbols that only exist post-expansion are findable via the
/// macro's definition/invocation sites, not as first-class entities. Only
/// namespace-shaping macros are rewritten below, because they otherwise
/// break the surrounding — real — declarations' extraction.
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
        if p >= 5 && &source[p - 5..p + 1] == b"define" {
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
