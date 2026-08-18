// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::{Node, Tree};

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, FileImport, ImportedName, ParseOutput};

pub struct CSharpAdapter;
pub struct RubyAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::CSharp
    }

    fn file_extensions(&self) -> &[&str] {
        &["cs"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_c_sharp::LANGUAGE)?;
        parser
            .parse(source, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            })
    }

    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput> {
        Ok(extract_csharp_output(tree, source, file_id))
    }
}

impl LanguageAdapter for RubyAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Ruby
    }

    fn file_extensions(&self) -> &[&str] {
        &["rb"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_ruby::LANGUAGE)?;
        parser
            .parse(source, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            })
    }

    fn extract(&self, tree: &Tree, source: &[u8], file_id: &FilePathId) -> Result<ParseOutput> {
        Ok(extract_ruby_output(tree, source, file_id))
    }
}

fn extract_csharp_output(tree: &Tree, source: &[u8], file_id: &FilePathId) -> ParseOutput {
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
        extract_csharp_node(
            &child,
            source,
            file_id,
            None,
            None,
            None,
            &mut entities,
            &mut relations,
            &mut imports,
        );
    }

    annotate_import_sources(&mut relations, &imports);

    ParseOutput {
        entities,
        relations,
        imports,
        tests: Vec::new(),
        parse_state,
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_csharp_node(
    node: &Node,
    source: &[u8],
    file_id: &FilePathId,
    namespace_ctx: Option<&str>,
    type_ctx: Option<&str>,
    callable_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    imports: &mut Vec<FileImport>,
) {
    match node.kind() {
        "compilation_unit" | "declaration_list" | "type_declaration" | "global_statement"
        | "preproc_if" | "preproc_else" | "preproc_elif" => {
            recurse_children(node, source, |child| {
                extract_csharp_node(
                    child,
                    source,
                    file_id,
                    namespace_ctx,
                    type_ctx,
                    callable_ctx,
                    entities,
                    relations,
                    imports,
                );
            });
        }
        "using_directive" => {
            if let Some(import) = extract_csharp_import(node, source) {
                imports.push(import);
            }
        }
        "namespace_declaration" | "file_scoped_namespace_declaration" => {
            if let Some(name) = child_field_text(node, "name", source) {
                let full_name = qualify_container(namespace_ctx, &normalize_scoped_name(&name));
                entities.push(ExtractedEntity {
                    kind: EntityKind::Module,
                    name: full_name.clone(),
                    signature: node_signature(node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                if let Some(parent) = namespace_ctx {
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: parent.to_string(),
                        dst_name: full_name.clone(),
                        import_source: None,
                    });
                }
                if let Some(body) = node.child_by_field_name("body") {
                    let body_name = full_name.clone();
                    recurse_children(&body, source, |child| {
                        extract_csharp_node(
                            child,
                            source,
                            file_id,
                            Some(body_name.as_str()),
                            None,
                            None,
                            entities,
                            relations,
                            imports,
                        );
                    });
                }
            }
        }
        "class_declaration"
        | "struct_declaration"
        | "record_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "delegate_declaration" => {
            if let Some(raw_name) = child_field_text(node, "name", source) {
                let full_name = qualify_container(namespace_ctx, &raw_name);
                let kind = match node.kind() {
                    "interface_declaration" => EntityKind::Interface,
                    "enum_declaration" => EntityKind::EnumDef,
                    "delegate_declaration" => EntityKind::Function,
                    _ => EntityKind::Class,
                };
                entities.push(ExtractedEntity {
                    kind,
                    name: full_name.clone(),
                    signature: node_signature(node, source),
                    visibility: csharp_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                if let Some(parent) = namespace_ctx.or(type_ctx) {
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: parent.to_string(),
                        dst_name: full_name.clone(),
                        import_source: None,
                    });
                }
                if matches!(
                    node.kind(),
                    "class_declaration"
                        | "struct_declaration"
                        | "record_declaration"
                        | "interface_declaration"
                ) {
                    for base in extract_csharp_base_types(node, source) {
                        relations.push(ExtractedRelation {
            site: None,
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::Extends,
                            src_name: full_name.clone(),
                            dst_name: base,
                            import_source: None,
                        });
                    }
                }
                if let Some(body) = node.child_by_field_name("body") {
                    let type_name = full_name.clone();
                    recurse_children(&body, source, |child| {
                        extract_csharp_node(
                            child,
                            source,
                            file_id,
                            namespace_ctx,
                            Some(type_name.as_str()),
                            callable_ctx,
                            entities,
                            relations,
                            imports,
                        );
                    });
                }
            }
        }
        "method_declaration" | "constructor_declaration" | "destructor_declaration" => {
            if let Some(owner) = type_ctx {
                if let Some(raw_name) = child_field_text(node, "name", source) {
                    let full_name = qualify_member(owner, &raw_name);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Method,
                        name: full_name.clone(),
                        signature: node_signature(node, source),
                        visibility: csharp_visibility(node, source),
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: owner.to_string(),
                        dst_name: full_name.clone(),
                        import_source: None,
                    });
                    extract_csharp_calls(node, source, &full_name, relations);
                }
            }
        }
        "property_declaration" => {
            if let Some(owner) = type_ctx {
                if let Some(raw_name) = child_field_text(node, "name", source) {
                    let full_name = qualify_member(owner, &raw_name);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Constant,
                        name: full_name.clone(),
                        signature: node_signature(node, source),
                        visibility: csharp_visibility(node, source),
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: owner.to_string(),
                        dst_name: full_name,
                        import_source: None,
                    });
                }
            }
        }
        "field_declaration" => {
            if let Some(owner) = type_ctx {
                for raw_name in extract_csharp_field_names(node, source) {
                    let full_name = qualify_member(owner, &raw_name);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Constant,
                        name: full_name.clone(),
                        signature: node_signature(node, source),
                        visibility: csharp_visibility(node, source),
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: owner.to_string(),
                        dst_name: full_name,
                        import_source: None,
                    });
                }
            }
        }
        "enum_member_declaration" => {
            if let Some(owner) = type_ctx {
                if let Some(raw_name) = child_field_text(node, "name", source) {
                    let full_name = qualify_member(owner, &raw_name);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Constant,
                        name: full_name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: owner.to_string(),
                        dst_name: full_name,
                        import_source: None,
                    });
                }
            }
        }
        _ => {
            if let Some(ctx) = callable_ctx {
                extract_csharp_calls(node, source, ctx, relations);
            }
        }
    }
}

fn extract_csharp_import(node: &Node, source: &[u8]) -> Option<FileImport> {
    let module_path = child_field_text(node, "name", source).or_else(|| {
        let mut cursor = node.walk();
        let fallback = node.children(&mut cursor).find_map(|child| {
            if child.is_named() {
                child.utf8_text(source).ok().map(|text| text.to_string())
            } else {
                None
            }
        });
        fallback
    })?;
    let module_path = normalize_scoped_name(&module_path);
    let local_name = module_path
        .rsplit('.')
        .next()
        .unwrap_or(module_path.as_str())
        .to_string();
    Some(FileImport {
        module_path,
        specifiers: vec![ImportedName {
            local_name,
            original_name: None,
            is_default: false,
        }],
    })
}

fn extract_csharp_base_types(node: &Node, source: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "base_list" {
            continue;
        }
        let mut base_cursor = child.walk();
        for base in child.children(&mut base_cursor) {
            if !base.is_named() {
                continue;
            }
            let text = base.utf8_text(source).unwrap_or("").trim().to_string();
            if !text.is_empty() {
                result.push(normalize_scoped_name(&text));
            }
        }
    }
    result
}

fn extract_csharp_field_names(node: &Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "variable_declaration" {
            continue;
        }
        let mut var_cursor = child.walk();
        for declarator in child.children(&mut var_cursor) {
            if declarator.kind() != "variable_declarator" {
                continue;
            }
            if let Some(name) = child_field_text(&declarator, "name", source) {
                names.push(name);
            }
        }
    }
    names
}

fn extract_csharp_calls(
    node: &Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    recurse_children(node, source, |child| {
        if child.kind() == "invocation_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                // A member access carries the invoked method in its `name`
                // field, so `obj.Execute()` and `Console.WriteLine(...)` emit
                // the rightmost simple name the name index can match, never
                // the dotted source text.
                let callee = match function.kind() {
                    "member_access_expression" | "member_binding_expression" => function
                        .child_by_field_name("name")
                        .map(|name| text_of(&name, source).trim().to_string())
                        .unwrap_or_default(),
                    _ => normalize_scoped_name(text_of(&function, source).trim()),
                };
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
        } else if child.kind() == "object_creation_expression" {
            if let Some(ty) = child.child_by_field_name("type") {
                let target = normalize_scoped_name(text_of(&ty, source).trim());
                if !target.is_empty() {
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::References,
                        src_name: context_name.to_string(),
                        dst_name: target,
                        import_source: None,
                    });
                }
            }
        } else {
            extract_csharp_calls(child, source, context_name, relations);
        }
    });
}

fn csharp_visibility(node: &Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "modifier" {
            continue;
        }
        let modifier = child.utf8_text(source).unwrap_or("").trim();
        match modifier {
            "public" => return Visibility::Public,
            "private" => return Visibility::Private,
            "internal" | "protected" | "protected_internal" | "private_protected" => {
                return Visibility::Internal;
            }
            _ => {}
        }
    }
    Visibility::Public
}

fn extract_ruby_output(tree: &Tree, source: &[u8], file_id: &FilePathId) -> ParseOutput {
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
        extract_ruby_node(
            &child,
            source,
            file_id,
            None,
            None,
            &mut entities,
            &mut relations,
            &mut imports,
        );
    }

    annotate_import_sources(&mut relations, &imports);

    ParseOutput {
        entities,
        relations,
        imports,
        tests: Vec::new(),
        parse_state,
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_ruby_node(
    node: &Node,
    source: &[u8],
    file_id: &FilePathId,
    container_ctx: Option<&str>,
    callable_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    imports: &mut Vec<FileImport>,
) {
    match node.kind() {
        "program" | "body_statement" | "then" | "else" => {
            recurse_children(node, source, |child| {
                extract_ruby_node(
                    child,
                    source,
                    file_id,
                    container_ctx,
                    callable_ctx,
                    entities,
                    relations,
                    imports,
                );
            });
        }
        "module" | "class" => {
            if let Some(raw_name) = child_field_text(node, "name", source) {
                let cleaned_name = normalize_ruby_name(&raw_name);
                let full_name = qualify_container(container_ctx, &cleaned_name);
                let kind = if node.kind() == "module" {
                    EntityKind::Module
                } else {
                    EntityKind::Class
                };
                entities.push(ExtractedEntity {
                    kind,
                    name: full_name.clone(),
                    signature: node_signature(node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                if let Some(parent) = container_ctx {
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: parent.to_string(),
                        dst_name: full_name.clone(),
                        import_source: None,
                    });
                }
                if node.kind() == "class" {
                    if let Some(superclass) = node.child_by_field_name("superclass") {
                        let base_name = normalize_ruby_name(text_of(&superclass, source).trim());
                        if !base_name.is_empty() {
                            relations.push(ExtractedRelation {
            site: None,
                                receiver: None,
                                call_shape: None,
                                kind: kin_model::RelationKind::Extends,
                                src_name: full_name.clone(),
                                dst_name: base_name,
                                import_source: None,
                            });
                        }
                    }
                }
                if let Some(body) = node.child_by_field_name("body") {
                    let next_ctx = full_name.clone();
                    recurse_children(&body, source, |child| {
                        extract_ruby_node(
                            child,
                            source,
                            file_id,
                            Some(next_ctx.as_str()),
                            None,
                            entities,
                            relations,
                            imports,
                        );
                    });
                }
            }
        }
        "method" | "singleton_method" => {
            if let Some(raw_name) = child_field_text(node, "name", source) {
                let owner = if node.kind() == "singleton_method" {
                    child_field_text(node, "object", source)
                        .map(|value| normalize_ruby_name(&value))
                        .or_else(|| container_ctx.map(|value| value.to_string()))
                } else {
                    container_ctx.map(|value| value.to_string())
                };
                let full_name = owner
                    .as_deref()
                    .map(|scope| qualify_member(scope, &raw_name))
                    .unwrap_or(raw_name.clone());
                entities.push(ExtractedEntity {
                    kind: if owner.is_some() {
                        EntityKind::Method
                    } else {
                        EntityKind::Function
                    },
                    name: full_name.clone(),
                    signature: node_signature(node, source),
                    visibility: ruby_visibility(&raw_name),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                if let Some(owner_name) = owner {
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: owner_name,
                        dst_name: full_name.clone(),
                        import_source: None,
                    });
                }
                if let Some(body) = node.child_by_field_name("body") {
                    let callable_name = full_name.clone();
                    extract_ruby_node(
                        &body,
                        source,
                        file_id,
                        container_ctx,
                        Some(callable_name.as_str()),
                        entities,
                        relations,
                        imports,
                    );
                }
            }
        }
        "assignment" | "operator_assignment" => {
            if let Some(raw_name) = child_field_text(node, "left", source) {
                if looks_like_ruby_constant_name(raw_name.trim()) {
                    let cleaned_name = normalize_ruby_name(raw_name.trim());
                    let full_name = qualify_container(container_ctx, &cleaned_name);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Constant,
                        name: full_name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                    if let Some(owner) = container_ctx {
                        relations.push(ExtractedRelation {
            site: None,
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::Contains,
                            src_name: owner.to_string(),
                            dst_name: full_name,
                            import_source: None,
                        });
                    }
                }
            }
        }
        "call" => {
            if let Some(method_name) = child_field_text(node, "method", source) {
                let method_name = method_name.trim().to_string();
                if method_name == "require" || method_name == "require_relative" {
                    if let Some(import) = extract_ruby_require(node, source) {
                        imports.push(import);
                    }
                } else if (method_name == "include"
                    || method_name == "extend"
                    || method_name == "prepend")
                    && callable_ctx.is_none()
                {
                    if let Some(target) = extract_ruby_first_argument(node, source) {
                        if let Some(owner) = container_ctx {
                            relations.push(ExtractedRelation {
            site: None,
                                receiver: None,
                                call_shape: None,
                                kind: kin_model::RelationKind::References,
                                src_name: owner.to_string(),
                                dst_name: normalize_ruby_name(target.trim()),
                                import_source: None,
                            });
                        }
                    }
                } else if let Some(current_callable) = callable_ctx {
                    relations.push(ExtractedRelation {
            site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: current_callable.to_string(),
                        dst_name: normalize_ruby_name(&method_name),
                        import_source: None,
                    });
                }
            }
            recurse_children(node, source, |child| {
                extract_ruby_node(
                    child,
                    source,
                    file_id,
                    container_ctx,
                    callable_ctx,
                    entities,
                    relations,
                    imports,
                );
            });
        }
        _ => {
            recurse_children(node, source, |child| {
                extract_ruby_node(
                    child,
                    source,
                    file_id,
                    container_ctx,
                    callable_ctx,
                    entities,
                    relations,
                    imports,
                );
            });
        }
    }
}

fn extract_ruby_require(node: &Node, source: &[u8]) -> Option<FileImport> {
    let module_path = extract_ruby_first_argument(node, source)?;
    let trimmed = trim_wrapping_quotes(module_path.trim());
    if trimmed.is_empty() {
        return None;
    }
    let local_name = trimmed
        .rsplit('/')
        .next()
        .unwrap_or(trimmed)
        .rsplit("::")
        .next()
        .unwrap_or(trimmed)
        .to_string();
    Some(FileImport {
        module_path: trimmed.to_string(),
        specifiers: vec![ImportedName {
            local_name,
            original_name: None,
            is_default: false,
        }],
    })
}

fn extract_ruby_first_argument<'a>(node: &Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    for child in arguments.children(&mut cursor) {
        if child.is_named() {
            return child.utf8_text(source).ok();
        }
    }
    None
}

fn annotate_import_sources(relations: &mut [ExtractedRelation], imports: &[FileImport]) {
    let import_map: std::collections::HashMap<&str, &str> = imports
        .iter()
        .flat_map(|imp| {
            imp.specifiers
                .iter()
                .map(move |spec| (spec.local_name.as_str(), imp.module_path.as_str()))
        })
        .collect();

    for relation in relations {
        if !matches!(
            relation.kind,
            kin_model::RelationKind::Calls | kin_model::RelationKind::References
        ) {
            continue;
        }
        if let Some(&module) = import_map.get(relation.dst_name.as_str()) {
            relation.import_source = Some(module.to_string());
            continue;
        }
        if let Some(first_segment) = relation
            .dst_name
            .split(['.', ':'])
            .find(|segment| !segment.is_empty())
        {
            if let Some(&module) = import_map.get(first_segment) {
                relation.import_source = Some(module.to_string());
            }
        }
    }
}

fn recurse_children(node: &Node, source: &[u8], mut f: impl FnMut(&Node)) {
    let _ = source;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            f(&child);
        }
    }
}

fn child_field_text(node: &Node, field: &str, source: &[u8]) -> Option<String> {
    node.child_by_field_name(field)
        .and_then(|child| child.utf8_text(source).ok().map(|text| text.to_string()))
}

fn text_of<'a>(node: &Node<'a>, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}

fn qualify_container(prefix: Option<&str>, name: &str) -> String {
    if let Some(prefix) = prefix {
        format!("{prefix}.{name}")
    } else {
        name.to_string()
    }
}

fn qualify_member(owner: &str, name: &str) -> String {
    format!("{owner}.{name}")
}

fn normalize_scoped_name(value: &str) -> String {
    value.trim().replace("::", ".")
}

fn normalize_ruby_name(value: &str) -> String {
    value.trim().replace("::", ".")
}

fn trim_wrapping_quotes(value: &str) -> &str {
    value.trim().trim_matches(|ch| ch == '"' || ch == '\'')
}

fn looks_like_ruby_constant_name(name: &str) -> bool {
    let base = name.rsplit("::").next().unwrap_or(name);
    base.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
}

fn ruby_visibility(name: &str) -> Visibility {
    if name.starts_with('_') {
        Visibility::Private
    } else {
        Visibility::Public
    }
}

fn node_signature(node: &Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_preceding_comment(node: &Node, source: &[u8]) -> Option<String> {
    let prev = node.prev_sibling()?;
    if !matches!(prev.kind(), "comment" | "line_comment" | "block_comment") {
        return None;
    }
    let text = prev.utf8_text(source).ok()?;
    let cleaned = text
        .lines()
        .map(|line| {
            line.trim()
                .trim_start_matches('#')
                .trim_start_matches('/')
                .trim_start_matches('*')
                .trim_end_matches('*')
                .trim_end_matches('/')
                .trim()
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_output<A: LanguageAdapter>(adapter: &A, file: &str, source: &[u8]) -> ParseOutput {
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new(file);
        adapter.extract(&tree, source, &file_id).unwrap()
    }

    #[test]
    fn parse_csharp_extracts_class_methods_and_imports() {
        let output = parse_output(
            &CSharpAdapter,
            "Basic.cs",
            b"using System;\nnamespace Demo { public interface IGreeter { string SayHi(); } public class Greeter : IGreeter { public string Name { get; } public Greeter(string name) { Name = name; } public string SayHi() { HelperInternal(); Console.WriteLine(Name); return Name; } private static int HelperInternal() { return 42; } } }\n",
        );

        let names = output
            .entities
            .iter()
            .map(|entity| entity.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"Demo"));
        assert!(names.contains(&"Demo.IGreeter"));
        assert!(names.contains(&"Demo.Greeter"));
        assert!(names.contains(&"Demo.Greeter.SayHi"));
        assert!(names.contains(&"Demo.Greeter.HelperInternal"));
        assert!(names.contains(&"Demo.Greeter.Name"));

        assert!(output.imports.iter().any(|imp| imp.module_path == "System"));
        assert!(output.relations.iter().any(|rel| {
            rel.kind == kin_model::RelationKind::Extends
                && rel.src_name == "Demo.Greeter"
                && rel.dst_name == "IGreeter"
        }));
        assert!(output.relations.iter().any(|rel| {
            rel.kind == kin_model::RelationKind::Contains
                && rel.src_name == "Demo.Greeter"
                && rel.dst_name == "Demo.Greeter.SayHi"
        }));
        assert!(output.relations.iter().any(|rel| {
            rel.kind == kin_model::RelationKind::Calls
                && rel.src_name == "Demo.Greeter.SayHi"
                && rel.dst_name == "HelperInternal"
        }));
    }

    #[test]
    fn parse_ruby_extracts_modules_constants_requires_and_calls() {
        let output = parse_output(
            &RubyAdapter,
            "service.rb",
            b"require 'json'\nmodule Services\n  class UserService\n    DEFAULT_ROLE = 'member'\n    def display_name(name)\n      helper_internal(name)\n    end\n  end\nend\n\ndef helper_internal(name)\n  JSON.generate(name: name)\nend\n",
        );

        let names = output
            .entities
            .iter()
            .map(|entity| entity.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"Services"));
        assert!(names.contains(&"Services.UserService"));
        assert!(names.contains(&"Services.UserService.DEFAULT_ROLE"));
        assert!(names.contains(&"Services.UserService.display_name"));
        assert!(names.contains(&"helper_internal"));
        assert!(output.imports.iter().any(|imp| imp.module_path == "json"));
        assert!(output.relations.iter().any(|rel| {
            rel.kind == kin_model::RelationKind::Contains
                && rel.src_name == "Services.UserService"
                && rel.dst_name == "Services.UserService.display_name"
        }));
        assert!(output.relations.iter().any(|rel| {
            rel.kind == kin_model::RelationKind::Calls
                && rel.src_name == "Services.UserService.display_name"
                && rel.dst_name == "helper_internal"
        }));
    }
}
