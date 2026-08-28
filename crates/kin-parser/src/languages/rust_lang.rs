// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, EditHint,
    LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    ExtractedEntity, ExtractedRelation, ExtractedTest, ExtractedTestKind, FileImport, ImportedName,
    ParseOutput,
};

pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Rust
    }

    fn file_extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_rust::LANGUAGE)?;
        parser
            .parse(source, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "tree-sitter returned None".into(),
            })
    }

    fn parse_incremental(&self, source: &[u8], old_tree: &Tree, edit: &EditHint) -> Result<Tree> {
        let mut tree = old_tree.clone();
        tree.edit(&tree_sitter::InputEdit {
            start_byte: edit.start_byte,
            old_end_byte: edit.old_end_byte,
            new_end_byte: edit.new_end_byte,
            start_position: tree_sitter::Point { row: 0, column: 0 },
            old_end_position: tree_sitter::Point { row: 0, column: 0 },
            new_end_position: tree_sitter::Point { row: 0, column: 0 },
        });
        let mut parser = make_parser(&tree_sitter_rust::LANGUAGE)?;
        parser
            .parse(source, Some(&tree))
            .ok_or_else(|| crate::error::ParseError::ParseFailed {
                file: String::new(),
                reason: "incremental parse failed".into(),
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
            extract_rust_node(&child, source, file_id, &mut entities, &mut relations);
            if child.kind() == "use_declaration" {
                if let Some(import) = extract_rust_use(&child, source) {
                    imports.push(import);
                }
            }
            // Detect #[test] functions
            if child.kind() == "function_item" && has_test_attribute(&child, source) {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    tests.push(ExtractedTest {
                        name,
                        kind: ExtractedTestKind::Unit,
                        runner: "cargo".to_string(),
                    });
                }
            }
            // Detect #[test] methods inside impl blocks and mod tests
            extract_rust_tests_from_block(&child, source, &mut tests);
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
            parsed_call_sites: None,
        })
    }
}

fn extract_rust_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                extract_calls_from_context(node, source, &name, None, relations);
            }
        }
        "struct_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                // Emit Implements relations for #[derive(...)] traits.
                for trait_name in extract_derive_traits(node, source) {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Implements,
                        src_name: name.clone(),
                        dst_name: trait_name,
                        import_source: None,
                    });
                }
            }
        }
        "enum_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let enum_name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::EnumDef,
                    name: enum_name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Emit Implements relations for #[derive(...)] traits.
                for trait_name in extract_derive_traits(node, source) {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Implements,
                        src_name: enum_name.clone(),
                        dst_name: trait_name,
                        import_source: None,
                    });
                }

                // Extract individual enum variants as EnumVariant entities.
                if let Some(body) = node.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for variant in body.children(&mut body_cursor) {
                        if variant.kind() == "enum_variant" {
                            if let Some(vname) = variant.child_by_field_name("name") {
                                let variant_name =
                                    vname.utf8_text(source).unwrap_or("").to_string();
                                let qualified = format!("{}::{}", enum_name, variant_name);
                                entities.push(ExtractedEntity {
                                    kind: EntityKind::EnumVariant,
                                    name: qualified.clone(),
                                    signature: node_signature(&variant, source),
                                    visibility: detect_rust_visibility(node, source),
                                    doc_summary: None,
                                    fingerprint: compute_fingerprint(&variant, source),
                                    span: span_from_node(&variant, file_id),
                                });
                                relations.push(ExtractedRelation {
                                    site: None,
                                    receiver: None,
                                    call_shape: None,
                                    kind: kin_model::RelationKind::Contains,
                                    src_name: enum_name.clone(),
                                    dst_name: qualified,
                                    import_source: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        "trait_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::TraitDef,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "type_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::TypeAlias,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "const_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Constant,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "static_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::StaticVar,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "impl_item" => {
            // Extract methods from impl blocks
            let type_name = node
                .child_by_field_name("type")
                .map(|t| t.utf8_text(source).unwrap_or("").to_string())
                .unwrap_or_default();

            // Check for trait impl
            let trait_name = node
                .child_by_field_name("trait")
                .map(|t| t.utf8_text(source).unwrap_or("").to_string());

            if let Some(ref trait_n) = trait_name {
                if !trait_n.is_empty() && !type_name.is_empty() {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Implements,
                        src_name: type_name.clone(),
                        dst_name: trait_n.clone(),
                        import_source: None,
                    });
                }
            }

            if let Some(body) = node.child_by_field_name("body") {
                let mut body_cursor = body.walk();
                for member in body.children(&mut body_cursor) {
                    if member.kind() == "function_item" {
                        if let Some(name_node) = member.child_by_field_name("name") {
                            let method_name = name_node.utf8_text(source).unwrap_or("").to_string();
                            let qualified = if type_name.is_empty() {
                                method_name
                            } else {
                                format!("{}::{}", type_name, method_name)
                            };
                            entities.push(ExtractedEntity {
                                kind: EntityKind::Method,
                                name: qualified.clone(),
                                signature: node_signature(&member, source),
                                visibility: detect_rust_visibility(&member, source),
                                doc_summary: extract_doc_comment(&member, source),
                                fingerprint: compute_fingerprint(&member, source),
                                span: span_from_node(&member, file_id),
                            });
                            extract_calls_from_context(
                                &member,
                                source,
                                &qualified,
                                (!type_name.is_empty()).then_some(type_name.as_str()),
                                relations,
                            );
                            // A method declared in `impl Trait for Type` satisfies
                            // the trait's contract, so a caller holding the trait
                            // reaches it without any edge naming the method. Only
                            // the implementing type carried that fact before, which
                            // left no way to tell a trait method apart from an
                            // inherent one that nothing calls.
                            if let Some(ref trait_n) = trait_name {
                                if !trait_n.is_empty() {
                                    relations.push(ExtractedRelation {
                                        site: None,
                                        receiver: None,
                                        call_shape: None,
                                        kind: kin_model::RelationKind::Implements,
                                        src_name: qualified.clone(),
                                        dst_name: trait_n.clone(),
                                        import_source: None,
                                    });
                                }
                            }
                            if !type_name.is_empty() {
                                relations.push(ExtractedRelation {
                                    site: None,
                                    receiver: None,
                                    call_shape: None,
                                    kind: kin_model::RelationKind::Contains,
                                    src_name: type_name.clone(),
                                    dst_name: qualified,
                                    import_source: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        "mod_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Module,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_rust_visibility(node, source),
                    doc_summary: extract_doc_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
            // Descend into an inline module body so functions, impls, and nested
            // modules declared inside `mod m { ... }` are extracted with their own
            // entities and call edges. Without this, everything below a module is
            // dropped, and calls made from module-scoped functions never reach
            // refs/impact — attribution effectively collapses onto the file/module
            // instead of the innermost enclosing function. `mod m;` (no body) has
            // nothing to descend into.
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for child in body.children(&mut cursor) {
                    extract_rust_node(&child, source, file_id, entities, relations);
                }
            }
        }
        "macro_definition" => {
            // `macro_rules! name { ... }`. The declarative-macro definition is a
            // first-class symbol; capturing it keeps the macro name graph-visible
            // so lookups resolve at ingestion rather than missing silently. The
            // rule bodies are intentionally not expanded (expansion would fabricate
            // entities at synthetic spans), mirroring the C/C++ macro boundary.
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    let visibility = if has_macro_export(node, source) {
                        Visibility::Public
                    } else {
                        detect_rust_visibility(node, source)
                    };
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Macro,
                        name,
                        signature: node_signature(node, source),
                        visibility,
                        doc_summary: extract_doc_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                    });
                }
            }
        }
        "use_declaration" => {}
        _ => {}
    }
}

/// Extract trait names from `#[derive(Trait1, Trait2)]` attributes preceding
/// a struct or enum. Returns a list of trait name strings.
fn extract_derive_traits(node: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut traits = Vec::new();
    // Check preceding attribute_item siblings
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "attribute_item" {
            let text = p.utf8_text(source).unwrap_or("");
            // Match #[derive(Trait1, Trait2, ...)]
            if let Some(start) = text.find("derive(") {
                let after = &text[start + 7..];
                if let Some(end) = after.find(')') {
                    let inner = &after[..end];
                    for t in inner.split(',') {
                        let t = t.trim();
                        if !t.is_empty() {
                            traits.push(t.to_string());
                        }
                    }
                }
            }
        } else {
            break;
        }
        prev = p.prev_sibling();
    }
    // Also check child attributes (tree-sitter sometimes nests them)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "attribute_item" {
            let text = child.utf8_text(source).unwrap_or("");
            if let Some(start) = text.find("derive(") {
                let after = &text[start + 7..];
                if let Some(end) = after.find(')') {
                    let inner = &after[..end];
                    for t in inner.split(',') {
                        let t = t.trim();
                        if !t.is_empty() {
                            traits.push(t.to_string());
                        }
                    }
                }
            }
        }
    }
    traits
}

fn detect_rust_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            let text = child.utf8_text(source).unwrap_or("");
            if text.contains("pub(crate)") {
                return Visibility::Crate;
            } else if text.contains("pub(super)") || text.contains("pub(in") {
                return Visibility::Internal;
            } else if text == "pub" {
                return Visibility::Public;
            }
        }
    }
    Visibility::Private
}

/// Detect a `#[macro_export]` attribute preceding a `macro_rules!` definition.
/// An exported macro is crate-public regardless of its module position, whereas
/// an unexported `macro_rules!` is module-local (Private).
fn has_macro_export(node: &tree_sitter::Node, source: &[u8]) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => {
                if p.utf8_text(source).unwrap_or("").contains("macro_export") {
                    return true;
                }
            }
            // Doc comments may sit between the attribute and the macro; skip them.
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        prev = p.prev_sibling();
    }
    false
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_doc_comment(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Collect preceding line_comment nodes that start with ///
    let mut comments = Vec::new();
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "line_comment" {
            let text = p.utf8_text(source).unwrap_or("");
            if text.starts_with("///") {
                comments.push(text.trim_start_matches('/').trim().to_string());
            } else {
                break;
            }
        } else {
            break;
        }
        prev = p.prev_sibling();
    }
    if comments.is_empty() {
        None
    } else {
        comments.reverse();
        Some(comments.join(" "))
    }
}

/// Extract all function/method calls within a function body.
fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    owner: Option<&str>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            // The callee is the `function` field
            if let Some(function) = child.child_by_field_name("function") {
                let (callee_name, receiver) = rust_callee_and_receiver(&function, source, owner);
                if is_valid_callee_name(&callee_name) {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver,
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                        import_source: None,
                    });
                }
            }
        } else if child.kind() == "macro_invocation" {
            // Macro arguments are token soup: tree-sitter does not parse
            // expressions inside token trees, so `format!("{}", total(x))`
            // carries no call_expression node for `total(x)`. Without this,
            // calls made inside format!/println!/assert!-style invocations
            // never become graph relations and downstream consumers vanish
            // from cross-file adjacency. Reconstruct call-shaped token runs
            // from the delimited token tree instead.
            let mut macro_cursor = child.walk();
            for macro_child in child.children(&mut macro_cursor) {
                if macro_child.kind() == "token_tree" {
                    extract_calls_from_token_tree(
                        &macro_child,
                        source,
                        context_name,
                        owner,
                        relations,
                    );
                }
            }
        }
        // Recurse into child nodes
        extract_calls_from_context(&child, source, context_name, owner, relations);
    }
}

/// Extract call-shaped token runs from a macro-invocation token tree.
///
/// Inside a token tree an invocation like `billing::compute_total(amount)`
/// is a flat token run: `identifier ("::" identifier)*` followed by a
/// parenthesized `token_tree`. Treat that shape as a call, mirroring the
/// `call_expression` extraction rules:
/// - method calls (`x.method(..)`) collapse to the bare method name, exactly
///   like the `field_expression` arm above;
/// - qualified paths keep their `a::b` text, exactly like scoped callees;
/// - `name!(..)` runs are nested macro uses, not calls (the identifier is
///   followed by `!`, never directly by the token tree);
/// - bracket/brace groups (`v[i]`, `S { .. }`) are not argument lists.
///
/// Nested token trees are scanned recursively so calls inside argument lists
/// and nested macro bodies are also captured.
fn extract_calls_from_token_tree(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    owner: Option<&str>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    let tokens: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();

    for (index, token) in tokens.iter().enumerate() {
        if token.kind() == "token_tree" {
            extract_calls_from_token_tree(token, source, context_name, owner, relations);
            continue;
        }
        if token.kind() != "identifier" {
            continue;
        }
        // A call needs a parenthesized group immediately after the name.
        let Some(next) = tokens.get(index + 1) else {
            continue;
        };
        if next.kind() != "token_tree" || next.child(0).map(|open| open.kind()) != Some("(") {
            continue;
        }
        // `x.method(..)`: bare method name, matching the field_expression arm.
        // The token before the dot is the receiver, so a macro-body dispatch
        // carries the same receiver evidence a `call_expression` one does. With
        // no such token there is nothing to attribute the call to, and recording
        // it receiverless would present a dispatch as a bare call.
        let is_method_call = index > 0 && tokens[index - 1].kind() == ".";
        let receiver = if is_method_call {
            let Some(receiver_token) = index.checked_sub(2).and_then(|at| tokens.get(at)) else {
                continue;
            };
            Some(receiver_token.utf8_text(source).unwrap_or("").to_string())
        } else {
            None
        };
        let mut callee_name = token.utf8_text(source).unwrap_or("").to_string();
        if !is_method_call {
            // Reconstruct a leading `a::b::` path so qualified callees keep
            // the same shape the call_expression arm extracts.
            let mut start = index;
            while start >= 2
                && tokens[start - 1].kind() == "::"
                && tokens[start - 2].kind() == "identifier"
            {
                start -= 2;
                callee_name = format!(
                    "{}::{}",
                    tokens[start].utf8_text(source).unwrap_or(""),
                    callee_name
                );
            }
        }
        let (callee_name, receiver) = fold_settled_rust_receiver(callee_name, receiver, owner);
        if is_valid_callee_name(&callee_name) {
            relations.push(ExtractedRelation {
                site: None,
                receiver,
                call_shape: None,
                kind: kin_model::RelationKind::Calls,
                src_name: context_name.to_string(),
                dst_name: callee_name,
                import_source: None,
            });
        }
    }
}

/// The callee name and receiver one Rust call site records.
///
/// A method reached through an object keeps its bare leaf and carries the
/// receiver as written, which is what lets the linker tell a dispatch from a
/// free-function call: without it, `builder.multi_line(..)` and a module-level
/// `multi_line(..)` are the same relation, and every same-named method in the
/// repository is an equally good answer.
///
/// A receiver the syntax settles is folded into the callee instead. Inside
/// `impl Type`, `self.m()` and `Self::m()` can only reach `Type`'s own `m`, and
/// `Type::m` is the exact key the method entity is stored under, so the call
/// resolves to that definition rather than fanning out by name. `self.field.m()`
/// is deliberately not folded: it dispatches on the field's type, which the
/// syntax does not settle.
fn rust_callee_and_receiver(
    function: &tree_sitter::Node,
    source: &[u8],
    owner: Option<&str>,
) -> (String, Option<String>) {
    if function.kind() == "field_expression" {
        let method = function
            .child_by_field_name("field")
            .map(|field| field.utf8_text(source).unwrap_or("").to_string())
            .unwrap_or_default();
        let receiver = function
            .child_by_field_name("value")
            .map(|value| value.utf8_text(source).unwrap_or("").to_string());
        return fold_settled_rust_receiver(method, receiver, owner);
    }
    let name = function.utf8_text(source).unwrap_or("").to_string();
    (fold_self_path(name, owner), None)
}

/// Fold a `self.m()` receiver into `Owner::m`, or keep the receiver as written.
///
/// Shared by the `call_expression` and macro-token-tree extraction paths so a
/// call inside `assert!(..)` records the same shape as the identical call
/// outside it.
fn fold_settled_rust_receiver(
    method: String,
    receiver: Option<String>,
    owner: Option<&str>,
) -> (String, Option<String>) {
    match (owner, receiver.as_deref()) {
        (Some(owner), Some("self")) if !method.is_empty() => (format!("{owner}::{method}"), None),
        _ => (method, receiver.filter(|value| !value.is_empty())),
    }
}

/// Rewrite a `Self::m` path callee as `Owner::m`.
///
/// `Self` names the impl's own type, so the call reaches that type's method and
/// nothing else. Left alone outside an impl, and for every other path.
fn fold_self_path(name: String, owner: Option<&str>) -> String {
    let Some(owner) = owner else {
        return name;
    };
    match name.strip_prefix("Self::") {
        Some(rest) if !rest.is_empty() => format!("{owner}::{rest}"),
        _ => name,
    }
}

/// Check if a callee name is valid (not a literal, not empty).
fn is_valid_callee_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.chars().all(|c| c.is_numeric())
}

/// Extract a `use` declaration into a `FileImport`.
fn extract_rust_use(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    // Walk direct children of use_declaration to find the argument
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "scoped_identifier" => {
                // use foo::bar;
                return extract_scoped_identifier_import(&child, source);
            }
            "use_as_clause" => {
                // use foo::bar as baz;
                return extract_use_as_clause_import(&child, source);
            }
            "scoped_use_list" => {
                // use foo::{bar, baz};
                return extract_scoped_use_list_import(&child, source);
            }
            "use_wildcard" => {
                // `use foo::*;` binds every public name in `foo`, and none of
                // them is written here. Recording the module with no specifier
                // is what tells a consumer this file's import list cannot answer
                // "does this file bind that name", the same shape the Python
                // adapter records `from foo import *` as. Dropping the import
                // entirely would leave the file looking name-complete.
                let module_path = child
                    .children(&mut child.walk())
                    .find(|node| {
                        matches!(node.kind(), "scoped_identifier" | "identifier" | "crate")
                    })
                    .map(|node| node.utf8_text(source).unwrap_or("").to_string())
                    .unwrap_or_default();
                return Some(FileImport {
                    site: crate::adapter::site_from_node(node),
                    module_path,
                    specifiers: Vec::new(),
                });
            }
            "identifier" => {
                // use foo;
                let name = child.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    return Some(FileImport {
                        site: crate::adapter::site_from_node(node),
                        module_path: String::new(),
                        specifiers: vec![ImportedName {
                            local_name: name,
                            original_name: None,
                            is_default: false,
                        }],
                    });
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract import from `use foo::bar;` (scoped_identifier).
fn extract_scoped_identifier_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let path_node = node.child_by_field_name("path")?;
    let name_node = node.child_by_field_name("name")?;
    let module_path = path_node.utf8_text(source).unwrap_or("").to_string();
    let local_name = name_node.utf8_text(source).unwrap_or("").to_string();
    if local_name.is_empty() {
        return None;
    }
    Some(FileImport {
        site: crate::adapter::site_from_node(node),
        module_path,
        specifiers: vec![ImportedName {
            local_name,
            original_name: None,
            is_default: false,
        }],
    })
}

/// Extract import from `use foo::bar as baz;` (use_as_clause).
fn extract_use_as_clause_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let path_node = node.child_by_field_name("path")?;
    let alias_node = node.child_by_field_name("alias")?;

    let full_path = path_node.utf8_text(source).unwrap_or("").to_string();
    let alias = alias_node.utf8_text(source).unwrap_or("").to_string();

    // path_node is a scoped_identifier like foo::bar; split into module + name
    let (module_path, original_name) = if let Some(pos) = full_path.rfind("::") {
        (
            full_path[..pos].to_string(),
            full_path[pos + 2..].to_string(),
        )
    } else {
        (String::new(), full_path)
    };

    if alias.is_empty() {
        return None;
    }

    Some(FileImport {
        site: crate::adapter::site_from_node(node),
        module_path,
        specifiers: vec![ImportedName {
            local_name: alias,
            original_name: Some(original_name),
            is_default: false,
        }],
    })
}

/// Extract import from `use foo::{bar, baz};` (scoped_use_list).
fn extract_scoped_use_list_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let path_node = node.child_by_field_name("path")?;
    let list_node = node.child_by_field_name("list")?;
    let module_path = path_node.utf8_text(source).unwrap_or("").to_string();

    let mut specifiers = Vec::new();
    let mut cursor = list_node.walk();
    for child in list_node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let name = child.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    specifiers.push(ImportedName {
                        local_name: name,
                        original_name: None,
                        is_default: false,
                    });
                }
            }
            "scoped_identifier" => {
                // Nested path like `use std::io::{self, Read}` — the `self` case
                // or `use foo::{bar::Baz}`
                let name = child.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    specifiers.push(ImportedName {
                        local_name: name,
                        original_name: None,
                        is_default: false,
                    });
                }
            }
            "use_as_clause" => {
                if let Some(path) = child.child_by_field_name("path") {
                    if let Some(alias) = child.child_by_field_name("alias") {
                        let orig = path.utf8_text(source).unwrap_or("").to_string();
                        let local = alias.utf8_text(source).unwrap_or("").to_string();
                        if !local.is_empty() {
                            specifiers.push(ImportedName {
                                local_name: local,
                                original_name: Some(orig),
                                is_default: false,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if module_path.is_empty() && specifiers.is_empty() {
        return None;
    }

    Some(FileImport {
        site: crate::adapter::site_from_node(node),
        module_path,
        specifiers,
    })
}

/// Check if a function node has a `#[test]` attribute.
fn has_test_attribute(node: &tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "attribute_item" {
            let text = child.utf8_text(source).unwrap_or("");
            if text.contains("test") {
                return true;
            }
        }
    }
    // Also check preceding sibling attributes
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.kind() == "attribute_item" {
            let text = p.utf8_text(source).unwrap_or("");
            if text.contains("test") {
                return true;
            }
        } else {
            break;
        }
        prev = p.prev_sibling();
    }
    false
}

/// Recursively extract test functions from mod blocks and impl blocks.
fn extract_rust_tests_from_block(
    node: &tree_sitter::Node,
    source: &[u8],
    tests: &mut Vec<ExtractedTest>,
) {
    if node.kind() == "mod_item" {
        if let Some(body) = node.child_by_field_name("body") {
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                if child.kind() == "function_item" && has_test_attribute(&child, source) {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        tests.push(ExtractedTest {
                            name,
                            kind: ExtractedTestKind::Unit,
                            runner: "cargo".to_string(),
                        });
                    }
                }
                extract_rust_tests_from_block(&child, source, tests);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_macro_rules_definition_as_macro_entity() {
        // A `macro_rules!` definition is a first-class declarative-macro symbol.
        // Without an extraction arm for it the macro name is invisible to the
        // graph, so a query for the macro misses at ingestion time, not ranking.
        let adapter = RustAdapter;
        let source = br#"
macro_rules! assemble_widget {
    ($n:expr) => { $n + 1 };
    ($a:expr, $b:expr) => { $a + $b };
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("src/widget.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macros: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Macro)
            .collect();
        assert_eq!(
            macros.len(),
            1,
            "macro_rules! definition should yield exactly one Macro entity, got {:?}",
            output
                .entities
                .iter()
                .map(|e| (&e.kind, &e.name))
                .collect::<Vec<_>>()
        );
        assert_eq!(macros[0].name, "assemble_widget");
        assert!(
            macros[0].signature.contains("assemble_widget"),
            "signature should carry the macro name, got {:?}",
            macros[0].signature
        );
    }

    #[test]
    fn extracts_calls_inside_macro_token_trees() {
        // Macro arguments are token trees, not parsed expressions: without
        // token-run reconstruction, a consumer calling through `format!` has
        // no Calls edge and disappears from cross-file impact entirely.
        let adapter = RustAdapter;
        let source = br#"
pub fn render_invoice(amount: u64) -> String {
    format!("total: {}", compute_total(amount))
}

fn callers() {
    assert_eq!(outer(inner(1)), billing::qualified(2));
    println!("{}", target.method(3));
    let v = vec![element(4)];
    log!("{}", matches!(v, _));
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("src/invoice.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();

        // The cross-file consumer edge the shadow gate depends on.
        assert!(
            calls.contains(&("render_invoice", "compute_total")),
            "call inside format! must be extracted, got {calls:?}"
        );
        // Nested argument-list calls, qualified paths, method calls, and
        // bracket-delimited macro bodies are all reconstructed.
        for expected in [
            ("callers", "outer"),
            ("callers", "inner"),
            ("callers", "billing::qualified"),
            ("callers", "method"),
            ("callers", "element"),
        ] {
            assert!(
                calls.contains(&expected),
                "expected {expected:?} in {calls:?}"
            );
        }
        // `matches!` is a nested macro use inside the token tree, not a call.
        assert!(
            !calls.iter().any(|(_, dst)| *dst == "matches"),
            "nested macro names must not become Calls edges, got {calls:?}"
        );
    }

    #[test]
    fn plain_macro_rules_is_module_private() {
        let adapter = RustAdapter;
        let source = b"macro_rules! internal_only { () => {}; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("src/lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let m = output
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Macro && e.name == "internal_only")
            .expect("macro_rules! should be extracted as a Macro entity");
        assert_eq!(
            m.visibility,
            Visibility::Private,
            "a macro_rules! without #[macro_export] is module-local"
        );
    }

    #[test]
    fn macro_export_promotes_macro_to_public() {
        let adapter = RustAdapter;
        let source = br#"
#[macro_export]
macro_rules! public_api {
    () => {};
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("src/lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let m = output
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Macro && e.name == "public_api")
            .expect("exported macro should be extracted");
        assert_eq!(
            m.visibility,
            Visibility::Public,
            "#[macro_export] promotes a macro to crate-public visibility"
        );
    }

    #[test]
    fn parse_rust_function() {
        let adapter = RustAdapter;
        let source = b"pub fn add(a: i32, b: i32) -> i32 { a + b }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
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
    fn parse_rust_struct_and_impl() {
        let adapter = RustAdapter;
        let source = br#"
pub struct Dog {
    name: String,
}

impl Dog {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub fn bark(&self) -> &str {
        "woof"
    }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("dog.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Dog");

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn parse_rust_trait() {
        let adapter = RustAdapter;
        let source = b"pub trait Animal { fn speak(&self) -> String; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("traits.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let traits: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::TraitDef)
            .collect();
        assert_eq!(traits.len(), 1);
        assert_eq!(traits[0].name, "Animal");
    }

    #[test]
    fn parse_rust_enum() {
        let adapter = RustAdapter;
        let source = b"pub enum Color { Red, Green, Blue }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("color.rs");
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
    fn parse_rust_function_calls() {
        let adapter = RustAdapter;
        let source = br#"
fn process(data: &str) -> String {
    let result = parse(data);
    helper::transform(result)
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .collect();
        assert!(!calls.is_empty(), "should extract at least one call");

        let call_names: Vec<&str> = calls.iter().map(|r| r.dst_name.as_str()).collect();
        assert!(call_names.contains(&"parse"), "should find call to parse()");
        assert!(
            call_names.contains(&"helper::transform"),
            "should find call to helper::transform()"
        );

        // All calls should have process as the src_name
        for call in &calls {
            assert_eq!(call.src_name, "process");
        }
    }

    #[test]
    fn parse_rust_method_calls() {
        let adapter = RustAdapter;
        let source = br#"
fn do_work(items: Vec<String>) -> usize {
    items.len()
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .collect();
        let call_names: Vec<&str> = calls.iter().map(|r| r.dst_name.as_str()).collect();
        assert!(
            call_names.contains(&"len"),
            "should find method call len(), found: {:?}",
            call_names
        );
    }

    #[test]
    fn parse_rust_use_statement() {
        let adapter = RustAdapter;
        let source = b"use std::collections::HashMap;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "std::collections");
        assert_eq!(import.specifiers.len(), 1);
        assert_eq!(import.specifiers[0].local_name, "HashMap");
        assert!(import.specifiers[0].original_name.is_none());
    }

    #[test]
    fn parse_rust_use_group() {
        let adapter = RustAdapter;
        let source = b"use std::io::{Read, Write};";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "std::io");
        assert_eq!(import.specifiers.len(), 2);

        let names: Vec<&str> = import
            .specifiers
            .iter()
            .map(|s| s.local_name.as_str())
            .collect();
        assert!(names.contains(&"Read"));
        assert!(names.contains(&"Write"));
    }

    #[test]
    fn parse_rust_enum_variants() {
        let adapter = RustAdapter;
        let source = br#"
pub enum Color {
    Red,
    Green,
    Blue,
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("color.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Color");

        let variants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumVariant)
            .collect();
        assert_eq!(variants.len(), 3, "should extract 3 enum variants");
        let variant_names: Vec<&str> = variants.iter().map(|v| v.name.as_str()).collect();
        assert!(variant_names.contains(&"Color::Red"));
        assert!(variant_names.contains(&"Color::Green"));
        assert!(variant_names.contains(&"Color::Blue"));

        // Check Contains relation from enum to variants
        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains && r.src_name == "Color")
            .collect();
        assert_eq!(contains.len(), 3, "should have 3 Contains relations");
    }

    #[test]
    fn extract_doc_comment_on_function() {
        let adapter = RustAdapter;
        let source = br#"
/// Adds two numbers together.
/// Returns the sum.
pub fn add(a: i32, b: i32) -> i32 { a + b }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "add")
            .expect("should find add");
        assert_eq!(
            func.doc_summary.as_deref(),
            Some("Adds two numbers together. Returns the sum.")
        );
    }

    #[test]
    fn no_doc_comment_yields_none() {
        let adapter = RustAdapter;
        let source = b"fn bare() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "bare")
            .expect("should find bare");
        assert!(func.doc_summary.is_none());
    }

    #[test]
    fn doc_comment_on_struct() {
        let adapter = RustAdapter;
        let source = br#"
/// A point in 2D space.
pub struct Point {
    x: f64,
    y: f64,
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let s = output
            .entities
            .iter()
            .find(|e| e.name == "Point")
            .expect("should find Point");
        assert_eq!(s.doc_summary.as_deref(), Some("A point in 2D space."));
    }

    #[test]
    fn regular_comment_not_captured_as_doc() {
        let adapter = RustAdapter;
        let source = br#"
// This is a regular comment, not a doc comment.
pub fn helper() {}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "helper")
            .expect("should find helper");
        assert!(
            func.doc_summary.is_none(),
            "regular // comments should not be captured as doc_summary"
        );
    }

    #[test]
    fn detect_derive_macro_implements_relations() {
        let adapter = RustAdapter;
        let source = br#"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    name: String,
    value: i32,
}

#[derive(PartialEq, Eq, Hash)]
pub enum Status {
    Active,
    Inactive,
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("config.rs");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let impls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Implements)
            .collect();

        // Config derives Debug, Clone, Serialize, Deserialize
        let config_impls: Vec<&str> = impls
            .iter()
            .filter(|r| r.src_name == "Config")
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(
            config_impls.contains(&"Debug"),
            "Config should derive Debug"
        );
        assert!(
            config_impls.contains(&"Clone"),
            "Config should derive Clone"
        );
        assert!(
            config_impls.contains(&"Serialize"),
            "Config should derive Serialize"
        );
        assert!(
            config_impls.contains(&"Deserialize"),
            "Config should derive Deserialize"
        );

        // Status derives PartialEq, Eq, Hash
        let status_impls: Vec<&str> = impls
            .iter()
            .filter(|r| r.src_name == "Status")
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(
            status_impls.contains(&"PartialEq"),
            "Status should derive PartialEq"
        );
        assert!(status_impls.contains(&"Hash"), "Status should derive Hash");
    }

    // ---- Module-scoped extraction ----
    //
    // Inline `mod m { ... }` bodies must be descended into so functions, impls,
    // and nested modules inside them become graph entities and their calls are
    // attributed to the innermost enclosing function. Before this, everything
    // under a module was dropped and module-scoped callers vanished from
    // refs/impact.

    fn call_edges(output: &crate::extract::ParseOutput) -> Vec<(&str, &str)> {
        output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect()
    }

    fn entity_names(output: &crate::extract::ParseOutput, kind: EntityKind) -> Vec<&str> {
        output
            .entities
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.name.as_str())
            .collect()
    }

    #[test]
    fn mod_nested_function_and_call_are_extracted() {
        let adapter = RustAdapter;
        let source = br#"
mod handlers {
    pub fn review() {
        do_work(1);
    }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let out = adapter
            .extract(&tree, source, &FilePathId::new("src/lib.rs"))
            .unwrap();

        assert!(
            entity_names(&out, EntityKind::Function).contains(&"review"),
            "module-scoped fn `review` should be an entity, got {:?}",
            entity_names(&out, EntityKind::Function)
        );
        assert!(
            call_edges(&out).contains(&("review", "do_work")),
            "the call should attribute to the enclosing fn `review`, got {:?}",
            call_edges(&out)
        );
    }

    #[test]
    fn deeply_nested_mod_functions_are_extracted() {
        let adapter = RustAdapter;
        let source = br#"
mod outer {
    mod inner {
        fn deep() {
            leaf_call(1);
        }
    }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let out = adapter
            .extract(&tree, source, &FilePathId::new("src/lib.rs"))
            .unwrap();

        assert!(
            entity_names(&out, EntityKind::Function).contains(&"deep"),
            "doubly-nested fn `deep` should be extracted, got {:?}",
            entity_names(&out, EntityKind::Function)
        );
        assert!(
            call_edges(&out).contains(&("deep", "leaf_call")),
            "call in a doubly-nested fn should attribute to `deep`, got {:?}",
            call_edges(&out)
        );
        let mods = entity_names(&out, EntityKind::Module);
        assert!(mods.contains(&"outer") && mods.contains(&"inner"));
    }

    #[test]
    fn impl_methods_inside_mod_are_extracted() {
        let adapter = RustAdapter;
        let source = br#"
mod model {
    struct Widget;
    impl Widget {
        fn make() {
            build(1);
        }
    }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let out = adapter
            .extract(&tree, source, &FilePathId::new("src/lib.rs"))
            .unwrap();

        assert!(
            entity_names(&out, EntityKind::Method).contains(&"Widget::make"),
            "method inside a module impl should be extracted, got {:?}",
            entity_names(&out, EntityKind::Method)
        );
        assert!(
            call_edges(&out).contains(&("Widget::make", "build")),
            "the method's call should attribute to `Widget::make`, got {:?}",
            call_edges(&out)
        );
    }

    #[test]
    fn qualified_call_inside_mod_keeps_full_path() {
        let adapter = RustAdapter;
        let source = br#"
mod handlers {
    fn review() {
        crate::impact::analyze_impact(1);
    }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let out = adapter
            .extract(&tree, source, &FilePathId::new("src/lib.rs"))
            .unwrap();

        assert!(
            call_edges(&out).contains(&("review", "crate::impact::analyze_impact")),
            "a qualified call inside a module fn should be emitted with its full \
             path for the linker to resolve, got {:?}",
            call_edges(&out)
        );
    }

    #[test]
    fn mod_without_body_is_still_a_module_entity() {
        // `mod other;` (declaration only) must not panic and still yields the
        // module entity without a body to descend into.
        let adapter = RustAdapter;
        let source = b"mod other;\nfn top() { local(1); }\n";
        let tree = adapter.parse(source).unwrap();
        let out = adapter
            .extract(&tree, source, &FilePathId::new("src/lib.rs"))
            .unwrap();

        assert!(entity_names(&out, EntityKind::Module).contains(&"other"));
        assert!(call_edges(&out).contains(&("top", "local")));
    }

    #[test]
    fn trait_impl_methods_declare_the_trait_they_satisfy() {
        let adapter = RustAdapter;
        let source = br#"
pub struct Summary;

impl Sink for Summary {
    fn matched(&mut self) -> bool { true }
    fn finish(&mut self) {}
}

impl Summary {
    fn helper(&self) -> u32 { 1 }
}
"#;
        let tree = adapter.parse(source).unwrap();
        let out = adapter
            .extract(&tree, source, &FilePathId::new("src/summary.rs"))
            .unwrap();

        let implements: Vec<(&str, &str)> = out
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Implements)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();

        assert!(
            implements.contains(&("Summary::matched", "Sink")),
            "a trait method must name the trait it satisfies: {implements:?}"
        );
        assert!(
            implements.contains(&("Summary::finish", "Sink")),
            "every method of the impl block satisfies the trait: {implements:?}"
        );
        assert!(
            implements.contains(&("Summary", "Sink")),
            "the implementing type keeps its own edge: {implements:?}"
        );
        assert!(
            !implements.iter().any(|(src, _)| *src == "Summary::helper"),
            "an inherent method satisfies no trait, so nothing shields it from a \
             dead-code report: {implements:?}"
        );
    }
}
