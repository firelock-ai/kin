// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, BTreeSet, HashMap};

use kin_model::{Entity, EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use serde_json::{json, Value};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    ExtractedEntity, ExtractedRelation, ExtractedTest, ExtractedTestKind, FileImport, ImportedName,
    ParseOutput, COMMAND_EFFECT_CONTRACT_KEY,
};

pub struct GoAdapter;

/// Package identity is parser evidence, not a directory-name guess. Go test
/// files can declare a separate package in the same directory.
pub fn attach_go_package_metadata(tree: &Tree, source: &[u8], entities: &mut [Entity]) {
    let root = tree.root_node();
    let mut cursor = root.walk();
    let package = root.named_children(&mut cursor).find_map(|node| {
        if node.kind() != "package_clause" {
            return None;
        }
        let mut cursor = node.walk();
        let package = node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "package_identifier")
            .and_then(|name| name.utf8_text(source).ok());
        package
    });
    if let Some(package) = package.filter(|name| !name.is_empty()) {
        for entity in entities {
            entity
                .metadata
                .extra
                .insert("go_package".into(), json!(package));
        }
    }
}

pub fn attach_go_command_effect_contract_metadata(
    tree: &Tree,
    source: &[u8],
    entities: &mut [Entity],
) {
    let contracts = extract_go_command_effect_contracts(tree, source);
    if contracts.is_empty() {
        return;
    }

    for entity in entities {
        if let Some(contract) = contracts.get(entity.name.as_str()) {
            entity
                .metadata
                .extra
                .insert(COMMAND_EFFECT_CONTRACT_KEY.into(), contract.clone());
        }
    }
}

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
        let mut interface_methods: Vec<(String, InterfaceContract)> = Vec::new();
        let mut type_methods: HashMap<String, Vec<String>> = HashMap::new();
        // Parallel bookkeeping: (index into `relations`, leftmost qualifier).
        // Populated for selector-expression calls like `fmt.Println` so that
        // the import-map post-pass can resolve `fmt` → module path even
        // after `dst_name` has been narrowed to the simple callee name.
        let mut call_prefixes: Vec<(usize, String)> = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_go_node(
                &child,
                source,
                file_id,
                &mut entities,
                &mut relations,
                &mut interface_methods,
                &mut type_methods,
                &mut call_prefixes,
            );
            if child.kind() == "import_declaration" {
                extract_go_imports(&child, source, &mut imports);
            }
        }

        // The file module owns entity-level import edges, and it has to sit
        // first so `module_entity_by_file` reads it rather than a declaration
        // that happens to sit above the rest. A file that declared nothing and
        // imported nothing contributes no entity: minting the synthetic module
        // there reported the file as parsed, which is what kept a comment-only
        // or unreadable file out of the parse-coverage census.
        if !entities.is_empty() || !imports.is_empty() {
            if let Some(module_name) = crate::adapter::file_module_surface_name(
                crate::adapter::declared_package_coordinate(&root, source).as_deref(),
                file_id,
            ) {
                entities.insert(
                    0,
                    crate::adapter::file_module_surface_entity(
                        module_name,
                        format!("package {}", file_id.0),
                        &root,
                        source,
                        file_id,
                    ),
                );
            }
        }

        // Infer implicit interface satisfaction by comparing method sets.
        // Same-file embedded interfaces are folded into the embedder's method
        // set first, so `type ReadCloser interface { Reader; Close() error }`
        // requires Read AND Close. Cross-file embeds cannot be resolved at
        // parse time; they contribute an Extends edge (emitted above) and are
        // otherwise ignored here. If a type's method names are a superset of
        // an interface's (expanded) method names, emit an Implements relation.
        let expanded_interfaces = expand_embedded_interface_methods(&interface_methods);
        for (iface_name, iface_method_names) in &expanded_interfaces {
            if iface_method_names.is_empty() {
                continue;
            }
            for (type_name, type_method_names) in &type_methods {
                if iface_method_names
                    .iter()
                    .all(|m| type_method_names.contains(m))
                {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Implements,
                        src_name: type_name.clone(),
                        dst_name: iface_name.clone(),
                        import_source: None,
                    });
                }
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

        // Build import lookup: local_name -> module_path
        let import_map: std::collections::HashMap<&str, &str> = imports
            .iter()
            .flat_map(|imp| {
                imp.specifiers
                    .iter()
                    .map(move |spec| (spec.local_name.as_str(), imp.module_path.as_str()))
            })
            .collect();

        // Annotate Calls/References relations with import_source.
        // Direct lookup handles the case where the simple callee name matches
        // an imported local name. The `call_prefixes` side channel handles
        // package-qualified calls like `fmt.Println` whose leftmost
        // qualifier was recorded during extraction.
        for (idx, prefix) in &call_prefixes {
            if let Some(rel) = relations.get_mut(*idx) {
                if rel.import_source.is_none() {
                    if let Some(&module) = import_map.get(prefix.as_str()) {
                        rel.import_source = Some(module.to_string());
                    }
                }
            }
        }
        for rel in &mut relations {
            if matches!(
                rel.kind,
                kin_model::RelationKind::Calls | kin_model::RelationKind::References
            ) && rel.import_source.is_none()
            {
                // A value selector belongs to its receiver's namespace.
                // Its leaf may coincidentally match an unrelated import alias.
                let import_name = if rel.kind == kin_model::RelationKind::References {
                    rel.receiver
                        .as_deref()
                        .map(|receiver| receiver.split('.').next().unwrap_or(receiver).trim())
                        .unwrap_or(rel.dst_name.as_str())
                } else {
                    rel.dst_name.as_str()
                };
                if let Some(&module) = import_map.get(import_name) {
                    rel.import_source = Some(module.to_string());
                }
            }
        }

        Ok(ParseOutput {
            derived_members: Vec::new(),
            entities,
            relations,
            imports,
            tests,
            parse_state,
            parsed_call_sites: None,
        })
    }
}

fn extract_go_command_effect_contracts(tree: &Tree, source: &[u8]) -> BTreeMap<String, Value> {
    let mut contracts = BTreeMap::new();
    let root = tree.root_node();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        let name = match child.kind() {
            "function_declaration" => child
                .child_by_field_name("name")
                .map(|name| name.utf8_text(source).unwrap_or("").to_string()),
            "method_declaration" => child.child_by_field_name("name").map(|name| {
                let method_name = name.utf8_text(source).unwrap_or("").to_string();
                let receiver_type = child
                    .child_by_field_name("receiver")
                    .and_then(|receiver| extract_receiver_type(&receiver, source))
                    .unwrap_or_default();
                if receiver_type.is_empty() {
                    method_name
                } else {
                    format!("{receiver_type}.{method_name}")
                }
            }),
            _ => None,
        };

        if let (Some(name), Some(body)) = (name, child.child_by_field_name("body")) {
            if name.is_empty() {
                continue;
            }
            if let Some(contract) = command_effect_contract_for_body(&body, source) {
                contracts.insert(name, contract);
            }
        }
    }

    contracts
}

fn command_effect_contract_for_body(node: &tree_sitter::Node, source: &[u8]) -> Option<Value> {
    let mut bindings = BTreeMap::new();
    let mut effects = Vec::new();
    let mut seen = BTreeSet::new();
    collect_go_command_effects_flow(node, source, &mut bindings, &mut effects, &mut seen);
    if effects.is_empty() {
        return None;
    }

    Some(json!({
        "schema_version": 1,
        "language": "go",
        "effects": effects,
    }))
}

fn collect_go_command_effects_flow(
    node: &tree_sitter::Node,
    source: &[u8],
    bindings: &mut BTreeMap<String, String>,
    effects: &mut Vec<Value>,
    seen: &mut BTreeSet<String>,
) {
    match node.kind() {
        "short_var_declaration" | "assignment_statement" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                collect_go_command_effects_flow(&right, source, bindings, effects, seen);
                let names = assigned_identifier_names(&left, source);
                if names.len() == 1 && is_contract_binding_value(&right, source) {
                    let rhs = normalize_go_contract_expr(&right, source);
                    if !rhs.is_empty() {
                        bindings.insert(names[0].clone(), rhs);
                    }
                }
            }
            return;
        }
        "var_spec" | "const_spec" => {
            if let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) {
                collect_go_command_effects_flow(&value, source, bindings, effects, seen);
                let name = name.utf8_text(source).unwrap_or("").trim().to_string();
                if !name.is_empty() && is_contract_binding_value(&value, source) {
                    let rhs = normalize_go_contract_expr(&value, source);
                    if !rhs.is_empty() {
                        bindings.insert(name, rhs);
                    }
                }
            }
            return;
        }
        "if_statement" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "block" || child.kind() == "else" {
                    let mut branch_bindings = bindings.clone();
                    collect_go_command_effects_flow(
                        &child,
                        source,
                        &mut branch_bindings,
                        effects,
                        seen,
                    );
                } else {
                    collect_go_command_effects_flow(&child, source, bindings, effects, seen);
                }
            }
            return;
        }
        "for_statement" | "range_clause" => {
            let mut loop_bindings = bindings.clone();
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_go_command_effects_flow(&child, source, &mut loop_bindings, effects, seen);
            }
            return;
        }
        "call_expression" => {
            if let Some((kind, expr)) = classify_go_command_effect_call(node, source) {
                if seen.insert(format!("{kind}\n{expr}")) {
                    let identifiers = identifiers_in_node(node, source);
                    let mut consumed_bindings = serde_json::Map::new();
                    for ident in identifiers {
                        if let Some(value) = bindings.get(&ident) {
                            consumed_bindings.insert(ident, Value::String(value.clone()));
                        }
                    }
                    effects.push(json!({
                        "kind": kind,
                        "expr": expr,
                        "bindings": consumed_bindings,
                    }));
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_command_effects_flow(&child, source, bindings, effects, seen);
    }
}

fn is_contract_binding_value(node: &tree_sitter::Node, source: &[u8]) -> bool {
    if node.kind() == "composite_literal" {
        return false;
    }
    !contains_go_command_effect_call(node, source)
}

fn contains_go_command_effect_call(node: &tree_sitter::Node, source: &[u8]) -> bool {
    if node.kind() == "call_expression" && classify_go_command_effect_call(node, source).is_some() {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| contains_go_command_effect_call(&child, source));
    found
}

fn classify_go_command_effect_call(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<(&'static str, String)> {
    let function = node.child_by_field_name("function")?;
    let callee = normalize_go_contract_expr(&function, source);
    let expr = normalize_go_contract_expr(node, source);

    if callee == "exec.Command" {
        return Some(("subprocess_argv", expr));
    }
    if callee == "git.Config" || callee == "git.VerifyRef" {
        return Some(("git_state_query", expr));
    }
    if callee == "append" && expr.contains("\"git\"") {
        return Some(("queued_git_argv", expr));
    }

    None
}

fn assigned_identifier_names(node: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source).unwrap_or("").trim();
            if !name.is_empty() && name != "_" {
                names.push(name.to_string());
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                names.extend(assigned_identifier_names(&child, source));
            }
        }
    }
    names
}

fn identifiers_in_node(node: &tree_sitter::Node, source: &[u8]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_identifiers_in_node(node, source, &mut names);
    names
}

fn collect_identifiers_in_node(
    node: &tree_sitter::Node,
    source: &[u8],
    names: &mut BTreeSet<String>,
) {
    if node.kind() == "identifier" {
        let name = node.utf8_text(source).unwrap_or("").trim();
        if !name.is_empty() && name != "_" {
            names.insert(name.to_string());
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifiers_in_node(&child, source, names);
    }
}

fn normalize_go_contract_expr(node: &tree_sitter::Node, source: &[u8]) -> String {
    node.utf8_text(source)
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_arguments)]
fn extract_go_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    interface_methods: &mut Vec<(String, InterfaceContract)>,
    type_methods: &mut HashMap<String, Vec<String>>,
    call_prefixes: &mut Vec<(usize, String)>,
) {
    match node.kind() {
        "function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let vis = go_visibility_with_path(&name, file_id);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                    declaration_line: None,
                });
                let mut ref_seen = std::collections::HashSet::new();
                extract_calls_from_body(
                    node,
                    source,
                    &name,
                    None,
                    relations,
                    call_prefixes,
                    &mut ref_seen,
                );
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

                // Track methods by receiver type for interface satisfaction inference.
                if !receiver_type.is_empty() {
                    type_methods
                        .entry(receiver_type.clone())
                        .or_default()
                        .push(method_name.clone());
                }

                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: go_visibility_with_path(&method_name, file_id),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                    declaration_line: None,
                });

                // Emit Contains relation from receiver type to method
                if !receiver_type.is_empty() {
                    relations.push(ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: receiver_type.clone(),
                        dst_name: qualified.clone(),
                        import_source: None,
                    });
                }

                let mut ref_seen = std::collections::HashSet::new();
                let receiver = GoMethodReceiver::from_method(node, source);
                extract_calls_from_body(
                    node,
                    source,
                    &qualified,
                    receiver.as_ref(),
                    relations,
                    call_prefixes,
                    &mut ref_seen,
                );
            }
        }
        "type_declaration" => {
            let mut cursor = node.walk();
            for spec in node.children(&mut cursor) {
                // `type Name = Other` is a `type_alias` node rather than a
                // `type_spec`. It declares a name exactly as a spec does, so it
                // is a TypeAlias entity spanning its own node; skipping it left
                // an alias invisible to every graph query.
                if spec.kind() == "type_alias" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        entities.push(ExtractedEntity {
                            kind: EntityKind::TypeAlias,
                            name: name.clone(),
                            signature: node_signature(&spec, source),
                            visibility: go_visibility(&name),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&spec, source),
                            span: span_from_node(&spec, file_id),
                            declaration_line: None,
                        });
                    }
                    continue;
                }
                if spec.kind() == "type_spec" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let type_node = spec.child_by_field_name("type");
                        let kind = match type_node.map(|t| t.kind()) {
                            Some("struct_type") => EntityKind::Class,
                            Some("interface_type") => EntityKind::Interface,
                            _ => EntityKind::TypeAlias,
                        };

                        // For interfaces, extract the contract surface as
                        // first-class entities: every method spec becomes a
                        // Method entity (qualified `Interface.Method`, like
                        // concrete `Receiver.Method`), contained by the
                        // interface — so the contract is retrievable, not just
                        // an inference input. Embedded interfaces are recorded
                        // for Extends edges and same-file method-set expansion.
                        if kind == EntityKind::Interface {
                            if let Some(ref iface_node) = type_node {
                                let members =
                                    extract_interface_members(iface_node, source, file_id);
                                for member in &members.methods {
                                    let qualified = format!("{}.{}", name, member.name);
                                    entities.push(ExtractedEntity {
                                        kind: EntityKind::Method,
                                        name: qualified.clone(),
                                        signature: member.signature.clone(),
                                        visibility: go_visibility_with_path(&member.name, file_id),
                                        doc_summary: member.doc_summary.clone(),
                                        fingerprint: member.fingerprint.clone(),
                                        span: member.span.clone(),
                                        declaration_line: None,
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
                                for embedded in &members.embedded {
                                    relations.push(ExtractedRelation {
                                        site: None,
                                        receiver: None,
                                        call_shape: None,
                                        kind: kin_model::RelationKind::Extends,
                                        src_name: name.clone(),
                                        dst_name: embedded.clone(),
                                        import_source: None,
                                    });
                                }
                                interface_methods.push((
                                    name.clone(),
                                    InterfaceContract {
                                        method_names: members
                                            .methods
                                            .iter()
                                            .map(|member| member.name.clone())
                                            .collect(),
                                        embedded: members.embedded,
                                    },
                                ));
                            }
                        }

                        // For structs, detect embedded types and emit Extends
                        // relations. Go embedded types provide method forwarding
                        // similar to inheritance.
                        if kind == EntityKind::Class {
                            if let Some(ref struct_node) = type_node {
                                for embedded in extract_embedded_types(struct_node, source) {
                                    relations.push(ExtractedRelation {
                                        site: None,
                                        receiver: None,
                                        call_shape: None,
                                        kind: kin_model::RelationKind::Extends,
                                        src_name: name.clone(),
                                        dst_name: embedded,
                                        import_source: None,
                                    });
                                }

                                // Every NAMED field becomes a first-class entity,
                                // owner-qualified (`Struct.Field`) the same way a
                                // method is `Receiver.Method`, so it is
                                // addressable and `find_references` has
                                // something in the graph to answer against. An
                                // embedded field (no name at all) stays out of
                                // this: it already produced the Extends relation
                                // above, and Go reaches its promoted members
                                // through THAT type's own fields, not through an
                                // entity named after the embedder.
                                for field in extract_struct_fields(struct_node, source, file_id) {
                                    let qualified = format!("{}.{}", name, field.name);
                                    entities.push(ExtractedEntity {
                                        kind: EntityKind::Field,
                                        name: qualified.clone(),
                                        signature: field.signature,
                                        visibility: go_visibility_with_path(&field.name, file_id),
                                        doc_summary: field.doc_summary,
                                        fingerprint: field.fingerprint,
                                        span: field.span,
                                        declaration_line: None,
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
                            }
                        }

                        entities.push(ExtractedEntity {
                            kind,
                            name,
                            signature: node_signature(&spec, source),
                            visibility: go_visibility(name_node.utf8_text(source).unwrap_or("")),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&spec, source),
                            span: span_from_node(&spec, file_id),
                            declaration_line: None,
                        });
                    }
                }
            }
        }
        "const_declaration" | "var_declaration" => {
            // A grouped `var ( ... )` wraps its specs in a `var_spec_list`,
            // while a grouped `const ( ... )` holds its specs directly. Both
            // are read through one flat list so a grouped var declares its
            // names exactly as a grouped const does.
            let mut cursor = node.walk();
            let mut specs = Vec::new();
            for child in node.children(&mut cursor) {
                if child.kind() == "var_spec_list" {
                    let mut inner = child.walk();
                    specs.extend(child.children(&mut inner));
                } else {
                    specs.push(child);
                }
            }
            for spec in specs {
                if spec.kind() == "const_spec" || spec.kind() == "var_spec" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = spec_entity_name(&spec, source).unwrap_or_default();
                        let kind = if node.kind() == "const_declaration" {
                            EntityKind::Constant
                        } else {
                            EntityKind::StaticVar
                        };
                        entities.push(ExtractedEntity {
                            kind,
                            name: name.clone(),
                            signature: node_signature(&spec, source),
                            visibility: go_visibility(name_node.utf8_text(source).unwrap_or("")),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&spec, source),
                            span: span_from_node(&spec, file_id),
                            declaration_line: None,
                        });

                        // A package-level const/var initializer references the
                        // identifiers read in its value expression (e.g. a
                        // cobra `&cobra.Command{RunE: prCheckout}` var
                        // references the handler `prCheckout`). Emit those as
                        // References edges sourced from the declared name.
                        if let Some(value) = spec.child_by_field_name("value") {
                            let mut ref_seen = std::collections::HashSet::new();
                            emit_value_references(&value, source, &name, relations, &mut ref_seen);
                        }
                    }
                }
            }
        }
        "import_declaration" => {}
        _ => {}
    }
}

/// Extract embedded type names from a Go struct_type node.
///
/// Go embedded fields are `field_declaration` nodes with a type but no
/// explicit field name. For example:
///   type LabeledShape struct {
///       Shape        // embedded — no field name
///       Label string // normal field — has a name
///   }
fn extract_embedded_types(node: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut embedded = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "field_declaration_list" {
            let mut list_cursor = child.walk();
            for field in child.children(&mut list_cursor) {
                if field.kind() == "field_declaration" {
                    // An embedded field has a type but no field name.
                    // In tree-sitter-go, embedded fields appear as field_declaration
                    // with just a type_identifier (no name child).
                    let has_name = field.child_by_field_name("name").is_some();
                    if !has_name {
                        // Look for the type identifier
                        if let Some(type_node) = field.child_by_field_name("type") {
                            let type_name = type_node.utf8_text(source).unwrap_or("").to_string();
                            // Strip pointer prefix
                            let clean = type_name.trim_start_matches('*').to_string();
                            if !clean.is_empty() {
                                embedded.push(clean);
                            }
                        }
                    }
                }
            }
        }
    }
    embedded
}

/// One named field declared directly in a Go struct body, carrying
/// everything needed to materialize it as a graph entity.
struct StructFieldSpec {
    name: String,
    signature: String,
    doc_summary: Option<String>,
    fingerprint: kin_model::SemanticFingerprint,
    span: kin_model::SourceSpan,
}

/// Extract the named fields of a Go struct_type node.
///
/// A `field_declaration` either declares one or more named fields sharing a
/// type (`X, Y int` is one `field_declaration` with two `name` children), or
/// embeds a type with no name at all (`Shape`, which
/// [`extract_embedded_types`] turns into an Extends relation instead and
/// which this function skips). Every co-declared name shares its
/// declaration's signature, doc comment, and span — the same choice the Java
/// adapter already makes for `int x, y;` — so `X` and `Y` above both read
/// "X, Y int" rather than a fabricated single-name signature neither wrote.
fn extract_struct_fields(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
) -> Vec<StructFieldSpec> {
    let mut fields = Vec::new();
    let mut cursor = node.walk();
    for list in node.children(&mut cursor) {
        if list.kind() != "field_declaration_list" {
            continue;
        }
        let mut list_cursor = list.walk();
        for decl in list.children(&mut list_cursor) {
            if decl.kind() != "field_declaration" {
                continue;
            }
            let mut name_cursor = decl.walk();
            let names: Vec<tree_sitter::Node> = decl
                .children_by_field_name("name", &mut name_cursor)
                .collect();
            if names.is_empty() {
                // An embedded field: a type with no name at all.
                continue;
            }
            let signature = node_signature(&decl, source);
            let doc_summary = extract_preceding_comment(&decl, source);
            let fingerprint = compute_fingerprint(&decl, source);
            let span = span_from_node(&decl, file_id);
            for name_node in names {
                let field_name = name_node.utf8_text(source).unwrap_or("").to_string();
                if field_name.is_empty() {
                    continue;
                }
                fields.push(StructFieldSpec {
                    name: field_name,
                    signature: signature.clone(),
                    doc_summary: doc_summary.clone(),
                    fingerprint: fingerprint.clone(),
                    span: span.clone(),
                });
            }
        }
    }
    fields
}

/// One method spec declared directly in a Go interface body, carrying
/// everything needed to materialize it as a graph entity.
struct InterfaceMethodSpec {
    name: String,
    signature: String,
    doc_summary: Option<String>,
    fingerprint: kin_model::SemanticFingerprint,
    span: kin_model::SourceSpan,
}

/// The members of one interface body: directly declared method specs plus
/// the names of embedded interfaces.
struct InterfaceMembers {
    methods: Vec<InterfaceMethodSpec>,
    embedded: Vec<String>,
}

/// An interface's contract surface as needed for satisfaction inference:
/// its direct method names and the embedded interfaces they extend.
struct InterfaceContract {
    method_names: Vec<String>,
    embedded: Vec<String>,
}

/// Extract the members of a Go interface_type node.
///
/// Go interfaces declare method signatures and may embed other interfaces:
///   type ReadCloser interface {
///       Reader        // embedded — folds Reader's contract in
///       Close() error // direct method spec
///   }
///
/// Direct method specs (`method_elem` nodes with a `field_identifier` name)
/// come back as full [`InterfaceMethodSpec`]s so the caller can emit them as
/// first-class Method entities. Embedded interfaces (`type_elem` nodes)
/// come back by name; only their simple identifier is kept (a qualified
/// `io.Reader` stays `io.Reader` for the Extends edge, but cannot be
/// expanded same-file).
fn extract_interface_members(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
) -> InterfaceMembers {
    let mut methods = Vec::new();
    let mut embedded = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // tree-sitter-go uses "method_elem" for interface method declarations,
        // with a "field_identifier" child holding the method name.
        if child.kind() == "method_elem" {
            let mut inner = child.walk();
            for field in child.children(&mut inner) {
                if field.kind() == "field_identifier" {
                    let name = field.utf8_text(source).unwrap_or("").to_string();
                    if !name.is_empty() {
                        methods.push(InterfaceMethodSpec {
                            name,
                            signature: node_signature(&child, source),
                            doc_summary: extract_preceding_comment(&child, source),
                            fingerprint: compute_fingerprint(&child, source),
                            span: span_from_node(&child, file_id),
                        });
                    }
                    break;
                }
            }
        }
        // Embedded interfaces appear as "type_elem" children (possibly a
        // union in Go 1.18+ generics; each term is a type identifier or a
        // qualified type). Record each named term.
        if child.kind() == "type_elem" {
            collect_embedded_interface_names(&child, source, &mut embedded);
        }
    }
    InterfaceMembers { methods, embedded }
}

/// Collect embedded-interface names from a `type_elem` node: plain
/// `type_identifier`s and package-qualified `qualified_type`s, skipping
/// operators/underlying-type markers from generics union syntax.
fn collect_embedded_interface_names(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut Vec<String>,
) {
    match node.kind() {
        "type_identifier" | "qualified_type" => {
            let name = node.utf8_text(source).unwrap_or("").to_string();
            if !name.is_empty() {
                out.push(name);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_embedded_interface_names(&child, source, out);
            }
        }
    }
}

/// Expand same-file embedded interfaces into their embedder's method-name
/// set (transitively, cycle-safe), yielding the effective contract each
/// interface requires for satisfaction inference. Cross-file embeds (names
/// not declared in this file, including package-qualified ones) cannot be
/// resolved here and are skipped.
fn expand_embedded_interface_methods(
    interfaces: &[(String, InterfaceContract)],
) -> Vec<(String, Vec<String>)> {
    fn collect(
        name: &str,
        by_name: &HashMap<&str, &InterfaceContract>,
        visiting: &mut Vec<String>,
        out: &mut Vec<String>,
    ) {
        if visiting.iter().any(|seen| seen == name) {
            return;
        }
        let Some(contract) = by_name.get(name) else {
            return;
        };
        visiting.push(name.to_string());
        for method in &contract.method_names {
            if !out.contains(method) {
                out.push(method.clone());
            }
        }
        for embedded in &contract.embedded {
            collect(embedded, by_name, visiting, out);
        }
        visiting.pop();
    }

    let by_name: HashMap<&str, &InterfaceContract> = interfaces
        .iter()
        .map(|(name, contract)| (name.as_str(), contract))
        .collect();
    interfaces
        .iter()
        .map(|(name, _)| {
            let mut methods = Vec::new();
            let mut visiting = Vec::new();
            collect(name, &by_name, &mut visiting, &mut methods);
            (name.clone(), methods)
        })
        .collect()
}

/// The entity name of a const or var spec: its first declared name, or, for a
/// spec that declares only the blank identifier, a name derived from the rest
/// of the spec (`_ Getter = (*Store)(nil)`).
///
/// Go lets `_` repeat, and interface assertions such as
/// `var _ io.Reader = (*File)(nil)` are written in every package. Naming each
/// one `_` gave every assertion in a file the same name, so none was
/// addressable and their identities could swap between parses. The derived
/// name is the assertion itself, rendered from its parsed tokens: every
/// string, raw-string and rune literal is kept byte-exact, comments are
/// dropped, and the spacing between tokens is canonical, so reformatting the
/// same spec keeps its identity and specs that differ in any token do not
/// share one.
pub(crate) fn spec_entity_name(spec: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = spec.walk();
    let names = spec
        .children_by_field_name("name", &mut cursor)
        .filter(|name| name.kind() == "identifier")
        .collect::<Vec<_>>();
    let first = *names.first()?;
    let name = first.utf8_text(source).ok()?;
    if name != "_" || names.len() != 1 {
        return Some(name.to_string());
    }
    let mut tokens = Vec::new();
    let mut cursor = spec.walk();
    for child in spec.children(&mut cursor) {
        if child.end_byte() <= first.end_byte() {
            continue;
        }
        collect_spec_tokens(child, source, &mut tokens);
    }
    Some(if tokens.is_empty() {
        "_".to_string()
    } else {
        format!("_ {}", render_tokens(&tokens))
    })
}

/// The leaf tokens of a node, with each literal taken whole and comments
/// skipped.
fn collect_spec_tokens<'a>(node: tree_sitter::Node<'_>, source: &'a [u8], out: &mut Vec<&'a str>) {
    match node.kind() {
        "comment" => {}
        "interpreted_string_literal" | "raw_string_literal" | "rune_literal" => {
            out.extend(std::str::from_utf8(&source[node.byte_range()]).ok());
        }
        _ if node.child_count() == 0 => {
            let text = std::str::from_utf8(&source[node.byte_range()]).unwrap_or("");
            if !text.trim().is_empty() {
                out.push(text);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_spec_tokens(child, source, out);
            }
        }
    }
}

/// Join tokens canonically. A space separates two word-like tokens and two
/// operator tokens, which could otherwise run together into different tokens
/// (`&` `^` against `&^`), and surrounds `=`; brackets and separators take
/// none. The same token sequence always renders the same text, and different
/// sequences never do.
fn render_tokens(tokens: &[&str]) -> String {
    #[derive(PartialEq, Clone, Copy)]
    enum Class {
        Word,
        Literal,
        Bracket,
        Operator,
    }
    fn class(token: &str) -> Class {
        let first = token.chars().next().unwrap_or(' ');
        if matches!(first, '"' | '`' | '\'') {
            Class::Literal
        } else if first.is_alphanumeric() || first == '_' {
            Class::Word
        } else if matches!(
            token,
            "(" | ")" | "[" | "]" | "{" | "}" | "," | ";" | "." | ":" | "..."
        ) {
            Class::Bracket
        } else {
            Class::Operator
        }
    }
    let mut rendered = String::new();
    let mut previous: Option<&str> = None;
    for token in tokens {
        if let Some(previous) = previous {
            let (left, right) = (class(previous), class(token));
            let spaced = *token == "="
                || previous == "="
                || (left == Class::Word && right == Class::Word)
                || (left == Class::Operator && right == Class::Operator)
                || (left == Class::Literal && right == Class::Literal)
                || (left == Class::Word && right == Class::Literal)
                || (left == Class::Literal && right == Class::Word);
            if spaced {
                rendered.push(' ');
            }
        }
        rendered.push_str(token);
        previous = Some(token);
    }
    rendered
}

/// The base receiver type a method is named after (`Store` for `(s *Store)` and
/// for `(s Store[T])`), exactly as this adapter names the method `Store.Name`.
pub(crate) fn method_receiver_type(method: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    method
        .child_by_field_name("receiver")
        .and_then(|receiver| extract_receiver_type(&receiver, source))
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

/// Determine Go entity visibility considering both name convention and file path.
/// Exported names (capitalized) are Public, unexported are Private.
/// Entities in internal/ packages get Internal visibility regardless of name.
fn go_visibility_with_path(name: &str, file_id: &FilePathId) -> Visibility {
    if file_id.0.contains("/internal/") || file_id.0.starts_with("internal/") {
        Visibility::Internal
    } else {
        go_visibility(name)
    }
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
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

/// The value reads one context has already emitted a `References` edge for,
/// keyed on (name, start byte) so repeated reads of one name each keep their
/// own position while a subtree the walk reaches twice still yields one edge.
type ValueReadsSeen = std::collections::HashSet<(String, usize)>;

struct GoMethodReceiver {
    name: String,
    owner: String,
    shadows: Vec<std::ops::Range<usize>>,
}

impl GoMethodReceiver {
    fn from_method(method: &tree_sitter::Node, source: &[u8]) -> Option<Self> {
        let receiver = method.child_by_field_name("receiver")?;
        let mut cursor = receiver.walk();
        let declaration = receiver
            .named_children(&mut cursor)
            .find(|node| node.kind() == "parameter_declaration")?;
        let name = declaration
            .child_by_field_name("name")?
            .utf8_text(source)
            .ok()?;
        if name.is_empty() || name == "_" {
            return None;
        }
        let owner = extract_receiver_type(&receiver, source)?;
        let body = method.child_by_field_name("body")?;
        let mut shadows = Vec::new();
        collect_receiver_shadows(&body, &body, name, source, &mut shadows);
        Some(Self {
            name: name.to_string(),
            owner,
            shadows,
        })
    }

    fn binds(&self, name: &str, position: usize) -> bool {
        name == self.name && !self.shadows.iter().any(|range| range.contains(&position))
    }
}

fn go_binding_scope(mut node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "block"
                | "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
                | "communication_case"
                | "expression_case"
                | "type_case"
                | "default_case"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

/// Receiver parameters remain in scope inside captured closures, but a local
/// declaration can hide them. A declaration's RHS still sees the outer binding.
fn collect_receiver_shadows(
    node: &tree_sitter::Node,
    method_body: &tree_sitter::Node,
    name: &str,
    source: &[u8],
    shadows: &mut Vec<std::ops::Range<usize>>,
) {
    let declares = |field: &str| {
        node.child_by_field_name(field).is_some_and(|part| {
            assigned_identifier_names(&part, source)
                .iter()
                .any(|n| n == name)
        })
    };
    match node.kind() {
        "short_var_declaration" | "range_clause" | "receive_statement" => {
            let mut cursor = node.walk();
            let short = node.children(&mut cursor).any(|child| child.kind() == ":=");
            if short && declares("left") {
                if let Some(scope) = go_binding_scope(*node) {
                    // A short declaration in the method's outer block reuses
                    // its receiver parameter; a nested block declares a new name.
                    if scope.id() != method_body.id() {
                        shadows.push(node.end_byte()..scope.end_byte());
                    }
                }
            }
        }
        "var_spec" | "const_spec" | "type_spec" => {
            let mut cursor = node.walk();
            let declares_name = node
                .children_by_field_name("name", &mut cursor)
                .any(|part| part.utf8_text(source).ok() == Some(name));
            if declares_name {
                if let Some(scope) = go_binding_scope(*node) {
                    shadows.push(node.end_byte()..scope.end_byte());
                }
            }
        }
        "func_literal" => {
            for field in ["parameters", "result"] {
                if let Some(parameters) = node.child_by_field_name(field) {
                    let mut cursor = parameters.walk();
                    let hides = parameters.named_children(&mut cursor).any(|parameter| {
                        let mut cursor = parameter.walk();
                        let hides = parameter
                            .children_by_field_name("name", &mut cursor)
                            .any(|part| part.utf8_text(source).ok() == Some(name));
                        hides
                    });
                    if hides {
                        if let Some(body) = node.child_by_field_name("body") {
                            shadows.push(body.byte_range());
                        }
                    }
                }
            }
        }
        "type_switch_statement" if declares("alias") => {
            if let Some(value) = node.child_by_field_name("value") {
                shadows.push(value.end_byte()..node.end_byte());
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_receiver_shadows(&child, method_body, name, source, shadows);
    }
}

/// Recursively walk a function/method body to find `call_expression` nodes.
///
/// Package selectors retain their simple name and import prefix. Calls on
/// the declared method receiver carry the owner-qualified method name; a
/// shadowed receiver retains its local identity without claiming a type.
///
/// The leftmost qualifier (e.g. `"fmt"` in `fmt.Println`) is recorded as a
/// side channel in `call_prefixes` — parallel to `relations` at the index of
/// the just-pushed relation — so the import-map post-pass can still annotate
/// package calls with their source module.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    method_receiver: Option<&GoMethodReceiver>,
    relations: &mut Vec<ExtractedRelation>,
    call_prefixes: &mut Vec<(usize, String)>,
    ref_seen: &mut ValueReadsSeen,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        // Value-position references: an identifier read as a VALUE (passed as a
        // call argument, used as a composite-literal element value, or on the
        // RHS of an assignment/declaration/return) is a `References` edge — not
        // a `Calls` edge. This is what wires cobra-style `RunE: prCheckout`
        // function-value handoffs and package-level const/var reads into impact.
        match child.kind() {
            "argument_list" | "literal_value" | "return_statement" => {
                emit_value_references(&child, source, context_name, relations, ref_seen);
            }
            "assignment_statement" => {
                // The write side: `t.Field = v` (or `t.Field += v`, whose
                // operator still binds through the `left`/`right` fields)
                // reads whatever locates the slot being written — a struct
                // field, an index, a pointer deref — but never the plain
                // local or global identifier being freshly bound, which is a
                // write with nothing to read. A struct field write has to
                // reach the graph as a reference the same way a read does, or
                // `find_references` on a field only ever sees half its sites.
                if let Some(lhs) = child.child_by_field_name("left") {
                    emit_write_target_references(&lhs, source, context_name, relations, ref_seen);
                }
                if let Some(rhs) = child.child_by_field_name("right") {
                    emit_value_references(&rhs, source, context_name, relations, ref_seen);
                }
            }
            "short_var_declaration" => {
                // `x := v` only ever binds fresh local names on its left, so
                // there is nothing there to read; unlike `assignment_statement`
                // it cannot write through a selector or index expression.
                if let Some(rhs) = child.child_by_field_name("right") {
                    emit_value_references(&rhs, source, context_name, relations, ref_seen);
                }
            }
            "var_spec" | "const_spec" => {
                if let Some(value) = child.child_by_field_name("value") {
                    emit_value_references(&value, source, context_name, relations, ref_seen);
                }
            }
            _ => {}
        }

        if child.kind() == "call_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                let (callee, prefix) = match function.kind() {
                    "selector_expression" => {
                        let name = function
                            .child_by_field_name("field")
                            .map(|f| f.utf8_text(source).unwrap_or("").to_string())
                            .unwrap_or_default();
                        let operand = function
                            .child_by_field_name("operand")
                            .map(|o| o.utf8_text(source).unwrap_or("").to_string());
                        // Only capture a prefix when it's a bare identifier
                        // (e.g. `fmt` in `fmt.Println`). Chained calls like
                        // `a.B().C()` have a non-identifier operand and don't
                        // map cleanly to a single import.
                        let prefix = operand.filter(|s| {
                            !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_')
                        });
                        (name, prefix)
                    }
                    "identifier" => (function.utf8_text(source).unwrap_or("").to_string(), None),
                    _ => (String::new(), None),
                };
                if is_valid_callee_name(&callee) {
                    let local_receiver = prefix.as_deref().and_then(|prefix| {
                        method_receiver.filter(|receiver| receiver.name == prefix)
                    });
                    let declared_receiver = local_receiver
                        .filter(|receiver| receiver.binds(&receiver.name, child.start_byte()));
                    let callee = declared_receiver
                        .map(|receiver| format!("{}.{}", receiver.owner, callee))
                        .unwrap_or(callee);
                    let idx = relations.len();
                    relations.push(ExtractedRelation {
                        // The call expression itself, so a reference row can
                        // report the line the call is written on. Without it the
                        // linker has no span to store and every consuming
                        // surface reports the edge as having no evidence span.
                        site: Some(crate::adapter::site_from_node(&child)),
                        receiver: local_receiver.map(|receiver| receiver.name.clone()),
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee,
                        import_source: None,
                    });
                    if let Some(p) = prefix.filter(|_| local_receiver.is_none()) {
                        call_prefixes.push((idx, p));
                    }
                }
            }
        }
        if child.kind() == "send_statement" {
            if let Some(channel) = child.child_by_field_name("channel") {
                let channel_name = channel.utf8_text(source).unwrap_or("").to_string();
                if !channel_name.is_empty() {
                    relations.push(ExtractedRelation {
                        // The send statement, for the same reason the call
                        // expression above is recorded.
                        site: Some(crate::adapter::site_from_node(&child)),
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::SendsMessage,
                        src_name: context_name.to_string(),
                        dst_name: channel_name,
                        import_source: None,
                    });
                }
            }
        }
        if child.kind() == "go_statement" {
            let mut go_cursor = child.walk();
            for go_child in child.children(&mut go_cursor) {
                if go_child.kind() == "call_expression" {
                    if let Some(function) = go_child.child_by_field_name("function") {
                        let spawned = function.utf8_text(source).unwrap_or("").to_string();
                        if !spawned.is_empty() {
                            relations.push(ExtractedRelation {
                                // The `go` statement's call expression.
                                site: Some(crate::adapter::site_from_node(&go_child)),
                                receiver: None,
                                call_shape: None,
                                kind: kin_model::RelationKind::Spawns,
                                src_name: context_name.to_string(),
                                dst_name: spawned,
                                import_source: None,
                            });
                        }
                    }
                }
            }
        }
        extract_calls_from_body(
            &child,
            source,
            context_name,
            method_receiver,
            relations,
            call_prefixes,
            ref_seen,
        );
    }
}

/// Emit `References` edges for the value-position identifiers read within
/// `node`, sourced from `context_name`, each carrying the position it was read
/// at. The linker resolves References by name and drops unresolvables, so
/// locals and parameters that match no package-level entity are harmless.
///
/// `ref_seen` is keyed on (name, start byte) rather than on the name alone.
/// Keying it on the name dropped every read after the first, so a body that
/// reads a name five times produced one edge carrying one position at best, and
/// the four other reads could not be recovered downstream: a relation's
/// evidence is the only record of where the syntax sat. The walk reaches some
/// subtrees from more than one match arm, and a position key still collapses
/// those to one edge per read, so the emitted set stays free of duplicates.
fn emit_value_references(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
    ref_seen: &mut ValueReadsSeen,
) {
    let mut reads = Vec::new();
    collect_value_refs(node, source, &mut reads);
    emit_references(reads, context_name, relations, ref_seen);
}

/// The write-side counterpart of [`emit_value_references`]: emits a
/// `References` edge for whatever a write TARGET reads to locate its slot.
///
/// `t.Field = v` still reads `t` to find the struct and reads `Field` to name
/// the member being written, the same two names a read of `t.Field` produces;
/// only a bare local or global identifier target (`x = v`) is a pure write
/// with nothing underneath it to read, which [`collect_write_target_refs`]
/// is what excludes.
fn emit_write_target_references(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
    ref_seen: &mut ValueReadsSeen,
) {
    let mut reads = Vec::new();
    collect_write_target_refs(node, source, &mut reads);
    emit_references(reads, context_name, relations, ref_seen);
}

struct ValueReference {
    name: String,
    receiver: Option<String>,
    site: crate::extract::RelationSite,
}

/// Turn collected reads into deduplicated `References` relations.
///
/// Shared by the read side ([`emit_value_references`]) and the write side
/// ([`emit_write_target_references`]) so a name read while being written and
/// a name read while being used are recorded identically.
fn emit_references(
    reads: Vec<ValueReference>,
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
    ref_seen: &mut ValueReadsSeen,
) {
    for ValueReference {
        name,
        receiver,
        site,
    } in reads
    {
        if (receiver.is_some() || name != context_name)
            && ref_seen.insert((name.clone(), site.start_byte))
        {
            relations.push(ExtractedRelation {
                // The identifier that read the name. The linker merges the
                // evidence of every edge that resolves to the same
                // (source, destination, kind), so the sites of repeated reads
                // accumulate onto one relation.
                site: Some(site),
                receiver,
                call_shape: None,
                kind: kin_model::RelationKind::References,
                src_name: context_name.to_string(),
                dst_name: name,
                import_source: None,
            });
        }
    }
}

/// Collect the names a write TARGET reads to locate the slot it assigns into.
///
/// A bare identifier (`x` in `x = v`, whether freshly bound, an existing
/// local, or the blank `_`) is a pure write with nothing to read, so it
/// contributes nothing. `expression_list` unpacks a multi-assignment (`a,
/// t.Field = 1, 2`) so each target is judged on its own rather than as one
/// blob. Every other shape — a selector (`t.Field`), an index (`arr[i]`), a
/// pointer deref (`*p`) — genuinely reads something to find the slot, and is
/// handed to [`collect_value_refs`] once the bare-identifier case has been
/// ruled out, which is what lets `t.Field = v` collect both `t` and `Field`
/// the same way a read of `t.Field` does.
fn collect_write_target_refs(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut Vec<ValueReference>,
) {
    match node.kind() {
        // The blank identifier `_` arrives as a plain `identifier` node
        // whose text is "_", not a distinct node kind, so this arm already
        // covers it: nothing here pushes to `out` unconditionally.
        "identifier" => {}
        "expression_list" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_write_target_refs(&child, source, out);
            }
        }
        _ => collect_value_refs(node, source, out),
    }
}

/// Collect bare identifier and field names read as VALUES within an
/// expression subtree, each paired with the position it sits at.
///
/// Walks value expressions while pruning positions that are not value reads:
/// a call's callee (already captured as a `Calls` edge), a composite
/// literal's `type`, and a `keyed_element`'s key. Type identifiers and the
/// blank identifier `_` are never collected. The receiver of a method call
/// (`obj` in `obj.M()`), every call argument, and a selector's `.field`
/// (`t.Name`, read as `t` AND `Name`) ARE collected, since they are genuine
/// value reads — a struct field access is exactly the same shape as a
/// method call's receiver, just without the trailing `()`.
fn collect_value_refs(node: &tree_sitter::Node, source: &[u8], out: &mut Vec<ValueReference>) {
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source).unwrap_or("");
            if !name.is_empty() && name != "_" {
                out.push(ValueReference {
                    name: name.to_string(),
                    receiver: None,
                    site: crate::adapter::site_from_node(node),
                });
            }
        }
        // A selector's leaf belongs to its receiver, not to a free symbol
        // with the same spelling. Preserve the operand, including chained
        // selectors and call/index expressions, for conservative linking.
        "selector_expression" => {
            if let Some(operand) = node.child_by_field_name("operand") {
                collect_value_refs(&operand, source, out);
                if let Some(field) = node.child_by_field_name("field") {
                    let name = field.utf8_text(source).unwrap_or("");
                    let receiver = operand.utf8_text(source).unwrap_or("");
                    if !name.is_empty() && !receiver.is_empty() {
                        out.push(ValueReference {
                            name: name.to_string(),
                            receiver: Some(receiver.to_string()),
                            site: crate::adapter::site_from_node(&field),
                        });
                    }
                }
            }
        }
        // A call in value position contributes its receiver (for `obj.M()`) and
        // its arguments; the callee is captured as a `Calls` edge elsewhere.
        "call_expression" => {
            if let Some(function) = node.child_by_field_name("function") {
                if function.kind() == "selector_expression" {
                    if let Some(operand) = function.child_by_field_name("operand") {
                        collect_value_refs(&operand, source, out);
                    }
                }
            }
            if let Some(args) = node.child_by_field_name("arguments") {
                collect_value_refs(&args, source, out);
            }
        }
        // `T{...}`: element values are reads, the `type` field is not.
        "composite_literal" => {
            if let Some(body) = node.child_by_field_name("body") {
                collect_value_refs(&body, source, out);
            }
        }
        // `Key: Value`: only the value is a read (the key names a field).
        "keyed_element" => {
            if let Some(value) = node.child_by_field_name("value") {
                collect_value_refs(&value, source, out);
            }
        }
        // Leaf type positions are never value reads.
        "type_identifier" | "qualified_type" | "package_identifier" | "field_identifier" => {}
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_value_refs(&child, source, out);
            }
        }
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
        // A grouped `import ( ... )` produces one `FileImport` per
        // `import_spec`, so the statement span is already the spec's own line
        // and the group's opening line is never what either span reports.
        site: crate::adapter::site_from_node(node),
        module_path,
        specifiers: vec![ImportedName {
            local_name,
            original_name,
            is_default: false,
            site: Some(crate::adapter::site_from_node(node)),
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

    fn blank_names(source: &[u8]) -> Vec<String> {
        let adapter = GoAdapter;
        let tree = adapter.parse(source).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            String::from_utf8_lossy(source)
        );
        adapter
            .extract(&tree, source, &FilePathId::new("p/p.go"))
            .unwrap()
            .entities
            .into_iter()
            .filter(|e| e.kind == EntityKind::StaticVar && e.name.starts_with('_'))
            .map(|e| e.name)
            .collect()
    }

    /// A blank spec's identity is its tokens: literals are kept byte-exact, and
    /// only the trivia between tokens (spacing, line breaks, comments) is
    /// normalized away.
    #[test]
    fn blank_spec_identity_keeps_literals_exact_and_ignores_trivia() {
        // (a) Specs that differ only inside a literal are distinct.
        for (left, right) in [
            (r#"var _ = f("a  b")"#, r#"var _ = f("a b")"#),
            ("var _ = `a  b`", "var _ = `a b`"),
            ("var _ = `a\n\tb`", "var _ = `a b`"),
            ("var _ = ' '", "var _ = '\t'"),
        ] {
            let names = blank_names(format!("package p\n\n{left}\n{right}\n").as_bytes());
            assert_eq!(names.len(), 2, "{left} | {right}");
            assert_ne!(names[0], names[1], "{left} | {right}");
        }
        // (b) The same spec reformatted keeps its identity.
        let canonical = blank_names(b"package p\n\nvar _ Getter = (*Store)(nil)\n");
        assert_eq!(canonical, ["_ Getter = (*Store)(nil)"]);
        for reformatted in [
            "var _   Getter=( *Store )( nil ) // Store satisfies Getter.",
            "var _ Getter = (\n\t*Store /* the concrete type */)(nil)",
            "var (\n\t_ Getter = (*Store)(nil)\n)",
        ] {
            assert_eq!(
                blank_names(format!("package p\n\n{reformatted}\n").as_bytes()),
                canonical,
                "{reformatted}"
            );
        }
        // Operators that would merge if written together stay apart.
        let apart = blank_names(b"package p\n\nvar _ = a & ^b\nvar _ = a &^ b\n");
        assert_ne!(apart[0], apart[1]);
    }

    #[test]
    fn blank_identifier_specs_get_distinct_derived_names() {
        let adapter = GoAdapter;
        let source = b"package store\n\nvar _ Getter = (*Store)(nil)\nvar _   Getter =  (*Cache)(nil)\n\nvar (\n\t_ = fmt.Sprintf\n)\n\nvar keep = 1\n";
        let tree = adapter.parse(source).unwrap();
        let output = adapter
            .extract(&tree, source, &FilePathId::new("store/store.go"))
            .unwrap();
        let mut names = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::StaticVar)
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                "_ = fmt.Sprintf",
                "_ Getter = (*Cache)(nil)",
                "_ Getter = (*Store)(nil)",
                "keep"
            ]
        );
    }

    #[test]
    fn grouped_vars_and_type_aliases_declare_entities() {
        let adapter = GoAdapter;
        let source = b"package store\n\nvar (\n\tErrMissing = errNew()\n\tlimit int\n)\n\nvar single = 1\n\ntype Key = string\n\ntype ID string\n";
        let tree = adapter.parse(source).unwrap();
        let output = adapter
            .extract(&tree, source, &FilePathId::new("store/store.go"))
            .unwrap();
        let named = |kind: EntityKind| {
            let mut names = output
                .entities
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        assert_eq!(
            named(EntityKind::StaticVar),
            ["ErrMissing", "limit", "single"]
        );
        assert_eq!(named(EntityKind::TypeAlias), ["ID", "Key"]);
        let alias = output.entities.iter().find(|e| e.name == "Key").unwrap();
        assert_eq!(
            &source[alias.span.start_byte..alias.span.end_byte],
            b"Key = string"
        );
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
        // Selector calls now emit the simple rightmost name; the package
        // qualifier (`fmt`) is preserved only via `import_source`.
        assert!(
            dst_names.contains(&"Println"),
            "expected simple-name 'Println' in {:?}",
            dst_names
        );
        assert!(dst_names.contains(&"doStuff"));
        let println_rel = calls.iter().find(|c| c.dst_name == "Println").unwrap();
        assert_eq!(println_rel.import_source.as_deref(), Some("fmt"));
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

    #[test]
    fn infer_implicit_interface_satisfaction() {
        let adapter = GoAdapter;
        let source = br#"
package shapes

type Shape interface {
    Area() float64
    Perimeter() float64
}

type Circle struct {
    Radius float64
}

func (c Circle) Area() float64 {
    return 3.14 * c.Radius * c.Radius
}

func (c Circle) Perimeter() float64 {
    return 2 * 3.14 * c.Radius
}

func (c Circle) String() string {
    return "circle"
}

// Square only implements Area, not Perimeter -- should NOT satisfy Shape.
type Square struct {
    Side float64
}

func (s Square) Area() float64 {
    return s.Side * s.Side
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("shapes.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let impls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Implements)
            .collect();

        // Circle has Area + Perimeter → satisfies Shape
        assert!(
            impls
                .iter()
                .any(|r| r.src_name == "Circle" && r.dst_name == "Shape"),
            "Circle should implement Shape, found: {:?}",
            impls
        );
        // Square only has Area → does NOT satisfy Shape
        assert!(
            !impls
                .iter()
                .any(|r| r.src_name == "Square" && r.dst_name == "Shape"),
            "Square should NOT implement Shape (missing Perimeter)"
        );
    }

    #[test]
    fn interface_methods_are_first_class_entities() {
        let adapter = GoAdapter;
        let source = br#"
package shapes

// Shape is the contract for closed figures.
type Shape interface {
    // Area returns the enclosed area.
    Area() float64
    Perimeter() float64
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("shapes.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        let area = methods
            .iter()
            .find(|e| e.name == "Shape.Area")
            .unwrap_or_else(|| panic!("Shape.Area must be a Method entity, got: {methods:?}"));
        assert_eq!(area.visibility, Visibility::Public);
        assert_eq!(area.signature, "Area() float64");
        assert!(
            area.span.start_line > 0,
            "interface method span must point at the method spec line"
        );
        assert!(
            methods.iter().any(|e| e.name == "Shape.Perimeter"),
            "Shape.Perimeter must be a Method entity"
        );

        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .collect();
        assert!(
            contains
                .iter()
                .any(|r| r.src_name == "Shape" && r.dst_name == "Shape.Area"),
            "Shape should contain Shape.Area, found: {contains:?}"
        );
    }

    #[test]
    fn embedded_interface_expands_contract_and_extends() {
        let adapter = GoAdapter;
        let source = br#"
package io

type Reader interface {
    Read(p []byte) (int, error)
}

type ReadCloser interface {
    Reader
    Close() error
}

// OnlyClose has Close but not Read: must NOT satisfy ReadCloser.
type OnlyClose struct{}

func (o OnlyClose) Close() error { return nil }

// File has both: satisfies Reader AND ReadCloser.
type File struct{}

func (f File) Read(p []byte) (int, error) { return 0, nil }

func (f File) Close() error { return nil }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("io.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert!(
            extends
                .iter()
                .any(|r| r.src_name == "ReadCloser" && r.dst_name == "Reader"),
            "ReadCloser should extend embedded Reader, found: {extends:?}"
        );

        let impls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Implements)
            .collect();
        assert!(
            impls
                .iter()
                .any(|r| r.src_name == "File" && r.dst_name == "ReadCloser"),
            "File (Read+Close) should implement ReadCloser via embedded expansion, found: {impls:?}"
        );
        assert!(
            impls
                .iter()
                .any(|r| r.src_name == "File" && r.dst_name == "Reader"),
            "File should implement Reader, found: {impls:?}"
        );
        assert!(
            !impls
                .iter()
                .any(|r| r.src_name == "OnlyClose" && r.dst_name == "ReadCloser"),
            "OnlyClose (missing Read) must NOT implement ReadCloser — embedded methods are \
             part of the contract, found: {impls:?}"
        );
    }

    #[test]
    fn detect_embedded_struct_extends() {
        let adapter = GoAdapter;
        let source = br#"
package shapes

type Shape interface {
    Area() float64
}

type Circle struct {
    Radius float64
}

type LabeledCircle struct {
    Circle
    Label string
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("shapes.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();

        assert!(
            extends
                .iter()
                .any(|r| r.src_name == "LabeledCircle" && r.dst_name == "Circle"),
            "LabeledCircle should extend Circle via embedding, found: {:?}",
            extends
        );
    }

    #[test]
    fn internal_package_visibility() {
        let adapter = GoAdapter;
        let source = b"package core\n\nfunc HandleRequest() {}";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("internal/core/handler.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "HandleRequest");
        assert_eq!(
            funcs[0].visibility,
            Visibility::Internal,
            "functions in internal/ should have Internal visibility"
        );
    }

    #[test]
    fn struct_contains_method() {
        let adapter = GoAdapter;
        let source = br#"
package main

import "fmt"

type Server struct { port int }

func (s *Server) Start() { fmt.Println("starting") }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("server.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .collect();

        assert!(
            contains
                .iter()
                .any(|r| r.src_name == "Server" && r.dst_name == "Server.Start"),
            "Server should contain Server.Start, found: {:?}",
            contains
        );
    }

    #[test]
    fn parse_go_channel_send() {
        let adapter = GoAdapter;
        let source = b"package main\nfunc producer(ch chan int) {\n    ch <- 42\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let sends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::SendsMessage)
            .collect();
        assert_eq!(sends.len(), 1, "expected 1 SendsMessage, got {:?}", sends);
        assert_eq!(sends[0].src_name, "producer");
        assert_eq!(sends[0].dst_name, "ch");
    }

    #[test]
    fn parse_go_goroutine_spawn() {
        let adapter = GoAdapter;
        let source =
            b"package main\nfunc main() {\n    go processItem()\n}\nfunc processItem() {}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("main.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let spawns: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Spawns)
            .collect();
        assert_eq!(spawns.len(), 1, "expected 1 Spawns, got {:?}", spawns);
        assert_eq!(spawns[0].src_name, "main");
        assert_eq!(spawns[0].dst_name, "processItem");
    }

    fn go_references(output: &ParseOutput) -> Vec<(&str, &str)> {
        output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::References)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect()
    }

    #[test]
    fn command_effect_contract_captures_git_branch_binding() {
        let adapter = GoAdapter;
        let source = br#"
package command

import (
    "fmt"
    "os/exec"

    "github.com/spf13/cobra"
)

func prCheckout(cmd *cobra.Command, args []string) error {
    newBranchName := fmt.Sprintf("pr/%d/%s", pr.Number, pr.HeadRefName)
    if git.VerifyRef("refs/heads/" + newBranchName) {
        cmdQueue = append(cmdQueue, []string{"git", "checkout", newBranchName})
    } else {
        cmdQueue = append(cmdQueue, []string{"git", "checkout", "-b", newBranchName, "--no-track", remoteBranch})
    }
    exec.Command("git", "config", fmt.Sprintf("branch.%s.remote", newBranchName), remote)
    return nil
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("checkout.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let mut entities: Vec<_> = output
            .entities
            .into_iter()
            .map(|entity| entity.into_entity(LanguageId::Go, &file_id))
            .collect();
        attach_go_command_effect_contract_metadata(&tree, source, &mut entities);
        let entity = entities
            .iter()
            .find(|entity| entity.name == "prCheckout")
            .expect("handler entity should exist");
        let contract = entity
            .metadata
            .extra
            .get(COMMAND_EFFECT_CONTRACT_KEY)
            .expect("command contract metadata should be attached")
            .to_string();

        assert!(
            contract.contains("queued_git_argv"),
            "queued git argv effects should be captured: {contract}"
        );
        assert!(
            contract.contains("subprocess_argv"),
            "direct exec.Command effects should be captured: {contract}"
        );
        assert!(
            contract.contains("fmt.Sprintf(\\\"pr/%d/%s\\\", pr.Number, pr.HeadRefName)"),
            "branch-name binding should be captured: {contract}"
        );
    }

    #[test]
    fn debug_print_change_does_not_emit_command_effect_contract() {
        let adapter = GoAdapter;
        let source = br#"
package command

import "fmt"

func prCheckout() error {
    fmt.Println("debug")
    return nil
}
"#;
        let tree = adapter.parse(source).unwrap();
        assert!(
            extract_go_command_effect_contracts(&tree, source).is_empty(),
            "debug-only output must not become a command-effect contract"
        );
    }

    #[test]
    fn command_effect_contract_uses_bindings_at_call_site() {
        let adapter = GoAdapter;
        let source = br#"
package command

import (
    "fmt"
    "os/exec"
)

func prCheckout() error {
    newBranchName := pr.HeadRefName
    exec.Command("git", "checkout", newBranchName)
    newBranchName = fmt.Sprintf("pr/%d/%s", pr.Number, pr.HeadRefName)
    exec.Command("git", "config", fmt.Sprintf("branch.%s.remote", newBranchName), "origin")
    return nil
}
"#;
        let tree = adapter.parse(source).unwrap();
        let contracts = extract_go_command_effect_contracts(&tree, source);
        let contract = contracts
            .get("prCheckout")
            .expect("contract should be extracted");
        let effects = contract["effects"].as_array().expect("effects array");
        assert_eq!(effects.len(), 2, "expected two command effects: {contract}");
        assert_eq!(
            effects[0]["bindings"]["newBranchName"], "pr.HeadRefName",
            "first command must use the binding visible before reassignment"
        );
        assert_eq!(
            effects[1]["bindings"]["newBranchName"],
            "fmt.Sprintf(\"pr/%d/%s\", pr.Number, pr.HeadRefName)",
            "second command must use the reassigned binding"
        );
    }

    #[test]
    fn command_effect_contract_attaches_to_go_methods() {
        let adapter = GoAdapter;
        let source = br#"
package command

import "os/exec"

type Runner struct{}

func (r *Runner) prCheckout() error {
    newBranchName := pr.HeadRefName
    exec.Command("git", "checkout", newBranchName)
    return nil
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("checkout.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let mut entities: Vec<_> = output
            .entities
            .into_iter()
            .map(|entity| entity.into_entity(LanguageId::Go, &file_id))
            .collect();
        attach_go_command_effect_contract_metadata(&tree, source, &mut entities);
        let entity = entities
            .iter()
            .find(|entity| entity.name == "Runner.prCheckout")
            .expect("method entity should be qualified by receiver type");
        assert!(
            entity
                .metadata
                .extra
                .contains_key(COMMAND_EFFECT_CONTRACT_KEY),
            "command-effect metadata should attach to method entities"
        );
    }

    #[test]
    fn func_value_in_composite_literal_emits_reference() {
        // cobra-style: a function passed by name as a struct-field value
        // (`RunE: prCheckout`) must reference the handler, not silently drop it.
        let adapter = GoAdapter;
        let source = br#"
package cmd

func prCheckout() {}

func newCmd() {
    cmd := &Command{RunE: prCheckout}
    _ = cmd
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("cmd.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let refs = go_references(&output);
        assert!(
            refs.contains(&("newCmd", "prCheckout")),
            "newCmd should reference prCheckout via the RunE field value, found: {refs:?}"
        );
        // The struct type name and the field key are not value reads.
        assert!(
            !refs
                .iter()
                .any(|(_, dst)| *dst == "Command" || *dst == "RunE"),
            "composite-literal type name and keys must not be referenced, found: {refs:?}"
        );
    }

    #[test]
    fn package_var_initializer_references_function_value() {
        // `var prCheckoutCmd = &cobra.Command{RunE: prCheckout}` must yield a
        // References edge prCheckoutCmd -> prCheckout so a change to the handler
        // shows impact on the command var.
        let adapter = GoAdapter;
        let source = br#"
package cmd

import "github.com/spf13/cobra"

func prCheckout(cmd *cobra.Command, args []string) error { return nil }

var prCheckoutCmd = &cobra.Command{
    Use:  "checkout",
    RunE: prCheckout,
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("checkout.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let refs = go_references(&output);
        assert!(
            refs.contains(&("prCheckoutCmd", "prCheckout")),
            "package var initializer should reference prCheckout, found: {refs:?}"
        );
        // `cobra.Command` is the composite type, not a value read.
        assert!(
            !refs.iter().any(|(_, dst)| *dst == "Command"),
            "composite-literal type must not be referenced, found: {refs:?}"
        );
    }

    #[test]
    fn call_argument_var_emits_reference_not_the_callee() {
        // A package-level var passed as a call argument
        // (`RunCommand(prCheckoutCmd, ...)`) must be referenced; the callee is a
        // Call, never a References edge.
        let adapter = GoAdapter;
        let source = br#"
package cmd

var prCheckoutCmd = 0

func run() {
    RunCommand(prCheckoutCmd, "arg")
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("run.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let refs = go_references(&output);
        assert!(
            refs.contains(&("run", "prCheckoutCmd")),
            "run should reference prCheckoutCmd passed as an argument, found: {refs:?}"
        );
        assert!(
            !refs.iter().any(|(_, dst)| *dst == "RunCommand"),
            "the callee must be a Calls edge, not a References edge, found: {refs:?}"
        );
        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert!(
            calls.contains(&("run", "RunCommand")),
            "run should still Call RunCommand, found: {calls:?}"
        );
    }

    #[test]
    fn package_const_read_in_body_emits_reference() {
        // A plain read of a package-level const inside a body is a reference.
        let adapter = GoAdapter;
        let source = br#"
package cmd

const defaultConfigStr = "default"

func load() string {
    return defaultConfigStr
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("load.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let refs = go_references(&output);
        assert!(
            refs.contains(&("load", "defaultConfigStr")),
            "load should reference defaultConfigStr it returns, found: {refs:?}"
        );
    }

    #[test]
    fn value_references_skip_lhs_types_and_blank() {
        // Binding names (LHS), type identifiers, keys, and the blank identifier
        // are not value reads — keep References targeted to bound noise.
        let adapter = GoAdapter;
        let source = br#"
package cmd

type Config struct { Name string }

func handler() {}

func build() {
    var h = handler
    _ = h
    cfg := Config{Name: "x"}
    _ = cfg
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("build.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let refs = go_references(&output);
        assert!(
            refs.contains(&("build", "handler")),
            "the RHS function value `handler` should be referenced, found: {refs:?}"
        );
        assert!(
            !refs
                .iter()
                .any(|(_, dst)| matches!(*dst, "Config" | "Name" | "_")),
            "type name, struct key, and blank identifier must not be referenced, found: {refs:?}"
        );
        // A reference edge is deduped to one per (src, dst) within a body.
        assert_eq!(
            refs.iter().filter(|(_, dst)| *dst == "handler").count(),
            1,
            "handler should be referenced exactly once, found: {refs:?}"
        );
    }

    #[test]
    fn struct_field_is_a_first_class_entity() {
        let adapter = GoAdapter;
        let source = br#"
package task

type Task struct {
    Name string
    X, Y int
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("task.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let fields: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Field)
            .collect();
        let name_field = fields
            .iter()
            .find(|e| e.name == "Task.Name")
            .unwrap_or_else(|| panic!("Task.Name must be a Field entity, got: {fields:?}"));
        assert_eq!(name_field.visibility, Visibility::Public);
        assert_eq!(name_field.signature, "Name string");
        assert!(
            name_field.span.start_line > 0,
            "the field's span must point at its declaration line"
        );

        // A field_declaration naming several fields off one type (`X, Y int`)
        // mints one entity per name, not one entity for the whole line.
        assert!(
            fields.iter().any(|e| e.name == "Task.X"),
            "Task.X must be a Field entity, got: {fields:?}"
        );
        assert!(
            fields.iter().any(|e| e.name == "Task.Y"),
            "Task.Y must be a Field entity, got: {fields:?}"
        );

        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .collect();
        assert!(
            contains
                .iter()
                .any(|r| r.src_name == "Task" && r.dst_name == "Task.Name"),
            "Task should contain Task.Name, found: {contains:?}"
        );
    }

    #[test]
    fn embedded_field_is_not_minted_as_a_field_entity() {
        // An embedded field (a type with no name of its own) already produces
        // an Extends relation; it must not also become a Field entity named
        // after the embedder, which would misrepresent it as a member Task
        // itself declares.
        let adapter = GoAdapter;
        let source = br#"
package task

type Base struct {
    ID string
}

type Task struct {
    Base
    Name string
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("task.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let fields: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Field)
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            fields.contains(&"Task.Name"),
            "the real field must still be minted, found: {fields:?}"
        );
        assert!(
            !fields.contains(&"Task.Base"),
            "an embedded type must not be minted as a field entity, found: {fields:?}"
        );
    }

    #[test]
    fn struct_field_reads_and_writes_emit_references_with_sites() {
        // A field read as a call argument in one function and written by
        // assignment in another. Both must produce a `References` edge to the
        // bare field name (the linker resolves it to `Task.Name`, mirroring
        // how a bare method name resolves to `Owner.Method`), each carrying
        // the line the access is written on.
        let adapter = GoAdapter;
        let source = br#"
package task

import "fmt"

type Task struct {
    Name string
}

func describe(t Task) {
    fmt.Println(t.Name)
}

func rename(t *Task, next string) {
    t.Name = next
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("task.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let refs = go_references(&output);

        assert!(
            refs.contains(&("describe", "Name")),
            "the argument read t.Name must reference the bare field name, found: {refs:?}"
        );
        assert!(
            refs.contains(&("rename", "Name")),
            "the assignment target t.Name must reference the bare field name, found: {refs:?}"
        );

        let read_line = source
            .split(|&b| b == b'\n')
            .position(|line| line.ends_with(b"fmt.Println(t.Name)"))
            .expect("the read line exists in the fixture");
        let write_line = source
            .split(|&b| b == b'\n')
            .position(|line| line.ends_with(b"t.Name = next"))
            .expect("the write line exists in the fixture");

        let name_sites: Vec<u32> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::References && r.dst_name == "Name")
            .filter_map(|r| r.site.as_ref())
            .map(|site| site.start_line)
            .collect();
        assert!(
            name_sites.contains(&(read_line as u32)),
            "the read site must carry the line t.Name is read on, found: {name_sites:?}"
        );
        assert!(
            name_sites.contains(&(write_line as u32)),
            "the write site must carry the line t.Name is written on, found: {name_sites:?}"
        );

        // The receiver `t` is a genuine value read in both cases too — a
        // struct field access reads its receiver the same way a method call
        // does.
        assert!(
            refs.contains(&("describe", "t")) || refs.contains(&("rename", "t")),
            "the receiver `t` should also be read, found: {refs:?}"
        );
    }

    /// A file whose bytes declare nothing mints no module surface.
    ///
    /// The surface is synthetic: it stands for the file, not for anything the
    /// file wrote. Minting it unconditionally made a comment-only or unreadable
    /// file count as parsed, so the parse-coverage census read a clean row for a
    /// repository holding a hole and could not name the file. Rust carried this
    /// rule already; these adapters did not.
    #[test]
    fn comment_only_go_file_mints_no_module_surface() {
        let adapter = GoAdapter;
        let source = b"// nothing is declared here\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/silent.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        // A comment is valid source, not a broken file. The census separates
        // the two, and only a file that parses clean and declares nothing is
        // the case this rule is about.
        assert!(matches!(output.parse_state, ParseState::Valid));
        assert!(
            output.entities.is_empty(),
            "expected no entity, got {:?}",
            output
                .entities
                .iter()
                .map(|e| (e.kind, e.name.as_str()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn go_file_with_one_declaration_mints_the_module_surface() {
        let adapter = GoAdapter;
        let source = b"package store\n\nfunc Get() {}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/store.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "store");
        assert_eq!(output.entities[0].kind, EntityKind::Module);
    }

    /// An import alone is a surface too, and the edge is sourced at the module.
    #[test]
    fn go_file_with_only_an_import_mints_the_module_surface() {
        let adapter = GoAdapter;
        let source = b"package store\n\nimport \"fmt\"\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/store.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(!output.imports.is_empty());
        assert_eq!(output.entities[0].kind, EntityKind::Module);
    }

    /// A file holding only its package coordinate mints no module surface
    /// either, and that is deliberate.
    ///
    /// The coordinate names the module; it does not declare anything inside it.
    /// A file that writes only the coordinate produced no declaration and no
    /// import, so it reaches the parse-coverage census as a file holding no
    /// entity, which is what it is. Rust reads the same way for a file holding
    /// only `//! docs`.
    #[test]
    fn package_clause_only_go_file_mints_no_module_surface() {
        let adapter = GoAdapter;
        let source = b"package store\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/store.go");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        assert!(
            output.entities.is_empty(),
            "expected no entity, got {:?}",
            output
                .entities
                .iter()
                .map(|e| (e.kind, e.name.as_str()))
                .collect::<Vec<_>>()
        );
    }
}
