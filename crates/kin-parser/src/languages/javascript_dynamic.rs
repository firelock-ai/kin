// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Census computed writes independently of the bounded candidate-name resolver.
//! Literal syntax suggests names; it never proves execution or runtime membership.

use crate::adapter::{compute_fingerprint, declaration_signature, span_from_node};
use crate::extract::ExtractedDerivedMember;
use kin_model::FilePathId;
use tree_sitter::Node;

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}
fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}
fn plain_string(node: Node<'_>, source: &[u8]) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = text(node, source);
    // Escape decoding is outside this rule: do not confuse spelling with a key.
    if raw.len() < 2 || raw.contains('\\') {
        return None;
    }
    Some(raw[1..raw.len() - 1].to_owned())
}
fn literal_values(node: Node<'_>, source: &[u8]) -> Option<Vec<String>> {
    if node.kind() != "array" {
        return None;
    }
    // Token alternation catches sparse arrays even when they have a trailing comma.
    let nodes: Vec<_> = children(node)
        .into_iter()
        .filter(|n| !n.is_extra())
        .collect();
    let mut cursor = node.walk();
    let mut expect_value = true;
    for child in node.children(&mut cursor).filter(|n| !n.is_extra()) {
        match child.kind() {
            "[" | "]" => {}
            "," if !expect_value => expect_value = true,
            "string" if expect_value => expect_value = false,
            _ => return None,
        }
    }
    let mut keys: Vec<String> = nodes
        .into_iter()
        .map(|n| plain_string(n, source))
        .collect::<Option<_>>()?;
    keys.sort();
    keys.dedup();
    Some(keys)
}
fn identifiers(node: Node<'_>, name: &str, source: &[u8], out: &mut Vec<usize>) {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
    ) && text(node, source) == name
    {
        out.push(node.start_byte());
    }
    for child in children(node) {
        identifiers(child, name, source, out);
    }
}

/// Follow only a preceding top-level const with no other references anywhere.
/// `const` protects the binding, not the array: mutation, escape and shadowing
/// are conservatively excluded by accounting for every identifier occurrence.
fn values(
    root: Node<'_>,
    iterable: Node<'_>,
    allowed_uses: &[usize],
    source: &[u8],
) -> Option<Vec<String>> {
    if let Some(keys) = literal_values(iterable, source) {
        return Some(keys);
    }
    if iterable.kind() != "identifier" {
        return None;
    }
    let name = text(iterable, source);
    for declaration in children(root) {
        if declaration.kind() != "lexical_declaration"
            || declaration.child_by_field_name("kind").map(|n| n.kind()) != Some("const")
        {
            continue;
        }
        for binding in children(declaration) {
            let Some(id) = binding.child_by_field_name("name") else {
                continue;
            };
            if id.kind() != "identifier" || text(id, source) != name {
                continue;
            }
            let value = binding.child_by_field_name("value")?;
            if value.end_byte() >= iterable.start_byte() {
                return None;
            }
            let mut uses = Vec::new();
            identifiers(root, name, source, &mut uses);
            let mut allowed = allowed_uses.to_vec();
            allowed.push(id.start_byte());
            uses.sort_unstable();
            allowed.sort_unstable();
            allowed.dedup();
            if uses != allowed {
                return None;
            }
            return literal_values(value, source);
        }
    }
    None
}
fn binding_written_or_shadowed(node: Node<'_>, name: &str, source: &[u8]) -> bool {
    // `with` introduces a runtime object environment for bare identifier reads.
    if node.kind() == "with_statement" {
        return true;
    }
    let field = match node.kind() {
        "assignment_expression" | "augmented_assignment_expression" | "for_in_statement" => {
            Some("left")
        }
        "catch_clause" => Some("parameter"),
        "variable_declarator" => Some("name"),
        "update_expression" => Some("argument"),
        _ => None,
    };
    if field
        .and_then(|field| node.child_by_field_name(field))
        .is_some_and(|n| text(n, source) == name)
    {
        return true;
    }
    // Destructuring and function/class declarations can bind the same spelling.
    if matches!(
        node.kind(),
        "object_pattern"
            | "array_pattern"
            | "formal_parameters"
            | "function_declaration"
            | "class_declaration"
    ) {
        let mut ids = Vec::new();
        identifiers(node, name, source, &mut ids);
        if !ids.is_empty() {
            return true;
        }
    }
    children(node)
        .into_iter()
        .any(|n| binding_written_or_shadowed(n, name, source))
}

fn first_parameter(node: Node<'_>, source: &[u8]) -> Option<String> {
    let parameter = node.child_by_field_name("parameter").or_else(|| {
        node.child_by_field_name("parameters")
            .and_then(|p| children(p).first().copied())
    })?;
    (parameter.kind() == "identifier").then(|| text(parameter, source).to_owned())
}
fn callable(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_expression" | "function" | "arrow_function" | "generator_function"
    )
}

fn candidate_rule<'t>(
    root: Node<'t>,
    key: Node<'t>,
    ancestors: &[Node<'t>],
    source: &[u8],
) -> (Vec<String>, &'static str, Vec<String>, Node<'t>) {
    let mut conditions = vec![
        "runtime_execution_and_final_membership_unproven".to_owned(),
        "receiver_identity_unproven".to_owned(),
    ];
    let mut generator = *ancestors.last().unwrap_or(&key);
    for ancestor in ancestors.iter().rev().copied() {
        if ancestor.kind() == "for_in_statement" {
            generator = ancestor;
            if ancestor
                .child_by_field_name("operator")
                .map(|n| text(n, source))
                == Some("in")
            {
                conditions.push("enumerable_keys_including_inherited_keys_unresolved".into());
                return (vec![], "for_in_unresolved", conditions, generator);
            }
            let left = ancestor.child_by_field_name("left");
            if key.kind() == "identifier"
                && left.is_some_and(|n| text(n, source) == text(key, source))
            {
                if let Some(iterable) = ancestor.child_by_field_name("right") {
                    if ancestor.child_by_field_name("body").is_some_and(|body| {
                        binding_written_or_shadowed(body, text(key, source), source)
                    }) {
                        conditions.push("loop_key_reassigned_or_shadowed".into());
                        return (vec![], "loop_key_unresolved", conditions, generator);
                    }
                    let keys = values(root, iterable, &[iterable.start_byte()], source)
                        .unwrap_or_default();
                    if keys.is_empty() {
                        conditions.push(
                            "iterable_values_mutation_escape_or_dependency_unresolved".into(),
                        );
                    }
                    conditions.push("iterator_behavior_unproven".into());
                    return (keys, "for_of_literal_candidates", conditions, generator);
                }
            }
            conditions.push("key_binding_or_shadowing_unresolved".into());
            return (vec![], "loop_key_unresolved", conditions, generator);
        }
        if ancestor.kind() == "for_statement" {
            generator = ancestor;
            // Read the actual initializer, condition and increment, not just a
            // convenient `.length` somewhere in the loop header.
            if key.kind() == "subscript_expression" {
                if let (Some(array), Some(index), Some(init), Some(cond), Some(increment)) = (
                    key.child_by_field_name("object"),
                    key.child_by_field_name("index"),
                    ancestor.child_by_field_name("initializer"),
                    ancestor.child_by_field_name("condition"),
                    ancestor.child_by_field_name("increment"),
                ) {
                    let compact = |n| {
                        text(n, source)
                            .chars()
                            .filter(|c| !c.is_whitespace())
                            .collect::<String>()
                    };
                    let counter = text(index, source);
                    let list = text(array, source);
                    let init_text = compact(init);
                    let valid_init = ["var", "let"].iter().any(|kind| {
                        init_text.trim_end_matches(';') == format!("{kind}{counter}=0")
                    });
                    if index.kind() == "identifier"
                        && array.kind() == "identifier"
                        && valid_init
                        && compact(cond) == format!("{counter}<{list}.length")
                        && [format!("{counter}++"), format!("++{counter}")]
                            .contains(&compact(increment))
                    {
                        let mut list_uses = Vec::new();
                        identifiers(ancestor, list, source, &mut list_uses);
                        let mut counter_uses = Vec::new();
                        identifiers(ancestor, counter, source, &mut counter_uses);
                        // Header + indexed write only. Extra uses can mutate,
                        // escape, shadow or alter control flow; leave a floor.
                        if list_uses.len() == 2 && counter_uses.len() == 4 {
                            let keys = values(root, array, &list_uses, source).unwrap_or_default();
                            if !keys.is_empty() {
                                return (
                                    keys,
                                    "counting_for_literal_candidates",
                                    conditions,
                                    generator,
                                );
                            }
                        }
                    }
                }
            }
            conditions.push("counting_loop_bounds_increment_or_mutation_unresolved".into());
            return (vec![], "counting_for_unresolved", conditions, generator);
        }
        if callable(ancestor) {
            let parent = ancestor.parent();
            let call = parent
                .filter(|n| n.kind() == "arguments")
                .and_then(|n| n.parent());
            if let Some(call) = call.filter(|n| n.kind() == "call_expression") {
                if let Some(callee) = call
                    .child_by_field_name("function")
                    .filter(|n| n.kind() == "member_expression")
                {
                    if let (Some(property), Some(iterable)) = (
                        callee.child_by_field_name("property"),
                        callee.child_by_field_name("object"),
                    ) {
                        if matches!(text(property, source), "forEach" | "map") {
                            generator = call;
                            let first_arg = call
                                .child_by_field_name("arguments")
                                .and_then(|n| children(n).first().copied());
                            if first_arg == Some(ancestor)
                                && key.kind() == "identifier"
                                && first_parameter(ancestor, source).as_deref()
                                    == Some(text(key, source))
                            {
                                let mut parameter_uses = Vec::new();
                                if let Some(parameters) = ancestor
                                    .child_by_field_name("parameters")
                                    .or_else(|| ancestor.child_by_field_name("parameter"))
                                {
                                    identifiers(
                                        parameters,
                                        text(key, source),
                                        source,
                                        &mut parameter_uses,
                                    );
                                }
                                if parameter_uses.len() != 1
                                    || ancestor.child_by_field_name("body").is_some_and(|body| {
                                        binding_written_or_shadowed(body, text(key, source), source)
                                    })
                                {
                                    conditions.push("callback_key_reassigned_or_shadowed".into());
                                    return (
                                        vec![],
                                        "callback_key_unresolved",
                                        conditions,
                                        generator,
                                    );
                                }
                                let keys = values(root, iterable, &[iterable.start_byte()], source)
                                    .unwrap_or_default();
                                if keys.is_empty() {
                                    conditions.push(
                                        "iterable_values_mutation_escape_or_dependency_unresolved"
                                            .into(),
                                    );
                                }
                                conditions.push(
                                    "callback_dispatch_and_array_method_behavior_unproven".into(),
                                );
                                return (
                                    keys,
                                    "callback_literal_candidates",
                                    conditions,
                                    generator,
                                );
                            }
                        }
                    }
                }
            }
            // Never bind an outer loop through a function boundary.
            conditions.push("function_scope_or_callback_binding_unresolved".into());
            break;
        }
        if matches!(
            ancestor.kind(),
            "if_statement"
                | "switch_statement"
                | "try_statement"
                | "while_statement"
                | "do_statement"
        ) {
            conditions.push("conditional_or_repeated_execution_unproven".into());
        }
    }
    if let Some(key) = plain_string(key, source) {
        return (vec![key], "literal_key_candidate", conditions, generator);
    }
    conditions.push("computed_key_unresolved".into());
    (vec![], "computed_write_unresolved", conditions, generator)
}

pub(super) fn extract(
    root: &Node<'_>,
    source: &[u8],
    file: &FilePathId,
) -> Vec<ExtractedDerivedMember> {
    fn walk<'t>(
        root: Node<'t>,
        node: Node<'t>,
        ancestors: &mut Vec<Node<'t>>,
        source: &[u8],
        file: &FilePathId,
        out: &mut Vec<ExtractedDerivedMember>,
    ) {
        if matches!(
            node.kind(),
            "assignment_expression" | "augmented_assignment_expression"
        ) {
            if let Some(left) = node
                .child_by_field_name("left")
                .filter(|n| n.kind() == "subscript_expression")
            {
                if let (Some(owner), Some(key), Some(value)) = (
                    left.child_by_field_name("object"),
                    left.child_by_field_name("index"),
                    node.child_by_field_name("right"),
                ) {
                    let (mut keys, rule, mut conditions, mut generator) =
                        candidate_rule(root, key, ancestors, source);
                    let owner =
                        (owner.kind() == "identifier").then(|| text(owner, source).to_owned());
                    if owner.is_none() {
                        keys.clear();
                        conditions.push("receiver_expression_unresolved".into());
                    }
                    if node.kind() != "assignment_expression" {
                        keys.clear();
                        conditions.push("compound_write_unresolved".into());
                    }
                    if generator.start_byte() > node.start_byte()
                        || generator.end_byte() < node.end_byte()
                    {
                        generator = node;
                    }
                    conditions.sort();
                    conditions.dedup();
                    out.push(ExtractedDerivedMember {
                        fingerprint: compute_fingerprint(&node, source),
                        owner,
                        keys,
                        callable: callable(value),
                        signature: declaration_signature(&value, source),
                        generator: span_from_node(&generator, file),
                        assignment: span_from_node(&node, file),
                        rule: rule.into(),
                        conditions,
                    });
                }
            }
        }
        if matches!(node.kind(), "update_expression" | "unary_expression") {
            if let Some(target) = node
                .child_by_field_name("argument")
                .filter(|n| n.kind() == "subscript_expression")
            {
                if node.kind() == "update_expression"
                    || node
                        .child_by_field_name("operator")
                        .is_some_and(|n| text(n, source) == "delete")
                {
                    let owner = target
                        .child_by_field_name("object")
                        .filter(|n| n.kind() == "identifier")
                        .map(|n| text(n, source).to_owned());
                    out.push(ExtractedDerivedMember {
                        fingerprint: compute_fingerprint(&node, source),
                        owner,
                        keys: vec![],
                        callable: false,
                        signature: declaration_signature(&node, source),
                        generator: span_from_node(&node, file),
                        assignment: span_from_node(&node, file),
                        rule: "computed_mutation_unresolved".into(),
                        conditions: vec![
                            "computed_update_or_delete_changes_runtime_membership".into()
                        ],
                    });
                }
            }
        }
        // Assignment patterns and iteration targets can write bracket members
        // without an assignment-expression node at the member itself.
        let pattern = if matches!(node.kind(), "assignment_expression" | "for_in_statement") {
            node.child_by_field_name("left").filter(|left| {
                matches!(left.kind(), "object_pattern" | "array_pattern")
                    || node.kind() == "for_in_statement" && left.kind() == "subscript_expression"
            })
        } else {
            None
        };
        if let Some(pattern) = pattern {
            fn targets<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
                if node.kind() == "subscript_expression" {
                    out.push(node);
                    return;
                }
                for child in children(node) {
                    targets(child, out);
                }
            }
            let mut writes = Vec::new();
            targets(pattern, &mut writes);
            for target in writes {
                out.push(ExtractedDerivedMember {
                    fingerprint: compute_fingerprint(&node, source),
                    owner: target
                        .child_by_field_name("object")
                        .filter(|n| n.kind() == "identifier")
                        .map(|n| text(n, source).to_owned()),
                    keys: vec![],
                    callable: false,
                    signature: declaration_signature(&node, source),
                    generator: span_from_node(&node, file),
                    assignment: span_from_node(&node, file),
                    rule: "computed_pattern_or_iteration_write_unresolved".into(),
                    conditions: vec!["pattern_or_iteration_target_membership_unresolved".into()],
                });
            }
        }
        ancestors.push(node);
        for child in children(node) {
            walk(root, child, ancestors, source, file, out);
        }
        ancestors.pop();
    }
    let mut out = Vec::new();
    walk(*root, *root, &mut Vec::new(), source, file, &mut out);
    if out.len() > 1 {
        for site in &mut out {
            site.conditions
                .push("multiple_computed_write_sites_in_file".into());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JavaScriptAdapter, LanguageAdapter};
    fn sites(source: &str) -> Vec<ExtractedDerivedMember> {
        let adapter = JavaScriptAdapter;
        let tree = adapter.parse(source.as_bytes()).unwrap();
        adapter
            .extract(&tree, source.as_bytes(), &FilePathId::new("test.js"))
            .unwrap()
            .derived_members
    }
    #[test]
    fn derived_member_census_visits_nested_multiple_and_non_callable_writes() {
        let source = "function install() { for (const key of ['get','post']) { if (enabled) { app[key] = () => {}; router[key] = 1; } } app[unknown()] = () => {}; app[other]++; delete app[old]; }";
        let found = sites(source);
        assert_eq!(found.len(), 5);
        assert_eq!(found[0].keys, vec!["get", "post"]);
        assert!(found[0].callable);
        assert!(!found[1].callable);
        assert!(found[2..].iter().all(|s| s.keys.is_empty()));
        for site in found {
            assert!(source
                .get(site.assignment.start_byte..site.assignment.end_byte)
                .is_some());
            assert!(!site.conditions.is_empty());
        }
    }
    #[test]
    fn derived_member_census_discloses_destructuring_and_iteration_targets() {
        for source in [
            "({x: app[key]} = value);",
            "[app[key], router[other]] = value;",
            "for (app[key] of values) {}",
        ] {
            let found = sites(source);
            assert!(!found.is_empty(), "{source}");
            assert!(found
                .iter()
                .all(|s| s.keys.is_empty()
                    && s.rule == "computed_pattern_or_iteration_write_unresolved"));
        }
    }

    #[test]
    fn derived_member_keys_reject_disproved_loop_and_callback_bindings() {
        for source in [
            "for (let method of ['get']) { let method = 'post'; app[method] = () => {}; }",
            "for (let method of ['get']) { method = 'post'; app[method] = () => {}; }",
            "['get'].forEach(method => { method = 'post'; app[method] = () => {}; });",
            "['get'].map(method => { { let method = 'post'; app[method] = () => {}; } });",
            "for (let method of ['get']) { method++; app[method] = () => {}; }",
            "for (const method of ['get']) { try { throw 'post'; } catch (method) { app[method] = () => {}; } }",
            "for (const method of ['get']) { const {method} = {method:'post'}; app[method] = () => {}; }",
            "for (let method of ['get']) { for (method of ['post']) {} app[method] = () => {}; }",
            "['get'].forEach(method => { try {} catch (method) { app[method] = () => {}; } });",
            "['get'].map(method => { const {method} = value; app[method] = () => {}; });",
            "['get'].forEach(function(method, method) { app[method] = () => {}; });",
            "for (let method of ['get']) { with ({method:'post'}) { app[method] = () => {}; } }",

        ] {
            let found = sites(source);
            assert_eq!(found.len(), 1, "{source}");
            assert!(found[0].keys.is_empty(), "{source}: {found:?}");
            assert!(
                found[0]
                    .conditions
                    .iter()
                    .any(|c| c.contains("reassigned_or_shadowed")),
                "{found:?}"
            );
        }
    }
    #[test]
    fn derived_member_const_is_not_array_immutability_or_dependency_execution() {
        for prefix in [
            "const names=['get']; names.push('post');",
            "const names=['get']; mutate(names);",
            "const names=['get']; mutate({names});",
            "const names=['get']; names[0]='post';",
            "let names=['get'];",
            "const names=require('methods');",
        ] {
            let source = format!("{prefix} for (const key of names) {{ app[key] = () => {{}}; }}");
            let found = sites(&source);
            assert!(found.last().unwrap().keys.is_empty(), "{source}");
        }
        assert!(
            sites("for (const key of ['get',,'post',]) { app[key] = () => {}; }")[0]
                .keys
                .is_empty()
        );
    }
    #[test]
    fn derived_member_counting_for_reads_actual_bounds_and_increment() {
        let valid = sites("const names=['get','post']; for (let i=0; i<names.length; i++) { app[names[i]] = () => {}; }");
        assert_eq!(valid[0].keys, vec!["get", "post"]);
        for header in [
            "let i=1; i<names.length; i++",
            "let i=0; i<=names.length; i++",
            "let i=0; i<names.length; i+=2",
            "let i=0; i<names.length; i--",
        ] {
            let source = format!(
                "const names=['get','post']; for ({header}) {{ app[names[i]] = () => {{}}; }}"
            );
            assert!(sites(&source)[0].keys.is_empty(), "{source}");
        }
        assert!(sites("const names=['get']; for (let i=0; i<names.length; i++) { i++; app[names[i]] = () => {}; }")[0].keys.is_empty());
    }
}
