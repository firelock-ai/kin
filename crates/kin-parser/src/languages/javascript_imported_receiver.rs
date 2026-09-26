// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded source-owned imported receiver derivation for lazy own getters.
//! This names a possible external crossing, not proof that initialization ran
//! or that JavaScript cannot replace the property. Unsupported control flow
//! and contradictory bindings leave the original receiver unresolved.

use crate::extract::{ExtractedRelation, RelationSyntacticRole};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    node.named_children(&mut node.walk())
        .filter(|n| !n.is_extra())
        .collect()
}
fn text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    node.utf8_text(source).unwrap_or("")
}
fn nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut out = vec![node];
    for child in children(node) {
        out.extend(nodes(child));
    }
    out
}
fn literal(node: Node<'_>, source: &[u8]) -> Option<String> {
    let raw = text(node, source);
    (node.kind() == "string" && raw.len() >= 2 && !raw.contains('\\'))
        .then(|| raw[1..raw.len() - 1].to_owned())
}
fn identifier<'a>(node: Node<'_>, source: &'a [u8]) -> Option<&'a str> {
    (node.kind() == "identifier").then(|| text(node, source))
}
fn member(node: Node<'_>, source: &[u8]) -> Option<(String, String)> {
    let object = node.child_by_field_name("object")?;
    if !matches!(object.kind(), "identifier" | "this") {
        return None;
    }
    let property = match node.kind() {
        "member_expression" => text(node.child_by_field_name("property")?, source).to_owned(),
        "subscript_expression" => literal(node.child_by_field_name("index")?, source)?,
        _ => return None,
    };
    Some((text(object, source).to_owned(), property))
}
fn function(node: Node<'_>) -> bool {
    matches!(node.kind(), "function_expression" | "function")
        && !node
            .children(&mut node.walk())
            .any(|child| child.kind() == "async")
}
fn method<'a>(node: Node<'a>, source: &[u8]) -> Option<(String, String, Node<'a>)> {
    if node.kind() != "expression_statement" {
        return None;
    }
    let assignment = node.named_child(0)?;
    if assignment.kind() != "assignment_expression" {
        return None;
    }
    let value = assignment.child_by_field_name("right")?;
    if !function(value) {
        return None;
    }
    let (owner, name) = member(assignment.child_by_field_name("left")?, source)?;
    (owner != "this").then_some((owner, name, value))
}
fn arguments(node: Node<'_>) -> Option<Vec<Node<'_>>> {
    Some(children(node.child_by_field_name("arguments")?))
}
fn definer<'a>(node: Node<'a>, source: &[u8]) -> Option<Vec<Node<'a>>> {
    if node.kind() != "call_expression"
        || text(node.child_by_field_name("function")?, source) != "Object.defineProperty"
    {
        return None;
    }
    let args = arguments(node)?;
    (args.len() == 3).then_some(args)
}
/// Refusing even unrelated nested shadows avoids treating builtin spelling as
/// evidence for the operation a lexical binding normally denotes.
fn replaced_builtin(root: Node<'_>, name: &str, source: &[u8]) -> bool {
    nodes(root).into_iter().any(|node| {
        let fields: &[&str] = match node.kind() {
            "variable_declarator"
            | "function_declaration"
            | "class_declaration"
            | "function_expression" => &["name"],
            "assignment_expression" | "augmented_assignment_expression" => &["left"],
            "catch_clause" => &["parameter"],
            "for_in_statement" => &["left"],
            "update_expression" => &["argument"],
            "formal_parameters" | "import_clause" => {
                return nodes(node).into_iter().any(|n| text(n, source) == name);
            }
            _ => &[],
        };
        fields.iter().any(|field| {
            node.child_by_field_name(field).is_some_and(|target| {
                nodes(target).into_iter().any(|n| {
                    matches!(
                        n.kind(),
                        "identifier" | "shorthand_property_identifier_pattern"
                    ) && text(n, source) == name
                })
            })
        })
    })
}
fn unique_object_owner(root: Node<'_>, owner: &str, source: &[u8]) -> bool {
    let mut declarations = Vec::new();
    for declaration in children(root) {
        if !matches!(
            declaration.kind(),
            "variable_declaration" | "lexical_declaration"
        ) {
            continue;
        }
        for binding in children(declaration) {
            if binding
                .child_by_field_name("name")
                .and_then(|n| identifier(n, source))
                != Some(owner)
            {
                continue;
            }
            let Some(mut value) = binding.child_by_field_name("value") else {
                return false;
            };
            while value.kind() == "assignment_expression" {
                let Some(right) = value.child_by_field_name("right") else {
                    return false;
                };
                value = right;
            }
            if value.kind() != "object" {
                return false;
            }
            declarations.push(binding);
        }
    }
    let [declaration] = declarations.as_slice() else {
        return false;
    };
    !nodes(root).into_iter().any(|node| {
        if node == *declaration {
            return false;
        }
        let field = match node.kind() {
            "variable_declarator"
            | "function_declaration"
            | "function_expression"
            | "class_declaration" => "name",
            "catch_clause" => "parameter",
            "formal_parameters" => return !mentions(node, owner, source).is_empty(),
            _ => return false,
        };
        node.child_by_field_name(field)
            .is_some_and(|target| !mentions(target, owner, source).is_empty())
    })
}

fn getter<'a>(descriptor: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    if descriptor.kind() != "object" {
        return None;
    }
    let mut implementation = None;
    let mut names = HashSet::new();
    for pair in children(descriptor) {
        if pair.kind() != "pair" {
            return None;
        }
        let key = pair.child_by_field_name("key")?;
        let key = literal(key, source).unwrap_or_else(|| text(key, source).to_owned());
        if !names.insert(key.clone()) {
            return None;
        }
        let value = pair.child_by_field_name("value")?;
        match key.as_str() {
            "get" if function(value) => implementation = Some(value),
            "configurable" | "enumerable" if matches!(value.kind(), "true" | "false") => {}
            _ => return None,
        }
    }
    let getter = implementation?;
    children(getter.child_by_field_name("parameters")?)
        .is_empty()
        .then_some(getter)
}
fn mentions<'a>(root: Node<'a>, name: &str, source: &[u8]) -> Vec<Node<'a>> {
    nodes(root)
        .into_iter()
        .filter(|n| {
            matches!(
                n.kind(),
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) && text(*n, source) == name
        })
        .collect()
}
fn imported_constructor(root: Node<'_>, constructor: Node<'_>, source: &[u8]) -> Option<String> {
    let name = identifier(constructor, source)?;
    let mut imports = Vec::new();
    for declaration in children(root) {
        if !matches!(
            declaration.kind(),
            "variable_declaration" | "lexical_declaration"
        ) {
            continue;
        }
        for binding in children(declaration) {
            let Some(id) = binding.child_by_field_name("name") else {
                continue;
            };
            if identifier(id, source) != Some(name) {
                continue;
            }
            let value = binding.child_by_field_name("value")?;
            if value.kind() != "call_expression"
                || text(value.child_by_field_name("function")?, source) != "require"
            {
                return None;
            }
            let args = arguments(value)?;
            if args.len() != 1 {
                return None;
            }
            let module = literal(args[0], source)?;
            if !crate::is_js_bare_package_specifier(&module) {
                return None;
            }
            imports.push((id, module));
        }
    }
    let [(binding, module)] = imports.as_slice() else {
        return None;
    };
    // Only the import declaration and this construction may mention the
    // constructor binding. Extra uses, mutations and shadows stay unresolved.
    let uses = mentions(root, name, source);
    (uses.len() == 2 && uses.contains(binding) && uses.contains(&constructor))
        .then(|| module.clone())
}
fn lazy_constructor<'a>(owner: Node<'a>, getter: Node<'a>, source: &[u8]) -> Option<Node<'a>> {
    let statements = children(getter.child_by_field_name("body")?);
    let [guard, returned] = statements.as_slice() else {
        return None;
    };
    if guard.kind() != "if_statement"
        || returned.kind() != "return_statement"
        || guard.child_by_field_name("alternative").is_some()
    {
        return None;
    }
    let returned_id = returned.named_child(0)?;
    let name = identifier(returned_id, source)?;
    let condition = guard.child_by_field_name("condition")?;
    let condition = if condition.kind() == "parenthesized_expression" {
        condition.named_child(0)?
    } else {
        condition
    };
    if condition.kind() != "binary_expression"
        || text(condition.child_by_field_name("operator")?, source) != "==="
        || condition.child_by_field_name("right")?.kind() != "null"
    {
        return None;
    }
    let tested = condition.child_by_field_name("left")?;
    if identifier(tested, source) != Some(name) {
        return None;
    }
    let consequence = guard.child_by_field_name("consequence")?;
    if consequence.kind() != "statement_block" {
        return None;
    }
    let assignments = children(consequence);
    let [statement] = assignments.as_slice() else {
        return None;
    };
    if statement.kind() != "expression_statement" {
        return None;
    }
    let assignment = statement.named_child(0)?;
    if assignment.kind() != "assignment_expression" {
        return None;
    }
    let assigned = assignment.child_by_field_name("left")?;
    if identifier(assigned, source) != Some(name) {
        return None;
    }
    let value = assignment.child_by_field_name("right")?;
    if value.kind() != "new_expression" {
        return None;
    }
    let constructor = value.child_by_field_name("constructor")?;
    identifier(constructor, source)?;
    let mut declared = Vec::new();
    for declaration in children(owner.child_by_field_name("body")?) {
        if !matches!(
            declaration.kind(),
            "variable_declaration" | "lexical_declaration"
        ) {
            continue;
        }
        for binding in children(declaration) {
            let Some(id) = binding.child_by_field_name("name") else {
                continue;
            };
            if identifier(id, source) == Some(name) {
                if declaration
                    .children(&mut declaration.walk())
                    .any(|n| n.kind() == "const")
                {
                    return None;
                }
                if binding.child_by_field_name("value")?.kind() != "null" {
                    return None;
                }
                declared.push(id);
            }
        }
    }
    let [declared] = declared.as_slice() else {
        return None;
    };
    if declared.start_byte() >= getter.start_byte() {
        return None;
    }
    let expected = [*declared, tested, assigned, returned_id];
    let uses = mentions(owner, name, source);
    (uses.len() == 4 && expected.iter().all(|n| uses.contains(n))).then_some(constructor)
}
fn target_binds(node: Node<'_>, name: &str, source: &[u8]) -> bool {
    match node.kind() {
        "member_expression" | "subscript_expression" => false,
        "identifier" | "shorthand_property_identifier_pattern" => text(node, source) == name,
        _ => children(node)
            .into_iter()
            .any(|child| target_binds(child, name, source)),
    }
}
/// A direct local binding may still denote the owner after a conditional
/// reassignment. Retain that possibility and reject a relevant mutation; this
/// never grants receiver or value authority to an alias.
fn owner_aliases(root: Node<'_>, owner: &str, source: &[u8]) -> HashSet<String> {
    let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
    for node in nodes(root) {
        let (target, value) = match node.kind() {
            "variable_declarator" => ("name", "value"),
            "assignment_expression" => ("left", "right"),
            _ => continue,
        };
        let Some(target) = node
            .child_by_field_name(target)
            .and_then(|target| identifier(target, source))
        else {
            continue;
        };
        let Some(mut value) = node.child_by_field_name(value) else {
            continue;
        };
        while matches!(
            value.kind(),
            "assignment_expression" | "parenthesized_expression"
        ) {
            let next = if value.kind() == "assignment_expression" {
                value.child_by_field_name("right")
            } else {
                value.named_child(0)
            };
            let Some(next) = next else { break };
            value = next;
        }
        if matches!(value.kind(), "identifier" | "this") {
            dependents
                .entry(text(value, source).to_owned())
                .or_default()
                .push(target.to_owned());
        }
    }
    let mut aliases = HashSet::new();
    let mut pending = vec![owner.to_owned(), "this".to_owned()];
    while let Some(alias) = pending.pop() {
        if aliases.insert(alias.clone()) {
            if let Some(next) = dependents.get(&alias) {
                pending.extend(next.iter().cloned());
            }
        }
    }
    aliases
}
fn property_replaced(root: Node<'_>, owner: &str, property: &str, source: &[u8]) -> bool {
    let aliases = owner_aliases(root, owner, source);
    let aliases_owner = |mut target: Node<'_>| {
        while target.kind() == "parenthesized_expression" {
            let Some(inner) = target.named_child(0) else {
                return false;
            };
            target = inner;
        }
        matches!(target.kind(), "identifier" | "this") && aliases.contains(text(target, source))
    };
    let mut definitions = 0;
    for node in nodes(root) {
        if node.kind() == "call_expression" {
            let callee = node
                .child_by_field_name("function")
                .map(|n| text(n, source));
            if matches!(
                callee,
                Some(
                    "Object.defineProperty"
                        | "Reflect.defineProperty"
                        | "Object.assign"
                        | "Object.defineProperties"
                        | "Reflect.set"
                        | "Reflect.deleteProperty"
                )
            ) {
                let Some(args) = arguments(node) else {
                    continue;
                };
                if !args.first().is_some_and(|target| aliases_owner(*target)) {
                    continue;
                }
                if matches!(callee, Some("Object.assign" | "Object.defineProperties")) {
                    return true;
                }
                let key = args.get(1).and_then(|n| literal(*n, source));
                if key.as_deref().is_none_or(|key| key == property) {
                    if callee != Some("Object.defineProperty") || key.is_none() {
                        return true;
                    }
                    definitions += 1;
                }
            }
        }
        let field = match node.kind() {
            "assignment_expression" | "augmented_assignment_expression" | "for_in_statement" => {
                "left"
            }
            "update_expression" | "unary_expression" => "argument",
            _ => continue,
        };
        if node.child_by_field_name(field).is_some_and(|lhs| {
            target_binds(lhs, owner, source)
                || nodes(lhs).into_iter().any(|target| {
                    if !matches!(target.kind(), "member_expression" | "subscript_expression")
                        || !target
                            .child_by_field_name("object")
                            .is_some_and(aliases_owner)
                    {
                        return false;
                    }
                    let key = match target.kind() {
                        "member_expression" => target
                            .child_by_field_name("property")
                            .map(|key| text(key, source).to_owned()),
                        _ => target
                            .child_by_field_name("index")
                            .and_then(|key| literal(key, source)),
                    };
                    key.as_deref().is_none_or(|key| key == property)
                })
        }) {
            return true;
        }
    }
    definitions != 1
}
fn lexical_calls<'a>(node: Node<'a>, calls: &mut Vec<Node<'a>>) {
    for child in children(node) {
        if matches!(
            child.kind(),
            "function_expression"
                | "function"
                | "function_declaration"
                | "method_definition"
                | "class"
                | "class_declaration"
        ) {
            continue;
        }
        if child.kind() == "call_expression" {
            calls.push(child);
        }
        lexical_calls(child, calls);
    }
}
pub(super) fn annotate(root: Node<'_>, source: &[u8], relations: &mut [ExtractedRelation]) {
    if root.has_error()
        || replaced_builtin(root, "Object", source)
        || replaced_builtin(root, "require", source)
        || nodes(root).iter().any(|n| {
            n.kind() == "with_statement"
                || (n.kind() == "call_expression"
                    && n.child_by_field_name("function")
                        .is_some_and(|f| text(f, source).split('.').next_back() == Some("eval")))
        })
    {
        return;
    }
    let methods: Vec<_> = children(root)
        .into_iter()
        .filter_map(|n| method(n, source))
        .collect();
    let mut method_counts = HashMap::new();
    for (owner, name, _) in &methods {
        *method_counts
            .entry((owner.clone(), name.clone()))
            .or_insert(0) += 1;
    }
    let owners: HashSet<_> = methods
        .iter()
        .map(|(owner, _, _)| owner)
        .filter(|owner| {
            unique_object_owner(root, owner, source)
                && method_counts
                    .iter()
                    .all(|((candidate, _), count)| candidate != *owner || *count == 1)
        })
        .cloned()
        .collect();
    let mut definitions: HashMap<(String, String), Vec<Option<String>>> = HashMap::new();
    for (owner, _, function) in &methods {
        if !owners.contains(owner) {
            continue;
        }
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        for statement in children(body) {
            if statement.kind() != "expression_statement" {
                continue;
            }
            let Some(call) = statement.named_child(0) else {
                continue;
            };
            let Some(args) = definer(call, source) else {
                continue;
            };
            if args[0].kind() != "this" {
                continue;
            }
            let Some(property) = literal(args[1], source) else {
                continue;
            };
            let module = getter(args[2], source)
                .and_then(|g| lazy_constructor(*function, g, source))
                .and_then(|c| imported_constructor(root, c, source));
            definitions
                .entry((owner.clone(), property))
                .or_default()
                .push(module);
        }
    }
    definitions.retain(|(owner, property), variants| {
        matches!(variants.as_slice(), [Some(_)])
            && !property_replaced(root, owner, property, source)
    });
    for (owner, name, function) in &methods {
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let mut calls = Vec::new();
        lexical_calls(body, &mut calls);
        for call in calls {
            let Some(callee) = call.child_by_field_name("function") else {
                continue;
            };
            if callee.kind() != "member_expression" {
                continue;
            }
            let Some(receiver) = callee.child_by_field_name("object") else {
                continue;
            };
            let Some((target, property)) = member(receiver, source) else {
                continue;
            };
            if target != "this" || receiver.kind() != "member_expression" {
                continue;
            }
            let Some([Some(module)]) = definitions
                .get(&(owner.clone(), property.clone()))
                .map(Vec::as_slice)
            else {
                continue;
            };
            let Some(member) = callee.child_by_field_name("property") else {
                continue;
            };
            let caller = format!("{owner}.{name}");
            for raw in relations.iter_mut().filter(|r| {
                r.src_name == caller
                    && r.site.as_ref().is_some_and(|s| {
                        s.start_byte == call.start_byte() && s.end_byte == call.end_byte()
                    })
            }) {
                raw.dst_name = format!("{property}.{}", text(member, source));
                raw.import_source = Some(module.clone());
                raw.site.as_mut().unwrap().syntactic_role =
                    Some(RelationSyntacticRole::JsImportedGetterReceiver);
            }
        }
    }
}
