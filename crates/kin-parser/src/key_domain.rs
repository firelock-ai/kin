// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Independent, deliberately narrow key-domain syntax facts.
//!
//! These facts do not establish JavaScript intrinsic dispatch, module loading,
//! runtime object identity, or an absence of mutations in other modules. A
//! caller must bind the spans to admitted source bytes and discharge every
//! intrinsic requirement before using a domain to exclude a computed write.
//! No parser output, call relation, or existing candidate contract is changed.

use std::collections::{BTreeMap, BTreeSet};

use kin_model::{FilePathId, SourceSpan};
use tree_sitter::{Node, Tree};

use crate::{adapter::span_from_node, JavaScriptAdapter, LanguageAdapter};

const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 64;
const MAX_KEYS: usize = 256;
const MAX_LITERAL_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyIntrinsic {
    ArrayMap,
    StringAsciiLowercase,
    ArrayForEach,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportKeyFacts {
    pub keys: Vec<String>,
    pub required_intrinsics: Vec<KeyIntrinsic>,
    pub spans: Vec<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportKeyFacts {
    pub module: String,
    pub export_name: String,
    pub required_intrinsics: Vec<KeyIntrinsic>,
    pub ascii_lowercase: bool,
    pub spans: Vec<SourceSpan>,
}

type AnalysisResult<T> = std::result::Result<T, String>;

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    // All public entry points validate UTF-8 before parsing.
    node.utf8_text(source).unwrap_or("")
}

fn parse(source: &[u8]) -> AnalysisResult<Tree> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err("key-domain source byte limit exceeded".into());
    }
    std::str::from_utf8(source).map_err(|_| "key-domain source is not UTF-8")?;
    let tree = JavaScriptAdapter.parse(source).map_err(|e| e.to_string())?;
    if tree.root_node().has_error()
        || crate::languages::javascript::tree_is_typescript_family(&tree)
    {
        return Err("key-domain source must be complete plain JavaScript".into());
    }
    Ok(tree)
}

/// Check the complete tree with a cursor before collecting any node inventory.
fn bounded_nodes(root: Node<'_>) -> AnalysisResult<Vec<Node<'_>>> {
    let mut cursor = root.walk();
    let mut depth = 0;
    let mut nodes = Vec::new();
    loop {
        if nodes.len() == MAX_NODES || depth > MAX_DEPTH {
            return Err("key-domain syntax limit exceeded".into());
        }
        let node = cursor.node();
        if node.is_missing() || node.is_error() {
            return Err("key-domain source contains recovered syntax".into());
        }
        nodes.push(node);
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(nodes);
            }
            depth -= 1;
        }
    }
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    node.named_children(&mut node.walk())
        .filter(|child| !child.is_extra())
        .collect()
}

fn field<'a>(node: Node<'a>, name: &str) -> AnalysisResult<Node<'a>> {
    node.child_by_field_name(name)
        .ok_or_else(|| format!("missing key-domain syntax field: {name}"))
}

fn identifier<'a>(node: Node<'_>, source: &'a [u8]) -> AnalysisResult<&'a str> {
    let name = text(node, source);
    if node.kind() != "identifier"
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
    {
        return Err("expected an unescaped ASCII identifier".into());
    }
    Ok(name)
}

fn literal(node: Node<'_>, source: &[u8]) -> AnalysisResult<String> {
    let raw = text(node, source);
    if node.kind() != "string"
        || raw.len() < 2
        || raw.len() - 2 > MAX_LITERAL_BYTES
        || !raw.is_ascii()
        || raw.contains(['\\', '\n', '\r'])
        || !matches!(raw.as_bytes()[0], b'\'' | b'"')
        || raw.as_bytes()[0] != raw.as_bytes()[raw.len() - 1]
    {
        return Err("expected a bounded unescaped ASCII string literal".into());
    }
    Ok(raw[1..raw.len() - 1].to_owned())
}

fn member<'a>(node: Node<'a>, property: &str, source: &[u8]) -> AnalysisResult<Node<'a>> {
    if node.kind() != "member_expression"
        || node.child_by_field_name("optional_chain").is_some()
        || text(field(node, "property")?, source) != property
    {
        return Err(format!("expected an exact .{property} member"));
    }
    field(node, "object")
}

fn args(node: Node<'_>) -> AnalysisResult<Vec<Node<'_>>> {
    if node.kind() != "call_expression" || node.child_by_field_name("optional_chain").is_some() {
        return Err("expected a direct call".into());
    }
    Ok(children(field(node, "arguments")?))
}

fn top_statements<'a>(root: Node<'a>, source: &[u8]) -> AnalysisResult<Vec<Node<'a>>> {
    let mut statements = Vec::new();
    for node in children(root) {
        if node.kind() == "expression_statement" {
            let values = children(node);
            if let [value] = values.as_slice() {
                if value.kind() == "string" && literal(*value, source)? == "use strict" {
                    if !statements.is_empty() {
                        return Err("directive after executable key-domain syntax".into());
                    }
                    continue;
                }
            }
        }
        statements.push(node);
    }
    Ok(statements)
}

fn const_binding<'a>(node: Node<'a>, source: &[u8]) -> AnalysisResult<(Node<'a>, Node<'a>)> {
    if node.kind() != "lexical_declaration"
        || node
            .child(0)
            .is_none_or(|token| text(token, source) != "const")
    {
        return Err("key-domain bindings must be top-level const declarations".into());
    }
    let declarations = children(node);
    let [declaration] = declarations.as_slice() else {
        return Err("expected one const binding per declaration".into());
    };
    let name = field(*declaration, "name")?;
    identifier(name, source)?;
    Ok((name, field(*declaration, "value")?))
}

fn expression(node: Node<'_>) -> AnalysisResult<Node<'_>> {
    if node.kind() != "expression_statement" {
        return Err("expected a key-domain expression statement".into());
    }
    let values = children(node);
    let [value] = values.as_slice() else {
        return Err("expected one expression".into());
    };
    Ok(*value)
}

/// Reject visible operations that can change the interpretation of intrinsic
/// spellings. Absence here is not proof that the runtime intrinsics are pristine.
fn intrinsic_syntax_guard(nodes: &[Node<'_>], source: &[u8]) -> AnalysisResult<()> {
    for &node in nodes {
        if node.kind() == "with_statement"
            || (matches!(
                node.kind(),
                "identifier"
                    | "property_identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) && text(node, source).contains('\\'))
            || (matches!(
                node.kind(),
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) && matches!(
                text(node, source),
                "Object"
                    | "Array"
                    | "String"
                    | "Reflect"
                    | "Proxy"
                    | "Function"
                    | "eval"
                    | "globalThis"
                    | "global"
                    | "window"
                    | "self"
                    | "process"
            ))
            || (matches!(node.kind(), "property_identifier" | "string")
                && matches!(
                    text(node, source).trim_matches(['\'', '"']),
                    "prototype" | "__proto__" | "constructor"
                ))
        {
            return Err("unproved intrinsic, prototype, or dynamic-scope operation".into());
        }
    }
    Ok(())
}

#[derive(Default)]
struct Uses(BTreeMap<String, BTreeSet<(usize, usize)>>);

impl Uses {
    fn allow(&mut self, node: Node<'_>, source: &[u8]) -> AnalysisResult<()> {
        let name = identifier(node, source)?;
        self.0
            .entry(name.to_owned())
            .or_default()
            .insert((node.start_byte(), node.end_byte()));
        Ok(())
    }

    fn check(&self, nodes: &[Node<'_>], source: &[u8]) -> AnalysisResult<()> {
        for node in nodes {
            if !matches!(
                node.kind(),
                "identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            ) {
                continue;
            }
            if let Some(allowed) = self.0.get(text(*node, source)) {
                if !allowed.contains(&(node.start_byte(), node.end_byte())) {
                    return Err(format!(
                        "unaccounted use, shadow, mutation, or escape of {}",
                        text(*node, source)
                    ));
                }
            }
        }
        Ok(())
    }
}

fn dense_array(node: Node<'_>, source: &[u8]) -> AnalysisResult<Vec<String>> {
    if node.kind() != "array" {
        return Err("expected a dense literal array".into());
    }
    let mut keys = Vec::new();
    let mut expect_value = true;
    for child in node
        .children(&mut node.walk())
        .filter(|child| !child.is_extra())
    {
        match child.kind() {
            "[" | "]" => {}
            "," if !expect_value => expect_value = true,
            "string" if expect_value => {
                if keys.len() == MAX_KEYS {
                    return Err("key-domain key count limit exceeded".into());
                }
                keys.push(literal(child, source)?);
                expect_value = false;
            }
            _ => return Err("sparse or nonliteral key-domain array".into()),
        }
    }
    Ok(keys)
}

fn one_parameter<'a>(node: Node<'a>, source: &[u8]) -> AnalysisResult<Node<'a>> {
    let parameter = if let Some(parameter) = node.child_by_field_name("parameter") {
        parameter
    } else {
        let parameters = children(field(node, "parameters")?);
        let [parameter] = parameters.as_slice() else {
            return Err("expected exactly one callback parameter".into());
        };
        *parameter
    };
    identifier(parameter, source)?;
    Ok(parameter)
}

fn ordinary_function(node: Node<'_>) -> bool {
    matches!(node.kind(), "function_expression" | "function")
        && !node
            .children(&mut node.walk())
            .any(|child| matches!(child.kind(), "async" | "*"))
}

/// Admit only `input.map(key => key.toLowerCase())`, retaining the intrinsic
/// requirements instead of claiming that either method dispatch was verified.
fn lowercase_map<'a>(
    node: Node<'a>,
    input: &str,
    source: &[u8],
    uses: &mut Uses,
) -> AnalysisResult<Node<'a>> {
    let arguments = args(node)?;
    let receiver = member(field(node, "function")?, "map", source)?;
    if identifier(receiver, source)? != input {
        return Err("map receiver does not name the selected array".into());
    }
    let [callback] = arguments.as_slice() else {
        return Err("map must have exactly one callback".into());
    };
    if callback.kind() != "arrow_function"
        || callback
            .children(&mut callback.walk())
            .any(|n| n.kind() == "async")
    {
        return Err("expected a synchronous lowercase arrow callback".into());
    }
    let parameter = one_parameter(*callback, source)?;
    if identifier(parameter, source)? == input {
        return Err("lowercase callback shadows its array binding".into());
    }
    let body = field(*callback, "body")?;
    if !args(body)?.is_empty() {
        return Err("lowercase call cannot have arguments".into());
    }
    let value = member(field(body, "function")?, "toLowerCase", source)?;
    if identifier(value, source)? != identifier(parameter, source)? {
        return Err("lowercase callback must return its own parameter".into());
    }
    for node in [receiver, parameter, value] {
        uses.allow(node, source)?;
    }
    Ok(parameter)
}

fn spans(nodes: &[Node<'_>], file: &FilePathId) -> Vec<SourceSpan> {
    let mut ranges = BTreeMap::new();
    for node in nodes {
        ranges
            .entry((node.start_byte(), node.end_byte()))
            .or_insert_with(|| span_from_node(node, file));
    }
    ranges.into_values().collect()
}

/// Analyze an exact named CommonJS export in a deliberately closed module:
/// one dense `const` array and `exports.name = array` (or its lowercase map).
/// The export is the one intentional boundary escape; consumers must prove
/// their own use of that exported mutable array independently.
pub fn analyze_named_export(
    source: &[u8],
    file: &FilePathId,
    name: &str,
) -> AnalysisResult<ExportKeyFacts> {
    let tree = parse(source)?;
    let nodes = bounded_nodes(tree.root_node())?;
    intrinsic_syntax_guard(&nodes, source)?;
    let statements = top_statements(tree.root_node(), source)?;
    let [declaration, exported] = statements.as_slice() else {
        return Err("export module must contain only a const array and its named export".into());
    };
    let (binding, value) = const_binding(*declaration, source)?;
    let binding_name = identifier(binding, source)?;
    if matches!(binding_name, "exports" | "module" | "require") {
        return Err("array binding shadows CommonJS machinery".into());
    }
    let mut keys = dense_array(value, source)?;
    let assignment = expression(*exported)?;
    if assignment.kind() != "assignment_expression" {
        return Err("expected an exact named export assignment".into());
    }
    let export_owner = member(field(assignment, "left")?, name, source)?;
    if identifier(export_owner, source)? != "exports" {
        return Err("expected the unshadowed exports object".into());
    }
    let mut uses = Uses::default();
    uses.allow(binding, source)?;
    uses.allow(export_owner, source)?;
    let exported_value = field(assignment, "right")?;
    let required_intrinsics = if exported_value.kind() == "identifier" {
        if identifier(exported_value, source)? != binding_name {
            return Err("export does not name the selected array".into());
        }
        uses.allow(exported_value, source)?;
        Vec::new()
    } else {
        let parameter = lowercase_map(exported_value, binding_name, source, &mut uses)?;
        if matches!(
            identifier(parameter, source)?,
            "exports" | "module" | "require"
        ) {
            return Err("lowercase callback shadows CommonJS machinery".into());
        }
        for key in &mut keys {
            key.make_ascii_lowercase();
        }
        vec![KeyIntrinsic::ArrayMap, KeyIntrinsic::StringAsciiLowercase]
    };
    uses.check(&nodes, source)?;
    Ok(ExportKeyFacts {
        keys,
        required_intrinsics,
        spans: spans(&[*declaration, assignment, exported_value], file),
    })
}

fn import_member<'a>(
    value: Node<'a>,
    source: &[u8],
    uses: &mut Uses,
) -> AnalysisResult<(String, String)> {
    if value.kind() != "member_expression" || value.child_by_field_name("optional_chain").is_some()
    {
        return Err("expected require('./module').namedExport".into());
    }
    let export_name = text(field(value, "property")?, source).to_owned();
    let call = field(value, "object")?;
    let arguments = args(call)?;
    let callee = field(call, "function")?;
    if identifier(callee, source)? != "require" {
        return Err("expected a direct CommonJS require".into());
    }
    let [module] = arguments.as_slice() else {
        return Err("require must have exactly one static argument".into());
    };
    let module = literal(*module, source)?;
    if !(module.starts_with("./") || module.starts_with("../")) || module.contains(['?', '#', '\0'])
    {
        return Err("key-domain import must name an explicit local relative module".into());
    }
    uses.allow(callee, source)?;
    Ok((module, export_name))
}

/// Analyze one local named import, an optional lowercase map, and a sole
/// forEach registration into a unique `const owner = {}`. Only the assigned
/// function's body is otherwise opaque; protected binding uses are still
/// checked through it, and visible intrinsic/prototype manipulation refuses.
pub fn analyze_import_iteration(
    source: &[u8],
    file: &FilePathId,
    binding: &str,
) -> AnalysisResult<ImportKeyFacts> {
    let tree = parse(source)?;
    let nodes = bounded_nodes(tree.root_node())?;
    intrinsic_syntax_guard(&nodes, source)?;
    let statements = top_statements(tree.root_node(), source)?;
    let Some((iteration, declarations)) = statements.split_last() else {
        return Err("missing key-domain iteration".into());
    };
    if !(2..=3).contains(&declarations.len()) {
        return Err("iteration requires one import, one empty owner, and at most one map".into());
    }
    let mut uses = Uses::default();
    let mut named = BTreeMap::new();
    for &declaration in declarations {
        let (name, value) = const_binding(declaration, source)?;
        let key = identifier(name, source)?;
        if matches!(key, "exports" | "module" | "require")
            || named.insert(key, (name, value)).is_some()
        {
            return Err("ambiguous or reserved key-domain binding".into());
        }
        uses.allow(name, source)?;
    }
    let &(_, import_value) = named
        .get(binding)
        .ok_or("selected import binding not found")?;
    let (module, export_name) = import_member(import_value, source, &mut uses)?;
    let mut iterator = binding;
    let mut ascii_lowercase = false;
    let mut owner = None;
    let mut map_parameter = None;
    for (&name, &(declaration, value)) in &named {
        if name == binding {
            continue;
        }
        if value.kind() == "object" && children(value).is_empty() {
            if owner.replace(name).is_some() {
                return Err("multiple possible registration owners".into());
            }
        } else {
            if ascii_lowercase || declaration.start_byte() <= import_value.end_byte() {
                return Err("ambiguous or out-of-order lowercase binding".into());
            }
            map_parameter = Some(lowercase_map(value, binding, source, &mut uses)?);
            ascii_lowercase = true;
            iterator = name;
        }
    }
    let owner = owner.ok_or("missing unique empty-object registration owner")?;
    let call = expression(*iteration)?;
    let receiver = member(field(call, "function")?, "forEach", source)?;
    if identifier(receiver, source)? != iterator {
        return Err("forEach receiver is not the selected domain".into());
    }
    uses.allow(receiver, source)?;
    let arguments = args(call)?;
    let [callback] = arguments.as_slice() else {
        return Err("forEach must have exactly one callback".into());
    };
    if !ordinary_function(*callback) || callback.child_by_field_name("name").is_some() {
        return Err("expected an anonymous synchronous registration callback".into());
    }
    let key = one_parameter(*callback, source)?;
    let key_name = identifier(key, source)?;
    if named.contains_key(key_name) || matches!(key_name, "require" | "module" | "exports") {
        return Err("registration key shadows a protected binding".into());
    }
    if map_parameter.is_some_and(|parameter| {
        named.contains_key(text(parameter, source))
            || matches!(text(parameter, source), "require" | "module" | "exports")
    }) {
        return Err("lowercase key shadows a protected binding".into());
    }
    let body = children(field(*callback, "body")?);
    let [statement] = body.as_slice() else {
        return Err("registration callback must contain only its computed assignment".into());
    };
    let assignment = expression(*statement)?;
    if assignment.kind() != "assignment_expression" {
        return Err("expected a plain computed assignment".into());
    }
    let target = field(assignment, "left")?;
    if target.kind() != "subscript_expression" {
        return Err("expected a computed owner key".into());
    }
    let target_owner = field(target, "object")?;
    let target_key = field(target, "index")?;
    if identifier(target_owner, source)? != owner || identifier(target_key, source)? != key_name {
        return Err("computed assignment does not use the unique owner and callback key".into());
    }
    if !ordinary_function(field(assignment, "right")?) {
        return Err("computed registration must assign an ordinary function".into());
    }
    for node in [key, target_owner, target_key] {
        uses.allow(node, source)?;
    }
    uses.check(&nodes, source)?;
    // Inventory the complete file as well, refusing hidden loading syntax in
    // the function body even though that body does not execute in the loop.
    static_require_nodes(&nodes, source)?;
    let required_intrinsics = if ascii_lowercase {
        vec![
            KeyIntrinsic::ArrayMap,
            KeyIntrinsic::StringAsciiLowercase,
            KeyIntrinsic::ArrayForEach,
        ]
    } else {
        vec![KeyIntrinsic::ArrayForEach]
    };
    Ok(ImportKeyFacts {
        module,
        export_name,
        required_intrinsics,
        ascii_lowercase,
        spans: spans(&statements, file),
    })
}

fn static_require_nodes(nodes: &[Node<'_>], source: &[u8]) -> AnalysisResult<Vec<String>> {
    intrinsic_syntax_guard(nodes, source)?;
    let mut modules = Vec::new();
    for &node in nodes {
        // The supported module grammar has no proven ambient/global receiver.
        // `arguments` can expose the CommonJS wrapper's require parameter, and
        // computed reads can hide loader spellings even without a require token.
        if node.kind() == "this" {
            return Err("unproved this/global authority in static inventory".into());
        }
        // A computed destructuring key is a property read even though its AST
        // is not a subscript expression. It can conceal e.g. a Function
        // constructor or loader behind a concatenated property name.
        if node.kind() == "computed_property_name" {
            return Err("computed property definition or destructuring in static inventory".into());
        }
        if node.kind() == "subscript_expression" {
            let parent = node.parent().ok_or("unbound computed member")?;
            if parent.kind() != "assignment_expression"
                || field(parent, "left")? != node
                || identifier(field(node, "object")?, source).is_err()
                || identifier(field(node, "index")?, source).is_err()
                || !ordinary_function(field(parent, "right")?)
            {
                return Err(
                    "computed read, dispatch, or unsupported write in static inventory".into(),
                );
            }
        }
        if matches!(
            node.kind(),
            "import" | "import_statement" | "export_statement" | "with_statement"
        ) {
            return Err(
                "ES module or dynamic import/scope syntax is outside the require inventory".into(),
            );
        }
        let spelling = text(node, source);
        if matches!(
            node.kind(),
            "identifier"
                | "property_identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) && spelling.contains('\\')
        {
            return Err("escaped loader names are outside the static inventory".into());
        }
        if matches!(
            node.kind(),
            "identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) {
            if matches!(
                spelling,
                "eval"
                    | "Function"
                    | "createRequire"
                    | "globalThis"
                    | "global"
                    | "window"
                    | "self"
                    | "process"
                    | "arguments"
                    | "importScripts"
                    | "Worker"
                    | "SharedWorker"
                    | "Deno"
                    | "Bun"
                    | "WebAssembly"
            ) {
                return Err("indirect module-loading authority is unproven".into());
            }
            if spelling == "module" {
                let parent = node.parent().ok_or("unbound module identifier")?;
                if parent.kind() != "member_expression"
                    || field(parent, "object")? != node
                    || text(field(parent, "property")?, source) != "exports"
                {
                    return Err("indirect or shadowed CommonJS module access".into());
                }
            }
            if spelling != "require" {
                continue;
            }
            let parent = node.parent().ok_or("unbound require identifier")?;
            if parent.kind() != "call_expression" || field(parent, "function")? != node {
                return Err("require is shadowed, mutated, aliased, or escaped".into());
            }
            let arguments = args(parent)?;
            let [module] = arguments.as_slice() else {
                return Err("require does not have one static argument".into());
            };
            let module = literal(*module, source)?;
            if module.is_empty() || module.contains('\0') {
                return Err("invalid static module specifier".into());
            }
            modules.push(module);
        } else if matches!(node.kind(), "property_identifier" | "string")
            && (matches!(
                spelling.trim_matches(['\'', '"']),
                "require"
                    | "createRequire"
                    | "constructor"
                    | "prototype"
                    | "__proto__"
                    | "eval"
                    | "Function"
                    | "caller"
                    | "callee"
            ) || (node.kind() == "string"
                && spelling.contains('\\')
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "subscript_expression")))
        {
            return Err("indirect require property is outside the static inventory".into());
        }
    }
    Ok(modules)
}

/// Complete syntactic inventory for the supported CommonJS subset. Static
/// requires in nested functions and duplicate sites are included in source
/// order. ESM syntax, dynamic arguments,
/// aliases/shadows of require, and indirect module-loading APIs refuse rather
/// than silently returning an incomplete list. This is not runtime reachability.
pub fn static_requires(source: &[u8]) -> AnalysisResult<Vec<String>> {
    let tree = parse(source)?;
    let nodes = bounded_nodes(tree.root_node())?;
    static_require_nodes(&nodes, source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> FilePathId {
        FilePathId::new("src/keys.js")
    }
    fn consumer(map: bool) -> String {
        let extra = if map {
            "const lowered = keys.map(item => item.toLowerCase());"
        } else {
            ""
        };
        let receiver = if map { "lowered" } else { "keys" };
        format!("const keys = require('./keys').names; const owner = {{}}; {extra} {receiver}.forEach(function(key) {{ owner[key] = function(value) {{ return value; }}; }});")
    }

    #[test]
    fn exact_export_preserves_empty_duplicates_and_lowercase_requirements() {
        for (input, expected, lowering) in [
            ("const names = []; exports.keys = names;", vec![], false),
            ("const names = ['A', 'A', '',]; exports.keys = names;", vec!["A", "A", ""], false),
            ("'use strict'; const names = ['GET', 'MiXeD']; exports.keys = names.map(k => k.toLowerCase());", vec!["get", "mixed"], true),
        ] {
            let facts = analyze_named_export(input.as_bytes(), &file(), "keys").unwrap();
            assert_eq!(facts.keys, expected);
            assert_eq!(!facts.required_intrinsics.is_empty(), lowering);
            for span in &facts.spans {
                assert_eq!(span.file, file());
                assert!(!input[span.start_byte..span.end_byte].is_empty());
            }
        }
    }

    #[test]
    fn exporter_refuses_holes_escapes_mutation_and_ambiguous_exports() {
        for source in [
            "const names = [,]; exports.keys = names;",
            "const names = ['a',,'b']; exports.keys = names;",
            "const names = [...other]; exports.keys = names;",
            "const names = ['\\x61']; exports.keys = names;",
            "const names = ['é']; exports.keys = names;",
            "let names = ['a']; exports.keys = names;",
            "const names = ['a']; names.push('router'); exports.keys = names;",
            "const names = ['a']; exports.keys = names; exports.keys = other;",
            "const names = ['a']; exports.keys = names.map(names => names.toLowerCase());",
            "const names = ['a']; exports.keys = names.map(k => other.toLowerCase());",
            "const names = ['a']; exports.keys = names.map(k => k.toLowerCase(extra));",
            "const names = ['a']; exports.keys = names.map(async k => k.toLowerCase());",
            "const names = ['a']; exports.keys = names?.map(k => k.toLowerCase());",
            "const names = ['a']; exports.keys = names.map(k => k?.toLowerCase());",
        ] {
            assert!(
                analyze_named_export(source.as_bytes(), &file(), "keys").is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn consumer_retains_intrinsic_requirements_and_exact_import_boundary() {
        for map in [false, true] {
            let source = consumer(map);
            let facts = analyze_import_iteration(source.as_bytes(), &file(), "keys").unwrap();
            assert_eq!(facts.module, "./keys");
            assert_eq!(facts.export_name, "names");
            assert_eq!(facts.ascii_lowercase, map);
            assert!(facts
                .required_intrinsics
                .contains(&KeyIntrinsic::ArrayForEach));
            assert_eq!(
                facts.required_intrinsics.contains(&KeyIntrinsic::ArrayMap),
                map
            );
            assert_eq!(static_requires(source.as_bytes()).unwrap(), vec!["./keys"]);
        }
    }

    #[test]
    fn consumer_refuses_key_and_array_escapes_shadowing_and_extra_execution() {
        let base = consumer(true);
        for source in [
            base.replace("owner[key]", "owner[other]"),
            base.replace("function(key)", "function(keys)"),
            base.replace("return value;", "return key;"),
            base.replace("function(value)", "function(keys)"),
            base.replace("return value;", "return keys;"),
            base.replace("return value;", "const alias = owner; return value;"),
            base.replace(
                "return value;",
                "Object.assign(owner, value); return value;",
            ),
            base.replace(
                "return value;",
                "Array.prototype.forEach = value; return value;",
            ),
            base.replace("owner[key] =", "key = 'router'; owner[key] ="),
            base.replace("const owner = {};", "const owner = {}; const second = {};"),
            base.replace("const owner = {};", "const owner = existing;"),
            base.replace(
                "const owner = {};",
                "const owner = {}; keys.push('router');",
            ),
            base.replace("keys.map(item", "keys.map(owner"),
            base.replace("require('./keys')", "require(path)"),
            base.replace("lowered.forEach", "keys.forEach"),
        ] {
            assert_ne!(source, base);
            assert!(
                analyze_import_iteration(source.as_bytes(), &file(), "keys").is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn require_inventory_is_complete_or_refuses() {
        assert_eq!(static_requires(b"const a = require('./a'); function later() { return require('pkg'); } require('./a');").unwrap(), vec!["./a", "pkg", "./a"]);
        assert!(static_requires(b"module.exports = {}; ")
            .unwrap()
            .is_empty());
        for source in [
            "require(path)",
            "require('./' + name)",
            "require(`./a`)",
            "const load = require; load('./a')",
            "function f(require) { require('./a'); }",
            "require.resolve('./a')",
            "module.require('./a')",
            "module[key]('./a')",
            "import('./a')",
            "import value from './a'",
            "export {value} from './a'",
            "const {createRequire} = require('node:module');",
            "eval(code)",
            "new Function(code)",
            "const load = ({}).constructor.constructor(code);",
            "holder['\\x72equire']('./a')",
            "const load = requ\\u0069re;",
            "const x = require('./a'",
            "require?.('./a')",
        ] {
            assert!(static_requires(source.as_bytes()).is_err(), "{source}");
        }
    }

    #[test]
    fn inventory_refuses_intrinsic_mutation_and_obscured_loader_authority() {
        for source in [
            "Array = custom;",
            "Object.getPrototypeOf([]).map = custom;",
            "String = custom;",
            "(function () { this['ev' + 'al'](code); })();",
            "const load = holder['requ' + 'ire']; load('./keys');",
            "holder['requ' + 'ire']('./keys');",
            "const { ['con' + 'structor']: make } = function() {}; make(code)();",
            "const { ['requ' + 'ire']: load } = holder; load('./keys');",
            "const ambient = this; ambient.load('./keys');",
            "const [, load] = arguments; load('./keys');",
            "function f() {} const wrapper = f.caller;",
            "importScripts('./keys');",
            "new Worker('./keys');",
            "const pending = owner[key];",
            "owner[key] = replacement;",
            "owner[key] += function() {};",
            "delete owner[key];",
        ] {
            assert!(static_requires(source.as_bytes()).is_err(), "{source}");
        }
        let source = consumer(false);
        assert_eq!(static_requires(source.as_bytes()).unwrap(), vec!["./keys"]);
        assert!(analyze_import_iteration(source.as_bytes(), &file(), "keys").is_ok());
    }

    #[test]
    fn bounds_refuse_before_returning_partial_domains() {
        let oversized = vec![b' '; MAX_SOURCE_BYTES + 1];
        assert!(static_requires(&oversized).is_err());
        let source = format!(
            "const names = [{}]; exports.keys = names;",
            vec!["'a'"; MAX_KEYS + 1].join(",")
        );
        assert!(analyze_named_export(source.as_bytes(), &file(), "keys").is_err());
        let source = format!(
            "const names = ['{}']; exports.keys = names;",
            "a".repeat(MAX_LITERAL_BYTES + 1)
        );
        assert!(analyze_named_export(source.as_bytes(), &file(), "keys").is_err());
        assert!(static_requires("0;".repeat(MAX_NODES).as_bytes()).is_err());
        let deep = format!(
            "{}0{};",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert!(static_requires(deep.as_bytes()).is_err());
        assert!(static_requires(&[0xff]).is_err());
    }
}
