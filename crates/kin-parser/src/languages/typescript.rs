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
// TypeScript is a superset of JavaScript, so the CommonJS import surface,
// receiver-method assignment forms and object-literal methods parse to the same
// nodes in both grammars. Sharing them keeps the two adapters from drifting into
// different answers for the same source.
use super::javascript::{
    collect_js_require_imports, extract_js_assignment_function, extract_js_object_methods,
    js_heritage_name, js_require_target, JsOwners,
};

pub struct TypeScriptAdapter;

impl LanguageAdapter for TypeScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::TypeScript
    }

    fn file_extensions(&self) -> &[&str] {
        &["ts", "tsx"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT)?;
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
        let mut owners = JsOwners::default();
        let root = tree.root_node();
        let mut cursor = root.walk();

        // Emit Module entity for index.ts/index.tsx files (TS packages).
        // This makes the module searchable by its directory name, e.g.,
        // `packages/mui-base/src/useSelect/index.ts` → entity "useSelect".
        if is_ts_index_file(&file_id.0) {
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
            extract_ts_node(
                &child,
                source,
                file_id,
                &mut entities,
                &mut relations,
                &mut owners,
            );
            if let Some(import_like) = extract_ts_import_like(&child, source) {
                imports.push(import_like);
            }
            // Extract CommonJS require() calls as imports
            collect_js_require_imports(&child, source, &mut imports);
            // Detect describe/it/test calls (Jest/Vitest/Mocha)
            extract_js_tests(&child, source, &mut tests);
        }

        owners.finish(&mut entities);

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

fn extract_ts_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    owners: &mut JsOwners,
) {
    match node.kind() {
        "function_declaration" | "function" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let sig = node_signature(node, source);
                let vis = detect_ts_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: name.clone(),
                    signature: sig,
                    visibility: vis,
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
                extract_ts_class_like(node, &name, source, file_id, entities, relations);
            }
        }
        "interface_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Interface,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_ts_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "type_alias_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::TypeAlias,
                    name,
                    signature: node_signature(node, source),
                    visibility: detect_ts_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        "enum_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let vis = detect_ts_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::EnumDef,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                // Extract enum members as EnumVariant entities
                if let Some(body) = node.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for member in body.children(&mut body_cursor) {
                        if member.kind() == "enum_member" || member.kind() == "property_identifier"
                        {
                            let member_name_node =
                                member.child_by_field_name("name").unwrap_or(member);
                            let variant_name =
                                member_name_node.utf8_text(source).unwrap_or("").to_string();
                            if !variant_name.is_empty()
                                && variant_name != "{"
                                && variant_name != "}"
                            {
                                let qualified = format!("{}.{}", name, variant_name);
                                entities.push(ExtractedEntity {
                                    kind: EntityKind::EnumVariant,
                                    name: qualified.clone(),
                                    signature: format!("{}.{}", name, variant_name),
                                    visibility: vis,
                                    doc_summary: extract_preceding_comment(&member, source),
                                    fingerprint: compute_fingerprint(&member, source),
                                    span: span_from_node(&member, file_id),
                                });
                                relations.push(ExtractedRelation {
                                    call_shape: None,
                                    kind: kin_model::RelationKind::Contains,
                                    src_name: name.clone(),
                                    dst_name: qualified,
                                    import_source: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        "expression_statement" => {
            // Prototype and receiver method assignments (`Foo.prototype.bar =
            // function () {}`) plus `module.exports = ...`. TypeScript files in
            // Node packages still carry these CommonJS shapes.
            extract_js_assignment_function(node, source, file_id, entities, relations, owners);
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut decl_cursor = node.walk();
            for declarator in node.children(&mut decl_cursor) {
                if declarator.kind() == "variable_declarator" {
                    if let Some(name_node) = declarator.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let value_node = declarator.child_by_field_name("value");

                        // A `require(...)` binding is a dependency line, not a
                        // constant; it is already carried as a `FileImport`.
                        if value_node
                            .as_ref()
                            .is_some_and(|value| js_require_target(value, source).is_some())
                        {
                            continue;
                        }

                        // `const Foo = class extends Bar {}` is a class
                        // declaration wearing a binding.
                        if let Some(class_value) =
                            value_node.filter(|value| value.kind() == "class")
                        {
                            if !name.is_empty() {
                                extract_ts_class_like(
                                    &class_value,
                                    &name,
                                    source,
                                    file_id,
                                    entities,
                                    relations,
                                );
                            }
                            continue;
                        }

                        let kind = if value_node.as_ref().is_some_and(is_ts_function_like_node) {
                            EntityKind::Function
                        } else {
                            EntityKind::Constant
                        };
                        // Filter noise: skip re-export barrels and trivial
                        // constants, but keep named constants with a scalar
                        // literal value (e.g. `MAX_RETRIES = 5`) — trace tasks
                        // resolve through them. Object/array literals stay
                        // filtered even when named (avoids config-token bloat).
                        if kind == EntityKind::Constant {
                            if let Some(ref value) = value_node {
                                let rescue = is_named_constant(&name) && is_scalar_literal(value);
                                if is_trivial_reexport(value, source) && !rescue {
                                    continue;
                                }
                            }
                        }
                        entities.push(ExtractedEntity {
                            kind,
                            name: name.clone(),
                            signature: node_signature(&declarator, source),
                            visibility: detect_ts_visibility(node, source),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&declarator, source),
                            span: span_from_node(&declarator, file_id),
                        });
                        if let Some(value_node) = value_node.filter(is_ts_function_like_node) {
                            let context_name = name_node.utf8_text(source).unwrap_or("");
                            extract_calls_from_context(
                                &value_node,
                                source,
                                context_name,
                                relations,
                            );
                        }
                        // `const utils = { parse() {} }` is a namespace object
                        // whose function properties are the methods it owns.
                        if let Some(object) = value_node.filter(|value| value.kind() == "object") {
                            extract_js_object_methods(
                                &object, &name, source, file_id, entities, relations, owners,
                            );
                        }
                    }
                }
            }
        }
        "export_statement" => {
            // Recurse into exported declaration
            let entities_before = entities.len();
            let mut cursor = node.walk();
            let mut has_default = false;
            for child in node.children(&mut cursor) {
                if child.kind() == "default" || child.utf8_text(source).unwrap_or("") == "default" {
                    has_default = true;
                }
                extract_ts_node(&child, source, file_id, entities, relations, owners);
            }
            // If this is a default export and recursion didn't create any entities,
            // create a synthetic "default" entity so the linker can resolve
            // `import Foo from './this-file'` to something.
            if has_default && entities.len() == entities_before {
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
        "import_statement" => {}
        _ => {}
    }
}

/// Extract a class entity, its heritage edges, and its members. Shared by
/// `class Foo {}` and `const Foo = class {}`, which differ only in where the
/// name comes from.
fn extract_ts_class_like(
    node: &tree_sitter::Node,
    name: &str,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    entities.push(ExtractedEntity {
        kind: EntityKind::Class,
        name: name.to_string(),
        signature: node_signature(node, source),
        visibility: detect_ts_visibility(node, source),
        doc_summary: extract_preceding_comment(node, source),
        fingerprint: compute_fingerprint(node, source),
        span: span_from_node(node, file_id),
    });

    // Extract heritage (extends/implements)
    extract_ts_heritage(node, source, name, relations);

    // Recurse into class body for methods
    if let Some(body) = node.child_by_field_name("body") {
        let mut cursor = body.walk();
        for member in body.children(&mut cursor) {
            extract_ts_class_member(&member, source, file_id, name, entities, relations);
        }
    }
}

fn extract_ts_class_member(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_name: &str,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "method_definition" | "public_field_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let qualified = format!("{}.{}", class_name, name);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: qualified.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_ts_member_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                relations.push(ExtractedRelation {
                    call_shape: None,
                    kind: kin_model::RelationKind::Contains,
                    src_name: class_name.to_string(),
                    dst_name: qualified.clone(),
                    import_source: None,
                });
                // Extract calls within method body
                extract_calls_from_context(node, source, &qualified, relations);
            }
        }
        _ => {}
    }
}

fn is_ts_function_like_node(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        "arrow_function" | "function" | "function_expression" | "generator_function" => true,
        // React patterns: React.forwardRef(...), React.memo(...), styled('div')(...),
        // observer(...). These are call expressions that wrap component definitions.
        // Treat them as function-like so the entity gets EntityKind::Function.
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                // Check via heuristic: if any argument
                // to the call is a function-like node, it's a HOC wrapper.
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for arg in args.children(&mut cursor) {
                        if arg.is_named() && is_ts_function_like_node(&arg) {
                            return true;
                        }
                    }
                }
                // Chained calls: styled('div')({...}) — the outer call wraps
                // another call_expression which may itself be function-like.
                matches!(func.kind(), "call_expression") && is_ts_function_like_node(&func)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Returns true if a value node is a trivial re-export or non-semantic constant
/// that should not become an entity.
///
/// Examples filtered out:
/// - `export const Foo = Bar` (bare identifier re-export)
/// - `export const X = pkg.default` (member access re-export)
/// - `const x = undefined` / `null` / `true` / `false`
/// - `const a = ""` (trivial short string)
/// - `const theme = { color: '#fff', ... }` (data-only object literal)
/// - `const items = [1, 2, 3]` (data-only array literal)
/// - `const x = X as Y` / `X satisfies Y` (type assertion/narrowing)
/// - `` const x = `template` `` (template literal without function calls)
///
/// Object/array literals that contain function-like nodes (arrow functions,
/// function expressions) are kept — they represent meaningful code such as
/// React components (`styled('div')(...)`) or configuration with callbacks.
fn is_trivial_reexport(node: &tree_sitter::Node, source: &[u8]) -> bool {
    match node.kind() {
        // `const X = Y` — bare identifier re-export
        "identifier" => true,
        // `const X = pkg.Y` — member access re-export
        "member_expression" => true,
        // `const X = undefined` / `null` / `true` / `false`
        "undefined" | "null" | "true" | "false" => true,
        // Short string literals are trivial (e.g., `""`, `"x"`, `"ab"`)
        "string" => {
            let text = node.utf8_text(source).unwrap_or("");
            text.len() <= 4 // includes quotes, so `""` = 2, `"ab"` = 4
        }
        // Template literals without embedded function calls are data
        "template_string" => !subtree_contains_function_like(node),
        // Object/array literals are data unless they contain callbacks/components
        "object" | "array" => !subtree_contains_function_like(node),
        // Type assertions: `X as Type` or `X satisfies Type`
        "as_expression" | "satisfies_expression" => true,
        // Numeric literals
        "number" => true,
        // Parenthesized expressions — unwrap and re-check the inner value
        "parenthesized_expression" => node
            .child(1)
            .map(|inner| is_trivial_reexport(&inner, source))
            .unwrap_or(false),
        _ => false,
    }
}

/// Returns true if `name` looks like a deliberately-named constant
/// (e.g. `MAX_RETRIES`, `API_URL`, `HTTP_TIMEOUT_ms`, `PROBE_BASE_d6177fd8`)
/// rather than an incidental local (`x`, `count`, `tmp`). Such constants are
/// kept even when their value is a trivial scalar so trace-computation tasks
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
/// named object/array literals (config tokens, theme maps) stay filtered.
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

/// Returns true if any node in the subtree is a function-like expression.
/// Used to distinguish data-only object/array literals from meaningful code
/// (e.g., React components with arrow function callbacks).
fn subtree_contains_function_like(node: &tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if is_ts_function_like_node(&current) || current.kind() == "call_expression" {
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

fn extract_ts_heritage(
    node: &tree_sitter::Node,
    source: &[u8],
    class_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_heritage" {
            let mut heritage_cursor = child.walk();
            for clause in child.children(&mut heritage_cursor) {
                match clause.kind() {
                    "extends_clause" => {
                        // The base may be a bare identifier, a namespace member
                        // (`extends React.Component`) or a mixin call; each
                        // reduces to the rightmost identifier, which is the name
                        // the linker resolves. A generic base
                        // (`extends Base<T>`) keeps only `Base`.
                        if let Some(parent) = clause
                            .child(1)
                            .and_then(|value| js_heritage_name(&value, source))
                        {
                            relations.push(ExtractedRelation {
                                call_shape: None,
                                kind: kin_model::RelationKind::Extends,
                                src_name: class_name.to_string(),
                                dst_name: parent,
                                import_source: None,
                            });
                        }
                    }
                    "implements_clause" => {
                        let mut impl_cursor = clause.walk();
                        for iface in clause.children(&mut impl_cursor) {
                            if iface.is_named() && iface.kind() != "implements" {
                                let iface_name = iface.utf8_text(source).unwrap_or("").to_string();
                                if !iface_name.is_empty() {
                                    relations.push(ExtractedRelation {
                                        call_shape: None,
                                        kind: kin_model::RelationKind::Implements,
                                        src_name: class_name.to_string(),
                                        dst_name: iface_name,
                                        import_source: None,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn detect_ts_visibility(node: &tree_sitter::Node, _source: &[u8]) -> Visibility {
    // Check if parent is an export statement
    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" {
            return Visibility::Public;
        }
    }
    Visibility::Private
}

fn detect_ts_member_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let text = node.utf8_text(source).unwrap_or("");
    if text.starts_with("private") || text.contains("private ") {
        Visibility::Private
    } else if text.starts_with("protected") || text.contains("protected ") {
        Visibility::Internal
    } else {
        Visibility::Public
    }
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
/// The `context_name` parameter is the name of the containing function or qualified method name.
/// This identifies cross-file references (unresolved function names from AST).
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
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                        import_source: None,
                    });
                }
            }
        }
        // Recurse into child nodes
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
fn extract_ts_import_like(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    match node.kind() {
        "import_statement" => extract_ts_import(node, source),
        "export_statement" => extract_ts_export_source(node, source),
        _ => None,
    }
}

/// Extract detailed import information from an import_statement node.
/// Returns FileImport with module path and list of imported names.
fn extract_ts_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut module_path = String::new();
    let mut specifiers = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" => {
                // Extract module path from string literal
                let text = child.utf8_text(source).unwrap_or("").to_string();
                module_path = text.trim_matches(|c| c == '\'' || c == '"').to_string();
            }
            "import_clause" => {
                // Extract specifiers from import_clause
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
                            extract_ts_named_imports(&clause_child, source, &mut specifiers);
                        }
                        "namespace_import" => {
                            if let Some(import_name) =
                                extract_namespace_import_name(&clause_child, source)
                            {
                                specifiers.push(import_name);
                            }
                        }
                        "import_specifier" => {
                            // Default import or single named import
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

fn extract_ts_export_source(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
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
                extract_ts_export_specifiers(&child, source, &mut specifiers);
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

/// Extract a namespace import from `import * as util from "./util"`.
///
/// We encode namespace imports as `local_name = util` and `original_name = "*"`
/// so the linker can later resolve member calls like `util.finalizeIssue(...)`
/// to the `finalizeIssue` entity exported by that module.
fn extract_namespace_import_name(node: &tree_sitter::Node, source: &[u8]) -> Option<ImportedName> {
    let local_name = node
        .children(&mut node.walk())
        .find(|child| child.is_named())
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("")
        .to_string();

    if local_name.is_empty() {
        return None;
    }

    Some(ImportedName {
        local_name,
        original_name: Some("*".to_string()),
        is_default: false,
    })
}

/// Extract named imports from a named_imports node (e.g., `{ foo, bar as baz }`).
fn extract_ts_named_imports(
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

fn extract_ts_export_specifiers(
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
                        local_name: text.clone(),
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
                // First identifier is the original name
                original_name = Some(text.clone());
                local_name = text;
            } else if child_index == 1 {
                // After "as" keyword, next identifier is the local name
                local_name = text;
            }
            child_index += 1;
        }
    }

    if local_name.is_empty() {
        return None;
    }

    // If original_name equals local_name, don't store it (not renamed)
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

/// Detect Jest/Vitest/Mocha test calls: `test(...)`, `it(...)`, `describe(...)`.
fn extract_js_tests(node: &tree_sitter::Node, source: &[u8], tests: &mut Vec<ExtractedTest>) {
    if node.kind() == "expression_statement" || node.kind() == "call_expression" {
        let mut expr_cursor = node.walk();
        let call = if node.kind() == "expression_statement" {
            // expression_statement > call_expression
            node.children(&mut expr_cursor)
                .find(|c| c.kind() == "call_expression")
        } else {
            Some(*node)
        };
        if let Some(call_node) = call {
            if let Some(func) = call_node.child_by_field_name("function") {
                let func_name = func.utf8_text(source).unwrap_or("");
                if matches!(func_name, "test" | "it") {
                    // Extract the test name from first argument (string literal)
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
                    // Recurse into describe block body to find nested it/test calls
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        let mut cursor = args.walk();
                        for arg in args.children(&mut cursor) {
                            if arg.kind() == "arrow_function" || arg.kind() == "function" {
                                if let Some(body) = arg.child_by_field_name("body") {
                                    let mut body_cursor = body.walk();
                                    for child in body.children(&mut body_cursor) {
                                        extract_js_tests(&child, source, tests);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Recurse for top-level statements that might contain tests
    if node.kind() == "program" || node.kind() == "statement_block" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_js_tests(&child, source, tests);
        }
    }
}

/// Check if a file is a TS index file (index.ts, index.tsx).
fn is_ts_index_file(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    matches!(basename, "index.ts" | "index.tsx")
}

/// Extract the module name from a file path for index files.
/// `packages/mui-base/src/useSelect/index.ts` → `"useSelect"`
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
    fn parse_typescript_function() {
        let adapter = TypeScriptAdapter;
        let source = b"export function greet(name: string): string { return `Hello ${name}`; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let func = output
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Function)
            .unwrap();
        assert_eq!(func.kind, EntityKind::Function);
        assert_eq!(func.name, "greet");
    }

    #[test]
    fn parse_typescript_class() {
        let adapter = TypeScriptAdapter;
        let source = br#"
export class Dog extends Animal implements Pet {
    name: string;
    bark(): void {}
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let class_entities: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(class_entities.len(), 1);
        assert_eq!(class_entities[0].name, "Dog");

        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert_eq!(extends.len(), 1);
        assert_eq!(extends[0].dst_name, "Animal");
    }

    #[test]
    fn detect_broken_ast() {
        let adapter = TypeScriptAdapter;
        let source = b"function foo( { return 1; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("broken.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Incomplete { .. }));
    }

    #[test]
    fn parse_typescript_namespace_import() {
        let adapter = TypeScriptAdapter;
        let source =
            b"import * as util from './util';\nexport const run = () => util.finalizeIssue();";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "./util");
        assert_eq!(import.specifiers.len(), 1);
        assert_eq!(import.specifiers[0].local_name, "util");
        assert_eq!(import.specifiers[0].original_name.as_deref(), Some("*"));
    }

    #[test]
    fn parse_typescript_function_valued_const_as_function() {
        let adapter = TypeScriptAdapter;
        let source =
            b"export const createApp = (...args) => { hydrate(args); return mount(args); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected one function-valued const entity");
        assert_eq!(funcs[0].name, "createApp");

        let callees: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(callees.contains(&"hydrate"));
        assert!(callees.contains(&"mount"));
    }

    #[test]
    fn parse_typescript_reexport_source_as_import_context() {
        let adapter = TypeScriptAdapter;
        let source =
            b"export { hydrate } from './runtime-dom';\nexport * from '@vue/runtime-core';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
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
    fn filter_trivial_reexport_const() {
        let adapter = TypeScriptAdapter;
        // `export const Foo = Bar` is a re-export barrel — should be filtered out
        let source = b"export const Foo = Bar;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert!(
            constants.is_empty(),
            "re-export `const Foo = Bar` should be filtered out, got: {:?}",
            constants.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn keep_function_valued_const() {
        let adapter = TypeScriptAdapter;
        // Arrow function const should still be extracted as Function
        let source = b"export const handler = () => {};";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "handler");
    }

    #[test]
    fn filter_data_only_object_literal_const() {
        let adapter = TypeScriptAdapter;
        // Data-only object literals (CSS theme tokens, config values) are
        // filtered to prevent constant explosion in repos like MUI.
        let source = b"export const CONFIG = { port: 3000 };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            0,
            "data-only object literals should be filtered"
        );
    }

    #[test]
    fn keep_object_literal_with_callbacks() {
        let adapter = TypeScriptAdapter;
        // Object literals containing function-like nodes are meaningful code.
        //
        // Contract (shared with the JavaScript adapter): such a literal is a
        // namespace object, so it is kinded Class and each function property
        // becomes a Method it contains.
        let source = b"export const handlers = { onClick: () => console.log('click') };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(
            named,
            vec![
                (EntityKind::Class, "handlers"),
                (EntityKind::Method, "handlers.onClick"),
            ]
        );
    }

    #[test]
    fn keep_meaningful_string_const() {
        let adapter = TypeScriptAdapter;
        // Long string constant should be kept (meaningful value)
        let source = b"export const API_URL = \"https://api.example.com\";";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].name, "API_URL");
    }

    #[test]
    fn filter_member_expression_reexport() {
        let adapter = TypeScriptAdapter;
        // `export const X = pkg.default` — member access re-export
        let source = b"export const X = pkg.default;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert!(
            constants.is_empty(),
            "member access re-export should be filtered out"
        );
    }

    #[test]
    fn filter_nonsemantic_values() {
        let adapter = TypeScriptAdapter;
        // undefined, null, true, false should all be filtered
        let source = b"const a = undefined;\nconst b = null;\nconst c = true;\nconst d = false;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert!(
            constants.is_empty(),
            "non-semantic constants should be filtered, got: {:?}",
            constants.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_typescript_enum_variants() {
        let adapter = TypeScriptAdapter;
        let source = b"export enum Direction { Up, Down, Left, Right }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Direction");

        let variants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumVariant)
            .collect();
        assert_eq!(
            variants.len(),
            4,
            "expected 4 enum variants, got {:?}",
            variants.iter().map(|v| &v.name).collect::<Vec<_>>()
        );
        let variant_names: Vec<&str> = variants.iter().map(|v| v.name.as_str()).collect();
        assert!(variant_names.contains(&"Direction.Up"));
        assert!(variant_names.contains(&"Direction.Down"));
        assert!(variant_names.contains(&"Direction.Left"));
        assert!(variant_names.contains(&"Direction.Right"));

        // Check Contains relations
        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains && r.src_name == "Direction")
            .collect();
        assert_eq!(contains.len(), 4);
    }

    #[test]
    fn parse_ts_default_import_specifier() {
        let adapter = TypeScriptAdapter;
        let source = b"import React from 'react';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
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
    fn parse_ts_export_default_anonymous_arrow() {
        let adapter = TypeScriptAdapter;
        let source = b"export default (val: unknown): string => { return String(val); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
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
    }

    #[test]
    fn parse_ts_default_import_with_named() {
        let adapter = TypeScriptAdapter;
        let source = b"import dayjs, { Dayjs } from 'dayjs';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert!(
            import.specifiers.len() >= 2,
            "expected default + named specifier, got {}",
            import.specifiers.len()
        );
        let default_spec = import.specifiers.iter().find(|s| s.is_default);
        assert!(default_spec.is_some(), "missing default import specifier");
    }

    #[test]
    fn keep_named_numeric_constant() {
        let adapter = TypeScriptAdapter;
        // A named numeric constant must be indexed so trace-computation tasks
        // can resolve through it — even though `13` is a trivial scalar.
        let source = b"export const PROBE_BASE_d6177fd8 = 13;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.ts");
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
        let adapter = TypeScriptAdapter;
        // Positive matrix: deliberately-named constants are kept even with
        // trivial scalar values. Negative matrix: incidental lowercase locals
        // with scalar values stay filtered (avoids entity-set bloat).
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
        let file_id = FilePathId::new("test.ts");
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
