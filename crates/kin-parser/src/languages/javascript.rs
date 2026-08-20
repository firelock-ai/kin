// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, site_from_node, span_from_node,
    LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    ExtractedEntity, ExtractedRelation, ExtractedTest, ExtractedTestKind, FileImport, ImportedName,
    ParseOutput,
};

pub struct JavaScriptAdapter;

impl LanguageAdapter for JavaScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::JavaScript
    }

    fn file_extensions(&self) -> &[&str] {
        &["js", "jsx", "mjs", "cjs"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_javascript::LANGUAGE)?;
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

        // Emit Module entity for index.js/index.jsx files (JS packages).
        // This makes the module searchable by its directory name, e.g.,
        // `src/plugin/customParseFormat/index.js` → entity "customParseFormat".
        if is_js_index_file(&file_id.0) {
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

        // Read the file's property-defining helpers before walking it.
        // Declaration order does not bind a helper to its uses: express
        // declares `defineGetter` below all twelve calls to it.
        let definers = collect_js_property_definers(&root, source);

        for child in root.children(&mut cursor) {
            extract_js_node(
                &child,
                source,
                file_id,
                &mut entities,
                &mut relations,
                &mut owners,
                &definers,
            );
            if let Some(import_like) = extract_js_import_like(&child, source) {
                imports.push(import_like);
            }
            // Extract CommonJS require() calls as imports
            collect_js_require_imports(&child, source, &mut imports);
            // Detect describe/it/test calls (Jest/Vitest/Mocha)
            extract_js_tests_from_node(&child, source, &mut tests);
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

/// Receivers that own member-assigned methods: `View.prototype.lookup = ...`,
/// `res.status = ...`, `const utils = { parse() {} }`.
///
/// Such a receiver is a class in all but syntax. It is either a constructor
/// function carrying `prototype` members or a prototype object built by
/// `Object.create`, so it is kinded [`EntityKind::Class`] once extraction
/// finishes. That kind is also what puts an `Owner.method` call on the linker's
/// receiver-method and inheritance tiers, which only fire for a class-like
/// owner.
#[derive(Default)]
pub(super) struct JsOwners {
    names: std::collections::BTreeSet<String>,
    /// A stand-in binding for a receiver that never declared one in this file
    /// (`app.foo = ...` where `app` came from elsewhere). Only pushed when no
    /// real entity claims the name, so every `Contains` edge keeps a resolvable
    /// source.
    synthesized: Vec<ExtractedEntity>,
}

impl JsOwners {
    pub(super) fn record(
        &mut self,
        name: &str,
        site: &tree_sitter::Node,
        source: &[u8],
        file_id: &FilePathId,
    ) {
        if self.names.insert(name.to_string()) {
            self.synthesized.push(ExtractedEntity {
                kind: EntityKind::Class,
                name: name.to_string(),
                signature: format!("object {name}"),
                visibility: Visibility::Public,
                doc_summary: None,
                fingerprint: compute_fingerprint(site, source),
                span: span_from_node(site, file_id),
            });
        }
    }

    pub(super) fn finish(self, entities: &mut Vec<ExtractedEntity>) {
        for name in &self.names {
            // The file's `Module` node can carry the receiver's name when an
            // `index.js` sits in a directory of that name. Leave it as a module
            // and let it hold the `Contains` edge: rekinding it would claim the
            // file is a class, and pushing a second entity beside it would give
            // one file two entities under one name, which the linker's
            // (file, name) index cannot tell apart.
            if let Some(existing) = entities
                .iter_mut()
                .find(|entity| &entity.name == name && entity.kind != EntityKind::Module)
            {
                existing.kind = EntityKind::Class;
            }
        }
        for candidate in self.synthesized {
            if !entities.iter().any(|entity| entity.name == candidate.name) {
                entities.push(candidate);
            }
        }
    }
}

/// Where a property-defining helper carries each part of the definition.
///
/// `Object.defineProperty(obj, name, descriptor)` is the shape every such
/// helper forwards to, so a wrapper is described by which of ITS parameters
/// reach those three positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct JsPropertyDefiner {
    /// Argument index naming the object the property lands on.
    target: usize,
    /// Argument index carrying the property name.
    name: usize,
    /// Argument index carrying the implementation function.
    value: usize,
}

/// The canonical definer: `Object.defineProperty` itself takes the object, the
/// key, and a descriptor, in that order.
const OBJECT_DEFINE_PROPERTY: &str = "Object.defineProperty";

/// Descriptor keys whose value is the property's implementation.
const JS_DESCRIPTOR_FUNCTION_KEYS: &[&str] = &["get", "set", "value"];

/// Local helpers that define a property by forwarding to
/// `Object.defineProperty`, keyed by the helper's own name.
///
/// This is recognized by what a function DOES, never by what it is called.
/// express writes `defineGetter(req, 'ip', fn)`, but a positional rule that
/// admitted any `ident(ident, 'string', function)` call would also admit
/// `registerHandler(emitter, 'click', fn)` and invent an `emitter.click`
/// property that no code defines. So the helper has to be read: its body must
/// pass its own parameters through to `Object.defineProperty`, and the
/// parameter positions it uses are what the call sites are then read with.
///
/// Collected in a pass of its own because declaration order does not bind a
/// helper to its uses. express declares `defineGetter` at the foot of
/// `lib/request.js`, below all twelve calls to it, so a single forward walk
/// reaches every call site before it has ever seen the helper.
pub(super) fn collect_js_property_definers(
    root: &tree_sitter::Node,
    source: &[u8],
) -> std::collections::HashMap<String, JsPropertyDefiner> {
    let mut definers = std::collections::HashMap::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "function_declaration" && child.kind() != "function" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let Ok(name) = name_node.utf8_text(source) else {
            continue;
        };
        let params = js_parameter_names(&child, source);
        if params.is_empty() {
            continue;
        }
        let Some(body) = child.child_by_field_name("body") else {
            continue;
        };
        if let Some(shape) = js_forwarded_define_property(&body, source, &params) {
            definers.insert(name.to_string(), shape);
        }
    }
    definers
}

/// A function's parameter names in declaration order. A destructured or
/// defaulted parameter yields an empty slot rather than being skipped, so the
/// positions of the parameters around it stay truthful.
fn js_parameter_names(function: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let Some(params) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = params.walk();
    for param in params.children(&mut cursor) {
        if !param.is_named() {
            continue;
        }
        names.push(if param.kind() == "identifier" {
            param.utf8_text(source).unwrap_or("").to_string()
        } else {
            String::new()
        });
    }
    names
}

/// The parameter positions a body forwards to `Object.defineProperty`, when it
/// forwards all three from its own parameter list.
///
/// A body that hands `Object.defineProperty` anything else, a captured local, a
/// literal, a computed expression, is not a general property definer and its
/// call sites say nothing about what property gets defined, so it is refused.
fn js_forwarded_define_property(
    body: &tree_sitter::Node,
    source: &[u8],
    params: &[String],
) -> Option<JsPropertyDefiner> {
    let call = js_find_define_property_call(body, source)?;
    let args = js_call_arguments(&call);
    let target = js_parameter_index(args.first(), source, params)?;
    let name = js_parameter_index(args.get(1), source, params)?;
    let descriptor = args.get(2)?;
    let value = js_descriptor_parameter_index(descriptor, source, params)?;
    Some(JsPropertyDefiner {
        target,
        name,
        value,
    })
}

/// The first `Object.defineProperty(...)` call anywhere inside `node`.
fn js_find_define_property_call<'t>(
    node: &tree_sitter::Node<'t>,
    source: &[u8],
) -> Option<tree_sitter::Node<'t>> {
    if node.kind() == "call_expression" {
        if let Some(function) = node.child_by_field_name("function") {
            if function.utf8_text(source).unwrap_or("") == OBJECT_DEFINE_PROPERTY {
                return Some(*node);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = js_find_define_property_call(&child, source) {
            return Some(found);
        }
    }
    None
}

/// The named argument nodes of a call, in order.
fn js_call_arguments<'t>(call: &tree_sitter::Node<'t>) -> Vec<tree_sitter::Node<'t>> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.children(&mut cursor)
        .filter(|arg| arg.is_named() && arg.kind() != "comment")
        .collect()
}

/// The position of `node` in `params`, when `node` is a bare identifier naming
/// one of them.
fn js_parameter_index(
    node: Option<&tree_sitter::Node>,
    source: &[u8],
    params: &[String],
) -> Option<usize> {
    let node = node?;
    if node.kind() != "identifier" {
        return None;
    }
    let text = node.utf8_text(source).ok()?;
    if text.is_empty() {
        return None;
    }
    params.iter().position(|param| param == text)
}

/// The position of the parameter a descriptor object hands to `get`, `set`, or
/// `value`.
fn js_descriptor_parameter_index(
    descriptor: &tree_sitter::Node,
    source: &[u8],
    params: &[String],
) -> Option<usize> {
    if descriptor.kind() != "object" {
        return None;
    }
    let mut cursor = descriptor.walk();
    for property in descriptor.children(&mut cursor) {
        if property.kind() != "pair" {
            continue;
        }
        let Some(key) = property.child_by_field_name("key") else {
            continue;
        };
        let key_text = key
            .utf8_text(source)
            .unwrap_or("")
            .trim_matches(|c| c == '"' || c == '\'');
        if !JS_DESCRIPTOR_FUNCTION_KEYS.contains(&key_text) {
            continue;
        }
        let value = property.child_by_field_name("value")?;
        if let Some(index) = js_parameter_index(Some(&value), source, params) {
            return Some(index);
        }
    }
    None
}

/// The implementation function a descriptor object supplies inline.
fn js_descriptor_function<'t>(
    descriptor: &tree_sitter::Node<'t>,
    source: &[u8],
) -> Option<tree_sitter::Node<'t>> {
    if descriptor.kind() != "object" {
        return None;
    }
    let mut cursor = descriptor.walk();
    for property in descriptor.children(&mut cursor) {
        if property.kind() != "pair" {
            continue;
        }
        let Some(key) = property.child_by_field_name("key") else {
            continue;
        };
        let key_text = key
            .utf8_text(source)
            .unwrap_or("")
            .trim_matches(|c| c == '"' || c == '\'');
        if !JS_DESCRIPTOR_FUNCTION_KEYS.contains(&key_text) {
            continue;
        }
        if let Some(value) = property.child_by_field_name("value") {
            if is_js_function_like_node(&value) {
                return Some(value);
            }
        }
    }
    None
}

/// The string a literal argument spells, when it is usable as a property name.
fn js_string_literal_value(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() != "string" && node.kind() != "template_string" {
        return None;
    }
    let text = node
        .utf8_text(source)
        .ok()?
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    if text.is_empty() || text.contains(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$')) {
        return None;
    }
    Some(text.to_string())
}

/// Extract the property a `defineProperty`-shaped statement defines.
///
/// `defineGetter(req, 'ip', function ip(){ ... })` defines `req.ip` exactly as
/// `req.get = function header(){ ... }` defines `req.get`, and both are the
/// same thing to a reader of express. Only the assignment form was ever an
/// entity, so twelve of the request API's most-used properties, `query`,
/// `protocol`, `secure`, `ip`, `ips`, `subdomains`, `path`, `host`,
/// `hostname`, `fresh`, `stale` and `xhr`, could not be located, packed or
/// traced at all.
///
/// The entity spans the whole statement rather than the getter body, because
/// the body is inside the statement and a position lookup for a line in the
/// body has to land here. It is kinded a method for the same reason its
/// assignment-form siblings are: it is a function on an owner, and that kind is
/// what puts `Owner.member` on the linker's receiver-method tier.
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_js_property_definition(
    stmt: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    owners: &mut JsOwners,
    definers: &std::collections::HashMap<String, JsPropertyDefiner>,
) -> bool {
    let mut cursor = stmt.walk();
    let Some(call) = stmt
        .children(&mut cursor)
        .find(|child| child.kind() == "call_expression")
    else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let callee = function.utf8_text(source).unwrap_or("");
    let args = js_call_arguments(&call);

    let (target_node, name_node, implementation) = if callee == OBJECT_DEFINE_PROPERTY {
        let (Some(target), Some(name), Some(descriptor)) =
            (args.first(), args.get(1), args.get(2))
        else {
            return false;
        };
        let Some(function_node) = js_descriptor_function(descriptor, source) else {
            // A data property carries no implementation to model. Refused
            // rather than recorded as a method it is not.
            return false;
        };
        (*target, *name, function_node)
    } else {
        let Some(shape) = definers.get(callee) else {
            return false;
        };
        let (Some(target), Some(name), Some(value)) = (
            args.get(shape.target),
            args.get(shape.name),
            args.get(shape.value),
        ) else {
            return false;
        };
        if !is_js_function_like_node(value) {
            return false;
        }
        (*target, *name, *value)
    };

    if target_node.kind() != "identifier" {
        return false;
    }
    let receiver = target_node.utf8_text(source).unwrap_or("");
    let Some(owner) = js_method_owner(receiver) else {
        return false;
    };
    let Some(property) = js_string_literal_value(&name_node, source) else {
        return false;
    };

    let qualified = format!("{owner}.{property}");
    owners.record(owner, &target_node, source, file_id);
    entities.push(ExtractedEntity {
        kind: EntityKind::Method,
        name: qualified.clone(),
        signature: node_signature(stmt, source),
        visibility: Visibility::Public,
        doc_summary: extract_preceding_comment(stmt, source),
        fingerprint: compute_fingerprint(stmt, source),
        span: span_from_node(stmt, file_id),
    });
    relations.push(ExtractedRelation {
        site: None,
        receiver: None,
        call_shape: None,
        kind: kin_model::RelationKind::Contains,
        src_name: owner.to_string(),
        dst_name: qualified.clone(),
        import_source: None,
    });
    extract_calls_from_context(&implementation, source, &qualified, Some(owner), relations);
    true
}

#[allow(clippy::too_many_arguments)]
fn extract_js_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    owners: &mut JsOwners,
    definers: &std::collections::HashMap<String, JsPropertyDefiner>,
) {
    match node.kind() {
        "function_declaration" | "function" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: detect_js_visibility(node),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                // Extract calls within function body
                extract_calls_from_context(node, source, &name, None, relations);
            }
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                extract_js_class_like(node, &name, source, file_id, entities, relations);
            }
        }
        "expression_statement" => {
            // `Object.defineProperty(obj, 'name', {...})` and the local
            // helpers that forward to it define a member exactly as an
            // assignment does; neither is an assignment, so it is tried first
            // and the assignment path is left untouched when it fires.
            if extract_js_property_definition(
                node, source, file_id, entities, relations, owners, definers,
            ) {
                return;
            }
            // Handle prototype method assignments: obj.method = function() {}
            // and module.exports = function name() {}
            extract_js_assignment_function(node, source, file_id, entities, relations, owners);
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut decl_cursor = node.walk();
            for declarator in node.children(&mut decl_cursor) {
                if declarator.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name_node) = declarator
                    .child_by_field_name("name")
                    .or_else(|| declarator.named_child(0))
                else {
                    continue;
                };
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                let value_node = declarator.child_by_field_name("value");

                // A `require(...)` binding is a dependency line, not a constant.
                // It is already carried as a `FileImport` with its specifiers,
                // and emitting a Constant beside it doubled every dependency
                // into the entity set: on express those bindings were the bulk
                // of the 451 constants that buried 133 functions.
                if value_node
                    .as_ref()
                    .is_some_and(|value| js_require_target(value, source).is_some())
                {
                    continue;
                }

                // `const Foo = class extends Bar {}` is a class declaration
                // wearing a binding; model it as the class it is.
                if let Some(class_value) = value_node.filter(|value| value.kind() == "class") {
                    if !name.is_empty() {
                        extract_js_class_like(
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

                let is_function_like = value_node.as_ref().is_some_and(is_js_function_like_node);
                let kind = if is_function_like {
                    EntityKind::Function
                } else {
                    EntityKind::Constant
                };
                // Filter data-only constants: object/array literals, bare
                // identifiers, strings, etc. without function calls or
                // callbacks are noise (CSS theme tokens, locale strings,
                // config objects). Keeps constants initialized with call
                // expressions (React.forwardRef, styled, memo) or containing
                // arrow functions — these represent real code entities.
                if kind == EntityKind::Constant {
                    if let Some(ref value) = value_node {
                        // Keep named constants with a scalar literal value
                        // (e.g. `MAX_RETRIES = 5`) so trace tasks resolve
                        // through them. Object/array literals stay filtered
                        // even when named (avoids config-token bloat).
                        let rescue = is_named_constant(&name) && is_scalar_literal(value);
                        if is_data_only_js_value(value) && !rescue {
                            continue;
                        }
                    }
                }
                entities.push(ExtractedEntity {
                    kind,
                    name: name.clone(),
                    signature: node_signature(&declarator, source),
                    visibility: detect_js_visibility(node),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(&declarator, source),
                    span: span_from_node(&declarator, file_id),
                });
                if let Some(value_node) = value_node.filter(is_js_function_like_node) {
                    let context_name = name_node.utf8_text(source).unwrap_or("");
                    extract_calls_from_context(&value_node, source, context_name, None, relations);
                }
                // `const utils = { parse() {}, print: () => {} }` is a namespace
                // object whose function properties are the methods it owns.
                if let Some(object) = value_node.filter(|value| value.kind() == "object") {
                    extract_js_object_methods(
                        &object, &name, source, file_id, entities, relations, owners,
                    );
                }
            }
        }
        "export_statement" => {
            let entities_before = entities.len();
            let mut cursor = node.walk();
            let mut has_default = false;
            for child in node.children(&mut cursor) {
                if child.kind() == "default" || child.utf8_text(source).unwrap_or("") == "default" {
                    has_default = true;
                }
                extract_js_node(&child, source, file_id, entities, relations, owners, definers);
            }
            // If this is a default export and recursion didn't create any entities,
            // create a synthetic "default" entity so the linker can resolve
            // `import Foo from './this-file'` to something.
            if has_default && entities.len() == entities_before {
                // Find the exported value (skip "export" and "default" keywords)
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
        "import_statement" => {
            // Import handling is done via FileImport records (extract_js_import).
            // The linker creates Imports edges from FileImport specifiers.
        }
        _ => {}
    }
}

fn is_js_function_like_node(node: &tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "function_expression" | "function" | "arrow_function" | "generator_function"
    )
}

/// Returns true if `name` looks like a deliberately-named constant
/// (e.g. `MAX_RETRIES`, `API_URL`, `HTTP_TIMEOUT_ms`, `PROBE_BASE_d6177fd8`)
/// rather than an incidental local (`x`, `count`, `tmp`). Such constants are
/// kept even when their value is a data-only scalar so trace-computation tasks
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
/// named object/array literals (theme tokens, config maps) stay filtered.
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

/// Returns true if a value node is a data-only constant that should be
/// filtered from entity extraction. Data-only values are object literals,
/// array literals, bare identifiers, and other non-functional patterns that
/// create noise in large repos like MUI (45K CSS theme tokens, locale objects).
///
/// Values containing function calls, arrow functions, or other executable
/// code are preserved — these represent meaningful code like React components
/// (e.g., `createSvgIcon(...)`, `styled('div')(...)`).
fn is_data_only_js_value(node: &tree_sitter::Node) -> bool {
    match node.kind() {
        // Bare identifier re-exports: `const X = Y`
        "identifier" => true,
        // Member access re-exports: `const X = pkg.Y`
        "member_expression" => !js_subtree_contains_function_like(node),
        // Primitives
        "undefined" | "null" | "true" | "false" | "number" => true,
        // Short strings are trivial (includes quotes, so "ab" = 4 bytes)
        "string" => node.byte_range().len() <= 4,
        // Template literals without function calls
        "template_string" => !js_subtree_contains_function_like(node),
        // Object/array literals: only data if no function-like children
        "object" | "array" => !js_subtree_contains_function_like(node),
        // Parenthesized: unwrap
        "parenthesized_expression" => node
            .child(1)
            .map(|inner| is_data_only_js_value(&inner))
            .unwrap_or(false),
        _ => false,
    }
}

/// Returns true if any node in the subtree is a function-like expression
/// or a call expression. Used to distinguish data-only object/array literals
/// from meaningful code (React components, styled-components, etc.).
fn js_subtree_contains_function_like(node: &tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if is_js_function_like_node(&current) || current.kind() == "call_expression" {
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

/// Extract a usable entity name from the LHS of an assignment.
/// For `member_expression` like `app.init` or `module.exports`, returns the property name.
/// For plain `identifier`, returns it directly.
fn extract_assignment_lhs_name(lhs: &tree_sitter::Node, source: &[u8]) -> String {
    match lhs.kind() {
        "member_expression" => {
            // Use the property (rightmost) part: app.init → "init", module.exports → "module.exports"
            let obj_text = lhs
                .child_by_field_name("object")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            let prop_text = lhs
                .child_by_field_name("property")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            // For module.exports, keep the full name since it's the module entry point
            if obj_text == "module" && prop_text == "exports" {
                "module.exports".to_string()
            } else {
                // Use the property name (e.g., app.init → "init", proto.method → "method")
                prop_text.to_string()
            }
        }
        "identifier" => lhs.utf8_text(source).unwrap_or("").to_string(),
        _ => lhs.utf8_text(source).unwrap_or("").to_string(),
    }
}

/// Split a `member_expression` assignment target into its receiver path and the
/// property being assigned: `res.status` -> (`res`, `status`),
/// `View.prototype.lookup` -> (`View.prototype`, `lookup`).
fn split_member_lhs(lhs: &tree_sitter::Node, source: &[u8]) -> Option<(String, String)> {
    let object = lhs.child_by_field_name("object")?;
    let property = lhs.child_by_field_name("property")?;
    Some((
        object.utf8_text(source).ok()?.to_string(),
        property.utf8_text(source).ok()?.to_string(),
    ))
}

/// The entity that owns a member assignment, or `None` when the receiver is a
/// module-export namespace, a runtime global, or a path this adapter does not
/// model.
///
/// `Foo.prototype` and `Foo` name the same owner: `Foo.prototype.bar` and
/// `Foo.bar` are both reached as `bar` on a `Foo`, and collapsing them yields
/// the `Owner.method` key the linker already resolves for Python and C++.
/// `module.exports` and `exports` are the module's public surface rather than an
/// object with methods, so their members stay module-level functions.
pub(super) fn js_method_owner(receiver_path: &str) -> Option<&str> {
    let base = receiver_path
        .strip_suffix(".prototype")
        .unwrap_or(receiver_path);
    if base.is_empty()
        || base.contains('.')
        || matches!(
            base,
            "module" | "exports" | "this" | "window" | "global" | "globalThis" | "self"
        )
    {
        return None;
    }
    base.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        .then_some(base)
}

/// Extract entities from a top-level assignment statement:
/// `res.status = function status() {}`, `res.set = res.header = function() {}`,
/// `View.prototype.lookup = function() {}`, `module.exports = { a() {} }`.
pub(super) fn extract_js_assignment_function(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    owners: &mut JsOwners,
) {
    // Find the assignment_expression child
    let assign = {
        let mut cursor = node.walk();
        let mut found = None;
        for child in node.children(&mut cursor) {
            if child.kind() == "assignment_expression" {
                found = Some(child);
                break;
            }
        }
        found
    };
    let Some(assign) = assign else {
        return;
    };

    // Unwrap a chained assignment so every target on the chain is modeled.
    // `res.contentType = res.type = function contentType(t) {}` defines both
    // names; reading only the outermost right-hand side sees another assignment
    // and records neither.
    let mut targets = Vec::new();
    let mut current = assign;
    let value = loop {
        let (Some(lhs), Some(rhs)) = (
            current.child_by_field_name("left"),
            current.child_by_field_name("right"),
        ) else {
            return;
        };
        targets.push(lhs);
        if rhs.kind() == "assignment_expression" {
            current = rhs;
        } else {
            break rhs;
        }
    };

    for lhs in targets {
        extract_js_assignment_target(
            node, &lhs, &value, source, file_id, entities, relations, owners,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_js_assignment_target(
    stmt: &tree_sitter::Node,
    lhs: &tree_sitter::Node,
    value: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    owners: &mut JsOwners,
) {
    let member = (lhs.kind() == "member_expression")
        .then(|| split_member_lhs(lhs, source))
        .flatten();

    // A receiver that is not the module-export namespace owns what is assigned
    // to it: `res.status = function () {}` is a method on `res`, the shape
    // express-era JavaScript uses instead of an ES class.
    if let Some((receiver_path, property)) = &member {
        if let Some(owner) = js_method_owner(receiver_path) {
            if is_js_function_like_node(value) && !property.is_empty() {
                let qualified = format!("{owner}.{property}");
                owners.record(owner, lhs, source, file_id);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Method,
                    name: qualified.clone(),
                    signature: node_signature(stmt, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(stmt, source),
                    fingerprint: compute_fingerprint(stmt, source),
                    span: span_from_node(stmt, file_id),
                });
                relations.push(ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: kin_model::RelationKind::Contains,
                    src_name: owner.to_string(),
                    dst_name: qualified.clone(),
                    import_source: None,
                });
                extract_calls_from_context(value, source, &qualified, Some(owner), relations);
            }
            return;
        }

        // `exports.X = <expr>` and `module.exports.X = <expr>` export X
        // whatever the right-hand side is. A function literal is named by the
        // tail of this function; every other right-hand side produced no entity
        // at all, so express's `exports.etag = createETagGenerator({ weak: false })`
        // was absent from the graph rather than merely unlinked. That is worse
        // than an unresolved reference: an export sweep run from the graph over
        // `lib/utils.js` returns six of its nine exports and reports nothing
        // missing, because from the graph's side there is nothing to hedge about.
        if matches!(receiver_path.as_str(), "exports" | "module.exports")
            && !property.is_empty()
            && !is_js_function_like_node(value)
            // A `require(...)` re-export already reaches the graph as a
            // `FileImport` specifier under this same name. Emitting a constant
            // beside it would double every re-exported dependency, which is the
            // shape that buried express's functions under 451 constants.
            && js_require_target(value, source).is_none()
        {
            entities.push(ExtractedEntity {
                kind: if value.kind() == "class" {
                    EntityKind::Class
                } else {
                    EntityKind::Constant
                },
                name: property.clone(),
                signature: node_signature(stmt, source),
                visibility: Visibility::Public,
                doc_summary: extract_preceding_comment(stmt, source),
                fingerprint: compute_fingerprint(stmt, source),
                span: span_from_node(stmt, file_id),
            });
            // The factory an export is built from is the one edge that makes
            // it reachable: `exports.etag` calls `createETagGenerator`. The
            // statement is what gets walked rather than the value, because the
            // walk tests a node's children and the value here IS the call.
            extract_calls_from_context(stmt, source, property, None, relations);
        }

        // `module.exports = { parse() {}, print() {} }` is the CommonJS way of
        // exporting a set of functions. Give each property its own entity so
        // `require('./m').parse` has something to bind to.
        if value.kind() == "object" && matches!(receiver_path.as_str(), "module" | "exports") {
            for (property_name, function_node) in js_object_literal_methods(value, source) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: property_name.clone(),
                    signature: node_signature(&function_node, source),
                    visibility: Visibility::Public,
                    doc_summary: extract_preceding_comment(&function_node, source),
                    fingerprint: compute_fingerprint(&function_node, source),
                    span: span_from_node(&function_node, file_id),
                });
                extract_calls_from_context(&function_node, source, &property_name, None, relations);
            }
            return;
        }
    }

    if !is_js_function_like_node(value) {
        return;
    }
    // Determine the entity name: prefer the function's own name, fall back to LHS property
    let name = matches!(
        value.kind(),
        "function_expression" | "function" | "generator_function"
    )
    .then(|| {
        value
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.to_string())
    })
    .flatten()
    .unwrap_or_else(|| extract_assignment_lhs_name(lhs, source));
    if name.is_empty() {
        return;
    }
    entities.push(ExtractedEntity {
        kind: EntityKind::Function,
        name: name.clone(),
        signature: node_signature(stmt, source),
        visibility: Visibility::Public,
        doc_summary: extract_preceding_comment(stmt, source),
        fingerprint: compute_fingerprint(stmt, source),
        span: span_from_node(stmt, file_id),
    });
    extract_calls_from_context(value, source, &name, None, relations);
}

/// The function-valued properties of an object literal, as
/// (property name, function node) pairs. Covers shorthand methods (`a() {}`),
/// function-expression properties (`a: function () {}`) and arrow properties
/// (`a: () => {}`).
pub(super) fn js_object_literal_methods<'a>(
    object: &tree_sitter::Node<'a>,
    source: &[u8],
) -> Vec<(String, tree_sitter::Node<'a>)> {
    let mut found = Vec::new();
    let mut cursor = object.walk();
    for child in object.children(&mut cursor) {
        match child.kind() {
            "method_definition" => {
                if let Some(name) = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                {
                    if !name.is_empty() {
                        found.push((name.to_string(), child));
                    }
                }
            }
            "pair" => {
                let (Some(key), Some(value)) = (
                    child.child_by_field_name("key"),
                    child.child_by_field_name("value"),
                ) else {
                    continue;
                };
                if !is_js_function_like_node(&value) {
                    continue;
                }
                let name = key
                    .utf8_text(source)
                    .unwrap_or("")
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                    .to_string();
                if !name.is_empty() {
                    found.push((name, value));
                }
            }
            _ => {}
        }
    }
    found
}

/// Emit `Method` entities and `Contains` edges for the function properties of a
/// named object literal (`const utils = { parse() {} }` -> `utils.parse`).
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_js_object_methods(
    object: &tree_sitter::Node,
    owner: &str,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    owners: &mut JsOwners,
) {
    if js_method_owner(owner).is_none() {
        return;
    }
    for (property_name, function_node) in js_object_literal_methods(object, source) {
        let qualified = format!("{owner}.{property_name}");
        owners.record(owner, object, source, file_id);
        entities.push(ExtractedEntity {
            kind: EntityKind::Method,
            name: qualified.clone(),
            signature: node_signature(&function_node, source),
            visibility: Visibility::Public,
            doc_summary: extract_preceding_comment(&function_node, source),
            fingerprint: compute_fingerprint(&function_node, source),
            span: span_from_node(&function_node, file_id),
        });
        relations.push(ExtractedRelation {
            site: None,
            receiver: None,
            call_shape: None,
            kind: kin_model::RelationKind::Contains,
            src_name: owner.to_string(),
            dst_name: qualified.clone(),
            import_source: None,
        });
        extract_calls_from_context(&function_node, source, &qualified, Some(owner), relations);
    }
}

/// Extract a class entity, its `Extends` edge, and its members. Shared by
/// `class Foo {}` and `const Foo = class {}`, which differ only in where the
/// name comes from.
fn extract_js_class_like(
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
        visibility: detect_js_visibility(node),
        doc_summary: extract_preceding_comment(node, source),
        fingerprint: compute_fingerprint(node, source),
        span: span_from_node(node, file_id),
    });

    // Extract Extends relation for class inheritance.
    // tree-sitter-javascript: class_declaration → class_heritage → <expression>.
    // The base may be a bare identifier (`extends Animal`), a namespace member
    // (`extends React.Component`) or a mixin call (`extends mixin(Base)`); each
    // reduces to the rightmost identifier, which is the name the linker resolves.
    let mut heritage_cursor = node.walk();
    for child in node.children(&mut heritage_cursor) {
        if child.kind() != "class_heritage" {
            continue;
        }
        let mut hc = child.walk();
        for hchild in child.children(&mut hc) {
            let Some(parent_name) = js_heritage_name(&hchild, source) else {
                continue;
            };
            relations.push(ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: None,
                kind: kin_model::RelationKind::Extends,
                src_name: name.to_string(),
                dst_name: parent_name,
                import_source: None,
            });
            break;
        }
        break;
    }

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    let mut body_cursor = body.walk();
    for member in body.children(&mut body_cursor) {
        // `method_definition` covers methods, getters, setters and static
        // members. `field_definition` is a method only when its value is a
        // function (`handleClick = () => {}`, the React class-property form);
        // a data field is not a callable and stays out of the graph. The
        // grammar gives `field_definition` no `name`/`value` fields, so its
        // parts are read positionally: the property first, the initializer last.
        let name_node = match member.kind() {
            "method_definition" => member.child_by_field_name("name"),
            "field_definition" => {
                let mut field_cursor = member.walk();
                let parts: Vec<tree_sitter::Node> =
                    member.named_children(&mut field_cursor).collect();
                match parts.last() {
                    Some(initializer) if is_js_function_like_node(initializer) => {
                        parts.first().copied()
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        let Some(method_name) = name_node
            .and_then(|n| n.utf8_text(source).ok())
            .filter(|n| !n.is_empty())
        else {
            continue;
        };
        let qualified = format!("{name}.{method_name}");
        entities.push(ExtractedEntity {
            kind: EntityKind::Method,
            name: qualified.clone(),
            signature: node_signature(&member, source),
            visibility: Visibility::Public,
            doc_summary: extract_preceding_comment(&member, source),
            fingerprint: compute_fingerprint(&member, source),
            span: span_from_node(&member, file_id),
        });
        relations.push(ExtractedRelation {
            site: None,
            receiver: None,
            call_shape: None,
            kind: kin_model::RelationKind::Contains,
            src_name: name.to_string(),
            dst_name: qualified.clone(),
            import_source: None,
        });
        // Extract calls within method body
        extract_calls_from_context(&member, source, &qualified, Some(name), relations);
    }
}

/// The name a `class_heritage` child contributes to an `Extends` edge: the
/// rightmost identifier of the base expression, or `None` for the `extends`
/// keyword and other unnamed nodes.
pub(super) fn js_heritage_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if !node.is_named() {
        return None;
    }
    match node.kind() {
        "identifier" => Some(node.utf8_text(source).ok()?.to_string()),
        "member_expression" => Some(
            node.child_by_field_name("property")?
                .utf8_text(source)
                .ok()?
                .to_string(),
        ),
        "call_expression" => js_heritage_name(&node.child_by_field_name("function")?, source),
        _ => None,
    }
    .filter(|name| !name.is_empty())
}

fn detect_js_visibility(node: &tree_sitter::Node) -> Visibility {
    if let Some(parent) = node.parent() {
        if parent.kind() == "export_statement" {
            return Visibility::Public;
        }
    }
    Visibility::Private
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

/// Whether a member call's receiver is provably the enclosing owner: `this.m()`
/// inside one of the owner's own methods, or `Owner.m()` naming the owner's own
/// binding from inside it.
///
/// Both are settled by the syntax rather than guessed, which is what lets the
/// callee be recorded owner-qualified. Any other receiver is a value that could
/// hold anything at run time (a parameter, an imported binding, a property chain
/// such as `this.router.handle`), so it keeps its bare leaf.
fn js_receiver_is_enclosing_owner(
    function: &tree_sitter::Node,
    source: &[u8],
    owner: &str,
) -> bool {
    let Some(object) = function.child_by_field_name("object") else {
        return false;
    };
    match object.kind() {
        "this" => true,
        "identifier" => object.utf8_text(source).is_ok_and(|text| text == owner),
        _ => false,
    }
}

/// Extract all function/method calls within a function/method body.
///
/// For a `call_expression`, the `function` field is the callee. A
/// `member_expression` callee normally unpacks to the rightmost identifier
/// (`a.b()` -> `b`), so graph edges key on the simple method name rather than
/// the dotted source text.
///
/// `owner` names the class or receiver object whose method body this is, when
/// there is one. A call through that same owner is recorded as `Owner.method`,
/// the same key the adapter gives the method entity itself, which is how a
/// sibling method in one file becomes reachable: every tier that matches a bare
/// method leaf considers cross-file candidates only, so only the exact same-file
/// tier can bind a sibling and it needs the qualified name. Where the qualified
/// name matches no entity the linker falls back to the bare leaf, so recall
/// never drops below the unqualified behavior.
///
/// `new X()` is a `new_expression` (not `call_expression`) and is intentionally
/// skipped here.
pub(super) fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    owner: Option<&str>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                let callee_name = match function.kind() {
                    "member_expression" => {
                        let property = function
                            .child_by_field_name("property")
                            .map(|f| f.utf8_text(source).unwrap_or("").to_string())
                            .unwrap_or_default();
                        match owner {
                            Some(owner)
                                if !property.is_empty()
                                    && js_receiver_is_enclosing_owner(&function, source, owner) =>
                            {
                                format!("{owner}.{property}")
                            }
                            _ => property,
                        }
                    }
                    "identifier" => function.utf8_text(source).unwrap_or("").to_string(),
                    _ => String::new(),
                };
                if is_valid_callee_name(&callee_name) {
                    relations.push(ExtractedRelation {
                        // The `call_expression` node, so a reference row can report
                        // the line the call is written on rather than the line the
                        // caller's definition starts on.
                        site: Some(site_from_node(&child)),
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee_name,
                        import_source: None,
                    });
                }
            }
        }
        extract_calls_from_context(&child, source, context_name, owner, relations);
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
fn extract_js_import_like(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    match node.kind() {
        "import_statement" => extract_js_import(node, source),
        "export_statement" => extract_js_export_source(node, source),
        _ => None,
    }
}

/// Extract detailed import information from an import_statement node.
fn extract_js_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut module_path = String::new();
    let mut specifiers = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" => {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                module_path = text.trim_matches(|c| c == '\'' || c == '"').to_string();
            }
            "import_clause" => {
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
                            extract_js_named_imports(&clause_child, source, &mut specifiers);
                        }
                        "import_specifier" => {
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

fn extract_js_export_source(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
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
                extract_js_export_specifiers(&child, source, &mut specifiers);
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

/// Extract named imports from a named_imports node (e.g., `{ foo, bar as baz }`).
fn extract_js_named_imports(
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

fn extract_js_export_specifiers(
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
                        local_name: text,
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
                original_name = Some(text.clone());
                local_name = text;
            } else if child_index == 1 {
                local_name = text;
            }
            child_index += 1;
        }
    }

    if local_name.is_empty() {
        return None;
    }

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

/// The module a `require(...)` expression names, plus the member picked off it.
///
/// Covers the three shapes a CommonJS dependency line actually takes:
/// `require('m')`, `require('m').x` (a named export bound directly) and
/// `require('m')(args)` (a module that is itself a factory). Anything else is
/// not a require expression.
pub(super) fn js_require_target(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<(String, Option<String>)> {
    match node.kind() {
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            if function.kind() == "identifier" && function.utf8_text(source).ok()? == "require" {
                let arguments = node.child_by_field_name("arguments")?;
                let mut cursor = arguments.walk();
                let literal = arguments
                    .children(&mut cursor)
                    .find(|arg| arg.kind() == "string")?;
                let module_path = literal
                    .utf8_text(source)
                    .ok()?
                    .trim_matches(|c| c == '\'' || c == '"' || c == '`')
                    .to_string();
                return (!module_path.is_empty()).then_some((module_path, None));
            }
            // `require('depd')('express')` still binds that module to the name.
            js_require_target(&function, source).map(|(module_path, _)| (module_path, None))
        }
        "member_expression" => {
            let object = node.child_by_field_name("object")?;
            let (module_path, _) = js_require_target(&object, source)?;
            let member = node
                .child_by_field_name("property")?
                .utf8_text(source)
                .ok()?
                .to_string();
            Some((module_path, (!member.is_empty()).then_some(member)))
        }
        _ => None,
    }
}

/// The specifiers a require binding contributes: one for an identifier target,
/// one per destructured key for `const { a, b: c } = require('m')`.
fn js_require_specifiers(
    name: &tree_sitter::Node,
    member: Option<&str>,
    source: &[u8],
) -> Vec<ImportedName> {
    match name.kind() {
        "identifier" => {
            let local_name = name.utf8_text(source).unwrap_or("").to_string();
            if local_name.is_empty() {
                return Vec::new();
            }
            vec![ImportedName {
                local_name,
                original_name: member.map(str::to_string),
                is_default: member.is_none(),
            }]
        }
        "object_pattern" => {
            let mut specifiers = Vec::new();
            let mut cursor = name.walk();
            for child in name.children(&mut cursor) {
                match child.kind() {
                    "shorthand_property_identifier_pattern" => {
                        let local_name = child.utf8_text(source).unwrap_or("").to_string();
                        if !local_name.is_empty() {
                            specifiers.push(ImportedName {
                                local_name,
                                original_name: None,
                                is_default: false,
                            });
                        }
                    }
                    "pair_pattern" => {
                        let original_name = child
                            .child_by_field_name("key")
                            .and_then(|n| n.utf8_text(source).ok())
                            .unwrap_or("")
                            .to_string();
                        let local_name = child
                            .child_by_field_name("value")
                            .and_then(|n| n.utf8_text(source).ok())
                            .unwrap_or("")
                            .to_string();
                        if !original_name.is_empty() && !local_name.is_empty() {
                            specifiers.push(ImportedName {
                                local_name,
                                original_name: Some(original_name),
                                is_default: false,
                            });
                        }
                    }
                    _ => {}
                }
            }
            specifiers
        }
        _ => Vec::new(),
    }
}

/// Record every CommonJS `require(...)` in a top-level statement as a
/// [`FileImport`].
///
/// ESM `import` is handled by `extract_js_import`; this is the half of the
/// import surface express-era JavaScript actually uses, and cross-file
/// resolution has no binding to work with without it.
pub(super) fn collect_js_require_imports(
    node: &tree_sitter::Node,
    source: &[u8],
    imports: &mut Vec<FileImport>,
) {
    match node.kind() {
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            for declarator in node.children(&mut cursor) {
                if declarator.kind() != "variable_declarator" {
                    continue;
                }
                let (Some(name), Some(value)) = (
                    declarator.child_by_field_name("name"),
                    declarator.child_by_field_name("value"),
                ) else {
                    continue;
                };
                let Some((module_path, member)) = js_require_target(&value, source) else {
                    continue;
                };
                let specifiers = js_require_specifiers(&name, member.as_deref(), source);
                if !specifiers.is_empty() {
                    imports.push(FileImport {
                        module_path,
                        specifiers,
                    });
                }
            }
        }
        "expression_statement" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    // `exports.static = require('serve-static')` re-exports a dependency.
                    "assignment_expression" => {
                        let (Some(lhs), Some(rhs)) = (
                            child.child_by_field_name("left"),
                            child.child_by_field_name("right"),
                        ) else {
                            continue;
                        };
                        let Some((module_path, member)) = js_require_target(&rhs, source) else {
                            continue;
                        };
                        let local_name = extract_assignment_lhs_name(&lhs, source);
                        if local_name.is_empty() {
                            continue;
                        }
                        imports.push(FileImport {
                            module_path,
                            specifiers: vec![ImportedName {
                                local_name,
                                is_default: member.is_none(),
                                original_name: member,
                            }],
                        });
                    }
                    // A bare `require('./polyfill')` is a side-effect dependency:
                    // it binds no name, but the file still depends on that module.
                    "call_expression" => {
                        if let Some((module_path, _)) = js_require_target(&child, source) {
                            imports.push(FileImport {
                                module_path,
                                specifiers: Vec::new(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Detect Jest/Vitest/Mocha test calls in JS: `test(...)`, `it(...)`, `describe(...)`.
fn extract_js_tests_from_node(
    node: &tree_sitter::Node,
    source: &[u8],
    tests: &mut Vec<ExtractedTest>,
) {
    if node.kind() == "expression_statement" || node.kind() == "call_expression" {
        let mut cursor = node.walk();
        let call = if node.kind() == "expression_statement" {
            node.children(&mut cursor)
                .find(|c| c.kind() == "call_expression")
        } else {
            Some(*node)
        };
        if let Some(call_node) = call {
            if let Some(func) = call_node.child_by_field_name("function") {
                let func_name = func.utf8_text(source).unwrap_or("");
                if matches!(func_name, "test" | "it") {
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
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        let mut cursor = args.walk();
                        for arg in args.children(&mut cursor) {
                            if arg.kind() == "arrow_function" || arg.kind() == "function" {
                                if let Some(body) = arg.child_by_field_name("body") {
                                    let mut body_cursor = body.walk();
                                    for child in body.children(&mut body_cursor) {
                                        extract_js_tests_from_node(&child, source, tests);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if node.kind() == "program" || node.kind() == "statement_block" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_js_tests_from_node(&child, source, tests);
        }
    }
}

/// Check if a file is a JS index file (index.js, index.jsx, index.mjs, index.cjs).
fn is_js_index_file(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    matches!(
        basename,
        "index.js" | "index.jsx" | "index.mjs" | "index.cjs"
    )
}

/// Extract the module name from a file path for index files.
/// `src/plugin/customParseFormat/index.js` → `"customParseFormat"`
/// `themes/index.js` → `"themes"`
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
    fn parse_javascript_function() {
        let adapter = JavaScriptAdapter;
        let source = b"function add(a, b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "add");
    }

    #[test]
    fn parse_javascript_class() {
        let adapter = JavaScriptAdapter;
        let source = b"class Foo { bar() {} baz() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 2);
    }

    #[test]
    fn parse_js_function_calls() {
        let adapter = JavaScriptAdapter;
        let source = b"function doWork(x) { console.log(x); helper(x); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
        let callees: Vec<&str> = calls.iter().map(|r| r.dst_name.as_str()).collect();
        // Member calls resolve to the rightmost identifier (`console.log` -> `log`).
        assert!(callees.contains(&"log"), "missing log call (console.log)");
        assert!(callees.contains(&"helper"), "missing helper call");
        // All calls should originate from doWork
        for c in &calls {
            assert_eq!(c.src_name, "doWork");
        }
    }

    #[test]
    fn parse_js_imports() {
        let adapter = JavaScriptAdapter;
        let source = b"import { foo, bar as baz } from './module';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "./module");
        assert_eq!(import.specifiers.len(), 2);
        // First specifier: foo (not renamed)
        assert_eq!(import.specifiers[0].local_name, "foo");
        assert!(import.specifiers[0].original_name.is_none());
        // Second specifier: bar as baz
        assert_eq!(import.specifiers[1].local_name, "baz");
        assert_eq!(import.specifiers[1].original_name.as_deref(), Some("bar"));
    }

    #[test]
    fn parse_js_require() {
        let adapter = JavaScriptAdapter;
        let source = b"const path = require('./utils/path');";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "./utils/path");
        assert_eq!(import.specifiers.len(), 1);
        assert_eq!(import.specifiers[0].local_name, "path");
        assert!(import.specifiers[0].is_default);
    }

    #[test]
    fn parse_js_prototype_method_named() {
        // app.init = function init() { ... }
        //
        // Contract: a function assigned to a receiver is that receiver's
        // METHOD, named `receiver.property` and contained by the receiver,
        // rather than a free function named after the right-hand side. The
        // right-hand name is an internal recursion label. `app.init` is how the
        // method is reached, and it is the key the linker resolves an
        // `Owner.method` call against.
        let adapter = JavaScriptAdapter;
        let source = b"app.init = function init() { console.log('starting'); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 1, "expected 1 method, got {:?}", methods);
        assert_eq!(methods[0].name, "app.init");
        // The receiver becomes the class-like owner that holds the method.
        let owners: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(owners, vec!["app"]);
        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .collect();
        assert_eq!(contains.len(), 1);
        assert_eq!(contains[0].src_name, "app");
        assert_eq!(contains[0].dst_name, "app.init");
    }

    #[test]
    fn parse_js_prototype_method_anonymous() {
        // res.status = function(code) { ... } — anonymous, use property name
        let adapter = JavaScriptAdapter;
        let source = b"res.status = function(code) { return this; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 1, "expected 1 method, got {:?}", methods);
        assert_eq!(methods[0].name, "res.status");
    }

    #[test]
    fn parse_js_prototype_assignment_owns_the_constructor() {
        // `View.prototype.lookup = ...` is a method on `View`, not on a
        // separate `View.prototype` object: `Foo.prototype.bar` and `Foo.bar`
        // are both reached as `bar` on a `Foo`, so both collapse to the same
        // `Owner.method` key.
        let adapter = JavaScriptAdapter;
        let source = b"function View(name) { this.name = name; }\nView.prototype.lookup = function lookup(n) { return n; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert!(
            named.contains(&(EntityKind::Class, "View")),
            "a constructor carrying prototype methods is class-like, got {named:?}"
        );
        assert!(
            named.contains(&(EntityKind::Method, "View.lookup")),
            "expected View.lookup method, got {named:?}"
        );
        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(contains, vec![("View", "View.lookup")]);
    }

    #[test]
    fn parse_js_chained_member_assignment_defines_every_target() {
        // `res.set = res.header = function header() {}` defines BOTH names.
        // Reading only the outermost right-hand side sees another assignment
        // and records neither.
        let adapter = JavaScriptAdapter;
        let source = b"res.set =\nres.header = function header(field, val) { return this; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let mut methods: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .map(|e| e.name.as_str())
            .collect();
        methods.sort_unstable();
        assert_eq!(methods, vec!["res.header", "res.set"]);
    }

    #[test]
    fn parse_js_module_exports_object_yields_one_function_per_property() {
        // `module.exports = { parse() {}, print: () => {} }` is the CommonJS
        // way of exporting a set of functions. `module.exports` is the module's
        // public surface rather than an object with methods, so its properties
        // stay module-level functions that `require('./m').parse` can bind to.
        let adapter = JavaScriptAdapter;
        let source =
            b"module.exports = { parse(input) { return scan(input); }, print: (x) => emit(x) };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let mut funcs: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .map(|e| e.name.as_str())
            .collect();
        funcs.sort_unstable();
        assert_eq!(funcs, vec!["parse", "print"]);
        let calls: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert!(calls.contains(&("parse", "scan")), "got {calls:?}");
        assert!(calls.contains(&("print", "emit")), "got {calls:?}");
    }

    #[test]
    fn parse_js_require_binding_is_an_import_not_a_constant() {
        // A `require(...)` binding is a dependency line, already carried as a
        // FileImport. Emitting a Constant beside it doubled every dependency
        // into the entity set: on express those bindings were the bulk of the
        // 451 constants that buried 133 functions.
        let adapter = JavaScriptAdapter;
        let source = br#"
var contentDisposition = require('content-disposition');
var { METHODS } = require('node:http');
var isAbsolute = require('node:path').isAbsolute;
var deprecate = require('depd')('express');
require('./polyfill');
exports.static = require('serve-static');
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert!(
            output.entities.is_empty(),
            "require bindings must not produce entities, got {:?}",
            output
                .entities
                .iter()
                .map(|e| (e.kind, e.name.as_str()))
                .collect::<Vec<_>>()
        );

        let by_module: Vec<(&str, Vec<&str>)> = output
            .imports
            .iter()
            .map(|imp| {
                (
                    imp.module_path.as_str(),
                    imp.specifiers
                        .iter()
                        .map(|s| s.local_name.as_str())
                        .collect(),
                )
            })
            .collect();
        assert_eq!(
            by_module,
            vec![
                ("content-disposition", vec!["contentDisposition"]),
                ("node:http", vec!["METHODS"]),
                ("node:path", vec!["isAbsolute"]),
                ("depd", vec!["deprecate"]),
                ("./polyfill", Vec::new()),
                ("serve-static", vec!["static"]),
            ]
        );
        // `require('m').x` binds the named export `x`, not the module default.
        let member = &output.imports[2].specifiers[0];
        assert_eq!(member.original_name.as_deref(), Some("isAbsolute"));
        assert!(!member.is_default);
    }

    #[test]
    fn parse_js_value_assignment_is_an_exported_constant() {
        // `exports.Router = Router` exports Router. The value is not callable
        // here, so it is a Constant rather than a Function, but it is an export
        // and has to exist: producing nothing leaves the name unaskable and an
        // export sweep short by one with nothing to report.
        let adapter = JavaScriptAdapter;
        let source = b"exports.Router = Router;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(named, vec![(EntityKind::Constant, "Router")]);
        assert_eq!(output.entities[0].visibility, Visibility::Public);
    }

    #[test]
    fn parse_js_exports_call_result_is_an_exported_constant() {
        // express `lib/utils.js:40`. The right-hand side is a call, so before
        // the export rule this statement produced no entity at all.
        let adapter = JavaScriptAdapter;
        let source = b"exports.etag = createETagGenerator({ weak: false });";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(named, vec![(EntityKind::Constant, "etag")]);
        assert_eq!(output.entities[0].visibility, Visibility::Public);
        assert!(
            output.entities[0].signature.contains("createETagGenerator"),
            "the assignment is the body of a call-result export, got {:?}",
            output.entities[0].signature
        );
        let calls: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(calls, vec![("etag", "createETagGenerator")]);
    }

    #[test]
    fn parse_js_module_exports_property_call_result_is_an_exported_constant() {
        // `module.exports.X` is the same export written the long way; the
        // receiver path carries the dot, so a bare `exports` match misses it.
        let adapter = JavaScriptAdapter;
        let source = b"module.exports.wetag = createETagGenerator({ weak: true });";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(named, vec![(EntityKind::Constant, "wetag")]);
    }

    #[test]
    fn parse_js_exports_class_expression_is_kinded_class() {
        let adapter = JavaScriptAdapter;
        let source = b"exports.Router = class {};";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(named, vec![(EntityKind::Class, "Router")]);
    }

    #[test]
    fn parse_js_exports_require_reexport_stays_an_import() {
        // `exports.static = require('serve-static')` already reaches the graph
        // as an import specifier named `static`. A constant beside it would
        // double every re-exported dependency, which is the shape that buried
        // express's functions under 451 constants.
        let adapter = JavaScriptAdapter;
        let source = b"exports.static = require('serve-static');";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(
            output.entities.is_empty(),
            "a require re-export is a dependency line, got {:?}",
            output
                .entities
                .iter()
                .map(|e| (e.kind, e.name.as_str()))
                .collect::<Vec<_>>()
        );
        let specifiers: Vec<&str> = output
            .imports
            .iter()
            .filter(|i| i.module_path == "serve-static")
            .flat_map(|i| i.specifiers.iter().map(|s| s.local_name.as_str()))
            .collect();
        assert_eq!(specifiers, vec!["static"]);
    }

    #[test]
    fn parse_js_export_rule_fires_only_on_the_export_namespace() {
        // Only `exports` and `module.exports` are the module's export surface.
        // `window.handler = createHandler()` assigns to a global, and
        // `module.exports = createApplication()` replaces the whole export
        // rather than naming one, so neither yields an exported property: the
        // second would otherwise be recorded under the name `exports`.
        let adapter = JavaScriptAdapter;
        for source in [
            &b"window.handler = createHandler();"[..],
            &b"module.exports = createApplication();"[..],
        ] {
            let tree = adapter.parse(source).unwrap();
            let file_id = FilePathId::new("test.js");
            let output = adapter.extract(&tree, source, &file_id).unwrap();
            assert!(
                output.entities.is_empty(),
                "{:?} is not an exported property, got {:?}",
                std::str::from_utf8(source).unwrap(),
                output
                    .entities
                    .iter()
                    .map(|e| (e.kind, e.name.as_str()))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn parse_js_module_exports_named() {
        // module.exports = function createApplication() { ... }
        let adapter = JavaScriptAdapter;
        let source = b"module.exports = function createApplication() { return app; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected 1 function, got {:?}", funcs);
        // Named function on RHS takes precedence
        assert_eq!(funcs[0].name, "createApplication");
    }

    #[test]
    fn parse_js_module_exports_anonymous() {
        // module.exports = function() { ... } — anonymous, falls back to "module.exports"
        let adapter = JavaScriptAdapter;
        let source = b"module.exports = function() { return app; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "module.exports");
    }

    #[test]
    fn parse_js_arrow_function_assignment() {
        // app.handler = (req, res) => { ... }
        // An arrow assigned to a receiver is that receiver's method, same as a
        // function expression.
        let adapter = JavaScriptAdapter;
        let source = b"app.handler = (req, res) => { res.send('ok'); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 1, "expected 1 method, got {:?}", methods);
        assert_eq!(methods[0].name, "app.handler");
        let calls: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(calls, vec![("app.handler", "send")]);
    }

    #[test]
    fn parse_js_uppercase_constant() {
        let adapter = JavaScriptAdapter;
        let source = b"export const PROBE_SECRET_abcd1234 = 'uuid';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            1,
            "expected 1 constant, got {:?}",
            constants
        );
        assert_eq!(constants[0].name, "PROBE_SECRET_abcd1234");
    }

    #[test]
    fn parse_js_function_valued_const_as_function() {
        let adapter = JavaScriptAdapter;
        let source = b"export const useAutocomplete = (props) => { helper(props); return props; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1, "expected one function-valued const entity");
        assert_eq!(funcs[0].name, "useAutocomplete");

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(calls.contains(&"helper"));
    }

    #[test]
    fn parse_js_reexport_source_as_import_context() {
        let adapter = JavaScriptAdapter;
        let source =
            b"export { hydrate } from './runtime-dom';\nexport * from '@vue/runtime-core';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
    fn parse_js_class_expression_binding() {
        // `const Foo = class extends Bar {}` is a class declaration wearing a
        // binding; it must produce the same shape as `class Foo extends Bar {}`.
        let adapter = JavaScriptAdapter;
        let source = b"const Timer = class extends Base { start() { return tick(); } };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(
            named,
            vec![
                (EntityKind::Class, "Timer"),
                (EntityKind::Method, "Timer.start"),
            ]
        );
        let extends: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(extends, vec![("Timer", "Base")]);
    }

    #[test]
    fn parse_js_class_extends_namespace_member() {
        // `extends React.Component` reduces to the rightmost identifier, which
        // is the name the linker resolves. Reading the whole member expression
        // yields `React.Component`, which matches no entity.
        let adapter = JavaScriptAdapter;
        let source = b"class Panel extends React.Component { render() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let extends: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(extends, vec![("Panel", "Component")]);
    }

    #[test]
    fn parse_js_class_field_arrow_is_a_method() {
        // The React class-property form `handleClick = () => {}` is a callable
        // member; a data field is not and stays out of the graph.
        let adapter = JavaScriptAdapter;
        let source =
            b"class Panel { state = { open: false }; handleClick = (e) => { this.toggle(e); } }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(methods, vec!["Panel.handleClick"]);
    }

    #[test]
    fn parse_js_class_extends() {
        let adapter = JavaScriptAdapter;
        let source = b"class Dog extends Animal { bark() {} }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        // Should have Dog class and Dog.bark method
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name, "Dog");

        // Should have Extends relation from Dog to Animal
        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert_eq!(
            extends.len(),
            1,
            "expected 1 Extends relation, got {:?}",
            extends
        );
        assert_eq!(extends[0].src_name, "Dog");
        assert_eq!(extends[0].dst_name, "Animal");
    }

    #[test]
    fn parse_js_exports_prop_function() {
        let adapter = JavaScriptAdapter;
        let source = b"exports.handler = function() { console.log('hi'); };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(
            funcs.len(),
            1,
            "expected 1 function from exports.handler, got {:?}",
            funcs
        );
        assert_eq!(funcs[0].name, "handler");
    }

    #[test]
    fn parse_js_default_import_specifier() {
        let adapter = JavaScriptAdapter;
        let source = b"import React from 'react';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
    fn parse_js_default_import_with_named() {
        let adapter = JavaScriptAdapter;
        let source = b"import dayjs, { Dayjs } from 'dayjs';";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        let import = &output.imports[0];
        assert_eq!(import.module_path, "dayjs");
        assert!(
            import.specifiers.len() >= 2,
            "expected at least 2 specifiers (default + named), got {}",
            import.specifiers.len()
        );
        let default_spec = import.specifiers.iter().find(|s| s.is_default);
        assert!(default_spec.is_some(), "missing default import specifier");
        assert_eq!(default_spec.unwrap().local_name, "dayjs");
    }

    #[test]
    fn parse_js_exported_data_only_object_filtered() {
        let adapter = JavaScriptAdapter;
        // Data-only object literals (theme tokens, configs) are filtered to
        // prevent constant explosion in repos like MUI.
        let source = b"export const themes = { dark: { bg: '#000' }, light: { bg: '#fff' } };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            0,
            "data-only exported object constants should be filtered"
        );
    }

    #[test]
    fn parse_js_exported_object_with_callback_kept() {
        let adapter = JavaScriptAdapter;
        // Object literals with function-like children are meaningful code.
        //
        // Contract: such a literal is a namespace object, so it is kinded
        // Class and each function property becomes a Method it contains. That
        // is the kind the linker's receiver-method tier requires; a Constant
        // owner would leave `handlers.onClick` unreachable as a call target.
        let source = b"export const handlers = { onClick: () => console.log('click') };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
        let contains: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(contains, vec![("handlers", "handlers.onClick")]);
    }

    #[test]
    fn parse_js_unexported_lowercase_const_skipped() {
        let adapter = JavaScriptAdapter;
        let source = b"const localHelper = { x: 1 };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let constants: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Constant)
            .collect();
        assert_eq!(
            constants.len(),
            0,
            "unexported non-UPPER_SNAKE_CASE constants should be skipped"
        );
    }

    #[test]
    fn parse_js_export_default_anonymous_function() {
        let adapter = JavaScriptAdapter;
        let source = b"export default function() { return 42; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
        assert_eq!(defaults[0].visibility, Visibility::Public);
    }

    #[test]
    fn parse_js_export_default_identifier() {
        let adapter = JavaScriptAdapter;
        let source = b"const dayjs = function(d) { return d; };\nexport default dayjs;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        // Should have the named function AND a "default" entity
        let defaults: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name == "default")
            .collect();
        assert_eq!(
            defaults.len(),
            1,
            "export default <identifier> should create a 'default' entity"
        );
    }

    #[test]
    fn receiver_named_like_the_index_module_keeps_one_entity() {
        // `router/index.js` assigning to a receiver called `router` collides
        // with the directory-named Module entity. One file must not hold two
        // entities under one name: the linker indexes on (file, name) and
        // cannot tell them apart.
        let adapter = JavaScriptAdapter;
        let source = b"router.handle = function handle(req) { return req; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/router/index.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let named: Vec<(EntityKind, &str)> = output
            .entities
            .iter()
            .map(|e| (e.kind, e.name.as_str()))
            .collect();
        assert_eq!(
            named,
            vec![
                (EntityKind::Module, "router"),
                (EntityKind::Method, "router.handle"),
            ],
            "the module keeps its kind and no second `router` is added"
        );
        // The Contains edge still resolves, against the module node.
        let contains: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert_eq!(contains, vec![("router", "router.handle")]);
    }

    #[test]
    fn parse_js_module_entity_for_index_file() {
        let adapter = JavaScriptAdapter;
        let source = b"export { default } from './LoadingButton';";
        let tree = adapter.parse(source).unwrap();
        // Key: file_id path ends with /index.js and has a directory component
        let file_id = FilePathId::new("packages/mui-lab/src/LoadingButton/index.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(
            modules.len(),
            1,
            "index.js should create a Module entity named after its directory"
        );
        assert_eq!(modules[0].name, "LoadingButton");
    }

    #[test]
    fn keep_named_numeric_constant() {
        let adapter = JavaScriptAdapter;
        // A named numeric constant must be indexed so trace-computation tasks
        // can resolve through it — even though `13` is a data-only scalar.
        let source = b"export const PROBE_BASE_d6177fd8 = 13;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.js");
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
        let adapter = JavaScriptAdapter;
        // Positive matrix: deliberately-named constants are kept even with
        // data-only scalar values. Negative matrix: incidental lowercase
        // locals with scalar values stay filtered (avoids entity-set bloat).
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
        let file_id = FilePathId::new("test.js");
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

    // ── defineProperty-shaped property definitions (FIR-2473) ───────────────
    //
    // express `lib/request.js` defines twelve of its most-used properties
    // through `defineGetter(req, 'name', fn)` and none was an entity, so
    // `req.ip` could not be located, packed, or traced while its
    // assignment-form sibling `req.get` could. The fixtures below are that
    // file's real shapes, plus the shapes a name-based rule would have
    // wrongly admitted.

    /// The express shape, verbatim in structure: the helper is declared BELOW
    /// every call to it, so a single forward walk meets the calls first.
    #[test]
    fn parse_js_define_getter_helper_declared_after_its_uses() {
        let adapter = JavaScriptAdapter;
        let source = br#"
var req = Object.create(http.IncomingMessage.prototype);

defineGetter(req, 'ip', function ip(){
  var trust = this.app.get('trust proxy fn');
  return proxyaddr(this, trust);
});

defineGetter(req, 'protocol', function protocol(){
  return this.connection.encrypted ? 'https' : 'http';
});

function defineGetter(obj, name, getter) {
  Object.defineProperty(obj, name, {
    configurable: true,
    enumerable: true,
    get: getter
  });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            methods.contains(&"req.ip"),
            "req.ip must be an entity, got {methods:?}"
        );
        assert!(
            methods.contains(&"req.protocol"),
            "req.protocol must be an entity, got {methods:?}"
        );
        let contains: Vec<(&str, &str)> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Contains)
            .map(|r| (r.src_name.as_str(), r.dst_name.as_str()))
            .collect();
        assert!(contains.contains(&("req", "req.ip")));
        assert!(contains.contains(&("req", "req.protocol")));
    }

    /// The span has to cover the getter BODY, because that is where the code a
    /// reader is looking for lives. express's `req.ip` bug is on the line
    /// inside the getter, not on the `defineGetter(` line, and a span stopping
    /// at the call head would leave that line owned by nothing.
    #[test]
    fn parse_js_define_getter_span_covers_the_getter_body() {
        let adapter = JavaScriptAdapter;
        let source = br#"defineGetter(req, 'ip', function ip(){
  var trust = this.app.get('trust proxy fn');
  return proxyaddr(this, trust);
});

function defineGetter(obj, name, getter) {
  Object.defineProperty(obj, name, { get: getter });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let ip = output
            .entities
            .iter()
            .find(|e| e.name == "req.ip")
            .expect("req.ip is an entity");
        // Parser spans carry tree-sitter rows, which are 0-based: source line
        // 1 is `start_line` 0. Asserted explicitly because a span read against
        // the wrong base still looks like a span.
        let span = &ip.span;
        assert_eq!(span.start_line, 0, "starts at the defining statement");
        // Source line 3, `return proxyaddr(this, trust);`, is the line a reader
        // chasing the express bug lands on. It has to be inside this entity.
        let body_line = 2;
        assert!(
            span.start_line <= body_line && body_line <= span.end_line,
            "the getter body line {body_line} must fall inside [{}, {}]",
            span.start_line,
            span.end_line
        );
    }

    /// Calls inside the getter belong to the property, not to the file. The
    /// measured task was tracing `req.ip` to `proxyaddr`, which needs the edge.
    #[test]
    fn parse_js_define_getter_body_calls_belong_to_the_property() {
        let adapter = JavaScriptAdapter;
        let source = br#"defineGetter(req, 'ip', function ip(){
  return proxyaddr(this, this.app.get('trust proxy fn'));
});

function defineGetter(obj, name, getter) {
  Object.defineProperty(obj, name, { get: getter });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let from_ip: Vec<&str> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls && r.src_name == "req.ip")
            .map(|r| r.dst_name.as_str())
            .collect();
        assert!(
            from_ip.contains(&"proxyaddr"),
            "req.ip must call proxyaddr, got {from_ip:?}"
        );
    }

    /// `fresh` is the one of the twelve whose implementation is anonymous, so
    /// the name can only come from the string argument.
    #[test]
    fn parse_js_define_getter_names_the_property_from_the_string_argument() {
        let adapter = JavaScriptAdapter;
        let source = br#"defineGetter(req, 'fresh', function(){
  return true;
});

function defineGetter(obj, name, getter) {
  Object.defineProperty(obj, name, { get: getter });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(methods, vec!["req.fresh"]);
    }

    /// `Object.defineProperty` used directly needs no helper at all.
    #[test]
    fn parse_js_object_define_property_direct_call_defines_the_member() {
        let adapter = JavaScriptAdapter;
        let source = br#"Object.defineProperty(res, 'charset', {
  get: function charset(){ return this._charset; }
});
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/response.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(methods, vec!["res.charset"]);
    }

    /// FALSIFICATION. The rule reads what a helper DOES. A three-argument call
    /// taking an object, a string and a function is also how every event
    /// registration in JavaScript is written, and admitting it on shape alone
    /// would invent `emitter.click`, a property no code defines.
    #[test]
    fn parse_js_a_three_argument_call_that_defines_nothing_produces_no_property() {
        let adapter = JavaScriptAdapter;
        let source = br#"registerHandler(emitter, 'click', function onClick(){
  return handle();
});

function registerHandler(target, event, handler) {
  target.addEventListener(event, handler);
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/events.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let invented: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("emitter."))
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            invented.is_empty(),
            "a handler registration defines no property, got {invented:?}"
        );
    }

    /// FALSIFICATION. A helper that hands `Object.defineProperty` a name of its
    /// own choosing rather than one of its parameters says nothing about what
    /// its call sites define, so its call sites must mint nothing.
    #[test]
    fn parse_js_a_helper_that_does_not_forward_its_own_arguments_is_not_a_definer() {
        let adapter = JavaScriptAdapter;
        let source = br#"lockDown(req, 'ip', function ip(){ return 1; });

function lockDown(obj, name, getter) {
  Object.defineProperty(obj, 'frozen', { value: true });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let invented: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("req."))
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            invented.is_empty(),
            "a helper that names its own property defines nothing for its callers, got {invented:?}"
        );
    }

    /// FALSIFICATION. A computed property name is not a name. Recording the
    /// expression's source text would put an entity called `req.[key]` in the
    /// graph that nothing can ever be resolved against.
    #[test]
    fn parse_js_a_computed_property_name_produces_no_property() {
        let adapter = JavaScriptAdapter;
        let source = br#"defineGetter(req, key, function(){ return 1; });

function defineGetter(obj, name, getter) {
  Object.defineProperty(obj, name, { get: getter });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let invented: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("req."))
            .map(|e| e.name.as_str())
            .collect();
        assert!(invented.is_empty(), "got {invented:?}");
    }

    /// FALSIFICATION. A data property carries no implementation, so recording
    /// it as a method would claim a function that does not exist.
    #[test]
    fn parse_js_a_data_property_is_not_recorded_as_a_method() {
        let adapter = JavaScriptAdapter;
        let source = br#"Object.defineProperty(res, 'version', { value: 3, enumerable: true });
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/response.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let invented: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.name.starts_with("res."))
            .map(|e| e.name.as_str())
            .collect();
        assert!(invented.is_empty(), "got {invented:?}");
    }

    /// The assignment path must keep working exactly as before. Both forms
    /// appear in the same express file and both have to land.
    #[test]
    fn parse_js_assignment_and_define_getter_forms_coexist() {
        let adapter = JavaScriptAdapter;
        let source = br#"req.get =
req.header = function header(name) {
  return this.headers[name];
};

defineGetter(req, 'ip', function ip(){
  return proxyaddr(this, trust);
});

function defineGetter(obj, name, getter) {
  Object.defineProperty(obj, name, { get: getter });
}
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/request.js");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let mut methods: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .map(|e| e.name.as_str())
            .collect();
        methods.sort_unstable();
        assert_eq!(methods, vec!["req.get", "req.header", "req.ip"]);
        let owners: Vec<&str> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(owners, vec!["req"], "one owner, not one per form");
    }
}
