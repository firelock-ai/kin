// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    call_extraction_incomplete_marker, CallArgShape, ExtractedEntity, ExtractedRelation,
    ExtractedTest, ExtractedTestKind, FileImport, ImportedName, ParseOutput,
};

pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Python
    }

    fn file_extensions(&self) -> &[&str] {
        &["py", "pyi"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_python::LANGUAGE)?;
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
        let mut call_audit = PythonCallExtractionAudit::default();
        let mut value_refs = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();

        // In Python, each `.py` file IS a module (PEP 328); `__init__.py`
        // additionally marks its containing directory as a *package*. The name
        // is resolved before the walk because module-scope statements are
        // sourced to the module entity.
        let (module_name, is_package) = python_module_identity(file_id);

        for child in root.children(&mut cursor) {
            extract_py_node(
                &child,
                source,
                file_id,
                None,
                &mut entities,
                &mut relations,
                &mut call_audit,
                &mut value_refs,
            );
            // Extract imports at top level
            match child.kind() {
                "import_statement" => {
                    if let Some(import) = extract_py_import(&child, source) {
                        imports.push(import);
                    }
                }
                "import_from_statement" => {
                    if let Some(import) = extract_py_from_import(&child, source) {
                        imports.push(import);
                    }
                }
                "function_definition" | "class_definition" | "decorated_definition" => {}
                _ => {
                    // Module-scope statements. `HANDLERS = {"ingest": cmd_ingest}`
                    // at module level names its target exactly as a body statement
                    // would, so the module entity sources those references.
                    if !module_name.is_empty() {
                        collect_python_value_refs(
                            &child,
                            source,
                            &module_name,
                            &std::collections::HashSet::new(),
                            &mut value_refs,
                        );
                    }
                }
            }
        }

        // A syntax-valid tree can still contain a call shape this adapter did
        // not represent with a proven destination, for example a dynamic callee,
        // an untyped receiver, or a call at module/class scope where no callable
        // entity owns the edge. Keep syntax state and call-coverage completeness
        // separate: carry one reserved negative record to the linker, which
        // fails closed without rejecting the valid file.
        if call_audit.incomplete || has_unobserved_call(&root, &call_audit.seen_calls) {
            relations.push(call_extraction_incomplete_marker());
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

        // Emit a Module entity for every Python source file. Previously only
        // package init files produced Module entities, leaving regular modules
        // without a node, which broke per-file graph queries on Python repos.
        if !module_name.is_empty() {
            entities.push(ExtractedEntity {
                kind: EntityKind::Module,
                name: module_name,
                signature: if is_package {
                    format!("package {}", file_id.0)
                } else {
                    format!("module {}", file_id.0)
                },
                visibility: Visibility::Public,
                doc_summary: extract_module_docstring(&root, source),
                fingerprint: compute_fingerprint(&root, source),
                span: span_from_node(&root, file_id),
            });
        }

        emit_python_value_references(value_refs, &entities, &imports, &mut relations);

        // Annotate Calls/References relations with import_source.
        //
        // A receiver-bearing call is skipped: its `dst_name` is an attribute
        // read off some object, not the local binding an import introduced, so
        // matching it against the import map pins `obj.get(...)` to whatever
        // module happened to export a name called `get`.
        for rel in &mut relations {
            if rel.receiver.is_some() {
                continue;
            }
            if matches!(
                rel.kind,
                kin_model::RelationKind::Calls | kin_model::RelationKind::References
            ) {
                if let Some(&module) = import_map.get(rel.dst_name.as_str()) {
                    rel.import_source = Some(module.to_string());
                }
            }
        }

        // Detect test functions (pytest: def test_*)
        let mut tests = Vec::new();
        for ent in &entities {
            if ent.kind == EntityKind::Function && ent.name.starts_with("test_") {
                tests.push(ExtractedTest {
                    name: ent.name.clone(),
                    kind: ExtractedTestKind::Unit,
                    runner: "pytest".to_string(),
                });
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

fn extract_py_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    call_audit: &mut PythonCallExtractionAudit,
    value_refs: &mut Vec<PythonValueRef>,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let raw_name = name_node.utf8_text(source).unwrap_or("").to_string();
                let (kind, name) = if let Some(cls) = class_ctx {
                    (EntityKind::Method, format!("{}.{}", cls, raw_name))
                } else {
                    (EntityKind::Function, raw_name.clone())
                };
                let vis = if raw_name.starts_with('_') {
                    Visibility::Private
                } else {
                    Visibility::Public
                };
                entities.push(ExtractedEntity {
                    kind,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_docstring(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                // Extract calls within function/method body
                extract_calls_from_context(node, source, &name, class_ctx, relations, call_audit);
                extract_value_refs_from_definition(node, source, &name, value_refs);
                if let Some(cls) = class_ctx {
                    relations.push(ExtractedRelation {
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Contains,
                        src_name: cls.to_string(),
                        dst_name: name,
                        import_source: None,
                    });
                }
            }
        }
        "class_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Class,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: if name.starts_with('_') {
                        Visibility::Private
                    } else {
                        Visibility::Public
                    },
                    doc_summary: extract_docstring(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });

                // Extract base classes
                if let Some(args) = node.child_by_field_name("superclasses") {
                    let mut is_enum = false;
                    let mut arg_cursor = args.walk();
                    for arg in args.children(&mut arg_cursor) {
                        if arg.is_named() {
                            let base = arg.utf8_text(source).unwrap_or("").to_string();
                            if !base.is_empty() {
                                const ENUM_BASES: &[&str] = &[
                                    "Enum",
                                    "IntEnum",
                                    "StrEnum",
                                    "Flag",
                                    "IntFlag",
                                    "enum.Enum",
                                    "enum.IntEnum",
                                    "enum.StrEnum",
                                    "enum.Flag",
                                    "enum.IntFlag",
                                ];
                                if ENUM_BASES.contains(&base.as_str()) {
                                    is_enum = true;
                                }
                                relations.push(ExtractedRelation {
                                    receiver: None,
                                    call_shape: None,
                                    kind: kin_model::RelationKind::Extends,
                                    src_name: name.clone(),
                                    dst_name: base,
                                    import_source: None,
                                });
                            }
                        }
                    }
                    if is_enum {
                        if let Some(last) = entities.last_mut() {
                            last.kind = EntityKind::EnumDef;
                        }
                    }
                }

                // Recurse into class body
                if let Some(body) = node.child_by_field_name("body") {
                    let mut body_cursor = body.walk();
                    for member in body.children(&mut body_cursor) {
                        extract_py_node(
                            &member,
                            source,
                            file_id,
                            Some(&name),
                            entities,
                            relations,
                            call_audit,
                            value_refs,
                        );
                        // Class-scope statements that define no entity of their
                        // own still name values: `handler = cmd_ingest` in a
                        // class body is a use of `cmd_ingest`, sourced from the
                        // class.
                        if !matches!(
                            member.kind(),
                            "function_definition" | "class_definition" | "decorated_definition"
                        ) {
                            collect_python_value_refs(
                                &member,
                                source,
                                &name,
                                &std::collections::HashSet::new(),
                                value_refs,
                            );
                        }
                    }
                }
            }
        }
        "import_statement" | "import_from_statement" => {}
        "decorated_definition" => {
            // Collect decorator names, then extract the inner definition
            // with decorators prepended to the signature.
            let decorators = extract_decorator_names(node, source);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "function_definition" || child.kind() == "class_definition" {
                    extract_py_node(
                        &child, source, file_id, class_ctx, entities, relations, call_audit,
                        value_refs,
                    );
                    // Prepend decorator names to the last-added entity's signature
                    if !decorators.is_empty() {
                        if let Some(last) = entities.last_mut() {
                            let prefix = decorators
                                .iter()
                                .map(|d| format!("@{}", d))
                                .collect::<Vec<_>>()
                                .join(" ");
                            last.signature = format!("{} {}", prefix, last.signature);
                        }
                        if let Some(last) = entities.last() {
                            let src_name = last.name.clone();
                            for dec in &decorators {
                                if is_valid_callee_name(dec) {
                                    relations.push(ExtractedRelation {
                                        receiver: None,
                                        call_shape: None,
                                        kind: kin_model::RelationKind::Calls,
                                        src_name: src_name.clone(),
                                        dst_name: dec.clone(),
                                        import_source: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        "expression_statement" if class_ctx.is_none() => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "assignment" || child.kind() == "assignment_statement" {
                    extract_py_node(
                        &child, source, file_id, class_ctx, entities, relations, call_audit,
                        value_refs,
                    );
                }
            }
        }
        "assignment" | "assignment_statement" if class_ctx.is_none() => {
            if let Some(name) = extract_py_constant_name(node, source) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Constant,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: if name.starts_with('_') {
                        Visibility::Private
                    } else {
                        Visibility::Public
                    },
                    doc_summary: None,
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        _ => {}
    }
}

/// Resolve a Python file's module name and whether it marks a package.
///
/// In Python each `.py` file IS a module (PEP 328); `__init__.py` additionally
/// marks its containing directory as a package.
fn python_module_identity(file_id: &FilePathId) -> (String, bool) {
    if file_id.0.ends_with("__init__.py") {
        let pkg = file_id
            .0
            .trim_end_matches("__init__.py")
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("__init__")
            .to_string();
        (pkg, true)
    } else {
        let stem = file_id
            .0
            .rsplit('/')
            .next()
            .and_then(|leaf| leaf.strip_suffix(".py"))
            .unwrap_or("")
            .to_string();
        (stem, false)
    }
}

/// A symbol read as a VALUE rather than invoked, recorded during the walk.
///
/// `member` is set when the reference was written as an attribute access
/// (`TAG_RE.pattern`), because whether that names the root or the leaf depends
/// on how the root was bound, and the file's imports are not known until the
/// walk finishes. Candidates are filtered rather than emitted directly because
/// a reference may precede its definition in the file.
struct PythonValueRef {
    src_name: String,
    root: String,
    member: Option<String>,
}

/// Collect the value references made by one `function_definition`, sourced from
/// the entity `context_name`.
///
/// Parameter defaults are walked because `def wire(handler=cmd_ingest)` reads
/// `cmd_ingest`; parameter names and annotations are not, since a name being
/// bound is not a name being read and a type position is a different edge
/// class. Names the function binds locally shadow the module scope in Python,
/// so a local called `parse` is not a read of a module-level `parse`.
fn extract_value_refs_from_definition(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    out: &mut Vec<PythonValueRef>,
) {
    let shadowed = collect_python_local_bindings(node, source);
    if let Some(params) = node.child_by_field_name("parameters") {
        let mut cursor = params.walk();
        for param in params.named_children(&mut cursor) {
            if matches!(
                param.kind(),
                "default_parameter" | "typed_default_parameter"
            ) {
                if let Some(value) = param.child_by_field_name("value") {
                    collect_python_value_refs(&value, source, context_name, &shadowed, out);
                }
            }
        }
    }
    if let Some(body) = node.child_by_field_name("body") {
        collect_python_value_refs(&body, source, context_name, &shadowed, out);
    }
}

/// Names a Python function binds in its own scope, which therefore shadow any
/// module-level entity of the same name.
///
/// A `global`/`nonlocal` declaration re-points the name at an outer scope, so
/// those names are removed again: `global TAG_RE` followed by an assignment is
/// a write to the module-level constant, not a local.
fn collect_python_local_bindings(
    node: &tree_sitter::Node,
    source: &[u8],
) -> std::collections::HashSet<String> {
    let mut bound = std::collections::HashSet::new();
    let mut rebound_outward = std::collections::HashSet::new();
    if let Some(params) = node.child_by_field_name("parameters") {
        collect_python_binding_targets(&params, source, &mut bound);
    }
    if let Some(body) = node.child_by_field_name("body") {
        collect_python_scope_bindings(&body, source, &mut bound, &mut rebound_outward);
    }
    for name in rebound_outward {
        bound.remove(&name);
    }
    bound
}

fn collect_python_scope_bindings(
    node: &tree_sitter::Node,
    source: &[u8],
    bound: &mut std::collections::HashSet<String>,
    rebound_outward: &mut std::collections::HashSet<String>,
) {
    match node.kind() {
        "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
            if let Some(left) = node.child_by_field_name("left") {
                collect_python_binding_targets(&left, source, bound);
            }
        }
        "named_expression" => {
            if let Some(name) = node.child_by_field_name("name") {
                collect_python_binding_targets(&name, source, bound);
            }
        }
        "as_pattern" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                collect_python_binding_targets(&alias, source, bound);
            }
        }
        "function_definition" | "class_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                collect_python_binding_targets(&name, source, bound);
            }
            if let Some(params) = node.child_by_field_name("parameters") {
                collect_python_binding_targets(&params, source, bound);
            }
        }
        "global_statement" | "nonlocal_statement" => {
            collect_python_binding_targets(node, source, rebound_outward);
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_scope_bindings(&child, source, bound, rebound_outward);
    }
}

/// Collect the identifiers a binding construct writes to, descending through
/// tuple and list patterns. An attribute or subscript target (`self.x = 1`,
/// `d["k"] = 1`) binds no new name, so its identifiers are not collected.
fn collect_python_binding_targets(
    node: &tree_sitter::Node,
    source: &[u8],
    out: &mut std::collections::HashSet<String>,
) {
    match node.kind() {
        "identifier" => {
            if let Ok(name) = node.utf8_text(source) {
                if !name.is_empty() {
                    out.insert(name.to_string());
                }
            }
        }
        "attribute" | "subscript" | "type" => {}
        "default_parameter" | "typed_default_parameter" | "typed_parameter" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "identifier" {
                    collect_python_binding_targets(&child, source, out);
                    break;
                }
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_python_binding_targets(&child, source, out);
            }
        }
    }
}

/// Collect the value reads within an expression subtree, pruning the positions
/// that are not reads.
///
/// Pruned: a call's callee identifier (already a `Calls` edge), an attribute's
/// `.leaf` selector, an assignment or loop target, a keyword argument's name, a
/// type annotation, and an import statement. Kept, because each is a genuine
/// read of the named symbol: a call argument (`set_defaults(func=cmd_ingest)`),
/// an assignment right-hand side, a collection literal element, a returned
/// expression, and the receiver of an attribute access (`TAG_RE.pattern`).
fn collect_python_value_refs(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    shadowed: &std::collections::HashSet<String>,
    out: &mut Vec<PythonValueRef>,
) {
    match node.kind() {
        "identifier" => {
            if let Ok(name) = node.utf8_text(source) {
                if !name.is_empty() && !shadowed.contains(name) {
                    out.push(PythonValueRef {
                        src_name: context_name.to_string(),
                        root: name.to_string(),
                        member: None,
                    });
                }
            }
        }
        // `X.leaf` reads `X`. Whether it also names `leaf` depends on how `X`
        // was bound, which only the import table can say, so both halves are
        // carried and decided at emit time.
        "attribute" => {
            let object = node.child_by_field_name("object");
            let leaf = node
                .child_by_field_name("attribute")
                .and_then(|n| n.utf8_text(source).ok());
            match (object, leaf) {
                (Some(object), Some(leaf)) if object.kind() == "identifier" && !leaf.is_empty() => {
                    if let Ok(root) = object.utf8_text(source) {
                        if !root.is_empty() && !shadowed.contains(root) {
                            out.push(PythonValueRef {
                                src_name: context_name.to_string(),
                                root: root.to_string(),
                                member: Some(leaf.to_string()),
                            });
                        }
                    }
                }
                (Some(object), _) => {
                    collect_python_value_refs(&object, source, context_name, shadowed, out)
                }
                _ => {}
            }
        }
        // A call contributes its arguments and, for `receiver.method()`, the
        // receiver. The callee name is already carried by the `Calls` edge.
        "call" => {
            if let Some(function) = node.child_by_field_name("function") {
                match function.kind() {
                    "identifier" => {}
                    "attribute" => {
                        if let Some(object) = function.child_by_field_name("object") {
                            collect_python_value_refs(&object, source, context_name, shadowed, out);
                        }
                    }
                    _ => collect_python_value_refs(&function, source, context_name, shadowed, out),
                }
            }
            if let Some(args) = node.child_by_field_name("arguments") {
                collect_python_value_refs(&args, source, context_name, shadowed, out);
            }
        }
        // `f(name=value)`: the keyword names a parameter of the callee, not a
        // symbol in this scope. Only the value is a read.
        "keyword_argument" => {
            if let Some(value) = node.child_by_field_name("value") {
                collect_python_value_refs(&value, source, context_name, shadowed, out);
            }
        }
        "assignment" | "augmented_assignment" => {
            if let Some(right) = node.child_by_field_name("right") {
                collect_python_value_refs(&right, source, context_name, shadowed, out);
            }
        }
        "for_statement" | "for_in_clause" => {
            if let Some(right) = node.child_by_field_name("right") {
                collect_python_value_refs(&right, source, context_name, shadowed, out);
            }
            if let Some(body) = node.child_by_field_name("body") {
                collect_python_value_refs(&body, source, context_name, shadowed, out);
            }
        }
        "parameters"
        | "type"
        | "import_statement"
        | "import_from_statement"
        | "future_import_statement"
        | "global_statement"
        | "nonlocal_statement" => {}
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_python_value_refs(&child, source, context_name, shadowed, out);
            }
        }
    }
}

/// Turn collected value reads into `References` edges.
///
/// Only a name this file DEFINES or IMPORTS may bind, which in Python is the
/// complete set: a module-level symbol is reachable from a module only when it
/// is defined there or imported into it, and anything else in a value position
/// is a local, a parameter, or a builtin. Filtering here rather than in the
/// linker is what keeps a local named `config` from binding by name alone to
/// some unrelated module-level `config` in another file.
///
/// `RelationKind::References` is the existing kind for a non-call reference,
/// already emitted by the Go, C++, C# and Ruby adapters and already read by the
/// linker's import and qualified-suffix tiers, the dead-code reference triple,
/// and `find_references`. No new kind is introduced.
fn emit_python_value_references(
    value_refs: Vec<PythonValueRef>,
    entities: &[ExtractedEntity],
    imports: &[FileImport],
    relations: &mut Vec<ExtractedRelation>,
) {
    let defined: std::collections::HashSet<&str> =
        entities.iter().map(|e| e.name.as_str()).collect();
    let mut module_bound: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut symbol_bound: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for import in imports {
        for spec in &import.specifiers {
            // `import parsing` binds the module itself under its own path;
            // `from parsing import TAG_RE` binds a symbol out of it.
            if spec.local_name == import.module_path {
                module_bound.insert(spec.local_name.as_str());
            } else {
                symbol_bound.insert(spec.local_name.as_str());
            }
        }
    }

    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for value_ref in value_refs {
        let root = value_ref.root.as_str();
        let dst = match &value_ref.member {
            // `parsing.TAG_RE` through a module binding names the member. The
            // dotted form is what the linker's namespace-member tier resolves,
            // and it cannot be reduced to the bare leaf without guessing which
            // module a same-named symbol came from.
            Some(member) if module_bound.contains(root) => format!("{root}.{member}"),
            _ if defined.contains(root) || symbol_bound.contains(root) => root.to_string(),
            _ => continue,
        };
        // A self-reference establishes no reachability from another entity, and
        // the reference collectors drop it anyway.
        if dst == value_ref.src_name {
            continue;
        }
        if !seen.insert((value_ref.src_name.clone(), dst.clone())) {
            continue;
        }
        relations.push(ExtractedRelation {
            call_shape: None,
            receiver: None,
            kind: kin_model::RelationKind::References,
            src_name: value_ref.src_name,
            dst_name: dst,
            import_source: None,
        });
    }
}

fn extract_py_constant_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let target = node
        .child_by_field_name("left")
        .or_else(|| node.named_child(0))?;
    let name = target.utf8_text(source).ok()?.trim().to_string();
    if looks_like_py_constant_name(&name) {
        Some(name)
    } else {
        None
    }
}

fn looks_like_py_constant_name(name: &str) -> bool {
    let mut has_upper = false;
    let mut has_underscore = false;
    for ch in name.chars() {
        if ch == '_' {
            has_underscore = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if !ch.is_ascii_alphanumeric() {
            return false;
        }
    }
    !name.is_empty() && has_upper && has_underscore
}

/// Extract decorator names from a `decorated_definition` node.
/// Returns a list of decorator names (e.g., ["staticmethod", "property"]).
fn extract_decorator_names(node: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "decorator" {
            if let Some(name) = extract_decorator_payload_name(&child, source) {
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// Resolve a decorator's bare name from its tree-sitter payload.
/// Handles `@name`, `@mod.name`, and `@mod.name(args)` — always returning the
/// trailing identifier (e.g., "route" for `@app.route("/")`).
fn extract_decorator_payload_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                return Some(child.utf8_text(source).unwrap_or("").to_string());
            }
            "attribute" => {
                return child
                    .child_by_field_name("attribute")
                    .map(|f| f.utf8_text(source).unwrap_or("").to_string());
            }
            "call" => {
                if let Some(function) = child.child_by_field_name("function") {
                    return match function.kind() {
                        "identifier" => Some(function.utf8_text(source).unwrap_or("").to_string()),
                        "attribute" => function
                            .child_by_field_name("attribute")
                            .map(|f| f.utf8_text(source).unwrap_or("").to_string()),
                        _ => None,
                    };
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

fn node_signature(node: &tree_sitter::Node, source: &[u8]) -> String {
    crate::adapter::declaration_signature(node, source)
}

fn extract_docstring(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // Python docstrings are the first expression_statement in a function/class body
    let body = node.child_by_field_name("body")?;
    let first = body.child(0)?;
    if first.kind() == "expression_statement" {
        let expr = first.child(0)?;
        if expr.kind() == "string" {
            let text = expr.utf8_text(source).ok()?;
            let cleaned = text.trim_matches('"').trim_matches('\'').trim().to_string();
            if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// Extract module-level docstring (first expression_statement containing a string at root level).
fn extract_module_docstring(root: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let first_child = root.child(0)?;
    if first_child.kind() == "expression_statement" {
        let expr = first_child.child(0)?;
        if expr.kind() == "string" {
            let text = expr.utf8_text(source).ok()?;
            let cleaned = text.trim_matches('"').trim_matches('\'').trim().to_string();
            if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            }
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Default)]
struct PythonCallExtractionAudit {
    seen_calls: std::collections::HashSet<(usize, usize)>,
    incomplete: bool,
}

fn has_unobserved_call(
    node: &tree_sitter::Node,
    seen_calls: &std::collections::HashSet<(usize, usize)>,
) -> bool {
    if node.kind() == "call" && !seen_calls.contains(&(node.start_byte(), node.end_byte())) {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| has_unobserved_call(&child, seen_calls));
    found
}

struct PythonNamedCallee {
    name: String,
    resolution_proven: bool,
    /// Receiver expression as written, for an attribute call whose owning type
    /// the parser could not pin. `None` for a bare call and for a `self`/`cls`
    /// call, whose owner is already folded into `name`.
    receiver: Option<String>,
}

/// Resolve the statically named portion of a Python callee. Parentheses are a
/// transparent expression wrapper, so `(target)(...)` has the same named
/// target as `target(...)`. A direct `self`/`cls` receiver is pinned to the
/// enclosing class. Other attribute receivers retain their historical bare
/// leaf for recall, but cannot prove which class owns that method: the linker
/// may otherwise bind a same-file free-function decoy or drop an over-cap
/// method fanout. Callers must therefore preserve the edge while downgrading
/// file-level call coverage. Those callees also carry the receiver expression
/// as written, which is what lets the linker separate a call through an object
/// from a call through an imported module. Other expression forms (conditional, subscript,
/// returned callable, lambda, and so on) do not prove one destination either.
fn extract_named_callee(
    function: &tree_sitter::Node,
    source: &[u8],
    class_ctx: Option<&str>,
) -> Option<PythonNamedCallee> {
    let callee = match function.kind() {
        "parenthesized_expression" => {
            let mut cursor = function.walk();
            let mut named = function.named_children(&mut cursor);
            let inner = named.next()?;
            if named.next().is_some() {
                return None;
            }
            return extract_named_callee(&inner, source, class_ctx);
        }
        "attribute" => {
            let attr = function
                .child_by_field_name("attribute")?
                .utf8_text(source)
                .ok()?;
            let receiver_text = function
                .child_by_field_name("object")
                .and_then(|obj| obj.utf8_text(source).ok())
                .map(str::to_string);
            let self_or_cls_receiver = function
                .child_by_field_name("object")
                .filter(|obj| obj.kind() == "identifier")
                .and_then(|obj| obj.utf8_text(source).ok())
                .is_some_and(|text| text == "self" || text == "cls");
            match class_ctx {
                Some(cls) if self_or_cls_receiver => PythonNamedCallee {
                    name: format!("{cls}.{attr}"),
                    resolution_proven: true,
                    receiver: None,
                },
                _ => PythonNamedCallee {
                    name: attr.to_string(),
                    resolution_proven: false,
                    receiver: receiver_text,
                },
            }
        }
        "identifier" => PythonNamedCallee {
            name: function.utf8_text(source).ok()?.to_string(),
            resolution_proven: true,
            receiver: None,
        },
        _ => return None,
    };
    is_valid_callee_name(&callee.name).then_some(callee)
}

/// Extract all function/method calls within a function/method body.
fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    class_ctx: Option<&str>,
    relations: &mut Vec<ExtractedRelation>,
    call_audit: &mut PythonCallExtractionAudit,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            call_audit
                .seen_calls
                .insert((child.start_byte(), child.end_byte()));
            let callee = child
                .child_by_field_name("function")
                .and_then(|function| extract_named_callee(&function, source, class_ctx));
            if let Some(callee) = callee {
                relations.push(ExtractedRelation {
                    receiver: callee.receiver,
                    call_shape: Some(extract_call_arg_shape(&child, source)),
                    kind: kin_model::RelationKind::Calls,
                    src_name: context_name.to_string(),
                    dst_name: callee.name,
                    import_source: None,
                });
                if !callee.resolution_proven {
                    call_audit.incomplete = true;
                }
            } else {
                call_audit.incomplete = true;
            }
        }
        // Recurse into child nodes
        extract_calls_from_context(
            &child,
            source,
            context_name,
            class_ctx,
            relations,
            call_audit,
        );
    }
}

/// Extract the [`CallArgShape`] of a tree-sitter `call` node: count positional
/// arguments, collect explicit keyword-argument names, and note `*args` /
/// `**kwargs` splats. Only the call's own argument list is inspected — arguments
/// of nested calls belong to those calls, not this one. A call with no argument
/// list yields the default (empty) shape. Keyword names are sorted and
/// deduplicated so the shape is order- and duplicate-independent.
pub fn extract_call_arg_shape(call: &tree_sitter::Node, source: &[u8]) -> CallArgShape {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return CallArgShape::default();
    };

    let mut positional = 0u32;
    let mut keywords = Vec::new();
    let mut has_var_positional = false;
    let mut has_var_keyword = false;

    let mut cursor = arguments.walk();
    for arg in arguments.named_children(&mut cursor) {
        match arg.kind() {
            "keyword_argument" => {
                if let Some(name) = arg
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                {
                    keywords.push(name.to_string());
                }
            }
            "list_splat" => has_var_positional = true,
            "dictionary_splat" => has_var_keyword = true,
            "comment" => {}
            _ => positional += 1,
        }
    }

    keywords.sort();
    keywords.dedup();
    CallArgShape {
        positional,
        keywords,
        has_var_positional,
        has_var_keyword,
    }
}

/// Check if a callee name is valid (not a literal, not empty).
fn is_valid_callee_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.chars().all(|c| c.is_numeric())
}

/// Extract import from `import foo` or `import foo.bar`.
fn extract_py_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut specifiers = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "dotted_name" {
            let module_path = child.utf8_text(source).unwrap_or("").to_string();
            if !module_path.is_empty() {
                specifiers.push(ImportedName {
                    local_name: module_path.clone(),
                    original_name: None,
                    is_default: false,
                });
                return Some(FileImport {
                    module_path,
                    specifiers,
                });
            }
        }
    }
    None
}

/// Extract import from `from foo import bar, baz as qux`.
fn extract_py_from_import(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let module_name = node.child_by_field_name("module_name")?;
    let module_path = module_name.utf8_text(source).unwrap_or("").to_string();
    if module_path.is_empty() {
        return None;
    }

    let mut specifiers = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                // Skip the module name itself (already captured)
                if child.id() != module_name.id() {
                    let name = child.utf8_text(source).unwrap_or("").to_string();
                    if !name.is_empty() {
                        specifiers.push(ImportedName {
                            local_name: name,
                            original_name: None,
                            is_default: false,
                        });
                    }
                }
            }
            "aliased_import" => {
                let orig = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                let alias = child
                    .child_by_field_name("alias")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string();
                if !alias.is_empty() {
                    specifiers.push(ImportedName {
                        local_name: alias,
                        original_name: Some(orig),
                        is_default: false,
                    });
                }
            }
            _ => {}
        }
    }

    Some(FileImport {
        module_path,
        specifiers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Depth-first search for the first `call` node in a parsed tree.
    fn first_call_node<'a>(node: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == "call" {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = first_call_node(child) {
                return Some(found);
            }
        }
        None
    }

    fn shape_of(src: &[u8]) -> CallArgShape {
        let adapter = PythonAdapter;
        let tree = adapter.parse(src).unwrap();
        let call = first_call_node(tree.root_node()).expect("a call node");
        extract_call_arg_shape(&call, src)
    }

    #[test]
    fn call_arg_shape_positional_only() {
        let shape = shape_of(b"f(a, b, c)");
        assert_eq!(shape.positional, 3);
        assert!(shape.keywords.is_empty());
        assert!(!shape.has_var_positional);
        assert!(!shape.has_var_keyword);
    }

    #[test]
    fn call_arg_shape_keyword_and_mixed() {
        let shape = shape_of(b"f(a, kw=c, other=d)");
        assert_eq!(shape.positional, 1);
        assert_eq!(shape.keywords, vec!["kw".to_string(), "other".to_string()]);
        assert!(!shape.has_var_keyword);
    }

    #[test]
    fn call_arg_shape_star_and_double_star() {
        let shape = shape_of(b"f(a, *args, **kwargs)");
        assert_eq!(shape.positional, 1);
        assert!(shape.has_var_positional);
        assert!(shape.has_var_keyword);
        assert!(shape.keywords.is_empty());
    }

    #[test]
    fn call_arg_shape_empty_call_is_default() {
        assert_eq!(shape_of(b"f()"), CallArgShape::default());
    }

    #[test]
    fn call_arg_shape_keyword_names_sorted_and_deduped() {
        let shape = shape_of(b"f(zebra=1, alpha=2)");
        assert_eq!(
            shape.keywords,
            vec!["alpha".to_string(), "zebra".to_string()]
        );
    }

    #[test]
    fn call_arg_shape_nested_call_counts_outer_args_only() {
        // The inner `y=1` keyword belongs to `g`, not the outer `f` call.
        let shape = shape_of(b"f(g(x, y=1), z)");
        assert_eq!(shape.positional, 2);
        assert!(
            shape.keywords.is_empty(),
            "inner keyword must not leak to the outer call"
        );
    }

    #[test]
    fn parse_python_function() {
        let adapter = PythonAdapter;
        let source = b"def greet(name):\n    return f'Hello {name}'";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let functions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
    }

    #[test]
    fn declaration_signature_preserves_default_literal_bytes() {
        let adapter = PythonAdapter;
        let source = br#"def target(value="a  b ) , c", other=(1, 2)):
    return value, other
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let target = output
            .entities
            .iter()
            .find(|entity| entity.name == "target")
            .expect("target entity");
        assert_eq!(
            target.signature,
            r#"def target(value="a  b ) , c", other=(1, 2))"#,
            "declaration canonicalization may normalize outer formatting but must copy a literal byte-for-byte"
        );
    }

    #[test]
    fn parse_python_uppercase_constant() {
        let adapter = PythonAdapter;
        let source = b"PROBE_SECRET_abcd1234 = 'uuid'\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
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
    fn parse_python_function_calls() {
        let adapter = PythonAdapter;
        let source = b"def foo():\n    bar()\n    baz(1, 2)";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].src_name, "foo");
        assert_eq!(calls[0].dst_name, "bar");
        assert_eq!(calls[1].src_name, "foo");
        assert_eq!(calls[1].dst_name, "baz");
    }

    #[test]
    fn parse_python_import() {
        let adapter = PythonAdapter;
        let source = b"import os";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        assert_eq!(output.imports[0].module_path, "os");
        assert_eq!(output.imports[0].specifiers.len(), 1);
        assert_eq!(output.imports[0].specifiers[0].local_name, "os");
    }

    #[test]
    fn parse_python_from_import() {
        let adapter = PythonAdapter;
        let source = b"from os import path";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.imports.len(), 1);
        assert_eq!(output.imports[0].module_path, "os");
        assert_eq!(output.imports[0].specifiers.len(), 1);
        assert_eq!(output.imports[0].specifiers[0].local_name, "path");
    }

    #[test]
    fn parse_python_class() {
        let adapter = PythonAdapter;
        let source = b"class Dog(Animal):\n    def bark(self):\n        pass";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
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
    fn extract_function_docstring() {
        let adapter = PythonAdapter;
        let source =
            b"def greet(name):\n    \"\"\"Say hello to someone.\"\"\"\n    return f'Hello {name}'";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "greet")
            .expect("should find greet");
        assert_eq!(func.doc_summary.as_deref(), Some("Say hello to someone."));
    }

    #[test]
    fn extract_class_docstring() {
        let adapter = PythonAdapter;
        let source =
            b"class Dog:\n    \"\"\"A loyal companion.\"\"\"\n    def bark(self):\n        pass";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let cls = output
            .entities
            .iter()
            .find(|e| e.name == "Dog")
            .expect("should find Dog");
        assert_eq!(cls.doc_summary.as_deref(), Some("A loyal companion."));
    }

    #[test]
    fn no_docstring_yields_none() {
        let adapter = PythonAdapter;
        let source = b"def bare():\n    pass";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "bare")
            .expect("should find bare");
        assert!(func.doc_summary.is_none());
    }

    #[test]
    fn self_calls_qualified_with_enclosing_class() {
        let adapter = PythonAdapter;
        let source =
            b"class Foo:\n    def run(self):\n        self.process()\n        self.helper(1)";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].src_name, "Foo.run");
        assert_eq!(calls[0].dst_name, "Foo.process");
        assert_eq!(calls[1].dst_name, "Foo.helper");
    }

    #[test]
    fn cls_calls_qualified_with_enclosing_class() {
        let adapter = PythonAdapter;
        let source = b"class Foo:\n    @classmethod\n    def make(cls):\n        cls.create()";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let body_calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls && r.dst_name != "classmethod")
            .collect();
        assert_eq!(body_calls.len(), 1);
        assert_eq!(body_calls[0].dst_name, "Foo.create");
    }

    #[test]
    fn non_self_receivers_stay_bare() {
        let adapter = PythonAdapter;
        let source = b"class Foo:\n    def run(self):\n        obj.render()\n        self.store.save()\n\ndef free():\n    conn.close()";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let dsts: Vec<&str> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls)
            .map(|r| r.dst_name.as_str())
            .collect();
        // `obj.render()` has an unknown receiver type; `self.store.save()`
        // dispatches through an attribute, not the class itself — both stay
        // bare. Only direct self./cls. receivers gain the class qualifier.
        assert_eq!(dsts, vec!["render", "save", "close"]);
    }

    #[test]
    fn init_py_emits_module_entity() {
        let adapter = PythonAdapter;
        let source = b"\"\"\"Flask web framework.\"\"\"\nfrom .app import Flask";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("flask/__init__.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(
            modules.len(),
            1,
            "expected 1 Module entity, got {:?}",
            modules
        );
        assert_eq!(modules[0].name, "flask");
        assert_eq!(modules[0].visibility, Visibility::Public);
        assert_eq!(
            modules[0].doc_summary.as_deref(),
            Some("Flask web framework.")
        );
    }

    #[test]
    fn enum_class_extends_relation() {
        let adapter = PythonAdapter;
        let source = b"class Color(Enum):\n    RED = 1\n    GREEN = 2";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.py");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let extends: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Extends)
            .collect();
        assert_eq!(extends.len(), 1);
        assert_eq!(extends[0].src_name, "Color");
        assert_eq!(extends[0].dst_name, "Enum");
        let classes: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.name == "Color")
            .collect();
        assert_eq!(classes[0].kind, EntityKind::EnumDef);
    }

    /// Value references made by `path`, as `(src, dst)` pairs.
    fn value_refs(path: &str, source: &str) -> Vec<(String, String)> {
        let adapter = PythonAdapter;
        let bytes = source.as_bytes();
        let tree = adapter.parse(bytes).unwrap();
        let output = adapter
            .extract(&tree, bytes, &FilePathId::new(path))
            .unwrap();
        output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::References)
            .map(|r| (r.src_name.clone(), r.dst_name.clone()))
            .collect()
    }

    #[test]
    fn a_function_passed_as_a_keyword_argument_is_referenced() {
        // The reported shape: an argparse subcommand wired by name. `cmd_ingest`
        // is never called anywhere, so without this edge it owns none at all.
        let refs = value_refs(
            "cli.py",
            "def cmd_ingest(args):\n    return 1\n\ndef main():\n    ingest.set_defaults(func=cmd_ingest)\n",
        );
        assert!(
            refs.contains(&("main".to_string(), "cmd_ingest".to_string())),
            "expected main -> cmd_ingest, got {refs:?}"
        );
    }

    #[test]
    fn every_value_position_that_names_a_local_entity_is_referenced() {
        let refs = value_refs(
            "wire.py",
            concat!(
                "def handler(args):\n    return 1\n\n",
                "def by_argument():\n    register(handler)\n\n",
                "def by_assignment():\n    chosen = handler\n    return chosen\n\n",
                "def by_collection():\n    return [handler]\n\n",
                "def by_mapping():\n    return {\"ingest\": handler}\n\n",
                "def by_default(fn=handler):\n    return fn\n\n",
                "def by_return():\n    return handler\n",
            ),
        );
        for src in [
            "by_argument",
            "by_assignment",
            "by_collection",
            "by_mapping",
            "by_default",
            "by_return",
        ] {
            assert!(
                refs.contains(&(src.to_string(), "handler".to_string())),
                "expected {src} -> handler, got {refs:?}"
            );
        }
    }

    #[test]
    fn attribute_access_on_a_module_constant_references_the_constant() {
        // `TAG_RE.findall(...)` reads TAG_RE. The `.findall` leaf names a method
        // of the compiled regex, not a symbol of this file.
        let refs = value_refs(
            "parsing.py",
            "TAG_RE = compile(\"#\")\n\ndef extract_tags(text):\n    return TAG_RE.findall(text)\n",
        );
        assert!(
            refs.contains(&("extract_tags".to_string(), "TAG_RE".to_string())),
            "expected extract_tags -> TAG_RE, got {refs:?}"
        );
        assert!(
            !refs.iter().any(|(_, dst)| dst == "findall"),
            "the attribute leaf is not a symbol of this file, got {refs:?}"
        );
    }

    #[test]
    fn an_imported_constant_read_through_an_attribute_is_referenced_by_its_bare_name() {
        // Cross-file: the linker binds this through the file's import table, so
        // the destination must be the imported name, not a dotted form.
        let refs = value_refs(
            "cli.py",
            "from parsing import TAG_RE\n\ndef build_parser():\n    return TAG_RE.pattern\n",
        );
        assert!(
            refs.contains(&("build_parser".to_string(), "TAG_RE".to_string())),
            "expected build_parser -> TAG_RE, got {refs:?}"
        );
    }

    #[test]
    fn a_constant_reached_through_a_module_import_keeps_its_module_qualifier() {
        // `import parsing` binds the module; `parsing.TAG_RE` names a member of
        // it. The dotted form is what the linker's namespace-member tier
        // resolves, and reducing it to the bare leaf would let a same-named
        // symbol in any other file answer for it.
        let refs = value_refs(
            "cli.py",
            "import parsing\n\ndef build_parser():\n    return parsing.TAG_RE\n",
        );
        assert!(
            refs.contains(&("build_parser".to_string(), "parsing.TAG_RE".to_string())),
            "expected build_parser -> parsing.TAG_RE, got {refs:?}"
        );
    }

    #[test]
    fn import_source_is_annotated_on_a_value_reference() {
        let adapter = PythonAdapter;
        let source =
            b"from parsing import TAG_RE\n\ndef build_parser():\n    return TAG_RE.pattern\n";
        let tree = adapter.parse(source).unwrap();
        let output = adapter
            .extract(&tree, source, &FilePathId::new("cli.py"))
            .unwrap();
        let annotated = output
            .relations
            .iter()
            .find(|r| r.kind == kin_model::RelationKind::References && r.dst_name == "TAG_RE")
            .expect("the value reference exists");
        assert_eq!(annotated.import_source.as_deref(), Some("parsing"));
    }

    #[test]
    fn a_module_scope_reference_is_sourced_from_the_module() {
        let refs = value_refs(
            "cli.py",
            "def cmd_ingest(args):\n    return 1\n\nHANDLERS = {\"ingest\": cmd_ingest}\n",
        );
        assert!(
            refs.contains(&("cli".to_string(), "cmd_ingest".to_string())),
            "expected cli -> cmd_ingest, got {refs:?}"
        );
    }

    #[test]
    fn a_class_body_assignment_references_from_the_class() {
        let refs = value_refs(
            "cli.py",
            "def handler(args):\n    return 1\n\nclass Router:\n    default = handler\n",
        );
        assert!(
            refs.contains(&("Router".to_string(), "handler".to_string())),
            "expected Router -> handler, got {refs:?}"
        );
    }

    #[test]
    fn a_local_binding_shadows_a_module_level_name_of_the_same_name() {
        // `handler` inside `run` is a local, so reading it says nothing about
        // the module-level function. Without the shadow rule this edge would
        // make genuinely dead code look alive.
        let refs = value_refs(
            "cli.py",
            "def handler(args):\n    return 1\n\ndef run(handler):\n    return handler\n\ndef other():\n    handler = 1\n    return handler\n",
        );
        assert!(
            !refs.contains(&("run".to_string(), "handler".to_string())),
            "a parameter shadows the module scope, got {refs:?}"
        );
        assert!(
            !refs.contains(&("other".to_string(), "handler".to_string())),
            "a local assignment shadows the module scope, got {refs:?}"
        );
    }

    #[test]
    fn a_global_declaration_lifts_the_local_shadow() {
        let refs = value_refs(
            "counters.py",
            "TOTAL_SEEN = 0\n\ndef bump():\n    global TOTAL_SEEN\n    TOTAL_SEEN = TOTAL_SEEN + 1\n",
        );
        assert!(
            refs.contains(&("bump".to_string(), "TOTAL_SEEN".to_string())),
            "expected bump -> TOTAL_SEEN, got {refs:?}"
        );
    }

    #[test]
    fn a_name_this_file_neither_defines_nor_imports_emits_no_reference() {
        // Locals, parameters and builtins are the bulk of every value position.
        // Emitting them would let the linker bind a local called `config` to an
        // unrelated module-level `config` in some other file, by name alone.
        let refs = value_refs(
            "cli.py",
            "def run(payload):\n    total = len(payload)\n    return total\n",
        );
        assert!(refs.is_empty(), "expected no references, got {refs:?}");
    }

    #[test]
    fn an_unreferenced_function_still_owns_no_edge() {
        // The opposite direction: the rows that should stay on a dead-code list
        // must keep reporting nothing.
        let refs = value_refs(
            "parsing.py",
            "def unused_helper(text):\n    return text\n\ndef used_helper(text):\n    return text\n\ndef caller():\n    return used_helper\n",
        );
        assert!(
            refs.contains(&("caller".to_string(), "used_helper".to_string())),
            "expected caller -> used_helper, got {refs:?}"
        );
        assert!(
            !refs.iter().any(|(_, dst)| dst == "unused_helper"),
            "unused_helper is named nowhere, got {refs:?}"
        );
    }

    #[test]
    fn a_self_reference_emits_no_edge() {
        let refs = value_refs(
            "rec.py",
            "def wrapper(n):\n    if n:\n        return wrapper\n    return None\n",
        );
        assert!(
            !refs.contains(&("wrapper".to_string(), "wrapper".to_string())),
            "a self-reference establishes no reachability, got {refs:?}"
        );
    }

    #[test]
    fn a_repeated_reference_emits_one_edge() {
        let refs = value_refs(
            "cli.py",
            "def handler(args):\n    return 1\n\ndef wire():\n    a.set_defaults(func=handler)\n    b.set_defaults(func=handler)\n",
        );
        let hits = refs
            .iter()
            .filter(|(src, dst)| src == "wire" && dst == "handler")
            .count();
        assert_eq!(hits, 1, "expected one deduped edge, got {refs:?}");
    }

    #[test]
    fn a_bare_decorator_stays_a_call_edge_and_gains_no_duplicate_reference() {
        // A decorator applies its target at definition time, so it is already a
        // Calls edge. Adding a second References edge for the same site would
        // double-count one use.
        let adapter = PythonAdapter;
        let source =
            b"def register(fn):\n    return fn\n\n@register\ndef handler():\n    return 1\n";
        let tree = adapter.parse(source).unwrap();
        let output = adapter
            .extract(&tree, source, &FilePathId::new("cli.py"))
            .unwrap();
        assert!(
            output.relations.iter().any(|r| {
                r.kind == kin_model::RelationKind::Calls
                    && r.src_name == "handler"
                    && r.dst_name == "register"
            }),
            "the decorator keeps its Calls edge"
        );
        assert!(
            !output
                .relations
                .iter()
                .any(|r| r.kind == kin_model::RelationKind::References && r.dst_name == "register"),
            "no duplicate reference for the same decorator site"
        );
    }

    #[test]
    fn a_value_reference_does_not_change_call_coverage() {
        // The call-extraction audit records what the CALL walk could not
        // represent. Routing value references through it would report a file as
        // call-incomplete for reading a constant.
        let adapter = PythonAdapter;
        let source = b"HANDLER = 1\n\ndef run():\n    return HANDLER\n";
        let tree = adapter.parse(source).unwrap();
        let output = adapter
            .extract(&tree, source, &FilePathId::new("cov.py"))
            .unwrap();
        assert!(
            !output
                .relations
                .iter()
                .any(crate::extract::is_call_extraction_incomplete_marker),
            "reading a constant is not an unrepresented call"
        );
    }
}
