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
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_py_node(&child, source, file_id, None, &mut entities, &mut relations);
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
                _ => {}
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

        // Emit a Module entity for every Python source file.
        //
        // In Python, each `.py` file IS a module (PEP 328); `__init__.py` additionally
        // marks its containing directory as a *package*. Previously only package init
        // files produced Module entities, leaving regular modules without a node —
        // breaking per-file graph queries on Python repos.
        let (module_name, is_package) = if file_id.0.ends_with("__init__.py") {
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
        };
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
                extract_calls_from_context(node, source, &name, class_ctx, relations);
                if let Some(cls) = class_ctx {
                    relations.push(ExtractedRelation {
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
                        extract_py_node(&member, source, file_id, Some(&name), entities, relations);
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
                    extract_py_node(&child, source, file_id, class_ctx, entities, relations);
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
                    extract_py_node(&child, source, file_id, class_ctx, entities, relations);
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

/// Extract all function/method calls within a function/method body.
fn extract_calls_from_context(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    class_ctx: Option<&str>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call" {
            if let Some(function) = child.child_by_field_name("function") {
                let callee_name = match function.kind() {
                    "attribute" => {
                        let attr = function
                            .child_by_field_name("attribute")
                            .map(|f| f.utf8_text(source).unwrap_or("").to_string())
                            .unwrap_or_default();
                        // `self.m()` / `cls.m()` dispatch through the enclosing
                        // class, so qualify the callee with it: the linker can
                        // then resolve an inherited method through the class's
                        // Extends chain instead of fanning out on the bare name.
                        // Any other receiver (`obj.m()`, `self.store.m()`) stays
                        // bare — its type is unknown at parse time.
                        let self_or_cls_receiver = function
                            .child_by_field_name("object")
                            .filter(|obj| obj.kind() == "identifier")
                            .and_then(|obj| obj.utf8_text(source).ok())
                            .map(|text| text == "self" || text == "cls")
                            .unwrap_or(false);
                        match class_ctx {
                            Some(cls) if self_or_cls_receiver && !attr.is_empty() => {
                                format!("{}.{}", cls, attr)
                            }
                            _ => attr,
                        }
                    }
                    "identifier" => {
                        let raw = function.utf8_text(source).unwrap_or("");
                        raw.strip_prefix("self.")
                            .or_else(|| raw.strip_prefix("cls."))
                            .unwrap_or(raw)
                            .to_string()
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
        extract_calls_from_context(&child, source, context_name, class_ctx, relations);
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
}
