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

pub struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Php
    }

    fn file_extensions(&self) -> &[&str] {
        &["php"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_php::LANGUAGE_PHP)?;
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
        extract_php_children(&root, source, file_id, None, &mut entities, &mut relations);
        extract_php_imports(&root, source, file_id, &mut imports, &mut relations);

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
                        format!("namespace {}", file_id.0),
                        &root,
                        source,
                        file_id,
                    ),
                );
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

        // Detect PHPUnit test methods (methods starting with test or annotated @test)
        let mut tests = Vec::new();
        for ent in &entities {
            if ent.kind == EntityKind::Method {
                let method_name = ent.name.rsplit('.').next().unwrap_or(&ent.name);
                if method_name.starts_with("test") {
                    tests.push(ExtractedTest {
                        name: ent.name.clone(),
                        kind: ExtractedTestKind::Unit,
                        runner: "phpunit".to_string(),
                    });
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

fn extract_php_children(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    class_ctx: Option<&str>,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_php_node(&child, source, file_id, class_ctx, entities, relations);
    }
}

fn extract_php_node(
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
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Function,
                        name: name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                        declaration_line: None,
                    });
                    extract_calls_from_body(node, source, &name, relations);
                }
            }
        }
        "method_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let method_name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !method_name.is_empty() {
                    let qualified = if let Some(cls) = class_ctx {
                        format!("{}.{}", cls, method_name)
                    } else {
                        method_name
                    };
                    let vis = detect_php_visibility(node, source);
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Method,
                        name: qualified.clone(),
                        signature: node_signature(node, source),
                        visibility: vis,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                        declaration_line: None,
                    });
                    if let Some(cls) = class_ctx {
                        relations.push(ExtractedRelation {
                            site: None,
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::Contains,
                            src_name: cls.to_string(),
                            dst_name: qualified.clone(),
                            import_source: None,
                        });
                    }
                    extract_calls_from_body(node, source, &qualified, relations);
                }
            }
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Class,
                        name: name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                        declaration_line: None,
                    });

                    // Extract base class (extends)
                    if let Some(base) = node.child_by_field_name("base_clause") {
                        let base_text = base.utf8_text(source).unwrap_or("").to_string();
                        let base_name = base_text
                            .trim()
                            .trim_start_matches("extends")
                            .trim()
                            .split(',')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if !base_name.is_empty() {
                            relations.push(ExtractedRelation {
                                site: None,
                                receiver: None,
                                call_shape: None,
                                kind: kin_model::RelationKind::Extends,
                                src_name: name.clone(),
                                dst_name: base_name,
                                import_source: None,
                            });
                        }
                    }

                    // Extract interfaces (implements)
                    extract_php_implements(node, source, &name, relations);

                    // Recurse into class body
                    if let Some(body) = node.child_by_field_name("body") {
                        extract_php_children(
                            &body,
                            source,
                            file_id,
                            Some(&name),
                            entities,
                            relations,
                        );
                    }
                }
            }
        }
        "interface_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Interface,
                        name: name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                        declaration_line: None,
                    });

                    // Recurse into interface body
                    if let Some(body) = node.child_by_field_name("body") {
                        extract_php_children(
                            &body,
                            source,
                            file_id,
                            Some(&name),
                            entities,
                            relations,
                        );
                    }
                }
            }
        }
        "trait_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::TraitDef,
                        name: name.clone(),
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                        declaration_line: None,
                    });

                    // Recurse into trait body
                    if let Some(body) = node.child_by_field_name("body") {
                        extract_php_children(
                            &body,
                            source,
                            file_id,
                            Some(&name),
                            entities,
                            relations,
                        );
                    }
                }
            }
        }
        "enum_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::EnumDef,
                        name,
                        signature: node_signature(node, source),
                        visibility: Visibility::Public,
                        doc_summary: extract_preceding_comment(node, source),
                        fingerprint: compute_fingerprint(node, source),
                        span: span_from_node(node, file_id),
                        declaration_line: None,
                    });
                }
            }
        }
        "const_declaration" => {
            let mut child_cursor = node.walk();
            for child in node.children(&mut child_cursor) {
                if child.kind() == "const_element" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        if !name.is_empty() {
                            let qualified = if let Some(cls) = class_ctx {
                                format!("{}.{}", cls, name)
                            } else {
                                name
                            };
                            entities.push(ExtractedEntity {
                                kind: EntityKind::Constant,
                                name: qualified,
                                signature: node_signature(node, source),
                                visibility: Visibility::Public,
                                doc_summary: None,
                                fingerprint: compute_fingerprint(node, source),
                                span: span_from_node(node, file_id),
                                declaration_line: None,
                            });
                        }
                    }
                }
            }
        }
        "property_declaration" => {
            // Extract class properties that are const-like (static final pattern not in PHP,
            // but we capture const properties via const_declaration above)
        }
        "namespace_definition" => {
            // Recurse into namespace body
            if let Some(body) = node.child_by_field_name("body") {
                extract_php_children(&body, source, file_id, class_ctx, entities, relations);
            }
        }
        // The top-level program node wraps everything
        "program" => {
            extract_php_children(node, source, file_id, class_ctx, entities, relations);
        }
        _ => {}
    }
}

/// Extract `implements` relations from a class declaration.
fn extract_php_implements(
    node: &tree_sitter::Node,
    source: &[u8],
    class_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "class_interface_clause" {
            let mut iface_cursor = child.walk();
            for iface in child.children(&mut iface_cursor) {
                if iface.is_named() && iface.kind() == "name" || iface.kind() == "qualified_name" {
                    let iface_name = iface.utf8_text(source).unwrap_or("").to_string();
                    if !iface_name.is_empty() {
                        relations.push(ExtractedRelation {
                            site: None,
                            receiver: None,
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
    }
}

fn detect_php_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            let text = child.utf8_text(source).unwrap_or("");
            return match text {
                "public" => Visibility::Public,
                "private" => Visibility::Private,
                "protected" => Visibility::Internal,
                _ => Visibility::Public,
            };
        }
    }
    // PHP default is public
    Visibility::Public
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
            .map(|l| {
                l.trim_start_matches('/')
                    .trim_start_matches('*')
                    .trim_end_matches('*')
                    .trim_end_matches('/')
                    .trim()
            })
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

/// Recursively walk a function/method body to find call expressions.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_call_expression" || child.kind() == "member_call_expression" {
            if let Some(name_node) = child.child_by_field_name("name") {
                let callee = name_node.utf8_text(source).unwrap_or("").to_string();
                if !callee.is_empty() {
                    relations.push(ExtractedRelation {
                        // The call expression itself, so a reference row can
                        // report the line the call is written on. Without it the
                        // linker has no span to store and every consuming
                        // surface reports the edge as having no evidence span.
                        site: Some(crate::adapter::site_from_node(&child)),
                        receiver: None,
                        call_shape: None,
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee,
                        import_source: None,
                    });
                }
            } else {
                // For function_call_expression, the function name might be a direct child
                let func = child.child_by_field_name("function");
                if let Some(func_node) = func {
                    let callee = func_node.utf8_text(source).unwrap_or("").to_string();
                    if !callee.is_empty() && !callee.starts_with('"') && !callee.starts_with('\'') {
                        relations.push(ExtractedRelation {
                            // The call expression itself, for the same reason
                            // the named-callee arm above records one.
                            site: Some(crate::adapter::site_from_node(&child)),
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::Calls,
                            src_name: context_name.to_string(),
                            dst_name: callee,
                            import_source: None,
                        });
                    }
                }
            }
        }
        extract_calls_from_body(&child, source, context_name, relations);
    }
}

/// Extract `use` imports at any nesting level.
#[allow(clippy::only_used_in_recursion)]
fn extract_php_imports(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    imports: &mut Vec<FileImport>,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "namespace_use_declaration" {
            let text = child.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                // Parse the use declaration into FileImport
                if let Some(file_import) = parse_php_use_declaration(&child, source) {
                    imports.push(file_import);
                }
            }
        }
        // Recurse to find use declarations inside namespace bodies
        extract_php_imports(&child, source, file_id, imports, relations);
    }
}

/// Parse a `namespace_use_declaration` into a structured `FileImport`.
fn parse_php_use_declaration(node: &tree_sitter::Node, source: &[u8]) -> Option<FileImport> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "namespace_use_clause" {
            // `use App\Models\Record as Row` puts the alias inside the use
            // clause, so the CLAUSE's own text is `App\Models\Record as Row`.
            // Reading it whole made the module path that whole string, which
            // names nothing this repository could resolve, and made the
            // original name the entire statement including the `use` keyword.
            // The coordinate is the clause's qualified name and nothing else.
            let alias_node = child.child_by_field_name("alias");
            let mut clause_cursor = child.walk();
            let path_node = child.children(&mut clause_cursor).find(|node| {
                node.kind() == "qualified_name"
                    || (node.is_named()
                        && node.kind() == "name"
                        && alias_node.is_none_or(|alias| alias.start_byte() != node.start_byte()))
            });
            let full_path = path_node
                .and_then(|node| node.utf8_text(source).ok())
                .unwrap_or("")
                .trim()
                .to_string();
            if full_path.is_empty() {
                continue;
            }

            let alias = alias_node
                .and_then(|node| node.utf8_text(source).ok())
                .map(str::trim)
                .filter(|alias| !alias.is_empty())
                .map(str::to_string);

            let leaf = full_path
                .rsplit('\\')
                .next()
                .unwrap_or(&full_path)
                .to_string();
            let has_alias = alias.is_some();
            let local_name = alias.unwrap_or_else(|| leaf.clone());

            return Some(FileImport {
                site: crate::adapter::site_from_node(node),
                module_path: full_path,
                specifiers: vec![ImportedName {
                    local_name,
                    // The name the TARGET declares, so an edge minted from this
                    // import points at a name some file actually writes.
                    original_name: has_alias.then_some(leaf),
                    is_default: false,
                    // The clause, not the declaration: `use\n    Foo\Bar;`
                    // opens on the `use` line and names the type on the next.
                    site: Some(crate::adapter::site_from_node(&child)),
                }],
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_php_function() {
        let adapter = PhpAdapter;
        let source = b"<?php\nfunction greet($name) {\n    return \"Hello $name\";\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        // The function, plus the file's own module surface: the entity an
        // entity-level `Imports` edge from this file is sourced at.
        assert_eq!(output.entities.len(), 2);
        let functions: Vec<_> = output
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Function)
            .collect();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "greet");
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Module)
            .collect();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "test");
    }

    #[test]
    fn parse_php_class() {
        let adapter = PhpAdapter;
        let source = b"<?php\nclass Dog {\n    public function bark() {}\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Dog.php");
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
    fn parse_php_interface() {
        let adapter = PhpAdapter;
        let source = b"<?php\ninterface Runnable {\n    public function run(): void;\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Runnable.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let ifaces: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Interface)
            .collect();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "Runnable");
    }

    #[test]
    fn parse_php_visibility() {
        let adapter = PhpAdapter;
        let source = b"<?php\nclass Foo {\n    public function pub_method() {}\n    private function priv_method() {}\n    protected function prot_method() {}\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Foo.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let methods: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Method)
            .collect();
        assert_eq!(methods.len(), 3);

        let pub_m = methods.iter().find(|m| m.name == "Foo.pub_method").unwrap();
        assert_eq!(pub_m.visibility, Visibility::Public);

        let priv_m = methods
            .iter()
            .find(|m| m.name == "Foo.priv_method")
            .unwrap();
        assert_eq!(priv_m.visibility, Visibility::Private);

        let prot_m = methods
            .iter()
            .find(|m| m.name == "Foo.prot_method")
            .unwrap();
        assert_eq!(prot_m.visibility, Visibility::Internal);
    }

    #[test]
    fn parse_php_trait() {
        let adapter = PhpAdapter;
        let source = b"<?php\ntrait Loggable {\n    public function log($msg) {}\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("Loggable.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let traits: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::TraitDef)
            .collect();
        assert_eq!(traits.len(), 1);
        assert_eq!(traits[0].name, "Loggable");
    }

    #[test]
    fn parse_php_test_detection() {
        let adapter = PhpAdapter;
        let source = b"<?php\nclass FooTest {\n    public function testSomething() {}\n    public function helper() {}\n}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("FooTest.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert_eq!(output.tests.len(), 1);
        assert_eq!(output.tests[0].name, "FooTest.testSomething");
        assert_eq!(output.tests[0].runner, "phpunit");
    }

    /// A file whose bytes declare nothing mints no module surface.
    ///
    /// The surface is synthetic: it stands for the file, not for anything the
    /// file wrote. Minting it unconditionally made a comment-only or unreadable
    /// file count as parsed, so the parse-coverage census read a clean row for a
    /// repository holding a hole and could not name the file. Rust carried this
    /// rule already; these adapters did not.
    #[test]
    fn comment_only_php_file_mints_no_module_surface() {
        let adapter = PhpAdapter;
        let source = b"<?php\n// nothing is declared here\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/Silent.php");
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
    fn php_file_with_one_declaration_mints_the_module_surface() {
        let adapter = PhpAdapter;
        let source = b"<?php\nfunction greet() {}\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/greet.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let modules: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Module)
            .collect();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "greet");
        assert_eq!(output.entities[0].kind, EntityKind::Module);
    }

    /// An import alone is a surface too, and the edge is sourced at the module.
    #[test]
    fn php_file_with_only_an_import_mints_the_module_surface() {
        let adapter = PhpAdapter;
        let source = b"<?php\nuse App\\Storage\\Dog;\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("lib/uses.php");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(!output.imports.is_empty());
        assert_eq!(output.entities[0].kind, EntityKind::Module);
    }
}
