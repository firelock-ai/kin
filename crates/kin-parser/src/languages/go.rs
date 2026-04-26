// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

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

pub struct GoAdapter;

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
        let mut interface_methods: Vec<(String, Vec<String>)> = Vec::new();
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

        // Infer implicit interface satisfaction by comparing method sets.
        // If a type's method names are a superset of an interface's method
        // names, emit an Implements relation.
        for (iface_name, iface_method_names) in &interface_methods {
            if iface_method_names.is_empty() {
                continue;
            }
            for (type_name, type_method_names) in &type_methods {
                if iface_method_names
                    .iter()
                    .all(|m| type_method_names.contains(m))
                {
                    relations.push(ExtractedRelation {
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

fn extract_go_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
    interface_methods: &mut Vec<(String, Vec<String>)>,
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
                });
                extract_calls_from_body(node, source, &name, relations, call_prefixes);
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
                });

                // Emit Contains relation from receiver type to method
                if !receiver_type.is_empty() {
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Contains,
                        src_name: receiver_type.clone(),
                        dst_name: qualified.clone(),
                        import_source: None,
                    });
                }

                extract_calls_from_body(node, source, &qualified, relations, call_prefixes);
            }
        }
        "type_declaration" => {
            let mut cursor = node.walk();
            for spec in node.children(&mut cursor) {
                if spec.kind() == "type_spec" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let type_node = spec.child_by_field_name("type");
                        let kind = match type_node.map(|t| t.kind()) {
                            Some("struct_type") => EntityKind::Class,
                            Some("interface_type") => EntityKind::Interface,
                            _ => EntityKind::TypeAlias,
                        };

                        // For interfaces, extract method names for implicit
                        // satisfaction inference.
                        if kind == EntityKind::Interface {
                            if let Some(ref iface_node) = type_node {
                                let method_names =
                                    extract_interface_method_names(iface_node, source);
                                interface_methods.push((name.clone(), method_names));
                            }
                        }

                        // For structs, detect embedded types and emit Extends
                        // relations. Go embedded types provide method forwarding
                        // similar to inheritance.
                        if kind == EntityKind::Class {
                            if let Some(ref struct_node) = type_node {
                                for embedded in extract_embedded_types(struct_node, source) {
                                    relations.push(ExtractedRelation {
                                        kind: kin_model::RelationKind::Extends,
                                        src_name: name.clone(),
                                        dst_name: embedded,
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
                        });
                    }
                }
            }
        }
        "const_declaration" | "var_declaration" => {
            let mut cursor = node.walk();
            for spec in node.children(&mut cursor) {
                if spec.kind() == "const_spec" || spec.kind() == "var_spec" {
                    if let Some(name_node) = spec.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        let kind = if node.kind() == "const_declaration" {
                            EntityKind::Constant
                        } else {
                            EntityKind::StaticVar
                        };
                        entities.push(ExtractedEntity {
                            kind,
                            name,
                            signature: node_signature(&spec, source),
                            visibility: go_visibility(name_node.utf8_text(source).unwrap_or("")),
                            doc_summary: extract_preceding_comment(node, source),
                            fingerprint: compute_fingerprint(&spec, source),
                            span: span_from_node(&spec, file_id),
                        });
                    }
                }
            }
        }
        "import_declaration" => {
            let text = node.utf8_text(source).unwrap_or("").to_string();
            if !text.is_empty() {
                relations.push(ExtractedRelation {
                    kind: kin_model::RelationKind::Imports,
                    src_name: file_id.to_string(),
                    dst_name: text,
                    import_source: None,
                });
            }
        }
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

/// Extract method names from a Go interface_type node.
///
/// Go interfaces declare method signatures like:
///   type Shape interface {
///       Area() float64
///       Perimeter() float64
///   }
///
/// We walk the interface body looking for method_spec nodes and collect
/// their names. This list is later compared against concrete type method
/// sets to infer implicit interface satisfaction.
fn extract_interface_method_names(node: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
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
                        names.push(name);
                    }
                }
            }
        }
    }
    names
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
    let text = node.utf8_text(source).unwrap_or("");
    text.lines()
        .next()
        .unwrap_or(text)
        .trim_end_matches('{')
        .trim()
        .to_string()
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

/// Recursively walk a function/method body to find `call_expression` nodes.
///
/// Callee names are extracted as *simple* identifiers: for a selector
/// expression like `fmt.Println(x)`, the emitted `dst_name` is `"Println"`,
/// not `"fmt.Println"`. This matches name-based edge resolution against
/// entity names elsewhere in the graph.
///
/// The leftmost qualifier (e.g. `"fmt"` in `fmt.Println`) is recorded as a
/// side channel in `call_prefixes` — parallel to `relations` at the index of
/// the just-pushed relation — so the import-map post-pass can still annotate
/// package calls with their source module.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
    call_prefixes: &mut Vec<(usize, String)>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
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
                    let idx = relations.len();
                    relations.push(ExtractedRelation {
                        kind: kin_model::RelationKind::Calls,
                        src_name: context_name.to_string(),
                        dst_name: callee,
                        import_source: None,
                    });
                    if let Some(p) = prefix {
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
        extract_calls_from_body(&child, source, context_name, relations, call_prefixes);
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
        module_path,
        specifiers: vec![ImportedName {
            local_name,
            original_name,
            is_default: false,
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
}
