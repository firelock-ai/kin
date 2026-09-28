// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persist syntax evidence for scalar bindings, using the tree already parsed
//! by ingestion. Consumers never infer immutability from an entity kind.

use std::collections::BTreeMap;

use kin_model::{Entity, EntityKind, LanguageId};
use serde_json::json;
use tree_sitter::{Node, Tree};

const BINDING: &str = "scalar_binding_v1";
const CENSUS: &str = "python_binding_census_v1";

/// Attach evidence only for a complete syntax tree. Old or partially parsed
/// graphs have no evidence and keep the conservative call-domain reading.
pub fn attach_binding_callability(
    tree: &Tree,
    source: &[u8],
    language: LanguageId,
    entities: &mut [Entity],
) {
    for entity in entities.iter_mut() {
        entity.metadata.extra.remove(BINDING);
        entity.metadata.extra.remove(CENSUS);
    }
    if tree.root_node().has_error() {
        return;
    }
    let mut nodes = vec![tree.root_node()];
    let mut bindings = Vec::new();
    let mut writes = BTreeMap::<String, usize>::new();
    let mut blocked = false;
    while let Some(node) = nodes.pop() {
        if let Some((name, value, immutable)) = scalar_binding(node, source, language) {
            if scalar(value, language) {
                // Java exposes the whole field declaration for each member;
                // other adapters expose the binding itself. Rust additionally
                // includes leading documentation, handled by its line marker.
                let declaration = if language == LanguageId::Java {
                    node.parent().unwrap_or(node)
                } else {
                    node
                };
                bindings.push((
                    name,
                    declaration.byte_range(),
                    declaration.start_position().row,
                    immutable,
                ));
            }
        }
        if language == LanguageId::Python {
            python_writes(node, source, &mut writes, &mut blocked);
        }
        let mut cursor = node.walk();
        nodes.extend(node.named_children(&mut cursor));
    }
    for entity in entities.iter_mut().filter(|entity| {
        matches!(
            entity.kind,
            EntityKind::Constant | EntityKind::StaticVar | EntityKind::Field
        )
    }) {
        let Some(span) = &entity.span else { continue };
        let leaf = entity.name.rsplit(['.', ':']).next().unwrap_or("");
        if let Some((_, _, _, immutable)) = bindings.iter().find(|(name, range, row, _)| {
            let declaration_line = entity
                .metadata
                .extra
                .get(crate::extract::DECLARATION_LINE_KEY)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(span.start_line as u64);
            name == leaf
                && span.end_byte == range.end
                && (span.start_byte == range.start
                    || (language == LanguageId::Rust
                        && span.start_byte < range.start
                        && declaration_line == *row as u64))
        }) {
            entity.metadata.extra.insert(
                BINDING.into(),
                json!({
                    "version":1,"name":leaf,"immutable":immutable,
                    "language":language.to_string(),
                }),
            );
        }
    }
    // One copy per file, on a deterministic source entity. Its existing
    // source digest binds the census to the selected tree's exact bytes.
    if language == LanguageId::Python {
        if let Some(entity) = entities.iter_mut().min_by_key(|entity| {
            (
                entity
                    .span
                    .as_ref()
                    .map(|span| span.start_byte)
                    .unwrap_or(usize::MAX),
                entity.id,
            )
        }) {
            entity.metadata.extra.insert(
                CENSUS.into(),
                json!({
                    "version":1,"writes":writes,"blocked":blocked,
                }),
            );
        }
    }
}

fn scalar_binding<'a>(
    node: Node<'a>,
    source: &[u8],
    language: LanguageId,
) -> Option<(String, Node<'a>, bool)> {
    let (name, value, immutable) = match language {
        LanguageId::Rust if matches!(node.kind(), "const_item" | "static_item") => {
            if node.kind() == "static_item" && has_token(node, "mut", source) {
                return None;
            }
            (
                node.child_by_field_name("name")?,
                node.child_by_field_name("value")?,
                true,
            )
        }
        LanguageId::Go if node.kind() == "const_spec" => {
            let name = node.child_by_field_name("name")?;
            let values = node.child_by_field_name("value")?;
            if values.named_child_count() != 1 {
                return None;
            }
            (name, values.named_child(0)?, true)
        }
        LanguageId::JavaScript | LanguageId::TypeScript if node.kind() == "variable_declarator" => {
            let declaration = node.parent()?;
            if declaration.kind() != "lexical_declaration"
                || !has_token(declaration, "const", source)
            {
                return None;
            }
            (
                node.child_by_field_name("name")?,
                node.child_by_field_name("value")?,
                true,
            )
        }
        LanguageId::Java if node.kind() == "variable_declarator" => {
            let declaration = node.parent()?;
            if declaration.kind() != "field_declaration"
                || !has_token(declaration, "static", source)
                || !has_token(declaration, "final", source)
            {
                return None;
            }
            (
                node.child_by_field_name("name")?,
                node.child_by_field_name("value")?,
                true,
            )
        }
        LanguageId::Python if node.kind() == "assignment" => {
            let parent = node.parent()?;
            if parent.kind() != "expression_statement" || parent.parent()?.kind() != "module" {
                return None;
            }
            (
                node.child_by_field_name("left")?,
                node.child_by_field_name("right")?,
                false,
            )
        }
        // PHP strings and C-family casts can designate callable values.
        _ => return None,
    };
    if !matches!(name.kind(), "identifier" | "field_identifier") {
        return None;
    }
    Some((name.utf8_text(source).ok()?.into(), value, immutable))
}

fn has_token(node: Node<'_>, token: &str, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).any(|child| {
        (child.child_count() == 0 && child.utf8_text(source) == Ok(token))
            || (child.kind() == "modifiers" && has_token(child, token, source))
    });
    found
}

fn scalar(node: Node<'_>, language: LanguageId) -> bool {
    match language {
        LanguageId::Rust => matches!(
            node.kind(),
            "string_literal"
                | "raw_string_literal"
                | "char_literal"
                | "integer_literal"
                | "float_literal"
                | "boolean_literal"
        ),
        LanguageId::Go => matches!(
            node.kind(),
            "interpreted_string_literal"
                | "raw_string_literal"
                | "rune_literal"
                | "int_literal"
                | "float_literal"
                | "imaginary_literal"
                | "true"
                | "false"
        ),
        LanguageId::JavaScript | LanguageId::TypeScript => {
            matches!(node.kind(), "string" | "number" | "true" | "false" | "null")
        }
        LanguageId::Java => matches!(
            node.kind(),
            "string_literal"
                | "character_literal"
                | "decimal_integer_literal"
                | "hex_integer_literal"
                | "octal_integer_literal"
                | "binary_integer_literal"
                | "decimal_floating_point_literal"
                | "hex_floating_point_literal"
                | "true"
                | "false"
                | "null_literal"
        ),
        LanguageId::Python => {
            if matches!(node.kind(), "integer" | "float" | "true" | "false" | "none") {
                return true;
            }
            if node.kind() != "string" {
                return false;
            }
            let mut cursor = node.walk();
            let interpolated = node
                .named_children(&mut cursor)
                .any(|child| child.kind() == "interpolation");
            !interpolated
        }
        _ => false,
    }
}

fn python_writes(
    node: Node<'_>,
    source: &[u8],
    writes: &mut BTreeMap<String, usize>,
    blocked: &mut bool,
) {
    if matches!(
        node.kind(),
        "global_statement"
            | "nonlocal_statement"
            | "delete_statement"
            | "wildcard_import"
            | "match_statement"
    ) {
        *blocked = true;
    }
    if node.kind() == "identifier"
        && matches!(
            node.utf8_text(source).unwrap_or(""),
            "setattr"
                | "delattr"
                | "globals"
                | "locals"
                | "vars"
                | "__dict__"
                | "exec"
                | "eval"
                | "getattr"
                | "__setattr__"
                | "__delattr__"
                | "__getattribute__"
                | "__getattr__"
                | "__globals__"
                | "__builtins__"
                | "__import__"
                | "importlib"
        )
    {
        *blocked = true;
    }
    let target = match node.kind() {
        "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
            node.child_by_field_name("left")
        }
        "named_expression" | "function_definition" | "class_definition" => {
            node.child_by_field_name("name")
        }
        _ => None,
    };
    if let Some(target) = target {
        count_target(target, source, writes, blocked);
    }
    // Imported names, context-manager aliases and exception aliases can bind
    // the same name too. Count every identifier conservatively in these nodes.
    if matches!(
        node.kind(),
        "import_statement" | "import_from_statement" | "as_pattern"
    ) {
        count_target(node, source, writes, blocked);
    }
}

fn count_target(
    node: Node<'_>,
    source: &[u8],
    writes: &mut BTreeMap<String, usize>,
    blocked: &mut bool,
) {
    if matches!(node.kind(), "attribute" | "subscript") {
        *blocked = true;
    }
    if node.kind() == "identifier" {
        if let Ok(name) = node.utf8_text(source) {
            *writes.entry(name.into()).or_default() += 1;
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        count_target(child, source, writes, blocked);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterRegistry, FilePathId};

    fn parsed(path: &str, source: &str) -> Vec<Entity> {
        let registry = AdapterRegistry::default();
        let extension = path.rsplit('.').next().unwrap();
        let adapter = registry
            .get_by_extension_and_content(extension, source.as_bytes())
            .unwrap();
        let file = FilePathId::new(path);
        let tree = adapter.parse(source.as_bytes()).unwrap();
        let output = adapter.extract(&tree, source.as_bytes(), &file).unwrap();
        let mut entities: Vec<_> = output
            .entities
            .into_iter()
            .map(|entity| {
                entity.into_entity_with_source(
                    adapter.language_id(),
                    &file,
                    Some(source.as_bytes()),
                )
            })
            .collect();
        attach_binding_callability(
            &tree,
            source.as_bytes(),
            adapter.language_id(),
            &mut entities,
        );
        entities
    }

    #[test]
    fn scalar_binding_evidence_uses_the_actual_language_declaration() {
        for (path, source, name, immutable) in [
            ("a.rs", "const VALUE: &str = \"value\";", "VALUE", true),
            ("a.rs", "static VALUE: i32 = 1;", "VALUE", true),
            (
                "a.rs",
                "/// A documented constant.\nconst VALUE: i32 = 1;",
                "VALUE",
                true,
            ),
            ("a.go", "package a\nconst VALUE = \"value\"", "VALUE", true),
            ("a.js", "const VALUE = 1;", "VALUE", true),
            ("a.ts", "const VALUE: number = 1;", "VALUE", true),
            (
                "A.java",
                "class A { static final String VALUE = \"value\"; }",
                "VALUE",
                true,
            ),
            (
                "a.py",
                "VALUE = \"value\"\ndef render(): return \"prefix\" + VALUE\n",
                "VALUE",
                false,
            ),
        ] {
            let entities = parsed(path, source);
            let found = entities
                .iter()
                .find(|entity| entity.name.rsplit(['.', ':']).next() == Some(name))
                .unwrap();
            assert_eq!(
                found
                    .metadata
                    .extra
                    .get(BINDING)
                    .and_then(|value| value.get("immutable")),
                Some(&json!(immutable)),
                "{path}: {source}, {entities:?}"
            );
        }
    }

    #[test]
    fn callable_members_mutable_bindings_and_computed_initializers_have_no_scalar_proof() {
        for (path, source) in [
            ("a.rs", "static mut VALUE: i32 = 1;"),
            ("a.go", "package a\nvar VALUE = 1"),
            (
                "a.js",
                "let VALUE = 1; function replace() { VALUE = () => 7; }",
            ),
            ("a.js", "var VALUE = 1;"),
            ("a.js", "const VALUE = 1..toString;"),
            ("a.ts", "const VALUE = () => 1;"),
            (
                "a.js",
                "const VALUE = (() => { const VALUE = 1; return () => 7; })();",
            ),
            (
                "a.rs",
                "const VALUE: fn() -> i32 = { const VALUE: i32 = 1; || 7 };",
            ),
            ("a.ts", "const VALUE = `value${other}`;"),
            ("A.java", "class A { static String VALUE = \"value\"; }"),
            ("a.py", "VALUE = 1.0.conjugate"),
            ("a.py", "VALUE = f\"value{other}\""),
            ("a.py", "VALUE = \"a\" + \"b\""),
            ("a.php", "<?php const VALUE = 'strlen';"),
            ("a.c", "int (*VALUE)() = (void*)1;"),
        ] {
            assert!(
                parsed(path, source)
                    .iter()
                    .all(|entity| !entity.metadata.extra.contains_key(BINDING)),
                "{path}: {source}"
            );
        }
    }

    #[test]
    fn python_census_records_rebinding_and_reflective_hazards() {
        let base = "VALUE = 'value'\n";
        for (suffix, count, blocked) in [
            ("def render(): return 'prefix' + VALUE\n", 1, false),
            ("VALUE = lambda: 7\n", 2, false),
            (
                "def replace():\n global VALUE\n VALUE = lambda: 7\n",
                2,
                true,
            ),
            ("module.VALUE = lambda: 7\n", 2, true),
            ("setattr(module, 'VALUE', lambda: 7)\n", 1, true),
            ("module.__setattr__('VALUE', lambda: 7)\n", 1, true),
            ("module.__delattr__('VALUE')\n", 1, true),
            ("globals()['VALUE'] = lambda: 7\n", 1, true),
            ("vars(module).update(VALUE=lambda: 7)\n", 1, true),
            ("namespace = module.__dict__\n", 1, true),
            ("exec('VALUE = lambda: 7')\n", 1, true),
        ] {
            let entities = parsed("a.py", &format!("{base}{suffix}"));
            let census = entities
                .iter()
                .find_map(|entity| entity.metadata.extra.get(CENSUS))
                .unwrap();
            assert_eq!(census["writes"]["VALUE"], count, "{suffix}");
            assert_eq!(census["blocked"], blocked, "{suffix}");
        }
    }
}
