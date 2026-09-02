// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{ExtractedEntity, ExtractedRelation, FileImport, ImportedName, ParseOutput};

pub struct CAdapter;

impl LanguageAdapter for CAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::C
    }

    fn file_extensions(&self) -> &[&str] {
        &["c", "h"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_c::LANGUAGE)?;
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
        let mut forward_decls = Vec::new();
        let mut relations = Vec::new();
        let mut imports = Vec::new();
        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_c_node(
                &child,
                source,
                file_id,
                &mut entities,
                &mut forward_decls,
                &mut relations,
            );
        }

        // A forward declaration names a type whose members are spelled out somewhere
        // else. Keep it only when this file never spells them out, so an opaque handle
        // still reaches the graph while `struct redisContext;` does not shadow the
        // definition that follows it further down the same header.
        for candidate in forward_decls {
            let defined_here = entities
                .iter()
                .any(|entity| entity.kind == candidate.kind && entity.name == candidate.name);
            if !defined_here {
                entities.push(candidate);
            }
        }

        // Recursively extract all includes and ALL_CAPS macro usages across the whole file
        extract_includes_and_macros_recursive(&root, source, file_id, &mut imports, &mut relations);

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
            tests: Vec::new(),
            parse_state,
            parsed_call_sites: None,
        })
    }
}

fn extract_c_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    forward_decls: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = extract_function_name(node, source) {
                let vis = c_visibility(node, source);
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name: name.clone(),
                    signature: node_signature(node, source),
                    visibility: vis,
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                extract_calls_from_body(node, source, &name, relations);
            }
        }
        "declaration" => {
            extract_declaration(node, source, file_id, entities, forward_decls);
        }
        "type_definition" => {
            extract_type_definition(node, source, file_id, entities, forward_decls);
        }
        "struct_specifier" | "union_specifier" | "enum_specifier" => {
            extract_type_specifier(node, node, source, file_id, entities, forward_decls);
        }
        // Recurse into preprocessor conditional blocks (#ifdef, #ifndef, #if, etc.)
        // so that code inside header guards is still extracted.
        //
        // `extern "C" { ... }` is a linkage_specification whose declaration_list body
        // holds the rest of the header. The C header idiom opens that brace inside one
        // `#ifdef __cplusplus` and closes it inside another, so tree-sitter puts every
        // declaration between them in the body rather than at the top level. An ERROR
        // node likewise keeps the well-formed subtrees error recovery salvaged. Walk
        // through all of them, or a header's entire public API stays invisible.
        "preproc_ifdef"
        | "preproc_if"
        | "preproc_else"
        | "preproc_elif"
        | "linkage_specification"
        | "declaration_list"
        | "ERROR" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_c_node(&child, source, file_id, entities, forward_decls, relations);
            }
        }
        "preproc_def" | "preproc_function_def" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                if !name.is_empty() {
                    entities.push(ExtractedEntity {
                        kind: EntityKind::Macro,
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
        _ => {}
    }
}

/// Extract the function name from a `function_definition` node.
///
/// In tree-sitter-c, the name lives inside the `declarator` field which is
/// typically a `function_declarator` containing an `identifier`.
fn extract_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    find_identifier(&declarator, source)
}

/// Recursively search for the first `identifier` node in a subtree.
fn find_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        let text = node.utf8_text(source).unwrap_or("").to_string();
        if !text.is_empty() {
            return Some(text);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = find_identifier(&child, source) {
            return Some(name);
        }
    }
    None
}

/// Check whether a node or its children contain a function_declarator.
fn has_function_declarator(node: &tree_sitter::Node) -> bool {
    if node.kind() == "function_declarator" {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declarator" || has_function_declarator(&child) {
            return true;
        }
    }
    false
}

/// Extract entities from a top-level `declaration` node.
///
/// Handles: `const` declarations, `enum_specifier`, `struct_specifier`.
fn extract_declaration(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    forward_decls: &mut Vec<ExtractedEntity>,
) {
    let text = node.utf8_text(source).unwrap_or("");

    // A declaration can carry the type it defines: `struct Point { int x; } origin;`.
    // It can also merely name one: `struct timeval tv;` or
    // `struct redisReply *redisCommand(...);`. A forward declaration is neither, and
    // always parses as a bare specifier rather than as a declaration, so a bodyless
    // specifier here is only this declaration's type. Keep reading past it, because
    // there may still be a prototype to record.
    for kind in ["enum_specifier", "struct_specifier", "union_specifier"] {
        let Some(specifier) = find_child_of_kind(node, kind) else {
            continue;
        };
        if specifier.child_by_field_name("body").is_none() {
            break;
        }
        extract_type_specifier(&specifier, node, source, file_id, entities, forward_decls);
        return;
    }

    // Check for function declarations/prototypes (including macro-prefixed).
    // A declaration with a function_declarator descendant is a function prototype.
    if let Some(declarator) = node.child_by_field_name("declarator") {
        if has_function_declarator(&declarator) {
            if let Some(name) = find_identifier(&declarator, source) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name,
                    signature: node_signature(node, source),
                    visibility: c_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
                return;
            }
        }
    }

    // Check for const-qualified variable declarations
    if text.contains("const ") || text.contains("const\t") {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(name) = find_identifier(&declarator, source) {
                entities.push(ExtractedEntity {
                    kind: EntityKind::Constant,
                    name,
                    signature: node_signature(node, source),
                    visibility: c_visibility(node, source),
                    doc_summary: extract_preceding_comment(node, source),
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
    }
}

/// Record the struct, union or enum a `struct_specifier`, `union_specifier` or
/// `enum_specifier` node introduces.
///
/// `span_node` supplies the span, signature and doc comment, so a declaration can
/// attribute the whole statement while a bare specifier attributes itself. A specifier
/// with no `body` field is a forward declaration or a bare type reference such as
/// `struct timeval tv;`. It names a type defined elsewhere, so it goes to
/// `forward_decls` and is admitted only if nothing in the file defines that name.
fn extract_type_specifier(
    specifier: &tree_sitter::Node,
    span_node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    forward_decls: &mut Vec<ExtractedEntity>,
) {
    let Some(kind) = specifier_entity_kind(specifier) else {
        return;
    };
    let Some(name) = node_field_text(specifier, "name", source) else {
        return;
    };
    let entity = ExtractedEntity {
        kind,
        name,
        signature: node_signature(span_node, source),
        visibility: Visibility::Public,
        doc_summary: extract_preceding_comment(span_node, source),
        fingerprint: compute_fingerprint(span_node, source),
        span: span_from_node(span_node, file_id),
    };
    if specifier.child_by_field_name("body").is_some() {
        entities.push(entity);
    } else {
        forward_decls.push(entity);
    }
}

/// A union is modeled as a Class, mirroring struct handling, because kin-model carries
/// no separate record kind for either.
fn specifier_entity_kind(specifier: &tree_sitter::Node) -> Option<EntityKind> {
    match specifier.kind() {
        "struct_specifier" | "union_specifier" => Some(EntityKind::Class),
        "enum_specifier" => Some(EntityKind::EnumDef),
        _ => None,
    }
}

/// Read a named field's text, treating an empty field as absent.
fn node_field_text(node: &tree_sitter::Node, field: &str, source: &[u8]) -> Option<String> {
    let child = node.child_by_field_name(field)?;
    let text = child.utf8_text(source).unwrap_or("").trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// How far to follow a declarator chain before giving up. Real C nests a handful of
/// pointers and parentheses; anything deeper is malformed input, not a name.
const MAX_DECLARATOR_DEPTH: usize = 16;

/// Resolve the name a declarator introduces.
///
/// A typedef alias arrives wrapped in whatever declarator syntax names it: `foo_t`,
/// `*foo_p`, `arr_t[10]` or `(*cb_t)(int, void *)`. Follow the chain down through
/// pointers, arrays, functions and parentheses to the name at the bottom, so a
/// function-pointer typedef is stored as `cb_t` and not as the text of its declarator.
fn declarator_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut current = *node;
    for _ in 0..MAX_DECLARATOR_DEPTH {
        // A parenthesized declarator holds its inner declarator as an unnamed child.
        let next = current
            .child_by_field_name("declarator")
            .or_else(|| current.named_child(0));
        let Some(next) = next else {
            // The chain bottoms out at the name. Read the leaf's text rather than
            // trusting its kind: the grammar calls most aliases `type_identifier` but
            // spells the ones it already knows, such as `size_t`, `primitive_type`.
            let text = current.utf8_text(source).unwrap_or("").trim().to_string();
            return if text.is_empty() { None } else { Some(text) };
        };
        current = next;
    }
    None
}

/// One name a typedef introduces.
struct TypedefAlias {
    name: String,
    /// True when the declarator is the bare name. `typedef struct dict { ... } dict,
    /// *dictPtr;` introduces `dict` as another name for the record and `dictPtr` as a
    /// pointer to it, so only the first is the record itself.
    names_the_type_itself: bool,
}

/// Collect every alias a `type_definition` introduces.
///
/// One typedef can name several: `typedef struct X { ... } A, *Ap;` carries two
/// `declarator` fields, and reading only the first loses `Ap`.
fn typedef_aliases(node: &tree_sitter::Node, source: &[u8]) -> Vec<TypedefAlias> {
    let mut aliases: Vec<TypedefAlias> = Vec::new();
    for i in 0..node.child_count() {
        let Ok(child_index) = i.try_into() else {
            continue;
        };
        if node.field_name_for_child(child_index) != Some("declarator") {
            continue;
        }
        let Some(child) = node.child(child_index) else {
            continue;
        };
        // A pointer, array or function declarator derives a new type from the record;
        // only a bare name is another name for the record itself.
        let names_the_type_itself =
            child.child_by_field_name("declarator").is_none() && child.named_child_count() == 0;
        if let Some(name) = declarator_name(&child, source) {
            if !aliases.iter().any(|alias| alias.name == name) {
                aliases.push(TypedefAlias {
                    name,
                    names_the_type_itself,
                });
            }
        }
    }
    aliases
}

/// Extract entities from a `type_definition` (typedef) node.
///
/// A typedef that wraps a struct, union or enum yields that record's kind; anything
/// else is a type alias. When the wrapped specifier carries a tag whose spelling
/// differs from the alias, both names are recorded against the same span, because C
/// code reaches the type either way: `struct redisReader *r` and `redisReader *r` name
/// the same thing, and an agent asking about a codebase uses whichever the source uses.
fn extract_type_definition(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    forward_decls: &mut Vec<ExtractedEntity>,
) {
    let mut aliases = typedef_aliases(node, source);

    let mut wrapped = None;
    for kind in ["struct_specifier", "union_specifier", "enum_specifier"] {
        if let Some(specifier) = find_child_of_kind(node, kind) {
            wrapped = Some(specifier);
            break;
        }
    }

    let Some(specifier) = wrapped else {
        // Plain typedef, such as `typedef unsigned long size_t;`.
        for alias in aliases {
            entities.push(ExtractedEntity {
                kind: EntityKind::TypeAlias,
                name: alias.name,
                signature: node_signature(node, source),
                visibility: Visibility::Public,
                doc_summary: extract_preceding_comment(node, source),
                fingerprint: compute_fingerprint(node, source),
                span: span_from_node(node, file_id),
            });
        }
        return;
    };

    let Some(record_kind) = specifier_entity_kind(&specifier) else {
        return;
    };
    // The tag is a name C code can spell on its own: `struct redisReader *r`.
    if let Some(tag) = node_field_text(&specifier, "name", source) {
        if !aliases.iter().any(|alias| alias.name == tag) {
            aliases.push(TypedefAlias {
                name: tag,
                names_the_type_itself: true,
            });
        }
    }

    let defined_here = specifier.child_by_field_name("body").is_some();
    for alias in aliases {
        let entity = ExtractedEntity {
            kind: if alias.names_the_type_itself {
                record_kind
            } else {
                EntityKind::TypeAlias
            },
            name: alias.name,
            signature: node_signature(node, source),
            visibility: Visibility::Public,
            doc_summary: extract_preceding_comment(node, source),
            fingerprint: compute_fingerprint(node, source),
            span: span_from_node(node, file_id),
        };
        if defined_here {
            entities.push(entity);
        } else {
            forward_decls.push(entity);
        }
    }
}

/// Find the first direct child of a given kind (non-recursive).
fn find_child_of_kind<'a>(
    node: &tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let count = node.child_count();
    for i in 0..count {
        let Ok(child_index) = i.try_into() else {
            continue;
        };
        if let Some(child) = node.child(child_index) {
            if child.kind() == kind {
                return Some(child);
            }
        }
    }
    None
}

/// Determine visibility for a C declaration.
/// `static` → Private, everything else → Public.
fn c_visibility(node: &tree_sitter::Node, source: &[u8]) -> Visibility {
    // Check for `static` storage class specifier among direct children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "storage_class_specifier" {
            let text = child.utf8_text(source).unwrap_or("");
            if text == "static" {
                return Visibility::Private;
            }
        }
    }
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
            .trim_start_matches("/*")
            .trim_end_matches("*/")
            .trim_start_matches("//")
            .trim()
            .to_string();
        if cleaned.is_empty() {
            None
        } else {
            Some(cleaned)
        }
    } else {
        None
    }
}

/// Extract `#include` directive as an import relation and a `FileImport`.
fn extract_c_include(
    node: &tree_sitter::Node,
    source: &[u8],
    _file_id: &FilePathId,
    _relations: &mut Vec<ExtractedRelation>,
    imports: &mut Vec<FileImport>,
) {
    // The path child is either a `system_lib_string` (<stdio.h>) or
    // `string_literal` ("myheader.h").
    let path_node = node.child_by_field_name("path").or_else(|| {
        // Fallback: search children for the path token.
        // Use index-based iteration to avoid borrow-checker issues with cursor.
        let count = node.child_count();
        (0..count)
            .filter_map(|i| i.try_into().ok().and_then(|index| node.child(index)))
            .find(|c| c.kind() == "system_lib_string" || c.kind() == "string_literal")
    });

    if let Some(path_node) = path_node {
        let raw_path = path_node.utf8_text(source).unwrap_or("").to_string();
        let module_path = raw_path
            .trim_matches(|c| c == '"' || c == '<' || c == '>')
            .to_string();

        if !module_path.is_empty() {
            let local_name = module_path
                .rsplit('/')
                .next()
                .unwrap_or(&module_path)
                .to_string();

            imports.push(FileImport {
                site: crate::adapter::site_from_node(node),
                module_path,
                specifiers: vec![ImportedName {
                    local_name,
                    original_name: Some("default".to_string()),
                    is_default: true,
                }],
            });
        }
    }
}

/// Recursively walk a function body to find `call_expression` nodes.
fn extract_calls_from_body(
    node: &tree_sitter::Node,
    source: &[u8],
    context_name: &str,
    relations: &mut Vec<ExtractedRelation>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_expression" {
            if let Some(function) = child.child_by_field_name("function") {
                let callee = function.utf8_text(source).unwrap_or("").to_string();
                if is_valid_callee(&callee) {
                    relations.push(ExtractedRelation {
                        site: None,
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
        extract_calls_from_body(&child, source, context_name, relations);
    }
}

fn is_valid_callee(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('"')
        && !name.starts_with('\'')
        && !name.chars().all(|c| c.is_numeric())
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_function() {
        let adapter = CAdapter;
        let source = b"int add(int a, int b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        assert!(matches!(output.parse_state, ParseState::Valid));
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "add");
        assert_eq!(funcs[0].visibility, Visibility::Public);
    }

    #[test]
    fn extract_static_function() {
        let adapter = CAdapter;
        let source = b"static int helper(void) { return 0; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let funcs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Function)
            .collect();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "helper");
        assert_eq!(funcs[0].visibility, Visibility::Private);
    }

    #[test]
    fn extract_struct() {
        let adapter = CAdapter;
        let source = b"struct Point { int x; int y; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Point");
    }

    #[test]
    fn extract_typedef_struct() {
        let adapter = CAdapter;
        let source = b"typedef struct { int x; int y; } Vec2;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let structs: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].name, "Vec2");
    }

    #[test]
    fn extract_enum() {
        let adapter = CAdapter;
        let source = b"enum Color { RED, GREEN, BLUE };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let enums: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::EnumDef)
            .collect();
        assert_eq!(enums.len(), 1);
        assert_eq!(enums[0].name, "Color");
    }

    #[test]
    fn extract_typedef_alias() {
        let adapter = CAdapter;
        let source = b"typedef unsigned long size_t;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let aliases: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::TypeAlias)
            .collect();
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].name, "size_t");
    }

    #[test]
    fn extract_includes_as_imports() {
        let adapter = CAdapter;
        let source = b"#include <stdio.h>\n#include \"myheader.h\"\nint main() { return 0; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        assert_eq!(output.imports.len(), 2);

        let stdio = output
            .imports
            .iter()
            .find(|i| i.module_path == "stdio.h")
            .expect("should have stdio.h import");
        assert_eq!(stdio.specifiers[0].local_name, "stdio.h");
        assert_eq!(
            stdio.specifiers[0].original_name.as_deref(),
            Some("default")
        );
        assert!(stdio.specifiers[0].is_default);

        let myheader = output
            .imports
            .iter()
            .find(|i| i.module_path == "myheader.h")
            .expect("should have myheader.h import");
        assert_eq!(myheader.specifiers[0].local_name, "myheader.h");

        assert!(
            output
                .relations
                .iter()
                .all(|r| r.kind != kin_model::RelationKind::Imports),
            "imports should be carried by FileImport, not fake file-sourced relations"
        );
    }

    #[test]
    fn extracts_lowercase_preprocessor_macro_definitions_without_use_noise() {
        let adapter = CAdapter;
        let source = b"#define private public\nstruct Secret { int value; };\n";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("secret.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macro_entity = output
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Macro && entity.name == "private")
            .expect("lowercase preprocessor definitions should remain graph-visible macros");
        assert!(
            macro_entity.signature.contains("#define private public"),
            "macro signature should preserve the source directive, got {:?}",
            macro_entity.signature
        );
        assert!(
            output.relations.iter().all(|relation| relation.kind
                != kin_model::RelationKind::UsesMacro
                || relation.dst_name != "private"),
            "lowercase identifiers should not be promoted to macro-use edges"
        );
    }

    #[test]
    fn extract_call_relations() {
        let adapter = CAdapter;
        let source = b"void greet() { printf(\"hello\"); helper(); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
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
        assert!(dst_names.contains(&"printf"));
        assert!(dst_names.contains(&"helper"));
    }

    #[test]
    fn extract_multiple_entities() {
        let adapter = CAdapter;
        let source = br#"
#include <stdlib.h>

typedef struct {
    int x;
    int y;
} Point;

enum Direction { NORTH, SOUTH, EAST, WEST };

static int internal_helper(void) { return 42; }

int compute(Point p) { return internal_helper() + p.x; }
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("multi.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let names: Vec<&str> = output.entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Point"), "missing Point, got: {:?}", names);
        assert!(
            names.contains(&"Direction"),
            "missing Direction, got: {:?}",
            names
        );
        assert!(
            names.contains(&"internal_helper"),
            "missing internal_helper, got: {:?}",
            names
        );
        assert!(
            names.contains(&"compute"),
            "missing compute, got: {:?}",
            names
        );

        // Verify visibility
        let helper = output
            .entities
            .iter()
            .find(|e| e.name == "internal_helper")
            .unwrap();
        assert_eq!(helper.visibility, Visibility::Private);

        let compute = output
            .entities
            .iter()
            .find(|e| e.name == "compute")
            .unwrap();
        assert_eq!(compute.visibility, Visibility::Public);

        // Verify call relation from compute -> internal_helper
        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::Calls && r.src_name == "compute")
            .collect();
        assert!(
            calls.iter().any(|c| c.dst_name == "internal_helper"),
            "compute should call internal_helper, got: {:?}",
            calls
        );

        // Verify include import
        assert_eq!(output.imports.len(), 1);
        assert_eq!(output.imports[0].module_path, "stdlib.h");
    }

    #[test]
    fn extract_preprocessor_macros_as_entities() {
        let adapter = CAdapter;
        let source = br#"
#define JSON_DIAGNOSTICS 1
#define JSON_ASSERT(x) do { if (!(x)) abort(); } while (0)
"#;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("include/nlohmann/detail/macro_scope.h");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let macros: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Macro)
            .collect();
        let names: Vec<&str> = macros.iter().map(|e| e.name.as_str()).collect();

        assert!(names.contains(&"JSON_DIAGNOSTICS"), "macros={names:?}");
        assert!(names.contains(&"JSON_ASSERT"), "macros={names:?}");
    }

    #[test]
    fn extract_block_comment_doc_summary() {
        let adapter = CAdapter;
        let source = b"/* Adds two integers. */\nint add(int a, int b) { return a + b; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "add")
            .expect("should find add");
        assert_eq!(func.doc_summary.as_deref(), Some("Adds two integers."));
    }

    #[test]
    fn extract_line_comment_doc_summary() {
        let adapter = CAdapter;
        let source = b"// Increments the counter.\nint inc(int x) { return x + 1; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "inc")
            .expect("should find inc");
        assert_eq!(func.doc_summary.as_deref(), Some("Increments the counter."));
    }

    #[test]
    fn no_comment_yields_none() {
        let adapter = CAdapter;
        let source = b"int bare(void) { return 0; }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let func = output
            .entities
            .iter()
            .find(|e| e.name == "bare")
            .expect("should find bare");
        assert!(func.doc_summary.is_none());
    }

    #[test]
    fn extract_macro_usages_with_enclosing_scope() {
        let adapter = CAdapter;
        let source = b"void my_func() { MY_MACRO(); }";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();

        let calls: Vec<_> = output
            .relations
            .iter()
            .filter(|r| r.kind == kin_model::RelationKind::UsesMacro && r.dst_name == "MY_MACRO")
            .collect();
        assert!(!calls.is_empty());
        for call in &calls {
            assert_eq!(call.src_name, "my_func");
        }
    }

    #[test]
    fn extract_union() {
        let adapter = CAdapter;
        let source = b"union Value { int i; float f; };";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let unions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(unions.len(), 1);
        assert_eq!(unions[0].name, "Value");
        assert_eq!(unions[0].visibility, Visibility::Public);
    }

    #[test]
    fn extract_union_declared_with_variable() {
        let adapter = CAdapter;
        let source = b"union Data { int i; float f; } shared;";
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.c");
        let output = adapter.extract(&tree, source, &file_id).unwrap();
        let unions: Vec<_> = output
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Class)
            .collect();
        assert_eq!(unions.len(), 1);
        assert_eq!(unions[0].name, "Data");
    }

    /// A header shaped like hiredis's `read.h`: one `#ifdef __cplusplus` opens the
    /// `extern "C"` brace and a second one closes it, so tree-sitter puts the entire
    /// public API inside a single linkage_specification.
    const HIREDIS_SHAPED_HEADER: &[u8] = br#"
#ifndef __EXAMPLE_READ_H
#define __EXAMPLE_READ_H

#ifdef __cplusplus
extern "C" {
#endif

#define REDIS_READER_MAX_BUF (1024*16)

typedef struct redisReadTask {
    int type;
    struct redisReadTask *parent;
} redisReadTask;

typedef struct {
    int fd;
    void *loop;
} redisRunLoop;

struct redisSSLContext {
    void *ssl_ctx;
};

enum redisConnectionType {
    REDIS_CONN_TCP,
    REDIS_CONN_UNIX
};

typedef union redisValue {
    long long integer;
    double dval;
} redisValue;

typedef void (redisPushFn)(void *, void *);
typedef void (*redisDisconnectFn)(struct redisReadTask *, int);

typedef struct redisReader {
    int err;
    char *buf;
    redisReadTask **task;
} redisReader;

redisReader *redisReaderCreate(void);

#ifdef __cplusplus
}
#endif

#endif
"#;

    fn c_entities(source: &[u8]) -> Vec<ExtractedEntity> {
        let adapter = CAdapter;
        let tree = adapter.parse(source).unwrap();
        let file_id = FilePathId::new("test.h");
        adapter.extract(&tree, source, &file_id).unwrap().entities
    }

    fn names_of(entities: &[ExtractedEntity], kind: EntityKind) -> Vec<String> {
        entities
            .iter()
            .filter(|entity| entity.kind == kind)
            .map(|entity| entity.name.clone())
            .collect()
    }

    #[test]
    fn extern_c_block_does_not_hide_the_public_api() {
        let entities = c_entities(HIREDIS_SHAPED_HEADER);
        let classes = names_of(&entities, EntityKind::Class);
        for expected in [
            "redisReadTask",
            "redisRunLoop",
            "redisSSLContext",
            "redisValue",
            "redisReader",
        ] {
            assert!(
                classes.iter().any(|name| name == expected),
                "{expected} missing from {classes:?}"
            );
        }
        assert!(
            names_of(&entities, EntityKind::EnumDef)
                .iter()
                .any(|name| name == "redisConnectionType"),
            "the enum inside the extern C block was dropped"
        );
        assert!(
            names_of(&entities, EntityKind::Function)
                .iter()
                .any(|name| name == "redisReaderCreate"),
            "the prototype inside the extern C block was dropped"
        );
        assert!(
            names_of(&entities, EntityKind::Macro)
                .iter()
                .any(|name| name == "REDIS_READER_MAX_BUF"),
            "the macro inside the extern C block was dropped"
        );
    }

    #[test]
    fn redis_reader_carries_the_span_of_its_definition() {
        let entities = c_entities(HIREDIS_SHAPED_HEADER);
        let reader = entities
            .iter()
            .find(|entity| entity.name == "redisReader" && entity.kind == EntityKind::Class)
            .expect("redisReader should be a Class");
        let text = std::str::from_utf8(
            &HIREDIS_SHAPED_HEADER[reader.span.start_byte..reader.span.end_byte],
        )
        .unwrap();
        assert!(
            text.contains("char *buf;"),
            "the span should cover the members, got: {text}"
        );
    }

    #[test]
    fn function_pointer_typedef_is_named_by_its_identifier() {
        let aliases = names_of(&c_entities(HIREDIS_SHAPED_HEADER), EntityKind::TypeAlias);
        assert!(
            aliases.iter().any(|name| name == "redisPushFn"),
            "{aliases:?}"
        );
        assert!(
            aliases.iter().any(|name| name == "redisDisconnectFn"),
            "{aliases:?}"
        );
        assert!(
            aliases.iter().all(|name| !name.contains('(')),
            "a raw declarator leaked into a name: {aliases:?}"
        );
    }

    #[test]
    fn typedef_union_is_a_class_and_not_an_alias() {
        let entities = c_entities(b"typedef union ffc_value { double d; long long i; } ffc_value;");
        assert_eq!(names_of(&entities, EntityKind::Class), vec!["ffc_value"]);
        assert!(names_of(&entities, EntityKind::TypeAlias).is_empty());
    }

    #[test]
    fn typedef_struct_records_the_tag_alongside_a_differing_alias() {
        let entities = c_entities(b"typedef struct foo_s { int a; } foo_t;");
        assert_eq!(
            names_of(&entities, EntityKind::Class),
            vec!["foo_t", "foo_s"]
        );
        let starts: Vec<usize> = entities
            .iter()
            .map(|entity| entity.span.start_byte)
            .collect();
        assert_eq!(
            starts[0], starts[1],
            "the tag and the alias should point at the same definition"
        );
    }

    #[test]
    fn a_typedef_records_every_alias_it_declares() {
        let entities = c_entities(b"typedef struct dict { int size; } dict, *dictPtr;");
        assert_eq!(names_of(&entities, EntityKind::Class), vec!["dict"]);
        assert_eq!(names_of(&entities, EntityKind::TypeAlias), vec!["dictPtr"]);
    }

    #[test]
    fn a_forward_declaration_does_not_shadow_the_definition_below_it() {
        let entities = c_entities(
            b"struct redisContext;\n\nstruct redisContext {\n    int fd;\n    char *obuf;\n};\n",
        );
        assert_eq!(names_of(&entities, EntityKind::Class), vec!["redisContext"]);
        let context = &entities[0];
        assert!(
            context.span.end_line > context.span.start_line,
            "the surviving entity should be the multi-line definition"
        );
    }

    #[test]
    fn an_opaque_type_declared_but_never_defined_still_reaches_the_graph() {
        let entities = c_entities(b"struct redisSSLContext;\nint use(struct redisSSLContext *c);");
        assert_eq!(
            names_of(&entities, EntityKind::Class),
            vec!["redisSSLContext"]
        );
    }

    #[test]
    fn a_bare_type_reference_is_not_recorded_as_a_definition() {
        let entities = c_entities(b"struct timeval tv;\nint elapsed(void) { return 0; }");
        assert!(
            names_of(&entities, EntityKind::Class).is_empty(),
            "a variable of an external type must not claim to define it"
        );
    }

    #[test]
    fn a_prototype_returning_a_struct_is_still_recorded() {
        let entities = c_entities(b"struct redisReply *redisCommand(void *c, const char *fmt);");
        assert!(
            names_of(&entities, EntityKind::Function)
                .iter()
                .any(|name| name == "redisCommand"),
            "{:?}",
            entities
                .iter()
                .map(|entity| (entity.kind, entity.name.as_str()))
                .collect::<Vec<_>>()
        );
    }

    /// hiredis's `adapters/libuv.h` shape: a `#if` arm opens a function body, the
    /// `#else` arm opens a second signature, and one closing brace serves both. The
    /// braces never balance, so tree-sitter makes the whole file a single ERROR node
    /// and hangs every well-formed declaration off it.
    const UNBALANCED_CONDITIONAL_HEADER: &[u8] = br#"
#ifndef __EXAMPLE_LIBUV_H
#define __EXAMPLE_LIBUV_H

typedef struct redisLibuvEvents {
    int events;
} redisLibuvEvents;

#if UV_VERSION_MINOR < 11
static void redisLibuvTimeout(void *timer, int status) {
    (void)status;
#else
static void redisLibuvTimeout(void *timer) {
#endif
    (void)timer;
}

static void redisLibuvCleanup(void *privdata) {
    (void)privdata;
}

#endif
"#;

    #[test]
    fn declarations_recovered_from_a_top_level_parse_error_are_kept() {
        let tree = CAdapter.parse(UNBALANCED_CONDITIONAL_HEADER).unwrap();
        let root = tree.root_node();
        assert_eq!(
            (root.child_count(), root.child(0).map(|node| node.kind())),
            (1, Some("ERROR")),
            "the fixture must reproduce the single top-level ERROR node, or this test \
             proves nothing about error recovery"
        );

        let entities = c_entities(UNBALANCED_CONDITIONAL_HEADER);
        assert!(
            names_of(&entities, EntityKind::Class)
                .iter()
                .any(|name| name == "redisLibuvEvents"),
            "{:?}",
            names_of(&entities, EntityKind::Class)
        );
        assert!(
            names_of(&entities, EntityKind::Function)
                .iter()
                .any(|name| name == "redisLibuvCleanup"),
            "{:?}",
            names_of(&entities, EntityKind::Function)
        );
    }
}

fn find_enclosing_entity(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut scopes = Vec::new();
    let mut curr = *node;

    while let Some(parent) = curr.parent() {
        match parent.kind() {
            "function_definition" => {
                if let Some(name) = extract_function_name(&parent, source) {
                    scopes.push(name);
                }
            }
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                if let Some(name_node) = parent.child_by_field_name("name") {
                    if let Ok(name_text) = name_node.utf8_text(source) {
                        let name = name_text.trim().to_string();
                        if !name.is_empty() {
                            scopes.push(name);
                        }
                    }
                }
            }
            _ => {}
        }
        curr = parent;
    }

    if scopes.is_empty() {
        None
    } else {
        scopes.reverse();
        Some(scopes.join("::"))
    }
}

fn extract_includes_and_macros_recursive(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &kin_model::FilePathId,
    imports: &mut Vec<crate::extract::FileImport>,
    relations: &mut Vec<crate::extract::ExtractedRelation>,
) {
    if node.kind() == "preproc_include" {
        extract_c_include(node, source, file_id, relations, imports);
    } else if matches!(
        node.kind(),
        "identifier" | "type_identifier" | "statement_identifier" | "field_identifier"
    ) {
        if let Ok(name) = node.utf8_text(source) {
            if is_all_caps_macro(name) {
                if let Some(src_name) = find_enclosing_entity(node, source) {
                    if src_name != name && !src_name.ends_with(&format!("::{}", name)) {
                        relations.push(crate::extract::ExtractedRelation {
                            site: None,
                            receiver: None,
                            call_shape: None,
                            kind: kin_model::RelationKind::UsesMacro,
                            src_name,
                            dst_name: name.to_string(),
                            import_source: None,
                        });
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_includes_and_macros_recursive(&child, source, file_id, imports, relations);
    }
}

fn is_all_caps_macro(name: &str) -> bool {
    let mut has_upper = false;
    for c in name.chars() {
        if c.is_ascii_lowercase() {
            return false;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    has_upper && name.len() >= 3
}
