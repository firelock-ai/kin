// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One Go source unit as Kin owns it: a package clause, a single managed import
//! block, and top-level declarations placed deterministically.
//!
//! Callers address a unit by its package and role and a declaration by its
//! name and kind, never by a path or a byte offset. This module turns those
//! requests into exact bytes. It reads and writes nothing itself: the caller
//! supplies the unit's current bytes from repository authority, and the result
//! is reparsed and published through the ordinary reconcile path.

use std::ops::Range;

use tree_sitter::{Node, Tree};

/// A top-level Go declaration kind a caller may create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoDeclarationKind {
    Function,
    Method,
    Struct,
    Interface,
    /// A named type or alias whose underlying type is neither a struct nor an
    /// interface (`type ID string`, `type Key = string`).
    Type,
    Const,
    Var,
}

impl GoDeclarationKind {
    /// The graph kind the Go adapter derives for this declaration.
    pub fn entity_kind(self) -> kin_model::EntityKind {
        match self {
            Self::Function => kin_model::EntityKind::Function,
            Self::Method => kin_model::EntityKind::Method,
            Self::Struct => kin_model::EntityKind::Class,
            Self::Interface => kin_model::EntityKind::Interface,
            Self::Type => kin_model::EntityKind::TypeAlias,
            Self::Const => kin_model::EntityKind::Constant,
            Self::Var => kin_model::EntityKind::StaticVar,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::Struct => "struct",
            Self::Interface => "interface",
            Self::Type => "type",
            Self::Const => "const",
            Self::Var => "var",
        }
    }

    fn declares_type(self) -> bool {
        matches!(self, Self::Struct | Self::Interface | Self::Type)
    }
}

/// One top-level declaration, named the way the graph names its entities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDeclaration {
    pub kind: GoDeclarationKind,
    /// Top-level entity names in declaration order: `Name`, or `Receiver.Name`
    /// for a method, exactly as the Go adapter names them.
    pub names: Vec<String>,
    /// The base receiver type of a method.
    pub receiver: Option<String>,
    /// The declaration node's bytes, excluding any leading comment.
    pub range: Range<usize>,
}

/// One import spec. `alias` is the explicit package name, `_` or `.`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoImport {
    pub path: String,
    pub alias: Option<String>,
}

impl GoImport {
    /// Refuse anything that is not a plain module-mode import path. The path is
    /// rendered inside a Go string literal, so quotes, backslashes and control
    /// characters are refused rather than escaped.
    pub fn validate(&self) -> Result<(), String> {
        let path = self.path.as_str();
        if path.is_empty() || path.len() > 512 {
            return Err("an import path must be 1 to 512 bytes".into());
        }
        if !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~+-/".contains(&byte))
        {
            return Err(format!(
                "import path {path:?} may contain only ASCII letters, digits and . _ ~ + - /"
            ));
        }
        if path
            .split('/')
            .any(|element| element.is_empty() || element.starts_with('.'))
        {
            return Err(format!(
                "import path {path:?} must be a module-mode import path with no empty, relative \
                 or dot-leading elements"
            ));
        }
        if path == "C" {
            return Err("cgo's import \"C\" is not a managed import".into());
        }
        if let Some(alias) = self.alias.as_deref() {
            if alias != "_" && alias != "." && !is_go_identifier(alias) {
                return Err(format!(
                    "import alias {alias:?} must be a Go identifier, \"_\" or \".\""
                ));
            }
        }
        Ok(())
    }

    fn is_standard_library(&self) -> bool {
        !self
            .path
            .split('/')
            .next()
            .is_some_and(|first| first.contains('.'))
    }

    fn render(&self) -> String {
        match self.alias.as_deref() {
            Some(alias) => format!("{alias} \"{}\"", self.path),
            None => format!("\"{}\"", self.path),
        }
    }
}

/// A parsed Go source unit.
#[derive(Debug, Clone)]
pub struct GoUnit {
    pub package: String,
    package_end: usize,
    pub imports: Vec<GoImport>,
    import_declarations: Vec<Range<usize>>,
    import_comments: bool,
    pub declarations: Vec<GoDeclaration>,
}

/// What one unit edit asks for.
#[derive(Debug, Clone, Default)]
pub struct GoUnitEdit {
    /// Complete declaration bodies, placed in this order.
    pub declarations: Vec<String>,
    pub add_imports: Vec<GoImport>,
    /// Import paths to remove. Absent paths are not an error.
    pub remove_imports: Vec<String>,
}

/// The unit's new bytes and where each requested declaration landed in them.
#[derive(Debug, Clone)]
pub struct GoUnitEditOutcome {
    pub source: Vec<u8>,
    /// One per requested declaration, in request order, located in `source`.
    pub created: Vec<GoDeclaration>,
    pub imports_changed: bool,
}

const GO_KEYWORDS: [&str; 25] = [
    "break",
    "case",
    "chan",
    "const",
    "continue",
    "default",
    "defer",
    "else",
    "fallthrough",
    "for",
    "func",
    "go",
    "goto",
    "if",
    "import",
    "interface",
    "map",
    "package",
    "range",
    "return",
    "select",
    "struct",
    "switch",
    "type",
    "var",
];

/// One ASCII Go identifier that is not a keyword.
pub fn is_go_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !GO_KEYWORDS.contains(&name)
}

fn parse_tree(source: &[u8]) -> Result<Tree, String> {
    let mut parser = crate::adapter::make_parser(&tree_sitter_go::LANGUAGE)
        .map_err(|error| error.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("the Go parser returned no syntax tree")?;
    if tree.root_node().has_error() {
        return Err("the source is not complete valid Go syntax".into());
    }
    Ok(tree)
}

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> &'a str {
    std::str::from_utf8(&source[node.byte_range()]).unwrap_or("")
}

fn import_spec(node: Node<'_>, source: &[u8]) -> Option<GoImport> {
    let path = node.child_by_field_name("path")?;
    let literal = text(path, source);
    let path = literal
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            literal
                .strip_prefix('`')
                .and_then(|rest| rest.strip_suffix('`'))
        })?
        .to_string();
    let alias = node
        .child_by_field_name("name")
        .map(|name| text(name, source).to_string());
    Some(GoImport { path, alias })
}

fn contains_comment(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let children = node.children(&mut cursor).collect::<Vec<_>>();
    children
        .into_iter()
        .any(|child| child.kind() == "comment" || contains_comment(child))
}

/// Const and var specs in declaration order. A grouped var wraps its specs in
/// a `var_spec_list`; a grouped const holds them directly.
fn value_specs(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    let mut specs = Vec::new();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "var_spec_list" {
            let mut inner = child.walk();
            specs.extend(
                child
                    .named_children(&mut inner)
                    .filter(|spec| spec.kind() == "var_spec"),
            );
        } else if matches!(child.kind(), "const_spec" | "var_spec") {
            specs.push(child);
        }
    }
    specs
}

fn spec_names<'a>(spec: Node<'a>, source: &[u8]) -> Vec<String> {
    let mut cursor = spec.walk();
    spec.children_by_field_name("name", &mut cursor)
        .filter(|name| name.kind() == "identifier")
        .map(|name| text(name, source).to_string())
        .collect()
}

fn type_specs(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "type_spec" | "type_alias"))
        .collect()
}

fn declaration(node: Node<'_>, source: &[u8]) -> Option<GoDeclaration> {
    let range = node.byte_range();
    match node.kind() {
        "function_declaration" => Some(GoDeclaration {
            kind: GoDeclarationKind::Function,
            names: vec![text(node.child_by_field_name("name")?, source).to_string()],
            receiver: None,
            range,
        }),
        "method_declaration" => {
            let name = text(node.child_by_field_name("name")?, source);
            let receiver = crate::languages::go::method_receiver_type(&node, source)
                .filter(|receiver| !receiver.is_empty());
            Some(GoDeclaration {
                kind: GoDeclarationKind::Method,
                names: vec![match receiver.as_deref() {
                    Some(receiver) => format!("{receiver}.{name}"),
                    None => name.to_string(),
                }],
                receiver,
                range,
            })
        }
        "type_declaration" => {
            let specs = type_specs(node);
            let kind = match specs.first().map(|spec| {
                (
                    spec.kind(),
                    spec.child_by_field_name("type").map(|ty| ty.kind()),
                )
            }) {
                Some(("type_spec", Some("struct_type"))) => GoDeclarationKind::Struct,
                Some(("type_spec", Some("interface_type"))) => GoDeclarationKind::Interface,
                _ => GoDeclarationKind::Type,
            };
            Some(GoDeclaration {
                kind,
                names: specs
                    .iter()
                    .filter_map(|spec| spec.child_by_field_name("name"))
                    .map(|name| text(name, source).to_string())
                    .collect(),
                receiver: None,
                range,
            })
        }
        "const_declaration" | "var_declaration" => Some(GoDeclaration {
            kind: if node.kind() == "const_declaration" {
                GoDeclarationKind::Const
            } else {
                GoDeclarationKind::Var
            },
            // The adapter names a spec after its first name; so does this.
            names: value_specs(node)
                .into_iter()
                .filter_map(|spec| crate::languages::go::spec_entity_name(&spec, source))
                .collect(),
            receiver: None,
            range,
        }),
        _ => None,
    }
}

/// Parse a complete Go source unit. Invalid syntax is refused, since a unit
/// Kin cannot parse is a unit it cannot prove it left intact.
pub fn parse_unit(source: &[u8]) -> Result<GoUnit, String> {
    let tree = parse_tree(source)?;
    let root = tree.root_node();
    let mut package = None;
    let mut unit = GoUnit {
        package: String::new(),
        package_end: 0,
        imports: Vec::new(),
        import_declarations: Vec::new(),
        import_comments: false,
        declarations: Vec::new(),
    };
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        match node.kind() {
            "package_clause" => {
                if package.is_some() {
                    return Err("the unit declares more than one package clause".into());
                }
                let mut inner = node.walk();
                let name = node
                    .named_children(&mut inner)
                    .find(|child| child.kind() == "package_identifier")
                    .ok_or("the package clause names no package")?;
                package = Some(text(name, source).to_string());
                unit.package_end = node.end_byte();
            }
            "import_declaration" => {
                unit.import_comments |= contains_comment(node);
                unit.import_declarations.push(node.byte_range());
                let mut inner = node.walk();
                for child in node.named_children(&mut inner) {
                    if child.kind() == "import_spec" {
                        unit.imports.extend(import_spec(child, source));
                    } else if child.kind() == "import_spec_list" {
                        let mut specs = child.walk();
                        for spec in child.named_children(&mut specs) {
                            if spec.kind() == "import_spec" {
                                unit.imports.extend(import_spec(spec, source));
                            } else if spec.kind() == "comment" {
                                unit.import_comments = true;
                            }
                        }
                    }
                }
            }
            _ => unit.declarations.extend(declaration(node, source)),
        }
    }
    unit.package = package.ok_or("the unit has no package clause")?;
    Ok(unit)
}

/// Parse exactly one top-level declaration a caller asked Kin to create.
///
/// The body is the declaration and nothing else: a leading doc comment is kept,
/// but a package clause, an import, or a second declaration is refused, because
/// Kin owns the unit's package clause and import block. Shapes whose graph
/// identity would be ambiguous are refused rather than guessed: a grouped
/// `type ( ... )`, a spec declaring several names, and the blank identifier.
pub fn parse_declaration(body: &str) -> Result<GoDeclaration, String> {
    if body.trim().is_empty() {
        return Err("a declaration body must be nonempty".into());
    }
    const PREFIX: &str = "package kin\n\n";
    let wrapped = format!("{PREFIX}{}\n", body.trim());
    let source = wrapped.as_bytes();
    let tree = parse_tree(source).map_err(|_| {
        "the body is not one complete, valid Go declaration; send exactly the declaration, \
         with no package clause or imports"
            .to_string()
    })?;
    let root = tree.root_node();
    let mut cursor = root.walk();
    let mut packages = 0;
    let mut found = None;
    for node in root.named_children(&mut cursor) {
        match node.kind() {
            "package_clause" => packages += 1,
            "comment" => {}
            "import_declaration" => {
                return Err(
                    "the body carries an import; list imports in `imports` and Kin \
                     writes the unit's import block"
                        .into(),
                )
            }
            kind => {
                let parsed = declaration(node, source).ok_or_else(|| {
                    format!("a top-level {kind} is not a declaration Kin can create")
                })?;
                if found.replace((node, parsed)).is_some() {
                    return Err("the body declares more than one top-level declaration; \
                         create each declaration with its own operation"
                        .into());
                }
            }
        }
    }
    if packages != 1 {
        return Err("the body carries a package clause; Kin owns the unit's package clause".into());
    }
    let (node, mut parsed) = found.ok_or("the body declares nothing")?;
    match node.kind() {
        "type_declaration" => {
            let specs = type_specs(node);
            if specs.len() != 1
                || text(node, source).trim_start()["type".len()..]
                    .trim_start()
                    .starts_with('(')
            {
                let names = specs
                    .iter()
                    .filter_map(|spec| spec.child_by_field_name("name"))
                    .map(|name| text(name, source))
                    .collect::<Vec<_>>();
                return Err(format!(
                    "a grouped type ( ... ) is created one type at a time: send one EntityCreate \
                     per type ({}), each body a single `type Name ...` declaration, in the same \
                     mutate call, and they publish together",
                    names.join(", ")
                ));
            }
        }
        "const_declaration" | "var_declaration" => {
            let specs = value_specs(node);
            if specs.is_empty() {
                return Err("the declaration declares no names".into());
            }
            for spec in specs {
                let names = spec_names(spec, source);
                if names.len() != 1 {
                    return Err(format!(
                        "a spec declaring {} names at once is written one name per spec: send \
                         the same declaration with each name on its own line inside one \
                         grouped block, such as const (\n\t{} = ...\n\t{} = ...\n), so each \
                         name is its own entity",
                        names.len(),
                        names[0],
                        names[1]
                    ));
                }
            }
        }
        "method_declaration" if parsed.receiver.is_none() => {
            return Err("the method's receiver names no type".into());
        }
        _ => {}
    }
    if parsed.names.iter().any(|name| {
        name == "_" || name.starts_with("_.") || name.ends_with("._") || name.is_empty()
    }) {
        return Err(
            "a blank function, type or method declares no entity Kin can address; name \
             the declaration (a blank var or const, such as var _ Getter = (*Store)(nil), is \
             supported)"
                .into(),
        );
    }
    parsed.range = parsed.range.start - PREFIX.len()..parsed.range.end - PREFIX.len();
    Ok(parsed)
}

/// The canonical import block: standard library first, then everything else,
/// each group sorted by path, as gofmt leaves it.
pub fn render_import_block(imports: &[GoImport]) -> String {
    let mut standard = imports
        .iter()
        .filter(|import| import.is_standard_library())
        .collect::<Vec<_>>();
    let mut other = imports
        .iter()
        .filter(|import| !import.is_standard_library())
        .collect::<Vec<_>>();
    standard.sort();
    other.sort();
    let mut block = String::from("import (\n");
    for import in &standard {
        block.push_str(&format!("\t{}\n", import.render()));
    }
    if !standard.is_empty() && !other.is_empty() {
        block.push('\n');
    }
    for import in &other {
        block.push_str(&format!("\t{}\n", import.render()));
    }
    block.push(')');
    block
}

fn sorted(imports: &[GoImport]) -> Vec<GoImport> {
    let mut sorted = imports.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}

/// Replace every import declaration with one canonical block directly after
/// the package clause. Declarations and comments elsewhere keep their bytes.
fn rewrite_imports(source: &[u8], unit: &GoUnit, imports: &[GoImport]) -> Vec<u8> {
    let mut remaining = source.to_vec();
    for range in unit.import_declarations.iter().rev() {
        let mut end = range.end;
        while end < remaining.len() && matches!(remaining[end], b' ' | b'\t' | b'\r' | b'\n') {
            end += 1;
        }
        remaining.drain(range.start..end);
    }
    let head = &remaining[..unit.package_end];
    let tail = &remaining[unit.package_end..];
    let tail = &tail[tail
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(tail.len())..];
    let mut result = head.to_vec();
    if !imports.is_empty() {
        result.extend_from_slice(b"\n\n");
        result.extend_from_slice(render_import_block(imports).as_bytes());
    }
    if tail.is_empty() {
        result.push(b'\n');
    } else {
        result.extend_from_slice(b"\n\n");
        result.extend_from_slice(tail);
    }
    result
}

/// Where a new declaration goes: a method directly after the last declaration
/// of its receiver type or of that type's methods in this unit, anything else
/// at the end of the unit.
fn insertion_point(unit: &GoUnit, source: &[u8], created: &GoDeclaration) -> Option<usize> {
    let receiver = created.receiver.as_deref()?;
    let end = unit
        .declarations
        .iter()
        .filter(|declaration| {
            (declaration.kind == GoDeclarationKind::Method
                && declaration.receiver.as_deref() == Some(receiver))
                || (declaration.kind.declares_type()
                    && declaration.names.iter().any(|name| name == receiver))
        })
        .map(|declaration| declaration.range.end)
        .max()?;
    // Keep a same-line trailing comment with the declaration it annotates.
    let line_end = source[end..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(source.len(), |offset| end + offset);
    let rest = std::str::from_utf8(&source[end..line_end]).ok()?.trim();
    Some(if rest.is_empty() || rest.starts_with("//") {
        line_end
    } else {
        end
    })
}

/// Apply declaration creations and import changes to one unit.
///
/// `existing` is the unit's current bytes, or `None` for a unit that does not
/// exist yet, in which case Kin writes its package clause. Every existing
/// declaration keeps its exact bytes; the import block is rewritten only when
/// the import set actually changes.
pub fn edit_unit(
    existing: Option<&[u8]>,
    package: &str,
    edit: &GoUnitEdit,
) -> Result<GoUnitEditOutcome, String> {
    if !is_go_identifier(package) {
        return Err(format!(
            "package name {package:?} must be one Go identifier"
        ));
    }
    let mut source = match existing {
        Some(bytes) => bytes.to_vec(),
        None => format!("package {package}\n").into_bytes(),
    };
    let unit = parse_unit(&source)?;
    if unit.package != package {
        return Err(format!(
            "this source unit declares package {}, not {package}",
            unit.package
        ));
    }
    let mut requested = Vec::with_capacity(edit.declarations.len());
    for body in &edit.declarations {
        let parsed = parse_declaration(body)?;
        let unit = parse_unit(&source)?;
        let body = body.trim();
        match insertion_point(&unit, &source, &parsed) {
            Some(offset) => {
                let insertion = format!("\n\n{body}");
                source.splice(offset..offset, insertion.bytes());
            }
            None => {
                let kept = source.len()
                    - source
                        .iter()
                        .rev()
                        .take_while(|byte| byte.is_ascii_whitespace())
                        .count();
                source.truncate(kept);
                source.extend_from_slice(format!("\n\n{body}\n").as_bytes());
            }
        }
        requested.push(parsed);
    }

    let unit = parse_unit(&source)?;
    let mut imports = unit.imports.clone();
    for add in &edit.add_imports {
        add.validate()?;
        match imports.iter().find(|import| import.path == add.path) {
            Some(held) if held.alias == add.alias => {}
            Some(held) => {
                return Err(format!(
                    "{:?} is already imported{}; remove it before importing it under another name",
                    add.path,
                    held.alias
                        .as_deref()
                        .map(|alias| format!(" as {alias}"))
                        .unwrap_or_default()
                ))
            }
            None => imports.push(add.clone()),
        }
    }
    for path in &edit.remove_imports {
        imports.retain(|import| &import.path != path);
    }
    let imports_changed = sorted(&imports) != sorted(&unit.imports);
    if imports_changed {
        if unit.import_comments {
            return Err(
                "this unit's import declarations carry comments, which Kin does not \
                 rewrite; its imports cannot be managed until those comments are removed"
                    .into(),
            );
        }
        if unit.imports.iter().any(|import| import.path == "C") {
            return Err(
                "this unit uses cgo (import \"C\"), whose imports Kin does not manage".into(),
            );
        }
        source = rewrite_imports(&source, &unit, &sorted(&imports));
    }

    let unit = parse_unit(&source)?;
    let created = requested
        .iter()
        .map(|wanted| {
            let mut matches = unit.declarations.iter().filter(|declaration| {
                declaration.kind == wanted.kind && declaration.names == wanted.names
            });
            match (matches.next(), matches.next()) {
                (Some(found), None) => Ok(found.clone()),
                _ => Err(format!(
                    "{} {} is not uniquely declared in the edited unit",
                    wanted.kind.label(),
                    wanted.names.join(", ")
                )),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GoUnitEditOutcome {
        source,
        created,
        imports_changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn import(path: &str) -> GoImport {
        GoImport {
            path: path.into(),
            alias: None,
        }
    }

    #[test]
    fn go_unit_creates_the_first_unit_with_its_package_and_imports() {
        let outcome = edit_unit(
            None,
            "main",
            &GoUnitEdit {
                declarations: vec!["func main() {\n\tfmt.Println(store.New().Len())\n}".into()],
                add_imports: vec![import("fmt"), import("example.com/app/internal/store")],
                remove_imports: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(outcome.source).unwrap(),
            "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/app/internal/store\"\n)\n\nfunc main() {\n\tfmt.Println(store.New().Len())\n}\n"
        );
        assert!(outcome.imports_changed);
        assert_eq!(outcome.created[0].names, ["main"]);
    }

    #[test]
    fn go_unit_places_methods_with_their_type_and_keeps_existing_bytes() {
        let existing = "package store\n\n// Store holds items.\ntype Store struct {\n\titems map[string]string\n} // trailing\n\nfunc (s *Store) Len() int { return len(s.items) }\n\nfunc other() {}\n";
        let outcome = edit_unit(
            Some(existing.as_bytes()),
            "store",
            &GoUnitEdit {
                declarations: vec![
                    "func (s *Store) Get(key string) string {\n\treturn s.items[key]\n}".into(),
                    "const Limit = 10".into(),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let source = String::from_utf8(outcome.source).unwrap();
        assert_eq!(
            source,
            "package store\n\n// Store holds items.\ntype Store struct {\n\titems map[string]string\n} // trailing\n\nfunc (s *Store) Len() int { return len(s.items) }\n\nfunc (s *Store) Get(key string) string {\n\treturn s.items[key]\n}\n\nfunc other() {}\n\nconst Limit = 10\n"
        );
        assert!(!outcome.imports_changed);
        assert_eq!(outcome.created[0].names, ["Store.Get"]);
        assert_eq!(outcome.created[1].kind, GoDeclarationKind::Const);
    }

    #[test]
    fn go_unit_import_management_is_idempotent_and_deterministic() {
        let existing = "package store\n\nimport \"sync\"\nimport (\n\tb \"bytes\"\n\t\"errors\"\n)\n\nvar mu sync.Mutex\n";
        let unchanged = edit_unit(
            Some(existing.as_bytes()),
            "store",
            &GoUnitEdit {
                add_imports: vec![import("sync"), import("errors")],
                remove_imports: vec!["absent".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!unchanged.imports_changed);
        assert_eq!(unchanged.source, existing.as_bytes());
        let changed = edit_unit(
            Some(existing.as_bytes()),
            "store",
            &GoUnitEdit {
                add_imports: vec![import("strings")],
                remove_imports: vec!["errors".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(changed.source).unwrap(),
            "package store\n\nimport (\n\tb \"bytes\"\n\t\"strings\"\n\t\"sync\"\n)\n\nvar mu sync.Mutex\n"
        );
        let cleared = edit_unit(
            Some(b"package store\n\nimport \"fmt\"\n\nfunc f() {}\n"),
            "store",
            &GoUnitEdit {
                remove_imports: vec!["fmt".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(cleared.source).unwrap(),
            "package store\n\nfunc f() {}\n"
        );
    }

    /// Every refusal an agent meets for a shape it writes often names the one
    /// call that works.
    #[test]
    fn go_unit_refusals_name_the_one_step_alternative() {
        let grouped = parse_declaration("type (\n\tA int\n\tB string\n)").unwrap_err();
        assert!(
            grouped.contains("one EntityCreate per type (A, B)"),
            "{grouped}"
        );
        assert!(grouped.contains("same mutate call"), "{grouped}");
        let multi = parse_declaration("const A, B = 1, 2").unwrap_err();
        assert!(
            multi.contains("A = ...") && multi.contains("B = ..."),
            "{multi}"
        );
        let blank = parse_declaration("func _() {}").unwrap_err();
        assert!(blank.contains("var _ Getter = (*Store)(nil)"), "{blank}");
    }

    #[test]
    fn go_unit_refuses_ambiguous_or_foreign_shapes() {
        for body in [
            "package x\nfunc f() {}",
            "import \"fmt\"\nfunc f() {}",
            "func f() {}\nfunc g() {}",
            "type (\n\tA int\n\tB int\n)",
            "const A, B = 1, 2",
            "func _() {}",
            "func f() {",
            "fmt.Println()",
            "",
        ] {
            assert!(parse_declaration(body).is_err(), "{body:?}");
        }
        for (body, kind, names) in [
            (
                "// F does it.\nfunc F() {}",
                GoDeclarationKind::Function,
                vec!["F"],
            ),
            (
                "func (s Store[T]) Get() T { var z T; return z }",
                GoDeclarationKind::Method,
                vec!["Store.Get"],
            ),
            (
                "type Store struct{}",
                GoDeclarationKind::Struct,
                vec!["Store"],
            ),
            (
                "type Getter interface{ Get() string }",
                GoDeclarationKind::Interface,
                vec!["Getter"],
            ),
            ("type Key = string", GoDeclarationKind::Type, vec!["Key"]),
            (
                "const (\n\tA Kind = iota\n\tB\n)",
                GoDeclarationKind::Const,
                vec!["A", "B"],
            ),
            (
                "var (\n\tErr = 1\n\tlimit int\n)",
                GoDeclarationKind::Var,
                vec!["Err", "limit"],
            ),
            (
                "var _ Getter = (*Store)(nil)",
                GoDeclarationKind::Var,
                vec!["_ Getter = (*Store)(nil)"],
            ),
            ("var _  =  1", GoDeclarationKind::Var, vec!["_ = 1"]),
        ] {
            let parsed = parse_declaration(body).unwrap();
            assert_eq!(
                (parsed.kind, parsed.names),
                (kind, names.iter().map(|n| n.to_string()).collect()),
                "{body}"
            );
        }
        assert!(edit_unit(Some(b"package other\n"), "store", &GoUnitEdit::default()).is_err());
        assert!(edit_unit(
            None,
            "store",
            &GoUnitEdit {
                add_imports: vec![GoImport {
                    path: "../escape".into(),
                    alias: None
                }],
                ..Default::default()
            }
        )
        .is_err());
        let commented = b"package store\n\nimport (\n\t// why\n\t\"fmt\"\n)\n";
        assert!(edit_unit(
            Some(commented),
            "store",
            &GoUnitEdit {
                add_imports: vec![import("sync")],
                ..Default::default()
            }
        )
        .is_err());
        assert!(edit_unit(
            Some(b"package store\n\nimport f \"fmt\"\n"),
            "store",
            &GoUnitEdit {
                add_imports: vec![import("fmt")],
                ..Default::default()
            }
        )
        .is_err());
    }
}
