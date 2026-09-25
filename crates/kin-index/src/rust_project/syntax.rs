// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded Rust source syntax, without Cargo or filesystem authority.
//!
//! Module keys are lexical paths within this one body. An external module has
//! a child record but no invented body. Named imports are syntactic bindings;
//! their roots, visibility and destinations still require project evidence.

use std::collections::{BTreeMap, BTreeSet};

use kin_parser::{languages::rust_lang::RustAdapter, LanguageAdapter};
use tree_sitter::Node;

const MAX_DEPTH: usize = 128;
const MAX_MODULES: usize = 512;
const MAX_BINDINGS: usize = 4096;
const MAX_RETAINED_BYTES: usize = 1024 * 1024;
const MAX_NAME_BYTES: usize = 1024;

/// Unsupported syntax is an observed unknown; exhausted analysis bounds are
/// not a completed observation and must refuse publication by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SyntaxError {
    Unproven(String),
    Limit(String),
}

impl From<String> for SyntaxError {
    fn from(reason: String) -> Self {
        Self::Unproven(reason)
    }
}

impl From<&str> for SyntaxError {
    fn from(reason: &str) -> Self {
        Self::Unproven(reason.into())
    }
}

impl std::fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unproven(reason) | Self::Limit(reason) => f.write_str(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SourceSyntax {
    pub modules: BTreeMap<Vec<String>, ModuleSyntax>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ModuleSyntax {
    pub body_start: usize,
    pub body_end: usize,
    pub declarations: Vec<Declaration>,
    pub imports: BTreeMap<String, NamedUse>,
    pub children: Vec<ModuleChild>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Declaration {
    pub name: String,
    pub start: usize,
    pub end: usize,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NamedUse {
    pub path: Vec<String>,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ModuleChild {
    pub name: String,
    pub visibility: Visibility,
    pub inline: bool,
    pub path_override: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Visibility {
    Public,
    Private,
    Crate,
    Super,
    InPath(Vec<String>),
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    modules: usize,
    bindings: usize,
    bytes: usize,
}

impl Budget {
    fn bytes(&mut self, amount: usize) -> Result<(), SyntaxError> {
        self.bytes = self
            .bytes
            .checked_add(amount)
            .filter(|n| *n <= MAX_RETAINED_BYTES)
            .ok_or_else(|| SyntaxError::Limit("Rust syntax copied-byte limit".into()))?;
        Ok(())
    }

    fn binding(&mut self) -> Result<(), SyntaxError> {
        self.bindings += 1;
        if self.bindings > MAX_BINDINGS {
            return Err(SyntaxError::Limit("Rust syntax binding limit".into()));
        }
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<String, SyntaxError> {
        self.bytes(value.len())?;
        Ok(value.to_owned())
    }

    fn path(&mut self, path: &[String]) -> Result<Vec<String>, SyntaxError> {
        self.bytes(path.iter().map(String::len).sum())?;
        Ok(path.to_vec())
    }

    fn visibility(&mut self, value: &Visibility) -> Result<Visibility, SyntaxError> {
        Ok(match value {
            Visibility::InPath(path) => Visibility::InPath(self.path(path)?),
            _ => value.clone(),
        })
    }
}

#[cfg(test)]
fn analyze(source: &[u8]) -> Result<SourceSyntax, SyntaxError> {
    analyze_with_limits(source, super::RustProjectLimits::default())
}

pub(super) fn analyze_with_limits(
    source: &[u8],
    limits: super::RustProjectLimits,
) -> Result<SourceSyntax, SyntaxError> {
    if source.len() > limits.body_bytes {
        return Err(SyntaxError::Limit("Rust syntax source-byte limit".into()));
    }
    std::str::from_utf8(source).map_err(|_| "Rust syntax is not UTF-8")?;
    let tree = RustAdapter
        .parse(source)
        .map_err(|error| error.to_string())?;
    if tree.root_node().has_error() {
        return Err("Rust syntax has parse errors".into());
    }
    let mut budget = Budget::default();
    inspect(tree.root_node(), source, 0, &mut budget, limits)?;
    let mut result = SourceSyntax {
        modules: BTreeMap::new(),
    };
    module(tree.root_node(), source, &[], &mut result, &mut budget)?;
    Ok(result)
}

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str, SyntaxError> {
    std::str::from_utf8(
        source
            .get(node.byte_range())
            .ok_or("Rust syntax node is outside source")?,
    )
    .map_err(|_| "Rust syntax node is not UTF-8".into())
}

fn field<'a>(node: Node<'a>, name: &str) -> Result<Node<'a>, SyntaxError> {
    node.child_by_field_name(name)
        .ok_or_else(|| SyntaxError::Unproven(format!("Rust syntax missing {name}")))
}

fn trivia(node: Node<'_>) -> bool {
    matches!(node.kind(), "line_comment" | "block_comment")
}

/// Inspect every node before retaining any facts. Macros and block-local
/// modules can introduce additional source membership, even when their items
/// are outside the module table below; an exhaustive observation refuses them.
fn inspect(
    node: Node<'_>,
    source: &[u8],
    depth: usize,
    budget: &mut Budget,
    limits: super::RustProjectLimits,
) -> Result<(), SyntaxError> {
    budget.nodes += 1;
    if budget.nodes > limits.syntax_nodes || depth > limits.syntax_depth {
        return Err(SyntaxError::Limit("Rust syntax AST limit".into()));
    }
    if node.is_error() || node.is_missing() {
        return Err("Rust syntax has an incomplete node".into());
    }
    match node.kind() {
        "identifier" | "type_identifier" => {
            identifier(node, source)?;
        }
        "attribute_item" | "inner_attribute_item" => {
            check_attribute(node, source)?;
        }
        "macro_definition" => return Err("Rust macro definitions are unsupported".into()),
        "macro_invocation" => {
            return Err("Rust macro membership is unsupported".into());
        }
        "mod_item" => {
            let supported_parent = node.parent().is_some_and(|parent| {
                parent.kind() == "source_file"
                    || (parent.kind() == "declaration_list"
                        && parent
                            .parent()
                            .is_some_and(|owner| owner.kind() == "mod_item"))
            });
            if !supported_parent {
                return Err("Rust block-local module membership is unsupported".into());
            }
        }
        "extern_crate_declaration" | "foreign_mod_item" => {
            return Err("Rust external declarations are unsupported".into());
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        inspect(child, source, depth + 1, budget, limits)?;
    }
    Ok(())
}

fn attribute_node(node: Node<'_>) -> Result<Node<'_>, SyntaxError> {
    let mut cursor = node.walk();
    let found = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "attribute")
        .ok_or_else(|| "Rust attribute body is missing".into());
    found
}

fn attribute_name<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str, SyntaxError> {
    let mut cursor = node.walk();
    let name = node
        .named_children(&mut cursor)
        .find(|child| {
            Some(*child) != node.child_by_field_name("arguments")
                && Some(*child) != node.child_by_field_name("value")
                && !trivia(*child)
        })
        .ok_or("Rust attribute name is missing")?;
    if name.kind() != "identifier" {
        return Err("Rust qualified attributes are unsupported".into());
    }
    text(name, source)
}

fn next_item(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        node = node.next_named_sibling()?;
        if !trivia(node) && node.kind() != "attribute_item" {
            return Some(node);
        }
    }
}

fn check_attribute(node: Node<'_>, source: &[u8]) -> Result<(), SyntaxError> {
    let attribute = attribute_node(node)?;
    let name = attribute_name(attribute, source)?;
    let value = attribute.child_by_field_name("value");
    let args = attribute.child_by_field_name("arguments");
    match name {
        "path" => {
            if node.kind() != "attribute_item"
                || args.is_some()
                || !next_item(node).is_some_and(|item| {
                    item.kind() == "mod_item" && item.child_by_field_name("body").is_none()
                })
            {
                return Err("Rust path attribute requires an external module".into());
            }
            literal_path(value.ok_or("Rust path attribute is not a literal")?, source)?;
        }
        "doc" | "must_use" => {
            if args.is_some()
                || value.is_some_and(|value| {
                    !matches!(value.kind(), "string_literal" | "raw_string_literal")
                })
                || (name == "doc" && value.is_none())
            {
                return Err("Rust documentation attribute is unsupported".into());
            }
        }
        "cold" if value.is_none() && args.is_none() => {}
        "inline" if value.is_none() => {
            if let Some(args) = args {
                if !matches!(text(args, source)?, "(always)" | "(never)") {
                    return Err("Rust inline attribute is unsupported".into());
                }
            }
        }
        _ => return Err("Rust attribute can change unsupported binding semantics".into()),
    }
    Ok(())
}

fn literal_path<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str, SyntaxError> {
    let value = text(node, source)?;
    let content = match node.kind() {
        "string_literal" => value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .filter(|value| !value.contains('\\')),
        "raw_string_literal" => {
            let quote = value.find('"').ok_or("Rust raw path is malformed")?;
            let prefix = &value[..quote];
            if !prefix.starts_with('r') || !prefix[1..].bytes().all(|b| b == b'#') {
                return Err("Rust raw path prefix is unsupported".into());
            }
            let end = value.len().checked_sub(prefix.len());
            end.and_then(|end| value.get(quote + 1..end))
        }
        _ => None,
    }
    .ok_or("Rust path requires an unescaped literal string")?;
    if content.len() > MAX_NAME_BYTES {
        return Err(SyntaxError::Limit(
            "Rust path literal is outside bounds".into(),
        ));
    }
    if content.is_empty() || content.contains(['\0', '\r', '\n']) {
        return Err("Rust path literal is outside bounds".into());
    }
    Ok(content)
}

fn identifier<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str, SyntaxError> {
    if !matches!(node.kind(), "identifier" | "type_identifier") {
        return Err("Rust named binding is unsupported".into());
    }
    let name = text(node, source)?;
    if name.len() > MAX_NAME_BYTES {
        return Err(SyntaxError::Limit("Rust name is outside bounds".into()));
    }
    if name == "_" || name.is_empty() {
        return Err("Rust name is outside bounds".into());
    }
    // Source spelling is retained to join with existing parser entities, but
    // Rust removes raw prefixes and applies Unicode NFC for actual identity.
    // Without a separate normalized-name field we cannot safely use those
    // spellings for duplicate checks or external module filenames.
    if name.starts_with("r#") || !name.is_ascii() {
        return Err("Rust raw or Unicode identifier identity is unsupported".into());
    }
    Ok(name)
}

fn path(node: Node<'_>, source: &[u8], budget: &mut Budget) -> Result<Vec<String>, SyntaxError> {
    match node.kind() {
        "identifier" | "type_identifier" => Ok(vec![budget.string(identifier(node, source)?)?]),
        "crate" | "self" | "super" => Ok(vec![budget.string(text(node, source)?)?]),
        "scoped_identifier" => {
            let head = node
                .child_by_field_name("path")
                .ok_or("Rust absolute paths require a separate root discriminator")?;
            let mut result = path(head, source, budget)?;
            result.extend(path(field(node, "name")?, source, budget)?);
            if result.len() > MAX_DEPTH {
                return Err(SyntaxError::Limit("Rust path depth limit".into()));
            }
            Ok(result)
        }
        _ => Err("Rust use path is unsupported".into()),
    }
}

fn visibility(
    node: Node<'_>,
    source: &[u8],
    budget: &mut Budget,
) -> Result<Visibility, SyntaxError> {
    let mut cursor = node.walk();
    let Some(visibility) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "visibility_modifier")
    else {
        return Ok(Visibility::Private);
    };
    let mut cursor = visibility.walk();
    let mut parts = visibility
        .named_children(&mut cursor)
        .filter(|child| !trivia(*child));
    let Some(scope) = parts.next() else {
        return if text(visibility, source)?.trim() == "pub" {
            Ok(Visibility::Public)
        } else {
            Err("Rust visibility is unsupported".into())
        };
    };
    if parts.next().is_some() {
        return Err("Rust visibility has multiple paths".into());
    }
    let parsed = path(scope, source, budget)?;
    // Presence of the keyword is structural, so comments or whitespace cannot
    // turn `pub(in path)` into the shorter restricted-visibility form.
    let mut cursor = visibility.walk();
    let in_path = visibility
        .children(&mut cursor)
        .any(|child| child.kind() == "in");
    if in_path {
        if !matches!(
            parsed.first().map(String::as_str),
            Some("crate" | "self" | "super")
        ) {
            return Err("Rust visibility path has no explicit lexical root".into());
        }
        return Ok(Visibility::InPath(parsed));
    }
    match parsed.as_slice() {
        [name] if name == "crate" => Ok(Visibility::Crate),
        [name] if name == "super" => Ok(Visibility::Super),
        [name] if name == "self" => Ok(Visibility::Private),
        _ => Err("Rust visibility is unsupported".into()),
    }
}

fn bind_name(
    names: &mut BTreeSet<String>,
    name: &str,
    budget: &mut Budget,
) -> Result<(), SyntaxError> {
    if names.contains(name) {
        return Err("Rust module has duplicate local bindings".into());
    }
    budget.binding()?;
    names.insert(budget.string(name)?);
    Ok(())
}

fn add_use(
    node: Node<'_>,
    source: &[u8],
    prefix: &[String],
    access: &Visibility,
    facts: &mut ModuleSyntax,
    names: &mut BTreeSet<String>,
    budget: &mut Budget,
) -> Result<(), SyntaxError> {
    match node.kind() {
        "use_list" => {
            let mut cursor = node.walk();
            for child in node
                .named_children(&mut cursor)
                .filter(|child| !trivia(*child))
            {
                add_use(child, source, prefix, access, facts, names, budget)?;
            }
            return Ok(());
        }
        "scoped_use_list" => {
            let mut joined = budget.path(prefix)?;
            joined.extend(path(
                node.child_by_field_name("path")
                    .ok_or("Rust absolute grouped use is unsupported")?,
                source,
                budget,
            )?);
            return add_use(
                field(node, "list")?,
                source,
                &joined,
                access,
                facts,
                names,
                budget,
            );
        }
        // Glob syntax never creates a named binding. Explicit named imports
        // and declarations keep Rust's stronger precedence over a glob.
        "use_wildcard" => return Ok(()),
        _ => {}
    }
    let (target, alias) = if node.kind() == "use_as_clause" {
        (
            field(node, "path")?,
            Some(identifier(field(node, "alias")?, source)?),
        )
    } else {
        (node, None)
    };
    let mut resolved = budget.path(prefix)?;
    let suffix = path(target, source, budget)?;
    if suffix.as_slice() != ["self"] || prefix.is_empty() {
        resolved.extend(suffix);
    }
    if resolved.len() > MAX_DEPTH {
        return Err(SyntaxError::Limit("Rust use depth limit".into()));
    }
    let local = alias
        .or_else(|| resolved.last().map(String::as_str))
        .ok_or("Rust use has no local binding")?;
    if matches!(local, "crate" | "self" | "super") {
        return Err("Rust use has no ordinary local name".into());
    }
    bind_name(names, local, budget)?;
    let key = budget.string(local)?;
    facts.imports.insert(
        key,
        NamedUse {
            path: resolved,
            visibility: budget.visibility(access)?,
        },
    );
    Ok(())
}

/// Match the existing extractor's item span: leading outer documentation and
/// attributes belong to the item; ordinary comments only bridge that run.
fn item_start(node: Node<'_>, source: &[u8]) -> Result<usize, SyntaxError> {
    let mut start = node.start_byte();
    let mut previous = node.prev_sibling();
    while let Some(node) = previous {
        let owned = match node.kind() {
            "attribute_item" => true,
            "line_comment" => {
                let value = text(node, source)?;
                if value.starts_with("//!") {
                    break;
                }
                value.starts_with("///") && !value.starts_with("////")
            }
            "block_comment" => {
                let value = text(node, source)?;
                if value.starts_with("/*!") {
                    break;
                }
                value.starts_with("/**") && !value.starts_with("/***") && value != "/**/"
            }
            _ => break,
        };
        if owned {
            start = node.start_byte();
        }
        previous = node.prev_sibling();
    }
    Ok(start)
}

fn declaration(
    node: Node<'_>,
    name: &str,
    source: &[u8],
    access: &Visibility,
    facts: &mut ModuleSyntax,
    budget: &mut Budget,
) -> Result<(), SyntaxError> {
    facts.declarations.push(Declaration {
        name: budget.string(name)?,
        start: item_start(node, source)?,
        end: node.end_byte(),
        visibility: budget.visibility(access)?,
    });
    Ok(())
}

fn module(
    body: Node<'_>,
    source: &[u8],
    lexical_path: &[String],
    result: &mut SourceSyntax,
    budget: &mut Budget,
) -> Result<(), SyntaxError> {
    budget.modules += 1;
    if budget.modules > MAX_MODULES || lexical_path.len() > MAX_DEPTH {
        return Err(SyntaxError::Limit(
            "Rust module count or depth limit".into(),
        ));
    }
    let mut facts = ModuleSyntax {
        body_start: body.start_byte(),
        body_end: body.end_byte(),
        declarations: Vec::new(),
        imports: BTreeMap::new(),
        children: Vec::new(),
    };
    let mut names = BTreeSet::new();
    let mut override_path: Option<&str> = None;
    let mut cursor = body.walk();
    for item in body.named_children(&mut cursor) {
        if trivia(item) {
            continue;
        }
        if matches!(item.kind(), "attribute_item" | "inner_attribute_item") {
            let attribute = attribute_node(item)?;
            if attribute_name(attribute, source)? == "path" {
                if override_path
                    .replace(literal_path(field(attribute, "value")?, source)?)
                    .is_some()
                {
                    return Err("Rust module has duplicate path attributes".into());
                }
            }
            continue;
        }
        if override_path.is_some() && item.kind() != "mod_item" {
            return Err("Rust path attribute was not attached to a module".into());
        }
        if item.kind() == "use_declaration" {
            let access = visibility(item, source, budget)?;
            add_use(
                field(item, "argument")?,
                source,
                &[],
                &access,
                &mut facts,
                &mut names,
                budget,
            )?;
            continue;
        }
        if item.kind() == "impl_item" {
            // Methods are not module-local bindings and are never named-import
            // targets in this model. The global pass still inspects attributes
            // and refuses item-generating macros in their declaration lists.
            continue;
        }
        if !matches!(
            item.kind(),
            "mod_item"
                | "function_item"
                | "struct_item"
                | "enum_item"
                | "trait_item"
                | "type_item"
                | "const_item"
                | "static_item"
        ) {
            return Err("Rust module item is unsupported".into());
        }
        let name = identifier(field(item, "name")?, source)?;
        bind_name(&mut names, name, budget)?;
        let access = visibility(item, source, budget)?;
        declaration(item, name, source, &access, &mut facts, budget)?;
        if item.kind() == "enum_item" {
            let variants = field(item, "body")?;
            let mut cursor = variants.walk();
            for variant in variants.named_children(&mut cursor) {
                if variant.kind() != "enum_variant" {
                    continue;
                }
                let member = identifier(field(variant, "name")?, source)?;
                budget.bytes(name.len() + 2 + member.len())?;
                let qualified = format!("{name}::{member}");
                bind_name(&mut names, &qualified, budget)?;
                declaration(variant, &qualified, source, &access, &mut facts, budget)?;
            }
        }
        if item.kind() == "mod_item" {
            let child_body = item.child_by_field_name("body");
            if child_body.is_some() && override_path.is_some() {
                return Err("Rust inline module path attributes are unsupported".into());
            }
            facts.children.push(ModuleChild {
                name: budget.string(name)?,
                visibility: budget.visibility(&access)?,
                inline: child_body.is_some(),
                path_override: override_path
                    .take()
                    .map(|path| budget.string(path))
                    .transpose()?,
            });
            if let Some(child_body) = child_body {
                let mut child_path = budget.path(lexical_path)?;
                child_path.push(budget.string(name)?);
                module(child_body, source, &child_path, result, budget)?;
            }
        }
    }
    if override_path.is_some() {
        return Err("Rust path attribute has no module".into());
    }
    let key = budget.path(lexical_path)?;
    if result.modules.insert(key, facts).is_some() {
        return Err("Rust module has duplicate lexical contexts".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(syntax: &SourceSyntax) -> &ModuleSyntax {
        syntax.modules.get(&Vec::new()).unwrap()
    }

    #[test]
    fn module_contexts_retain_inline_bodies_and_external_path_literals() {
        let source = br##"#[path = r#"../shared/leaf.rs"#] pub(crate) mod leaf;
pub mod nested { pub mod external; pub fn work() {} }
"##;
        let syntax = analyze(source).unwrap();
        assert_eq!(syntax.modules.len(), 2);
        let outer = root(&syntax);
        assert_eq!(
            outer.children[0].path_override.as_deref(),
            Some("../shared/leaf.rs")
        );
        assert_eq!(outer.children[0].visibility, Visibility::Crate);
        assert!(!outer.children[0].inline);
        assert!(!syntax.modules.contains_key(&vec!["leaf".into()]));
        let nested = syntax.modules.get(&vec!["nested".into()]).unwrap();
        assert_eq!(&source[nested.body_start..nested.body_start + 1], b"{");
        assert_eq!(nested.children[0].name, "external");
        assert!(!nested.children[0].inline);
        assert_eq!(nested.declarations[1].name, "work");
    }

    #[test]
    fn named_group_alias_and_self_reexports_do_not_enumerate_globs() {
        let syntax = analyze(b"pub use crate::api::{self as surface, Work, nested::{Ready as Make, Other}}; use crate::other::*; use super::work as invoke;").unwrap();
        let imports = &root(&syntax).imports;
        assert_eq!(imports.len(), 5);
        assert_eq!(imports["surface"].path, ["crate", "api"]);
        assert_eq!(imports["Make"].path, ["crate", "api", "nested", "Ready"]);
        assert_eq!(imports["Make"].visibility, Visibility::Public);
        assert_eq!(imports["invoke"].path, ["super", "work"]);
        assert!(!imports.contains_key("*"));
    }

    #[test]
    fn restricted_visibility_is_lexical_and_not_flattened_to_public() {
        let syntax = analyze(b"pub(self) fn a() {} pub(super) fn b() {} pub(crate) fn c() {} pub(in crate::outer) fn d() {} fn e() {}").unwrap();
        let vis: Vec<_> = root(&syntax)
            .declarations
            .iter()
            .map(|d| d.visibility.clone())
            .collect();
        assert_eq!(
            vis,
            vec![
                Visibility::Private,
                Visibility::Super,
                Visibility::Crate,
                Visibility::InPath(vec!["crate".into(), "outer".into()]),
                Visibility::Private
            ]
        );
    }

    #[test]
    fn declaration_spans_and_enum_names_match_the_existing_extractor() {
        let source = b"/// module\npub mod inner {\n/// enum\n// bridge\n#[doc = \"state\"]\npub enum Status {\n/// ready\nReady(u32), Done }\n/// f\n#[inline]\npub fn work() {}\n}\n";
        let syntax = analyze(source).unwrap();
        let tree = RustAdapter.parse(source).unwrap();
        let parsed = RustAdapter
            .extract(&tree, source, &kin_model::FilePathId::new("source.rs"))
            .unwrap();
        for declaration in syntax.modules.values().flat_map(|m| &m.declarations) {
            let matching: Vec<_> = parsed
                .entities
                .iter()
                .filter(|entity| {
                    entity.name == declaration.name
                        && entity.span.start_byte == declaration.start
                        && entity.span.end_byte == declaration.end
                })
                .collect();
            assert_eq!(matching.len(), 1, "{declaration:?}");
        }
        let inner = &syntax.modules[&vec!["inner".into()]];
        assert!(inner
            .declarations
            .iter()
            .any(|d| d.name == "Status::Ready" && d.visibility == Visibility::Public));
    }

    #[test]
    fn ambiguous_and_expansion_dependent_names_refuse_the_whole_observation() {
        for source in [
            "use crate::a::work; use crate::b::work;",
            "use crate::a::work; fn work() {}",
            "mod a {} mod a;",
            "#[cfg(feature = \"x\")] mod a;",
            "#[cfg_attr(any(), path = \"other.rs\")] mod a;",
            "#[derive(Custom)] pub struct S;",
            "make_items!();",
            "mod a { include!(\"generated.rs\"); }",
            "macro_rules! m { () => {} }",
            "fn f() { format!(\"{}\", 1); }",
            "fn f() { mod nested; }",
            "fn f() { mod nested { pub fn work() {} } }",
            "const VALUE: () = { #[path = \"same.rs\"] mod nested; };",
            "#[path = \"x.rs\"] #[path = \"y.rs\"] mod a;",
            "#[path = \"x.rs\"] mod a {}",
            "#[path = \"x\\x2ers\"] mod a;",
            "use ::external::work;",
            "pub(in elsewhere) fn f() {}",
            "fn broken( {",
        ] {
            assert!(analyze(source.as_bytes()).is_err(), "{source}");
        }
    }

    #[test]
    fn implementation_methods_and_body_local_names_are_not_module_bindings() {
        let syntax = analyze(b"pub struct Owner; impl Owner { pub fn method() {} } pub fn work() { fn inner() {} let value = 1; }").unwrap();
        let names: Vec<_> = root(&syntax)
            .declarations
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, ["Owner", "work"]);
        assert!(root(&syntax).imports.is_empty());
    }

    #[test]
    fn raw_and_unicode_spellings_cannot_authorize_module_paths_or_distinct_bindings() {
        for source in [
            "pub mod r#type;",
            "pub mod r#name; pub mod name;",
            "pub fn r#work() {} pub fn work() {}",
            "use crate::owner::r#work;",
            "pub mod café;",
            "pub fn café() {} pub fn cafe\u{301}() {}",
            "fn work() { let r#alias = 1; }",
        ] {
            assert!(analyze(source.as_bytes()).is_err(), "{source}");
        }
        // Unicode source bytes in documentation/literals are not identifiers.
        assert!(analyze("/// café\npub fn work() { let text = \"東京\"; }".as_bytes()).is_ok());
    }

    #[test]
    fn source_and_binding_caps_refuse_without_a_partial_result() {
        assert!(matches!(
            analyze(&vec![
                b' ';
                super::super::RustProjectLimits::default().body_bytes
                    + 1
            ]),
            Err(SyntaxError::Limit(_))
        ));
        let source: String = (0..=MAX_BINDINGS)
            .map(|i| format!("fn f{i}() {{}}\n"))
            .collect();
        assert!(matches!(
            analyze(source.as_bytes()),
            Err(SyntaxError::Limit(_))
        ));
        assert_eq!(analyze(b"").unwrap().modules.len(), 1);
    }

    #[test]
    fn exhausted_processing_bounds_are_distinct_from_observed_unsupported_syntax() {
        let path = format!(
            "#[path = \"{}\"] mod child;",
            "a".repeat(MAX_NAME_BYTES + 1)
        );
        let name = format!("fn {}() {{}}", "a".repeat(MAX_NAME_BYTES + 1));
        for source in [path, name] {
            assert!(matches!(
                analyze(source.as_bytes()),
                Err(SyntaxError::Limit(_))
            ));
        }
        let mut budget = Budget::default();
        assert!(matches!(
            budget.bytes(MAX_RETAINED_BYTES + 1),
            Err(SyntaxError::Limit(_))
        ));
        let mut budget = Budget {
            bindings: MAX_BINDINGS,
            ..Default::default()
        };
        assert!(matches!(budget.binding(), Err(SyntaxError::Limit(_))));
        for source in [
            "#[cfg(any())] mod child;",
            "fn f() { include!(\"x\"); }",
            "fn broken(",
            "pub mod r#type;",
        ] {
            assert!(
                matches!(analyze(source.as_bytes()), Err(SyntaxError::Unproven(_))),
                "{source}"
            );
        }
    }
}
