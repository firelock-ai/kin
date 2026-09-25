// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded source evidence for new exact-import resolution paths.
//!
//! These records are parser controls, never graph relations. They establish
//! syntax and lexical binding in a deliberately small subset, not Python
//! runtime immutability or Rust macro/configuration evaluation. A consumer must
//! additionally bind the digest to admitted source and match the exact site.

use std::collections::{BTreeMap, BTreeSet};

use kin_model::{FilePathId, RelationKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tree_sitter::{Node, Tree};

use crate::extract::{ExtractedRelation, FileImport};

pub const IMPORT_WITNESS_MARKER_V1: &str = "kin-internal://exact-import-witness/v1";

const MAX_SOURCE_BYTES: usize = 256 * 1024;
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_NODES: usize = 32_768;
const MAX_DEPTH: usize = 128;
const MAX_BINDINGS: usize = 512;
const MAX_SITES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedImport {
    pub module: String,
    pub original: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSiteKind {
    Calls,
    References,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallableImportSite {
    pub start_byte: usize,
    pub end_byte: usize,
    pub caller: String,
    pub local: String,
    pub module: String,
    pub original: String,
    pub kind: ImportSiteKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactImportWitness {
    pub file: String,
    pub source_digest: String,
    pub source_len: usize,
    pub python_reexports: BTreeMap<String, NamedImport>,
    pub callable_import_sites: Vec<CallableImportSite>,
}

impl ExactImportWitness {
    /// Validate a decoded or checkpoint-restored record without trusting its
    /// source binding. The linker must separately check admitted source bytes.
    pub fn validate(&self) -> Result<(), String> {
        validate(self)
    }
}

/// Claims are recognized even when their payload or relation shape is invalid,
/// so consumers can discard malformed controls rather than materialize them.
pub fn claims_import_witness(relation: &ExtractedRelation) -> bool {
    relation.src_name == IMPORT_WITNESS_MARKER_V1
        || relation.dst_name == IMPORT_WITNESS_MARKER_V1
        || relation.import_source.as_deref() == Some(IMPORT_WITNESS_MARKER_V1)
}

pub fn decode_import_witness(relation: &ExtractedRelation) -> Result<ExactImportWitness, String> {
    if relation.src_name != IMPORT_WITNESS_MARKER_V1
        || relation.kind != RelationKind::DependsOn
        || relation.site.is_some()
        || relation.receiver.is_some()
        || relation.import_source.is_some()
        || relation.call_shape.is_some()
        || relation.dst_name.len() > MAX_PAYLOAD_BYTES
    {
        return Err("invalid exact-import control shape".into());
    }
    let witness: ExactImportWitness = serde_json::from_str(&relation.dst_name)
        .map_err(|_| "invalid exact-import control schema".to_string())?;
    validate(&witness)?;
    // Canonical serialization also rejects duplicate map keys, which ordinary
    // BTreeMap deserialization would silently overwrite.
    if serde_json::to_string(&witness).ok().as_deref() != Some(relation.dst_name.as_str()) {
        return Err("noncanonical exact-import control".into());
    }
    Ok(witness)
}

fn validate(witness: &ExactImportWitness) -> Result<(), String> {
    let fail = || Err("invalid exact-import control evidence".into());
    if witness.file.is_empty()
        || witness.file.len() > 4096
        || witness.file.contains('\0')
        || witness.source_len > MAX_SOURCE_BYTES
        || witness.source_digest.len() != 64
        || !witness
            .source_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || witness.python_reexports.len() > MAX_BINDINGS
        || witness.callable_import_sites.len() > MAX_SITES
    {
        return fail();
    }
    for (local, import) in &witness.python_reexports {
        if !identifier(local) || !module_name(&import.module) || !identifier(&import.original) {
            return fail();
        }
    }
    for site in &witness.callable_import_sites {
        if site.start_byte >= site.end_byte
            || site.end_byte > witness.source_len
            || !identifier(&site.caller)
            || !identifier(&site.local)
            || !module_name(&site.module)
            || !qualified_name(&site.original)
        {
            return fail();
        }
    }
    if witness
        .callable_import_sites
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return fail();
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 256
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn qualified_name(value: &str) -> bool {
    value.len() <= 2048 && value.split("::").all(identifier)
}

fn module_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 2048 {
        return false;
    }
    if value.contains(':') {
        return qualified_name(value);
    }
    let remainder = value.trim_start_matches('.');
    remainder.is_empty() || remainder.split('.').all(identifier)
}

fn bounded_nodes<'tree>(tree: &'tree Tree, source: &[u8]) -> Option<Vec<Node<'tree>>> {
    if source.len() > MAX_SOURCE_BYTES || tree.root_node().has_error() {
        return None;
    }
    let mut stack = vec![(tree.root_node(), 0)];
    let mut nodes = Vec::new();
    while let Some((node, depth)) = stack.pop() {
        if nodes.len() >= MAX_NODES || depth > MAX_DEPTH || node.is_missing() {
            return None;
        }
        nodes.push(node);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if stack.len() + nodes.len() >= MAX_NODES {
                return None;
            }
            stack.push((child, depth + 1));
        }
    }
    Some(nodes)
}

fn text<'source>(node: Node<'_>, source: &'source [u8]) -> Option<&'source str> {
    node.utf8_text(source).ok()
}

fn node_name<'source>(node: Node<'_>, source: &'source [u8]) -> Option<&'source str> {
    text(node.child_by_field_name("name")?, source).filter(|name| identifier(name))
}

fn insert_binding(names: &mut BTreeSet<String>, name: &str) -> Option<()> {
    if !identifier(name) || names.len() >= MAX_BINDINGS || !names.insert(name.to_string()) {
        None
    } else {
        Some(())
    }
}

fn exact_named_imports(imports: &[FileImport]) -> Option<BTreeMap<String, NamedImport>> {
    if imports.len() > MAX_BINDINGS {
        return None;
    }
    let mut result = BTreeMap::new();
    for import in imports {
        if !module_name(&import.module_path) || import.specifiers.len() > MAX_BINDINGS {
            return None;
        }
        for specifier in &import.specifiers {
            let original = specifier
                .original_name
                .as_deref()
                .unwrap_or(&specifier.local_name);
            if !identifier(&specifier.local_name)
                || !qualified_name(original)
                || specifier.is_default
                || result.len() >= MAX_BINDINGS
                || result
                    .insert(
                        specifier.local_name.clone(),
                        NamedImport {
                            module: import.module_path.clone(),
                            original: original.to_string(),
                        },
                    )
                    .is_some()
            {
                return None;
            }
        }
    }
    Some(result)
}

fn empty_witness(file: &FilePathId, source: &[u8]) -> ExactImportWitness {
    ExactImportWitness {
        file: file.0.clone(),
        source_digest: Sha256::digest(source)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        source_len: source.len(),
        python_reexports: BTreeMap::new(),
        callable_import_sites: Vec::new(),
    }
}

fn append(witness: ExactImportWitness, relations: &mut Vec<ExtractedRelation>) {
    if validate(&witness).is_err() {
        return;
    }
    let Ok(payload) = serde_json::to_string(&witness) else {
        return;
    };
    if payload.len() > MAX_PAYLOAD_BYTES {
        return;
    }
    relations.push(ExtractedRelation {
        kind: RelationKind::DependsOn,
        src_name: IMPORT_WITNESS_MARKER_V1.into(),
        dst_name: payload,
        import_source: None,
        receiver: None,
        call_shape: None,
        site: None,
    });
}

/// Append source evidence without changing ordinary extraction semantics.
pub fn append_python_import_witness(
    tree: &Tree,
    source: &[u8],
    file: &FilePathId,
    imports: &[FileImport],
    relations: &mut Vec<ExtractedRelation>,
) {
    if file.0.is_empty()
        || file.0.len() > 4096
        || imports.len() > MAX_BINDINGS
        || relations.len() > MAX_NODES
    {
        return;
    }
    let Some(nodes) = bounded_nodes(tree, source) else {
        return;
    };
    let Some((named, functions, import_only)) = python_module(tree, source, imports, &nodes) else {
        return;
    };
    let mut witness = empty_witness(file, source);
    if import_only {
        witness.python_reexports = named.clone();
    }
    let Some(sites) = callable_sites(&nodes, source, &functions, &named, relations, true) else {
        return;
    };
    witness.callable_import_sites = sites;
    append(witness, relations);
}

type ModuleBindings<'tree> = (BTreeMap<String, NamedImport>, Vec<Node<'tree>>, bool);

fn python_module<'tree>(
    tree: &'tree Tree,
    source: &[u8],
    imports: &[FileImport],
    nodes: &[Node<'tree>],
) -> Option<ModuleBindings<'tree>> {
    // These forms can mutate an outer binding or inspect/write the namespace
    // without an ordinary assignment target. Do not try to interpret them.
    if nodes.iter().any(|node| {
        matches!(
            node.kind(),
            "global_statement" | "nonlocal_statement" | "named_expression"
        ) || (node.kind() == "identifier"
            && text(*node, source).is_some_and(|name| {
                matches!(
                    name,
                    "globals"
                        | "locals"
                        | "vars"
                        | "eval"
                        | "exec"
                        | "setattr"
                        | "delattr"
                        | "__import__"
                        | "__builtins__"
                        | "builtins"
                )
            }))
    }) {
        return None;
    }
    let root = tree.root_node();
    let mut names = BTreeSet::new();
    let mut named = BTreeMap::new();
    let mut functions = Vec::new();
    let mut import_only = true;
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        match node.kind() {
            "comment" | "pass_statement" => {}
            "expression_statement" if python_docstring(node, source) => {}
            "import_statement" | "import_from_statement" => {
                let matching: Vec<_> = imports
                    .iter()
                    .filter(|import| {
                        import.site.start_byte == node.start_byte()
                            && import.site.end_byte == node.end_byte()
                    })
                    .collect();
                if matching.is_empty() {
                    return None;
                }
                for import in matching {
                    if import.specifiers.is_empty() || !module_name(&import.module_path) {
                        return None;
                    }
                    for specifier in &import.specifiers {
                        let local = if node.kind() == "import_statement"
                            && specifier.original_name.is_none()
                        {
                            specifier.local_name.split('.').next()?
                        } else {
                            &specifier.local_name
                        };
                        insert_binding(&mut names, local)?;
                        if node.kind() == "import_from_statement" {
                            let original = specifier
                                .original_name
                                .as_deref()
                                .unwrap_or(&specifier.local_name);
                            if !identifier(original) || specifier.is_default {
                                return None;
                            }
                            named.insert(
                                local.to_string(),
                                NamedImport {
                                    module: import.module_path.clone(),
                                    original: original.to_string(),
                                },
                            );
                        }
                    }
                }
            }
            "function_definition" => {
                insert_binding(&mut names, node_name(node, source)?)?;
                functions.push(node);
                import_only = false;
            }
            "class_definition" if simple_python_class(node, source) => {
                insert_binding(&mut names, node_name(node, source)?)?;
                import_only = false;
            }
            _ => return None,
        }
    }
    Some((named, functions, import_only))
}

fn python_docstring(node: Node<'_>, source: &[u8]) -> bool {
    node.named_child_count() == 1
        && node.named_child(0).is_some_and(|child| {
            child.kind() == "string"
                && text(child, source)
                    .is_some_and(|raw| raw.starts_with('\'') || raw.starts_with('"'))
        })
}

fn simple_python_class(node: Node<'_>, source: &[u8]) -> bool {
    if node.child_by_field_name("superclasses").is_some() {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = body.walk();
    let supported = body.named_children(&mut cursor).all(|child| {
        matches!(
            child.kind(),
            "function_definition" | "pass_statement" | "comment"
        ) || (child.kind() == "expression_statement" && python_docstring(child, source))
    });
    supported
}

/// Rust named uses take precedence over unrelated globs. Only explicit names
/// get sites; a glob never becomes traversal or target-identity evidence.
pub fn append_rust_import_witness(
    tree: &Tree,
    source: &[u8],
    file: &FilePathId,
    imports: &[FileImport],
    relations: &mut Vec<ExtractedRelation>,
) {
    if file.0.is_empty()
        || file.0.len() > 4096
        || imports.len() > MAX_BINDINGS
        || relations.len() > MAX_NODES
    {
        return;
    }
    let Some(nodes) = bounded_nodes(tree, source) else {
        return;
    };
    if nodes
        .iter()
        .any(|node| matches!(node.kind(), "attribute_item" | "inner_attribute_item"))
    {
        return;
    }
    // The parser collects uses from nested scopes too. Only uses declared at
    // this lexical root can pin calls in the root functions below. An inline
    // module's imports neither shadow nor supply a root binding.
    let root = tree.root_node();
    let mut cursor = root.walk();
    let root_uses: BTreeSet<_> = root
        .named_children(&mut cursor)
        .filter(|node| node.kind() == "use_declaration")
        .map(|node| (node.start_byte(), node.end_byte()))
        .collect();
    let root_imports: Vec<_> = imports
        .iter()
        .filter(|import| {
            root_uses.iter().any(|(start, end)| {
                *start <= import.site.start_byte && import.site.end_byte <= *end
            })
        })
        .cloned()
        .collect();
    let Some(named) = exact_named_imports(&root_imports) else {
        return;
    };
    let mut names: BTreeSet<String> = named.keys().cloned().collect();
    let mut functions = Vec::new();
    let root = tree.root_node();
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        match node.kind() {
            "line_comment" | "block_comment" | "use_declaration" | "empty_statement" => {}
            "mod_item" => {
                // Either module form declares only this name in the root.
                // This witnesses root import occurrences, not child membership
                // or root identity; the admitted project resolver proves those.
                let Some(name) = node_name(node, source) else {
                    return;
                };
                if insert_binding(&mut names, name).is_none() {
                    return;
                }
            }
            "function_item" => {
                let Some(name) = node_name(node, source) else {
                    return;
                };
                if insert_binding(&mut names, name).is_none() {
                    return;
                }
                functions.push(node);
            }
            "struct_item" | "enum_item" | "type_item" | "const_item" | "static_item"
            | "trait_item" => {
                let Some(name) = node_name(node, source) else {
                    return;
                };
                if insert_binding(&mut names, name).is_none() {
                    return;
                }
            }
            "impl_item" => {}
            _ => return,
        }
    }
    let mut witness = empty_witness(file, source);
    let Some(sites) = callable_sites(&nodes, source, &functions, &named, relations, false) else {
        return;
    };
    witness.callable_import_sites = sites;
    append(witness, relations);
}

fn callable_sites(
    nodes: &[Node<'_>],
    source: &[u8],
    functions: &[Node<'_>],
    named: &BTreeMap<String, NamedImport>,
    relations: &[ExtractedRelation],
    python: bool,
) -> Option<Vec<CallableImportSite>> {
    let mut sites = BTreeSet::new();
    // Build small exact-site indexes once. Do not multiply a full AST walk by
    // every relation; producer bounds apply even on a source with many calls.
    let by_range: BTreeMap<_, _> = nodes
        .iter()
        .filter(|node| matches!(node.kind(), "identifier" | "call" | "call_expression"))
        .map(|node| ((node.start_byte(), node.end_byte(), node.kind()), *node))
        .collect();
    let mut safe = BTreeMap::new();
    for relation in relations {
        let kind = match relation.kind {
            RelationKind::Calls => ImportSiteKind::Calls,
            RelationKind::References if python => ImportSiteKind::References,
            _ => continue,
        };
        let Some(import) = named.get(&relation.dst_name) else {
            continue;
        };
        if relation.receiver.is_some()
            || relation.import_source.as_deref() != Some(import.module.as_str())
        {
            continue;
        }
        let Some(site) = &relation.site else {
            continue;
        };
        let node_kind = match kind {
            ImportSiteKind::References => "identifier",
            ImportSiteKind::Calls if python => "call",
            _ => "call_expression",
        };
        let Some(node) = by_range
            .get(&(site.start_byte, site.end_byte, node_kind))
            .copied()
        else {
            continue;
        };
        if kind == ImportSiteKind::Calls
            && !node.child_by_field_name("function").is_some_and(|callee| {
                callee.kind() == "identifier"
                    && text(callee, source) == Some(relation.dst_name.as_str())
            })
        {
            continue;
        }
        let Some(function) = functions
            .iter()
            .find(|function| {
                function.child_by_field_name("body").is_some_and(|body| {
                    body.start_byte() <= node.start_byte() && node.end_byte() <= body.end_byte()
                }) && node_name(**function, source) == Some(relation.src_name.as_str())
            })
            .copied()
        else {
            continue;
        };
        if !same_callable_scope(node, function, python) {
            continue;
        }
        let key = (function.start_byte(), relation.dst_name.as_str());
        let eligible = *safe.entry(key).or_insert_with(|| {
            callable_binding_is_unshadowed(function, nodes, source, &relation.dst_name, python)
        });
        if !eligible {
            continue;
        }
        if sites.len() >= MAX_SITES {
            return None;
        }
        sites.insert(CallableImportSite {
            start_byte: site.start_byte,
            end_byte: site.end_byte,
            caller: relation.src_name.clone(),
            local: relation.dst_name.clone(),
            module: import.module.clone(),
            original: import.original.clone(),
            kind,
        });
    }
    Some(sites.into_iter().collect())
}

fn same_callable_scope(mut node: Node<'_>, function: Node<'_>, python: bool) -> bool {
    while let Some(parent) = node.parent() {
        if parent.id() == function.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "function_definition"
                | "class_definition"
                | "lambda"
                | "function_item"
                | "closure_expression"
                | "mod_item"
                | "macro_invocation"
                | "token_tree"
        ) || (python
            && matches!(
                parent.kind(),
                "list_comprehension"
                    | "set_comprehension"
                    | "dictionary_comprehension"
                    | "generator_expression"
            ))
        {
            return false;
        }
        node = parent;
    }
    false
}

fn callable_binding_is_unshadowed(
    function: Node<'_>,
    nodes: &[Node<'_>],
    source: &[u8],
    local: &str,
    python: bool,
) -> bool {
    for node in nodes.iter().filter(|node| {
        function.start_byte() <= node.start_byte() && node.end_byte() <= function.end_byte()
    }) {
        if !python
            && matches!(
                node.kind(),
                "macro_invocation" | "attribute_item" | "inner_attribute_item"
            )
        {
            return false;
        }
        // Rust shorthand field patterns use `shorthand_field_identifier`, not
        // `identifier`. Treat every matching named leaf as unsupported unless
        // its immediate parent proves one of the admitted read positions.
        if node.named_child_count() != 0 || text(*node, source) != Some(local) {
            continue;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        // Positive syntax, rather than an incomplete list of binding patterns:
        // a name in a parameter, let/assignment, pattern, import, deletion,
        // nested declaration or unknown form cannot pass as a read.
        let call_read = matches!(parent.kind(), "call" | "call_expression")
            && parent
                .child_by_field_name("function")
                .is_some_and(|callee| callee.id() == node.id());
        let returned_read = python && parent.kind() == "return_statement";
        let argument_read = matches!(parent.kind(), "argument_list" | "arguments");
        if !call_read && !returned_read && !argument_read {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LanguageAdapter, PythonAdapter, RustAdapter};

    fn python(source: &str) -> Option<ExactImportWitness> {
        witness(&PythonAdapter, "pkg/__init__.py", source)
    }
    fn rust(source: &str) -> Option<ExactImportWitness> {
        witness(&RustAdapter, "src/lib.rs", source)
    }
    fn witness(
        adapter: &dyn LanguageAdapter,
        file: &str,
        source: &str,
    ) -> Option<ExactImportWitness> {
        let tree = adapter.parse(source.as_bytes()).unwrap();
        let output = adapter
            .extract(&tree, source.as_bytes(), &FilePathId::new(file))
            .unwrap();
        let controls: Vec<_> = output
            .relations
            .iter()
            .filter(|relation| claims_import_witness(relation))
            .collect();
        assert!(controls.len() <= 1);
        controls
            .first()
            .map(|control| decode_import_witness(control).unwrap())
    }

    #[test]
    fn python_reexport_facts_preserve_exact_form_alias_and_source() {
        let source = "\"\"\"Exports.\"\"\"\nfrom .implementation import execute as public\n";
        let facts = python(source).unwrap();
        assert_eq!(
            facts.python_reexports["public"],
            NamedImport {
                module: ".implementation".into(),
                original: "execute".into()
            }
        );
        assert_eq!(
            facts.source_digest,
            kin_model::Hash256::from_bytes(Sha256::digest(source.as_bytes()).into()).to_string()
        );
        assert_eq!(facts.source_len, source.len());
        assert!(python("import search\n")
            .unwrap()
            .python_reexports
            .is_empty());
        assert_eq!(
            python("from search import search\n")
                .unwrap()
                .python_reexports["search"]
                .original,
            "search"
        );
        assert!(python("class Hit:\n    def __init__(self, path):\n        self.path = path\ndef search(terms):\n    return [Hit(term) for term in terms]\n").is_some());
    }

    #[test]
    fn python_module_writes_deletions_guards_and_duplicates_refuse() {
        for tail in [
            "work = None\n",
            "del work\n",
            "work, other = (None, None)\n",
            "if enabled:\n    work = None\n",
            "from .other import work\n",
            "from .other import *\n",
            "globals()['work'] = None\n",
        ] {
            assert!(
                python(&format!("from .implementation import work\n{tail}")).is_none(),
                "{tail}"
            );
        }
    }

    #[test]
    fn python_callable_sites_require_actual_unshadowed_root_function_reads() {
        let source = "from pkg import work as invoke\ndef run(value):\n    return invoke(value)\ndef reference():\n    return invoke\n";
        let facts = python(source).unwrap();
        assert!(facts.python_reexports.is_empty());
        assert_eq!(facts.callable_import_sites.len(), 2);
        assert_eq!(facts.callable_import_sites[0].kind, ImportSiteKind::Calls);
        assert_eq!(
            &source[facts.callable_import_sites[0].start_byte
                ..facts.callable_import_sites[0].end_byte],
            "invoke(value)"
        );
        assert_eq!(
            facts.callable_import_sites[1].kind,
            ImportSiteKind::References
        );
        for body in [
            "def run(work):\n    return work()\n", "def run():\n    work = replacement\n    return work()\n",
            "def run():\n    from other import work\n    return work()\n", "def run():\n    del work\n    return work()\n",
            "def run():\n    return (lambda work: work())(replacement)\n", "def run():\n    def nested(work):\n        return work()\n    return nested(replacement)\n",
            "def run():\n    return [work() for work in values]\n", "def run():\n    global work\n    work = replacement\n    return work()\n",
        ] {
            assert!(python(&format!("from pkg import work\n{body}")).is_none_or(|facts| facts.callable_import_sites.is_empty()), "{body}");
        }
    }

    #[test]
    fn rust_self_named_import_site_preserves_alias_beside_unrelated_glob() {
        let facts = rust("mod variants;\nuse self::work as invoke;\nuse self::variants::*;\npub fn work(value: u32) -> u32 { value }\npub fn run(value: u32) -> u32 { invoke(value) }\n").unwrap();
        assert_eq!(facts.callable_import_sites.len(), 1);
        let site = &facts.callable_import_sites[0];
        assert_eq!(
            (&*site.local, &*site.module, &*site.original),
            ("invoke", "self", "work")
        );
        assert!(rust("pub enum Status { Ready(u32) }\npub fn work() {}\n").is_some());
    }

    #[test]
    fn rust_inline_modules_do_not_change_root_import_site_custody() {
        let source = "mod owner { pub fn work() {} } use crate::owner::work; fn run() { work(); }";
        let facts = rust(source).unwrap();
        assert_eq!(facts.callable_import_sites.len(), 1);
        assert_eq!(facts.callable_import_sites[0].module, "crate::owner");
        assert_eq!(facts.callable_import_sites[0].caller, "run");
        // A same-named nested import must not become a root import, nor hide
        // the real root one. Calls inside the child get no invented root pin.
        let source = "mod child { use crate::other::work; fn nested() { work(); } } use crate::owner::work; fn run() { work(); }";
        let facts = rust(source).unwrap();
        assert_eq!(facts.callable_import_sites.len(), 1);
        assert_eq!(facts.callable_import_sites[0].module, "crate::owner");
        assert_eq!(facts.callable_import_sites[0].caller, "run");
        let facts = rust("mod child { use crate::other::work; } fn run() { work(); }").unwrap();
        assert!(facts.callable_import_sites.is_empty());
    }

    #[test]
    fn rust_cfg_path_and_duplicate_named_uses_refuse() {
        for source in [
            "#[cfg(feature = \"x\")] mod parser;",
            "#[path = \"other.rs\"] mod parser;",
            "mod parser; mod parser;",
            "use self::left as work; use self::right as work; fn run() { work(); }",
        ] {
            assert!(rust(source).is_none(), "{source}");
        }
        for body in [
            "fn run(work: fn()) { work(); }",
            "fn run() { let work = || {}; work(); }",
            "fn run() { use self::other as work; work(); }",
            "fn run() { for work in values { work(); } }",
            "fn run() { let closure = |work: fn()| work(); }",
            "fn run() { shadow!(work); work(); }",
            "fn run() { fn work() {} work(); }",
            "fn run() { let Holder { work } = value; work(); }",
        ] {
            assert!(
                rust(&format!("use self::implementation as work; {body}"))
                    .unwrap()
                    .callable_import_sites
                    .is_empty(),
                "{body}"
            );
        }
    }

    #[test]
    fn malformed_controls_are_claimed_but_never_decoded_as_authority() {
        let facts = python("from pkg import work\ndef run():\n    return work()\n").unwrap();
        let mut records = Vec::new();
        append(facts.clone(), &mut records);
        let record = &records[0];
        assert_eq!(decode_import_witness(record).unwrap(), facts);
        let mut wrong_shape = record.clone();
        wrong_shape.kind = RelationKind::Calls;
        assert!(claims_import_witness(&wrong_shape));
        assert!(decode_import_witness(&wrong_shape).is_err());
        let mut unknown = record.clone();
        unknown.dst_name = unknown.dst_name.replacen('{', "{\"unknown\":true,", 1);
        assert!(decode_import_witness(&unknown).is_err());
        let mut bad_digest = facts.clone();
        bad_digest.source_digest = "A".repeat(64);
        assert!(validate(&bad_digest).is_err());
        let mut bad_site = facts.clone();
        bad_site.callable_import_sites[0].end_byte = facts.source_len + 1;
        assert!(validate(&bad_site).is_err());
        let mut duplicate = facts.clone();
        duplicate
            .callable_import_sites
            .push(duplicate.callable_import_sites[0].clone());
        assert!(validate(&duplicate).is_err());
        let mut huge = record.clone();
        huge.dst_name = " ".repeat(MAX_PAYLOAD_BYTES + 1);
        assert!(decode_import_witness(&huge).is_err());
        assert!(python(&format!("#{}", "x".repeat(MAX_SOURCE_BYTES))).is_none());
    }
}
