// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source-bound function lifecycle planning, before native publication.
//! All locations come from exact graph/CAS authority; payloads name entities.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use kin_mcp::entity_lifecycle::{EntityCreate, EntityPlacement};
use kin_mcp::{McpMutationOperation, McpMutationPayload};
use kin_model::{
    Entity, EntityKind, EntityStore, FileLayout, FilePathId, Hash256, LanguageId, LocatedEntry,
    ParseState, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};

use crate::local_repository_authority::LocalRepositoryAuthorityContext;
use crate::repository_commit::{load_native_source_blob, NativeCommitBase};
use crate::state::DaemonState;

pub(crate) struct LifecyclePlan {
    pub snapshot: kin_db::GraphSnapshot,
    pub authored_files: BTreeSet<RepoPath>,
    pub layouts: Vec<FileLayout>,
}

/// Anchored creation and removal. Unit-addressed creation is planned by
/// `unit_lifecycle`, after entity edits, against the prospective graph.
pub(crate) fn is_lifecycle(operation: &McpMutationOperation) -> bool {
    match operation.payload.as_ref() {
        Some(McpMutationPayload::EntityCreate(create)) => create.anchor().is_some(),
        Some(McpMutationPayload::EntityRemove(_)) => true,
        _ => false,
    }
}

fn supported(language: LanguageId) -> Result<&'static str, String> {
    match language {
        LanguageId::Rust => Ok("rs"),
        LanguageId::Python => Ok("py"),
        LanguageId::Go => Ok("go"),
        _ => Err(
            "entity lifecycle currently supports top-level leaf functions in Rust, Python and Go"
                .into(),
        ),
    }
}

/// Prove the exact declaration is top-level syntax, not merely an entity whose
/// name happens to match. Parser-widened docs/attributes must be inside its span.
fn function_span(
    source: &[u8],
    file: &FilePathId,
    language: LanguageId,
    name: &str,
) -> Result<(Range<usize>, Option<String>), String> {
    supported(language)?;
    let registry = kin_parser::AdapterRegistry::new();
    let adapter = registry
        .get_by_language(language)
        .ok_or("missing lifecycle parser")?;
    let tree = adapter.parse(source).map_err(|error| error.to_string())?;
    if tree.root_node().has_error() {
        return Err("entity lifecycle requires complete valid source syntax".into());
    }
    let parsed = adapter
        .extract(&tree, source, file)
        .map_err(|error| error.to_string())?;
    if !matches!(parsed.parse_state, ParseState::Valid) {
        return Err("entity lifecycle refuses an incomplete parse".into());
    }
    let matches = parsed
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Function && entity.name == name)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "lifecycle function {name:?} is absent or ambiguous in its exact owner"
        ));
    }
    let entity = matches[0];
    let span = entity.span.start_byte..entity.span.end_byte;
    let mut cursor = tree.root_node().walk();
    let top = tree
        .root_node()
        .named_children(&mut cursor)
        .find_map(|node| {
            let declaration = match (language, node.kind()) {
                (LanguageId::Rust, "function_item")
                | (LanguageId::Python, "function_definition")
                | (LanguageId::Go, "function_declaration") => Some(node),
                (LanguageId::Python, "decorated_definition") => node
                    .child_by_field_name("definition")
                    .filter(|child| child.kind() == "function_definition"),
                _ => None,
            };
            declaration.filter(|declaration| {
                node.start_byte() >= span.start
                    && declaration.end_byte() == span.end
                    && declaration.start_byte() >= span.start
                    && declaration
                        .child_by_field_name("name")
                        .is_some_and(|name_node| name_node.utf8_text(source).ok() == Some(name))
            })
        });
    if top.is_none() || span.start >= span.end || span.end > source.len() {
        return Err("entity lifecycle requires a proven top-level function including its declaration prefix".into());
    }
    // Some adapters intentionally do not extract declarations nested inside
    // function bodies. Prove the leaf property from the actual syntax too.
    let declaration = top.expect("proved top-level declaration");
    let mut pending = Vec::new();
    let mut cursor = declaration.walk();
    pending.extend(declaration.named_children(&mut cursor));
    while let Some(node) = pending.pop() {
        let nested = match language {
            LanguageId::Rust => matches!(
                node.kind(),
                "function_item"
                    | "struct_item"
                    | "enum_item"
                    | "trait_item"
                    | "impl_item"
                    | "mod_item"
                    | "type_item"
                    | "const_item"
                    | "static_item"
                    | "macro_definition"
                    | "use_declaration"
                    | "extern_crate_declaration"
            ),
            LanguageId::Python => matches!(node.kind(), "function_definition" | "class_definition"),
            LanguageId::Go => matches!(
                node.kind(),
                "function_declaration" | "method_declaration" | "type_declaration"
            ),
            _ => unreachable!(),
        };
        if nested {
            return Err(
                "entity lifecycle does not yet support functions owning nested declarations".into(),
            );
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    if parsed.entities.iter().any(|other| {
        !(std::ptr::eq(other, entity)
            // Adapter-created whole-file module metadata is not a nested declaration.
            || (matches!(other.kind, EntityKind::Module | EntityKind::Package)
                && ["module ", "package ", "namespace "].iter().any(|prefix| other.signature.strip_prefix(prefix).is_some_and(|tail| tail == file.0)))
        )
            && other.span.start_byte >= span.start
            && other.span.end_byte <= span.end
    }) {
        return Err(
            "entity lifecycle does not yet support functions owning nested declarations".into(),
        );
    }
    let package = if language == LanguageId::Go {
        let mut cursor = tree.root_node().walk();
        let packages = tree
            .root_node()
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "package_clause")
            .map(|node| std::str::from_utf8(&source[node.byte_range()]).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if packages.len() != 1 {
            return Err("Go lifecycle requires one exact package owner".into());
        }
        packages.into_iter().next()
    } else {
        None
    };
    Ok((span, package))
}

fn declaration_body(
    create: &EntityCreate,
    anchor: &Entity,
    package: Option<&str>,
) -> Result<Vec<u8>, String> {
    create.validate()?;
    let prefix = package
        .map(|package| format!("{package}\n\n"))
        .unwrap_or_default();
    let candidate = format!("{prefix}{}", create.body);
    let file = anchor
        .file_origin
        .as_ref()
        .ok_or("anchor has no source owner")?;
    let (span, _) = function_span(candidate.as_bytes(), file, anchor.language, &create.name)?;
    if span.start < prefix.len()
        || !candidate.as_bytes()[prefix.len()..span.start]
            .iter()
            .all(u8::is_ascii_whitespace)
        || !candidate.as_bytes()[span.end..]
            .iter()
            .all(u8::is_ascii_whitespace)
    {
        return Err("EntityCreate body must contain exactly the named function, not package/import statements or sibling declarations".into());
    }
    Ok(candidate.as_bytes()[span].to_vec())
}

fn new_unit_path(anchor: &Entity, name: &str) -> Result<RepoPath, String> {
    let origin = anchor
        .file_origin
        .as_ref()
        .ok_or("anchor has no source owner")?;
    kin_mcp::entity_lifecycle::generated_source_path(origin, anchor.language, name)
}

/// This increment does not synthesize compiler build ownership. Refuse Go
/// owners whose filename or leading directives may restrict membership rather
/// than accidentally promote a test/platform function into an ordinary unit.
fn require_new_unit_owner(anchor: &Entity, source: &[u8]) -> Result<(), String> {
    if anchor.language == LanguageId::Rust {
        return Err("Rust new source units require a module-owner declaration; use sibling_after until module-owner creation is supported".into());
    }
    if anchor.language != LanguageId::Go {
        return Ok(());
    }
    let origin = anchor.file_origin.as_ref().ok_or("anchor has no owner")?;
    let filename = std::path::Path::new(&origin.0)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("anchor owner is not UTF8")?;
    if filename.contains('_') || filename.starts_with('.') {
        return Err("Go new source units currently require a plain owner filename without underscores or a leading dot; test/platform build-owner placement is not yet supported; use sibling_after".into());
    }
    let registry = kin_parser::AdapterRegistry::new();
    let adapter = registry
        .get_by_language(LanguageId::Go)
        .ok_or("missing Go parser")?;
    let tree = adapter.parse(source).map_err(|e| e.to_string())?;
    let mut cursor = tree.root_node().walk();
    let package = tree
        .root_node()
        .named_children(&mut cursor)
        .find(|n| n.kind() == "package_clause")
        .ok_or("missing Go package owner")?;
    let header = std::str::from_utf8(&source[..package.start_byte()]).map_err(|e| e.to_string())?;
    if header.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("//go:build") || line.starts_with("// +build")
    }) {
        return Err("Go new source units with build directives require build-owner placement, which is not yet supported; use sibling_after".into());
    }
    Ok(())
}

struct Expected {
    file: FilePathId,
    created: Option<(String, Vec<u8>)>,
    removed: Option<kin_model::EntityId>,
}

/// Keep cached admitted bodies. Missing bodies are recovered only from exact
/// repository CAS, as in authored merge preparation, never from host files.
fn ensure_source_cache(
    state: &DaemonState,
    context: &LocalRepositoryAuthorityContext,
    snapshot: &kin_db::GraphSnapshot,
) -> Result<(), String> {
    let paths = snapshot
        .entities
        .values()
        .filter_map(|entity| entity.file_origin.as_ref().map(|path| path.0.as_str()))
        .collect::<BTreeSet<_>>();
    let mut hashes = BTreeSet::new();
    for artifact in snapshot.resolved_tree.artifacts() {
        if paths.contains(artifact.path.to_string().as_str()) {
            if let TreeEntry::Blob { hash, .. } = artifact.entry {
                hashes.insert(hash);
            }
        }
    }
    for relation in snapshot
        .relations
        .values()
        .filter(|relation| kin_index::binding_debt::claims_local_binding_debt(relation))
    {
        let kin_model::GraphNodeId::Artifact(id) = relation.src else {
            return Err("binding debt has no source artifact".into());
        };
        let artifact = snapshot
            .resolved_tree
            .get(&id)
            .ok_or("binding debt artifact is absent")?;
        if let Some(debt) = kin_index::binding_debt::decode_local_binding_debt(
            &FilePathId::new(artifact.path.to_string()),
            id,
            relation,
        )
        .map_err(|error| error.to_string())?
        {
            hashes.extend(
                debt.obligations
                    .into_iter()
                    .map(|obligation| obligation.source_digest),
            );
        }
    }
    for hash in hashes {
        let digest = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        if !state
            .blobs
            .exists(&digest)
            .map_err(|error| error.to_string())?
        {
            let body = load_native_source_blob(context, hash).map_err(|error| error.to_string())?;
            if state
                .blobs
                .write(&body)
                .map_err(|error| error.to_string())?
                != digest
            {
                return Err("repository lifecycle source digest differs".into());
            }
        }
    }
    Ok(())
}

pub(crate) fn prepare(
    state: &DaemonState,
    context: &LocalRepositoryAuthorityContext,
    base: &NativeCommitBase,
    operations: &[McpMutationOperation],
) -> Result<Option<LifecyclePlan>, String> {
    if !operations.iter().any(is_lifecycle) {
        return Ok(None);
    }
    let before = base.graph.to_snapshot();
    ensure_source_cache(state, context, &before)?;
    let prospective =
        kin_db::InMemoryGraph::from_snapshot(before.clone()).map_err(|error| error.to_string())?;
    let mut expected = Vec::new();
    let mut created_package_names = BTreeSet::new();
    let mut authored_files = BTreeSet::new();
    let mut old_bodies = BTreeMap::new();
    let mut bodies = BTreeMap::new();
    for operation in operations
        .iter()
        .filter(|operation| is_lifecycle(operation))
    {
        let (source_base, create) = match operation.payload.as_ref().unwrap() {
            McpMutationPayload::EntityCreate(create) => {
                let (source_base, placement) =
                    create.anchor().ok_or("anchored creation lost its anchor")?;
                (source_base, Some((create, placement)))
            }
            McpMutationPayload::EntityRemove(remove) => (&remove.source_base, None),
            _ => unreachable!(),
        };
        let anchor = base
            .graph
            .get_entity(&source_base.entity_id)
            .map_err(|error| error.to_string())?
            .ok_or("lifecycle anchor no longer exists")?;
        kin_model::require_independent_source(&anchor)?;
        if anchor.kind != EntityKind::Function {
            return Err("entity lifecycle requires a top-level leaf function".into());
        }
        let file = anchor
            .file_origin
            .as_ref()
            .ok_or("lifecycle anchor has no source owner")?;
        let path = RepoPath::from_utf8(file.0.clone()).map_err(|error| error.to_string())?;
        let artifact = base
            .tree
            .artifact_at_path(&path)
            .ok_or("lifecycle source artifact is absent")?;
        let TreeEntry::Blob { hash, executable } = artifact.entry else {
            return Err("lifecycle source is not a regular blob".into());
        };
        let original = load_native_source_blob(context, hash).map_err(|error| error.to_string())?;
        let (span, package) = function_span(&original, file, anchor.language, &anchor.name)?;
        let held = anchor
            .span
            .as_ref()
            .ok_or("lifecycle anchor has no source span")?;
        if span != (held.start_byte..held.end_byte) {
            return Err("lifecycle anchor span differs from its exact parsed declaration".into());
        }
        let (target, projected, created, removed) = if let Some((create, placement)) = create {
            let declaration = declaration_body(create, &anchor, package.as_deref())?;
            if anchor.language == LanguageId::Go
                && !created_package_names.insert((
                    std::path::Path::new(&file.0).parent().map(|p| p.to_owned()),
                    create.name.clone(),
                ))
            {
                return Err("two creations name the same Go package member".into());
            }

            if before.entities.values().any(|entity| {
                entity.name == create.name
                    && (entity.file_origin.as_ref() == Some(file)
                        || (anchor.language == LanguageId::Go
                            && entity.language == LanguageId::Go
                            && entity.file_origin.as_ref().is_some_and(|origin| {
                                std::path::Path::new(&origin.0).parent()
                                    == std::path::Path::new(&file.0).parent()
                            })))
            }) {
                return Err(
                    "a declaration with that name already occupies the anchor's owner".into(),
                );
            }
            match placement {
                EntityPlacement::SiblingAfter => {
                    let mut insertion = b"\n\n".to_vec();
                    insertion.extend_from_slice(create.body.as_bytes());
                    insertion.push(b'\n');
                    let projected = kin_projection::apply_splices(
                        &original,
                        vec![kin_projection::Splice {
                            byte_range: span.end..span.end,
                            new_content: insertion,
                        }],
                    )
                    .map_err(|error| error.to_string())?;
                    (
                        path.clone(),
                        projected,
                        Some((create.name.clone(), declaration)),
                        None,
                    )
                }
                EntityPlacement::NewSourceUnit => {
                    require_new_unit_owner(&anchor, &original)?;
                    let target = new_unit_path(&anchor, &create.name)?;
                    if prospective
                        .resolved_tree()
                        .artifact_at_path(&target)
                        .is_some()
                    {
                        return Err("the generated source unit is already occupied; no existing artifact was overwritten".into());
                    }
                    let prefix = package
                        .map(|package| format!("{package}\n\n"))
                        .unwrap_or_default();
                    (
                        target,
                        format!("{prefix}{}\n", create.body).into_bytes(),
                        Some((create.name.clone(), declaration)),
                        None,
                    )
                }
            }
        } else {
            let projected = kin_projection::apply_splices(
                &original,
                vec![kin_projection::Splice {
                    byte_range: span,
                    new_content: Vec::new(),
                }],
            )
            .map_err(|error| error.to_string())?;
            (path.clone(), projected, None, Some(anchor.id))
        };
        if !authored_files.insert(target.clone()) {
            return Err("multiple lifecycle operations on one source unit are not yet supported; split them into guarded transactions".into());
        }
        let target_file = FilePathId::new(target.to_string());
        let digest = state
            .blobs
            .write(&projected)
            .map_err(|error| error.to_string())?;
        let new_hash = Hash256::from_bytes(digest.0);
        let delta = if target == path {
            old_bodies.insert(file.0.clone(), original);
            TreeDelta::Updated {
                artifact_id: artifact.artifact_id,
                old: artifact.located_entry(),
                new: LocatedEntry::new(target, TreeEntry::blob(new_hash, executable)),
            }
        } else {
            TreeDelta::Added {
                artifact_id: kin_model::ArtifactId::new(),
                new: LocatedEntry::new(target, TreeEntry::blob(new_hash, false)),
            }
        };
        prospective
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![delta],
                ..Default::default()
            })
            .map_err(|error| error.to_string())?;
        bodies.insert(target_file.0.clone(), projected);
        expected.push(Expected {
            file: target_file,
            created,
            removed,
        });
    }
    let predecessor = kin_model::graph::ResolvedGraphState {
        entities: before.entities.clone(),
        relations: before.relations.clone(),
        external_references: before.external_references.clone(),
        tree: before.resolved_tree.clone(),
        ..Default::default()
    };
    let files = expected
        .iter()
        .map(|item| item.file.clone())
        .collect::<Vec<_>>();
    let prepared = kin_reconcile::Reconciler::prepare_admitted_source_batch(
        prospective.to_snapshot(),
        &files,
        &state.blobs,
        &[predecessor],
    )
    .map_err(|error| format!("reconcile source-bound lifecycle: {error}"))?;
    validate_footprint(
        &before,
        prepared.snapshot(),
        &expected,
        &old_bodies,
        &bodies,
    )?;
    let layouts = prepared
        .sources()
        .iter()
        .map(|source| source.layout.clone())
        .collect();
    Ok(Some(LifecyclePlan {
        snapshot: prepared.into_snapshot(),
        authored_files,
        layouts,
    }))
}

fn validate_footprint(
    before: &kin_db::GraphSnapshot,
    after: &kin_db::GraphSnapshot,
    expected: &[Expected],
    old_bodies: &BTreeMap<String, Vec<u8>>,
    bodies: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    for item in expected {
        let body = &bodies[&item.file.0];
        let old_body = old_bodies.get(&item.file.0);
        for old in before.entities.values().filter(|entity| {
            entity.file_origin.as_ref() == Some(&item.file)
                && !kin_model::is_file_module_surface(entity)
        }) {
            if item.removed == Some(old.id) {
                if after.entities.contains_key(&old.id) {
                    return Err("removed function remains in the prepared graph".into());
                }
                continue;
            }
            let new = after
                .entities
                .get(&old.id)
                .ok_or("lifecycle unexpectedly removed a sibling declaration")?;
            let old_span = old
                .span
                .as_ref()
                .ok_or("lifecycle owner has an unbounded sibling declaration")?;
            let new_span = new
                .span
                .as_ref()
                .ok_or("lifecycle lost a sibling's independent source")?;
            if new.name != old.name
                || new.kind != old.kind
                || new.file_origin != old.file_origin
                || old_body.and_then(|body| body.get(old_span.start_byte..old_span.end_byte))
                    != body.get(new_span.start_byte..new_span.end_byte)
            {
                return Err("lifecycle changed an unrelated sibling declaration".into());
            }
        }
        let added = after
            .entities
            .values()
            .filter(|entity| {
                entity.file_origin.as_ref() == Some(&item.file)
                    && !kin_model::is_file_module_surface(entity)
                    && !before.entities.contains_key(&entity.id)
            })
            .collect::<Vec<_>>();
        if let Some((name, desired)) = &item.created {
            if added.len() != 1 || added[0].kind != EntityKind::Function || added[0].name != *name {
                return Err("creation did not derive exactly the requested new function".into());
            }
            let span = added[0]
                .span
                .as_ref()
                .ok_or("created function has no source span")?;
            if body.get(span.start_byte..span.end_byte) != Some(desired.as_slice()) {
                return Err("created function body differs from the requested declaration".into());
            }
        } else if !added.is_empty() {
            return Err("removal unexpectedly created a declaration".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_lifecycle_proves_top_level_leaf_spans() {
        for (language, source, expected) in [
            (
                LanguageId::Rust,
                "// header\npub fn value() -> u8 { 1 }\n",
                "pub fn value() -> u8 { 1 }",
            ),
            (
                LanguageId::Python,
                "# header\ndef value():\n    return 1\n",
                "def value():\n    return 1",
            ),
            (
                LanguageId::Go,
                "package sample\n\nfunc value() int { return 1 }\n",
                "func value() int { return 1 }",
            ),
        ] {
            let (span, _) = function_span(
                source.as_bytes(),
                &FilePathId::new("fixture"),
                language,
                "value",
            )
            .unwrap();
            assert_eq!(&source[span], expected);
        }
    }

    #[test]
    fn entity_lifecycle_refuses_nested_or_ambiguous_syntax() {
        for (language, source, name) in [
            (LanguageId::Rust, "mod owner { fn value() {} }", "value"),
            (LanguageId::Rust, "fn value() { fn nested() {} }", "value"),
            (
                LanguageId::Python,
                "class Owner:\n    def value(self):\n        return 1\n",
                "value",
            ),
            (
                LanguageId::Python,
                "def value():\n    def nested():\n        return 1\n    return nested()\n",
                "value",
            ),
            (
                LanguageId::Go,
                "package sample\nfunc (owner Owner) value() {}",
                "value",
            ),
            (LanguageId::Rust, "fn value() {}\nfn value() {}", "value"),
            (LanguageId::Rust, "fn value() {", "value"),
        ] {
            assert!(
                function_span(
                    source.as_bytes(),
                    &FilePathId::new("fixture"),
                    language,
                    name
                )
                .is_err(),
                "{source}"
            );
        }
    }
}
