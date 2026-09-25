// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::{ReconcileError, Result};
use kin_index::binding_debt::{
    decode_local_binding_debt, local_binding_debt_id, relocate_local_binding_debt,
};
use kin_model::{FilePathId, GraphNodeId, GraphStore, RelationDelta, RepoPath, TreeEntry};

fn invalid(reason: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("binding obligation relocation: {reason}"))
}

/// Relocate source-owned obligations in the prospective semantic transaction.
/// Historical occurrences remain at their original location. Exact lookup and
/// all-kind source reads preflight malformed or foreign reserved occupants even
/// when another part of the same transaction creates or replaces the fact.
pub fn relocate_binding_obligations<G: GraphStore>(
    graph: &G,
    moves: &[(FilePathId, FilePathId)],
    deltas: &mut Vec<RelationDelta>,
) -> Result<()> {
    let mut replacements = Vec::new();
    for (from, to) in moves {
        let path = RepoPath::from_utf8(from.0.clone()).map_err(invalid)?;
        let artifact = graph
            .artifact_id_at_path(&path)
            .ok_or_else(|| invalid(format!("source {from} has no admitted artifact")))?;
        let reserved = local_binding_debt_id(artifact);
        let mut held_debt = None;
        for relation in crate::binding_debt::held(graph, artifact)? {
            if relation.src != GraphNodeId::Artifact(artifact) && relation.id != reserved {
                continue;
            }
            if decode_local_binding_debt(from, artifact, &relation)
                .map_err(invalid)?
                .is_some()
            {
                if held_debt.replace(relation).is_some() {
                    return Err(invalid("multiple facts claim the moved source"));
                }
            }
        }
        let staged: Vec<_> = deltas
            .iter()
            .filter(|d| d.target_id() == reserved)
            .collect();
        if staged.len() > 1 {
            return Err(invalid(
                "prospective source obligation has duplicate deltas",
            ));
        }
        let effective = match staged.first().copied() {
            Some(RelationDelta::Added { new }) => {
                if held_debt.is_some() {
                    return Err(invalid("prospective debt adds an occupied identity"));
                }
                Some(new)
            }
            Some(RelationDelta::Modified { old, new }) => {
                if held_debt.as_ref() != Some(old) {
                    return Err(invalid("prospective debt has a stale prior payload"));
                }
                Some(new)
            }
            Some(RelationDelta::Removed { old }) => {
                if held_debt.as_ref() != Some(old) {
                    return Err(invalid(
                        "prospective debt removal has a stale prior payload",
                    ));
                }
                None
            }
            None => held_debt.as_ref(),
        };
        let Some(effective) = effective else {
            continue;
        };
        let Some(TreeEntry::Blob { hash, .. }) = graph
            .get_tree_entry(from)
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
        else {
            return Err(invalid("moved obligation source is not an admitted blob"));
        };
        let new = relocate_local_binding_debt(from, to, artifact, hash, effective)
            .map_err(invalid)?
            .ok_or_else(|| invalid("prospective payload does not claim its reserved identity"))?;
        replacements.push((
            reserved,
            match held_debt {
                Some(old) => RelationDelta::Modified { old, new },
                None => RelationDelta::Added { new },
            },
        ));
    }
    for (id, replacement) in replacements {
        deltas.retain(|delta| delta.target_id() != id);
        deltas.push(replacement);
    }
    Ok(())
}

/// Withdraw imported bindings whose real current resolution is invalidated by
/// a path relocation. This explicit admission boundary builds two indexes from
/// one graph entity census; ordinary edits continue to use the live index.
/// Only sources incident to the moved identities are reparsed, from admitted
/// CAS bytes. A current binding that cannot be reproduced refuses publication.
pub fn plan_moved_import_bindings<G: GraphStore>(
    graph: &G,
    moves: &[(FilePathId, FilePathId)],
    deltas: &mut Vec<RelationDelta>,
    mut read_source: impl FnMut(kin_model::Hash256) -> Result<Vec<u8>>,
) -> Result<()> {
    use kin_index::{FileParseData, IncrementalLinker, RelationResolution};
    use kin_model::{Entity, EntityId, Relation, RelationKind};
    use std::collections::{BTreeMap, HashMap, HashSet};

    if moves.is_empty() {
        return Ok(());
    }
    let paths: HashMap<_, _> = moves.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
    if paths.len() != moves.len() || moves.iter().any(|(a, b)| a == b) {
        return Err(invalid("move paths are duplicated or unchanged"));
    }
    let mut by_file: BTreeMap<String, Vec<Entity>> = BTreeMap::new();
    let mut entities = HashMap::new();
    for entity in graph
        .list_all_entities()
        .map_err(|e| invalid(e.to_string()))?
    {
        if let Some(file) = &entity.file_origin {
            by_file
                .entry(file.0.clone())
                .or_default()
                .push(entity.clone());
        }
        entities.insert(entity.id, entity);
    }
    // Include moved entity-free files: artifact import edges are still real.
    for (from, _) in moves {
        by_file.entry(from.0.clone()).or_default();
    }
    let mut artifacts = HashMap::new();
    let mut file_by_artifact = HashMap::new();
    let mut current = IncrementalLinker::new();
    let mut future = IncrementalLinker::new();
    let mut incident = HashMap::new();
    for (file_name, declarations) in &by_file {
        let file_id = FilePathId::new(file_name);
        let file = &file_id;
        let path = RepoPath::from_utf8(file.0.clone()).map_err(invalid)?;
        let Some(artifact) = graph.artifact_id_at_path(&path) else {
            continue;
        };
        let Some(TreeEntry::Blob { hash, .. }) = graph
            .get_tree_entry(file)
            .map_err(|e| invalid(e.to_string()))?
        else {
            continue;
        };
        artifacts.insert(file.clone(), (artifact, hash));
        file_by_artifact.insert(artifact, file.clone());
        current.add_file(&file.0, artifact, declarations);
        let relocated = paths.get(file).unwrap_or(file);
        let mut proposed = declarations.clone();
        for entity in &mut proposed {
            entity.file_origin = Some(relocated.clone());
            if let Some(span) = &mut entity.span {
                span.file = relocated.clone();
            }
        }
        future.add_file(&relocated.0, artifact, &proposed);
        if paths.contains_key(file) {
            for entity in declarations {
                for relation in graph
                    .get_all_relations_for_entity(&entity.id)
                    .map_err(|e| invalid(e.to_string()))?
                {
                    incident.insert(relation.id, relation);
                }
            }
            for relation in graph
                .traverse(&GraphNodeId::Artifact(artifact), &[], 1)
                .map_err(|e| invalid(e.to_string()))?
                .relations
            {
                incident.insert(relation.id, relation);
            }
        }
    }
    let node_file = |node: GraphNodeId| match node {
        GraphNodeId::Entity(id) => entities.get(&id).and_then(|e| e.file_origin.clone()),
        GraphNodeId::Artifact(id) => file_by_artifact.get(&id).cloned(),
        _ => None,
    };
    let already_retired: HashSet<_> = deltas
        .iter()
        .filter_map(|d| match d {
            RelationDelta::Removed { old } => Some(old.id),
            _ => None,
        })
        .collect();
    let mut sources: BTreeMap<String, Vec<Relation>> = BTreeMap::new();
    for relation in incident.into_values() {
        if already_retired.contains(&relation.id)
            || !RelationResolution::of(&relation).is_proven()
            || !matches!(
                relation.kind,
                RelationKind::Calls
                    | RelationKind::References
                    | RelationKind::Imports
                    | RelationKind::Includes
            )
        {
            continue;
        }
        let (Some(source), Some(target)) = (node_file(relation.src), node_file(relation.dst))
        else {
            continue;
        };
        if source == target || (!paths.contains_key(&source) && !paths.contains_key(&target)) {
            continue;
        }
        sources.entry(source.0).or_default().push(relation);
    }
    let mut withdrawn = Vec::new();
    let mut relocated_bindings = Vec::new();
    for (file_name, held) in sources {
        let file = FilePathId::new(file_name);
        let indexed = crate::admitted_source::load_with(graph, &file, &mut read_source)?
            .ok_or_else(|| invalid("moved binding source is not a complete admitted parse"))?;
        let source = FileParseData {
            file_path: file.0.clone(),
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        };
        let old = resolve_move_source(graph, &source, &current)?;
        let mut proposed = source.clone();
        let prospective_file = paths.get(&file).unwrap_or(&file);
        proposed.file_path = prospective_file.0.clone();
        for entity in &mut proposed.entities {
            entity.file_origin = Some(prospective_file.clone());
            if let Some(span) = &mut entity.span {
                span.file = prospective_file.clone();
            }
        }
        let new = resolve_move_source(graph, &proposed, &future)?;
        for relation in held {
            let target_file = node_file(relation.dst).expect("selected admitted endpoint");
            let target_artifact = artifacts.get(&target_file).map(|(id, _)| *id);
            let imported_target = relation
                .import_source
                .as_deref()
                .is_some_and(|s| !s.is_empty())
                || old.iter().any(|r| {
                    r.src == GraphNodeId::Artifact(artifacts[&file].0)
                        && matches!(r.dst, GraphNodeId::Artifact(id) if Some(id) == target_artifact)
                        && matches!(r.kind, RelationKind::Imports | RelationKind::Includes)
                });
            if !imported_target {
                continue;
            }
            if !old.iter().any(|r| {
                reproduced_move_binding(
                    r,
                    &relation,
                    &source,
                    &file,
                    &target_file.0,
                    &HashMap::new(),
                )
                .is_some()
            }) {
                return Err(invalid(format!("current imported occurrence {} cannot be reproduced from admitted source {file}", relation.id)));
            }
            let prospective_target = paths.get(&target_file).unwrap_or(&target_file);
            if let Some(mut proposed) = new.iter().find_map(|r| {
                reproduced_move_binding(
                    r,
                    &relation,
                    &source,
                    prospective_file,
                    &prospective_target.0,
                    &paths,
                )
            }) {
                proposed.created_in = relation.created_in;
                if proposed != relation {
                    relocated_bindings.push(RelationDelta::Modified {
                        old: relation,
                        new: proposed,
                    });
                }
            } else {
                withdrawn.push(relation);
            }
        }
    }
    // Feed the same exact obligation factory used for removals, with the
    // prospective debt overlay so a combined removal+move cannot lose either.
    let effective = |id: kin_model::RelationId, held: Option<Relation>| -> Option<Relation> {
        deltas
            .iter()
            .find(|d| d.target_id() == id)
            .map_or(held, |d| match d {
                RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => {
                    Some(new.clone())
                }
                RelationDelta::Removed { .. } => None,
            })
    };
    let debt = crate::coverage::plan_withdrawn_local_binding_obligations(
        &withdrawn,
        |id: EntityId| Ok(entities.get(&id).cloned()),
        |file| Ok(artifacts.get(file).copied()),
        |artifact| {
            let mut held = crate::binding_debt::held(graph, artifact)?;
            let reserved = local_binding_debt_id(artifact);
            let original = held.iter().find(|r| r.id == reserved).cloned();
            // Validate the held occupant before any staged replacement hides it.
            if let Some(old) = &original {
                let file = file_by_artifact
                    .get(&artifact)
                    .ok_or_else(|| invalid("source artifact path missing"))?;
                decode_local_binding_debt(file, artifact, old).map_err(invalid)?;
            }
            held.retain(|r| r.id != reserved);
            if let Some(new) = effective(reserved, original) {
                held.push(new);
            }
            Ok(held)
        },
        |id| Ok(effective(id, crate::binding_debt::exact(graph, id)?)),
    )?;
    for change in debt {
        let id = change.target_id();
        let original = crate::binding_debt::exact(graph, id)?;
        let new = match change {
            RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => new,
            RelationDelta::Removed { .. } => {
                return Err(invalid("withdrawal unexpectedly clears debt"))
            }
        };
        deltas.retain(|d| d.target_id() != id);
        deltas.push(match original {
            Some(old) => RelationDelta::Modified { old, new },
            None => RelationDelta::Added { new },
        });
    }
    for change in relocated_bindings {
        if deltas.iter().any(|d| d.target_id() == change.target_id()) {
            return Err(invalid(
                "relocated imported occurrence already has a competing delta",
            ));
        }
        deltas.push(change);
    }
    for old in withdrawn {
        if deltas.iter().any(|d| d.target_id() == old.id) {
            return Err(invalid(
                "moved imported occurrence already has a competing delta",
            ));
        }
        deltas.push(RelationDelta::Removed { old });
    }
    Ok(())
}

fn resolve_move_source<G: GraphStore>(
    graph: &G,
    source: &kin_index::FileParseData,
    linker: &kin_index::IncrementalLinker,
) -> Result<Vec<kin_model::Relation>> {
    let completeness = std::collections::HashMap::from([(
        source.file_path.clone(),
        kin_model::ParseCompleteness::Full,
    )]);
    kin_index::link_cross_file_incremental_with_graph(
        std::slice::from_ref(source),
        linker,
        &completeness,
        graph,
    )
    .map_err(|e| invalid(e.to_string()))
}

fn reproduced_move_binding(
    candidate: &kin_model::Relation,
    held: &kin_model::Relation,
    source: &kin_index::FileParseData,
    emitted_file: &FilePathId,
    target_file: &str,
    paths: &std::collections::HashMap<FilePathId, FilePathId>,
) -> Option<kin_model::Relation> {
    if same_move_binding(candidate, held, paths) {
        return Some(candidate.clone());
    }
    // This additional reproduction path owns only the exact named-import
    // factory. Never erase authored/LSP/foreign evidence to manufacture a match.
    if !kin_index::linker::has_named_import_factory_identity(held)
        || held.origin != kin_model::RelationOrigin::Inferred
        || held.confidence.to_bits() != 0.95_f32.to_bits()
    {
        return None;
    }
    let reproduced = kin_index::linker::reproduce_named_import_evidence(
        source,
        emitted_file,
        candidate,
        target_file,
    )?;
    same_move_binding(&reproduced, held, paths).then_some(reproduced)
}

fn same_move_binding(
    candidate: &kin_model::Relation,
    held: &kin_model::Relation,
    paths: &std::collections::HashMap<FilePathId, FilePathId>,
) -> bool {
    if candidate.src != held.src
        || candidate.dst != held.dst
        || candidate.kind != held.kind
        || candidate.import_source != held.import_source
        || !kin_index::RelationResolution::of(candidate).is_proven()
    {
        return false;
    }
    let (Some(candidate_records), Some(held_records)) = (
        kin_index::occurrence::uniform_original_evidence(candidate),
        kin_index::occurrence::uniform_original_evidence(held),
    ) else {
        return false;
    };
    let mut evidence: Vec<_> = held_records.into_iter().cloned().collect();
    for item in &mut evidence {
        if let Some(span) = &mut item.source_span {
            if let Some(path) = paths.get(&span.file) {
                span.file = path.clone();
            }
        }
        if let Some(path) = &mut item.resolved_path {
            if let Some(new) = paths.get(&FilePathId::new(path.as_str())) {
                *path = new.0.clone();
            }
        }
    }
    candidate_records.into_iter().eq(evidence.iter())
}
