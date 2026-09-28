// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Replace only source-bound exact named-import derivations. An unproven
//! outcome withdraws that derivation and records prior-local debt; it does not
//! prove the runtime dependency absent. Legacy and authored evidence is kept.

use std::collections::HashSet;

use crate::error::{ReconcileError, Result};
use kin_index::{
    binding_debt::{build_local_binding_debt, decode_local_binding_debt},
    linker::{named_import_evidence, NamedImportObservation},
    IndexedFile,
};
use kin_model::{
    Entity, EntityId, FilePathId, GraphNodeId, GraphStore, ParseCompleteness, Relation,
    RelationDelta, RelationId, RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeEntry,
};

fn invalid(reason: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("exact named-import rederivation: {reason}"))
}

fn change_id(change: &RelationDelta) -> RelationId {
    match change {
        RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => new.id,
        RelationDelta::Removed { old } => old.id,
    }
}

fn effective(
    old: Option<Relation>,
    id: RelationId,
    delta: &TransactionDelta,
) -> Result<Option<Relation>> {
    let mut changes = delta
        .relation_deltas
        .iter()
        .filter(|change| change_id(change) == id);
    let found = changes.next();
    if changes.next().is_some() {
        return Err(invalid("duplicate staged relation identity"));
    }
    Ok(match found {
        Some(RelationDelta::Added { new } | RelationDelta::Modified { new, .. }) => {
            Some(new.clone())
        }
        Some(RelationDelta::Removed { .. }) => None,
        None => old,
    })
}

/// Compose into the original graph precondition, never append a second claim
/// for a debt/relation identity already changed by the standard settle pass.
fn set_final(
    old: Option<Relation>,
    new: Option<Relation>,
    delta: &mut TransactionDelta,
) -> Result<()> {
    let id = old
        .as_ref()
        .or(new.as_ref())
        .ok_or_else(|| invalid("empty relation transition"))?
        .id;
    if new.as_ref().is_some_and(|relation| relation.id != id) {
        return Err(invalid("relation identity changed"));
    }
    for change in delta
        .relation_deltas
        .iter()
        .filter(|change| change_id(change) == id)
    {
        let expected = match change {
            RelationDelta::Added { .. } => None,
            RelationDelta::Modified { old, .. } | RelationDelta::Removed { old } => Some(old),
        };
        if expected != old.as_ref() {
            return Err(invalid("staged original relation disagrees with graph"));
        }
    }
    delta
        .relation_deltas
        .retain(|change| change_id(change) != id);
    match (old, new) {
        (Some(old), Some(new)) if old != new => delta
            .relation_deltas
            .push(RelationDelta::Modified { old, new }),
        (None, Some(new)) => delta.relation_deltas.push(RelationDelta::Added { new }),
        (Some(old), None) => delta.relation_deltas.push(RelationDelta::Removed { old }),
        _ => {}
    }
    Ok(())
}

fn entity<G: GraphStore>(
    graph: &G,
    id: EntityId,
    delta: &TransactionDelta,
) -> Result<Option<Entity>> {
    for change in &delta.entity_deltas {
        match change {
            kin_model::EntityDelta::Added { new }
            | kin_model::EntityDelta::Modified { new, .. }
                if new.id == id =>
            {
                return Ok(Some(new.clone()))
            }
            kin_model::EntityDelta::Removed { old } if old.id == id => return Ok(None),
            _ => {}
        }
    }
    graph
        .get_entity(&id)
        .map_err(|e| ReconcileError::Graph(e.to_string()))
}

fn artifact<G: GraphStore>(
    graph: &G,
    file: &FilePathId,
) -> Result<Option<(kin_model::ArtifactId, kin_model::Hash256)>> {
    let path = RepoPath::from_utf8(file.0.clone()).map_err(invalid)?;
    let Some(id) = graph.artifact_id_at_path(&path) else {
        return Ok(None);
    };
    Ok(
        match graph
            .get_tree_entry(file)
            .map_err(|e| ReconcileError::Graph(e.to_string()))?
        {
            Some(TreeEntry::Blob { hash, .. }) => Some((id, hash)),
            _ => None,
        },
    )
}

fn exact<G: GraphStore>(
    graph: &G,
    id: RelationId,
    delta: &TransactionDelta,
) -> Result<Option<Relation>> {
    effective(crate::binding_debt::exact(graph, id)?, id, delta)
}

fn held<G: GraphStore>(
    graph: &G,
    id: kin_model::ArtifactId,
    delta: &TransactionDelta,
) -> Result<Vec<Relation>> {
    let original = crate::binding_debt::held(graph, id)?;
    let mut ids: HashSet<_> = original.iter().map(|relation| relation.id).collect();
    ids.extend(
        delta
            .relation_deltas
            .iter()
            .filter_map(|change| match change {
                RelationDelta::Added { new } | RelationDelta::Modified { new, .. }
                    if new.src == GraphNodeId::Artifact(id) =>
                {
                    Some(new.id)
                }
                _ => None,
            }),
    );
    ids.into_iter()
        .map(|key| effective(original.iter().find(|r| r.id == key).cloned(), key, delta))
        .collect::<Result<Vec<_>>>()
        .map(|rows| rows.into_iter().flatten().collect())
}

/// Return all occurrences only for a complete canonical factory-owned edge.
/// An arbitrary inferred confidence, name or absent result is never ownership.
fn owned_occurrences<'a>(
    relation: &Relation,
    source: &IndexedFile,
    target_file: &str,
    observations: &'a [NamedImportObservation],
) -> Result<Option<Vec<&'a NamedImportObservation>>> {
    let Some(evidence_records) = kin_index::occurrence::uniform_original_evidence(relation) else {
        return Ok(None);
    };
    if !kin_index::linker::has_named_import_factory_identity(relation)
        || relation.origin != RelationOrigin::Inferred
        || relation.confidence.to_bits() != 0.95_f32.to_bits()
        || !matches!(
            relation.kind,
            RelationKind::Calls | RelationKind::References
        )
        || relation.import_source.is_some()
        || evidence_records.is_empty()
        || evidence_records
            .iter()
            .any(|e| e.token.is_none() || e.source_path.is_none() || e.resolved_path.is_none())
    {
        return Ok(None);
    }
    let extraction_complete = !source
        .extracted_relations
        .iter()
        .any(kin_parser::is_call_extraction_incomplete_marker);
    let mut selected = Vec::new();
    let mut sites = HashSet::new();
    for evidence in evidence_records {
        let candidates: Vec<_> = observations
            .iter()
            .filter(|observation| {
                relation.src.as_entity() == Some(observation.source)
                    && observation.raw.kind == relation.kind
                    && named_import_evidence(
                        &observation.raw,
                        &source.file_id,
                        target_file,
                        &ParseCompleteness::Full,
                        extraction_complete,
                    )
                    .as_slice()
                        == std::slice::from_ref(evidence)
            })
            .collect();
        let [observation] = candidates.as_slice() else {
            return Ok(None);
        };
        let Some(span) = &evidence.source_span else {
            return Ok(None);
        };
        if !sites.insert((span.start_byte, span.end_byte)) || evidence.occurrence_count != 1 {
            return Err(invalid("duplicate exact-import occurrence"));
        }
        selected.push(*observation);
    }
    Ok(Some(selected))
}

/// Validate exactly the assumptions consumed by a published or withdrawn
/// exact derivation, not unrelated unresolved external imports.
fn validate_observation<G: GraphStore>(
    graph: &G,
    observation: &NamedImportObservation,
    delta: &TransactionDelta,
) -> Result<()> {
    if let Some(expected) = observation.rust_project_tree {
        let tree = graph
            .resolved_tree_snapshot()
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
            .ok_or_else(|| {
                invalid("selected tree inventory is unavailable for Rust project authority")
            })?;
        let actual = kin_index::rust_project::selected_tree_digest(&tree).map_err(invalid)?;
        if actual != expected {
            return Err(invalid(
                "Rust project inventory differs from selected admitted tree",
            ));
        }
    }
    for (candidate, expected) in &observation.candidate_presence {
        let actual = graph
            .get_tree_entry(&FilePathId::new(candidate))
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
            .is_some();
        if actual != *expected {
            return Err(invalid(
                "module candidate inventory differs from admitted tree",
            ));
        }
    }
    for (file, expected) in &observation.source_bindings {
        let (_, actual) = artifact(graph, &FilePathId::new(file))?
            .ok_or_else(|| invalid("witnessed source is no longer admitted"))?;
        if actual.to_string() != *expected {
            return Err(invalid(
                "cached import witness differs from admitted source",
            ));
        }
    }
    for id in std::iter::once(observation.source).chain(observation.target) {
        let endpoint = entity(graph, id, delta)?
            .ok_or_else(|| invalid("witnessed endpoint is not admitted"))?;
        let file = endpoint
            .file_origin
            .as_ref()
            .ok_or_else(|| invalid("witnessed endpoint has no source"))?;
        let expected = observation
            .source_bindings
            .get(&file.0)
            .ok_or_else(|| invalid("witnessed endpoint lacks exact body evidence"))?;
        if endpoint
            .metadata
            .extra
            .get("blob_hash")
            .and_then(|value| value.as_str())
            != Some(expected.as_str())
        {
            return Err(invalid(
                "cached import endpoint differs from admitted declaration",
            ));
        }
    }
    Ok(())
}

fn accepted<G: GraphStore>(
    graph: &G,
    source: &IndexedFile,
    observation: &NamedImportObservation,
    produced: &[Relation],
    delta: &TransactionDelta,
) -> Result<bool> {
    validate_observation(graph, observation, delta)?;
    let Some(target) = observation.target else {
        return Ok(false);
    };
    let destination = entity(graph, target, delta)?
        .ok_or_else(|| invalid("exact replacement endpoint is not admitted"))?;
    let file = destination
        .file_origin
        .ok_or_else(|| invalid("exact replacement has no source"))?;
    let expected = named_import_evidence(
        &observation.raw,
        &source.file_id,
        &file.0,
        &ParseCompleteness::Full,
        !source
            .extracted_relations
            .iter()
            .any(kin_parser::is_call_extraction_incomplete_marker),
    );
    let matches = produced.iter().any(|relation| {
        relation.src.as_entity() == Some(observation.source)
            && relation.dst.as_entity() == Some(target)
            && relation.kind == observation.raw.kind
            && relation.origin == RelationOrigin::Inferred
            && relation.confidence.to_bits() == 0.95_f32.to_bits()
            && relation.import_source.is_none()
            && !expected.is_empty()
            && expected
                .iter()
                .all(|evidence| relation.evidence.contains(evidence))
    });
    let accepted_relation = produced.iter().find(|relation| {
        relation.src.as_entity() == Some(observation.source)
            && relation.dst.as_entity() == Some(target)
            && relation.kind == observation.raw.kind
    });
    let remains = if let Some(relation) = accepted_relation {
        effective(
            crate::binding_debt::exact(graph, relation.id)?,
            relation.id,
            delta,
        )?
        .is_some_and(|final_relation| expected.iter().all(|e| final_relation.evidence.contains(e)))
    } else {
        false
    };
    if !matches || !remains {
        return Err(invalid(
            "resolved exact occurrence was not admitted in this transaction",
        ));
    }
    Ok(true)
}

/// A repeated exact named-import payload is fresh evidence only when every
/// original occurrence is independently resolved again against the admitted
/// source and target bodies, and that exact payload is staged for publication.
/// A confidence value or a remembered factory certificate alone is not enough.
pub(crate) fn independently_reproves<G: GraphStore>(
    graph: &G,
    source: &IndexedFile,
    retired: &Relation,
    observations: &[NamedImportObservation],
    delta: &TransactionDelta,
) -> Result<bool> {
    let Some(current) = exact(graph, retired.id, delta)? else {
        return Ok(false);
    };
    if !crate::binding_debt::repeats_withdrawn_guess(&current, retired) {
        return Ok(false);
    }
    let Some(target) = current.dst.as_entity() else {
        return Ok(false);
    };
    let Some(target) = entity(graph, target, delta)? else {
        return Ok(false);
    };
    let Some(target_file) = target.file_origin else {
        return Ok(false);
    };
    let Some(sites) = owned_occurrences(&current, source, &target_file.0, observations)? else {
        return Ok(false);
    };
    if sites
        .iter()
        .any(|site| site.target != current.dst.as_entity())
    {
        return Ok(false);
    }
    for site in sites {
        if !accepted(graph, source, site, std::slice::from_ref(&current), delta)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Run after ordinary settlement. Inputs are freshly reparsed unchanged sources
/// and the actual admitted relation overlay from this transaction, not raw
/// linker candidates. Every error refuses the entire unpublished delta.
pub(crate) fn refresh<G: GraphStore>(
    graph: &G,
    sources: &[IndexedFile],
    observations: &[NamedImportObservation],
    produced: &[Relation],
    delta: &mut TransactionDelta,
) -> Result<()> {
    // Positive exact facts always need publication authority. An unproven
    // site is checked below only if this helper uses it to withdraw its own
    // prior local proof; unrelated external placeholders keep their contract.
    for observation in observations
        .iter()
        .filter(|observation| observation.target.is_some())
    {
        validate_observation(graph, observation, delta)?;
    }
    let mut unresolved_withdrawals = Vec::new();
    for source in sources {
        let (_, digest) = artifact(graph, &source.file_id)?
            .ok_or_else(|| invalid("caller lost its admitted source"))?;
        if digest != source.blob_hash {
            return Err(invalid("caller body changed during rederivation"));
        }
        for caller in &source.entities {
            if graph
                .get_entity(&caller.id)
                .map_err(|e| ReconcileError::Graph(e.to_string()))?
                .as_ref()
                != Some(caller)
            {
                return Err(invalid("caller declaration changed during rederivation"));
            }
            let old = graph
                .get_all_relations_for_entity(&caller.id)
                .map_err(|e| ReconcileError::Graph(e.to_string()))?;
            for relation in old
                .into_iter()
                .filter(|relation| relation.src.as_entity() == Some(caller.id))
            {
                let Some(target) = relation.dst.as_entity() else {
                    continue;
                };
                let Some(target) = graph
                    .get_entity(&target)
                    .map_err(|e| ReconcileError::Graph(e.to_string()))?
                else {
                    continue;
                };
                let Some(file) = target.file_origin else {
                    continue;
                };
                let Some(sites) = owned_occurrences(&relation, source, &file.0, observations)?
                else {
                    continue;
                };
                let mut unresolved = false;
                let mut retained = Vec::new();
                for site in sites {
                    if !accepted(graph, source, site, produced, delta)? {
                        unresolved = true;
                    }
                    if site.target == relation.dst.as_entity() {
                        retained.extend(named_import_evidence(
                            &site.raw,
                            &source.file_id,
                            &file.0,
                            &ParseCompleteness::Full,
                            !source
                                .extracted_relations
                                .iter()
                                .any(kin_parser::is_call_extraction_incomplete_marker),
                        ));
                    }
                }
                if Some(retained.len())
                    == kin_index::occurrence::uniform_original_evidence(&relation)
                        .map(|records| records.len())
                {
                    continue;
                }
                if unresolved {
                    unresolved_withdrawals.push(relation.clone());
                }
                // A relation may lose every OLD site while acquiring another
                // current one (e.g. two aliases swap targets). Preserve the
                // complete accepted current payload, not a subset of old sites.
                let replacement = produced
                    .iter()
                    .find(|fresh| {
                        fresh.id == relation.id
                            && fresh.src == relation.src
                            && fresh.dst == relation.dst
                            && fresh.kind == relation.kind
                    })
                    .cloned()
                    .map(|mut fresh| {
                        fresh.created_in = relation.created_in;
                        fresh
                    });
                set_final(Some(relation), replacement, delta)?;
            }
        }

        // Generic settlement deliberately requires the previous local target.
        // Only this exact factory's source-bound rederivation may also justify
        // a changed re-export destination on an unchanged caller body.
        let (artifact_id, _) =
            artifact(graph, &source.file_id)?.ok_or_else(|| invalid("caller artifact missing"))?;
        let reserved = kin_index::binding_debt::local_binding_debt_id(artifact_id);
        for relation in held(graph, artifact_id, delta)? {
            let Some(mut debt) = decode_local_binding_debt(&source.file_id, artifact_id, &relation)
                .map_err(invalid)?
            else {
                continue;
            };
            let before = debt.obligations.len();
            let mut remaining = Vec::new();
            for obligation in debt.obligations {
                if obligation.source_digest != digest
                    || obligation
                        .prior_source_file
                        .as_ref()
                        .is_some_and(|file| file != &source.file_id)
                {
                    remaining.push(obligation);
                    continue;
                }
                let Some(sites) = owned_occurrences(
                    &obligation.retired_relation,
                    source,
                    &obligation.target_file.0,
                    observations,
                )?
                else {
                    remaining.push(obligation);
                    continue;
                };
                let mut proven = true;
                for site in sites {
                    proven &= accepted(graph, source, site, produced, delta)?;
                }
                if !proven {
                    remaining.push(obligation);
                }
            }
            if remaining.len() != before {
                debt.obligations = remaining;
                let new = if debt.obligations.is_empty() {
                    None
                } else {
                    let mut new = build_local_binding_debt(artifact_id, debt).map_err(invalid)?;
                    new.created_in = relation.created_in;
                    Some(new)
                };
                set_final(crate::binding_debt::exact(graph, reserved)?, new, delta)?;
            }
        }
    }
    // A later withdrawal can be an exact subset of an obligation already
    // retained for this same source body and factory ID. Keep the original
    // immutable retired payload; do not replace it with the reduced live edge
    // or waive an arbitrary identity collision/new provenance.
    for withdrawal in &mut unresolved_withdrawals {
        let withdrawal_id = withdrawal.id;
        let Some(source) = sources.iter().find(|source| {
            source
                .entities
                .iter()
                .any(|entity| withdrawal.src.as_entity() == Some(entity.id))
        }) else {
            return Err(invalid("withdrawn source observation is missing"));
        };
        let (artifact_id, digest) = artifact(graph, &source.file_id)?
            .ok_or_else(|| invalid("withdrawn source artifact is missing"))?;
        for relation in held(graph, artifact_id, delta)? {
            let Some(debt) = decode_local_binding_debt(&source.file_id, artifact_id, &relation)
                .map_err(invalid)?
            else {
                continue;
            };
            for prior in debt
                .obligations
                .iter()
                .filter(|old| old.retired_relation.id == withdrawal_id)
            {
                if prior.source_digest != digest
                    || prior
                        .prior_source_file
                        .as_ref()
                        .is_some_and(|file| file != &source.file_id)
                    || owned_occurrences(
                        &prior.retired_relation,
                        source,
                        &prior.target_file.0,
                        observations,
                    )?
                    .is_none()
                {
                    return Err(invalid(
                        "prior factory obligation has different source provenance",
                    ));
                }
                let mut comparable = withdrawal.clone();
                comparable.evidence = prior.retired_relation.evidence.clone();
                if comparable != prior.retired_relation
                    || !withdrawal
                        .evidence
                        .iter()
                        .all(|evidence| prior.retired_relation.evidence.contains(evidence))
                {
                    return Err(invalid(
                        "prior factory obligation does not cover this exact withdrawal",
                    ));
                }
                *withdrawal = prior.retired_relation.clone();
            }
        }
    }
    let planned = crate::coverage::plan_withdrawn_local_binding_obligations(
        &unresolved_withdrawals,
        |id| {
            graph
                .get_entity(&id)
                .map_err(|e| ReconcileError::Graph(e.to_string()))
        },
        |file| artifact(graph, file),
        |id| held(graph, id, delta),
        |id| exact(graph, id, delta),
    )?;
    for change in planned {
        let id = change_id(&change);
        let new = match change {
            RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => Some(new),
            RelationDelta::Removed { .. } => None,
        };
        set_final(crate::binding_debt::exact(graph, id)?, new, delta)?;
    }
    Ok(())
}

/// Stage only canonical exact named-import derivations whose every occurrence
/// has a current admitted source/target observation. Foreign/legacy occupants
/// of the same relation identity are never silently rewritten.
pub(crate) fn stage_project_derivations<G: GraphStore>(
    graph: &G,
    sources: &[IndexedFile],
    observations: &[NamedImportObservation],
    linked: &[Relation],
    delta: &mut TransactionDelta,
) -> Result<Vec<Relation>> {
    let mut accepted = Vec::new();
    for relation in linked {
        let (Some(source_id), Some(target_id)) =
            (relation.src.as_entity(), relation.dst.as_entity())
        else {
            continue;
        };
        if !observations.iter().any(|site| {
            site.source == source_id
                && site.target == Some(target_id)
                && site.raw.kind == relation.kind
        }) {
            continue;
        }
        let Some(source) = sources
            .iter()
            .find(|source| source.entities.iter().any(|entity| entity.id == source_id))
        else {
            return Err(invalid("project caller was not rederived"));
        };
        let target = graph
            .get_entity(&target_id)
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
            .ok_or_else(|| invalid("project target is not admitted"))?;
        let file = target
            .file_origin
            .as_ref()
            .ok_or_else(|| invalid("project target has no source"))?;
        let Some(sites) = owned_occurrences(relation, source, &file.0, observations)? else {
            return Err(invalid(
                "project derivation is not canonical exact occurrence evidence",
            ));
        };
        for site in sites {
            validate_observation(graph, site, delta)?;
        }
        let old = match graph
            .lookup_relation_by_id(&relation.id)
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
        {
            kin_model::RelationLookup::Unavailable => {
                return Err(invalid("project relation identity lookup unavailable"))
            }
            kin_model::RelationLookup::Absent => None,
            kin_model::RelationLookup::Present(old) => Some(old),
        };
        if old.as_ref().is_some_and(|old| old != relation) {
            let previous = old.as_ref().unwrap();
            if owned_occurrences(previous, source, &file.0, observations)?.is_none() {
                return Err(invalid(
                    "project derivation identity has unrecognized held provenance",
                ));
            }
        }
        let mut fresh = relation.clone();
        if let Some(old) = &old {
            fresh.created_in = old.created_in;
        }
        set_final(old, Some(fresh.clone()), delta)?;
        accepted.push(fresh);
    }
    Ok(accepted)
}
