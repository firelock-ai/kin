// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact admission and withdrawal of the parser's current-file certificate.

use crate::error::{ReconcileError, Result};
use kin_index::IndexedFile;
use kin_model::{
    ArtifactId, FilePathId, GraphNodeId, GraphStore, Relation, RelationDelta, RepoPath, TreeEntry,
};

fn invalid(reason: &str) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("parse coverage authority: {reason}"))
}

pub(crate) fn admitted_artifact<G: GraphStore>(
    graph: &G,
    indexed: &IndexedFile,
) -> Result<Option<ArtifactId>> {
    let path =
        RepoPath::from_utf8(indexed.file_id.0.clone()).map_err(|e| invalid(&e.to_string()))?;
    let entry = graph
        .get_tree_entry(&indexed.file_id)
        .map_err(|e| ReconcileError::Graph(e.to_string()))?;
    let id = graph.artifact_id_at_path(&path);
    match (entry, id) {
        (None, None) => Ok(None),
        (Some(TreeEntry::Blob { hash, .. }), Some(id))
            if hash.to_string() == indexed.blob_hash.to_string() =>
        {
            Ok(Some(id))
        }
        _ => Err(invalid(
            "indexed bytes are not the admitted file version or artifact identity",
        )),
    }
}

fn claims_coverage(relation: &Relation) -> bool {
    relation.evidence.iter().any(|e| {
        matches!(
            e.parser_rule.as_deref(),
            Some(
                kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1
                    | kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
                    | kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1
                    | kin_index::IMPORT_RESOLUTION_COVERAGE_V1
            )
        )
    })
}

pub(crate) fn reconcile<G: GraphStore>(
    graph: &G,
    file: &FilePathId,
    artifact: ArtifactId,
    current: Option<Relation>,
) -> Result<Vec<RelationDelta>> {
    if current
        .as_ref()
        .is_some_and(|r| !kin_index::is_parse_coverage_relation(r, &file.0, artifact))
    {
        return Err(invalid(
            "fresh certificate does not match the shared factory",
        ));
    }
    reconcile_with(file, artifact, current, || {
        graph
            .traverse(&GraphNodeId::Artifact(artifact), &[], 1)
            .map(|subgraph| subgraph.relations)
            .map_err(|e| ReconcileError::Graph(e.to_string()))
    })
}

fn reconcile_with(
    file: &FilePathId,
    artifact: ArtifactId,
    mut current: Option<Relation>,
    read: impl FnOnce() -> Result<Vec<Relation>>,
) -> Result<Vec<RelationDelta>> {
    let node = GraphNodeId::Artifact(artifact);
    let held = read()?;
    let mut previous = None;
    for relation in held {
        let same_id = current.as_ref().is_some_and(|r| r.id == relation.id);
        if !same_id && !claims_coverage(&relation) {
            continue;
        }
        // Incoming evidence about a different source is not owned by this file.
        if relation.src != node && !same_id {
            continue;
        }
        // A certificate an earlier build minted for this artifact is the
        // factory's own, in an older shape, and this derivation replaces it.
        // A store an older build wrote holds one for every file it parsed.
        if !kin_index::is_parse_coverage_relation(&relation, &file.0, artifact)
            && !kin_index::is_superseded_parse_coverage_relation(&relation, &file.0, artifact)
        {
            return Err(invalid(
                "stored certificate is malformed or its identity is occupied",
            ));
        }
        if previous.replace(relation).is_some() {
            return Err(invalid("multiple stored certificates claim this artifact"));
        }
    }
    if let (Some(old), Some(new)) = (&previous, &mut current) {
        new.created_in = old.created_in;
    }
    Ok(match (previous, current) {
        (Some(old), Some(new)) if old == new => vec![],
        (Some(old), Some(new)) => vec![RelationDelta::Modified { old, new }],
        (Some(old), None) => vec![RelationDelta::Removed { old }],
        (None, Some(new)) => vec![RelationDelta::Added { new }],
        (None, None) => vec![],
    })
}

/// Record prior local bindings before their destination is removed. The
/// surviving source's parse coverage stays independent of these obligations.
pub fn plan_local_binding_obligations(
    departing: &std::collections::HashSet<kin_model::EntityId>,
    incident: &[Relation],
    entity: impl FnMut(kin_model::EntityId) -> Result<Option<kin_model::Entity>>,
    artifact: impl FnMut(&FilePathId) -> Result<Option<(ArtifactId, kin_model::Hash256)>>,
    held_at: impl FnMut(ArtifactId) -> Result<Vec<Relation>>,
    exact: impl FnMut(kin_model::RelationId) -> Result<Option<Relation>>,
) -> Result<Vec<RelationDelta>> {
    let selected: Vec<_> = incident
        .iter()
        .filter(|relation| {
            relation
                .dst
                .as_entity()
                .is_some_and(|id| departing.contains(&id))
                && relation
                    .src
                    .as_entity()
                    .is_some_and(|id| !departing.contains(&id))
        })
        .cloned()
        .collect();
    plan_withdrawn_local_binding_obligations(&selected, entity, artifact, held_at, exact)
}

pub(crate) fn plan_withdrawn_local_binding_obligations(
    incident: &[Relation],
    mut entity: impl FnMut(kin_model::EntityId) -> Result<Option<kin_model::Entity>>,
    mut artifact: impl FnMut(&FilePathId) -> Result<Option<(ArtifactId, kin_model::Hash256)>>,
    mut held_at: impl FnMut(ArtifactId) -> Result<Vec<Relation>>,
    mut exact: impl FnMut(kin_model::RelationId) -> Result<Option<Relation>>,
) -> Result<Vec<RelationDelta>> {
    use kin_index::binding_debt::{
        build_local_binding_debt, decode_local_binding_debt, LocalBindingDebt,
        LocalBindingObligation,
    };
    let mut sources: std::collections::BTreeMap<String, (ArtifactId, LocalBindingDebt)> =
        Default::default();
    for relation in incident {
        let Some(target_id) = relation.dst.as_entity() else {
            continue;
        };
        let Some(source_id) = relation.src.as_entity() else {
            continue;
        };
        let source =
            entity(source_id)?.ok_or_else(|| invalid("surviving relation source missing"))?;
        let target =
            entity(target_id)?.ok_or_else(|| invalid("departing relation target missing"))?;
        let (Some(source_file), Some(target_file)) = (source.file_origin, target.file_origin)
        else {
            continue;
        };
        if source_file == target_file {
            continue;
        }
        let (source_artifact, source_digest) = artifact(&source_file)?
            .ok_or_else(|| invalid("surviving source has no admitted blob"))?;
        let (target_artifact, _) = artifact(&target_file)?
            .ok_or_else(|| invalid("departing target has no admitted blob"))?;
        if source
            .metadata
            .extra
            .get("blob_hash")
            .and_then(|value| value.as_str())
            != Some(source_digest.to_string().as_str())
        {
            return Err(invalid("prior local binding source is not current"));
        }
        let (_, debt) = sources.entry(source_file.0.clone()).or_insert_with(|| {
            (
                source_artifact,
                LocalBindingDebt {
                    source_file,
                    observed_source_digest: source_digest,
                    obligations: vec![],
                },
            )
        });
        if !debt
            .obligations
            .iter()
            .any(|old| old.retired_relation.id == relation.id)
        {
            debt.obligations.push(LocalBindingObligation {
                retired_relation: relation.clone(),
                source_name: source.name,
                source_digest,
                prior_source_file: None,
                target_artifact,
                target_file,
                target_name: target.name,
            });
        }
    }
    let mut changes = Vec::new();
    for (_, (artifact, mut debt)) in sources {
        let mut old = None;
        let reserved = kin_index::binding_debt::local_binding_debt_id(artifact);
        let mut held = held_at(artifact)?;
        let occupant = exact(reserved)?;
        if let Some(found) = held.iter().find(|relation| relation.id == reserved) {
            if occupant.as_ref() != Some(found) {
                return Err(invalid(
                    "binding debt exact identity read disagrees with source evidence",
                ));
            }
        } else if let Some(occupant) = occupant {
            held.push(occupant);
        }
        for relation in held {
            if relation.src != GraphNodeId::Artifact(artifact) && relation.id != reserved {
                continue;
            }
            if let Some(held) = decode_local_binding_debt(&debt.source_file, artifact, &relation)
                .map_err(|error| invalid(&error))?
            {
                if old.is_some() || held.observed_source_digest != debt.observed_source_digest {
                    return Err(invalid("prior binding debt is duplicated or stale"));
                }
                for obligation in held.obligations {
                    if let Some(new) = debt
                        .obligations
                        .iter()
                        .find(|new| new.retired_relation.id == obligation.retired_relation.id)
                    {
                        if new != &obligation {
                            return Err(invalid("binding obligation identity collision"));
                        }
                    } else {
                        debt.obligations.push(obligation);
                    }
                }
                old = Some(relation);
            }
        }
        let mut new = build_local_binding_debt(artifact, debt).map_err(|error| invalid(&error))?;
        if let Some(old) = old {
            new.created_in = old.created_in;
            if new != old {
                changes.push(RelationDelta::Modified { old, new });
            }
        } else {
            changes.push(RelationDelta::Added { new });
        }
    }
    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn graph_read_error_refuses_admission_and_withdrawal() {
        let file = FilePathId::new("app.py");
        let artifact = ArtifactId::new();
        let current = kin_index::build_parse_coverage_relation(
            &kin_index::FileParseData {
                file_path: file.0.clone(),
                entities: vec![],
                relations: vec![],
                imports: vec![],
            },
            artifact,
            &kin_model::ParseCompleteness::Full,
            &HashSet::<String>::new(),
        );
        for candidate in [Some(current), None] {
            let error = reconcile_with(&file, artifact, candidate, || {
                Err(ReconcileError::Graph("injected held coverage read".into()))
            })
            .unwrap_err();
            assert!(matches!(error, ReconcileError::Graph(_)));
        }
    }
}
