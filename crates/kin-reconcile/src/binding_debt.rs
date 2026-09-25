// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::error::{ReconcileError, Result};
use kin_index::{
    binding_debt::{build_local_binding_debt, decode_local_binding_debt},
    IndexedFile,
};
use kin_model::{Entity, EntityId, GraphNodeId, GraphStore, Relation, RelationDelta};

fn invalid(reason: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("local binding obligation: {reason}"))
}

pub(crate) fn exact<G: GraphStore>(
    graph: &G,
    id: kin_model::RelationId,
) -> Result<Option<Relation>> {
    match graph
        .lookup_relation_by_id(&id)
        .map_err(|error| ReconcileError::Graph(error.to_string()))?
    {
        kin_model::RelationLookup::Unavailable => {
            Err(invalid("exact relation identity lookup is unavailable"))
        }
        kin_model::RelationLookup::Absent => Ok(None),
        kin_model::RelationLookup::Present(relation) if relation.id == id => Ok(Some(relation)),
        kin_model::RelationLookup::Present(_) => {
            Err(invalid("exact lookup returned another relation identity"))
        }
    }
}

pub(crate) fn held<G: GraphStore>(
    graph: &G,
    artifact: kin_model::ArtifactId,
) -> Result<Vec<Relation>> {
    let reserved = kin_index::binding_debt::local_binding_debt_id(artifact);
    let occupant = exact(graph, reserved)?;
    let mut held = graph
        .traverse(&GraphNodeId::Artifact(artifact), &[], 1)
        .map_err(|error| ReconcileError::Graph(error.to_string()))?
        .relations;
    if let Some(found) = held.iter().find(|relation| relation.id == reserved) {
        if occupant.as_ref() != Some(found) {
            return Err(invalid(
                "exact identity read disagrees with source evidence",
            ));
        }
    } else if let Some(occupant) = occupant {
        held.push(occupant);
    }
    Ok(held)
}

/// A complete parse may retain an obligation, but only current source plus a
/// real matching local binding (or proven removal of the old occurrence) clears
/// it. The returned changes publish beside the corresponding source/edge delta.
pub(crate) fn settle<G: GraphStore>(
    graph: &G,
    blobs: &kin_blobs::BlobStore,
    current: &IndexedFile,
    current_entities: &[Entity],
    produced: &[Relation],
    mut target: impl FnMut(EntityId) -> Result<Option<Entity>>,
) -> Result<Vec<RelationDelta>> {
    let Some(artifact) = crate::coverage::admitted_artifact(graph, current)? else {
        return Ok(vec![]);
    };
    let held = held(graph, artifact)?;
    let reserved = kin_index::binding_debt::local_binding_debt_id(artifact);
    let mut prior = None;
    for relation in held.iter().filter(|relation| {
        relation.src == GraphNodeId::Artifact(artifact) || relation.id == reserved
    }) {
        if let Some(debt) =
            decode_local_binding_debt(&current.file_id, artifact, relation).map_err(invalid)?
        {
            if prior.is_some() {
                return Err(invalid("multiple records claim this source"));
            }
            prior = Some((relation.clone(), debt));
        }
    }
    let Some((old_relation, mut debt)) = prior else {
        return Ok(vec![]);
    };
    if !matches!(current.parse_state, kin_model::ParseState::Valid) {
        return Ok(vec![]);
    }
    let mut remaining = Vec::new();
    for obligation in debt.obligations {
        let digest =
            kin_blobs::Hash256::from_hex(&obligation.source_digest.to_string()).map_err(invalid)?;
        let bytes = blobs.read(&digest)?;
        if kin_blobs::digest(&bytes) != digest {
            return Err(invalid("prior source digest mismatch"));
        }
        let old = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(
                obligation
                    .prior_source_file
                    .as_ref()
                    .unwrap_or(&current.file_id),
                &bytes,
                digest,
            )?
            .indexed_file;
        if !matches!(old.parse_state, kin_model::ParseState::Valid) {
            return Err(invalid(
                "prior local relation source does not parse completely",
            ));
        }
        if !kin_index::binding_debt::obligation_is_satisfied(
            graph,
            artifact,
            &obligation,
            &old,
            &bytes,
            current,
            current_entities,
            produced,
            &mut |id| target(id).map_err(|error| error.to_string()),
        )
        .map_err(invalid)?
        {
            remaining.push(obligation);
        }
    }
    if remaining.is_empty() {
        return Ok(vec![RelationDelta::Removed { old: old_relation }]);
    }
    debt.obligations = remaining;
    debt.observed_source_digest = kin_model::Hash256::from_bytes(current.blob_hash.0);
    let mut new = build_local_binding_debt(artifact, debt).map_err(invalid)?;
    new.created_in = old_relation.created_in;
    Ok(if new == old_relation {
        vec![]
    } else {
        vec![RelationDelta::Modified {
            old: old_relation,
            new,
        }]
    })
}
