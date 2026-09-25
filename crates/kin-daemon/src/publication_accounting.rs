// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A response projection, never part of a retained mutation receipt or its proof.
//! The change records parent -> result; the operation records workspace -> result.
//! Their complete values distinguish pending state from publication transitions
//! without consulting a later graph, an audit window, or source materialization.

use std::collections::BTreeMap;
use std::fmt::Display;

use kin_model::{
    RefTarget, SemanticChange, SemanticChangeId, WorkspaceExpectation, WorkspaceMutation,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::repository_commit::NativeCommitResult;

const ID_SAMPLE_LIMIT: usize = 3;

#[derive(Default, Serialize)]
struct IdentityCount {
    count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sample_ids: Vec<String>,
}

impl IdentityCount {
    fn record(&mut self, id: &impl Display, sample: bool) {
        self.count += 1;
        if sample && self.sample_ids.len() < ID_SAMPLE_LIMIT {
            self.sample_ids.push(id.to_string());
        }
    }
}

#[derive(Default, Serialize)]
struct Transitions {
    published_total: usize,
    publication_only: IdentityCount,
    carried_unchanged: IdentityCount,
    pending_and_publication: IdentityCount,
    // These undo pending state to the parent's value and do not occur in the
    // published delta. Do not count them a second time in published_total.
    workspace_only: IdentityCount,
}

fn transitions<'a, K: Ord + Display, T: PartialEq + 'a>(
    published: impl IntoIterator<Item = (K, Option<&'a T>, Option<&'a T>)>,
    workspace: impl IntoIterator<Item = (K, Option<&'a T>, Option<&'a T>)>,
    sample: bool,
) -> Result<Transitions, &'static str> {
    let mut changes = BTreeMap::new();
    for (id, old, new) in workspace {
        if old == new || changes.insert(id, (old, new)).is_some() {
            return Err("noncanonical workspace transition");
        }
    }
    // Sorting gives stable compact examples even for a historical delta whose
    // original serialization order differs. Reject duplicates, never hide them.
    let mut published_by_id = BTreeMap::new();
    for (id, old, new) in published {
        if old == new || published_by_id.insert(id, (old, new)).is_some() {
            return Err("noncanonical published transition");
        }
    }
    let mut result = Transitions::default();
    for (id, (parent, final_value)) in published_by_id {
        let before = match changes.remove(&id) {
            Some((before, after)) if after == final_value => before,
            Some(_) => return Err("workspace and change disagree about the published value"),
            None => final_value,
        };
        result.published_total += 1;
        if before == parent {
            result.publication_only.record(&id, sample);
        } else if before == final_value {
            result.carried_unchanged.record(&id, sample);
        } else {
            result.pending_and_publication.record(&id, sample);
        }
    }
    for id in changes.keys() {
        result.workspace_only.record(id, sample);
    }
    Ok(result)
}

fn classified(
    change: &SemanticChange,
    workspace: Option<&WorkspaceMutation>,
    resolved_base: Option<SemanticChangeId>,
) -> Result<Value, &'static str> {
    let workspace = workspace.ok_or("publication has no retained workspace transition")?;
    let WorkspaceExpectation::MustEqual { base_target, .. } = &workspace.expected else {
        return Err("publication did not start from an existing bound workspace");
    };
    let parent_matches = match (base_target, change.parents.as_slice()) {
        (None, []) => resolved_base.is_none(),
        (Some(RefTarget::Change { .. } | RefTarget::ExternalObject { .. }), [parent]) => {
            resolved_base == Some(*parent)
        }
        _ => false,
    };
    if !parent_matches || workspace.new_base_target != Some(RefTarget::change(change.id)) {
        return Err("publication does not advance this workspace from the change's parent");
    }
    let entities = transitions(
        change
            .entity_deltas
            .iter()
            .map(|d| (d.target_id(), d.old_state(), d.new_state())),
        workspace
            .semantic_delta
            .entity_deltas()
            .iter()
            .map(|d| (d.target_id(), d.old_state(), d.new_state())),
        true,
    )?;
    let relationships = transitions(
        change
            .relation_deltas
            .iter()
            .map(|d| (d.target_id(), d.old_state(), d.new_state())),
        workspace
            .semantic_delta
            .relation_deltas()
            .iter()
            .map(|d| (d.target_id(), d.old_state(), d.new_state())),
        true,
    )?;
    let source_units = transitions(
        change
            .tree_deltas
            .iter()
            .map(|d| (d.artifact_id().0, d.old_state(), d.new_state())),
        workspace
            .tree_deltas
            .iter()
            .map(|d| (d.artifact_id().0, d.old_state(), d.new_state())),
        false,
    )?;
    Ok(
        json!({"status":"exact", "entities":entities, "relationships":relationships, "source_units":source_units}),
    )
}

fn requested(operations: Option<&Value>) -> Value {
    let Some(operations) = operations else {
        return json!({"status":"unavailable", "reason":"legacy publication does not retain requested target identities"});
    };
    let Ok(operations) = kin_mcp::session::parse_staged_operations(operations) else {
        // An already-published historical request may use a retired syntax.
        // Reporting cannot turn a valid publication into an unapplied failure.
        return json!({"status":"unavailable", "reason":"historical request target syntax is not understood"});
    };
    let sample = operations
        .iter()
        .take(ID_SAMPLE_LIMIT)
        .map(|operation| {
            use kin_mcp::McpMutationPayload as Payload;
            let target = match &operation.payload {
                Some(Payload::EntitySourceBase(base)) => json!({"entity_id":base.entity_id}),
                Some(Payload::EntitySourcePatch(patch)) => {
                    json!({"entity_id":patch.source_base.entity_id})
                }
                Some(Payload::EntityRemove(remove)) => {
                    json!({"entity_id":remove.source_base.entity_id})
                }
                Some(Payload::EntityCreate(create)) => match create.anchor() {
                    Some((source_base, _)) => json!({"anchor_entity_id":source_base.entity_id}),
                    None => json!({"declared_name":create.name}),
                },
                Some(Payload::UnitImports(imports)) => {
                    json!({"unit_package":imports.unit.package_name()})
                }
                Some(Payload::Entity(entity)) => json!({"entity_id":entity.id}),
                Some(Payload::Relation { from, to, kind }) => {
                    json!({"from_entity_id":from, "to_entity_id":to, "relationship_kind":kind})
                }
                None if kin_mcp::session::is_target_body_update(operation) => {
                    match uuid::Uuid::parse_str(&operation.target) {
                        Ok(id) => json!({"entity_id":id}),
                        Err(_) => json!({"identity_status":"not_recorded_in_request"}),
                    }
                }
                None => json!({"identity_status":"historical_payload"}),
                Some(Payload::Blob(_)) => json!({"identity_status":"historical_payload"}),
            };
            json!({"verb":operation.verb.chars().take(32).collect::<String>(), "target":target})
        })
        .collect::<Vec<_>>();
    json!({"status":"verified_request", "operation_count":operations.len(), "sample_operations":sample, "omitted_operations":operations.len().saturating_sub(ID_SAMPLE_LIMIT)})
}

/// `operations` is supplied only after the keyed request's complete hash agrees
/// with its retained binding. Legacy calls pass None even on initial success,
/// so their projection does not change after transaction eviction.
pub(crate) fn project(committed: &NativeCommitResult, operations: Option<&Value>) -> Value {
    let operation = &committed.receipt.operation;
    let consistent = kin_core::published_change(operation)
        .is_some_and(|published| published.change_id == committed.change.id);
    let classified = if consistent {
        classified(
            &committed.change,
            operation.workspace_mutation.as_ref(),
            committed.resolved_publication_base,
        )
    } else {
        Err("operation does not identify this published change")
    };
    let mut result =
        classified.unwrap_or_else(|reason| json!({"status":"unavailable", "reason":reason}));
    result["schema"] = json!("kin.publication_accounting.v1");
    result["requested"] = requested(operations);
    result["meaning"] = json!("Counts compare parent, admitted workspace, and published values; publication transitions include derivation and are not authorship or behavior-change counts. Source-unit transitions independently disclose pending bytes.");
    result["identity_sample_limit"] = json!(ID_SAMPLE_LIMIT);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_separate_clean_pending_and_same_identity_overlap() {
        let (parent, pending, final_value) = (0, 1, 2);
        let summary = transitions(
            [
                (1, Some(&parent), Some(&final_value)),
                (2, Some(&parent), Some(&pending)),
                (3, Some(&parent), Some(&final_value)),
            ],
            [
                (1, Some(&parent), Some(&final_value)),
                (3, Some(&pending), Some(&final_value)),
            ],
            true,
        )
        .unwrap();
        assert_eq!(summary.published_total, 3);
        assert_eq!(summary.publication_only.sample_ids, ["1"]);
        assert_eq!(summary.carried_unchanged.sample_ids, ["2"]);
        assert_eq!(summary.pending_and_publication.sample_ids, ["3"]);
        assert_eq!(summary.workspace_only.count, 0);
    }

    #[test]
    fn transitions_cover_creation_deletion_and_cancelled_pending_work() {
        let (parent, pending) = (0, 1);
        let summary = transitions(
            [
                (1, None, Some(&pending)),
                (2, Some(&parent), None),
                (3, Some(&parent), None),
            ],
            [
                (1, None, Some(&pending)),
                (3, Some(&pending), None),
                (4, Some(&pending), Some(&parent)),
            ],
            true,
        )
        .unwrap();
        assert_eq!(summary.published_total, 3);
        assert_eq!(summary.publication_only.sample_ids, ["1"]);
        assert_eq!(summary.carried_unchanged.sample_ids, ["2"]);
        assert_eq!(summary.pending_and_publication.sample_ids, ["3"]);
        assert_eq!(summary.workspace_only.sample_ids, ["4"]);
    }

    #[test]
    fn transitions_refuse_inconsistent_or_duplicate_evidence() {
        assert!(transitions([(1, Some(&0), Some(&1))], [(1, Some(&0), Some(&2))], true).is_err());
        assert!(transitions([(1, Some(&0), Some(&1)), (1, Some(&0), Some(&1))], [], true).is_err());
        assert!(transitions([], [(1, Some(&0), Some(&1)), (1, Some(&0), Some(&1))], true).is_err());
        assert!(transitions([(1, Some(&0), Some(&0))], [], true).is_err());
    }

    #[test]
    fn large_counts_remain_exact_with_deterministic_bounded_identity_samples() {
        let summary = transitions(
            (0..44_164).rev().map(|id| (id, Some(&0), Some(&1))),
            [],
            true,
        )
        .unwrap();
        assert_eq!(summary.carried_unchanged.count, 44_164);
        assert_eq!(summary.carried_unchanged.sample_ids, ["0", "1", "2"]);
        assert!(serde_json::to_vec(&summary).unwrap().len() < 500);
    }

    #[test]
    fn request_projection_reports_semantic_identity_without_bodies_or_descriptions() {
        let id = uuid::Uuid::new_v4();
        let operations = json!([{"verb":"update","target":id.to_string(),"body":"private source body","description":"private description"}]);
        let projection = requested(Some(&operations));
        assert_eq!(projection["operation_count"], 1);
        assert_eq!(
            projection["sample_operations"][0]["target"]["entity_id"],
            id.to_string()
        );
        assert!(!projection.to_string().contains("private"));
        assert_eq!(requested(None)["status"], "unavailable");
    }

    #[test]
    fn historical_file_names_that_parse_as_uuids_are_not_entity_identities() {
        let id = uuid::Uuid::new_v4().to_string();
        for verb in ["create", "replace", "remove"] {
            let operations = json!([{"verb":verb,"target":id,"body":"historical file body","description":"retired"}]);
            let projection = requested(Some(&operations));
            assert_eq!(
                projection["sample_operations"][0]["target"]["identity_status"],
                "historical_payload"
            );
            assert!(!projection.to_string().contains(&id));
        }
    }
}
