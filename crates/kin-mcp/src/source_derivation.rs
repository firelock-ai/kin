// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Selected-graph source observations. These only qualify an answer; matching
//! source bytes cannot certify extraction, resolution or answer completeness.

use kin_review::source_derivation::{
    PriorLocalBindingStatus, SourceBinding, SourceDerivationReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::envelope::AbsenceSubstrate;
use crate::{ContentBlock, ToolCallResult};

pub const KEY: &str = "source_derivation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceObservationScope {
    LiveHead,
    SelectedHistorical,
    SelectedScopeUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionFailureObservation {
    pub consecutive_failures: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Which evidence the answer needs for local dependency bindings. A missing
/// field from an older producer remains conservative.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalBindingRequirement {
    #[default]
    Required,
    /// The answer reads source/declarations or ranks entities, not bindings.
    NotRequired,
    /// A store-wide calls reading established current, durable-context-valid
    /// ledgers, live proven targets and no unattributed expressions.
    CurrentCallSites,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDerivationObservation {
    pub scope: SourceObservationScope,
    /// `selected_paths` or `admitted_inventory`. Neither covers excluded source tiers.
    pub checked_scope: String,
    /// Distinct from the earlier query's reads; no atomic payload attestation.
    pub sampled: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<SourceDerivationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_failure: Option<AdmissionFailureObservation>,
    #[serde(default)]
    pub local_binding_requirement: LocalBindingRequirement,
}

impl SourceDerivationObservation {
    pub fn unavailable(reason: &str) -> Self {
        Self {
            scope: SourceObservationScope::SelectedScopeUnavailable,
            checked_scope: "selected_authority_unavailable".into(),
            sampled: "selected_graph_after_query".into(),
            report: Some(SourceDerivationReport::unproven(reason)),
            admission_failure: None,
            local_binding_requirement: LocalBindingRequirement::Required,
        }
    }

    pub fn historical() -> Self {
        Self {
            scope: SourceObservationScope::SelectedHistorical,
            checked_scope: "historical_not_assessed_against_live_source".into(),
            sampled: "selected_graph_after_query".into(),
            report: None,
            admission_failure: None,
            local_binding_requirement: LocalBindingRequirement::Required,
        }
    }

    pub fn limiting_factor(&self, substrate: AbsenceSubstrate) -> Option<&'static str> {
        if substrate == AbsenceSubstrate::History
            || self.scope == SourceObservationScope::SelectedHistorical
        {
            return None;
        }
        if self.scope == SourceObservationScope::SelectedScopeUnavailable {
            return Some("derived_source_unproven: the selected graph authority changed or could not be established, so current source binding is unproven");
        }
        // A store-wide failure need not affect a selected file whose current
        // binding was independently established. Keep the failure visible, but
        // do not turn it into an unrelated file-level trust downgrade.
        if (self.checked_scope != "selected_paths"
            || self
                .report
                .as_ref()
                .is_none_or(|report| report.body_binding != SourceBinding::Current))
            && self
                .admission_failure
                .as_ref()
                .is_some_and(|failure| failure.consecutive_failures > 0)
        {
            return Some("semantic_readmission_failed: semantic readmission failed for admitted source, so these useful graph rows may describe last-good derived source, so they cannot establish complete current repository semantics");
        }
        match self.report.as_ref().map(|report| report.body_binding) {
            Some(SourceBinding::Current) if substrate != AbsenceSubstrate::Relations
                || self.local_binding_requirement == LocalBindingRequirement::NotRequired => None,
            Some(SourceBinding::Current) => match self.report.as_ref().map(|report| (report.prior_local_binding, report.outstanding_local_binding_obligations)) {
                Some((PriorLocalBindingStatus::NoRecordedDebt, Some(0))) => None,
                Some((PriorLocalBindingStatus::Outstanding, _)) => Some("local_binding_outstanding: previously local source bindings remain unresolved, so current body and parse evidence cannot establish complete dependency or call-shape knowledge"),
                Some((PriorLocalBindingStatus::Unproven, None | Some(0)))
                    if self.local_binding_requirement == LocalBindingRequirement::CurrentCallSites => None,
                _ => Some("local_binding_unproven: prior-local binding evidence could not be validated for the checked scope, so complete dependency or call-shape knowledge is unproven"),
            },
            Some(SourceBinding::Stale) => Some("derived_source_stale: graph-held source derivation differs from admitted source bytes, so returned rows may describe last-good source and do not establish current completeness"),
            Some(SourceBinding::Unproven) | None => Some("derived_source_unproven: bounded graph evidence did not establish source binding for the checked scope, so current completeness cannot be inferred"),
        }
    }
}

/// Only source-derived queries read this substrate. Work/session/history and
/// exact artifact-byte reads have their own authorities and are not relabeled.
pub fn observes_sources(tool: &str, args: &std::collections::HashMap<String, Value>) -> bool {
    // resolve_diff gives current entity/files modes precedence. With neither,
    // semantic_diff reads committed changes only; impact/review still walk live
    // relations and must retain their source observation.
    if tool == "semantic_diff"
        && !["entity_ids", "files"].iter().any(|key| {
            args.get(*key)
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(Value::is_string))
        })
    {
        return false;
    }
    matches!(
        tool,
        "semantic_search"
            | "semantic_locate"
            | "get_entity"
            | "get_entity_source"
            | "get_entity_body"
            | "get_entity_sources"
            | "get_context_pack"
            | "trace_computation"
            | "trace_data_flow"
            | "trace_path"
            | "find_references"
            | "bulk_check_references"
            | "explore_codebase"
            | "dead_code"
            | "find_dead_code_seeded"
            | "graph_neighborhood"
            | "lexical_lookup"
            | "semantic_diff"
            | "impact_analysis"
            | "semantic_review"
            | "kin_graph_status"
    )
}

/// Source-only tools do not ask whether dependencies or references are
/// complete. Context, traversal and entity records with attached calls do.
pub fn local_bindings_required(tool: &str) -> bool {
    !matches!(
        tool,
        "semantic_search"
            | "semantic_locate"
            | "lexical_lookup"
            | "get_entity_source"
            | "get_entity_body"
            | "get_entity_sources"
    )
}

/// Resolve the source paths of a bounded semantic answer from graph identities,
/// never from presentation paths supplied by the payload. Inbound, traversal
/// and inventory answers retain inventory scope: returned rows cannot establish
/// that an unseen caller's admitted source is current.
pub fn selected_answer_paths<G: kin_model::GraphStore + ?Sized>(
    tool: &str,
    result: &ToolCallResult,
    store: &G,
) -> Option<Vec<kin_model::RepoPath>> {
    if result.is_error == Some(true)
        || !matches!(
            tool,
            "get_entity" | "get_entity_source" | "get_entity_body" | "get_entity_sources"
        )
    {
        return None;
    }
    fn identities(value: &Value, found: &mut std::collections::BTreeSet<kin_model::EntityId>) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    if matches!(key.as_str(), "id" | "entity_id" | "caller_id" | "target_id") {
                        if let Some(id) = child
                            .as_str()
                            .and_then(|id| uuid::Uuid::parse_str(id).ok())
                            .map(kin_model::EntityId)
                        {
                            found.insert(id);
                        }
                    }
                    identities(child, found);
                }
            }
            Value::Array(values) => {
                for child in values {
                    identities(child, found);
                }
            }
            _ => {}
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for block in &result.content {
        let ContentBlock::Text { text } = block;
        let value: Value = serde_json::from_str(text).ok()?;
        // A partial batch also answers a missing-source question. Its successful
        // rows do not establish the derivation state behind the missing rows.
        if tool == "get_entity_sources" && value.get("total_requested") != value.get("returned") {
            return None;
        }
        identities(&value, &mut ids);
    }
    let mut paths = std::collections::BTreeMap::new();
    for id in ids {
        // A relation or outside-symbol identity is not a local entity.
        let Some(entity) = store.get_entity(&id).ok()? else {
            continue;
        };
        let file = entity
            .span
            .as_ref()
            .map(|span| &span.file)
            .or(entity.file_origin.as_ref())?;
        let path = kin_model::RepoPath::from_utf8(&file.0).ok()?;
        paths.insert(path.as_bytes().to_vec(), path);
    }
    (!paths.is_empty()).then(|| paths.into_values().collect())
}

/// Inspect the original declared kinds, without filtering unknown classes into
/// an apparently calls-only answer.
fn calls_only_answer(payload: &Value) -> bool {
    payload
        .get("relation_kinds")
        .and_then(Value::as_array)
        .is_some_and(|kinds| {
            !kinds.is_empty()
                && kinds.iter().all(|kind| {
                    kind.as_str()
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("calls"))
                })
        })
}

impl SourceDerivationObservation {
    /// Select the binding requirement separately from the source-path scope.
    /// A path subset proves no call-candidate completeness by itself.
    pub fn qualify_for_answer<G: kin_model::GraphStore + ?Sized>(
        &mut self,
        tool: &str,
        result: &ToolCallResult,
        store: &G,
    ) {
        self.local_binding_requirement = if local_bindings_required(tool) {
            LocalBindingRequirement::Required
        } else {
            LocalBindingRequirement::NotRequired
        };
        if self.local_binding_requirement == LocalBindingRequirement::NotRequired {
            return;
        }
        // References are the surface that can explicitly ask for calls alone.
        // Missing classes, a union, or shared-name sections remain conservative.
        if tool != "find_references" || result.content.len() != 1 {
            return;
        }
        let ContentBlock::Text { text } = &result.content[0];
        let Ok(payload) = serde_json::from_str::<Value>(text) else {
            return;
        };
        if !calls_only_answer(&payload) {
            return;
        }
        let Some(id) = payload
            .pointer("/focal_entity/id")
            .and_then(Value::as_str)
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .map(kin_model::EntityId)
        else {
            return;
        };
        let Ok(Some(focal)) = store.get_entity(&id) else {
            return;
        };
        self.qualify_current_calls(store, &focal);
    }

    /// The caller must establish that its answer reads calls alone. This
    /// producer scans the store, not only the focal's import family.
    pub fn qualify_current_calls<G: kin_model::GraphStore + ?Sized>(
        &mut self,
        store: &G,
        focal: &kin_model::Entity,
    ) {
        if crate::call_sites::calls_evidence_for(store, focal)
            .is_ok_and(|evidence| evidence.settled)
        {
            self.local_binding_requirement = LocalBindingRequirement::CurrentCallSites;
        }
    }
}

/// Preserve raw useful rows and qualify any existing trust summary. Stdio later
/// recomputes its canonical verdict with this same typed observation.
pub fn disclose(
    mut result: ToolCallResult,
    observation: &SourceDerivationObservation,
) -> ToolCallResult {
    for block in &mut result.content {
        let ContentBlock::Text { text } = block;
        let mut value = match serde_json::from_str::<Value>(text) {
            Ok(value @ Value::Object(_)) => value,
            Ok(value) => json!({"result":value}),
            Err(_) => json!({"message":text}),
        };
        value[KEY] = serde_json::to_value(observation).expect("source observation serializes");
        qualify_existing(&mut value, observation);
        *text = serde_json::to_string(&value).expect("source observation payload serializes");
    }
    result
}

pub(crate) fn qualify_existing(value: &mut Value, observation: &SourceDerivationObservation) {
    if let Some(envelope) = value.get_mut("_kin").and_then(Value::as_object_mut) {
        envelope.insert(
            KEY.into(),
            serde_json::to_value(observation).expect("source observation serializes"),
        );
    }
    let Some(reason) = observation.limiting_factor(AbsenceSubstrate::Relations) else {
        return;
    };
    crate::verdict::qualify_source_observation(value, reason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, NegativeClass};
    fn observation(binding: SourceBinding) -> SourceDerivationObservation {
        let mut report = SourceDerivationReport::unproven("fixture");
        report.body_binding = binding;
        SourceDerivationObservation {
            scope: SourceObservationScope::LiveHead,
            checked_scope: "admitted_inventory".into(),
            sampled: "selected_graph_after_query".into(),
            report: Some(report),
            admission_failure: None,
            local_binding_requirement: LocalBindingRequirement::Required,
        }
    }
    fn payload(result: &ToolCallResult) -> Value {
        let ContentBlock::Text { text } = result.content.first().unwrap();
        serde_json::from_str(text).unwrap()
    }
    fn healthy_envelope() -> Envelope {
        Envelope::daemon().with_health(&json!({"initialized":true,"graph_loaded":true,"graph_entity_count":1,"graph_relation_count":1,"durable_entity_count":1,"durable_relation_count":1,"reconcile":{"untracked_path_count":0,"untracked_observed_age_seconds":0,"last_admission_success_at":"2026-09-19T00:00:00Z","last_admission_success_age_seconds":0}}))
    }
    #[test]
    fn source_only_answers_do_not_inherit_unrelated_local_binding_debt() {
        let graph = kin_db::InMemoryGraph::new();
        let result = ToolCallResult::text(json!({"results":[]}).to_string());
        for tool in [
            "get_entity_source",
            "get_entity_body",
            "get_entity_sources",
            "semantic_search",
            "semantic_locate",
            "lexical_lookup",
        ] {
            for binding in [
                PriorLocalBindingStatus::Unproven,
                PriorLocalBindingStatus::Outstanding,
            ] {
                let mut current = observation(SourceBinding::Current);
                current.report.as_mut().unwrap().prior_local_binding = binding;
                current
                    .report
                    .as_mut()
                    .unwrap()
                    .outstanding_local_binding_obligations = Some(3);
                current.qualify_for_answer(tool, &result, &graph);
                assert_eq!(
                    current.local_binding_requirement,
                    LocalBindingRequirement::NotRequired
                );
                assert_eq!(
                    current.limiting_factor(AbsenceSubstrate::Relations),
                    None,
                    "{tool}"
                );
                assert_eq!(
                    current.report.as_ref().unwrap().prior_local_binding,
                    binding,
                    "the observation still discloses real binding state"
                );
                for body in [SourceBinding::Stale, SourceBinding::Unproven] {
                    current.report.as_mut().unwrap().body_binding = body;
                    assert!(
                        current
                            .limiting_factor(AbsenceSubstrate::Relations)
                            .is_some(),
                        "source-only still needs current body binding"
                    );
                }
            }
        }
    }

    #[test]
    fn relation_answers_and_legacy_observations_retain_binding_requirements() {
        let graph = kin_db::InMemoryGraph::new();
        let result = ToolCallResult::text(json!({"results":[]}).to_string());
        for tool in [
            "find_references",
            "get_context_pack",
            "impact_analysis",
            "semantic_review",
            "graph_neighborhood",
            "trace_data_flow",
            "unknown_tool",
        ] {
            let mut current = observation(SourceBinding::Current);
            current.qualify_for_answer(tool, &result, &graph);
            assert_eq!(
                current.local_binding_requirement,
                LocalBindingRequirement::Required
            );
            assert!(
                current
                    .limiting_factor(AbsenceSubstrate::Relations)
                    .unwrap()
                    .starts_with("local_binding_unproven:"),
                "{tool}"
            );
        }
        let mut legacy = serde_json::to_value(observation(SourceBinding::Current)).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("local_binding_requirement");
        let reopened: SourceDerivationObservation = serde_json::from_value(legacy).unwrap();
        assert_eq!(
            reopened.local_binding_requirement,
            LocalBindingRequirement::Required
        );
        assert!(reopened
            .limiting_factor(AbsenceSubstrate::Relations)
            .is_some());
        assert_eq!(
            reopened.limiting_factor(AbsenceSubstrate::EntityIndex),
            None
        );
        assert_eq!(reopened.limiting_factor(AbsenceSubstrate::Vectors), None);
    }

    #[test]
    fn current_call_sites_can_replace_missing_witness_but_never_recorded_debt() {
        let mut current = observation(SourceBinding::Current);
        current.local_binding_requirement = LocalBindingRequirement::CurrentCallSites;
        assert_eq!(current.limiting_factor(AbsenceSubstrate::Relations), None);
        current.report.as_mut().unwrap().prior_local_binding = PriorLocalBindingStatus::Outstanding;
        current
            .report
            .as_mut()
            .unwrap()
            .outstanding_local_binding_obligations = Some(1);
        assert!(current
            .limiting_factor(AbsenceSubstrate::Relations)
            .unwrap()
            .starts_with("local_binding_outstanding:"));
        current.report.as_mut().unwrap().prior_local_binding = PriorLocalBindingStatus::Unproven;
        assert!(
            current
                .limiting_factor(AbsenceSubstrate::Relations)
                .is_some(),
            "an unknown status with a positive obligation count is still debt"
        );
    }

    #[test]
    fn calls_only_qualification_requires_current_storewide_ledger_evidence() {
        use crate::call_sites::fixture::{admit, ledger, proof_context, spanned_entity};
        use kin_model::*;
        let graph = kin_db::InMemoryGraph::new();
        let focal_body = "def focal():\n    return 1\n";
        let caller_body = "def caller():\n    return focal()\n";
        let mut focal = spanned_entity("focal", "focal.py", LanguageId::Python, 0, focal_body);
        focal
            .metadata
            .extra
            .insert(kin_parser::FILE_PARSED_CALL_SITES_KEY.into(), json!(0));
        let mut caller = spanned_entity(
            "caller",
            "unimported.py",
            LanguageId::Python,
            0,
            caller_body,
        );
        caller.metadata.extra.insert(
            kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
            json!(caller_body),
        );
        caller
            .metadata
            .extra
            .insert(kin_parser::FILE_PARSED_CALL_SITES_KEY.into(), json!(1));
        let context = proof_context(LanguageId::Python, "current");
        let context_id = context.id();
        admit(
            &graph,
            &[&focal, &caller],
            vec![
                context,
                ledger(&focal, focal_body, context_id, Vec::new()),
                ledger(
                    &caller,
                    caller_body,
                    context_id,
                    vec![("focal", CallSiteState::ProvenTarget { target: focal.id })],
                ),
            ],
        );
        // A replacement proof also needs the admitted source inventory and
        // each file's parse census; entity ledgers alone cannot prove there
        // is no admitted file whose calls were never attributed.
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: [("focal.py", focal_body), ("unimported.py", caller_body)]
                    .into_iter()
                    .map(|(path, body)| TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(path).unwrap(),
                            TreeEntry::blob(kin_blobs::digest(body.as_bytes()), false),
                        ),
                    })
                    .collect(),
                ..Default::default()
            })
            .unwrap();
        let answer = ToolCallResult::text(
            json!({
                "focal_entity":{"id":focal.id}, "references":[], "relation_kinds":["Calls"]
            })
            .to_string(),
        );
        let mut observed = observation(SourceBinding::Current);
        observed.qualify_for_answer("find_references", &answer, &graph);
        assert_eq!(
            observed.local_binding_requirement,
            LocalBindingRequirement::CurrentCallSites
        );
        assert_eq!(observed.limiting_factor(AbsenceSubstrate::Relations), None);

        // This caller has no import edge to the focal's file. Its unresolved
        // matching call must still revoke the replacement proof.
        let old = graph
            .lookup_resolution_record(&ResolutionRecordId::call_sites(caller.id))
            .unwrap()
            .unwrap();
        let new = ledger(
            &caller,
            caller_body,
            context_id,
            vec![(
                "focal",
                CallSiteState::Unresolved {
                    reason: UnresolvedReason::NoAnswer,
                },
            )],
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                resolution_record_deltas: vec![ResolutionRecordDelta::Modified { old, new }],
                ..Default::default()
            })
            .unwrap();
        observed.qualify_for_answer("find_references", &answer, &graph);
        assert_eq!(
            observed.local_binding_requirement,
            LocalBindingRequirement::Required
        );
        assert!(observed
            .limiting_factor(AbsenceSubstrate::Relations)
            .unwrap()
            .starts_with("local_binding_unproven:"));
    }

    fn scoped_entity(file: &str) -> kin_model::Entity {
        use kin_model::*;
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "focal".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([4; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: "fn focal()".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn answer_path_scope_uses_graph_identity_and_never_narrows_broad_queries() {
        use kin_model::EntityStore;
        let graph = kin_db::InMemoryGraph::new();
        let mut focal = scoped_entity("presentation.rs");
        focal.span = Some(kin_model::SourceSpan {
            file: kin_model::FilePathId::new("truth.rs"),
            start_byte: 0,
            end_byte: 3,
            start_line: 0,
            end_line: 0,
            start_col: 0,
            end_col: 3,
        });
        graph.upsert_entity(&focal).unwrap();
        let other = scoped_entity("caller.rs");
        graph.upsert_entity(&other).unwrap();
        let result = ToolCallResult::text(
            json!({
                "focal_entity":{"id":focal.id,"file_path":"wrong.rs"},
                "references":[{"entity_id":other.id,"file_path":"also-wrong.rs"}]
            })
            .to_string(),
        );
        assert_eq!(
            selected_answer_paths("get_entity_sources", &result, &graph),
            Some(vec![
                kin_model::RepoPath::from_utf8("caller.rs").unwrap(),
                kin_model::RepoPath::from_utf8("truth.rs").unwrap(),
            ])
        );
        for tool in [
            "find_references",
            "bulk_check_references",
            "get_context_pack",
            "graph_neighborhood",
            "trace_computation",
            "trace_data_flow",
            "trace_path",
            "impact_analysis",
            "semantic_review",
            "semantic_search",
            "semantic_locate",
            "dead_code",
            "find_dead_code_seeded",
            "kin_graph_status",
            "explore_codebase",
            "unknown_tool",
        ] {
            assert_eq!(selected_answer_paths(tool, &result, &graph), None, "{tool}");
        }
        let partial = ToolCallResult::text(
            json!({
                "total_requested":2, "returned":1,
                "results":[{"id":focal.id}, {"id":kin_model::EntityId::new(), "reason":"not_found"}]
            })
            .to_string(),
        );
        assert_eq!(
            selected_answer_paths("get_entity_sources", &partial, &graph),
            None
        );
        let unknown = ToolCallResult::text(
            json!({"focal_entity":{"id":kin_model::EntityId::new()}}).to_string(),
        );
        assert_eq!(
            selected_answer_paths("get_entity_source", &unknown, &graph),
            None
        );
        assert_eq!(
            selected_answer_paths(
                "get_entity_source",
                &ToolCallResult::error("no source"),
                &graph
            ),
            None
        );
    }

    #[test]
    fn unknown_or_mixed_relation_classes_cannot_claim_calls_only() {
        assert!(calls_only_answer(&json!({"relation_kinds":["Calls"]})));
        for value in [
            json!({}),
            json!({"relation_kinds":[]}),
            json!({"relation_kinds":["Calls", "unknown"]}),
            json!({"relation_kinds":["Calls", "References"]}),
            json!({"relation_kinds":["Calls", null]}),
        ] {
            assert!(!calls_only_answer(&value), "{value}");
        }
    }

    #[test]
    fn unseen_stale_source_still_bounds_empty_inbound_answers() {
        use kin_model::*;
        let graph = kin_db::InMemoryGraph::new();
        let mut focal_id = EntityId::new();
        for (file, admitted_byte, derived_byte) in [("focal.rs", 1, 1), ("unreturned.rs", 2, 1)] {
            let artifact = ArtifactId::new();
            let mut entity = scoped_entity(file);
            if file == "focal.rs" {
                focal_id = entity.id;
            }
            let derived = Hash256::from_bytes([derived_byte; 32]);
            entity
                .metadata
                .extra
                .insert("blob_hash".into(), json!(derived.to_string()));
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: artifact,
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(file).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes([admitted_byte; 32]), false),
                        ),
                    }],
                    ..Default::default()
                })
                .unwrap();
            let mut certificate = kin_index::build_parse_coverage_relation(
                &kin_index::FileParseData {
                    file_path: file.into(),
                    entities: vec![entity.clone()],
                    relations: Vec::new(),
                    imports: Vec::new(),
                },
                artifact,
                &ParseCompleteness::Full,
                &std::collections::HashSet::<String>::new(),
            );
            kin_index::bind_parse_coverage_source(&mut certificate, file, derived);
            graph.upsert_entity(&entity).unwrap();
            graph.upsert_relation(&certificate).unwrap();
        }
        let empty = ToolCallResult::text(
            json!({
                "focal_entity":{"id":focal_id}, "references":[], "relation_kinds":["Calls"]
            })
            .to_string(),
        );
        let body_paths = selected_answer_paths("get_entity_body", &empty, &graph).unwrap();
        let body_facts = graph
            .source_derivation_facts_with_reserved_relation(
                kin_db::SourceDerivationLimits::default(),
                Some(&body_paths),
                kin_index::binding_debt::local_binding_debt_id,
            )
            .unwrap();
        assert_eq!(
            kin_review::source_derivation::inspect_source_derivation(&body_facts).body_binding,
            SourceBinding::Current,
            "the returned focal's source really is current"
        );
        for tool in [
            "find_references",
            "bulk_check_references",
            "impact_analysis",
            "semantic_review",
        ] {
            let paths = selected_answer_paths(tool, &empty, &graph);
            assert!(
                paths.is_none(),
                "{tool} must inspect unseen possible callers"
            );
            let facts = graph
                .source_derivation_facts_with_reserved_relation(
                    kin_db::SourceDerivationLimits::default(),
                    paths.as_deref(),
                    kin_index::binding_debt::local_binding_debt_id,
                )
                .unwrap();
            let mut observation = observation(SourceBinding::Current);
            observation.report = Some(kin_review::source_derivation::inspect_source_derivation(
                &facts,
            ));
            // Even complete current call ledgers cannot rebind stale admitted bytes.
            observation.local_binding_requirement = LocalBindingRequirement::CurrentCallSites;
            assert_eq!(
                observation.report.as_ref().unwrap().body_binding,
                SourceBinding::Stale
            );
            let value = payload(&disclose(empty.clone(), &observation));
            assert!(observation
                .limiting_factor(AbsenceSubstrate::Relations)
                .unwrap()
                .starts_with("derived_source_stale:"));
            assert_eq!(
                value["source_derivation"]["report"]["body_binding"],
                "stale"
            );
        }
    }

    #[test]
    fn unparsed_admitted_file_bounds_inbound_and_trace_but_not_targeted_body() {
        use kin_model::*;
        let graph = kin_db::InMemoryGraph::new();
        let artifact = ArtifactId::new();
        let hash = Hash256::from_bytes([0x51; 32]);
        let mut focal = scoped_entity("focal.rs");
        focal
            .metadata
            .extra
            .insert("blob_hash".into(), json!(hash.to_string()));
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![
                    TreeDelta::Added {
                        artifact_id: artifact,
                        new: LocatedEntry::new(
                            RepoPath::from_utf8("focal.rs").unwrap(),
                            TreeEntry::blob(hash, false),
                        ),
                    },
                    TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(
                            RepoPath::from_utf8("new_caller.rs").unwrap(),
                            TreeEntry::blob(Hash256::from_bytes([0x52; 32]), false),
                        ),
                    },
                ],
                ..Default::default()
            })
            .unwrap();
        let mut certificate = kin_index::build_parse_coverage_relation(
            &kin_index::FileParseData {
                file_path: "focal.rs".into(),
                entities: vec![focal.clone()],
                relations: Vec::new(),
                imports: Vec::new(),
            },
            artifact,
            &ParseCompleteness::Full,
            &std::collections::HashSet::<String>::new(),
        );
        kin_index::bind_parse_coverage_source(&mut certificate, "focal.rs", hash);
        graph.upsert_entity(&focal).unwrap();
        graph.upsert_relation(&certificate).unwrap();
        // The admitted potential caller has neither an entity nor a parse
        // certificate. An entity-only scan would silently omit this debt.
        let answer = ToolCallResult::text(
            json!({
                "focal_entity":{"id":focal.id}, "references":[], "relation_kinds":["Calls"]
            })
            .to_string(),
        );
        let inspect = |paths: Option<&[RepoPath]>| {
            graph
                .source_derivation_facts_with_reserved_relation(
                    kin_db::SourceDerivationLimits::default(),
                    paths,
                    kin_index::binding_debt::local_binding_debt_id,
                )
                .unwrap()
        };
        let body_paths = selected_answer_paths("get_entity_body", &answer, &graph).unwrap();
        let body_facts = inspect(Some(&body_paths));
        assert_eq!(body_facts.artifacts.len(), 1);
        let mut body = observation(SourceBinding::Current);
        body.checked_scope = "selected_paths".into();
        body.report = Some(kin_review::source_derivation::inspect_source_derivation(
            &body_facts,
        ));
        body.qualify_for_answer("get_entity_body", &answer, &graph);
        assert_eq!(
            body.report.as_ref().unwrap().body_binding,
            SourceBinding::Current
        );
        assert_eq!(body.limiting_factor(AbsenceSubstrate::Relations), None);

        for tool in [
            "find_references",
            "bulk_check_references",
            "impact_analysis",
            "semantic_review",
            "trace_data_flow",
        ] {
            let paths = selected_answer_paths(tool, &answer, &graph);
            assert!(paths.is_none(), "{tool} must retain the admitted inventory");
            let facts = inspect(paths.as_deref());
            assert_eq!(facts.artifacts.len(), 2);
            assert_eq!(facts.entities.len(), 1);
            let mut observed = observation(SourceBinding::Current);
            observed.report = Some(kin_review::source_derivation::inspect_source_derivation(
                &facts,
            ));
            observed.qualify_for_answer(tool, &answer, &graph);
            if tool == "find_references" {
                // Even granting the strongest permitted calls-only replacement
                // cannot prove the source of a file not yet parsed into callers.
                observed.local_binding_requirement = LocalBindingRequirement::CurrentCallSites;
            } else {
                assert_eq!(
                    observed.local_binding_requirement,
                    LocalBindingRequirement::Required
                );
            }
            assert_eq!(
                observed.report.as_ref().unwrap().body_binding,
                SourceBinding::Unproven
            );
            let finalized = crate::envelope::finalize(
                disclose(answer.clone(), &observed),
                healthy_envelope(),
                tool,
            );
            let value = payload(&finalized);
            assert_eq!(
                value["_kin"][KEY]["report"]["body_binding"], "unproven",
                "{tool}"
            );
            assert_eq!(
                value["_kin"]["verdict"]["safe_to_conclude_absent"], false,
                "{tool}"
            );
            assert!(
                value["_kin"]["verdict"]["limiting_factor"]
                    .as_str()
                    .unwrap()
                    .contains("derived_source_unproven"),
                "{tool}: {value}"
            );
        }
    }

    #[test]
    fn stale_source_qualifies_populated_and_resolution_miss_answers() {
        let observation = observation(SourceBinding::Stale);
        for result in [
            ToolCallResult::text(json!({"entity_impacts":[{"entity_name":"target"}]}).to_string()),
            ToolCallResult::error("Entity not found: missing"),
        ] {
            let is_error = result.is_error;
            let raw = disclose(result, &observation);
            let finalized = crate::envelope::finalize(
                raw,
                healthy_envelope(),
                if is_error == Some(true) {
                    "find_references"
                } else {
                    "impact_analysis"
                },
            );
            let value = payload(&finalized);
            assert_eq!(finalized.is_error, is_error);
            assert_eq!(value["_kin"][KEY]["report"]["body_binding"], "stale");
            assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive");
            assert!(!value["_kin"]["verdict"]["limiting_factor"]
                .as_str()
                .unwrap()
                .contains("unlisted_clause"));
            assert!(value["_kin"]["verdict"]["limiting_factor"]
                .as_str()
                .unwrap()
                .contains("derived_source_stale"));
            if is_error == Some(true) {
                assert_eq!(value["negative"]["trust"], "inconclusive");
                assert_eq!(value["negative"]["safe_to_conclude_absent"], false);
            }
        }
    }
    #[test]
    fn answer_only_keeps_source_observation_and_canonical_warning() {
        let result = disclose(
            ToolCallResult::text(
                json!({"references":[],"focal_entity":{"name":"target"}}).to_string(),
            ),
            &observation(SourceBinding::Unproven),
        );
        let budget = crate::budget::ResponseBudget::from_arguments(
            &[("answer_only".into(), json!(true))].into_iter().collect(),
        );
        let value = payload(&crate::envelope::finalize_bounded(
            result,
            healthy_envelope(),
            "find_references",
            &budget,
        ));
        assert_eq!(value["_kin"][KEY]["report"]["body_binding"], "unproven");
        assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive");
    }
    #[test]
    fn binding_does_not_certify_and_history_does_not_inherit_head_failure() {
        let current = observation(SourceBinding::Current);
        let raw = disclose(
            ToolCallResult::text(json!({"results":[]}).to_string()),
            &current,
        );
        let value = payload(&crate::envelope::finalize(
            raw,
            healthy_envelope(),
            "semantic_search",
        ));
        assert_ne!(value["_kin"]["verdict"]["state"], "certified");
        let historical = SourceDerivationObservation::historical();
        let mut envelope = healthy_envelope();
        envelope.source_derivation = Some(historical);
        assert!(
            envelope
                .negative_trust(NegativeClass::Structural, AbsenceSubstrate::EntityIndex)
                .0
        );
        let mut failure = observation(SourceBinding::Stale);
        failure.admission_failure = Some(AdmissionFailureObservation {
            consecutive_failures: 1,
            last_error: Some("injected".into()),
        });
        envelope.source_derivation = Some(failure);
        assert!(
            envelope
                .negative_trust(NegativeClass::Structural, AbsenceSubstrate::History)
                .0
        );
        assert!(
            !envelope
                .negative_trust(NegativeClass::Structural, AbsenceSubstrate::Relations)
                .0
        );
    }
    #[test]
    fn existing_raw_trust_is_only_downgraded_and_malformed_metadata_refuses() {
        let focal = "00000000-0000-0000-0000-000000000001";
        let original = crate::envelope::finalize(
            ToolCallResult::text(json!({"references":[],"total_upstream":0,"counts":{"receiver_name_candidates":0},"degradations":[],"focal_entity":{"id":focal},"cross_repo":{"status":"available","authority_complete":true,"authority_revision":"sha256:complete","authority_roots":{"local":"local-root"},"authority_anchor":{"repo_id":"local","entity_id":focal}},"focal_resolution":{"addressed_by":"entity_id","same_name_candidates":1,"matched":"exact_focal_name","other_candidates":[]},"edge_coverage":{"scope":"language","language":"Python","requested_classes":["calls","imports","references"],"classes":{"calls":"present","imports":"present","references":"present"},"reference_enrichment":"available","budget_exhausted":false}}).to_string()),
            healthy_envelope(), "find_references");
        assert_eq!(
            payload(&original)["_kin"]["verdict"]["state"],
            "certified",
            "{}",
            payload(&original)
        );
        let raw = disclose(original, &observation(SourceBinding::Stale));
        let repeated = disclose(raw.clone(), &observation(SourceBinding::Stale));
        assert_eq!(
            payload(&raw),
            payload(&repeated),
            "late qualification is idempotent"
        );
        for value in [
            payload(&raw),
            payload(&crate::envelope::finalize(
                raw,
                healthy_envelope(),
                "find_references",
            )),
        ] {
            assert_eq!(value["negative"]["safe_to_conclude_absent"], false);
            assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive");
            assert_eq!(
                value["_kin"]["verdict"]["absence_claim"],
                "not_authoritative"
            );
            assert_eq!(value["_kin"]["verdict"]["inputs"][KEY], "inconclusive");
            assert!(value["negative"]["advice"]
                .as_str()
                .unwrap()
                .contains("Absence is NOT authoritative"));
            assert!(value["edge_coverage"]["limits"]
                .as_array()
                .unwrap()
                .contains(&json!("source_derivation:inconclusive")));
            assert!(crate::verdict::disagreements(&value).is_empty(), "{value}");
        }
        let envelope = healthy_envelope().with_payload_metadata(&json!({KEY:"invalid"}));
        assert!(
            !envelope
                .negative_trust(NegativeClass::Structural, AbsenceSubstrate::EntityIndex)
                .0
        );
    }
    #[test]
    fn history_only_diff_and_unrelated_selected_file_keep_their_own_scope() {
        for args in [
            json!({"change_ids":["change"]}),
            json!({"base":"old","head":"new"}),
        ] {
            let args = serde_json::from_value(args).unwrap();
            assert!(!observes_sources("semantic_diff", &args));
            assert!(observes_sources("impact_analysis", &args));
        }
        for args in [
            json!({"entity_ids":["entity"],"base":"old","head":"new"}),
            json!({"files":["file.py"],"change_ids":["change"]}),
        ] {
            assert!(observes_sources(
                "semantic_diff",
                &serde_json::from_value(args).unwrap()
            ));
        }
        let mut selected = observation(SourceBinding::Current);
        selected.checked_scope = "selected_paths".into();
        selected.report.as_mut().unwrap().prior_local_binding =
            PriorLocalBindingStatus::NoRecordedDebt;
        selected
            .report
            .as_mut()
            .unwrap()
            .outstanding_local_binding_obligations = Some(0);
        selected.admission_failure = Some(AdmissionFailureObservation {
            consecutive_failures: 1,
            last_error: Some("other path failed".into()),
        });
        assert_eq!(
            selected.limiting_factor(AbsenceSubstrate::EntityIndex),
            None
        );
        selected.report.as_mut().unwrap().body_binding = SourceBinding::Stale;
        assert!(selected
            .limiting_factor(AbsenceSubstrate::EntityIndex)
            .unwrap()
            .contains("semantic_readmission_failed"));
    }
    #[test]
    fn small_budgets_keep_the_observation_and_do_not_certify() {
        for answer_only in [false, true] {
            let raw = disclose(
                ToolCallResult::text(
                    json!({"references":[],"focal_entity":{"id":"focal"}}).to_string(),
                ),
                &observation(SourceBinding::Stale),
            );
            let budget = crate::budget::ResponseBudget::from_arguments(
                &[
                    ("answer_only".into(), json!(answer_only)),
                    ("max_chars".into(), json!(2000)),
                ]
                .into_iter()
                .collect(),
            );
            let result = crate::envelope::finalize_bounded(
                raw,
                healthy_envelope(),
                "find_references",
                &budget,
            );
            let value = payload(&result);
            assert_eq!(value["_kin"][KEY]["report"]["body_binding"], "stale");
            assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive");
            assert!(crate::verdict::disagreements(&value).is_empty(), "{value}");
        }
    }
    #[test]
    fn current_parse_and_prior_local_debt_stay_separate_in_raw_and_stdio_trust() {
        for status in [
            PriorLocalBindingStatus::Outstanding,
            PriorLocalBindingStatus::Unproven,
        ] {
            let mut observed = observation(SourceBinding::Current);
            let report = observed.report.as_mut().unwrap();
            report.parse_coverage = kin_review::source_derivation::DerivationCoverage::Complete;
            report.call_shape_parse_coverage_complete = true;
            report.prior_local_binding = status;
            report.outstanding_local_binding_obligations =
                (status == PriorLocalBindingStatus::Outstanding).then_some(2);
            let expected = if status == PriorLocalBindingStatus::Outstanding {
                "local_binding_outstanding"
            } else {
                "local_binding_unproven"
            };
            let raw = disclose(ToolCallResult::text(json!({"references":[],"focal_entity":{"id":"focal"},"negative":{"trust":"authoritative","safe_to_conclude_absent":true}}).to_string()), &observed);
            assert_eq!(payload(&raw)["negative"]["safe_to_conclude_absent"], false);
            for answer_only in [false, true] {
                let budget = crate::budget::ResponseBudget::from_arguments(
                    &[
                        ("answer_only".into(), json!(answer_only)),
                        ("max_chars".into(), json!(2000)),
                    ]
                    .into_iter()
                    .collect(),
                );
                let value = payload(&crate::envelope::finalize_bounded(
                    raw.clone(),
                    healthy_envelope(),
                    "find_references",
                    &budget,
                ));
                assert_eq!(value["_kin"][KEY]["report"]["body_binding"], "current");
                assert_eq!(value["_kin"][KEY]["report"]["parse_coverage"], "complete");
                assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive");
                assert!(
                    value["_kin"]["verdict"]["limiting_factor"]
                        .as_str()
                        .unwrap()
                        .contains(expected),
                    "{value}"
                );
                // Tiny responses may omit the duplicate negative object;
                // the canonical inconclusive verdict and reason must survive.
                if let Some(negative) = value.get("negative") {
                    assert_eq!(negative["safe_to_conclude_absent"], false);
                }
                assert!(crate::verdict::disagreements(&value).is_empty(), "{value}");
            }
            observed.scope = SourceObservationScope::SelectedHistorical;
            assert_eq!(observed.limiting_factor(AbsenceSubstrate::Relations), None);
        }
    }

    /// A store `kin upgrade` brought current does not hide what its binding
    /// history still owes. With the hydration record current, outstanding or
    /// unproven prior-local binding is still what limits a live answer, named
    /// as such rather than as a store-semantics gap.
    #[test]
    fn an_upgraded_store_keeps_its_binding_limiting_factor_honest() {
        let upgraded = kin_core::hydration_semantics::HydrationStanding::Rederived {
            under: 10,
            created_under: Some(9),
            derives: 10,
        };
        for (status, outstanding, expected) in [
            (
                PriorLocalBindingStatus::Outstanding,
                Some(2),
                "local_binding_outstanding",
            ),
            (
                PriorLocalBindingStatus::Unproven,
                None,
                "local_binding_unproven",
            ),
        ] {
            let mut observed = observation(SourceBinding::Current);
            let report = observed.report.as_mut().unwrap();
            report.parse_coverage = kin_review::source_derivation::DerivationCoverage::Complete;
            report.call_shape_parse_coverage_complete = true;
            report.prior_local_binding = status;
            report.outstanding_local_binding_obligations = outstanding;
            let raw = disclose(ToolCallResult::text(json!({"references":[],"focal_entity":{"id":"focal"},"negative":{"trust":"authoritative","safe_to_conclude_absent":true}}).to_string()), &observed);
            let value = payload(&crate::envelope::finalize(
                raw,
                healthy_envelope().with_hydration_semantics_observation(Some(&upgraded)),
                "find_references",
            ));
            assert_eq!(value["_kin"]["hydration_semantics"]["standing"], "current");
            assert_eq!(value["_kin"]["hydration_semantics"]["upgraded_under"], 10);
            assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive", "{value}");
            let factor = value["_kin"]["verdict"]["limiting_factor"]
                .as_str()
                .unwrap_or_default();
            assert!(factor.starts_with(expected), "{value}");
            assert!(crate::verdict::disagreements(&value).is_empty(), "{value}");
        }
    }

    #[test]
    fn older_source_metadata_cannot_default_to_no_binding_debt() {
        let mut value = serde_json::to_value(observation(SourceBinding::Current)).unwrap();
        value["report"]
            .as_object_mut()
            .unwrap()
            .remove("prior_local_binding");
        value["report"]
            .as_object_mut()
            .unwrap()
            .remove("outstanding_local_binding_obligations");
        let older: SourceDerivationObservation = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            older.report.as_ref().unwrap().prior_local_binding,
            PriorLocalBindingStatus::Unproven
        );
        assert_eq!(
            older
                .report
                .as_ref()
                .unwrap()
                .outstanding_local_binding_obligations,
            None
        );
        assert!(older
            .limiting_factor(AbsenceSubstrate::Relations)
            .unwrap()
            .contains("local_binding_unproven"));
        value["report"]["prior_local_binding"] = json!("unknown_future_status");
        let envelope = healthy_envelope().with_payload_metadata(&json!({KEY:value}));
        assert!(
            !envelope
                .negative_trust(NegativeClass::Structural, AbsenceSubstrate::Relations)
                .0
        );
    }
    #[test]
    fn no_recorded_debt_requires_observed_zero_not_missing_or_contradictory_count() {
        let mut clear = observation(SourceBinding::Current);
        let report = clear.report.as_mut().unwrap();
        report.prior_local_binding = PriorLocalBindingStatus::NoRecordedDebt;
        report.outstanding_local_binding_obligations = Some(0);
        assert_eq!(clear.limiting_factor(AbsenceSubstrate::Relations), None);
        let valid = serde_json::to_value(clear).unwrap();
        for count in [None, Some(json!(null)), Some(json!(1))] {
            let mut value = valid.clone();
            if let Some(count) = count {
                value["report"]["outstanding_local_binding_obligations"] = count;
            } else {
                value["report"]
                    .as_object_mut()
                    .unwrap()
                    .remove("outstanding_local_binding_obligations");
            }
            let observed: SourceDerivationObservation =
                serde_json::from_value(value.clone()).unwrap();
            assert!(observed
                .limiting_factor(AbsenceSubstrate::Relations)
                .unwrap()
                .contains("local_binding_unproven"));
            let envelope = healthy_envelope().with_payload_metadata(&json!({KEY:value}));
            assert!(
                !envelope
                    .negative_trust(NegativeClass::Structural, AbsenceSubstrate::Relations)
                    .0
            );
        }
    }
}
