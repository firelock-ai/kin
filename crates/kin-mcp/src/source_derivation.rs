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
}

impl SourceDerivationObservation {
    pub fn unavailable(reason: &str) -> Self {
        Self {
            scope: SourceObservationScope::SelectedScopeUnavailable,
            checked_scope: "selected_authority_unavailable".into(),
            sampled: "selected_graph_after_query".into(),
            report: Some(SourceDerivationReport::unproven(reason)),
            admission_failure: None,
        }
    }

    pub fn historical() -> Self {
        Self {
            scope: SourceObservationScope::SelectedHistorical,
            checked_scope: "historical_not_assessed_against_live_source".into(),
            sampled: "selected_graph_after_query".into(),
            report: None,
            admission_failure: None,
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
            Some(SourceBinding::Current) => match self.report.as_ref().map(|report| (report.prior_local_binding, report.outstanding_local_binding_obligations)) {
                Some((PriorLocalBindingStatus::NoRecordedDebt, Some(0))) => None,
                Some((PriorLocalBindingStatus::Outstanding, _)) => Some("local_binding_outstanding: previously local source bindings remain unresolved, so current body and parse evidence cannot establish complete dependency or call-shape knowledge"),
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
