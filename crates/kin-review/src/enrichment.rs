// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Recorded call-site limits on an impact or review answer.
//!
//! This is a conservative observation over the selected repository graph, not
//! evidence that each unsettled caller reaches the changed entities. Paths
//! label projections of entity identities; no file bytes are read here.

use std::collections::{BTreeSet, HashMap, HashSet};

use kin_model::{
    read_caller_sites, CallSiteFacts, CallSiteLedger, CallSiteTally, ContextValidationState,
    Entity, EntityId, GraphStore, LanguageId, ResolutionRecord, ResolutionRecordId,
    SemanticChangeId,
};
use serde::{Deserialize, Serialize};

use crate::ReviewError;

const PENDING_ENTITIES_MAX: usize = 20;

/// One batch of value-containment observations from the answer's source
/// authority. A named change requests that committed revision; `None` keeps
/// the caller's selected graph scope. Results correspond to the supplied
/// targets in order. Missing evidence never proves containment.
pub type EscapeEvidence<'a> =
    dyn Fn(&[Entity], Option<SemanticChangeId>) -> EscapeEvidenceBatch + 'a;

pub struct EscapeEvidenceBatch {
    pub selected_change: Option<SemanticChangeId>,
    pub readings: Vec<kin_model::FocalEscape>,
}

fn contained_targets(
    targets: &[Entity],
    at: Option<SemanticChangeId>,
    evidence: Option<&EscapeEvidence<'_>>,
) -> (Option<SemanticChangeId>, HashSet<EntityId>) {
    let Some(evidence) = evidence else {
        return (at, HashSet::new());
    };
    let batch = evidence(targets, at);
    if at.is_some() && batch.selected_change != at {
        return (at, HashSet::new());
    }
    if batch.readings.len() != targets.len() {
        return (batch.selected_change, HashSet::new());
    }
    let mut contained: HashSet<_> = targets.iter().map(|target| target.id).collect();
    for (target, reading) in targets.iter().zip(batch.readings) {
        if reading.may_escape() {
            contained.remove(&target.id);
        }
    }
    (batch.selected_change, contained)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentProjection {
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEnrichmentEntity {
    pub entity_id: EntityId,
    pub name: String,
    pub projection: EnrichmentProjection,
    pub states: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentObservation {
    /// `selected_graph_repository`, `selected_graph_impact` or `committed_graph`.
    pub scope: String,
    pub selected_change: Option<SemanticChangeId>,
    /// `bounded` or `no_recorded_call_site_debt`. The latter does not establish
    /// that reference, type or other enrichment has completed.
    pub status: String,
    pub basis: String,
    pub limitation: Option<String>,
    pub total_pending_entities: usize,
    pub pending_entities: Vec<PendingEnrichmentEntity>,
    pub entities_withheld: usize,
}

impl EnrichmentObservation {
    pub fn bounds_answer(&self) -> bool {
        self.status == "bounded"
    }
}

struct StoreLedgers<'a, G: ?Sized>(&'a G);

impl<G: GraphStore + ?Sized> CallSiteFacts for StoreLedgers<'_, G> {
    fn ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
        self.0
            .lookup_resolution_record(&ResolutionRecordId::call_sites(caller))
            .ok()
            .flatten()
            .and_then(|record| record.as_call_sites().cloned())
    }

    fn current_context(&self, language: LanguageId) -> Option<ResolutionRecordId> {
        self.0
            .lookup_resolution_record(&ResolutionRecordId::context_validation(language))
            .ok()
            .flatten()
            .and_then(|record| {
                record
                    .as_context_validation()
                    .and_then(|validation| validation.current_context())
            })
    }

    fn context_unverified_reason(&self, language: LanguageId) -> String {
        match self
            .0
            .lookup_resolution_record(&ResolutionRecordId::context_validation(language))
        {
            Ok(record) => validation_reason(record.as_ref()),
            Err(_) => "the selected graph's proof-context validation could not be read".into(),
        }
    }
}

struct CommittedLedgers<'a>(&'a HashMap<ResolutionRecordId, ResolutionRecord>);

impl CallSiteFacts for CommittedLedgers<'_> {
    fn ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
        self.0
            .get(&ResolutionRecordId::call_sites(caller))
            .and_then(|record| record.as_call_sites().cloned())
    }

    fn current_context(&self, language: LanguageId) -> Option<ResolutionRecordId> {
        self.0
            .get(&ResolutionRecordId::context_validation(language))
            .and_then(ResolutionRecord::as_context_validation)
            .and_then(|validation| validation.current_context())
    }

    fn context_unverified_reason(&self, language: LanguageId) -> String {
        validation_reason(
            self.0
                .get(&ResolutionRecordId::context_validation(language)),
        )
    }
}

fn validation_reason(record: Option<&ResolutionRecord>) -> String {
    match record
        .and_then(ResolutionRecord::as_context_validation)
        .map(|validation| &validation.state)
    {
        Some(ContextValidationState::Unverified { reason }) => reason.clone(),
        _ => "the selected graph has no recorded proof-context validation".into(),
    }
}

/// Read only the selected graph's persisted site evidence. No live server
/// readiness or retry queue can certify this observation.
pub fn observe_selected_graph<G: GraphStore + ?Sized>(
    store: &G,
) -> Result<EnrichmentObservation, ReviewError> {
    let entities = store.list_all_entities().map_err(ReviewError::graph)?;
    Ok(observe(&entities, &StoreLedgers(store), None, None))
}

/// Read the same replayed entities and ledgers as a committed review's impact.
pub(crate) fn observe_committed_graph(
    entities: &HashMap<EntityId, Entity>,
    records: &HashMap<ResolutionRecordId, ResolutionRecord>,
    change: SemanticChangeId,
) -> EnrichmentObservation {
    observe(
        entities.values(),
        &CommittedLedgers(records),
        Some(change),
        None,
    )
}

/// Observe this answer's reach, plus possible inbound callers across the
/// entire selected graph. Import families are never an exclusion boundary.
pub fn observe_selected_impact<G: GraphStore + ?Sized>(
    store: &G,
    targets: &[Entity],
    unknown_target: bool,
) -> Result<EnrichmentObservation, ReviewError> {
    observe_selected_impact_with_source(store, targets, unknown_target, None)
}

pub fn observe_selected_impact_with_source<G: GraphStore + ?Sized>(
    store: &G,
    targets: &[Entity],
    unknown_target: bool,
    escape_evidence: Option<&EscapeEvidence<'_>>,
) -> Result<EnrichmentObservation, ReviewError> {
    let entities = store.list_all_entities().map_err(ReviewError::graph)?;
    // Missing References edges do not prove value containment. A definitions
    // pass may leave a non-call occurrence unanswered, while its call ledger
    // still has a complete zero-site census. Until the selected graph supplies
    // positive containment evidence, retain possible callers through aliases.
    let (selected_change, contained) = contained_targets(targets, None, escape_evidence);
    let scope = ImpactScope::new(targets, &contained, unknown_target);
    Ok(observe(
        &entities,
        &StoreLedgers(store),
        selected_change,
        Some(&scope),
    ))
}

pub(crate) fn observe_committed_impact(
    entities: &HashMap<EntityId, Entity>,
    records: &HashMap<ResolutionRecordId, ResolutionRecord>,
    change: SemanticChangeId,
    targets: &[Entity],
    unknown_target: bool,
) -> EnrichmentObservation {
    observe_committed_impact_with_source(entities, records, change, targets, unknown_target, None)
}

pub(crate) fn observe_committed_impact_with_source(
    entities: &HashMap<EntityId, Entity>,
    records: &HashMap<ResolutionRecordId, ResolutionRecord>,
    change: SemanticChangeId,
    targets: &[Entity],
    unknown_target: bool,
    escape_evidence: Option<&EscapeEvidence<'_>>,
) -> EnrichmentObservation {
    // A historical view needs containment evidence from that selected graph.
    // Today's reference edges or source census cannot settle its value escapes.
    let (_, contained) = contained_targets(targets, Some(change), escape_evidence);
    let scope = ImpactScope::new(targets, &contained, unknown_target);
    observe(
        entities.values(),
        &CommittedLedgers(records),
        Some(change),
        Some(&scope),
    )
}

struct ImpactScope {
    reached: HashSet<EntityId>,
    names: Vec<(Vec<String>, bool)>,
    unknown_target: bool,
}

impl ImpactScope {
    /// Only a positive census from the selected graph may mark a target
    /// contained. Missing References edges never belong in this set.
    fn new(targets: &[Entity], contained: &HashSet<EntityId>, unknown_target: bool) -> Self {
        Self {
            reached: targets.iter().map(|target| target.id).collect(),
            names: targets
                .iter()
                .map(|target| {
                    (
                        kin_model::call_site_reading::focal_call_names(target),
                        !contained.contains(&target.id),
                    )
                })
                .collect(),
            unknown_target,
        }
    }

    fn readings(
        &self,
        entity: &Entity,
        reading: &kin_model::CallerSites,
    ) -> Vec<kin_model::CallerSites> {
        if self.unknown_target || self.reached.contains(&entity.id) {
            return vec![reading.clone()];
        }
        // A missing or abbreviated graph-owned preview cannot rule a call out.
        // Keep the model's name and call-site rules shared with reference reads.
        let body = entity
            .metadata
            .extra
            .get("embedding_body_preview")
            .and_then(serde_json::Value::as_str)
            .filter(|body| body.chars().count() <= 8000);
        self.names
            .iter()
            // Site filtering retains caller-level debt. Decide whether an
            // outside caller belongs to this scope before filtering its sites.
            // Only a whole body without a target spelling, and no possible
            // value escape, can exclude an owed or unverified outside caller.
            .filter(|(names, escapes)| {
                *escapes
                    || names.is_empty()
                    || body.is_none_or(|body| names.iter().any(|name| body.contains(name)))
            })
            .map(|(names, escapes)| {
                kin_model::call_site_reading::scope_caller_sites(reading, names, body, *escapes)
            })
            .collect()
    }
}

fn observe<'a, F: CallSiteFacts>(
    entities: impl IntoIterator<Item = &'a Entity>,
    facts: &F,
    selected_change: Option<SemanticChangeId>,
    scope: Option<&ImpactScope>,
) -> EnrichmentObservation {
    let mut pending = Vec::new();
    for entity in entities {
        let reading = read_caller_sites(facts, entity);
        let readings = scope.map_or_else(
            || vec![reading.clone()],
            |scope| scope.readings(entity, &reading),
        );
        let mut states = BTreeSet::new();
        for scoped in readings {
            let mut tally = CallSiteTally::default();
            tally.add(&scoped);
            if tally.is_settled() {
                continue;
            }
            let mut site_states: BTreeSet<String> = tally
                .by_state
                .iter()
                .filter(|(kind, count)| !kind.is_settled() && **count > 0)
                .map(|(kind, _)| kind.wire().to_string())
                .collect();
            if site_states.is_empty() {
                site_states.insert(scoped.wire().to_string());
            }
            states.extend(site_states);
        }
        if states.is_empty() {
            continue;
        }
        pending.push(PendingEnrichmentEntity {
            entity_id: entity.id,
            name: entity.name.clone(),
            projection: EnrichmentProjection {
                path: entity
                    .span
                    .as_ref()
                    .map(|span| span.file.to_string())
                    .or_else(|| entity.file_origin.as_ref().map(ToString::to_string)),
            },
            states: states.into_iter().collect(),
            validation_reason: match &reading {
                kin_model::CallerSites::Unverified { reason, .. } => Some(reason.clone()),
                _ => None,
            },
        });
    }
    pending.sort_by(|left, right| {
        (&left.projection.path, &left.name, left.entity_id).cmp(&(
            &right.projection.path,
            &right.name,
            right.entity_id,
        ))
    });
    let total_pending_entities = pending.len();
    pending.truncate(PENDING_ENTITIES_MAX);
    let bounded = total_pending_entities > 0;
    EnrichmentObservation {
        scope: if selected_change.is_some() { "committed_graph" } else if scope.is_some() { "selected_graph_impact" } else { "selected_graph_repository" }.into(),
        selected_change,
        status: if bounded { "bounded" } else { "no_recorded_call_site_debt" }.into(),
        basis: if scope.is_some() {
            "persisted_call_site_ledgers_and_context_validation_in_impact_reach_and_store_wide_possible_inbound_callers; other relation enrichment is not established by this observation"
        } else {
            "persisted_call_site_ledgers_and_context_validation; other relation enrichment is not established by this observation"
        }.into(),
        limitation: bounded.then(|| format!(
            "enrichment_incomplete: {total_pending_entities} entities {} have unsettled call-site evidence. Impact counts are a lower bound and review risk may change. This conservatively bounds the answer. It does not prove that every listed entity reaches the changed code.",
            if scope.is_some() { "in this impact's reach or among its possible inbound callers across the selected graph" } else { "in the selected repository graph" }
        )),
        total_pending_entities,
        entities_withheld: total_pending_entities.saturating_sub(pending.len()),
        pending_entities: pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        CallSite, CallSiteState, EntityKind, EntityMetadata, EntityRole, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, RelationKind, SemanticFingerprint,
        ServerFailure, SourceSpan, Visibility,
    };

    fn entity(name: &str, path: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 3,
                start_line: 41,
                start_col: 0,
                end_line: 41,
                end_col: 3,
            }),
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn validation() -> ResolutionRecord {
        ResolutionRecord::ContextValidation(kin_model::ContextValidation {
            language: LanguageId::Python,
            state: ContextValidationState::Validated {
                context: kin_model::ProofContext {
                    language: LanguageId::Python,
                    resolver: "lsp:test".into(),
                    resolver_version: "1".into(),
                    configuration_hash: Hash256::from_bytes([0; 32]),
                    environment_hash: Hash256::from_bytes([0; 32]),
                    environment_summary: "test".into(),
                },
            },
        })
    }

    fn record(entity: &Entity, state: CallSiteState) -> ResolutionRecord {
        ResolutionRecord::CallSites(CallSiteLedger {
            caller: entity.id,
            behavior_hash: entity.fingerprint.behavior_hash,
            body_hash: Hash256::from_bytes([0; 32]),
            context: validation()
                .as_context_validation()
                .unwrap()
                .current_context()
                .unwrap(),
            census: 1,
            sites: vec![CallSite {
                offset: 0,
                length: 1,
                state,
            }],
        })
    }

    #[test]
    fn missing_failed_and_proven_ledgers_have_distinct_truthful_disclosures() {
        let pending = entity("pending", "src/pending.py");
        let failed = entity("failed", "src/failed.py");
        let settled = entity("settled", "src/settled.py");
        let records = [
            record(
                &failed,
                CallSiteState::ServerFailed {
                    reason: ServerFailure::Timeout,
                },
            ),
            record(&settled, CallSiteState::ProvenOutside),
        ]
        .into_iter()
        .chain(std::iter::once(validation()))
        .map(|record| (record.id(), record))
        .collect();
        let entities = [&pending, &failed, &settled];
        let observation = observe(entities, &CommittedLedgers(&records), None, None);
        assert!(observation.bounds_answer());
        assert_eq!(observation.total_pending_entities, 2);
        assert_eq!(observation.pending_entities[0].entity_id, failed.id);
        assert_eq!(observation.pending_entities[0].states, ["server_failed"]);
        assert_eq!(observation.pending_entities[1].states, ["owed_enrichment"]);
        let json = serde_json::to_value(&observation).unwrap();
        assert_eq!(
            json["pending_entities"][1]["projection"]["path"],
            "src/pending.py"
        );
        assert!(json["pending_entities"][1].get("line").is_none());
        assert!(json["pending_entities"][1]["projection"]
            .get("line")
            .is_none());
        assert!(observation.limitation.unwrap().contains("does not prove"));

        let records = entities
            .into_iter()
            .map(|entity| record(entity, CallSiteState::ProvenOutside))
            .chain(std::iter::once(validation()))
            .map(|record| (record.id(), record))
            .collect();
        let settled = observe(entities, &CommittedLedgers(&records), None, None);
        assert_eq!(settled.status, "no_recorded_call_site_debt");
        assert!(!settled.bounds_answer());
        assert!(settled.limitation.is_none());
        assert!(settled
            .basis
            .contains("other relation enrichment is not established"));
    }

    #[test]
    fn context_validation_committed_observation_preserves_unverified_reason() {
        let caller = entity("recorded", "src/app.py");
        let ledger = record(&caller, CallSiteState::ProvenOutside);
        let mut records = HashMap::from([(ledger.id(), ledger)]);
        let change = SemanticChangeId::from_hash(Hash256::from_bytes([7; 32]));
        let entities = HashMap::from([(caller.id, caller.clone())]);
        let missing = observe_committed_graph(&entities, &records, change);
        assert_eq!(missing.scope, "committed_graph");
        assert_eq!(missing.selected_change, Some(change));
        assert_eq!(
            missing.pending_entities[0].states,
            ["proof_context_unverified"]
        );
        assert!(missing.pending_entities[0]
            .validation_reason
            .as_ref()
            .unwrap()
            .contains("no recorded"));
        let record = ResolutionRecord::ContextValidation(kin_model::ContextValidation {
            language: LanguageId::Python,
            state: ContextValidationState::Unverified {
                reason: "resolver validation failed".into(),
            },
        });
        records.insert(record.id(), record);
        let unverified = observe_committed_graph(&entities, &records, change);
        assert_eq!(
            unverified.pending_entities[0].validation_reason.as_deref(),
            Some("resolver validation failed")
        );
        let validated = validation();
        records.insert(validated.id(), validated);
        let recorded = observe_committed_graph(&entities, &records, change);
        assert_eq!(recorded.status, "no_recorded_call_site_debt");
        assert!(recorded
            .basis
            .contains("other relation enrichment is not established"));
    }

    fn with_body(mut entity: Entity, body: &str) -> Entity {
        entity
            .metadata
            .extra
            .insert("embedding_body_preview".into(), serde_json::json!(body));
        entity.span.as_mut().unwrap().end_byte = body.len();
        entity
    }

    fn unresolved(entity: &Entity, callee: &str) -> ResolutionRecord {
        let body = entity.metadata.extra["embedding_body_preview"]
            .as_str()
            .unwrap();
        let mut record = record(
            entity,
            CallSiteState::Unresolved {
                reason: kin_model::UnresolvedReason::NoAnswer,
            },
        );
        if let ResolutionRecord::CallSites(ledger) = &mut record {
            ledger.sites[0].offset = body.find(callee).unwrap() as u32;
            ledger.sites[0].length = callee.len() as u32;
        }
        record
    }

    fn empty_ledger(entity: &Entity) -> ResolutionRecord {
        let mut record = record(entity, CallSiteState::ProvenOutside);
        if let ResolutionRecord::CallSites(ledger) = &mut record {
            ledger.census = 0;
            ledger.sites.clear();
        }
        record
    }

    fn records_with_validation(
        records: Vec<ResolutionRecord>,
    ) -> HashMap<ResolutionRecordId, ResolutionRecord> {
        records
            .into_iter()
            .chain(std::iter::once(validation()))
            .map(|record| (record.id(), record))
            .collect()
    }

    #[test]
    fn impact_scope_contained_target_keeps_only_store_wide_name_candidates() {
        let target = entity("AppContext.pop", "src/ctx.py");
        let unrelated = with_body(entity("json_reader", "src/other.py"), "json.dumps(value)");
        let missed = with_body(entity("fixture_user", "tests/test_reqctx.py"), "app.pop()");
        let entities: HashMap<EntityId, Entity> = HashMap::from_iter(
            [target.clone(), unrelated.clone(), missed.clone()]
                .into_iter()
                .map(|entity| (entity.id, entity)),
        );
        let records = records_with_validation(vec![
            empty_ledger(&target),
            unresolved(&unrelated, "dumps"),
            unresolved(&missed, "pop"),
        ]);
        let scope = ImpactScope::new(
            std::slice::from_ref(&target),
            &HashSet::from([target.id]),
            false,
        );
        let observation = observe(
            entities.values(),
            &CommittedLedgers(&records),
            None,
            Some(&scope),
        );
        assert_eq!(observation.scope, "selected_graph_impact");
        assert_eq!(observation.total_pending_entities, 1);
        assert_eq!(observation.pending_entities[0].entity_id, missed.id);
        assert_eq!(observation.pending_entities[0].states, ["unresolved"]);
        let without_candidate = [&target, &unrelated];
        let scoped = observe(
            without_candidate,
            &CommittedLedgers(&records),
            None,
            Some(&scope),
        );
        assert!(!scoped.bounds_answer());
        assert!(
            observe(without_candidate, &CommittedLedgers(&records), None, None).bounds_answer()
        );
    }

    #[test]
    fn impact_scope_includes_possible_callers_of_reached_entities_without_import_edges() {
        use kin_model::{
            EntityStore, GraphNodeId, Relation, RelationId, RelationOrigin, ResolutionRecordDelta,
            TransactionDelta,
        };
        let target = entity("changed", "src/a.py");
        let caller = with_body(entity("reached", "src/b.py"), "changed()");
        let candidate = with_body(entity("not_importing", "tests/fixture.py"), "reached()");
        let unrelated = with_body(entity("unrelated", "elsewhere/c.py"), "other()");
        let graph = kin_db::InMemoryGraph::new();
        for entity in [&target, &caller, &candidate, &unrelated] {
            graph.upsert_entity(entity).unwrap();
        }
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 1.0,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: vec![],
            })
            .unwrap();
        let validation = validation();
        let ContextValidationState::Validated { context } =
            &validation.as_context_validation().unwrap().state
        else {
            unreachable!()
        };
        let mut proven = unresolved(&caller, "changed");
        if let ResolutionRecord::CallSites(ledger) = &mut proven {
            ledger.sites[0].state = CallSiteState::ProvenTarget { target: target.id };
        }
        let records = vec![
            ResolutionRecord::ProofContext(context.clone()),
            validation,
            empty_ledger(&target),
            proven,
            unresolved(&candidate, "reached"),
            unresolved(&unrelated, "other"),
        ];
        graph
            .apply_transaction_delta(&TransactionDelta {
                resolution_record_deltas: records
                    .into_iter()
                    .map(|new| ResolutionRecordDelta::Added { new })
                    .collect(),
                ..Default::default()
            })
            .unwrap();
        let diff = crate::diff::SemanticDiff {
            entity_changes: vec![crate::diff::EntityChange {
                entity_id: target.id,
                kind: crate::diff::EntityChangeKind::Added(target.clone()),
            }],
            ..Default::default()
        };
        let report = crate::impact::analyze_impact(&graph, &diff).unwrap();
        assert_eq!(
            report
                .affected_callers
                .iter()
                .map(|entity| entity.id)
                .collect::<Vec<_>>(),
            [caller.id]
        );
        let observation = report.enrichment.unwrap();
        assert_eq!(observation.total_pending_entities, 2);
        assert!(observation
            .pending_entities
            .iter()
            .any(|entity| entity.entity_id == candidate.id));
        assert!(observation
            .pending_entities
            .iter()
            .any(|entity| entity.entity_id == unrelated.id));
        assert!(observation.bounds_answer());
        assert!(observation
            .basis
            .contains("store_wide_possible_inbound_callers"));
        // The graph has not proved value containment, so a different spelling
        // alone cannot exclude an unsettled caller of the initial focal.
        assert!(
            observe_selected_impact(&graph, std::slice::from_ref(&target), false)
                .unwrap()
                .bounds_answer()
        );
        let changed_relation = graph
            .get_all_relations_for_entity(&target.id)
            .unwrap()
            .remove(0);
        let relation_diff = crate::diff::SemanticDiff {
            relation_changes: vec![crate::diff::RelationChange {
                kind: crate::diff::RelationChangeKind::Modified {
                    old: changed_relation.clone(),
                    new: changed_relation,
                },
            }],
            ..Default::default()
        };
        let relation_observation = crate::impact::analyze_impact(&graph, &relation_diff)
            .unwrap()
            .enrichment
            .unwrap();
        assert_eq!(relation_observation.total_pending_entities, 2);
        assert!(relation_observation
            .pending_entities
            .iter()
            .any(|entity| entity.entity_id == candidate.id));
    }

    #[test]
    fn impact_scope_binding_candidates_stay_bounded_when_a_reached_value_escapes() {
        let target = entity("target", "src/a.py");
        let callback = with_body(entity("callback_user", "other/callback.py"), "callback()");
        let mut binding = unresolved(&callback, "callback");
        if let ResolutionRecord::CallSites(ledger) = &mut binding {
            ledger.sites[0].state = CallSiteState::Binding { may_call: None };
        }
        let records = records_with_validation(vec![empty_ledger(&target), binding]);
        let escaped = ImpactScope::new(std::slice::from_ref(&target), &HashSet::new(), false);
        let observation = observe(
            [&target, &callback],
            &CommittedLedgers(&records),
            None,
            Some(&escaped),
        );
        assert!(observation.bounds_answer());
        assert_eq!(observation.pending_entities[0].entity_id, callback.id);
        assert_eq!(observation.pending_entities[0].states, ["binding"]);
        let contained = ImpactScope::new(
            std::slice::from_ref(&target),
            &HashSet::from([target.id]),
            false,
        );
        assert!(!observe(
            [&target, &callback],
            &CommittedLedgers(&records),
            None,
            Some(&contained),
        )
        .bounds_answer());
    }

    #[test]
    fn impact_scope_unanswered_non_call_value_escape_keeps_binding_callers() {
        use kin_model::{EntityStore, ResolutionRecordDelta, TransactionDelta};

        let target = with_body(entity("target", "src/target.py"), "def target(): return 1");
        let factory = with_body(
            entity("factory", "src/factory.py"),
            "def factory(): return target",
        );
        let callback = with_body(entity("consumer", "other/callback.py"), "callback()");
        let mut binding = unresolved(&callback, "callback");
        if let ResolutionRecord::CallSites(ledger) = &mut binding {
            ledger.sites[0].state = CallSiteState::Binding { may_call: None };
        }
        // NoAnswer for `target` in `return target` mints no References edge.
        // The call-only ledger still truthfully records zero sites in factory.
        let records =
            records_with_validation(vec![empty_ledger(&target), empty_ledger(&factory), binding]);
        let graph = kin_db::InMemoryGraph::new();
        let entities: HashMap<EntityId, Entity> = HashMap::from_iter(
            [target.clone(), factory, callback.clone()]
                .into_iter()
                .map(|entity| (entity.id, entity)),
        );
        for entity in entities.values() {
            graph.upsert_entity(entity).unwrap();
        }
        let validated = validation();
        let ContextValidationState::Validated { context } =
            &validated.as_context_validation().unwrap().state
        else {
            unreachable!()
        };
        graph
            .apply_transaction_delta(&TransactionDelta {
                resolution_record_deltas: std::iter::once(ResolutionRecord::ProofContext(
                    context.clone(),
                ))
                .chain(records.values().cloned())
                .map(|new| ResolutionRecordDelta::Added { new })
                .collect(),
                ..Default::default()
            })
            .unwrap();
        assert!(graph
            .get_all_relations_for_entity(&target.id)
            .unwrap()
            .is_empty());

        let current =
            observe_selected_impact(&graph, std::slice::from_ref(&target), false).unwrap();
        let change = SemanticChangeId::from_hash(Hash256::from_bytes([82; 32]));
        let historical = observe_committed_impact(
            &entities,
            &records,
            change,
            std::slice::from_ref(&target),
            false,
        );
        assert_eq!(historical.selected_change, Some(change));
        assert_eq!(historical.scope, "committed_graph");
        for observation in [current, historical] {
            assert!(observation.bounds_answer());
            assert_eq!(observation.total_pending_entities, 1);
            assert_eq!(observation.pending_entities[0].entity_id, callback.id);
            assert_eq!(observation.pending_entities[0].states, ["binding"]);
        }

        // Unknown containment does not manufacture debt for settled ledgers.
        let settled = record(&callback, CallSiteState::ProvenOutside);
        let mut settled_records = records.clone();
        settled_records.insert(settled.id(), settled);
        assert!(
            !observe_committed_impact(&entities, &settled_records, change, &[target], false,)
                .bounds_answer()
        );
    }

    #[test]
    fn impact_scope_keeps_missing_bodies_and_unknown_removed_identities_conservative() {
        let target = entity("target", "src/a.py");
        let unknown = entity("unknown", "other/b.py");
        let unrelated = with_body(entity("unrelated", "other/c.py"), "other()");
        // No ledger: its complete body still excludes this outside caller
        // because it names no target and no target escapes as a value.
        let records = records_with_validation(vec![empty_ledger(&target)]);
        let scope = ImpactScope::new(
            std::slice::from_ref(&target),
            &HashSet::from([target.id]),
            false,
        );
        let observation = observe(
            [&target, &unknown, &unrelated],
            &CommittedLedgers(&records),
            None,
            Some(&scope),
        );
        assert_eq!(observation.total_pending_entities, 1);
        assert_eq!(observation.pending_entities[0].entity_id, unknown.id);
        let unknown_removal = ImpactScope::new(&[], &HashSet::new(), true);
        assert!(observe(
            [&unrelated],
            &CommittedLedgers(&records),
            None,
            Some(&unknown_removal)
        )
        .bounds_answer());
        let no_change = ImpactScope::new(&[], &HashSet::new(), false);
        assert!(!observe(
            [&unrelated],
            &CommittedLedgers(&records),
            None,
            Some(&no_change)
        )
        .bounds_answer());
    }

    #[test]
    fn impact_scope_source_batch_is_selected_once_and_rejects_wrong_revision() {
        use kin_model::FocalEscape;
        let target = entity("target", "src/target.py");
        let callback = with_body(entity("consumer", "other/callback.py"), "callback()");
        let mut binding = unresolved(&callback, "callback");
        if let ResolutionRecord::CallSites(ledger) = &mut binding {
            ledger.sites[0].state = CallSiteState::Binding { may_call: None };
        }
        let entities = HashMap::from([(target.id, target.clone()), (callback.id, callback)]);
        let records = records_with_validation(vec![empty_ledger(&target), binding]);
        let change = SemanticChangeId::from_hash(Hash256::from_bytes([83; 32]));
        let calls = std::cell::Cell::new(0);
        let exact = |targets: &[Entity], at| {
            calls.set(calls.get() + 1);
            assert_eq!(at, Some(change));
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].id, target.id);
            EscapeEvidenceBatch {
                selected_change: at,
                readings: vec![FocalEscape::Contained {
                    entities_checked: 2,
                }],
            }
        };
        let settled = observe_committed_impact_with_source(
            &entities,
            &records,
            change,
            std::slice::from_ref(&target),
            false,
            Some(&exact),
        );
        assert_eq!(calls.get(), 1);
        assert!(!settled.bounds_answer());
        assert_eq!(settled.selected_change, Some(change));

        let wrong_revision = |_: &[Entity], _| EscapeEvidenceBatch {
            selected_change: None,
            readings: vec![FocalEscape::Contained {
                entities_checked: 2,
            }],
        };
        let bounded = observe_committed_impact_with_source(
            &entities,
            &records,
            change,
            std::slice::from_ref(&target),
            false,
            Some(&wrong_revision),
        );
        assert!(bounded.bounds_answer());
        assert_eq!(bounded.selected_change, Some(change));
        let missing = |_: &[Entity], at| EscapeEvidenceBatch {
            selected_change: at,
            readings: Vec::new(),
        };
        assert!(observe_committed_impact_with_source(
            &entities,
            &records,
            change,
            std::slice::from_ref(&target),
            false,
            Some(&missing),
        )
        .bounds_answer());

        // A rename may retain one identity on both sides. One contained
        // spelling must not erase unknown evidence for the other spelling.
        let mut renamed = target.clone();
        renamed.name = "renamed".into();
        let mixed = |_: &[Entity], at| EscapeEvidenceBatch {
            selected_change: at,
            readings: vec![
                FocalEscape::Contained {
                    entities_checked: 2,
                },
                FocalEscape::Unknown {
                    reason: "old spelling unavailable",
                },
            ],
        };
        assert!(
            contained_targets(&[target, renamed], Some(change), Some(&mixed))
                .1
                .is_empty()
        );
    }

    #[test]
    fn impact_scope_preserves_committed_validation_and_relevant_pending_counts() {
        let target = entity("target", "src/a.py");
        let pending = with_body(entity("historical_caller", "old/b.py"), "target()");
        let entities = HashMap::from([(target.id, target.clone()), (pending.id, pending.clone())]);
        let records = HashMap::from_iter(
            [empty_ledger(&target), unresolved(&pending, "target")]
                .into_iter()
                .map(|record| (record.id(), record)),
        );
        let change = SemanticChangeId::from_hash(Hash256::from_bytes([81; 32]));
        let observation = observe_committed_impact(&entities, &records, change, &[target], false);
        assert_eq!(observation.scope, "committed_graph");
        assert_eq!(observation.selected_change, Some(change));
        assert!(observation.bounds_answer());
        let held = observation
            .pending_entities
            .iter()
            .find(|row| row.entity_id == pending.id)
            .unwrap();
        assert_eq!(held.states, ["proof_context_unverified"]);
        assert!(held
            .validation_reason
            .as_ref()
            .unwrap()
            .contains("no recorded"));
    }

    #[test]
    fn pending_entity_order_and_withheld_count_are_deterministic() {
        let entities: Vec<_> = (0..25)
            .rev()
            .map(|index| entity(&format!("pending_{index:02}"), "src/app.py"))
            .collect();
        let observation = observe(&entities, &CommittedLedgers(&HashMap::new()), None, None);
        assert_eq!(observation.total_pending_entities, 25);
        assert_eq!(observation.pending_entities.len(), 20);
        assert_eq!(observation.entities_withheld, 5);
        assert_eq!(observation.pending_entities[0].name, "pending_00");
        assert_eq!(observation.pending_entities[19].name, "pending_19");
    }
}
