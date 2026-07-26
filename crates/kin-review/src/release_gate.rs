// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared release-gate and security-scan logic.
//!
//! These checks back both `kin release --require-approval` / `kin security`
//! (the CLI surface) and the `kin_release_check` / `kin_security_scan` MCP
//! tools. Keeping the gate semantics in one place prevents the two surfaces
//! from drifting — a divergence that previously let the MCP approval gate pass
//! on any audit event while the CLI required an actual approval.

use kin_model::change::EntityDelta;
use kin_model::entity::{EntityKind, Visibility};
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, SemanticChangeId};
use kin_model::provenance::{ActorKind, ApprovalDecision};
use kin_model::relation::{GraphNodeId, RelationKind};
use kin_model::verification::{CoverageSummary, VerificationStatus};

use crate::error::ReviewError;

/// A non-root change without a recorded human approval, found while walking history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnapprovedChange {
    pub change_id: SemanticChangeId,
    pub author: String,
}

/// Walk change history from `head` and collect non-root changes that lack a
/// recorded approval by a known human actor.
///
/// `SemanticChange.author` is an unauthenticated display string and supported
/// daemon commits commonly populate it with the OS username even when an agent
/// authored the change. It therefore cannot safely decide whether approval is
/// required. The release gate fails closed for every non-root change and only
/// accepts an `Approved` decision whose approver resolves to `ActorKind::Human`.
pub fn unapproved_changes<G: GraphStore>(
    store: &G,
    head: &SemanticChangeId,
    limit: usize,
) -> Result<Vec<UnapprovedChange>, ReviewError> {
    let mut unapproved = Vec::new();
    let mut pending = vec![*head];
    let mut visited = std::collections::HashSet::new();

    for _ in 0..limit {
        let Some(current) = pending.pop() else {
            break;
        };
        if !visited.insert(current) {
            continue;
        }
        let change = store
            .get_change(&current)
            .map_err(ReviewError::graph)?
            .ok_or(ReviewError::RefStateUnavailable {
                at: *head,
                missing: current,
            })?;

        let mut is_approved = false;
        for approval in store
            .get_approvals_for_change(&change.id)
            .map_err(ReviewError::graph)?
        {
            if approval.decision != ApprovalDecision::Approved {
                continue;
            }
            if store
                .get_actor(&approval.approver)
                .map_err(ReviewError::graph)?
                .is_some_and(|actor| actor.kind == ActorKind::Human)
            {
                is_approved = true;
                break;
            }
        }
        if !change.parents.is_empty() && !is_approved {
            unapproved.push(UnapprovedChange {
                change_id: change.id,
                author: change.author.0.clone(),
            });
        }

        for parent in change.parents.iter().rev() {
            if !visited.contains(parent) {
                pending.push(*parent);
            }
        }
    }

    unapproved.sort_by_key(|change| change.change_id.to_string());
    Ok(unapproved)
}

// Compatibility aliases for downstream crates compiled against the pre-0.3
// symbol names. The policy has always been conservative at this boundary: it
// applies to every non-root change, regardless of the unauthenticated author
// display string.
pub use unapproved_changes as unapproved_agent_changes;
pub use UnapprovedChange as UnapprovedAgentChange;

/// Compute current, advisory proof coverage for a graph.
///
/// Structural `Test -> Covers -> Entity` links describe intended coverage,
/// but do not prove that a test ran or passed. Release proof therefore counts
/// an entity only when at least one persisted `VerificationRun` linked through
/// `run_proves_entity` has status `Passing`.
pub fn passing_proof_coverage<G: GraphStore>(store: &G) -> Result<CoverageSummary, ReviewError> {
    let mut entities = store.list_all_entities().map_err(ReviewError::graph)?;
    entities.sort_by_key(|entity| entity.id.to_string());

    let mut covered_entities = 0_usize;
    let mut missing_proof = Vec::new();
    for entity in &entities {
        let has_passing_run = store
            .list_runs_proving_entity(&entity.id)
            .map_err(ReviewError::graph)?
            .iter()
            .any(|run| run.status == VerificationStatus::Passing);
        if has_passing_run {
            covered_entities += 1;
        } else {
            missing_proof.push(entity.id);
        }
    }

    let total_entities = entities.len();
    let coverage_ratio = if total_entities == 0 {
        0.0
    } else {
        covered_entities as f64 / total_entities as f64
    };
    Ok(CoverageSummary {
        total_entities,
        covered_entities,
        coverage_ratio,
        missing_proof,
    })
}

/// Compute proof coverage admissible for an immutable release source.
///
/// `VerificationRun` currently has no source-change or source-manifest field,
/// so a passing run in live graph state cannot prove an older immutable source
/// and must not authorize publication. Until that binding exists, release
/// admission fails closed by reporting every source entity as missing proof.
/// The empty source is vacuously covered.
pub fn source_bound_release_proof_coverage<G: GraphStore>(
    store: &G,
) -> Result<CoverageSummary, ReviewError> {
    let mut entities = store.list_all_entities().map_err(ReviewError::graph)?;
    entities.sort_by_key(|entity| entity.id.to_string());
    Ok(source_bound_release_proof_coverage_for_entities(
        entities.iter(),
    ))
}

/// Compute fail-closed release coverage for an already-resolved immutable
/// source state.
///
/// Callers use this after resolving a specific branch head or change, so
/// ambient graph overlays cannot change the release count. Verification runs
/// do not yet carry an immutable source binding; every entity in a non-empty
/// source therefore remains missing and coverage is exactly 0%.
pub fn source_bound_release_proof_coverage_for_entities<'a>(
    entities: impl IntoIterator<Item = &'a kin_model::Entity>,
) -> CoverageSummary {
    let mut missing_proof = entities
        .into_iter()
        .map(|entity| entity.id)
        .collect::<Vec<_>>();
    missing_proof.sort_by_key(ToString::to_string);
    let total_entities = missing_proof.len();
    CoverageSummary {
        total_entities,
        covered_entities: 0,
        coverage_ratio: if total_entities == 0 { 1.0 } else { 0.0 },
        missing_proof,
    }
}

/// Severity of a security finding, ordered low → high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecuritySeverity::Info => write!(f, "INFO"),
            SecuritySeverity::Low => write!(f, "LOW"),
            SecuritySeverity::Medium => write!(f, "MEDIUM"),
            SecuritySeverity::High => write!(f, "HIGH"),
        }
    }
}

/// A single security/quality finding from the graph scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    pub severity: SecuritySeverity,
    pub category: &'static str,
    pub message: String,
    pub entity_id: EntityId,
    pub entity_name: String,
}

/// Run the graph-based security/quality scan and return structured findings.
///
/// Surfaces, for the entity graph:
///   - `untested-api`: API endpoints with no test coverage (high)
///   - `orphaned-public`: public functions/methods with no callers or tests (low)
///   - `high-fan-out`: public entities with a large downstream blast radius (medium)
///   - `dead-event`: event contracts with no consumers (medium)
///   - `encapsulation-leak`: public entities calling private internals (low)
///
/// When `propagate` is set, additionally emits `transitive-dependency` (info)
/// findings for every entity downstream of a flagged entity. Findings are
/// returned sorted by severity, highest first.
pub fn security_findings<G: GraphStore>(
    store: &G,
    propagate: bool,
) -> Result<Vec<SecurityFinding>, ReviewError> {
    let entities = store.list_all_entities().map_err(ReviewError::graph)?;

    let mut findings: Vec<SecurityFinding> = Vec::new();

    for entity in &entities {
        let relations = store
            .get_all_relations_for_entity(&entity.id)
            .map_err(ReviewError::graph)?;

        // 1. Exposed API endpoints without test coverage.
        if entity.kind == EntityKind::ApiEndpoint {
            let has_test = relations.iter().any(|r| r.kind == RelationKind::Tests);
            if !has_test {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    category: "untested-api",
                    message: "API endpoint has no test coverage".into(),
                    entity_id: entity.id,
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 2. Public functions/methods with no callers (orphaned surface area).
        if entity.visibility == Visibility::Public
            && matches!(entity.kind, EntityKind::Function | EntityKind::Method)
        {
            let has_callers = relations
                .iter()
                .any(|r| r.kind == RelationKind::Calls && r.dst == GraphNodeId::Entity(entity.id));
            let has_tests = relations.iter().any(|r| r.kind == RelationKind::Tests);
            if !has_callers && !has_tests {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Low,
                    category: "orphaned-public",
                    message: "Public entity has no callers or tests — unnecessary attack surface"
                        .into(),
                    entity_id: entity.id,
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 3. Deep dependency chains (transitive risk).
        if entity.visibility == Visibility::Public {
            let downstream = store
                .get_downstream_impact(&entity.id, 5)
                .map_err(ReviewError::graph)?;
            if downstream.len() > 20 {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Medium,
                    category: "high-fan-out",
                    message: format!(
                        "Public entity has {} downstream dependents (high blast radius)",
                        downstream.len()
                    ),
                    entity_id: entity.id,
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 4. Event contracts without consumers.
        if entity.kind == EntityKind::EventContract {
            let has_consumer = relations.iter().any(|r| {
                r.kind == RelationKind::ConsumesContract && r.src != GraphNodeId::Entity(entity.id)
            });
            if !has_consumer {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::Medium,
                    category: "dead-event",
                    message:
                        "Event contract has no consumers — potential dead code or missing handler"
                            .into(),
                    entity_id: entity.id,
                    entity_name: entity.name.clone(),
                });
            }
        }

        // 5. Public entity calling private internals (encapsulation leak).
        if entity.visibility == Visibility::Public {
            let outgoing_calls = relations.iter().filter(|r| {
                r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(entity.id)
            });
            for call in outgoing_calls {
                let Some(target_id) = call.dst.as_entity() else {
                    continue;
                };
                if let Some(target) = store.get_entity(&target_id).map_err(ReviewError::graph)? {
                    if target.visibility == Visibility::Private {
                        findings.push(SecurityFinding {
                            severity: SecuritySeverity::Low,
                            category: "encapsulation-leak",
                            message: format!(
                                "Public entity calls private '{}' — encapsulation boundary violation",
                                target.name
                            ),
                            entity_id: entity.id,
                            entity_name: entity.name.clone(),
                        });
                    }
                }
            }
        }
    }

    // 6. Transitive vulnerability propagation.
    if propagate {
        let flagged_ids: std::collections::HashSet<EntityId> =
            findings.iter().map(|f| f.entity_id).collect();
        let mut transitive = Vec::new();

        for entity in &entities {
            if !flagged_ids.contains(&entity.id) {
                continue;
            }
            let downstream = store
                .get_downstream_impact(&entity.id, 10)
                .map_err(ReviewError::graph)?;
            for dep in &downstream {
                transitive.push(SecurityFinding {
                    severity: SecuritySeverity::Info,
                    category: "transitive-dependency",
                    message: format!(
                        "Transitively affected by vulnerable '{}' (depth <= 10)",
                        entity.name
                    ),
                    entity_id: dep.id,
                    entity_name: dep.name.clone(),
                });
            }
        }

        findings.extend(transitive);
    }

    // Sort highest severity first, then by a total key (category, name, entity id)
    // so the findings list is byte-stable run-to-run. Without the tie-break, order
    // within a severity tier would follow `list_all_entities` iteration order and
    // reorder across identical-state scans — phantom diffs for agents.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.category.cmp(b.category))
            .then_with(|| a.entity_name.cmp(&b.entity_name))
            .then_with(|| a.entity_id.cmp(&b.entity_id))
    });
    Ok(findings)
}

/// Tally of findings by severity, for summary rendering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityFindingCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SecurityFindingCounts {
    pub fn of(findings: &[SecurityFinding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.severity {
                SecuritySeverity::High => counts.high += 1,
                SecuritySeverity::Medium => counts.medium += 1,
                SecuritySeverity::Low => counts.low += 1,
                SecuritySeverity::Info => counts.info += 1,
            }
        }
        counts
    }
}

/// Entity IDs touched by a change's entity deltas (added/modified/removed).
///
/// Useful for release gates that need to relate a change to the entities it
/// affects.
pub fn entities_touched_by_change(deltas: &[EntityDelta]) -> Vec<EntityId> {
    deltas
        .iter()
        .map(|delta| match delta {
            EntityDelta::Added(entity) => entity.id,
            EntityDelta::Modified { new, .. } => new.id,
            EntityDelta::Removed(id) => *id,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::change::SemanticChange;
    use kin_model::entity::{
        Entity, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
    };
    use kin_model::graph::{ChangeStore, EntityStore, ProvenanceStore, VerificationStore};
    use kin_model::ids::{AuthorId, Hash256, LanguageId, RelationId};
    use kin_model::provenance::{Actor, ActorId, Approval, ApprovalId};
    use kin_model::relation::{Relation, RelationOrigin};
    use kin_model::timestamp::Timestamp;

    fn entity(name: &str, kind: EntityKind, visibility: Visibility) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn change(id: u8, parent: Option<u8>, author: &str) -> SemanticChange {
        SemanticChange {
            id: change_id(id),
            parents: parent.map(|p| vec![change_id(p)]).unwrap_or_default(),
            timestamp: Timestamp::now(),
            author: AuthorId::new(author),
            message: format!("change {}", id),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn approval(change: &SemanticChange, decision: ApprovalDecision) -> Approval {
        Approval {
            approval_id: ApprovalId::new(),
            change_id: change.id,
            approver: ActorId::from_hash(Hash256::from_bytes([0xa5; 32])),
            decision,
            reason: "test".into(),
            timestamp: Timestamp::now(),
        }
    }

    fn register_approver(store: &InMemoryGraph, kind: ActorKind) {
        store
            .create_actor(&Actor {
                actor_id: ActorId::from_hash(Hash256::from_bytes([0xa5; 32])),
                kind,
                display_name: "reviewer".into(),
                external_refs: vec![],
            })
            .unwrap();
    }

    fn add_root(store: &InMemoryGraph) {
        store.create_change(&change(0, None, "kin")).unwrap();
    }

    fn calls(src: &Entity, dst: &Entity) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    // ── require_approval gate (unapproved_agent_changes) ────────────────────

    #[test]
    fn agent_change_without_approval_is_flagged() {
        let store = InMemoryGraph::new();
        add_root(&store);
        let c = change(1, Some(0), "claude-agent");
        store.create_change(&c).unwrap();

        let found = unapproved_agent_changes(&store, &c.id, 50).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].change_id, c.id);
        assert_eq!(found[0].author, "claude-agent");
    }

    #[test]
    fn agent_change_with_approval_is_not_flagged() {
        let store = InMemoryGraph::new();
        add_root(&store);
        register_approver(&store, ActorKind::Human);
        let c = change(1, Some(0), "claude-agent");
        store.create_change(&c).unwrap();
        store
            .create_approval(&approval(&c, ApprovalDecision::Approved))
            .unwrap();

        let found = unapproved_agent_changes(&store, &c.id, 50).unwrap();
        assert!(found.is_empty(), "approved agent change must not block");
    }

    #[test]
    fn display_name_cannot_bypass_required_approval() {
        let store = InMemoryGraph::new();
        add_root(&store);
        let c = change(1, Some(0), "alice");
        store.create_change(&c).unwrap();

        let found = unapproved_agent_changes(&store, &c.id, 50).unwrap();
        assert_eq!(found.len(), 1, "display text must not bypass the gate");
    }

    #[test]
    fn assistant_approval_does_not_satisfy_human_gate() {
        let store = InMemoryGraph::new();
        add_root(&store);
        register_approver(&store, ActorKind::Assistant);
        let c = change(1, Some(0), "alice");
        store.create_change(&c).unwrap();
        store
            .create_approval(&approval(&c, ApprovalDecision::Approved))
            .unwrap();

        let found = unapproved_agent_changes(&store, &c.id, 50).unwrap();
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn rejected_and_conditional_do_not_satisfy_approval() {
        for decision in [ApprovalDecision::Rejected, ApprovalDecision::Conditional] {
            let store = InMemoryGraph::new();
            add_root(&store);
            let c = change(1, Some(0), "agent-x");
            store.create_change(&c).unwrap();
            store.create_approval(&approval(&c, decision)).unwrap();

            let found = unapproved_agent_changes(&store, &c.id, 50).unwrap();
            assert_eq!(
                found.len(),
                1,
                "{decision:?} is not an approval and must still block"
            );
        }
    }

    #[test]
    fn previously_approved_then_mutated_blocks_until_reapproved() {
        // History: c1 (agent, approved) <- c2 (agent, NOT approved, HEAD).
        // The new unapproved mutation must block even though an earlier change
        // was approved — this is the audit-events-exist-but-latest-unapproved case.
        let store = InMemoryGraph::new();
        register_approver(&store, ActorKind::Human);
        let c1 = change(1, None, "agent-a");
        let c2 = change(2, Some(1), "agent-a");
        store.create_change(&c1).unwrap();
        store.create_change(&c2).unwrap();
        store
            .create_approval(&approval(&c1, ApprovalDecision::Approved))
            .unwrap();

        let found = unapproved_agent_changes(&store, &c2.id, 50).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].change_id, c2.id);

        // Approving the head clears the gate.
        store
            .create_approval(&approval(&c2, ApprovalDecision::Approved))
            .unwrap();
        let found = unapproved_agent_changes(&store, &c2.id, 50).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn walk_respects_limit() {
        // c1 (agent, unapproved) <- c2 (agent, unapproved, HEAD). Limit 1 only
        // visits the head, so the older unapproved change is not reported.
        let store = InMemoryGraph::new();
        let c1 = change(1, None, "agent-a");
        let c2 = change(2, Some(1), "agent-a");
        store.create_change(&c1).unwrap();
        store.create_change(&c2).unwrap();

        let found = unapproved_agent_changes(&store, &c2.id, 1).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].change_id, c2.id);
    }

    #[test]
    fn missing_head_change_fails_closed() {
        let store = InMemoryGraph::new();
        let head = change_id(9);
        let error = unapproved_agent_changes(&store, &head, 50).unwrap_err();
        assert!(matches!(
            error,
            ReviewError::RefStateUnavailable { at, missing }
                if at == head && missing == head
        ));
    }

    #[test]
    fn unbound_passing_run_is_advisory_but_never_release_authority() {
        let store = InMemoryGraph::new();
        let source = entity("source", EntityKind::Function, Visibility::Public);
        store.upsert_entity(&source).unwrap();
        let run = kin_model::VerificationRun {
            run_id: kin_model::VerificationRunId::new(),
            test_ids: vec![],
            status: VerificationStatus::Passing,
            runner: kin_model::TestRunner::Cargo,
            started_at: Timestamp::now(),
            finished_at: Some(Timestamp::now()),
            duration_ms: Some(1),
            evidence_blob: None,
            exit_code: Some(0),
        };
        store.create_verification_run(&run).unwrap();
        store
            .link_run_proves_entity(&run.run_id, &source.id)
            .unwrap();

        assert_eq!(passing_proof_coverage(&store).unwrap().covered_entities, 1);
        let release = source_bound_release_proof_coverage(&store).unwrap();
        assert_eq!(release.covered_entities, 0);
        assert_eq!(release.missing_proof, vec![source.id]);

        let empty = source_bound_release_proof_coverage(&InMemoryGraph::new()).unwrap();
        assert_eq!(empty.coverage_ratio, 1.0);
    }

    // ── security_findings ───────────────────────────────────────────────────

    #[test]
    fn untested_api_endpoint_is_high_severity() {
        let store = InMemoryGraph::new();
        let api = entity("login", EntityKind::ApiEndpoint, Visibility::Public);
        store.upsert_entity(&api).unwrap();

        let findings = security_findings(&store, false).unwrap();
        let api_finding = findings
            .iter()
            .find(|f| f.category == "untested-api")
            .expect("untested API endpoint must be flagged");
        assert_eq!(api_finding.severity, SecuritySeverity::High);
        assert_eq!(api_finding.entity_id, api.id);
    }

    #[test]
    fn orphaned_public_function_is_low_severity() {
        let store = InMemoryGraph::new();
        let func = entity("helper", EntityKind::Function, Visibility::Public);
        store.upsert_entity(&func).unwrap();

        let findings = security_findings(&store, false).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "orphaned-public" && f.severity == SecuritySeverity::Low),
            "public function with no callers/tests must be flagged"
        );
    }

    #[test]
    fn encapsulation_leak_is_detected() {
        let store = InMemoryGraph::new();
        let public_fn = entity("api", EntityKind::Function, Visibility::Public);
        let private_fn = entity("internal", EntityKind::Function, Visibility::Private);
        store.upsert_entity(&public_fn).unwrap();
        store.upsert_entity(&private_fn).unwrap();
        store
            .upsert_relation(&calls(&public_fn, &private_fn))
            .unwrap();

        let findings = security_findings(&store, false).unwrap();
        assert!(
            findings.iter().any(|f| f.category == "encapsulation-leak"),
            "public->private call must be flagged"
        );
    }

    #[test]
    fn empty_graph_has_no_findings() {
        let store = InMemoryGraph::new();
        let findings = security_findings(&store, false).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn finding_counts_tally_by_severity() {
        let store = InMemoryGraph::new();
        store
            .upsert_entity(&entity("ep", EntityKind::ApiEndpoint, Visibility::Public))
            .unwrap();
        store
            .upsert_entity(&entity("orphan", EntityKind::Function, Visibility::Public))
            .unwrap();

        let findings = security_findings(&store, false).unwrap();
        let counts = SecurityFindingCounts::of(&findings);
        assert_eq!(counts.high, 1, "one untested API endpoint");
        assert!(counts.low >= 1, "at least one orphaned public function");
    }

    #[test]
    fn findings_sorted_by_severity_descending() {
        let store = InMemoryGraph::new();
        store
            .upsert_entity(&entity("ep", EntityKind::ApiEndpoint, Visibility::Public))
            .unwrap();
        store
            .upsert_entity(&entity("orphan", EntityKind::Function, Visibility::Public))
            .unwrap();

        let findings = security_findings(&store, false).unwrap();
        assert!(findings.len() >= 2);
        for pair in findings.windows(2) {
            assert!(
                pair[0].severity >= pair[1].severity,
                "findings must be sorted highest severity first"
            );
        }
    }

    #[test]
    fn findings_order_is_byte_stable_within_severity_tier() {
        // Several entities land in the same (Low) severity tier, so ordering is
        // decided by the total tie-break, not entity iteration order. Two scans of
        // the same store must produce byte-identical ordering.
        let store = InMemoryGraph::new();
        for name in ["zeta", "alpha", "mike", "bravo", "yankee"] {
            store
                .upsert_entity(&entity(name, EntityKind::Function, Visibility::Public))
                .unwrap();
        }

        let first = security_findings(&store, false).unwrap();
        let second = security_findings(&store, false).unwrap();
        assert!(first.len() >= 5, "all orphaned publics should be flagged");

        let key = |fs: &[SecurityFinding]| {
            fs.iter()
                .map(|f| (f.severity, f.category, f.entity_name.clone(), f.entity_id))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            key(&first),
            key(&second),
            "scan order must be deterministic"
        );

        // And the names within the tier are actually in ascending order.
        let low_names: Vec<&str> = first
            .iter()
            .filter(|f| f.category == "orphaned-public")
            .map(|f| f.entity_name.as_str())
            .collect();
        let mut sorted = low_names.clone();
        sorted.sort_unstable();
        assert_eq!(low_names, sorted, "tie-break should order names ascending");
    }
}
