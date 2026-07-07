// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shadow-mode merge-gate report.
//!
//! Packages one PR-shaped change evaluation into a single payload: what
//! changed at the entity level, the graph-proven blast radius, the policy
//! verdict the gate would have issued, the context a reviewer or agent needs
//! to repair findings, and the audit evidence for the evaluation itself.
//!
//! Shadow mode is report-only. It never blocks and never mutates graph
//! state; a blocking verdict is reported as `would_block`.
//!
//! Every section is graph-derived. When the graph cannot prove something —
//! files with no captured entities, entities without spans, an empty impact
//! signal, cross-repo federation not evaluated — the report carries an
//! explicit entry in `evidence_gaps` instead of passing silently.

use std::collections::{BTreeMap, BTreeSet};

use kin_blobs::{BlobStore, Hash256};
use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, SemanticChangeId};
use kin_model::timestamp::Timestamp;
use serde::{Deserialize, Serialize};

use crate::diff::{self, EntityChangeKind, SemanticDiff};
use crate::gate::{derive_decision, GateStatus, ReviewFinding, ReviewSignalKind};
use crate::impact::{analyze_impact_at, ImpactGraph, ImpactReport};
use crate::inline::{self, InlineComment, InlineCommentKind};
use crate::ref_graph::GraphAtRef;
use crate::review::{Review, SemanticReview};
use crate::risk;
use crate::ReviewError;

/// Version of the shadow gate report payload schema. Mirrored by
/// `packages/boundary-contracts/schemas/shadow-gate-report.schema.json`.
pub const SHADOW_GATE_REPORT_SCHEMA_VERSION: u32 = 1;

/// Enforcement label carried by every shadow report.
pub const SHADOW_ENFORCEMENT_REPORT_ONLY: &str = "report_only";

/// Inputs for one shadow gate evaluation.
#[derive(Debug, Clone)]
pub struct ShadowRequest {
    /// Base ref exactly as supplied by the caller.
    pub base_ref: String,
    /// Head ref exactly as supplied by the caller.
    pub head_ref: String,
    /// Resolved base change.
    pub resolved_base: SemanticChangeId,
    /// Resolved head change.
    pub resolved_head: SemanticChangeId,
    /// Optional change title (e.g. PR title).
    pub title: Option<String>,
    /// Optional source URL (e.g. PR URL).
    pub source_url: Option<String>,
    /// Optional change author identity.
    pub author: Option<String>,
    /// Identity running the evaluation (for audit evidence).
    pub actor: String,
}

/// Echo of the evaluated input, with resolution results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowInputEcho {
    pub base_ref: String,
    pub head_ref: String,
    pub resolved_base: String,
    pub resolved_head: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// One directly changed entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowChangedEntity {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    /// "added" | "modified" | "removed"
    pub change: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub signature_changed: bool,
    pub visibility_changed: bool,
    /// Graph role of the changed entity. Test/Generated/Vendored entities are
    /// not a contract surface any non-test consumer depends on, so their
    /// signature/visibility changes must not feed the gate.
    #[serde(default)]
    pub role: EntityRole,
}

use crate::inline::is_non_contract_surface_role;

/// One entity reached by blast-radius traversal, with the graph relationship
/// bucket that proves why it is affected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAffectedEntity {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Relationship bucket: "calls" | "depends_on" | "consumes_contract" | "tests"
    pub via: String,
}

/// Open work item scoped to a changed entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowWorkItem {
    pub work_id: String,
    pub title: String,
    pub status: String,
}

/// Cross-repo federation section. v1 reports single-repo blast radius only
/// and labels the cross-repo section explicitly instead of implying coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCrossRepo {
    /// "not_evaluated" | "unavailable" | "available"
    pub status: String,
    pub detail: String,
    pub nodes: Vec<ShadowCrossRepoNode>,
}

/// One cross-repo node (populated only when `status` is "available").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCrossRepoNode {
    pub repo_id: String,
    pub entity_id: String,
    pub name: String,
}

/// Graph-proven blast radius for the changed entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowBlastRadius {
    pub callers: Vec<ShadowAffectedEntity>,
    pub dependents: Vec<ShadowAffectedEntity>,
    pub contract_consumers: Vec<ShadowAffectedEntity>,
    pub tests: Vec<ShadowAffectedEntity>,
    pub open_work_items: Vec<ShadowWorkItem>,
    pub total_affected: usize,
    pub cross_repo: ShadowCrossRepo,
}

/// Gate status a shadow evaluation reports (never enforces).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowGateVerdict {
    Pass,
    NeedsAttention,
    WouldBlock,
}

/// One policy finding, anchored to source where the graph has a span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowPolicyFinding {
    /// Machine-readable kind, e.g. "breaking", "coverage_gap".
    pub kind: String,
    /// "error" | "warning" | "info"
    pub severity: String,
    /// Whether this finding would block in enforcing mode.
    pub blocking: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// The verdict the gate would have issued, plus its inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowPolicyResult {
    /// Always "report_only" in shadow mode.
    pub enforcement: String,
    pub verdict: ShadowGateVerdict,
    /// Overall risk from the risk assessment: "low" | "medium" | "high" | "critical".
    pub risk_level: String,
    pub blocking_count: usize,
    pub attention_count: usize,
    pub summary: String,
    pub findings: Vec<ShadowPolicyFinding>,
}

/// What a reviewer or agent needs to address one finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowRepairItem {
    pub finding: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Graph-known tests covering the changed entities ("name (file)").
    pub covering_tests: Vec<String>,
    /// Graph-known callers/consumers to check ("name (file)").
    pub affected_consumers: Vec<String>,
    pub guidance: String,
}

/// Explicit statement that the graph could not prove something.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowEvidenceGap {
    /// "artifact_only_change" | "entity_inert_change" | "missing_span"
    /// | "actor_attribution_unavailable" | "impact_signal_absent"
    /// | "cross_repo_not_evaluated" | "ref_state_unavailable"
    /// | "base_not_on_head_ancestry"
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

/// Actor attribution for one changed entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAttribution {
    pub entity_id: String,
    pub actor_kind: String,
}

/// One recorded approval on the head change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowApproval {
    pub approver: String,
    pub decision: String,
    pub reason: String,
}

/// Who/what/when evidence for the evaluation itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAuditEvidence {
    pub generated_at: Timestamp,
    pub actor: String,
    /// "human" | "assistant" | "service"
    pub actor_kind: String,
    pub tool: String,
    pub tool_version: String,
    pub base_change: String,
    pub head_change: String,
    pub changes_in_range: usize,
    pub entity_attribution: Vec<ShadowAttribution>,
    pub head_approvals: Vec<ShadowApproval>,
}

/// The complete shadow-mode merge-gate report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowGateReport {
    pub schema_version: u32,
    /// Always "shadow".
    pub mode: String,
    pub input: ShadowInputEcho,
    pub changed_entities: Vec<ShadowChangedEntity>,
    pub blast_radius: ShadowBlastRadius,
    pub policy: ShadowPolicyResult,
    pub repair_context: Vec<ShadowRepairItem>,
    pub evidence_gaps: Vec<ShadowEvidenceGap>,
    pub audit: ShadowAuditEvidence,
}

/// Build a shadow-mode merge-gate report for a resolved base..head range.
///
/// Read-only: consumes graph truth, produces a report, records nothing.
///
/// Blast radius and impact are computed against the graph state materialized
/// at the resolved head ref, never against the mutable live adjacency. When
/// that state cannot be materialized the report carries an explicit
/// `ref_state_unavailable` evidence gap with an empty blast radius instead of
/// silently answering from another era's adjacency.
pub fn build_shadow_report<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
) -> Result<ShadowGateReport, ReviewError> {
    match GraphAtRef::materialize(store, &request.resolved_head) {
        Ok(at_head) => build_shadow_report_at(store, request, &at_head),
        Err(ReviewError::RefStateUnavailable { at, missing }) => {
            build_report_without_ref_state(store, request, at, missing)
        }
        Err(other) => Err(other),
    }
}

/// Build a shadow report with an already-materialized head state.
///
/// Callers evaluating the same head repeatedly (e.g. repeated determinism
/// passes) can materialize the [`GraphAtRef`] once and reuse it here;
/// [`build_shadow_report`] materializes per call.
pub fn build_shadow_report_at<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
    at_head: &GraphAtRef<'_, G>,
) -> Result<ShadowGateReport, ReviewError> {
    if !at_head.ancestry_contains(&request.resolved_base) {
        return build_report_with_base_off_ancestry(store, request);
    }
    // DAG-true `base..head` membership: reachable from head, not reachable
    // from base. The store's backward walk stops only at the literal base
    // node, so on a merge head it crosses into the base's own history
    // through the other parent; every consumer of the walked rows below
    // scopes them with this test so the diff and the audited range describe
    // the reviewed range and nothing older.
    let base_ancestry = crate::ref_graph::collect_ancestry(store, &request.resolved_base)?;
    let in_range =
        |id: &SemanticChangeId| at_head.ancestry_contains(id) && !base_ancestry.contains(id);
    let mut review = SemanticReview::create_review_scoped(
        &request.resolved_base,
        &request.resolved_head,
        store,
        at_head,
        in_range,
    )?;
    let changes: Vec<_> = store
        .get_changes_since(&request.resolved_base, &request.resolved_head)
        .map_err(ReviewError::graph)?
        .into_iter()
        .filter(|change| in_range(&change.id))
        .collect();
    // A removed entity is absent at head: its head-scoped inbound edges and
    // its own name/kind cannot be read there. The base ref still holds the
    // entity and the edges its removal severs, so removed-entity impact and
    // identity are harvested from base state. Materialization is sound here —
    // `at_head` already validated the base is on-ancestry and every ancestry
    // row is present, so the base state (a subset of that ancestry) resolves.
    let at_base = GraphAtRef::materialize(store, &request.resolved_base)?;
    overlay_removed_entity_impact_from_base(&mut review, &at_base)?;
    assemble_report_with_changes(
        store,
        request,
        review,
        None,
        &changes,
        Some(at_head),
        Some(&at_base),
    )
}

/// Overlay base-side inbound attribution onto the head-computed impact for
/// every REMOVED entity.
///
/// A removed entity does not exist at head, so its head-scoped
/// `consumer_count` understates (often to zero) the surviving non-test
/// consumers that still reference the deleted surface. The base ref still
/// holds the entity and its inbound edges, so the breaking-removal rule reads
/// the surviving-consumer count from there. Only removed-entity entries are
/// replaced; Added/Modified attribution stays head-scoped. The FULL diff is
/// harvested so a consumer that was itself changed in the same range is
/// excluded exactly as the head-side harvest excludes a co-updated consumer —
/// a consumer that let go of the removed surface in the same change is not a
/// broken contract. Removed ids are iterated in sorted order and the impacts
/// are re-sorted by id, so the overlay is replay-deterministic.
fn overlay_removed_entity_impact_from_base<G: GraphStore>(
    review: &mut Review,
    at_base: &GraphAtRef<'_, G>,
) -> Result<(), ReviewError> {
    let removed_ids: BTreeSet<EntityId> = review
        .diff
        .entity_changes
        .iter()
        .filter_map(|change| match &change.kind {
            EntityChangeKind::Removed(id) => Some(*id),
            _ => None,
        })
        .collect();
    if removed_ids.is_empty() {
        return Ok(());
    }
    let base_impact = analyze_impact_at(at_base, &review.diff)?;
    for removed_id in &removed_ids {
        if let Some(base_entry) = base_impact.entity_impact(removed_id) {
            review
                .impact
                .entity_impacts
                .retain(|entry| entry.entity_id != *removed_id);
            review.impact.entity_impacts.push(base_entry.clone());
        }
    }
    review
        .impact
        .entity_impacts
        .sort_by_key(|entry| entry.entity_id);
    Ok(())
}

/// The graph state at the head ref could not be materialized. Report the gap
/// loudly with an empty blast radius; the live adjacency is deliberately not
/// consulted — it reflects another era's graph, not this ref.
fn build_report_without_ref_state<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
    at: SemanticChangeId,
    missing: SemanticChangeId,
) -> Result<ShadowGateReport, ReviewError> {
    let semantic_diff = diff::compute_diff(store, &request.resolved_base, &request.resolved_head)?;
    let impact_report = ImpactReport {
        changed_ids: semantic_diff.changed_entity_ids(),
        ..Default::default()
    };
    let risk_summary = risk::assess_risk(&semantic_diff, &impact_report);
    let inline_comments = inline::collect_inline_comments(&semantic_diff, &impact_report);
    let review = Review {
        base: Some(request.resolved_base),
        head: Some(request.resolved_head),
        diff: semantic_diff,
        impact: impact_report,
        risk: risk_summary,
        inline_comments,
    };

    let gap = ShadowEvidenceGap {
        kind: "ref_state_unavailable".to_string(),
        subject: request.head_ref.clone(),
        detail: format!(
            "graph state at ref not materialized: change {missing} in the ancestry of {at} is \
             not in the graph; blast radius and impact were NOT computed for this report, and \
             the live adjacency was deliberately not consulted in its place"
        ),
    };
    // Head state is unmaterializable here, so there is nothing to prove
    // entities-in-file against: artifact-only gaps stay demoting.
    assemble_report(store, request, review, Some(gap), None)
}

/// The resolved base is not on the head's ancestry in the change DAG. A range
/// walk from that base would not describe this head's history — it degrades
/// into a sweep across unrelated eras of the DAG — so the range is refused
/// loudly: no diff, no blast radius, no impact, no range walk, and an
/// explicit blocking evidence gap in their place.
fn build_report_with_base_off_ancestry<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
) -> Result<ShadowGateReport, ReviewError> {
    let semantic_diff = SemanticDiff {
        base: Some(request.resolved_base),
        head: Some(request.resolved_head),
        ..Default::default()
    };
    let impact_report = ImpactReport::default();
    let risk_summary = risk::assess_risk(&semantic_diff, &impact_report);
    let inline_comments = inline::collect_inline_comments(&semantic_diff, &impact_report);
    let review = Review {
        base: Some(request.resolved_base),
        head: Some(request.resolved_head),
        diff: semantic_diff,
        impact: impact_report,
        risk: risk_summary,
        inline_comments,
    };

    let gap = ShadowEvidenceGap {
        kind: "base_not_on_head_ancestry".to_string(),
        subject: format!("{}..{}", request.base_ref, request.head_ref),
        detail: format!(
            "resolved base {} is not on the ancestry of head {} in the change DAG; a range walk \
             from this base would span unrelated history, so diff, blast radius, and impact were \
             NOT computed for this report",
            request.resolved_base, request.resolved_head
        ),
    };
    // No range was walked, so there are no artifact deltas to reclassify;
    // pass no head or base state.
    assemble_report_with_changes(store, request, review, Some(gap), &[], None, None)
}

fn assemble_report<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
    review: Review,
    range_gap: Option<ShadowEvidenceGap>,
    at_head: Option<&GraphAtRef<'_, G>>,
) -> Result<ShadowGateReport, ReviewError> {
    let changes = store
        .get_changes_since(&request.resolved_base, &request.resolved_head)
        .map_err(ReviewError::graph)?;
    assemble_report_with_changes(store, request, review, range_gap, &changes, at_head, None)
}

fn assemble_report_with_changes<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
    mut review: Review,
    range_gap: Option<ShadowEvidenceGap>,
    changes: &[kin_model::change::SemanticChange],
    at_head: Option<&GraphAtRef<'_, G>>,
    at_base: Option<&GraphAtRef<'_, G>>,
) -> Result<ShadowGateReport, ReviewError> {
    let changed_entities = collect_changed_entities(store, &review, at_base)?;
    let blast_radius = collect_blast_radius(&review);
    // No blob reader is reachable here: the shadow entry points take only the
    // graph store, and threading a real reader would change their public
    // signature and their out-of-crate callers. The toolchain-surface channel
    // is therefore inert on this path (blobs = None) until that wiring lands.
    let (mut evidence_gaps, toolchain_findings) =
        collect_evidence_gaps(&review, changes, &changed_entities, at_head, None);
    if let Some(gap) = range_gap {
        // The generic empty-impact gap advises verifying relation ingestion,
        // which misleads here: impact was not computed at all. The specific
        // range gap (unmaterializable ref state, base off the head ancestry)
        // subsumes it.
        evidence_gaps.retain(|existing| existing.kind != "impact_signal_absent");
        evidence_gaps.insert(0, gap);
    }
    // Toolchain-surface findings feed the gate as ordinary warning findings via
    // the inline-comment channel, never through the evidence-gap demotion path.
    review.inline_comments.extend(toolchain_findings);
    // Revert-history findings feed the gate the same way: ordinary warning
    // findings, with an honest gap when the base has too little history to
    // scan. Temporal evidence available at review time only — the window looks
    // strictly BEFORE the base.
    let (revert_findings, revert_gap) = crate::revert_history::collect_revert_history_findings(
        store,
        &request.resolved_base,
        changes,
    )?;
    review.inline_comments.extend(revert_findings);
    if let Some(gap) = revert_gap {
        evidence_gaps.push(gap);
    }
    let policy = derive_policy(&review, &evidence_gaps, &changed_entities);
    let repair_context = collect_repair_context(&policy.findings, &review);
    let audit = collect_audit_evidence(store, request, &review, changes.len())?;

    Ok(ShadowGateReport {
        schema_version: SHADOW_GATE_REPORT_SCHEMA_VERSION,
        mode: "shadow".to_string(),
        input: ShadowInputEcho {
            base_ref: request.base_ref.clone(),
            head_ref: request.head_ref.clone(),
            resolved_base: request.resolved_base.to_string(),
            resolved_head: request.resolved_head.to_string(),
            title: request.title.clone(),
            source_url: request.source_url.clone(),
            author: request.author.clone(),
        },
        changed_entities,
        blast_radius,
        policy,
        repair_context,
        evidence_gaps,
        audit,
    })
}

fn entity_location(entity: &Entity) -> (Option<String>, Option<u32>, Option<u32>) {
    match &entity.span {
        Some(span) => (
            Some(span.file.to_string()),
            Some(span.start_line),
            Some(span.end_line),
        ),
        None => (
            entity.file_origin.as_ref().map(|file| file.to_string()),
            None,
            None,
        ),
    }
}

fn collect_changed_entities<G: GraphStore>(
    store: &G,
    review: &Review,
    at_base: Option<&GraphAtRef<'_, G>>,
) -> Result<Vec<ShadowChangedEntity>, ReviewError> {
    let mut changed = Vec::new();
    for change in &review.diff.entity_changes {
        match &change.kind {
            EntityChangeKind::Added(entity) => {
                let (file, start_line, end_line) = entity_location(entity);
                changed.push(ShadowChangedEntity {
                    entity_id: entity.id.to_string(),
                    name: entity.name.clone(),
                    kind: format!("{:?}", entity.kind),
                    change: "added".to_string(),
                    file,
                    start_line,
                    end_line,
                    signature_changed: false,
                    visibility_changed: false,
                    role: entity.role,
                });
            }
            EntityChangeKind::Modified { old, new } => {
                let (file, start_line, end_line) = entity_location(new);
                changed.push(ShadowChangedEntity {
                    entity_id: new.id.to_string(),
                    name: new.name.clone(),
                    kind: format!("{:?}", new.kind),
                    change: "modified".to_string(),
                    file,
                    start_line,
                    end_line,
                    signature_changed: old.signature != new.signature
                        && !crate::inline::signature_strengthened_only(
                            &old.signature,
                            &new.signature,
                        ),
                    visibility_changed: old.visibility != new.visibility,
                    role: new.role,
                });
            }
            EntityChangeKind::Removed(id) => {
                // The diff carries only the removed entity's id, and the entity
                // is absent at head. Resolve its name/kind/file where it still
                // exists — the base ref — so findings and the entity list read
                // as code, not opaque ids, and the breaking-removal rule keeps
                // demotion only for a surface the BASE graph also cannot name.
                // Fall back to the live store, then to the id string when the
                // graph has genuinely forgotten the entity.
                let removed = match at_base {
                    Some(base) => base.get_entity(id)?,
                    None => None,
                };
                let removed = match removed {
                    Some(entity) => Some(entity),
                    None => store.get_entity(id).map_err(ReviewError::graph)?,
                };
                let (name, kind, file, role) = match removed {
                    Some(entity) => {
                        let (file, _, _) = entity_location(&entity);
                        (
                            entity.name.clone(),
                            format!("{:?}", entity.kind),
                            file,
                            entity.role,
                        )
                    }
                    None => (
                        id.to_string(),
                        "unknown".to_string(),
                        None,
                        EntityRole::Source,
                    ),
                };
                changed.push(ShadowChangedEntity {
                    entity_id: id.to_string(),
                    name,
                    kind,
                    change: "removed".to_string(),
                    file,
                    start_line: None,
                    end_line: None,
                    signature_changed: false,
                    visibility_changed: false,
                    role,
                });
            }
        }
    }
    changed.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.entity_id.cmp(&b.entity_id))
    });
    Ok(changed)
}

fn affected_from(entities: &[Entity], via: &str) -> Vec<ShadowAffectedEntity> {
    let mut affected: Vec<ShadowAffectedEntity> = entities
        .iter()
        .map(|entity| {
            let (file, _, _) = entity_location(entity);
            ShadowAffectedEntity {
                entity_id: entity.id.to_string(),
                name: entity.name.clone(),
                kind: format!("{:?}", entity.kind),
                file,
                via: via.to_string(),
            }
        })
        .collect();
    affected.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.entity_id.cmp(&b.entity_id))
    });
    affected
}

fn collect_blast_radius(review: &Review) -> ShadowBlastRadius {
    let impact = &review.impact;
    let mut open_work_items: Vec<ShadowWorkItem> = impact
        .affected_work_items
        .iter()
        .map(|item| ShadowWorkItem {
            work_id: item.work_id.to_string(),
            title: item.title.clone(),
            status: format!("{:?}", item.status),
        })
        .collect();
    open_work_items.sort_by(|a, b| a.work_id.cmp(&b.work_id));

    ShadowBlastRadius {
        callers: affected_from(&impact.affected_callers, "calls"),
        dependents: affected_from(&impact.affected_dependents, "depends_on"),
        contract_consumers: affected_from(&impact.affected_contract_consumers, "consumes_contract"),
        tests: affected_from(&impact.affected_tests, "tests"),
        open_work_items,
        total_affected: impact.total_affected(),
        cross_repo: ShadowCrossRepo {
            status: "not_evaluated".to_string(),
            detail: "cross-repo federation is not evaluated by shadow report v1; blast radius \
                     covers this repository only"
                .to_string(),
            nodes: Vec::new(),
        },
    }
}

fn finding_kind_label(kind: InlineCommentKind) -> &'static str {
    match kind {
        InlineCommentKind::Breaking => "breaking",
        InlineCommentKind::CoverageGap => "coverage_gap",
        InlineCommentKind::ContractViolation => "contract_violation",
        InlineCommentKind::CommandEffectContract => "command_effect_contract_change",
        InlineCommentKind::SignatureChange => "signature_change",
        InlineCommentKind::VisibilityChange => "visibility_change",
        InlineCommentKind::ConsumerFanout => "consumer_fanout",
        InlineCommentKind::Added => "entity_added",
        InlineCommentKind::Removed => "entity_removed",
        InlineCommentKind::Renamed => "entity_renamed",
        InlineCommentKind::AgentUnreviewed => "agent_unreviewed",
        InlineCommentKind::ToolchainSurfaceChange => "toolchain_surface_change",
        InlineCommentKind::RevertHistory => "revert_history",
    }
}

fn finding_severity(kind: InlineCommentKind) -> &'static str {
    match kind {
        InlineCommentKind::Breaking | InlineCommentKind::ContractViolation => "error",
        InlineCommentKind::CoverageGap
        | InlineCommentKind::SignatureChange
        | InlineCommentKind::VisibilityChange
        | InlineCommentKind::CommandEffectContract
        | InlineCommentKind::ConsumerFanout
        | InlineCommentKind::Renamed
        | InlineCommentKind::AgentUnreviewed
        | InlineCommentKind::ToolchainSurfaceChange
        | InlineCommentKind::RevertHistory => "warning",
        InlineCommentKind::Added | InlineCommentKind::Removed => "info",
    }
}

fn is_blocking(kind: InlineCommentKind) -> bool {
    matches!(
        kind,
        InlineCommentKind::Breaking | InlineCommentKind::ContractViolation
    )
}

/// Whether an evidence gap describes a deficit severe enough that the gate
/// cannot certify `pass` over it.
///
/// Only gaps that hide SOURCE the graph should have captured demote:
///
/// - `missing_span`: a changed semantic entity has no source anchor — code
///   changed that findings cannot point at.
/// - `artifact_only_change` on a source-class file: the ingest classifier
///   says the file should have produced entities and none were captured, so
///   real code changed invisibly. The same gap on docs, CI, config, or other
///   non-source artifacts stays reported but does not demote — those files
///   are EXPECTED to carry no entities, and demoting on them turns every
///   docs-only change into a false attention signal.
/// - `ref_state_unavailable`: the graph state at the reviewed head ref could
///   not be materialized, so blast radius and impact were not computed at
///   all. The gate cannot certify `pass` over an impact surface it never
///   evaluated.
/// - `base_not_on_head_ancestry`: the resolved base is not on the head's
///   ancestry in the change DAG, so the requested range does not describe
///   this head's history and diff, blast radius, and impact were refused.
///   The gate cannot certify `pass` over a range it never evaluated.
/// - `impact_signal_absent` is reported but never demotes the verdict: an
///   empty relation channel cannot distinguish "genuinely isolated" from
///   "relations never ingested", and treating that ambiguity as risk flags
///   every change in a sparsely-related region of the graph. The gap entry
///   itself remains the honest record of the deficit, and the coverage-gap
///   channel is suppressed on the same condition so the empty channel is
///   never double-counted.
/// - Structural v1 limits (cross-repo not evaluated, attribution
///   unavailable) are constant framing, reported but never demoting.
fn gap_blocks_pass(gap: &ShadowEvidenceGap) -> bool {
    match gap.kind.as_str() {
        "missing_span" | "ref_state_unavailable" | "base_not_on_head_ancestry" => true,
        "artifact_only_change" => artifact_subject_is_source_class(&gap.subject),
        _ => false,
    }
}

/// Whether an artifact-only changed file is source-class per the ingest
/// classifier — the same verdict the indexing pipeline used when it failed
/// to capture entities for it. Reusing the classifier keeps this rule
/// aligned with what ingestion actually attempts; no separate path
/// heuristics are introduced here.
fn artifact_subject_is_source_class(subject: &str) -> bool {
    matches!(
        kin_index::FileClassifier::classify(std::path::Path::new(subject)),
        kin_index::FileClassification::EntitySource
            | kin_index::FileClassification::ShallowSyntax { .. }
    )
}

fn derive_policy(
    review: &Review,
    evidence_gaps: &[ShadowEvidenceGap],
    changed_entities: &[ShadowChangedEntity],
) -> ShadowPolicyResult {
    let mut findings: Vec<ShadowPolicyFinding> = review
        .inline_comments
        .iter()
        .map(|comment| ShadowPolicyFinding {
            kind: finding_kind_label(comment.kind).to_string(),
            severity: finding_severity(comment.kind).to_string(),
            blocking: is_blocking(comment.kind),
            message: comment.message.clone(),
            file: Some(comment.file.clone()),
            line: Some(comment.start_line),
        })
        .collect();

    // Resolved names for changed entities (removed entities carry only an id
    // in the diff), and the set of names added in this same diff: a removal
    // whose name is re-added in the same change set is a move, not a
    // breaking removal.
    let resolved_names: BTreeMap<&str, &str> = changed_entities
        .iter()
        .map(|entity| (entity.entity_id.as_str(), entity.name.as_str()))
        .collect();
    let added_names: BTreeSet<&str> = changed_entities
        .iter()
        .filter(|entity| entity.change == "added")
        .map(|entity| entity.name.as_str())
        .collect();
    // Graph role per changed entity, so the surface-finding loop can skip
    // roles that are not a contract surface (test/generated/vendored) even for
    // removed entities, whose role was resolved from the base graph.
    let resolved_roles: BTreeMap<&str, EntityRole> = changed_entities
        .iter()
        .map(|entity| (entity.entity_id.as_str(), entity.role))
        .collect();
    // Removed entities the graph can no longer resolve are surfaced as a raw
    // UUID (kind "unknown" from `collect_changed_entities`). We cannot certify
    // a confident BLOCKING breakage for a surface we cannot even name, so such
    // a removal's downstream risk is demoted to an attention signal rather
    // than a would_block. A resolvable removal with surviving consumers still
    // blocks.
    let unresolvable_removed: BTreeSet<&str> = changed_entities
        .iter()
        .filter(|entity| entity.change == "removed" && entity.kind == "unknown")
        .map(|entity| entity.entity_id.as_str())
        .collect();

    // Gate rule: a contract-surface change (signature/visibility/removal) is
    // a blocking downstream risk when THAT entity has graph-known non-test
    // consumers. Another entity's consumers do not make this entity's
    // surface change risky; the per-entity inbound attribution decides.
    {
        // Emit contract-surface findings in a deterministic entity-id order.
        // Removed entities have no span, so several collapse onto the same
        // `(file=None, line=None)` dedup key; iterating in a stable order fixes
        // which one survives as the representative, keeping the finding prose
        // byte-identical across repeated evaluations.
        let mut surface_candidates: Vec<_> = review.diff.entity_changes.iter().collect();
        surface_candidates.sort_by_key(|change| change.entity_id);
        for change in surface_candidates {
            let (name, location, surface_changed, demote_removal) = match &change.kind {
                EntityChangeKind::Modified { old, new } => (
                    new.name.clone(),
                    new.span
                        .as_ref()
                        .map(|span| (span.file.to_string(), span.start_line)),
                    old.signature != new.signature || old.visibility != new.visibility,
                    false,
                ),
                EntityChangeKind::Removed(id) => {
                    let id_string = id.to_string();
                    let unresolvable = unresolvable_removed.contains(id_string.as_str());
                    let name = resolved_names
                        .get(id_string.as_str())
                        .map(|name| name.to_string())
                        .unwrap_or(id_string);
                    // Same-diff remove + re-add of the same entity name is a
                    // move; the surviving entity carries any surface risk.
                    if added_names.contains(name.as_str()) {
                        continue;
                    }
                    (name, None, true, unresolvable)
                }
                EntityChangeKind::Added(_) => continue,
            };
            if !surface_changed {
                continue;
            }
            // A test's, generated artifact's, or vendored copy's declaration is
            // not a contract surface — its signature change breaks no consumer
            // the review protects, so it never emits a downstream-risk finding.
            if resolved_roles
                .get(change.entity_id.to_string().as_str())
                .is_some_and(|role| is_non_contract_surface_role(*role))
            {
                continue;
            }
            let entity_consumers = review
                .impact
                .entity_impact(&change.entity_id)
                .map_or(0, |entry| entry.consumer_count);
            if entity_consumers == 0 {
                continue;
            }
            let already_blocking = findings.iter().any(|finding| {
                finding.blocking
                    && finding.file == location.as_ref().map(|(file, _)| file.clone())
                    && finding.line == location.as_ref().map(|(_, line)| *line)
            });
            if already_blocking {
                continue;
            }
            // An unresolvable removal reports its downstream risk as attention,
            // not a would_block: naming the severed surface as a raw UUID is
            // not enough proof to certify a blocking breakage.
            findings.push(ShadowPolicyFinding {
                kind: "downstream_risk".to_string(),
                severity: if demote_removal { "warning" } else { "error" }.to_string(),
                blocking: !demote_removal,
                message: format!(
                    "Contract surface of `{}` changed with {} graph-known downstream entity(ies)",
                    name, entity_consumers
                ),
                file: location.as_ref().map(|(file, _)| file.clone()),
                line: location.as_ref().map(|(_, line)| *line),
            });
        }
    }

    // Per-anchor inbound totals for the gate feed below: a signature or
    // visibility finding on an entity the graph connects to NOTHING (no
    // consumer, no test) is reported but cannot justify an attention verdict
    // by itself — with zero graph-known inbound edges there is no proven
    // audience for the surface change. Anchors resolve by the same
    // (file, start_line) key the findings carry.
    let mut anchor_inbound: BTreeMap<(String, u32), usize> = BTreeMap::new();
    for change in &review.diff.entity_changes {
        if let EntityChangeKind::Modified { new, .. } = &change.kind {
            if let Some(span) = &new.span {
                let inbound = review
                    .impact
                    .entity_impact(&new.id)
                    .map_or(0, |entry| entry.inbound_total());
                let slot = anchor_inbound
                    .entry((span.file.to_string(), span.start_line))
                    .or_insert(0);
                *slot = (*slot).max(inbound);
            }
        }
    }
    // An entirely absent relation channel is not proof of isolation. When the
    // report carries an `impact_signal_absent` gap, the graph held no relations
    // to answer with, so an anchor's zero inbound is "never ingested", not
    // "genuinely isolated" — the same trust condition the coverage-gap channel
    // uses. In that state a real signature/visibility change must still feed
    // the gate rather than be silently suppressed into a pass.
    let relation_channel_absent = evidence_gaps
        .iter()
        .any(|gap| gap.kind == "impact_signal_absent");
    let surface_finding_feeds_gate = |finding: &ShadowPolicyFinding| -> bool {
        if finding.kind != "signature_change" && finding.kind != "visibility_change" {
            return true;
        }
        // Suppression is a claim of proven isolation; an absent channel cannot
        // make that claim, so the surface change keeps feeding the gate.
        if relation_channel_absent {
            return true;
        }
        match (&finding.file, finding.line) {
            (Some(file), Some(line)) => anchor_inbound
                .get(&(file.clone(), line))
                // Unresolvable anchors keep feeding the gate: suppression
                // requires proof of isolation, not absence of a lookup.
                .is_none_or(|inbound| *inbound > 0),
            _ => true,
        }
    };

    // The coverage-gap channel is warning-only: it documents a missing test
    // but must not drive the verdict for a pure body-only refactor. When
    // nothing blocks AND no changed entity altered its contract surface
    // (signature or visibility), a lone coverage_gap stays in the report yet
    // does not feed the gate — a benign body-only change is not escalated by
    // it. Any blocking finding or a real surface change restores its gate
    // weight.
    //
    // consumer_fanout is deliberately NOT suppressed this way. It already
    // requires a graph-native wide blast — at least CONSUMER_FANOUT_THRESHOLD
    // distinct non-test consumer entities — so a body-only behavior change
    // reaching that many consumers is a genuine downstream-risk signal that
    // must feed the gate on its own weight even when the contract surface is
    // unchanged. The decision is on graph-owned consumer entities, never files.
    let has_blocking_finding = findings.iter().any(|finding| finding.blocking);
    let has_surface_change = changed_entities.iter().any(|entity| {
        (entity.signature_changed || entity.visibility_changed)
            && !is_non_contract_surface_role(entity.role)
    });
    let coverage_gap_feeds_gate = has_blocking_finding || has_surface_change;

    // Informational findings (entity added/removed) describe the diff, not a
    // gate signal; they are reported but do not feed the verdict. Surface
    // findings on graph-isolated entities are likewise reported without
    // feeding the gate, and the warning-only coverage-gap channel is withheld
    // from the gate on a benign body-only change.
    let gate_findings: Vec<ReviewFinding> = findings
        .iter()
        .filter(|finding| finding.severity != "info")
        .filter(|finding| surface_finding_feeds_gate(finding))
        .filter(|finding| coverage_gap_feeds_gate || finding.kind != "coverage_gap")
        .map(|finding| ReviewFinding {
            kind: match finding.kind.as_str() {
                "contract_violation" | "agent_unreviewed" => ReviewSignalKind::PolicyViolation,
                "coverage_gap" => ReviewSignalKind::CoverageGap,
                _ => ReviewSignalKind::DownstreamRisk,
            },
            title: finding.message.clone(),
            blocking: finding.blocking,
        })
        .collect();

    let decision = derive_decision(&gate_findings, 0);
    let mut verdict = match decision.status {
        GateStatus::Pass => ShadowGateVerdict::Pass,
        GateStatus::NeedsAttention => ShadowGateVerdict::NeedsAttention,
        GateStatus::Blocked => ShadowGateVerdict::WouldBlock,
    };

    // Missing SOURCE evidence is never a pass: when the graph could not
    // capture code this change touched, the gate reports needs_attention
    // instead of certifying a clean result it did not actually verify. See
    // `gap_blocks_pass` for which gap kinds carry that weight.
    let pass_blocking_gaps = evidence_gaps
        .iter()
        .filter(|gap| gap_blocks_pass(gap))
        .count();
    if verdict == ShadowGateVerdict::Pass && pass_blocking_gaps > 0 {
        verdict = ShadowGateVerdict::NeedsAttention;
    }

    let risk_level = format!("{:?}", review.risk.overall_risk).to_lowercase();
    let summary = match verdict {
        ShadowGateVerdict::Pass => "no gate signals; would pass".to_string(),
        ShadowGateVerdict::NeedsAttention if decision.attention_count == 0 => format!(
            "{} evidence gap(s) prevent certifying a pass; evidence missing is not evidence of \
             safety",
            pass_blocking_gaps
        ),
        ShadowGateVerdict::NeedsAttention => format!(
            "{} attention signal(s); would pass with attention",
            decision.attention_count
        ),
        ShadowGateVerdict::WouldBlock => format!(
            "{} blocking finding(s), {} attention signal(s); would block in enforcing mode",
            decision.blocking_count, decision.attention_count
        ),
    };

    ShadowPolicyResult {
        enforcement: SHADOW_ENFORCEMENT_REPORT_ONLY.to_string(),
        verdict,
        risk_level,
        blocking_count: decision.blocking_count,
        attention_count: decision.attention_count,
        summary,
        findings,
    }
}

fn repair_guidance(kind: &str) -> &'static str {
    match kind {
        "breaking" => {
            "Update the listed consumers to the new contract or restore compatibility, then run \
             the covering tests."
        }
        "contract_violation" => {
            "The contract has graph-known consumers; version the contract or migrate every \
             consumer in the same change."
        }
        "coverage_gap" => {
            "No graph-known test covers this entity; add or link a test so the gate has proof."
        }
        "signature_change" => {
            "Verify every listed caller against the new signature before merging."
        }
        "visibility_change" => {
            "Confirm the visibility change is intentional; listed dependents may lose access."
        }
        "agent_unreviewed" => {
            "Record a human review decision for the agent-authored change before enforcing."
        }
        "entity_renamed" => "Confirm references were updated for the rename.",
        "consumer_fanout" => {
            "Behavior changed on an entity consumed from multiple files; verify each listed \
             consumer still gets the behavior it expects, then run the covering tests."
        }
        "downstream_risk" => {
            "The contract surface changed with graph-known downstream entities; verify each \
             listed dependent and consumer, then run the covering tests."
        }
        "revert_history" => {
            "This change is revert-shaped: it reintroduces or removes recently-changed \
             history. Confirm the original removal/addition was wrong before merging, and \
             check the linked history for the regression the earlier change addressed."
        }
        "toolchain_surface_change" => {
            "Inline lint or deprecation directives changed; confirm the shift in toolchain \
             enforcement is intended before merging."
        }
        _ => "Review the change against the listed blast radius.",
    }
}

fn collect_repair_context(
    findings: &[ShadowPolicyFinding],
    review: &Review,
) -> Vec<ShadowRepairItem> {
    let mut covering_tests: Vec<String> = review
        .impact
        .affected_tests
        .iter()
        .map(|test| {
            let (file, _, _) = entity_location(test);
            match file {
                Some(file) => format!("{} ({})", test.name, file),
                None => test.name.clone(),
            }
        })
        .collect();
    covering_tests.sort();
    covering_tests.dedup();

    let mut affected_consumers: Vec<String> = review
        .impact
        .affected_callers
        .iter()
        .chain(review.impact.affected_contract_consumers.iter())
        .map(|consumer| {
            let (file, _, _) = entity_location(consumer);
            match file {
                Some(file) => format!("{} ({})", consumer.name, file),
                None => consumer.name.clone(),
            }
        })
        .collect();
    affected_consumers.sort();
    affected_consumers.dedup();

    findings
        .iter()
        .filter(|finding| finding.severity != "info")
        .map(|finding| ShadowRepairItem {
            finding: finding.message.clone(),
            kind: finding.kind.clone(),
            file: finding.file.clone(),
            line: finding.line,
            covering_tests: covering_tests.clone(),
            affected_consumers: affected_consumers.clone(),
            guidance: repair_guidance(&finding.kind).to_string(),
        })
        .collect()
}

/// Inline lint-suppression and deprecation directives whose presence changes
/// what the toolchain enforces. A source edit touching only these lines alters
/// no semantic entity — comment-insensitive fingerprints produce zero entity
/// deltas — yet it shifts lint or deprecation enforcement, which is
/// review-worthy. Matched as case-sensitive substrings: a line counts only when
/// one of these tokens appears in it.
const TOOLCHAIN_DIRECTIVE_TOKENS: &[&str] = &[
    "//nolint",
    "# noqa",
    "# type: ignore",
    "eslint-disable",
    "#[allow(",
    "#[expect(",
    "@SuppressWarnings",
    "// Deprecated:",
    "@deprecated",
];

/// Whether a single line carries a toolchain-surface directive token.
fn line_has_directive(line: &str) -> bool {
    TOOLCHAIN_DIRECTIVE_TOKENS
        .iter()
        .any(|token| line.contains(token))
}

/// The set of directive-bearing lines in `bytes`, trimmed so relocation or
/// re-indentation of an otherwise unchanged directive does not read as a
/// change. Non-UTF8 bytes are decoded lossily; directive tokens are ASCII, so
/// that never changes which lines match.
fn directive_line_set(bytes: &[u8]) -> BTreeSet<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|line| line_has_directive(line))
        .map(str::to_string)
        .collect()
}

/// Directive lines added and removed between two blob revisions of a file.
/// Compares directive-line SETS, so a directive moved with identical text nets
/// to zero. Returns `None` when neither set changed. Deterministic: the sets
/// are ordered and the difference counts are order-independent.
fn directive_surface_delta(old: &[u8], new: &[u8]) -> Option<(usize, usize)> {
    let old_set = directive_line_set(old);
    let new_set = directive_line_set(new);
    let added = new_set.difference(&old_set).count();
    let removed = old_set.difference(&new_set).count();
    if added == 0 && removed == 0 {
        None
    } else {
        Some((added, removed))
    }
}

/// Build a toolchain-surface finding for one inert source edit when its two
/// blob revisions differ in directive lines. Reads are hash-addressed against
/// the blob store — never the filesystem. Silent when either hash is absent,
/// the two hashes are identical, a blob cannot be read, or no directive line
/// changed.
fn toolchain_surface_finding(
    blobs: &BlobStore,
    file: &str,
    old_hash: Option<Hash256>,
    new_hash: Option<Hash256>,
) -> Option<InlineComment> {
    let (old_hash, new_hash) = (old_hash?, new_hash?);
    if old_hash == new_hash {
        return None;
    }
    let old_bytes = blobs.read(&old_hash).ok()?;
    let new_bytes = blobs.read(&new_hash).ok()?;
    let (added, removed) = directive_surface_delta(&old_bytes, &new_bytes)?;
    Some(InlineComment {
        file: file.to_string(),
        start_line: 1,
        end_line: 1,
        kind: InlineCommentKind::ToolchainSurfaceChange,
        message: format!(
            "Toolchain directives changed in {file}: {added} added, {removed} removed; \
             lint/deprecation enforcement shifted"
        ),
    })
}

/// Collect evidence gaps for the report, plus any toolchain-surface findings
/// discovered while classifying inert source edits.
///
/// The findings are returned separately from the gaps: a directive change on an
/// inert edit is a normal warning finding that feeds the gate through
/// [`derive_policy`], NOT an evidence-gap demotion. `blobs` is `Option` because
/// the current shadow entry points cannot reach a blob reader without changing
/// their public signature (and their out-of-crate callers); the toolchain
/// channel is emitted only when a reader is supplied.
fn collect_evidence_gaps<G: GraphStore>(
    review: &Review,
    changes: &[kin_model::change::SemanticChange],
    changed_entities: &[ShadowChangedEntity],
    at_head: Option<&GraphAtRef<'_, G>>,
    blobs: Option<&BlobStore>,
) -> (Vec<ShadowEvidenceGap>, Vec<InlineComment>) {
    let mut gaps = Vec::new();
    let mut toolchain_findings: Vec<InlineComment> = Vec::new();

    // Files whose changes were recorded only as raw artifacts: the graph has
    // no entities for them, so they are invisible to blast radius and policy.
    // Retain each file's net old->new blob hashes across the range — first old,
    // last new, folded in stable slice order — so an inert source edit can be
    // inspected for toolchain-directive churn. Ordered by file (BTreeMap) so
    // both the gaps and any findings emit deterministically.
    let entity_files: BTreeSet<String> = changed_entities
        .iter()
        .filter_map(|entity| entity.file.clone())
        .collect();
    let mut artifact_hashes: BTreeMap<String, (Option<Hash256>, Option<Hash256>)> = BTreeMap::new();
    for change in changes {
        for delta in &change.artifact_deltas {
            let file = delta.file_id.to_string();
            if entity_files.contains(&file) {
                continue;
            }
            let entry = artifact_hashes
                .entry(file)
                .or_insert((delta.old_hash, delta.new_hash));
            entry.1 = delta.new_hash;
        }
    }
    for (file, (old_hash, new_hash)) in &artifact_hashes {
        // A source-class file whose raw bytes changed but whose entities the
        // graph DID capture at head is an inert edit — a comment, formatting,
        // or preprocessor-only change that altered no entity — not an
        // unparsed artifact. Report it with a non-demoting kind so a real
        // source file with living entities does not flip the verdict merely
        // for a comment touch. Genuinely uncaptured files (no entity anchored
        // at head, or head state unavailable) keep the demoting kind.
        let inert_source_edit = artifact_subject_is_source_class(file)
            && at_head.is_some_and(|at| at.has_entity_in_file(file));
        let (kind, detail) = if inert_source_edit {
            // The edit altered no entity, but if it changed inline lint or
            // deprecation directives it shifted what the toolchain enforces —
            // review-worthy on its own. Surface that as a normal warning
            // finding (not an evidence-gap demotion) when a blob reader is
            // available to diff the two revisions hash-addressed.
            if let Some(blobs) = blobs {
                if let Some(finding) = toolchain_surface_finding(blobs, file, *old_hash, *new_hash)
                {
                    toolchain_findings.push(finding);
                }
            }
            (
                "entity_inert_change",
                "source file changed but no semantic entity was altered (comment, formatting, or \
                 preprocessor-only edit); entities for this file remain captured at head, so the \
                 change is inert rather than an unparsed-source gap",
            )
        } else {
            (
                "artifact_only_change",
                "file changed but no semantic entities were captured for it (unsupported \
                 language or unparsed artifact); its impact is NOT included in the blast radius \
                 or policy result",
            )
        };
        gaps.push(ShadowEvidenceGap {
            kind: kind.to_string(),
            subject: file.clone(),
            detail: detail.to_string(),
        });
    }

    // Changed entities without a source span cannot anchor line-level findings.
    for entity in changed_entities {
        if entity.change != "removed" && entity.start_line.is_none() {
            gaps.push(ShadowEvidenceGap {
                kind: "missing_span".to_string(),
                subject: entity.name.clone(),
                detail: "changed entity has no source span in the graph; line-anchored findings \
                         and inline evidence are unavailable for it"
                    .to_string(),
            });
        }
    }

    // An empty impact signal is only trustworthy when relation data exists.
    // Distinguishing "genuinely isolated" from "relations never ingested"
    // requires coverage state the report does not have, so say so.
    if !changed_entities.is_empty() && review.impact.is_empty() {
        gaps.push(ShadowEvidenceGap {
            kind: "impact_signal_absent".to_string(),
            subject: "blast_radius".to_string(),
            detail: "no graph relations connect the changed entities to any caller, dependent, \
                     contract consumer, or test; verify relation ingestion completed for this \
                     repository before treating the empty blast radius as proof of isolation"
                .to_string(),
        });
    }

    // Actor attribution requires recorded audit events; absence is a gap, not
    // a claim that no agent was involved.
    if review.impact.actor_attribution.is_empty() && !changed_entities.is_empty() {
        gaps.push(ShadowEvidenceGap {
            kind: "actor_attribution_unavailable".to_string(),
            subject: "audit.entity_attribution".to_string(),
            detail: "no recorded audit events attribute the changed entities to an actor; \
                     author identity comes from change metadata only"
                .to_string(),
        });
    }

    gaps.push(ShadowEvidenceGap {
        kind: "cross_repo_not_evaluated".to_string(),
        subject: "blast_radius.cross_repo".to_string(),
        detail: "cross-repo federation is not evaluated by shadow report v1; consumers in other \
                 repositories are not represented in this report"
            .to_string(),
    });

    (gaps, toolchain_findings)
}

fn actor_kind_label(actor: &str) -> &'static str {
    let lowered = actor.to_ascii_lowercase();
    if lowered.contains("codex")
        || lowered.contains("assistant")
        || lowered.contains("claude")
        || lowered.contains("gemini")
        || lowered.contains("agent")
    {
        "assistant"
    } else if lowered.contains("service") || lowered.contains("daemon") {
        "service"
    } else {
        "human"
    }
}

fn collect_audit_evidence<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
    review: &Review,
    changes_in_range: usize,
) -> Result<ShadowAuditEvidence, ReviewError> {
    let mut entity_attribution: Vec<ShadowAttribution> = review
        .impact
        .actor_attribution
        .iter()
        .map(|(entity_id, kind)| ShadowAttribution {
            entity_id: entity_id.to_string(),
            actor_kind: format!("{:?}", kind).to_lowercase(),
        })
        .collect();
    entity_attribution.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));

    let mut head_approvals: Vec<ShadowApproval> = store
        .get_approvals_for_change(&request.resolved_head)
        .map_err(ReviewError::graph)?
        .iter()
        .map(|approval| ShadowApproval {
            approver: approval.approver.to_string(),
            decision: approval.decision.to_string(),
            reason: approval.reason.clone(),
        })
        .collect();
    head_approvals.sort_by(|a, b| a.approver.cmp(&b.approver));

    Ok(ShadowAuditEvidence {
        generated_at: Timestamp::now(),
        actor: request.actor.clone(),
        actor_kind: actor_kind_label(&request.actor).to_string(),
        tool: "kin-review".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        base_change: request.resolved_base.to_string(),
        head_change: request.resolved_head.to_string(),
        changes_in_range,
        entity_attribution,
        head_approvals,
    })
}

/// Render a shadow gate report for humans.
pub fn format_shadow_report(report: &ShadowGateReport) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "Shadow Merge Gate Report (report-only; never blocks)");
    let _ = writeln!(
        out,
        "  Range: {} .. {}",
        report.input.base_ref, report.input.head_ref
    );
    if let Some(title) = &report.input.title {
        let _ = writeln!(out, "  Title: {}", title);
    }
    if let Some(source_url) = &report.input.source_url {
        let _ = writeln!(out, "  Source: {}", source_url);
    }

    let verdict = match report.policy.verdict {
        ShadowGateVerdict::Pass => "PASS",
        ShadowGateVerdict::NeedsAttention => "NEEDS ATTENTION",
        ShadowGateVerdict::WouldBlock => "WOULD BLOCK",
    };
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Verdict: {} (risk: {}) — {}",
        verdict, report.policy.risk_level, report.policy.summary
    );

    let _ = writeln!(out);
    let _ = writeln!(out, "Changed entities ({}):", report.changed_entities.len());
    for entity in &report.changed_entities {
        let location = match (&entity.file, entity.start_line) {
            (Some(file), Some(line)) => format!(" [{}:{}]", file, line),
            (Some(file), None) => format!(" [{}]", file),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "  {} {} ({}){}",
            match entity.change.as_str() {
                "added" => "+",
                "removed" => "-",
                _ => "~",
            },
            entity.name,
            entity.kind,
            location
        );
    }

    let radius = &report.blast_radius;
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Blast radius ({} affected; this repository):",
        radius.total_affected
    );
    for (label, entries) in [
        ("callers", &radius.callers),
        ("dependents", &radius.dependents),
        ("contract consumers", &radius.contract_consumers),
        ("tests", &radius.tests),
    ] {
        if !entries.is_empty() {
            let _ = writeln!(out, "  {} ({}):", label, entries.len());
            for entry in entries {
                let location = entry
                    .file
                    .as_ref()
                    .map(|file| format!(" [{}]", file))
                    .unwrap_or_default();
                let _ = writeln!(out, "    {}{}", entry.name, location);
            }
        }
    }
    if !radius.open_work_items.is_empty() {
        let _ = writeln!(out, "  open work items ({}):", radius.open_work_items.len());
        for item in &radius.open_work_items {
            let _ = writeln!(out, "    {} [{}]", item.title, item.status);
        }
    }
    let _ = writeln!(
        out,
        "  cross-repo: {} — {}",
        radius.cross_repo.status, radius.cross_repo.detail
    );

    if !report.policy.findings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Findings ({}):", report.policy.findings.len());
        for finding in &report.policy.findings {
            let location = match (&finding.file, finding.line) {
                (Some(file), Some(line)) => format!(" [{}:{}]", file, line),
                (Some(file), None) => format!(" [{}]", file),
                _ => String::new(),
            };
            let _ = writeln!(
                out,
                "  [{}]{} {}{}",
                finding.severity,
                if finding.blocking { " [blocking]" } else { "" },
                finding.message,
                location
            );
        }
    }

    if !report.repair_context.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Repair context:");
        for item in &report.repair_context {
            let _ = writeln!(out, "  - {}", item.finding);
            let _ = writeln!(out, "    {}", item.guidance);
            if !item.covering_tests.is_empty() {
                let _ = writeln!(out, "    tests: {}", item.covering_tests.join(", "));
            }
            if !item.affected_consumers.is_empty() {
                let _ = writeln!(out, "    consumers: {}", item.affected_consumers.join(", "));
            }
        }
    }

    if !report.evidence_gaps.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Evidence gaps ({}):", report.evidence_gaps.len());
        for gap in &report.evidence_gaps {
            let _ = writeln!(out, "  [{}] {}: {}", gap.kind, gap.subject, gap.detail);
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Audit: generated {} by {} ({}) via {} {} over {} change(s) [{} -> {}]",
        report.audit.generated_at,
        report.audit.actor,
        report.audit.actor_kind,
        report.audit.tool,
        report.audit.tool_version,
        report.audit.changes_in_range,
        report.audit.base_change,
        report.audit.head_change
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::change::{
        ArtifactDelta, ArtifactDeltaKind, EntityDelta, RelationDelta, SemanticChange,
    };
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        SourceSpan, Visibility,
    };
    use kin_model::graph::{ChangeStore, EntityStore};
    use kin_model::ids::*;
    use kin_model::relation::{GraphNodeId, Relation, RelationKind, RelationOrigin};
    use kin_model::timestamp::Timestamp;

    fn entity_with_span(name: &str, file: &str, start_line: u32, role: EntityRole) -> Entity {
        let file_id = FilePathId::new(file);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: 10,
                start_line,
                start_col: 0,
                end_line: start_line + 2,
                end_col: 1,
            }),
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role,
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

    fn change_with_deltas(
        id: SemanticChangeId,
        parents: Vec<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        artifact_deltas: Vec<ArtifactDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test-author"),
            message: "test change".into(),
            entity_deltas,
            relation_deltas,
            artifact_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn relation(src: &Entity, dst: &Entity, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    fn request(base: SemanticChangeId, head: SemanticChangeId) -> ShadowRequest {
        ShadowRequest {
            base_ref: "main".into(),
            head_ref: "feature/change".into(),
            resolved_base: base,
            resolved_head: head,
            title: Some("test PR".into()),
            source_url: None,
            author: Some("agent-bot".into()),
            actor: "test-runner".into(),
        }
    }

    /// Graph with: base change adding `target` + `caller` + `test`, head
    /// change modifying `target`'s signature. Caller and test are wired to
    /// `target` via relations recorded in the committed change DAG and
    /// mirrored into the live adjacency (a consistent repo).
    fn signature_change_graph() -> (InMemoryGraph, SemanticChangeId, SemanticChangeId) {
        let graph = InMemoryGraph::new();

        let target_v1 = entity_with_span("compute_total", "src/billing.rs", 10, EntityRole::Source);
        let mut target_v2 = target_v1.clone();
        target_v2.signature = "fn compute_total(currency: &str)".into();

        let caller = entity_with_span("render_invoice", "src/invoice.rs", 5, EntityRole::Source);
        let test = entity_with_span(
            "test_compute_total",
            "tests/billing.rs",
            3,
            EntityRole::Test,
        );

        let calls_rel = relation(&caller, &target_v2, RelationKind::Calls);
        let tests_rel = relation(&test, &target_v2, RelationKind::Tests);

        graph.upsert_entity(&target_v2).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&test).unwrap();
        graph.upsert_relation(&calls_rel).unwrap();
        graph.upsert_relation(&tests_rel).unwrap();

        let base_id = change_id(1);
        let head_id = change_id(2);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![
                EntityDelta::Added(target_v1.clone()),
                EntityDelta::Added(caller),
                EntityDelta::Added(test),
            ],
            vec![
                RelationDelta::Added(calls_rel),
                RelationDelta::Added(tests_rel),
            ],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        (graph, base_id, head_id)
    }

    #[test]
    fn report_carries_blast_radius_verdict_and_audit() {
        let (graph, base_id, head_id) = signature_change_graph();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        assert_eq!(report.schema_version, SHADOW_GATE_REPORT_SCHEMA_VERSION);
        assert_eq!(report.mode, "shadow");
        assert_eq!(report.policy.enforcement, SHADOW_ENFORCEMENT_REPORT_ONLY);

        assert_eq!(report.changed_entities.len(), 1);
        assert_eq!(report.changed_entities[0].name, "compute_total");
        assert_eq!(report.changed_entities[0].change, "modified");
        assert!(report.changed_entities[0].signature_changed);

        // The impact walker reaches incoming consumers through the
        // incoming-edge downstream traversal, bucketing them as dependents.
        assert!(report
            .blast_radius
            .dependents
            .iter()
            .any(|dependent| dependent.name == "render_invoice"));
        assert!(report
            .blast_radius
            .tests
            .iter()
            .any(|test| test.name == "test_compute_total"));
        assert!(report.blast_radius.total_affected >= 2);

        // Signature change with graph-known downstream entities -> would block.
        // The blocking anchor is the per-entity breaking finding; downstream_risk
        // dedups against an existing blocking finding at the same location.
        assert_eq!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
        assert!(report.policy.blocking_count >= 1);
        assert!(report.policy.findings.iter().any(|finding| finding.blocking
            && (finding.kind == "breaking" || finding.kind == "downstream_risk")));

        // Repair context points at the covering test.
        assert!(!report.repair_context.is_empty());
        assert!(report.repair_context.iter().any(|item| item
            .covering_tests
            .iter()
            .any(|test| test.contains("test_compute_total"))));

        // Audit evidence identifies range, actor, and tool.
        assert_eq!(report.audit.base_change, base_id.to_string());
        assert_eq!(report.audit.head_change, head_id.to_string());
        assert_eq!(report.audit.changes_in_range, 1);
        assert_eq!(report.audit.actor, "test-runner");
        assert_eq!(report.audit.tool, "kin-review");
        assert!(!report.audit.tool_version.is_empty());

        // Cross-repo is labeled, never silently green.
        assert_eq!(report.blast_radius.cross_repo.status, "not_evaluated");
        assert!(report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "cross_repo_not_evaluated"));
    }

    #[test]
    fn contract_surface_representative_is_deterministic() {
        use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
        use crate::impact::{EntityImpact, ImpactReport};
        use kin_model::review::{RiskLevel, RiskSummary};

        // A tie of removed entities: each renders with location=None, so the
        // finding builder's (file,line) dedup collapses them onto a single
        // representative. Before the fix the survivor was whichever the source
        // collection happened to yield first; it must now be the smallest id.
        let ids: Vec<EntityId> = ["gamma", "alpha", "beta", "delta"]
            .iter()
            .map(|&name| EntityId::from_content("src/tie.rs", name, "function", 1))
            .collect();
        let expected = *ids.iter().min().unwrap();

        let build_review = |order: &[usize]| -> Review {
            let entity_changes: Vec<EntityChange> = order
                .iter()
                .map(|&i| EntityChange {
                    entity_id: ids[i],
                    kind: EntityChangeKind::Removed(ids[i]),
                })
                .collect();
            Review {
                base: None,
                head: None,
                diff: SemanticDiff {
                    base: None,
                    head: None,
                    entity_changes,
                    relation_changes: vec![],
                },
                // One graph-known consumer per removed entity makes the
                // per-entity contract-surface rule fire for each candidate.
                impact: ImpactReport {
                    affected_dependents: vec![entity_with_span(
                        "downstream_consumer",
                        "src/consumer.rs",
                        1,
                        EntityRole::Source,
                    )],
                    entity_impacts: ids
                        .iter()
                        .map(|&entity_id| EntityImpact {
                            entity_id,
                            consumer_count: 1,
                            strong_consumer_count: 1,
                            contract_consumer_count: 0,
                            consumer_files: vec!["src/consumer.rs".to_string()],
                            covering_tests: 0,
                        })
                        .collect(),
                    ..Default::default()
                },
                risk: RiskSummary {
                    overall_risk: RiskLevel::Low,
                    breaking_changes: vec![],
                    test_coverage_gaps: vec![],
                    contract_violations: vec![],
                    work_risks: vec![],
                    notes: vec![],
                },
                inline_comments: vec![],
            }
        };

        // Exactly one contract-surface representative survives, naming the
        // smallest entity id regardless of the input order.
        let natural = derive_policy(&build_review(&[0, 1, 2, 3]), &[], &[]);
        let contract: Vec<&ShadowPolicyFinding> = natural
            .findings
            .iter()
            .filter(|finding| finding.kind == "downstream_risk")
            .collect();
        assert_eq!(
            contract.len(),
            1,
            "removed tie must collapse to a single representative finding"
        );
        assert_eq!(
            contract[0].message,
            format!(
                "Contract surface of `{expected}` changed with 1 graph-known downstream entity(ies)"
            ),
        );

        // Emitted findings must be byte-identical across repeated in-process
        // runs and across every input order — the determinism the merge-trust
        // n=3 bit-identity gate depends on.
        let baseline =
            serde_json::to_string(&derive_policy(&build_review(&[0, 1, 2, 3]), &[], &[]).findings)
                .unwrap();
        for order in [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]] {
            for _ in 0..3 {
                let result = derive_policy(&build_review(&order), &[], &[]);
                assert_eq!(result.verdict, ShadowGateVerdict::WouldBlock);
                assert_eq!(
                    serde_json::to_string(&result.findings).unwrap(),
                    baseline,
                    "findings must be byte-identical regardless of entity_changes order"
                );
            }
        }
    }

    #[test]
    fn benign_class_artifact_gap_reports_without_demoting() {
        // Named forensic case: a benign body-touch plus a config-only
        // artifact change. Every deficit stays reported as an explicit gap,
        // but a non-source artifact and an empty relation channel are not
        // treated as risk: the verdict is an honest pass with gaps attached.
        let graph = InMemoryGraph::new();
        let entity = entity_with_span("helper", "src/lib.rs", 1, EntityRole::Source);
        graph.upsert_entity(&entity).unwrap();

        let base_id = change_id(3);
        let head_id = change_id(4);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![EntityDelta::Added(entity.clone())],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: entity.clone(),
                new: entity,
            }],
            vec![],
            vec![ArtifactDelta {
                file_id: FilePathId::new("config/policy.yaml"),
                kind: ArtifactDeltaKind::Modified,
                old_hash: Some(Hash256::from_bytes([7; 32])),
                new_hash: Some(Hash256::from_bytes([8; 32])),
            }],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let artifact_gap = report
            .evidence_gaps
            .iter()
            .find(|gap| gap.kind == "artifact_only_change")
            .expect("artifact-only change must surface as an evidence gap");
        assert_eq!(artifact_gap.subject, "config/policy.yaml");

        // No relations exist -> the empty impact channel stays reported.
        assert!(report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "impact_signal_absent"));
        assert!(report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "actor_attribution_unavailable"));

        // A config-class artifact and an ambiguous-empty channel are
        // reported, not flagged: the gate passes while saying what it could
        // not see.
        assert_eq!(report.policy.verdict, ShadowGateVerdict::Pass);
    }

    #[test]
    fn source_class_artifact_gap_still_demotes() {
        // Counter-case: the same artifact-only gap on a file the ingest
        // classifier calls source means real code changed that the graph
        // never captured. That deficit still demotes the pass.
        let graph = InMemoryGraph::new();
        let entity = entity_with_span("helper", "src/lib.rs", 1, EntityRole::Source);
        graph.upsert_entity(&entity).unwrap();

        let base_id = change_id(6);
        let head_id = change_id(7);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![EntityDelta::Added(entity.clone())],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: entity.clone(),
                new: entity,
            }],
            vec![],
            vec![ArtifactDelta {
                file_id: FilePathId::new("src/legacy.c"),
                kind: ArtifactDeltaKind::Modified,
                old_hash: Some(Hash256::from_bytes([9; 32])),
                new_hash: Some(Hash256::from_bytes([10; 32])),
            }],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        assert!(report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "artifact_only_change" && gap.subject == "src/legacy.c"));
        assert_eq!(report.policy.verdict, ShadowGateVerdict::NeedsAttention);
    }

    #[test]
    fn gap_demotion_is_artifact_class_aware() {
        use crate::diff::SemanticDiff;
        use crate::impact::ImpactReport;
        use kin_model::review::{RiskLevel, RiskSummary};

        let empty_review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };
        let gap = |kind: &str, subject: &str| ShadowEvidenceGap {
            kind: kind.to_string(),
            subject: subject.to_string(),
            detail: "test gap".to_string(),
        };

        // Docs / CI / config-class artifacts report without demoting.
        for subject in ["README.md", ".github/workflows/ci.yml", "policy.yaml"] {
            let policy = derive_policy(&empty_review, &[gap("artifact_only_change", subject)], &[]);
            assert_eq!(
                policy.verdict,
                ShadowGateVerdict::Pass,
                "non-source artifact gap must not demote: {subject}"
            );
        }

        // Source-class artifacts demote: code changed invisibly.
        for subject in ["src/legacy.c", "pkg/util.go", "app/views.py"] {
            let policy = derive_policy(&empty_review, &[gap("artifact_only_change", subject)], &[]);
            assert_eq!(
                policy.verdict,
                ShadowGateVerdict::NeedsAttention,
                "source-class artifact gap must demote: {subject}"
            );
        }

        // A changed entity without a source anchor always demotes.
        let policy = derive_policy(&empty_review, &[gap("missing_span", "helper")], &[]);
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);

        // The empty relation channel is reported but does not flip the
        // verdict by itself; the coverage channel is suppressed on the same
        // condition so the ambiguity is neither hidden nor double-counted.
        let policy = derive_policy(
            &empty_review,
            &[gap("impact_signal_absent", "blast_radius")],
            &[],
        );
        assert_eq!(policy.verdict, ShadowGateVerdict::Pass);
    }

    #[test]
    fn removed_entity_names_resolve_from_graph() {
        // The diff carries only the removed entity's id; findings and the
        // changed-entity list must read as code, not opaque ids.
        let graph = InMemoryGraph::new();
        let legacy = entity_with_span("legacy_helper", "src/old.rs", 4, EntityRole::Source);
        let consumer = entity_with_span("still_calls_it", "src/live.rs", 9, EntityRole::Source);
        let calls_rel = relation(&consumer, &legacy, RelationKind::Calls);
        graph.upsert_entity(&legacy).unwrap();
        graph.upsert_entity(&consumer).unwrap();
        graph.upsert_relation(&calls_rel).unwrap();

        let base_id = change_id(8);
        let head_id = change_id(9);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![
                EntityDelta::Added(legacy.clone()),
                EntityDelta::Added(consumer.clone()),
            ],
            vec![RelationDelta::Added(calls_rel)],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Removed(legacy.id)],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let removed = report
            .changed_entities
            .iter()
            .find(|entity| entity.change == "removed")
            .expect("removed entity must be listed");
        assert_eq!(removed.name, "legacy_helper");
        assert_eq!(removed.file.as_deref(), Some("src/old.rs"));

        // Removal with a graph-known consumer — committed at base, severed
        // by the removal at head — is a blocking downstream risk, and the
        // finding names the entity, not its uuid.
        let downstream = report
            .policy
            .findings
            .iter()
            .find(|finding| finding.kind == "downstream_risk")
            .expect("removal with consumers must carry a downstream risk");
        assert!(
            downstream.message.contains("legacy_helper"),
            "finding must name the removed entity: {}",
            downstream.message
        );
        assert_eq!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    /// Committed DAG modelling a real deletion: a base change adds a public
    /// entity, a non-test consumer, and (optionally) a covering test wired by
    /// committed relations; the head change removes the entity. Nothing is
    /// mirrored into the live adjacency, so the removed entity is genuinely
    /// absent at head — `store.get_entity` on the live store returns `None`,
    /// exactly as after a real removal. The removed entity and its inbound
    /// edges survive only in the base ref's replayed state.
    fn removal_graph(
        consumer_role: EntityRole,
        include_consumer: bool,
    ) -> (InMemoryGraph, SemanticChangeId, SemanticChangeId) {
        let graph = InMemoryGraph::new();
        let validate = entity_with_span("validate", "src/base.rs", 111, EntityRole::Source);
        let (consumer_file, consumer_name) = match consumer_role {
            EntityRole::Test => ("tests/base.rs", "test_validate"),
            _ => ("src/runserver.rs", "run_from_argv"),
        };
        let consumer = entity_with_span(consumer_name, consumer_file, 111, consumer_role);
        let calls_kind = match consumer_role {
            EntityRole::Test => RelationKind::Tests,
            _ => RelationKind::Calls,
        };
        let consume_rel = relation(&consumer, &validate, calls_kind);

        let base_id = change_id(20);
        let head_id = change_id(21);
        let mut base_entities = vec![EntityDelta::Added(validate.clone())];
        let mut base_relations = vec![];
        if include_consumer {
            base_entities.push(EntityDelta::Added(consumer));
            base_relations.push(RelationDelta::Added(consume_rel));
        }
        let base = change_with_deltas(base_id, vec![], base_entities, base_relations, vec![]);
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Removed(validate.id)],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();
        (graph, base_id, head_id)
    }

    #[test]
    fn removed_public_entity_with_live_consumer_blocks_from_base_state() {
        // (a) `validate` is deleted while a live non-test consumer still calls
        // it. The consumer edge and the entity's identity survive only in the
        // base ref, so the breaking-removal rule must harvest the
        // surviving-consumer count and the entity name from base state: a
        // blocking downstream_risk that names `validate`, verdict WouldBlock.
        let (graph, base_id, head_id) = removal_graph(EntityRole::Source, true);
        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let downstream = report
            .policy
            .findings
            .iter()
            .find(|finding| finding.kind == "downstream_risk")
            .expect("deleting a consumed public entity is a downstream risk");
        assert!(
            downstream.blocking,
            "a deleted-yet-consumed API is a genuine block, not a demoted warning"
        );
        assert_eq!(downstream.severity, "error");
        assert!(
            downstream.message.contains("validate"),
            "finding must name the removed entity from base state: {}",
            downstream.message
        );
        assert_eq!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    #[test]
    fn removed_entity_with_only_test_consumers_does_not_block() {
        // (b) The only base consumer of the removed entity is a test. Tests
        // that cover a deleted thing are co-updated, not a broken contract, so
        // the base harvest excludes them: no downstream_risk, no block.
        let (graph, base_id, head_id) = removal_graph(EntityRole::Test, true);
        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        assert!(
            !report
                .policy
                .findings
                .iter()
                .any(|finding| finding.kind == "downstream_risk" || finding.kind == "breaking"),
            "a removal whose only base consumers are tests is not a breaking removal"
        );
        assert_ne!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
        // The name still resolves from base even without a blocking finding.
        let removed = report
            .changed_entities
            .iter()
            .find(|entity| entity.change == "removed")
            .expect("removed entity is listed");
        assert_eq!(removed.name, "validate");
    }

    #[test]
    fn removed_entity_with_no_base_consumers_does_not_block() {
        // (c) The removed entity has zero base consumers. There is no surviving
        // surface to break, so no downstream_risk fires and the gate does not
        // block.
        let (graph, base_id, head_id) = removal_graph(EntityRole::Source, false);
        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        assert!(
            !report
                .policy
                .findings
                .iter()
                .any(|finding| finding.kind == "downstream_risk" || finding.kind == "breaking"),
            "a removal with no base consumers is not a breaking removal"
        );
        assert_ne!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    #[test]
    fn remove_and_readd_same_name_is_move_not_breaking_from_base() {
        // (d) One diff removes `validate` (which has a base consumer) and adds a
        // fresh entity of the SAME name. Because the removed id now resolves to
        // `validate` from base, the same-name re-add is recognised as a move:
        // no downstream_risk despite the base consumer. Without base-side name
        // resolution the removed side reads as a uuid, fails the move match,
        // and fires a demoted downstream_risk instead.
        let graph = InMemoryGraph::new();
        let validate_old = entity_with_span("validate", "src/base.rs", 111, EntityRole::Source);
        let validate_new = entity_with_span("validate", "src/base_v2.rs", 5, EntityRole::Source);
        let consumer =
            entity_with_span("run_from_argv", "src/runserver.rs", 111, EntityRole::Source);
        let calls_rel = relation(&consumer, &validate_old, RelationKind::Calls);

        let base_id = change_id(22);
        let head_id = change_id(23);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![
                EntityDelta::Added(validate_old.clone()),
                EntityDelta::Added(consumer),
            ],
            vec![RelationDelta::Added(calls_rel)],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![
                EntityDelta::Removed(validate_old.id),
                EntityDelta::Added(validate_new),
            ],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        assert!(
            !report
                .policy
                .findings
                .iter()
                .any(|finding| finding.kind == "downstream_risk"),
            "same-diff remove + re-add of one name is a move, not a breaking removal"
        );
        assert_ne!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
        let removed = report
            .changed_entities
            .iter()
            .find(|entity| entity.change == "removed")
            .expect("removed entity is listed");
        assert_eq!(removed.name, "validate");
    }

    #[test]
    fn removed_entity_name_resolves_from_base_not_uuid() {
        // (e) A removed entity absent at head still resolves its name, kind, and
        // file from the base ref for the changed-entities output — never the
        // raw uuid / "unknown" fallback the head-only lookup produced.
        let (graph, base_id, head_id) = removal_graph(EntityRole::Source, false);
        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let removed = report
            .changed_entities
            .iter()
            .find(|entity| entity.change == "removed")
            .expect("removed entity is listed");
        assert_eq!(removed.name, "validate");
        assert_eq!(removed.kind, "Function");
        assert_eq!(removed.file.as_deref(), Some("src/base.rs"));
        assert_ne!(
            removed.name, removed.entity_id,
            "the name must not fall back to the raw id"
        );
    }

    #[test]
    fn same_diff_remove_and_readd_is_move_not_breaking() {
        use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
        use crate::impact::{EntityImpact, ImpactReport};
        use kin_model::review::{RiskLevel, RiskSummary};

        let moved_old_id = EntityId::from_content("src/before.rs", "mover", "function", 1);
        let readded = entity_with_span("mover", "src/after.rs", 1, EntityRole::Source);

        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff {
                base: None,
                head: None,
                entity_changes: vec![
                    EntityChange {
                        entity_id: moved_old_id,
                        kind: EntityChangeKind::Removed(moved_old_id),
                    },
                    EntityChange {
                        entity_id: readded.id,
                        kind: EntityChangeKind::Added(readded.clone()),
                    },
                ],
                relation_changes: vec![],
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: moved_old_id,
                    consumer_count: 1,
                    strong_consumer_count: 1,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/consumer.rs".to_string()],
                    covering_tests: 0,
                }],
                ..Default::default()
            },
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let removed_entry = ShadowChangedEntity {
            entity_id: moved_old_id.to_string(),
            name: "mover".to_string(),
            kind: "Function".to_string(),
            change: "removed".to_string(),
            file: Some("src/before.rs".to_string()),
            start_line: None,
            end_line: None,
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        };
        let added_entry = ShadowChangedEntity {
            entity_id: readded.id.to_string(),
            name: "mover".to_string(),
            kind: "Function".to_string(),
            change: "added".to_string(),
            file: Some("src/after.rs".to_string()),
            start_line: Some(1),
            end_line: Some(3),
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        };

        // With the same-name re-add present, the removal is a move: no
        // downstream risk, nothing to block.
        let policy = derive_policy(&review, &[], &[removed_entry.clone(), added_entry]);
        assert!(
            !policy
                .findings
                .iter()
                .any(|finding| finding.kind == "downstream_risk"),
            "same-diff remove+re-add of one name is a move, not a removal"
        );
        assert_eq!(policy.verdict, ShadowGateVerdict::Pass);

        // Without the re-add the identical removal is a breaking removal.
        let policy = derive_policy(&review, &[], &[removed_entry]);
        assert!(policy
            .findings
            .iter()
            .any(|finding| finding.kind == "downstream_risk" && finding.message.contains("mover")));
        assert_eq!(policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    #[test]
    fn isolated_signature_change_reports_without_gating() {
        // A signature change on an entity the graph connects to nothing is
        // reported as a finding but cannot justify an attention verdict by
        // itself: with zero inbound edges there is no proven audience.
        use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
        use crate::impact::{EntityImpact, ImpactReport};
        use crate::inline::InlineComment;
        use kin_model::review::{RiskLevel, RiskSummary};

        let old = entity_with_span("loner", "src/loner.rs", 2, EntityRole::Source);
        let mut new = old.clone();
        new.signature = "fn loner(flag: bool)".to_string();

        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff {
                base: None,
                head: None,
                entity_changes: vec![EntityChange {
                    entity_id: new.id,
                    kind: EntityChangeKind::Modified {
                        old,
                        new: new.clone(),
                    },
                }],
                relation_changes: vec![],
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: new.id,
                    consumer_count: 0,
                    strong_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    covering_tests: 0,
                }],
                ..Default::default()
            },
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![InlineComment {
                file: "src/loner.rs".to_string(),
                start_line: 2,
                end_line: 4,
                kind: InlineCommentKind::SignatureChange,
                message: "Signature changed: `fn loner()` → `fn loner(flag: bool)`".to_string(),
            }],
        };

        let policy = derive_policy(&review, &[], &[]);
        assert!(
            policy
                .findings
                .iter()
                .any(|finding| finding.kind == "signature_change"),
            "the signature change stays reported"
        );
        assert_eq!(
            policy.verdict,
            ShadowGateVerdict::Pass,
            "an isolated surface change must not gate on its own"
        );
        assert_eq!(policy.attention_count, 0);
    }

    #[test]
    fn blast_radius_derives_from_ref_state_not_live_adjacency() {
        // The production bug shape: committed changes carry relation deltas,
        // but the live adjacency was never updated from them and holds a
        // divergent set. The blast radius must come from the committed state
        // at the head ref, not from whatever happens to be resident.
        let graph = InMemoryGraph::new();

        let target_v1 = entity_with_span("compute_total", "src/billing.rs", 10, EntityRole::Source);
        let mut target_v2 = target_v1.clone();
        target_v2.signature = "fn compute_total(currency: &str)".into();
        let caller = entity_with_span("render_invoice", "src/invoice.rs", 5, EntityRole::Source);
        let live_only =
            entity_with_span("live_only_consumer", "src/live.rs", 8, EntityRole::Source);

        // Live store: entities present, but the ONLY resident relation is one
        // the committed history never recorded.
        graph.upsert_entity(&target_v2).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&live_only).unwrap();
        graph
            .upsert_relation(&relation(&live_only, &target_v2, RelationKind::Calls))
            .unwrap();

        let base_id = change_id(0x21);
        let head_id = change_id(0x22);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![
                EntityDelta::Added(target_v1.clone()),
                EntityDelta::Added(caller.clone()),
            ],
            vec![RelationDelta::Added(relation(
                &caller,
                &target_v1,
                RelationKind::Calls,
            ))],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        // The committed caller is reached through the replayed ref state even
        // though the live adjacency never held that relation.
        assert!(report
            .blast_radius
            .dependents
            .iter()
            .any(|dependent| dependent.name == "render_invoice"));

        // The live-only relation is invisible: it belongs to another era.
        let mentions_live_only = report
            .blast_radius
            .callers
            .iter()
            .chain(report.blast_radius.dependents.iter())
            .chain(report.blast_radius.contract_consumers.iter())
            .chain(report.blast_radius.tests.iter())
            .any(|affected| affected.name == "live_only_consumer");
        assert!(!mentions_live_only);
    }

    #[test]
    fn unmaterializable_ref_state_reports_loud_gap_not_live_fallback() {
        let graph = InMemoryGraph::new();

        let target_v1 = entity_with_span("orphan_target", "src/orphan.rs", 4, EntityRole::Source);
        let mut target_v2 = target_v1.clone();
        target_v2.signature = "fn orphan_target(x: u8)".into();
        let live_caller = entity_with_span("live_caller", "src/live.rs", 6, EntityRole::Source);

        // The live adjacency has a caller wired to the changed entity; a
        // silent fallback would report it as blast radius.
        graph.upsert_entity(&target_v2).unwrap();
        graph.upsert_entity(&live_caller).unwrap();
        graph
            .upsert_relation(&relation(&live_caller, &target_v2, RelationKind::Calls))
            .unwrap();

        // base's parent was never imported, so the state at head cannot be
        // replayed even though the base..head rows themselves exist.
        let ghost_parent = change_id(0x31);
        let base_id = change_id(0x32);
        let head_id = change_id(0x33);
        let base = change_with_deltas(
            base_id,
            vec![ghost_parent],
            vec![EntityDelta::Added(target_v1.clone())],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let gap = report
            .evidence_gaps
            .iter()
            .find(|gap| gap.kind == "ref_state_unavailable")
            .expect("unmaterializable ref state must surface as an evidence gap");
        assert!(gap.detail.contains("graph state at ref not materialized"));
        assert!(gap.detail.contains(&ghost_parent.to_string()));

        // No silent fallback: the blast radius stays empty even though the
        // live adjacency holds a caller for the changed entity.
        assert_eq!(report.blast_radius.total_affected, 0);
        assert!(report.blast_radius.callers.is_empty());
        assert!(report.blast_radius.dependents.is_empty());

        // The specific ref-state gap subsumes the generic empty-impact gap.
        assert!(!report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "impact_signal_absent"));

        // Missing evidence never certifies a pass.
        assert_ne!(report.policy.verdict, ShadowGateVerdict::Pass);
    }

    #[test]
    fn base_off_head_ancestry_reports_loud_gap_not_range_walk() {
        let graph = InMemoryGraph::new();

        let target_v1 = entity_with_span("routed_target", "src/routed.rs", 4, EntityRole::Source);
        let mut target_v2 = target_v1.clone();
        target_v2.signature = "fn routed_target(x: u8)".into();
        let stray = entity_with_span("stray_entity", "src/stray.rs", 9, EntityRole::Source);

        // Main line: root -> head, fully materializable.
        let root_id = change_id(0x41);
        let head_id = change_id(0x42);
        let root = change_with_deltas(
            root_id,
            vec![],
            vec![EntityDelta::Added(target_v1.clone())],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![root_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        // Disjoint branch: a change that is NOT on head's ancestry.
        let disjoint_id = change_id(0x43);
        let disjoint = change_with_deltas(
            disjoint_id,
            vec![],
            vec![EntityDelta::Added(stray)],
            vec![],
            vec![],
        );
        graph.create_change(&root).unwrap();
        graph.create_change(&head).unwrap();
        graph.create_change(&disjoint).unwrap();

        let report = build_shadow_report(&graph, &request(disjoint_id, head_id)).unwrap();

        let gap = report
            .evidence_gaps
            .iter()
            .find(|gap| gap.kind == "base_not_on_head_ancestry")
            .expect("a base off the head ancestry must surface as an evidence gap");
        assert!(gap.detail.contains("not on the ancestry"));
        assert!(gap.detail.contains(&disjoint_id.to_string()));

        // The range walk is refused: no genesis-spanning diff, no changed
        // entities, no blast radius, and zero changes in range.
        assert!(report.changed_entities.is_empty());
        assert_eq!(report.blast_radius.total_affected, 0);
        assert_eq!(report.audit.changes_in_range, 0);

        // The specific range gap subsumes the generic empty-impact gap.
        assert!(!report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "impact_signal_absent"));

        // A range the gate never evaluated is never certified as a pass.
        assert_ne!(report.policy.verdict, ShadowGateVerdict::Pass);

        // The refusal is deterministic modulo the generation timestamp.
        let strip = |report: ShadowGateReport| {
            let mut value = serde_json::to_value(&report).unwrap();
            value["audit"]["generated_at"] = serde_json::json!(null);
            value
        };
        let second = build_shadow_report(&graph, &request(disjoint_id, head_id)).unwrap();
        assert_eq!(strip(report), strip(second));
    }

    #[test]
    fn merge_head_range_excludes_base_side_history() {
        let graph = InMemoryGraph::new();

        let stale = entity_with_span("stale_entity", "src/stale.rs", 3, EntityRole::Source);
        let mainline = entity_with_span("mainline_entity", "src/main.rs", 5, EntityRole::Source);
        let branch_v1 = entity_with_span("branch_entity", "src/branch.rs", 7, EntityRole::Source);
        let mut branch_v2 = branch_v1.clone();
        branch_v2.signature = "fn branch_entity(x: u8)".into();

        // G -> A (base, mainline); G -> B (branch); head merges [A, B]. The
        // store's backward walk from head reaches G through B because it
        // only stops at the literal base node, so an unscoped diff would
        // carry G's deltas — history the base already contains.
        let genesis_id = change_id(0x51);
        let base_id = change_id(0x52);
        let branch_id = change_id(0x53);
        let head_id = change_id(0x54);
        let genesis = change_with_deltas(
            genesis_id,
            vec![],
            vec![EntityDelta::Added(stale.clone())],
            vec![],
            vec![],
        );
        let base = change_with_deltas(
            base_id,
            vec![genesis_id],
            vec![EntityDelta::Added(mainline.clone())],
            vec![],
            vec![],
        );
        let branch = change_with_deltas(
            branch_id,
            vec![genesis_id],
            vec![EntityDelta::Added(branch_v1.clone())],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id, branch_id],
            vec![EntityDelta::Modified {
                old: branch_v1,
                new: branch_v2,
            }],
            vec![],
            vec![],
        );
        graph.create_change(&genesis).unwrap();
        graph.create_change(&base).unwrap();
        graph.create_change(&branch).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        // Only the merged-in side of the range is in scope: two changes
        // (branch + head), one changed entity.
        assert_eq!(report.audit.changes_in_range, 2);
        let changed_names: Vec<&str> = report
            .changed_entities
            .iter()
            .map(|entity| entity.name.as_str())
            .collect();
        assert!(changed_names.contains(&"branch_entity"));
        assert!(
            !changed_names.contains(&"stale_entity"),
            "history reachable from the base must not enter the range diff"
        );
        assert!(!changed_names.contains(&"mainline_entity"));

        // The scoped range stays deterministic modulo the timestamp.
        let strip = |report: ShadowGateReport| {
            let mut value = serde_json::to_value(&report).unwrap();
            value["audit"]["generated_at"] = serde_json::json!(null);
            value
        };
        let second = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        assert_eq!(strip(report), strip(second));
    }

    #[test]
    fn empty_range_fails_loud() {
        let graph = InMemoryGraph::new();
        let base_id = change_id(5);
        let base = change_with_deltas(base_id, vec![], vec![], vec![], vec![]);
        graph.create_change(&base).unwrap();

        let result = build_shadow_report(&graph, &request(base_id, base_id));
        assert!(
            result.is_err(),
            "empty base..head range must error, not report"
        );
    }

    #[test]
    fn report_json_is_deterministic_modulo_timestamp() {
        let (graph, base_id, head_id) = signature_change_graph();

        let strip = |report: ShadowGateReport| {
            let mut value = serde_json::to_value(&report).unwrap();
            value["audit"]["generated_at"] = serde_json::json!(null);
            value
        };

        let first = strip(build_shadow_report(&graph, &request(base_id, head_id)).unwrap());
        let second = strip(build_shadow_report(&graph, &request(base_id, head_id)).unwrap());
        assert_eq!(first, second, "shadow report must be deterministic");
    }

    #[test]
    fn human_rendering_carries_all_sections() {
        let (graph, base_id, head_id) = signature_change_graph();
        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let text = format_shadow_report(&report);
        assert!(text.contains("Shadow Merge Gate Report"));
        assert!(text.contains("report-only"));
        assert!(text.contains("WOULD BLOCK"));
        assert!(text.contains("Blast radius"));
        assert!(text.contains("Evidence gaps"));
        assert!(text.contains("Audit:"));
    }

    #[test]
    fn body_only_coverage_gap_only_does_not_gate() {
        use crate::diff::SemanticDiff;
        use crate::impact::ImpactReport;
        use crate::inline::{InlineComment, InlineCommentKind};
        use kin_model::review::{RiskLevel, RiskSummary};

        // A pure body-only modification (no signature/visibility change, no
        // blocking finding) whose ONLY warning-only evidence is a coverage
        // gap. The coverage-gap channel documents a missing test but must not
        // drive the verdict for a benign refactor: it stays in the report yet
        // does not feed the gate, so the verdict is a pass. This is the benign
        // case that must not regress when consumer_fanout begins to gate.
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![InlineComment {
                file: "src/hot.rs".to_string(),
                start_line: 10,
                end_line: 20,
                kind: InlineCommentKind::CoverageGap,
                message: "Modified entity `hot_path` has no test coverage".to_string(),
            }],
        };

        let mut changed = vec![ShadowChangedEntity {
            entity_id: EntityId::new().to_string(),
            name: "hot_path".to_string(),
            kind: "Function".to_string(),
            change: "modified".to_string(),
            file: Some("src/hot.rs".to_string()),
            start_line: Some(10),
            end_line: Some(20),
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        }];

        // Body-only: the coverage gap is reported but withheld from the gate —
        // the verdict is a pass.
        let policy = derive_policy(&review, &[], &changed);
        assert!(policy.findings.iter().any(|f| f.kind == "coverage_gap"));
        assert_eq!(policy.verdict, ShadowGateVerdict::Pass);
        assert_eq!(policy.attention_count, 0);

        // A real contract-surface change on the same entity restores the gate
        // weight of the coverage-gap channel.
        changed[0].signature_changed = true;
        let policy = derive_policy(&review, &[], &changed);
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);
        assert_eq!(policy.attention_count, 1);
    }

    #[test]
    fn body_only_consumer_fanout_gates_to_needs_attention() {
        use crate::diff::SemanticDiff;
        use crate::impact::ImpactReport;
        use crate::inline::{InlineComment, InlineCommentKind};
        use kin_model::review::{RiskLevel, RiskSummary};

        // A pure body-only modification (no signature/visibility change, no
        // blocking finding) that fires consumer_fanout — a graph-native wide
        // blast reaching many distinct non-test consumer entities. Unlike the
        // coverage-gap channel, this signal is NOT suppressed on a body-only
        // change: a behavior change with that reach is a genuine downstream
        // risk, so it feeds the gate and escalates the verdict to
        // needs_attention. This is the risky-revert case that previously
        // slipped through as a pass.
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![InlineComment {
                file: "src/hot.rs".to_string(),
                start_line: 10,
                end_line: 20,
                kind: InlineCommentKind::ConsumerFanout,
                message: "Behavior of `hot_path` changed with 3 distinct non-test consumer(s) \
                          across 3 file(s)"
                    .to_string(),
            }],
        };

        let changed = vec![ShadowChangedEntity {
            entity_id: EntityId::new().to_string(),
            name: "hot_path".to_string(),
            kind: "Function".to_string(),
            change: "modified".to_string(),
            file: Some("src/hot.rs".to_string()),
            start_line: Some(10),
            end_line: Some(20),
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        }];

        // Body-only, but the wide consumer fanout gates: the verdict escalates
        // to needs_attention, driven by the single fanout signal.
        let policy = derive_policy(&review, &[], &changed);
        assert!(policy.findings.iter().any(|f| f.kind == "consumer_fanout"));
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);
        assert_eq!(policy.attention_count, 1);

        // The two channels are independent: with the noisy coverage-gap channel
        // ALSO present on the same body-only change, only the fanout gates. The
        // coverage gap stays suppressed, so the attention count is driven by
        // the fanout alone (1, not 2) — this is the shape of the real risky
        // revert that carries both signals.
        let mut review_both = review.clone();
        review_both.inline_comments.push(InlineComment {
            file: "src/hot.rs".to_string(),
            start_line: 10,
            end_line: 20,
            kind: InlineCommentKind::CoverageGap,
            message: "Modified entity `hot_path` has no test coverage".to_string(),
        });
        let policy = derive_policy(&review_both, &[], &changed);
        assert!(policy.findings.iter().any(|f| f.kind == "consumer_fanout"));
        assert!(policy.findings.iter().any(|f| f.kind == "coverage_gap"));
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);
        assert_eq!(policy.attention_count, 1);
    }

    #[test]
    fn command_effect_contract_change_feeds_shadow_gate() {
        use crate::diff::SemanticDiff;
        use crate::impact::ImpactReport;
        use crate::inline::{InlineComment, InlineCommentKind};
        use kin_model::review::{RiskLevel, RiskSummary};

        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![InlineComment {
                file: "command/pr_checkout.go".to_string(),
                start_line: 14,
                end_line: 102,
                kind: InlineCommentKind::CommandEffectContract,
                message: "Command-effect contract for `prCheckout` changed; external command \
                          behavior needs review"
                    .to_string(),
            }],
        };

        let changed = vec![ShadowChangedEntity {
            entity_id: EntityId::new().to_string(),
            name: "prCheckout".to_string(),
            kind: "Function".to_string(),
            change: "modified".to_string(),
            file: Some("command/pr_checkout.go".to_string()),
            start_line: Some(14),
            end_line: Some(102),
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        }];

        let policy = derive_policy(&review, &[], &changed);
        assert!(policy
            .findings
            .iter()
            .any(|finding| finding.kind == "command_effect_contract_change"));
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);
        assert_eq!(policy.attention_count, 1);
    }

    #[test]
    fn unresolvable_removed_downstream_risk_is_attention_not_would_block() {
        use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
        use crate::impact::{EntityImpact, ImpactReport};
        use kin_model::review::{RiskLevel, RiskSummary};

        // A removed entity the graph can no longer resolve renders as a raw
        // UUID (kind "unknown"). We cannot certify a blocking breakage for a
        // surface we cannot even name, so its downstream risk is reported as
        // attention, not a would_block. The identical removal, resolvable to a
        // named entity, still blocks.
        let removed_id = EntityId::new();
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff {
                base: None,
                head: None,
                entity_changes: vec![EntityChange {
                    entity_id: removed_id,
                    kind: EntityChangeKind::Removed(removed_id),
                }],
                relation_changes: vec![],
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: removed_id,
                    consumer_count: 1,
                    strong_consumer_count: 1,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/consumer.rs".to_string()],
                    covering_tests: 0,
                }],
                ..Default::default()
            },
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        // Unresolvable removal (kind "unknown"): attention, not would_block.
        let unresolvable = vec![ShadowChangedEntity {
            entity_id: removed_id.to_string(),
            name: removed_id.to_string(),
            kind: "unknown".to_string(),
            change: "removed".to_string(),
            file: None,
            start_line: None,
            end_line: None,
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        }];
        let policy = derive_policy(&review, &[], &unresolvable);
        let finding = policy
            .findings
            .iter()
            .find(|f| f.kind == "downstream_risk")
            .expect("removal with a surviving consumer carries a downstream risk");
        assert!(
            !finding.blocking,
            "an unnameable removal cannot certify a block"
        );
        assert_eq!(finding.severity, "warning");
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);

        // The identical removal, resolvable to a named entity, still blocks.
        let resolvable = vec![ShadowChangedEntity {
            kind: "Function".to_string(),
            name: "legacy_helper".to_string(),
            ..unresolvable[0].clone()
        }];
        let policy = derive_policy(&review, &[], &resolvable);
        let finding = policy
            .findings
            .iter()
            .find(|f| f.kind == "downstream_risk")
            .expect("resolvable removal with a consumer carries a downstream risk");
        assert!(finding.blocking);
        assert_eq!(policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    #[test]
    fn inert_source_edit_with_captured_entities_reports_without_demoting() {
        // A source-class file (src/sensor.c) gets a comment/preprocessor-only
        // artifact change that alters no entity. The graph still has an entity
        // anchored in it at head, so the change is inert — reported as a
        // non-demoting entity_inert_change, not an unparsed-source gap — and
        // the verdict stays pass. (Contrast `source_class_artifact_gap_still_
        // demotes`, where the file has no captured entity at all.)
        let graph = InMemoryGraph::new();
        let sensor = entity_with_span("sensor", "src/sensor.c", 3, EntityRole::Source);
        let app = entity_with_span("app", "src/app.rs", 1, EntityRole::Source);
        graph.upsert_entity(&sensor).unwrap();
        graph.upsert_entity(&app).unwrap();

        let base_id = change_id(0x61);
        let head_id = change_id(0x62);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![
                EntityDelta::Added(sensor.clone()),
                EntityDelta::Added(app.clone()),
            ],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: app.clone(),
                new: app,
            }],
            vec![],
            vec![ArtifactDelta {
                file_id: FilePathId::new("src/sensor.c"),
                kind: ArtifactDeltaKind::Modified,
                old_hash: Some(Hash256::from_bytes([11; 32])),
                new_hash: Some(Hash256::from_bytes([12; 32])),
            }],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        assert!(
            report
                .evidence_gaps
                .iter()
                .any(|gap| gap.kind == "entity_inert_change" && gap.subject == "src/sensor.c"),
            "an inert edit of a captured source file is reported as a non-demoting gap"
        );
        assert!(
            !report
                .evidence_gaps
                .iter()
                .any(|gap| gap.kind == "artifact_only_change" && gap.subject == "src/sensor.c"),
            "the inert edit must not be flagged as an unparsed-source artifact gap"
        );
        assert_eq!(report.policy.verdict, ShadowGateVerdict::Pass);
    }

    #[test]
    fn absent_relation_channel_keeps_surface_change_feeding_gate() {
        // A real signature change in a repo whose relation channel was never
        // ingested: the empty channel cannot prove the change is isolated, so
        // it must still feed the gate → needs_attention, rather than being
        // silently suppressed into a pass on an unprovable zero inbound.
        let graph = InMemoryGraph::new();
        let widget_v1 = entity_with_span("widget", "src/widget.rs", 4, EntityRole::Source);
        let mut widget_v2 = widget_v1.clone();
        widget_v2.signature = "fn widget(scale: u8)".into();
        graph.upsert_entity(&widget_v2).unwrap();

        let base_id = change_id(0x71);
        let head_id = change_id(0x72);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![EntityDelta::Added(widget_v1.clone())],
            vec![],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: widget_v1,
                new: widget_v2,
            }],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        // The relation channel is entirely absent (no relations committed).
        assert!(report
            .evidence_gaps
            .iter()
            .any(|gap| gap.kind == "impact_signal_absent"));
        // The signature change is reported ...
        assert!(report
            .policy
            .findings
            .iter()
            .any(|finding| finding.kind == "signature_change"));
        // ... and, because isolation is unprovable, still feeds the gate.
        assert_eq!(report.policy.verdict, ShadowGateVerdict::NeedsAttention);
    }

    #[test]
    fn test_role_surface_change_does_not_feed_gate() {
        // A test method whose signature changed (e.g. a decorator/async edit)
        // is not a contract surface: nothing the review protects depends on it,
        // so it must not emit a downstream-risk finding or drive the verdict —
        // even with a live caller. The Source-role twin below still fires. This
        // is the c042 false positive: benign prod change + a test-method
        // signature edit escalated to needs_attention.
        for (role, expect_risk) in [(EntityRole::Test, false), (EntityRole::Source, true)] {
            let graph = InMemoryGraph::new();
            let target_v1 = entity_with_span("streaming_case", "tests/handlers.rs", 4, role);
            let mut target_v2 = target_v1.clone();
            target_v2.signature = "fn streaming_case(scale: u8)".into();
            let caller = entity_with_span("driver", "src/driver.rs", 6, EntityRole::Source);
            graph.upsert_entity(&target_v2).unwrap();
            graph.upsert_entity(&caller).unwrap();
            graph
                .upsert_relation(&relation(&caller, &target_v2, RelationKind::Calls))
                .unwrap();

            let base_id = change_id(0x73);
            let head_id = change_id(0x74);
            let base = change_with_deltas(
                base_id,
                vec![],
                vec![
                    EntityDelta::Added(target_v1.clone()),
                    EntityDelta::Added(caller.clone()),
                ],
                vec![],
                vec![],
            );
            let head = change_with_deltas(
                head_id,
                vec![base_id],
                vec![EntityDelta::Modified {
                    old: target_v1,
                    new: target_v2,
                }],
                vec![],
                vec![],
            );
            graph.create_change(&base).unwrap();
            graph.create_change(&head).unwrap();

            let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
            let has_surface_finding = report.policy.findings.iter().any(|finding| {
                finding.kind == "signature_change"
                    || finding.kind == "downstream_risk"
                    || finding.kind == "breaking"
            });
            assert_eq!(
                has_surface_finding,
                expect_risk,
                "role {:?} should {}emit a contract-surface finding",
                role,
                if expect_risk { "" } else { "not " }
            );
            let expected_verdict = if expect_risk {
                ShadowGateVerdict::NeedsAttention
            } else {
                ShadowGateVerdict::Pass
            };
            assert_eq!(
                report.policy.verdict, expected_verdict,
                "role {:?} verdict",
                role
            );
        }
    }

    // ── Toolchain-surface directive channel ─────────────────────────────

    fn empty_review() -> Review {
        use crate::diff::SemanticDiff;
        use crate::impact::ImpactReport;
        use kin_model::review::{RiskLevel, RiskSummary};
        Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        }
    }

    #[test]
    fn directive_added_blob_pair_fires() {
        // A source edit that only adds a lint-suppression directive alters no
        // entity, but it shifts what the toolchain enforces: the directive
        // delta must be detected.
        let old = b"fn compute() -> i32 {\n    let x = 1;\n    x\n}\n";
        let new = b"#[allow(dead_code)]\nfn compute() -> i32 {\n    let x = 1;\n    x\n}\n";
        let delta = directive_surface_delta(old, new).expect("added directive must be detected");
        assert_eq!(delta, (1, 0), "one directive added, none removed");
    }

    #[test]
    fn plain_comment_edit_is_silent() {
        // Editing an ordinary comment carrying no directive token is not a
        // toolchain-surface change.
        let old = b"// old note\nfn f() {}\n";
        let new = b"// a completely different note\nfn f() {}\n";
        assert!(
            directive_surface_delta(old, new).is_none(),
            "a plain comment edit carries no toolchain directive"
        );
    }

    #[test]
    fn relocated_directive_is_silent() {
        // The same directive line moved to a new position nets to zero against
        // the directive-line SET: no enforcement changed.
        let old = b"#[allow(unused)]\nfn a() {}\nfn b() {}\n";
        let new = b"fn a() {}\nfn b() {}\n#[allow(unused)]\n";
        assert!(
            directive_surface_delta(old, new).is_none(),
            "relocating an unchanged directive is not a surface change"
        );
    }

    #[test]
    fn one_sided_hash_is_silent() {
        // A delta missing either side's blob hash cannot be diffed; emit
        // nothing rather than guessing.
        use kin_blobs::BlobStore;
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(dir.path().to_path_buf()).unwrap();
        let present = blobs.write(b"#[allow(dead_code)]\nfn f() {}\n").unwrap();

        assert!(
            toolchain_surface_finding(&blobs, "src/foo.rs", None, Some(present)).is_none(),
            "missing old hash must stay silent"
        );
        assert!(
            toolchain_surface_finding(&blobs, "src/foo.rs", Some(present), None).is_none(),
            "missing new hash must stay silent"
        );
    }

    #[test]
    fn toolchain_finding_maps_like_command_effect_contract() {
        // Mirror the command-effect-contract mapping: a reported, non-blocking
        // warning finding — never an error, never blocking.
        assert_eq!(
            finding_kind_label(InlineCommentKind::ToolchainSurfaceChange),
            "toolchain_surface_change"
        );
        assert_eq!(
            finding_severity(InlineCommentKind::ToolchainSurfaceChange),
            "warning"
        );
        assert!(!is_blocking(InlineCommentKind::ToolchainSurfaceChange));

        // Same gate shape as the channel it mirrors.
        assert_eq!(
            finding_severity(InlineCommentKind::CommandEffectContract),
            finding_severity(InlineCommentKind::ToolchainSurfaceChange)
        );
        assert_eq!(
            is_blocking(InlineCommentKind::CommandEffectContract),
            is_blocking(InlineCommentKind::ToolchainSurfaceChange)
        );
    }

    #[test]
    fn toolchain_finding_feeds_gate_as_needs_attention() {
        // A toolchain-surface finding moves the verdict to needs_attention as
        // an ordinary non-blocking warning — through the finding channel, not
        // the evidence-gap demotion path (no gaps supplied here).
        let mut review = empty_review();
        review.inline_comments.push(InlineComment {
            file: "src/foo.rs".to_string(),
            start_line: 1,
            end_line: 1,
            kind: InlineCommentKind::ToolchainSurfaceChange,
            message: "Toolchain directives changed in src/foo.rs: 1 added, 0 removed; \
                      lint/deprecation enforcement shifted"
                .to_string(),
        });

        let policy = derive_policy(&review, &[], &[]);
        assert!(
            policy
                .findings
                .iter()
                .any(|finding| finding.kind == "toolchain_surface_change"
                    && finding.severity == "warning"
                    && !finding.blocking),
            "the toolchain finding is reported as a non-blocking warning"
        );
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);
    }

    #[test]
    fn inert_directive_edit_emits_toolchain_finding_through_collect() {
        // End-to-end through collect_evidence_gaps: an inert edit of a captured
        // source file whose directive lines changed yields a toolchain finding
        // when a blob reader is present, and stays silent without one — while
        // the inert edit itself is still reported as a non-demoting gap either
        // way.
        use kin_blobs::BlobStore;
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(dir.path().to_path_buf()).unwrap();
        let old_hash = blobs.write(b"fn sensor() {}\n").unwrap();
        let new_hash = blobs
            .write(b"// Deprecated: use sensor_v2\nfn sensor() {}\n")
            .unwrap();

        // Graph with an entity anchored in src/sensor.c at head, so the
        // artifact edit classifies as an inert source edit (entity captured,
        // none altered).
        let graph = InMemoryGraph::new();
        let sensor = entity_with_span("sensor", "src/sensor.c", 2, EntityRole::Source);
        let base_id = change_id(0x91);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![EntityDelta::Added(sensor.clone())],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        let at_head = GraphAtRef::materialize(&graph, &base_id).unwrap();

        let changes = vec![change_with_deltas(
            change_id(0x92),
            vec![base_id],
            vec![],
            vec![],
            vec![ArtifactDelta {
                file_id: FilePathId::new("src/sensor.c"),
                kind: ArtifactDeltaKind::Modified,
                old_hash: Some(old_hash),
                new_hash: Some(new_hash),
            }],
        )];

        let review = empty_review();

        let (gaps, findings) =
            collect_evidence_gaps(&review, &changes, &[], Some(&at_head), Some(&blobs));
        assert!(
            gaps.iter()
                .any(|gap| gap.kind == "entity_inert_change" && gap.subject == "src/sensor.c"),
            "the inert edit is still reported as a non-demoting gap"
        );
        assert!(
            findings.iter().any(|finding| finding.kind
                == InlineCommentKind::ToolchainSurfaceChange
                && finding.file == "src/sensor.c"),
            "the directive change surfaces as a toolchain finding"
        );

        // No blob reader → the branch cannot inspect directives, so it stays
        // silent even though the inert-edit gap is unchanged.
        let (gaps_no_blob, findings_no_blob) =
            collect_evidence_gaps(&review, &changes, &[], Some(&at_head), None);
        assert!(gaps_no_blob
            .iter()
            .any(|gap| gap.kind == "entity_inert_change" && gap.subject == "src/sensor.c"));
        assert!(
            findings_no_blob.is_empty(),
            "without a blob reader the toolchain channel emits nothing"
        );
    }

    /// Chain of `n` changes: c1 applies `first_deltas`, c2 applies
    /// `second_deltas`, the rest are empty padding so the revert-history window
    /// sees enough depth to scan without reporting the shallow-history gap.
    fn padded_history_graph(
        graph: &InMemoryGraph,
        first_deltas: Vec<EntityDelta>,
        second_deltas: Vec<EntityDelta>,
        n: u8,
    ) -> SemanticChangeId {
        let mut prev: Option<SemanticChangeId> = None;
        for i in 1..=n {
            let deltas = match i {
                1 => first_deltas.clone(),
                2 => second_deltas.clone(),
                _ => vec![],
            };
            let change = change_with_deltas(
                change_id(i),
                prev.map(|p| vec![p]).unwrap_or_default(),
                deltas,
                vec![],
                vec![],
            );
            graph.create_change(&change).unwrap();
            prev = Some(change_id(i));
        }
        prev.expect("chain is non-empty")
    }

    #[test]
    fn revert_history_reintroduction_flags_needs_attention() {
        // c1 adds `retry_budget`, c2 removes it, padding to depth 30, then the
        // head re-adds an entity with the SAME behavior fingerprint at a new
        // location. The channel must call out the revert-shaped reintroduction
        // and move the verdict to needs_attention.
        let graph = InMemoryGraph::new();
        let mut original = entity_with_span("retry_budget", "src/net.rs", 40, EntityRole::Source);
        original.fingerprint.behavior_hash = Hash256::from_bytes([7; 32]);
        let mut readded = original.clone();
        readded.id = EntityId::from_content("src/net.rs", "retry_budget", "Function", 77);
        let base_id = padded_history_graph(
            &graph,
            vec![EntityDelta::Added(original.clone())],
            vec![EntityDelta::Removed(original.id)],
            30,
        );
        graph.upsert_entity(&readded).unwrap();
        let head_id = change_id(200);
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Added(readded.clone())],
            vec![],
            vec![],
        );
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        let finding = report
            .policy
            .findings
            .iter()
            .find(|f| f.kind == "revert_history")
            .expect("reintroduction must produce a revert_history finding");
        assert!(
            finding.message.contains("restores the exact content"),
            "fingerprint match must report the strong form, got: {}",
            finding.message
        );
        assert_eq!(report.policy.verdict, ShadowGateVerdict::NeedsAttention);
        assert!(
            !report
                .evidence_gaps
                .iter()
                .any(|g| g.kind == "revert_history_shallow"),
            "30 changes of history must not report the shallow gap"
        );
    }

    #[test]
    fn revert_history_recent_addition_removal_flags() {
        // c2 adds `beta_flag`; the head removes that exact entity id. Deleting
        // something that only just landed is revert-shaped and must be called
        // out even though a bare removal of an unconsumed entity would
        // otherwise stay quiet.
        let graph = InMemoryGraph::new();
        let recent = entity_with_span("beta_flag", "src/flags.rs", 12, EntityRole::Source);
        let base_id =
            padded_history_graph(&graph, vec![], vec![EntityDelta::Added(recent.clone())], 30);
        let head_id = change_id(201);
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Removed(recent.id)],
            vec![],
            vec![],
        );
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        let finding = report
            .policy
            .findings
            .iter()
            .find(|f| f.kind == "revert_history")
            .expect("recent-addition removal must produce a revert_history finding");
        assert!(
            finding.message.contains("revert-shaped removal"),
            "got: {}",
            finding.message
        );
    }

    #[test]
    fn fresh_addition_produces_no_revert_history_finding() {
        // History contains an unrelated removal; the head adds a brand-new
        // entity. No temporal match exists, so the channel must stay silent —
        // fresh additions are the benign default this channel must never tax.
        let graph = InMemoryGraph::new();
        let mut unrelated = entity_with_span("old_helper", "src/util.rs", 9, EntityRole::Source);
        unrelated.fingerprint.behavior_hash = Hash256::from_bytes([9; 32]);
        let fresh = entity_with_span("brand_new_api", "src/api.rs", 21, EntityRole::Source);
        let base_id = padded_history_graph(
            &graph,
            vec![EntityDelta::Added(unrelated.clone())],
            vec![EntityDelta::Removed(unrelated.id)],
            30,
        );
        graph.upsert_entity(&fresh).unwrap();
        let head_id = change_id(202);
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Added(fresh)],
            vec![],
            vec![],
        );
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        assert!(
            !report
                .policy
                .findings
                .iter()
                .any(|f| f.kind == "revert_history"),
            "a fresh addition must not read as revert-shaped"
        );
    }

    #[test]
    fn shallow_history_reports_honest_gap() {
        // Two changes of history is not enough to assess revert evidence: the
        // channel must say so through an evidence gap instead of certifying
        // silence, and must not invent findings.
        let graph = InMemoryGraph::new();
        let fresh = entity_with_span("early_api", "src/api.rs", 5, EntityRole::Source);
        let base_id = padded_history_graph(&graph, vec![], vec![], 2);
        graph.upsert_entity(&fresh).unwrap();
        let head_id = change_id(203);
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Added(fresh)],
            vec![],
            vec![],
        );
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        assert!(
            report
                .evidence_gaps
                .iter()
                .any(|g| g.kind == "revert_history_shallow"),
            "shallow history must surface the honesty gap"
        );
        assert!(
            !report
                .policy
                .findings
                .iter()
                .any(|f| f.kind == "revert_history"),
            "no finding may be invented from unscannable history"
        );
    }

    #[test]
    fn revert_of_the_base_change_itself_flags() {
        // The most common revert shape: the head reverts exactly the change at
        // the base — the removal lives in the base change's own deltas, which
        // are part of the state the head builds on and must be scanned.
        let graph = InMemoryGraph::new();
        let mut original = entity_with_span("retry_budget", "src/net.rs", 40, EntityRole::Source);
        original.fingerprint.behavior_hash = Hash256::from_bytes([5; 32]);
        let mut readded = original.clone();
        readded.id = EntityId::from_content("src/net2.rs", "retry_budget", "Function", 8);
        // 29 pads, then the base change REMOVES the entity, then head re-adds.
        let pad_tail = padded_history_graph(
            &graph,
            vec![EntityDelta::Added(original.clone())],
            vec![],
            29,
        );
        let base_id = change_id(150);
        let base = change_with_deltas(
            base_id,
            vec![pad_tail],
            vec![EntityDelta::Removed(original.id)],
            vec![],
            vec![],
        );
        graph.create_change(&base).unwrap();
        graph.upsert_entity(&readded).unwrap();
        let head_id = change_id(151);
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Added(readded)],
            vec![],
            vec![],
        );
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        let finding = report
            .policy
            .findings
            .iter()
            .find(|f| f.kind == "revert_history")
            .expect("a revert of the base change itself must flag");
        assert!(
            finding.message.contains("in the base change itself"),
            "distance-0 phrasing expected, got: {}",
            finding.message
        );
    }
}
