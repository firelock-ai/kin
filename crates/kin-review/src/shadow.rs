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

use kin_model::entity::Entity;
use kin_model::graph::GraphStore;
use kin_model::ids::SemanticChangeId;
use kin_model::timestamp::Timestamp;
use serde::{Deserialize, Serialize};

use crate::diff::EntityChangeKind;
use crate::gate::{derive_decision, GateStatus, ReviewFinding, ReviewSignalKind};
use crate::inline::InlineCommentKind;
use crate::review::{Review, SemanticReview};
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
}

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
    /// "artifact_only_change" | "missing_span" | "actor_attribution_unavailable"
    /// | "impact_signal_absent" | "cross_repo_not_evaluated"
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
pub fn build_shadow_report<G: GraphStore>(
    store: &G,
    request: &ShadowRequest,
) -> Result<ShadowGateReport, ReviewError> {
    let review =
        SemanticReview::create_review(&request.resolved_base, &request.resolved_head, store)?;

    let changes = store
        .get_changes_since(&request.resolved_base, &request.resolved_head)
        .map_err(ReviewError::graph)?;

    let changed_entities = collect_changed_entities(store, &review)?;
    let blast_radius = collect_blast_radius(&review);
    let evidence_gaps = collect_evidence_gaps(&review, &changes, &changed_entities);
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
                    signature_changed: old.signature != new.signature,
                    visibility_changed: old.visibility != new.visibility,
                });
            }
            EntityChangeKind::Removed(id) => {
                // The diff carries only the removed entity's id; the graph
                // still knows what the id named. Resolve so findings and the
                // entity list read as code, not opaque ids. When the graph
                // has genuinely forgotten the entity, fall back to the id
                // string rather than inventing a name.
                let removed = store.get_entity(id).map_err(ReviewError::graph)?;
                let (name, kind, file) = match removed {
                    Some(entity) => {
                        let (file, _, _) = entity_location(&entity);
                        (entity.name.clone(), format!("{:?}", entity.kind), file)
                    }
                    None => (id.to_string(), "unknown".to_string(), None),
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
        InlineCommentKind::SignatureChange => "signature_change",
        InlineCommentKind::VisibilityChange => "visibility_change",
        InlineCommentKind::ConsumerFanout => "consumer_fanout",
        InlineCommentKind::Added => "entity_added",
        InlineCommentKind::Removed => "entity_removed",
        InlineCommentKind::Renamed => "entity_renamed",
        InlineCommentKind::AgentUnreviewed => "agent_unreviewed",
    }
}

fn finding_severity(kind: InlineCommentKind) -> &'static str {
    match kind {
        InlineCommentKind::Breaking | InlineCommentKind::ContractViolation => "error",
        InlineCommentKind::CoverageGap
        | InlineCommentKind::SignatureChange
        | InlineCommentKind::VisibilityChange
        | InlineCommentKind::ConsumerFanout
        | InlineCommentKind::Renamed
        | InlineCommentKind::AgentUnreviewed => "warning",
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
        "missing_span" => true,
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
            let (name, location, surface_changed) = match &change.kind {
                EntityChangeKind::Modified { old, new } => (
                    new.name.clone(),
                    new.span
                        .as_ref()
                        .map(|span| (span.file.to_string(), span.start_line)),
                    old.signature != new.signature || old.visibility != new.visibility,
                ),
                EntityChangeKind::Removed(id) => {
                    let id_string = id.to_string();
                    let name = resolved_names
                        .get(id_string.as_str())
                        .map(|name| name.to_string())
                        .unwrap_or(id_string);
                    // Same-diff remove + re-add of the same entity name is a
                    // move; the surviving entity carries any surface risk.
                    if added_names.contains(name.as_str()) {
                        continue;
                    }
                    (name, None, true)
                }
                EntityChangeKind::Added(_) => continue,
            };
            if !surface_changed {
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
            findings.push(ShadowPolicyFinding {
                kind: "downstream_risk".to_string(),
                severity: "error".to_string(),
                blocking: true,
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
    let surface_finding_feeds_gate = |finding: &ShadowPolicyFinding| -> bool {
        if finding.kind != "signature_change" && finding.kind != "visibility_change" {
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

    // Informational findings (entity added/removed) describe the diff, not a
    // gate signal; they are reported but do not feed the verdict. Surface
    // findings on graph-isolated entities are likewise reported without
    // feeding the gate.
    let gate_findings: Vec<ReviewFinding> = findings
        .iter()
        .filter(|finding| finding.severity != "info")
        .filter(|finding| surface_finding_feeds_gate(finding))
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

fn collect_evidence_gaps(
    review: &Review,
    changes: &[kin_model::change::SemanticChange],
    changed_entities: &[ShadowChangedEntity],
) -> Vec<ShadowEvidenceGap> {
    let mut gaps = Vec::new();

    // Files whose changes were recorded only as raw artifacts: the graph has
    // no entities for them, so they are invisible to blast radius and policy.
    let entity_files: BTreeSet<String> = changed_entities
        .iter()
        .filter_map(|entity| entity.file.clone())
        .collect();
    let mut artifact_only: BTreeSet<String> = BTreeSet::new();
    for change in changes {
        for delta in &change.artifact_deltas {
            let file = delta.file_id.to_string();
            if !entity_files.contains(&file) {
                artifact_only.insert(file);
            }
        }
    }
    for file in artifact_only {
        gaps.push(ShadowEvidenceGap {
            kind: "artifact_only_change".to_string(),
            subject: file,
            detail: "file changed but no semantic entities were captured for it (unsupported \
                     language or unparsed artifact); its impact is NOT included in the blast \
                     radius or policy result"
                .to_string(),
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

    gaps
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
    use kin_model::change::{ArtifactDelta, ArtifactDeltaKind, EntityDelta, SemanticChange};
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
        artifact_deltas: Vec<ArtifactDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test-author"),
            message: "test change".into(),
            entity_deltas,
            relation_deltas: vec![],
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
    /// `target` via graph relations.
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

        graph.upsert_entity(&target_v2).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&test).unwrap();
        graph
            .upsert_relation(&relation(&caller, &target_v2, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&relation(&test, &target_v2, RelationKind::Tests))
            .unwrap();

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
        assert_eq!(report.policy.verdict, ShadowGateVerdict::WouldBlock);
        assert!(report.policy.blocking_count >= 1);
        assert!(report
            .policy
            .findings
            .iter()
            .any(|finding| finding.blocking && finding.kind == "downstream_risk"));

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
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: entity.clone(),
                new: entity,
            }],
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
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Modified {
                old: entity.clone(),
                new: entity,
            }],
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
        graph.upsert_entity(&legacy).unwrap();
        graph.upsert_entity(&consumer).unwrap();
        graph
            .upsert_relation(&relation(&consumer, &legacy, RelationKind::Calls))
            .unwrap();

        let base_id = change_id(8);
        let head_id = change_id(9);
        let base = change_with_deltas(
            base_id,
            vec![],
            vec![
                EntityDelta::Added(legacy.clone()),
                EntityDelta::Added(consumer.clone()),
            ],
            vec![],
        );
        let head = change_with_deltas(
            head_id,
            vec![base_id],
            vec![EntityDelta::Removed(legacy.id)],
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

        // Removal with a live graph-known consumer is a blocking downstream
        // risk, and the finding names the entity, not its uuid.
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
    fn empty_range_fails_loud() {
        let graph = InMemoryGraph::new();
        let base_id = change_id(5);
        let base = change_with_deltas(base_id, vec![], vec![], vec![]);
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
}
