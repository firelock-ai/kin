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
use kin_model::change::{LocatedEntry, ResolvedTree, TreeEntry};
use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, GitObjectId, RepoPath, SemanticChangeId};
use kin_model::timestamp::Timestamp;
use kin_model::ArtifactId;
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
pub const SHADOW_GATE_REPORT_SCHEMA_VERSION: u32 = 2;

/// Enforcement label carried by every shadow report.
pub const SHADOW_ENFORCEMENT_REPORT_ONLY: &str = "report_only";

/// In-range committed-change count above which an empty blast radius is
/// attributed to a deep-history substrate-fidelity ceiling rather than treated
/// as proven isolation.
///
/// A review whose base..head range spans this many committed changes reaches
/// far enough back that the persisted graph substrate it reads at the head ref
/// — replayed faithfully, but built long ago — drifts further from what a live
/// re-index would produce than a nearby range does: the deeper the
/// range, the more the persisted relation closure and entity roles diverge.
/// When such a range ALSO
/// yields an empty blast radius, that emptiness is more plausibly a ceiling of
/// the historical substrate than evidence the change is genuinely isolated, so
/// the report attributes it explicitly (a non-demoting `deep_history_impact_ceiling`
/// gap) instead of leaving it folded into the generic `impact_signal_absent`.
///
/// This threshold is a RANGE-DEPTH PROXY, not a measurement of reconstruction:
/// it gates only whether the attribution gap is emitted. The raw in-range
/// change count is always stamped on the report (`range_depth.in_range_changes`)
/// so downstream scoring can apply its own policy to the exact number.
pub const DEEP_HISTORY_IMPACT_CEILING_THRESHOLD: usize = 1000;

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

/// Range-level operation for one identity-bearing repository artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowArtifactOperation {
    Added,
    Updated,
    Removed,
}

/// Independently reviewable aspect of an exact repository-tree transition.
///
/// A transition may carry more than one aspect: a stable artifact can move,
/// change blob content, and become executable in the same update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowArtifactAspect {
    Added,
    Removed,
    Renamed,
    BlobContentChanged,
    ExecutableModeChanged,
    SymlinkTargetChanged,
    GitlinkTargetChanged,
    EntryTypeChanged,
}

/// Exact net base-to-head transition for one stable artifact identity.
///
/// Paths remain byte-exact [`RepoPath`] values inside [`LocatedEntry`].
/// Presentation happens only at the report formatter boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowArtifactChange {
    pub artifact_id: ArtifactId,
    pub operation: ShadowArtifactOperation,
    pub old: Option<LocatedEntry>,
    pub new: Option<LocatedEntry>,
    pub aspects: Vec<ShadowArtifactAspect>,
}

/// One committed tree delta in the reviewed range.
///
/// This is provenance, not the net diff. It deliberately preserves
/// intermediate activity (including add-then-remove or edit-then-revert)
/// that disappears when the exact base and head trees converge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowArtifactActivity {
    /// Canonical lowercase-hex semantic change ID.
    pub change_id: String,
    pub transition: ShadowArtifactChange,
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

/// Cross-repo federation section. v2 reports single-repo blast radius only
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
    /// | "artifact_structure_change" | "artifact_path_unrepresentable"
    /// | "artifact_range_only_activity"
    /// | "actor_attribution_unavailable" | "impact_signal_absent"
    /// | "deep_history_impact_ceiling" | "cross_repo_not_evaluated"
    /// | "ref_state_unavailable" | "base_not_on_head_ancestry"
    /// | "revert_history_shallow" | "revert_history_incomplete_ancestry"
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

/// Provenance for how deep the reviewed `base..head` range reaches, stamped on
/// every report so downstream scoring can attribute an accepted historical-
/// substrate ceiling instead of scoring a deep-history row as clean.
///
/// The raw count is ALWAYS present and independent of any threshold; the
/// threshold gates only the non-demoting `deep_history_impact_ceiling` evidence
/// gap, never this data. A scorer may read `in_range_changes` and apply its own
/// policy, or trust `is_deep_history` for the report's own default policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShadowRangeDepth {
    /// Count of committed semantic changes in the reviewed `base..head` range
    /// (the same range the audit records as `changes_in_range`).
    pub in_range_changes: usize,
    /// The documented threshold this report used to decide `is_deep_history`.
    pub deep_history_threshold: usize,
    /// `in_range_changes > deep_history_threshold`. When this is true AND the
    /// blast radius is empty, the report carries a non-demoting
    /// `deep_history_impact_ceiling` gap attributing the empty impact to a
    /// range-depth proxy for historical-substrate fidelity rather than to
    /// proven isolation.
    pub is_deep_history: bool,
}

/// The complete shadow-mode merge-gate report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowGateReport {
    pub schema_version: u32,
    /// Always "shadow".
    pub mode: String,
    pub input: ShadowInputEcho,
    pub changed_entities: Vec<ShadowChangedEntity>,
    /// Exact net artifact diff derived from resolved base and head trees.
    pub changed_artifacts: Vec<ShadowArtifactChange>,
    /// Exact committed artifact deltas in the reviewed range.
    pub artifact_activity: Vec<ShadowArtifactActivity>,
    pub blast_radius: ShadowBlastRadius,
    pub policy: ShadowPolicyResult,
    pub repair_context: Vec<ShadowRepairItem>,
    pub evidence_gaps: Vec<ShadowEvidenceGap>,
    pub audit: ShadowAuditEvidence,
    /// Range-depth provenance (see [`ShadowRangeDepth`]). Additive and
    /// `serde(default)` so a report serialized before this field existed still
    /// deserializes.
    #[serde(default)]
    pub range_depth: ShadowRangeDepth,
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
        return build_shadow_report_base_off_ancestry(store, request);
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
/// `external_consumer_count` understates (often to zero) the surviving non-test
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
            EntityChangeKind::Removed { .. } => Some(change.entity_id),
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
///
/// Unlike [`build_shadow_report`], this entry point never materializes graph
/// state at either ref, so it is safe to call with a `resolved_base` and
/// `resolved_head` that are not present in `store` at all. Callers that can
/// prove ancestry does not hold through a cheaper channel than full
/// resolution (e.g. a Git-native ancestry check ahead of importing either
/// side) can go straight to this report instead of paying for resolution
/// first only to reach the same conclusion.
pub fn build_shadow_report_base_off_ancestry<G: GraphStore>(
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

fn artifact_transition(
    artifact_id: ArtifactId,
    old: Option<LocatedEntry>,
    new: Option<LocatedEntry>,
) -> Option<ShadowArtifactChange> {
    let operation = match (&old, &new) {
        (None, Some(_)) => ShadowArtifactOperation::Added,
        (Some(_), Some(_)) => ShadowArtifactOperation::Updated,
        (Some(_), None) => ShadowArtifactOperation::Removed,
        (None, None) => return None,
    };
    let aspects = match (&old, &new) {
        (None, Some(_)) => vec![ShadowArtifactAspect::Added],
        (Some(_), None) => vec![ShadowArtifactAspect::Removed],
        (Some(old), Some(new)) => {
            let mut aspects = Vec::new();
            if old.path != new.path {
                aspects.push(ShadowArtifactAspect::Renamed);
            }
            match (old.entry, new.entry) {
                (
                    TreeEntry::Blob {
                        hash: old_hash,
                        executable: old_executable,
                    },
                    TreeEntry::Blob {
                        hash: new_hash,
                        executable: new_executable,
                    },
                ) => {
                    if old_hash != new_hash {
                        aspects.push(ShadowArtifactAspect::BlobContentChanged);
                    }
                    if old_executable != new_executable {
                        aspects.push(ShadowArtifactAspect::ExecutableModeChanged);
                    }
                }
                (
                    TreeEntry::Symlink {
                        target_blob: old_target,
                    },
                    TreeEntry::Symlink {
                        target_blob: new_target,
                    },
                ) => {
                    if old_target != new_target {
                        aspects.push(ShadowArtifactAspect::SymlinkTargetChanged);
                    }
                }
                (
                    TreeEntry::Gitlink { target: old_target },
                    TreeEntry::Gitlink { target: new_target },
                ) => {
                    if old_target != new_target {
                        aspects.push(ShadowArtifactAspect::GitlinkTargetChanged);
                    }
                }
                _ => aspects.push(ShadowArtifactAspect::EntryTypeChanged),
            }
            aspects
        }
        (None, None) => unreachable!("operation excludes an empty transition"),
    };

    Some(ShadowArtifactChange {
        artifact_id,
        operation,
        old,
        new,
        aspects,
    })
}

/// Compare exact resolved base and head trees by stable identity.
///
/// Path equality never participates in identity and path reuse by a new
/// artifact therefore remains an explicit remove-plus-add.
fn collect_changed_artifacts(
    base: &ResolvedTree,
    head: &ResolvedTree,
) -> Vec<ShadowArtifactChange> {
    let artifact_ids: BTreeSet<ArtifactId> = base
        .artifacts()
        .map(|artifact| artifact.artifact_id)
        .chain(head.artifacts().map(|artifact| artifact.artifact_id))
        .collect();

    artifact_ids
        .into_iter()
        .filter_map(|artifact_id| {
            let old = base
                .get(&artifact_id)
                .map(|artifact| artifact.located_entry());
            let new = head
                .get(&artifact_id)
                .map(|artifact| artifact.located_entry());
            if old == new {
                return None;
            }
            artifact_transition(artifact_id, old, new)
        })
        .collect()
}

/// Preserve every exact tree delta declared by an in-range semantic change.
///
/// This channel is intentionally separate from [`collect_changed_artifacts`]:
/// branch activity and reverted/intermediate transitions are provenance, not
/// the authoritative net base-to-head tree.
fn collect_artifact_activity(
    changes: &[kin_model::change::SemanticChange],
) -> Vec<ShadowArtifactActivity> {
    let mut activity = Vec::new();
    for change in changes {
        for delta in &change.tree_deltas {
            let transition = artifact_transition(
                delta.artifact_id(),
                delta.old_state().cloned(),
                delta.new_state().cloned(),
            )
            .expect("a tree delta always has an old or new state");
            activity.push(ShadowArtifactActivity {
                change_id: change.id.to_string(),
                transition,
            });
        }
    }
    activity.sort_by(|left, right| {
        left.change_id.cmp(&right.change_id).then_with(|| {
            left.transition
                .artifact_id
                .cmp(&right.transition.artifact_id)
        })
    });
    activity
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
    let changed_artifacts = if at_base.is_some() && at_head.is_some() {
        let base_tree = store
            .resolve_tree_at(&request.resolved_base)
            .map_err(ReviewError::graph)?;
        let head_tree = store
            .resolve_tree_at(&request.resolved_head)
            .map_err(ReviewError::graph)?;
        collect_changed_artifacts(&base_tree, &head_tree)
    } else {
        Vec::new()
    };
    let artifact_activity = collect_artifact_activity(changes);
    let blast_radius = collect_blast_radius(&review);
    // No blob reader is reachable here: the shadow entry points take only the
    // graph store, and threading a real reader would change their public
    // signature and their out-of-crate callers. The toolchain-surface channel
    // is therefore inert on this path (blobs = None) until that wiring lands.
    let (mut evidence_gaps, toolchain_findings) = collect_evidence_gaps(
        &review,
        changes,
        &changed_entities,
        &changed_artifacts,
        &artifact_activity,
        at_head,
        None,
    );
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
    // Revert-history findings use the same inline-comment channel, with honest
    // gaps when the base has too little history to scan or when the graph could
    // not resolve part of the ancestry the DAG declares. Strong matches may gate
    // as warnings; weak temporal hints stay informational. Evidence is available
    // at review time only: the window looks strictly BEFORE the base.
    let (revert_findings, revert_gaps) = crate::revert_history::collect_revert_history_findings(
        store,
        &request.resolved_base,
        changes,
    )?;
    review.inline_comments.extend(revert_findings);
    evidence_gaps.extend(revert_gaps);
    let policy = derive_policy(&review, &evidence_gaps, &changed_entities);
    let repair_context = collect_repair_context(&policy.findings, &review);
    let audit = collect_audit_evidence(store, request, &review, changes.len())?;

    // Range-depth provenance is stamped on every report from the same in-range
    // change count the audit records. Always present and threshold-independent;
    // the threshold decides only `is_deep_history` (and thus whether the
    // non-demoting `deep_history_impact_ceiling` gap fires in
    // `collect_evidence_gaps`), never whether the raw count is reported.
    let range_depth = ShadowRangeDepth {
        in_range_changes: changes.len(),
        deep_history_threshold: DEEP_HISTORY_IMPACT_CEILING_THRESHOLD,
        is_deep_history: changes.len() > DEEP_HISTORY_IMPACT_CEILING_THRESHOLD,
    };

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
        changed_artifacts,
        artifact_activity,
        blast_radius,
        policy,
        repair_context,
        evidence_gaps,
        audit,
        range_depth,
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
                        && !crate::inline::signature_runtime_neutral(
                            &old.signature,
                            &new.signature,
                        ),
                    visibility_changed: old.visibility != new.visibility,
                    role: new.role,
                });
            }
            EntityChangeKind::Removed { old } => {
                let id = &change.entity_id;
                // The diff now carries the removed entity's base-side record, so
                // prefer it. The base ref and then the live store remain as
                // fallbacks for a diff built before the payload existed, or for
                // a removal whose record was genuinely unrecoverable, and the
                // breaking-removal rule keeps demotion only for a surface none
                // of the three can name.
                let removed = match old {
                    Some(entity) => Some(entity.clone()),
                    None => match at_base {
                        Some(base) => base.get_entity(id)?,
                        None => None,
                    },
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
            detail: "cross-repo federation is not evaluated by shadow report v2; blast radius \
                     covers this repository only"
                .to_string(),
            nodes: Vec::new(),
        },
    }
}

fn finding_kind_label(kind: InlineCommentKind) -> &'static str {
    match kind {
        InlineCommentKind::Breaking => "breaking",
        InlineCommentKind::BreakingMigrated => "breaking_migrated",
        InlineCommentKind::CoverageGap => "coverage_gap",
        InlineCommentKind::ContractViolation => "contract_violation",
        InlineCommentKind::CommandEffectContract => "command_effect_contract_change",
        InlineCommentKind::SignatureChange => "signature_change",
        InlineCommentKind::VisibilityChange => "visibility_change",
        InlineCommentKind::ConsumerFanout => "consumer_fanout",
        InlineCommentKind::ConsumerFanoutEquivalent => "consumer_fanout_equivalent",
        InlineCommentKind::Added => "entity_added",
        InlineCommentKind::Removed => "entity_removed",
        InlineCommentKind::Renamed => "entity_renamed",
        InlineCommentKind::AgentUnreviewed => "agent_unreviewed",
        InlineCommentKind::ToolchainSurfaceChange => "toolchain_surface_change",
        InlineCommentKind::RevertHistory => "revert_history",
        InlineCommentKind::RevertHistoryIncidental => "revert_history_incidental",
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
        InlineCommentKind::RevertHistoryIncidental => "info",
        InlineCommentKind::Added | InlineCommentKind::Removed => "info",
        // Coherent-migration evidence: reported, but never a gate signal — the
        // break has no stranded external consumer to escalate on.
        InlineCommentKind::BreakingMigrated => "info",
        // Behavior-preserving wide fanout: the body change is provably
        // equivalent (docstring / comment / formatting), so the fanout is
        // reported as evidence but never feeds the gate.
        InlineCommentKind::ConsumerFanoutEquivalent => "info",
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
/// - `artifact_structure_change`: a stable artifact was added, removed,
///   moved, had its executable mode changed, changed entry type, or changed a
///   symlink/gitlink target. Entity deltas do not encode those repository-tree
///   facts, so entity review cannot prove the effect of the exact transition.
/// - `artifact_path_unrepresentable`: an exact repository path is not UTF-8,
///   so the string-based entity/source classifier cannot prove its coverage.
/// - `artifact_range_only_activity`: committed tree activity converged back
///   to the base state and is absent from the net diff. It remains history and
///   cannot be certified as no activity.
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
/// - `deep_history_impact_ceiling` is reported but never demotes: it is a
///   range-depth PROXY attributing an empty blast radius on a deep range to a
///   historical-substrate ceiling. Absence of evidence is not
///   evidence of risk, so it makes the ceiling attributable without changing
///   the verdict.
/// - Structural report limits (cross-repo not evaluated, attribution
///   unavailable) are constant framing, reported but never demoting.
fn gap_blocks_pass(gap: &ShadowEvidenceGap) -> bool {
    match gap.kind.as_str() {
        "missing_span"
        | "ref_state_unavailable"
        | "base_not_on_head_ancestry"
        | "artifact_structure_change"
        | "artifact_path_unrepresentable"
        | "artifact_range_only_activity" => true,
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

/// Derive the shadow gate policy from an already-assembled [`Review`].
///
/// The production path materializes ref-state to build the `Review`,
/// `evidence_gaps`, and `changed_entities` before running the internal policy
/// step. Callers and tests that already hold a `Review` (diff + impact + inline
/// comments) — a review-only re-evaluation over an existing prepared graph, or
/// an end-to-end gate assertion — derive the same verdict here without
/// re-materializing ref-state. Mirrors the crate-public [`crate::derive_decision`].
pub fn derive_shadow_policy(
    review: &Review,
    evidence_gaps: &[ShadowEvidenceGap],
    changed_entities: &[ShadowChangedEntity],
) -> ShadowPolicyResult {
    derive_policy(review, evidence_gaps, changed_entities)
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
            let (name, location, surface_changed, demote_removal, rename_neutral) =
                match &change.kind {
                    EntityChangeKind::Modified { old, new } => {
                        // An arity-preserving parameter rename whose graph-known
                        // call sites all pass positionally strands no consumer.
                        // Mirror the inline signature-change channel (inline.rs)
                        // so this shadow downstream_risk channel demotes the same
                        // runtime-neutral rename instead of re-blocking it. Reuse
                        // the shipped classifiers (single source of truth); they
                        // are Python-only, so a non-Python rename yields `None`
                        // here and stays blocking.
                        let rename_neutral = match crate::inline::arity_preserving_rename(
                            &old.signature,
                            &new.signature,
                        ) {
                            Some(renamed) => {
                                let summary = review
                                    .impact
                                    .entity_impact(&change.entity_id)
                                    .map(|entry| entry.call_shapes.clone())
                                    .unwrap_or_default();
                                crate::inline::rename_is_runtime_neutral_for_consumers(
                                    &renamed, &summary,
                                )
                            }
                            None => false,
                        };
                        (
                            new.name.clone(),
                            new.span
                                .as_ref()
                                .map(|span| (span.file.to_string(), span.start_line)),
                            (old.signature != new.signature
                                && !crate::inline::signature_runtime_neutral(
                                    &old.signature,
                                    &new.signature,
                                ))
                                || old.visibility != new.visibility,
                            false,
                            rename_neutral,
                        )
                    }
                    EntityChangeKind::Removed { .. } => {
                        let id_string = change.entity_id.to_string();
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
                        (name, None, true, unresolvable, false)
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
            // The EXTERNAL count. This gate decides whether a removed or
            // changed surface strands somebody, and a test that goes with the
            // code it tests was never stranded, so the wider `consumer_count`
            // would block on exactly the case the rule below exists to let
            // through.
            let entity_consumers = review
                .impact
                .entity_impact(&change.entity_id)
                .map_or(0, crate::impact::EntityImpact::external_consumers);
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
            // Demote (do not suppress) this downstream risk to attention when we
            // cannot certify a block: an unresolvable removal (severed surface
            // named only as a raw UUID) or an arity-preserving rename proven
            // runtime-neutral by its call sites. The contract surface genuinely
            // changed, so the finding stays visible evidence; it just no longer
            // gates. A rename carries the positional-safety proof in its message
            // for parity with the inline signature-change channel.
            let demote = demote_removal || rename_neutral;
            findings.push(ShadowPolicyFinding {
                kind: "downstream_risk".to_string(),
                severity: if demote { "warning" } else { "error" }.to_string(),
                blocking: !demote,
                message: if rename_neutral {
                    format!(
                        "Contract surface of `{}` changed with {} graph-known downstream entity(ies); all {} graph-known call site(s) pass positionally — no runtime break",
                        name, entity_consumers, entity_consumers
                    )
                } else {
                    format!(
                        "Contract surface of `{}` changed with {} graph-known downstream entity(ies)",
                        name, entity_consumers
                    )
                },
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
        "breaking_migrated" => {
            "The contract surface changed but every graph-known consumer was co-updated in this \
             same change — a coherent migration. Confirm no consumer outside the graph (e.g. a \
             cross-repo caller) still depends on the old surface."
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
        "revert_history_incidental" => {
            "One entity's body matches an older revision — often incidental on small \
             bodies; worth a glance at the linked history, not a gate."
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

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut bytes_hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(bytes_hex, "{byte:02x}");
    }
    bytes_hex
}

fn repo_path_subject(path: &RepoPath) -> String {
    if let Some(path) = path.as_utf8() {
        return path.to_string();
    }
    let bytes_hex = lower_hex(path.as_bytes());
    format!("non_utf8_path(bytes_hex={bytes_hex})")
}

fn tree_entry_description(entry: TreeEntry) -> String {
    match entry {
        TreeEntry::Blob { hash, executable } => {
            format!("blob(hash={hash}, executable={executable})")
        }
        TreeEntry::Symlink { target_blob } => {
            format!("symlink(target_blob={target_blob})")
        }
        TreeEntry::Gitlink {
            target: GitObjectId::Sha1(target),
        } => format!("gitlink(sha1={})", lower_hex(&target)),
        TreeEntry::Gitlink {
            target: GitObjectId::Sha256(target),
        } => format!("gitlink(sha256={})", lower_hex(&target)),
    }
}

fn located_entry_description(entry: &LocatedEntry) -> String {
    format!(
        "{} {}",
        repo_path_subject(&entry.path),
        tree_entry_description(entry.entry)
    )
}

fn artifact_aspect_label(aspect: ShadowArtifactAspect) -> &'static str {
    match aspect {
        ShadowArtifactAspect::Added => "added",
        ShadowArtifactAspect::Removed => "removed",
        ShadowArtifactAspect::Renamed => "renamed",
        ShadowArtifactAspect::BlobContentChanged => "blob_content_changed",
        ShadowArtifactAspect::ExecutableModeChanged => "executable_mode_changed",
        ShadowArtifactAspect::SymlinkTargetChanged => "symlink_target_changed",
        ShadowArtifactAspect::GitlinkTargetChanged => "gitlink_target_changed",
        ShadowArtifactAspect::EntryTypeChanged => "entry_type_changed",
    }
}

fn artifact_operation_label(operation: ShadowArtifactOperation) -> &'static str {
    match operation {
        ShadowArtifactOperation::Added => "added",
        ShadowArtifactOperation::Updated => "updated",
        ShadowArtifactOperation::Removed => "removed",
    }
}

fn artifact_change_detail(change: &ShadowArtifactChange) -> String {
    let aspects = change
        .aspects
        .iter()
        .copied()
        .map(artifact_aspect_label)
        .collect::<Vec<_>>()
        .join(",");
    let old = change
        .old
        .as_ref()
        .map(located_entry_description)
        .unwrap_or_else(|| "<absent>".to_string());
    let new = change
        .new
        .as_ref()
        .map(located_entry_description)
        .unwrap_or_else(|| "<absent>".to_string());
    format!(
        "artifact {} {}; aspects=[{}]; old={old}; new={new}",
        change.artifact_id.0,
        artifact_operation_label(change.operation),
        aspects
    )
}

fn artifact_change_path(change: &ShadowArtifactChange) -> Option<&RepoPath> {
    change
        .new
        .as_ref()
        .or(change.old.as_ref())
        .map(|state| &state.path)
}

fn artifact_change_has_non_utf8_path(change: &ShadowArtifactChange) -> bool {
    change
        .old
        .iter()
        .chain(change.new.iter())
        .any(|state| state.path.as_utf8().is_none())
}

fn artifact_change_matches_entity_file(
    change: &ShadowArtifactChange,
    entity_files: &BTreeSet<String>,
) -> bool {
    change
        .old
        .iter()
        .chain(change.new.iter())
        .filter_map(|state| state.path.as_utf8())
        .any(|path| entity_files.contains(path))
}

fn artifact_change_is_blob_content_only(change: &ShadowArtifactChange) -> bool {
    change.aspects.as_slice() == [ShadowArtifactAspect::BlobContentChanged]
}

fn artifact_blob_hash_pair(change: &ShadowArtifactChange) -> Option<(Hash256, Hash256)> {
    match (
        change.old.as_ref().map(|state| state.entry),
        change.new.as_ref().map(|state| state.entry),
    ) {
        (Some(TreeEntry::Blob { hash: old, .. }), Some(TreeEntry::Blob { hash: new, .. })) => {
            Some((old, new))
        }
        _ => None,
    }
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
    changed_artifacts: &[ShadowArtifactChange],
    artifact_activity: &[ShadowArtifactActivity],
    at_head: Option<&GraphAtRef<'_, G>>,
    blobs: Option<&BlobStore>,
) -> (Vec<ShadowEvidenceGap>, Vec<InlineComment>) {
    let mut gaps = Vec::new();
    let mut toolchain_findings: Vec<InlineComment> = Vec::new();

    // Net tree changes whose exact old/new path does not match a changed
    // entity are invisible to semantic blast radius and policy. Identity,
    // location, and entry kind remain separate throughout this classification.
    let entity_files: BTreeSet<String> = changed_entities
        .iter()
        .filter_map(|entity| entity.file.clone())
        .collect();

    for change in changed_artifacts {
        // A matching entity delta accounts only for a Blob->Blob content
        // edit. Entity records do not encode repository moves, executable
        // mode, entry type, symlink targets, gitlink targets, or whole-artifact
        // admission/removal, so those aspects must remain explicit even when
        // one parsed entity happens to share the path.
        if artifact_change_is_blob_content_only(change)
            && artifact_change_matches_entity_file(change, &entity_files)
        {
            continue;
        }

        let path =
            artifact_change_path(change).expect("every artifact change has an old or new location");
        let subject = repo_path_subject(path);
        let detail = artifact_change_detail(change);
        let (kind, detail) = if artifact_change_has_non_utf8_path(change) {
            (
                "artifact_path_unrepresentable",
                format!(
                    "{detail}; at least one path is not UTF-8, so entity matching and \
                     source classification cannot prove its semantic impact"
                ),
            )
        } else if !artifact_change_is_blob_content_only(change) {
            (
                "artifact_structure_change",
                format!(
                    "{detail}; semantic entity deltas do not encode or prove this exact \
                     add/remove/move/mode/type/target transition"
                ),
            )
        } else {
            let file = path
                .as_utf8()
                .expect("non-UTF8 paths were classified above");
            let inert_source_edit = artifact_subject_is_source_class(file)
                && at_head.is_some_and(|at| at.has_entity_in_file(file));
            if inert_source_edit {
                // Only a Blob->Blob content edit has hashes that can support a
                // directive diff. Symlink targets and gitlinks are never read
                // as source content.
                if let (Some(blobs), Some((old_hash, new_hash))) =
                    (blobs, artifact_blob_hash_pair(change))
                {
                    if let Some(finding) =
                        toolchain_surface_finding(blobs, file, Some(old_hash), Some(new_hash))
                    {
                        toolchain_findings.push(finding);
                    }
                }
                (
                    "entity_inert_change",
                    format!(
                        "{detail}; the exact Blob content changed without a semantic entity \
                         delta, while entities for this UTF-8 source path remain captured at \
                         head"
                    ),
                )
            } else {
                (
                    "artifact_only_change",
                    format!(
                        "{detail}; exact Blob content changed without a matching semantic entity \
                         delta, so its impact is not included in semantic blast radius"
                    ),
                )
            }
        };
        gaps.push(ShadowEvidenceGap {
            kind: kind.to_string(),
            subject,
            detail,
        });
    }

    // Exact range activity can converge back to the base tree. Preserve and
    // demote that case separately: absence from the net diff is not evidence
    // that no artifact entered history or changed in an intermediate commit.
    let net_artifact_ids: BTreeSet<ArtifactId> = changed_artifacts
        .iter()
        .map(|change| change.artifact_id)
        .collect();
    let mut range_only: BTreeMap<ArtifactId, Vec<&ShadowArtifactActivity>> = BTreeMap::new();
    for activity in artifact_activity {
        if !net_artifact_ids.contains(&activity.transition.artifact_id) {
            range_only
                .entry(activity.transition.artifact_id)
                .or_default()
                .push(activity);
        }
    }
    for (artifact_id, activity) in range_only {
        let subject = activity
            .last()
            .and_then(|event| artifact_change_path(&event.transition))
            .map(repo_path_subject)
            .unwrap_or_else(|| format!("artifact:{}", artifact_id.0));
        let change_ids = activity
            .iter()
            .map(|event| event.change_id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        gaps.push(ShadowEvidenceGap {
            kind: "artifact_range_only_activity".to_string(),
            subject,
            detail: format!(
                "artifact {} has {} exact tree transition(s) in changes [{}], but its resolved \
                 base and head states are identical or both absent; the activity remains review \
                 provenance and cannot be treated as proof of no change",
                artifact_id.0,
                activity.len(),
                change_ids
            ),
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

        // A deep base..head range reaches far enough back that the persisted
        // graph substrate the review replays at head drifts further from a live
        // re-index than a nearby range does. When such a range ALSO
        // yields an empty blast radius (the condition above), attribute that
        // emptiness explicitly to the range-depth ceiling instead of leaving it
        // folded into the generic impact_signal_absent gap. This is a
        // RANGE-DEPTH PROXY, not a measurement of reconstruction, and it is
        // NON-DEMOTING (`gap_blocks_pass` returns false for this kind): it never
        // changes the verdict, only makes the ceiling attributable to scoring.
        // The raw range depth is stamped on the report regardless (`range_depth`).
        if changes.len() > DEEP_HISTORY_IMPACT_CEILING_THRESHOLD {
            gaps.push(ShadowEvidenceGap {
                kind: "deep_history_impact_ceiling".to_string(),
                subject: "blast_radius".to_string(),
                detail: format!(
                    "reviewed range spans {} committed changes (over the {} deep-history \
                     threshold). This is a RANGE-DEPTH PROXY for historical-substrate fidelity: \
                     across a range this deep the graph state materialized at the \
                     head ref is a less faithful representation than a live re-index, so an empty \
                     blast radius is more plausibly a substrate ceiling than proof the change is \
                     isolated. Reported as an accepted ceiling and NON-DEMOTING; the raw range \
                     depth is stamped on the report for scoring",
                    changes.len(),
                    DEEP_HISTORY_IMPACT_CEILING_THRESHOLD
                ),
            });
        }
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
        detail: "cross-repo federation is not evaluated by shadow report v2; consumers in other \
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

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Changed artifacts ({} net):",
        report.changed_artifacts.len()
    );
    for change in &report.changed_artifacts {
        let aspects = change
            .aspects
            .iter()
            .copied()
            .map(artifact_aspect_label)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "  {} {} [{}]",
            match change.operation {
                ShadowArtifactOperation::Added => "+",
                ShadowArtifactOperation::Removed => "-",
                ShadowArtifactOperation::Updated => "~",
            },
            change.artifact_id.0,
            aspects
        );
        if let Some(old) = &change.old {
            let _ = writeln!(out, "    old: {}", located_entry_description(old));
        }
        if let Some(new) = &change.new {
            let _ = writeln!(out, "    new: {}", located_entry_description(new));
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Artifact activity ({} committed transition(s)):",
        report.artifact_activity.len()
    );
    for activity in &report.artifact_activity {
        let _ = writeln!(
            out,
            "  {} {}",
            activity.change_id,
            artifact_change_detail(&activity.transition)
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
        EntityDelta, LocatedEntry, RelationDelta, SemanticChange, TreeDelta, TreeEntry,
    };
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        SourceSpan, Visibility,
    };
    use kin_model::graph::{ChangeStore, EntityStore};
    use kin_model::ids::*;
    use kin_model::relation::{GraphNodeId, Relation, RelationKind, RelationOrigin};
    use kin_model::timestamp::Timestamp;
    use kin_model::ArtifactId;

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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
        fixture_id: SemanticChangeId,
        parents: Vec<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        tree_deltas: Vec<TreeDelta>,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test-author"),
            message: format!("test change {fixture_id}"),
            entity_deltas,
            relation_deltas,
            tree_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn repo_path(path: &str) -> RepoPath {
        RepoPath::from_utf8(path).expect("valid test repository path")
    }

    fn tree_add(artifact_id: ArtifactId, path: &str, entry: TreeEntry) -> TreeDelta {
        TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(repo_path(path), entry),
        }
    }

    fn tree_update(
        artifact_id: ArtifactId,
        old_path: &str,
        old_entry: TreeEntry,
        new_path: &str,
        new_entry: TreeEntry,
    ) -> TreeDelta {
        TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path(old_path), old_entry),
            new: LocatedEntry::new(repo_path(new_path), new_entry),
        }
    }

    fn tree_remove(artifact_id: ArtifactId, path: &str, entry: TreeEntry) -> TreeDelta {
        TreeDelta::Removed {
            artifact_id,
            old: LocatedEntry::new(repo_path(path), entry),
        }
    }

    fn tree_with_exact_path(
        artifact_id: ArtifactId,
        path: RepoPath,
        entry: TreeEntry,
    ) -> ResolvedTree {
        ResolvedTree::default()
            .apply(&[TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path, entry),
            }])
            .unwrap()
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

        let base = change_with_deltas(
            change_id(1),
            vec![],
            vec![
                EntityDelta::Added {
                    new: target_v1.clone(),
                },
                EntityDelta::Added { new: caller },
                EntityDelta::Added { new: test },
            ],
            vec![
                RelationDelta::Added { new: calls_rel },
                RelationDelta::Added { new: tests_rel },
            ],
            vec![],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(2),
            vec![base_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
                    kind: EntityChangeKind::Removed { old: None },
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
                    ..SemanticDiff::default()
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
                            external_consumer_count: 1,
                            test_consumer_count: 0,
                            derived_consumer_count: 0,
                            strong_consumer_count: 1,
                            proven_consumer_count: 0,
                            contract_consumer_count: 0,
                            consumer_files: vec!["src/consumer.rs".to_string()],
                            external_consumer_files: vec!["src/consumer.rs".to_string()],
                            covering_tests: 0,
                            consumers_migrated_in_diff: 0,
                            call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
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
        let mut updated_entity = entity.clone();
        updated_entity.doc_summary = Some("clarified helper documentation".into());
        graph.upsert_entity(&updated_entity).unwrap();
        let artifact_id = ArtifactId::new();
        let old_entry = TreeEntry::blob(Hash256::from_bytes([7; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([8; 32]), false);

        let base = change_with_deltas(
            change_id(3),
            vec![],
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![tree_add(artifact_id, "config/policy.yaml", old_entry)],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(4),
            vec![base_id],
            vec![EntityDelta::Modified {
                old: entity,
                new: updated_entity,
            }],
            vec![],
            vec![tree_update(
                artifact_id,
                "config/policy.yaml",
                old_entry,
                "config/policy.yaml",
                new_entry,
            )],
        );
        let head_id = head.id;
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
    fn mode_only_tree_delta_is_not_dropped_from_evidence_gaps() {
        let hash = Hash256::from_bytes([0x44; 32]);
        let artifact_id = ArtifactId::new();
        let regular = TreeEntry::blob(hash, false);
        let executable = TreeEntry::blob(hash, true);
        let base_tree = ResolvedTree::default()
            .apply(&[tree_add(artifact_id, "bin/run", regular)])
            .unwrap();
        let delta = tree_update(artifact_id, "bin/run", regular, "bin/run", executable);
        let head_tree = base_tree.apply(std::slice::from_ref(&delta)).unwrap();
        let change = change_with_deltas(change_id(5), vec![], vec![], vec![], vec![delta]);
        let changed_artifacts = collect_changed_artifacts(&base_tree, &head_tree);
        let artifact_activity = collect_artifact_activity(std::slice::from_ref(&change));

        let (gaps, findings) = collect_evidence_gaps::<InMemoryGraph>(
            &empty_review(),
            &[change],
            &[],
            &changed_artifacts,
            &artifact_activity,
            None,
            None,
        );

        assert!(
            gaps.iter()
                .any(|gap| gap.kind == "artifact_structure_change" && gap.subject == "bin/run"),
            "an executable-bit-only tree transition must remain review-visible"
        );
        assert!(gaps
            .iter()
            .find(|gap| gap.kind == "artifact_structure_change")
            .is_some_and(gap_blocks_pass));
        assert!(findings.is_empty());
    }

    #[test]
    fn exact_artifact_diff_distinguishes_rename_edit_and_mode() {
        let artifact_id = ArtifactId::new();
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let edited_entry = TreeEntry::blob(Hash256::from_bytes([0x32; 32]), false);
        let executable_entry = TreeEntry::blob(Hash256::from_bytes([0x32; 32]), true);
        let base = tree_with_exact_path(artifact_id, repo_path("src/old.rs"), old_entry);

        let renamed = base
            .apply(&[tree_update(
                artifact_id,
                "src/old.rs",
                old_entry,
                "src/new.rs",
                old_entry,
            )])
            .unwrap();
        let pure_rename = collect_changed_artifacts(&base, &renamed);
        assert_eq!(pure_rename.len(), 1);
        assert_eq!(pure_rename[0].artifact_id, artifact_id);
        assert_eq!(pure_rename[0].aspects, vec![ShadowArtifactAspect::Renamed]);
        assert_eq!(
            pure_rename[0].old.as_ref().unwrap().path,
            repo_path("src/old.rs")
        );
        assert_eq!(
            pure_rename[0].new.as_ref().unwrap().path,
            repo_path("src/new.rs")
        );

        let renamed_and_edited = base
            .apply(&[tree_update(
                artifact_id,
                "src/old.rs",
                old_entry,
                "src/new.rs",
                edited_entry,
            )])
            .unwrap();
        let rename_edit = collect_changed_artifacts(&base, &renamed_and_edited);
        assert_eq!(
            rename_edit[0].aspects,
            vec![
                ShadowArtifactAspect::Renamed,
                ShadowArtifactAspect::BlobContentChanged,
            ]
        );

        let mode_base = tree_with_exact_path(artifact_id, repo_path("src/new.rs"), edited_entry);
        let mode_head = mode_base
            .apply(&[tree_update(
                artifact_id,
                "src/new.rs",
                edited_entry,
                "src/new.rs",
                executable_entry,
            )])
            .unwrap();
        let mode = collect_changed_artifacts(&mode_base, &mode_head);
        assert_eq!(
            mode[0].aspects,
            vec![ShadowArtifactAspect::ExecutableModeChanged]
        );
        assert_eq!(mode[0].artifact_id, artifact_id);

        for change in [&pure_rename[0], &rename_edit[0]] {
            let (gaps, _) = collect_evidence_gaps::<InMemoryGraph>(
                &empty_review(),
                &[],
                &[],
                std::slice::from_ref(change),
                &[],
                None,
                None,
            );
            assert!(gaps
                .iter()
                .find(|gap| gap.kind == "artifact_structure_change")
                .is_some_and(gap_blocks_pass));
        }
    }

    #[test]
    fn exact_artifact_diff_distinguishes_entry_types_and_targets() {
        let artifact_id = ArtifactId::new();
        let blob = TreeEntry::blob(Hash256::from_bytes([0x41; 32]), false);
        let symlink_a = TreeEntry::symlink(Hash256::from_bytes([0x42; 32]));
        let symlink_b = TreeEntry::symlink(Hash256::from_bytes([0x43; 32]));
        let gitlink_a = TreeEntry::gitlink(GitObjectId::sha1([0x44; 20]));
        let gitlink_b = TreeEntry::gitlink(GitObjectId::sha1([0x45; 20]));

        let blob_tree = tree_with_exact_path(artifact_id, repo_path("vendor/ref"), blob);
        let symlink_tree = blob_tree
            .apply(&[tree_update(
                artifact_id,
                "vendor/ref",
                blob,
                "vendor/ref",
                symlink_a,
            )])
            .unwrap();
        let type_change = collect_changed_artifacts(&blob_tree, &symlink_tree);
        assert_eq!(
            type_change[0].aspects,
            vec![ShadowArtifactAspect::EntryTypeChanged]
        );
        assert_eq!(
            artifact_blob_hash_pair(&type_change[0]),
            None,
            "a symlink target blob is not source-file content"
        );

        let symlink_head = symlink_tree
            .apply(&[tree_update(
                artifact_id,
                "vendor/ref",
                symlink_a,
                "vendor/ref",
                symlink_b,
            )])
            .unwrap();
        let symlink_change = collect_changed_artifacts(&symlink_tree, &symlink_head);
        assert_eq!(
            symlink_change[0].aspects,
            vec![ShadowArtifactAspect::SymlinkTargetChanged]
        );
        assert_eq!(artifact_blob_hash_pair(&symlink_change[0]), None);

        let gitlink_tree =
            tree_with_exact_path(artifact_id, repo_path("vendor/submodule"), gitlink_a);
        let gitlink_head = gitlink_tree
            .apply(&[tree_update(
                artifact_id,
                "vendor/submodule",
                gitlink_a,
                "vendor/submodule",
                gitlink_b,
            )])
            .unwrap();
        let gitlink_change = collect_changed_artifacts(&gitlink_tree, &gitlink_head);
        assert_eq!(
            gitlink_change[0].aspects,
            vec![ShadowArtifactAspect::GitlinkTargetChanged]
        );
        assert_eq!(artifact_blob_hash_pair(&gitlink_change[0]), None);

        for change in [&type_change[0], &symlink_change[0], &gitlink_change[0]] {
            let (gaps, findings) = collect_evidence_gaps::<InMemoryGraph>(
                &empty_review(),
                &[],
                &[],
                std::slice::from_ref(change),
                &[],
                None,
                None,
            );
            assert!(gaps
                .iter()
                .find(|gap| gap.kind == "artifact_structure_change")
                .is_some_and(gap_blocks_pass));
            assert!(
                findings.is_empty(),
                "non-Blob transitions must never be content-diffed"
            );
        }
    }

    #[test]
    fn exact_artifact_diff_preserves_add_remove_and_path_reuse_identity() {
        let removed_id = ArtifactId::new();
        let added_id = ArtifactId::new();
        let path = repo_path("compose.yaml");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x51; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x52; 32]), false);
        let base = tree_with_exact_path(removed_id, path.clone(), old_entry);
        let head = ResolvedTree::default()
            .apply(&[TreeDelta::Added {
                artifact_id: added_id,
                new: LocatedEntry::new(path, new_entry),
            }])
            .unwrap();

        let changes = collect_changed_artifacts(&base, &head);
        assert_eq!(changes.len(), 2);
        let added = changes
            .iter()
            .find(|change| change.artifact_id == added_id)
            .unwrap();
        let removed = changes
            .iter()
            .find(|change| change.artifact_id == removed_id)
            .unwrap();
        assert_eq!(added.operation, ShadowArtifactOperation::Added);
        assert_eq!(added.aspects, vec![ShadowArtifactAspect::Added]);
        assert_eq!(removed.operation, ShadowArtifactOperation::Removed);
        assert_eq!(removed.aspects, vec![ShadowArtifactAspect::Removed]);
        assert_ne!(added.artifact_id, removed.artifact_id);
    }

    #[test]
    fn non_utf8_artifact_paths_are_exact_and_fail_closed() {
        let artifact_id = ArtifactId::new();
        let old_path = RepoPath::from_bytes(vec![b's', b'r', b'c', b'/', 0xff]).unwrap();
        let new_path = RepoPath::from_bytes(vec![b's', b'r', b'c', b'/', 0xfe]).unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x61; 32]), false);
        let base = tree_with_exact_path(artifact_id, old_path.clone(), entry);
        let head = base
            .apply(&[TreeDelta::Updated {
                artifact_id,
                old: LocatedEntry::new(old_path, entry),
                new: LocatedEntry::new(new_path, entry),
            }])
            .unwrap();
        let changes = collect_changed_artifacts(&base, &head);

        let json = serde_json::to_value(&changes[0]).unwrap();
        assert!(json["artifact_id"].as_str().is_some());
        assert_eq!(json["old"]["path"]["bytes_hex"], "7372632fff");
        assert_eq!(json["new"]["path"]["bytes_hex"], "7372632ffe");
        let human = artifact_change_detail(&changes[0]);
        assert!(human.contains("non_utf8_path(bytes_hex=7372632fff)"));
        assert!(human.contains("non_utf8_path(bytes_hex=7372632ffe)"));
        assert!(
            !human.contains('\u{fffd}'),
            "non-UTF8 paths must never be rendered through lossy replacement"
        );

        let (gaps, _) = collect_evidence_gaps::<InMemoryGraph>(
            &empty_review(),
            &[],
            &[],
            &changes,
            &[],
            None,
            None,
        );
        let gap = gaps
            .iter()
            .find(|gap| gap.kind == "artifact_path_unrepresentable")
            .expect("non-UTF8 authority path must remain an explicit gap");
        assert_eq!(gap.subject, "non_utf8_path(bytes_hex=7372632ffe)");
        assert!(gap_blocks_pass(gap));
    }

    #[test]
    fn converged_range_activity_remains_exact_and_fail_closed() {
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x71; 32]), false);
        let add = change_with_deltas(
            change_id(0x71),
            vec![],
            vec![],
            vec![],
            vec![tree_add(artifact_id, "scratch.bin", entry)],
        );
        let add_id = add.id;
        let remove = change_with_deltas(
            change_id(0x72),
            vec![add_id],
            vec![],
            vec![],
            vec![tree_remove(artifact_id, "scratch.bin", entry)],
        );
        let remove_id = remove.id;
        let activity = collect_artifact_activity(&[remove, add]);

        assert_eq!(activity.len(), 2);
        assert_eq!(activity[0].transition.artifact_id, artifact_id);
        assert_eq!(activity[1].transition.artifact_id, artifact_id);
        assert!(activity
            .iter()
            .any(|event| event.transition.operation == ShadowArtifactOperation::Added));
        assert!(activity
            .iter()
            .any(|event| event.transition.operation == ShadowArtifactOperation::Removed));

        let (gaps, _) = collect_evidence_gaps::<InMemoryGraph>(
            &empty_review(),
            &[],
            &[],
            &[],
            &activity,
            None,
            None,
        );
        let gap = gaps
            .iter()
            .find(|gap| gap.kind == "artifact_range_only_activity")
            .expect("converged range activity must not disappear behind an empty net diff");
        assert!(gap_blocks_pass(gap));
        assert!(gap.detail.contains(&add_id.to_string()));
        assert!(gap.detail.contains(&remove_id.to_string()));
    }

    #[test]
    fn source_class_artifact_gap_still_demotes() {
        // Counter-case: the same artifact-only gap on a file the ingest
        // classifier calls source means real code changed that the graph
        // never captured. That deficit still demotes the pass.
        let graph = InMemoryGraph::new();
        let entity = entity_with_span("helper", "src/lib.rs", 1, EntityRole::Source);
        graph.upsert_entity(&entity).unwrap();
        let artifact_id = ArtifactId::new();
        let old_entry = TreeEntry::blob(Hash256::from_bytes([9; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([10; 32]), false);

        let base = change_with_deltas(
            change_id(6),
            vec![],
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![tree_add(artifact_id, "src/legacy.c", old_entry)],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(7),
            vec![base_id],
            vec![],
            vec![],
            vec![tree_update(
                artifact_id,
                "src/legacy.c",
                old_entry,
                "src/legacy.c",
                new_entry,
            )],
        );
        let head_id = head.id;
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

    fn low_risk() -> kin_model::review::RiskSummary {
        kin_model::review::RiskSummary {
            overall_risk: kin_model::review::RiskLevel::Low,
            breaking_changes: vec![],
            test_coverage_gaps: vec![],
            contract_violations: vec![],
            work_risks: vec![],
            notes: vec![],
        }
    }

    fn review_with_impact(impact: ImpactReport) -> Review {
        Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact,
            risk: low_risk(),
            inline_comments: vec![],
        }
    }

    // A range of `n` committed changes. Ids may repeat: only the count feeds the
    // deep-history gate, and the changes carry no artifact deltas so they add no
    // other gaps.
    fn range_of(n: usize) -> Vec<SemanticChange> {
        (0..n)
            .map(|i| change_with_deltas(change_id((i % 251) as u8), vec![], vec![], vec![], vec![]))
            .collect()
    }

    fn one_changed_entity() -> Vec<ShadowChangedEntity> {
        vec![ShadowChangedEntity {
            entity_id: "e1".to_string(),
            name: "foo".to_string(),
            kind: "Function".to_string(),
            change: "modified".to_string(),
            file: Some("src/lib.rs".to_string()),
            start_line: Some(1),
            end_line: Some(2),
            signature_changed: false,
            visibility_changed: false,
            role: EntityRole::Source,
        }]
    }

    #[test]
    fn deep_history_impact_ceiling_gap_fires_only_on_deep_empty_range() {
        let changed = one_changed_entity();
        let has_ceiling = |gaps: &[ShadowEvidenceGap]| {
            gaps.iter().any(|g| g.kind == "deep_history_impact_ceiling")
        };

        // Deep range + empty blast radius + changed entities -> ceiling attributed,
        // riding ALONGSIDE the generic empty-impact gap (never replacing it, so
        // the existing relation_channel_absent gate logic is untouched).
        let deep = range_of(DEEP_HISTORY_IMPACT_CEILING_THRESHOLD + 1);
        let (gaps, _) = collect_evidence_gaps::<InMemoryGraph>(
            &review_with_impact(ImpactReport::default()),
            &deep,
            &changed,
            &[],
            &[],
            None,
            None,
        );
        assert!(
            has_ceiling(&gaps),
            "a deep range with an empty blast radius must attribute the ceiling"
        );
        assert!(gaps.iter().any(|g| g.kind == "impact_signal_absent"));

        // A range AT the threshold (not over it) attributes no ceiling.
        let shallow = range_of(DEEP_HISTORY_IMPACT_CEILING_THRESHOLD);
        let (gaps, _) = collect_evidence_gaps::<InMemoryGraph>(
            &review_with_impact(ImpactReport::default()),
            &shallow,
            &changed,
            &[],
            &[],
            None,
            None,
        );
        assert!(
            !has_ceiling(&gaps),
            "a range at the threshold must not attribute a ceiling"
        );
        assert!(gaps.iter().any(|g| g.kind == "impact_signal_absent"));

        // Deep range but a NON-empty blast radius: impact was proven, so there is
        // nothing to attribute to a substrate ceiling.
        let nonempty = ImpactReport {
            affected_callers: vec![entity_with_span(
                "consumer",
                "src/c.rs",
                1,
                EntityRole::Source,
            )],
            ..ImpactReport::default()
        };
        let (gaps, _) = collect_evidence_gaps::<InMemoryGraph>(
            &review_with_impact(nonempty),
            &deep,
            &changed,
            &[],
            &[],
            None,
            None,
        );
        assert!(
            !has_ceiling(&gaps),
            "a non-empty blast radius must not attribute a ceiling"
        );
    }

    #[test]
    fn deep_history_impact_ceiling_gap_is_non_demoting() {
        let ceiling = ShadowEvidenceGap {
            kind: "deep_history_impact_ceiling".to_string(),
            subject: "blast_radius".to_string(),
            detail: "range-depth proxy".to_string(),
        };
        // The gate never fails to certify a pass over an accepted ceiling.
        assert!(!gap_blocks_pass(&ceiling));

        // And it leaves the verdict a would-be pass produces exactly as it was.
        let review = review_with_impact(ImpactReport::default());
        let baseline = derive_policy(&review, &[], &[]);
        let with_ceiling = derive_policy(&review, std::slice::from_ref(&ceiling), &[]);
        assert_eq!(baseline.verdict, ShadowGateVerdict::Pass);
        assert_eq!(
            with_ceiling.verdict, baseline.verdict,
            "the ceiling attribution must not change the verdict"
        );
    }

    #[test]
    fn report_stamps_range_depth_and_round_trips() {
        let (graph, base_id, head_id) = signature_change_graph();
        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        // T1b: the raw in-range count is always stamped, mirrors the audit
        // count, and records the threshold used. This fixture's range is shallow.
        assert_eq!(
            report.range_depth.in_range_changes,
            report.audit.changes_in_range
        );
        assert_eq!(
            report.range_depth.deep_history_threshold,
            DEEP_HISTORY_IMPACT_CEILING_THRESHOLD
        );
        assert!(!report.range_depth.is_deep_history);
        assert!(report
            .evidence_gaps
            .iter()
            .all(|g| g.kind != "deep_history_impact_ceiling"));

        // JSON round-trip: the additive field survives serialize -> deserialize.
        let json = serde_json::to_string(&report).unwrap();
        let parsed: ShadowGateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.range_depth.in_range_changes,
            report.range_depth.in_range_changes
        );
        assert_eq!(
            parsed.range_depth.deep_history_threshold,
            DEEP_HISTORY_IMPACT_CEILING_THRESHOLD
        );
        assert_eq!(
            parsed.range_depth.is_deep_history,
            report.range_depth.is_deep_history
        );

        // A payload serialized before the field existed still deserializes: the
        // field is serde(default). Drop it from the JSON and re-parse.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("range_depth");
        let legacy: ShadowGateReport = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.range_depth.in_range_changes, 0);
        assert!(!legacy.range_depth.is_deep_history);
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

        let base = change_with_deltas(
            change_id(8),
            vec![],
            vec![
                EntityDelta::Added {
                    new: legacy.clone(),
                },
                EntityDelta::Added {
                    new: consumer.clone(),
                },
            ],
            vec![RelationDelta::Added {
                new: calls_rel.clone(),
            }],
            vec![],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(9),
            vec![base_id],
            vec![EntityDelta::Removed {
                old: legacy.clone(),
            }],
            vec![RelationDelta::Removed { old: calls_rel }],
            vec![],
        );
        let head_id = head.id;
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

        let mut base_entities = vec![EntityDelta::Added {
            new: validate.clone(),
        }];
        let mut base_relations = vec![];
        if include_consumer {
            base_entities.push(EntityDelta::Added { new: consumer });
            base_relations.push(RelationDelta::Added {
                new: consume_rel.clone(),
            });
        }
        let base = change_with_deltas(change_id(20), vec![], base_entities, base_relations, vec![]);
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(21),
            vec![base_id],
            vec![EntityDelta::Removed {
                old: validate.clone(),
            }],
            include_consumer
                .then_some(RelationDelta::Removed { old: consume_rel })
                .into_iter()
                .collect(),
            vec![],
        );
        let head_id = head.id;
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

        let base = change_with_deltas(
            change_id(22),
            vec![],
            vec![
                EntityDelta::Added {
                    new: validate_old.clone(),
                },
                EntityDelta::Added { new: consumer },
            ],
            vec![RelationDelta::Added {
                new: calls_rel.clone(),
            }],
            vec![],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(23),
            vec![base_id],
            vec![
                EntityDelta::Removed {
                    old: validate_old.clone(),
                },
                EntityDelta::Added { new: validate_new },
            ],
            vec![RelationDelta::Removed { old: calls_rel }],
            vec![],
        );
        let head_id = head.id;
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
                        kind: EntityChangeKind::Removed { old: None },
                    },
                    EntityChange {
                        entity_id: readded.id,
                        kind: EntityChangeKind::Added(readded.clone()),
                    },
                ],
                relation_changes: vec![],
                ..SemanticDiff::default()
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: moved_old_id,
                    consumer_count: 1,
                    external_consumer_count: 1,
                    test_consumer_count: 0,
                    derived_consumer_count: 0,
                    strong_consumer_count: 1,
                    proven_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/consumer.rs".to_string()],
                    external_consumer_files: vec!["src/consumer.rs".to_string()],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
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
                ..SemanticDiff::default()
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: new.id,
                    consumer_count: 0,
                    external_consumer_count: 0,
                    test_consumer_count: 0,
                    derived_consumer_count: 0,
                    strong_consumer_count: 0,
                    proven_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![],
                    external_consumer_files: vec![],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
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

        let base = change_with_deltas(
            change_id(0x21),
            vec![],
            vec![
                EntityDelta::Added {
                    new: target_v1.clone(),
                },
                EntityDelta::Added {
                    new: caller.clone(),
                },
            ],
            vec![RelationDelta::Added {
                new: relation(&caller, &target_v1, RelationKind::Calls),
            }],
            vec![],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(0x22),
            vec![base_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
        let base = change_with_deltas(
            change_id(0x32),
            vec![ghost_parent],
            vec![EntityDelta::Added {
                new: target_v1.clone(),
            }],
            vec![],
            vec![],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(0x33),
            vec![base_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
        let root = change_with_deltas(
            change_id(0x41),
            vec![],
            vec![EntityDelta::Added {
                new: target_v1.clone(),
            }],
            vec![],
            vec![],
        );
        let root_id = root.id;
        let head = change_with_deltas(
            change_id(0x42),
            vec![root_id],
            vec![EntityDelta::Modified {
                old: target_v1,
                new: target_v2,
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
        // Disjoint branch: a change that is NOT on head's ancestry.
        let disjoint = change_with_deltas(
            change_id(0x43),
            vec![],
            vec![EntityDelta::Added { new: stray }],
            vec![],
            vec![],
        );
        let disjoint_id = disjoint.id;
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
        let genesis = change_with_deltas(
            change_id(0x51),
            vec![],
            vec![EntityDelta::Added { new: stale.clone() }],
            vec![],
            vec![],
        );
        let genesis_id = genesis.id;
        let base = change_with_deltas(
            change_id(0x52),
            vec![genesis_id],
            vec![EntityDelta::Added {
                new: mainline.clone(),
            }],
            vec![],
            vec![],
        );
        let base_id = base.id;
        let branch = change_with_deltas(
            change_id(0x53),
            vec![genesis_id],
            vec![EntityDelta::Added { new: branch_v2 }],
            vec![],
            vec![],
        );
        let branch_id = branch.id;
        let head = change_with_deltas(
            change_id(0x54),
            vec![base_id, branch_id],
            vec![],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
        let base = change_with_deltas(change_id(5), vec![], vec![], vec![], vec![]);
        let base_id = base.id;
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
                    kind: EntityChangeKind::Removed { old: None },
                }],
                relation_changes: vec![],
                ..SemanticDiff::default()
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: removed_id,
                    consumer_count: 1,
                    external_consumer_count: 1,
                    test_consumer_count: 0,
                    derived_consumer_count: 0,
                    strong_consumer_count: 1,
                    proven_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec!["src/consumer.rs".to_string()],
                    external_consumer_files: vec!["src/consumer.rs".to_string()],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes: crate::impact::ConsumerCallShapeSummary::default(),
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

    /// Build a Review for an arity-preserving positional rename
    /// (`def makefile_target(ext, args)` → `def makefile_target(ext, lines)`)
    /// with 3 graph-known consumers whose call shapes are `call_shapes`. Exercises
    /// the shadow `downstream_risk` channel in isolation (no inline comments).
    fn positional_rename_review_with_signatures(
        old_signature: &str,
        new_signature: &str,
        call_shapes: crate::impact::ConsumerCallShapeSummary,
    ) -> Review {
        use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
        use crate::impact::{EntityImpact, ImpactReport};
        use kin_model::review::{RiskLevel, RiskSummary};

        let mut old = entity_with_span(
            "makefile_target",
            "src/pytester.py",
            610,
            EntityRole::Source,
        );
        old.signature = old_signature.to_string();
        let mut new = old.clone();
        new.signature = new_signature.to_string();

        Review {
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
                ..SemanticDiff::default()
            },
            impact: ImpactReport {
                entity_impacts: vec![EntityImpact {
                    entity_id: new.id,
                    consumer_count: 3,
                    external_consumer_count: 3,
                    test_consumer_count: 0,
                    derived_consumer_count: 0,
                    strong_consumer_count: 3,
                    proven_consumer_count: 0,
                    contract_consumer_count: 0,
                    consumer_files: vec![
                        "src/pytester.py".to_string(),
                        "src/pytester.py".to_string(),
                        "src/pytester.py".to_string(),
                    ],
                    external_consumer_files: vec![
                        "src/pytester.py".to_string(),
                        "src/pytester.py".to_string(),
                        "src/pytester.py".to_string(),
                    ],
                    covering_tests: 0,
                    consumers_migrated_in_diff: 0,
                    call_shapes,
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
        }
    }

    fn positional_rename_review(call_shapes: crate::impact::ConsumerCallShapeSummary) -> Review {
        positional_rename_review_with_signatures(
            "def makefile_target(ext, args)",
            "def makefile_target(ext, lines)",
            call_shapes,
        )
    }

    #[test]
    fn shadow_downstream_risk_demotes_runtime_neutral_positional_rename() {
        // The shadow `downstream_risk` channel is a SEPARATE gate from
        // the inline signature-change channel. An arity-preserving rename whose
        // graph-known call sites all pass positionally is runtime-neutral, yet
        // pre-fix this channel still emitted a BLOCKING downstream_risk (verdict
        // WouldBlock) because it consulted only `signature_runtime_neutral`, not
        // the rename classifiers. Post-fix it demotes to a non-blocking warning
        // (verdict NeedsAttention), matching the inline channel.
        let call_shapes = crate::impact::ConsumerCallShapeSummary {
            caller_keyword_names: std::collections::BTreeSet::new(),
            any_var_keyword_caller: false,
            all_consumers_shaped_calls: true,
        };
        let review = positional_rename_review(call_shapes);
        let policy = derive_policy(&review, &[], &[]);
        let finding = policy
            .findings
            .iter()
            .find(|f| f.kind == "downstream_risk")
            .expect("a renamed contract surface with 3 consumers carries a downstream risk");
        // GREEN (post-fix): demoted to attention. Pre-fix this was blocking/error
        // with a WouldBlock verdict — the previously shipped bug.
        assert!(
            !finding.blocking,
            "a positional-safe rename must not block the shadow gate"
        );
        assert_eq!(finding.severity, "warning");
        assert!(
            finding
                .message
                .contains("pass positionally — no runtime break"),
            "the demoted message carries the positional-safety proof for parity with \
             the inline channel; got: {}",
            finding.message
        );
        assert!(
            finding
                .message
                .contains("3 graph-known downstream entity(ies)"),
            "message names the consumer count; got: {}",
            finding.message
        );
        assert_eq!(policy.verdict, ShadowGateVerdict::NeedsAttention);
        assert_ne!(policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    #[test]
    fn shadow_downstream_risk_blocks_rename_with_default_change() {
        // Even complete positional call-shape evidence cannot certify a rename
        // with a simultaneous default change as runtime-neutral. The default is
        // part of the callable contract independently of the observed callers.
        let review = positional_rename_review_with_signatures(
            "def makefile_target(ext, args=1)",
            "def makefile_target(ext, lines=2)",
            crate::impact::ConsumerCallShapeSummary {
                caller_keyword_names: std::collections::BTreeSet::new(),
                any_var_keyword_caller: false,
                all_consumers_shaped_calls: true,
            },
        );
        let policy = derive_policy(&review, &[], &[]);
        let finding = policy
            .findings
            .iter()
            .find(|finding| finding.kind == "downstream_risk")
            .expect("a renamed surface with a changed default carries downstream risk");
        assert!(finding.blocking, "changed defaults must stay blocking");
        assert_eq!(finding.severity, "error");
        assert!(
            !finding.message.contains("no runtime break"),
            "changed defaults must not carry the positional-safe proof"
        );
        assert_eq!(policy.verdict, ShadowGateVerdict::WouldBlock);
    }

    #[test]
    fn shadow_treats_collector_rename_as_neutral_but_role_change_as_blocking() {
        let collector_rename = positional_rename_review_with_signatures(
            "def makefile_target(ext, *args, **kwargs)",
            "def makefile_target(ext, *items, **options)",
            crate::impact::ConsumerCallShapeSummary::default(),
        );
        let neutral = derive_policy(&collector_rename, &[], &[]);
        assert_eq!(neutral.verdict, ShadowGateVerdict::Pass);
        assert!(
            neutral
                .findings
                .iter()
                .all(|finding| finding.kind != "downstream_risk"),
            "collector-only local binding renames are not contract-surface risk"
        );

        let role_change = positional_rename_review_with_signatures(
            "def makefile_target(ext, *args)",
            "def makefile_target(ext, **args)",
            crate::impact::ConsumerCallShapeSummary::default(),
        );
        let blocking = derive_policy(&role_change, &[], &[]);
        assert_eq!(blocking.verdict, ShadowGateVerdict::WouldBlock);
        assert!(blocking
            .findings
            .iter()
            .any(|finding| finding.kind == "downstream_risk" && finding.blocking));
    }

    /// Negative-control helper: a rename we cannot prove runtime-neutral must keep
    /// blocking the shadow gate — guards against over-suppression.
    fn assert_positional_rename_stays_blocking(
        call_shapes: crate::impact::ConsumerCallShapeSummary,
        case: &str,
    ) {
        let review = positional_rename_review(call_shapes);
        let policy = derive_policy(&review, &[], &[]);
        let finding = policy
            .findings
            .iter()
            .find(|f| f.kind == "downstream_risk")
            .unwrap_or_else(|| panic!("{case}: expected a downstream_risk finding"));
        assert!(
            finding.blocking,
            "{case}: an unprovable rename must stay blocking (no over-suppression)"
        );
        assert_eq!(finding.severity, "error", "{case}: stays error severity");
        assert!(
            !finding.message.contains("no runtime break"),
            "{case}: must not carry the positional-safe proof"
        );
        assert_eq!(
            policy.verdict,
            ShadowGateVerdict::WouldBlock,
            "{case}: a rename that is not provably neutral still blocks"
        );
    }

    #[test]
    fn shadow_downstream_risk_blocks_keyword_caller_rename() {
        // A consumer passes the RENAMED parameter (`args`) by keyword, so the
        // rename strands it. Stays blocking.
        let mut kw = std::collections::BTreeSet::new();
        kw.insert("args".to_string());
        assert_positional_rename_stays_blocking(
            crate::impact::ConsumerCallShapeSummary {
                caller_keyword_names: kw,
                any_var_keyword_caller: false,
                all_consumers_shaped_calls: true,
            },
            "keyword-caller",
        );
    }

    #[test]
    fn shadow_downstream_risk_blocks_var_keyword_caller_rename() {
        // A consumer forwards `**kwargs`; its keyword set is unknown and could
        // carry the renamed name. Stays blocking.
        assert_positional_rename_stays_blocking(
            crate::impact::ConsumerCallShapeSummary {
                caller_keyword_names: std::collections::BTreeSet::new(),
                any_var_keyword_caller: true,
                all_consumers_shaped_calls: true,
            },
            "var-keyword-caller",
        );
    }

    #[test]
    fn shadow_downstream_risk_blocks_unshaped_consumer_rename() {
        // A counted consumer carries no call-shape evidence (non-call edge or an
        // uncaptured shape), so the rename cannot be proven safe. Stays blocking.
        assert_positional_rename_stays_blocking(
            crate::impact::ConsumerCallShapeSummary {
                caller_keyword_names: std::collections::BTreeSet::new(),
                any_var_keyword_caller: false,
                all_consumers_shaped_calls: false,
            },
            "unshaped-consumer",
        );
    }

    #[test]
    fn shadow_demoted_rename_message_is_deterministic() {
        // The demoted message reads only a count and sorted BTreeSet call_shapes,
        // so repeated evaluation must be byte-identical (citable-gate determinism).
        let call_shapes = crate::impact::ConsumerCallShapeSummary {
            caller_keyword_names: std::collections::BTreeSet::new(),
            any_var_keyword_caller: false,
            all_consumers_shaped_calls: true,
        };
        let message_of = || {
            let review = positional_rename_review(call_shapes.clone());
            derive_policy(&review, &[], &[])
                .findings
                .into_iter()
                .find(|f| f.kind == "downstream_risk")
                .expect("downstream_risk present")
                .message
        };
        assert_eq!(
            message_of(),
            message_of(),
            "the demoted rename message must be byte-identical across runs"
        );
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
        let artifact_id = ArtifactId::new();
        let old_entry = TreeEntry::blob(Hash256::from_bytes([11; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([12; 32]), false);

        let base = change_with_deltas(
            change_id(0x61),
            vec![],
            vec![
                EntityDelta::Added {
                    new: sensor.clone(),
                },
                EntityDelta::Added { new: app.clone() },
            ],
            vec![],
            vec![tree_add(artifact_id, "src/sensor.c", old_entry)],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(0x62),
            vec![base_id],
            vec![],
            vec![],
            vec![tree_update(
                artifact_id,
                "src/sensor.c",
                old_entry,
                "src/sensor.c",
                new_entry,
            )],
        );
        let head_id = head.id;
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
    fn removed_entity_under_historical_path_does_not_hide_structural_move() {
        // Historical rename shape: the exact artifact moves while the removed
        // entity still carries the pre-rename file origin. Exact old-path
        // equality accounts for the entity content, but an entity delta does
        // not prove the move or the artifact's new bytes. The structural
        // transition therefore remains visible and fail-closed.
        let graph = InMemoryGraph::new();
        let legacy = entity_with_span(
            "animate",
            "src/shared/keyed-each.js",
            105,
            EntityRole::Source,
        );
        graph.upsert_entity(&legacy).unwrap();
        let artifact_id = ArtifactId::new();
        let old_entry = TreeEntry::blob(Hash256::from_bytes([21; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([22; 32]), false);

        let base = change_with_deltas(
            change_id(0x71),
            vec![],
            vec![EntityDelta::Added {
                new: legacy.clone(),
            }],
            vec![],
            vec![tree_add(artifact_id, "src/shared/keyed-each.js", old_entry)],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(0x72),
            vec![base_id],
            vec![EntityDelta::Removed {
                old: legacy.clone(),
            }],
            vec![],
            vec![tree_update(
                artifact_id,
                "src/shared/keyed-each.js",
                old_entry,
                "src/internal/keyed-each.js",
                new_entry,
            )],
        );
        let head_id = head.id;
        graph.create_change(&base).unwrap();
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();

        let gap = report
            .evidence_gaps
            .iter()
            .find(|gap| {
                gap.kind == "artifact_structure_change"
                    && gap.subject == "src/internal/keyed-each.js"
            })
            .expect("the move-plus-edit must remain explicit despite an old-path entity match");
        assert!(gap_blocks_pass(gap));
        assert_eq!(report.policy.verdict, ShadowGateVerdict::NeedsAttention);
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

        let base = change_with_deltas(
            change_id(0x71),
            vec![],
            vec![EntityDelta::Added {
                new: widget_v1.clone(),
            }],
            vec![],
            vec![],
        );
        let base_id = base.id;
        let head = change_with_deltas(
            change_id(0x72),
            vec![base_id],
            vec![EntityDelta::Modified {
                old: widget_v1,
                new: widget_v2,
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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

            let base = change_with_deltas(
                change_id(0x73),
                vec![],
                vec![
                    EntityDelta::Added {
                        new: target_v1.clone(),
                    },
                    EntityDelta::Added {
                        new: caller.clone(),
                    },
                ],
                vec![],
                vec![],
            );
            let base_id = base.id;
            let head = change_with_deltas(
                change_id(0x74),
                vec![base_id],
                vec![EntityDelta::Modified {
                    old: target_v1,
                    new: target_v2,
                }],
                vec![],
                vec![],
            );
            let head_id = head.id;
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
        let artifact_id = ArtifactId::new();
        let old_entry = TreeEntry::blob(old_hash, false);
        let new_entry = TreeEntry::blob(new_hash, false);
        let base = change_with_deltas(
            change_id(0x91),
            vec![],
            vec![EntityDelta::Added {
                new: sensor.clone(),
            }],
            vec![],
            vec![tree_add(artifact_id, "src/sensor.c", old_entry)],
        );
        let base_id = base.id;
        graph.create_change(&base).unwrap();
        let at_head = GraphAtRef::materialize(&graph, &base_id).unwrap();

        let delta = tree_update(
            artifact_id,
            "src/sensor.c",
            old_entry,
            "src/sensor.c",
            new_entry,
        );
        let changes = vec![change_with_deltas(
            change_id(0x92),
            vec![base_id],
            vec![],
            vec![],
            vec![delta.clone()],
        )];
        let base_tree = graph.resolve_tree_at(&base_id).unwrap();
        let head_tree = base_tree.apply(&[delta]).unwrap();
        let changed_artifacts = collect_changed_artifacts(&base_tree, &head_tree);
        let artifact_activity = collect_artifact_activity(&changes);

        let review = empty_review();

        let (gaps, findings) = collect_evidence_gaps(
            &review,
            &changes,
            &[],
            &changed_artifacts,
            &artifact_activity,
            Some(&at_head),
            Some(&blobs),
        );
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
        let (gaps_no_blob, findings_no_blob) = collect_evidence_gaps(
            &review,
            &changes,
            &[],
            &changed_artifacts,
            &artifact_activity,
            Some(&at_head),
            None,
        );
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
        padded_history_graph_with_root(graph, first_deltas, second_deltas, n).1
    }

    fn padded_history_graph_with_root(
        graph: &InMemoryGraph,
        first_deltas: Vec<EntityDelta>,
        second_deltas: Vec<EntityDelta>,
        n: u8,
    ) -> (SemanticChangeId, SemanticChangeId) {
        let mut prev: Option<SemanticChangeId> = None;
        let mut root = None;
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
            root.get_or_insert(change.id);
            prev = Some(change.id);
        }
        (
            root.expect("chain is non-empty"),
            prev.expect("chain is non-empty"),
        )
    }

    // An ancestry reference the graph cannot produce costs the window twice:
    // the unresolved change's deltas never land, and its own ancestry is never
    // enqueued. A clean scan of whatever remains reachable is therefore not
    // evidence that no revert exists, so the channel must report the deficit
    // rather than absorb it and certify silence.
    #[test]
    fn revert_history_unresolvable_ancestry_reports_incomplete_gap() {
        let graph = InMemoryGraph::new();
        let reachable_tail = padded_history_graph(&graph, vec![], vec![], 30);
        let dangling = change_id(199);
        let base = change_with_deltas(
            change_id(150),
            vec![reachable_tail, dangling],
            vec![],
            vec![],
            vec![],
        );
        let base_id = base.id;
        graph.create_change(&base).unwrap();

        let (_, gaps) =
            crate::revert_history::collect_revert_history_findings(&graph, &base_id, &[]).unwrap();

        let gap = gaps
            .iter()
            .find(|g| g.kind == "revert_history_incomplete_ancestry")
            .expect("an unresolvable ancestry reference must be reported as an evidence gap");
        assert!(
            gap.detail.contains(&dangling.to_string()),
            "the gap must name the unresolved change, got: {}",
            gap.detail
        );
        assert!(
            !gaps.iter().any(|g| g.kind == "revert_history_shallow"),
            "ample reachable depth must not also report the shallow gap: the two \
             deficits are independent"
        );
    }

    // Negative control for the guard above: a fully resolvable ancestry must
    // stay silent, or the gap becomes noise on every healthy review.
    #[test]
    fn revert_history_complete_ancestry_reports_no_gap() {
        let graph = InMemoryGraph::new();
        let base_id = padded_history_graph(&graph, vec![], vec![], 30);

        let (_, gaps) =
            crate::revert_history::collect_revert_history_findings(&graph, &base_id, &[]).unwrap();

        assert!(
            gaps.is_empty(),
            "a complete 30-change ancestry must report no revert-history gap, got: {:?}",
            gaps.iter().map(|g| g.kind.as_str()).collect::<Vec<_>>()
        );
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
            vec![EntityDelta::Added {
                new: original.clone(),
            }],
            vec![EntityDelta::Removed {
                old: original.clone(),
            }],
            30,
        );
        graph.upsert_entity(&readded).unwrap();
        let head = change_with_deltas(
            change_id(200),
            vec![base_id],
            vec![EntityDelta::Added {
                new: readded.clone(),
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
    fn revert_history_modified_content_reintroduction_is_evidence_only() {
        // c1 adds `retry_budget`, c2 removes it, padding to depth 30, then the
        // head re-adds a same-named public function whose body DIFFERS (a new
        // behavior fingerprint). A name+kind match with modified content is weak
        // temporal evidence — a same-named surface recurs naturally and the
        // namesake may live in another file — so it is reported but must not
        // move the verdict off pass.
        let graph = InMemoryGraph::new();
        let mut original = entity_with_span("retry_budget", "src/net.rs", 40, EntityRole::Source);
        original.fingerprint.behavior_hash = Hash256::from_bytes([7; 32]);
        let base_id = padded_history_graph(
            &graph,
            vec![EntityDelta::Added {
                new: original.clone(),
            }],
            vec![EntityDelta::Removed {
                old: original.clone(),
            }],
            30,
        );
        let mut readded = entity_with_span("retry_budget", "src/net.rs", 77, EntityRole::Source);
        readded.fingerprint.behavior_hash = Hash256::from_bytes([8; 32]);
        graph.upsert_entity(&readded).unwrap();
        let head = change_with_deltas(
            change_id(204),
            vec![base_id],
            vec![EntityDelta::Added {
                new: readded.clone(),
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        let finding = report
            .policy
            .findings
            .iter()
            .find(|f| f.message.contains("with modified content"))
            .expect("modified-content reintroduction must still be reported");
        assert_eq!(
            finding.kind, "revert_history_incidental",
            "a modified-content match is weak evidence and must not gate"
        );
        assert_eq!(finding.severity, "info");
        assert_eq!(report.policy.verdict, ShadowGateVerdict::Pass);
    }

    #[test]
    fn revert_history_recent_addition_removal_is_evidence_only() {
        // c2 adds `beta_flag`; the head removes that exact entity id. Deleting
        // something that only just landed is revert-shaped and must be called
        // out, but benign-60 proved the signal is too weak to drive the gate
        // without an independent risk channel.
        let graph = InMemoryGraph::new();
        let recent = entity_with_span("beta_flag", "src/flags.rs", 12, EntityRole::Source);
        let base_id = padded_history_graph(
            &graph,
            vec![],
            vec![EntityDelta::Added {
                new: recent.clone(),
            }],
            30,
        );
        let head = change_with_deltas(
            change_id(201),
            vec![base_id],
            vec![EntityDelta::Removed {
                old: recent.clone(),
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        let finding = report
            .policy
            .findings
            .iter()
            .find(|f| f.kind == "revert_history_incidental")
            .expect("recent-addition removal must produce an evidence-only finding");
        assert!(
            finding.message.contains("revert-shaped removal"),
            "got: {}",
            finding.message
        );
        assert_eq!(finding.severity, "info");
        assert_eq!(report.policy.verdict, ShadowGateVerdict::Pass);
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
            vec![EntityDelta::Added {
                new: unrelated.clone(),
            }],
            vec![EntityDelta::Removed {
                old: unrelated.clone(),
            }],
            30,
        );
        graph.upsert_entity(&fresh).unwrap();
        let head = change_with_deltas(
            change_id(202),
            vec![base_id],
            vec![EntityDelta::Added { new: fresh }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
        let head = change_with_deltas(
            change_id(203),
            vec![base_id],
            vec![EntityDelta::Added { new: fresh }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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
            vec![EntityDelta::Added {
                new: original.clone(),
            }],
            vec![],
            29,
        );
        let base = change_with_deltas(
            change_id(150),
            vec![pad_tail],
            vec![EntityDelta::Removed {
                old: original.clone(),
            }],
            vec![],
            vec![],
        );
        let base_id = base.id;
        graph.create_change(&base).unwrap();
        graph.upsert_entity(&readded).unwrap();
        let head = change_with_deltas(
            change_id(151),
            vec![base_id],
            vec![EntityDelta::Added { new: readded }],
            vec![],
            vec![],
        );
        let head_id = head.id;
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

    #[test]
    fn body_reversion_to_older_revision_flags() {
        // v1 -> v2 -> (head) back to v1's body: the head un-does the v2 edit.
        // An ordinary new edit (v3 with a fresh body) must NOT match.
        let graph = InMemoryGraph::new();
        let mut v1 = entity_with_span("compute", "src/calc.rs", 10, EntityRole::Source);
        v1.fingerprint.behavior_hash = Hash256::from_bytes([1; 32]);
        let mut v2 = v1.clone();
        v2.fingerprint.behavior_hash = Hash256::from_bytes([2; 32]);
        let mut v_back = v2.clone();
        v_back.fingerprint.behavior_hash = Hash256::from_bytes([1; 32]);

        let pad_tail = padded_history_graph(
            &graph,
            vec![EntityDelta::Added { new: v1.clone() }],
            vec![EntityDelta::Modified {
                old: v1.clone(),
                new: v2.clone(),
            }],
            30,
        );
        graph.upsert_entity(&v_back).unwrap();
        let head = change_with_deltas(
            change_id(210),
            vec![pad_tail],
            vec![EntityDelta::Modified {
                old: v2.clone(),
                new: v_back,
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(pad_tail, head_id)).unwrap();
        // A single entity reverting is incidental: reported at info severity,
        // never verdict-driving (small bodies recur naturally in long
        // histories — the v7 backtest measured 5/6 benign regressions when
        // singletons gated).
        let finding = report
            .policy
            .findings
            .iter()
            .find(|f| f.kind == "revert_history_incidental")
            .expect("a lone body reversion must surface as incidental");
        assert!(
            finding.message.contains("revert-shaped body reversion"),
            "got: {}",
            finding.message
        );
        assert_eq!(finding.severity, "info");
        assert!(
            !report
                .policy
                .findings
                .iter()
                .any(|f| f.kind == "revert_history"),
            "a lone body reversion must not produce the gating kind"
        );

        // Control: an ordinary forward edit must not produce the finding.
        let graph2 = InMemoryGraph::new();
        let mut v3 = v2.clone();
        v3.fingerprint.behavior_hash = Hash256::from_bytes([3; 32]);
        let pad_tail2 = padded_history_graph(
            &graph2,
            vec![EntityDelta::Added { new: v1.clone() }],
            vec![EntityDelta::Modified {
                old: v1.clone(),
                new: v2.clone(),
            }],
            30,
        );
        graph2.upsert_entity(&v3).unwrap();
        let head2 = change_with_deltas(
            change_id(211),
            vec![pad_tail2],
            vec![EntityDelta::Modified {
                old: v2.clone(),
                new: v3,
            }],
            vec![],
            vec![],
        );
        let head2_id = head2.id;
        graph2.create_change(&head2).unwrap();
        let report2 = build_shadow_report(&graph2, &request(pad_tail2, head2_id)).unwrap();
        assert!(
            !report2
                .policy
                .findings
                .iter()
                .any(|f| f.kind == "revert_history"),
            "an ordinary forward edit must not read as a body reversion"
        );
    }

    #[test]
    fn coherent_public_leaf_body_reversion_gates() {
        // Two entities whose new bodies both restore states un-done by the
        // SAME historical change: a coherent snapshot restoration — the true
        // revert shape — gates as a warning.
        let graph = InMemoryGraph::new();
        let mut a1 = entity_with_span("alpha", "src/a.rs", 5, EntityRole::Source);
        a1.fingerprint.behavior_hash = Hash256::from_bytes([11; 32]);
        let mut b1 = entity_with_span("beta", "src/b.rs", 9, EntityRole::Source);
        b1.fingerprint.behavior_hash = Hash256::from_bytes([21; 32]);
        let mut a2 = a1.clone();
        a2.fingerprint.behavior_hash = Hash256::from_bytes([12; 32]);
        let mut b2 = b1.clone();
        b2.fingerprint.behavior_hash = Hash256::from_bytes([22; 32]);

        // c1 adds both; c2 edits BOTH (the change the head un-does); padding.
        let mut prev: Option<SemanticChangeId> = None;
        for i in 1..=30u8 {
            let deltas = match i {
                1 => vec![
                    EntityDelta::Added { new: a1.clone() },
                    EntityDelta::Added { new: b1.clone() },
                ],
                2 => vec![
                    EntityDelta::Modified {
                        old: a1.clone(),
                        new: a2.clone(),
                    },
                    EntityDelta::Modified {
                        old: b1.clone(),
                        new: b2.clone(),
                    },
                ],
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
            prev = Some(change.id);
        }
        let base_id = prev.unwrap();
        let mut a_back = a2.clone();
        a_back.fingerprint.behavior_hash = Hash256::from_bytes([11; 32]);
        let mut b_back = b2.clone();
        b_back.fingerprint.behavior_hash = Hash256::from_bytes([21; 32]);
        graph.upsert_entity(&a_back).unwrap();
        graph.upsert_entity(&b_back).unwrap();
        let head = change_with_deltas(
            change_id(220),
            vec![base_id],
            vec![
                EntityDelta::Modified {
                    old: a2.clone(),
                    new: a_back,
                },
                EntityDelta::Modified {
                    old: b2.clone(),
                    new: b_back,
                },
            ],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        let gating: Vec<_> = report
            .policy
            .findings
            .iter()
            .filter(|f| f.kind == "revert_history")
            .collect();
        assert_eq!(
            gating.len(),
            2,
            "both public-leaf reversions must gate, got findings: {:?}",
            report
                .policy
                .findings
                .iter()
                .map(|f| (&f.kind, &f.message))
                .collect::<Vec<_>>()
        );
        assert!(gating.iter().all(|f| f.severity == "warning"));
        assert!(gating[0].message.contains("un-doing the same change"));
        assert_eq!(report.policy.verdict, ShadowGateVerdict::NeedsAttention);
    }

    #[test]
    fn coherent_module_body_reversion_does_not_gate() {
        // Module/class aggregates co-revert for free (a module mirrors its
        // file), so a coherent group with no public leaf stays informational —
        // the false-coherence protection that motivated the leaf filter.
        let graph = InMemoryGraph::new();
        let mut a1 = entity_with_span("mod_a", "src/a.rs", 1, EntityRole::Source);
        a1.kind = EntityKind::Module;
        a1.fingerprint.behavior_hash = Hash256::from_bytes([11; 32]);
        let mut b1 = entity_with_span("_helper", "src/b.rs", 9, EntityRole::Source);
        b1.visibility = Visibility::Private;
        b1.fingerprint.behavior_hash = Hash256::from_bytes([21; 32]);
        let mut a2 = a1.clone();
        a2.fingerprint.behavior_hash = Hash256::from_bytes([12; 32]);
        let mut b2 = b1.clone();
        b2.fingerprint.behavior_hash = Hash256::from_bytes([22; 32]);

        let mut prev: Option<SemanticChangeId> = None;
        for i in 1..=30u8 {
            let deltas = match i {
                1 => vec![
                    EntityDelta::Added { new: a1.clone() },
                    EntityDelta::Added { new: b1.clone() },
                ],
                2 => vec![
                    EntityDelta::Modified {
                        old: a1.clone(),
                        new: a2.clone(),
                    },
                    EntityDelta::Modified {
                        old: b1.clone(),
                        new: b2.clone(),
                    },
                ],
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
            prev = Some(change.id);
        }
        let base_id = prev.unwrap();
        let mut a_back = a2.clone();
        a_back.fingerprint.behavior_hash = Hash256::from_bytes([11; 32]);
        let mut b_back = b2.clone();
        b_back.fingerprint.behavior_hash = Hash256::from_bytes([21; 32]);
        graph.upsert_entity(&a_back).unwrap();
        graph.upsert_entity(&b_back).unwrap();
        let head = change_with_deltas(
            change_id(220),
            vec![base_id],
            vec![
                EntityDelta::Modified {
                    old: a2.clone(),
                    new: a_back,
                },
                EntityDelta::Modified {
                    old: b2.clone(),
                    new: b_back,
                },
            ],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(base_id, head_id)).unwrap();
        assert!(
            report
                .policy
                .findings
                .iter()
                .all(|f| f.kind != "revert_history"),
            "module/private coherent reversion must not gate: {:?}",
            report
                .policy
                .findings
                .iter()
                .map(|f| &f.kind)
                .collect::<Vec<_>>()
        );
        assert_eq!(report.policy.verdict, ShadowGateVerdict::Pass);
    }

    #[test]
    fn future_change_never_supplies_prior_bodies() {
        // A change made AFTER the head trivially has the head's result as its
        // pre-state, so a graph holding changes newer than the reviewed head
        // (other reviews' hydrations, a warmed shared graph) must never let
        // them serve as "prior" bodies: that reads the head's own future back
        // as revert evidence.
        let graph = InMemoryGraph::new();
        let mut v1 = entity_with_span("gamma", "src/g.rs", 5, EntityRole::Source);
        v1.fingerprint.behavior_hash = Hash256::from_bytes([31; 32]);
        let mut v2 = v1.clone();
        v2.fingerprint.behavior_hash = Hash256::from_bytes([32; 32]);
        let pad_tail = padded_history_graph(
            &graph,
            vec![EntityDelta::Added { new: v1.clone() }],
            vec![EntityDelta::Modified {
                old: v1.clone(),
                new: v2.clone(),
            }],
            30,
        );
        // Head gives gamma a body it has NEVER carried before.
        let mut v_new = v2.clone();
        v_new.fingerprint.behavior_hash = Hash256::from_bytes([33; 32]);
        graph.upsert_entity(&v_new).unwrap();
        let head = change_with_deltas(
            change_id(240),
            vec![pad_tail],
            vec![EntityDelta::Modified {
                old: v2.clone(),
                new: v_new.clone(),
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();
        // A future edit whose pre-state IS the head's result.
        let mut v_future = v_new.clone();
        v_future.fingerprint.behavior_hash = Hash256::from_bytes([34; 32]);
        let future = change_with_deltas(
            change_id(241),
            vec![head_id],
            vec![EntityDelta::Modified {
                old: v_new.clone(),
                new: v_future,
            }],
            vec![],
            vec![],
        );
        graph.create_change(&future).unwrap();

        let report = build_shadow_report(&graph, &request(pad_tail, head_id)).unwrap();
        assert!(
            report
                .policy
                .findings
                .iter()
                .all(|f| !f.kind.starts_with("revert_history")),
            "a future change must never read as revert history: {:?}",
            report
                .policy
                .findings
                .iter()
                .map(|f| (&f.kind, &f.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merge_branch_side_never_supplies_prior_bodies() {
        // Changes reachable only through the head's merge (the branch being
        // merged) are not part of the BASE's causal past; their pre-states
        // must not serve as prior bodies either.
        let graph = InMemoryGraph::new();
        let mut v1 = entity_with_span("delta_fn", "src/d.rs", 5, EntityRole::Source);
        v1.fingerprint.behavior_hash = Hash256::from_bytes([51; 32]);
        let mut v2 = v1.clone();
        v2.fingerprint.behavior_hash = Hash256::from_bytes([52; 32]);
        let (root_id, pad_tail) = padded_history_graph_with_root(
            &graph,
            vec![EntityDelta::Added { new: v1.clone() }],
            vec![EntityDelta::Modified {
                old: v1.clone(),
                new: v2.clone(),
            }],
            30,
        );
        // The merge result: a body delta_fn never carried on the base lineage.
        let mut v_new = v2.clone();
        v_new.fingerprint.behavior_hash = Hash256::from_bytes([53; 32]);
        // Branch-side change (parented off c1, reachable only via the merge):
        // its pre-state equals the merge result's body.
        let mut v_branch = v_new.clone();
        v_branch.fingerprint.behavior_hash = Hash256::from_bytes([54; 32]);
        let branch = change_with_deltas(
            change_id(250),
            vec![root_id],
            vec![EntityDelta::Modified {
                old: v_new.clone(),
                new: v_branch,
            }],
            vec![],
            vec![],
        );
        let branch_id = branch.id;
        graph.create_change(&branch).unwrap();
        graph.upsert_entity(&v_new).unwrap();
        let head = change_with_deltas(
            change_id(251),
            vec![pad_tail, branch_id],
            vec![EntityDelta::Modified {
                old: v2.clone(),
                new: v_new.clone(),
            }],
            vec![],
            vec![],
        );
        let head_id = head.id;
        graph.create_change(&head).unwrap();

        let report = build_shadow_report(&graph, &request(pad_tail, head_id)).unwrap();
        assert!(
            report
                .policy
                .findings
                .iter()
                .all(|f| !f.kind.starts_with("revert_history")),
            "branch-side changes must never read as revert history: {:?}",
            report
                .policy
                .findings
                .iter()
                .map(|f| (&f.kind, &f.message))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn equivalent_fanout_is_non_gating_info() {
        // The downgraded fanout kind maps to `info`, so gate_findings (which
        // filters `severity != "info"`) drops it: an equivalent body change
        // never feeds the verdict, while the attention fanout stays a warning
        // that does.
        assert_eq!(
            finding_severity(InlineCommentKind::ConsumerFanoutEquivalent),
            "info"
        );
        assert_eq!(
            finding_severity(InlineCommentKind::ConsumerFanout),
            "warning"
        );
        assert_eq!(
            finding_kind_label(InlineCommentKind::ConsumerFanoutEquivalent),
            "consumer_fanout_equivalent"
        );
        assert!(!is_blocking(InlineCommentKind::ConsumerFanoutEquivalent));
    }
}
