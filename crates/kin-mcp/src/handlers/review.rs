// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use super::repository_authority::RequestRepositoryAuthority;
use kin_model::graph::GraphStore;
use kin_model::ids::SemanticChangeId;
use kin_review::write::{PlannedReviewEvent, ReviewGroup, ReviewWrite};
use kin_review::{format_review, SemanticReview};

use crate::error::{McpError, Result};
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

use super::common::*;

pub const SEMANTIC_DIFF_DESC: &str = "\
Compute an entity-level diff — what declarations were added, removed, or changed — \
rather than a line-by-line text diff. You can target it four ways (pick one): base/head \
semantic change IDs, a set of entity_ids (current state vs. their history), file paths \
(resolved to their entities), or a list of change_ids to combine. Reach for it when you \
want to understand a change in terms of the code's structure — \"which functions/types \
actually changed?\" — instead of reading raw hunks, which is far more meaningful for \
review and impact reasoning. When you also want the downstream blast radius or a risk \
summary alongside the diff, use impact_analysis or semantic_review.";

pub fn handle_semantic_diff<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let diff = resolve_diff(args, store)?;
    let formatted = kin_review::format_diff(&diff);
    Ok(ToolCallResult::text(formatted))
}

pub const IMPACT_ANALYSIS_DESC: &str = "\
Analyze the downstream impact of a change: starting from what changed, walk the \
relation graph to find every entity that could be affected. Target it four ways (one at \
a time): base/head change IDs, entity_ids, file paths, or a list of change_ids to \
combine. Optionally include active agent traffic on the impacted entities so you can see \
who else is working nearby. Reach for it before merging or refactoring to gauge blast \
radius, answering \"if I change this, what else might break?\", from the graph in one \
call instead of hand-tracing callers. Pair it with semantic_diff (what changed) or use \
semantic_review when you want diff + impact + risk together in a single report. \
Per-entity, `consumer_count` is every direct inbound consumer, and it is never narrowed \
without saying so: `external_consumer_count`, `test_consumer_count` and \
`derived_consumer_count` name each class beside it and sum to it, so a zero is a zero and \
an exclusion has a name. One set sits outside it and is reported rather than dropped: a \
consumer changed in this same diff is counted in `consumers_migrated_in_diff`, which is \
why this count matches what `find_references` reports for the same entity id except where \
a consumer co-changed, and the migrated count is exactly that difference. Read a \
break against `external_consumer_count`, since a test that breaks with the code it tests \
was never stranded, and read a used/unused claim against `consumer_count`. \
`proven_consumer_count` narrows the external count to edges resolved above `name_only`. \
`covering_tests` is a \
graph-observed lower bound, labeled beside every count rather than a claim about every \
test in the working copy, and it also counts tests two hops out, so it is wider than \
`test_consumer_count` and cannot be subtracted from anything. This response carries \
counts and buckets rather than ranked paths: the per-hop ranked report, where every step \
carries its own `resolution` and a confidence score, is produced only by \
`kin impact --json` on the CLI and is not reachable from here. Read that used/unused claim \
against the proven count as well: a \
call edge matched by bare method name is a candidate, not a fact. The response also \
carries an additive `negative` object whose `safe_to_conclude_absent` flag says whether \
this graph could have seen the impact it reports missing: the verdicts are read off \
cross-file call, import and reference edges, so on a language whose reference edges this \
build cannot produce, or on a graph holding none of them, an empty blast radius means \
the query could not observe what it was asked about rather than that nothing depends on \
the change. Check it before reading a zero consumer count as safe to change.";

/// The field a serialized impact row carries beside `covering_tests`, and the
/// one value it takes.
///
/// Named once rather than spelled at each surface. The budget-survival test in
/// [`crate::envelope`] builds its impact rows by hand, so a literal there would
/// go on asserting a spelling this producer had renamed, and the pair would
/// drift with both halves green.
pub(crate) const COVERING_TESTS_BOUND_KEY: &str = "covering_tests_bound";
/// See [`COVERING_TESTS_BOUND_KEY`].
pub(crate) const COVERING_TESTS_BOUND: &str = "graph_observed_lower_bound";

/// The blast-radius buckets of an [`kin_review::ImpactReport`] that serialize as
/// arrays of raw entities, paired with their key in the response object.
const IMPACT_ENTITY_BUCKETS: [&str; 4] = [
    "affected_callers",
    "affected_dependents",
    "affected_contract_consumers",
    "affected_tests",
];

/// Add the presentation fields and explicit bounds an impact response needs.
///
/// `ImpactReport` holds raw `Entity` values, so serializing it exposes only the
/// nested `span`, whose rows are the graph's 0-based tree-sitter positions. An
/// agent reading those numbers to locate an affected caller lands one line above
/// it. The convention used everywhere else applies here: `span` stays a faithful
/// serialization of graph truth (its byte offsets are read as offsets), and the
/// top-level `start_line`/`end_line` carry the editor-ready position.
fn annotate_impact_presentation_lines(
    result: &mut serde_json::Value,
    impact: &kin_review::ImpactReport,
) {
    let buckets: [&Vec<kin_model::Entity>; 4] = [
        &impact.affected_callers,
        &impact.affected_dependents,
        &impact.affected_contract_consumers,
        &impact.affected_tests,
    ];
    for (key, entities) in IMPACT_ENTITY_BUCKETS.iter().zip(buckets) {
        let Some(serde_json::Value::Array(rows)) = result.get_mut(*key) else {
            continue;
        };
        // `to_value` preserves order, so a positional zip stays aligned with the
        // entities the report actually carries.
        for (row, entity) in rows.iter_mut().zip(entities) {
            let Some(object) = row.as_object_mut() else {
                continue;
            };
            object.insert(
                "start_line".to_string(),
                serde_json::json!(entity_presentation_start_line(entity)),
            );
            object.insert(
                "end_line".to_string(),
                serde_json::json!(entity_presentation_end_line(entity)),
            );
        }
    }

    let Some(entity_impacts) = result
        .get_mut("entity_impacts")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for row in entity_impacts {
        let Some(object) = row.as_object_mut() else {
            continue;
        };
        if object.contains_key("covering_tests") {
            object.insert(
                COVERING_TESTS_BOUND_KEY.to_string(),
                serde_json::json!(COVERING_TESTS_BOUND),
            );
        }
    }
}

pub async fn handle_impact_analysis<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let depth = get_optional_u64(args, "depth", 3) as u32;
    let diff = resolve_diff(args, store)?;

    let impact =
        kin_review::analyze_impact(store, &diff).map_err(|e| McpError::Review(e.to_string()))?;

    let mut result = serde_json::to_value(&impact).map_err(McpError::Json)?;
    annotate_impact_presentation_lines(&mut result, &impact);

    if include_traffic {
        // Collect traffic for all changed entities.
        let mut all_traffic = Vec::new();
        for change in &diff.entity_changes {
            let traffic = sessions.get_traffic_near_entity(&change.entity_id);
            for summary in traffic {
                if !all_traffic
                    .iter()
                    .any(|t: &kin_model::session::IntentSummary| t.intent_id == summary.intent_id)
                {
                    all_traffic.push(summary);
                }
            }
        }
        if !all_traffic.is_empty() {
            result["active_traffic"] =
                serde_json::to_value(&all_traffic).map_err(McpError::Json)?;
        }
    }

    // ── Cross-repo federation via spine ──────────────────────────────────
    let repo_id = std::env::var("KIN_REPO_ID").unwrap_or_else(|_| "unknown".into());
    let changed_ids = diff.changed_entity_ids();
    let mut cross_repo_nodes: Vec<kin_spine::FederatedNode> = Vec::new();
    let mut spine_unavailable: Option<String> = None;

    for eid in &changed_ids {
        match fetch_spine_impact_typed(&repo_id, eid, depth).await {
            kin_spine::SpineQuery::Found(federated) => {
                for node in federated.nodes {
                    if node.repo_id != repo_id {
                        cross_repo_nodes.push(node);
                    }
                }
            }
            // Configured but a query failed — record the first reason so the
            // result reports the gap rather than silently omitting cross-repo
            // impact (which would read as "analyzed, none").
            kin_spine::SpineQuery::Unavailable(reason) => {
                spine_unavailable.get_or_insert(reason);
            }
            // No spine in this context (local-only MCP server): a quiet absence
            // of cross-repo impact is correct, so stay non-noisy.
            kin_spine::SpineQuery::NotConfigured => {}
        }
    }

    if !cross_repo_nodes.is_empty() {
        result["cross_repo_impact"] =
            serde_json::to_value(&cross_repo_nodes).map_err(McpError::Json)?;
    }
    if let Some(reason) = spine_unavailable {
        // Additive, failure-only field: present only when the spine was
        // expected but unreachable, so an empty/absent cross_repo_impact is
        // never mistaken for a healthy "no cross-repo impact" result.
        result["cross_repo_impact_status"] =
            serde_json::json!(format!("spine_unavailable: {reason}"));
    }

    // FIR-2452. Every `entity_impacts` row carrying no consumers is a
    // used/unused verdict a caller reads before changing or deleting something,
    // and it is read off the same cross-file reference edges `find_references`
    // reads. Until this observation existed, `impact_analysis` was the one
    // retrieval surface with no `negative` object at all, so the tool with the
    // highest blast radius per wrong absence was the only one outside the gate
    // every smaller one passes.
    //
    // The languages are the CHANGED entities' own. A verdict covers all of them
    // and the weakest governs, which is the same rule the batch reachability
    // surface applies for the same reason: one language whose reference edges
    // were never produced must not have its absences certified by a sibling
    // language that links cleanly. Unresolvable ids contribute no language
    // rather than a guessed one.
    let impact_languages = crate::edge_coverage::languages_of(
        &impact
            .changed_ids
            .iter()
            .filter_map(|id| store.get_entity(id).ok().flatten())
            .collect::<Vec<_>>(),
    );
    result[crate::edge_coverage::EDGE_COVERAGE_KEY] =
        crate::edge_coverage::observe_cross_file_reference_coverage_for_languages(
            store,
            &impact_languages,
            &IMPACT_REFERENCE_KINDS,
        );

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// The cross-file reference classes an impact verdict is read off, matching what
/// [`crate::negative::absence_cross_file_classes`] declares `impact_analysis`
/// depends on. Declaring one set and observing another is how a gate comes to
/// judge a class the answer never measured.
///
/// Public because the CLI's `kin impact` renders the same verdict over the same
/// classes (FIR-2524). Two consumers reading one declaration is the whole point;
/// a second copy in `kin-cli` would be the drift this comment already warns
/// about, arriving by the door it does not watch.
pub const IMPACT_REFERENCE_KINDS: [kin_model::relation::RelationKind; 3] = [
    kin_model::relation::RelationKind::Calls,
    kin_model::relation::RelationKind::Imports,
    kin_model::relation::RelationKind::References,
];

pub const SEMANTIC_REVIEW_DESC: &str = "\
Produce a complete semantic review of a change in one call: the entity-level diff, the \
downstream impact, and an overall risk assessment, combined into a single report. \
Target it four ways (one at a time): base/head change IDs, entity_ids, file paths, or a \
list of change_ids. Choose format='text' for a human-readable summary or format='json' \
for structured output suited to editor/CI integrations, and optionally fold in active \
agent traffic on the reviewed entities. Reach for it when you want the whole \"what \
changed, what it touches, how risky is it\" picture at once — it saves you from running \
semantic_diff and impact_analysis separately and stitching them together yourself. Use \
the narrower tools when you only need one of those facets.";

pub fn handle_semantic_review<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let format = get_optional_string_param(args, "format").unwrap_or_else(|| "text".into());
    let diff = resolve_diff(args, store)?;

    let review = SemanticReview::review_from_diff(diff, store)
        .map_err(|e| McpError::Review(e.to_string()))?;

    let formatted = format_review(&review);

    if format.eq_ignore_ascii_case("json") {
        let mut result = serde_json::to_value(&review).map_err(McpError::Json)?;
        // `semantic_review format=json` carries the same impact buckets
        // `impact_analysis` returns, so it gets the same 1-based presentation
        // lines. Annotating one and not the other left two agent surfaces
        // reporting the same entity's position under two conventions.
        if let Some(impact) = result.get_mut("impact") {
            annotate_impact_presentation_lines(impact, &review.impact);
        }
        if let Some(obj) = result.as_object_mut() {
            obj.insert(
                "summary".into(),
                serde_json::json!(format!("Risk: {:?}", review.risk.overall_risk)),
            );
            obj.insert("formatted".into(), serde_json::json!(formatted));
            if include_traffic {
                let traffic = collect_review_traffic_lines(&review, sessions);
                if !traffic.is_empty() {
                    obj.insert("active_traffic".into(), serde_json::json!(traffic));
                }
            }
        }
        let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
        return Ok(ToolCallResult::text(json));
    }

    if include_traffic {
        // Collect traffic for all entities in the diff.
        let traffic_lines = collect_review_traffic_lines(&review, sessions);

        if traffic_lines.is_empty() {
            Ok(ToolCallResult::text(formatted))
        } else {
            let with_traffic = format!(
                "{}\n\n--- Active Traffic ---\n{}",
                formatted,
                traffic_lines.join("\n")
            );
            Ok(ToolCallResult::text(with_traffic))
        }
    } else {
        Ok(ToolCallResult::text(formatted))
    }
}

fn collect_review_traffic_lines(
    review: &kin_review::Review,
    sessions: &SessionRegistry,
) -> Vec<String> {
    let mut traffic_lines = Vec::new();
    for change in &review.diff.entity_changes {
        let traffic = sessions.get_traffic_near_entity(&change.entity_id);
        for summary in &traffic {
            traffic_lines.push(format!(
                "  {} ({}) is {} entity {} [{}]",
                summary.vendor,
                summary.session_id,
                summary.task_description,
                change.entity_id,
                summary.lock_type_label(),
            ));
        }
    }
    traffic_lines
}

pub const SHADOW_GATE_REPORT_DESC: &str = "\
Run the shadow-mode merge gate over a PR-shaped change (base ref .. head ref) and return \
ONE report: changed entities, graph-proven blast radius, the policy verdict the gate \
WOULD have issued (report-only — shadow mode never blocks), the repair context a reviewer \
or agent needs to fix findings, explicit evidence gaps, and audit evidence for the \
evaluation. Refs accept branch names and semantic change IDs; imported Git commit SHAs \
resolve when their history has been imported into the graph. When the graph cannot prove \
something — unparsed files, missing spans, an empty impact signal — the report says so in \
`evidence_gaps` instead of passing silently. Reach for it to evaluate an AI-authored \
change before merge, or to feed a merge-gate dashboard.";

fn resolve_shadow_ref<G: GraphStore>(
    store: &G,
    reference: &str,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<SemanticChangeId> {
    if let Some(branch_name) = reference.strip_prefix("branch:") {
        return resolve_shadow_branch(store, branch_name, repository_authority);
    }

    if let Some(change_ref) = reference
        .strip_prefix("kin:")
        .or_else(|| reference.strip_prefix("change:"))
    {
        return resolve_shadow_change(store, change_ref);
    }

    if let Some(git_oid) = reference.strip_prefix("git:") {
        return resolve_shadow_git(store, git_oid, repository_authority);
    }

    if reference.len() == 40 {
        return resolve_shadow_git(store, reference, repository_authority);
    }

    if reference.len() == 64 {
        return resolve_shadow_change(store, reference);
    }

    resolve_shadow_branch(store, reference, repository_authority)
}

fn resolve_shadow_branch<G: GraphStore>(
    store: &G,
    branch_name: &str,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<SemanticChangeId> {
    let authority = repository_authority
        .ok_or_else(|| {
            McpError::Context(
                "graph authority gap: shadow ref resolution requires a startup-pinned local \
                 repository authority binding"
                    .to_string(),
            )
        })?
        .open()?;
    let ref_name = super::repository_authority::parse_branch_ref(branch_name)?;
    let change_id = authority.resolve_named_ref(&ref_name)?;
    ensure_shadow_change(store, change_id, branch_name)
}

fn resolve_shadow_change<G: GraphStore>(store: &G, change_ref: &str) -> Result<SemanticChangeId> {
    let change_id = parse_change_id(change_ref)?;
    ensure_shadow_change(store, change_id, change_ref)
}

fn ensure_shadow_change<G: GraphStore>(
    store: &G,
    change_id: SemanticChangeId,
    reference: &str,
) -> Result<SemanticChangeId> {
    match store.get_change(&change_id).map_err(McpError::graph)? {
        Some(_) => Ok(change_id),
        None => Err(McpError::InvalidParams(format!(
            "change '{}' resolved to {}, which is not materialized in graph authority",
            reference, change_id
        ))),
    }
}

fn resolve_shadow_git<G: GraphStore>(
    store: &G,
    git_oid: &str,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<SemanticChangeId> {
    let oid = super::repository_authority::parse_git_object_id(git_oid)?;
    let authority = repository_authority
        .ok_or_else(|| {
            McpError::Context(
                "graph authority gap: Git alias resolution requires a startup-pinned local \
                 repository authority binding"
                    .to_string(),
            )
        })?
        .open()?;
    let change_id = authority.resolve_git_oid(oid)?;
    ensure_shadow_change(store, change_id, git_oid)
}

pub fn handle_shadow_gate_report<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let base_ref = get_string_param(args, "base")?;
    let head_ref = get_string_param(args, "head")?;
    let resolved_base = resolve_shadow_ref(store, &base_ref, repository_authority)?;
    let resolved_head = resolve_shadow_ref(store, &head_ref, repository_authority)?;

    let request = kin_review::ShadowRequest {
        base_ref,
        head_ref,
        resolved_base,
        resolved_head,
        title: get_optional_string_param(args, "title"),
        source_url: get_optional_string_param(args, "source_url"),
        author: get_optional_string_param(args, "author"),
        actor: get_optional_string_param(args, "actor").unwrap_or_else(|| "mcp-client".into()),
    };

    let report = kin_review::build_shadow_report(store, &request)
        .map_err(|e| McpError::Review(e.to_string()))?;

    let json = serde_json::to_string_pretty(&report).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const ENTITY_HISTORY_DESC: &str = "\
Return the change history of a single entity — the ordered list of semantic changes \
that created, modified, or superseded it over time. Reach for it to answer \"how did \
this declaration get to its current form?\", to find the change IDs you can feed into \
semantic_diff/impact_analysis, or as a starting point for provenance questions. For \
who-made-the-change and approval status, kin_provenance_query builds on this. \
When no history comes back, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether \"no recorded history\" is authoritative or merely \"not indexed yet\".";

pub fn handle_entity_history<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    let history = store
        .get_entity_history(&entity_id)
        .map_err(McpError::graph)?;

    let json = serde_json::to_string_pretty(&history).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

// ── Review mutation handlers (Phase 11) ──

pub const REVIEW_CREATE_DESC: &str = "\
Open a new review over a set of changes and persist it in the graph. Scope it by \
base/head refs (branch names or change IDs), by KinLab-style scope_type + entity_ids, \
or by raw semantic scopes — and optionally seed a title, description, creator identity, \
and an initial reviewer list. Reach for it to start a code-review workflow that lives \
in graph truth (so decisions, notes, and discussions attach to entities, not just \
files), whether driven by a human, an assistant, or CI. Returns the new review's ID, \
which the other kin_review_* tools (decide, note_add, discuss, assign, get) operate on.";

pub fn handle_review_create<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_create(args, store)?, store)
}

fn plan_review_create<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    _store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::{
        Review, ReviewAssignment, ReviewCompletionState, ReviewDecisionState, ReviewId,
    };
    use kin_model::timestamp::Timestamp;

    let title = get_string_param(args, "title")?;
    let base = get_optional_string_param(args, "base").unwrap_or_else(|| "working-tree".into());
    let head = get_optional_string_param(args, "head").unwrap_or_else(|| "working-tree".into());
    let scopes = parse_review_create_scopes(args)?;
    let created_by = parse_identity_arg(args, "created_by", "created_by_kind", "mcp-client");
    // Optional, as the tool's schema says: a review may open with no reviewer.
    let reviewers = parse_optional_reviewer_list(args)?;
    let now = Timestamp::now();

    let review = Review {
        review_id: ReviewId::new(),
        title,
        base_ref: base,
        head_ref: head,
        state: ReviewDecisionState::Pending,
        completion: ReviewCompletionState::InReview,
        scopes,
        created_by: created_by.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let review_id = review.review_id;
    let assignments = (!reviewers.is_empty()).then(|| ReviewGroup {
        review_id,
        entries: reviewers
            .into_iter()
            .map(|reviewer| ReviewAssignment {
                review_id,
                reviewer: kin_model::IdentityRef::human(reviewer),
                assigned_at: now.clone(),
                assigned_by: created_by.clone(),
            })
            .collect(),
    });

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "title": review.title,
        "state": "pending",
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.create",
        review_id,
        details: format!(
            "review_id={}; title={}; base={}; head={}",
            review_id, review.title, review.base_ref, review.head_ref
        ),
        actor_label: created_by.name.clone(),
        refs: Some((review.base_ref.clone(), review.head_ref.clone())),
        write: ReviewWrite {
            review: Some(review),
            assignments,
            ..ReviewWrite::default()
        },
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_DECIDE_DESC: &str = "\
Record a reviewer's verdict on a review: approved, needs_work, or blocked, with an \
optional explanatory comment and reviewer identity. Reach for it to land the outcome of \
a review in graph truth so downstream gates (like kin_release_check's approval \
requirement) and other agents can see where the review stands. The decision is appended \
to the review's history rather than overwriting prior verdicts.";

pub fn handle_review_decide<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_decide(args, store)?, store)
}

fn plan_review_decide<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::ReviewDecision;
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let state_str = get_string_param(args, "state")?;
    let comment_str = get_optional_string_param(args, "comment")
        .or_else(|| get_optional_string_param(args, "summary"))
        .unwrap_or_default();
    let reviewer = parse_identity_arg(args, "reviewer", "reviewer_kind", "mcp-client");

    let state = parse_review_decision_state(&state_str)?;
    let mut review = existing_review(store, &review_id)?;

    let decision = ReviewDecision {
        state,
        comment: if comment_str.is_empty() {
            None
        } else {
            Some(comment_str)
        },
        reviewer: reviewer.clone(),
        decided_at: Timestamp::now(),
    };
    // The decision is history and the review's state is where it stands now, so
    // one event moves both: without this an approved review reads pending on
    // every surface that prints its state.
    review.state = state;
    review.updated_at = decision.decided_at.clone();
    let mut history = store
        .get_review_decisions(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    history.push(decision);

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "state": state_str,
        "reviewer": reviewer.name,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.decide",
        review_id,
        details: format!("review_id={review_id}; decision={state_str}"),
        actor_label: reviewer.name,
        refs: None,
        write: ReviewWrite {
            review: Some(review),
            decisions: Some(ReviewGroup {
                review_id,
                entries: history,
            }),
            ..ReviewWrite::default()
        },
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_NOTE_ADD_DESC: &str = "\
Attach a standalone note to a review, optionally anchored to a specific entity or file \
(and line). Reach for it to leave a non-blocking observation or comment that doesn't \
need a back-and-forth thread — \"FYI this also affects X\". Because notes can be scoped \
to an entity, they travel with that declaration in graph truth rather than being pinned \
to a line number that drifts. For a comment that expects replies, start a thread with \
kin_review_discuss instead.";

pub fn handle_review_note_add<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_note_add(args, store)?, store)
}

fn plan_review_note_add<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::{ReviewNote, ReviewNoteId};
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let body = get_string_param(args, "body")?;
    let scope = parse_optional_scope_arg(args)?;
    let author = parse_identity_arg(args, "author", "author_kind", "mcp-client");
    existing_review(store, &review_id)?;

    let note = ReviewNote {
        note_id: ReviewNoteId::new(),
        review_id,
        body: body.clone(),
        scope: scope.clone(),
        authored_by: author.clone(),
        created_at: Timestamp::now(),
    };

    let result = serde_json::json!({
        "note_id": note.note_id.to_string(),
        "review_id": review_id.to_string(),
        "scope": scope.map(|s| s.to_string()),
        "author": author.name,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.note",
        review_id,
        details: format!("review_id={review_id}; note_id={}", note.note_id),
        actor_label: author.name,
        refs: None,
        write: ReviewWrite {
            notes: vec![note],
            ..ReviewWrite::default()
        },
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_DISCUSS_DESC: &str = "\
Open a discussion thread on a review with an initial message, optionally anchored to a \
specific entity or file/line. Reach for it when a point needs conversation — a question \
or concern others should reply to and eventually resolve — rather than a one-off note. \
Returns the new discussion's ID; reply with kin_review_discuss_reply and close it out \
with kin_review_discuss_resolve. Anchoring to an entity keeps the thread attached to \
the code in graph truth as it evolves.";

pub fn handle_review_discuss<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_discuss(args, store)?, store)
}

fn plan_review_discuss<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::{
        ReviewComment, ReviewDiscussion, ReviewDiscussionId, ReviewDiscussionState,
    };
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let body = get_string_param(args, "body")?;
    let scope = parse_optional_scope_arg(args)?;
    let author = parse_identity_arg(args, "author", "author_kind", "mcp-client");
    existing_review(store, &review_id)?;

    let now = Timestamp::now();
    let discussion_id = ReviewDiscussionId::new();
    let discussion = ReviewDiscussion {
        discussion_id,
        review_id,
        scope: scope.clone(),
        state: ReviewDiscussionState::Open,
        comments: vec![ReviewComment {
            body: body.clone(),
            authored_by: author.clone(),
            created_at: now.clone(),
        }],
        created_at: now,
    };

    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "review_id": review_id.to_string(),
        "scope": scope.map(|s| s.to_string()),
        "state": "open",
        "author": author.name,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.discuss",
        review_id,
        details: format!("review_id={review_id}; discussion_id={discussion_id}"),
        actor_label: author.name,
        refs: None,
        write: ReviewWrite {
            discussions: vec![discussion],
            ..ReviewWrite::default()
        },
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_DISCUSS_REPLY_DESC: &str = "\
Append a reply to an existing review discussion thread, identified by its discussion \
ID. Reach for it to continue a conversation started with kin_review_discuss — the reply \
is added in order with its author recorded, so the thread reads as a coherent exchange. \
When the conversation has reached a conclusion, resolve it with \
kin_review_discuss_resolve.";

pub fn handle_review_discuss_reply<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_discuss_reply(args, store)?, store)
}

fn plan_review_discuss_reply<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::ReviewComment;
    use kin_model::timestamp::Timestamp;

    let discussion_id = parse_discussion_id(args, "discussion_id")?;
    let body = get_string_param(args, "body")?;
    let author = parse_identity_arg(args, "author", "author_kind", "mcp-client");
    let mut discussion = existing_discussion(store, &discussion_id)?;
    discussion.comments.push(ReviewComment {
        body: body.clone(),
        authored_by: author.clone(),
        created_at: Timestamp::now(),
    });

    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "replied": true,
        "author": author.name,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.reply",
        review_id: discussion.review_id,
        details: format!("discussion_id={discussion_id}"),
        actor_label: author.name,
        refs: None,
        write: ReviewWrite {
            discussions: vec![discussion],
            ..ReviewWrite::default()
        },
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_DISCUSS_RESOLVE_DESC: &str = "\
Resolve a review discussion thread (or reopen one) by its discussion ID. Reach for it \
to mark a conversation as settled once its concern is addressed, or to reopen it if the \
issue resurfaces. Tracking resolution in graph truth lets a review report which threads \
are still outstanding versus done.";

pub fn handle_review_discuss_resolve<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_discuss_resolve(args, store)?, store)
}

fn plan_review_discuss_resolve<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::ReviewDiscussionState;

    let discussion_id = parse_discussion_id(args, "discussion_id")?;
    let resolved = match get_optional_string_param(args, "state") {
        Some(state) if state.eq_ignore_ascii_case("resolved") => true,
        Some(state) if state.eq_ignore_ascii_case("open") => false,
        Some(state) => {
            return Err(McpError::InvalidParams(format!(
                "invalid discussion state: {}. Valid values: resolved, open",
                state
            )))
        }
        None => get_optional_bool(args, "resolved", true),
    };

    let new_state = if resolved {
        ReviewDiscussionState::Resolved
    } else {
        ReviewDiscussionState::Open
    };
    let mut discussion = existing_discussion(store, &discussion_id)?;
    let review_id = discussion.review_id;
    // A thread already in the asked-for state changes nothing, so nothing is
    // written and no transaction is spent on it.
    let write = if discussion.state == new_state {
        ReviewWrite::default()
    } else {
        discussion.state = new_state;
        ReviewWrite {
            discussions: vec![discussion],
            ..ReviewWrite::default()
        }
    };

    let label = if resolved { "resolved" } else { "open" };
    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "state": label,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.resolve",
        review_id,
        details: format!("discussion_id={discussion_id}; state={label}"),
        actor_label: "mcp-client".to_string(),
        refs: None,
        write,
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_ASSIGN_DESC: &str = "\
Assign one or more reviewers to a review. Pass a single `reviewer` or a batch via \
`reviewers`, and optionally who assigned them. Reach for it to route a review to the \
people (or agents) who should weigh in, so the request shows up as their responsibility \
in graph truth. Remove an assignment with kin_review_unassign.";

pub fn handle_review_assign<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_assign(args, store)?, store)
}

fn plan_review_assign<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    use kin_model::review::ReviewAssignment;
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let reviewers = parse_reviewer_list(args)?;
    let assigner = parse_identity_arg(args, "assigned_by", "assigned_by_kind", "mcp-client");
    existing_review(store, &review_id)?;
    let assigned_at = Timestamp::now();

    // The stored set, which is an add log: it only grows, a removal is recorded
    // as its own event, and a review's reviewers are derived from the two.
    let mut entries = store
        .get_review_assignments(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let assigned: Vec<ReviewAssignment> = reviewers
        .iter()
        .map(|reviewer| ReviewAssignment {
            review_id,
            reviewer: kin_model::IdentityRef::human(reviewer.clone()),
            assigned_at: assigned_at.clone(),
            assigned_by: assigner.clone(),
        })
        .collect();
    let tags: Vec<_> = assigned
        .iter()
        .map(kin_review::assignments::AssignmentTag::of)
        .collect();
    entries.extend(assigned);

    let details = format!(
        "review_id={review_id}; reviewers={}; {}",
        reviewers.join(","),
        kin_review::assignments::tag_details(&tags)
    );
    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "reviewers": reviewers,
        "assigned_by": assigner.name,
        "assigned": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: "review.assign",
        review_id,
        details,
        actor_label: assigner.name,
        refs: None,
        write: ReviewWrite {
            assignments: Some(ReviewGroup { review_id, entries }),
            ..ReviewWrite::default()
        },
        answer: ToolCallResult::text(json),
    })
}

pub const REVIEW_UNASSIGN_DESC: &str = "\
Remove a reviewer's assignment from a review. Reach for it when someone is no longer \
expected to review — reassigned, out, or added by mistake — so the review's outstanding \
reviewer list stays accurate in graph truth. Add assignments with kin_review_assign.";

pub fn handle_review_unassign<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    apply_planned(plan_review_unassign(args, store)?, store)
}

fn plan_review_unassign<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<PlannedReviewTool> {
    let review_id = parse_review_id(args, "review_id")?;
    let reviewer = get_string_param(args, "reviewer")?;
    existing_review(store, &review_id)?;

    // The reviewers this review has, so removing someone already removed
    // records nothing a second time.
    let live = kin_review::assignments::current_assignments(store, &review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let removed: Vec<_> = live
        .into_iter()
        .filter(|assignment| assignment.reviewer.name == reviewer)
        .collect();
    let tags: Vec<_> = removed
        .iter()
        .map(kin_review::assignments::AssignmentTag::of)
        .collect();
    let write = if removed.is_empty() {
        // Not assigned, so there is nothing to remove and nothing to record.
        ReviewWrite::default()
    } else {
        // The removal is the audit event this write carries, which the review
        // writer records for a write that carries records. It is not a smaller
        // set: the set is an add log, a delta refuses an empty one, and shrinking
        // it would leave a later re-assignment of the same reviewer unable to
        // reach the live graph. So the set is written unchanged.
        ReviewWrite {
            assignments: Some(ReviewGroup {
                review_id,
                entries: store
                    .get_review_assignments(&review_id)
                    .map_err(|e| McpError::Other(e.to_string()))?,
            }),
            ..ReviewWrite::default()
        }
    };

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "reviewer": reviewer,
        "unassigned": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(PlannedReviewEvent {
        action: kin_review::assignments::UNASSIGN_ACTION,
        review_id,
        details: format!(
            "review_id={review_id}; reviewer={reviewer}; {}",
            kin_review::assignments::tag_details(&tags)
        ),
        actor_label: "mcp-client".to_string(),
        refs: None,
        write,
        answer: ToolCallResult::text(json),
    })
}

/// A review write tool planned as the records it writes and the answer it gives
/// once they are written.
pub type PlannedReviewTool = PlannedReviewEvent<ToolCallResult>;

/// The review tools that write review state.
pub const REVIEW_MUTATION_TOOLS: [&str; 8] = [
    "kin_review_create",
    "kin_review_decide",
    "kin_review_note_add",
    "kin_review_discuss",
    "kin_review_discuss_reply",
    "kin_review_discuss_resolve",
    "kin_review_assign",
    "kin_review_unassign",
];

/// Whether `tool` writes review state.
pub fn is_review_mutation(tool: &str) -> bool {
    REVIEW_MUTATION_TOOLS.contains(&tool)
}

/// Plan one review write tool against `store` without writing anything, or
/// `None` when `tool` writes no review state.
///
/// A daemon commits the planned records to repository authority before its live
/// graph sees them, so its dispatch calls this rather than the
/// `handle_review_*` functions, which apply the same plan straight to a store.
pub fn plan_review_mutation<G: GraphStore>(
    tool: &str,
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Option<Result<PlannedReviewTool>> {
    Some(match tool {
        "kin_review_create" => plan_review_create(args, store),
        "kin_review_decide" => plan_review_decide(args, store),
        "kin_review_note_add" => plan_review_note_add(args, store),
        "kin_review_discuss" => plan_review_discuss(args, store),
        "kin_review_discuss_reply" => plan_review_discuss_reply(args, store),
        "kin_review_discuss_resolve" => plan_review_discuss_resolve(args, store),
        "kin_review_assign" => plan_review_assign(args, store),
        "kin_review_unassign" => plan_review_unassign(args, store),
        _ => return None,
    })
}

/// Apply a planned review write straight to `store`, for a caller with no
/// repository authority behind it.
///
/// Nothing here records the audit event the daemon's review writer records, and
/// a removal is proven by that event. Most removals are also expressed by the
/// set they leave, so they land either way. The one that is not is a review's
/// last reviewer, whose removal leaves a set a collaboration delta cannot carry:
/// on this path it would leave no trace at all, so it is refused by name rather
/// than answered as done.
fn apply_planned<G: GraphStore>(planned: PlannedReviewTool, store: &G) -> Result<ToolCallResult> {
    planned
        .write
        .apply_to(store)
        .map_err(|error| McpError::Other(error.to_string()))?;
    // A removal is an audit event, and this path records none, because nothing
    // here holds repository authority. Its graph is its whole state, so the
    // reviewer comes off that graph directly, which is what this surface did
    // before removals were recorded at all.
    if planned.action == kin_review::assignments::UNASSIGN_ACTION {
        for tag in kin_review::assignments::tags_in_details(&planned.details) {
            store
                .remove_reviewer(&planned.review_id, &tag.reviewer)
                .map_err(|error| McpError::Other(error.to_string()))?;
        }
    }
    Ok(planned.answer)
}

fn existing_review<G: GraphStore>(
    store: &G,
    review_id: &kin_model::review::ReviewId,
) -> Result<kin_model::review::Review> {
    store
        .get_review(review_id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("review not found: {review_id}")))
}

/// The discussion with `discussion_id`, found through the reviews that hold
/// discussions, since the store answers discussions by review.
fn existing_discussion<G: GraphStore>(
    store: &G,
    discussion_id: &kin_model::review::ReviewDiscussionId,
) -> Result<kin_model::review::ReviewDiscussion> {
    let reviews = store
        .list_reviews(&kin_model::review::ReviewFilter::default())
        .map_err(|e| McpError::Other(e.to_string()))?;
    for review in reviews {
        let found = store
            .get_review_discussions(&review.review_id)
            .map_err(|e| McpError::Other(e.to_string()))?
            .into_iter()
            .find(|discussion| discussion.discussion_id == *discussion_id);
        if let Some(discussion) = found {
            return Ok(discussion);
        }
    }
    Err(McpError::InvalidParams(format!(
        "review discussion not found: {discussion_id}"
    )))
}

pub const REVIEW_LIST_DESC: &str = "\
List reviews, optionally filtered by state (pending, approved, needs_work, blocked). \
Each row is a compact summary — review ID, title, state, and base/head refs. Reach for \
it to see what reviews exist and triage them: what's awaiting a decision, what's \
blocked, what's done. Use kin_review_get to pull the full detail of any one review.";

pub fn handle_review_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let state = get_optional_string_param(args, "state");
    let state_filter = state
        .as_deref()
        .map(parse_review_decision_state)
        .transpose()?;

    // The shared read, so this tool, `kin review list` and the daemon's
    // repo-scoped listing cannot drift apart on what a review row is.
    let reviews = kin_review::records::list_stored_reviews(store, state_filter)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let result: Vec<kin_review::records::ReviewSummaryView> = reviews
        .iter()
        .map(kin_review::records::ReviewSummaryView::from)
        .collect();

    // Printed through a `Value`, as the `json!` rows this replaced were, so
    // the key order is the one serde_json's `preserve_order` feature gives
    // `json!` in whichever build this is, and the text stays what it was.
    let value = serde_json::to_value(&result).map_err(McpError::Json)?;
    let json = serde_json::to_string_pretty(&value).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const REVIEW_GET_DESC: &str = "\
Fetch one review in full by ID: its decisions, notes, discussion threads, and reviewer \
assignments together in a single response. Reach for it to see the complete state of a \
review — where it stands, what's been said, what's unresolved — in one call rather than \
piecing it together. Use kin_review_list first when you need to find the review ID.";

pub fn handle_review_get<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let review_id = parse_review_id(args, "review_id")?;

    // The shared read and its JSON view, the same object the daemon's
    // repo-scoped review route answers, so a client maps one shape.
    let record = kin_review::records::read_review_record(store, &review_id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("review not found: {}", review_id)))?;
    let result = kin_review::records::ReviewRecordView::from(&record);

    // Through a `Value` for the reason `handle_review_list` gives.
    let value = serde_json::to_value(&result).map_err(McpError::Json)?;
    let json = serde_json::to_string_pretty(&value).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

// ── Review ID parsing helpers ──

fn parse_review_id(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<kin_model::review::ReviewId> {
    let id_str = get_string_param(args, key)?;
    let uuid = uuid::Uuid::parse_str(&id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid {}: {}", key, id_str)))?;
    Ok(kin_model::review::ReviewId(uuid))
}

fn parse_discussion_id(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<kin_model::review::ReviewDiscussionId> {
    let id_str = get_string_param(args, key)?;
    let uuid = uuid::Uuid::parse_str(&id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid {}: {}", key, id_str)))?;
    Ok(kin_model::review::ReviewDiscussionId(uuid))
}

fn parse_review_decision_state(s: &str) -> Result<kin_model::review::ReviewDecisionState> {
    kin_review::records::parse_review_decision_state(s).ok_or_else(|| {
        McpError::InvalidParams(format!(
            "invalid review state: {}. Valid values: pending, approved, needs_work, blocked",
            s
        ))
    })
}

/// Parse an optional work scope from a JSON value (string like "entity:ID").
fn parse_optional_work_scope(
    val: Option<&serde_json::Value>,
) -> Result<Option<kin_model::WorkScope>> {
    // A scope spelled in none of the documented forms is refused, not dropped:
    // dropping it would fall through to `file_path`, or to no scope at all, and
    // the note would anchor somewhere the caller did not ask for.
    val.and_then(|v| v.as_str())
        .map(parse_single_work_scope)
        .transpose()
}

fn parse_optional_scope_arg(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Option<kin_model::WorkScope>> {
    if let Some(scope) = parse_optional_work_scope(args.get("scope"))? {
        return Ok(Some(scope));
    }

    if let Some(file_path) = get_optional_string_param(args, "file_path") {
        return Ok(Some(kin_model::WorkScope::Artifact(
            kin_model::FilePathId::new(file_path),
        )));
    }

    Ok(None)
}

fn parse_review_create_scopes(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Vec<kin_model::WorkScope>> {
    let scopes = parse_work_scopes(args.get("scopes"))?;
    if !scopes.is_empty() {
        return Ok(scopes);
    }

    let Some(entity_ids) = args.get("entity_ids").and_then(|value| value.as_array()) else {
        return Ok(Vec::new());
    };

    entity_ids
        .iter()
        .map(|value| {
            let raw = value.as_str().ok_or_else(|| {
                McpError::InvalidParams("entity_ids entries must be strings".into())
            })?;
            if raw.starts_with("entity:")
                || raw.starts_with("artifact:")
                || raw.starts_with("contract:")
            {
                return parse_single_work_scope(raw);
            }

            if let Ok(uuid) = uuid::Uuid::parse_str(raw) {
                return Ok(kin_model::WorkScope::Entity(kin_model::EntityId(uuid)));
            }

            Ok(kin_model::WorkScope::Artifact(kin_model::FilePathId::new(
                raw,
            )))
        })
        .collect()
}

/// Every reviewer the call names, deduplicated, possibly none.
///
/// `requested_reviewers` is the name the create tool's schema documents and
/// `reviewers` the assign tool's; both are read so a caller following either
/// schema is heard.
fn parse_optional_reviewer_list(args: &HashMap<String, serde_json::Value>) -> Result<Vec<String>> {
    let mut reviewers = Vec::new();

    if let Some(reviewer) = get_optional_string_param(args, "reviewer") {
        let trimmed = reviewer.trim();
        if !trimmed.is_empty() {
            reviewers.push(trimmed.to_string());
        }
    }

    for key in ["reviewers", "requested_reviewers"] {
        if let Some(values) = args.get(key).and_then(|value| value.as_array()) {
            for value in values {
                let reviewer = value.as_str().ok_or_else(|| {
                    McpError::InvalidParams(format!("{key} entries must be strings"))
                })?;
                let trimmed = reviewer.trim();
                if !trimmed.is_empty() {
                    reviewers.push(trimmed.to_string());
                }
            }
        }
    }

    reviewers.sort();
    reviewers.dedup();
    Ok(reviewers)
}

fn parse_reviewer_list(args: &HashMap<String, serde_json::Value>) -> Result<Vec<String>> {
    let reviewers = parse_optional_reviewer_list(args)?;
    if reviewers.is_empty() {
        return Err(McpError::InvalidParams(
            "missing reviewer assignment: provide reviewer or reviewers".into(),
        ));
    }

    Ok(reviewers)
}

fn parse_identity_arg(
    args: &HashMap<String, serde_json::Value>,
    name_key: &str,
    kind_key: &str,
    default_name: &str,
) -> kin_model::IdentityRef {
    let name =
        get_optional_string_param(args, name_key).unwrap_or_else(|| default_name.to_string());
    let kind = get_optional_string_param(args, kind_key).unwrap_or_default();
    if kind.eq_ignore_ascii_case("human") {
        kin_model::IdentityRef::human(name)
    } else {
        kin_model::IdentityRef::assistant(name)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::with_empty_test_repository;
    use super::*;

    /// Impact rows must locate an affected caller where an editor would.
    ///
    /// `ImpactReport` holds raw entities, so serializing it exposed only the
    /// nested 0-based graph span. An agent reading that to open the caller landed
    /// one line above it, which is the same off-by-one the other read surfaces
    /// carried before the presentation seam.
    #[test]
    fn impact_rows_carry_one_based_presentation_lines_beside_the_raw_span() {
        fn caller(name: &str, graph_row: u32) -> kin_model::Entity {
            let file = kin_model::ids::FilePathId::new("src/consumer.ts");
            let mut entity = kin_model::Entity {
                id: kin_model::EntityId::new(),
                kind: kin_model::EntityKind::Function,
                name: name.to_string(),
                language: kin_model::LanguageId::TypeScript,
                fingerprint: kin_model::entity::SemanticFingerprint {
                    algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: kin_model::Hash256::from_bytes([4; 32]),
                    signature_hash: kin_model::Hash256::from_bytes([5; 32]),
                    behavior_hash: kin_model::Hash256::from_bytes([6; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(file.clone()),
                span: None,
                signature: format!("function {name}(): void"),
                visibility: kin_model::entity::Visibility::Public,
                role: kin_model::entity::EntityRole::Source,
                doc_summary: None,
                metadata: kin_model::entity::EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            };
            entity.span = Some(kin_model::entity::SourceSpan {
                file,
                start_byte: 0,
                end_byte: 20,
                start_line: graph_row,
                start_col: 0,
                end_line: graph_row + 2,
                end_col: 1,
            });
            entity
        }

        let direct = caller("probe_direct_9ab1", 41);
        let spanless = {
            let mut entity = caller("probe_spanless_9ab1", 0);
            entity.span = None;
            entity
        };
        let report = kin_review::ImpactReport {
            affected_callers: vec![direct.clone(), spanless.clone()],
            affected_dependents: vec![],
            affected_contract_consumers: vec![],
            affected_tests: vec![],
            affected_work_items: vec![],
            affected_annotations: vec![],
            changed_ids: vec![],
            unreviewed_agent_changes: vec![],
            actor_attribution: vec![],
            entity_impacts: vec![kin_review::EntityImpact {
                entity_id: direct.id,
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
                call_shapes: kin_review::impact::ConsumerCallShapeSummary::default(),
            }],
        };

        let mut value = serde_json::to_value(&report).unwrap();
        annotate_impact_presentation_lines(&mut value, &report);
        let rows = value["affected_callers"].as_array().unwrap();

        assert_eq!(
            rows[0]["start_line"], 42,
            "graph row 41 is line 42: {}",
            rows[0]
        );
        assert_eq!(rows[0]["end_line"], 44);
        // The raw span is untouched: its byte offsets are read as offsets, so it
        // stays a faithful serialization of graph truth.
        assert_eq!(rows[0]["span"]["start_line"], 41);
        assert_eq!(rows[0]["name"], "probe_direct_9ab1");

        // A spanless entity gets null rather than a fabricated line 1.
        assert!(
            rows[1]["start_line"].is_null(),
            "an entity with no span has no line to report: {}",
            rows[1]
        );

        let coverage = &value["entity_impacts"][0];
        assert_eq!(coverage["covering_tests"], 0);
        assert_eq!(
            coverage[COVERING_TESTS_BOUND_KEY], COVERING_TESTS_BOUND,
            "a zero must say beside the number that missing local-variable property edges can \
             make it a false negative: {coverage}"
        );
    }

    /// A review scope spelled in none of the documented forms is refused. Dropping
    /// it instead would fall through to `file_path`, or to no scope, and the note
    /// would anchor somewhere the caller did not ask for; a `scopes` entry would
    /// fall through to `entity_ids`.
    #[test]
    fn a_misspelled_review_scope_is_refused_not_dropped() {
        for args in [
            serde_json::json!({ "scope": "src/a.rs" }),
            serde_json::json!({ "scope": "src/a.rs", "file_path": "src/b.rs" }),
        ] {
            let args: HashMap<String, serde_json::Value> =
                serde_json::from_value(args).expect("an argument object");
            assert!(
                parse_optional_scope_arg(&args).is_err(),
                "a misspelled scope must refuse: {args:?}"
            );
        }

        let mut args = HashMap::new();
        args.insert("scopes".into(), serde_json::json!(["src/a.rs"]));
        assert!(
            parse_review_create_scopes(&args).is_err(),
            "a misspelled scopes entry must refuse, not fall through to entity_ids"
        );
    }

    #[test]
    fn parse_review_create_scopes_accepts_uuid_and_paths() {
        let entity_id = uuid::Uuid::new_v4().to_string();
        let mut args = HashMap::new();
        args.insert(
            "entity_ids".into(),
            serde_json::json!([entity_id, "src/lib.rs", "artifact:README.md"]),
        );

        let scopes = parse_review_create_scopes(&args).unwrap();
        assert_eq!(scopes.len(), 3);
        assert!(matches!(scopes[0], kin_model::WorkScope::Entity(_)));
        assert_eq!(scopes[1].to_string(), "artifact:src/lib.rs");
        assert_eq!(scopes[2].to_string(), "artifact:README.md");
    }

    #[test]
    fn parse_optional_scope_arg_uses_file_anchor_when_scope_missing() {
        let mut args = HashMap::new();
        args.insert("file_path".into(), serde_json::json!("src/main.ts"));

        let scope = parse_optional_scope_arg(&args).unwrap();
        assert_eq!(scope.unwrap().to_string(), "artifact:src/main.ts");
    }

    #[test]
    fn parse_reviewer_list_accepts_batch_assignments() {
        let mut args = HashMap::new();
        args.insert(
            "reviewers".into(),
            serde_json::json!(["alice", "bob", "alice"]),
        );

        let reviewers = parse_reviewer_list(&args).unwrap();
        assert_eq!(reviewers, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn parse_identity_arg_maps_human_kind_to_human_identity() {
        let mut args = HashMap::new();
        args.insert("author".into(), serde_json::json!("troy"));
        args.insert("author_kind".into(), serde_json::json!("human"));

        let identity = parse_identity_arg(&args, "author", "author_kind", "mcp-client");
        assert_eq!(identity.name, "troy");
        assert!(matches!(identity.kind, kin_model::IdentityKind::Human));
    }

    #[test]
    fn shadow_gate_report_fails_loud_on_unknown_base_ref() {
        let store = kin_db::InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert("base".into(), serde_json::json!("branch:missing"));
        args.insert("head".into(), serde_json::json!("branch:missing"));

        let err = with_empty_test_repository(|authority| {
            handle_shadow_gate_report(&args, &store, Some(authority))
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "unknown branch must error, got: {err}"
        );
    }

    #[test]
    fn shadow_gate_report_fails_loud_on_unimported_git_sha() {
        let store = kin_db::InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert(
            "base".into(),
            serde_json::json!("1111111111111111111111111111111111111111"),
        );
        args.insert(
            "head".into(),
            serde_json::json!("2222222222222222222222222222222222222222"),
        );

        let err = with_empty_test_repository(|authority| {
            handle_shadow_gate_report(&args, &store, Some(authority))
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("no imported repository alias"),
            "unimported git sha must error, got: {err}"
        );
    }
}
