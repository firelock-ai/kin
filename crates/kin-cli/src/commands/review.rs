// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::provenance::ApprovalDecision;
use kin_model::{ChangeStore, ProvenanceStore, ReviewStore};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ReviewRequest {
    Run {
        change: Option<String>,
        entities: Option<String>,
        files: Option<String>,
        changes: Option<String>,
        #[serde(default)]
        json: bool,
    },
    Shadow {
        base: String,
        head: String,
        title: Option<String>,
        source_url: Option<String>,
        author: Option<String>,
        #[serde(default)]
        json: bool,
    },
    Create {
        title: String,
        base: String,
        head: String,
        description: Option<String>,
    },
    Decide {
        review_id: String,
        state: String,
        comment: Option<String>,
    },
    Note {
        review_id: String,
        body: String,
        scope: Option<String>,
    },
    Discuss {
        review_id: String,
        body: String,
        scope: Option<String>,
    },
    Reply {
        discussion_id: String,
        body: String,
    },
    Resolve {
        discussion_id: String,
    },
    Assign {
        review_id: String,
        reviewer: String,
    },
    List {
        state: Option<String>,
    },
    Show {
        review_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewResponse {
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReviewExecution {
    pub response: ReviewResponse,
    /// Whether this review op itself mutated review/graph state (a decision,
    /// note, discussion, etc.). Always `false` for `Run` and `Shadow`, which
    /// are read-only evaluations.
    pub mutated: bool,
    /// Count of historical changes a shadow evaluation lazily hydrated into
    /// the graph (0 for every op other than `Shadow`, and 0 for a `Shadow`
    /// whose base/head were already imported). Reported distinctly from
    /// `mutated` so a cold import that persists thousands of changes is never
    /// described the same way as a no-op: daemon owners persist the hydrated
    /// state so the import happens once per repo instead of once per process.
    pub hydrated_changes: usize,
}

#[derive(Serialize)]
struct ReviewFindingJson {
    entity: String,
    kind: String,
    file: String,
    line: u32,
    severity: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ReviewResultJson {
    file: String,
    findings: Vec<ReviewFindingJson>,
    summary: String,
}

async fn run_daemon_review(request: &ReviewRequest) -> Result<ReviewResponse> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(&layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for review but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.review(request).await.context("daemon review failed")
}

fn print_review_response(response: ReviewResponse) {
    if let Some(json) = response.json {
        println!("{json}");
    } else {
        print!("{}", response.text);
    }
}

pub async fn run(
    change: Option<String>,
    entities: Option<String>,
    files: Option<String>,
    changes: Option<String>,
) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Run {
            change,
            entities,
            files,
            changes,
            json: false,
        })
        .await?,
    );
    Ok(())
}

pub async fn run_json(
    change: Option<String>,
    entities: Option<String>,
    files: Option<String>,
    changes: Option<String>,
) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Run {
            change,
            entities,
            files,
            changes,
            json: true,
        })
        .await?,
    );
    Ok(())
}

pub async fn execute_review_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: ReviewRequest,
) -> Result<ReviewExecution> {
    match request {
        ReviewRequest::Run {
            change,
            entities,
            files,
            changes,
            json,
        } => Ok(ReviewExecution {
            response: build_review_run_response(
                layout, graph, change, entities, files, changes, json,
            )?,
            mutated: false,
            hydrated_changes: 0,
        }),
        ReviewRequest::Shadow {
            base,
            head,
            title,
            source_url,
            author,
            json,
        } => {
            let (response, hydrated_changes) = build_shadow_run_response(
                layout, graph, base, head, title, source_url, author, json,
            )?;
            Ok(ReviewExecution {
                response,
                mutated: false,
                hydrated_changes,
            })
        }
        ReviewRequest::Create {
            title,
            base,
            head,
            description,
        } => create_review_with_graph(graph, title, base, head, description),
        ReviewRequest::Decide {
            review_id,
            state,
            comment,
        } => decide_review_with_graph(graph, review_id, state, comment),
        ReviewRequest::Note {
            review_id,
            body,
            scope,
        } => add_note_with_graph(graph, review_id, body, scope),
        ReviewRequest::Discuss {
            review_id,
            body,
            scope,
        } => start_discussion_with_graph(graph, review_id, body, scope),
        ReviewRequest::Reply {
            discussion_id,
            body,
        } => reply_discussion_with_graph(graph, discussion_id, body),
        ReviewRequest::Resolve { discussion_id } => {
            resolve_discussion_with_graph(graph, discussion_id)
        }
        ReviewRequest::Assign {
            review_id,
            reviewer,
        } => assign_reviewer_with_graph(graph, review_id, reviewer),
        ReviewRequest::List { state } => list_reviews_with_graph(graph, state),
        ReviewRequest::Show { review_id } => show_review_with_graph(graph, review_id),
    }
}

fn build_review_run_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    change: Option<String>,
    entities: Option<String>,
    files: Option<String>,
    changes: Option<String>,
    json: bool,
) -> Result<ReviewResponse> {
    let (review, file_hint, text_prefix, change_context) =
        compute_review(layout, graph, change, entities, files, changes)?;

    if json {
        let findings = review
            .inline_comments
            .iter()
            .map(|comment| ReviewFindingJson {
                entity: comment.file.clone(),
                kind: format!("{:?}", comment.kind),
                file: comment.file.clone(),
                line: comment.start_line,
                severity: inline_comment_severity(comment.kind),
                message: comment.message.clone(),
            })
            .collect::<Vec<_>>();

        let summary = format!(
            "Overall risk: {:?}; {} finding(s)",
            review.risk.overall_risk,
            findings.len()
        );

        return Ok(ReviewResponse {
            text: String::new(),
            json: Some(serde_json::to_string(&ReviewResultJson {
                file: file_hint,
                findings,
                summary,
            })?),
        });
    }

    let mut text = text_prefix;
    text.push_str(&kin_review::format_review(&review));
    if let Some((change_id, semantic_change)) = change_context {
        append_review_provenance(graph, &mut text, &change_id, &semantic_change)?;
    }

    Ok(ReviewResponse { text, json: None })
}

/// Shadow review JSON payload: the gate report plus the two distinct
/// bookkeeping signals a shadow evaluation can produce. Flattened alongside
/// `report`'s own fields so existing consumers keep reading the report shape
/// unchanged and additionally see these two counts.
#[derive(Serialize)]
struct ShadowReviewResponseJson<'a> {
    #[serde(flatten)]
    report: &'a kin_review::ShadowGateReport,
    /// Historical changes lazily imported into the graph while resolving the
    /// base/head refs (0 when both were already present). Reported as a real
    /// count, never collapsed to a boolean, so a cold multi-thousand-change
    /// import is never described the same way as a no-op.
    hydrated_changes: usize,
    /// Mutations the review operation itself made to review/graph state.
    /// Always 0: a shadow evaluation is read-only by construction. Reported
    /// explicitly, distinct from `hydrated_changes`, so the two never blur
    /// into a single collapsed signal.
    review_mutations: usize,
}

#[allow(clippy::too_many_arguments)]
fn build_shadow_run_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    base: String,
    head: String,
    title: Option<String>,
    source_url: Option<String>,
    author: Option<String>,
    json: bool,
) -> Result<(ReviewResponse, usize)> {
    // The everyday "your branch is behind main" case: base is not on head's
    // ancestry. That gap is provable from the Git commit-parent DAG alone —
    // no semantic hydration needed — so it is checked before either ref pays
    // for a full history import. Returns `None` whenever the fast
    // conclusion can't be drawn, in which case the normal resolve-and-hydrate
    // path below runs exactly as it always has.
    if let Some(report) =
        shadow_ancestry_fast_path_gap(graph, layout, &base, &head, &title, &source_url, &author)?
    {
        // The fast path never hydrates anything, so this is always a true
        // zero, not a placeholder.
        return Ok((shadow_response_from_report(&report, json, 0)?, 0));
    }

    // Resolve the head ref before the base ref. A review pair is almost always
    // ancestor..descendant, so importing the head first hydrates the full git
    // ancestry in a single pass; the base is then already present in the graph
    // and resolves on the fast path instead of re-walking the shared history.
    let resolved_head =
        crate::commands::ref_lookup::resolve_ref_importing_git_if_needed_with_report(
            graph,
            layout,
            Some(head.as_str()),
        )
        .with_context(|| format!("resolve shadow head ref '{}'", head))?;
    let resolved_base =
        crate::commands::ref_lookup::resolve_ref_importing_git_if_needed_with_report(
            graph,
            layout,
            Some(base.as_str()),
        )
        .with_context(|| format!("resolve shadow base ref '{}'", base))?;
    let hydrated_changes = resolved_base.hydrated_changes + resolved_head.hydrated_changes;

    let request = kin_review::ShadowRequest {
        base_ref: base,
        head_ref: head,
        resolved_base: resolved_base.head,
        resolved_head: resolved_head.head,
        title,
        source_url,
        author,
        actor: crate::provenance::current_actor_label(),
    };

    let report = kin_review::build_shadow_report(graph, &request)?;
    Ok((
        shadow_response_from_report(&report, json, hydrated_changes)?,
        hydrated_changes,
    ))
}

/// Cheap pre-check for the shadow path's `base_not_on_head_ancestry` gap.
///
/// Applies only when both refs are bare Git commit forms (`git:<oid>` or a
/// 40-character hex oid) and at least one is not yet present in the graph —
/// the only situation where the default path below pays for a full history
/// import before `kin_review::build_shadow_report`'s own ancestry check
/// would run. Reads only the on-disk Git commit-parent graph (via
/// `kin_git::is_ancestor_commit`), never the working tree or blobs, so a
/// stale base returns the existing gap report without importing anything.
///
/// Returns `Ok(None)` whenever the fast conclusion can't be drawn — either
/// ref isn't a bare Git commit form, either commit is missing from the Git
/// object database, or ancestry actually holds — so the caller falls
/// through to the exact existing resolve-and-hydrate path, unchanged.
#[allow(clippy::too_many_arguments)]
fn shadow_ancestry_fast_path_gap(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    base: &str,
    head: &str,
    title: &Option<String>,
    source_url: &Option<String>,
    author: &Option<String>,
) -> Result<Option<kin_review::ShadowGateReport>> {
    let Some(base_oid) = crate::commands::ref_lookup::extract_git_ref(base) else {
        return Ok(None);
    };
    let Some(head_oid) = crate::commands::ref_lookup::extract_git_ref(head) else {
        return Ok(None);
    };
    let needs_check = crate::commands::ref_lookup::git_ref_requires_hydration(graph, base)
        || crate::commands::ref_lookup::git_ref_requires_hydration(graph, head);
    if !needs_check {
        return Ok(None);
    }

    let Some(false) = kin_git::is_ancestor_commit(layout.working_dir(), base_oid, head_oid) else {
        return Ok(None);
    };

    let request = kin_review::ShadowRequest {
        base_ref: base.to_string(),
        head_ref: head.to_string(),
        resolved_base: kin_git::semantic_change_id_from_git_oid_hex(base_oid)?,
        resolved_head: kin_git::semantic_change_id_from_git_oid_hex(head_oid)?,
        title: title.clone(),
        source_url: source_url.clone(),
        author: author.clone(),
        actor: crate::provenance::current_actor_label(),
    };
    Ok(Some(kin_review::build_shadow_report_base_off_ancestry(
        graph, &request,
    )?))
}

fn shadow_response_from_report(
    report: &kin_review::ShadowGateReport,
    json: bool,
    hydrated_changes: usize,
) -> Result<ReviewResponse> {
    if json {
        return Ok(ReviewResponse {
            text: String::new(),
            json: Some(serde_json::to_string_pretty(&ShadowReviewResponseJson {
                report,
                hydrated_changes,
                review_mutations: 0,
            })?),
        });
    }

    let mut text = kin_review::format_shadow_report(report);
    if hydrated_changes > 0 {
        writeln!(
            text,
            "\n(hydrated {hydrated_changes} historical change(s) into the graph; 0 review mutations)"
        )?;
    }
    Ok(ReviewResponse { text, json: None })
}

fn compute_review(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    change: Option<String>,
    entities: Option<String>,
    files: Option<String>,
    changes: Option<String>,
) -> Result<(
    kin_review::Review,
    String,
    String,
    Option<(kin_model::SemanticChangeId, kin_model::SemanticChange)>,
)> {
    if let Some(entity_csv) = entities {
        let entity_ids = parse_entity_ids(&entity_csv)?;
        let mut text = String::new();
        writeln!(
            text,
            "Reviewing {} user-specified entities",
            entity_ids.len()
        )?;
        writeln!(text)?;
        return Ok((
            kin_review::SemanticReview::review_entities(&entity_ids, graph)?,
            String::new(),
            text,
            None,
        ));
    }

    if let Some(file_csv) = files {
        let file_paths: Vec<String> = file_csv.split(',').map(|s| s.trim().to_string()).collect();
        let mut text = String::new();
        writeln!(text, "Reviewing entities from {} files:", file_paths.len())?;
        for f in &file_paths {
            writeln!(text, "  {}", f)?;
        }
        writeln!(text)?;
        return Ok((
            kin_review::SemanticReview::review_files(&file_paths, graph)?,
            file_paths.first().cloned().unwrap_or_default(),
            text,
            None,
        ));
    }

    if let Some(change_csv) = changes {
        let change_ids = parse_change_ids(&change_csv)?;
        let mut semantic_changes = Vec::new();
        for cid in &change_ids {
            let sc = graph
                .get_change(cid)?
                .ok_or_else(|| anyhow::anyhow!("change {} not found", cid))?;
            semantic_changes.push(sc);
        }

        let mut text = String::new();
        writeln!(
            text,
            "Reviewing {} user-specified changes as a single unit",
            semantic_changes.len()
        )?;
        writeln!(text)?;
        return Ok((
            kin_review::SemanticReview::review_changes(&semantic_changes, graph)?,
            String::new(),
            text,
            None,
        ));
    }

    let change_id = match change {
        Some(h) => kin_model::SemanticChangeId::from_hash(
            kin_model::Hash256::from_hex(&h).map_err(|e| anyhow::anyhow!("invalid hash: {}", e))?,
        ),
        None => {
            let current = kin_core::read_current_branch(layout)?;
            let branch = graph
                .get_branch(&current)?
                .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", current))?;
            branch.head
        }
    };

    let semantic_change = graph
        .get_change(&change_id)?
        .ok_or_else(|| anyhow::anyhow!("change {} not found", change_id))?;

    let mut text = String::new();
    writeln!(text, "Reviewing semantic change: {}", change_id)?;
    writeln!(text, "  Message: {}", semantic_change.message)?;
    writeln!(text, "  Author: {}", semantic_change.author)?;
    writeln!(text)?;

    let review = if let Some(parent_id) = semantic_change.parents.first() {
        match kin_review::SemanticReview::create_review(parent_id, &change_id, graph) {
            Ok(r) => r,
            // An unmaterializable ref state must surface, not degrade into a
            // live-adjacency review of another era's graph.
            Err(err @ kin_review::ReviewError::RefStateUnavailable { .. }) => {
                return Err(err.into())
            }
            Err(_) => {
                let diff = kin_review::diff_from_change(&semantic_change);
                kin_review::SemanticReview::review_from_diff(diff, graph)?
            }
        }
    } else {
        let diff = kin_review::diff_from_change(&semantic_change);
        kin_review::SemanticReview::review_from_diff(diff, graph)?
    };

    Ok((
        review,
        String::new(),
        text,
        Some((change_id, semantic_change)),
    ))
}

fn append_review_provenance(
    graph: &kin_db::InMemoryGraph,
    text: &mut String,
    change_id: &kin_model::SemanticChangeId,
    semantic_change: &kin_model::SemanticChange,
) -> Result<()> {
    let approvals = graph.get_approvals_for_change(change_id)?;
    let is_agent_change = semantic_change.author.0.contains("agent")
        || semantic_change.author.0.contains("assistant")
        || semantic_change.author.0.contains("codex")
        || semantic_change.author.0.contains("claude")
        || semantic_change.author.0.contains("gemini");

    let is_approved = approvals
        .iter()
        .any(|a| a.decision == ApprovalDecision::Approved);

    if is_agent_change || !approvals.is_empty() {
        writeln!(text)?;
        writeln!(text, "--- Provenance ---")?;
        writeln!(
            text,
            "Author: {} {}",
            semantic_change.author,
            if is_agent_change {
                "(agent)"
            } else {
                "(human)"
            }
        )?;

        let changed_entity_count = semantic_change.entity_deltas.len();
        if changed_entity_count > 0 {
            writeln!(text, "Changed entities: {}", changed_entity_count)?;
            for delta in &semantic_change.entity_deltas {
                match delta {
                    kin_model::EntityDelta::Added(e) => {
                        writeln!(
                            text,
                            "  + {} ({:?}) by {}",
                            e.name, e.kind, semantic_change.author
                        )?;
                    }
                    kin_model::EntityDelta::Modified { new, .. } => {
                        writeln!(
                            text,
                            "  ~ {} ({:?}) by {}",
                            new.name, new.kind, semantic_change.author
                        )?;
                    }
                    kin_model::EntityDelta::Removed(id) => {
                        writeln!(text, "  - {} by {}", id, semantic_change.author)?;
                    }
                }
            }
        }

        if is_agent_change && !is_approved {
            writeln!(text)?;
            writeln!(text, "Agent Changes Pending Review:")?;
            writeln!(
                text,
                "  Change {} by {} has NO human approval.",
                change_id, semantic_change.author
            )?;
            for a in &approvals {
                writeln!(
                    text,
                    "  Approval: {} - {} ({})",
                    a.approver, a.decision, a.reason
                )?;
            }
        } else if is_agent_change && is_approved {
            writeln!(text)?;
            writeln!(text, "Agent change approved:")?;
            for a in &approvals {
                if a.decision == ApprovalDecision::Approved {
                    writeln!(text, "  Approved by {} - {}", a.approver, a.reason)?;
                }
            }
        }
    }

    Ok(())
}

fn parse_entity_ids(entity_csv: &str) -> Result<Vec<kin_model::EntityId>> {
    entity_csv
        .split(',')
        .map(|s| {
            let trimmed = s.trim();
            let uuid = uuid::Uuid::parse_str(trimmed)
                .map_err(|e| anyhow::anyhow!("invalid entity UUID '{}': {}", trimmed, e))?;
            Ok(kin_model::EntityId(uuid))
        })
        .collect()
}

fn parse_change_ids(change_csv: &str) -> Result<Vec<kin_model::SemanticChangeId>> {
    change_csv
        .split(',')
        .map(|s| {
            let trimmed = s.trim();
            Ok(kin_model::SemanticChangeId::from_hash(
                kin_model::Hash256::from_hex(trimmed)
                    .map_err(|e| anyhow::anyhow!("invalid change ID '{}': {}", trimmed, e))?,
            ))
        })
        .collect()
}

// ── Review mutation subcommands (Phase 11) ──
// These depend on kin_model::review types being added by a teammate.
// Structurally complete; will compile once kin-model review types land.

pub async fn shadow_report(
    base: String,
    head: String,
    title: Option<String>,
    source_url: Option<String>,
    author: Option<String>,
    json: bool,
) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Shadow {
            base,
            head,
            title,
            source_url,
            author,
            json,
        })
        .await?,
    );
    Ok(())
}

pub async fn create_review(
    title: String,
    base: String,
    head: String,
    description: Option<String>,
) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Create {
            title,
            base,
            head,
            description,
        })
        .await?,
    );
    Ok(())
}

fn create_review_with_graph(
    graph: &kin_db::InMemoryGraph,
    title: String,
    base: String,
    head: String,
    description: Option<String>,
) -> Result<ReviewExecution> {
    use kin_model::review::{
        Review, ReviewCompletionState, ReviewDecisionState, ReviewId, ReviewNote, ReviewNoteId,
    };
    use kin_model::timestamp::Timestamp;

    let now = Timestamp::now();
    let review = Review {
        review_id: ReviewId::new(),
        title: title.clone(),
        base_ref: base.clone(),
        head_ref: head.clone(),
        state: ReviewDecisionState::Pending,
        completion: ReviewCompletionState::InReview,
        scopes: vec![],
        created_by: kin_model::IdentityRef::human("cli-user"),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    graph.create_review(&review)?;
    if let Some(body) = description.filter(|body| !body.trim().is_empty()) {
        let note = ReviewNote {
            note_id: ReviewNoteId::new(),
            review_id: review.review_id,
            body,
            scope: None,
            authored_by: kin_model::IdentityRef::human("cli-user"),
            created_at: now,
        };
        graph.add_review_note(&note)?;
    }
    crate::provenance::record_cli_audit_event(
        graph,
        "review.create",
        None,
        Some(format!(
            "review_id={}; title={}; base={}; head={}",
            review.review_id, title, base, head
        )),
    )?;
    Ok(ReviewExecution {
        response: ReviewResponse {
            text: format!(
                "Created review {}\n  Title: {}\n  Base: {} -> Head: {}\n",
                review.review_id, title, base, head
            ),
            json: None,
        },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn decide_review(
    review_id: String,
    state: String,
    comment: Option<String>,
) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Decide {
            review_id,
            state,
            comment,
        })
        .await?,
    );
    Ok(())
}

fn decide_review_with_graph(
    graph: &kin_db::InMemoryGraph,
    review_id: String,
    state: String,
    comment: Option<String>,
) -> Result<ReviewExecution> {
    use kin_model::review::{ReviewDecision, ReviewDecisionState, ReviewId};
    use kin_model::timestamp::Timestamp;

    let rid = ReviewId(uuid::Uuid::parse_str(&review_id)?);
    let decision_state = match state.to_lowercase().as_str() {
        "approved" | "approve" => ReviewDecisionState::Approved,
        "needs_work" | "needs-work" => ReviewDecisionState::NeedsWork,
        "blocked" | "block" => ReviewDecisionState::Blocked,
        _ => anyhow::bail!(
            "invalid state: {}. Use: approved, needs_work, blocked",
            state
        ),
    };

    let decision = ReviewDecision {
        state: decision_state,
        comment: comment.filter(|value| !value.trim().is_empty()),
        reviewer: kin_model::IdentityRef::human("cli-user"),
        decided_at: Timestamp::now(),
    };

    graph.add_review_decision(&rid, &decision)?;
    crate::provenance::record_cli_audit_event(
        graph,
        "review.decide",
        None,
        Some(format!("review_id={}; decision={}", review_id, state)),
    )?;
    Ok(ReviewExecution {
        response: ReviewResponse {
            text: format!("Recorded decision '{}' on review {}\n", state, review_id),
            json: None,
        },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn add_note(review_id: String, body: String, scope: Option<String>) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Note {
            review_id,
            body,
            scope,
        })
        .await?,
    );
    Ok(())
}

fn add_note_with_graph(
    graph: &kin_db::InMemoryGraph,
    review_id: String,
    body: String,
    scope: Option<String>,
) -> Result<ReviewExecution> {
    use kin_model::review::{ReviewId, ReviewNote, ReviewNoteId};
    use kin_model::timestamp::Timestamp;

    let scope = scope
        .as_deref()
        .map(crate::commands::work::parse_work_scope)
        .transpose()?;
    let rid = ReviewId(uuid::Uuid::parse_str(&review_id)?);
    let note = ReviewNote {
        note_id: ReviewNoteId::new(),
        review_id: rid,
        body: body.clone(),
        scope: scope.clone(),
        authored_by: kin_model::IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
    };

    graph.add_review_note(&note)?;
    let mut text = format!("Added note {} to review {}\n", note.note_id, review_id);
    if let Some(s) = scope {
        writeln!(text, "  Scope: {}", s)?;
    }
    Ok(ReviewExecution {
        response: ReviewResponse { text, json: None },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn start_discussion(
    review_id: String,
    body: String,
    scope: Option<String>,
) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Discuss {
            review_id,
            body,
            scope,
        })
        .await?,
    );
    Ok(())
}

fn start_discussion_with_graph(
    graph: &kin_db::InMemoryGraph,
    review_id: String,
    body: String,
    scope: Option<String>,
) -> Result<ReviewExecution> {
    use kin_model::review::{
        ReviewComment, ReviewDiscussion, ReviewDiscussionId, ReviewDiscussionState, ReviewId,
    };
    use kin_model::timestamp::Timestamp;

    let scope = scope
        .as_deref()
        .map(crate::commands::work::parse_work_scope)
        .transpose()?;
    let rid = ReviewId(uuid::Uuid::parse_str(&review_id)?);
    let discussion = ReviewDiscussion {
        discussion_id: ReviewDiscussionId::new(),
        review_id: rid,
        scope: scope.clone(),
        state: ReviewDiscussionState::Open,
        comments: vec![ReviewComment {
            body: body.clone(),
            authored_by: kin_model::IdentityRef::human("cli-user"),
            created_at: Timestamp::now(),
        }],
        created_at: Timestamp::now(),
    };

    graph.create_review_discussion(&discussion)?;
    let mut text = format!(
        "Started discussion {} on review {}",
        discussion.discussion_id, review_id
    );
    text.push('\n');
    if let Some(s) = scope {
        writeln!(text, "  Scope: {}", s)?;
    }
    Ok(ReviewExecution {
        response: ReviewResponse { text, json: None },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn reply_discussion(discussion_id: String, body: String) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Reply {
            discussion_id,
            body,
        })
        .await?,
    );
    Ok(())
}

fn reply_discussion_with_graph(
    graph: &kin_db::InMemoryGraph,
    discussion_id: String,
    body: String,
) -> Result<ReviewExecution> {
    use kin_model::review::{ReviewComment, ReviewDiscussionId};
    use kin_model::timestamp::Timestamp;

    let did = ReviewDiscussionId(uuid::Uuid::parse_str(&discussion_id)?);
    let comment = ReviewComment {
        body: body.clone(),
        authored_by: kin_model::IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
    };

    graph.add_discussion_comment(&did, &comment)?;
    Ok(ReviewExecution {
        response: ReviewResponse {
            text: format!("Replied to discussion {}\n", discussion_id),
            json: None,
        },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn resolve_discussion(discussion_id: String) -> Result<()> {
    print_review_response(run_daemon_review(&ReviewRequest::Resolve { discussion_id }).await?);
    Ok(())
}

fn resolve_discussion_with_graph(
    graph: &kin_db::InMemoryGraph,
    discussion_id: String,
) -> Result<ReviewExecution> {
    use kin_model::review::{ReviewDiscussionId, ReviewDiscussionState};

    let did = ReviewDiscussionId(uuid::Uuid::parse_str(&discussion_id)?);
    graph.set_discussion_state(&did, ReviewDiscussionState::Resolved)?;
    Ok(ReviewExecution {
        response: ReviewResponse {
            text: format!("Resolved discussion {}\n", discussion_id),
            json: None,
        },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn assign_reviewer(review_id: String, reviewer: String) -> Result<()> {
    print_review_response(
        run_daemon_review(&ReviewRequest::Assign {
            review_id,
            reviewer,
        })
        .await?,
    );
    Ok(())
}

fn assign_reviewer_with_graph(
    graph: &kin_db::InMemoryGraph,
    review_id: String,
    reviewer: String,
) -> Result<ReviewExecution> {
    use kin_model::review::{ReviewAssignment, ReviewId};
    use kin_model::timestamp::Timestamp;

    let rid = ReviewId(uuid::Uuid::parse_str(&review_id)?);
    let assignment = ReviewAssignment {
        review_id: rid,
        reviewer: kin_model::IdentityRef::human(&reviewer),
        assigned_at: Timestamp::now(),
        assigned_by: kin_model::IdentityRef::human("cli-user"),
    };

    graph.assign_reviewer(&assignment)?;
    Ok(ReviewExecution {
        response: ReviewResponse {
            text: format!("Assigned {} to review {}\n", reviewer, review_id),
            json: None,
        },
        mutated: true,
        hydrated_changes: 0,
    })
}

pub async fn list_reviews(state: Option<String>) -> Result<()> {
    print_review_response(run_daemon_review(&ReviewRequest::List { state }).await?);
    Ok(())
}

fn list_reviews_with_graph(
    graph: &kin_db::InMemoryGraph,
    state: Option<String>,
) -> Result<ReviewExecution> {
    use kin_model::review::{ReviewDecisionState, ReviewFilter};

    let state_filter = state
        .as_deref()
        .map(|s| match s.to_lowercase().as_str() {
            "pending" => Ok(ReviewDecisionState::Pending),
            "approved" => Ok(ReviewDecisionState::Approved),
            "needs_work" | "needs-work" => Ok(ReviewDecisionState::NeedsWork),
            "blocked" => Ok(ReviewDecisionState::Blocked),
            _ => Err(anyhow::anyhow!(
                "invalid state: {}. Use: pending, approved, needs_work, blocked",
                s
            )),
        })
        .transpose()?;

    let filter = ReviewFilter {
        states: state_filter.map(|value| vec![value]),
        reviewer: None,
    };

    let reviews = graph.list_reviews(&filter)?;

    if reviews.is_empty() {
        return Ok(ReviewExecution {
            response: ReviewResponse {
                text: "No reviews found.\n".to_string(),
                json: None,
            },
            mutated: false,
            hydrated_changes: 0,
        });
    }

    let mut text = String::new();
    for review in &reviews {
        writeln!(
            text,
            "{} [{}] {} ({}..{})",
            review.review_id,
            format!("{:?}", review.state).to_lowercase(),
            review.title,
            review.base_ref,
            review.head_ref,
        )?;
    }
    writeln!(text, "\n{} review(s)", reviews.len())?;
    Ok(ReviewExecution {
        response: ReviewResponse { text, json: None },
        mutated: false,
        hydrated_changes: 0,
    })
}

pub async fn show_review(review_id: String) -> Result<()> {
    print_review_response(run_daemon_review(&ReviewRequest::Show { review_id }).await?);
    Ok(())
}

fn show_review_with_graph(
    graph: &kin_db::InMemoryGraph,
    review_id: String,
) -> Result<ReviewExecution> {
    use kin_model::review::ReviewId;

    let rid = ReviewId(uuid::Uuid::parse_str(&review_id)?);
    let review = graph
        .get_review(&rid)?
        .ok_or_else(|| anyhow::anyhow!("review not found: {}", review_id))?;

    let mut text = String::new();
    writeln!(text, "Review: {}", review.review_id)?;
    writeln!(text, "  Title: {}", review.title)?;
    writeln!(text, "  State: {:?}", review.state)?;
    writeln!(
        text,
        "  Base: {} -> Head: {}",
        review.base_ref, review.head_ref
    )?;

    let decisions = graph.get_review_decisions(&rid)?;
    if !decisions.is_empty() {
        writeln!(text, "\nDecisions:")?;
        for d in &decisions {
            writeln!(
                text,
                "  {:?} by {:?}{}",
                d.state,
                d.reviewer,
                d.comment
                    .as_ref()
                    .map(|comment| format!(" - {}", comment))
                    .unwrap_or_default()
            )?;
        }
    }

    let notes = graph.get_review_notes(&rid)?;
    if !notes.is_empty() {
        writeln!(text, "\nNotes:")?;
        for n in &notes {
            let scope_hint = n
                .scope
                .as_ref()
                .map(|scope| scope.to_string())
                .unwrap_or_else(|| "(global)".to_string());
            writeln!(text, "  [{}] {:?} - {}", scope_hint, n.authored_by, n.body)?;
        }
    }

    let discussions = graph.get_review_discussions(&rid)?;
    if !discussions.is_empty() {
        writeln!(text, "\nDiscussions:")?;
        for d in &discussions {
            let scope_hint = d
                .scope
                .as_ref()
                .map(|scope| scope.to_string())
                .unwrap_or_else(|| "(global)".to_string());
            writeln!(
                text,
                "  {} [{}] {}",
                d.discussion_id,
                scope_hint,
                format!("{:?}", d.state).to_lowercase()
            )?;
            for c in &d.comments {
                writeln!(text, "    {:?} - {}", c.authored_by, c.body)?;
            }
        }
    }

    let assignments = graph.get_review_assignments(&rid)?;
    if !assignments.is_empty() {
        writeln!(text, "\nAssigned reviewers:")?;
        for a in &assignments {
            writeln!(text, "  {:?}", a.reviewer)?;
        }
    }

    Ok(ReviewExecution {
        response: ReviewResponse { text, json: None },
        mutated: false,
        hydrated_changes: 0,
    })
}

fn inline_comment_severity(kind: kin_review::InlineCommentKind) -> &'static str {
    use kin_review::InlineCommentKind;

    match kind {
        InlineCommentKind::Breaking | InlineCommentKind::ContractViolation => "error",
        InlineCommentKind::CoverageGap
        | InlineCommentKind::SignatureChange
        | InlineCommentKind::VisibilityChange
        | InlineCommentKind::CommandEffectContract
        | InlineCommentKind::ToolchainSurfaceChange
        | InlineCommentKind::ConsumerFanout
        | InlineCommentKind::Renamed
        | InlineCommentKind::AgentUnreviewed
        | InlineCommentKind::RevertHistory => "warning",
        InlineCommentKind::Added
        | InlineCommentKind::Removed
        | InlineCommentKind::BreakingMigrated
        | InlineCommentKind::RevertHistoryIncidental => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::ProvenanceStore;

    #[test]
    fn command_effect_contract_comment_severity_is_warning() {
        assert_eq!(
            inline_comment_severity(kin_review::InlineCommentKind::CommandEffectContract),
            "warning"
        );
    }

    #[test]
    fn create_review_records_audit_event() {
        let graph = kin_db::InMemoryGraph::new();

        create_review_with_graph(
            &graph,
            "Fix login".into(),
            "main".into(),
            "feature/login".into(),
            Some("body edit".into()),
        )
        .unwrap();

        let events = graph.query_audit_events(None, 10).unwrap();
        assert_eq!(events.len(), 1, "review create must record one audit event");
        assert_eq!(events[0].action, "review.create");
        let details = events[0].details.as_deref().unwrap_or_default();
        assert!(
            details.contains("base=main") && details.contains("head=feature/login"),
            "audit details should carry review refs: {details}"
        );
    }

    #[test]
    fn decide_review_records_audit_event() {
        let graph = kin_db::InMemoryGraph::new();

        let execution = create_review_with_graph(
            &graph,
            "Fix login".into(),
            "main".into(),
            "feature/login".into(),
            None,
        )
        .unwrap();
        // Recover the review id from the create response text.
        let review_id = execution
            .response
            .text
            .lines()
            .find_map(|line| line.strip_prefix("Created review "))
            .map(|s| s.trim().to_string())
            .expect("review id in create response");

        decide_review_with_graph(&graph, review_id, "approved".into(), None).unwrap();

        let events = graph.query_audit_events(None, 10).unwrap();
        assert_eq!(
            events.len(),
            2,
            "create + decide must each record an audit event"
        );
        // query_audit_events returns most-recent first.
        assert_eq!(events[0].action, "review.decide");
        assert_eq!(events[1].action, "review.create");
    }

    /// The everyday "your branch is behind main" case: a stale, unrelated
    /// base against a raw Git commit head that has never been imported.
    /// Proves the fast path returns the identical `base_not_on_head_ancestry`
    /// gap report without ever hydrating either side — checked structurally
    /// (both refs still report "requires hydration" afterward), not by wall
    /// clock, per the fix's own contract.
    #[test]
    fn shadow_stale_base_returns_gap_report_without_hydrating() {
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();

        let git = |args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(repo)
                .output()
                .expect("run git");
            assert!(
                output.status.success(),
                "git {:?} failed: stdout={} stderr={}",
                args,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        let commit = |file: &str, content: &str, message: &str, epoch: &str| {
            std::fs::write(repo.join(file), content).unwrap();
            git(&["add", "."]);
            let date = format!("{epoch} +0000");
            let output = Command::new("git")
                .args(["commit", "-m", message])
                .env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date)
                .current_dir(repo)
                .output()
                .expect("git commit");
            assert!(output.status.success(), "git commit failed");
        };
        let head_sha = || {
            let output = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(repo)
                .output()
                .expect("git rev-parse HEAD");
            String::from_utf8(output.stdout)
                .expect("utf8 sha")
                .trim()
                .to_string()
        };

        git(&["init"]);
        git(&["config", "user.email", "shadow-fastpath@example.com"]);
        git(&["config", "user.name", "Shadow Fastpath Test"]);

        commit("a.txt", "1\n", "root", "1000000000");
        let root = head_sha();

        commit("a.txt", "a\n", "branch a", "1000000100");
        let branch_a = head_sha();

        // Fork branch b from root, independent of branch a — neither is an
        // ancestor of the other.
        git(&["checkout", &root]);
        commit("a.txt", "b\n", "branch b", "1000000200");
        let branch_b = head_sha();

        let layout = kin_core::KinLayout::new(repo.join(".kin"));
        let graph = kin_db::InMemoryGraph::new();

        assert!(
            crate::commands::ref_lookup::git_ref_requires_hydration(&graph, &branch_a),
            "branch a must not be imported before the call"
        );
        assert!(
            crate::commands::ref_lookup::git_ref_requires_hydration(&graph, &branch_b),
            "branch b must not be imported before the call"
        );

        let (response, hydrated_changes) = build_shadow_run_response(
            &layout,
            &graph,
            branch_a.clone(),
            branch_b.clone(),
            None,
            None,
            None,
            true,
        )
        .expect("a stale base must produce a gap report, not an error");

        assert_eq!(
            hydrated_changes, 0,
            "the fast path must report no hydration was performed"
        );

        let json: serde_json::Value =
            serde_json::from_str(response.json.as_deref().expect("json response")).unwrap();
        assert_eq!(json["hydrated_changes"], 0);
        assert_eq!(json["review_mutations"], 0);
        let gaps = json["evidence_gaps"].as_array().unwrap();
        assert!(
            gaps.iter()
                .any(|gap| gap["kind"] == "base_not_on_head_ancestry"),
            "expected a base_not_on_head_ancestry gap: {gaps:?}"
        );

        // Structural proof, not a timing assertion: neither commit was ever
        // imported into the graph, so both still report "requires hydration".
        assert!(
            crate::commands::ref_lookup::git_ref_requires_hydration(&graph, &branch_a),
            "branch a must remain un-imported: the fast path must not hydrate it"
        );
        assert!(
            crate::commands::ref_lookup::git_ref_requires_hydration(&graph, &branch_b),
            "branch b must remain un-imported: the fast path must not hydrate it"
        );
    }

    /// Warm case: both `kin:` refs already resolve directly, so no Git
    /// hydration ever runs. The response must report `hydrated_changes: 0`
    /// distinctly from `review_mutations: 0` — two truthful zeros, not a
    /// single collapsed flag — both in the returned count and in the actual
    /// JSON payload a client parses.
    #[test]
    fn shadow_reports_zero_hydrated_changes_when_refs_need_no_import() {
        let graph = kin_db::InMemoryGraph::new();
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/nonexistent/.kin"));

        let base_id =
            kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0x10; 32]));
        let head_id =
            kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0x20; 32]));
        graph
            .create_change(&kin_model::SemanticChange {
                id: base_id,
                parents: vec![],
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: "base".into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();
        graph
            .create_change(&kin_model::SemanticChange {
                id: head_id,
                parents: vec![base_id],
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: "head".into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let (response, hydrated_changes) = build_shadow_run_response(
            &layout,
            &graph,
            format!("kin:{base_id}"),
            format!("kin:{head_id}"),
            None,
            None,
            None,
            true,
        )
        .unwrap();

        assert_eq!(
            hydrated_changes, 0,
            "already-resolved refs must report zero hydrated changes"
        );
        let json: serde_json::Value =
            serde_json::from_str(response.json.as_deref().expect("json response")).unwrap();
        assert_eq!(json["hydrated_changes"], 0);
        assert_eq!(json["review_mutations"], 0);
    }
}
