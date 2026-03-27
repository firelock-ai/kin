// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;
use kin_review::{format_review, SemanticReview};

use crate::error::{McpError, Result};
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

use super::common::*;

pub fn handle_semantic_diff<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let diff = resolve_diff(args, store)?;
    let formatted = kin_review::format_diff(&diff);
    Ok(ToolCallResult::text(formatted))
}

pub fn handle_impact_analysis<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let diff = resolve_diff(args, store)?;

    let impact =
        kin_review::analyze_impact(store, &diff).map_err(|e| McpError::Review(e.to_string()))?;

    let mut result = serde_json::to_value(&impact).map_err(McpError::Json)?;

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

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_semantic_review<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let diff = resolve_diff(args, store)?;

    let review = SemanticReview::review_from_diff(diff, store)
        .map_err(|e| McpError::Review(e.to_string()))?;

    let formatted = format_review(&review);

    if include_traffic {
        // Collect traffic for all entities in the diff.
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

pub fn handle_review_create<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::{Review, ReviewCompletionState, ReviewDecisionState, ReviewId};
    use kin_model::timestamp::Timestamp;

    let title = get_string_param(args, "title")?;
    let base = get_string_param(args, "base")?;
    let head = get_string_param(args, "head")?;
    let scopes = parse_work_scopes(args.get("scopes")).unwrap_or_default();
    let now = Timestamp::now();

    let review = Review {
        review_id: ReviewId::new(),
        title,
        base_ref: base,
        head_ref: head,
        state: ReviewDecisionState::Pending,
        completion: ReviewCompletionState::InReview,
        scopes,
        created_by: kin_model::IdentityRef::assistant("mcp-client"),
        created_at: now.clone(),
        updated_at: now,
    };

    store
        .create_review(&review)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "review_id": review.review_id.to_string(),
        "title": review.title,
        "state": "pending",
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_decide<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::ReviewDecision;
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let state_str = get_string_param(args, "state")?;
    let comment_str = get_optional_string_param(args, "comment").unwrap_or_default();
    let reviewer =
        get_optional_string_param(args, "reviewer").unwrap_or_else(|| "mcp-client".to_string());

    let state = parse_review_decision_state(&state_str)?;

    let decision = ReviewDecision {
        state,
        comment: if comment_str.is_empty() {
            None
        } else {
            Some(comment_str)
        },
        reviewer: kin_model::IdentityRef::human(&reviewer),
        decided_at: Timestamp::now(),
    };

    store
        .add_review_decision(&review_id, &decision)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "state": state_str,
        "reviewer": reviewer,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_note_add<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::{ReviewNote, ReviewNoteId};
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let body = get_string_param(args, "body")?;
    let scope = parse_optional_work_scope(args.get("scope"));
    let author =
        get_optional_string_param(args, "author").unwrap_or_else(|| "mcp-client".to_string());

    let note = ReviewNote {
        note_id: ReviewNoteId::new(),
        review_id,
        body: body.clone(),
        scope: scope.clone(),
        authored_by: kin_model::IdentityRef::assistant(&author),
        created_at: Timestamp::now(),
    };

    store
        .add_review_note(&note)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "note_id": note.note_id.to_string(),
        "review_id": review_id.to_string(),
        "scope": scope.map(|s| s.to_string()),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_discuss<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::{
        ReviewComment, ReviewDiscussion, ReviewDiscussionId, ReviewDiscussionState,
    };
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let body = get_string_param(args, "body")?;
    let scope = parse_optional_work_scope(args.get("scope"));
    let author =
        get_optional_string_param(args, "author").unwrap_or_else(|| "mcp-client".to_string());

    let discussion_id = ReviewDiscussionId::new();
    let discussion = ReviewDiscussion {
        discussion_id,
        review_id,
        scope: scope.clone(),
        state: ReviewDiscussionState::Open,
        comments: vec![ReviewComment {
            body: body.clone(),
            authored_by: kin_model::IdentityRef::assistant(&author),
            created_at: Timestamp::now(),
        }],
        created_at: Timestamp::now(),
    };

    store
        .create_review_discussion(&discussion)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "review_id": review_id.to_string(),
        "scope": scope.map(|s| s.to_string()),
        "state": "open",
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_discuss_reply<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::ReviewComment;
    use kin_model::timestamp::Timestamp;

    let discussion_id = parse_discussion_id(args, "discussion_id")?;
    let body = get_string_param(args, "body")?;
    let author =
        get_optional_string_param(args, "author").unwrap_or_else(|| "mcp-client".to_string());

    let comment = ReviewComment {
        body: body.clone(),
        authored_by: kin_model::IdentityRef::assistant(&author),
        created_at: Timestamp::now(),
    };

    store
        .add_discussion_comment(&discussion_id, &comment)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "replied": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_discuss_resolve<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::ReviewDiscussionState;

    let discussion_id = parse_discussion_id(args, "discussion_id")?;
    let resolved = get_optional_bool(args, "resolved", true);

    let new_state = if resolved {
        ReviewDiscussionState::Resolved
    } else {
        ReviewDiscussionState::Open
    };

    store
        .set_discussion_state(&discussion_id, new_state)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "state": if resolved { "resolved" } else { "open" },
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_assign<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::ReviewAssignment;
    use kin_model::timestamp::Timestamp;

    let review_id = parse_review_id(args, "review_id")?;
    let reviewer = get_string_param(args, "reviewer")?;
    let assigner = get_optional_string_param(args, "assigned_by")
        .unwrap_or_else(|| "mcp-client".to_string());

    let assignment = ReviewAssignment {
        review_id,
        reviewer: kin_model::IdentityRef::human(&reviewer),
        assigned_at: Timestamp::now(),
        assigned_by: kin_model::IdentityRef::assistant(&assigner),
    };

    store
        .assign_reviewer(&assignment)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "reviewer": reviewer,
        "assigned": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_unassign<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let review_id = parse_review_id(args, "review_id")?;
    let reviewer = get_string_param(args, "reviewer")?;

    store
        .remove_reviewer(&review_id, &reviewer)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "reviewer": reviewer,
        "unassigned": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    use kin_model::review::ReviewFilter;

    let state = get_optional_string_param(args, "state");
    let state_filter = state
        .as_deref()
        .map(parse_review_decision_state)
        .transpose()?;

    let filter = ReviewFilter {
        states: state_filter.map(|s| vec![s]),
        reviewer: None,
    };

    let reviews = store
        .list_reviews(&filter)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result: Vec<_> = reviews
        .iter()
        .map(|r| {
            serde_json::json!({
                "review_id": r.review_id.to_string(),
                "title": r.title,
                "state": format!("{:?}", r.state).to_lowercase(),
                "base_ref": r.base_ref,
                "head_ref": r.head_ref,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub fn handle_review_get<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let review_id = parse_review_id(args, "review_id")?;

    let review = store
        .get_review(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("review not found: {}", review_id)))?;

    let decisions = store
        .get_review_decisions(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let notes = store
        .get_review_notes(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let discussions = store
        .get_review_discussions(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let assignments = store
        .get_review_assignments(&review_id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "review_id": review.review_id.to_string(),
        "title": review.title,
        "state": format!("{:?}", review.state).to_lowercase(),
        "base_ref": review.base_ref,
        "head_ref": review.head_ref,
        "scopes": review.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "decisions": decisions.iter().map(|d| serde_json::json!({
            "state": format!("{:?}", d.state).to_lowercase(),
            "comment": d.comment,
            "reviewer": d.reviewer.name,
        })).collect::<Vec<_>>(),
        "notes": notes.iter().map(|n| serde_json::json!({
            "note_id": n.note_id.to_string(),
            "body": n.body,
            "scope": n.scope.as_ref().map(|s| s.to_string()),
            "author": n.authored_by.name,
        })).collect::<Vec<_>>(),
        "discussions": discussions.iter().map(|d| serde_json::json!({
            "discussion_id": d.discussion_id.to_string(),
            "state": format!("{:?}", d.state).to_lowercase(),
            "scope": d.scope.as_ref().map(|s| s.to_string()),
            "comments": d.comments.iter().map(|c| serde_json::json!({
                "body": c.body,
                "author": c.authored_by.name,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "assignments": assignments.iter().map(|a| serde_json::json!({
            "reviewer": a.reviewer.name,
        })).collect::<Vec<_>>(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
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
    use kin_model::review::ReviewDecisionState;
    match s.to_lowercase().as_str() {
        "pending" => Ok(ReviewDecisionState::Pending),
        "approved" | "approve" => Ok(ReviewDecisionState::Approved),
        "needs_work" | "needs-work" | "needswork" => Ok(ReviewDecisionState::NeedsWork),
        "blocked" | "block" => Ok(ReviewDecisionState::Blocked),
        _ => Err(McpError::InvalidParams(format!(
            "invalid review state: {}. Valid values: pending, approved, needs_work, blocked",
            s
        ))),
    }
}

/// Parse an optional work scope from a JSON value (string like "entity:ID").
fn parse_optional_work_scope(
    val: Option<&serde_json::Value>,
) -> Option<kin_model::WorkScope> {
    val.and_then(|v| v.as_str())
        .and_then(|s| parse_work_scope_str(s).ok())
}

fn parse_work_scope_str(s: &str) -> Result<kin_model::WorkScope> {
    use kin_model::{EntityId, FilePathId, WorkScope};
    if let Some(rest) = s.strip_prefix("entity:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|e| McpError::InvalidParams(format!("invalid entity id: {}", e)))?;
        Ok(WorkScope::Entity(EntityId(uuid)))
    } else if let Some(rest) = s.strip_prefix("artifact:") {
        Ok(WorkScope::Artifact(FilePathId::new(rest)))
    } else {
        Err(McpError::InvalidParams(format!(
            "invalid scope format: {}. Expected 'entity:<id>' or 'artifact:<path>'",
            s
        )))
    }
}
