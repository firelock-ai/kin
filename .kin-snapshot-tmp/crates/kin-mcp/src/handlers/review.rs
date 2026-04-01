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

    for eid in &changed_ids {
        if let Ok(Some(federated)) = fetch_spine_impact_typed(&repo_id, eid, depth).await {
            for node in federated.nodes {
                if node.repo_id != repo_id {
                    cross_repo_nodes.push(node);
                }
            }
        }
    }

    if !cross_repo_nodes.is_empty() {
        result["cross_repo_impact"] =
            serde_json::to_value(&cross_repo_nodes).map_err(McpError::Json)?;
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
    use kin_model::review::{
        Review, ReviewAssignment, ReviewCompletionState, ReviewDecisionState, ReviewId,
    };
    use kin_model::timestamp::Timestamp;

    let title = get_string_param(args, "title")?;
    let base = get_optional_string_param(args, "base").unwrap_or_else(|| "working-tree".into());
    let head = get_optional_string_param(args, "head").unwrap_or_else(|| "working-tree".into());
    let scopes = parse_review_create_scopes(args)?;
    let created_by = parse_identity_arg(args, "created_by", "created_by_kind", "mcp-client");
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

    store
        .create_review(&review)
        .map_err(|e| McpError::Other(e.to_string()))?;

    for reviewer in parse_reviewer_list(args)? {
        let assignment = ReviewAssignment {
            review_id: review.review_id,
            reviewer: kin_model::IdentityRef::human(reviewer),
            assigned_at: now.clone(),
            assigned_by: created_by.clone(),
        };
        store
            .assign_reviewer(&assignment)
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

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
    let comment_str = get_optional_string_param(args, "comment")
        .or_else(|| get_optional_string_param(args, "summary"))
        .unwrap_or_default();
    let reviewer = parse_identity_arg(args, "reviewer", "reviewer_kind", "mcp-client");

    let state = parse_review_decision_state(&state_str)?;

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

    store
        .add_review_decision(&review_id, &decision)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "state": state_str,
        "reviewer": reviewer.name,
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
    let scope = parse_optional_scope_arg(args)?;
    let author = parse_identity_arg(args, "author", "author_kind", "mcp-client");

    let note = ReviewNote {
        note_id: ReviewNoteId::new(),
        review_id,
        body: body.clone(),
        scope: scope.clone(),
        authored_by: author.clone(),
        created_at: Timestamp::now(),
    };

    store
        .add_review_note(&note)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "note_id": note.note_id.to_string(),
        "review_id": review_id.to_string(),
        "scope": scope.map(|s| s.to_string()),
        "author": author.name,
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
    let scope = parse_optional_scope_arg(args)?;
    let author = parse_identity_arg(args, "author", "author_kind", "mcp-client");

    let discussion_id = ReviewDiscussionId::new();
    let discussion = ReviewDiscussion {
        discussion_id,
        review_id,
        scope: scope.clone(),
        state: ReviewDiscussionState::Open,
        comments: vec![ReviewComment {
            body: body.clone(),
            authored_by: author.clone(),
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
        "author": author.name,
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
    let author = parse_identity_arg(args, "author", "author_kind", "mcp-client");

    let comment = ReviewComment {
        body: body.clone(),
        authored_by: author.clone(),
        created_at: Timestamp::now(),
    };

    store
        .add_discussion_comment(&discussion_id, &comment)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "discussion_id": discussion_id.to_string(),
        "replied": true,
        "author": author.name,
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
    let reviewers = parse_reviewer_list(args)?;
    let assigner = parse_identity_arg(args, "assigned_by", "assigned_by_kind", "mcp-client");
    let assigned_at = Timestamp::now();

    for reviewer in &reviewers {
        let assignment = ReviewAssignment {
            review_id,
            reviewer: kin_model::IdentityRef::human(reviewer.clone()),
            assigned_at: assigned_at.clone(),
            assigned_by: assigner.clone(),
        };

        store
            .assign_reviewer(&assignment)
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

    let result = serde_json::json!({
        "review_id": review_id.to_string(),
        "reviewers": reviewers,
        "assigned_by": assigner.name,
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
fn parse_optional_work_scope(val: Option<&serde_json::Value>) -> Option<kin_model::WorkScope> {
    val.and_then(|v| v.as_str())
        .and_then(|s| parse_single_work_scope(s).ok())
}

fn parse_optional_scope_arg(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Option<kin_model::WorkScope>> {
    if let Some(scope) = parse_optional_work_scope(args.get("scope")) {
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
    let scopes = parse_work_scopes(args.get("scopes")).unwrap_or_default();
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

fn parse_reviewer_list(args: &HashMap<String, serde_json::Value>) -> Result<Vec<String>> {
    let mut reviewers = Vec::new();

    if let Some(reviewer) = get_optional_string_param(args, "reviewer") {
        let trimmed = reviewer.trim();
        if !trimmed.is_empty() {
            reviewers.push(trimmed.to_string());
        }
    }

    if let Some(values) = args.get("reviewers").and_then(|value| value.as_array()) {
        for value in values {
            let reviewer = value.as_str().ok_or_else(|| {
                McpError::InvalidParams("reviewers entries must be strings".into())
            })?;
            let trimmed = reviewer.trim();
            if !trimmed.is_empty() {
                reviewers.push(trimmed.to_string());
            }
        }
    }

    reviewers.sort();
    reviewers.dedup();

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
    use super::*;

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
}
