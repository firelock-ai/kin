// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;
use kin_model::timestamp::Timestamp;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

pub const WORK_CREATE_DESC: &str = "\
Create a work item in Kin's work graph (a feature, task, issue, debt, todo, or \
investigation) with a title and optional description, acceptance criteria, and linked \
scopes. Reach for it to capture a unit of work as first-class graph truth so it can be \
linked to the actual entities it concerns, decomposed into children, blocked by other \
work, and tracked through status changes. Returns the new work item's ID, which the \
other kin_work_* tools operate on. This keeps planning attached to code rather than \
living in a separate tracker.";

pub fn handle_work_create<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let kind_str = get_string_param(args, "kind")?;
    let title = get_string_param(args, "title")?;
    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let kind: kin_model::WorkKind = kind_str
        .parse()
        .map_err(|e: String| McpError::InvalidParams(e))?;

    let scopes = parse_work_scopes(args.get("scopes"))?;
    let acceptance_criteria = args
        .get("acceptance_criteria")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let item = kin_model::WorkItem {
        work_id: kin_model::WorkId::new(),
        kind,
        title: title.clone(),
        description,
        status: kin_model::WorkStatus::Proposed,
        priority: kin_model::Priority::None,
        scopes,
        acceptance_criteria,
        external_refs: vec![],
        created_by: kin_model::IdentityRef::assistant("mcp-client"),
        created_at: Timestamp::now(),
    };

    store
        .create_work_item(&item)
        .map_err(|e| McpError::Other(e.to_string()))?;
    for scope in &item.scopes {
        store
            .create_work_link(&kin_model::WorkLink::Affects {
                work_id: item.work_id,
                scope: scope.clone(),
            })
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

    let result = serde_json::json!({
        "work_id": item.work_id.to_string(),
        "kind": item.kind.to_string(),
        "title": title,
        "status": "proposed",
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const WORK_LIST_DESC: &str = "\
List work items, optionally filtered by status (proposed, planned, in_progress, \
blocked, done, verified, archived), kind, or scope. Reach for it to survey the backlog \
or current work: what's in progress, what's blocked, what touches a given scope. \
Returns compact rows; use kin_work_show to pull the full detail (relationships, \
annotations) of a specific item.";

pub fn handle_work_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let status = args.get("status").and_then(|v| v.as_str());
    let kind = args.get("kind").and_then(|v| v.as_str());
    let scope = args.get("scope").and_then(|v| v.as_str());

    let filter = kin_model::WorkFilter {
        statuses: status
            .map(|s| {
                s.parse::<kin_model::WorkStatus>()
                    .map(|ws| vec![ws])
                    .map_err(McpError::InvalidParams)
            })
            .transpose()?,
        kinds: kind
            .map(|k| {
                k.parse::<kin_model::WorkKind>()
                    .map(|wk| vec![wk])
                    .map_err(McpError::InvalidParams)
            })
            .transpose()?,
        scope: scope.map(parse_single_work_scope).transpose()?,
    };

    let items = store
        .list_work_items(&filter)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result: Vec<_> = items
        .iter()
        .map(|i| {
            serde_json::json!({
                "work_id": i.work_id.to_string(),
                "kind": i.kind.to_string(),
                "title": i.title,
                "status": i.status.to_string(),
                "priority": i.priority.to_string(),
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const WORK_SHOW_DESC: &str = "\
Show one work item in full: its details plus its graph relationships (parents, \
children, blockers, the scopes/entities implementing it) and any attached annotations. \
Reach for it to understand a single piece of work in context: what it depends on, what \
breaks it down into, and what code realizes it. It assembles the whole picture in one \
call rather than chasing each relationship separately. Find work IDs with kin_work_list.";

pub fn handle_work_show<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, id) = parse_work_id_param(args, "work_id")?;

    let item = store
        .get_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", work_id_str)))?;

    let children = store
        .get_child_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let parents = store
        .get_parent_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let blockers = store
        .get_blockers(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let blocked_items = store
        .get_blocked_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let implementors = store
        .get_implementors(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let annotations = store
        .get_annotations_for_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "work_id": item.work_id.to_string(),
        "kind": item.kind.to_string(),
        "title": item.title,
        "description": item.description,
        "status": item.status.to_string(),
        "priority": item.priority.to_string(),
        "scopes": item.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "acceptance_criteria": item.acceptance_criteria,
        "parents": parents.iter().map(summarize_work_item).collect::<Vec<_>>(),
        "children": children.iter().map(|c| serde_json::json!({
            "work_id": c.work_id.to_string(),
            "kind": c.kind.to_string(),
            "title": c.title,
            "status": c.status.to_string(),
        })).collect::<Vec<_>>(),
        "blockers": blockers.iter().map(summarize_work_item).collect::<Vec<_>>(),
        "blocked_items": blocked_items.iter().map(summarize_work_item).collect::<Vec<_>>(),
        "implementors": implementors.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "annotations": annotations.iter().map(summarize_annotation).collect::<Vec<_>>(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const WORK_LINK_DESC: &str = "\
Link a work item to semantic scopes: the entities, contracts, or artifacts it concerns. \
Reach for it to connect planning to code so the work item shows up in context when \
someone looks at those scopes, and so impact/coverage reasoning can relate work to the \
declarations it touches. This expresses what the work is *about*; use kin_work_implement \
to record the scopes that actually *implement* it.";

pub fn handle_work_link<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, id) = parse_work_id_param(args, "work_id")?;

    let scopes = parse_work_scopes(args.get("scopes"))?;
    if scopes.is_empty() {
        return Err(McpError::InvalidParams("scopes array is empty".into()));
    }

    let mut item = store
        .get_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", work_id_str)))?;

    for scope in &scopes {
        if !item.scopes.contains(scope) {
            item.scopes.push(scope.clone());
        }
        let link = kin_model::WorkLink::Affects {
            work_id: id,
            scope: scope.clone(),
        };
        store
            .create_work_link(&link)
            .map_err(|e| McpError::Other(e.to_string()))?;
    }
    store
        .create_work_item(&item)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "work_id": work_id_str,
        "linked_scopes": scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const WORK_DECOMPOSE_DESC: &str = "\
Establish a parent/child relationship between two work items, breaking a larger item \
down into a smaller one. Reach for it to build a work hierarchy (an epic into tasks, a \
feature into subtasks) so progress and structure roll up through the graph. Both items \
must already exist (create them with kin_work_create first).";

pub fn handle_work_decompose<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (parent_work_id, parent) = parse_work_id_param(args, "parent_work_id")?;
    let (child_work_id, child) = parse_work_id_param(args, "child_work_id")?;
    ensure_work_item_exists(store, &parent, &parent_work_id)?;
    ensure_work_item_exists(store, &child, &child_work_id)?;
    store
        .create_work_link(&kin_model::WorkLink::DecomposesTo { parent, child })
        .map_err(|e| McpError::Other(e.to_string()))?;
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "parent_work_id": parent_work_id,
            "child_work_id": child_work_id,
            "linked": true,
        }))
        .map_err(McpError::Json)?,
    ))
}

pub const WORK_BLOCK_DESC: &str = "\
Record that one work item is blocked by another. Reach for it to capture real \
dependencies between pieces of work so the graph reflects what can't start until \
something else lands. This is useful for sequencing and for surfacing what's holding a task up \
(visible via kin_work_show). Both items must already exist.";

pub fn handle_work_block<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (blocked_work_id, blocked) = parse_work_id_param(args, "blocked_work_id")?;
    let (blocker_work_id, blocker) = parse_work_id_param(args, "blocker_work_id")?;
    ensure_work_item_exists(store, &blocked, &blocked_work_id)?;
    ensure_work_item_exists(store, &blocker, &blocker_work_id)?;
    store
        .create_work_link(&kin_model::WorkLink::BlockedBy { blocked, blocker })
        .map_err(|e| McpError::Other(e.to_string()))?;
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "blocked_work_id": blocked_work_id,
            "blocker_work_id": blocker_work_id,
            "linked": true,
        }))
        .map_err(McpError::Json)?,
    ))
}

pub const WORK_IMPLEMENT_DESC: &str = "\
Record the semantic scopes (entities, contracts, artifacts) that actually implement a \
work item: the code that fulfills it. Reach for it once you've written or identified \
the implementation, so the graph ties the work to its realization: this powers \
traceability (\"what code delivered this feature?\") and lets coverage/verification \
relate tests back to the work. Distinct from kin_work_link, which marks what the work \
is merely *about*.";

pub fn handle_work_implement<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, work_id) = parse_work_id_param(args, "work_id")?;
    ensure_work_item_exists(store, &work_id, &work_id_str)?;
    let scopes = parse_work_scopes(args.get("scopes"))?;
    if scopes.is_empty() {
        return Err(McpError::InvalidParams("scopes array is empty".into()));
    }
    for scope in &scopes {
        store
            .create_work_link(&kin_model::WorkLink::Implements {
                scope: scope.clone(),
                work_id,
            })
            .map_err(|e| McpError::Other(e.to_string()))?;
    }
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "work_id": work_id_str,
            "implementors": scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        }))
        .map_err(McpError::Json)?,
    ))
}

pub const WORK_STATUS_DESC: &str = "\
Update a work item's status: proposed, planned, in_progress, blocked, done, verified, \
or archived. Reach for it to move work through its lifecycle so the graph reflects \
current reality and kin_work_list filters stay meaningful. The item must already exist.";

pub fn handle_work_status<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, work_id) = parse_work_id_param(args, "work_id")?;
    ensure_work_item_exists(store, &work_id, &work_id_str)?;
    let status_str = get_string_param(args, "status")?;
    let status = status_str
        .parse::<kin_model::WorkStatus>()
        .map_err(McpError::InvalidParams)?;
    store
        .update_work_status(&work_id, status)
        .map_err(|e| McpError::Other(e.to_string()))?;
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "work_id": work_id_str,
            "status": status.to_string(),
        }))
        .map_err(McpError::Json)?,
    ))
}

pub const ANNOTATION_ADD_DESC: &str = "\
Attach a semantic annotation (a comment, warning, instruction, or piece of reasoning) \
to one or more targets (entities, contracts, artifacts, changes, or work items). Reach \
for it to leave durable, scope-anchored knowledge in the graph: a warning on a fragile \
function, an instruction for whoever touches a module, the reasoning behind a decision. \
Because annotations attach to graph scopes rather than file lines, they surface in \
context (e.g. in get_context_pack) and travel with the code as it evolves, instead of \
rotting as an inline comment. List them with kin_annotation_list and clear them with \
kin_annotation_mark_resolved.";

pub fn handle_annotation_add<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let kind_str = get_string_param(args, "kind")?;
    let body = get_string_param(args, "body")?;
    let kind: kin_model::AnnotationKind = kind_str
        .parse()
        .map_err(|e: String| McpError::InvalidParams(e))?;

    let targets = parse_annotation_targets(args)?;
    if targets.is_empty() {
        return Err(McpError::InvalidParams(
            "targets or scopes must contain at least one value".into(),
        ));
    }

    let mut scopes = Vec::new();
    let mut seen_scopes = std::collections::HashSet::new();
    for target in &targets {
        match target {
            kin_model::AnnotationTarget::Scope(scope) => {
                if seen_scopes.insert(scope.to_string()) {
                    scopes.push(scope.clone());
                }
            }
            kin_model::AnnotationTarget::Work(work_id) => {
                let item = ensure_work_item_exists(store, work_id, &work_id.to_string())?;
                for scope in item.scopes {
                    if seen_scopes.insert(scope.to_string()) {
                        scopes.push(scope);
                    }
                }
            }
        }
    }

    let ann = kin_model::Annotation {
        annotation_id: kin_model::AnnotationId::new(),
        kind,
        body: body.clone(),
        scopes,
        anchored_fingerprint: None,
        authored_by: kin_model::IdentityRef::assistant("mcp-client"),
        created_at: Timestamp::now(),
        staleness: kin_model::StalenessState::Fresh,
    };

    store
        .create_annotation(&ann)
        .map_err(|e| McpError::Other(e.to_string()))?;
    for target in &targets {
        store
            .create_work_link(&kin_model::WorkLink::AttachedTo {
                annotation_id: ann.annotation_id,
                target: target.clone(),
            })
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

    let result = serde_json::json!({
        "annotation_id": ann.annotation_id.to_string(),
        "kind": ann.kind.to_string(),
        "targets": targets.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const ANNOTATION_LIST_DESC: &str = "\
List the annotations attached to given targets (entities, contracts, artifacts, \
changes, or work items), or across the graph when no targets are given. Set \
include_stale to control whether annotations whose anchor has drifted are included. \
Reach for it to surface the warnings, instructions, comments, and reasoning recorded \
about the code you're about to touch. This is the read side of kin_annotation_add. Resolve \
ones that no longer apply with kin_annotation_mark_resolved.";

pub fn handle_annotation_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let include_stale = get_optional_bool(args, "include_stale", true);
    let targets = parse_annotation_targets(args)?;

    let annotations = if targets.is_empty() {
        let filter = kin_model::AnnotationFilter {
            include_stale,
            ..Default::default()
        };
        store
            .list_annotations(&filter)
            .map_err(|e| McpError::Other(e.to_string()))?
    } else {
        let mut seen = std::collections::HashSet::new();
        let mut collected = Vec::new();
        for target in targets {
            let items = match target {
                kin_model::AnnotationTarget::Scope(scope) => store
                    .get_annotations_for_scope(&scope)
                    .map_err(|e| McpError::Other(e.to_string()))?,
                kin_model::AnnotationTarget::Work(work_id) => store
                    .get_annotations_for_work_item(&work_id)
                    .map_err(|e| McpError::Other(e.to_string()))?,
            };
            for annotation in items {
                if (!matches!(annotation.staleness, kin_model::StalenessState::Stale)
                    || include_stale)
                    && seen.insert(annotation.annotation_id)
                {
                    collected.push(annotation);
                }
            }
        }
        collected
    };

    let result: Vec<_> = annotations
        .iter()
        .map(|a| {
            serde_json::json!({
                "annotation_id": a.annotation_id.to_string(),
                "kind": a.kind.to_string(),
                "body": a.body,
                "staleness": a.staleness.to_string(),
                "scopes": a.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const ANNOTATION_MARK_RESOLVED_DESC: &str = "\
Mark an annotation as resolved, which removes it. Reach for it once a warning has been \
addressed, an instruction carried out, or a comment is no longer relevant, so the graph \
stops surfacing stale guidance on the affected scopes. The counterpart to \
kin_annotation_add; find the annotation IDs with kin_annotation_list.";

pub fn handle_annotation_mark_resolved<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let ann_id_str = get_string_param(args, "annotation_id")?;
    let uuid = uuid::Uuid::parse_str(&ann_id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid annotation_id: {}", ann_id_str)))?;
    let id = kin_model::AnnotationId(uuid);

    store
        .delete_annotation(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "annotation_id": ann_id_str,
        "resolved": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const TODO_IMPORT_DESC: &str = "\
Scan source files for inline TODO/FIXME/HACK markers and import each as a work item in \
the graph. Point it at a root directory (defaults to the working directory). Reach for \
it to promote scattered in-code reminders into tracked, linkable work, so they can be \
prioritized, decomposed, and tracked like any other work item rather than being lost in \
comments. A one-shot way to bootstrap a backlog from an existing codebase.";

pub fn handle_todo_import<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let todos = kin_parser::extract_todos(&path)
        .map_err(|e| McpError::Other(format!("todo extraction failed: {}", e)))?;

    let mut imported = 0usize;
    for todo in &todos {
        let work_kind = match todo.kind.as_str() {
            "FIXME" => kin_model::WorkKind::Issue,
            "HACK" => kin_model::WorkKind::Debt,
            _ => kin_model::WorkKind::Todo,
        };

        let item = kin_model::WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: work_kind,
            title: todo.body.clone(),
            description: format!(
                "Imported from {} (line {})",
                todo.file_path, todo.line_number
            ),
            status: kin_model::WorkStatus::Proposed,
            priority: if todo.kind == "FIXME" {
                kin_model::Priority::High
            } else {
                kin_model::Priority::Medium
            },
            scopes: vec![kin_model::WorkScope::Artifact(kin_model::FilePathId::new(
                &todo.file_path,
            ))],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: kin_model::IdentityRef::assistant("kin-todo-import"),
            created_at: Timestamp::now(),
        };

        store
            .create_work_item(&item)
            .map_err(|e| McpError::Other(e.to_string()))?;
        imported += 1;
    }

    let result = serde_json::json!({
        "todos_found": todos.len(),
        "work_items_created": imported,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}
