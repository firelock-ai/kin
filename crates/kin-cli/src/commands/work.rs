use anyhow::Result;
use kin_model::*;
use std::collections::HashSet;

/// `kin work create` — Create a new work item.
pub async fn create(
    kind: String,
    title: String,
    description: Option<String>,
    scope: Option<String>,
    priority: Option<String>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let item = create_in_layout(&layout, kind, title.clone(), description, scope, priority)?;
    println!("Created {} '{}' ({})", item.kind, title, item.work_id);
    Ok(())
}

/// `kin work list` — List work items with optional filters.
pub async fn list(
    status: Option<String>,
    kind: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let filter = WorkFilter {
        kinds: kind
            .map(|k| {
                k.parse::<WorkKind>()
                    .map(|wk| vec![wk])
                    .map_err(|e| anyhow::anyhow!(e))
            })
            .transpose()?,
        statuses: status
            .map(|s| {
                s.parse::<WorkStatus>()
                    .map(|ws| vec![ws])
                    .map_err(|e| anyhow::anyhow!(e))
            })
            .transpose()?,
        scope: scope.as_deref().map(parse_work_scope).transpose()?,
    };

    let items = graph.list_work_items(&filter)?;

    if items.is_empty() {
        println!("No work items found.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<12}  {:<12}  {:<8}  {}",
        "ID", "KIND", "STATUS", "PRIORITY", "TITLE"
    );
    println!("{}", "-".repeat(100));

    for item in &items {
        println!(
            "{:<36}  {:<12}  {:<12}  {:<8}  {}",
            item.work_id, item.kind, item.status, item.priority, item.title,
        );
    }

    if let Some(scope) = scope {
        println!("\nScope filter: {}", scope);
    }

    println!("\n{} work item(s)", items.len());
    Ok(())
}

/// `kin work show` — Show details of a work item.
pub async fn show(work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let id = parse_work_id(&work_id)?;
    let item = graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;

    println!("Work Item: {}", item.work_id);
    println!("  Kind:     {}", item.kind);
    println!("  Title:    {}", item.title);
    println!("  Status:   {}", item.status);
    println!("  Priority: {}", item.priority);
    println!("  Created:  {}", item.created_at);
    println!(
        "  Author:   {} ({})",
        item.created_by.name,
        format!("{:?}", item.created_by.kind)
    );

    if !item.description.is_empty() {
        println!("\n  Description:\n    {}", item.description);
    }

    if !item.scopes.is_empty() {
        println!("\n  Scopes:");
        for scope in &item.scopes {
            println!("    - {}", scope);
        }
    }

    if !item.acceptance_criteria.is_empty() {
        println!("\n  Acceptance Criteria:");
        for (i, crit) in item.acceptance_criteria.iter().enumerate() {
            println!("    {}. {}", i + 1, crit);
        }
    }

    if !item.external_refs.is_empty() {
        println!("\n  External References:");
        for ext in &item.external_refs {
            println!("    - {} #{}", ext.system, ext.identifier);
        }
    }

    let children = graph.get_child_work_items(&id)?;
    let parents = graph.get_parent_work_items(&id)?;
    let blockers = graph.get_blockers(&id)?;
    let blocked_items = graph.get_blocked_work_items(&id)?;
    let annotations = graph.get_annotations_for_work_item(&id)?;

    if !children.is_empty() {
        println!("\n  Child Items:");
        for child in &children {
            println!("    - [{}] {} ({})", child.kind, child.title, child.status);
        }
    }

    if !parents.is_empty() {
        println!("\n  Parent Items:");
        for parent in &parents {
            println!(
                "    - [{}] {} ({})",
                parent.kind, parent.title, parent.status
            );
        }
    }

    if !blockers.is_empty() {
        println!("\n  Blocked By:");
        for blocker in &blockers {
            println!(
                "    - [{}] {} ({})",
                blocker.kind, blocker.title, blocker.status
            );
        }
    }

    if !blocked_items.is_empty() {
        println!("\n  Blocking:");
        for blocked in &blocked_items {
            println!(
                "    - [{}] {} ({})",
                blocked.kind, blocked.title, blocked.status
            );
        }
    }

    let implementors = graph.get_implementors(&id)?;
    if !implementors.is_empty() {
        println!("\n  Implemented By:");
        for scope in &implementors {
            println!("    - {}", scope);
        }
    }

    if !annotations.is_empty() {
        println!("\n  Annotations:");
        for ann in &annotations {
            println!("    - [{}|{}] {}", ann.kind, ann.staleness, ann.body);
        }
    }

    Ok(())
}

/// `kin work link` — Link a work item to a scope.
pub async fn link(work_id: String, scope: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let ws = link_in_layout(&layout, &work_id, &scope)?;
    println!("Linked {} -> {}", work_id, ws);
    Ok(())
}

/// `kin work decompose` — Link a parent work item to a child work item.
pub async fn decompose(parent_work_id: String, child_work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    decompose_in_layout(&layout, &parent_work_id, &child_work_id)?;
    println!(
        "Linked parent {} -> child {}",
        parent_work_id, child_work_id
    );
    Ok(())
}

/// `kin work block` — Mark one work item as blocked by another.
pub async fn block(blocked_work_id: String, blocker_work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    block_in_layout(&layout, &blocked_work_id, &blocker_work_id)?;
    println!(
        "Marked {} as blocked by {}",
        blocked_work_id, blocker_work_id
    );
    Ok(())
}

/// `kin work implement` — Link an implementing scope to a work item.
pub async fn implement(work_id: String, scope: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let scope = implement_in_layout(&layout, &work_id, &scope)?;
    println!("Linked implementor {} -> {}", scope, work_id);
    Ok(())
}

/// `kin work status` — Update a work item status.
pub async fn status(work_id: String, status: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let status = set_status_in_layout(&layout, &work_id, &status)?;
    println!("Updated {} -> {}", work_id, status);
    Ok(())
}

/// `kin work close` — Close a work item (set status to Done).
///
/// Warns if implementing entities lack test coverage but still closes.
pub async fn close(work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let uncovered = close_in_layout(&layout, &work_id)?;
    if !uncovered.is_empty() {
        println!(
            "Warning: {} implementing entity(ies) lack test coverage:",
            uncovered.len()
        );
        for (eid, name) in &uncovered {
            if let Some(name) = name {
                println!("  - {} ({})", name, eid);
            } else {
                println!("  - {}", eid);
            }
        }
        println!();
    }
    println!("Closed work item {}", work_id);
    Ok(())
}

/// `kin work verify` — Check verification status of a work item.
///
/// Checks that implementing entities have linked tests and reports
/// whether the work item has sufficient proof for completion.
pub async fn verify(work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let id = parse_work_id(&work_id)?;
    let item = graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;

    println!("Work item: {} ({})", item.title, item.kind);
    println!("  Status: {}", item.status);

    // Check acceptance criteria.
    if !item.acceptance_criteria.is_empty() {
        println!("  Acceptance criteria: {}", item.acceptance_criteria.len());
        for (i, crit) in item.acceptance_criteria.iter().enumerate() {
            println!("    {}. {}", i + 1, crit);
        }
    }

    // Check implementors and their test coverage.
    let implementors = graph.get_implementors(&id)?;
    if implementors.is_empty() {
        println!("  Implementors: none");
        println!("  Completion: INCOMPLETE — no implementing entities linked");
        return Ok(());
    }

    println!("  Implementors: {}", implementors.len());

    let mut covered = 0usize;
    let mut uncovered = 0usize;

    for scope in &implementors {
        if let WorkScope::Entity(eid) = scope {
            let tests = graph.get_tests_for_entity(eid)?;
            if tests.is_empty() {
                uncovered += 1;
                if let Some(entity) = graph.get_entity(eid)? {
                    println!("    MISSING  {} ({})", entity.name, eid);
                } else {
                    println!("    MISSING  {}", eid);
                }
            } else {
                covered += 1;
                if let Some(entity) = graph.get_entity(eid)? {
                    println!("    COVERED  {} — {} test(s)", entity.name, tests.len());
                } else {
                    println!("    COVERED  {} — {} test(s)", eid, tests.len());
                }
            }
        }
    }

    let total = covered + uncovered;
    if uncovered == 0 && total > 0 {
        println!(
            "  Completion: COVERED — all {} implementing entities have tests",
            total
        );
    } else {
        println!(
            "  Completion: INCOMPLETE — {}/{} entities covered, {} missing proof",
            covered, total, uncovered
        );
    }

    Ok(())
}

// -- Helpers --

fn parse_work_id(s: &str) -> Result<WorkId> {
    let uuid =
        uuid::Uuid::parse_str(s).map_err(|_| anyhow::anyhow!("invalid work item UUID: {}", s))?;
    Ok(WorkId(uuid))
}

pub(crate) fn parse_work_scope(s: &str) -> Result<WorkScope> {
    if let Some(rest) = s.strip_prefix("entity:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid entity UUID: {}", rest))?;
        Ok(WorkScope::Entity(EntityId(uuid)))
    } else if let Some(rest) = s.strip_prefix("contract:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid contract UUID: {}", rest))?;
        Ok(WorkScope::Contract(ContractId(uuid)))
    } else if let Some(rest) = s.strip_prefix("artifact:") {
        Ok(WorkScope::Artifact(FilePathId::new(rest)))
    } else if let Some(rest) = s.strip_prefix("file:") {
        Ok(WorkScope::Artifact(FilePathId::new(rest)))
    } else if let Some(rest) = s.strip_prefix("change:") {
        let hash = Hash256::from_hex(rest)
            .map_err(|_| anyhow::anyhow!("invalid semantic change ID: {}", rest))?;
        Ok(WorkScope::Change(SemanticChangeId::from_hash(hash)))
    } else {
        // Try as UUID (entity), then fall back to file path.
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            Ok(WorkScope::Entity(EntityId(uuid)))
        } else {
            Ok(WorkScope::Artifact(FilePathId::new(s)))
        }
    }
}

pub(crate) fn create_in_layout(
    layout: &kin_core::KinLayout,
    kind: String,
    title: String,
    description: Option<String>,
    scope: Option<String>,
    priority: Option<String>,
) -> Result<WorkItem> {
    let work_kind: WorkKind = kind.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let pri: Priority = priority
        .as_deref()
        .unwrap_or("none")
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let scopes = match scope {
        Some(s) => vec![parse_work_scope(&s)?],
        None => vec![],
    };

    let item = WorkItem {
        work_id: WorkId::new(),
        kind: work_kind,
        title,
        description: description.unwrap_or_default(),
        status: WorkStatus::Proposed,
        priority: pri,
        scopes,
        acceptance_criteria: vec![],
        external_refs: vec![],
        created_by: IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
    };

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();
    graph.create_work_item(&item)?;
    for scope in &item.scopes {
        graph.create_work_link(&WorkLink::Affects {
            work_id: item.work_id,
            scope: scope.clone(),
        })?;
    }
    snap.save()?;

    Ok(item)
}

fn link_in_layout(layout: &kin_core::KinLayout, work_id: &str, scope: &str) -> Result<WorkScope> {
    let id = parse_work_id(work_id)?;
    let ws = parse_work_scope(scope)?;

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    let mut item = graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;
    if !item.scopes.contains(&ws) {
        item.scopes.push(ws.clone());
        graph.create_work_item(&item)?;
    }

    graph.create_work_link(&WorkLink::Affects {
        work_id: id,
        scope: ws.clone(),
    })?;
    snap.save()?;

    Ok(ws)
}

fn decompose_in_layout(
    layout: &kin_core::KinLayout,
    parent_work_id: &str,
    child_work_id: &str,
) -> Result<()> {
    let parent = parse_work_id(parent_work_id)?;
    let child = parse_work_id(child_work_id)?;

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    graph
        .get_work_item(&parent)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", parent_work_id))?;
    graph
        .get_work_item(&child)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", child_work_id))?;

    graph.create_work_link(&WorkLink::DecomposesTo { parent, child })?;
    snap.save()?;
    Ok(())
}

fn block_in_layout(
    layout: &kin_core::KinLayout,
    blocked_work_id: &str,
    blocker_work_id: &str,
) -> Result<()> {
    let blocked = parse_work_id(blocked_work_id)?;
    let blocker = parse_work_id(blocker_work_id)?;

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    graph
        .get_work_item(&blocked)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", blocked_work_id))?;
    graph
        .get_work_item(&blocker)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", blocker_work_id))?;

    graph.create_work_link(&WorkLink::BlockedBy { blocked, blocker })?;
    snap.save()?;
    Ok(())
}

fn implement_in_layout(
    layout: &kin_core::KinLayout,
    work_id: &str,
    scope: &str,
) -> Result<WorkScope> {
    let work_id = parse_work_id(work_id)?;
    let scope = parse_work_scope(scope)?;

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    graph
        .get_work_item(&work_id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;
    graph.create_work_link(&WorkLink::Implements {
        scope: scope.clone(),
        work_id,
    })?;
    snap.save()?;

    Ok(scope)
}

fn set_status_in_layout(
    layout: &kin_core::KinLayout,
    work_id: &str,
    status: &str,
) -> Result<WorkStatus> {
    let work_id = parse_work_id(work_id)?;
    let status = status
        .parse::<WorkStatus>()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();
    graph
        .get_work_item(&work_id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;
    graph.update_work_status(&work_id, status)?;
    snap.save()?;

    Ok(status)
}

fn close_in_layout(
    layout: &kin_core::KinLayout,
    work_id: &str,
) -> Result<Vec<(EntityId, Option<String>)>> {
    let id = parse_work_id(work_id)?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;

    let implementors = graph.get_implementors(&id)?;
    let mut uncovered = Vec::new();
    for scope in &implementors {
        if let WorkScope::Entity(eid) = scope {
            let tests = graph.get_tests_for_entity(eid)?;
            if tests.is_empty() {
                let name = graph.get_entity(eid)?.map(|entity| entity.name);
                uncovered.push((*eid, name));
            }
        }
    }

    graph.update_work_status(&id, WorkStatus::Done)?;
    snap.save()?;
    Ok(uncovered)
}

pub(crate) fn todo_import_in_layout(
    layout: &kin_core::KinLayout,
    path: Option<String>,
) -> Result<(usize, usize)> {
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    let scan_root = path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| kin_core::source_dir(layout));
    let todos = kin_parser::extract_todos(&scan_root)?;

    let existing = graph.list_work_items(&WorkFilter::default())?;
    let mut existing_keys: HashSet<(WorkKind, String, String)> = existing
        .into_iter()
        .flat_map(|item| {
            item.scopes
                .into_iter()
                .filter_map(move |scope| match scope {
                    WorkScope::Artifact(file_id) => {
                        Some((item.kind, item.title.clone(), file_id.0))
                    }
                    _ => None,
                })
        })
        .collect();

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for todo in &todos {
        let work_kind = match todo.kind.as_str() {
            "FIXME" => WorkKind::Issue,
            "HACK" => WorkKind::Debt,
            _ => WorkKind::Todo,
        };
        let key = (work_kind, todo.body.clone(), todo.file_path.clone());
        if existing_keys.contains(&key) {
            skipped += 1;
            continue;
        }

        let scope = WorkScope::Artifact(FilePathId::new(&todo.file_path));
        let item = WorkItem {
            work_id: WorkId::new(),
            kind: work_kind,
            title: todo.body.clone(),
            description: format!(
                "Imported from {} (line {})",
                todo.file_path, todo.line_number
            ),
            status: WorkStatus::Proposed,
            priority: if todo.kind == "FIXME" {
                Priority::High
            } else {
                Priority::Medium
            },
            scopes: vec![scope.clone()],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("kin-todo-import"),
            created_at: Timestamp::now(),
        };

        graph.create_work_item(&item)?;
        graph.create_work_link(&WorkLink::Affects {
            work_id: item.work_id,
            scope,
        })?;
        existing_keys.insert(key);
        imported += 1;
    }

    snap.save()?;
    Ok((imported, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::GraphStore;

    #[test]
    fn create_and_link_work_persist_to_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let item = create_in_layout(
            &layout,
            "task".into(),
            "wire persistence".into(),
            Some("make work writes stick".into()),
            Some("src/main.rs".into()),
            Some("high".into()),
        )
        .unwrap();
        let linked_scope =
            link_in_layout(&layout, &item.work_id.to_string(), "file:src/lib.rs").unwrap();

        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();
        let stored = graph.get_work_item(&item.work_id).unwrap().unwrap();
        assert!(stored
            .scopes
            .contains(&WorkScope::Artifact(FilePathId::new("src/main.rs"))));
        assert!(stored.scopes.contains(&linked_scope));

        let linked_items = graph.get_work_for_scope(&linked_scope).unwrap();
        assert_eq!(linked_items.len(), 1);
        assert_eq!(linked_items[0].work_id, item.work_id);
    }

    #[test]
    fn close_work_updates_persisted_status() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let item =
            create_in_layout(&layout, "task".into(), "close me".into(), None, None, None).unwrap();

        let uncovered = close_in_layout(&layout, &item.work_id.to_string()).unwrap();
        assert!(uncovered.is_empty());

        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();
        let stored = graph.get_work_item(&item.work_id).unwrap().unwrap();
        assert_eq!(stored.status, WorkStatus::Done);
    }

    #[test]
    fn work_relationships_persist_to_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let feature = create_in_layout(
            &layout,
            "feature".into(),
            "ship semantic work graph".into(),
            None,
            Some("src/main.rs".into()),
            None,
        )
        .unwrap();
        let task = create_in_layout(
            &layout,
            "task".into(),
            "wire graph queries".into(),
            None,
            Some("src/lib.rs".into()),
            None,
        )
        .unwrap();
        let blocker = create_in_layout(
            &layout,
            "issue".into(),
            "resolve schema drift".into(),
            None,
            None,
            None,
        )
        .unwrap();

        decompose_in_layout(
            &layout,
            &feature.work_id.to_string(),
            &task.work_id.to_string(),
        )
        .unwrap();
        block_in_layout(
            &layout,
            &task.work_id.to_string(),
            &blocker.work_id.to_string(),
        )
        .unwrap();
        let implementor =
            implement_in_layout(&layout, &task.work_id.to_string(), "file:src/lib.rs").unwrap();
        let status =
            set_status_in_layout(&layout, &task.work_id.to_string(), "in_progress").unwrap();

        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();

        let children = graph.get_child_work_items(&feature.work_id).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].work_id, task.work_id);

        let blockers = graph.get_blockers(&task.work_id).unwrap();
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].work_id, blocker.work_id);

        let implementors = graph.get_implementors(&task.work_id).unwrap();
        assert_eq!(implementors, vec![implementor]);

        let stored = graph.get_work_item(&task.work_id).unwrap().unwrap();
        assert_eq!(stored.status, status);
    }

    #[test]
    fn todo_import_uses_snapshot_and_skips_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        std::fs::write(
            dir.path().join("src.rs"),
            "// TODO: keep this stable\n// FIXME: make it safer\n",
        )
        .unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let first = todo_import_in_layout(&layout, None).unwrap();
        let second = todo_import_in_layout(&layout, None).unwrap();
        assert_eq!(first, (2, 0));
        assert_eq!(second, (0, 2));

        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();
        let items = graph.list_work_items(&WorkFilter::default()).unwrap();
        assert_eq!(items.len(), 2);
    }
}
