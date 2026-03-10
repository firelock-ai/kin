use anyhow::Result;
use kin_model::*;

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
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let work_kind: WorkKind = kind
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
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
        title: title.clone(),
        description: description.unwrap_or_default(),
        status: WorkStatus::Proposed,
        priority: pri,
        scopes,
        acceptance_criteria: vec![],
        external_refs: vec![],
        created_by: IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
    };

    graph.create_work_item(&item)?;
    println!("Created {} '{}' ({})", item.kind, title, item.work_id);
    Ok(())
}

/// `kin work list` — List work items with optional filters.
pub async fn list(status: Option<String>, kind: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

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
        scope: None,
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

    println!("\n{} work item(s)", items.len());
    Ok(())
}

/// `kin work show` — Show details of a work item.
pub async fn show(work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

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
    println!("  Author:   {} ({})", item.created_by.name, format!("{:?}", item.created_by.kind));

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

    // Show child work items (decomposition).
    let children = graph.get_child_work_items(&id)?;
    if !children.is_empty() {
        println!("\n  Child Items:");
        for child in &children {
            println!("    - [{}] {} ({})", child.kind, child.title, child.status);
        }
    }

    // Show implementing entities.
    let implementors = graph.get_implementors(&id)?;
    if !implementors.is_empty() {
        println!("\n  Implemented By:");
        for scope in &implementors {
            println!("    - {}", scope);
        }
    }

    Ok(())
}

/// `kin work link` — Link a work item to a scope.
pub async fn link(work_id: String, scope: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let id = parse_work_id(&work_id)?;
    let ws = parse_work_scope(&scope)?;

    // Verify work item exists.
    graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;

    let link = WorkLink::Affects {
        work_id: id,
        scope: ws.clone(),
    };
    graph.create_work_link(&link)?;

    println!("Linked {} -> {}", work_id, ws);
    Ok(())
}

/// `kin work close` — Close a work item (set status to Done).
pub async fn close(work_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let id = parse_work_id(&work_id)?;

    graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;

    graph.update_work_status(&id, WorkStatus::Done)?;
    println!("Closed work item {}", work_id);
    Ok(())
}

// -- Helpers --

fn parse_work_id(s: &str) -> Result<WorkId> {
    let uuid = uuid::Uuid::parse_str(s)
        .map_err(|_| anyhow::anyhow!("invalid work item UUID: {}", s))?;
    Ok(WorkId(uuid))
}

fn parse_work_scope(s: &str) -> Result<WorkScope> {
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
    } else {
        // Try as UUID (entity), then fall back to file path.
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            Ok(WorkScope::Entity(EntityId(uuid)))
        } else {
            Ok(WorkScope::Artifact(FilePathId::new(s)))
        }
    }
}
