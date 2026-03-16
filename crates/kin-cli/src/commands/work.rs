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
    let report = build_work_verification_report(graph, &id)?;

    println!("Work item: {} ({})", report.work.title, report.work.kind);
    println!("  Status: {}", report.work.status);

    if !report.work.acceptance_criteria.is_empty() {
        println!(
            "  Acceptance criteria: {}",
            report.work.acceptance_criteria.len()
        );
        for (i, crit) in report.work.acceptance_criteria.iter().enumerate() {
            println!("    {}. {}", i + 1, crit);
        }
    }

    if report.implementors.is_empty() {
        println!("  Implementors: none (falling back to work scopes)");
    } else {
        println!("  Implementors: {}", report.implementors.len());
    }

    if report.direct_work_tests.is_empty() {
        println!("  Direct work tests: none");
    } else {
        println!("  Direct work tests: {}", report.direct_work_tests.len());
        for test in &report.direct_work_tests {
            println!("    - {} [{}] runner={}", test.name, test.kind, test.runner);
        }
    }

    if report.direct_work_runs.is_empty() {
        println!("  Direct proof runs: none");
    } else {
        println!("  Direct proof runs: {}", report.direct_work_runs.len());
        for run in &report.direct_work_runs {
            println!("    - {} via {}", run.status, run.runner);
        }
    }

    if !report.missing_scope_proof.is_empty() {
        println!("  Missing proof on scopes:");
        for scope in &report.missing_scope_proof {
            println!("    - {}", scope);
        }
    }

    let has_passing_work_run = report
        .direct_work_runs
        .iter()
        .any(|run| run.status == VerificationStatus::Passing);

    if report.targeted_tests.is_empty() && !has_passing_work_run {
        println!("  Targeted test set: none");
        println!("  Completion: INCOMPLETE — no targeted proof exists for this work item");
        return Ok(());
    }

    if report.targeted_tests.is_empty() {
        println!("  Targeted test set: none");
    } else {
        println!("  Targeted test set: {}", report.targeted_tests.len());
        for targeted in &report.targeted_tests {
            let latest = targeted
                .latest_run
                .as_ref()
                .map(|run| run.status.to_string())
                .unwrap_or_else(|| "not_run".to_string());
            println!(
                "    - {} [{}] runner={} latest={}",
                targeted.test.name, targeted.test.kind, targeted.test.runner, latest
            );
        }
    }

    if report.tests_without_passing_run == 0
        && report.missing_scope_proof.is_empty()
        && (!report.targeted_tests.is_empty() || has_passing_work_run)
    {
        println!("  Completion: VERIFIED — targeted proof set is passing for this work item");
    } else {
        println!(
            "  Completion: PARTIAL — {} targeted test(s) lack a passing run, {} scope(s) still lack proof",
            report.tests_without_passing_run,
            report.missing_scope_proof.len()
        );
    }

    Ok(())
}

// -- Helpers --

#[derive(Debug, Clone)]
struct TargetedTestStatus {
    test: TestCase,
    latest_run: Option<VerificationRun>,
}

#[derive(Debug, Clone)]
struct WorkVerificationReport {
    work: WorkItem,
    implementors: Vec<WorkScope>,
    direct_work_tests: Vec<TestCase>,
    direct_work_runs: Vec<VerificationRun>,
    targeted_tests: Vec<TargetedTestStatus>,
    missing_scope_proof: Vec<WorkScope>,
    tests_without_passing_run: usize,
}

fn build_work_verification_report<G>(graph: &G, work_id: &WorkId) -> Result<WorkVerificationReport>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let work = graph
        .get_work_item(work_id)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;

    let implementors = graph
        .get_implementors(work_id)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let coverage_scopes = if implementors.is_empty() {
        work.scopes.clone()
    } else {
        implementors.clone()
    };

    let direct_work_tests = graph
        .get_tests_verifying_work(work_id)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let direct_work_runs = graph
        .list_runs_proving_work(work_id)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut targeted_tests = Vec::new();
    let mut seen_tests = HashSet::new();
    let mut missing_scope_proof = Vec::new();

    for scope in &coverage_scopes {
        let tests = tests_for_scope(graph, scope)?;
        if !scope_has_proof(graph, scope, &tests)? {
            missing_scope_proof.push(scope.clone());
        }
        for test in tests {
            if seen_tests.insert(test.test_id) {
                targeted_tests.push(test);
            }
        }
    }

    for test in &direct_work_tests {
        if seen_tests.insert(test.test_id) {
            targeted_tests.push(test.clone());
        }
    }

    let targeted_tests: Vec<_> = targeted_tests
        .into_iter()
        .map(|test| {
            let latest_run = graph
                .list_runs_for_test(&test.test_id)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                .into_iter()
                .max_by_key(|run| {
                    run.finished_at
                        .clone()
                        .unwrap_or_else(|| run.started_at.clone())
                });
            Ok(TargetedTestStatus { test, latest_run })
        })
        .collect::<Result<Vec<_>>>()?;

    let tests_without_passing_run = targeted_tests
        .iter()
        .filter(|targeted| {
            !matches!(
                targeted.latest_run.as_ref().map(|run| run.status),
                Some(VerificationStatus::Passing)
            )
        })
        .count();

    Ok(WorkVerificationReport {
        work,
        implementors,
        direct_work_tests,
        direct_work_runs,
        targeted_tests,
        missing_scope_proof,
        tests_without_passing_run,
    })
}

fn tests_for_scope<G>(graph: &G, scope: &WorkScope) -> Result<Vec<TestCase>>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    match scope {
        WorkScope::Entity(entity_id) => graph
            .get_tests_for_entity(entity_id)
            .map_err(|e| anyhow::anyhow!(e.to_string())),
        WorkScope::Contract(contract_id) => graph
            .get_tests_covering_contract(contract_id)
            .map_err(|e| anyhow::anyhow!(e.to_string())),
        WorkScope::Artifact(_) | WorkScope::Change(_) => Ok(vec![]),
    }
}

fn scope_has_proof<G>(graph: &G, scope: &WorkScope, tests: &[TestCase]) -> Result<bool>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    if !tests.is_empty() {
        return Ok(true);
    }

    match scope {
        WorkScope::Entity(entity_id) => Ok(graph
            .list_runs_proving_entity(entity_id)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .into_iter()
            .any(|run| run.status == VerificationStatus::Passing)),
        WorkScope::Contract(_) | WorkScope::Artifact(_) | WorkScope::Change(_) => Ok(false),
    }
}

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
    crate::provenance::record_cli_audit_event(
        graph.as_ref(),
        "work.create",
        item.scopes.first().cloned(),
        Some(format!(
            "work_id={}; kind={}; status={}",
            item.work_id, item.kind, item.status
        )),
    )?;
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
    let item = graph
        .get_work_item(&work_id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found after status update: {}", work_id))?;
    crate::provenance::record_cli_audit_event(
        graph.as_ref(),
        "work.status",
        item.scopes.first().cloned(),
        Some(format!("work_id={}; status={}", item.work_id, item.status)),
    )?;
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
    let item = graph
        .get_work_item(&id)?
        .ok_or_else(|| anyhow::anyhow!("work item not found after close: {}", work_id))?;
    crate::provenance::record_cli_audit_event(
        graph.as_ref(),
        "work.close",
        item.scopes.first().cloned(),
        Some(format!("work_id={}; uncovered={}", item.work_id, uncovered.len())),
    )?;
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

        let audit_events = graph.query_audit_events(None, 10).unwrap();
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].action, "work.create");
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

        let audit_events = graph.query_audit_events(None, 10).unwrap();
        assert_eq!(audit_events.len(), 2);
        assert_eq!(audit_events[0].action, "work.close");
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

        let audit_events = graph.query_audit_events(None, 10).unwrap();
        assert!(audit_events.iter().any(|event| event.action == "work.status"));
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

    #[test]
    fn work_verification_report_uses_runs_and_work_tests() {
        let store = kin_db::InMemoryGraph::new();

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "checkout".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/checkout.rs")),
            span: None,
            signature: "fn checkout()".into(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        store.upsert_entity(&entity).unwrap();

        let work = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Feature,
            title: "Ship checkout".into(),
            description: "Implement checkout flow".into(),
            status: WorkStatus::InProgress,
            priority: Priority::High,
            scopes: vec![WorkScope::Entity(entity.id)],
            acceptance_criteria: vec!["passing checkout proof".into()],
            external_refs: vec![],
            created_by: IdentityRef::human("cli-user"),
            created_at: Timestamp::now(),
        };
        store.create_work_item(&work).unwrap();

        let test = TestCase {
            test_id: TestId::new(),
            name: "test_checkout_flow".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout.rs")),
        };
        store.create_test_case(&test).unwrap();
        store
            .create_test_verifies_work(&test.test_id, &work.work_id)
            .unwrap();

        let run = VerificationRun {
            run_id: VerificationRunId::new(),
            test_ids: vec![test.test_id],
            status: VerificationStatus::Passing,
            runner: TestRunner::Cargo,
            started_at: Timestamp::now(),
            finished_at: Some(Timestamp::now()),
            duration_ms: Some(25),
            evidence_blob: None,
            exit_code: Some(0),
        };
        store.create_verification_run(&run).unwrap();
        store
            .link_run_proves_entity(&run.run_id, &entity.id)
            .unwrap();
        store
            .link_run_proves_work(&run.run_id, &work.work_id)
            .unwrap();

        let report = build_work_verification_report(&store, &work.work_id).unwrap();
        assert_eq!(report.targeted_tests.len(), 1);
        assert_eq!(report.tests_without_passing_run, 0);
        assert!(report.missing_scope_proof.is_empty());
        assert_eq!(report.direct_work_runs.len(), 1);
        assert_eq!(report.direct_work_runs[0].run_id, run.run_id);
    }
}
