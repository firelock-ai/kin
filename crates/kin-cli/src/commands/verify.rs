// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Context, Result};
use kin_model::{
    Entity, EntityDelta, EntityFilter, EntityStore, GraphStore, Hash256, SemanticChange,
    SemanticChangeId, TestCase, TestRunner, Timestamp, VerificationRun, VerificationRunId,
    VerificationStatus, VerificationStore, WorkItem, WorkScope,
};
use kin_runtime::workspace::record_verification_evidence;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRunRequest {
    pub entity: String,
    pub runner: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRunResponse {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum VerifyCommandRequest {
    Entity {
        entity: String,
    },
    Summary,
    Missing,
    Plan {
        entity: String,
        depth: u32,
    },
    PlanChange {
        #[serde(default)]
        change_id: Option<String>,
        depth: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCommandResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

/// `kin verify <entity>` — Check verification / test coverage for an entity.
///
/// Shows per-entity test linkage and overall coverage summary.
pub async fn run(entity: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_verify_response(
        run_daemon_verify_command(&layout, &VerifyCommandRequest::Entity { entity }).await?,
    )
}

/// `kin verify --summary` — Show repository-wide coverage summary only.
pub async fn summary() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_verify_response(run_daemon_verify_command(&layout, &VerifyCommandRequest::Summary).await?)
}

/// `kin verify --missing` — Show only entities without any linked test.
pub async fn missing() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_verify_response(run_daemon_verify_command(&layout, &VerifyCommandRequest::Missing).await?)
}

/// `kin verify plan <entity> --depth 2` — Show the targeted proof set Kin would
/// use for verification, widened by downstream semantic impact.
pub async fn plan(entity: String, depth: u32) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_verify_response(
        run_daemon_verify_command(&layout, &VerifyCommandRequest::Plan { entity, depth }).await?,
    )
}

/// `kin verify change [<change-id>] --depth 2` — Show the targeted proof set
/// Kin would use for a semantic change, defaulting to the current HEAD.
pub async fn plan_change(change_id: Option<String>, depth: u32) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_verify_response(
        run_daemon_verify_command(
            &layout,
            &VerifyCommandRequest::PlanChange { change_id, depth },
        )
        .await?,
    )
}

/// `kin verify run <entity> --runner cargo` — Execute a targeted runner and
/// record a persisted `VerificationRun`.
///
/// If linked tests exist for the entity, Kin drives the runner from that proof
/// set. Otherwise it falls back to an entity-name filter and still records a
/// proof run for the entity.
pub async fn run_verification(entity: String, runner: String, depth: u32) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_verify_run(
        &layout,
        &VerifyRunRequest {
            entity,
            runner,
            depth,
        },
    )
    .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_verify_run(
    layout: &kin_core::KinLayout,
    request: &VerifyRunRequest,
) -> Result<VerifyRunResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("verify run", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .verify_run(request)
        .await
        .context("daemon verify run failed")
}

async fn run_daemon_verify_command(
    layout: &kin_core::KinLayout,
    request: &VerifyCommandRequest,
) -> Result<VerifyCommandResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("verify", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .verify_command(request)
        .await
        .context("daemon verify failed")
}

fn print_verify_response(response: VerifyCommandResponse) -> Result<()> {
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn execute_verify_command(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &VerifyCommandRequest,
) -> Result<VerifyCommandResponse> {
    match request {
        VerifyCommandRequest::Entity { entity } => build_entity_verify_response(graph, entity),
        VerifyCommandRequest::Summary => build_verify_summary_response(graph),
        VerifyCommandRequest::Missing => build_verify_missing_response(graph),
        VerifyCommandRequest::Plan { entity, depth } => {
            let plan = build_verification_plan(graph, entity, *depth)?;
            Ok(VerifyCommandResponse {
                lines: verification_plan_lines(&plan),
            })
        }
        VerifyCommandRequest::PlanChange { change_id, depth } => {
            let change = resolve_change(graph, binding, change_id.as_deref())?;
            let plan = build_change_verification_plan(graph, &change, *depth)?;
            Ok(VerifyCommandResponse {
                lines: change_verification_plan_lines(&plan),
            })
        }
    }
}

fn build_entity_verify_response(
    graph: &kin_db::InMemoryGraph,
    entity: &str,
) -> Result<VerifyCommandResponse> {
    let filter = EntityFilter {
        name_pattern: Some(entity.to_string()),
        ..Default::default()
    };
    let entities = graph.query_entities(&filter)?;

    if entities.is_empty() {
        return Ok(VerifyCommandResponse {
            lines: vec![format!("No entity matching '{}' found.", entity)],
        });
    }

    let mut lines = Vec::new();
    let mut covered_count = 0usize;
    let mut uncovered_count = 0usize;

    for ent in &entities {
        let tests = graph.get_tests_for_entity(&ent.id)?;
        if tests.is_empty() {
            uncovered_count += 1;
            lines.push(format!("  MISSING  {} ({:?})", ent.name, ent.kind));
        } else {
            covered_count += 1;
            lines.push(format!(
                "  COVERED  {} ({:?}) — {} test(s)",
                ent.name,
                ent.kind,
                tests.len()
            ));
            for test in &tests {
                lines.push(format!(
                    "           - {} [{}] runner={}",
                    test.name, test.kind, test.runner
                ));
            }
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "Matched {} entity(ies): {} covered, {} missing proof",
        entities.len(),
        covered_count,
        uncovered_count,
    ));
    lines.push(String::new());
    lines.extend(verify_summary_lines(graph)?);

    Ok(VerifyCommandResponse { lines })
}

fn build_verify_summary_response(graph: &kin_db::InMemoryGraph) -> Result<VerifyCommandResponse> {
    Ok(VerifyCommandResponse {
        lines: verify_summary_lines(graph)?,
    })
}

fn build_verify_missing_response(graph: &kin_db::InMemoryGraph) -> Result<VerifyCommandResponse> {
    let summary = graph.get_coverage_summary()?;
    if summary.missing_proof.is_empty() {
        return Ok(VerifyCommandResponse {
            lines: vec![format!(
                "All {} entities have linked proof.",
                summary.total_entities
            )],
        });
    }

    let mut lines = vec![format!(
        "Entities missing proof ({}/{}):",
        summary.missing_proof.len(),
        summary.total_entities
    )];

    for eid in &summary.missing_proof {
        if let Some(entity) = graph.get_entity(eid)? {
            let file = entity
                .file_origin
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            lines.push(format!(
                "  - {} ({:?}) in {}",
                entity.name, entity.kind, file
            ));
        } else {
            lines.push(format!("  - {}", eid));
        }
    }

    Ok(VerifyCommandResponse { lines })
}

fn verify_summary_lines(graph: &kin_db::InMemoryGraph) -> Result<Vec<String>> {
    let summary = graph.get_coverage_summary()?;
    let mut lines = vec![
        "Repository Coverage:".to_string(),
        format!(
            "  {}/{} entities covered ({:.1}%)",
            summary.covered_entities,
            summary.total_entities,
            summary.coverage_ratio * 100.0
        ),
    ];

    if summary.missing_proof.is_empty() {
        lines.push("  All entities have linked proof.".to_string());
    } else {
        lines.push(format!(
            "  {} entities missing proof",
            summary.missing_proof.len()
        ));
    }

    Ok(lines)
}

pub fn execute_verify_run(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &VerifyRunRequest,
) -> Result<VerifyRunResponse> {
    let plan = build_verification_plan(graph, &request.entity, request.depth)?;
    let test_runner = parse_runner(&request.runner);
    let cmd_str = build_runner_command(&test_runner, &plan.entity.name, &plan.tests);
    let mut lines = Vec::new();

    if plan.tests.is_empty() {
        lines.push(format!(
            "No linked tests found for '{}'; falling back to an entity-scoped runner filter.",
            plan.entity.name
        ));
    } else {
        lines.extend(verification_plan_lines(&plan));
    }

    lines.push(format!("Running: {}", cmd_str));

    let started_at = Timestamp::now();
    let start_instant = std::time::Instant::now();
    let output = verification_command(layout.working_dir(), &cmd_str).output();
    let duration = start_instant.elapsed();
    let finished_at = Timestamp::now();

    let (status, exit_code, evidence_text) = match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let evidence = format!("=== STDOUT ===\n{}\n=== STDERR ===\n{}", stdout, stderr);
            let exit = out.status.code().unwrap_or(-1);
            let status = if out.status.success() {
                VerificationStatus::Passing
            } else {
                VerificationStatus::Failing
            };
            (status, exit, evidence)
        }
        Err(err) => {
            let evidence = format!("Failed to execute test runner: {}", err);
            (VerificationStatus::Failing, -1, evidence)
        }
    };

    let evidence_blob = store_evidence_blob(binding, &evidence_text);
    let run_id = VerificationRunId::new();
    let verification_run = VerificationRun {
        run_id,
        test_ids: plan.tests.iter().map(|test| test.test_id).collect(),
        status,
        runner: test_runner,
        started_at,
        finished_at: Some(finished_at),
        duration_ms: Some(duration.as_millis() as u64),
        evidence_blob,
        exit_code: Some(exit_code),
    };
    let proved_work_ids = plan
        .proved_work_items
        .iter()
        .map(|work| work.work_id)
        .collect::<Vec<_>>();
    let proved_entity_ids = plan
        .proved_entities
        .iter()
        .map(|entity| entity.id)
        .collect::<Vec<_>>();

    record_verification_evidence(
        graph,
        &verification_run,
        &proved_entity_ids,
        &proved_work_ids,
    )
    .map_err(|err: Box<dyn std::error::Error>| anyhow!(err.to_string()))?;
    crate::provenance::record_cli_audit_event(
        graph,
        "verify.run",
        Some(WorkScope::Entity(plan.entity.id)),
        Some(format!(
            "runner={}; status={}; tests={}; impacted_entities={}",
            request.runner,
            verification_run.status,
            verification_run.test_ids.len(),
            proved_entity_ids.len()
        )),
    )?;

    lines.push(String::new());
    lines.push("VerificationRun recorded:".to_string());
    lines.push(format!("  Run ID:   {}", run_id));
    lines.push(format!(
        "  Entity:   {} ({:?})",
        plan.entity.name, plan.entity.kind
    ));
    lines.push(format!("  Status:   {}", verification_run.status));
    lines.push(format!("  Duration: {}ms", duration.as_millis()));
    lines.push(format!("  Exit:     {}", exit_code));
    lines.push(format!("  Tests:    {}", verification_run.test_ids.len()));
    lines.push(format!("  Entities: {}", proved_entity_ids.len()));
    lines.push(format!("  Work:     {}", proved_work_ids.len()));
    if let Some(ref blob) = verification_run.evidence_blob {
        lines.push(format!("  Evidence: {}", blob));
    }

    Ok(VerifyRunResponse { lines })
}

#[cfg(unix)]
fn verification_shell_program() -> &'static str {
    // POSIX systems provide /bin/sh; resolving through PATH makes verification
    // fail under otherwise valid restricted-path environments.
    "/bin/sh"
}

#[cfg(not(unix))]
fn verification_shell_program() -> &'static str {
    "sh"
}

fn verification_command(working_dir: &std::path::Path, command: &str) -> std::process::Command {
    let mut shell = std::process::Command::new(verification_shell_program());
    shell.current_dir(working_dir).arg("-c").arg(command);
    shell
}

#[derive(Debug, Clone)]
struct VerificationPlan {
    entity: Entity,
    depth: u32,
    direct: EntityProofSlice,
    impacted: Vec<EntityProofSlice>,
    tests: Vec<TestCase>,
    latest_test_runs: HashMap<kin_model::TestId, VerificationRun>,
    proved_entities: Vec<Entity>,
    proved_work_items: Vec<WorkItem>,
}

#[derive(Debug, Clone)]
struct EntityProofSlice {
    entity: Entity,
    tests: Vec<TestCase>,
    work_items: Vec<WorkItem>,
}

#[derive(Debug, Clone)]
struct ChangeVerificationPlan {
    change: SemanticChange,
    depth: u32,
    entity_plans: Vec<VerificationPlan>,
    tests: Vec<TestCase>,
    latest_test_runs: HashMap<kin_model::TestId, VerificationRun>,
    removed_entities: Vec<kin_model::EntityId>,
}

fn build_verification_plan<G>(graph: &G, entity_query: &str, depth: u32) -> Result<VerificationPlan>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let entity = resolve_entity(graph, entity_query)?;
    build_verification_plan_for_entity(graph, entity, depth)
}

fn build_verification_plan_for_entity<G>(
    graph: &G,
    entity: Entity,
    depth: u32,
) -> Result<VerificationPlan>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let direct = build_entity_proof_slice(graph, entity.clone())?;
    let impacted_entities = graph
        .get_downstream_impact(&entity.id, depth)
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut impacted = Vec::new();
    for impacted_entity in impacted_entities {
        impacted.push(build_entity_proof_slice(graph, impacted_entity)?);
    }

    let mut seen_test_ids = HashSet::new();
    let mut tests = Vec::new();
    for test in &direct.tests {
        if seen_test_ids.insert(test.test_id) {
            tests.push(test.clone());
        }
    }
    for slice in &impacted {
        for test in &slice.tests {
            if seen_test_ids.insert(test.test_id) {
                tests.push(test.clone());
            }
        }
    }

    let mut proved_entities = Vec::new();
    let mut seen_entity_ids = HashSet::new();
    if seen_entity_ids.insert(entity.id) {
        proved_entities.push(entity.clone());
    }
    if !direct.tests.is_empty() && seen_entity_ids.insert(direct.entity.id) {
        proved_entities.push(direct.entity.clone());
    }
    for slice in &impacted {
        if !slice.tests.is_empty() && seen_entity_ids.insert(slice.entity.id) {
            proved_entities.push(slice.entity.clone());
        }
    }

    let mut proved_work_items = Vec::new();
    let mut seen_work_ids = HashSet::new();
    let selected_test_ids = tests
        .iter()
        .map(|test| test.test_id)
        .collect::<HashSet<_>>();
    for slice in std::iter::once(&direct).chain(impacted.iter()) {
        for work in &slice.work_items {
            let verifies = graph
                .get_tests_verifying_work(&work.work_id)
                .map_err(|err| anyhow!(err.to_string()))?;
            if verifies
                .iter()
                .any(|linked_test| selected_test_ids.contains(&linked_test.test_id))
                && seen_work_ids.insert(work.work_id)
            {
                proved_work_items.push(work.clone());
            }
        }
    }
    let latest_test_runs = build_latest_test_runs(graph, &tests)?;

    Ok(VerificationPlan {
        entity,
        depth,
        direct,
        impacted,
        tests,
        latest_test_runs,
        proved_entities,
        proved_work_items,
    })
}

fn build_change_verification_plan<G>(
    graph: &G,
    change: &SemanticChange,
    depth: u32,
) -> Result<ChangeVerificationPlan>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut entity_plans = Vec::new();
    let mut tests = Vec::new();
    let mut seen_test_ids = HashSet::new();
    let mut removed_entities = Vec::new();

    for delta in &change.entity_deltas {
        match delta {
            EntityDelta::Added { new: entity } => {
                let plan = build_verification_plan_for_entity(graph, entity.clone(), depth)?;
                for test in &plan.tests {
                    if seen_test_ids.insert(test.test_id) {
                        tests.push(test.clone());
                    }
                }
                entity_plans.push(plan);
            }
            EntityDelta::Modified { new, .. } => {
                let plan = build_verification_plan_for_entity(graph, new.clone(), depth)?;
                for test in &plan.tests {
                    if seen_test_ids.insert(test.test_id) {
                        tests.push(test.clone());
                    }
                }
                entity_plans.push(plan);
            }
            EntityDelta::Removed { old } => removed_entities.push(old.id),
        }
    }
    let latest_test_runs = build_latest_test_runs(graph, &tests)?;

    Ok(ChangeVerificationPlan {
        change: change.clone(),
        depth,
        entity_plans,
        tests,
        latest_test_runs,
        removed_entities,
    })
}

fn build_latest_test_runs<G>(
    graph: &G,
    tests: &[TestCase],
) -> Result<HashMap<kin_model::TestId, VerificationRun>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut latest = HashMap::new();
    for test in tests {
        if let Some(run) = latest_run_for_test(graph, test.test_id)? {
            latest.insert(test.test_id, run);
        }
    }
    Ok(latest)
}

fn latest_run_for_test<G>(graph: &G, test_id: kin_model::TestId) -> Result<Option<VerificationRun>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let runs = graph
        .list_runs_for_test(&test_id)
        .map_err(|err| anyhow!(err.to_string()))?;
    Ok(runs.into_iter().max_by(|left, right| {
        let left_finished = left
            .finished_at
            .clone()
            .unwrap_or_else(|| left.started_at.clone());
        let right_finished = right
            .finished_at
            .clone()
            .unwrap_or_else(|| right.started_at.clone());
        left_finished.cmp(&right_finished)
    }))
}

fn build_entity_proof_slice<G>(graph: &G, entity: Entity) -> Result<EntityProofSlice>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut tests = graph
        .get_tests_for_entity(&entity.id)
        .map_err(|err| anyhow!(err.to_string()))?;
    let work_items = graph
        .get_work_for_scope(&WorkScope::Entity(entity.id))
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut seen_test_ids = tests
        .iter()
        .map(|test| test.test_id)
        .collect::<HashSet<_>>();
    for work in &work_items {
        let linked_tests = graph
            .get_tests_verifying_work(&work.work_id)
            .map_err(|err| anyhow!(err.to_string()))?;
        for linked_test in linked_tests {
            if seen_test_ids.insert(linked_test.test_id) {
                tests.push(linked_test);
            }
        }
    }

    Ok(EntityProofSlice {
        entity,
        tests,
        work_items,
    })
}

fn verification_plan_lines(plan: &VerificationPlan) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Targeted proof plan for {} ({:?})",
        plan.entity.name, plan.entity.kind
    ));
    lines.push(format!("  Impact depth: {}", plan.depth));
    lines.push(format!("  Planned entities: {}", 1 + plan.impacted.len()));
    lines.push(format!(
        "  Direct scope: {} test(s), {} work item(s)",
        plan.direct.tests.len(),
        plan.direct.work_items.len()
    ));

    if !plan.impacted.is_empty() {
        lines.push("  Impacted dependents:".to_string());
        for slice in &plan.impacted {
            lines.push(format!(
                "    - {} ({:?}) — {} test(s), {} work item(s)",
                slice.entity.name,
                slice.entity.kind,
                slice.tests.len(),
                slice.work_items.len()
            ));
        }
    }

    lines.push(format!(
        "  Selected proof set: {} test(s)",
        plan.tests.len()
    ));
    for test in &plan.tests {
        let latest = plan
            .latest_test_runs
            .get(&test.test_id)
            .map(|run| run.status.to_string())
            .unwrap_or_else(|| "missing".to_string());
        lines.push(format!(
            "    - {} [{}] runner={} latest={}",
            test.name, test.kind, test.runner, latest
        ));
    }

    if !plan.proved_work_items.is_empty() {
        lines.push("  Linked work items:".to_string());
        for work in &plan.proved_work_items {
            lines.push(format!("    - {} ({})", work.title, work.work_id));
        }
    }
    lines
}

fn change_verification_plan_lines(plan: &ChangeVerificationPlan) -> Vec<String> {
    let mut lines = vec![
        format!("Targeted proof plan for change {}", plan.change.id),
        format!("  Message: {}", plan.change.message),
        format!("  Impact depth: {}", plan.depth),
        format!("  Changed entities planned: {}", plan.entity_plans.len()),
        format!("  Selected proof set: {} test(s)", plan.tests.len()),
    ];
    if !plan.removed_entities.is_empty() {
        lines.push(format!(
            "  Removed entities without active proof graph state: {}",
            plan.removed_entities.len()
        ));
        for entity_id in &plan.removed_entities {
            lines.push(format!("    - {}", entity_id));
        }
    }
    if !plan.entity_plans.is_empty() {
        lines.push("  Entity plans:".to_string());
        for entity_plan in &plan.entity_plans {
            lines.push(format!(
                "    - {} ({:?}) — {} selected test(s), {} impacted dependents",
                entity_plan.entity.name,
                entity_plan.entity.kind,
                entity_plan.tests.len(),
                entity_plan.impacted.len()
            ));
        }
    }
    if !plan.tests.is_empty() {
        lines.push("  Proof tests:".to_string());
        for test in &plan.tests {
            let latest = plan
                .latest_test_runs
                .get(&test.test_id)
                .map(|run| run.status.to_string())
                .unwrap_or_else(|| "missing".to_string());
            lines.push(format!(
                "    - {} [{}] runner={} latest={}",
                test.name, test.kind, test.runner, latest
            ));
        }
    }
    lines
}

fn resolve_change<G>(
    graph: &G,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    change_id: Option<&str>,
) -> Result<SemanticChange>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let change_id = match change_id {
        Some(hash) => parse_change_id(hash)?,
        None => crate::commands::repository_authority::ActiveRepositoryAuthority::open(binding)?
            .current_change_id()?
            .ok_or_else(|| {
                anyhow!(
                    "this workspace has no commits yet, so there is nothing to verify; make one \
                     with `kin commit`"
                )
            })?,
    };

    graph
        .get_change(&change_id)
        .map_err(|err| anyhow!(err.to_string()))?
        .ok_or_else(|| anyhow!("change {} not found", change_id))
}

fn parse_change_id(input: &str) -> Result<SemanticChangeId> {
    Ok(SemanticChangeId::from_hash(
        Hash256::from_hex(input).map_err(|err| anyhow!("invalid change hash: {}", err))?,
    ))
}

fn resolve_entity<G>(graph: &G, entity_query: &str) -> Result<Entity>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let filter = EntityFilter {
        name_pattern: Some(entity_query.to_string()),
        ..Default::default()
    };
    let entities = graph
        .query_entities(&filter)
        .map_err(|err| anyhow!(err.to_string()))?;

    match entities.as_slice() {
        [] => bail!("No entity matching '{}' found.", entity_query),
        [entity] => Ok(entity.clone()),
        many => {
            let preview = many
                .iter()
                .take(5)
                .map(|entity| entity.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "Multiple entities match '{}': {}. Use a more exact name.",
                entity_query,
                preview
            );
        }
    }
}

fn parse_runner(runner: &str) -> TestRunner {
    match runner {
        "cargo" => TestRunner::Cargo,
        "jest" => TestRunner::Jest,
        "pytest" => TestRunner::Pytest,
        "go" => TestRunner::Go,
        "junit" => TestRunner::JUnit,
        other => TestRunner::Custom(other.to_string()),
    }
}

fn build_runner_command(test_runner: &TestRunner, entity_name: &str, tests: &[TestCase]) -> String {
    match test_runner {
        TestRunner::Cargo => {
            let filter = if tests.len() == 1 {
                tests[0].name.clone()
            } else {
                entity_name.to_string()
            };
            format!("cargo test {}", shell_quote(&filter))
        }
        TestRunner::Jest => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            };
            format!("npx jest --testNamePattern={}", shell_quote(&pattern))
        }
        TestRunner::Pytest => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" or ")
            };
            format!("pytest -k {}", shell_quote(&pattern))
        }
        TestRunner::Go => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            };
            format!("go test -run {}", shell_quote(&pattern))
        }
        TestRunner::JUnit => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            format!("mvn test -Dtest={}", shell_quote(&pattern))
        }
        TestRunner::Custom(command) => format!("{} {}", command, shell_quote(entity_name)),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn store_evidence_blob(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    evidence_text: &str,
) -> Option<Hash256> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(evidence_text.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let hash = Hash256::from_bytes(bytes);

    let authority =
        crate::commands::repository_authority::ActiveRepositoryAuthority::open(binding).ok()?;
    authority
        .save_source_blob(hash, evidence_text.as_bytes())
        .ok()?;
    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        AuthorId, ChangeOrigin, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId,
        FingerprintAlgorithm, GraphNodeId, IdentityRef, LanguageId, Priority, ProvenanceStore,
        Relation, RelationId, RelationKind, RelationOrigin, SemanticFingerprint, TestKind,
        Visibility, WorkStatus, WorkStore,
    };
    fn make_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn verification_shell_does_not_depend_on_path_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let empty_path = dir.path().join("empty-path");
        std::fs::create_dir(&empty_path).unwrap();

        let output = verification_command(dir.path(), "printf path-independent")
            .env("PATH", &empty_path)
            .output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"path-independent");
    }

    #[tokio::test]
    async fn run_verification_persists_targeted_run_and_links_work() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();

        let entity = make_entity("checkout", "src/checkout.rs");
        graph.upsert_entity(&entity).unwrap();

        let work = WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: kin_model::WorkKind::Feature,
            title: "Implement checkout".into(),
            description: "Ship checkout flow".into(),
            status: WorkStatus::InProgress,
            priority: Priority::High,
            scopes: vec![WorkScope::Entity(entity.id)],
            acceptance_criteria: vec!["passing checkout proof".into()],
            external_refs: vec![],
            created_by: IdentityRef::human("cli-user"),
            created_at: Timestamp::now(),
        };
        graph.create_work_item(&work).unwrap();

        let test = TestCase {
            test_id: kin_model::TestId::new(),
            name: "test_checkout_flow".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout.rs")),
        };
        graph.create_test_case(&test).unwrap();
        graph
            .create_test_verifies_work(&test.test_id, &work.work_id)
            .unwrap();
        snap.save().unwrap();

        let response = execute_verify_run(
            &layout,
            &binding,
            graph.as_ref(),
            &VerifyRunRequest {
                entity: "checkout".into(),
                runner: "printf".into(),
                depth: 2,
            },
        )
        .unwrap();
        assert!(response
            .lines
            .iter()
            .any(|line| line.contains("VerificationRun recorded")));
        snap.save().unwrap();
        drop(graph);
        drop(snap);

        let reopened = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = reopened.graph();

        let runs = graph.list_runs_for_test(&test.test_id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, VerificationStatus::Passing);

        let entity_runs = graph.list_runs_proving_entity(&entity.id).unwrap();
        assert_eq!(entity_runs.len(), 1);
        assert_eq!(entity_runs[0].run_id, runs[0].run_id);

        let work_runs = graph.list_runs_proving_work(&work.work_id).unwrap();
        assert_eq!(work_runs.len(), 1);
        assert_eq!(work_runs[0].run_id, runs[0].run_id);

        let plan = build_verification_plan(graph.as_ref(), "checkout", 2).unwrap();
        assert_eq!(
            plan.latest_test_runs
                .get(&test.test_id)
                .map(|run| run.status),
            Some(VerificationStatus::Passing)
        );

        let audit_events = graph.query_audit_events(None, 10).unwrap();
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].action, "verify.run");
    }

    #[test]
    fn build_verification_plan_includes_impacted_dependents() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();

        let callee = make_entity("checkout_core", "src/checkout.rs");
        let caller = make_entity("checkout_handler", "src/handler.rs");
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(callee.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![],
            })
            .unwrap();

        let caller_test = TestCase {
            test_id: kin_model::TestId::new(),
            name: "test_checkout_handler".into(),
            language: "rust".into(),
            kind: TestKind::Integration,
            scopes: vec![WorkScope::Entity(caller.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout_handler.rs")),
        };
        graph.create_test_case(&caller_test).unwrap();

        let plan = build_verification_plan(graph.as_ref(), "checkout_core", 1).unwrap();

        assert_eq!(plan.direct.entity.id, callee.id);
        assert!(plan.direct.tests.is_empty());
        assert_eq!(plan.impacted.len(), 1);
        assert_eq!(plan.impacted[0].entity.id, caller.id);
        assert_eq!(plan.impacted[0].tests.len(), 1);
        assert_eq!(plan.impacted[0].tests[0].test_id, caller_test.test_id);
        assert_eq!(plan.tests.len(), 1);
        assert_eq!(plan.tests[0].test_id, caller_test.test_id);
        assert_eq!(plan.proved_entities.len(), 2);
        assert!(plan
            .proved_entities
            .iter()
            .any(|entity| entity.id == callee.id));
        assert!(plan
            .proved_entities
            .iter()
            .any(|entity| entity.id == caller.id));
    }

    #[test]
    fn build_change_verification_plan_aggregates_impacted_tests() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();

        let callee = make_entity("checkout_core", "src/checkout.rs");
        let caller = make_entity("checkout_handler", "src/handler.rs");
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(callee.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![],
            })
            .unwrap();

        let caller_test = TestCase {
            test_id: kin_model::TestId::new(),
            name: "test_checkout_handler".into(),
            language: "rust".into(),
            kind: TestKind::Integration,
            scopes: vec![WorkScope::Entity(caller.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout_handler.rs")),
        };
        graph.create_test_case(&caller_test).unwrap();

        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([7; 32])),
            parents: vec![],
            origin: ChangeOrigin::Native,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "touch checkout core".into(),
            entity_deltas: vec![EntityDelta::Modified {
                old: callee.clone(),
                new: callee.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let plan = build_change_verification_plan(graph.as_ref(), &change, 1).unwrap();

        assert_eq!(plan.entity_plans.len(), 1);
        assert_eq!(plan.entity_plans[0].entity.id, callee.id);
        assert_eq!(plan.entity_plans[0].impacted.len(), 1);
        assert_eq!(plan.entity_plans[0].impacted[0].entity.id, caller.id);
        assert_eq!(plan.tests.len(), 1);
        assert_eq!(plan.tests[0].test_id, caller_test.test_id);
        assert!(plan.removed_entities.is_empty());
    }
}
