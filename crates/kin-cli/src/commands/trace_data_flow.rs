// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin trace-data-flow` — return the actual call/data-flow chain rooted at a
//! focal entity in a single substrate call.
//!
//! Fix #3 in the per-family accuracy plan. The v4 `trace_computation` primitive
//! aliases `get_context_pack` and returns a flat snippet pack — not a chain.
//! When the LLM has to "trace computation step by step" it falls back to
//! calling `get_entity_source` per step, which hits the 24-round tool-call cap
//! on large repos.
//!
//! This primitive walks the relation graph from the focal entity in the
//! requested direction (callees, callers, or both), recursing to a bounded
//! depth and capping per-step branching, and inlines each step's body so the
//! model can read the chain without further tool calls.

use anyhow::{Context, Result};
use kin_index::RelationResolution;
use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, RelationKind};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::commands::graph::{graph_source_record_from, GraphSourceRecord};
use crate::commands::locate::{record_degradation, RetrievalDegradation};
use crate::commands::repository_authority::{
    ActiveRepositoryAuthority, RequestRepositoryAuthority,
};

const DEFAULT_DEPTH: usize = 3;
const MAX_DEPTH: usize = 8;
const DEFAULT_LIMIT_PER_STEP: usize = 5;
const MAX_LIMIT_PER_STEP: usize = 25;
const MAX_TOTAL_STEPS: usize = 200;

/// Wall-clock ceiling for one trace walk.
///
/// Every bound above this one is structural — depth, per-step fan-out, total
/// steps — and structural bounds say nothing about elapsed time. A walk of 200
/// steps is small by every one of them while still running for minutes, because
/// what each step costs depends on the store rather than on the shape of the
/// chain. This is the only bound that holds when a step turns out to be
/// expensive, so it is the one that keeps a trace answerable.
const DEFAULT_TIME_BUDGET: Duration = Duration::from_secs(20);

/// Relations examined before the walk stops regardless of the clock.
///
/// A time budget alone leaves the response time-dependent: the same query
/// against the same store returns a different chain on a loaded machine than on
/// an idle one. This bound is deterministic, so a pathological fan-in is cut at
/// the same place every run and a trace stays reproducible.
const DEFAULT_MAX_EDGES_SCANNED: usize = 250_000;

/// A caller's standing answer to "does anyone still want this result?".
///
/// Set by whoever owns the request once nobody is waiting on it. The walk reads
/// it at the same points it charges its budget, so abandonment costs at most one
/// more relation rather than the rest of the traversal.
#[derive(Debug, Clone, Default)]
pub struct TraceCancel(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl TraceCancel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop the walk at its next checkpoint.
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Hard ceilings applied to one trace walk, independent of the request's own
/// depth / fan-out parameters.
///
/// Those parameters bound the SHAPE of the answer and are the caller's to
/// choose. These bound the WORK, and are not: a caller cannot ask for an
/// unbounded walk, because the daemon serving it has other callers.
/// NOT `#[derive(Default)]`. A derived default is a zero budget, which reads as
/// "no limits" and behaves as "stop before the first step", and every caller
/// here reaches the default through struct-update syntax where that mistake
/// would be invisible.
#[derive(Debug, Clone)]
pub struct TraceBudget {
    pub time_budget: Duration,
    pub max_edges_scanned: usize,
    /// Absent for a walk nobody can abandon, such as the CLI's own in-process
    /// call, where the process waiting for the answer is the one running it.
    pub cancel: Option<TraceCancel>,
}

impl Default for TraceBudget {
    fn default() -> Self {
        Self::bounded()
    }
}

impl TraceBudget {
    pub fn bounded() -> Self {
        Self {
            time_budget: DEFAULT_TIME_BUDGET,
            max_edges_scanned: DEFAULT_MAX_EDGES_SCANNED,
            cancel: None,
        }
    }

    /// The shipped budget, stopped early when `cancel` fires.
    pub fn cancellable(cancel: TraceCancel) -> Self {
        Self {
            cancel: Some(cancel),
            ..Self::bounded()
        }
    }
}

/// Why a walk stopped expanding.
///
/// `Exhausted` is the healthy end: the frontier ran out within every bound.
/// The rest are refusals to keep working, and each one is reported to the
/// caller as a degradation rather than silently shortening the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceStop {
    Exhausted,
    TimeBudget,
    EdgeBudget,
    Cancelled,
}

/// Running cost of one walk, checked at each frontier node and each relation.
struct TraceMeter {
    budget: TraceBudget,
    started: Instant,
    edges_scanned: usize,
}

impl TraceMeter {
    fn new(budget: TraceBudget) -> Self {
        Self {
            budget,
            started: Instant::now(),
            edges_scanned: 0,
        }
    }

    /// Charge one examined relation and report whether the walk may continue.
    fn charge_edge(&mut self) -> Option<TraceStop> {
        self.edges_scanned = self.edges_scanned.saturating_add(1);
        if self.edges_scanned >= self.budget.max_edges_scanned {
            return Some(TraceStop::EdgeBudget);
        }
        self.should_stop()
    }

    /// Cancellation is checked first. A walk nobody is waiting for should stop
    /// for that reason rather than be reported as having run out of time.
    fn should_stop(&self) -> Option<TraceStop> {
        if self
            .budget
            .cancel
            .as_ref()
            .is_some_and(TraceCancel::is_cancelled)
        {
            return Some(TraceStop::Cancelled);
        }
        (self.started.elapsed() >= self.budget.time_budget).then_some(TraceStop::TimeBudget)
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Translate a stop reason into the caller-facing degradation record.
///
/// `Exhausted` produces nothing: a walk that finished inside every bound has
/// nothing to disclose, which is what keeps an unaffected trace byte-identical
/// to the one this bound was added to.
fn record_trace_stop(
    sink: &mut Vec<RetrievalDegradation>,
    stop: TraceStop,
    meter: &TraceMeter,
    steps: usize,
) {
    let (reason, detail) = match stop {
        TraceStop::Exhausted => return,
        TraceStop::TimeBudget => (
            "time_budget_exceeded",
            format!(
                "trace walk stopped after {:.1}s (budget {:.0}s) with {} steps and {} relations \
                 examined; the chain below is the part that was reached",
                meter.elapsed().as_secs_f64(),
                meter.budget.time_budget.as_secs_f64(),
                steps,
                meter.edges_scanned,
            ),
        ),
        TraceStop::EdgeBudget => (
            "edge_budget_exceeded",
            format!(
                "trace walk examined {} relations (budget {}) in {:.1}s and stopped with {} \
                 steps; the chain below is the part that was reached",
                meter.edges_scanned,
                meter.budget.max_edges_scanned,
                meter.elapsed().as_secs_f64(),
                steps,
            ),
        ),
        // Recorded even though the caller who would read it has, by definition,
        // stopped listening. The walk still returns rather than being discarded
        // silently, so anything that does observe the result — a log, a cache, a
        // test — can tell an abandoned walk from a complete one.
        TraceStop::Cancelled => (
            "cancelled",
            format!(
                "trace walk was cancelled after {:.1}s with {} steps and {} relations examined; \
                 the requester stopped waiting for this result",
                meter.elapsed().as_secs_f64(),
                steps,
                meter.edges_scanned,
            ),
        ),
    };
    record_degradation(
        sink,
        RetrievalDegradation {
            component: "trace_walk".to_string(),
            reason: reason.to_string(),
            detail,
            remediation: "narrow the trace with a smaller --depth or --limit-per-step, or start \
                          from a more specific focal entity"
                .to_string(),
        },
    );
}

/// Direction of traversal from the focal entity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraceDirection {
    /// Walk outgoing edges (the focal calls / imports / references these).
    Calls,
    /// Walk incoming edges (these call / import / reference the focal).
    Callers,
    /// Walk both directions and merge into a single chain.
    #[default]
    Both,
}

impl TraceDirection {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_lowercase().as_str() {
            "calls" | "callee" | "callees" | "out" | "outgoing" => Ok(TraceDirection::Calls),
            "callers" | "caller" | "in" | "incoming" => Ok(TraceDirection::Callers),
            "both" | "all" => Ok(TraceDirection::Both),
            other => anyhow::bail!(
                "invalid direction '{}': expected calls, callers, or both",
                other
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TraceDirection::Calls => "calls",
            TraceDirection::Callers => "callers",
            TraceDirection::Both => "both",
        }
    }
}

/// Request shape for the trace-data-flow primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataFlowRequest {
    /// Focal entity to start tracing from. Accepts an entity UUID or an exact
    /// entity name (resolved via the same ranking path as `graph source`).
    pub focal: String,
    /// Maximum traversal depth from the focal (default 3, capped at 8).
    #[serde(default)]
    pub depth: Option<usize>,
    /// Direction of traversal (default `both`).
    #[serde(default)]
    pub direction: Option<TraceDirection>,
    /// Maximum number of relations expanded per step (default 5, capped at 25).
    #[serde(default)]
    pub limit_per_step: Option<usize>,
}

/// One step in the data-flow chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// 1-based step index (0 is reserved for the focal entity).
    pub step: usize,
    /// `caller` when this step reached focal via an incoming edge, `callee`
    /// when via an outgoing edge.
    pub role: String,
    /// Relation kind that linked this step to its parent (e.g., `Calls`,
    /// `Imports`, `References`).
    pub relation_kind: String,
    /// How the edge INTO this step was resolved: `type_resolved`,
    /// `import_scoped`, or `name_only`. A chain is only as trustworthy as its
    /// weakest hop; a `name_only` hop was matched by name alone, so the flow it
    /// claims may not exist. Defaulted on read so a payload recorded before the
    /// marker existed still deserializes.
    #[serde(default)]
    pub resolution: String,
    /// Step index of the parent that introduced this step into the chain.
    /// `0` means "directly attached to the focal entity".
    pub parent_step: usize,
    /// Depth from the focal (1 = direct neighbor of focal, 2 = neighbor of
    /// neighbor, etc.).
    pub depth: usize,
    /// Source record for this entity, including the inlined body. Optional
    /// because some entities (external symbols, headers without spans) may
    /// not be readable from the graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<GraphSourceRecord>,
    /// Fallback fields for entities without a readable body. Always present
    /// so the consumer can render even when `entity` is None.
    pub entity_id: String,
    pub entity_name: String,
    pub entity_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_file: Option<String>,
}

/// Response from the trace-data-flow primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataFlowResponse {
    /// Focal entity. When the entity has a readable body, the record is
    /// populated; otherwise the fallback identity fields below are used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focal: Option<GraphSourceRecord>,
    pub focal_id: String,
    pub focal_name: String,
    pub focal_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focal_file: Option<String>,
    /// Direction that was traversed.
    pub direction: String,
    /// Depth that was traversed.
    pub depth: usize,
    /// The ordered chain of steps reached from the focal. Already deduplicated
    /// (each entity appears at most once).
    pub chain: Vec<TraceStep>,
    /// Total number of steps in the chain (excludes the focal).
    pub total_steps: usize,
    /// True when the traversal was cut off because per-step or total caps
    /// were hit. Lets callers detect when they need to widen the limit.
    pub truncated: bool,
    /// Every work bound that cut this walk short, in the same machine-readable
    /// shape `semantic_locate` reports retrieval degradation in. Empty — and
    /// omitted from the payload — for a walk that finished inside every bound,
    /// so a trace unaffected by these ceilings is unchanged by them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradations: Vec<RetrievalDegradation>,
}

/// CLI entry: `kin trace-data-flow --focal <e> [--depth N] [--direction D]
/// [--limit-per-step M]`.
pub async fn run_seeded(
    focal: String,
    depth: Option<usize>,
    direction: Option<String>,
    limit_per_step: Option<usize>,
) -> Result<()> {
    let direction = match direction {
        Some(value) => Some(TraceDirection::parse(&value)?),
        None => None,
    };
    let request = TraceDataFlowRequest {
        focal,
        depth,
        direction,
        limit_per_step,
    };
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_trace_data_flow(&layout, &request).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_daemon_trace_data_flow(
    layout: &kin_core::KinLayout,
    request: &TraceDataFlowRequest,
) -> Result<TraceDataFlowResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("trace-data-flow", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .trace_data_flow(request)
        .await
        .context("daemon trace-data-flow command failed")
}

/// Build a trace-data-flow response from the live graph.
///
/// This is the single substrate primitive used by both the CLI route and the
/// MCP tool dispatcher so the chain construction stays in one place.
pub fn build_trace_data_flow_response(
    repository_authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    request: &TraceDataFlowRequest,
) -> Result<TraceDataFlowResponse> {
    build_trace_data_flow_response_within(
        repository_authority,
        graph,
        request,
        TraceBudget::default(),
    )
}

/// The same walk under caller-supplied work ceilings.
///
/// Split out so the bounds are testable at a scale a test can actually reach:
/// the shipped budget is measured in seconds and hundreds of thousands of
/// edges, and a test that had to exhaust it would be as slow as the defect.
pub fn build_trace_data_flow_response_within(
    repository_authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    request: &TraceDataFlowRequest,
    budget: TraceBudget,
) -> Result<TraceDataFlowResponse> {
    let trimmed = request.focal.trim();
    if trimmed.is_empty() {
        anyhow::bail!("trace_data_flow requires a non-empty focal");
    }
    let depth = request.depth.unwrap_or(DEFAULT_DEPTH).clamp(1, MAX_DEPTH);
    let direction = request.direction.unwrap_or_default();
    let limit_per_step = request
        .limit_per_step
        .unwrap_or(DEFAULT_LIMIT_PER_STEP)
        .clamp(1, MAX_LIMIT_PER_STEP);

    let focal_entity = match resolve_trace_focal(graph, trimmed)? {
        Some(entity) => entity,
        None => return Err(focal_not_found_error(trimmed)),
    };

    let mut meter = TraceMeter::new(budget);
    let mut degradations: Vec<RetrievalDegradation> = Vec::new();

    // One authority open for the whole chain, not one per step.
    //
    // Opening authority verifies every stored body, linear in store size. The
    // per-step body projection used to open its own, so a chain of N steps paid
    // N+1 full-store verifications and a structurally tiny trace ran for
    // minutes on a large store. Holding one open also makes the chain coherent:
    // every step is now read from the same generation, where per-step opens
    // could straddle a publication.
    //
    // A store with no readable authority still gets its chain. Bodies were
    // always optional per step, and hoisting the open must not turn a payload
    // that used to arrive body-less into a failed call — so the failure is
    // disclosed and the walk continues on identity alone.
    let projection = match open_body_projection(repository_authority) {
        Ok(projection) => Some(projection),
        Err(error) => {
            record_degradation(
                &mut degradations,
                RetrievalDegradation {
                    component: "entity_bodies".to_string(),
                    reason: "authority_unavailable".to_string(),
                    detail: format!(
                        "repository authority could not be opened, so no step carries an inlined \
                         body: {error:#}"
                    ),
                    remediation: "run 'kin status' to check the repository store, and 'kin init' \
                                  if it has not been initialized"
                        .to_string(),
                },
            );
            None
        }
    };

    // Try to load the focal source record. Failures (missing span, OOB blob)
    // degrade gracefully to the identity-only payload — the chain still works.
    let focal_record = source_record_or_none(projection.as_ref(), &focal_entity);

    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    let allowed: HashSet<RelationKind> = reference_kinds.iter().copied().collect();

    let mut chain: Vec<TraceStep> = Vec::new();
    let mut visited: HashSet<EntityId> = HashSet::new();
    visited.insert(focal_entity.id);
    let mut truncated = false;
    let mut stop = TraceStop::Exhausted;

    // Frontier: (parent_step, parent_entity, parent_depth).
    let mut frontier: Vec<(usize, EntityId, usize)> = vec![(0, focal_entity.id, 0)];
    let mut next_frontier: Vec<(usize, EntityId, usize)>;

    'walk: while !frontier.is_empty() {
        next_frontier = Vec::new();

        for (parent_step, parent_id, parent_depth) in frontier.drain(..) {
            if parent_depth >= depth {
                continue;
            }

            // Checked before the relation read rather than only inside the
            // relation loop: reading one node's relations is itself unbounded
            // work on a high-fan-in entity, so a walk that has already spent
            // its budget must not start another one.
            if let Some(reason) = meter.should_stop() {
                stop = reason;
                break 'walk;
            }

            let relations = graph
                .get_all_relations_for_entity(&parent_id)
                .context("read relations for trace step")?;

            // Expand outgoing edges (parent calls these) when direction allows.
            let want_callees = matches!(direction, TraceDirection::Calls | TraceDirection::Both);
            // Expand incoming edges (these call parent) when direction allows.
            let want_callers = matches!(direction, TraceDirection::Callers | TraceDirection::Both);

            // Independent budgets per direction so `direction=both` doesn't
            // starve callers when callees are listed first (or vice versa).
            let mut callee_count = 0usize;
            let mut caller_count = 0usize;
            for rel in &relations {
                if let Some(reason) = meter.charge_edge() {
                    stop = reason;
                    break 'walk;
                }
                if !allowed.contains(&rel.kind) {
                    continue;
                }
                let src_entity = rel.src.as_entity();
                let dst_entity = match rel.dst {
                    GraphNodeId::Entity(id) => Some(id),
                    _ => None,
                };

                // Decide which side of the relation is the "next" node.
                let (next_id, role) = if want_callees
                    && src_entity == Some(parent_id)
                    && dst_entity.is_some()
                    && dst_entity != Some(parent_id)
                {
                    (dst_entity.unwrap(), "callee")
                } else if want_callers
                    && dst_entity == Some(parent_id)
                    && src_entity.is_some()
                    && src_entity != Some(parent_id)
                {
                    (src_entity.unwrap(), "caller")
                } else {
                    continue;
                };

                // Independent per-direction budget — cap callees and callers
                // separately so `direction=both` doesn't starve one side.
                // Check budget BEFORE marking visited so the next relation
                // (potentially in the other direction) can still consider
                // this entity if appropriate.
                if role == "callee" && callee_count >= limit_per_step {
                    truncated = true;
                    continue;
                }
                if role == "caller" && caller_count >= limit_per_step {
                    truncated = true;
                    continue;
                }

                if !visited.insert(next_id) {
                    continue;
                }

                if role == "callee" {
                    callee_count += 1;
                } else {
                    caller_count += 1;
                }

                if chain.len() >= MAX_TOTAL_STEPS {
                    truncated = true;
                    break;
                }

                let next_entity = match graph
                    .get_entity(&next_id)
                    .context("load trace step entity")?
                {
                    Some(entity) => entity,
                    None => continue,
                };
                let next_record = source_record_or_none(projection.as_ref(), &next_entity);
                let next_depth = parent_depth + 1;
                let step_index = chain.len() + 1;

                chain.push(TraceStep {
                    step: step_index,
                    role: role.to_string(),
                    relation_kind: format!("{:?}", rel.kind),
                    resolution: RelationResolution::of(&rel).as_str().to_string(),
                    parent_step,
                    depth: next_depth,
                    entity: next_record,
                    entity_id: next_entity.id.to_string(),
                    entity_name: next_entity.name.clone(),
                    entity_kind: format!("{:?}", next_entity.kind),
                    entity_file: next_entity.file_origin.as_ref().map(|p| p.0.clone()),
                });

                if next_depth < depth {
                    next_frontier.push((step_index, next_id, next_depth));
                }
            }

            if chain.len() >= MAX_TOTAL_STEPS {
                truncated = true;
                break;
            }
        }

        if chain.len() >= MAX_TOTAL_STEPS {
            truncated = true;
            break;
        }

        frontier = next_frontier;
    }

    // A walk stopped by a work ceiling is truncated in exactly the sense the
    // existing flag already means, so it sets that flag too; the degradation
    // adds which ceiling and what it cost, which the flag alone cannot say.
    if stop != TraceStop::Exhausted {
        truncated = true;
        record_trace_stop(&mut degradations, stop, &meter, chain.len());
    }

    Ok(TraceDataFlowResponse {
        focal: focal_record,
        focal_id: focal_entity.id.to_string(),
        focal_name: focal_entity.name.clone(),
        focal_kind: format!("{:?}", focal_entity.kind),
        focal_file: focal_entity.file_origin.as_ref().map(|p| p.0.clone()),
        direction: direction.as_str().to_string(),
        depth,
        total_steps: chain.len(),
        chain,
        truncated,
        degradations,
    })
}

/// What a trace answers when the focal it was given resolves to nothing.
///
/// Public because a caller that has already ruled the focal out from the name
/// index answers with this rather than a second wording: `kin_mcp::negative`
/// keys the `focal_not_resolved` envelope off the text, so two producers
/// drifting apart would silently drop the qualifier from one of them.
pub fn focal_not_found_error(focal: &str) -> anyhow::Error {
    anyhow::anyhow!("no entity found matching '{}'", focal.trim())
}

/// Resolve a trace focal by UUID, exact name, or the entity-ranking fallback.
///
/// Mirrors `resolve_source_entity` in graph.rs so trace_data_flow and
/// `graph source` agree on which entity a name maps to.
fn resolve_trace_focal(graph: &kin_db::InMemoryGraph, query: &str) -> Result<Option<Entity>> {
    let trimmed = query.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        return Ok(graph.get_entity(&EntityId(uuid))?);
    }
    if let Some(entity) = kin_ranking::entity_ranking::select_best_entity(graph, trimmed)? {
        return Ok(Some(entity));
    }
    let matches = kin_core::query_trace_matches(graph, trimmed)?;
    Ok(matches.into_iter().next())
}

/// The open authority a walk reads every step's body through.
///
/// Held for the whole walk so the repeated per-step open is structurally
/// impossible rather than merely avoided at the current call sites.
struct BodyProjection {
    authority: std::sync::Arc<ActiveRepositoryAuthority>,
    workspace: kin_model::WorkspaceState,
}

fn open_body_projection(
    repository_authority: &RequestRepositoryAuthority,
) -> Result<BodyProjection> {
    let authority = repository_authority
        .open()
        .context("open repository authority for trace-data-flow")?;
    let workspace = authority
        .workspace()
        .context("resolve workspace for trace-data-flow")?;
    Ok(BodyProjection {
        authority,
        workspace,
    })
}

/// Try to read an entity's source record; fall back to None for entities
/// without a readable span / blob so the chain still includes their identity.
///
/// Takes the already-open projection rather than the binding. The entity is
/// also passed directly instead of being re-resolved from its own id string,
/// which is what the previous route through `build_graph_source_response` did:
/// that wrapper exists to answer a text query, and the walk already holds the
/// entity the query would resolve back to.
fn source_record_or_none(
    projection: Option<&BodyProjection>,
    entity: &Entity,
) -> Option<GraphSourceRecord> {
    let projection = projection?;
    graph_source_record_from(&projection.authority, &projection.workspace, entity).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::{InMemoryGraph, LocalFileBackend};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256, LanguageId, RelationId, RepositoryId, WorkspaceId};
    use kin_model::relation::{Relation, RelationOrigin};
    use std::sync::Arc;

    fn make_entity(name: &str, file: &str) -> Entity {
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

    fn make_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    /// Synthesize an absent repository authority. The body itself isn't
    /// required for the chain-shape tests; we only assert on identity fields.
    fn empty_binding() -> (tempfile::TempDir, kin_core::LocalRepositoryAuthorityBinding) {
        let temp = tempfile::tempdir().unwrap();
        let kin_root = temp.path().join(".kin");
        std::fs::create_dir_all(kin_root.join("objects")).unwrap();
        let layout = kin_core::KinLayout::new(kin_root);
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_parts(
            RepositoryId::new("trace-data-flow-test").unwrap(),
            WorkspaceId::new(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        );
        (temp, binding)
    }

    #[test]
    fn rejects_empty_focal() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();
        let err = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &TraceDataFlowRequest {
                focal: "   ".to_string(),
                depth: None,
                direction: None,
                limit_per_step: None,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("non-empty focal"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_missing_focal_entity() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();
        let err = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &TraceDataFlowRequest {
                focal: "does_not_exist".to_string(),
                depth: None,
                direction: None,
                limit_per_step: None,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no entity found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn callee_direction_walks_outgoing_calls() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("focal", "src/focal.rs");
        let callee_a = make_entity("callee_a", "src/a.rs");
        let callee_b = make_entity("callee_b", "src/b.rs");
        let leaf = make_entity("leaf", "src/leaf.rs");
        let focal_id = focal.id;
        let callee_a_id = callee_a.id;
        let callee_b_id = callee_b.id;
        let leaf_id = leaf.id;

        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&callee_a).unwrap();
        graph.upsert_entity(&callee_b).unwrap();
        graph.upsert_entity(&leaf).unwrap();

        // focal -> callee_a, focal -> callee_b, callee_a -> leaf
        graph
            .upsert_relation(&make_relation(focal_id, callee_a_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(focal_id, callee_b_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(callee_a_id, leaf_id, RelationKind::Calls))
            .unwrap();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &TraceDataFlowRequest {
                focal: focal_id.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(5),
            },
        )
        .unwrap();

        assert_eq!(response.focal_id, focal_id.to_string());
        assert_eq!(response.direction, "calls");
        assert_eq!(response.depth, 2);
        // 2 direct callees + 1 transitive (leaf) = 3 steps
        assert_eq!(response.total_steps, 3);
        assert_eq!(response.chain.len(), 3);
        assert!(
            response.chain.iter().all(|step| step.role == "callee"),
            "all steps must be callees in calls-only direction"
        );
        let leaf_step = response
            .chain
            .iter()
            .find(|s| s.entity_id == leaf_id.to_string())
            .expect("leaf must be reached at depth 2");
        assert_eq!(leaf_step.depth, 2);
        assert!(leaf_step.parent_step >= 1, "leaf's parent must be a step");
    }

    #[test]
    fn caller_direction_walks_incoming_calls() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("target", "src/target.rs");
        let caller_a = make_entity("caller_a", "src/a.rs");
        let caller_b = make_entity("caller_b", "src/b.rs");
        let focal_id = focal.id;
        let caller_a_id = caller_a.id;
        let caller_b_id = caller_b.id;

        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&caller_a).unwrap();
        graph.upsert_entity(&caller_b).unwrap();

        // caller_a -> focal, caller_b -> focal
        graph
            .upsert_relation(&make_relation(caller_a_id, focal_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(caller_b_id, focal_id, RelationKind::Calls))
            .unwrap();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &TraceDataFlowRequest {
                focal: focal_id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Callers),
                limit_per_step: Some(5),
            },
        )
        .unwrap();

        assert_eq!(response.direction, "callers");
        assert_eq!(response.total_steps, 2);
        assert!(
            response.chain.iter().all(|step| step.role == "caller"),
            "all steps must be callers in callers-only direction"
        );
        let names: Vec<_> = response
            .chain
            .iter()
            .map(|s| s.entity_name.clone())
            .collect();
        assert!(names.contains(&"caller_a".to_string()));
        assert!(names.contains(&"caller_b".to_string()));
    }

    #[test]
    fn limit_per_step_truncates_branching() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("hub", "src/hub.rs");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();
        for i in 0..10 {
            let callee = make_entity(&format!("callee_{i}"), &format!("src/c_{i}.rs"));
            let callee_id = callee.id;
            graph.upsert_entity(&callee).unwrap();
            graph
                .upsert_relation(&make_relation(focal_id, callee_id, RelationKind::Calls))
                .unwrap();
        }

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &TraceDataFlowRequest {
                focal: focal_id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(3),
            },
        )
        .unwrap();

        assert_eq!(response.total_steps, 3, "limit_per_step caps the fan-out");
        assert!(response.truncated, "truncated flag must be set when capped");
    }

    /// A hub whose fan-out is far wider than any per-step limit, so a walk over
    /// it examines many more relations than it can ever turn into steps.
    fn hub_graph(fan_out: usize) -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("hub", "src/hub.rs");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();
        for i in 0..fan_out {
            let callee = make_entity(&format!("callee_{i}"), &format!("src/c_{i}.rs"));
            let callee_id = callee.id;
            graph.upsert_entity(&callee).unwrap();
            graph
                .upsert_relation(&make_relation(focal_id, callee_id, RelationKind::Calls))
                .unwrap();
        }
        (graph, focal_id)
    }

    fn hub_request(focal_id: EntityId) -> TraceDataFlowRequest {
        TraceDataFlowRequest {
            focal: focal_id.to_string(),
            depth: Some(2),
            direction: Some(TraceDirection::Calls),
            limit_per_step: Some(5),
        }
    }

    #[test]
    fn edge_budget_bounds_the_walk_and_says_so() {
        let (graph, focal_id) = hub_graph(200);
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &hub_request(focal_id),
            TraceBudget {
                max_edges_scanned: 10,
                ..TraceBudget::default()
            },
        )
        .unwrap();

        assert!(
            response.truncated,
            "a walk stopped by the edge budget is truncated"
        );
        let stop = response
            .degradations
            .iter()
            .find(|d| d.component == "trace_walk")
            .expect("the edge budget must be disclosed, not silently applied");
        assert_eq!(stop.reason, "edge_budget_exceeded");
        assert!(
            !stop.remediation.is_empty(),
            "a degradation must say what restores full capability"
        );
        // The bound is what stopped it: fewer steps than the per-step limit
        // would otherwise have produced from a 200-wide hub.
        assert!(
            response.total_steps < 10,
            "edge budget must cut the chain short, got {} steps",
            response.total_steps
        );
    }

    #[test]
    fn time_budget_bounds_the_walk_and_says_so() {
        let (graph, focal_id) = hub_graph(200);
        let (_t, binding) = empty_binding();

        // A zero budget is already spent at the first check, so this asserts
        // the bound without making the test wait for a real one to elapse.
        let response = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &hub_request(focal_id),
            TraceBudget {
                time_budget: Duration::ZERO,
                ..TraceBudget::default()
            },
        )
        .unwrap();

        assert!(response.truncated, "a timed-out walk is truncated");
        let stop = response
            .degradations
            .iter()
            .find(|d| d.component == "trace_walk")
            .expect("the time budget must be disclosed");
        assert_eq!(stop.reason, "time_budget_exceeded");
        assert_eq!(
            response.total_steps, 0,
            "a budget spent before the first expansion yields no steps"
        );
        // Still a well-formed answer about the right entity rather than an
        // error: the caller learns what was asked and why it stopped.
        assert_eq!(response.focal_id, focal_id.to_string());
    }

    #[test]
    fn a_walk_inside_every_bound_reports_no_work_degradation() {
        let (graph, focal_id) = hub_graph(3);
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &hub_request(focal_id),
            TraceBudget::default(),
        )
        .unwrap();

        assert_eq!(response.total_steps, 3, "the whole hub fits inside limits");
        assert!(!response.truncated, "nothing was cut off");
        assert!(
            !response
                .degradations
                .iter()
                .any(|d| d.component == "trace_walk"),
            "an unaffected walk must carry no work degradation: {:?}",
            response.degradations
        );
    }

    #[test]
    fn an_unopenable_authority_still_returns_the_chain() {
        // The walk holds one authority open for every step's body. This asserts
        // that hoisting the open did not turn a store whose bodies were already
        // unreadable into a failed call: the chain still arrives, identity
        // only, and the missing bodies are disclosed rather than unexplained.
        let (graph, focal_id) = hub_graph(3);
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &hub_request(focal_id),
            TraceBudget::default(),
        )
        .unwrap();

        assert_eq!(response.total_steps, 3);
        assert!(
            response.chain.iter().all(|step| step.entity.is_none()),
            "no body is readable through an absent authority"
        );
        assert!(
            response
                .degradations
                .iter()
                .any(|d| d.component == "entity_bodies" && d.reason == "authority_unavailable"),
            "absent bodies must be explained: {:?}",
            response.degradations
        );
    }

    #[test]
    fn a_cancelled_walk_stops_and_says_why() {
        let (graph, focal_id) = hub_graph(200);
        let (_t, binding) = empty_binding();

        let cancel = TraceCancel::new();
        cancel.cancel();
        let response = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &hub_request(focal_id),
            TraceBudget::cancellable(cancel),
        )
        .unwrap();

        assert_eq!(
            response.total_steps, 0,
            "a walk cancelled before it began expands nothing"
        );
        assert!(response.truncated);
        let stop = response
            .degradations
            .iter()
            .find(|d| d.component == "trace_walk")
            .expect("cancellation must be disclosed");
        assert_eq!(stop.reason, "cancelled");
        assert_ne!(
            stop.reason, "time_budget_exceeded",
            "an abandoned walk must not be reported as having run out of time"
        );
    }

    /// The property cancellation is actually about: the WORK stops, not just
    /// the response. A cancelled walk must leave traversal undone that the same
    /// walk uncancelled completes, measured against that walk rather than a
    /// constant.
    ///
    /// Cancellation is set before the call rather than raced against a running
    /// one. A walk over a test-sized graph finishes in microseconds, so a
    /// cancel-from-another-thread test would be deciding a race, and a test that
    /// sometimes cancels a walk that already ended proves nothing on the runs
    /// where it loses. The checkpoint being exercised is the same one either
    /// way.
    #[test]
    fn a_cancelled_walk_leaves_traversal_undone() {
        let (graph, focal_id) = hub_graph(400);
        let (_t, binding) = empty_binding();
        let request = TraceDataFlowRequest {
            focal: focal_id.to_string(),
            depth: Some(2),
            direction: Some(TraceDirection::Calls),
            limit_per_step: Some(25),
        };

        let uncancelled = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
            TraceBudget::bounded(),
        )
        .unwrap();
        assert!(
            uncancelled.total_steps > 0,
            "the control must actually walk something"
        );
        assert!(
            !uncancelled
                .degradations
                .iter()
                .any(|d| d.component == "trace_walk"),
            "the control must run to completion inside every bound"
        );

        let cancel = TraceCancel::new();
        cancel.cancel();
        let cancelled = build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
            TraceBudget::cancellable(cancel),
        )
        .unwrap();

        assert!(
            cancelled.total_steps < uncancelled.total_steps,
            "cancelling must leave steps unwalked: {} vs {}",
            cancelled.total_steps,
            uncancelled.total_steps
        );
    }

    #[test]
    fn direction_parse_accepts_aliases() {
        assert_eq!(
            TraceDirection::parse("calls").unwrap(),
            TraceDirection::Calls
        );
        assert_eq!(
            TraceDirection::parse("callees").unwrap(),
            TraceDirection::Calls
        );
        assert_eq!(
            TraceDirection::parse("caller").unwrap(),
            TraceDirection::Callers
        );
        assert_eq!(TraceDirection::parse("BOTH").unwrap(), TraceDirection::Both);
        assert!(TraceDirection::parse("sideways").is_err());
    }
}
