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
use std::collections::{HashMap, HashSet};
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

/// Serialized characters one response may occupy before this walk cuts its own
/// payload, and the floor and ceiling a caller may move it to.
///
/// Read from `kin_mcp` rather than restated here: both arms of this one tool have
/// to promise the same bound, and the arm that serves a generic graph store lives
/// there. A refused result is worse than a truncated one, since a caller gets
/// neither the chain nor a way to ask for less, which is why the number exists at
/// all — see the definition for what it was measured against.
pub use kin_mcp::handlers::common::TRACE_DEFAULT_MAX_RESPONSE_CHARS as DEFAULT_MAX_RESPONSE_CHARS;
use kin_mcp::handlers::common::{trace_response_budget, TRACE_DISCLOSURE_RESERVE_CHARS};

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
    /// Inline each step's source body (default true). `false` returns the SHAPE
    /// of the chain — names, kinds, roles, spans, and edges — at a fraction of
    /// the size, which is what a caller asking "what does this reach" wants.
    #[serde(default)]
    pub include_body: Option<bool>,
    /// Serialized characters this response may occupy (default
    /// [`DEFAULT_MAX_RESPONSE_CHARS`]). The tool cuts bodies, and only then
    /// steps, to stay inside it, and says so in `degradations`.
    #[serde(default)]
    pub max_response_chars: Option<usize>,
}

impl TraceDataFlowRequest {
    fn bodies_included(&self) -> bool {
        self.include_body.unwrap_or(true)
    }

    fn budget_chars(&self) -> usize {
        trace_response_budget(self.max_response_chars)
    }
}

/// One entity as a trace reports it, with the same keys whether the graph owns a
/// location for it or holds it only as a reference target.
///
/// Flattened into its step rather than nested, so the step keys a consumer
/// already parses (`entity_id`, `entity_name`, `entity_kind`, `entity_file`) are
/// unchanged, and the span, signature, and body that used to live in a
/// sometimes-absent nested record sit beside them as explicit nulls.
///
/// The absent-record shape is what this replaces. 16 of 106 steps in one
/// measured response carried `entity_name` and `entity_kind` with no file, no
/// line, and no body, so one array held two different key sets and broke its
/// consumer's parser twice. Nothing is invented to fix that: a symbol the graph
/// owns no file for still reports null for every field it has no answer for, and
/// says which case it is in `external`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntityRecord {
    pub entity_id: String,
    pub entity_name: String,
    pub entity_kind: String,
    /// `source`, `test`, `external`, … — the role the per-step relevance order
    /// reads, so a caller can see why a test callee lost a slot to a source one.
    pub entity_role: String,
    pub entity_file: Option<String>,
    /// True when the graph holds no file for this symbol: an import another
    /// repository defines, a builtin, or an alias split off its definition. Such
    /// a record carries identity and nothing else, and the nulls beside it are
    /// facts about the graph rather than a failed read.
    pub external: bool,
    /// 1-based inclusive presentation lines, from the entity's own span. Present
    /// without a body, because a span is what makes a shape query actionable.
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub signature: Option<String>,
    /// Inlined source, or null when bodies were not requested, could not be
    /// read, or were dropped to fit the response budget. `bodies_included` and
    /// `degradations` on the response say which.
    pub body: Option<String>,
    /// Whether the span that cut `body` was proven to describe those exact bytes.
    /// Null whenever no body was served, since the pairing is what it describes.
    pub span_coherence: Option<String>,
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
    /// This step's identity, location, and (when served) body.
    #[serde(flatten)]
    pub entity: TraceEntityRecord,
    /// True when THIS node's own fan-out was cut by `limit_per_step`, so the
    /// chain below it is partial. A top-level flag cannot say this: the measured
    /// response reported `truncated: true` once for 106 steps, which named no
    /// node and left every step indistinguishable from a complete one.
    pub fanout_truncated: bool,
    /// How many of this node's neighbors the cap dropped. Re-query this node
    /// with a wider `limit_per_step` to recover exactly them.
    pub fanout_dropped: usize,
}

/// A node whose fan-out the per-step cap clipped, listed so a caller can repair
/// the chain without scanning every step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFanoutClip {
    /// Step index of the clipped node; `0` is the focal entity.
    pub step: usize,
    pub entity_id: String,
    pub entity_name: String,
    pub dropped_callees: usize,
    pub dropped_callers: usize,
    /// The cap that did the clipping, so the remedy is a number the caller can
    /// raise rather than a guess.
    pub limit_per_step: usize,
}

/// Response from the trace-data-flow primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDataFlowResponse {
    /// Focal entity's source record. Present when a body was requested and
    /// readable, null otherwise; `focal_*` below always carry its identity, and
    /// `focal_span` its location, in both modes.
    pub focal: Option<GraphSourceRecord>,
    pub focal_id: String,
    pub focal_name: String,
    pub focal_kind: String,
    pub focal_file: Option<String>,
    /// The focal in the same shape every step uses, so a consumer can read the
    /// whole response through one record type. Carries the focal's span and
    /// signature even when no body was served.
    pub focal_entity: TraceEntityRecord,
    /// Direction that was traversed.
    pub direction: String,
    /// Depth that was traversed.
    pub depth: usize,
    /// The per-step fan-out cap this walk applied, echoed because it is what a
    /// caller raises to recover a clipped step.
    pub limit_per_step: usize,
    /// Whether step bodies were inlined. False when the caller asked for the
    /// chain's shape, and also when the response budget dropped them.
    pub bodies_included: bool,
    /// The ordered chain of steps reached from the focal. Already deduplicated
    /// (each entity appears at most once), ordered per node by relevance rather
    /// than by whatever order the relation table returned.
    pub chain: Vec<TraceStep>,
    /// Total number of steps in the chain (excludes the focal).
    pub total_steps: usize,
    /// True when the traversal was cut off because per-step or total caps
    /// were hit. Lets callers detect when they need to widen the limit.
    ///
    /// Bodies dropped to fit the response budget do NOT set this: the chain and
    /// its edges are complete in that case, and `bodies_included` plus a
    /// `response_budget` degradation report the cut. Steps dropped to fit the
    /// budget DO set it, because those are edges the caller did not receive.
    pub truncated: bool,
    /// Every node whose fan-out the per-step cap clipped, with the count it
    /// dropped. Empty — and omitted — for a walk that expanded every neighbor it
    /// reached.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clipped_steps: Vec<TraceFanoutClip>,
    /// Step bodies the response budget dropped, and steps it dropped after that.
    /// Both zero — and omitted — for a response that fit as built.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bodies_omitted: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub steps_omitted: usize,
    /// File-less duplicates of a symbol the graph also holds with a file, merged
    /// into the located record so one symbol carries one identity in one
    /// response. Zero — and omitted — when no name arrived both ways.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub external_identities_merged: usize,
    /// The ceiling this response was measured against, echoed so a caller that
    /// wants more (or less) knows the name and the number to send.
    ///
    /// The response's own size is deliberately not a field here: writing it in
    /// changes it, so the number would be wrong by however many digits it took to
    /// say. A caller measuring the payload it received is measuring the truth.
    pub max_response_chars: usize,
    /// Every work bound that cut this walk short, in the same machine-readable
    /// shape `semantic_locate` reports retrieval degradation in. Empty — and
    /// omitted from the payload — for a walk that finished inside every bound,
    /// so a trace unaffected by these ceilings is unchanged by them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradations: Vec<RetrievalDegradation>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// CLI entry: `kin trace-data-flow --focal <e> [--depth N] [--direction D]
/// [--limit-per-step M] [--no-bodies] [--max-response-chars C]`.
pub async fn run_seeded(
    focal: String,
    depth: Option<usize>,
    direction: Option<String>,
    limit_per_step: Option<usize>,
    include_body: Option<bool>,
    max_response_chars: Option<usize>,
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
        include_body,
        max_response_chars,
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
    let bodies_included = request.bodies_included();

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
    // Read once and shared by both focal shapes, so asking for the focal in two
    // shapes never costs two body reads.
    let focal_record = bodies_included
        .then(|| source_record_or_none(projection.as_ref(), &focal_entity))
        .flatten();
    let focal_entity_record = entity_record(&focal_entity, focal_record.as_ref());

    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    let allowed: HashSet<RelationKind> = reference_kinds.iter().copied().collect();

    let mut chain: Vec<TraceStep> = Vec::new();
    let mut visited: HashSet<EntityId> = HashSet::new();
    visited.insert(focal_entity.id);
    // Which step already stands for a symbol NAME.
    //
    // `visited` cannot answer this: an import alias and the function it aliases
    // are two entities with two ids, so id-dedup admitted `cookiejar_from_dict`
    // twice in one measured response — once located in cookies.py and once as a
    // file-less Module — and the same symbol read as both admitted and external
    // depending on which edge reached it.
    //
    // Seeded with the focal only when the graph owns a file for it. An admitted
    // focal makes a file-less twin redundant; a file-less focal must not be
    // rewritten into an entity the caller did not ask about.
    let mut name_index: HashMap<String, usize> = HashMap::new();
    if focal_entity.file_origin.is_some() {
        name_index.insert(focal_entity.name.clone(), 0);
    }
    let mut external_identities_merged = 0usize;
    let mut clipped_steps: Vec<TraceFanoutClip> = Vec::new();
    let mut truncated = false;
    let mut stop = TraceStop::Exhausted;

    let mut frontier: Vec<FrontierNode> = vec![FrontierNode::rooted(&focal_entity)];
    let mut next_frontier: Vec<FrontierNode>;

    'walk: while !frontier.is_empty() {
        next_frontier = Vec::new();

        for node in frontier.drain(..) {
            if node.depth >= depth {
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
                .get_all_relations_for_entity(&node.id)
                .context("read relations for trace step")?;

            // Expand outgoing edges (parent calls these) when direction allows.
            let want_callees = matches!(direction, TraceDirection::Calls | TraceDirection::Both);
            // Expand incoming edges (these call parent) when direction allows.
            let want_callers = matches!(direction, TraceDirection::Callers | TraceDirection::Both);

            // Every neighbor this node offers is collected BEFORE any is kept.
            //
            // The per-step cap is a choice between candidates, and a loop that
            // admitted as it read had no candidates to choose between: it kept
            // whichever the relation table listed first. On the measured trace
            // that cost the answer — `resolve_redirects` kept `SupportsRead.read`
            // and `HTTPAdapter.close` while dropping `get_redirect_target` and
            // `rebuild_method`, the two functions that decide whether a redirect
            // exists and what method replays it, both of which sit in its own
            // file and were in the graph the whole time.
            let mut candidates: Vec<FanoutCandidate> = Vec::new();
            let mut candidate_index: HashMap<(EntityId, &'static str), usize> = HashMap::new();
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
                    && src_entity == Some(node.id)
                    && dst_entity.is_some()
                    && dst_entity != Some(node.id)
                {
                    (dst_entity.unwrap(), "callee")
                } else if want_callers
                    && dst_entity == Some(node.id)
                    && src_entity.is_some()
                    && src_entity != Some(node.id)
                {
                    (src_entity.unwrap(), "caller")
                } else {
                    continue;
                };

                // Already in the chain by another edge. Not a candidate, and not
                // a drop either: the caller has the node, so counting it as
                // dropped would send them re-querying for something they hold.
                if visited.contains(&next_id) {
                    continue;
                }

                match candidate_index.get(&(next_id, role)) {
                    // The same neighbor reached twice, by two edges of different
                    // kinds or confidences. One step, described by the stronger
                    // edge, rather than one candidate per edge.
                    Some(&existing) => {
                        let candidate: &mut FanoutCandidate = &mut candidates[existing];
                        let stronger = kin_ranking::entity_ranking::trace_relation_rank(rel.kind)
                            > kin_ranking::entity_ranking::trace_relation_rank(
                                candidate.relation_kind,
                            )
                            || (rel.kind == candidate.relation_kind
                                && rel.confidence > candidate.confidence);
                        if stronger {
                            candidate.relation_kind = rel.kind;
                            candidate.confidence = rel.confidence;
                            candidate.resolution = RelationResolution::of(rel);
                        }
                    }
                    None => {
                        let Some(entity) = graph
                            .get_entity(&next_id)
                            .context("load trace step entity")?
                        else {
                            continue;
                        };
                        candidate_index.insert((next_id, role), candidates.len());
                        candidates.push(FanoutCandidate {
                            entity,
                            role,
                            relation_kind: rel.kind,
                            confidence: rel.confidence,
                            resolution: RelationResolution::of(rel),
                        });
                    }
                }
            }

            // Independent budgets per direction so `direction=both` doesn't
            // starve callers when callees are listed first (or vice versa).
            let (mut callees, mut callers): (Vec<FanoutCandidate>, Vec<FanoutCandidate>) =
                candidates.into_iter().partition(|c| c.role == "callee");
            sort_by_relevance(&mut callees, &node);
            sort_by_relevance(&mut callers, &node);
            let dropped_callees = callees.len().saturating_sub(limit_per_step);
            let dropped_callers = callers.len().saturating_sub(limit_per_step);
            callees.truncate(limit_per_step);
            callers.truncate(limit_per_step);

            // Localize the cut on the node it happened at. A single top-level
            // flag names no node, so a caller cannot tell a complete step from a
            // clipped one and cannot repair either.
            if dropped_callees + dropped_callers > 0 {
                truncated = true;
                let dropped = dropped_callees + dropped_callers;
                if node.step > 0 {
                    let step = &mut chain[node.step - 1];
                    step.fanout_truncated = true;
                    step.fanout_dropped = step.fanout_dropped.saturating_add(dropped);
                }
                let (entity_id, entity_name) = if node.step == 0 {
                    (focal_entity.id.to_string(), focal_entity.name.clone())
                } else {
                    let step = &chain[node.step - 1];
                    (
                        step.entity.entity_id.clone(),
                        step.entity.entity_name.clone(),
                    )
                };
                clipped_steps.push(TraceFanoutClip {
                    step: node.step,
                    entity_id,
                    entity_name,
                    dropped_callees,
                    dropped_callers,
                    limit_per_step,
                });
            }

            for candidate in callees.into_iter().chain(callers) {
                if chain.len() >= MAX_TOTAL_STEPS {
                    truncated = true;
                    break;
                }
                let candidate_external =
                    kin_ranking::entity_ranking::trace_entity_is_external(&candidate.entity);
                if let Some(&existing) = name_index.get(candidate.entity.name.as_str()) {
                    let existing_external = existing > 0 && chain[existing - 1].entity.external;
                    if candidate_external {
                        // A record for this name is already in the response.
                        // A second, location-less one adds no information and
                        // gives the symbol a second identity.
                        visited.insert(candidate.entity.id);
                        external_identities_merged += 1;
                        continue;
                    }
                    if existing_external {
                        // The placeholder arrived first, by a different edge.
                        // Fill it in with the record the graph does own rather
                        // than admitting one symbol twice.
                        let source = bodies_included
                            .then(|| source_record_or_none(projection.as_ref(), &candidate.entity))
                            .flatten();
                        let promoted = &mut chain[existing - 1];
                        promoted.entity = entity_record(&candidate.entity, source.as_ref());
                        visited.insert(candidate.entity.id);
                        external_identities_merged += 1;
                        // The placeholder had no edges to walk; the record that
                        // replaced it does, so it re-enters the frontier at the
                        // depth it already sits at.
                        if promoted.depth < depth {
                            next_frontier.push(FrontierNode::at(
                                existing,
                                promoted.depth,
                                &candidate.entity,
                            ));
                        }
                        continue;
                    }
                }
                if !visited.insert(candidate.entity.id) {
                    continue;
                }

                let source = bodies_included
                    .then(|| source_record_or_none(projection.as_ref(), &candidate.entity))
                    .flatten();
                let next_depth = node.depth + 1;
                let step_index = chain.len() + 1;
                name_index
                    .entry(candidate.entity.name.clone())
                    .or_insert(step_index);

                chain.push(TraceStep {
                    step: step_index,
                    role: candidate.role.to_string(),
                    relation_kind: format!("{:?}", candidate.relation_kind),
                    resolution: candidate.resolution.as_str().to_string(),
                    parent_step: node.step,
                    depth: next_depth,
                    entity: entity_record(&candidate.entity, source.as_ref()),
                    fanout_truncated: false,
                    fanout_dropped: 0,
                });

                if next_depth < depth {
                    next_frontier.push(FrontierNode::at(step_index, next_depth, &candidate.entity));
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

    let mut response = TraceDataFlowResponse {
        focal: focal_record,
        focal_id: focal_entity.id.to_string(),
        focal_name: focal_entity.name.clone(),
        focal_kind: format!("{:?}", focal_entity.kind),
        focal_file: focal_entity.file_origin.as_ref().map(|p| p.0.clone()),
        focal_entity: focal_entity_record,
        direction: direction.as_str().to_string(),
        depth,
        limit_per_step,
        bodies_included,
        total_steps: chain.len(),
        chain,
        truncated,
        clipped_steps,
        bodies_omitted: 0,
        steps_omitted: 0,
        external_identities_merged,
        max_response_chars: request.budget_chars(),
        degradations,
    };
    enforce_response_budget(&mut response);
    Ok(response)
}

/// One node of the walk, carrying the file and directory its fan-out is scored
/// against.
///
/// The parent's own location travels with it rather than being re-read per
/// expansion, and relevance is measured against IT rather than against the
/// focal: at depth 3 the focal's directory says nothing about which of a distant
/// node's callees continue the chain.
struct FrontierNode {
    /// Step index of this node; `0` is the focal.
    step: usize,
    id: EntityId,
    depth: usize,
    file: Option<String>,
    dir: Option<String>,
}

impl FrontierNode {
    fn at(step: usize, depth: usize, entity: &Entity) -> Self {
        Self {
            step,
            id: entity.id,
            depth,
            file: entity.file_origin.as_ref().map(|path| path.0.clone()),
            dir: kin_ranking::entity_ranking::entity_directory(entity),
        }
    }

    fn rooted(entity: &Entity) -> Self {
        Self::at(0, 0, entity)
    }
}

/// One neighbor a node offers, before the per-step cap decides whether it is
/// kept.
struct FanoutCandidate {
    entity: Entity,
    role: &'static str,
    relation_kind: RelationKind,
    confidence: f32,
    resolution: RelationResolution,
}

/// Order one side of a node's fan-out by relevance, most relevant first.
///
/// Ties break on name and then id so the same store returns the same chain every
/// run: a reproducible answer is worth more than a marginally better one that
/// moves under the caller.
fn sort_by_relevance(candidates: &mut [FanoutCandidate], node: &FrontierNode) {
    candidates.sort_by(|left, right| {
        let left_score = kin_ranking::entity_ranking::trace_fanout_score(
            &left.entity,
            left.relation_kind,
            node.file.as_deref(),
            node.dir.as_deref(),
            left.confidence,
        );
        let right_score = kin_ranking::entity_ranking::trace_fanout_score(
            &right.entity,
            right.relation_kind,
            node.file.as_deref(),
            node.dir.as_deref(),
            right.confidence,
        );
        right_score
            .cmp(&left_score)
            .then_with(|| left.entity.name.cmp(&right.entity.name))
            .then_with(|| left.entity.id.0.cmp(&right.entity.id.0))
    });
}

/// The one record shape every entity in a trace is reported in.
///
/// `source` is the body read, already attempted by the caller (or skipped
/// entirely for a shape query). When it is absent the span still comes from the
/// entity's own graph span, because a caller asking for the shape of a chain
/// still needs to know where each step lives.
fn entity_record(entity: &Entity, source: Option<&GraphSourceRecord>) -> TraceEntityRecord {
    let (start_line, end_line) = match (source, entity.span.as_ref()) {
        (Some(record), _) => (Some(record.start_line), Some(record.end_line)),
        (None, Some(span)) => {
            let (start, end) = kin_mcp::handlers::common::presentation_span_lines(span);
            (Some(start), Some(end))
        }
        (None, None) => (None, None),
    };
    TraceEntityRecord {
        entity_id: entity.id.to_string(),
        entity_name: entity.name.clone(),
        entity_kind: format!("{:?}", entity.kind),
        entity_role: format!("{:?}", entity.role).to_lowercase(),
        entity_file: entity.file_origin.as_ref().map(|path| path.0.clone()),
        external: kin_ranking::entity_ranking::trace_entity_is_external(entity),
        start_line,
        end_line,
        signature: (!entity.signature.is_empty()).then(|| entity.signature.clone()),
        body: source.map(|record| record.body.clone()),
        span_coherence: source.map(|record| record.span_coherence.clone()),
    }
}

/// Serialized size of a response, measured the way it will be sent.
///
/// Both surfaces that return this — the CLI's `println!` and the daemon's MCP
/// text result — serialize it pretty-printed, so the budget is charged for the
/// indentation the caller receives rather than for a compact form nobody sends.
fn measure_response(response: &TraceDataFlowResponse) -> usize {
    serde_json::to_string_pretty(response).map_or(usize::MAX, |json| json.len())
}

/// Bound the response the tool is about to return, cutting BODIES before EDGES.
///
/// The defect this closes: a walk inside every work bound produced 228,413
/// characters and the client refused the whole result, so the caller received
/// neither the chain nor a usable error and recovered by parsing a spill file
/// with a script. A tool that can measure its own output has no excuse for
/// that.
///
/// The cut order is the priority order. A chain with every edge and no source
/// still answers "what does this reach"; a chain missing edges answers a
/// different, smaller question, and a caller cannot tell which question was
/// answered unless the cut says so. Bodies go first, then the focal's body, then
/// steps from the tail — a suffix, because the chain is discovery-ordered, so
/// removing the end never orphans a surviving step's parent.
fn enforce_response_budget(response: &mut TraceDataFlowResponse) {
    let ceiling = response.max_response_chars;
    if measure_response(response) <= ceiling {
        return;
    }
    let target = ceiling.saturating_sub(TRACE_DISCLOSURE_RESERVE_CHARS);

    let mut bodies_omitted = 0usize;
    for step in &mut response.chain {
        if step.entity.body.take().is_some() {
            step.entity.span_coherence = None;
            bodies_omitted += 1;
        }
    }
    if bodies_omitted > 0 {
        response.bodies_included = false;
        response.bodies_omitted = bodies_omitted;
    }

    let mut focal_body_omitted = false;
    if measure_response(response) > target && response.focal.take().is_some() {
        response.focal_entity.body = None;
        response.focal_entity.span_coherence = None;
        response.bodies_included = false;
        focal_body_omitted = true;
    }

    let mut steps_omitted = 0usize;
    if measure_response(response) > target {
        // Bisected rather than popped one step at a time: the same answer, in a
        // handful of serializations instead of one per dropped step.
        let full = std::mem::take(&mut response.chain);
        let mut kept = 0usize;
        let mut low = 0usize;
        let mut high = full.len();
        while low <= high {
            let mid = (low + high) / 2;
            response.chain = full[..mid].to_vec();
            response.total_steps = mid;
            if measure_response(response) <= target {
                kept = mid;
                low = mid + 1;
            } else if mid == 0 {
                break;
            } else {
                high = mid - 1;
            }
        }
        steps_omitted = full.len() - kept;
        response.chain = full[..kept].to_vec();
        response.total_steps = kept;
        response.steps_omitted = steps_omitted;
        if steps_omitted > 0 {
            // Dropped steps are edges the caller did not receive, which is what
            // this flag has always meant. Dropped bodies are not.
            response.truncated = true;
            // A clip recorded against a step that is no longer here would send a
            // caller re-querying a node the response does not name.
            let kept_steps = response.chain.len();
            response
                .clipped_steps
                .retain(|clip| clip.step <= kept_steps);
        }
    }

    if bodies_omitted == 0 && !focal_body_omitted && steps_omitted == 0 {
        return;
    }
    let reason = if steps_omitted > 0 {
        "steps_omitted"
    } else {
        "bodies_omitted"
    };
    let cut = match (
        bodies_omitted + usize::from(focal_body_omitted),
        steps_omitted,
    ) {
        (bodies, 0) => format!("{bodies} inlined bodies were dropped"),
        (0, steps) => format!("{steps} steps were dropped from the end of the chain"),
        (bodies, steps) => format!(
            "{bodies} inlined bodies were dropped, and {steps} steps after that were dropped from \
             the end of the chain"
        ),
    };
    record_degradation(
        &mut response.degradations,
        RetrievalDegradation {
            component: "response_budget".to_string(),
            reason: reason.to_string(),
            detail: format!(
                "the response exceeded its {ceiling}-character budget, so {cut}; bodies are cut \
                 before edges, so the chain's shape survives a cut that its source cannot"
            ),
            remediation: "ask for the shape directly with include_body: false, or narrow the walk \
                          with a smaller depth or limit_per_step; raise max_response_chars only if \
                          the caller's own result limit accepts a larger payload"
                .to_string(),
        },
    );
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
            // A span, because a shape query's whole value is names plus
            // locations: a fixture with none cannot tell a compact response that
            // kept its spans from one that dropped them.
            span: Some(kin_model::entity::SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 32,
                start_line: 9,
                start_col: 0,
                end_line: 19,
                end_col: 1,
            }),
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

    /// The shape a symbol the graph owns no file for actually has: identity, no
    /// location, no span, and (in the measured repository) `Module` kind.
    fn make_external_entity(name: &str) -> Entity {
        let mut entity = make_entity(name, "unused");
        entity.kind = EntityKind::Module;
        entity.file_origin = None;
        entity.span = None;
        entity
    }

    fn trace_request(
        focal: &EntityId,
        depth: usize,
        direction: TraceDirection,
        limit_per_step: usize,
    ) -> TraceDataFlowRequest {
        TraceDataFlowRequest {
            focal: focal.to_string(),
            depth: Some(depth),
            direction: Some(direction),
            limit_per_step: Some(limit_per_step),
            include_body: None,
            max_response_chars: None,
        }
    }

    fn step_names(response: &TraceDataFlowResponse) -> Vec<String> {
        response
            .chain
            .iter()
            .map(|step| step.entity.entity_name.clone())
            .collect()
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
                include_body: None,
                max_response_chars: None,
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
                include_body: None,
                max_response_chars: None,
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
                include_body: None,
                max_response_chars: None,
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
            .find(|s| s.entity.entity_id == leaf_id.to_string())
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
                include_body: None,
                max_response_chars: None,
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
            .map(|s| s.entity.entity_name.clone())
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
                include_body: None,
                max_response_chars: None,
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
            include_body: None,
            max_response_chars: None,
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
            response.chain.iter().all(|step| step.entity.body.is_none()),
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
            include_body: None,
            max_response_chars: None,
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

    /// The measured inversion, as a fixture: `resolve_redirects` fanning out
    /// wider than its cap, where which callees matter is knowable from the graph
    /// alone.
    ///
    /// Two of its callees sit in its own file and decide the redirect (the two
    /// the shipped cap dropped); the others are a distant adapter method, a test
    /// helper, and a file-less import placeholder (three the shipped cap kept).
    fn redirect_graph() -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("resolve_redirects", "src/requests/sessions.py");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();

        let mut callees = vec![
            make_entity("get_redirect_target", "src/requests/sessions.py"),
            make_entity("rebuild_method", "src/requests/sessions.py"),
            make_entity("HTTPAdapter.close", "src/requests/adapters.py"),
        ];
        let mut harness = make_entity("RedirectSession.send", "tests/test_requests.py");
        harness.role = EntityRole::Test;
        callees.push(harness);
        callees.push(make_external_entity("urljoin"));

        for callee in &callees {
            graph.upsert_entity(callee).unwrap();
            graph
                .upsert_relation(&make_relation(focal_id, callee.id, RelationKind::Calls))
                .unwrap();
        }
        (graph, focal_id)
    }

    #[test]
    fn the_per_step_cap_keeps_the_callees_that_continue_the_chain() {
        let (graph, focal_id) = redirect_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 2),
        )
        .unwrap();

        let mut kept = step_names(&response);
        kept.sort();
        assert_eq!(
            kept,
            vec![
                "get_redirect_target".to_string(),
                "rebuild_method".to_string()
            ],
            "a two-wide cap must keep the two located source callees in the expanded node's own \
             file, not a distant method, a test double, or a file-less placeholder"
        );
    }

    #[test]
    fn a_clipped_fan_out_says_which_node_was_clipped_and_how_much_it_dropped() {
        let (graph, focal_id) = redirect_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 2),
        )
        .unwrap();

        assert!(response.truncated);
        assert_eq!(
            response.clipped_steps.len(),
            1,
            "exactly one node fanned out here: {:?}",
            response.clipped_steps
        );
        let clip = &response.clipped_steps[0];
        assert_eq!(clip.step, 0, "the focal is step 0");
        assert_eq!(clip.entity_name, "resolve_redirects");
        assert_eq!(
            clip.dropped_callees, 3,
            "five candidates minus a two-wide cap is three dropped"
        );
        assert_eq!(clip.dropped_callers, 0);
        assert_eq!(
            clip.limit_per_step, 2,
            "the clip names the cap a caller would raise"
        );
    }

    /// The repair path the top-level flag could not support: a clipped node that
    /// is not the focal has to carry its own truncation, or a caller cannot tell
    /// which of 106 steps to re-query.
    #[test]
    fn a_clipped_step_carries_its_own_truncation_flag_and_count() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("Session.send", "src/requests/sessions.py");
        let mid = make_entity("resolve_redirects", "src/requests/sessions.py");
        let focal_id = focal.id;
        let mid_id = mid.id;
        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&mid).unwrap();
        graph
            .upsert_relation(&make_relation(focal_id, mid_id, RelationKind::Calls))
            .unwrap();
        for index in 0..3 {
            let leaf = make_entity(&format!("rebuild_{index}"), "src/requests/sessions.py");
            graph.upsert_entity(&leaf).unwrap();
            graph
                .upsert_relation(&make_relation(mid_id, leaf.id, RelationKind::Calls))
                .unwrap();
        }

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 2, TraceDirection::Calls, 1),
        )
        .unwrap();

        let mid_step = response
            .chain
            .iter()
            .find(|step| step.entity.entity_name == "resolve_redirects")
            .expect("the mid node must be in the chain");
        assert!(
            mid_step.fanout_truncated,
            "the node whose fan-out was cut must say so on itself"
        );
        assert_eq!(
            mid_step.fanout_dropped, 2,
            "three callees under a one-wide cap drops two"
        );
        let unclipped = response
            .chain
            .iter()
            .find(|step| step.entity.entity_name.starts_with("rebuild_"))
            .expect("the kept leaf must be in the chain");
        assert!(
            !unclipped.fanout_truncated && unclipped.fanout_dropped == 0,
            "a step whose fan-out was complete must be distinguishable from a clipped one"
        );
        assert!(
            response
                .clipped_steps
                .iter()
                .any(|clip| clip.step == mid_step.step && clip.dropped_callees == 2),
            "the clip list must name the step: {:?}",
            response.clipped_steps
        );
    }

    /// A walk that expands every neighbor it reaches must be byte-identical to
    /// the one before per-step clip reporting existed.
    #[test]
    fn an_unclipped_walk_reports_no_clip_at_all() {
        let (graph, focal_id) = hub_graph(3);
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 2, TraceDirection::Calls, 5),
        )
        .unwrap();

        assert!(!response.truncated);
        assert!(response.clipped_steps.is_empty());
        assert!(response.chain.iter().all(|step| !step.fanout_truncated));
        let json = serde_json::to_value(&response).unwrap();
        assert!(
            json.get("clipped_steps").is_none(),
            "an unaffected walk must not carry the field at all"
        );
    }

    #[test]
    fn compact_mode_keeps_every_edge_and_span_while_inlining_no_body() {
        let (graph, focal_id) = redirect_graph();
        let (_t, binding) = empty_binding();

        let mut request = trace_request(&focal_id, 1, TraceDirection::Calls, 25);
        let with_bodies = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
        )
        .unwrap();
        request.include_body = Some(false);
        let compact = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
        )
        .unwrap();

        assert_eq!(
            compact.total_steps, with_bodies.total_steps,
            "asking for the shape must not change which edges are walked"
        );
        assert_eq!(step_names(&compact), step_names(&with_bodies));
        assert!(!compact.bodies_included);
        assert!(compact.focal.is_none());
        assert!(compact.chain.iter().all(|step| step.entity.body.is_none()));
        // The point of the mode: shape, not silence. Every located step still
        // reports where it is.
        assert!(compact
            .chain
            .iter()
            .filter(|step| !step.entity.external)
            .all(|step| step.entity.entity_file.is_some()
                && step.entity.start_line == Some(10)
                && step.entity.end_line == Some(20)
                && step.entity.signature.is_some()));
        assert_eq!(
            compact.focal_entity.start_line,
            Some(10),
            "the focal keeps its span in a shape query too"
        );
    }

    /// The regression a character count is the only guard against: a change that
    /// re-inlines bodies on a shape query is invisible to every assertion about
    /// chain contents.
    #[test]
    fn a_compact_trace_stays_far_under_its_budget() {
        let (graph, focal_id) = hub_graph(120);
        let (_t, binding) = empty_binding();

        let mut request = trace_request(&focal_id, 1, TraceDirection::Calls, 25);
        request.include_body = Some(false);
        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
        )
        .unwrap();

        assert_eq!(response.total_steps, 25, "the fixture must produce a chain");
        let json = serde_json::to_string_pretty(&response).unwrap();
        assert!(
            json.len() <= response.max_response_chars,
            "a response must fit the budget it reports: {} chars against {}",
            json.len(),
            response.max_response_chars
        );
        assert!(
            !json.contains("\"body\": \""),
            "a shape query must carry no inlined body"
        );
        assert!(
            json.len() < 20_000,
            "25 steps of shape are small; {} chars means bodies or per-step bloat crept back in",
            json.len()
        );
    }

    /// A response is refused whole or not at all, so the tool bounds its own
    /// payload rather than discovering the ceiling at the client.
    fn fat_response(steps: usize, body_chars: usize) -> TraceDataFlowResponse {
        let entity = make_entity("focal", "src/focal.rs");
        let mut chain = Vec::new();
        for index in 1..=steps {
            let step_entity = make_entity(&format!("step_{index}"), "src/step.rs");
            let mut record = entity_record(&step_entity, None);
            record.body = Some("x".repeat(body_chars));
            record.span_coherence = Some("verified".to_string());
            chain.push(TraceStep {
                step: index,
                role: "callee".to_string(),
                relation_kind: "Calls".to_string(),
                parent_step: index.saturating_sub(1),
                depth: 1,
                entity: record,
                fanout_truncated: false,
                fanout_dropped: 0,
            });
        }
        TraceDataFlowResponse {
            focal: None,
            focal_id: entity.id.to_string(),
            focal_name: entity.name.clone(),
            focal_kind: "Function".to_string(),
            focal_file: Some("src/focal.rs".to_string()),
            focal_entity: entity_record(&entity, None),
            direction: "calls".to_string(),
            depth: 1,
            limit_per_step: 25,
            bodies_included: true,
            total_steps: chain.len(),
            chain,
            truncated: false,
            clipped_steps: Vec::new(),
            bodies_omitted: 0,
            steps_omitted: 0,
            external_identities_merged: 0,
            max_response_chars: DEFAULT_MAX_RESPONSE_CHARS,
            degradations: Vec::new(),
        }
    }

    #[test]
    fn the_response_budget_cuts_bodies_before_it_cuts_edges() {
        let mut response = fat_response(40, 4_000);
        assert!(
            serde_json::to_string_pretty(&response).unwrap().len() > response.max_response_chars,
            "the fixture must start over budget or this proves nothing"
        );

        enforce_response_budget(&mut response);

        assert_eq!(
            response.total_steps, 40,
            "every edge survives a cut that bodies can absorb"
        );
        assert_eq!(response.bodies_omitted, 40);
        assert_eq!(response.steps_omitted, 0);
        assert!(!response.bodies_included);
        assert!(
            !response.truncated,
            "dropping bodies leaves the chain complete, so the chain-truncation flag must stay off"
        );
        assert!(response.chain.iter().all(|step| step.entity.body.is_none()
            && step.entity.span_coherence.is_none()
            && step.entity.entity_file.is_some()));
        let cut = response
            .degradations
            .iter()
            .find(|d| d.component == "response_budget")
            .expect("a cut must be disclosed, not silently applied");
        assert_eq!(cut.reason, "bodies_omitted");
        assert!(cut.detail.contains("40"), "the cut states its own numbers");
        assert!(!cut.remediation.is_empty());
        assert!(
            serde_json::to_string_pretty(&response).unwrap().len() <= response.max_response_chars,
            "the payload must end up inside the budget it reports"
        );
    }

    #[test]
    fn the_response_budget_drops_steps_only_after_every_body_and_says_so() {
        let mut response = fat_response(200, 2_000);
        response.max_response_chars = 8_000;
        response.clipped_steps.push(TraceFanoutClip {
            step: 199,
            entity_id: "late".to_string(),
            entity_name: "step_199".to_string(),
            dropped_callees: 4,
            dropped_callers: 0,
            limit_per_step: 25,
        });

        enforce_response_budget(&mut response);

        assert_eq!(response.bodies_omitted, 200, "bodies go first, all of them");
        assert!(
            response.steps_omitted > 0,
            "a budget no body-free chain can meet must drop steps too"
        );
        assert_eq!(response.total_steps, response.chain.len());
        assert_eq!(response.total_steps + response.steps_omitted, 200);
        assert!(
            response.truncated,
            "dropped steps are edges the caller did not receive"
        );
        // The chain that survives is a prefix, so no surviving step points at a
        // parent the response no longer contains.
        let kept = response.chain.len();
        assert!(response
            .chain
            .iter()
            .all(|step| step.step <= kept && step.parent_step <= kept));
        assert!(
            response.clipped_steps.iter().all(|clip| clip.step <= kept),
            "a clip must not name a step the response dropped"
        );
        let cut = response
            .degradations
            .iter()
            .find(|d| d.component == "response_budget")
            .expect("the cut must be disclosed");
        assert_eq!(cut.reason, "steps_omitted");
        assert!(
            serde_json::to_string_pretty(&response).unwrap().len() <= response.max_response_chars,
            "the payload must end up inside the budget it reports"
        );
    }

    #[test]
    fn a_response_that_fits_is_left_exactly_as_built() {
        let mut response = fat_response(2, 100);
        let before = serde_json::to_string_pretty(&response).unwrap();

        enforce_response_budget(&mut response);

        assert_eq!(
            serde_json::to_string_pretty(&response).unwrap(),
            before,
            "a response inside its budget must be byte-identical after enforcement"
        );
        assert!(response.bodies_included);
        assert_eq!(response.bodies_omitted, 0);
        assert_eq!(response.steps_omitted, 0);
    }

    /// One symbol, two entities: the located definition and a file-less alias of
    /// the same name. The measured response admitted both, so
    /// `cookiejar_from_dict` was simultaneously a real entity in cookies.py and
    /// an external Module, depending on which edge reached it.
    #[test]
    fn a_name_the_graph_holds_both_ways_yields_one_identity() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("Session.prepare_request", "src/requests/sessions.py");
        let admitted = make_entity("cookiejar_from_dict", "src/requests/cookies.py");
        let alias = make_external_entity("cookiejar_from_dict");
        let focal_id = focal.id;
        let admitted_id = admitted.id;
        let alias_id = alias.id;
        assert_ne!(admitted_id, alias_id, "the graph holds two entities here");

        for entity in [&focal, &admitted, &alias] {
            graph.upsert_entity(entity).unwrap();
        }
        graph
            .upsert_relation(&make_relation(focal_id, admitted_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(focal_id, alias_id, RelationKind::Calls))
            .unwrap();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 25),
        )
        .unwrap();

        let carrying: Vec<&TraceStep> = response
            .chain
            .iter()
            .filter(|step| step.entity.entity_name == "cookiejar_from_dict")
            .collect();
        assert_eq!(
            carrying.len(),
            1,
            "one symbol, one step: {:?}",
            step_names(&response)
        );
        assert_eq!(
            carrying[0].entity.entity_id,
            admitted_id.to_string(),
            "the located record wins over the placeholder"
        );
        assert!(!carrying[0].entity.external);
        assert_eq!(response.external_identities_merged, 1);
    }

    /// The same rule when the placeholder is reached FIRST, by a different edge:
    /// the located record fills it in rather than adding a second identity.
    #[test]
    fn a_placeholder_reached_first_is_filled_in_by_the_located_record() {
        let graph = InMemoryGraph::new();
        let (_t, binding) = empty_binding();

        let focal = make_entity("Session.request", "src/requests/sessions.py");
        let mid = make_entity("Session.prepare_request", "src/requests/sessions.py");
        let alias = make_external_entity("cookiejar_from_dict");
        let admitted = make_entity("cookiejar_from_dict", "src/requests/cookies.py");
        let focal_id = focal.id;
        let mid_id = mid.id;
        let alias_id = alias.id;
        let admitted_id = admitted.id;

        for entity in [&focal, &mid, &alias, &admitted] {
            graph.upsert_entity(entity).unwrap();
        }
        // depth 1: the placeholder and the mid node. depth 2: the located record,
        // reached through the mid node.
        graph
            .upsert_relation(&make_relation(focal_id, alias_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(focal_id, mid_id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation(mid_id, admitted_id, RelationKind::Calls))
            .unwrap();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 3, TraceDirection::Calls, 25),
        )
        .unwrap();

        let carrying: Vec<&TraceStep> = response
            .chain
            .iter()
            .filter(|step| step.entity.entity_name == "cookiejar_from_dict")
            .collect();
        assert_eq!(
            carrying.len(),
            1,
            "the placeholder must be filled in, not doubled: {:?}",
            step_names(&response)
        );
        assert_eq!(carrying[0].entity.entity_id, admitted_id.to_string());
        assert!(!carrying[0].entity.external);
        assert_eq!(
            carrying[0].entity.entity_file.as_deref(),
            Some("src/requests/cookies.py")
        );
        assert_eq!(response.external_identities_merged, 1);
        assert_ne!(
            alias_id.to_string(),
            carrying[0].entity.entity_id,
            "the placeholder's id must not be what the response reports"
        );
    }

    /// The parser break, asserted structurally: one array, one key set, whatever
    /// the graph knows about each symbol.
    #[test]
    fn every_step_carries_the_same_keys_admitted_or_external() {
        let (graph, focal_id) = redirect_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 25),
        )
        .unwrap();
        assert!(
            response.chain.iter().any(|step| step.entity.external),
            "the fixture must include a file-less symbol or this proves nothing"
        );
        assert!(
            response.chain.iter().any(|step| !step.entity.external),
            "and a located one"
        );

        let json = serde_json::to_value(&response).unwrap();
        let steps = json["chain"].as_array().unwrap();
        let expected: Vec<String> = steps[0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for key in [
            "step",
            "role",
            "relation_kind",
            "parent_step",
            "depth",
            "entity_id",
            "entity_name",
            "entity_kind",
            "entity_role",
            "entity_file",
            "external",
            "start_line",
            "end_line",
            "signature",
            "body",
            "span_coherence",
            "fanout_truncated",
            "fanout_dropped",
        ] {
            assert!(
                expected.contains(&key.to_string()),
                "a step must carry '{key}': {expected:?}"
            );
        }
        for step in steps {
            let keys: Vec<String> = step.as_object().unwrap().keys().cloned().collect();
            assert_eq!(
                keys, expected,
                "every step must carry the same keys; this one differs: {step}"
            );
        }
        // Not inventing data is the other half: the placeholder's location fields
        // are present and null rather than absent.
        let external = steps
            .iter()
            .find(|step| step["external"] == serde_json::Value::Bool(true))
            .unwrap();
        assert!(external["entity_file"].is_null());
        assert!(external["start_line"].is_null());
        assert!(external["end_line"].is_null());
        assert!(external["entity_name"].is_string());
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
