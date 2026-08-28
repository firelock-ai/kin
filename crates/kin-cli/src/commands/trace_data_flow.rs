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
use kin_ranking::entity_ranking::{
    trace_terminal_named, trace_walk_terminal, TraceExpansion, TraceTerminal,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

use kin_mcp::budget::Elision;
/// Serialized characters one response may occupy before this walk cuts its own
/// payload, and the floor and ceiling a caller may move it to.
///
/// Read from `kin_mcp` rather than restated here: both arms of this one tool have
/// to promise the same bound, and the arm that serves a generic graph store lives
/// there. A refused result is worse than a truncated one, since a caller gets
/// neither the chain nor a way to ask for less, which is why the number exists at
/// all — see the definition for what it was measured against.
pub use kin_mcp::handlers::common::TRACE_DEFAULT_MAX_RESPONSE_CHARS as DEFAULT_MAX_RESPONSE_CHARS;
use kin_mcp::handlers::common::{
    relation_reference_lines, trace_response_budget, ReferenceLinesAbsent,
    TRACE_DISCLOSURE_RESERVE_CHARS,
};

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
    /// A symbol the caller is trying to reach, and the only way the question
    /// itself gets a vote on which hops survive.
    ///
    /// Without one, the per-step cap orders neighbors by proximity terms no
    /// question is an input to, so on a wide node it discards by a rule
    /// unrelated to what was asked. With one, every candidate from which the
    /// target is still reachable inside the requested depth sorts ahead of
    /// every candidate that is not, before the cap cuts anything.
    ///
    /// It changes only which neighbors survive the cap. No edge is invented,
    /// no edge is hidden, and a walk whose target resolves to nothing is a walk
    /// with a disclosure on it rather than an error, because the chain is still
    /// the chain.
    #[serde(default)]
    pub target: Option<String>,
    /// Walk THROUGH a type-annotation edge to a type this repository defines
    /// (default false). A dataclass field typed with a repo class is a real
    /// flow into that class, so the hop is available; it is off by default
    /// because a shared type name otherwise joins every entity that annotates
    /// with it to every other one. An annotation target the repository does not
    /// define stays a leaf either way.
    #[serde(default)]
    pub include_type_edges: Option<bool>,
}

impl TraceDataFlowRequest {
    fn bodies_included(&self) -> bool {
        self.include_body.unwrap_or(true)
    }

    fn type_edges_included(&self) -> bool {
        self.include_type_edges.unwrap_or(false)
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
    /// Where the in-repo graph ends, for a step sitting on the boundary.
    /// Non-null on exactly the records `external` is true for; a step the
    /// repository owns crosses nothing and carries an explicit null.
    ///
    /// Always serialized, never skipped: this array's keys are uniform by
    /// contract, and a sometimes-absent key is the shape that broke a
    /// consumer's parser twice. `every_step_carries_the_same_keys_admitted_or_external`
    /// caught this field trying to become the third time.
    #[serde(default)]
    pub crossing: Option<kin_index::TraceCrossing>,
}

/// One step in the data-flow chain.
fn legacy_trace_reference_lines_absent_reason() -> Option<String> {
    Some("unreported_by_daemon".to_string())
}

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
    /// 1-based source lines of the edge that introduced this step, accumulated
    /// across every contributing relation and deduplicated.
    ///
    /// These are call/reference sites, not this entity's definition lines. For
    /// a `callee` step they live in its parent's file; for a `caller` step they
    /// live in this step's own `entity_file`. The role and `parent_step` make
    /// that file explicit without repeating a path on every row.
    #[serde(default)]
    pub reference_lines: Vec<u32>,
    /// Why `reference_lines` is empty, and null when at least one line is
    /// present. Uses the same vocabulary as `find_references` so an absent
    /// parser span and an unusable cross-file span never collapse together.
    #[serde(default = "legacy_trace_reference_lines_absent_reason")]
    pub reference_lines_absent_reason: Option<String>,
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
    /// Why the walk stopped here instead of expanding this node, or null for an
    /// ordinary step. `external_reference` means the repository defines nothing
    /// for this symbol; `type_annotation` means the edge that reached it states
    /// a type and `include_type_edges` was not set.
    ///
    /// Distinct from `fanout_truncated`, which says a cap chose between
    /// neighbors this node has. A terminal has no next hop to give, so raising
    /// `limit_per_step` recovers nothing here.
    ///
    /// Serialized as an explicit null rather than omitted: every step in this
    /// array carries the same keys, and a sometimes-absent one is the shape
    /// that broke a consumer's parser twice.
    #[serde(default)]
    pub terminal: Option<String>,
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
    /// How many of the dropped neighbors lived outside this node's own file.
    ///
    /// The class of hop, not just the count. A node that dropped eleven
    /// same-file callees lost breadth; a node that dropped the only hops that
    /// leave its module lost the kind of edge a data-flow question is about,
    /// and a single `dropped` number cannot tell those apart.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped_crossing_file: usize,
    /// Whether the walk went on beneath this node, so the chain reads as a
    /// path that continues while a sibling branch was discarded.
    ///
    /// This is the shape that produced a wrong answer: a clip at a leaf costs
    /// breadth the caller can see is missing, while a clip on the spine hands
    /// back a chain that looks like a complete route and is one of several.
    /// A reader deciding whether "X never reaches Y" is safe reads this.
    #[serde(default)]
    pub continued_below: bool,
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
    /// Whether a type-annotation edge to a repo-defined type was walked
    /// through. Echoed because it is the parameter a caller reading a
    /// `type_annotation` terminal has to change, and a caller cannot otherwise
    /// tell a walk that had no such edges from one that refused them.
    ///
    /// Defaulted on read, because the CLI parses this payload from whatever
    /// daemon is already running. A daemon started before this parameter
    /// existed answers without the key, and a required field would turn that
    /// ordinary upgrade window into a failed call rather than a chain.
    #[serde(default)]
    pub include_type_edges: bool,
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
    /// The target this walk ranked toward, echoed so a caller can see the
    /// question was received. Null when none was named, and null when the one
    /// that was named resolved to nothing, which the degradations say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    /// Every node whose fan-out the per-step cap clipped, with the count it
    /// dropped. Empty — and omitted — for a walk that expanded every neighbor it
    /// reached.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clipped_steps: Vec<TraceFanoutClip>,
    /// How many clipped nodes the walk went on beneath, so a reader has the
    /// one number that decides whether an absence in this chain means anything.
    ///
    /// Zero — and omitted — when no clip sits on the surviving chain's spine,
    /// which is the only case where a hop this chain does not contain is a hop
    /// the walk actually looked for and did not find.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub spine_clipped_steps: usize,
    /// How many neighbors the spine clips dropped that lived outside their
    /// node's own file: the count of module-crossing hops this chain was never
    /// offered. Zero — and omitted — when clipping cost only same-file breadth.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub spine_dropped_crossing_file: usize,
    /// Step bodies the response budget dropped, and steps it dropped after that.
    /// Both zero — and omitted — for a response that fit as built.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bodies_omitted: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub steps_omitted: usize,
    /// How many of `steps_omitted` went as whole branches the budget narrowed
    /// away, rather than off the end of the chain. Zero — and omitted — when
    /// the suffix fallback did the cutting or when nothing was cut at all.
    ///
    /// Worth its own count because the two losses are different answers. A
    /// narrowed chain still reaches as deep as the walk did and lists fewer
    /// neighbours per node; an amputated one is shallower than the walk was,
    /// and a reader who cannot tell them apart cannot tell whether the far end
    /// of the answer is missing.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fanout_narrowed: usize,
    /// Every list the response budget cut, keyed by the field it cut, with what
    /// survived, what was withheld, and why.
    ///
    /// `steps_omitted` said the same thing about `chain` and was not enough. A
    /// reader looks at the array first, and a budget that cut a chain to nothing
    /// handed back `"chain": []`, which is the shape that means the walk reached
    /// nothing. So the chain now keeps at least one step and this map says what
    /// it lost, and an empty `chain` means one thing only.
    ///
    /// Empty — and omitted — for a response that fit as built, so a walk the
    /// budget never touched is unchanged by this.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub elisions: BTreeMap<String, Elision>,
    /// Steps this response reached through a `name_only` edge, out of
    /// `total_steps`.
    ///
    /// A chain that lists three callees looks equally complete whether all three
    /// were proven or all three were guessed from a bare name, and a reader who
    /// does not scan every step's `resolution` cannot tell. The count says it
    /// once, at the top, so a chain narrowed by a resolution gate is not mistaken
    /// for a complete proven one. Zero — and omitted — when every hop was
    /// proven, which is the only case where the chain is a claim about what runs
    /// rather than about what might.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unproven_steps: usize,
    /// File-less duplicates of a symbol the graph also holds with a file, merged
    /// into the located record so one symbol carries one identity in one
    /// response. Zero — and omitted — when no name arrived both ways.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub external_identities_merged: usize,
    /// Steps this walk reported as leaves because the repository defines
    /// nothing for them, and steps it reported as leaves because a type edge
    /// reached them and `include_type_edges` was not set.
    ///
    /// Counted rather than left to a scan of `chain`, and kept apart rather
    /// than summed, because only the second is recoverable: raising
    /// `include_type_edges` opens the annotation leaves and opens none of the
    /// external ones.
    ///
    /// Neither sets `truncated`. A cap that dropped neighbors means the caller
    /// received less of a chain that exists; a boundary means the chain ends
    /// there, and marking it as a shortfall would report every honest trace as
    /// a floor.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub terminal_external_steps: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub terminal_annotation_steps: usize,
    /// Steps whose relations were read and held no admissible edge, split by
    /// whether the graph could have held one.
    ///
    /// `terminal_leaf_steps` is the only count in this response that asserts a
    /// branch ended because the code ends. `terminal_coverage_gap_steps` is the
    /// same empty read on a language whose deciding coverage classes were not
    /// observed present, so the walk cannot tell an absent hop from a graph
    /// that never held one. `terminal_bound_steps` counts nodes whose relations
    /// were never read at all, because the requested depth or a work budget
    /// stopped the walk first.
    ///
    /// Kept apart rather than summed, and counted rather than left to a scan of
    /// `chain`, because a caller acts differently on each: raise `depth` for a
    /// bound, repair enrichment for a gap, and believe a leaf.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub terminal_leaf_steps: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub terminal_bound_steps: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub terminal_coverage_gap_steps: usize,
    /// Why the walk stopped at the FOCAL itself, in the same vocabulary each
    /// step's `terminal` uses, or null when the focal was expanded and had
    /// neighbors.
    ///
    /// The focal is not a member of `chain`, so an empty chain otherwise
    /// carries no statement at all about why it is empty, and an empty chain is
    /// precisely the answer whose trust depends on that statement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focal_terminal: Option<String>,
    /// This walk's own cross-file edge-class observation for the focal's
    /// language, in the shape every reference tool publishes it in.
    ///
    /// Published on every walk rather than only on an empty one. A chain built
    /// over a graph holding no cross-file calls has stayed inside one file, and
    /// a response that reported nothing about coverage made the envelope say
    /// `edge_coverage_unreported` on complete walks and short ones alike, which
    /// is a limit that distinguishes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_coverage: Option<serde_json::Value>,
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
    include_type_edges: Option<bool>,
    target: Option<String>,
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
        include_type_edges,
        target,
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
    let include_type_edges = request.type_edges_included();

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
    let focal_entity_record = entity_record(&focal_entity, focal_record.as_ref(), None);

    // The kinds a data-flow claim actually rests on.
    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    // `UsesType` is walkable only in the sense that it can REACH a step:
    // admitted so an annotation target is a NAMED leaf rather than a symbol the
    // walk silently never mentions, and so `include_type_edges` has an edge to
    // open. Whether it is walked THROUGH is decided per step, below. It is kept
    // out of `reference_kinds` to match the arm in `kin_mcp`, where that array
    // is also what the coverage observation is measured against and an
    // annotation edge must not join it.
    let allowed: HashSet<RelationKind> = reference_kinds
        .iter()
        .copied()
        .chain(std::iter::once(RelationKind::UsesType))
        .collect();

    // The question, resolved once and consulted per candidate.
    //
    // A target that resolves to nothing is disclosed rather than fatal: the
    // chain the caller asked for is still the chain, and failing the call would
    // turn a typo in an optional hint into no answer at all.
    let mut target_name: Option<String> = None;
    let mut reach_set: Option<HashSet<EntityId>> = None;
    if let Some(target) = request
        .target
        .as_deref()
        .map(str::trim)
        .filter(|target| !target.is_empty())
    {
        match resolve_trace_focal(graph, target)? {
            Some(entity) => {
                let (set, complete) =
                    reach_set_toward(graph, &entity, direction, depth, &allowed, &mut meter)?;
                if !complete {
                    record_degradation(
                        &mut degradations,
                        RetrievalDegradation {
                            component: "target_reachability".to_string(),
                            reason: "reachability_bounded".to_string(),
                            detail: format!(
                                "the reverse walk from '{}' hit a work ceiling before it finished,                                  so some neighbors that do reach it were not recognized and                                  ranked as though they do not",
                                entity.name
                            ),
                            remediation: "narrow the walk with a smaller depth, or name a target                                           closer to the focal"
                                .to_string(),
                        },
                    );
                }
                target_name = Some(entity.name.clone());
                reach_set = Some(set);
            }
            None => record_degradation(
                &mut degradations,
                RetrievalDegradation {
                    component: "target_reachability".to_string(),
                    reason: "target_not_resolved".to_string(),
                    detail: format!(
                        "no entity matches target '{target}', so this walk ranked its fan-out by                          relevance alone and the question had no vote in what the cap kept"
                    ),
                    remediation: "check the target's spelling, or find it first with                                   semantic_locate"
                        .to_string(),
                },
            ),
        }
    }

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
    // What each node's expansion produced, keyed by step index (`0` is the
    // focal). Recorded here because none of it survives into the chain: a step
    // with no children looks the same whether its relations were read and held
    // nothing or were never read at all, which is the whole defect.
    //
    // Only expanded nodes are inserted. Everything else is read as "never
    // expanded" below, which covers both ways that happens: a step at the
    // requested depth is never pushed onto the frontier, and a walk that hits a
    // work ceiling abandons the frontier it had.
    let mut expansion: HashMap<usize, TraceExpansion> = HashMap::new();
    // Each step's language, so a coverage verdict is read for the node it is
    // about rather than borrowed from the focal. A chain that crosses a
    // language boundary crosses an extraction boundary with it.
    let mut step_language: HashMap<usize, kin_model::ids::LanguageId> = HashMap::new();

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
            // Counted before the visited filter, and before the per-step cap.
            // The question a terminal answers is whether the GRAPH held a next
            // hop for this node, not whether this response admitted one: a node
            // whose only neighbors are already in the chain has neighbors, and
            // calling it a leaf would claim the code ends where the walk merely
            // stopped repeating itself.
            let mut admissible_neighbors = 0usize;
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

                admissible_neighbors += 1;

                // Already in the chain by another edge. Not a candidate, and not
                // a drop either: the caller has the node, so counting it as
                // dropped would send them re-querying for something they hold.
                if visited.contains(&next_id) {
                    continue;
                }

                let candidate_at = match candidate_index.get(&(next_id, role)) {
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
                        // These two accumulate across EVERY edge rather than
                        // moving with the strongest one. A class reached by a
                        // `raise` and also by an ordinary call is on the data
                        // path, and a boundary one edge can name stays named
                        // when a weaker anonymous edge arrives beside it.
                        candidate.call_edges +=
                            usize::from(kin_index::is_raise_classifiable_call_edge(rel));
                        candidate.raise_call_edges +=
                            usize::from(kin_index::is_raise_target_edge(rel));
                        if candidate
                            .crossing
                            .as_ref()
                            .is_none_or(|crossing| crossing.specifier.is_none())
                        {
                            if let Some(named) =
                                kin_index::trace_crossing_for(&candidate.entity, Some(rel))
                                    .filter(|crossing| crossing.specifier.is_some())
                            {
                                candidate.crossing = Some(named);
                            }
                        }
                        existing
                    }
                    None => {
                        let Some(entity) = graph
                            .get_entity(&next_id)
                            .context("load trace step entity")?
                        else {
                            continue;
                        };
                        candidate_index.insert((next_id, role), candidates.len());
                        let crossing = kin_index::trace_crossing_for(&entity, Some(rel));
                        let reaches_target =
                            reach_set.as_ref().is_some_and(|set| set.contains(&next_id));
                        candidates.push(FanoutCandidate {
                            reaches_target,
                            call_edges: usize::from(kin_index::is_raise_classifiable_call_edge(
                                rel,
                            )),
                            raise_call_edges: usize::from(kin_index::is_raise_target_edge(rel)),
                            entity,
                            role,
                            relation_kind: rel.kind,
                            confidence: rel.confidence,
                            resolution: RelationResolution::of(rel),
                            crossing,
                            reference_lines: Vec::new(),
                            reference_spans_outside_caller_file: 0,
                        });
                        candidates.len() - 1
                    }
                };

                // The syntax site belongs to the referencing entity. Walking
                // out to a callee means the caller is the parent node; walking
                // in to a caller means the caller is the child step itself.
                // A candidate can collect several edges, so the lines collect
                // beside them rather than moving with whichever edge is ranked
                // strongest for display.
                //
                // Only from a REFERENCE edge, though. `allowed` carries
                // `UsesType` as well, so an annotation target is a named leaf
                // rather than a symbol the walk never mentions, and the graph
                // holds a `UsesType` edge beside the `Calls` edge for the same
                // pair. Its span is the annotation's target, which is the
                // callee's own definition, not a site where the caller calls
                // anything. Accumulating it published `[def_line, call_line]`
                // on every row and a reader could not tell which was which.
                // `reference_kinds` is the set the reference surface reads, so
                // gating on it is what keeps the two answers the same.
                if reference_kinds.contains(&rel.kind) {
                    let caller_file = if role == "callee" {
                        node.file_origin.as_ref()
                    } else {
                        candidates[candidate_at].entity.file_origin.as_ref()
                    };
                    let tally = relation_reference_lines(rel, caller_file);
                    candidates[candidate_at].reference_lines.extend(tally.lines);
                    candidates[candidate_at].reference_spans_outside_caller_file +=
                        tally.outside_caller_file;
                }
            }

            // This node's relations were read to the end, so what the graph
            // held for it is now a fact rather than a guess.
            expansion.insert(
                node.step,
                if admissible_neighbors > 0 {
                    TraceExpansion::HadEdges
                } else {
                    TraceExpansion::NoEdges
                },
            );

            // Independent budgets per direction so `direction=both` doesn't
            // starve callers when callees are listed first (or vice versa).
            let (mut callees, mut callers): (Vec<FanoutCandidate>, Vec<FanoutCandidate>) =
                candidates.into_iter().partition(|c| c.role == "callee");
            sort_by_relevance(&mut callees, &node);
            sort_by_relevance(&mut callers, &node);
            let (dropped_callees, crossing_callees) =
                apply_fanout_cap(&mut callees, node.file.as_deref(), limit_per_step);
            let (dropped_callers, crossing_callers) =
                apply_fanout_cap(&mut callers, node.file.as_deref(), limit_per_step);

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
                    dropped_crossing_file: crossing_callees + crossing_callers,
                    continued_below: false,
                    limit_per_step,
                });
            }

            for mut candidate in callees.into_iter().chain(callers) {
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
                        promoted.entity = entity_record(
                            &candidate.entity,
                            source.as_ref(),
                            candidate.crossing.clone(),
                        );
                        // A promoted record is located by construction, so the
                        // external boundary no longer applies to it; the edge
                        // that reached it is unchanged, so the annotation one
                        // still does. The placeholder's own terminal is undone
                        // rather than left behind, or the step would keep saying
                        // it ended at a symbol this response no longer carries.
                        promoted.terminal = kin_ranking::entity_ranking::trace_step_terminal(
                            &candidate.entity,
                            candidate.relation_kind,
                            include_type_edges,
                        )
                        .map(|terminal| terminal.as_str().to_string());
                        let promoted_terminal = promoted.terminal.is_some();
                        let promoted_depth = promoted.depth;
                        // The record that replaced the placeholder brings its
                        // own language, and the coverage verdict this step is
                        // read against has to follow it.
                        step_language.insert(existing, candidate.entity.language);
                        visited.insert(candidate.entity.id);
                        external_identities_merged += 1;
                        // The placeholder had no edges to walk; the record that
                        // replaced it does, so it re-enters the frontier at the
                        // depth it already sits at.
                        if !promoted_terminal && promoted_depth < depth {
                            next_frontier.push(FrontierNode::at(
                                existing,
                                promoted_depth,
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

                // Decided before the step is pushed, because it decides both
                // what the step says and whether the node is expanded at all.
                let terminal = kin_ranking::entity_ranking::trace_step_terminal(
                    &candidate.entity,
                    candidate.relation_kind,
                    include_type_edges,
                );
                candidate.normalize_reference_lines();
                let reference_lines_absent_reason = candidate.reference_lines_absent_reason();
                chain.push(TraceStep {
                    step: step_index,
                    role: candidate.role.to_string(),
                    relation_kind: format!("{:?}", candidate.relation_kind),
                    resolution: candidate.resolution.as_str().to_string(),
                    parent_step: node.step,
                    depth: next_depth,
                    reference_lines: candidate.reference_lines,
                    reference_lines_absent_reason,
                    entity: entity_record(
                        &candidate.entity,
                        source.as_ref(),
                        candidate.crossing.clone(),
                    ),
                    fanout_truncated: false,
                    fanout_dropped: 0,
                    terminal: terminal.map(|terminal| terminal.as_str().to_string()),
                });
                step_language.insert(step_index, candidate.entity.language);

                if terminal.is_none() && next_depth < depth {
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
        include_type_edges,
        total_steps: chain.len(),
        chain,
        truncated,
        target_name,
        clipped_steps,
        spine_clipped_steps: 0,
        spine_dropped_crossing_file: 0,
        bodies_omitted: 0,
        steps_omitted: 0,
        fanout_narrowed: 0,
        elisions: BTreeMap::new(),
        unproven_steps: 0,
        external_identities_merged,
        terminal_external_steps: 0,
        terminal_annotation_steps: 0,
        terminal_leaf_steps: 0,
        terminal_bound_steps: 0,
        terminal_coverage_gap_steps: 0,
        focal_terminal: None,
        edge_coverage: None,
        max_response_chars: request.budget_chars(),
        degradations,
    };
    // Before the budget, because it reads facts the walk recorded per node and
    // the budget only ever removes steps. Counting them is what happens after.
    classify_walk_terminals(
        graph,
        &focal_entity,
        &reference_kinds,
        &expansion,
        &step_language,
        &mut response,
    );
    enforce_response_budget(&mut response);
    record_unproven_steps(&mut response);
    record_terminal_steps(&mut response);
    // After the budget, because a clip is on the spine only if the walk beneath
    // it is in the response the caller receives. A branch the budget removed
    // took its own evidence of continuation with it.
    record_spine_clipping(&mut response);
    Ok(response)
}

/// Mark the clips the chain continued beneath, and count them once at the top.
///
/// The distinction is the whole point of the field. A clip at the end of a
/// branch costs breadth a reader can see missing; a clip the walk went on
/// beneath hands back a route that reads like the route, while the neighbors it
/// dropped were never followed. Only the second makes "this chain does not
/// contain X" mean nothing at all.
fn record_spine_clipping(response: &mut TraceDataFlowResponse) {
    let parents: HashSet<usize> = response.chain.iter().map(|step| step.parent_step).collect();
    let mut spine_steps = 0usize;
    let mut spine_crossing = 0usize;
    for clip in &mut response.clipped_steps {
        clip.continued_below = parents.contains(&clip.step);
        if clip.continued_below {
            spine_steps += 1;
            spine_crossing += clip.dropped_crossing_file;
        }
    }
    response.spine_clipped_steps = spine_steps;
    response.spine_dropped_crossing_file = spine_crossing;
    if spine_steps == 0 {
        return;
    }
    let widest = response
        .clipped_steps
        .iter()
        .filter(|clip| clip.continued_below)
        .max_by_key(|clip| clip.dropped_callees + clip.dropped_callers);
    let Some(widest) = widest else {
        return;
    };
    let dropped = widest.dropped_callees + widest.dropped_callers;
    let crossing = if spine_crossing > 0 {
        format!(", {spine_crossing} of which lived outside the file of the node that offered them")
    } else {
        String::new()
    };
    record_degradation(
        &mut response.degradations,
        RetrievalDegradation {
            component: "fanout_cap".to_string(),
            reason: "spine_clipped".to_string(),
            detail: format!(
                "the walk continued beneath {spine_steps} node(s) whose fan-out limit_per_step                  {} had already cut, dropping {} neighbor(s) that were never followed{crossing};                  the widest was '{}', which offered {} more than the cap kept. This chain is one                  route among the ones the cap left, so a hop it does not contain was not looked                  for and its absence proves nothing",
                widest.limit_per_step,
                response
                    .clipped_steps
                    .iter()
                    .filter(|clip| clip.continued_below)
                    .map(|clip| clip.dropped_callees + clip.dropped_callers)
                    .sum::<usize>(),
                widest.entity_name,
                dropped,
            ),
            remediation: format!(
                "name the symbol you are looking for as `target` so the cap ranks toward it, or                  re-query '{}' with limit_per_step above {}",
                widest.entity_name, widest.limit_per_step
            ),
        },
    );
}

/// Entities from which `target` is reachable, walking the requested direction
/// backwards, bounded by the same depth and the same work meter as the chain.
///
/// Returns the set and whether the reverse walk finished. An unfinished one is
/// a SUBSET, so a candidate that does reach the target can be missing from it,
/// which is why the caller discloses rather than trusts it silently.
///
/// The depth bound is deliberately the walk's whole depth rather than the
/// remaining depth at each candidate, which makes the set a superset in that
/// direction: a candidate is preferred when the target is reachable from it
/// within `depth` hops, not only within the hops it has left. Preferring a
/// neighbor that might reach the target costs a cap slot; missing one costs the
/// answer.
fn reach_set_toward(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    direction: TraceDirection,
    depth: usize,
    allowed: &HashSet<RelationKind>,
    meter: &mut TraceMeter,
) -> Result<(HashSet<EntityId>, bool)> {
    let want_callees = matches!(direction, TraceDirection::Calls | TraceDirection::Both);
    let want_callers = matches!(direction, TraceDirection::Callers | TraceDirection::Both);
    let mut seen: HashSet<EntityId> = HashSet::new();
    seen.insert(target.id);
    let mut frontier = vec![target.id];
    for _ in 0..depth {
        let mut next = Vec::new();
        for node in frontier.drain(..) {
            if meter.should_stop().is_some() {
                return Ok((seen, false));
            }
            let relations = graph
                .get_all_relations_for_entity(&node)
                .context("read relations for target reachability")?;
            for rel in &relations {
                if meter.charge_edge().is_some() {
                    return Ok((seen, false));
                }
                if !allowed.contains(&rel.kind) {
                    continue;
                }
                let src = rel.src.as_entity();
                let dst = match rel.dst {
                    GraphNodeId::Entity(id) => Some(id),
                    _ => None,
                };
                // One step back along whichever sense the forward walk takes:
                // a `calls` chain reaches the target through outgoing edges, so
                // whoever reaches it is on the incoming side.
                let prior = if want_callees && dst == Some(node) {
                    src
                } else if want_callers && src == Some(node) {
                    dst
                } else {
                    None
                };
                let Some(prior) = prior else { continue };
                if prior != node && seen.insert(prior) {
                    next.push(prior);
                }
            }
        }
        if next.is_empty() {
            return Ok((seen, true));
        }
        frontier = next;
    }
    Ok((seen, true))
}

/// Apply the per-step cap to one side of a node's ranked fan-out.
///
/// Returns how many candidates were dropped, and how many of those lived
/// outside the expanding node's own file. The keep rule itself is
/// [`kin_ranking::entity_ranking::fanout_cap_keeps`], shared with the
/// GraphStore walker in `kin_mcp` so the two cannot answer differently.
fn apply_fanout_cap(
    candidates: &mut Vec<FanoutCandidate>,
    node_file: Option<&str>,
    limit: usize,
) -> (usize, usize) {
    let locality: Vec<kin_ranking::entity_ranking::FanoutLocality> = candidates
        .iter()
        .map(|candidate| match candidate.entity.file_origin.as_ref() {
            None => kin_ranking::entity_ranking::FanoutLocality::Unlocated,
            Some(file) if node_file == Some(file.0.as_str()) => {
                kin_ranking::entity_ranking::FanoutLocality::SameFile
            }
            Some(_) => kin_ranking::entity_ranking::FanoutLocality::OtherFile,
        })
        .collect();
    let keep = kin_ranking::entity_ranking::fanout_cap_keeps(&locality, limit);
    if keep.len() == candidates.len() {
        return (0, 0);
    }
    let kept: HashSet<usize> = keep.iter().copied().collect();
    let dropped_crossing = (0..candidates.len())
        .filter(|index| {
            !kept.contains(index)
                && locality[*index] == kin_ranking::entity_ranking::FanoutLocality::OtherFile
        })
        .count();
    let dropped = candidates.len() - keep.len();
    let mut taken: Vec<FanoutCandidate> = Vec::with_capacity(keep.len());
    for (index, candidate) in std::mem::take(candidates).into_iter().enumerate() {
        if kept.contains(&index) {
            taken.push(candidate);
        }
    }
    *candidates = taken;
    (dropped, dropped_crossing)
}

/// Give every node the walk did not continue through a reason, and publish the
/// coverage observation those reasons rest on.
///
/// Runs once, after the walk and before the response budget. The three states
/// it decides between are the ticket this exists for: a walk that stopped
/// because the code ends, one that stopped at a bound the caller can raise, and
/// one that stopped on a graph that could not have held the next hop. Before
/// this, all three arrived as a step with no children and `truncated: false`.
fn classify_walk_terminals<S: EntityStore>(
    store: &S,
    focal: &Entity,
    reference_kinds: &[RelationKind],
    expansion: &HashMap<usize, TraceExpansion>,
    step_language: &HashMap<usize, kin_model::ids::LanguageId>,
    response: &mut TraceDataFlowResponse,
) {
    // The focal's own observation is the one the response publishes, matching
    // what `find_references` publishes and what the envelope's absence gate
    // reads. Per-step verdicts below may consult another language's, but the
    // published object stays the focal's so one payload carries one scope.
    let focal_observation = kin_mcp::edge_coverage::observe_cross_file_reference_coverage(
        store,
        focal,
        reference_kinds,
    );
    let mut certain: HashMap<kin_model::ids::LanguageId, bool> = HashMap::new();
    certain.insert(
        focal.language,
        kin_mcp::edge_coverage::deciding_classes_observed_present(&focal_observation),
    );
    response.edge_coverage = Some(focal_observation);

    // A walk whose focal was never expanded, or was expanded and held nothing,
    // is the answer whose trust depends most on saying which. The chain carries
    // no row for the focal, so the statement has nowhere else to go.
    let focal_expansion = expansion
        .get(&0)
        .copied()
        .unwrap_or(TraceExpansion::BoundStopped);
    let focal_certain = certain.get(&focal.language).copied().unwrap_or(false);
    response.focal_terminal = trace_walk_terminal(focal_expansion, focal_certain)
        .map(|terminal| terminal.as_str().to_string());

    for step in response.chain.iter_mut() {
        // An external or annotation boundary was decided at the edge that
        // reached the node and is a stronger statement than anything the
        // expansion can add: there is nothing on the other side to walk.
        if step.terminal.is_some() {
            continue;
        }
        let step_number = step.step;
        let outcome = expansion
            .get(&step_number)
            .copied()
            .unwrap_or(TraceExpansion::BoundStopped);
        // Only an empty read consults coverage, so a healthy chain pays one
        // language scan for the focal and none for its steps.
        let coverage_certain = if matches!(outcome, TraceExpansion::NoEdges) {
            let language = step_language
                .get(&step_number)
                .copied()
                .unwrap_or(focal.language);
            match certain.get(&language) {
                Some(&known) => known,
                None => {
                    let observation =
                        kin_mcp::edge_coverage::observe_cross_file_reference_coverage_for_languages(
                            store,
                            &[language],
                            reference_kinds,
                        );
                    let known =
                        kin_mcp::edge_coverage::deciding_classes_observed_present(&observation);
                    certain.insert(language, known);
                    known
                }
            }
        } else {
            false
        };
        step.terminal = trace_walk_terminal(outcome, coverage_certain)
            .map(|terminal| terminal.as_str().to_string());
    }
}

/// Count the leaves this walk refused to expand, from the chain the caller
/// actually receives.
///
/// Recounted rather than accumulated during the walk for the same reason
/// [`record_unproven_steps`] is: the response budget drops steps from the tail
/// after the walk ends, and a counter incremented at admission would keep
/// describing steps the payload no longer carries. A placeholder promoted to a
/// located record mid-walk has the same effect from the other direction.
fn record_terminal_steps(response: &mut TraceDataFlowResponse) {
    let count = |terminal: TraceTerminal| {
        let name = terminal.as_str();
        response
            .chain
            .iter()
            .filter(|step| step.terminal.as_deref() == Some(name))
            .count()
    };
    response.terminal_external_steps = count(TraceTerminal::ExternalReference);
    response.terminal_annotation_steps = count(TraceTerminal::TypeAnnotation);
    response.terminal_leaf_steps = count(TraceTerminal::Leaf);
    response.terminal_bound_steps = count(TraceTerminal::BoundReached);
    response.terminal_coverage_gap_steps = count(TraceTerminal::CoverageGap);

    // The flag follows the hops, and ONE rule decides which hops move it.
    //
    // Deliberately read back off each terminal through
    // [`TraceTerminal::truncates`] rather than off the counts above, even
    // though the counts are right there. Two derivations of one fact is how
    // they come to disagree: an earlier draft summed the counts here and
    // consulted the shared rule only for the focal, so deleting the rule left
    // every chain-side shortfall still reporting itself correctly and the
    // guard could not fail.
    //
    // A bound the caller can raise and a graph that could not have held the
    // next hop are both cases where the chain may be shorter than the code, and
    // both used to arrive as `truncated: false`. That is the whole defect: two
    // real walks on `psf/requests` stopped one caller short and reported
    // themselves complete. Never cleared here, because the walk's own ceilings
    // set it first and this pass must not overturn them.
    let shortfall = |name: Option<&str>| {
        name.and_then(trace_terminal_named)
            .is_some_and(TraceTerminal::truncates)
    };
    if shortfall(response.focal_terminal.as_deref())
        || response
            .chain
            .iter()
            .any(|step| shortfall(step.terminal.as_deref()))
    {
        response.truncated = true;
    }
}

/// Count the hops this response rests on that were matched by name alone, and
/// disclose the count rather than leaving it to be inferred per step.
///
/// Run after the response budget has cut whatever it cuts, so the number
/// describes the chain the caller actually receives. A resolution gate that
/// refuses an edge makes the chain shorter without saying so anywhere; this is
/// what keeps a shortened chain from reading as a proven one.
fn record_unproven_steps(response: &mut TraceDataFlowResponse) {
    let name_only = RelationResolution::NameOnly.as_str();
    response.unproven_steps = response
        .chain
        .iter()
        .filter(|step| step.resolution == name_only)
        .count();
    if response.unproven_steps == 0 {
        return;
    }
    let total = response.chain.len();
    record_degradation(
        &mut response.degradations,
        RetrievalDegradation {
            component: "call_resolution".to_string(),
            reason: "name_only_steps".to_string(),
            detail: format!(
                "{} of {total} steps were reached through an edge matched by name alone, so the flow each claims may not exist",
                response.unproven_steps
            ),
            remediation:
                "read each step's `resolution` field, and treat a `name_only` hop as a candidate rather than a call"
                    .to_string(),
        },
    );
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
    /// The same file as `file`, retained in its graph identity type so relation
    /// evidence can be checked against the caller file without reconstructing
    /// one from presentation text.
    file_origin: Option<kin_model::ids::FilePathId>,
    dir: Option<String>,
}

impl FrontierNode {
    fn at(step: usize, depth: usize, entity: &Entity) -> Self {
        Self {
            step,
            id: entity.id,
            depth,
            file: entity.file_origin.as_ref().map(|path| path.0.clone()),
            file_origin: entity.file_origin.clone(),
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
    /// Classification of the edge this candidate is currently described by.
    /// It moves with `relation_kind` and `confidence` when a stronger edge to
    /// the same neighbor replaces them, so the step reports what the edge it
    /// names actually proved.
    resolution: RelationResolution,
    /// Where the in-repo graph ends, when this candidate sits on the boundary.
    /// Read off the edge that reached it, because the edge is where the module
    /// pin and the receiver text live; the entity carries only identity.
    crossing: Option<kin_index::TraceCrossing>,
    /// Call edges into this candidate, and how many of them were the operand of
    /// a `raise`. A candidate is a throw site when it has call edges and every
    /// one of them is a raise: a class that is also constructed normally is on
    /// the data path and must not be demoted.
    ///
    /// Counted rather than folded into a bool, because a bool was order-
    /// dependent and measurably wrong. Folding with `&&` meant whichever edge
    /// happened to create the candidate set the starting value, so one
    /// reference edge arriving first left the flag false for the whole
    /// candidate. On a converted `psf/requests` that was every exception class
    /// in `HTTPAdapter.send`'s fan-out, so the demotion this field exists for
    /// never once fired on the corpus it was written from, and a check that
    /// inverted the ordering could not tell the difference.
    call_edges: usize,
    raise_call_edges: usize,
    /// Whether a named target is still reachable from this candidate inside the
    /// requested depth. False for every candidate when no target was named, so
    /// an untargeted walk orders exactly as it did before this existed.
    reaches_target: bool,
    /// Every source site carried by every edge that reaches this one step.
    /// These accumulate even when a different, stronger edge supplies the
    /// displayed relation kind.
    reference_lines: Vec<u32>,
    /// Evidence spans that could not be reported because they named a file
    /// other than the caller's. Counted so an empty list can say whether the
    /// parser recorded no span or recorded an unusable one.
    reference_spans_outside_caller_file: usize,
}

impl FanoutCandidate {
    /// Whether this candidate is only ever thrown, never called for its value.
    ///
    /// Only parse-authored call edges vote. An LSP call-hierarchy edge cannot
    /// see a `raise`, so its silence is not a claim that the call was ordinary,
    /// and counting it made this answer `false` for every candidate on any
    /// repository with a language server installed.
    fn is_raise_target(&self) -> bool {
        self.call_edges > 0 && self.raise_call_edges == self.call_edges
    }

    fn normalize_reference_lines(&mut self) {
        self.reference_lines.sort_unstable();
        self.reference_lines.dedup();
    }

    fn reference_lines_absent_reason(&self) -> Option<String> {
        if !self.reference_lines.is_empty() {
            None
        } else if self.reference_spans_outside_caller_file > 0 {
            Some(
                ReferenceLinesAbsent::SpanOutsideCallerFile
                    .as_str()
                    .to_string(),
            )
        } else {
            Some(ReferenceLinesAbsent::NoEvidenceSpan.as_str().to_string())
        }
    }
}

/// Order one side of a node's fan-out by relevance, most relevant first.
///
/// Ties break on name and then id so the same store returns the same chain every
/// run: a reproducible answer is worth more than a marginally better one that
/// moves under the caller.
fn sort_by_relevance(candidates: &mut [FanoutCandidate], node: &FrontierNode) {
    candidates.sort_by(|left, right| {
        // The question first, when there is one. Every proximity term below is
        // a guess about what the caller meant; reachability toward a named
        // target is the one term that knows.
        if left.reaches_target != right.reaches_target {
            return right.reaches_target.cmp(&left.reaches_target);
        }
        let left_score = kin_ranking::entity_ranking::trace_fanout_score(
            &left.entity,
            left.relation_kind,
            node.file.as_deref(),
            node.dir.as_deref(),
            left.confidence,
            left.is_raise_target(),
        );
        let right_score = kin_ranking::entity_ranking::trace_fanout_score(
            &right.entity,
            right.relation_kind,
            node.file.as_deref(),
            node.dir.as_deref(),
            right.confidence,
            right.is_raise_target(),
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
fn entity_record(
    entity: &Entity,
    source: Option<&GraphSourceRecord>,
    crossing: Option<kin_index::TraceCrossing>,
) -> TraceEntityRecord {
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
        crossing,
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
/// steps.
///
/// ## Why the step cut narrows before it amputates
///
/// A suffix cut is safe, because the chain is discovery-ordered and removing
/// the end never orphans a surviving step's parent. It is also what produced a
/// wrong answer. Discovery order is breadth-first, so the tail of the chain is
/// its DEEPEST steps, and cutting a suffix spends the whole budget on the
/// shallow fan-out and amputates the far end, which is where a trace stops
/// being a list of neighbours and becomes an answer.
///
/// Measured on a converted `psf/requests` by the rc0550 stranger at the
/// documented cheap settings (`depth: 3`, `limit_per_step: 12`,
/// `include_body: false`): 67 of 117 steps went, and the survivors did not
/// include `_urllib3_request_context`, one hop past
/// `build_connection_pool_key_attributes`, which is the function that folds
/// `verify` into the urllib3 pool key. Read alone the answer said `verify`
/// reaches TLS at `cert_verify` and stopped, missing the half that governs
/// connection reuse. The stranger's words: "If I had trusted the Kin arm alone
/// I would have written a wrong answer." The edge was in the graph the whole
/// time.
///
/// So the cut now gives up whole branches, least relevant first, and only falls
/// back to the suffix when nothing is left to narrow, so a pathological walk is
/// still answered rather than refused. The rule itself is
/// [`kin_mcp::budget::narrow_fanout_to_fit`], shared with the MCP arm so the
/// two surfaces cannot drift.
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
        let full = std::mem::take(&mut response.chain);
        // Narrow first. Every candidate the shared rule offers is measured the
        // way this response will be sent, so the arithmetic is the budget's own
        // rather than an estimate of it.
        // The question this walk was given. A step standing for the named target
        // is never offered up as "least relevant", and neither is any step
        // between it and the focal; a walk that named nothing, or named
        // something it never reached, protects nothing and narrows as before.
        let named = response.target_name.clone();
        let must_keep = |step: &TraceStep| {
            named
                .as_deref()
                .is_some_and(|name| step.entity.entity_name == name)
        };
        let narrowed = kin_mcp::budget::narrow_fanout_to_fit(
            &full,
            &|step: &TraceStep| step.step as u64,
            &|step: &TraceStep| Some(step.parent_step as u64),
            &must_keep,
            &mut |kept: &[TraceStep]| {
                response.chain = kept.to_vec();
                response.total_steps = kept.len();
                measure_response(response) <= target
            },
        );
        let kept_chain = match narrowed {
            Some(kept) => {
                response.fanout_narrowed = full.len() - kept.len();
                kept
            }
            None => {
                // Nothing narrow enough fits, so fall back to the suffix, which
                // always terminates.
                //
                // Bisected rather than popped one step at a time: the same
                // answer, in a handful of serializations instead of one per
                // dropped step.
                //
                // The floor is one step, not zero. A walk that reached 200 steps
                // and returns `"chain": []` is indistinguishable from a walk
                // that reached none, and no counter elsewhere in the response
                // outranks the empty array for a reader. One surviving step plus
                // the elision beside it says both what was reached and what was
                // withheld.
                let floor = usize::from(!full.is_empty());
                let mut kept = floor;
                let mut low = floor;
                let mut high = full.len();
                while low <= high {
                    let mid = (low + high) / 2;
                    response.chain = full[..mid].to_vec();
                    response.total_steps = mid;
                    if measure_response(response) <= target {
                        kept = mid;
                        low = mid + 1;
                    } else if mid <= floor {
                        break;
                    } else {
                        high = mid - 1;
                    }
                }
                full[..kept].to_vec()
            }
        };
        steps_omitted = full.len() - kept_chain.len();
        response.chain = kept_chain;
        response.total_steps = response.chain.len();
        response.steps_omitted = steps_omitted;
        if steps_omitted > 0 {
            // The same loss in the shape every budgeted list reports it in, so a
            // caller reads one key whether the tool cut a chain or a bucket of
            // tests.
            response.elisions.insert(
                "chain".to_string(),
                Elision::budget(response.chain.len(), steps_omitted),
            );
            // Dropped steps are edges the caller did not receive, which is what
            // this flag has always meant. Dropped bodies are not.
            response.truncated = true;
            // A clip recorded against a step that is no longer here would send a
            // caller re-querying a node the response does not name. Membership
            // rather than `clip.step <= kept`: a narrowed chain is no longer a
            // prefix, so a bound on the index would keep clips for steps that
            // went and drop clips for steps that stayed.
            let surviving: BTreeSet<usize> = response.chain.iter().map(|step| step.step).collect();
            response
                .clipped_steps
                .retain(|clip| clip.step == 0 || surviving.contains(&clip.step));
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
    // Named for HOW the steps went, because "from the end of the chain" and
    // "as whole branches" leave a caller in different places: the first says
    // the far end of the answer is missing, the second says every node lists
    // fewer neighbours and the depth is intact.
    let how = if response.fanout_narrowed > 0 {
        "as whole branches, least relevant first"
    } else {
        "from the end of the chain"
    };
    let cut = match (
        bodies_omitted + usize::from(focal_body_omitted),
        steps_omitted,
    ) {
        (bodies, 0) => format!("{bodies} inlined bodies were dropped"),
        (0, steps) => format!("{steps} steps were dropped {how}"),
        (bodies, steps) => format!(
            "{bodies} inlined bodies were dropped, and {steps} steps after that were dropped \
             {how}"
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
            remediation: format!(
                "ask for the shape directly with include_body: false, or narrow the walk with a \
                 smaller depth or limit_per_step; raise max_response_chars, up to the {} this \
                 server will build, only if the caller's own result limit accepts a larger payload",
                kin_mcp::handlers::common::TRACE_MAX_MAX_RESPONSE_CHARS
            ),
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
    use kin_model::relation::{Relation, RelationEvidence, RelationOrigin};
    use std::sync::Arc;

    pub(super) fn make_entity(name: &str, file: &str) -> Entity {
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
    pub(super) fn make_external_entity(name: &str) -> Entity {
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
            include_type_edges: None,
            target: None,
        }
    }

    pub(super) fn step_names(response: &TraceDataFlowResponse) -> Vec<String> {
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

    fn make_relation_with_site(
        src: EntityId,
        dst: EntityId,
        kind: RelationKind,
        file: &str,
        row: u32,
    ) -> Relation {
        let mut relation = make_relation(src, dst, kind);
        relation.evidence = vec![RelationEvidence {
            source_span: Some(kin_model::entity::SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 1,
                start_line: row,
                start_col: 0,
                end_line: row,
                end_col: 1,
            }),
            ..RelationEvidence::default()
        }];
        relation
    }

    /// Synthesize an absent repository authority. The body itself isn't
    /// required for the chain-shape tests; we only assert on identity fields.
    pub(super) fn empty_binding() -> (tempfile::TempDir, kin_core::LocalRepositoryAuthorityBinding)
    {
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
                include_type_edges: None,
                target: None,
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
                include_type_edges: None,
                target: None,
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
                include_type_edges: None,
                target: None,
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
                include_type_edges: None,
                target: None,
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
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        assert_eq!(response.total_steps, 3, "limit_per_step caps the fan-out");
        assert!(response.truncated, "truncated flag must be set when capped");
    }

    /// Two entities in different files joined by every reference class the
    /// verdict reads, off to the side of whatever chain a fixture walks.
    ///
    /// This is what makes a fixture "a graph that links this language across
    /// files": since FIR-2672 every requested class decides, so a graph that
    /// links only its calls reads a chain end as a coverage gap rather than a
    /// leaf, and honestly so. The witness pair is reached by no walk, so it
    /// changes no chain, only what the graph is known to be able to hold.
    fn seed_cross_file_witness(graph: &InMemoryGraph, extension: &str) {
        let caller = make_entity("witness_caller", &format!("src/witness_caller.{extension}"));
        let callee = make_entity("witness_callee", &format!("src/witness_callee.{extension}"));
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            graph
                .upsert_relation(&make_relation(caller.id, callee.id, kind))
                .unwrap();
        }
    }

    /// A hub whose fan-out is far wider than any per-step limit, so a walk over
    /// it examines many more relations than it can ever turn into steps.
    fn hub_graph(fan_out: usize) -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        seed_cross_file_witness(&graph, "rs");
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
            include_type_edges: None,
            target: None,
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
            include_type_edges: None,
            target: None,
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

    /// The stranger run's own fan-out, rebuilt from the tiers the linker really
    /// stamps.
    ///
    /// `Session.send` in `psf/requests` offers fifteen callees. Eleven sit in
    /// `sessions.py` and are parser-certain, because a call whose destination is
    /// defined in the calling file is stamped 1.0. Three leave the module: two
    /// through an explicit import (0.9), and `HTTPAdapter.send` through the
    /// declared `BaseAdapter` return type and the override edge beneath it
    /// (`INHERITED_METHOD_CONFIDENCE`, 0.85). One is a builtin the repository
    /// does not define.
    ///
    /// The confidences are not decoration. They are what makes this fixture a
    /// statement about the product rather than about itself: a same-file call
    /// outranking a module-crossing one is not an accident of the fan-out order,
    /// it is the ladder in `kin_index::resolution`, and a fixture that stamped
    /// every edge 1.0 would have proven nothing about which term did the
    /// clipping.
    fn requests_send_graph() -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("Session.send", "src/requests/sessions.py");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();

        let mut edges: Vec<(Entity, f32)> = Vec::new();
        for name in [
            "Session.get_adapter",
            "Session.prepare_request",
            "SessionRedirectMixin.resolve_redirects",
            "Session.merge_environment_settings",
            "Session.rebuild_auth",
            "Session.rebuild_proxies",
            "Session.rebuild_method",
            "Session.get_redirect_target",
            "Session.should_strip_auth",
            "Session.mount",
            "Session.close",
        ] {
            edges.push((make_entity(name, "src/requests/sessions.py"), 1.0));
        }
        edges.push((
            make_entity("extract_cookies_to_jar", "src/requests/cookies.py"),
            0.9,
        ));
        edges.push((make_entity("dispatch_hook", "src/requests/hooks.py"), 0.9));
        edges.push((
            make_entity("HTTPAdapter.send", "src/requests/adapters.py"),
            0.85,
        ));
        edges.push((make_external_entity("preferred_clock"), 0.7));

        for (entity, confidence) in &edges {
            graph.upsert_entity(entity).unwrap();
            let mut relation = make_relation(focal_id, entity.id, RelationKind::Calls);
            relation.confidence = *confidence;
            graph.upsert_relation(&relation).unwrap();
        }
        (graph, focal_id)
    }

    /// What the stranger measured, and what it costs now.
    ///
    /// The premise is unchanged and still asserted: fifteen callees under a
    /// four-wide cap drops eleven. What changed is which four survive. Every
    /// one of them used to be in `sessions.py`, so the chain answered a
    /// question about where a value goes without ever leaving the module the
    /// value starts in.
    #[test]
    fn the_measured_fan_out_now_leaves_the_module_it_started_in() {
        let (graph, focal_id) = requests_send_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 4),
        )
        .unwrap();

        let kept = step_names(&response);
        assert_eq!(
            kept.len(),
            4,
            "the four-wide cap still keeps four: {kept:?}"
        );
        assert_eq!(
            response.clipped_steps[0].dropped_callees, 11,
            "and still drops eleven, because a floor is not extra breadth"
        );
        let crossed: Vec<&String> = kept
            .iter()
            .filter(|name| !name.starts_with("Session"))
            .collect();
        assert_eq!(
            crossed.len(),
            1,
            "exactly one slot goes to a hop that leaves the file, no more: {kept:?}"
        );
        assert_eq!(
            response.clipped_steps[0].dropped_crossing_file, 2,
            "three callees live in another file, one now takes the reserved slot, \
             so two module-crossing hops are still dropped"
        );
    }

    /// The acceptance, first arm: name the hop and the cap keeps it.
    ///
    /// Same fifteen-callee node, same four-wide cap, same everything except
    /// that the caller said what they were looking for. `HTTPAdapter.send` is
    /// the worst-ranked hop in this fan-out by every proximity term the cap
    /// consults, which is what makes it the right fixture: nothing but the
    /// question can put it in the chain.
    #[test]
    fn naming_the_target_puts_the_asked_about_hop_in_the_chain() {
        let (graph, focal_id) = requests_send_graph();
        let (_t, binding) = empty_binding();

        let mut request = trace_request(&focal_id, 1, TraceDirection::Calls, 4);
        request.target = Some("HTTPAdapter.send".to_string());
        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
        )
        .unwrap();

        let kept = step_names(&response);
        assert!(
            kept.iter().any(|name| name == "HTTPAdapter.send"),
            "the hop the caller named must survive the cap: {kept:?}"
        );
        assert_eq!(
            response.target_name.as_deref(),
            Some("HTTPAdapter.send"),
            "and the response echoes the question it was given"
        );
        // The control on the control: without the target, this same walk does
        // not contain it, so the assertion above is testing the target and not
        // the floor that landed beside it.
        let untargeted = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 4),
        )
        .unwrap();
        assert!(
            !step_names(&untargeted)
                .iter()
                .any(|name| name == "HTTPAdapter.send"),
            "the untargeted walk must still miss it, or this check proves nothing"
        );
    }

    /// A target that names nothing is a disclosure, not a failed call.
    #[test]
    fn an_unresolved_target_is_disclosed_and_the_chain_still_comes_back() {
        let (graph, focal_id) = requests_send_graph();
        let (_t, binding) = empty_binding();

        let mut request = trace_request(&focal_id, 1, TraceDirection::Calls, 4);
        request.target = Some("HTTPAdapter.sendd".to_string());
        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &request,
        )
        .unwrap();

        assert_eq!(response.chain.len(), 4, "the chain is still the chain");
        assert!(response.target_name.is_none(), "nothing was ranked toward");
        assert!(
            response
                .degradations
                .iter()
                .any(|degradation| degradation.reason == "target_not_resolved"),
            "and the walk says the question had no vote: {:?}",
            response.degradations
        );
    }

    /// The acceptance, second arm: when nothing was named, say so loudly.
    ///
    /// The failure this exists for is not a missing hop, it is a chain that
    /// reads like a route while eleven siblings were never followed. The
    /// disclosure has to name the node, the parameter and the count, and it has
    /// to say in words that an absence here proves nothing.
    #[test]
    fn a_clip_the_walk_continued_beneath_refuses_to_be_read_as_an_absence() {
        let (graph, focal_id) = requests_send_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 4),
        )
        .unwrap();

        assert_eq!(
            response.spine_clipped_steps, 1,
            "the focal was clipped and the chain continues beneath it"
        );
        assert_eq!(
            response.spine_dropped_crossing_file, 2,
            "two of the hops it never followed left the module"
        );
        assert!(
            response.clipped_steps[0].continued_below,
            "and the clip itself carries the distinction"
        );
        let disclosure = response
            .degradations
            .iter()
            .find(|degradation| degradation.reason == "spine_clipped")
            .expect("a spine clip must be disclosed");
        assert!(
            disclosure.detail.contains("Session.send")
                && disclosure.detail.contains("limit_per_step"),
            "the disclosure names the node and the parameter: {}",
            disclosure.detail
        );
        assert!(
            disclosure.detail.contains("absence proves nothing"),
            "and says what a reader may not conclude: {}",
            disclosure.detail
        );
        assert!(
            disclosure.remediation.contains("target"),
            "and names the lever that fixes it: {}",
            disclosure.remediation
        );
    }

    /// The control the acceptance asks for: a walk the cap never cut carries
    /// none of this, so a complete answer is not qualified by machinery that
    /// exists for incomplete ones.
    #[test]
    fn an_unclipped_walk_still_certifies_and_says_nothing_about_spines() {
        let (graph, focal_id) = requests_send_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding.clone()),
            &graph,
            &trace_request(&focal_id, 1, TraceDirection::Calls, 25),
        )
        .unwrap();

        assert_eq!(
            response.total_steps, 15,
            "a 25-wide cap expands all fifteen callees"
        );
        assert!(response.clipped_steps.is_empty());
        assert_eq!(response.spine_clipped_steps, 0);
        assert_eq!(response.spine_dropped_crossing_file, 0);
        assert!(
            !response
                .degradations
                .iter()
                .any(|degradation| degradation.component == "fanout_cap"),
            "no cap disclosure on a walk no cap cut: {:?}",
            response.degradations
        );
        let json = serde_json::to_value(&response).unwrap();
        for absent in ["spine_clipped_steps", "spine_dropped_crossing_file"] {
            assert!(
                json.get(absent).is_none(),
                "an unaffected walk must not carry {absent} at all"
            );
        }
    }

    /// A fan-out the size of a real one, so a change to how the cap chooses can
    /// be timed rather than guessed at.
    ///
    /// Every node below the focal offers the same fifteen-wide fan-out the
    /// measured `Session.send` did, at the same tiers, four levels deep. That is
    /// roughly fifty thousand entities and as many edges, which is the scale at
    /// which a per-candidate cost shows up as time instead of as noise.
    fn deep_requests_shaped_graph(levels: usize) -> (InMemoryGraph, EntityId, String) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("Session.send", "src/requests/sessions.py");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();

        let mut frontier = vec![(focal_id, 0usize)];
        let mut serial = 0usize;
        let mut deepest = String::new();
        for level in 0..levels {
            let mut next = Vec::new();
            for (parent, _) in frontier.drain(..) {
                for index in 0..15usize {
                    serial += 1;
                    let (file, confidence) = match index {
                        0..=10 => ("src/requests/sessions.py", 1.0),
                        11 => ("src/requests/cookies.py", 0.9),
                        12 => ("src/requests/hooks.py", 0.9),
                        13 => ("src/requests/adapters.py", 0.85),
                        _ => ("src/requests/utils.py", 0.7),
                    };
                    let name = format!("n{level}_{serial}_{index}");
                    let entity = make_entity(&name, file);
                    graph.upsert_entity(&entity).unwrap();
                    let mut relation = make_relation(parent, entity.id, RelationKind::Calls);
                    relation.confidence = confidence;
                    graph.upsert_relation(&relation).unwrap();
                    if level + 1 < levels {
                        next.push((entity.id, level + 1));
                    } else if index == 13 {
                        deepest = name;
                    }
                }
            }
            frontier = next;
        }
        (graph, focal_id, deepest)
    }

    /// Wall time of the walk itself, printed rather than asserted.
    ///
    /// Ignored by default because it is a measurement, not a gate: a threshold
    /// on a shared machine fails on load rather than on the diff. Run it with
    /// `--ignored --nocapture` on both sides of a change and read the numbers.
    #[test]
    #[ignore = "timing measurement: cargo test -p kin-cli --lib measure_walk_wall_time -- --ignored --nocapture"]
    fn measure_walk_wall_time_on_a_requests_shaped_fan_out() {
        let (graph, focal_id, target) = deep_requests_shaped_graph(4);
        let (_t, binding) = empty_binding();
        let authority = RequestRepositoryAuthority::pinned(binding.clone());

        let mut samples = Vec::new();
        for _ in 0..9 {
            let request = trace_request(&focal_id, 5, TraceDirection::Calls, 4);
            let started = std::time::Instant::now();
            let response = build_trace_data_flow_response(&authority, &graph, &request).unwrap();
            samples.push(started.elapsed());
            assert!(!response.chain.is_empty());
        }
        samples.sort();
        println!(
            "WALK_MEDIAN_MS untargeted {:.3}",
            samples[samples.len() / 2].as_secs_f64() * 1000.0
        );

        // What naming a target costs: one bounded reverse walk from it, plus a
        // set lookup per candidate. The target is the deepest node in the
        // fixture and it is reached through the module-crossing edge, which is
        // the worst case for the reverse walk on this shape.
        let mut targeted = Vec::new();
        for _ in 0..9 {
            let mut request = trace_request(&focal_id, 5, TraceDirection::Calls, 4);
            request.target = Some(target.clone());
            let started = std::time::Instant::now();
            let response = build_trace_data_flow_response(&authority, &graph, &request).unwrap();
            targeted.push(started.elapsed());
            assert_eq!(response.target_name.as_deref(), Some(target.as_str()));
        }
        targeted.sort();
        println!(
            "WALK_MEDIAN_MS targeted {:.3}",
            targeted[targeted.len() / 2].as_secs_f64() * 1000.0
        );
        println!("WALK_TARGET_NAME {target}");
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

    /// A chain is only actionable when each hop names
    /// the syntax site that created it, not only the callee's definition.
    /// Outgoing and incoming steps have different callers, duplicate edges must
    /// accumulate, and an empty list must explain which absence occurred.
    #[test]
    fn every_chain_step_carries_its_call_site_lines_or_an_explicit_reason() {
        let graph = InMemoryGraph::new();
        let focal = make_entity("focal", "src/focal.rs");
        let callee = make_entity("callee", "src/callee.rs");
        let caller = make_entity("caller", "src/caller.rs");
        let missing = make_entity("missing_site", "src/missing.rs");
        let outside = make_entity("outside_site", "src/outside.rs");
        for entity in [&focal, &callee, &caller, &missing, &outside] {
            graph.upsert_entity(entity).unwrap();
        }

        // Two sites on two edges into one callee. They must union even though
        // one displayed step can name only one strongest relation.
        graph
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::Calls,
                "src/focal.rs",
                11,
            ))
            .unwrap();
        graph
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::References,
                "src/focal.rs",
                41,
            ))
            .unwrap();
        graph
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::Imports,
                "src/focal.rs",
                41,
            ))
            .unwrap();
        // An incoming step's call site lives in the CHILD/caller's file.
        graph
            .upsert_relation(&make_relation_with_site(
                caller.id,
                focal.id,
                RelationKind::Calls,
                "src/caller.rs",
                7,
            ))
            .unwrap();
        // One parser edge carried no span; one carried a span in the wrong
        // file. The reasons have to stay distinguishable.
        graph
            .upsert_relation(&make_relation(focal.id, missing.id, RelationKind::Calls))
            .unwrap();
        graph
            .upsert_relation(&make_relation_with_site(
                focal.id,
                outside.id,
                RelationKind::Calls,
                "src/not-the-caller.rs",
                19,
            ))
            .unwrap();

        let mut request = trace_request(&focal.id, 1, TraceDirection::Both, 25);
        request.include_body = Some(false);
        let response = traced(&graph, &request);
        let step = |name: &str| {
            response
                .chain
                .iter()
                .find(|step| step.entity.entity_name == name)
                .unwrap_or_else(|| panic!("missing {name} in {:?}", step_names(&response)))
        };

        assert_eq!(step("callee").reference_lines, vec![12, 42]);
        assert_eq!(step("callee").reference_lines_absent_reason, None);
        assert_eq!(step("caller").reference_lines, vec![8]);
        assert_eq!(step("caller").reference_lines_absent_reason, None);
        assert!(step("missing_site").reference_lines.is_empty());
        assert_eq!(
            step("missing_site")
                .reference_lines_absent_reason
                .as_deref(),
            Some("no_evidence_span")
        );
        assert!(step("outside_site").reference_lines.is_empty());
        assert_eq!(
            step("outside_site")
                .reference_lines_absent_reason
                .as_deref(),
            Some("span_outside_caller_file")
        );

        let mut old_payload = serde_json::to_value(&response).unwrap();
        for item in old_payload["chain"].as_array_mut().unwrap() {
            item.as_object_mut().unwrap().remove("reference_lines");
            item.as_object_mut()
                .unwrap()
                .remove("reference_lines_absent_reason");
        }
        let parsed: TraceDataFlowResponse = serde_json::from_value(old_payload)
            .expect("a daemon predating call-site fields must remain readable");
        assert!(parsed
            .chain
            .iter()
            .all(|step| step.reference_lines.is_empty()
                && step.reference_lines_absent_reason.as_deref() == Some("unreported_by_daemon")));
    }

    /// An annotation edge's span is not a call site, on this arm too.
    ///
    /// The generic GraphStore arm has a test for exactly this. The CLI arm
    /// carried the same edge-class gate with nothing grading it, so restoring
    /// the old accumulation here went unnoticed on this surface while the other
    /// surface caught it, which is a guard that cannot fail. The graph holds a
    /// `UsesType` edge beside the `Calls` edge for the same pair, and its span
    /// is the annotation's target, which is the callee's own definition rather
    /// than anywhere the caller calls it.
    #[test]
    fn an_annotation_span_is_not_a_call_site() {
        let graph = InMemoryGraph::new();
        let focal = make_entity("focal", "src/focal.rs");
        let callee = make_entity("callee", "src/callee.rs");
        for entity in [&focal, &callee] {
            graph.upsert_entity(entity).unwrap();
        }
        graph
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::Calls,
                "src/focal.rs",
                11,
            ))
            .unwrap();
        graph
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::UsesType,
                "src/focal.rs",
                4,
            ))
            .unwrap();

        let mut request = trace_request(&focal.id, 1, TraceDirection::Calls, 25);
        request.include_body = Some(false);
        let response = traced(&graph, &request);
        let row = response
            .chain
            .iter()
            .find(|step| step.entity.entity_name == "callee")
            .unwrap_or_else(|| {
                panic!(
                    "the annotation edge must still reach the leaf: {:?}",
                    step_names(&response)
                )
            });

        // The premise: the leaf is here at all, which is what `UsesType` being
        // in the allowed set buys and what this gate must not take away.
        assert_eq!(
            row.reference_lines,
            vec![12],
            "only the call site belongs here, not the annotation's target: {row:?}"
        );
        assert_eq!(row.reference_lines_absent_reason, None);
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
        // Keep the original compact-shape tripwire load-bearing rather than
        // weakening it for the two uniform site-contract fields. Measure the
        // old shape with exactly those fields removed, then bound their own
        // incremental cost separately. A future unrelated per-step expansion
        // still trips the original 20k ceiling, while the call-site contract
        // gets a named allowance rather than silently consuming its margin.
        let mut without_site_contract = serde_json::to_value(&response).unwrap();
        for step in without_site_contract["chain"].as_array_mut().unwrap() {
            let row = step.as_object_mut().unwrap();
            row.remove("reference_lines");
            row.remove("reference_lines_absent_reason");
        }
        let compact_shape = serde_json::to_string_pretty(&without_site_contract).unwrap();
        assert!(
            compact_shape.len() < 20_000,
            "25 steps without the site contract are small; {} chars means bodies or unrelated \
             per-step bloat crept back in",
            compact_shape.len()
        );
        let site_contract_chars = json.len().saturating_sub(compact_shape.len());
        assert!(
            site_contract_chars < 3_000,
            "the two uniform site fields added {site_contract_chars} chars across 25 steps"
        );
    }

    /// A response is refused whole or not at all, so the tool bounds its own
    /// payload rather than discovering the ceiling at the client.
    fn fat_response(steps: usize, body_chars: usize) -> TraceDataFlowResponse {
        let entity = make_entity("focal", "src/focal.rs");
        let mut chain = Vec::new();
        for index in 1..=steps {
            let step_entity = make_entity(&format!("step_{index}"), "src/step.rs");
            let mut record = entity_record(&step_entity, None, None);
            record.body = Some("x".repeat(body_chars));
            record.span_coherence = Some("verified".to_string());
            chain.push(TraceStep {
                step: index,
                role: "callee".to_string(),
                relation_kind: "Calls".to_string(),
                resolution: RelationResolution::TypeResolved.as_str().to_string(),
                parent_step: index.saturating_sub(1),
                depth: 1,
                reference_lines: Vec::new(),
                reference_lines_absent_reason: Some(
                    ReferenceLinesAbsent::NoEvidenceSpan.as_str().to_string(),
                ),
                entity: record,
                fanout_truncated: false,
                fanout_dropped: 0,
                terminal: None,
            });
        }
        TraceDataFlowResponse {
            focal: None,
            focal_id: entity.id.to_string(),
            focal_name: entity.name.clone(),
            focal_kind: "Function".to_string(),
            focal_file: Some("src/focal.rs".to_string()),
            focal_entity: entity_record(&entity, None, None),
            direction: "calls".to_string(),
            depth: 1,
            limit_per_step: 25,
            bodies_included: true,
            include_type_edges: false,
            total_steps: chain.len(),
            chain,
            truncated: false,
            target_name: None,
            clipped_steps: Vec::new(),
            spine_clipped_steps: 0,
            spine_dropped_crossing_file: 0,
            bodies_omitted: 0,
            steps_omitted: 0,
            fanout_narrowed: 0,
            elisions: BTreeMap::new(),
            unproven_steps: 0,
            external_identities_merged: 0,
            terminal_external_steps: 0,
            terminal_annotation_steps: 0,
            terminal_leaf_steps: 0,
            terminal_bound_steps: 0,
            terminal_coverage_gap_steps: 0,
            focal_terminal: None,
            edge_coverage: None,
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
            dropped_crossing_file: 0,
            continued_below: false,
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

    /// The measured shape, in miniature: a focal with a wide fan-out, one deep
    /// branch hanging off its FIRST child, and steps numbered in discovery
    /// order, which is breadth-first, so the deep steps are last.
    ///
    /// `psf/requests` gave `HTTPAdapter.send` twelve depth-1 children and put
    /// `_urllib3_request_context` at depth 3, which is where the tail is.
    fn wide_then_deep_response(
        width: usize,
        deep: usize,
        pad_chars: usize,
    ) -> TraceDataFlowResponse {
        let mut response = fat_response(0, 0);
        let mut chain: Vec<TraceStep> = Vec::new();
        let push = |chain: &mut Vec<TraceStep>, name: String, parent: usize, depth: usize| {
            let entity = make_entity(&name, "src/step.rs");
            let mut record = entity_record(&entity, None, None);
            record.signature = Some("s".repeat(pad_chars));
            chain.push(TraceStep {
                step: chain.len() + 1,
                role: "callee".to_string(),
                relation_kind: "Calls".to_string(),
                resolution: RelationResolution::TypeResolved.as_str().to_string(),
                parent_step: parent,
                depth,
                reference_lines: Vec::new(),
                reference_lines_absent_reason: Some(
                    ReferenceLinesAbsent::NoEvidenceSpan.as_str().to_string(),
                ),
                entity: record,
                fanout_truncated: false,
                fanout_dropped: 0,
                terminal: None,
            });
        };
        for index in 1..=width {
            push(&mut chain, format!("neighbour_{index}"), 0, 1);
        }
        let mut parent = 1usize;
        for level in 0..deep {
            push(&mut chain, format!("deep_{level}"), parent, level + 2);
            parent = chain.len();
        }
        response.bodies_included = false;
        response.total_steps = chain.len();
        response.chain = chain;
        response
    }

    /// The smallest payload narrowing can produce for [`wide_then_deep_response`]:
    /// the focal's first child and the deep branch below it, which is what
    /// "every node keeps its first child" leaves behind.
    ///
    /// Computed rather than guessed, so these tests calibrate against the
    /// serializer instead of against a number that drifts the first time a field
    /// is added to a step.
    fn narrowest_budget(width: usize, deep: usize, pad_chars: usize) -> usize {
        let mut floor = wide_then_deep_response(width, deep, pad_chars);
        let survivors: BTreeSet<usize> = std::iter::once(1)
            .chain((width + 1)..=(width + deep))
            .collect();
        floor.chain.retain(|step| survivors.contains(&step.step));
        floor.total_steps = floor.chain.len();
        serde_json::to_string_pretty(&floor).map_or(usize::MAX, |json| json.len())
            + TRACE_DISCLOSURE_RESERVE_CHARS
    }

    /// FIR-2642. The budget must give up the focal's least relevant neighbours
    /// before it gives up the end of the chain, because the end of the chain is
    /// the answer.
    ///
    /// Measured on a converted `psf/requests` at the stranger's own settings:
    /// the suffix cut returned nothing past depth 2 while the walk had reached
    /// depth 3, so the response said `verify` reaches TLS at `cert_verify` and
    /// stopped, missing the pool-key path that governs connection reuse.
    #[test]
    fn the_budget_narrows_the_fan_out_before_it_amputates_the_chain() {
        let mut response = wide_then_deep_response(12, 2, 900);
        response.max_response_chars = narrowest_budget(12, 2, 900);
        let deepest = response
            .chain
            .last()
            .expect("the fixture has a deep end")
            .entity
            .entity_name
            .clone();
        assert!(
            serde_json::to_string_pretty(&response).unwrap().len() > response.max_response_chars,
            "the fixture must start over budget or this proves nothing"
        );

        enforce_response_budget(&mut response);

        assert!(
            step_names(&response).contains(&deepest),
            "the budget amputated the deep end instead of narrowing the fan-out: {:?}",
            step_names(&response)
        );
        assert!(
            response.fanout_narrowed > 0,
            "a narrowed cut must say it narrowed"
        );
        assert_eq!(
            response.fanout_narrowed, response.steps_omitted,
            "every step this cut dropped went as part of a branch"
        );
        // No survivor may name a parent the response no longer carries, which is
        // the property a prefix cut got for free and this one has to earn.
        let present: BTreeSet<usize> = response.chain.iter().map(|step| step.step).collect();
        assert!(
            response
                .chain
                .iter()
                .all(|step| step.parent_step == 0 || present.contains(&step.parent_step)),
            "a surviving step names a parent the cut removed: {present:?}"
        );
        let cut = response
            .degradations
            .iter()
            .find(|d| d.component == "response_budget")
            .expect("the cut must be disclosed");
        assert!(
            cut.detail.contains("as whole branches"),
            "the disclosure must say which cut a caller received: {}",
            cut.detail
        );
        assert!(
            serde_json::to_string_pretty(&response).unwrap().len() <= response.max_response_chars,
            "the payload must end up inside the budget it reports"
        );
    }

    /// At the typed response arm, the target is a shallow leaf that
    /// ordinary depth-first preservation gives up before the deeper branch, so
    /// target-aware walk ordering alone cannot make this pass. At one explicit
    /// response cut the unnamed arm loses it and the named arm keeps it.
    #[test]
    fn a_named_target_survives_the_cli_response_budget_that_drops_it_unnamed() {
        let fixture = wide_then_deep_response(12, 2, 900);
        let target = "neighbour_12";
        let found = (kin_mcp::handlers::common::TRACE_MIN_MAX_RESPONSE_CHARS
            ..=kin_mcp::handlers::common::TRACE_MAX_MAX_RESPONSE_CHARS)
            .step_by(250)
            .find_map(|budget| {
                let mut unnamed = fixture.clone();
                unnamed.max_response_chars = budget;
                enforce_response_budget(&mut unnamed);

                let mut targeted = fixture.clone();
                targeted.target_name = Some(target.to_string());
                targeted.max_response_chars = budget;
                enforce_response_budget(&mut targeted);

                let unnamed_names = step_names(&unnamed);
                let targeted_names = step_names(&targeted);
                (unnamed.steps_omitted > 0
                    && targeted.steps_omitted > 0
                    && unnamed.fanout_narrowed > 0
                    && targeted.fanout_narrowed > 0
                    && !unnamed_names.iter().any(|name| name == target)
                    && targeted_names.iter().any(|name| name == target))
                .then_some((budget, unnamed, targeted))
            })
            .expect(
                "no accepted response budget separated the unnamed and targeted arms; either the \
                 fixture no longer reaches branch narrowing or the named branch is not protected",
            );

        let (budget, unnamed, targeted) = found;
        assert!(
            unnamed.fanout_narrowed > 0 && targeted.fanout_narrowed > 0,
            "both arms must exercise branch narrowing at budget {budget}"
        );
        let target_step = targeted
            .chain
            .iter()
            .find(|step| step.entity.entity_name == target)
            .expect("the protected target survives");
        assert_eq!(
            target_step.parent_step, 0,
            "the target must not survive with a missing parent"
        );
        assert!(
            !step_names(&unnamed).iter().any(|name| name == target),
            "the unnamed control kept {target} at budget {budget}: {:?}",
            step_names(&unnamed)
        );
    }

    /// The other direction, so the disclosure cannot be a constant. A chain with
    /// no node wider than one child has no branch to give up, so the suffix cut
    /// runs, `fanout_narrowed` stays zero, and the wording says end-of-chain.
    #[test]
    fn a_chain_with_nothing_to_narrow_still_takes_the_suffix_cut_and_says_so() {
        let mut response = fat_response(200, 0);
        response.bodies_included = false;
        for step in &mut response.chain {
            step.entity.body = None;
            step.entity.span_coherence = None;
            step.entity.signature = Some("s".repeat(400));
        }
        response.max_response_chars = 8_000;

        enforce_response_budget(&mut response);

        assert!(response.steps_omitted > 0, "the fixture must reach the cut");
        assert_eq!(
            response.fanout_narrowed, 0,
            "a spine has no branch to give up, so nothing may claim it narrowed one"
        );
        let cut = response
            .degradations
            .iter()
            .find(|d| d.component == "response_budget")
            .expect("the cut must be disclosed");
        assert!(
            cut.detail.contains("from the end of the chain"),
            "the suffix cut must still say so: {}",
            cut.detail
        );
    }

    /// A clip is a pointer into `chain`, and a narrowed chain is no longer a
    /// prefix, so keeping clips by index would keep pointers to steps that went
    /// and drop pointers to steps that stayed.
    #[test]
    fn a_narrowed_chain_keeps_exactly_the_clips_whose_steps_survived() {
        let mut response = wide_then_deep_response(12, 2, 900);
        for step in [1usize, 12, 14] {
            response.clipped_steps.push(TraceFanoutClip {
                step,
                entity_id: format!("clip-{step}"),
                entity_name: format!("step_{step}"),
                dropped_callees: 3,
                dropped_callers: 0,
                dropped_crossing_file: 0,
                continued_below: false,
                limit_per_step: 12,
            });
        }
        // Calibrated on THIS response, clips included, because the clips are
        // part of what the budget measures.
        let mut floor = response.clone();
        floor.chain.retain(|step| [1, 13, 14].contains(&step.step));
        floor.total_steps = floor.chain.len();
        response.max_response_chars =
            serde_json::to_string_pretty(&floor).unwrap().len() + TRACE_DISCLOSURE_RESERVE_CHARS;

        enforce_response_budget(&mut response);

        let present: BTreeSet<usize> = response.chain.iter().map(|step| step.step).collect();
        assert!(
            present.contains(&1) && present.contains(&14),
            "the fixture must keep the first neighbour and the deep end: {present:?}"
        );
        assert!(
            !present.contains(&12),
            "the fixture must drop the last neighbour or the clip test proves nothing: \
             {present:?}"
        );
        let clipped: BTreeSet<usize> = response.clipped_steps.iter().map(|c| c.step).collect();
        assert_eq!(
            clipped,
            BTreeSet::from([1, 14]),
            "a clip must name a step the response still carries, and must not lose one it does"
        );
    }

    /// The defect FIR-2600 names, on the arm the daemon actually runs. A walk
    /// that reached 200 steps and comes back with `"chain": []` is
    /// indistinguishable from a walk that reached none, and `steps_omitted`
    /// three fields away does not outrank the empty array for a reader. One step
    /// survives, and `elisions.chain` says what the budget took and why.
    #[test]
    fn a_budget_never_returns_an_empty_chain_for_a_walk_that_found_steps() {
        let mut response = fat_response(200, 2_000);
        // The floor of the clamp, where the disclosure is a large fraction of the
        // whole budget and the ladder would otherwise strip the chain to nothing
        // to make room for the note explaining that it had.
        response.max_response_chars = kin_mcp::handlers::common::TRACE_MIN_MAX_RESPONSE_CHARS;

        enforce_response_budget(&mut response);

        assert!(
            !response.chain.is_empty(),
            "the budget emptied a chain of 200 steps: {}",
            serde_json::to_string_pretty(&response).unwrap()
        );
        let kept = response.chain.len();
        assert_eq!(kept + response.steps_omitted, 200);
        assert_eq!(response.total_steps, kept);
        let elision = response
            .elisions
            .get("chain")
            .expect("a cut chain publishes what it lost");
        assert_eq!(elision.kept, kept);
        assert_eq!(elision.elided, response.steps_omitted);
        assert_eq!(elision.total, 200);
        assert_eq!(elision.reason, kin_mcp::budget::ELISION_REASON_BUDGET);
        assert!(response.truncated);
    }

    /// The direction that makes the rule worth having. A walk that reached
    /// nothing answers with an empty chain and claims no elision, so an empty
    /// `chain` means one thing. Without this, "never empty" could be satisfied
    /// by inventing a step.
    #[test]
    fn a_walk_that_reached_nothing_still_answers_with_an_empty_chain() {
        let mut response = fat_response(0, 0);
        response.max_response_chars = kin_mcp::handlers::common::TRACE_MIN_MAX_RESPONSE_CHARS;

        enforce_response_budget(&mut response);

        assert!(
            response.chain.is_empty(),
            "an empty walk must report itself"
        );
        assert_eq!(response.total_steps, 0);
        assert_eq!(response.steps_omitted, 0);
        assert!(
            response.elisions.is_empty(),
            "nothing was withheld, so nothing may be claimed"
        );
        let rendered = serde_json::to_string_pretty(&response).unwrap();
        assert!(
            !rendered.contains("elisions"),
            "an untouched response must not grow a key: {rendered}"
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
            "reference_lines",
            "reference_lines_absent_reason",
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
    /// The reported shape, built to its own numbers: a TLS-configuration focal
    /// that names `typing.Any` in a signature, and an `Any` the graph holds
    /// with no file and 44 further referrers.
    ///
    /// `direction: "both"` is where it bit. The inbound half of an annotation
    /// edge is "every other thing that mentions this type", so the walk arrived
    /// at 44 unrelated entities through one node that this repository defines
    /// nothing for.
    fn annotation_hub_graph(other_referrers: usize) -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("cert_verify", "src/adapters.rs");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();

        let hub = make_external_entity("Any");
        let hub_id = hub.id;
        graph.upsert_entity(&hub).unwrap();
        graph
            .upsert_relation(&make_relation(focal_id, hub_id, RelationKind::References))
            .unwrap();

        for index in 0..other_referrers {
            let other = make_entity(&format!("unrelated_{index}"), &format!("src/u_{index}.rs"));
            let other_id = other.id;
            graph.upsert_entity(&other).unwrap();
            graph
                .upsert_relation(&make_relation(other_id, hub_id, RelationKind::References))
                .unwrap();
        }
        (graph, focal_id)
    }

    fn traced(graph: &InMemoryGraph, request: &TraceDataFlowRequest) -> TraceDataFlowResponse {
        let (_temp, binding) = empty_binding();
        build_trace_data_flow_response_within(
            &RequestRepositoryAuthority::pinned(binding),
            graph,
            request,
            TraceBudget::default(),
        )
        .unwrap()
    }

    /// The defect, at the reported parameters: `depth: 2`, `limit_per_step: 8`,
    /// `direction: "both"`.
    #[test]
    fn an_external_annotation_hub_is_a_leaf_and_its_referrers_never_enter_the_chain() {
        let (graph, focal_id) = annotation_hub_graph(44);
        let mut request = trace_request(&focal_id, 2, TraceDirection::Both, 8);
        request.include_body = Some(false);

        let response = traced(&graph, &request);

        let names = step_names(&response);
        assert_eq!(
            names,
            vec!["Any".to_string()],
            "the chain must end at the file-less hub; it reached {names:?}"
        );
        assert!(
            !names.iter().any(|name| name.starts_with("unrelated_")),
            "no referrer of an external hub belongs in a data-flow chain: {names:?}"
        );
        let hub = &response.chain[0];
        assert_eq!(hub.terminal.as_deref(), Some("external_reference"));
        assert_eq!(
            hub.fanout_dropped, 0,
            "a node that was never expanded dropped no neighbors; reporting a \
             count here would send a caller re-querying with a wider limit for \
             nothing"
        );
        assert!(response.clipped_steps.is_empty());
        assert_eq!(response.terminal_external_steps, 1);
        assert_eq!(response.terminal_annotation_steps, 0);
        assert!(
            !response.truncated,
            "a boundary is not a truncation: the chain ends at Any, it was not cut short of it"
        );
    }

    /// The before number, from the same fixture with the gate removed. Guards
    /// the fixture itself: if `annotation_hub_graph` stopped reproducing the
    /// hub, the assertion above would pass for the wrong reason.
    #[test]
    fn the_same_hub_without_the_gate_fills_the_chain_with_unrelated_entities() {
        let (graph, focal_id) = annotation_hub_graph(44);
        let mut request = trace_request(&focal_id, 2, TraceDirection::Both, 8);
        request.include_body = Some(false);
        // What the walk did before the terminal gate: the hub is admitted and
        // then expanded, and its inbound half spends the whole step budget.
        request.include_type_edges = Some(true);

        let response = traced(&graph, &request);

        assert_eq!(
            response.total_steps,
            1,
            "include_type_edges must not reopen an EXTERNAL target: {:?}",
            step_names(&response)
        );
        assert_eq!(
            response.chain[0].terminal.as_deref(),
            Some("external_reference"),
            "no parameter makes a symbol this repository does not define walkable"
        );
    }

    /// A same-repo type is a different case from a stdlib one, and the
    /// difference is the whole reason the gate is a parameter rather than a
    /// rule: a field typed with a repo class is a real flow into that class.
    fn repo_type_graph() -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("ParsedNote", "src/notes.rs");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();

        let repo_type = make_entity("WikiLink", "src/links.rs");
        let repo_type_id = repo_type.id;
        graph.upsert_entity(&repo_type).unwrap();
        graph
            .upsert_relation(&make_relation(
                focal_id,
                repo_type_id,
                RelationKind::UsesType,
            ))
            .unwrap();

        let beyond = make_entity("normalize_target", "src/links.rs");
        let beyond_id = beyond.id;
        graph.upsert_entity(&beyond).unwrap();
        graph
            .upsert_relation(&make_relation(repo_type_id, beyond_id, RelationKind::Calls))
            .unwrap();
        (graph, focal_id)
    }

    #[test]
    fn a_repo_defined_annotation_target_is_a_named_leaf_by_default() {
        let (graph, focal_id) = repo_type_graph();
        let mut request = trace_request(&focal_id, 3, TraceDirection::Calls, 8);
        request.include_body = Some(false);

        let response = traced(&graph, &request);

        assert_eq!(step_names(&response), vec!["WikiLink".to_string()]);
        assert_eq!(response.chain[0].relation_kind, "UsesType");
        assert_eq!(
            response.chain[0].terminal.as_deref(),
            Some("type_annotation")
        );
        assert_eq!(response.terminal_annotation_steps, 1);
        assert_eq!(response.terminal_external_steps, 0);
        assert!(!response.include_type_edges);
        assert!(
            !response.truncated,
            "declining a type hop is not a cut: the caller has every step the default walk means"
        );
    }

    #[test]
    fn a_repo_defined_annotation_target_is_walkable_on_request() {
        let (graph, focal_id) = repo_type_graph();
        let mut request = trace_request(&focal_id, 3, TraceDirection::Calls, 8);
        request.include_body = Some(false);
        request.include_type_edges = Some(true);

        let response = traced(&graph, &request);

        assert_eq!(
            step_names(&response),
            vec!["WikiLink".to_string(), "normalize_target".to_string()],
            "a field typed with a repo class flows into it, so the hop continues"
        );
        assert_eq!(
            response.chain[0].terminal, None,
            "the annotation gate opened, so the type is an ordinary step"
        );
        assert_eq!(response.terminal_annotation_steps, 0);
        assert!(response.include_type_edges);
        // The fixture's only call edge sits inside one file, so the walk cannot
        // certify the hop past `normalize_target` as absent. Asserted rather
        // than ignored: this is the FIR-2353 graph shape, and a walk that
        // reported a leaf here would be making exactly the claim FIR-2542 is
        // about.
        assert_eq!(
            response.chain[1].terminal.as_deref(),
            Some("coverage_gap"),
            "no cross-file call edge exists in this fixture, so an empty read proves nothing"
        );
    }

    /// The CLI parses this payload from whatever daemon is already running, and
    /// a daemon started before this parameter existed answers without the key.
    /// A required field would turn that ordinary upgrade window into a failed
    /// call rather than a chain.
    #[test]
    fn a_payload_from_a_daemon_that_never_had_the_parameter_still_parses() {
        let graph = InMemoryGraph::new();
        let focal = make_entity("send", "src/sessions.rs");
        let focal_id = focal.id;
        graph.upsert_entity(&focal).unwrap();
        let mut request = trace_request(&focal_id, 1, TraceDirection::Calls, 5);
        request.include_body = Some(false);
        let response = traced(&graph, &request);

        let mut payload = serde_json::to_value(&response).unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .remove("include_type_edges")
            .expect("the fixture must carry the key or its removal proves nothing");

        let parsed: TraceDataFlowResponse = serde_json::from_value(payload)
            .expect("a response without include_type_edges must still deserialize");
        assert!(
            !parsed.include_type_edges,
            "a daemon that never had the parameter never walked a type edge"
        );
    }

    /// An ordinary chain must be untouched by the external and annotation
    /// gates, or the fix would have bought correctness with coverage.
    #[test]
    fn an_ordinary_call_chain_reports_no_boundary_terminal_at_all() {
        let (graph, focal_id) = call_chain(&[
            ("send", "src/sessions.rs"),
            ("resolve_redirects", "src/adapters.rs"),
            ("rebuild_method", "src/models.rs"),
        ]);

        let mut request = trace_request(&focal_id, 3, TraceDirection::Calls, 8);
        request.include_body = Some(false);
        let response = traced(&graph, &request);

        assert_eq!(response.total_steps, 2);
        assert_eq!(response.terminal_external_steps, 0);
        assert_eq!(response.terminal_annotation_steps, 0);
        // Present as an explicit key on every step, never omitted: one array
        // holding two key sets is the shape `every_step_carries_the_same_keys`
        // exists to bar.
        let json = serde_json::to_value(&response).unwrap();
        for step in json["chain"].as_array().unwrap() {
            assert!(
                step.as_object().unwrap().contains_key("terminal"),
                "every step carries the key whatever its value: {step}"
            );
        }
        // The middle of a chain is an ordinary step and says nothing.
        assert_eq!(response.chain[0].terminal, None);
    }

    /// Three entities in the given files, each calling the next, and the id of
    /// the first. A chain that crosses files is a linked graph and carries the
    /// witness pair that proves every class links across files, which is the
    /// fact a leaf terminal rests on; a chain inside one file, or a lone
    /// entity, is a graph that never linked anything.
    fn call_chain(nodes: &[(&str, &str)]) -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let distinct_files: BTreeSet<&str> = nodes.iter().map(|(_, file)| *file).collect();
        if distinct_files.len() >= 2 {
            seed_cross_file_witness(&graph, "py");
        }
        let entities: Vec<Entity> = nodes
            .iter()
            .map(|(name, file)| make_entity(name, file))
            .collect();
        for entity in &entities {
            graph.upsert_entity(entity).unwrap();
        }
        for pair in entities.windows(2) {
            graph
                .upsert_relation(&make_relation(pair[0].id, pair[1].id, RelationKind::Calls))
                .unwrap();
        }
        (graph, entities[0].id)
    }

    fn terminals(response: &TraceDataFlowResponse) -> Vec<Option<&str>> {
        response
            .chain
            .iter()
            .map(|step| step.terminal.as_deref())
            .collect()
    }

    /// The positive control for the whole ticket. A chain that ran out of code
    /// on a graph that links calls across files says so, and says it without
    /// claiming a shortfall.
    #[test]
    fn a_chain_that_ran_out_of_code_reports_a_leaf_and_no_shortfall() {
        let (graph, focal_id) = call_chain(&[
            ("cert_verify", "src/adapters.py"),
            ("send", "src/sessions.py"),
            ("request", "src/api.py"),
        ]);
        let mut request = trace_request(&focal_id, 5, TraceDirection::Calls, 15);
        request.include_body = Some(false);
        let response = traced(&graph, &request);

        assert_eq!(response.total_steps, 2, "the fixture must produce a chain");
        assert_eq!(
            terminals(&response),
            vec![None, Some("leaf")],
            "only the last hop ended, and it ended because the code ends"
        );
        assert_eq!(response.terminal_leaf_steps, 1);
        assert_eq!(response.terminal_bound_steps, 0);
        assert_eq!(response.terminal_coverage_gap_steps, 0);
        assert!(
            !response.truncated,
            "a walk that reached the end of the code received the whole chain"
        );
        assert_eq!(
            response.focal_terminal, None,
            "the focal had a neighbor, so it is not an end of any kind"
        );
        // The observation the leaf rests on travels with the answer, so the
        // envelope's absence gate reads a measured class instead of reporting
        // that nothing was measured.
        let coverage = response
            .edge_coverage
            .as_ref()
            .expect("a walk must publish the coverage its terminals rest on");
        assert_eq!(
            coverage["classes"]["calls"],
            serde_json::json!("present"),
            "the fixture links calls across files: {coverage}"
        );
    }

    /// The defect's own shape, in the smallest graph that has it: every call
    /// edge sits inside one file, so an empty read cannot be told apart from a
    /// graph that could never have held the next hop.
    #[test]
    fn a_chain_that_stopped_on_an_unlinked_graph_reports_a_coverage_gap() {
        let (graph, focal_id) = call_chain(&[
            ("cert_verify", "src/one.py"),
            ("send", "src/one.py"),
            ("request", "src/one.py"),
        ]);
        let mut request = trace_request(&focal_id, 5, TraceDirection::Calls, 15);
        request.include_body = Some(false);
        let response = traced(&graph, &request);

        assert_eq!(response.total_steps, 2, "the fixture must produce a chain");
        assert_eq!(
            terminals(&response),
            vec![None, Some("coverage_gap")],
            "the walk cannot know whether this hop was the last one"
        );
        assert_eq!(response.terminal_coverage_gap_steps, 1);
        assert_eq!(response.terminal_leaf_steps, 0);
        assert!(
            response.truncated,
            "an answer the graph could not have completed is not a complete answer"
        );
        let coverage = response.edge_coverage.as_ref().expect("published");
        assert_eq!(
            coverage["classes"]["calls"],
            serde_json::json!("absent"),
            "the fixture holds no cross-file call edge: {coverage}"
        );
    }

    /// The third state. A node whose relations were never read is not a leaf on
    /// any graph, however well linked, and the caller has a number to raise.
    #[test]
    fn a_chain_cut_by_the_depth_bound_reports_a_bound_and_not_a_leaf() {
        let (graph, focal_id) = call_chain(&[
            ("cert_verify", "src/adapters.py"),
            ("send", "src/sessions.py"),
            ("request", "src/api.py"),
        ]);
        let mut request = trace_request(&focal_id, 2, TraceDirection::Calls, 15);
        request.include_body = Some(false);
        let response = traced(&graph, &request);

        assert_eq!(response.total_steps, 2, "the fixture must produce a chain");
        assert_eq!(
            terminals(&response),
            vec![None, Some("bound_reached")],
            "the last hop sits at the requested depth and was never expanded"
        );
        assert_eq!(response.terminal_bound_steps, 1);
        assert_eq!(response.terminal_leaf_steps, 0);
        assert_eq!(response.terminal_coverage_gap_steps, 0);
        assert!(
            response.truncated,
            "a chain the caller can lengthen by raising depth is truncated"
        );
        // Same graph, same focal, one more level of depth: the identical last
        // entity now reads as an end rather than as a cut. Without this the
        // bound arm could be passing because the fixture has no third hop.
        let mut deeper = trace_request(&focal_id, 5, TraceDirection::Calls, 15);
        deeper.include_body = Some(false);
        let opened = traced(&graph, &deeper);
        assert_eq!(terminals(&opened), vec![None, Some("leaf")]);
        assert!(!opened.truncated);
    }

    /// An empty chain is the answer whose trust depends most on why it is
    /// empty, and the focal has no row in `chain` to say so on.
    #[test]
    fn an_empty_chain_says_why_it_is_empty() {
        // A lone entity on a graph that links nothing: nothing was found, and
        // nothing could have been.
        let (unlinked, alone) = call_chain(&[("cert_verify", "src/one.py")]);
        let mut request = trace_request(&alone, 3, TraceDirection::Calls, 15);
        request.include_body = Some(false);
        let blind = traced(&unlinked, &request);
        assert_eq!(blind.total_steps, 0);
        assert_eq!(blind.focal_terminal.as_deref(), Some("coverage_gap"));
        assert!(
            blind.truncated,
            "an empty chain on a graph holding no cross-file calls is not a proven absence"
        );

        // The same empty answer on a graph that demonstrably links calls across
        // files. Now the emptiness is a fact about the code.
        let (linked, _) = call_chain(&[("send", "src/a.py"), ("request", "src/b.py")]);
        let lone = make_entity("cert_verify", "src/c.py");
        linked.upsert_entity(&lone).unwrap();
        let mut request = trace_request(&lone.id, 3, TraceDirection::Calls, 15);
        request.include_body = Some(false);
        let certain = traced(&linked, &request);
        assert_eq!(certain.total_steps, 0);
        assert_eq!(
            certain.focal_terminal.as_deref(),
            Some("leaf"),
            "the same empty chain, on a graph that can tell empty from blind"
        );
        assert!(!certain.truncated);
    }

    /// A node whose only neighbors are already in the chain has neighbors. A
    /// counter placed after the visited filter would call it a leaf and claim
    /// the code ends where the walk merely stopped repeating itself.
    #[test]
    fn a_cycle_back_into_the_chain_is_not_a_leaf() {
        let (graph, focal_id) = call_chain(&[
            ("send", "src/sessions.py"),
            ("resolve_redirects", "src/adapters.py"),
        ]);
        graph
            .upsert_relation(&make_relation(
                graph
                    .query_entities(&kin_model::graph::EntityFilter::default())
                    .unwrap()
                    .iter()
                    .find(|entity| entity.name == "resolve_redirects")
                    .unwrap()
                    .id,
                focal_id,
                RelationKind::Calls,
            ))
            .unwrap();

        let mut request = trace_request(&focal_id, 5, TraceDirection::Calls, 15);
        request.include_body = Some(false);
        let response = traced(&graph, &request);

        assert_eq!(response.total_steps, 1);
        assert_eq!(
            terminals(&response),
            vec![None],
            "its one neighbor is the focal, which the response already carries"
        );
        assert!(!response.truncated);
    }
}

#[cfg(test)]
mod boundary_and_ranking_tests {
    //! FIR-2642, from the rc0550 brown stranger run. Two halves of one
    //! contract: Kin must say where the in-repo graph ends and name the
    //! crossing.
    //!
    //! Half one. `trace_data_flow(HTTPAdapter.send, direction=calls, depth=3,
    //! limit_per_step=12)` spent nine of its twelve depth-1 slots on exception
    //! classes, which are `raise` targets in `except` blocks and not data flow
    //! at all. They crowded out the hop that governs connection reuse, and the
    //! stranger's verdict was that the Kin arm trusted alone writes a wrong
    //! answer. The edge was in the graph; the failure is ranking.
    //!
    //! Half two. `router.handle` is an external node connected to nothing. The
    //! graph knows a boundary exists and says nothing about the other side, so
    //! a reader cannot tell an npm package from a builtin from a typo.

    use super::tests::{empty_binding, make_entity, make_external_entity, step_names};
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::relation::{Relation, RelationEvidence, RelationOrigin};
    use kin_model::{EntityKind, GraphNodeId, RelationId, RelationKind};

    /// An ordinary call: the kind of edge a data-flow walk is following.
    fn call(src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    /// A call the parser read as the operand of a `raise`, which is a throw
    /// site rather than a hop the value travels along.
    fn raise_call(src: EntityId, dst: EntityId) -> Relation {
        let mut relation = call(src, dst);
        relation.evidence = vec![RelationEvidence {
            parser_rule: Some(kin_index::RAISE_TARGET_CALL_RULE.to_string()),
            ..RelationEvidence::default()
        }];
        relation
    }

    /// The second call edge a repository with a language server carries for
    /// every resolved call: it says the call exists and nothing about the
    /// syntax, because an LSP call hierarchy cannot see a `raise`.
    fn lsp_call(src: EntityId, dst: EntityId) -> Relation {
        let mut relation = call(src, dst);
        relation.origin = RelationOrigin::Lsp;
        relation.evidence = vec![RelationEvidence {
            parser_rule: Some("lsp_call_hierarchy".to_string()),
            ..RelationEvidence::default()
        }];
        relation
    }

    fn exception_class(name: &str, file: &str) -> Entity {
        let mut entity = make_entity(name, file);
        entity.kind = EntityKind::Class;
        entity
    }

    /// The measured shape: everything in ONE file, as `psf/requests` has it,
    /// where `HTTPAdapter.send` and the exceptions it throws share
    /// `adapters.py` and locality decides nothing.
    ///
    /// Three candidates, so both terms that matter are exercised. `pool_key` is
    /// a Function and wins on declaration kind, which is what actually delivers
    /// "data flow above throw sites" on real bytes. `Retryer` is a Class the
    /// focal calls ordinarily, and it is the only candidate the raise marker
    /// itself decides against: alike in every other term, so if the marker goes
    /// inert, `SSLError` outranks it on name length alone.
    fn raise_crowding_graph() -> (InMemoryGraph, EntityId) {
        let graph = InMemoryGraph::new();
        let focal = make_entity("Adapter.send", "pkg/adapters.py");
        let ssl_error = exception_class("SSLError", "pkg/adapters.py");
        let proxy_error = exception_class("ProxyError", "pkg/adapters.py");
        let retryer = exception_class("Retryer", "pkg/adapters.py");
        let pool_key = make_entity("build_pool_key", "pkg/adapters.py");

        for entity in [&focal, &ssl_error, &proxy_error, &retryer, &pool_key] {
            graph.upsert_entity(entity).unwrap();
        }
        for relation in [
            raise_call(focal.id, ssl_error.id),
            raise_call(focal.id, proxy_error.id),
            call(focal.id, retryer.id),
            call(focal.id, pool_key.id),
        ] {
            graph.upsert_relation(&relation).unwrap();
        }
        (graph, focal.id)
    }

    /// Where each name landed in the fan-out, so a test can assert an ORDER
    /// rather than only a membership.
    fn rank_of(names: &[String], wanted: &str) -> usize {
        names
            .iter()
            .position(|name| name == wanted)
            .unwrap_or_else(|| panic!("{wanted} is not in the walk: {names:?}"))
    }

    #[test]
    fn a_raise_target_does_not_take_a_slot_from_a_data_flow_hop() {
        let (graph, focal) = raise_crowding_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(2),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let names = step_names(&response);
        assert_eq!(
            names,
            vec!["build_pool_key".to_string(), "Retryer".to_string()],
            "two slots go to the hop the value travels through and to the \
             class the focal actually constructs; a throw site takes neither. \
             Got {names:?}"
        );
    }

    #[test]
    fn a_raise_target_is_still_reported_when_the_budget_allows_it() {
        // The recall half. Demoting a raise target orders it last; it must
        // never drop it, because "what does this throw" is a real question and
        // the edge is real evidence.
        let (graph, focal) = raise_crowding_graph();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(8),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let names = step_names(&response);
        for expected in ["build_pool_key", "Retryer", "SSLError", "ProxyError"] {
            assert!(
                names.iter().any(|n| n == expected),
                "a wide enough step reports every callee including the throw \
                 sites; ranking may reorder and must not remove. Missing \
                 {expected} from {names:?}"
            );
        }
        assert!(
            rank_of(&names, "Retryer") < rank_of(&names, "SSLError"),
            "and the throw sites sit below the class the focal constructs, \
             which is the one comparison the raise marker decides. Got {names:?}"
        );
        assert_eq!(
            names.first().map(String::as_str),
            Some("build_pool_key"),
            "and the data-flow hop leads, so a reader who stops at the first \
             row stops on the one that carries the value. Got {names:?}"
        );
    }

    /// A relation that is a mention rather than a call, which is what a real
    /// store carries beside a call edge and what a hand-built fixture had never
    /// had.
    fn reference(src: EntityId, dst: EntityId) -> Relation {
        let mut relation = call(src, dst);
        relation.kind = RelationKind::References;
        relation
    }

    /// FIR-2642. A reference edge beside the raise must not undo the demotion.
    ///
    /// This is the defect a hand-built fixture could not see. The flag was
    /// folded with `&&` across every edge, so whichever edge happened to create
    /// the candidate set its starting value and one non-call edge arriving
    /// first left it false forever. On a converted `psf/requests` that was
    /// every exception class in `HTTPAdapter.send`'s fan-out: the demotion
    /// never fired on the corpus it was written from, and inverting the whole
    /// ranking signal changed the answer not at all, which is the definition of
    /// a check that cannot fail.
    #[test]
    fn a_reference_edge_beside_the_raise_does_not_promote_a_throw_site() {
        let graph = InMemoryGraph::new();
        let focal = make_entity("Adapter.send", "pkg/adapters.py");
        let ssl_error = exception_class("SSLError", "pkg/adapters.py");
        let retryer = exception_class("Retryer", "pkg/adapters.py");
        for entity in [&focal, &ssl_error, &retryer] {
            graph.upsert_entity(entity).unwrap();
        }
        // The reference edge is upserted FIRST, which is the order that made
        // the fold answer wrong.
        for relation in [
            reference(focal.id, ssl_error.id),
            raise_call(focal.id, ssl_error.id),
            call(focal.id, retryer.id),
        ] {
            graph.upsert_relation(&relation).unwrap();
        }
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.id.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(1),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let names = step_names(&response);
        assert_eq!(
            names.first().map(String::as_str),
            Some("Retryer"),
            "one slot, and it belongs to the class the focal constructs rather than the one it \
             throws; a mention of the exception class is not a reason to promote a throw site. \
             Got {names:?}"
        );
    }

    /// FIR-2642, and the reason this whole signal was dead on real bytes. Every
    /// resolved call on a repository with a language server reaches the graph
    /// twice, once from the parser and once from the LSP call hierarchy, and
    /// only the parser can see a `raise`. Letting the LSP edge vote made "every
    /// call edge is a raise" false for every candidate, so the demotion never
    /// once fired on the corpus it was written from and inverting the ranking
    /// changed nothing.
    ///
    /// Measured on a converted `psf/requests`: `SSLError` arrived on
    /// `[Inferred, raise_target_call]` and `[Lsp, lsp_call_hierarchy]`, one of
    /// two, so the rule read false.
    #[test]
    fn a_language_server_edge_does_not_get_a_vote_on_what_a_raise_is() {
        let graph = InMemoryGraph::new();
        let focal = make_entity("Adapter.send", "pkg/adapters.py");
        let ssl_error = exception_class("SSLError", "pkg/adapters.py");
        let retryer = exception_class("Retryer", "pkg/adapters.py");
        for entity in [&focal, &ssl_error, &retryer] {
            graph.upsert_entity(entity).unwrap();
        }
        for relation in [
            raise_call(focal.id, ssl_error.id),
            lsp_call(focal.id, ssl_error.id),
            call(focal.id, retryer.id),
            lsp_call(focal.id, retryer.id),
        ] {
            graph.upsert_relation(&relation).unwrap();
        }
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.id.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(1),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let names = step_names(&response);
        assert_eq!(
            names.first().map(String::as_str),
            Some("Retryer"),
            "the one slot belongs to the class the focal constructs; an LSP edge that cannot see \
             a `raise` must not vote the throw site back level with it. Got {names:?}"
        );
    }

    /// The other direction, so the rule is about calls and not about counting
    /// edges. A class the focal both raises AND constructs normally is on the
    /// data path, and demoting it would cost the recall the marker exists to
    /// protect.
    #[test]
    fn a_class_that_is_also_constructed_normally_is_not_a_throw_site() {
        let graph = InMemoryGraph::new();
        let focal = make_entity("Adapter.send", "pkg/adapters.py");
        let both = exception_class("Retry", "pkg/adapters.py");
        let elsewhere = make_entity("build_pool_key", "pkg/pool.py");
        for entity in [&focal, &both, &elsewhere] {
            graph.upsert_entity(entity).unwrap();
        }
        for relation in [
            raise_call(focal.id, both.id),
            call(focal.id, both.id),
            call(focal.id, elsewhere.id),
        ] {
            graph.upsert_relation(&relation).unwrap();
        }
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.id.to_string(),
                depth: Some(2),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(1),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let names = step_names(&response);
        assert_eq!(
            names.first().map(String::as_str),
            Some("Retry"),
            "same file beats another directory once the throw-site demotion no \
             longer applies, and it must not apply to a class that is also \
             called for its value. Got {names:?}"
        );
    }

    #[test]
    fn an_external_step_names_the_module_it_crosses_into() {
        // Half two. `router.handle` reached through `require('router')` must
        // say `router`, so a reader can tell an npm package from a builtin
        // from a typo without leaving the tool.
        let graph = InMemoryGraph::new();
        let focal = make_entity("app.handle", "lib/application.js");
        let external = make_external_entity("router.handle");
        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&external).unwrap();
        let mut relation = call(focal.id, external.id);
        relation.import_source = Some("router".to_string());
        graph.upsert_relation(&relation).unwrap();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(8),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let step = response
            .chain
            .iter()
            .find(|s| s.entity.entity_name == "router.handle")
            .expect("the external step is in the chain");
        assert!(step.entity.external, "the fixture's premise");
        let crossing = step
            .entity
            .crossing
            .as_ref()
            .expect("an external record must carry a crossing, known or not");
        assert_eq!(
            crossing.specifier.as_deref(),
            Some("router"),
            "the graph holds the specifier the importing file named, so the \
             answer must say it rather than emit a bare external symbol"
        );
    }

    #[test]
    fn an_external_step_the_graph_cannot_place_says_so_rather_than_going_quiet() {
        // The disclosure half, and the one that matters more. With import
        // edges absent the graph genuinely does not know what is on the other
        // side. Saying nothing reads as an in-repo symbol; saying "unknown"
        // reads as a boundary, which is the truth.
        let graph = InMemoryGraph::new();
        let focal = make_entity("app.handle", "lib/application.js");
        let external = make_external_entity("router.handle");
        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&external).unwrap();
        graph.upsert_relation(&call(focal.id, external.id)).unwrap();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(8),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let step = response
            .chain
            .iter()
            .find(|s| s.entity.entity_name == "router.handle")
            .expect("the external step is in the chain");
        let crossing = step
            .entity
            .crossing
            .as_ref()
            .expect("an external record carries a crossing even when unknown");
        assert_eq!(
            crossing.specifier, None,
            "the graph holds no specifier here, so inventing one would be worse \
             than the silence it replaces"
        );
        assert_eq!(
            crossing.status, "unknown",
            "and the record must say the boundary is unplaced rather than \
             leave a bare symbol that reads like an in-repo entity"
        );
    }

    #[test]
    fn an_in_repo_step_carries_no_crossing_at_all() {
        // The bound. A crossing on a step the repository owns would be a
        // boundary that is not there, and every reader would learn to ignore
        // the field.
        let graph = InMemoryGraph::new();
        let focal = make_entity("app.handle", "lib/application.js");
        let local = make_entity("app.route", "lib/application.js");
        graph.upsert_entity(&focal).unwrap();
        graph.upsert_entity(&local).unwrap();
        graph.upsert_relation(&call(focal.id, local.id)).unwrap();
        let (_t, binding) = empty_binding();

        let response = build_trace_data_flow_response(
            &RequestRepositoryAuthority::pinned(binding),
            &graph,
            &TraceDataFlowRequest {
                focal: focal.id.to_string(),
                depth: Some(1),
                direction: Some(TraceDirection::Calls),
                limit_per_step: Some(8),
                include_body: Some(false),
                max_response_chars: None,
                include_type_edges: None,
                target: None,
            },
        )
        .unwrap();

        let step = response
            .chain
            .iter()
            .find(|s| s.entity.entity_name == "app.route")
            .expect("the local step is in the chain");
        assert!(!step.entity.external, "the fixture's premise");
        assert!(
            step.entity.crossing.is_none(),
            "a step the repository owns crosses nothing"
        );
    }
}
