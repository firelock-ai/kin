// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `trace_path`: the route from one entity to another over the relation graph.
//!
//! Every other query in Kin is rooted at one entity. `trace_data_flow` walks out
//! from a focal, `find_references` walks in, `get_context_pack` packs one
//! neighbourhood, and `impact_analysis` fans out from a change. The ordinary
//! shape of a code question is a route between two named things, "how does an
//! edit typed into the editor reach the text model", and a single-rooted walk
//! sits at one end of that chain and never meets the other (FIR-3070). This
//! walker answers that question in one call: it resolves both ends, runs a
//! breadth-first search from the source over the reference edges the graph
//! records, and returns up to K shortest routes with every hop named, located
//! and joined to the next by the relation the graph holds.
//!
//! One implementation serves three surfaces. The module is generic over
//! [`GraphStore`], so the offline MCP arm, the daemon's `/commands/path` route
//! and the daemon-served MCP tool all run this code, and `kin path` is a client
//! of the daemon route. The crates sit in that order (this one under `kin-cli`
//! under `kin-daemon`), which is why the walker lives here rather than beside
//! `trace_data_flow`'s CLI arm.
//!
//! A class stands for its members. Each endpoint expands downward over
//! `Contains` edges before the walk starts, so a route between two classes runs
//! through the methods that carry it and is reported with those containment
//! hops in place. The expansion goes down only: walking up from a method to its
//! class and down to a sibling would claim that the method reaches whatever its
//! sibling reaches, which is not a route the code has.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kin_index::RelationResolution;
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::ids::EntityId;
use kin_model::relation::Relation;
use kin_model::{Entity, RelationKind};
use serde::{Deserialize, Serialize};

use crate::error::{McpError, Result};
use crate::handlers::common::{
    get_optional_string_param, get_string_param, presentation_line, presentation_span_lines,
    ReferenceLinesAbsent,
};
use crate::types::ToolCallResult;

/// The MCP tool name, and the name every registry keyed by tool uses for it.
pub const TOOL_NAME: &str = "trace_path";

/// Written for a small model: the first sentence says when to call it.
pub const TRACE_PATH_DESC: &str = "\
Call this when the question is how one thing reaches another: it returns the shortest \
routes from entity A to entity B over the graph's call, instantiation, reference, import \
and include edges, every hop named with its kind, file and line and the relation that \
joins it to the next hop, in one call. Address each end by exact name, by entity id, or by \
name@file to pin one of two same-named entities. A class stands for its members, so a \
route between two classes runs through the methods that carry it. `direction` defaults to \
`either`: the forward sense (A reaches B) is tried first, and the answer says which sense \
held. When no route exists the answer says so with `found: false`, a `gap` naming what \
stopped the walk and how much of the graph it explored, and the same-name twin count on \
each end, so read `_kin.verdict` before concluding that A never reaches B.";

const DEFAULT_MAX_DEPTH: usize = 6;
// The one number the schema declares and the gap's advice quotes.
const MAX_MAX_DEPTH: usize = crate::remediation::PATH_MAX_MAX_DEPTH;
const DEFAULT_LIMIT: usize = 3;
const MAX_LIMIT: usize = 25;
/// Relations examined before the walk stops regardless of the clock, so a
/// pathological fan-out is cut at the same place every run.
const DEFAULT_MAX_EDGES_SCANNED: usize = 250_000;
/// Wall-clock ceiling for one call, both senses included.
const DEFAULT_TIME_BUDGET: Duration = Duration::from_secs(10);
/// How far an endpoint expands over `Contains` edges, and how many members it
/// may stand for. A module names every declaration it holds; past the cap the
/// endpoint is disclosed as partial rather than silently narrowed.
const CONTAINMENT_DEPTH: usize = 4;
const CONTAINMENT_CAP: usize = 5_000;
const OTHER_CANDIDATES_SHOWN: usize = 5;
/// Shortest routes counted before the count itself is reported as a floor.
const ROUTE_COUNT_CEILING: usize = 1_000;

/// The edge classes a cross-file coverage observation is measured against,
/// the same three every other reference query declares.
const REFERENCE_KINDS: [RelationKind; 3] = [
    RelationKind::Calls,
    RelationKind::Imports,
    RelationKind::References,
];

/// Which way a route may run between the two ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathDirection {
    /// `from` reaches `to`: every edge runs from the source side to the target side.
    Forward,
    /// `to` reaches `from`.
    Reverse,
    /// Forward first; reverse only when forward finds nothing. The answer says
    /// which sense held.
    #[default]
    Either,
}

impl PathDirection {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "forward" | "out" | "outgoing" => Ok(Self::Forward),
            "reverse" | "back" | "backward" | "backwards" | "in" | "incoming" => Ok(Self::Reverse),
            "either" | "any" | "both" | "" => Ok(Self::Either),
            other => Err(format!(
                "invalid direction '{other}': expected forward, reverse, or either"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Reverse => "reverse",
            Self::Either => "either",
        }
    }
}

/// One sense of a walk. Both walk outgoing edges; they differ in which end is
/// the seed set, so a reverse route is listed from `to` to `from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sense {
    Forward,
    Reverse,
}

impl Sense {
    fn as_str(self) -> &'static str {
        match self {
            Sense::Forward => "forward",
            Sense::Reverse => "reverse",
        }
    }
}

/// Request shape for the route query, shared by the CLI, the daemon route and
/// the MCP tool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathRequest {
    /// Source end: an entity uuid, an exact name, or `name@file`.
    pub from: String,
    /// Target end, in the same forms.
    pub to: String,
    /// Pins `from` to the entity of that name whose file matches this path or
    /// path suffix. The `name@file` spelling is the same request.
    #[serde(default)]
    pub from_file: Option<String>,
    #[serde(default)]
    pub to_file: Option<String>,
    /// Hops walked between the two endpoint closures (default 6, ceiling 12).
    /// Containment hops that join a class to its members are not counted.
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Routes returned (default 3, ceiling 25). Shortest first.
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub direction: Option<PathDirection>,
    /// Walk through `UsesType` edges too (default false). Off for the reason
    /// `trace_data_flow` keeps it off: a shared type name joins every entity that
    /// annotates with it to every other one.
    #[serde(default)]
    pub include_type_edges: Option<bool>,
}

/// A caller's standing answer to "does anyone still want this result?".
#[derive(Debug, Clone, Default)]
pub struct PathCancel(Arc<AtomicBool>);

impl PathCancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Work ceilings for one call.
#[derive(Debug, Clone)]
pub struct PathBudget {
    pub max_edges: usize,
    pub time: Duration,
    cancel: Option<PathCancel>,
}

impl Default for PathBudget {
    fn default() -> Self {
        Self {
            max_edges: DEFAULT_MAX_EDGES_SCANNED,
            time: DEFAULT_TIME_BUDGET,
            cancel: None,
        }
    }
}

impl PathBudget {
    /// Caller-supplied ceilings, so the bounds are testable at a scale a test
    /// can reach.
    pub fn bounded(max_edges: usize, time: Duration) -> Self {
        Self {
            max_edges,
            time,
            cancel: None,
        }
    }

    /// The shipped ceilings plus a cancellation flag the walk reads at every
    /// checkpoint.
    pub fn cancellable(cancel: PathCancel) -> Self {
        Self {
            cancel: Some(cancel),
            ..Self::default()
        }
    }
}

/// Why a walk stopped, in the vocabulary the response reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    RouteFound,
    FrontierExhausted,
    DepthBound,
    EdgeCeiling,
    TimeBudget,
    Cancelled,
}

impl Stop {
    fn as_str(self) -> &'static str {
        match self {
            Stop::RouteFound => "route_found",
            Stop::FrontierExhausted => "frontier_exhausted",
            Stop::DepthBound => "depth_bound",
            Stop::EdgeCeiling => "edge_ceiling",
            Stop::TimeBudget => "time_budget",
            Stop::Cancelled => "cancelled",
        }
    }

    /// A stop the walk did not choose: the frontier was not empty and the
    /// depth bound was not reached, so the answer is bounded by work rather
    /// than by the graph.
    fn is_ceiling(self) -> bool {
        matches!(self, Stop::EdgeCeiling | Stop::TimeBudget | Stop::Cancelled)
    }

    /// Ordered by how much of the answer the stop takes away, so a gap over two
    /// walks names the more limiting one.
    fn severity(self) -> u8 {
        match self {
            Stop::RouteFound => 0,
            Stop::FrontierExhausted => 1,
            Stop::DepthBound => 2,
            Stop::EdgeCeiling => 3,
            Stop::TimeBudget => 4,
            Stop::Cancelled => 5,
        }
    }
}

struct Meter {
    budget: PathBudget,
    started: Instant,
    edges: usize,
}

impl Meter {
    fn new(budget: PathBudget) -> Self {
        Self {
            budget,
            started: Instant::now(),
            edges: 0,
        }
    }

    fn charge_edge(&mut self) -> Option<Stop> {
        self.edges += 1;
        self.ceiling()
    }

    fn ceiling(&self) -> Option<Stop> {
        if self
            .budget
            .cancel
            .as_ref()
            .is_some_and(PathCancel::is_cancelled)
        {
            return Some(Stop::Cancelled);
        }
        if self.edges >= self.budget.max_edges {
            return Some(Stop::EdgeCeiling);
        }
        if self.started.elapsed() >= self.budget.time {
            return Some(Stop::TimeBudget);
        }
        None
    }
}

/// One entity the caller could have meant instead of the one chosen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCandidate {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    pub file: Option<String>,
    pub start_line: Option<u32>,
}

/// One end of the route as it was resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathEndpoint {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    pub file: Option<String>,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    /// True when the graph holds no file for this symbol.
    pub external: bool,
    /// `entity_id`, `name`, or `name_and_file`: which form the caller used, so
    /// a reader can tell a pinned end from one the ranking chose.
    pub addressed_by: String,
    /// Entities carrying exactly this name, the chosen one included. Above one
    /// and not pinned, an empty route set answers for one twin a question that
    /// was asked of any of them.
    pub same_name_candidates: usize,
    /// The other same-named entities, bounded, never including the chosen one,
    /// each addressable by id or by `name@file`.
    pub other_candidates: Vec<PathCandidate>,
    /// Members reached through `Contains` edges that stand for this end.
    pub members_expanded: usize,
}

/// One entity on a route, with the edge that joins it to the next hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHop {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    pub file: Option<String>,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub external: bool,
    /// Relation kind joining this hop to the next one; null on the last hop.
    pub relation: Option<String>,
    /// `outgoing` when the edge runs from this hop to the next, `incoming` when
    /// it runs from the next hop into this one (a member joined to the class
    /// that contains it); null on the last hop.
    pub edge: Option<String>,
    /// How the edge was resolved (`type_resolved`, `import_scoped`,
    /// `name_only`); null on containment hops and on the last hop. A route is
    /// only as trustworthy as its weakest hop.
    pub resolution: Option<String>,
    /// 1-based lines of the syntax that produced the edge, in the file of the
    /// edge's source entity. Empty when the graph carries no site for it.
    pub site_lines: Vec<u32>,
    /// Why `site_lines` is empty, in the vocabulary `find_references` uses
    /// (`no_evidence_span`, `span_outside_caller_file`), and null when at
    /// least one line is present or the hop carries no edge.
    pub site_lines_absent_reason: Option<String>,
}

/// One route, listed in the direction its edges run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRoute {
    /// `forward` (listed from `from` to `to`) or `reverse` (from `to` to `from`).
    pub direction: String,
    /// Edges in `steps`, containment hops included.
    pub hops: usize,
    /// Edges walked between the two endpoint closures, the number `max_depth`
    /// bounds.
    pub walked_hops: usize,
    pub steps: Vec<PathHop>,
}

/// What one walk covered and why it stopped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathExplored {
    pub sense: String,
    pub nodes: usize,
    pub edges: usize,
    pub depth_reached: usize,
    /// `route_found`, `frontier_exhausted`, `depth_bound`, `edge_ceiling`,
    /// `time_budget` or `cancelled`.
    pub stopped_by: String,
    pub elapsed_ms: u64,
}

/// Why no route came back, stated so that the absence can be acted on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathGap {
    /// The most limiting stop across the walks that ran.
    pub reason: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathDegradation {
    pub component: String,
    pub reason: String,
    pub detail: String,
    pub remediation: String,
}

/// The whole answer.
///
/// Every key is always serialized. The optional-on-read defaults exist because
/// the envelope annotator lifts some payload keys (`degradations` among them)
/// into `_kin` when it stamps a daemon answer, and the CLI reads that stamped
/// form back into this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathResponse {
    pub from: PathEndpoint,
    pub to: PathEndpoint,
    pub direction_requested: String,
    /// The sense the routes run in, null when none was found.
    #[serde(default)]
    pub direction: Option<String>,
    pub max_depth: usize,
    pub limit: usize,
    #[serde(default)]
    pub walked_kinds: Vec<String>,
    #[serde(default)]
    pub include_type_edges: bool,
    pub found: bool,
    #[serde(default)]
    pub routes: Vec<PathRoute>,
    /// Shortest routes that exist, of which `routes` holds the first `limit`.
    #[serde(default)]
    pub routes_total: usize,
    #[serde(default)]
    pub routes_truncated: bool,
    #[serde(default)]
    pub explored: Vec<PathExplored>,
    #[serde(default)]
    pub gap: Option<PathGap>,
    #[serde(default)]
    pub degradations: Vec<PathDegradation>,
    /// Whether the graph links references across files for the source end's
    /// language, the fact an absence rests on.
    #[serde(default)]
    pub edge_coverage: serde_json::Value,
}

/// What can go wrong before a walk starts.
#[derive(Debug)]
pub enum PathError {
    InvalidRequest(String),
    EndpointNotFound {
        which: &'static str,
        spec: String,
        detail: String,
    },
    EndpointAmbiguous {
        which: &'static str,
        spec: String,
        candidates: Vec<PathCandidate>,
    },
    Graph(String),
}

impl PathError {
    /// A miss on one of the two names, which the negative classifier reports
    /// as a resolution miss rather than as an absent route.
    pub fn is_resolution_miss(&self) -> bool {
        matches!(
            self,
            PathError::EndpointNotFound { .. } | PathError::EndpointAmbiguous { .. }
        )
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::InvalidRequest(message) => write!(f, "{message}"),
            PathError::EndpointNotFound {
                which,
                spec,
                detail,
            } => write!(f, "no entity found for {which} '{spec}': {detail}"),
            PathError::EndpointAmbiguous {
                which,
                spec,
                candidates,
            } => {
                write!(
                    f,
                    "{which} '{spec}' names {} entities; pin one by id or name@file:",
                    candidates.len()
                )?;
                for candidate in candidates {
                    write!(
                        f,
                        " [{} {} {}:{} {}]",
                        candidate.kind,
                        candidate.name,
                        candidate.file.as_deref().unwrap_or("<no file>"),
                        candidate
                            .start_line
                            .map(|line| line.to_string())
                            .unwrap_or_else(|| "?".to_string()),
                        candidate.entity_id
                    )?;
                }
                Ok(())
            }
            PathError::Graph(message) => write!(f, "graph store error: {message}"),
        }
    }
}

impl std::error::Error for PathError {}

fn graph_error<E: fmt::Display>(error: E) -> PathError {
    PathError::Graph(error.to_string())
}

/// The relation kinds a route may run over.
fn walked_kinds(include_type_edges: bool) -> Vec<RelationKind> {
    let mut kinds = vec![
        RelationKind::Calls,
        RelationKind::Instantiates,
        RelationKind::Imports,
        RelationKind::Includes,
        RelationKind::UsesMacro,
        RelationKind::References,
    ];
    if include_type_edges {
        kinds.push(RelationKind::UsesType);
    }
    kinds
}

/// Preference among several edges joining the same two hops: a call is a
/// stronger claim than a reference, so the route names the call.
fn kind_rank(kind: RelationKind) -> u8 {
    match kind {
        RelationKind::Calls => 0,
        RelationKind::Instantiates => 1,
        RelationKind::Imports => 2,
        RelationKind::Includes => 3,
        RelationKind::UsesMacro => 4,
        RelationKind::References => 5,
        RelationKind::UsesType => 6,
        _ => 7,
    }
}

fn kind_label(entity: &Entity) -> String {
    format!("{:?}", entity.kind)
}

fn span_lines(entity: &Entity) -> (Option<u32>, Option<u32>) {
    match entity.span.as_ref() {
        Some(span) => {
            let (start, end) = presentation_span_lines(span);
            (Some(start), Some(end))
        }
        None => (None, None),
    }
}

fn candidate_record(entity: &Entity) -> PathCandidate {
    PathCandidate {
        entity_id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: kind_label(entity),
        file: entity.file_origin.as_ref().map(|file| file.0.clone()),
        start_line: span_lines(entity).0,
    }
}

/// Deterministic order for a candidate list: file, then line, then id.
fn sort_candidates(list: &mut [Entity]) {
    list.sort_by(|a, b| {
        let file_a = a.file_origin.as_ref().map(|file| file.0.as_str());
        let file_b = b.file_origin.as_ref().map(|file| file.0.as_str());
        file_a
            .cmp(&file_b)
            .then_with(|| span_lines(a).0.cmp(&span_lines(b).0))
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// Entities carrying exactly `name`, in a stable order.
fn exact_name_matches<G: GraphStore>(
    store: &G,
    name: &str,
) -> std::result::Result<Vec<Entity>, PathError> {
    let filter = EntityFilter {
        name_pattern: Some(name.to_string()),
        ..Default::default()
    };
    let mut matches: Vec<Entity> = store
        .query_entities(&filter)
        .map_err(graph_error)?
        .into_iter()
        .filter(|entity| entity.name == name)
        .collect();
    sort_candidates(&mut matches);
    Ok(matches)
}

/// Whether `entity` lives in the file `hint` names: the exact path, a path
/// suffix (`sessions.py`, `requests/sessions.py`), or a longer path that ends
/// in the graph's relative one.
fn file_matches(entity: &Entity, hint: &str) -> bool {
    let Some(path) = entity.file_origin.as_ref() else {
        return false;
    };
    let path = path.0.replace('\\', "/");
    let hint = hint.trim().replace('\\', "/");
    let hint = hint.trim_start_matches("./");
    if hint.is_empty() {
        return false;
    }
    path == hint || path.ends_with(&format!("/{hint}")) || hint.ends_with(&format!("/{path}"))
}

/// `name@file` split at the last `@`, when both halves are present.
fn split_pinned(spec: &str) -> (&str, Option<&str>) {
    match spec.rsplit_once('@') {
        Some((name, file)) if !name.trim().is_empty() && !file.trim().is_empty() => {
            (name.trim(), Some(file.trim()))
        }
        _ => (spec, None),
    }
}

/// Among same-named candidates the caller already narrowed, the one `kin trace`
/// would choose: a body beats a declaration, then the file path, then the
/// start line, then the id (`kin_core::definition_identity_key`, FIR-3071).
/// Read off the entity records, so the same tree answers the same way in
/// every store built from it.
fn strongest_definition<G: GraphStore>(
    _store: &G,
    candidates: Vec<Entity>,
) -> std::result::Result<Entity, PathError> {
    candidates
        .into_iter()
        .min_by_key(kin_core::definition_identity_key)
        .ok_or_else(|| PathError::Graph("no candidate to rank".to_string()))
}

struct ResolvedEnd {
    entity: Entity,
    endpoint: PathEndpoint,
}

fn endpoint_record(entity: &Entity, addressed_by: &str, twins: &[Entity]) -> PathEndpoint {
    let (start_line, end_line) = span_lines(entity);
    let same_name_candidates = twins
        .iter()
        .filter(|twin| twin.name == entity.name)
        .count()
        .max(1);
    let other_candidates = twins
        .iter()
        .filter(|twin| twin.id != entity.id)
        .take(OTHER_CANDIDATES_SHOWN)
        .map(candidate_record)
        .collect();
    PathEndpoint {
        entity_id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: kind_label(entity),
        file: entity.file_origin.as_ref().map(|file| file.0.clone()),
        start_line,
        end_line,
        external: kin_ranking::entity_ranking::trace_entity_is_external(entity),
        addressed_by: addressed_by.to_string(),
        same_name_candidates,
        other_candidates,
        members_expanded: 0,
    }
}

/// Resolve one end by uuid, by `name@file` or `file_hint`, or by name through
/// the same ranking `trace_data_flow` resolves its focal with.
///
/// Public so the trace surface can address a twin the same way once it grows
/// a `--file` (FIR-3071): one resolver, one disclosure shape.
pub fn resolve_endpoint<G: GraphStore>(
    store: &G,
    which: &'static str,
    spec: &str,
    file_hint: Option<&str>,
) -> std::result::Result<ResolvedEndpoint, PathError> {
    let end = resolve_end(store, which, spec, file_hint)?;
    Ok(ResolvedEndpoint {
        entity: end.entity,
        endpoint: end.endpoint,
    })
}

/// A resolved end as the public resolver hands it back.
pub struct ResolvedEndpoint {
    pub entity: Entity,
    pub endpoint: PathEndpoint,
}

fn resolve_end<G: GraphStore>(
    store: &G,
    which: &'static str,
    spec: &str,
    file_hint: Option<&str>,
) -> std::result::Result<ResolvedEnd, PathError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(PathError::InvalidRequest(format!(
            "{which} must name an entity"
        )));
    }
    if let Ok(uuid) = uuid::Uuid::parse_str(spec) {
        let entity = store
            .get_entity(&EntityId(uuid))
            .map_err(graph_error)?
            .ok_or_else(|| PathError::EndpointNotFound {
                which,
                spec: spec.to_string(),
                detail: "no entity carries this id".to_string(),
            })?;
        let twins = exact_name_matches(store, &entity.name)?;
        let endpoint = endpoint_record(&entity, "entity_id", &twins);
        return Ok(ResolvedEnd { entity, endpoint });
    }

    let (name, hint) = match file_hint.map(str::trim).filter(|hint| !hint.is_empty()) {
        Some(hint) => (spec, Some(hint)),
        None => split_pinned(spec),
    };
    let matches = kin_core::query_trace_matches(store, name).map_err(graph_error)?;
    let exact: Vec<Entity> = matches
        .iter()
        .filter(|entity| entity.name == name)
        .cloned()
        .collect();
    // A qualified name that names no entity falls back to its bare leaf, the
    // way `kin trace` does through `kin_core::fallback_leaf_trace_matches`,
    // but never silently onto one of several: a unique leaf is accepted and
    // reported as `leaf_name`, and leaf twins are refused with the candidates
    // listed so the caller pins one by file or id. Measured on ripgrep, where
    // `SearchWorker::search` was refused outright while three entities named
    // `search` sat in the graph.
    let leaf_only = matches.is_empty();
    let mut pool = if leaf_only {
        let leaf = name
            .rfind("::")
            .map(|index| &name[index + 2..])
            .or_else(|| name.rfind('.').map(|index| &name[index + 1..]))
            .unwrap_or(name);
        let mut leaf_pool: Vec<Entity> =
            kin_core::fallback_leaf_trace_matches(store, name).map_err(graph_error)?;
        leaf_pool.retain(|entity| {
            entity.file_origin.is_some() || entity.role != kin_model::entity::EntityRole::External
        });
        let exact_leaf: Vec<Entity> = leaf_pool
            .iter()
            .filter(|entity| entity.name == leaf)
            .cloned()
            .collect();
        if exact_leaf.is_empty() {
            leaf_pool
        } else {
            exact_leaf
        }
    } else if exact.is_empty() {
        matches
    } else {
        exact
    };
    sort_candidates(&mut pool);

    if let Some(hint) = hint {
        let pinned: Vec<Entity> = pool
            .iter()
            .filter(|entity| file_matches(entity, hint))
            .cloned()
            .collect();
        if pinned.is_empty() {
            let detail = if pool.is_empty() {
                "no entity carries this name".to_string()
            } else {
                let mut files: Vec<String> = pool
                    .iter()
                    .filter_map(|entity| entity.file_origin.as_ref().map(|file| file.0.clone()))
                    .collect();
                files.dedup();
                files.truncate(OTHER_CANDIDATES_SHOWN);
                format!(
                    "'{name}' is not in a file matching '{hint}'; it is in: {}",
                    files.join(", ")
                )
            };
            return Err(PathError::EndpointNotFound {
                which,
                spec: spec.to_string(),
                detail,
            });
        }
        let chosen = strongest_definition(store, pinned)?;
        let twins = exact_name_matches(store, &chosen.name)?;
        let endpoint = endpoint_record(&chosen, "name_and_file", &twins);
        return Ok(ResolvedEnd {
            entity: chosen,
            endpoint,
        });
    }

    if pool.is_empty() {
        return Err(PathError::EndpointNotFound {
            which,
            spec: spec.to_string(),
            detail: "no entity carries this name".to_string(),
        });
    }
    if leaf_only {
        if pool.len() > 1 {
            return Err(PathError::EndpointAmbiguous {
                which,
                spec: spec.to_string(),
                candidates: pool.iter().map(candidate_record).collect(),
            });
        }
        let chosen = pool.remove(0);
        let twins = exact_name_matches(store, &chosen.name)?;
        let endpoint = endpoint_record(&chosen, "leaf_name", &twins);
        return Ok(ResolvedEnd {
            entity: chosen,
            endpoint,
        });
    }
    // `select_best_entity` ranks by name quality, export status, declaration
    // kind and reference counts. Every one of those ties for a C prototype and
    // its definition, so it can and does answer with the declaration, and
    // `strongest_definition` below was only ever reached when it answered with
    // nothing at all. That made the definition preference this function
    // documents unreachable in the case it was written for.
    //
    // The cost was not a cosmetic one. A prototype has no body, so it owns no
    // outgoing edges: `kin path redisGetReplyFromReader redisReaderGetReply` on
    // hiredis resolved the from end to `hiredis.h:338`, explored one entity over
    // one edge, and reported no route between two functions where
    // `hiredis.c:1053` calls the target directly. A wrong answer to the question
    // asked, not a wrong entity in a listing (FIR-3071).
    //
    // Narrow rather than replace: the ranked answer stands unless it is a
    // declaration AND the pool holds a definition under that same name, which
    // is exactly the case its key cannot see.
    let ranked =
        kin_ranking::entity_ranking::select_best_entity(store, name).map_err(graph_error)?;
    let chosen = match ranked {
        Some(entity) => kin_core::prefer_definition_among_same_name(entity, &pool),
        None => strongest_definition(store, pool)?,
    };
    let twins = exact_name_matches(store, &chosen.name)?;
    let endpoint = endpoint_record(&chosen, "name", &twins);
    Ok(ResolvedEnd {
        entity: chosen,
        endpoint,
    })
}

/// An endpoint and every member it stands for, with the `Contains` edge that
/// admitted each member so the route can show the hop.
struct Closure {
    /// Member to `(parent, relation)`; the root maps to `None`.
    parents: HashMap<EntityId, Option<(EntityId, Relation)>>,
    capped: bool,
}

impl Closure {
    fn contains(&self, id: &EntityId) -> bool {
        self.parents.contains_key(id)
    }

    /// Ids from the root down to `member`, both inclusive.
    fn chain_to(&self, member: EntityId) -> Vec<EntityId> {
        let mut chain = vec![member];
        let mut current = member;
        while let Some(Some((parent, _))) = self.parents.get(&current) {
            chain.push(*parent);
            current = *parent;
        }
        chain.reverse();
        chain
    }
}

fn containment_closure<G: GraphStore>(
    store: &G,
    root: &Entity,
    meter: &mut Meter,
) -> std::result::Result<Closure, PathError> {
    let mut closure = Closure {
        parents: HashMap::new(),
        capped: false,
    };
    closure.parents.insert(root.id, None);
    let mut frontier = vec![root.id];
    for _ in 0..CONTAINMENT_DEPTH {
        let mut next = Vec::new();
        'frontier: for node in frontier.drain(..) {
            let relations = store
                .get_all_relations_for_entity(&node)
                .map_err(graph_error)?;
            for relation in relations {
                meter.charge_edge();
                if relation.kind != RelationKind::Contains || relation.src.as_entity() != Some(node)
                {
                    continue;
                }
                let Some(child) = relation.dst.as_entity() else {
                    continue;
                };
                if child == node || closure.parents.contains_key(&child) {
                    continue;
                }
                if closure.parents.len() >= CONTAINMENT_CAP {
                    closure.capped = true;
                    break 'frontier;
                }
                closure.parents.insert(child, Some((node, relation)));
                next.push(child);
            }
        }
        if next.is_empty() || closure.capped {
            break;
        }
        next.sort();
        frontier = next;
    }
    Ok(closure)
}

/// One shortest-path predecessor of a node, with the edge that reached it.
#[derive(Debug, Clone)]
struct ParentEdge {
    parent: EntityId,
    kind: RelationKind,
    resolution: RelationResolution,
    /// `(file, 1-based line)` of every syntax site the edge's evidence records.
    sites: Vec<(String, u32)>,
}

fn evidence_sites(relation: &Relation) -> Vec<(String, u32)> {
    let mut sites: Vec<(String, u32)> = relation
        .evidence
        .iter()
        .filter_map(|evidence| evidence.source_span.as_ref())
        .map(|span| (span.file.0.clone(), presentation_line(span.start_line)))
        .collect();
    sites.sort();
    sites.dedup();
    sites
}

/// Merge a second edge from the same predecessor: the stronger kind names the
/// hop, and every site is kept.
fn record_parent(parents: &mut Vec<ParentEdge>, edge: ParentEdge) {
    if let Some(existing) = parents.iter_mut().find(|known| known.parent == edge.parent) {
        if kind_rank(edge.kind) < kind_rank(existing.kind) {
            existing.kind = edge.kind;
            existing.resolution = edge.resolution;
        }
        existing.sites.extend(edge.sites);
        existing.sites.sort();
        existing.sites.dedup();
    } else {
        parents.push(edge);
    }
}

struct Walk {
    depth_of: HashMap<EntityId, usize>,
    parents: HashMap<EntityId, Vec<ParentEdge>>,
    /// Goal members reached at the first depth any goal member appeared.
    hits: Vec<EntityId>,
    hit_depth: usize,
    stop: Stop,
    nodes: usize,
    edges: usize,
    elapsed: Duration,
}

impl Walk {
    fn explored(&self, sense: Sense) -> PathExplored {
        PathExplored {
            sense: sense.as_str().to_string(),
            nodes: self.nodes,
            edges: self.edges,
            depth_reached: self.depth_of.values().copied().max().unwrap_or(0),
            stopped_by: self.stop.as_str().to_string(),
            elapsed_ms: self.elapsed.as_millis() as u64,
        }
    }
}

/// Breadth-first over outgoing edges from every member of `seeds`, level by
/// level, recording every shortest-path predecessor, until a level holds a
/// member of `goals`, the frontier empties, the depth bound is reached, or the
/// meter stops it.
///
/// A level is finished before it is judged, so every goal member at the hit
/// depth is collected and every route of that length can be enumerated.
fn walk_outgoing<G: GraphStore>(
    store: &G,
    seeds: &Closure,
    goals: &Closure,
    allowed: &HashSet<RelationKind>,
    max_depth: usize,
    meter: &mut Meter,
) -> std::result::Result<Walk, PathError> {
    let started = Instant::now();
    let edges_before = meter.edges;
    let mut depth_of: HashMap<EntityId, usize> = HashMap::new();
    let mut parents: HashMap<EntityId, Vec<ParentEdge>> = HashMap::new();
    let mut frontier: Vec<EntityId> = seeds.parents.keys().copied().collect();
    frontier.sort();
    for id in &frontier {
        depth_of.insert(*id, 0);
    }
    let mut hits: Vec<EntityId> = frontier
        .iter()
        .filter(|id| goals.contains(id))
        .copied()
        .collect();
    let mut nodes = 0usize;
    let mut depth = 0usize;
    let stop;
    if !hits.is_empty() {
        stop = Stop::RouteFound;
    } else {
        loop {
            if depth >= max_depth {
                stop = Stop::DepthBound;
                break;
            }
            let mut next: Vec<EntityId> = Vec::new();
            let mut level_hits: Vec<EntityId> = Vec::new();
            let mut ceiling: Option<Stop> = None;
            'level: for node in &frontier {
                if let Some(reason) = meter.ceiling() {
                    ceiling = Some(reason);
                    break 'level;
                }
                let relations = store
                    .get_all_relations_for_entity(node)
                    .map_err(graph_error)?;
                nodes += 1;
                for relation in &relations {
                    if let Some(reason) = meter.charge_edge() {
                        ceiling = Some(reason);
                        break 'level;
                    }
                    if !allowed.contains(&relation.kind) || relation.src.as_entity() != Some(*node)
                    {
                        continue;
                    }
                    let Some(neighbor) = relation.dst.as_entity() else {
                        continue;
                    };
                    if neighbor == *node {
                        continue;
                    }
                    let edge = ParentEdge {
                        parent: *node,
                        kind: relation.kind,
                        resolution: RelationResolution::of(relation),
                        sites: evidence_sites(relation),
                    };
                    match depth_of.get(&neighbor).copied() {
                        None => {
                            depth_of.insert(neighbor, depth + 1);
                            parents.entry(neighbor).or_default().push(edge);
                            next.push(neighbor);
                            if goals.contains(&neighbor) {
                                level_hits.push(neighbor);
                            }
                        }
                        Some(known) if known == depth + 1 => {
                            record_parent(parents.entry(neighbor).or_default(), edge);
                        }
                        Some(_) => {}
                    }
                }
            }
            depth += 1;
            if let Some(reason) = ceiling {
                hits = level_hits;
                stop = reason;
                break;
            }
            if !level_hits.is_empty() {
                hits = level_hits;
                stop = Stop::RouteFound;
                break;
            }
            if next.is_empty() {
                stop = Stop::FrontierExhausted;
                break;
            }
            next.sort();
            next.dedup();
            frontier = next;
        }
    }
    hits.sort();
    hits.dedup();
    let hit_depth = hits
        .first()
        .and_then(|id| depth_of.get(id).copied())
        .unwrap_or(depth);
    Ok(Walk {
        depth_of,
        parents,
        hits,
        hit_depth,
        stop,
        nodes,
        edges: meter.edges - edges_before,
        elapsed: started.elapsed(),
    })
}

/// A route between the closures: `nodes[i]` is joined to `nodes[i + 1]` by
/// `edges[i]`.
struct CoreRoute {
    nodes: Vec<EntityId>,
    edges: Vec<ParentEdge>,
}

/// Every shortest route from a seed to a hit, enumerated backwards through the
/// predecessor lists, up to [`ROUTE_COUNT_CEILING`]. Returns the routes, how
/// many were counted, and whether the count stopped at the ceiling.
fn enumerate_routes(walk: &Walk) -> (Vec<CoreRoute>, usize, bool) {
    let mut routes: Vec<CoreRoute> = Vec::new();
    let mut ceiling_hit = false;
    'hits: for goal in &walk.hits {
        let mut stack: Vec<(EntityId, Vec<EntityId>, Vec<ParentEdge>)> =
            vec![(*goal, vec![*goal], Vec::new())];
        while let Some((node, path_nodes, path_edges)) = stack.pop() {
            if routes.len() >= ROUTE_COUNT_CEILING {
                ceiling_hit = true;
                break 'hits;
            }
            if walk.depth_of.get(&node).copied().unwrap_or(0) == 0 {
                let mut nodes = path_nodes;
                let mut edges = path_edges;
                nodes.reverse();
                edges.reverse();
                routes.push(CoreRoute { nodes, edges });
                continue;
            }
            let Some(predecessors) = walk.parents.get(&node) else {
                continue;
            };
            let mut ordered: Vec<&ParentEdge> = predecessors.iter().collect();
            ordered.sort_by_key(|edge| (kind_rank(edge.kind), edge.parent));
            for edge in ordered.into_iter().rev() {
                if path_nodes.contains(&edge.parent) {
                    continue;
                }
                let mut nodes = path_nodes.clone();
                nodes.push(edge.parent);
                let mut edges = path_edges.clone();
                edges.push(edge.clone());
                stack.push((edge.parent, nodes, edges));
            }
        }
    }
    let total = routes.len();
    (routes, total, ceiling_hit)
}

struct EntityCache<'a, G: GraphStore> {
    store: &'a G,
    seen: HashMap<EntityId, Option<Entity>>,
}

impl<'a, G: GraphStore> EntityCache<'a, G> {
    fn new(store: &'a G) -> Self {
        Self {
            store,
            seen: HashMap::new(),
        }
    }

    fn get(&mut self, id: EntityId) -> std::result::Result<Option<Entity>, PathError> {
        if let Some(known) = self.seen.get(&id) {
            return Ok(known.clone());
        }
        let entity = self.store.get_entity(&id).map_err(graph_error)?;
        self.seen.insert(id, entity.clone());
        Ok(entity)
    }
}

/// The edge leaving one hop toward the next.
struct HopEdge {
    kind: RelationKind,
    outgoing: bool,
    resolution: Option<&'static str>,
    sites: Vec<(String, u32)>,
}

fn hop_record(
    entity: Option<&Entity>,
    id: EntityId,
    edge: Option<&HopEdge>,
    next_file: Option<&str>,
) -> PathHop {
    let (start_line, end_line) = entity.map(span_lines).unwrap_or((None, None));
    let file = entity.and_then(|entity| entity.file_origin.as_ref().map(|file| file.0.clone()));
    // Sites are reported in the file of the edge's source entity: this hop's
    // file for an outgoing edge, the next hop's for an incoming one.
    let site_file = edge.and_then(|edge| {
        if edge.outgoing {
            file.as_deref()
        } else {
            next_file
        }
    });
    let site_lines: Vec<u32> = edge
        .map(|edge| {
            edge.sites
                .iter()
                .filter(|(site_file_name, _)| Some(site_file_name.as_str()) == site_file)
                .map(|(_, line)| *line)
                .collect()
        })
        .unwrap_or_default();
    let site_lines_absent_reason = match edge {
        Some(_) if !site_lines.is_empty() => None,
        Some(edge) if edge.sites.is_empty() => {
            Some(ReferenceLinesAbsent::NoEvidenceSpan.as_str().to_string())
        }
        Some(_) => Some(
            ReferenceLinesAbsent::SpanOutsideCallerFile
                .as_str()
                .to_string(),
        ),
        None => None,
    };
    PathHop {
        entity_id: id.to_string(),
        name: entity
            .map(|entity| entity.name.clone())
            .unwrap_or_else(|| "<missing entity>".to_string()),
        kind: entity
            .map(kind_label)
            .unwrap_or_else(|| "Unknown".to_string()),
        file,
        start_line,
        end_line,
        external: entity.is_some_and(kin_ranking::entity_ranking::trace_entity_is_external),
        relation: edge.map(|edge| format!("{:?}", edge.kind)),
        edge: edge.map(|edge| {
            let label = if edge.outgoing {
                "outgoing"
            } else {
                "incoming"
            };
            label.to_string()
        }),
        resolution: edge.and_then(|edge| edge.resolution.map(str::to_string)),
        site_lines,
        site_lines_absent_reason,
    }
}

/// A core route with its containment prefix and suffix, rendered to hops.
fn render_route<G: GraphStore>(
    route: &CoreRoute,
    sense: Sense,
    seeds: &Closure,
    goals: &Closure,
    cache: &mut EntityCache<'_, G>,
) -> std::result::Result<PathRoute, PathError> {
    let first = *route.nodes.first().expect("a route has at least one node");
    let last = *route.nodes.last().expect("a route has at least one node");
    let mut chain: Vec<(EntityId, Option<HopEdge>)> = Vec::new();
    let prefix = seeds.chain_to(first);
    for node in prefix.iter().take(prefix.len().saturating_sub(1)) {
        chain.push((
            *node,
            Some(HopEdge {
                kind: RelationKind::Contains,
                outgoing: true,
                resolution: None,
                sites: Vec::new(),
            }),
        ));
    }
    for (index, node) in route.nodes.iter().enumerate() {
        let edge = route.edges.get(index).map(|edge| HopEdge {
            kind: edge.kind,
            outgoing: true,
            resolution: Some(edge.resolution.as_str()),
            sites: edge.sites.clone(),
        });
        chain.push((*node, edge));
    }
    let suffix = goals.chain_to(last);
    for node in suffix.iter().rev().skip(1) {
        if let Some((_, tail_edge)) = chain.last_mut() {
            *tail_edge = Some(HopEdge {
                kind: RelationKind::Contains,
                outgoing: false,
                resolution: None,
                sites: Vec::new(),
            });
        }
        chain.push((*node, None));
    }
    let hops = chain.len().saturating_sub(1);
    let mut steps = Vec::with_capacity(chain.len());
    for (index, (id, edge)) in chain.iter().enumerate() {
        let entity = cache.get(*id)?;
        let next_file = match chain.get(index + 1) {
            Some((next_id, _)) => cache
                .get(*next_id)?
                .and_then(|next| next.file_origin.as_ref().map(|file| file.0.clone())),
            None => None,
        };
        steps.push(hop_record(
            entity.as_ref(),
            *id,
            edge.as_ref(),
            next_file.as_deref(),
        ));
    }
    Ok(PathRoute {
        direction: sense.as_str().to_string(),
        hops,
        walked_hops: route.edges.len(),
        steps,
    })
}

fn route_key(route: &PathRoute) -> Vec<String> {
    route.steps.iter().map(|step| step.name.clone()).collect()
}

fn degradation(
    component: &str,
    reason: &str,
    detail: String,
    remediation: &str,
) -> PathDegradation {
    PathDegradation {
        component: component.to_string(),
        reason: reason.to_string(),
        detail,
        remediation: remediation.to_string(),
    }
}

fn stop_phrase(stopped_by: &str) -> &'static str {
    match stopped_by {
        "frontier_exhausted" => "ran out of reachable entities before meeting the target",
        "depth_bound" => "stopped at the depth bound",
        "edge_ceiling" => "stopped at the edge ceiling",
        "time_budget" => "stopped at the time budget",
        "cancelled" => "was cancelled",
        _ => "stopped",
    }
}

fn compose_gap(
    from: &PathEndpoint,
    to: &PathEndpoint,
    max_depth: usize,
    explored: &[PathExplored],
) -> PathGap {
    let most_limiting = explored
        .iter()
        .map(|walk| walk.stopped_by.as_str())
        .max_by_key(|stopped_by| match *stopped_by {
            "frontier_exhausted" => Stop::FrontierExhausted.severity(),
            "depth_bound" => Stop::DepthBound.severity(),
            "edge_ceiling" => Stop::EdgeCeiling.severity(),
            "time_budget" => Stop::TimeBudget.severity(),
            "cancelled" => Stop::Cancelled.severity(),
            _ => 0,
        })
        .unwrap_or("frontier_exhausted")
        .to_string();
    let walks: Vec<String> = explored
        .iter()
        .map(|walk| {
            format!(
                "the {} walk explored {} entities over {} edges and {}",
                walk.sense,
                walk.nodes,
                walk.edges,
                stop_phrase(&walk.stopped_by)
            )
        })
        .collect();
    let mut detail = format!(
        "no route between '{}' and '{}' within {max_depth} hops: {}",
        from.name,
        to.name,
        walks.join("; ")
    );
    for (which, end) in [("from", from), ("to", to)] {
        if end.same_name_candidates > 1 && end.addressed_by == "name" {
            detail.push_str(&format!(
                ". '{}' is one of {} entities with that name and the {which} end was the one at {}:{}; the others were not walked",
                end.name,
                end.same_name_candidates,
                end.file.as_deref().unwrap_or("<no file>"),
                end.start_line
                    .map(|line| line.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ));
        }
    }
    let remediation = match most_limiting.as_str() {
        // At the ceiling there is no larger `max_depth` to name, and the
        // sentence says so rather than sending the caller to set the value
        // already in force.
        "depth_bound" => format!(
            "{}, or name a pair that sits closer together",
            crate::remediation::raise_bounded_knob("max_depth", max_depth, MAX_MAX_DEPTH)
        ),
        "edge_ceiling" | "time_budget" | "cancelled" => {
            "narrow the walk with a smaller max_depth or a closer pair; the graph beyond the ceiling was not explored".to_string()
        }
        _ => "check that both ends resolved to the entities you meant (same_name_candidates and other_candidates on from and to), pin a twin with name@file or its entity id, or pass include_type_edges to walk type annotations too".to_string(),
    };
    PathGap {
        reason: most_limiting,
        detail,
        remediation,
    }
}

/// Build the answer under the shipped ceilings.
pub fn build_path_response<G: GraphStore>(
    store: &G,
    request: &PathRequest,
) -> std::result::Result<PathResponse, PathError> {
    build_path_response_within(store, request, PathBudget::default())
}

/// The same walk under caller-supplied ceilings.
pub fn build_path_response_within<G: GraphStore>(
    store: &G,
    request: &PathRequest,
    budget: PathBudget,
) -> std::result::Result<PathResponse, PathError> {
    let max_depth = request
        .max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(1, MAX_MAX_DEPTH);
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let direction = request.direction.unwrap_or_default();
    let include_type_edges = request.include_type_edges.unwrap_or(false);
    let mut meter = Meter::new(budget);
    let mut degradations: Vec<PathDegradation> = Vec::new();

    let ResolvedEnd {
        entity: from_entity,
        endpoint: mut from,
    } = resolve_end(store, "from", &request.from, request.from_file.as_deref())?;
    let ResolvedEnd {
        entity: to_entity,
        endpoint: mut to,
    } = resolve_end(store, "to", &request.to, request.to_file.as_deref())?;

    let kinds = walked_kinds(include_type_edges);
    let allowed: HashSet<RelationKind> = kinds.iter().copied().collect();
    let from_closure = containment_closure(store, &from_entity, &mut meter)?;
    let to_closure = containment_closure(store, &to_entity, &mut meter)?;
    from.members_expanded = from_closure.parents.len().saturating_sub(1);
    to.members_expanded = to_closure.parents.len().saturating_sub(1);
    for (which, closure) in [("from", &from_closure), ("to", &to_closure)] {
        if closure.capped {
            degradations.push(degradation(
                "endpoint_members",
                "members_capped",
                format!(
                    "the {which} end stands for more than {CONTAINMENT_CAP} members and only the first {CONTAINMENT_CAP} were walked, so a route through a later member was not looked for"
                ),
                "name a member of that end directly rather than the container",
            ));
        }
    }

    let senses: &[Sense] = match direction {
        PathDirection::Forward => &[Sense::Forward],
        PathDirection::Reverse => &[Sense::Reverse],
        PathDirection::Either => &[Sense::Forward, Sense::Reverse],
    };
    let mut explored: Vec<PathExplored> = Vec::new();
    let mut routes: Vec<PathRoute> = Vec::new();
    let mut routes_total = 0usize;
    let mut routes_truncated = false;
    let mut sense_held: Option<Sense> = None;
    let mut cache = EntityCache::new(store);
    for (index, sense) in senses.iter().enumerate() {
        let (seeds, goals) = match sense {
            Sense::Forward => (&from_closure, &to_closure),
            Sense::Reverse => (&to_closure, &from_closure),
        };
        let walk = walk_outgoing(store, seeds, goals, &allowed, max_depth, &mut meter)?;
        let bounded = walk.stop.is_ceiling();
        explored.push(walk.explored(*sense));
        if !walk.hits.is_empty() {
            let (core, total, ceiling_hit) = enumerate_routes(&walk);
            let mut rendered = Vec::with_capacity(core.len());
            for route in &core {
                rendered.push(render_route(route, *sense, seeds, goals, &mut cache)?);
            }
            rendered.sort_by(|a, b| {
                a.hops
                    .cmp(&b.hops)
                    .then_with(|| route_key(a).cmp(&route_key(b)))
            });
            routes_total = total;
            routes_truncated = total > limit || ceiling_hit;
            rendered.truncate(limit);
            routes = rendered;
            sense_held = Some(*sense);
            if bounded {
                degradations.push(degradation(
                    "route_enumeration",
                    "walk_bounded",
                    format!(
                        "the {} walk {} while expanding the level that reached the target, so other routes of {} hops may be missing",
                        sense.as_str(),
                        stop_phrase(walk.stop.as_str()),
                        walk.hit_depth
                    ),
                    "re-run with a smaller max_depth to spend the budget closer to the pair",
                ));
            }
            if ceiling_hit {
                degradations.push(degradation(
                    "route_enumeration",
                    "route_count_ceiling",
                    format!(
                        "more than {ROUTE_COUNT_CEILING} shortest routes exist and only the first {ROUTE_COUNT_CEILING} were counted, so routes_total is a floor"
                    ),
                    "name a member of each end rather than the container to narrow the pair",
                ));
            }
            break;
        }
        if bounded {
            if index + 1 < senses.len() {
                degradations.push(degradation(
                    "direction",
                    "reverse_not_walked",
                    format!(
                        "the forward walk {} before the reverse sense could run, so no reverse route was looked for",
                        stop_phrase(walk.stop.as_str())
                    ),
                    "re-run with direction=reverse to walk that sense on its own budget",
                ));
            }
            break;
        }
    }

    let found = !routes.is_empty();
    let gap = if found {
        None
    } else {
        Some(compose_gap(&from, &to, max_depth, &explored))
    };
    let edge_coverage = crate::edge_coverage::observe_cross_file_reference_coverage(
        store,
        &from_entity,
        &REFERENCE_KINDS,
    );
    Ok(PathResponse {
        from,
        to,
        direction_requested: direction.as_str().to_string(),
        direction: sense_held.map(|sense| sense.as_str().to_string()),
        max_depth,
        limit,
        walked_kinds: kinds.iter().map(|kind| format!("{kind:?}")).collect(),
        include_type_edges,
        found,
        routes,
        routes_total,
        routes_truncated,
        explored,
        gap,
        degradations,
        edge_coverage,
    })
}

/// One line per hop, sized for a prompt: the first line names the start, and
/// every line after it is one edge and the entity it reaches.
pub fn render_route_lines(route: &PathRoute) -> Vec<String> {
    let mut lines = Vec::with_capacity(route.steps.len());
    let mut pending: Option<String> = None;
    for step in &route.steps {
        let location = match (&step.file, step.start_line) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            (None, _) => "(no file)".to_string(),
        };
        let node = format!("{} [{}] {}", step.name, step.kind.to_lowercase(), location);
        lines.push(match pending.take() {
            Some(arrow) => format!("{arrow} {node}"),
            None => node,
        });
        if let (Some(relation), Some(edge)) = (&step.relation, &step.edge) {
            let sites = if step.site_lines.is_empty() {
                String::new()
            } else {
                format!(
                    "@{}",
                    step.site_lines
                        .iter()
                        .map(|line| line.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            pending = Some(if edge == "outgoing" {
                format!("-{relation}{sites}->")
            } else {
                format!("<-{relation}{sites}-")
            });
        }
    }
    lines
}

/// The compact form: a header per route and one line per hop, nothing else.
pub fn render_compact(response: &PathResponse) -> String {
    if !response.found {
        let gap = response
            .gap
            .as_ref()
            .map(|gap| gap.detail.clone())
            .unwrap_or_else(|| "no route".to_string());
        return format!("no route: {gap}\n");
    }
    let mut out = String::new();
    let shown = response.routes.len();
    for (index, route) in response.routes.iter().enumerate() {
        let first = route
            .steps
            .first()
            .map(|step| step.name.as_str())
            .unwrap_or("?");
        let last = route
            .steps
            .last()
            .map(|step| step.name.as_str())
            .unwrap_or("?");
        out.push_str(&format!(
            "route {} of {} ({}, {} hops): {} -> {}\n",
            index + 1,
            if response.routes_truncated {
                format!("{shown} shown of {}", response.routes_total)
            } else {
                shown.to_string()
            },
            route.direction,
            route.hops,
            first,
            last
        ));
        for line in render_route_lines(route) {
            out.push_str("  ");
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Parse the MCP tool arguments into a request.
pub fn request_from_args(args: &HashMap<String, serde_json::Value>) -> Result<PathRequest> {
    let from = get_string_param(args, "from")?;
    let to = get_string_param(args, "to")?;
    let direction = match get_optional_string_param(args, "direction") {
        Some(value) => Some(PathDirection::parse(&value).map_err(McpError::InvalidParams)?),
        None => None,
    };
    let usize_param = |key: &str| {
        args.get(key)
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as usize)
    };
    Ok(PathRequest {
        from,
        to,
        from_file: get_optional_string_param(args, "from_file"),
        to_file: get_optional_string_param(args, "to_file"),
        max_depth: usize_param("max_depth"),
        limit: usize_param("limit"),
        direction,
        include_type_edges: args
            .get("include_type_edges")
            .and_then(serde_json::Value::as_bool),
    })
}

/// The MCP tool: the same walk, answered as JSON text. A name that resolves to
/// nothing is a tool error rather than a transport error, so the envelope can
/// carry a resolution-miss negative beside it.
pub fn handle_trace_path<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let request = request_from_args(args)?;
    match build_path_response(store, &request) {
        Ok(response) => {
            let json = serde_json::to_string_pretty(&response).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        Err(PathError::InvalidRequest(message)) => Err(McpError::InvalidParams(message)),
        Err(error) if error.is_resolution_miss() => {
            Ok(ToolCallResult::error(format!("{TOOL_NAME}: {error}")))
        }
        Err(error) => Err(McpError::GraphStore(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::entity::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        SourceSpan, Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256, LanguageId, RelationId};
    use kin_model::relation::{RelationEvidence, RelationOrigin};
    use kin_model::{EntityStore, GraphNodeId};

    fn make_entity(name: &str, file: &str, kind: EntityKind, line: u32) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 32,
                start_line: line,
                start_col: 0,
                end_line: line + 10,
                end_col: 1,
            }),
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn function(name: &str, file: &str) -> Entity {
        make_entity(name, file, EntityKind::Function, 4)
    }

    fn relation(src: &Entity, dst: &Entity, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    /// A relation whose evidence records the syntax site, in `src`'s file.
    fn call_at(src: &Entity, dst: &Entity, row: u32) -> Relation {
        let mut rel = relation(src, dst, RelationKind::Calls);
        rel.evidence = vec![RelationEvidence {
            source_span: Some(SourceSpan {
                file: src.file_origin.clone().unwrap(),
                start_byte: 0,
                end_byte: 1,
                start_line: row,
                start_col: 0,
                end_line: row,
                end_col: 1,
            }),
            ..RelationEvidence::default()
        }];
        rel
    }

    fn seed(store: &InMemoryGraph, entities: &[&Entity], relations: &[Relation]) {
        for entity in entities {
            store.upsert_entity(entity).unwrap();
        }
        for rel in relations {
            store.upsert_relation(rel).unwrap();
        }
    }

    fn request(from: &str, to: &str) -> PathRequest {
        PathRequest {
            from: from.to_string(),
            to: to.to_string(),
            ..Default::default()
        }
    }

    fn names(route: &PathRoute) -> Vec<&str> {
        route.steps.iter().map(|step| step.name.as_str()).collect()
    }

    /// A three-link chain answers with the chain, in order, with every hop
    /// located and joined by the relation the graph holds.
    #[test]
    fn a_route_is_listed_from_source_to_target_with_every_hop_located() {
        let store = InMemoryGraph::new();
        let a = function("edit", "src/editor.ts");
        let b = function("apply", "src/view.ts");
        let c = function("push", "src/model.ts");
        seed(
            &store,
            &[&a, &b, &c],
            &[call_at(&a, &b, 11), call_at(&b, &c, 21)],
        );

        let response = build_path_response(&store, &request("edit", "push")).unwrap();

        assert!(response.found, "{response:?}");
        assert_eq!(response.direction.as_deref(), Some("forward"));
        assert_eq!(response.routes.len(), 1);
        assert_eq!(response.routes_total, 1);
        assert!(!response.routes_truncated);
        let route = &response.routes[0];
        assert_eq!(route.hops, 2);
        assert_eq!(route.walked_hops, 2);
        assert_eq!(names(route), vec!["edit", "apply", "push"]);
        assert_eq!(route.steps[0].relation.as_deref(), Some("Calls"));
        assert_eq!(route.steps[0].edge.as_deref(), Some("outgoing"));
        assert_eq!(route.steps[0].site_lines, vec![12]);
        assert!(route.steps[0].site_lines_absent_reason.is_none());
        assert_eq!(route.steps[0].file.as_deref(), Some("src/editor.ts"));
        assert_eq!(route.steps[0].start_line, Some(5));
        assert_eq!(route.steps[1].site_lines, vec![22]);
        assert!(route.steps[2].relation.is_none() && route.steps[2].edge.is_none());
        assert_eq!(response.explored[0].stopped_by, "route_found");
        assert!(response.gap.is_none());
        assert_eq!(response.from.entity_id, a.id.to_string());
        assert_eq!(response.to.entity_id, c.id.to_string());
    }

    /// A one-hop route beats every two-hop one, and the two-hop ones are never
    /// enumerated because the walk stops at the level that met the target.
    #[test]
    fn the_shortest_route_comes_first_and_nothing_longer_is_listed() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let b1 = function("b1", "src/b.ts");
        let b2 = function("b2", "src/b.ts");
        let c = function("c", "src/c.ts");
        seed(
            &store,
            &[&a, &b1, &b2, &c],
            &[
                relation(&a, &b1, RelationKind::Calls),
                relation(&b1, &c, RelationKind::Calls),
                relation(&a, &b2, RelationKind::Calls),
                relation(&b2, &c, RelationKind::Calls),
                relation(&a, &c, RelationKind::References),
            ],
        );

        let response = build_path_response(&store, &request("a", "c")).unwrap();
        assert_eq!(response.routes.len(), 1, "{response:?}");
        assert_eq!(response.routes[0].hops, 1);
        assert_eq!(
            response.routes[0].steps[0].relation.as_deref(),
            Some("References")
        );
        assert_eq!(response.routes_total, 1);
        // An edge recorded without a syntax site says so rather than printing
        // an empty list a reader cannot tell from "no site in this file".
        assert!(response.routes[0].steps[0].site_lines.is_empty());
        assert_eq!(
            response.routes[0].steps[0]
                .site_lines_absent_reason
                .as_deref(),
            Some("no_evidence_span")
        );
        assert!(response.routes[0].steps[1]
            .site_lines_absent_reason
            .is_none());
    }

    /// Parallel shortest routes are all counted, listed in a stable order, and
    /// cut to `limit` with the cut disclosed.
    #[test]
    fn the_limit_cuts_parallel_routes_and_says_how_many_exist() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let b1 = function("b1", "src/b.ts");
        let b2 = function("b2", "src/b.ts");
        let c = function("c", "src/c.ts");
        seed(
            &store,
            &[&a, &b1, &b2, &c],
            &[
                relation(&a, &b1, RelationKind::Calls),
                relation(&b1, &c, RelationKind::Calls),
                relation(&a, &b2, RelationKind::Calls),
                relation(&b2, &c, RelationKind::Calls),
            ],
        );

        let both = build_path_response(
            &store,
            &PathRequest {
                limit: Some(2),
                ..request("a", "c")
            },
        )
        .unwrap();
        assert_eq!(both.routes.len(), 2);
        assert_eq!(names(&both.routes[0]), vec!["a", "b1", "c"]);
        assert_eq!(names(&both.routes[1]), vec!["a", "b2", "c"]);
        assert_eq!(both.routes_total, 2);
        assert!(!both.routes_truncated);

        let one = build_path_response(
            &store,
            &PathRequest {
                limit: Some(1),
                ..request("a", "c")
            },
        )
        .unwrap();
        assert_eq!(one.routes.len(), 1);
        assert_eq!(names(&one.routes[0]), vec!["a", "b1", "c"]);
        assert_eq!(one.routes_total, 2);
        assert!(one.routes_truncated);
    }

    /// A walk that stopped at the depth bound with `max_depth` already at the
    /// schema ceiling has no larger value to be sent to, and the gap says so
    /// rather than "raise max_depth (now 12, ceiling 12)".
    #[test]
    fn a_walk_at_the_depth_ceiling_is_not_told_to_raise_max_depth() {
        let store = InMemoryGraph::new();
        // Thirteen hops end to end, one more than the ceiling can walk.
        let chain: Vec<_> = (0..=MAX_MAX_DEPTH + 1)
            .map(|index| function(&format!("hop{index:02}"), &format!("src/hop{index:02}.ts")))
            .collect();
        let relations: Vec<_> = chain
            .windows(2)
            .map(|pair| relation(&pair[0], &pair[1], RelationKind::Calls))
            .collect();
        let entities: Vec<_> = chain.iter().collect();
        seed(&store, &entities, &relations);

        let bounded = build_path_response(
            &store,
            &PathRequest {
                max_depth: Some(MAX_MAX_DEPTH),
                direction: Some(PathDirection::Forward),
                ..request("hop00", &format!("hop{:02}", MAX_MAX_DEPTH + 1))
            },
        )
        .unwrap();
        assert!(!bounded.found);
        let gap = bounded
            .gap
            .as_ref()
            .expect("a gap on every no-route answer");
        assert_eq!(gap.reason, "depth_bound");
        assert!(
            !gap.remediation.contains("raise max_depth"),
            "a walk at the ceiling was told to raise past it: {}",
            gap.remediation
        );
        assert!(
            gap.remediation.contains(&format!(
                "max_depth is already at its {MAX_MAX_DEPTH} ceiling"
            )),
            "a walk at the ceiling must be told the knob is spent: {}",
            gap.remediation
        );
        assert!(
            gap.remediation
                .contains("name a pair that sits closer together"),
            "and still be handed the alternative: {}",
            gap.remediation
        );
    }

    /// The depth bound is a bound on walked hops, and a walk that stopped
    /// there says so rather than reporting the target unreachable.
    #[test]
    fn the_depth_bound_is_honest_about_what_it_did_not_walk() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let b = function("b", "src/b.ts");
        let c = function("c", "src/c.ts");
        let d = function("d", "src/d.ts");
        seed(
            &store,
            &[&a, &b, &c, &d],
            &[
                relation(&a, &b, RelationKind::Calls),
                relation(&b, &c, RelationKind::Calls),
                relation(&c, &d, RelationKind::Calls),
            ],
        );

        let bounded = build_path_response(
            &store,
            &PathRequest {
                max_depth: Some(2),
                direction: Some(PathDirection::Forward),
                ..request("a", "d")
            },
        )
        .unwrap();
        assert!(!bounded.found);
        assert!(bounded.routes.is_empty());
        let gap = bounded
            .gap
            .as_ref()
            .expect("a gap on every no-route answer");
        assert_eq!(gap.reason, "depth_bound");
        assert!(gap.remediation.contains("max_depth"), "{gap:?}");
        assert_eq!(bounded.explored[0].stopped_by, "depth_bound");
        assert_eq!(bounded.explored[0].depth_reached, 2);

        let reached = build_path_response(
            &store,
            &PathRequest {
                max_depth: Some(3),
                direction: Some(PathDirection::Forward),
                ..request("a", "d")
            },
        )
        .unwrap();
        assert!(reached.found);
        assert_eq!(reached.routes[0].hops, 3);
    }

    /// The answer says which sense held, and a pinned sense is honoured.
    #[test]
    fn direction_is_reported_and_can_be_pinned() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let b = function("b", "src/b.ts");
        seed(&store, &[&a, &b], &[relation(&b, &a, RelationKind::Calls)]);

        let either = build_path_response(&store, &request("a", "b")).unwrap();
        assert!(either.found, "{either:?}");
        assert_eq!(either.direction.as_deref(), Some("reverse"));
        assert_eq!(either.direction_requested, "either");
        assert_eq!(names(&either.routes[0]), vec!["b", "a"]);
        assert_eq!(either.routes[0].direction, "reverse");
        assert_eq!(either.explored.len(), 2);
        assert_eq!(either.explored[0].sense, "forward");
        assert_eq!(either.explored[0].stopped_by, "frontier_exhausted");
        assert_eq!(either.explored[1].sense, "reverse");
        assert_eq!(either.explored[1].stopped_by, "route_found");

        let forward = build_path_response(
            &store,
            &PathRequest {
                direction: Some(PathDirection::Forward),
                ..request("a", "b")
            },
        )
        .unwrap();
        assert!(!forward.found);
        assert_eq!(forward.explored.len(), 1);
        assert_eq!(forward.gap.as_ref().unwrap().reason, "frontier_exhausted");

        let reverse = build_path_response(
            &store,
            &PathRequest {
                direction: Some(PathDirection::Reverse),
                ..request("a", "b")
            },
        )
        .unwrap();
        assert!(reverse.found);
        assert_eq!(reverse.direction.as_deref(), Some("reverse"));
    }

    /// No route is an explicit answer: empty routes, a gap that names both
    /// ends and both walks, and nothing plausible in their place.
    #[test]
    fn no_route_fails_loud_with_the_gap() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let x = function("x", "src/x.ts");
        let b = function("b", "src/b.ts");
        seed(
            &store,
            &[&a, &x, &b],
            &[relation(&a, &x, RelationKind::Calls)],
        );

        let response = build_path_response(&store, &request("a", "b")).unwrap();
        assert!(!response.found);
        assert!(response.routes.is_empty());
        assert_eq!(response.routes_total, 0);
        assert!(response.direction.is_none());
        let gap = response.gap.as_ref().unwrap();
        assert_eq!(gap.reason, "frontier_exhausted");
        assert!(
            gap.detail.contains("'a'") && gap.detail.contains("'b'"),
            "{gap:?}"
        );
        assert!(gap.detail.contains("forward walk") && gap.detail.contains("reverse walk"));
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["found"], serde_json::json!(false));
        assert_eq!(json["routes"], serde_json::json!([]));
        assert!(json["gap"]["detail"].is_string());
    }

    /// A twin is pinned by `name@file` or `from_file`, the choice is disclosed
    /// either way, and a no-route answer across a twin names the twin.
    #[test]
    fn a_twin_is_pinned_by_file_and_disclosed_by_name() {
        let store = InMemoryGraph::new();
        let declared = make_entity("run", "src/main.c", EntityKind::Function, 3);
        let defined = make_entity("run", "src/mod1.c", EntityKind::Function, 40);
        let target = function("target", "src/mod2.c");
        seed(
            &store,
            &[&declared, &defined, &target],
            &[relation(&defined, &target, RelationKind::Calls)],
        );

        let pinned = build_path_response(&store, &request("run@mod1.c", "target")).unwrap();
        assert!(pinned.found, "{pinned:?}");
        assert_eq!(pinned.from.entity_id, defined.id.to_string());
        assert_eq!(pinned.from.addressed_by, "name_and_file");
        assert_eq!(pinned.from.same_name_candidates, 2);
        assert_eq!(pinned.from.other_candidates.len(), 1);
        assert_eq!(
            pinned.from.other_candidates[0].entity_id,
            declared.id.to_string()
        );

        let by_flag = build_path_response(
            &store,
            &PathRequest {
                from_file: Some("src/mod1.c".to_string()),
                ..request("run", "target")
            },
        )
        .unwrap();
        assert_eq!(by_flag.from.entity_id, defined.id.to_string());
        assert_eq!(by_flag.from.addressed_by, "name_and_file");

        let wrong_twin = build_path_response(&store, &request("run@main.c", "target")).unwrap();
        assert!(!wrong_twin.found);
        assert_eq!(wrong_twin.from.entity_id, declared.id.to_string());

        let by_name = build_path_response(&store, &request("run", "target")).unwrap();
        assert_eq!(by_name.from.addressed_by, "name");
        assert_eq!(by_name.from.same_name_candidates, 2);

        let missing = build_path_response(&store, &request("run@nowhere.c", "target"));
        let error = missing.expect_err("a file that holds no twin is a miss");
        assert!(error.is_resolution_miss());
        let message = error.to_string();
        assert!(
            message.contains("src/main.c") && message.contains("src/mod1.c"),
            "the miss names the files the twins live in: {message}"
        );
    }

    /// A name-addressed twin that hides the route is named in the gap.
    #[test]
    fn a_no_route_answer_names_a_twin_it_did_not_walk() {
        let store = InMemoryGraph::new();
        let declared = make_entity("run", "src/main.c", EntityKind::Function, 3);
        let defined = make_entity("run", "src/mod1.c", EntityKind::Function, 40);
        let target = function("target", "src/mod2.c");
        seed(
            &store,
            &[&declared, &defined, &target],
            &[relation(&defined, &target, RelationKind::Calls)],
        );
        let response = build_path_response(&store, &request("run@main.c", "target")).unwrap();
        assert!(!response.found);
        // Pinned by file, so the gap does not claim ambiguity; the twin count
        // is on the endpoint for the reader instead.
        assert_eq!(response.from.same_name_candidates, 2);

        let mut by_name = build_path_response(&store, &request("run", "target")).unwrap();
        // Force the by-name choice onto the declaration to exercise the clause.
        by_name.from.addressed_by = "name".to_string();
        by_name.from.file = Some("src/main.c".to_string());
        let gap = compose_gap(&by_name.from, &by_name.to, 6, &by_name.explored);
        assert!(
            gap.detail.contains("one of 2 entities with that name"),
            "{gap:?}"
        );
    }

    /// A class stands for its members: the route runs through the method that
    /// carries it, and the containment hops are shown with their direction.
    #[test]
    fn a_class_reaches_through_its_members() {
        let store = InMemoryGraph::new();
        let widget = make_entity("CodeEditorWidget", "src/widget.ts", EntityKind::Class, 20);
        let execute = make_entity(
            "CodeEditorWidget.executeEdits",
            "src/widget.ts",
            EntityKind::Method,
            300,
        );
        let push = make_entity(
            "TextModel.pushEditOperations",
            "src/model.ts",
            EntityKind::Method,
            900,
        );
        let model = make_entity("TextModel", "src/model.ts", EntityKind::Class, 50);
        seed(
            &store,
            &[&widget, &execute, &push, &model],
            &[
                relation(&widget, &execute, RelationKind::Contains),
                call_at(&execute, &push, 310),
                relation(&model, &push, RelationKind::Contains),
            ],
        );

        let response =
            build_path_response(&store, &request("CodeEditorWidget", "TextModel")).unwrap();
        assert!(response.found, "{response:?}");
        assert_eq!(response.from.members_expanded, 1);
        assert_eq!(response.to.members_expanded, 1);
        let route = &response.routes[0];
        assert_eq!(route.hops, 3);
        assert_eq!(route.walked_hops, 1);
        assert_eq!(
            names(route),
            vec![
                "CodeEditorWidget",
                "CodeEditorWidget.executeEdits",
                "TextModel.pushEditOperations",
                "TextModel"
            ]
        );
        assert_eq!(route.steps[0].relation.as_deref(), Some("Contains"));
        assert_eq!(route.steps[0].edge.as_deref(), Some("outgoing"));
        assert_eq!(route.steps[1].relation.as_deref(), Some("Calls"));
        assert_eq!(route.steps[1].site_lines, vec![311]);
        assert_eq!(route.steps[2].relation.as_deref(), Some("Contains"));
        assert_eq!(route.steps[2].edge.as_deref(), Some("incoming"));
        assert!(route.steps[3].relation.is_none());

        let lines = render_route_lines(route);
        assert_eq!(lines.len(), 4, "one line per hop plus the start: {lines:?}");
        assert!(lines[1].starts_with("-Contains->"), "{lines:?}");
        assert!(lines[2].starts_with("-Calls@311->"), "{lines:?}");
        assert!(lines[3].starts_with("<-Contains-"), "{lines:?}");
        let compact = render_compact(&response);
        assert!(
            compact.starts_with("route 1 of 1 (forward, 3 hops): CodeEditorWidget -> TextModel\n")
        );
    }

    /// A method never reaches its siblings through its class: the expansion
    /// runs down from an endpoint only.
    #[test]
    fn a_member_does_not_reach_its_sibling_through_the_class() {
        let store = InMemoryGraph::new();
        let class = make_entity("A", "src/a.ts", EntityKind::Class, 1);
        let m = make_entity("A.m", "src/a.ts", EntityKind::Method, 10);
        let k = make_entity("A.k", "src/a.ts", EntityKind::Method, 20);
        let target = function("target", "src/t.ts");
        seed(
            &store,
            &[&class, &m, &k, &target],
            &[
                relation(&class, &m, RelationKind::Contains),
                relation(&class, &k, RelationKind::Contains),
                relation(&k, &target, RelationKind::Calls),
            ],
        );
        let from_method = build_path_response(
            &store,
            &PathRequest {
                direction: Some(PathDirection::Forward),
                ..request("A.m", "target")
            },
        )
        .unwrap();
        assert!(!from_method.found, "{from_method:?}");
        let from_class = build_path_response(&store, &request("A", "target")).unwrap();
        assert!(from_class.found);
        assert_eq!(names(&from_class.routes[0]), vec!["A", "A.k", "target"]);
    }

    /// A work ceiling stops the walk and the answer says the graph beyond it
    /// was not explored.
    #[test]
    fn a_work_ceiling_stops_the_walk_and_says_so() {
        let store = InMemoryGraph::new();
        let hub = function("hub", "src/hub.ts");
        let far = function("far", "src/far.ts");
        let mut entities = vec![hub.clone(), far.clone()];
        let mut relations = Vec::new();
        for index in 0..40 {
            let spoke = function(&format!("spoke{index}"), "src/spokes.ts");
            relations.push(relation(&hub, &spoke, RelationKind::Calls));
            entities.push(spoke);
        }
        let refs: Vec<&Entity> = entities.iter().collect();
        seed(&store, &refs, &relations);

        let response = build_path_response_within(
            &store,
            &PathRequest {
                direction: Some(PathDirection::Forward),
                ..request("hub", "far")
            },
            PathBudget::bounded(10, Duration::from_secs(30)),
        )
        .unwrap();
        assert!(!response.found);
        assert_eq!(response.explored[0].stopped_by, "edge_ceiling");
        let gap = response.gap.as_ref().unwrap();
        assert_eq!(gap.reason, "edge_ceiling");
        assert!(gap.detail.contains("edge ceiling"), "{gap:?}");
    }

    /// The handler answers JSON with the keys the negative classifier and the
    /// envelope read, refuses a missing end as a tool error, and refuses a
    /// missing parameter as invalid params.
    #[test]
    fn the_handler_answers_json_and_refuses_a_missing_end() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let b = function("b", "src/b.ts");
        seed(&store, &[&a, &b], &[relation(&a, &b, RelationKind::Calls)]);

        let args: HashMap<String, serde_json::Value> = [
            ("from".to_string(), serde_json::json!("a")),
            ("to".to_string(), serde_json::json!("b")),
        ]
        .into_iter()
        .collect();
        let result = handle_trace_path(&args, &store).unwrap();
        assert_ne!(result.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        let payload: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(payload["found"], serde_json::json!(true));
        assert_eq!(payload["routes"].as_array().unwrap().len(), 1);
        assert_eq!(payload["routes_total"], serde_json::json!(1));
        assert_eq!(
            payload["from"]["same_name_candidates"],
            serde_json::json!(1)
        );
        assert!(
            payload
                .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
                .is_some(),
            "the payload carries the coverage observation under the key the classifier reads"
        );

        let enveloped =
            crate::finalize_with_envelope(result, crate::Envelope::offline(), TOOL_NAME);
        let crate::types::ContentBlock::Text { text } = &enveloped.content[0];
        let annotated: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(annotated.get(crate::ENVELOPE_KEY).is_some(), "{annotated}");
        assert!(annotated.get(crate::NEGATIVE_KEY).is_some(), "{annotated}");

        let missing: HashMap<String, serde_json::Value> = [
            ("from".to_string(), serde_json::json!("nope")),
            ("to".to_string(), serde_json::json!("b")),
        ]
        .into_iter()
        .collect();
        let refused = handle_trace_path(&missing, &store).unwrap();
        assert_eq!(refused.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &refused.content[0];
        assert!(text.contains("nope"), "{text}");

        let no_to: HashMap<String, serde_json::Value> =
            [("from".to_string(), serde_json::json!("a"))]
                .into_iter()
                .collect();
        assert!(matches!(
            handle_trace_path(&no_to, &store),
            Err(McpError::InvalidParams(_))
        ));
    }

    /// An absent route carries a negative whose kind names the route, so an
    /// agent calibrates the absence instead of reading an empty list.
    #[test]
    fn a_no_route_answer_carries_a_no_route_negative() {
        let store = InMemoryGraph::new();
        let a = function("a", "src/a.ts");
        let b = function("b", "src/b.ts");
        seed(&store, &[&a, &b], &[]);
        let args: HashMap<String, serde_json::Value> = [
            ("from".to_string(), serde_json::json!("a")),
            ("to".to_string(), serde_json::json!("b")),
        ]
        .into_iter()
        .collect();
        let result = handle_trace_path(&args, &store).unwrap();
        let enveloped =
            crate::finalize_with_envelope(result, crate::Envelope::offline(), TOOL_NAME);
        let crate::types::ContentBlock::Text { text } = &enveloped.content[0];
        let annotated: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(annotated["found"], serde_json::json!(false));
        assert_eq!(
            annotated[crate::NEGATIVE_KEY]["kind"],
            serde_json::json!("no_route")
        );
        assert!(annotated[crate::NEGATIVE_KEY]["safe_to_conclude_absent"].is_boolean());
    }

    /// A qualified name that names no entity resolves to its leaf when one
    /// entity carries it, and is refused with the candidates listed when
    /// several do, so a twin is never chosen silently under a qualifier.
    #[test]
    fn a_qualified_name_takes_a_unique_leaf_and_refuses_leaf_twins() {
        let store = InMemoryGraph::new();
        let run = function("run", "src/core/main.rs");
        let search_a = function("search", "src/core/main.rs");
        let search_b = function("search", "src/core/search.rs");
        seed(
            &store,
            &[&run, &search_a, &search_b],
            &[
                relation(&run, &search_a, RelationKind::Calls),
                relation(&search_a, &search_b, RelationKind::Calls),
            ],
        );

        let unique =
            build_path_response(&store, &request("Worker::run", "search@search.rs")).unwrap();
        assert!(unique.found, "{unique:?}");
        assert_eq!(unique.from.entity_id, run.id.to_string());
        assert_eq!(unique.from.addressed_by, "leaf_name");

        let refused = build_path_response(&store, &request("Worker::run", "Worker::search"));
        let error = refused.expect_err("two leaf twins under a qualifier are refused");
        assert!(error.is_resolution_miss());
        let message = error.to_string();
        assert!(message.contains("names 2 entities"), "{message}");
        assert!(
            message.contains("src/core/main.rs") && message.contains("src/core/search.rs"),
            "the refusal lists the twins so the caller can pin one: {message}"
        );

        let pinned =
            build_path_response(&store, &request("Worker::run", "Worker::search@search.rs"))
                .unwrap();
        assert_eq!(pinned.to.entity_id, search_b.id.to_string());
        assert_eq!(pinned.to.addressed_by, "name_and_file");
    }

    #[test]
    fn direction_parse_accepts_aliases_and_refuses_nonsense() {
        assert_eq!(
            PathDirection::parse("Forward").unwrap(),
            PathDirection::Forward
        );
        assert_eq!(PathDirection::parse("in").unwrap(), PathDirection::Reverse);
        assert_eq!(PathDirection::parse("").unwrap(), PathDirection::Either);
        assert!(PathDirection::parse("sideways").is_err());
    }

    #[test]
    fn file_hints_match_suffixes_and_longer_paths() {
        let entity = function("f", "src/requests/sessions.py");
        assert!(file_matches(&entity, "sessions.py"));
        assert!(file_matches(&entity, "requests/sessions.py"));
        assert!(file_matches(&entity, "src/requests/sessions.py"));
        assert!(file_matches(&entity, "/workspace/src/requests/sessions.py"));
        assert!(!file_matches(&entity, "models.py"));
        assert!(!file_matches(&entity, "s.py"));
        assert_eq!(split_pinned("run@src/a.c"), ("run", Some("src/a.c")));
        assert_eq!(split_pinned("run"), ("run", None));
        assert_eq!(split_pinned("@a.c"), ("@a.c", None));
    }
}
