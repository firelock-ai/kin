// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Context packs built from several focal entities at once.
//!
//! A real question names several things. "When I type a character in the
//! editor, how does it end up in the document" names the typing, the editor and
//! the document, and the answer is the material between them. The single-focal
//! builder in [`crate::builder`] answers a different question: it takes one
//! entity and spends the whole budget around it, so a pack built for one end of
//! a chain carries that end twice over and the other end not at all.
//!
//! This module assembles a pack from every focal, under three rules:
//!
//! 1. **Every focal is in the pack.** Focal bodies are admitted first, each at
//!    the deepest projection its share affords, so a chain question never comes
//!    back describing one end.
//! 2. **The route between connected focals comes before either focal's
//!    neighbourhood.** Two focals joined by a dependency chain are joined by
//!    something, and that something is the answer. Spending the budget on the
//!    ends first is what leaves the middle out.
//! 3. **The rest is water-filled.** Each focal's neighbourhood gets an equal
//!    share; a focal that needs less than its share hands the surplus back and
//!    the rest split it again, so a short neighbourhood never holds budget a
//!    long one needed.
//!
//! The pack also comes in **under** the budget it was given. The single-focal
//! builder keeps one row per section whatever the budget says, which is a
//! deliberate choice there and reports itself in the rendering, but it means
//! `--budget 500` can return more than 500 tokens. Here the assembled output is
//! rendered, measured with [`crate::estimate_tokens`], and shrunk row by row
//! until it fits, and the measured number is reported beside the requested one.

use std::collections::{BTreeMap, HashMap, HashSet};

use kin_model::{
    ContextEntry, ContextPack, Entity, EntityId, GraphNodeId, GraphStore, ProjectionLevel,
    TokenBudget,
};
use serde::{Deserialize, Serialize};

use crate::builder::{
    build_context_pack_with_provenance, group, is_dependency_edge, project_full_body,
    project_name_and_kind, project_signature_only, AssistantHint, ContextOptions,
    DependencyRelation,
};
use crate::error::{ContextError, Result};
use crate::tokens::estimate_tokens;

/// The reason code a row the token budget refused carries.
///
/// The same string `kin_mcp::budget::ELISION_REASON_TOKEN_BUDGET` and the CLI's
/// `CONTEXT_ELISION_REASON_TOKEN_BUDGET` publish, so a reader moving between the
/// three surfaces is not learning three vocabularies for one fact.
pub const ELISION_REASON_TOKEN_BUDGET: &str = "token_budget";

/// The elision group naming focals the budget could not carry at all.
pub const FOCAL_GROUP: &str = "focal_entities";

/// The pack section route rows join.
///
/// [`ContextPack`] is defined in `kin-model`, which this repository consumes
/// from the registry at a pinned version, so route material cannot have a field
/// of its own yet. `transitive_deps` is its honest home rather than a hiding
/// place: a route entity is reached at more than one hop, which is exactly what
/// that section means. Every route row also opens with [`ROUTE_MARKER`] and is
/// named by id in [`RouteReport::via`], so no reader has to parse a comment to
/// tell a route row from a transitive dependency.
pub const ROUTE_GROUP: &str = "route";

/// The comment a route row's content opens with.
pub const ROUTE_MARKER: &str = "// route:";

/// How far a route search walks from one focal before giving up.
///
/// Four hops is two more than the single-focal pack's own depth, which is what
/// makes a route worth searching for at all: the pair this exists for is the
/// one neither focal's neighbourhood already reaches.
pub const ROUTE_MAX_HOPS: usize = 4;

/// How many entities one route search may expand before it stops.
///
/// A bound that stops a search is reported as [`RouteSearch::bounded`] rather
/// than folded into "no route found". They are different facts: one says the
/// graph joins nothing, the other says nobody looked far enough, and a caller
/// deciding whether "these are unrelated" is safe needs to know which it has.
pub const ROUTE_VISIT_MAX: usize = 4_000;

/// Passes allowed to settle the measured token count against the bytes that
/// carry it.
///
/// The measurement is self-referential: the method line names the number, so
/// writing it back changes the text being counted. It settles because
/// [`estimate_tokens`] counts a number as one token however many digits it has,
/// so the second pass confirms the first rather than chasing it. Borrowed
/// wholesale from `kin_mcp`'s `serialize_with_measured_tokens`, which solved
/// the same problem on the MCP payload.
const MEASURED_TOKEN_PASSES: usize = 4;

/// Options for [`build_multi_focal_pack`].
#[derive(Debug, Clone)]
pub struct MultiFocalOptions {
    pub budget: TokenBudget,
    /// Neighbourhood depth for a single focal. Shrinks with the focal count;
    /// see [`neighborhood_depth_for`].
    pub max_depth: u32,
    pub include_tests: bool,
    pub include_contracts: bool,
    pub assistant_hint: Option<AssistantHint>,
    /// How the caller arrived at each focal, in the same order as the focal
    /// ids. Purely descriptive: the assembler renders it into the method line
    /// and counts the tokens it costs, so the budget it guarantees covers every
    /// byte the caller will print.
    pub resolutions: Vec<FocalResolution>,
    /// One sentence on the store's semantic coverage, from the caller that
    /// asked the graph for it. Rendered into the method line, so a reader
    /// learns what the ranking behind these focals could and could not see.
    pub coverage: Option<String>,
}

impl Default for MultiFocalOptions {
    fn default() -> Self {
        Self {
            budget: TokenBudget::Small8k,
            max_depth: 2,
            include_tests: true,
            include_contracts: true,
            assistant_hint: None,
            resolutions: Vec::new(),
            coverage: None,
        }
    }
}

/// How a caller arrived at one focal.
///
/// A pack whose focals were located from a question is a different claim from
/// one whose focals were named, and a reader deciding how much to trust the
/// selection needs the difference. The score is the ranking's own number,
/// carried rather than re-derived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FocalResolution {
    /// `id`, `name` or `question`.
    pub route: String,
    /// What the caller typed. Empty when the question route chose this focal.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub query: String,
    /// The ranking score, on the question route only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// How many entities the store carries under this exact name.
    ///
    /// Two is the ordinary case for a definition beside its header
    /// declaration, and it is the case that used to be invisible: the store
    /// lists twins in no stable order, so two ingests of one tree resolved the
    /// same name to different entities. Reported so a reader knows a choice was
    /// made, and so a caller that wants the other twin knows there is one.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub twins: usize,
    /// What pinned this twin, when the caller said which one they meant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl FocalResolution {
    /// The caller gave this focal's entity id.
    pub fn by_id(query: impl Into<String>) -> Self {
        Self {
            route: "id".to_string(),
            query: query.into(),
            score: None,
            twins: 0,
            pin: None,
        }
    }

    /// The caller gave a name that resolved to this focal.
    pub fn by_name(query: impl Into<String>) -> Self {
        Self {
            route: "name".to_string(),
            query: query.into(),
            score: None,
            twins: 0,
            pin: None,
        }
    }

    /// The question's own ranking chose this focal, at this score.
    pub fn from_question(score: f32) -> Self {
        Self {
            route: "question".to_string(),
            query: String::new(),
            score: Some(score),
            twins: 0,
            pin: None,
        }
    }

    /// Note that this name has twins in the store, and which one was taken.
    pub fn with_twins(mut self, twins: usize, pin: Option<String>) -> Self {
        self.twins = twins;
        self.pin = pin;
        self
    }

    /// One clause for the method line.
    fn describe(&self) -> String {
        let base = match self.route.as_str() {
            "question" => match self.score {
                Some(score) => format!("located from the question, score {score:.2}"),
                None => "located from the question".to_string(),
            },
            "id" => "named by id".to_string(),
            _ if self.query.is_empty() => "named".to_string(),
            _ => format!("named as {}", self.query),
        };
        match (self.twins, &self.pin) {
            (0 | 1, _) => base,
            (twins, Some(pin)) => format!("{base}, 1 of {twins} under that name, pinned by {pin}"),
            (twins, None) => format!("{base}, 1 of {twins} under that name"),
        }
    }
}

impl Default for FocalResolution {
    fn default() -> Self {
        Self {
            route: "name".to_string(),
            query: String::new(),
            score: None,
            twins: 0,
            pin: None,
        }
    }
}

/// What one focal put into the pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FocalContribution {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// `full_body`, `signature_only`, `name_and_kind`, or `elided` when the
    /// budget could not carry even this focal's name.
    pub projection: String,
    /// Tokens the focal's own entry costs.
    pub focal_tokens: usize,
    /// Neighbourhood rows this focal contributed.
    pub neighborhood_rows: usize,
    /// Tokens those rows cost.
    pub neighborhood_tokens: usize,
    /// Rows this focal's neighbourhood offered that an earlier focal or a route
    /// had already contributed. Reported rather than dropped silently: overlap
    /// is evidence the focals are related, which is the opposite of waste.
    pub shared_rows: usize,
    /// Rows the budget refused after this focal's allowance ran out.
    pub withheld_rows: usize,
    pub resolution: FocalResolution,
}

/// A route the graph carries between two focals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteReport {
    pub from: String,
    pub from_name: String,
    pub to: String,
    pub to_name: String,
    /// Edges on the route, which is one more than the entities between the
    /// ends.
    pub hops: usize,
    /// Entities admitted from this route, in walk order from `from` to `to`.
    pub via: Vec<String>,
    pub via_names: Vec<String>,
    pub tokens: usize,
    /// Route entities the budget could not carry, or that another focal had
    /// already put in the pack.
    pub withheld: usize,
}

/// What the route search did, including whether a bound stopped it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RouteSearch {
    pub pairs_examined: usize,
    pub pairs_connected: usize,
    /// True when [`ROUTE_VISIT_MAX`] stopped a search before it could answer.
    /// While this is true, an absent route is not evidence that none exists.
    pub bounded: bool,
    pub max_hops: usize,
}

/// What one pack section lost to the token budget.
///
/// The same four fields, under the same names, that `kin context --json` and
/// the `get_context_pack` MCP tool already publish.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackElision {
    pub elided: usize,
    pub kept: usize,
    pub total: usize,
    pub reason: String,
}

/// How a multi-focal pack was built, and what it cost.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultiFocalReport {
    pub focals: Vec<FocalContribution>,
    pub routes: Vec<RouteReport>,
    pub route_search: RouteSearch,
    /// The neighbourhood depth each focal got, after shaping by focal count.
    pub neighborhood_depth: u32,
    /// The budget the caller asked for.
    pub budget_tokens: usize,
    /// What the rendered output actually costs, by [`crate::estimate_tokens`].
    /// Never above `budget_tokens`: the assembler drops rows until it is not.
    pub measured_tokens: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub elisions: BTreeMap<String, PackElision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<String>,
    /// The method sentence, as rendered into the human form.
    pub method: String,
    /// `full` or `compact`.
    ///
    /// The method line costs tokens like everything else, and on a tight budget
    /// with several focals it can be the largest single thing in the pack. When
    /// dropping every row still leaves the output over budget, the sentence
    /// itself shortens rather than the pack silently going over, and this field
    /// is how a reader knows which sentence they are reading.
    #[serde(default = "default_method_style")]
    pub method_style: String,
}

fn default_method_style() -> String {
    "full".to_string()
}

/// The neighbourhood depth one focal gets, given how many share the pack.
///
/// One focal keeps the depth the single-focal pack always used. Two or more
/// shrink to direct neighbours, because the answer to a chain question lives
/// between the focals: paying two hops around each end spends the budget on the
/// ends and leaves the middle for whatever is left, which is the failure this
/// module exists to fix.
pub fn neighborhood_depth_for(focal_count: usize, base: u32) -> u32 {
    if focal_count <= 1 {
        base
    } else {
        1
    }
}

/// Split `capacity` across `demands` so a small claim never holds budget a
/// large one needed.
///
/// Every claimant gets an equal share. A claimant whose demand is under its
/// share takes exactly what it needs and hands the surplus back, and the
/// remaining claimants split the remainder again, until nobody fits their share
/// and the rest divide it evenly. Returns one allowance per demand, in order.
///
/// The alternative, an equal share for everyone, is what makes a short
/// neighbourhood waste budget: a focal needing 40 tokens holds 300 while the
/// focal that carried the answer is cut at 300.
pub fn water_fill(demands: &[usize], capacity: usize) -> Vec<usize> {
    let mut allowance = vec![0usize; demands.len()];
    let mut pending: Vec<usize> = (0..demands.len()).collect();
    let mut room = capacity;

    while !pending.is_empty() {
        let share = room / pending.len();
        let fits: Vec<usize> = pending
            .iter()
            .copied()
            .filter(|index| demands[*index] <= share)
            .collect();
        if fits.is_empty() {
            for index in pending {
                allowance[index] = share;
            }
            break;
        }
        for index in &fits {
            allowance[*index] = demands[*index];
            room -= demands[*index];
        }
        pending.retain(|index| !fits.contains(index));
    }

    allowance
}

/// The outcome of one route search between two focals.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RouteOutcome {
    /// The entities strictly between the two focals, in walk order.
    Found(Vec<EntityId>),
    /// The walk finished within its bounds and found nothing.
    None,
    /// A bound stopped the walk, so nothing was proved either way.
    Bounded,
}

/// Work allowance for one route search.
struct RouteMeter {
    remaining: usize,
}

impl RouteMeter {
    fn new(budget: usize) -> Self {
        Self { remaining: budget }
    }

    /// Charge one expansion. Returns false once the allowance is spent.
    fn charge(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

/// The entities on a dependency route between two focals, if the graph joins
/// them within `max_hops`.
///
/// Direction is deliberately ignored. "How does a character reach the document"
/// is answered by the chain whether the walk reads it as calls out of the
/// keyboard or callers into the document, and a route search that respected
/// direction would report two halves of one answer as no answer at all. The
/// edges are still restricted to real dependency edges by
/// [`is_dependency_edge`], so a co-change or containment coincidence cannot
/// manufacture a route.
fn route_between<G>(
    graph: &G,
    from: &EntityId,
    to: &EntityId,
    max_hops: usize,
    meter: &mut RouteMeter,
) -> Result<RouteOutcome>
where
    G: GraphStore,
{
    if from == to {
        return Ok(RouteOutcome::Found(Vec::new()));
    }

    let mut parent: HashMap<EntityId, EntityId> = HashMap::new();
    let mut seen: HashSet<EntityId> = HashSet::new();
    seen.insert(*from);
    let mut frontier = vec![*from];

    for _hop in 0..max_hops {
        let mut next = Vec::new();
        for node in frontier.drain(..) {
            if !meter.charge() {
                return Ok(RouteOutcome::Bounded);
            }
            let relations = graph
                .get_all_relations_for_entity(&node)
                .map_err(|error| ContextError::Graph(error.to_string()))?;
            let node_ref = GraphNodeId::Entity(node);
            for relation in &relations {
                if !is_dependency_edge(&relation.kind) {
                    continue;
                }
                let neighbor = if relation.src == node_ref {
                    relation.dst.as_entity()
                } else if relation.dst == node_ref {
                    relation.src.as_entity()
                } else {
                    None
                };
                let Some(neighbor) = neighbor else { continue };
                if neighbor == node {
                    continue;
                }
                if neighbor == *to {
                    parent.insert(neighbor, node);
                    return Ok(RouteOutcome::Found(walk_back(&parent, from, to)));
                }
                if seen.insert(neighbor) {
                    parent.insert(neighbor, node);
                    next.push(neighbor);
                }
            }
        }
        if next.is_empty() {
            return Ok(RouteOutcome::None);
        }
        frontier = next;
    }

    Ok(RouteOutcome::None)
}

/// The entities strictly between `from` and `to`, read out of a parent map.
fn walk_back(
    parent: &HashMap<EntityId, EntityId>,
    from: &EntityId,
    to: &EntityId,
) -> Vec<EntityId> {
    let mut chain = Vec::new();
    let mut cursor = *to;
    while let Some(previous) = parent.get(&cursor) {
        if previous == from {
            break;
        }
        chain.push(*previous);
        cursor = *previous;
    }
    chain.reverse();
    chain
}

/// One row waiting for a place in the pack.
struct Candidate {
    entity_id: EntityId,
    projection_level: ProjectionLevel,
    content: String,
    tokens: usize,
    /// Which section this row joins, by the names in [`crate::group`] plus
    /// [`ROUTE_GROUP`].
    group: &'static str,
}

/// A row that reached the pack, in admission order, so the budget fit can drop
/// the lowest-priority row first.
struct Admitted {
    group: &'static str,
    entity_id: EntityId,
    tokens: usize,
    /// The focal whose neighbourhood offered it, or the route it came from.
    origin: Origin,
}

#[derive(Clone, Copy)]
enum Origin {
    Route(usize),
    Neighborhood(usize),
}

/// Where a pack section's rows live, so an admitted row can be dropped again.
fn section_mut<'pack>(
    pack: &'pack mut ContextPack,
    group_name: &str,
) -> &'pack mut Vec<ContextEntry> {
    match group_name {
        group::DEPENDENCIES | group::DEPENDENTS => &mut pack.dependency_signatures,
        group::TESTS => &mut pack.tests,
        group::CONTRACTS => &mut pack.contracts,
        // Route rows and transitive dependencies share a section; see
        // [`ROUTE_GROUP`] for why, and [`RouteReport::via`] for how a reader
        // tells them apart without reading content.
        _ => &mut pack.transitive_deps,
    }
}

/// Build a context pack from several focal entities.
///
/// `focal_ids` is taken in the caller's order, which is the order the question
/// named them, and duplicates collapse to the first mention. The pack that
/// comes back carries every focal it could afford, the route material between
/// connected focals, and each focal's neighbourhood water-filled into what
/// remained, and it measures under `opts.budget`.
pub fn build_multi_focal_pack<G>(
    graph: &G,
    focal_ids: &[EntityId],
    opts: &MultiFocalOptions,
) -> Result<(ContextPack, MultiFocalReport)>
where
    G: GraphStore,
{
    let mut ordered: Vec<EntityId> = Vec::new();
    for id in focal_ids {
        if !ordered.contains(id) {
            ordered.push(*id);
        }
    }
    if ordered.is_empty() {
        return Err(ContextError::Other(
            "a context pack needs at least one focal entity".to_string(),
        ));
    }

    let budget_max = opts.budget.max_tokens();
    let mut focals: Vec<Entity> = Vec::with_capacity(ordered.len());
    for id in &ordered {
        let entity = graph
            .get_entity(id)
            .map_err(|error| ContextError::Graph(error.to_string()))?
            .ok_or_else(|| ContextError::EntityNotFound(id.to_string()))?;
        focals.push(entity);
    }

    let depth = neighborhood_depth_for(focals.len(), opts.max_depth);
    let mut admitted: HashSet<EntityId> = focals.iter().map(|entity| entity.id).collect();
    let mut spent = 0usize;

    // 1. The focals themselves, each at the deepest projection its share
    //    affords. A focal that cannot fit even its name is reported rather than
    //    dropped quietly, because a pack silently missing one end of a chain is
    //    the exact failure this module was written for.
    let full_bodies: Vec<String> = focals.iter().map(project_full_body).collect();
    let demands: Vec<usize> = full_bodies
        .iter()
        .map(|body| estimate_tokens(body))
        .collect();
    let allowances = water_fill(&demands, budget_max);

    let mut focal_entries: Vec<ContextEntry> = Vec::new();
    let mut contributions: Vec<FocalContribution> = Vec::new();
    let mut focals_elided = 0usize;
    // The cheaper rungs of each focal's projection ladder, kept so the budget
    // fit can walk a focal down instead of dropping it. Built here because the
    // fit runs on the assembled pack and no longer holds the entities.
    let mut ladders: HashMap<EntityId, (String, String)> = HashMap::new();

    for (index, entity) in focals.iter().enumerate() {
        let room = allowances[index].min(budget_max.saturating_sub(spent));
        let signature = project_signature_only(entity);
        let name_and_kind = project_name_and_kind(entity);
        ladders.insert(entity.id, (signature.clone(), name_and_kind.clone()));
        let ladder = [
            (ProjectionLevel::FullBody, full_bodies[index].clone()),
            (ProjectionLevel::SignatureOnly, signature),
            (ProjectionLevel::NameAndKind, name_and_kind),
        ];
        let chosen = ladder
            .into_iter()
            .find(|(_, content)| estimate_tokens(content) <= room);

        let resolution = opts
            .resolutions
            .get(index)
            .cloned()
            .unwrap_or_else(|| FocalResolution::by_name(entity.name.clone()));
        let (projection, focal_tokens) = match chosen {
            Some((level, content)) => {
                let cost = estimate_tokens(&content);
                spent += cost;
                focal_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: level,
                    content,
                });
                (projection_name(level).to_string(), cost)
            }
            None => {
                focals_elided += 1;
                // Not in the pack, so not spoken for: a later route or
                // neighbourhood row may still carry this entity's signature,
                // which is more of it than the pack would otherwise have.
                admitted.remove(&entity.id);
                ("elided".to_string(), 0)
            }
        };

        contributions.push(FocalContribution {
            entity_id: entity.id.to_string(),
            name: entity.name.clone(),
            kind: format!("{:?}", entity.kind),
            file: entity.file_origin.as_ref().map(|origin| origin.to_string()),
            line: entity.span.as_ref().map(|span| span.start_line),
            projection,
            focal_tokens,
            neighborhood_rows: 0,
            neighborhood_tokens: 0,
            shared_rows: 0,
            withheld_rows: 0,
            resolution,
        });
    }

    // A pack with no focal is not an answer, and refusing here would refuse with
    // the wrong number: the cheapest body is not what the output costs. Keep the
    // first focal at its cheapest projection even when the budget cannot hold
    // it, and let the fit below refuse with what the rendering actually costs.
    // One refusal, one number, and the number is a budget that would have worked.
    if focal_entries.is_empty() {
        let entity = &focals[0];
        let content = project_name_and_kind(entity);
        spent += estimate_tokens(&content);
        focal_entries.push(ContextEntry {
            entity_id: entity.id,
            projection_level: ProjectionLevel::NameAndKind,
            content,
        });
        admitted.insert(entity.id);
        focals_elided -= 1;
        contributions[0].projection = projection_name(ProjectionLevel::NameAndKind).to_string();
        contributions[0].focal_tokens = estimate_tokens(&project_name_and_kind(entity));
    }

    // 2. The route between connected focals, before either end's neighbourhood.
    let mut route_search = RouteSearch {
        max_hops: ROUTE_MAX_HOPS,
        ..RouteSearch::default()
    };
    let mut routes: Vec<RouteReport> = Vec::new();
    let mut route_candidates: Vec<(usize, Candidate, String)> = Vec::new();

    for left in 0..focals.len() {
        for right in (left + 1)..focals.len() {
            route_search.pairs_examined += 1;
            let mut meter = RouteMeter::new(ROUTE_VISIT_MAX);
            let outcome = route_between(
                graph,
                &focals[left].id,
                &focals[right].id,
                ROUTE_MAX_HOPS,
                &mut meter,
            )?;
            let via = match outcome {
                RouteOutcome::Bounded => {
                    route_search.bounded = true;
                    continue;
                }
                RouteOutcome::None => continue,
                RouteOutcome::Found(via) => via,
            };
            route_search.pairs_connected += 1;
            let route_index = routes.len();
            let mut report = RouteReport {
                from: focals[left].id.to_string(),
                from_name: focals[left].name.clone(),
                to: focals[right].id.to_string(),
                to_name: focals[right].name.clone(),
                hops: via.len() + 1,
                via: Vec::new(),
                via_names: Vec::new(),
                tokens: 0,
                withheld: 0,
            };
            for (step, id) in via.iter().enumerate() {
                if admitted.contains(id) {
                    report.withheld += 1;
                    continue;
                }
                let Some(entity) = graph
                    .get_entity(id)
                    .map_err(|error| ContextError::Graph(error.to_string()))?
                else {
                    report.withheld += 1;
                    continue;
                };
                let content = format!(
                    "{ROUTE_MARKER} {} to {}, step {} of {}\n{}",
                    focals[left].name,
                    focals[right].name,
                    step + 1,
                    via.len(),
                    project_signature_only(&entity)
                );
                let tokens = estimate_tokens(&content);
                admitted.insert(*id);
                route_candidates.push((
                    route_index,
                    Candidate {
                        entity_id: *id,
                        projection_level: ProjectionLevel::SignatureOnly,
                        content,
                        tokens,
                        group: ROUTE_GROUP,
                    },
                    entity.name.clone(),
                ));
            }
            routes.push(report);
        }
    }

    // 3. Each focal's neighbourhood, offered whole so the water-filling sees
    //    real demands, then admitted under the share those demands earn.
    let mut neighborhood: Vec<Vec<Candidate>> = Vec::with_capacity(focals.len());
    for entity in &focals {
        let sub_opts = ContextOptions {
            budget: opts.budget,
            max_depth: depth,
            include_tests: opts.include_tests,
            include_contracts: opts.include_contracts,
            include_traffic: false,
            assistant_hint: opts.assistant_hint,
        };
        let (pack, selection) = build_context_pack_with_provenance(graph, &entity.id, &sub_opts)?;
        let mut rows: Vec<Candidate> = Vec::new();
        for entry in &pack.dependency_signatures {
            let group_name = match selection.relation_for(&entry.entity_id) {
                DependencyRelation::DependentEdge => group::DEPENDENTS,
                _ => group::DEPENDENCIES,
            };
            rows.push(candidate_from(entry, group_name));
        }
        for entry in &pack.transitive_deps {
            rows.push(candidate_from(entry, group::TRANSITIVE_DEPS));
        }
        for entry in &pack.tests {
            rows.push(candidate_from(entry, group::TESTS));
        }
        for entry in &pack.contracts {
            rows.push(candidate_from(entry, group::CONTRACTS));
        }
        neighborhood.push(rows);
    }

    let mut assembled = ContextPack {
        focal_entities: focal_entries,
        dependency_signatures: Vec::new(),
        transitive_deps: Vec::new(),
        contracts: Vec::new(),
        tests: Vec::new(),
        work_items: Vec::new(),
        annotations: Vec::new(),
        traffic: Vec::new(),
        supporting_artifacts: Vec::new(),
        token_budget: opts.budget,
        actual_tokens: 0,
    };

    // Route rows are admitted before any neighbourhood row, and dropped last.
    let mut order: Vec<Admitted> = Vec::new();
    let mut withheld: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (route_index, candidate, name) in route_candidates {
        if spent + candidate.tokens > budget_max {
            routes[route_index].withheld += 1;
            *withheld.entry(ROUTE_GROUP).or_default() += 1;
            continue;
        }
        spent += candidate.tokens;
        routes[route_index].tokens += candidate.tokens;
        routes[route_index]
            .via
            .push(candidate.entity_id.to_string());
        routes[route_index].via_names.push(name);
        order.push(Admitted {
            group: candidate.group,
            entity_id: candidate.entity_id,
            tokens: candidate.tokens,
            origin: Origin::Route(route_index),
        });
        section_mut(&mut assembled, candidate.group).push(ContextEntry {
            entity_id: candidate.entity_id,
            projection_level: candidate.projection_level,
            content: candidate.content,
        });
    }

    // The neighbourhood share is what the focals and routes left.
    let neighborhood_demands: Vec<usize> = neighborhood
        .iter()
        .map(|rows| {
            rows.iter()
                .filter(|row| !admitted.contains(&row.entity_id))
                .map(|row| row.tokens)
                .sum()
        })
        .collect();
    let neighborhood_allowances =
        water_fill(&neighborhood_demands, budget_max.saturating_sub(spent));

    for (index, rows) in neighborhood.into_iter().enumerate() {
        let mut left = neighborhood_allowances[index];
        for row in rows {
            if admitted.contains(&row.entity_id) {
                contributions[index].shared_rows += 1;
                continue;
            }
            if row.tokens > left || spent + row.tokens > budget_max {
                contributions[index].withheld_rows += 1;
                *withheld.entry(row.group).or_default() += 1;
                continue;
            }
            left -= row.tokens;
            spent += row.tokens;
            admitted.insert(row.entity_id);
            contributions[index].neighborhood_rows += 1;
            contributions[index].neighborhood_tokens += row.tokens;
            order.push(Admitted {
                group: row.group,
                entity_id: row.entity_id,
                tokens: row.tokens,
                origin: Origin::Neighborhood(index),
            });
            section_mut(&mut assembled, row.group).push(ContextEntry {
                entity_id: row.entity_id,
                projection_level: row.projection_level,
                content: row.content,
            });
        }
    }

    assembled.actual_tokens = spent;

    let mut report = MultiFocalReport {
        focals: contributions,
        routes,
        route_search,
        neighborhood_depth: depth,
        budget_tokens: budget_max,
        measured_tokens: 0,
        elisions: BTreeMap::new(),
        coverage: opts.coverage.clone(),
        method: String::new(),
        method_style: default_method_style(),
    };
    if focals_elided > 0 {
        let kept = report.focals.len() - focals_elided;
        record_elision(&mut report.elisions, FOCAL_GROUP, focals_elided, kept);
    }
    for (group_name, count) in withheld {
        let kept = kept_in_group(&assembled, group_name);
        record_elision(&mut report.elisions, group_name, count, kept);
    }

    // 4. Render, measure what the rendering costs, and shrink until the pack is
    //    under the budget it was given. The single-focal builder reports going
    //    over; this one does not go over. A caller that asked for 500 tokens
    //    and received 700 spent budget it did not have, on every call, which is
    //    what the demo measured and had to compensate for.
    fit_to_budget(
        &mut assembled,
        &mut report,
        &mut order,
        &ladders,
        budget_max,
    )?;

    Ok((assembled, report))
}

fn candidate_from(entry: &ContextEntry, group_name: &'static str) -> Candidate {
    Candidate {
        entity_id: entry.entity_id,
        projection_level: entry.projection_level,
        content: entry.content.clone(),
        tokens: estimate_tokens(&entry.content),
        group: group_name,
    }
}

/// Render, measure, and drop the lowest-priority row until the whole output
/// fits the budget.
///
/// Dropping runs in reverse admission order, so a neighbourhood row goes before
/// a route row and a route row before a focal. The loop only ever shrinks the
/// output, so it terminates; when nothing is left to drop and the header alone
/// is still over, that is a budget too small to answer in and it is reported as
/// one rather than silently exceeded.
fn fit_to_budget(
    pack: &mut ContextPack,
    report: &mut MultiFocalReport,
    order: &mut Vec<Admitted>,
    ladders: &HashMap<EntityId, (String, String)>,
    budget_max: usize,
) -> Result<()> {
    loop {
        let measured = settle_measurement(pack, report);
        if measured <= budget_max {
            pack.actual_tokens = measured;
            return Ok(());
        }
        let Some(dropped) = order.pop() else {
            // Nothing left to drop. The sentence describing the pack is now
            // most of the pack, so shorten it once and try again.
            if report.method_style == "full" {
                report.method_style = "compact".to_string();
                continue;
            }
            // Then the focals themselves shrink, deepest projection first and
            // last focal first, because a pack of five names beats a pack of
            // one body when the question named five things.
            if shrink_one_focal(pack, report, ladders) {
                continue;
            }
            // Then focals go, last named first, keeping the one the caller
            // asked for first. A pack of two of five focals is a narrower
            // answer than the question, and the method line says which ones it
            // lost, which is worth more than refusing outright. Below one focal
            // there is no pack to have, and that is a budget too small to
            // answer in.
            if pack.focal_entities.len() > 1 {
                let dropped = pack
                    .focal_entities
                    .pop()
                    .expect("a list of more than one has a last element");
                let id = dropped.entity_id.to_string();
                if let Some(contribution) =
                    report.focals.iter_mut().find(|focal| focal.entity_id == id)
                {
                    contribution.projection = "elided".to_string();
                    contribution.focal_tokens = 0;
                }
                bump_elision(&mut report.elisions, FOCAL_GROUP, pack.focal_entities.len());
                continue;
            }
            return Err(ContextError::BudgetExceeded {
                actual: measured,
                budget: budget_max,
            });
        };
        let section = section_mut(pack, dropped.group);
        if let Some(position) = section
            .iter()
            .position(|entry| entry.entity_id == dropped.entity_id)
        {
            section.remove(position);
        }
        match dropped.origin {
            Origin::Neighborhood(index) => {
                if let Some(contribution) = report.focals.get_mut(index) {
                    contribution.neighborhood_rows =
                        contribution.neighborhood_rows.saturating_sub(1);
                    contribution.neighborhood_tokens = contribution
                        .neighborhood_tokens
                        .saturating_sub(dropped.tokens);
                    contribution.withheld_rows += 1;
                }
            }
            Origin::Route(index) => {
                if let Some(route) = report.routes.get_mut(index) {
                    let id = dropped.entity_id.to_string();
                    if let Some(position) = route.via.iter().position(|via| *via == id) {
                        route.via.remove(position);
                        if position < route.via_names.len() {
                            route.via_names.remove(position);
                        }
                    }
                    route.tokens = route.tokens.saturating_sub(dropped.tokens);
                    route.withheld += 1;
                }
            }
        }
        let kept = kept_in_group(pack, dropped.group);
        bump_elision(&mut report.elisions, dropped.group, kept);
    }
}

/// Walk one focal down its projection ladder, and report whether anything
/// moved.
///
/// Deepest projection first so the most expensive row is the one that shrinks,
/// and last focal first so the entity the caller named first is the last to
/// lose its body.
fn shrink_one_focal(
    pack: &mut ContextPack,
    report: &mut MultiFocalReport,
    ladders: &HashMap<EntityId, (String, String)>,
) -> bool {
    for level in [ProjectionLevel::FullBody, ProjectionLevel::SignatureOnly] {
        let Some(position) = pack
            .focal_entities
            .iter()
            .rposition(|entry| entry.projection_level == level)
        else {
            continue;
        };
        let entry = &mut pack.focal_entities[position];
        let Some((signature, name_and_kind)) = ladders.get(&entry.entity_id) else {
            continue;
        };
        let (next_level, next_content) = match level {
            ProjectionLevel::FullBody => (ProjectionLevel::SignatureOnly, signature),
            _ => (ProjectionLevel::NameAndKind, name_and_kind),
        };
        entry.projection_level = next_level;
        entry.content = next_content.clone();
        let id = entry.entity_id.to_string();
        let cost = estimate_tokens(next_content);
        if let Some(contribution) = report.focals.iter_mut().find(|focal| focal.entity_id == id) {
            contribution.projection = projection_name(next_level).to_string();
            contribution.focal_tokens = cost;
        }
        return true;
    }
    false
}

/// Settle the measured token count against the bytes carrying it, and return
/// what the rendering the report now describes actually costs.
///
/// See [`MEASURED_TOKEN_PASSES`] for why this converges. The returned number is
/// always the cost of the rendering produced by the report's final method line,
/// so the budget decision is made against the real output rather than against
/// an earlier draft of it.
fn settle_measurement(pack: &ContextPack, report: &mut MultiFocalReport) -> usize {
    let mut measured = report.measured_tokens;
    for _ in 0..MEASURED_TOKEN_PASSES {
        report.measured_tokens = measured;
        report.method = method_line(report);
        let rendered = estimate_tokens(&render_multi_focal_lines(pack, report).join("\n"));
        if rendered == measured {
            return measured;
        }
        measured = rendered;
    }
    report.measured_tokens = measured;
    report.method = method_line(report);
    estimate_tokens(&render_multi_focal_lines(pack, report).join("\n"))
}

/// Rows one group still carries.
fn kept_in_group(pack: &ContextPack, group_name: &str) -> usize {
    match group_name {
        FOCAL_GROUP => pack.focal_entities.len(),
        group::DEPENDENCIES | group::DEPENDENTS => pack.dependency_signatures.len(),
        group::TESTS => pack.tests.len(),
        group::CONTRACTS => pack.contracts.len(),
        ROUTE_GROUP => pack
            .transitive_deps
            .iter()
            .filter(|entry| entry.content.starts_with(ROUTE_MARKER))
            .count(),
        _ => pack
            .transitive_deps
            .iter()
            .filter(|entry| !entry.content.starts_with(ROUTE_MARKER))
            .count(),
    }
}

fn record_elision(
    elisions: &mut BTreeMap<String, PackElision>,
    group_name: &str,
    elided: usize,
    kept: usize,
) {
    if elided == 0 {
        return;
    }
    let entry = elisions
        .entry(group_name.to_string())
        .or_insert_with(|| PackElision {
            elided: 0,
            kept,
            total: kept,
            reason: ELISION_REASON_TOKEN_BUDGET.to_string(),
        });
    entry.elided += elided;
    entry.kept = kept;
    entry.total = kept + entry.elided;
}

fn bump_elision(elisions: &mut BTreeMap<String, PackElision>, group_name: &str, kept: usize) {
    record_elision(elisions, group_name, 1, kept);
}

fn projection_name(level: ProjectionLevel) -> &'static str {
    match level {
        ProjectionLevel::FullBody => "full_body",
        ProjectionLevel::SignatureOnly => "signature_only",
        ProjectionLevel::NameAndKind => "name_and_kind",
    }
}

/// One sentence naming every focal, how it was resolved, what it contributed,
/// how the pack was merged, what it measured, and what the ranking behind it
/// could see.
///
/// It is one line on purpose. A reader scanning a pack should be able to tell
/// at a glance whether the selection is trustworthy, and a reader who wants the
/// detail has the same facts in the JSON under the same names.
pub fn method_line(report: &MultiFocalReport) -> String {
    if report.method_style == "compact" {
        return compact_method_line(report);
    }
    let focals: Vec<String> = report
        .focals
        .iter()
        .map(|contribution| {
            let where_at = match (&contribution.file, contribution.line) {
                (Some(file), Some(line)) => format!("{file}:{line}"),
                (Some(file), None) => file.clone(),
                _ => "an unknown file".to_string(),
            };
            let carried = if contribution.projection == "elided" {
                "did not fit".to_string()
            } else {
                format!(
                    "{} plus {} row{}",
                    contribution.projection,
                    contribution.neighborhood_rows,
                    if contribution.neighborhood_rows == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            };
            format!(
                "{}, {} in {}, {}, {}",
                contribution.name,
                contribution.kind,
                where_at,
                contribution.resolution.describe(),
                carried
            )
        })
        .collect();

    let route_text = if report.routes.iter().all(|route| route.via.is_empty()) {
        if report.route_search.bounded {
            format!(
                "no route material admitted, and a route search stopped at its {ROUTE_VISIT_MAX}-entity \
                 bound, so an absent route is not evidence there is none"
            )
        } else if report.route_search.pairs_connected > 0 {
            "the pairs the graph joins are joined by a direct edge, so there is no material between them"
                .to_string()
        } else {
            format!(
                "the graph joins no pair of them within {} hops",
                report.route_search.max_hops
            )
        }
    } else {
        let pairs: Vec<String> = report
            .routes
            .iter()
            .filter(|route| !route.via.is_empty())
            .map(|route| {
                format!(
                    "{} to {} in {} hop{} through {}",
                    route.from_name,
                    route.to_name,
                    route.hops,
                    if route.hops == 1 { "" } else { "s" },
                    route.via_names.join(", ")
                )
            })
            .collect();
        format!("the route between them first ({})", pairs.join("; "))
    };

    let coverage = match &report.coverage {
        Some(note) => format!("; semantic coverage: {note}"),
        None => String::new(),
    };

    format!(
        "Method: {} focal{} at depth {} ({}), {}, neighbourhoods merged by water-filling; \
         measured {} of {} tokens by kin's structure-aware estimator{}",
        report.focals.len(),
        if report.focals.len() == 1 { "" } else { "s" },
        report.neighborhood_depth,
        focals.join("; "),
        route_text,
        report.measured_tokens,
        report.budget_tokens,
        coverage
    )
}

/// The method line with everything but the load-bearing facts removed.
///
/// Which focals, how the pack was merged, and what it measured. What goes is
/// the per-focal detail (kind, file, resolution, contribution), which the JSON
/// still carries in full under `focals`: a reader on a budget this tight has
/// room for the answer or for the description of the answer, and the answer
/// wins.
fn compact_method_line(report: &MultiFocalReport) -> String {
    let names: Vec<&str> = report
        .focals
        .iter()
        .map(|contribution| contribution.name.as_str())
        .collect();
    let carried = report
        .focals
        .iter()
        .filter(|contribution| contribution.projection != "elided")
        .count();
    // Which focals did not fit is never "detail". It is the answer coming back
    // narrower than the question, and a compact line that hid it would be
    // exactly the silence the full line exists to prevent.
    let count = if carried == report.focals.len() {
        format!(
            "{} focal{}",
            report.focals.len(),
            if report.focals.len() == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{carried} of {} focals carried, the rest did not fit",
            report.focals.len()
        )
    };
    format!(
        "Method: {count} ({}), route material first, neighbourhoods water-filled; measured {} of \
         {} tokens; per-focal detail withheld to fit the budget, and carried in the JSON",
        names.join(", "),
        report.measured_tokens,
        report.budget_tokens
    )
}

/// The human rendering of a multi-focal pack, header and body.
///
/// The whole output, because the budget is a claim about the whole output. The
/// header and the method line are tokens a reader pays for just as the entries
/// are, so counting only the entries would be the same understatement this
/// module exists to remove.
pub fn render_multi_focal_lines(pack: &ContextPack, report: &MultiFocalReport) -> Vec<String> {
    let route_rows = kept_in_group(pack, ROUTE_GROUP);
    let mut lines = vec![
        format!(
            "Context pack for {} focal entit{}:",
            report.focals.len(),
            if report.focals.len() == 1 { "y" } else { "ies" }
        ),
        report.method.clone(),
        format!("  Focals: {} entries", pack.focal_entities.len()),
        format!(
            "  Route: {route_rows} entries across {} connected pair{}",
            report.route_search.pairs_connected,
            if report.route_search.pairs_connected == 1 {
                ""
            } else {
                "s"
            }
        ),
        format!(
            "  Dependencies: {} entries",
            pack.dependency_signatures.len()
        ),
        format!(
            "  Transitive: {} entries",
            kept_in_group(pack, group::TRANSITIVE_DEPS)
        ),
        format!("  Tests: {} entries", pack.tests.len()),
        format!("  Contracts: {} entries", pack.contracts.len()),
        format!(
            "  Budget: {}/{} tokens measured",
            report.measured_tokens, report.budget_tokens
        ),
    ];

    let total_elided: usize = report.elisions.values().map(|elision| elision.elided).sum();
    if total_elided > 0 {
        lines.push(format!(
            "  Raise --budget above {} to recover the {total_elided} {} the token budget withheld.",
            report.budget_tokens,
            if total_elided == 1 {
                "entry"
            } else {
                "entries"
            }
        ));
    }

    lines.push(String::new());
    lines.push("--- Context Pack ---".to_string());
    for entry in &pack.focal_entities {
        lines.push(entry.content.clone());
    }
    for entry in &pack.transitive_deps {
        if entry.content.starts_with(ROUTE_MARKER) {
            lines.push(entry.content.clone());
        }
    }
    for entry in &pack.dependency_signatures {
        lines.push(entry.content.clone());
    }
    for entry in &pack.transitive_deps {
        if !entry.content.starts_with(ROUTE_MARKER) {
            lines.push(entry.content.clone());
        }
    }
    for entry in &pack.tests {
        lines.push(entry.content.clone());
    }
    for entry in &pack.contracts {
        lines.push(entry.content.clone());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::relation::{Relation, RelationKind, RelationOrigin};
    use kin_model::*;

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
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(format!("Does {name} things")),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn calls(store: &kin_db::InMemoryGraph, src: &Entity, dst: &Entity) {
        store
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(src.id),
                dst: GraphNodeId::Entity(dst.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    /// A five-link chain, each entity in its own file so no same-file fallback
    /// can supply what only the route should.
    fn chain(len: usize) -> (kin_db::InMemoryGraph, Vec<Entity>) {
        let store = kin_db::InMemoryGraph::new();
        let mut links = Vec::new();
        for index in 0..len {
            let entity = make_entity(&format!("link_{index}"), &format!("src/link_{index}.rs"));
            store.upsert_entity(&entity).unwrap();
            links.push(entity);
        }
        for pair in links.windows(2) {
            calls(&store, &pair[0], &pair[1]);
        }
        (store, links)
    }

    /// The smallest budget this pack can be built in, taken from the refusal
    /// itself.
    ///
    /// The builder degrades until it cannot degrade further and then refuses
    /// with what the rendering costs at that point, so the number in the
    /// refusal is a budget that works. Reading it here rather than writing a
    /// constant is what keeps these tests honest when the header or the method
    /// line changes shape.
    fn floor_for(store: &kin_db::InMemoryGraph, ids: &[EntityId]) -> usize {
        match build_multi_focal_pack(store, ids, &opts(1)) {
            Err(ContextError::BudgetExceeded { actual, .. }) => actual,
            other => panic!("a one-token budget must refuse with its floor, got {other:?}"),
        }
    }

    fn opts(budget: usize) -> MultiFocalOptions {
        MultiFocalOptions {
            budget: TokenBudget::Custom(budget),
            ..MultiFocalOptions::default()
        }
    }

    // ---- water-filling -------------------------------------------------

    #[test]
    fn water_filling_hands_a_small_claim_surplus_back_to_a_large_one() {
        // Equal shares would be 50 each and the large claim would be cut at 50
        // while the small one held 40 it could not use.
        let allowances = water_fill(&[10, 190], 100);
        assert_eq!(
            allowances,
            vec![10, 90],
            "the small claim takes what it needs and the rest goes to the large one"
        );
    }

    #[test]
    fn water_filling_splits_evenly_when_nobody_fits_a_share() {
        assert_eq!(water_fill(&[500, 500, 500], 90), vec![30, 30, 30]);
    }

    #[test]
    fn water_filling_over_several_rounds_keeps_handing_surplus_up() {
        // Shares: 25 each. Only 5 fits, leaving 95 over three, share 31: 20 and
        // 30 fit, leaving 45 for the last one.
        assert_eq!(water_fill(&[5, 20, 30, 400], 100), vec![5, 20, 30, 45]);
    }

    #[test]
    fn water_filling_never_hands_out_more_than_capacity() {
        for capacity in [0usize, 1, 7, 99, 1000] {
            let allowances = water_fill(&[3, 60, 900, 1], capacity);
            let total: usize = allowances.iter().sum();
            assert!(
                total <= capacity,
                "handed out {total} of {capacity}: {allowances:?}"
            );
        }
    }

    // ---- several focals ------------------------------------------------

    #[test]
    fn every_focal_reaches_the_pack() {
        let (store, links) = chain(5);
        let focal_ids = vec![links[0].id, links[2].id, links[4].id];
        let (pack, report) = build_multi_focal_pack(&store, &focal_ids, &opts(8000)).unwrap();

        let in_pack: Vec<EntityId> = pack
            .focal_entities
            .iter()
            .map(|entry| entry.entity_id)
            .collect();
        assert_eq!(
            in_pack, focal_ids,
            "every focal is in the pack, in the order the caller named them"
        );
        assert_eq!(report.focals.len(), 3);
        assert!(
            report
                .focals
                .iter()
                .all(|focal| focal.projection == "full_body"),
            "a generous budget carries every focal whole: {:?}",
            report
                .focals
                .iter()
                .map(|focal| focal.projection.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_repeated_focal_is_carried_once() {
        let (store, links) = chain(3);
        let (pack, report) =
            build_multi_focal_pack(&store, &[links[0].id, links[0].id], &opts(8000)).unwrap();
        assert_eq!(pack.focal_entities.len(), 1);
        assert_eq!(report.focals.len(), 1);
    }

    #[test]
    fn no_focal_is_a_refusal_rather_than_an_empty_pack() {
        let store = kin_db::InMemoryGraph::new();
        let error = build_multi_focal_pack(&store, &[], &opts(8000)).unwrap_err();
        assert!(
            error.to_string().contains("at least one focal"),
            "says what was missing: {error}"
        );
    }

    #[test]
    fn a_focal_id_the_graph_does_not_carry_is_named_in_the_refusal() {
        let (store, links) = chain(2);
        let missing = EntityId::new();
        let error =
            build_multi_focal_pack(&store, &[links[0].id, missing], &opts(8000)).unwrap_err();
        assert!(
            error.to_string().contains(&missing.to_string()),
            "names the id that did not resolve: {error}"
        );
    }

    // ---- the route between connected focals -----------------------------

    #[test]
    fn the_material_between_two_connected_focals_reaches_the_pack_first() {
        // link_0 -> link_1 -> link_2 -> link_3 -> link_4, focals at the ends.
        // link_2 is two hops from either focal, so no depth-1 neighbourhood
        // reaches it: if it is in the pack, the route put it there.
        let (store, links) = chain(5);
        // A neighbour of link_0 that is not on the route, so the neighbourhood
        // sections have something of their own to contribute. Without it every
        // neighbour IS route material, and the ordering assertion below would
        // have nothing to order against.
        let aside = make_entity("aside", "src/aside.rs");
        store.upsert_entity(&aside).unwrap();
        calls(&store, &links[0], &aside);

        let (pack, report) =
            build_multi_focal_pack(&store, &[links[0].id, links[4].id], &opts(8000)).unwrap();

        assert_eq!(report.route_search.pairs_connected, 1);
        assert_eq!(report.routes.len(), 1);
        let route = &report.routes[0];
        assert_eq!(
            route.via_names,
            vec![
                "link_1".to_string(),
                "link_2".to_string(),
                "link_3".to_string()
            ],
            "the route is carried in walk order from one focal to the other"
        );
        assert_eq!(route.hops, 4);

        let middle = pack
            .transitive_deps
            .iter()
            .find(|entry| entry.entity_id == links[2].id)
            .expect("the entity in the middle of the chain is in the pack");
        assert!(
            middle.content.starts_with(ROUTE_MARKER),
            "a route row says which pair it joins: {}",
            middle.content
        );

        let rendered = render_multi_focal_lines(&pack, &report).join("\n");
        let body = rendered
            .split_once("--- Context Pack ---")
            .expect("a rendered pack has a body")
            .1;
        let route_at = body.find(ROUTE_MARKER).expect("a route row in the body");
        // A row from a section that is not the route, matched on its own exact
        // content so the position cannot land inside a route row that happens
        // to quote the same signature.
        let neighbour = pack
            .dependency_signatures
            .first()
            .expect("the neighbourhoods contribute rows too");
        let neighbour_at = body
            .find(neighbour.content.trim())
            .expect("the neighbourhood row is rendered");
        assert!(
            route_at < neighbour_at,
            "route material is rendered before the neighbourhoods: route at {route_at}, \
             neighbour at {neighbour_at}"
        );
    }

    #[test]
    fn two_unconnected_focals_report_no_route_rather_than_inventing_one() {
        let store = kin_db::InMemoryGraph::new();
        let lonely = make_entity("lonely", "src/a.rs");
        let stranger = make_entity("stranger", "src/b.rs");
        store.upsert_entity(&lonely).unwrap();
        store.upsert_entity(&stranger).unwrap();

        let (pack, report) =
            build_multi_focal_pack(&store, &[lonely.id, stranger.id], &opts(8000)).unwrap();

        assert_eq!(report.route_search.pairs_examined, 1);
        assert_eq!(report.route_search.pairs_connected, 0);
        assert!(!report.route_search.bounded, "nothing stopped the search");
        assert!(report.routes.is_empty());
        assert!(
            pack.transitive_deps
                .iter()
                .all(|entry| !entry.content.starts_with(ROUTE_MARKER)),
            "no route rows without a route"
        );
        assert!(
            report.method.contains("joins no pair of them"),
            "the method line says the graph joins them nowhere: {}",
            report.method
        );
    }

    #[test]
    fn a_route_beyond_the_hop_bound_is_not_reported_as_connected() {
        // Longer than ROUTE_MAX_HOPS, so the walk ends without reaching the far
        // end. That is "not within the bound", never "unrelated".
        let (store, links) = chain(ROUTE_MAX_HOPS + 3);
        let last = links.len() - 1;
        let (_, report) =
            build_multi_focal_pack(&store, &[links[0].id, links[last].id], &opts(8000)).unwrap();
        assert_eq!(report.route_search.pairs_connected, 0);
        assert!(report.method.contains("within 4 hops"), "{}", report.method);
    }

    #[test]
    fn a_co_change_edge_cannot_manufacture_a_route() {
        let store = kin_db::InMemoryGraph::new();
        let left = make_entity("left", "src/a.rs");
        let right = make_entity("right", "src/b.rs");
        store.upsert_entity(&left).unwrap();
        store.upsert_entity(&right).unwrap();
        store
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::CoChanges,
                src: GraphNodeId::Entity(left.id),
                dst: GraphNodeId::Entity(right.id),
                confidence: 1.0,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let (_, report) =
            build_multi_focal_pack(&store, &[left.id, right.id], &opts(8000)).unwrap();
        assert_eq!(
            report.route_search.pairs_connected, 0,
            "co-change is a coincidence, not a route"
        );
    }

    #[test]
    fn a_route_is_found_whichever_way_the_edges_point() {
        // Both focals call into the middle, so no directed walk from either one
        // reaches the other. The chain still joins them and is still the answer.
        let store = kin_db::InMemoryGraph::new();
        let left = make_entity("left", "src/a.rs");
        let middle = make_entity("middle", "src/m.rs");
        let right = make_entity("right", "src/b.rs");
        for entity in [&left, &middle, &right] {
            store.upsert_entity(entity).unwrap();
        }
        calls(&store, &left, &middle);
        calls(&store, &right, &middle);

        let (_, report) =
            build_multi_focal_pack(&store, &[left.id, right.id], &opts(8000)).unwrap();
        assert_eq!(report.route_search.pairs_connected, 1);
        assert_eq!(report.routes[0].via_names, vec!["middle".to_string()]);
    }

    // ---- the budget bound ------------------------------------------------

    #[test]
    fn the_pack_measures_under_the_budget_it_was_given() {
        let (store, links) = chain(6);
        let focal_ids: Vec<EntityId> = links.iter().map(|link| link.id).collect();
        let floor = floor_for(&store, &focal_ids);
        for budget in [floor, floor + 40, 350, 500, 1500] {
            let (pack, report) = build_multi_focal_pack(&store, &focal_ids, &opts(budget)).unwrap();
            let rendered = render_multi_focal_lines(&pack, &report).join("\n");
            let measured = estimate_tokens(&rendered);
            assert!(
                measured <= budget,
                "at {budget} tokens the rendering cost {measured}:\n{rendered}"
            );
            assert_eq!(
                report.measured_tokens, measured,
                "the reported size is the size of the bytes returned"
            );
            assert_eq!(report.budget_tokens, budget);
        }
    }

    /// The sentence describing the pack is the last thing to shrink, and it
    /// shrinks visibly rather than the pack quietly going over budget.
    #[test]
    fn a_budget_too_tight_for_the_method_line_shortens_it_rather_than_overspending() {
        let (store, links) = chain(6);
        let focal_ids: Vec<EntityId> = links.iter().map(|link| link.id).collect();
        let full = {
            let (_, report) = build_multi_focal_pack(&store, &focal_ids, &opts(8000)).unwrap();
            report
        };
        assert_eq!(
            full.method_style, "full",
            "a generous budget keeps the detail"
        );
        let tight_budget = floor_for(&store, &focal_ids);

        let (pack, report) = build_multi_focal_pack(&store, &focal_ids, &opts(tight_budget))
            .expect("a pack that fits by shortening its own description");
        assert_eq!(report.method_style, "compact");
        assert!(
            report.method.contains("detail withheld"),
            "the shortening says so: {}",
            report.method
        );
        let measured = estimate_tokens(&render_multi_focal_lines(&pack, &report).join("\n"));
        assert!(
            measured <= tight_budget,
            "measured {measured} of {tight_budget}"
        );
    }

    /// The number the refusal names is a budget that works. A refusal reporting
    /// a floor nobody can build at sends the caller round the loop again, which
    /// is the same as not reporting one.
    #[test]
    fn the_floor_a_refusal_names_is_a_budget_that_builds() {
        let (store, links) = chain(6);
        let focal_ids: Vec<EntityId> = links.iter().map(|link| link.id).collect();
        let floor = floor_for(&store, &focal_ids);
        let (pack, report) = build_multi_focal_pack(&store, &focal_ids, &opts(floor))
            .expect("the floor the refusal named must build");
        let measured = estimate_tokens(&render_multi_focal_lines(&pack, &report).join("\n"));
        assert!(
            measured <= floor,
            "measured {measured} at its own floor {floor}"
        );
        assert!(
            !pack.focal_entities.is_empty(),
            "a pack at its floor still carries a focal"
        );
    }

    #[test]
    fn a_budget_too_small_for_one_focal_is_a_refusal_rather_than_an_overspend() {
        let (store, links) = chain(3);
        let error = build_multi_focal_pack(&store, &[links[0].id], &opts(2)).unwrap_err();
        assert!(
            matches!(error, ContextError::BudgetExceeded { .. }),
            "refuses rather than returning a pack over its budget: {error}"
        );
    }

    #[test]
    fn a_focal_the_budget_cannot_carry_is_reported_rather_than_dropped() {
        let (store, links) = chain(6);
        let focal_ids: Vec<EntityId> = links.iter().map(|link| link.id).collect();
        let floor = floor_for(&store, &focal_ids);
        let (pack, report) = build_multi_focal_pack(&store, &focal_ids, &opts(floor)).unwrap();
        assert!(
            pack.focal_entities.len() < focal_ids.len(),
            "this budget cannot carry six focals, which is the case under test"
        );
        let elided = report
            .focals
            .iter()
            .filter(|focal| focal.projection == "elided")
            .count();
        assert!(elided > 0);
        assert_eq!(
            report.elisions.get(FOCAL_GROUP).map(|e| e.elided),
            Some(elided),
            "the focals that did not fit are named in the elision map"
        );
        assert_eq!(
            report.elisions[FOCAL_GROUP].reason,
            ELISION_REASON_TOKEN_BUDGET
        );
        assert!(
            report.method.contains("did not fit"),
            "and the method line says so, in whichever form it is rendering: {}",
            report.method
        );
        assert!(
            report.method.contains(&format!(
                "{} of {} focals carried",
                pack.focal_entities.len(),
                report.focals.len()
            )),
            "with the count a reader can act on: {}",
            report.method
        );
    }

    /// A focal too expensive to carry whole is carried smaller, not dropped.
    ///
    /// The fixture puts the weight in the doc summary, which is what separates
    /// the three projections: the full body and the signature form both carry
    /// it, and the name-and-kind form does not.
    #[test]
    fn a_tight_budget_degrades_a_focal_rather_than_losing_it() {
        let store = kin_db::InMemoryGraph::new();
        let mut wordy = make_entity("wordy", "src/wordy.rs");
        wordy.doc_summary = Some("a documented behaviour ".repeat(60));
        store.upsert_entity(&wordy).unwrap();

        let full = estimate_tokens(&project_full_body(&wordy));
        let name_only = estimate_tokens(&project_name_and_kind(&wordy));
        assert!(
            name_only * 4 < full,
            "the fixture needs a ladder worth walking down: {name_only} against {full}"
        );

        let floor = floor_for(&store, &[wordy.id]);
        let (pack, report) = build_multi_focal_pack(&store, &[wordy.id], &opts(floor + 10))
            .expect("a budget above the floor builds");
        assert_eq!(
            report.focals[0].projection, "name_and_kind",
            "the cheapest projection that fits is the one taken"
        );
        assert_eq!(pack.focal_entities.len(), 1, "and the focal is still there");
        let measured = estimate_tokens(&render_multi_focal_lines(&pack, &report).join("\n"));
        assert!(measured <= floor + 10, "measured {measured}");
    }

    /// The fit loop walks a focal down its ladder before it drops one.
    ///
    /// Reaching that rung at all takes a specific budget, and finding it was
    /// the point. Two earlier attempts could not: the water-filled first pass
    /// already admits a focal at its cheapest projection whenever the budget is
    /// tight enough to matter, so at the floor, or with one focal, the fit
    /// loop's rung is dead code the mutation cannot touch. It fires only when
    /// the bodies DO fit their shares and the pack's own header and method line
    /// are what overflow. So the budget here is the two bodies plus a little,
    /// which admits both whole and leaves no room for the frame around them.
    #[test]
    fn the_fit_shrinks_a_focal_before_it_drops_one() {
        let store = kin_db::InMemoryGraph::new();
        let mut left = make_entity("left", "src/left.rs");
        left.doc_summary = Some("the left behaviour described at length ".repeat(12));
        let mut right = make_entity("right", "src/right.rs");
        right.doc_summary = Some("the right behaviour described at length ".repeat(12));
        store.upsert_entity(&left).unwrap();
        store.upsert_entity(&right).unwrap();
        calls(&store, &left, &right);

        let ids = vec![left.id, right.id];
        let bodies = estimate_tokens(&project_full_body(&left))
            + estimate_tokens(&project_full_body(&right));
        let budget = bodies + 20;

        let generous = build_multi_focal_pack(&store, &ids, &opts(8000)).unwrap().1;
        assert!(
            generous
                .focals
                .iter()
                .all(|focal| focal.projection == "full_body"),
            "control: both focals are admitted whole when there is room"
        );

        let (pack, report) =
            build_multi_focal_pack(&store, &ids, &opts(budget)).expect("this budget builds");
        assert_eq!(
            pack.focal_entities.len(),
            2,
            "both focals survive, because shrinking comes before dropping: {}",
            report.method
        );
        assert!(
            report
                .focals
                .iter()
                .any(|focal| focal.projection != "full_body"),
            "and at least one was walked down to make the frame fit: {:?}",
            report
                .focals
                .iter()
                .map(|focal| focal.projection.clone())
                .collect::<Vec<_>>()
        );
        let measured = estimate_tokens(&render_multi_focal_lines(&pack, &report).join("\n"));
        assert!(measured <= budget, "measured {measured} of {budget}");
    }

    // ---- the method line --------------------------------------------------

    #[test]
    fn the_method_line_names_every_focal_and_how_it_was_resolved() {
        let (store, links) = chain(3);
        let mut options = opts(8000);
        options.resolutions = vec![
            FocalResolution::by_name("link_0"),
            FocalResolution::from_question(0.8125),
        ];
        options.coverage = Some("3 of 3 entities embedded".to_string());

        let (_, report) =
            build_multi_focal_pack(&store, &[links[0].id, links[2].id], &options).unwrap();

        let method = &report.method;
        assert!(method.starts_with("Method: 2 focals"), "{method}");
        assert!(
            method.contains("link_0, Function in src/link_0.rs"),
            "{method}"
        );
        assert!(method.contains("named as link_0"), "{method}");
        assert!(
            method.contains("located from the question, score 0.81"),
            "the question route carries its own score: {method}"
        );
        assert!(method.contains("water-filling"), "{method}");
        assert!(
            method.contains("semantic coverage: 3 of 3 entities embedded"),
            "the coverage the ranking had is part of the method: {method}"
        );
        assert!(
            method.contains(&format!("of {} tokens", report.budget_tokens)),
            "{method}"
        );
        assert!(!method.contains('\n'), "the method is one line: {method}");
    }

    #[test]
    fn the_rendered_pack_carries_the_method_line_and_the_measured_budget() {
        let (store, links) = chain(3);
        let (pack, report) =
            build_multi_focal_pack(&store, &[links[0].id, links[2].id], &opts(8000)).unwrap();
        let lines = render_multi_focal_lines(&pack, &report);
        assert!(lines[0].contains("2 focal entities"), "{:?}", lines[0]);
        assert_eq!(lines[1], report.method);
        assert!(
            lines.iter().any(|line| line
                == &format!(
                    "  Budget: {}/{} tokens measured",
                    report.measured_tokens, report.budget_tokens
                )),
            "the header states the measured cost: {lines:?}"
        );
    }

    // ---- neighbourhood shaping -------------------------------------------

    #[test]
    fn one_focal_keeps_the_single_focal_depth_and_several_shrink() {
        assert_eq!(neighborhood_depth_for(1, 2), 2);
        assert_eq!(neighborhood_depth_for(2, 2), 1);
        assert_eq!(neighborhood_depth_for(5, 3), 1);
    }

    #[test]
    fn a_row_two_focals_share_is_carried_once_and_counted_as_shared() {
        // link_1 is a direct neighbour of both link_0 and link_2.
        let (store, links) = chain(3);
        let (pack, report) =
            build_multi_focal_pack(&store, &[links[0].id, links[2].id], &opts(8000)).unwrap();

        let carried = pack
            .dependency_signatures
            .iter()
            .chain(pack.transitive_deps.iter())
            .filter(|entry| entry.entity_id == links[1].id)
            .count();
        assert_eq!(carried, 1, "the shared entity is in the pack once");
        assert!(
            report.focals.iter().any(|focal| focal.shared_rows > 0),
            "and the overlap is reported rather than hidden: {:?}",
            report.focals
        );
    }
}
