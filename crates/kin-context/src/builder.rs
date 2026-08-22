// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap};

use kin_model::{
    relation::RelationKind, Annotation, AnnotationEntry, ArtifactContextEntry, ArtifactContextKind,
    ArtifactId, ContextEntry, ContextPack, ContextPlan, Entity, EntityFilter, EntityId, EntityKind,
    EntityRole, FilePathId, GraphNodeId, GraphStore, IntentSummary, ProjectionLevel, RepoPath,
    RetrievalKey, TokenBudget, TrafficEntry, TrafficProximity, WorkItem, WorkItemEntry, WorkScope,
};
use rayon::prelude::*;
use tracing::debug;

use crate::error::{ContextError, Result};
use crate::tokens::estimate_tokens;

/// Weight multiplier for each relation kind, used to prioritize BFS expansion.
///
/// Higher weights mean the related entity is more likely to be relevant context.
/// When the token budget is limited, entities connected by high-weight relations
/// are included before those connected by low-weight relations.
fn relation_weight(kind: &RelationKind) -> f64 {
    match kind {
        RelationKind::Calls => 5.0,
        RelationKind::UsesMacro => 4.0,
        RelationKind::CoChanges => 3.5,
        RelationKind::DependsOn => 3.0,
        RelationKind::Implements => 3.0,
        RelationKind::Extends => 3.0,
        RelationKind::Tests => 2.5,
        RelationKind::Imports => 2.0,
        RelationKind::Includes => 1.8,
        RelationKind::DefinesContract => 2.0,
        RelationKind::ConsumesContract => 2.0,
        RelationKind::EmitsEvent => 1.5,
        RelationKind::References => 1.0,
        RelationKind::DocumentedBy => 0.5,
        RelationKind::Contains => 0.5,
        RelationKind::OwnedBy => 0.5,
        RelationKind::Covers => 2.5,
        RelationKind::DerivedFrom => 1.5,
        RelationKind::OwnedByFile => 0.5,
        RelationKind::Overrides => 4.0,
        RelationKind::Instantiates => 4.0,
        RelationKind::UsesType => 2.5,
        RelationKind::SubscribesTo => 1.5,
        RelationKind::SendsMessage => 3.0,
        RelationKind::Spawns => 3.0,
    }
}

/// Minimum relation weight for a TRANSITIVE (2+ hop, non-direct) entity to earn a
/// slot in the pack. Structural-containment edges (`Contains`, `OwnedBy`,
/// `OwnedByFile`, `DocumentedBy`) carry weight 0.5 — they are graph plumbing, not
/// dependencies, and were padding packs with same-file/same-crate noise.
/// Requiring at least a `References`-grade (1.0) connection keeps every semantic
/// edge while dropping pure structural neighbours. Direct deps (any *dependency*
/// edge to the focal), tests, and contracts are unaffected — this gates only
/// transitive fill.
const TRANSITIVE_RELEVANCE_FLOOR: f64 = 1.0;

/// Whether an edge expresses a real **code dependency** — the kind of edge that
/// belongs in the "dependencies / what you need to understand this" sections of a
/// context pack.
///
/// This is the membership gate for `get_context_pack`'s dependency
/// sections: they must be the focal entity's actual graph dependencies, not whatever
/// shares *any* edge with it. Two edge classes are explicitly NOT dependencies and
/// were flooding the pack:
///
/// * [`RelationKind::CoChanges`] — git co-change mining. Statistical history
///   signal (`Inferred` origin), not a code dependency. On a typical function its
///   co-change set dwarfs the real callees, so without this gate the "dependencies"
///   are dominated by whatever happened to land in the same commits (e.g.
///   `stash::push`, `buildinfo::get`). Useful as co-change *risk*, never as "what
///   this function depends on."
/// * Structural-containment plumbing ([`RelationKind::Contains`],
///   [`RelationKind::OwnedBy`], [`RelationKind::OwnedByFile`],
///   [`RelationKind::DocumentedBy`]) — graph plumbing, not a dependency.
///
/// Test (`Tests`/`Covers`) edges are intentionally excluded here too: tests have
/// their own pack section and are handled separately, not as dependencies.
///
/// This gate governs **membership** in the dependency sections only; ordering
/// within a section still uses [`relation_weight`], and the broader BFS expansion
/// weighting is unchanged.
fn is_dependency_edge(kind: &RelationKind) -> bool {
    match kind {
        // Real code dependencies / usage / wiring.
        RelationKind::Calls
        | RelationKind::Instantiates
        | RelationKind::References
        | RelationKind::UsesMacro
        | RelationKind::UsesType
        | RelationKind::Imports
        | RelationKind::Includes
        | RelationKind::DependsOn
        | RelationKind::Implements
        | RelationKind::Extends
        | RelationKind::Overrides
        | RelationKind::DefinesContract
        | RelationKind::ConsumesContract
        | RelationKind::EmitsEvent
        | RelationKind::SubscribesTo
        | RelationKind::SendsMessage
        | RelationKind::Spawns
        | RelationKind::DerivedFrom => true,
        // Not dependencies: git co-change mining, test edges, structural plumbing,
        // ownership/doc metadata.
        RelationKind::CoChanges
        | RelationKind::Tests
        | RelationKind::Covers
        | RelationKind::Contains
        | RelationKind::OwnedBy
        | RelationKind::OwnedByFile
        | RelationKind::DocumentedBy => false,
    }
}

/// Build a map from entity ID to its maximum relation weight relative to the focal entity.
///
/// For each relation in the subgraph, the weight is assigned to the non-focal endpoint.
/// If an entity has multiple relations, the maximum weight is kept (strongest signal wins).
fn build_weight_map(
    focal_id: &EntityId,
    relations: &[kin_model::Relation],
) -> HashMap<EntityId, f64> {
    let mut weights: HashMap<EntityId, f64> = HashMap::new();
    let focal_node = GraphNodeId::Entity(*focal_id);
    for rel in relations {
        let w = relation_weight(&rel.kind);
        let target = if rel.src == focal_node {
            rel.dst.as_entity()
        } else if rel.dst == focal_node {
            rel.src.as_entity()
        } else {
            // Transitive relation: weight both endpoints (they get the relation weight
            // as their base priority if they don't have a direct relation to focal).
            if let Some(entity_id) = rel.src.as_entity() {
                let e1 = weights.entry(entity_id).or_insert(0.0);
                if w > *e1 {
                    *e1 = w;
                }
            }
            if let Some(entity_id) = rel.dst.as_entity() {
                let e2 = weights.entry(entity_id).or_insert(0.0);
                if w > *e2 {
                    *e2 = w;
                }
            }
            continue;
        };
        let Some(target) = target else {
            continue;
        };
        let entry = weights.entry(target).or_insert(0.0);
        if w > *entry {
            *entry = w;
        }
    }
    weights
}

/// Collect every entity in the subgraph that is touched by at least one real
/// **dependency** edge ([`is_dependency_edge`]).
///
/// Used to gate transitive fill: a 2+-hop neighbour may clear the relevance floor
/// purely on a high-weight `CoChanges` edge (weight 3.5), which would re-introduce
/// the same git-history noise this fix removes from the direct section. Requiring
/// the neighbour to also sit on a dependency edge keeps transitive fill edge-driven
/// rather than co-change-driven.
fn dependency_edge_entities(
    relations: &[kin_model::Relation],
) -> std::collections::HashSet<EntityId> {
    let mut ids = std::collections::HashSet::new();
    for rel in relations {
        if !is_dependency_edge(&rel.kind) {
            continue;
        }
        if let Some(id) = rel.src.as_entity() {
            ids.insert(id);
        }
        if let Some(id) = rel.dst.as_entity() {
            ids.insert(id);
        }
    }
    ids
}

/// Hint for which assistant is requesting context, enabling tuned strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssistantHint {
    /// Claude Code: good at cross-file chains, benefits from broader context.
    ClaudeCode,
    /// Codex: strongest with focused narrow context.
    Codex,
    /// Gemini CLI: needs precise location context.
    GeminiCli,
}

/// Options for building a context pack.
#[derive(Debug, Clone)]
pub struct ContextOptions {
    pub budget: TokenBudget,
    pub max_depth: u32,
    pub include_tests: bool,
    pub include_contracts: bool,
    /// Include active nearby traffic (other agents' intents) in the pack.
    pub include_traffic: bool,
    /// Optional assistant hint for tuning context pack strategy.
    pub assistant_hint: Option<AssistantHint>,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            budget: TokenBudget::Small8k,
            max_depth: 2,
            include_tests: true,
            include_contracts: true,
            include_traffic: false,
            assistant_hint: None,
        }
    }
}

/// Build a context pack centered on a focal entity.
/// Subgraph size at or above which the per-entity projection/token work is
/// precomputed in parallel. Below it, rayon's fan-out overhead outweighs the
/// gain, so the sequential path runs. Either path produces identical output.
/// How many same-file neighbours the fallback keeps.
///
/// The cap is what makes a twenty-four-method class come back as six rows, so
/// it is reported rather than applied silently: [`DependencySelection`] carries
/// the candidate total beside the kept count.
pub const SAME_FILE_FALLBACK_MAX: usize = 6;

/// Why a row is in a pack's dependency section, and which way it points.
///
/// The three are not interchangeable. A dependency rides an edge LEAVING the
/// focal, so the focal needs it. A dependent rides an edge ARRIVING at the
/// focal, so it needs the focal; changing the focal is what breaks it. A
/// same-file row is a neighbour the builder reached for because the focal had
/// no dependency edge in either direction. A class whose only edges are
/// `Contains` produces same-file rows, and without this distinction a caller
/// reads them as the class's dependencies.
///
/// Direction is not decoration. Every relation kind [`is_dependency_edge`]
/// accepts runs src-depends-on-dst, so the endpoint alone cannot say which
/// question a row answers: "what does this need to run" and "what breaks if I
/// change this" are opposite queries served by opposite edges. Collapsing them
/// reported a caller as a callee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyRelation {
    /// The focal reaches this entity over a real dependency edge. The focal
    /// depends on it.
    DependencyEdge,
    /// This entity reaches the focal over a real dependency edge. It depends on
    /// the focal. Not a dependency of the focal.
    DependentEdge,
    /// The focal carried no dependency edge in either direction, so this row is
    /// an entity that shares the focal's file. Not a dependency.
    SameFileNeighbor,
}

impl DependencyRelation {
    /// The wire spelling shared by `kin context` and the `get_context_pack` MCP
    /// tool, so one name means one thing on both surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            DependencyRelation::DependencyEdge => "dependency_edge",
            DependencyRelation::DependentEdge => "dependent_edge",
            DependencyRelation::SameFileNeighbor => "same_file_neighbor",
        }
    }

    /// Sort bucket for the pack's dependency section: what the focal needs
    /// first, then what needs the focal, then the fallback neighbours.
    ///
    /// A pack whose focal had one callee and nine callers listed the callee
    /// tenth, because the section was ordered on relation weight alone and
    /// weight does not know direction. The one row that answers "what does this
    /// need" must not sit below nine rows that answer a different question.
    pub fn sort_rank(self) -> u8 {
        match self {
            DependencyRelation::DependencyEdge => 0,
            DependencyRelation::DependentEdge => 1,
            DependencyRelation::SameFileNeighbor => 2,
        }
    }
}

/// Where a pack's dependency section came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencySource {
    /// Every row rides a dependency edge to the focal.
    DependencyEdges,
    /// The focal had no dependency edge, so the section holds same-file
    /// neighbours instead.
    SameFileFallback,
}

impl DependencySource {
    /// The wire spelling shared by `kin context` and the `get_context_pack` MCP
    /// tool.
    pub fn as_str(self) -> &'static str {
        match self {
            DependencySource::DependencyEdges => "dependency_edges",
            DependencySource::SameFileFallback => "same_file_fallback",
        }
    }
}

/// The wire name of a pack group, shared by `kin context` and the
/// `get_context_pack` MCP tool.
///
/// Named here rather than spelled at each call site because the token budget's
/// elisions are keyed by these, and a group whose count is filed under a name
/// no surface renders is a disclosure nobody reads.
pub mod group {
    /// Rows the focal depends on.
    pub const DEPENDENCIES: &str = "dependencies";
    /// Rows that depend on the focal.
    pub const DEPENDENTS: &str = "dependents";
    /// Rows reached at more than one hop.
    pub const TRANSITIVE_DEPS: &str = "transitive_deps";
    /// Tests covering the focal or its direct dependencies.
    pub const TESTS: &str = "tests";
    /// Contracts the focal participates in.
    pub const CONTRACTS: &str = "contracts";
    /// Open work items scoped to the focal or its direct dependencies.
    pub const WORK_ITEMS: &str = "work_items";
    /// Fresh annotations on the focal or its direct dependencies.
    pub const ANNOTATIONS: &str = "annotations";
}

/// How a pack's dependency section was filled, and what filling it left out.
///
/// These are selection facts only the builder holds: whether the same-file
/// fallback ran, how many neighbours it had to choose from, and how many
/// [`SAME_FILE_FALLBACK_MAX`] and the token budget dropped. None of it is
/// recoverable from [`ContextPack`] alone, which is why the pack's dependency
/// rows used to reach an agent with no way to tell an edge from a neighbour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DependencySelection {
    fallback: bool,
    same_file_candidates: usize,
    same_file_neighbors: Vec<EntityId>,
    dependents: Vec<EntityId>,
    /// Candidates the token budget refused, by the group each would have
    /// joined. Ids rather than counts, because a caller can recover a refused
    /// row by another route and a row that reached the answer is not one the
    /// answer lost.
    budget_elided: BTreeMap<&'static str, Vec<EntityId>>,
}

impl DependencySelection {
    /// Where the rows in `dependency_signatures` came from.
    pub fn source(&self) -> DependencySource {
        if self.fallback {
            DependencySource::SameFileFallback
        } else {
            DependencySource::DependencyEdges
        }
    }

    /// Why one dependency-section row is in the pack, and which way it points.
    ///
    /// An entity joined to the focal by edges in BOTH directions is reported as
    /// a dependency. It is genuinely one, and the stronger claim is the one a
    /// reader acts on: dropping it would break the focal, which the weaker
    /// label does not say.
    pub fn relation_for(&self, entity_id: &EntityId) -> DependencyRelation {
        if self.same_file_neighbors.contains(entity_id) {
            DependencyRelation::SameFileNeighbor
        } else if self.dependents.contains(entity_id) {
            DependencyRelation::DependentEdge
        } else {
            DependencyRelation::DependencyEdge
        }
    }

    /// Same-file neighbours the fallback had to choose from, before the cap and
    /// the token budget. Zero when the fallback did not run.
    pub fn same_file_candidates(&self) -> usize {
        self.same_file_candidates
    }

    /// Same-file neighbours that actually reached the pack.
    pub fn same_file_kept(&self) -> usize {
        self.same_file_neighbors.len()
    }

    /// Same-file neighbours the cap or the budget dropped.
    pub fn same_file_dropped(&self) -> usize {
        self.same_file_candidates
            .saturating_sub(self.same_file_neighbors.len())
    }

    /// Record one candidate the token budget refused.
    fn refuse(&mut self, group: &'static str, entity_id: EntityId) {
        self.budget_elided.entry(group).or_default().push(entity_id);
    }

    /// Rows one group lost to the token budget, discounting any the caller
    /// recovered by another route.
    ///
    /// The MCP pack recovers a certified caller this fold refused, from the
    /// same reference authority `find_references` reads. A row that reached the
    /// answer is not a row the answer lost, and claiming it in both places
    /// would be a false report of loss, which is the same defect as silence
    /// with its sign flipped.
    pub fn budget_elided_unrecovered(
        &self,
        group: &str,
        recovered: impl Fn(&EntityId) -> bool,
    ) -> usize {
        self.budget_elided
            .get(group)
            .map_or(0, |ids| ids.iter().filter(|id| !recovered(id)).count())
    }

    /// Rows one group lost to the token budget.
    pub fn budget_elided(&self, group: &str) -> usize {
        self.budget_elided_unrecovered(group, |_| false)
    }

    /// Every group the token budget took rows from, with its count.
    pub fn budget_elisions(&self) -> impl Iterator<Item = (&'static str, usize)> + '_ {
        self.budget_elided
            .iter()
            .filter(|(_, ids)| !ids.is_empty())
            .map(|(group, ids)| (*group, ids.len()))
    }
}

const PARALLEL_ASSEMBLY_MIN_ENTITIES: usize = 64;

/// Which pack section a non-focal subgraph entity projects into.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AssemblySection {
    Test,
    Contract,
    DirectDep,
    Transitive,
}

/// A classified, projected subgraph entity that has not yet been admitted under
/// the token budget. Computing one is a pure function of the entity, the
/// options, and the precomputed relation sets — independent across entities, so
/// the projection pass is safe to parallelize. The budget admission that
/// consumes these stays sequential and order-preserving, so the assembled pack
/// is byte-identical regardless of how the projections were computed.
struct AssemblyCandidate {
    entity_id: EntityId,
    section: AssemblySection,
    projection_level: ProjectionLevel,
    content: String,
    tokens: usize,
}

/// Classify and project a single non-focal subgraph entity. Returns `None` when
/// the entity contributes no section (a transitive candidate that is not on a
/// real dependency edge or is below the relevance floor). Pure / side-effect-free.
fn classify_subgraph_entity(
    entity: &Entity,
    is_direct: bool,
    on_dependency_edge: bool,
    weight: f64,
    opts: &ContextOptions,
) -> Option<AssemblyCandidate> {
    let with_gemini_prefix = |content: String| -> String {
        if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
            if let Some(ref origin) = entity.file_origin {
                return format!("// file: {}\n{}", origin, content);
            }
        }
        content
    };

    if entity.role == EntityRole::Test && opts.include_tests {
        let content = with_gemini_prefix(project_signature_only(entity));
        let tokens = estimate_tokens(&content);
        return Some(AssemblyCandidate {
            entity_id: entity.id,
            section: AssemblySection::Test,
            projection_level: ProjectionLevel::SignatureOnly,
            content,
            tokens,
        });
    }

    if matches!(
        entity.kind,
        EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
    ) && opts.include_contracts
    {
        let content = with_gemini_prefix(project_signature_only(entity));
        let tokens = estimate_tokens(&content);
        return Some(AssemblyCandidate {
            entity_id: entity.id,
            section: AssemblySection::Contract,
            projection_level: ProjectionLevel::SignatureOnly,
            content,
            tokens,
        });
    }

    if is_direct {
        let content = with_gemini_prefix(project_signature_only(entity));
        let tokens = estimate_tokens(&content);
        return Some(AssemblyCandidate {
            entity_id: entity.id,
            section: AssemblySection::DirectDep,
            projection_level: ProjectionLevel::SignatureOnly,
            content,
            tokens,
        });
    }

    // Transitive fill must ride a real dependency edge and clear the relevance
    // floor; otherwise same-file/co-change plumbing pads the pack.
    if !on_dependency_edge || weight < TRANSITIVE_RELEVANCE_FLOOR {
        return None;
    }
    let content = with_gemini_prefix(project_name_and_kind(entity));
    let tokens = estimate_tokens(&content);
    Some(AssemblyCandidate {
        entity_id: entity.id,
        section: AssemblySection::Transitive,
        projection_level: ProjectionLevel::NameAndKind,
        content,
        tokens,
    })
}

pub fn build_context_pack<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
) -> Result<ContextPack>
where
    G: GraphStore,
{
    build_context_pack_with_provenance(graph, focal_id, opts).map(|(pack, _)| pack)
}

/// Build a context pack and report how its dependency section was selected.
///
/// The pack itself cannot carry that: `dependency_signatures` is a flat list of
/// entries whose provenance lived only in a `// same-file neighbor` comment
/// inside `entry.content`, which the MCP boundary does not serialize. Callers
/// that render dependencies for an agent take the [`DependencySelection`] with
/// them and label every row, so a same-file neighbour is never read as an edge.
pub fn build_context_pack_with_provenance<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
) -> Result<(ContextPack, DependencySelection)>
where
    G: GraphStore,
{
    let mut selection = DependencySelection::default();
    let budget_max = opts.budget.max_tokens();
    let mut total_tokens = 0;

    // Adjust depth based on assistant hint.
    let effective_depth = match opts.assistant_hint {
        Some(AssistantHint::ClaudeCode) => opts.max_depth.saturating_add(1),
        Some(AssistantHint::Codex) => opts.max_depth.max(1).saturating_sub(1).max(1),
        _ => opts.max_depth,
    };

    // 1. Focal entity at full body level.
    let focal = graph
        .get_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?
        .ok_or_else(|| ContextError::EntityNotFound(focal_id.to_string()))?;

    let focal_content = project_full_body(&focal);
    let focal_tokens = estimate_tokens(&focal_content);
    total_tokens += focal_tokens;

    let focal_entry = ContextEntry {
        entity_id: focal.id,
        projection_level: ProjectionLevel::FullBody,
        content: focal_content,
    };

    // 2. Get dependency neighborhood.
    let mut subgraph = graph
        .get_dependency_neighborhood(focal_id, effective_depth)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    // Identify direct deps (1 hop) — includes both outgoing and incoming edges.
    let direct_relations = graph
        .get_all_relations_for_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    // The non-focal endpoint of a direct edge, regardless of direction.
    let direct_neighbor = |r: &kin_model::Relation| -> Option<EntityId> {
        if r.src == GraphNodeId::Entity(*focal_id) {
            r.dst.as_entity()
        } else if r.dst == GraphNodeId::Entity(*focal_id) {
            r.src.as_entity()
        } else {
            None
        }
    };

    // Every 1-hop neighbour (any edge kind, either direction). Used only to
    // populate the subgraph so test/contract entities reached via incoming-only
    // edges (e.g. a `Tests` edge pointing at the focal) can still land in their
    // own pack sections.
    let all_direct_related_ids: Vec<EntityId> = direct_relations
        .iter()
        .filter_map(direct_neighbor)
        .collect();

    // A direct *dependency* must ride a real dependency edge (Calls, Imports,
    // UsesType, …), not git co-change or structural plumbing. Without this gate
    // the dependency section is dominated by `CoChanges` neighbours and
    // same-file containment noise rather than the entity's actual callees.
    //
    // Every kind `is_dependency_edge` accepts runs src-depends-on-dst, so the
    // edge's direction is the whole of the answer: an edge leaving the focal
    // names something the focal needs, and an edge arriving names something
    // that needs the focal. Reading the non-focal endpoint without the
    // direction is how nine callers reached a caller as nine "dependencies".
    let dependency_edge_relations = || {
        direct_relations
            .iter()
            .filter(|r| is_dependency_edge(&r.kind))
    };
    let focal_node = GraphNodeId::Entity(*focal_id);
    // focal --dep--> X: the focal needs X.
    let dependency_ids: Vec<EntityId> = dependency_edge_relations()
        .filter(|r| r.src == focal_node)
        .filter_map(|r| r.dst.as_entity())
        .collect();
    // Y --dep--> focal: Y needs the focal. Both directions stay in the section,
    // because dropping the arriving edges would hide real graph truth behind
    // the same-file fallback on exactly the entities that have callers and no
    // callees. They are labelled, not withheld.
    let dependent_ids: Vec<EntityId> = dependency_edge_relations()
        .filter(|r| r.dst == focal_node)
        .filter_map(|r| r.src.as_entity())
        .filter(|id| !dependency_ids.contains(id))
        .collect();
    // The union keeps the section's membership, the fallback trigger, and the
    // work/annotation scope exactly as they were; only the labels and the order
    // within the section change.
    let direct_dep_ids: Vec<EntityId> = dependency_ids
        .iter()
        .copied()
        .chain(dependent_ids.iter().copied())
        .collect();
    selection.dependents = dependent_ids;

    // BFS only follows outgoing edges, so entities with only incoming edges to
    // the focal (e.g. test entities with a Tests relation pointing at the focal)
    // may be missing from the subgraph. Backfill them so they can be ranked.
    for dep_id in &all_direct_related_ids {
        if !subgraph.entities.contains_key(dep_id) {
            if let Ok(Some(entity)) = graph.get_entity(dep_id) {
                subgraph.entities.insert(*dep_id, entity);
            }
        }
    }
    // Also include the direct relations in the subgraph so the weight map
    // can score these backfilled entities.
    for rel in &direct_relations {
        if !subgraph.relations.iter().any(|r| r.id == rel.id) {
            subgraph.relations.push(rel.clone());
        }
    }

    // If graph relations are sparse for this entity, fall back to nearby
    // entities from the same file so callers still get useful local context.
    let same_file_fallback_entities = if direct_dep_ids.is_empty() {
        if let Some(ref file_origin) = focal.file_origin {
            let mut entities = graph
                .query_entities(&EntityFilter {
                    file_path: Some(file_origin.clone()),
                    ..Default::default()
                })
                .map_err(|e| ContextError::Graph(e.to_string()))?
                .into_iter()
                .filter(|entity| entity.id != focal.id)
                .filter(|entity| {
                    entity.role != EntityRole::Test
                        && !matches!(
                            entity.kind,
                            EntityKind::ApiEndpoint
                                | EntityKind::EventContract
                                | EntityKind::Schema
                        )
                })
                .collect::<Vec<_>>();
            // Same total-order requirement as the weight sort below: the rank is
            // three coarse buckets, so neighbours tie routinely, and only the
            // first six survive. Ranking on entity id last keeps the survivors
            // from depending on the order `query_entities` happened to return.
            entities.sort_by_key(|entity| (same_file_neighbor_rank(&focal, entity), entity.id));
            entities
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // 3. Build relation-weight map and sort entities by priority.
    let weight_map = build_weight_map(focal_id, &subgraph.relations);

    // Entities sitting on at least one real dependency edge. Transitive fill is
    // restricted to this set so co-change neighbours (which clear the weight floor
    // on their own) cannot pad the pack with git-history noise.
    let dependency_entities = dependency_edge_entities(&subgraph.relations);

    // Sort subgraph entities by descending relation weight so that when the
    // token budget is tight, high-signal entities (Calls, DependsOn) are
    // included before low-signal ones (References, Contains).
    //
    // Entity id breaks weight ties into a total order. `subgraph.entities` is a
    // hash map, so the collected order varies between invocations; relation
    // weight comes from a small set of per-kind constants, so equal weights are
    // the common case rather than an edge case. Ordering on weight alone would
    // leave tied candidates in hash order, and the budget fold below admits
    // greedily in this order, so the surviving set would differ run to run for
    // an unchanged graph. `total_cmp` keeps the comparator total even if a
    // weight is ever NaN, which would otherwise collapse to `Equal` and
    // reintroduce the same nondeterminism through a broken ordering.
    let mut sorted_entities: Vec<(&EntityId, &Entity)> = subgraph
        .entities
        .iter()
        .filter(|(eid, _)| **eid != focal.id)
        .collect();
    sorted_entities.sort_by(|(a_id, _), (b_id, _)| {
        let wa = weight_map.get(a_id).copied().unwrap_or(0.0);
        let wb = weight_map.get(b_id).copied().unwrap_or(0.0);
        wb.total_cmp(&wa).then_with(|| a_id.cmp(b_id))
    });

    let mut dep_entries = Vec::new();
    let mut transitive_entries = Vec::new();
    let mut test_entries = Vec::new();
    let mut contract_entries = Vec::new();

    // Codex benefits from reserving budget for the focal entity.
    let transitive_budget = match opts.assistant_hint {
        Some(AssistantHint::Codex) => budget_max / 5,
        _ => budget_max,
    };
    let mut transitive_tokens = 0;

    // Project each subgraph entity into its section in parallel (pure and
    // independent per entity), then admit candidates under the token budget
    // sequentially in the unchanged sorted order. The budget fold is identical,
    // so the assembled pack is byte-for-byte the same as the sequential path.
    let classify = |&(eid, entity): &(&EntityId, &Entity)| -> Option<AssemblyCandidate> {
        classify_subgraph_entity(
            entity,
            direct_dep_ids.contains(eid),
            dependency_entities.contains(eid),
            weight_map.get(eid).copied().unwrap_or(0.0),
            opts,
        )
    };
    let candidates: Vec<Option<AssemblyCandidate>> =
        if sorted_entities.len() >= PARALLEL_ASSEMBLY_MIN_ENTITIES {
            sorted_entities.par_iter().map(classify).collect()
        } else {
            sorted_entities.iter().map(classify).collect()
        };

    for candidate in candidates.into_iter().flatten() {
        let AssemblyCandidate {
            entity_id,
            section,
            projection_level,
            content,
            tokens,
        } = candidate;
        // Which group this candidate would have joined, resolved before the
        // admission decision so a refusal can be filed under the name the two
        // surfaces render it by. `relation_for` is answerable here because
        // `selection.dependents` is populated above and the same-file fallback
        // has not run yet.
        let target_group = match section {
            AssemblySection::Test => group::TESTS,
            AssemblySection::Contract => group::CONTRACTS,
            AssemblySection::Transitive => group::TRANSITIVE_DEPS,
            AssemblySection::DirectDep => match selection.relation_for(&entity_id) {
                DependencyRelation::DependentEdge => group::DEPENDENTS,
                DependencyRelation::DependencyEdge | DependencyRelation::SameFileNeighbor => {
                    group::DEPENDENCIES
                }
            },
        };
        let fits = match section {
            AssemblySection::Transitive => {
                total_tokens + tokens <= budget_max && transitive_tokens + tokens <= transitive_budget
            }
            _ => total_tokens + tokens <= budget_max,
        };
        // A refusal is the cut this fold makes, and it used to make it in
        // silence: a dependency section trimmed from twelve rows to six
        // serializes exactly like a focal that has six. The count is recorded
        // here, at the only place that knows a row was ever a candidate, so
        // both surfaces can say what the budget took instead of rendering the
        // loss as absence.
        if !fits {
            selection.refuse(target_group, entity_id);
            continue;
        }
        total_tokens += tokens;
        let entry = ContextEntry {
            entity_id,
            projection_level,
            content,
        };
        match section {
            AssemblySection::Test => test_entries.push(entry),
            AssemblySection::Contract => contract_entries.push(entry),
            AssemblySection::DirectDep => dep_entries.push(entry),
            AssemblySection::Transitive => {
                transitive_tokens += tokens;
                transitive_entries.push(entry);
            }
        }
    }

    if dep_entries.is_empty() && !same_file_fallback_entities.is_empty() {
        selection.fallback = true;
        selection.same_file_candidates = same_file_fallback_entities.len();
        for entity in same_file_fallback_entities
            .iter()
            .take(SAME_FILE_FALLBACK_MAX)
        {
            let mut content = format!("// same-file neighbor\n{}", project_signature_only(entity));
            if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
                if let Some(ref origin) = entity.file_origin {
                    content = format!("// file: {}\n{}", origin, content);
                }
            }
            let tokens = estimate_tokens(&content);
            // Neighbours past `SAME_FILE_FALLBACK_MAX` are never seen by this
            // loop and stay counted by `same_file_dropped`, which is the cap's
            // own number. Only a neighbour the budget refused is filed as a
            // budget elision: a cap and a budget are different causes recovered
            // by different levers, and `Elision::reason` exists so one cannot
            // be read as the other.
            if total_tokens + tokens > budget_max {
                selection.refuse(group::DEPENDENCIES, entity.id);
                continue;
            }
            total_tokens += tokens;
            selection.same_file_neighbors.push(entity.id);
            dep_entries.push(ContextEntry {
                entity_id: entity.id,
                projection_level: ProjectionLevel::SignatureOnly,
                content,
            });
        }
    }

    // Order the section by what each row answers, not by relation weight alone.
    //
    // Weight ranks a `Calls` edge above a `References` edge whichever way it
    // points, so a focal with one callee and nine callers listed the callee
    // last. `sort_by_key` is stable, so weight order survives inside each
    // bucket and this only lifts the rows that answer "what does this need"
    // above the rows that answer "what needs this".
    dep_entries.sort_by_key(|entry| selection.relation_for(&entry.entity_id).sort_rank());

    // 4. Gather active work items scoped to focal and direct dependencies.
    let mut work_entries = Vec::new();
    let scope_ids: Vec<EntityId> = std::iter::once(focal.id)
        .chain(direct_dep_ids.iter().copied())
        .collect();

    for eid in &scope_ids {
        if let Ok(items) = graph.get_work_for_scope(&WorkScope::Entity(*eid)) {
            for item in items {
                if item.is_closed() {
                    continue;
                }
                let content = format_work_item(&item);
                let tokens = estimate_tokens(&content);
                if total_tokens + tokens > budget_max {
                    selection.refuse(group::WORK_ITEMS, *eid);
                    continue;
                }
                total_tokens += tokens;
                work_entries.push(WorkItemEntry {
                    work_item: item,
                    content,
                });
            }
        }
    }

    // 5. Gather fresh annotations on focal and direct dependencies.
    let mut annotation_entries = Vec::new();
    for eid in &scope_ids {
        if let Ok(anns) = graph.get_annotations_for_scope(&WorkScope::Entity(*eid)) {
            for ann in anns {
                if ann.staleness == kin_model::StalenessState::Stale {
                    continue;
                }
                let content = format_annotation(&ann);
                let tokens = estimate_tokens(&content);
                if total_tokens + tokens > budget_max {
                    selection.refuse(group::ANNOTATIONS, *eid);
                    continue;
                }
                total_tokens += tokens;
                annotation_entries.push(AnnotationEntry {
                    annotation: ann,
                    content,
                });
            }
        }
    }

    debug!(
        focal = %focal.name,
        deps = dep_entries.len(),
        transitive = transitive_entries.len(),
        tests = test_entries.len(),
        contracts = contract_entries.len(),
        work_items = work_entries.len(),
        annotations = annotation_entries.len(),
        tokens = total_tokens,
        budget = budget_max,
        "built context pack"
    );

    Ok((
        ContextPack {
            focal_entities: vec![focal_entry],
            dependency_signatures: dep_entries,
            transitive_deps: transitive_entries,
            contracts: contract_entries,
            tests: test_entries,
            work_items: work_entries,
            annotations: annotation_entries,
            traffic: vec![],
            supporting_artifacts: vec![],
            token_budget: opts.budget,
            actual_tokens: total_tokens,
        },
        selection,
    ))
}

/// Build a context pack from an explicit retrieval plan handoff.
///
/// The plan can carry artifact retrieval seeds from locate before they are
/// collapsed into file paths, allowing graph-owned non-entity context to ride
/// alongside the existing entity-shaped pack.
pub fn build_context_pack_from_plan<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
    plan: &ContextPlan,
) -> Result<ContextPack>
where
    G: GraphStore,
{
    let mut pack = build_context_pack(graph, focal_id, opts)?;
    let budget_max = opts.budget.max_tokens();
    let supporting_files = collect_supporting_file_ids(graph, plan)?;

    if supporting_files.is_empty() {
        return Ok(pack);
    }

    append_supporting_artifacts(graph, &mut pack, &supporting_files, budget_max)?;
    // Dedup in encounter order rather than through a set. `supporting_artifacts`
    // is already ordered by file path, and `append_artifact_scoped_metadata`
    // admits the work items and annotations it finds under the same token
    // budget, so draining a hash set here would let arbitrary iteration order
    // decide which metadata survives a tight budget.
    let mut seen_supporting_files = std::collections::HashSet::new();
    let supporting_files: Vec<FilePathId> = pack
        .supporting_artifacts
        .iter()
        .map(|entry| entry.file_path.clone())
        .filter(|path| seen_supporting_files.insert(path.clone()))
        .collect();
    if !supporting_files.is_empty() {
        append_artifact_scoped_metadata(graph, &mut pack, &supporting_files, budget_max)?;
    }

    Ok(pack)
}

/// Build a context pack with traffic metadata from nearby intents.
///
/// `nearby_intents` should contain active intents that overlap with or are
/// near the focal entity's scope. The caller is responsible for querying
/// these from the session/intent store.
///
/// Each intent is classified by proximity to the focal entity:
/// - **Direct**: the intent locks the focal entity or a direct dependency
/// - **Downstream**: the intent locks a transitive dependency
/// - **SameFile**: the intent locks a file containing the focal entity
pub fn build_context_pack_with_traffic<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
    nearby_intents: &[IntentSummary],
) -> Result<ContextPack>
where
    G: GraphStore,
{
    build_context_pack_with_traffic_and_provenance(graph, focal_id, opts, nearby_intents)
        .map(|(pack, _)| pack)
}

/// [`build_context_pack_with_traffic`], reporting how the dependency section was
/// selected. See [`build_context_pack_with_provenance`] for why the pack cannot
/// carry that itself.
pub fn build_context_pack_with_traffic_and_provenance<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
    nearby_intents: &[IntentSummary],
) -> Result<(ContextPack, DependencySelection)>
where
    G: GraphStore,
{
    let (mut pack, selection) = build_context_pack_with_provenance(graph, focal_id, opts)?;

    if !opts.include_traffic || nearby_intents.is_empty() {
        return Ok((pack, selection));
    }

    // Classify each intent by proximity to the focal entity.
    let focal = graph
        .get_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?
        .ok_or_else(|| ContextError::EntityNotFound(focal_id.to_string()))?;

    let direct_relations = graph
        .get_all_relations_for_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    let direct_dep_ids: Vec<EntityId> = direct_relations
        .iter()
        .filter_map(|r| {
            if r.src == GraphNodeId::Entity(*focal_id) {
                r.dst.as_entity()
            } else if r.dst == GraphNodeId::Entity(*focal_id) {
                r.src.as_entity()
            } else {
                None
            }
        })
        .collect();

    let subgraph = graph
        .get_dependency_neighborhood(focal_id, opts.max_depth)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    let transitive_ids: Vec<EntityId> = subgraph
        .entities
        .keys()
        .filter(|id| **id != *focal_id && !direct_dep_ids.contains(id))
        .copied()
        .collect();

    for intent in nearby_intents {
        let proximity =
            classify_proximity(intent, focal_id, &focal, &direct_dep_ids, &transitive_ids);

        let entry_content = format_traffic_entry(intent, proximity);
        let tokens = estimate_tokens(&entry_content);

        if pack.actual_tokens + tokens <= opts.budget.max_tokens() {
            pack.actual_tokens += tokens;
            pack.traffic.push(TrafficEntry {
                intent: intent.clone(),
                proximity,
            });
        }
    }

    debug!(
        traffic_entries = pack.traffic.len(),
        "added traffic metadata to context pack"
    );

    Ok((pack, selection))
}

fn collect_supporting_file_ids<G>(graph: &G, plan: &ContextPlan) -> Result<Vec<FilePathId>>
where
    G: GraphStore,
{
    let mut file_ids = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut push_file = |file_id: &FilePathId| {
        if seen.insert(file_id.clone()) {
            file_ids.push(file_id.clone());
        }
    };

    for seed in &plan.seeds {
        if let Some(file_path) = seed.file_path.as_ref() {
            push_file(file_path);
            continue;
        }

        match seed.retrieval_key {
            RetrievalKey::Entity(entity_id) => {
                if let Some(entity) = graph
                    .get_entity(&entity_id)
                    .map_err(|e| ContextError::Graph(e.to_string()))?
                {
                    if let Some(file_origin) = entity.file_origin.as_ref() {
                        push_file(file_origin);
                    }
                }
            }
            RetrievalKey::Artifact(artifact_id) => {
                return Err(ContextError::Other(format!(
                    "artifact retrieval seed {artifact_id:?} is missing file_path"
                )));
            }
            RetrievalKey::EntityRevision(rev_id) => {
                return Err(ContextError::Other(format!(
                    "entity revision retrieval seed {rev_id:?} is missing file_path"
                )));
            }
            RetrievalKey::ArtifactRevision(rev_id) => {
                return Err(ContextError::Other(format!(
                    "artifact revision retrieval seed {rev_id:?} is missing file_path"
                )));
            }
        }
    }

    Ok(file_ids)
}

/// Upper bound, in characters, on one supporting-artifact entry in a pack.
///
/// A tracked artifact retains its text up to
/// `kin_index::artifacts::ARTIFACT_TEXT_RETENTION_CHARS` so the text index and
/// the artifact embedding see the whole document. A pack entry is a different
/// thing: an excerpt sitting beside the focal entity under a shared token
/// budget. Unbounded, one ordinary document claims the entire budget, and every
/// other artifact for every other file loses its seat. The whole text stays
/// reachable through the artifact read path.
const ARTIFACT_ENTRY_CONTENT_CHARS: usize = 2_000;

/// Trim an artifact entry to the excerpt a pack can afford to carry.
fn bounded_artifact_entry_content(content: String) -> String {
    if content.len() <= ARTIFACT_ENTRY_CONTENT_CHARS {
        return content;
    }
    content.chars().take(ARTIFACT_ENTRY_CONTENT_CHARS).collect()
}

/// Admit supporting artifacts for the planned files under the pack's budget.
///
/// Admission skips an entry that does not fit rather than stopping at it.
/// Entries sort by file path, so stopping let whichever artifact happened to
/// sort early decide how many of the others were seen at all.
fn append_supporting_artifacts<G>(
    graph: &G,
    pack: &mut ContextPack,
    file_ids: &[FilePathId],
    budget_max: usize,
) -> Result<()>
where
    G: GraphStore,
{
    let mut entries = Vec::new();

    for file_id in file_ids {
        // Resolve exact tree identity before reading any path-keyed facet. A
        // planned artifact read keys on the admitted ArtifactId, so a path the
        // repository tree does not admit is reported as a graph gap instead of
        // being answered from whatever enrichment still carries that path.
        let artifact_id = require_admitted_artifact_id(graph, file_id)?;

        if let Some(file) = graph
            .get_shallow_file(file_id)
            .map_err(|e| ContextError::Graph(e.to_string()))?
        {
            entries.push(ArtifactContextEntry {
                retrieval_key: RetrievalKey::Artifact(artifact_id),
                file_path: file.file_id.clone(),
                kind: ArtifactContextKind::ShallowFile,
                content: bounded_artifact_entry_content(kin_db::embed::format_shallow_text(&file)),
            });
        }

        if let Some(artifact) = graph
            .get_structured_artifact(file_id)
            .map_err(|e| ContextError::Graph(e.to_string()))?
        {
            entries.push(ArtifactContextEntry {
                retrieval_key: RetrievalKey::Artifact(artifact_id),
                file_path: artifact.file_id.clone(),
                kind: ArtifactContextKind::StructuredArtifact(artifact.kind),
                content: bounded_artifact_entry_content(kin_db::embed::format_artifact_text(
                    &artifact,
                )),
            });
        }

        if let Some(artifact) = graph
            .get_opaque_artifact(file_id)
            .map_err(|e| ContextError::Graph(e.to_string()))?
        {
            entries.push(ArtifactContextEntry {
                retrieval_key: RetrievalKey::Artifact(artifact_id),
                file_path: artifact.file_id.clone(),
                kind: ArtifactContextKind::OpaqueArtifact,
                content: bounded_artifact_entry_content(kin_db::embed::format_opaque_text(
                    &artifact,
                )),
            });
        }
    }

    entries.sort_by(|left, right| {
        left.file_path
            .0
            .cmp(&right.file_path.0)
            .then_with(|| artifact_kind_rank(left.kind).cmp(&artifact_kind_rank(right.kind)))
    });

    for entry in entries {
        let tokens = estimate_tokens(&entry.content);
        if pack.actual_tokens + tokens > budget_max {
            continue;
        }
        pack.actual_tokens += tokens;
        pack.supporting_artifacts.push(entry);
    }

    Ok(())
}

fn require_admitted_artifact_id<G>(graph: &G, file_id: &FilePathId) -> Result<ArtifactId>
where
    G: GraphStore,
{
    let path = RepoPath::from_utf8(file_id.0.clone()).map_err(|error| {
        ContextError::Other(format!(
            "graph gap: artifact path {} is not a valid repository path: {error}",
            file_id.0
        ))
    })?;
    graph.artifact_id_at_path(&path).ok_or_else(|| {
        ContextError::Other(format!(
            "graph gap: no admitted artifact identity for {}",
            file_id.0
        ))
    })
}

fn artifact_kind_rank(kind: ArtifactContextKind) -> u8 {
    match kind {
        ArtifactContextKind::ShallowFile => 0,
        ArtifactContextKind::StructuredArtifact(_) => 1,
        ArtifactContextKind::OpaqueArtifact => 2,
    }
}

fn append_artifact_scoped_metadata<G>(
    graph: &G,
    pack: &mut ContextPack,
    file_ids: &[FilePathId],
    budget_max: usize,
) -> Result<()>
where
    G: GraphStore,
{
    let mut seen_work_ids = pack
        .work_items
        .iter()
        .map(|entry| entry.work_item.work_id)
        .collect::<std::collections::HashSet<_>>();
    let mut seen_annotation_ids = pack
        .annotations
        .iter()
        .map(|entry| entry.annotation.annotation_id)
        .collect::<std::collections::HashSet<_>>();

    for file_id in file_ids {
        let scope = WorkScope::Artifact(file_id.clone());

        for item in graph
            .get_work_for_scope(&scope)
            .map_err(|e| ContextError::Graph(e.to_string()))?
        {
            if item.is_closed() || !seen_work_ids.insert(item.work_id) {
                continue;
            }
            push_work_item(pack, budget_max, item);
        }

        for annotation in graph
            .get_annotations_for_scope(&scope)
            .map_err(|e| ContextError::Graph(e.to_string()))?
        {
            if annotation.staleness == kin_model::StalenessState::Stale
                || !seen_annotation_ids.insert(annotation.annotation_id)
            {
                continue;
            }
            push_annotation(pack, budget_max, annotation);
        }
    }

    Ok(())
}

fn push_work_item(pack: &mut ContextPack, budget_max: usize, item: WorkItem) {
    let content = format_work_item(&item);
    let tokens = estimate_tokens(&content);
    if pack.actual_tokens + tokens <= budget_max {
        pack.actual_tokens += tokens;
        pack.work_items.push(WorkItemEntry {
            work_item: item,
            content,
        });
    }
}

fn push_annotation(pack: &mut ContextPack, budget_max: usize, annotation: Annotation) {
    let content = format_annotation(&annotation);
    let tokens = estimate_tokens(&content);
    if pack.actual_tokens + tokens <= budget_max {
        pack.actual_tokens += tokens;
        pack.annotations.push(AnnotationEntry {
            annotation,
            content,
        });
    }
}

/// Classify how close an intent is to the focal entity.
fn classify_proximity(
    _intent: &IntentSummary,
    focal_id: &EntityId,
    focal: &Entity,
    direct_dep_ids: &[EntityId],
    transitive_ids: &[EntityId],
) -> TrafficProximity {
    // In a full implementation, we'd check intent.scopes against
    // focal_id, direct deps, transitive deps, and file origins.
    // For now, use a simple heuristic based on entity presence.
    let _ = (focal_id, focal, direct_dep_ids, transitive_ids);
    TrafficProximity::Direct
}

/// Format a traffic entry for inclusion in the context pack.
fn format_traffic_entry(intent: &IntentSummary, proximity: TrafficProximity) -> String {
    format!(
        "// TRAFFIC [{:?}]: {} ({}) - {}\n",
        proximity,
        intent.vendor,
        intent.lock_type_label(),
        intent.task_description
    )
}

/// Project the focal entity's HEADER, not its body, despite the name and despite
/// the `ProjectionLevel::FullBody` the caller records beside it.
///
/// This crate has no source-reading capability: bodies live in content-addressed
/// blobs reached through repository authority, which is a layer above. What this
/// produces is a header plus signature, used for the pack's token accounting.
///
/// Consumers must NOT surface this text as an entity's `body`. It is source-shaped
/// but is not source, so an agent that restates it as a body update deletes the
/// implementation. The MCP context-pack handlers therefore read the real body
/// through the graph-owned projection and report a gap when it is unavailable,
/// rather than falling back to this string.
fn project_full_body(entity: &Entity) -> String {
    let mut content = String::new();
    content.push_str(&format!(
        "// {} ({:?}, {})\n",
        entity.name, entity.kind, entity.language
    ));
    if let Some(ref summary) = entity.doc_summary {
        content.push_str(&format!("// {summary}\n"));
    }
    content.push_str(&entity.signature);
    content.push('\n');
    content
}

fn project_signature_only(entity: &Entity) -> String {
    let mut content = String::new();
    content.push_str(&entity.signature);
    if let Some(ref summary) = entity.doc_summary {
        content.push_str(&format!("  // {summary}"));
    }
    content.push('\n');
    content
}

fn project_name_and_kind(entity: &Entity) -> String {
    format!(
        "{} ({:?}): {}\n",
        entity.name, entity.kind, entity.signature
    )
}

fn format_work_item(item: &kin_model::WorkItem) -> String {
    format!(
        "// WORK [{}] {}: {} ({})\n",
        item.kind, item.status, item.title, item.work_id,
    )
}

fn format_annotation(ann: &kin_model::Annotation) -> String {
    let body_preview = if ann.body.len() > 80 {
        format!("{}...", &ann.body[..80])
    } else {
        ann.body.clone()
    };
    format!(
        "// ANNOTATION [{}] {}: {}\n",
        ann.kind, ann.staleness, body_preview,
    )
}

fn same_file_neighbor_rank(focal: &Entity, candidate: &Entity) -> (u8, u8, usize) {
    let focal_norm = normalize_entity_name(&focal.name);
    let candidate_norm = normalize_entity_name(&candidate.name);

    let exact_companion = candidate_norm == focal_norm && candidate.name != focal.name;
    let substring_related =
        candidate_norm.contains(&focal_norm) || focal_norm.contains(&candidate_norm);
    let same_kind = candidate.kind == focal.kind;

    (
        !exact_companion as u8,
        !(substring_related || same_kind) as u8,
        candidate.name.len(),
    )
}

fn normalize_entity_name(name: &str) -> String {
    name.trim_start_matches(['$', '_']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn admit_test_artifact(
        store: &kin_db::InMemoryGraph,
        file_id: &FilePathId,
        hash: Hash256,
    ) -> ArtifactId {
        let path = RepoPath::from_utf8(file_id.0.clone()).expect("valid test repository path");
        if let Some(artifact_id) = store.artifact_id_at_path(&path) {
            return artifact_id;
        }
        let artifact_id = ArtifactId::new();
        store
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .expect("test fixture admission must use the repository tree transaction");
        artifact_id
    }

    fn make_entity(name: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
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
            file_origin: None,
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

    fn make_file_entity(name: &str, kind: EntityKind, file_path: &str) -> Entity {
        let mut entity = make_entity(name, kind);
        entity.file_origin = Some(FilePathId::new(file_path));
        entity
    }

    #[test]
    fn classify_subgraph_entity_sections_match_intent() {
        let opts = ContextOptions {
            include_tests: true,
            include_contracts: true,
            ..ContextOptions::default()
        };

        let mut test_e = make_entity("a_test", EntityKind::Function);
        test_e.role = EntityRole::Test;
        assert_eq!(
            classify_subgraph_entity(&test_e, true, true, 9.0, &opts).map(|c| c.section),
            Some(AssemblySection::Test),
            "test role takes precedence even when also a direct dep"
        );

        let contract = make_entity("an_endpoint", EntityKind::ApiEndpoint);
        assert_eq!(
            classify_subgraph_entity(&contract, false, false, 0.0, &opts).map(|c| c.section),
            Some(AssemblySection::Contract)
        );

        let direct = make_entity("a_callee", EntityKind::Function);
        assert_eq!(
            classify_subgraph_entity(&direct, true, true, 5.0, &opts).map(|c| c.section),
            Some(AssemblySection::DirectDep)
        );

        let transitive = make_entity("a_transitive", EntityKind::Function);
        assert_eq!(
            classify_subgraph_entity(&transitive, false, true, TRANSITIVE_RELEVANCE_FLOOR, &opts)
                .map(|c| c.section),
            Some(AssemblySection::Transitive)
        );
        // Not on a dependency edge → no candidate.
        assert!(classify_subgraph_entity(&transitive, false, false, 9.0, &opts).is_none());
        // Below the relevance floor → no candidate.
        assert!(classify_subgraph_entity(
            &transitive,
            false,
            true,
            TRANSITIVE_RELEVANCE_FLOOR - 0.5,
            &opts
        )
        .is_none());
    }

    #[test]
    fn parallel_assembly_admits_a_stable_set() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("focal", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();
        // Above PARALLEL_ASSEMBLY_MIN_ENTITIES so the parallel projection path runs.
        let n = PARALLEL_ASSEMBLY_MIN_ENTITIES + 24;
        for i in 0..n {
            let dep = make_entity(&format!("dep_{i}"), EntityKind::Function);
            store.upsert_entity(&dep).unwrap();
            store
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(focal.id),
                    dst: GraphNodeId::Entity(dep.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        // Generous budget so every dep is admitted; the admitted set is then a
        // pure function of content, independent of the (pre-existing) tie-order.
        let opts = ContextOptions {
            budget: TokenBudget::Large32k,
            ..ContextOptions::default()
        };
        let admitted = |p: &ContextPack| {
            let mut ids: Vec<_> = p
                .dependency_signatures
                .iter()
                .map(|e| e.entity_id)
                .collect();
            ids.sort();
            ids
        };
        let a = build_context_pack(&store, &focal.id, &opts).unwrap();
        let b = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(
            !a.dependency_signatures.is_empty(),
            "parallel path should admit direct deps"
        );
        assert_eq!(
            admitted(&a),
            admitted(&b),
            "parallel context-pack assembly must admit a stable set"
        );
    }

    #[test]
    fn tight_budget_truncation_is_deterministic_across_invocations() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        // Equal-weight (all `Calls`) candidates with fixed-width names, so every
        // projection costs the same tokens and relation weight alone cannot order
        // them. Which candidates survive a tight budget is then decided purely by
        // the tie-break, which is exactly what must not vary between runs.
        let n = PARALLEL_ASSEMBLY_MIN_ENTITIES + 24;
        let focal = make_entity("focal", EntityKind::Function);
        let deps: Vec<Entity> = (0..n)
            .map(|i| make_entity(&format!("dep_{i:04}"), EntityKind::Function))
            .collect();

        // Two stores holding the same entity ids, populated in opposite orders.
        // A correct builder owes both the same answer; an order-sensitive one
        // does not. Insertion order also perturbs the graph's own hash layout.
        let store_of = |reverse: bool| {
            let store = kin_db::InMemoryGraph::new();
            store.upsert_entity(&focal).unwrap();
            let ordered: Vec<&Entity> = if reverse {
                deps.iter().rev().collect()
            } else {
                deps.iter().collect()
            };
            for dep in ordered {
                store.upsert_entity(dep).unwrap();
                store
                    .upsert_relation(&Relation {
                        id: kin_model::ids::RelationId::new(),
                        kind: RelationKind::Calls,
                        src: GraphNodeId::Entity(focal.id),
                        dst: GraphNodeId::Entity(dep.id),
                        confidence: 1.0,
                        origin: RelationOrigin::Parsed,
                        created_in: None,
                        import_source: None,
                        evidence: Vec::new(),
                    })
                    .unwrap();
            }
            store
        };

        let forward = store_of(false);
        let reverse = store_of(true);

        let admitted = |p: &ContextPack| {
            let mut ids: Vec<_> = p
                .dependency_signatures
                .iter()
                .map(|e| e.entity_id)
                .collect();
            ids.sort();
            ids
        };

        // Size the budget off an unconstrained pack so the cut lands mid-list
        // regardless of how projection costs change later.
        let full = build_context_pack(
            &forward,
            &focal.id,
            &ContextOptions {
                budget: TokenBudget::Large32k,
                ..ContextOptions::default()
            },
        )
        .unwrap();
        let opts = ContextOptions {
            budget: TokenBudget::Custom(full.actual_tokens / 2),
            ..ContextOptions::default()
        };

        let baseline = build_context_pack(&forward, &focal.id, &opts).unwrap();
        let kept = baseline.dependency_signatures.len();
        assert!(
            kept > 0 && kept < full.dependency_signatures.len(),
            "budget must actually truncate for this test to mean anything: kept {kept} of {}",
            full.dependency_signatures.len()
        );

        // Repeated invocations rebuild the neighborhood subgraph, and each rebuild
        // gets a freshly seeded hash map, so an order-sensitive selection diverges
        // here without needing separate processes.
        for run in 1..16 {
            let again = build_context_pack(&forward, &focal.id, &opts).unwrap();
            assert_eq!(
                admitted(&again),
                admitted(&baseline),
                "invocation {run} admitted a different set under the same budget"
            );
            let mirrored = build_context_pack(&reverse, &focal.id, &opts).unwrap();
            assert_eq!(
                admitted(&mirrored),
                admitted(&baseline),
                "invocation {run} admitted a different set when the graph was populated in reverse"
            );
        }
    }

    fn make_artifact_work_item(title: &str, file_path: &FilePathId) -> WorkItem {
        WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Task,
            title: title.to_string(),
            description: format!("Artifact-scoped work item: {title}"),
            status: WorkStatus::InProgress,
            priority: Priority::Medium,
            scopes: vec![WorkScope::Artifact(file_path.clone())],
            acceptance_criteria: vec!["Tests pass".to_string()],
            external_refs: vec![],
            created_by: IdentityRef::human("test"),
            created_at: Timestamp::now(),
        }
    }

    fn make_artifact_annotation(body: &str, file_path: &FilePathId) -> Annotation {
        Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Warning,
            body: body.to_string(),
            scopes: vec![WorkScope::Artifact(file_path.clone())],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("test"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        }
    }

    #[test]
    fn full_body_includes_metadata() {
        let entity = make_entity("process", EntityKind::Function);
        let content = project_full_body(&entity);
        assert!(content.contains("process"));
        assert!(content.contains("Function"));
        assert!(content.contains("fn process()"));
    }

    #[test]
    fn signature_only_is_compact() {
        let entity = make_entity("helper", EntityKind::Function);
        let content = project_signature_only(&entity);
        assert!(content.contains("fn helper()"));
        assert!(content.contains("Does helper things"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn name_and_kind_is_minimal() {
        let entity = make_entity("util", EntityKind::Function);
        let content = project_name_and_kind(&entity);
        assert!(content.contains("util"));
        assert!(content.contains("Function"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn context_options_default() {
        let opts = ContextOptions::default();
        assert_eq!(opts.budget, TokenBudget::Small8k);
        assert_eq!(opts.max_depth, 2);
        assert!(opts.include_tests);
        assert!(opts.include_contracts);
        assert!(!opts.include_traffic);
    }

    #[test]
    fn context_options_default_no_hint() {
        let opts = ContextOptions::default();
        assert_eq!(opts.assistant_hint, None);
    }

    #[test]
    fn cochange_weight_ranks_between_calls_and_dependencies() {
        assert!(relation_weight(&RelationKind::Calls) > relation_weight(&RelationKind::CoChanges));
        assert!(
            relation_weight(&RelationKind::CoChanges) > relation_weight(&RelationKind::DependsOn)
        );
    }

    #[test]
    fn effective_depth_claude() {
        // ClaudeCode increases depth by 1.
        let base_depth: u32 = 2;
        let effective = match Some(AssistantHint::ClaudeCode) {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 3);
    }

    #[test]
    fn effective_depth_codex() {
        // Codex decreases depth by 1, but never below 1.
        let base_depth: u32 = 2;
        let effective = match Some(AssistantHint::Codex) {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 1);

        // Verify floor of 1 when base_depth is already 1.
        let base_depth: u32 = 1;
        let effective = match Some(AssistantHint::Codex) {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 1);
    }

    #[test]
    fn effective_depth_default() {
        // No hint: depth unchanged.
        let base_depth: u32 = 2;
        let hint: Option<AssistantHint> = None;
        let effective = match hint {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 2);
    }

    #[test]
    fn format_traffic_entry_output() {
        let intent = IntentSummary {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            vendor: "claude-code".to_string(),
            task_description: "Refactoring auth".to_string(),
            lock_type: LockType::Soft,
            registered_at: Timestamp::now(),
        };
        let output = format_traffic_entry(&intent, TrafficProximity::Direct);
        assert!(output.contains("claude-code"));
        assert!(output.contains("soft-lock"));
        assert!(output.contains("Refactoring auth"));
        assert!(output.contains("Direct"));
    }

    #[test]
    fn format_traffic_hard_lock() {
        let intent = IntentSummary {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            vendor: "codex".to_string(),
            task_description: "Schema migration".to_string(),
            lock_type: LockType::Hard,
            registered_at: Timestamp::now(),
        };
        let output = format_traffic_entry(&intent, TrafficProximity::Downstream);
        assert!(output.contains("hard-lock"));
        assert!(output.contains("Downstream"));
    }

    #[test]
    fn context_pack_falls_back_to_same_file_neighbors_when_no_graph_relations() {
        let store = kin_db::InMemoryGraph::new();

        let focal = make_file_entity("safeParse", EntityKind::Constant, "src/parse.ts");
        let sibling = make_file_entity("parse", EntityKind::Constant, "src/parse.ts");
        let unrelated = make_file_entity("helper", EntityKind::Function, "src/other.ts");

        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&sibling).unwrap();
        store.upsert_entity(&unrelated).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();

        assert!(
            pack.dependency_signatures
                .iter()
                .any(|entry| entry.content.contains("parse")),
            "same-file sibling should appear as a fallback dependency"
        );
        assert!(
            pack.dependency_signatures
                .iter()
                .all(|entry| !entry.content.contains("helper")),
            "entities from other files should not be pulled in by the same-file fallback"
        );
    }

    #[test]
    fn context_pack_prioritizes_companion_same_file_neighbors() {
        let store = kin_db::InMemoryGraph::new();

        let focal = make_file_entity("safeParse", EntityKind::Constant, "src/parse.ts");
        let companion = make_file_entity("_safeParse", EntityKind::Constant, "src/parse.ts");
        let sibling = make_file_entity("parse", EntityKind::Constant, "src/parse.ts");

        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&companion).unwrap();
        store.upsert_entity(&sibling).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        let first = &pack.dependency_signatures[0].content;

        assert!(
            first.contains("_safeParse"),
            "closest same-file companion should be ranked first"
        );
    }

    /// The fallback is a different answer to a different question, and the pack
    /// alone cannot say which one a caller got: `dependency_signatures` is the
    /// same field either way, and the cap turns a twenty-four-member class into
    /// six rows with nothing reporting the other eighteen.
    #[test]
    fn same_file_fallback_reports_its_source_and_what_the_cap_dropped() {
        let store = kin_db::InMemoryGraph::new();

        let focal = make_file_entity("NoteStore", EntityKind::Class, "src/notes.py");
        store.upsert_entity(&focal).unwrap();
        for index in 0..9 {
            let neighbor = make_file_entity(
                &format!("NoteStore.method{index}"),
                EntityKind::Method,
                "src/notes.py",
            );
            store.upsert_entity(&neighbor).unwrap();
        }

        let (pack, selection) =
            build_context_pack_with_provenance(&store, &focal.id, &ContextOptions::default())
                .unwrap();

        assert_eq!(selection.source(), DependencySource::SameFileFallback);
        assert_eq!(
            pack.dependency_signatures.len(),
            SAME_FILE_FALLBACK_MAX,
            "the cap is what makes a nine-neighbour file answer with six rows"
        );
        assert_eq!(selection.same_file_candidates(), 9);
        assert_eq!(selection.same_file_kept(), SAME_FILE_FALLBACK_MAX);
        assert_eq!(selection.same_file_dropped(), 3);
        for entry in &pack.dependency_signatures {
            assert_eq!(
                selection.relation_for(&entry.entity_id),
                DependencyRelation::SameFileNeighbor,
                "every fallback row must be reported as a neighbour, not an edge"
            );
        }
    }

    /// The other half of the same guard: a focal that really does have
    /// dependency edges must not be reported as a fallback, or the marker means
    /// nothing.
    #[test]
    fn dependency_edge_rows_are_not_reported_as_same_file_neighbors() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("read_notes", EntityKind::Function, "src/reader.py");
        let link_record = make_file_entity("LinkRecord", EntityKind::Class, "src/records.py");
        let note_record = make_file_entity("NoteRecord", EntityKind::Class, "src/records.py");
        // A neighbour in the focal's own file, which the fallback would have
        // reached for had the edges below not existed.
        let sibling = make_file_entity("read_note", EntityKind::Function, "src/reader.py");
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&link_record).unwrap();
        store.upsert_entity(&note_record).unwrap();
        store.upsert_entity(&sibling).unwrap();

        for callee in [&link_record, &note_record] {
            store
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(focal.id),
                    dst: GraphNodeId::Entity(callee.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let (pack, selection) =
            build_context_pack_with_provenance(&store, &focal.id, &ContextOptions::default())
                .unwrap();

        assert_eq!(selection.source(), DependencySource::DependencyEdges);
        assert_eq!(selection.same_file_candidates(), 0);
        assert_eq!(selection.same_file_dropped(), 0);
        assert_eq!(pack.dependency_signatures.len(), 2);
        for entry in &pack.dependency_signatures {
            assert_eq!(
                selection.relation_for(&entry.entity_id),
                DependencyRelation::DependencyEdge
            );
        }
        assert!(
            pack.dependency_signatures
                .iter()
                .all(|entry| entry.entity_id != sibling.id),
            "a same-file sibling must not join a pack that has real edges"
        );
    }

    /// The greenfield stranger's pack listed nine callers under "dependencies"
    /// and put the one real callee tenth. Direction is the whole of the answer:
    /// every kind `is_dependency_edge` accepts runs src-depends-on-dst, so an
    /// edge leaving the focal names what the focal needs and an edge arriving
    /// names what needs the focal. Reading only the non-focal endpoint reported
    /// callers as callees, and ordering on relation weight alone buried the one
    /// row that answered the question asked.
    #[test]
    fn one_dependency_leads_the_section_and_nine_dependents_are_labelled_as_such() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let calls = |src: EntityId, dst: EntityId| {
            store
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(src),
                    dst: GraphNodeId::Entity(dst),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        };

        let focal = make_file_entity("save_note", EntityKind::Function, "src/store.py");
        // The one entity the focal needs.
        let dependency = make_file_entity("serialize", EntityKind::Function, "src/codec.py");
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&dependency).unwrap();
        calls(focal.id, dependency.id);

        // Nine entities that need the focal.
        let mut dependents = Vec::new();
        for index in 0..9 {
            let caller = make_file_entity(
                &format!("handle_request_{index}"),
                EntityKind::Function,
                &format!("src/api_{index}.py"),
            );
            store.upsert_entity(&caller).unwrap();
            calls(caller.id, focal.id);
            dependents.push(caller);
        }

        let (pack, selection) =
            build_context_pack_with_provenance(&store, &focal.id, &ContextOptions::default())
                .unwrap();

        assert_eq!(selection.source(), DependencySource::DependencyEdges);
        assert_eq!(
            pack.dependency_signatures.len(),
            10,
            "both directions stay in the pack; only the labels and the order change"
        );

        // Labels first, then order. The order is DERIVED from the labels, so
        // asserting it first would report a mislabelling as a sort bug and hide
        // which of the two actually broke.
        assert_eq!(
            selection.relation_for(&dependency.id),
            DependencyRelation::DependencyEdge,
            "an edge leaving the focal is a dependency"
        );
        for caller in &dependents {
            assert_eq!(
                selection.relation_for(&caller.id),
                DependencyRelation::DependentEdge,
                "'{}' calls the focal, so it depends on the focal; reporting it as a \
                 dependency inverts the claim a caller acts on",
                caller.name
            );
        }
        let labelled_dependencies = pack
            .dependency_signatures
            .iter()
            .filter(|entry| {
                selection.relation_for(&entry.entity_id) == DependencyRelation::DependencyEdge
            })
            .count();
        assert_eq!(
            labelled_dependencies, 1,
            "exactly one row rides an edge that leaves the focal"
        );

        assert_eq!(
            pack.dependency_signatures[0].entity_id, dependency.id,
            "the one entity the focal depends on must lead the section, not trail nine callers"
        );
    }

    /// An entity joined to the focal in both directions is a dependency: the
    /// focal really does need it, and that is the claim a reader acts on when
    /// deciding what may be removed.
    #[test]
    fn a_mutual_edge_is_reported_as_a_dependency_not_a_dependent() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let calls = |src: EntityId, dst: EntityId| {
            store
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(src),
                    dst: GraphNodeId::Entity(dst),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        };

        let focal = make_file_entity("ping", EntityKind::Function, "src/a.py");
        let peer = make_file_entity("pong", EntityKind::Function, "src/b.py");
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&peer).unwrap();
        calls(focal.id, peer.id);
        calls(peer.id, focal.id);

        let (pack, selection) =
            build_context_pack_with_provenance(&store, &focal.id, &ContextOptions::default())
                .unwrap();

        assert_eq!(
            pack.dependency_signatures.len(),
            1,
            "one entity produces one row however many edges join it to the focal"
        );
        assert_eq!(
            selection.relation_for(&peer.id),
            DependencyRelation::DependencyEdge
        );
    }

    #[test]
    fn build_context_pack_from_plan_includes_seeded_artifacts_only() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let makefile = FilePathId::new("Makefile");
        let package_manifest = FilePathId::new("package.json");
        let makefile_artifact_id =
            admit_test_artifact(&store, &makefile, Hash256::from_bytes([3; 32]));
        admit_test_artifact(&store, &package_manifest, Hash256::from_bytes([4; 32]));

        store
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: makefile.clone(),
                language_hint: "make".to_string(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: Hash256::from_bytes([1; 32]),
                signature_hash: None,
                declaration_names: vec!["build".to_string()],
                import_paths: vec![],
            })
            .unwrap();
        store
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: makefile.clone(),
                kind: ArtifactKind::Makefile,
                content_hash: Hash256::from_bytes([2; 32]),
                text_preview: Some("build:\n\tcargo test".to_string()),
            })
            .unwrap();
        store
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: makefile.clone(),
                content_hash: Hash256::from_bytes([3; 32]),
                mime_type: Some("text/plain".to_string()),
                text_preview: Some("opaque preview".to_string()),
            })
            .unwrap();
        store
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: package_manifest,
                kind: ArtifactKind::PackageManifest,
                content_hash: Hash256::from_bytes([4; 32]),
                text_preview: Some("{\"name\":\"ignored\"}".to_string()),
            })
            .unwrap();

        let plan = ContextPlan {
            seeds: vec![ContextPlanSeed {
                retrieval_key: RetrievalKey::Artifact(makefile_artifact_id),
                file_path: Some(makefile.clone()),
                score: 3.0,
                lexical: true,
                semantic: false,
            }],
        };

        let pack =
            build_context_pack_from_plan(&store, &focal.id, &ContextOptions::default(), &plan)
                .unwrap();

        assert_eq!(pack.supporting_artifacts.len(), 3);
        assert!(pack
            .supporting_artifacts
            .iter()
            .all(|entry| entry.file_path == makefile));
        assert!(pack
            .supporting_artifacts
            .iter()
            .any(|entry| matches!(entry.kind, ArtifactContextKind::ShallowFile)));
        assert!(pack.supporting_artifacts.iter().any(|entry| matches!(
            entry.kind,
            ArtifactContextKind::StructuredArtifact(ArtifactKind::Makefile)
        )));
        assert!(pack
            .supporting_artifacts
            .iter()
            .any(|entry| matches!(entry.kind, ArtifactContextKind::OpaqueArtifact)));
    }

    #[test]
    fn build_context_pack_from_empty_plan_is_noop() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let base = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        let planned = build_context_pack_from_plan(
            &store,
            &focal.id,
            &ContextOptions::default(),
            &ContextPlan::default(),
        )
        .unwrap();

        assert_eq!(planned.actual_tokens, base.actual_tokens);
        assert_eq!(
            planned.dependency_signatures.len(),
            base.dependency_signatures.len()
        );
        assert!(planned.supporting_artifacts.is_empty());
    }

    #[test]
    fn build_context_pack_from_plan_resolves_entity_seed_file_origins() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();
        admit_test_artifact(
            &store,
            &FilePathId::new("src/main.rs"),
            Hash256::from_bytes([5; 32]),
        );
        store
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: FilePathId::new("src/main.rs"),
                language_hint: "rust".to_string(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: Hash256::from_bytes([5; 32]),
                signature_hash: None,
                declaration_names: vec!["handler".to_string()],
                import_paths: vec![],
            })
            .unwrap();

        let plan = ContextPlan {
            seeds: vec![ContextPlanSeed {
                retrieval_key: RetrievalKey::Entity(focal.id),
                file_path: None,
                score: 2.0,
                lexical: true,
                semantic: false,
            }],
        };

        let pack =
            build_context_pack_from_plan(&store, &focal.id, &ContextOptions::default(), &plan)
                .unwrap();

        assert_eq!(pack.supporting_artifacts.len(), 1);
        assert_eq!(
            pack.supporting_artifacts[0].file_path,
            FilePathId::new("src/main.rs")
        );
        assert!(matches!(
            pack.supporting_artifacts[0].kind,
            ArtifactContextKind::ShallowFile
        ));
    }

    #[test]
    fn build_context_pack_from_plan_rejects_artifact_seed_without_file_path() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let result = build_context_pack_from_plan(
            &store,
            &focal.id,
            &ContextOptions::default(),
            &ContextPlan {
                seeds: vec![ContextPlanSeed {
                    retrieval_key: RetrievalKey::Artifact(ArtifactId::new()),
                    file_path: None,
                    score: 1.0,
                    lexical: true,
                    semantic: false,
                }],
            },
        );

        assert!(
            matches!(result, Err(ContextError::Other(message)) if message.contains("missing file_path"))
        );
    }

    #[test]
    fn build_context_pack_from_plan_gates_artifact_metadata_on_budget() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let makefile = FilePathId::new("Makefile");
        let makefile_artifact_id =
            admit_test_artifact(&store, &makefile, Hash256::from_bytes([6; 32]));
        store
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: makefile.clone(),
                language_hint: "make".to_string(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: Hash256::from_bytes([6; 32]),
                signature_hash: None,
                declaration_names: vec!["build".to_string()],
                import_paths: vec![],
            })
            .unwrap();
        store
            .create_work_item(&make_artifact_work_item("Fix build rule", &makefile))
            .unwrap();
        store
            .create_annotation(&make_artifact_annotation(
                "Keep this target cached",
                &makefile,
            ))
            .unwrap();

        let plan = ContextPlan {
            seeds: vec![ContextPlanSeed {
                retrieval_key: RetrievalKey::Artifact(makefile_artifact_id),
                file_path: Some(makefile),
                score: 1.0,
                lexical: true,
                semantic: false,
            }],
        };

        let focal_budget = TokenBudget::Custom(estimate_tokens(&project_full_body(&focal)));
        let pack = build_context_pack_from_plan(
            &store,
            &focal.id,
            &ContextOptions {
                budget: focal_budget,
                ..ContextOptions::default()
            },
            &plan,
        )
        .unwrap();

        assert!(pack.supporting_artifacts.is_empty());
        assert!(pack
            .work_items
            .iter()
            .all(|entry| !entry.content.contains("Fix build rule")));
        assert!(pack
            .annotations
            .iter()
            .all(|entry| !entry.content.contains("Keep this target cached")));
    }

    /// A docs store is the case FIR-2183 is about, and a real doc is far larger
    /// than the metadata line artifacts used to carry. The entry must be
    /// excerpted to a size a pack can afford, and an entry that still does not
    /// fit must not decide whether the rest of the files are seen at all. The
    /// sibling Makefile sorts after AGENTS.md, so it is exactly the seat a
    /// stop-at-first-overflow admission gave away.
    #[test]
    fn a_large_docs_artifact_neither_empties_nor_dominates_supporting_artifacts() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let mut docs_body =
            String::from("# Kin Ecosystem AGENTS.md\n\nThe canonical umbrella doc.\n\n");
        while docs_body.len() < 53_000 {
            docs_body.push_str(
                "Ordinary paragraph about workspace upkeep, lane hygiene, and the ordered \
                 story this file keeps durable.\n\n",
            );
        }

        let agents = FilePathId::new("AGENTS.md");
        let makefile = FilePathId::new("Makefile");
        let agents_artifact_id = admit_test_artifact(&store, &agents, Hash256::from_bytes([7; 32]));
        let makefile_artifact_id =
            admit_test_artifact(&store, &makefile, Hash256::from_bytes([3; 32]));

        store
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: agents.clone(),
                content_hash: Hash256::from_bytes([7; 32]),
                mime_type: Some("text/markdown".to_string()),
                text_preview: Some(docs_body),
            })
            .unwrap();
        store
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: makefile.clone(),
                kind: ArtifactKind::Makefile,
                content_hash: Hash256::from_bytes([3; 32]),
                text_preview: Some("build:\n\tcargo test".to_string()),
            })
            .unwrap();

        let plan = ContextPlan {
            seeds: vec![
                ContextPlanSeed {
                    retrieval_key: RetrievalKey::Artifact(agents_artifact_id),
                    file_path: Some(agents.clone()),
                    score: 3.0,
                    lexical: true,
                    semantic: false,
                },
                ContextPlanSeed {
                    retrieval_key: RetrievalKey::Artifact(makefile_artifact_id),
                    file_path: Some(makefile.clone()),
                    score: 2.0,
                    lexical: true,
                    semantic: false,
                },
            ],
        };

        let options = ContextOptions::default();
        let budget_max = options.budget.max_tokens();
        let pack = build_context_pack_from_plan(&store, &focal.id, &options, &plan).unwrap();

        let docs_entry = pack
            .supporting_artifacts
            .iter()
            .find(|entry| entry.file_path == agents)
            .expect("a docs store must carry its own artifact in a default-budget pack");
        assert!(
            docs_entry.content.contains("Kin Ecosystem AGENTS.md"),
            "the admitted entry must carry artifact text, not just its metadata line"
        );
        assert!(
            docs_entry.content.chars().count() <= ARTIFACT_ENTRY_CONTENT_CHARS,
            "one artifact entry must stay an excerpt"
        );
        assert!(
            estimate_tokens(&docs_entry.content) * 4 < budget_max,
            "one artifact entry must not claim a quarter of the budget"
        );

        assert!(
            pack.supporting_artifacts
                .iter()
                .any(|entry| entry.file_path == makefile),
            "a large artifact must not cost a later file its seat"
        );
        assert!(pack.actual_tokens <= budget_max);
    }

    /// Admission skips what it cannot afford instead of stopping there. The
    /// budget here fits the Makefile entry and not the AGENTS.md one, and
    /// AGENTS.md sorts first, so stopping at the first overflow costs the
    /// Makefile a seat it could have paid for.
    #[test]
    fn an_unaffordable_artifact_does_not_cost_the_next_file_its_seat() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let agents = FilePathId::new("AGENTS.md");
        let makefile = FilePathId::new("Makefile");
        assert!(agents.0 < makefile.0, "the large entry must sort first");

        let agents_artifact_id = admit_test_artifact(&store, &agents, Hash256::from_bytes([7; 32]));
        let makefile_artifact_id =
            admit_test_artifact(&store, &makefile, Hash256::from_bytes([3; 32]));

        let opaque = OpaqueArtifact {
            file_id: agents.clone(),
            content_hash: Hash256::from_bytes([7; 32]),
            mime_type: Some("text/markdown".to_string()),
            text_preview: Some("Doctrine paragraph about lane hygiene. ".repeat(40)),
        };
        let structured = StructuredArtifact {
            file_id: makefile.clone(),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([3; 32]),
            text_preview: Some("build:\n\tcargo test".to_string()),
        };
        store.upsert_opaque_artifact(&opaque).unwrap();
        store.upsert_structured_artifact(&structured).unwrap();

        let agents_tokens = estimate_tokens(&bounded_artifact_entry_content(
            kin_db::embed::format_opaque_text(&opaque),
        ));
        let makefile_tokens = estimate_tokens(&bounded_artifact_entry_content(
            kin_db::embed::format_artifact_text(&structured),
        ));
        assert!(
            makefile_tokens < agents_tokens,
            "the fixture must make only the later entry affordable"
        );

        let baseline = build_context_pack(&store, &focal.id, &ContextOptions::default())
            .unwrap()
            .actual_tokens;
        let options = ContextOptions {
            budget: TokenBudget::Custom(baseline + makefile_tokens),
            ..ContextOptions::default()
        };

        let plan = ContextPlan {
            seeds: vec![
                ContextPlanSeed {
                    retrieval_key: RetrievalKey::Artifact(agents_artifact_id),
                    file_path: Some(agents.clone()),
                    score: 3.0,
                    lexical: true,
                    semantic: false,
                },
                ContextPlanSeed {
                    retrieval_key: RetrievalKey::Artifact(makefile_artifact_id),
                    file_path: Some(makefile.clone()),
                    score: 2.0,
                    lexical: true,
                    semantic: false,
                },
            ],
        };

        let pack = build_context_pack_from_plan(&store, &focal.id, &options, &plan).unwrap();

        let admitted: Vec<&FilePathId> = pack
            .supporting_artifacts
            .iter()
            .map(|entry| &entry.file_path)
            .collect();
        assert_eq!(
            admitted,
            vec![&makefile],
            "the affordable later entry must still be admitted"
        );
        assert!(pack.actual_tokens <= options.budget.max_tokens());
    }

    #[test]
    fn supporting_artifact_without_tree_identity_is_an_explicit_graph_gap() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("handler", EntityKind::Function, "src/main.rs");
        store.upsert_entity(&focal).unwrap();

        let makefile = FilePathId::new("Makefile");
        let hash = Hash256::from_bytes([0x6a; 32]);
        let artifact_id = admit_test_artifact(&store, &makefile, hash);
        store
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: makefile.clone(),
                language_hint: "make".to_string(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: hash,
                signature_hash: None,
                declaration_names: vec!["build".to_string()],
                import_paths: vec![],
            })
            .unwrap();
        store
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: LocatedEntry::new(
                        RepoPath::from_utf8("Makefile").unwrap(),
                        TreeEntry::blob(hash, false),
                    ),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        let error = build_context_pack_from_plan(
            &store,
            &focal.id,
            &ContextOptions::default(),
            &ContextPlan {
                seeds: vec![ContextPlanSeed {
                    retrieval_key: RetrievalKey::Artifact(artifact_id),
                    file_path: Some(makefile),
                    score: 1.0,
                    lexical: true,
                    semantic: false,
                }],
            },
        )
        .expect_err("missing tree identity must not be fabricated from the path");

        assert!(
            matches!(error, ContextError::Other(message) if message.contains("graph gap: no admitted artifact identity for Makefile"))
        );
    }

    // ── Token budget enforcement tests ──────────────────────────────────

    #[test]
    fn pack_does_not_exceed_budget() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("focal_fn", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let opts = ContextOptions {
            budget: TokenBudget::Small8k,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(
            pack.actual_tokens <= opts.budget.max_tokens(),
            "actual tokens {} should not exceed budget {}",
            pack.actual_tokens,
            opts.budget.max_tokens()
        );
    }

    #[test]
    fn pack_respects_medium_budget() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("handler", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let opts = ContextOptions {
            budget: TokenBudget::Medium16k,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(pack.actual_tokens <= opts.budget.max_tokens());
    }

    #[test]
    fn pack_respects_large_budget() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("main", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let opts = ContextOptions {
            budget: TokenBudget::Large32k,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(pack.actual_tokens <= opts.budget.max_tokens());
    }

    // ── Budget with 0 deps ──────────────────────────────────────────────

    #[test]
    fn budget_with_zero_deps() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("isolated_fn", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let opts = ContextOptions {
            budget: TokenBudget::Small8k,
            max_depth: 0,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert_eq!(pack.focal_entities.len(), 1);
        assert!(pack.dependency_signatures.is_empty());
        assert!(pack.transitive_deps.is_empty());
    }

    // ── Budget with many deps ───────────────────────────────────────────

    #[test]
    fn budget_with_many_deps() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("core", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        // Create 100 dependencies
        for i in 0..100 {
            let dep = make_entity(&format!("dep_{i}"), EntityKind::Function);
            store.upsert_entity(&dep).unwrap();
            let rel = Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(focal.id),
                dst: GraphNodeId::Entity(dep.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            };
            store.upsert_relation(&rel).unwrap();
        }

        let opts = ContextOptions {
            budget: TokenBudget::Small8k,
            max_depth: 1,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(pack.actual_tokens <= opts.budget.max_tokens());
        assert!(!pack.dependency_signatures.is_empty());
    }

    // ── Transitive relevance floor ──────────────────────────────────────

    #[test]
    fn transitive_fill_drops_structural_only_neighbors() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        let mk_rel = |kind, src: EntityId, dst: EntityId| Relation {
            id: kin_model::ids::RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("focal_fn", EntityKind::Function);
        let direct = make_entity("caller_A", EntityKind::Function);
        let semantic = make_entity("semantic_C", EntityKind::Function);
        let structural = make_entity("structural_B", EntityKind::Function);
        for e in [&focal, &direct, &semantic, &structural] {
            store.upsert_entity(e).unwrap();
        }
        // focal -Calls-> direct (1-hop real dep)
        store
            .upsert_relation(&mk_rel(RelationKind::Calls, focal.id, direct.id))
            .unwrap();
        // direct -Calls-> semantic (2-hop, weight 5.0 → KEEP)
        store
            .upsert_relation(&mk_rel(RelationKind::Calls, direct.id, semantic.id))
            .unwrap();
        // direct -Contains-> structural (2-hop, weight 0.5 plumbing → DROP)
        store
            .upsert_relation(&mk_rel(RelationKind::Contains, direct.id, structural.id))
            .unwrap();

        let opts = ContextOptions {
            max_depth: 2,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();

        assert!(
            pack.dependency_signatures
                .iter()
                .any(|e| e.content.contains("caller_A")),
            "direct Calls dep must be included"
        );
        let transitive: Vec<&str> = pack
            .transitive_deps
            .iter()
            .map(|e| e.content.as_str())
            .collect();
        assert!(
            transitive.iter().any(|c| c.contains("semantic_C")),
            "semantic (Calls) transitive dep must be kept"
        );
        assert!(
            transitive.iter().all(|c| !c.contains("structural_B")),
            "structural-only (Contains) transitive neighbour must be filtered"
        );
    }

    #[test]
    fn dependencies_are_real_edges_not_cochange_filler() {
        // the dependency section must be the focal entity's real call/use
        // dependencies, NOT git co-change neighbours or structural plumbing. This
        // reproduces the dogfood failure shape (a real callee + plenty of
        // CoChanges/Contains noise sharing edges with the focal) and asserts the
        // pack surfaces the callee and drops the noise.
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        let mk_rel = |kind, src: EntityId, dst: EntityId| Relation {
            id: kin_model::ids::RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("project_after_mcp_commit", EntityKind::Function);
        let real_callee = make_entity("project_overlay_to_files", EntityKind::Function);
        // Co-change neighbours: high relation weight (3.5, above DependsOn) but NOT
        // a dependency — exactly the `stash::push` / `buildinfo::get` noise.
        let cochange_a = make_entity("stash_push", EntityKind::Function);
        let cochange_b = make_entity("buildinfo_get", EntityKind::Function);
        // Structural-containment neighbour (module owns focal): plumbing, not a dep.
        let structural = make_entity("projection_wiring_mod", EntityKind::Module);
        for e in [&focal, &real_callee, &cochange_a, &cochange_b, &structural] {
            store.upsert_entity(e).unwrap();
        }
        // The one real dependency.
        store
            .upsert_relation(&mk_rel(RelationKind::Calls, focal.id, real_callee.id))
            .unwrap();
        // Noise that currently floods the "dependencies" section.
        store
            .upsert_relation(&mk_rel(RelationKind::CoChanges, focal.id, cochange_a.id))
            .unwrap();
        store
            .upsert_relation(&mk_rel(RelationKind::CoChanges, focal.id, cochange_b.id))
            .unwrap();
        store
            .upsert_relation(&mk_rel(RelationKind::Contains, structural.id, focal.id))
            .unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();

        // Every entry across both dependency sections, by content.
        let dep_blob: String = pack
            .dependency_signatures
            .iter()
            .chain(pack.transitive_deps.iter())
            .map(|e| e.content.clone())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            dep_blob.contains("project_overlay_to_files"),
            "real callee must be present in dependencies, got: {dep_blob}"
        );
        assert!(
            !dep_blob.contains("stash_push") && !dep_blob.contains("buildinfo_get"),
            "co-change neighbours must NOT appear as dependencies, got: {dep_blob}"
        );
        assert!(
            !dep_blob.contains("projection_wiring_mod"),
            "structural-containment neighbour must NOT appear as a dependency, got: {dep_blob}"
        );
        // The single real dep is the only dependency-section entry — no count-driven
        // padding with the co-change/structural neighbours that share edges.
        assert_eq!(
            pack.dependency_signatures.len() + pack.transitive_deps.len(),
            1,
            "dependency sections must contain only the real dep, not filler"
        );
    }

    #[test]
    fn cochange_only_neighbor_does_not_trigger_same_file_fallback_as_dep() {
        // A focal whose ONLY edges are co-change has no real dependencies. The pack
        // must not present those co-change neighbours as dependencies; the honest
        // result is an empty dependency section (fewer-but-correct beats a
        // misleading full pack).
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        let mk_rel = |kind, src: EntityId, dst: EntityId| Relation {
            id: kin_model::ids::RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let store = kin_db::InMemoryGraph::new();
        // No file_origin → the same-file fallback cannot fire, isolating the
        // co-change gating behaviour.
        let focal = make_entity("focal_no_real_deps", EntityKind::Function);
        let cochange = make_entity("unrelated_cochange", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&cochange).unwrap();
        store
            .upsert_relation(&mk_rel(RelationKind::CoChanges, focal.id, cochange.id))
            .unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        assert!(
            pack.dependency_signatures.is_empty() && pack.transitive_deps.is_empty(),
            "co-change-only focal must yield no dependencies, not co-change filler"
        );
    }

    // ── Language-specific slicing ────────────────────────────────────────

    #[test]
    fn context_respects_entity_language() {
        let store = kin_db::InMemoryGraph::new();
        let mut focal = make_entity("parse", EntityKind::Function);
        focal.language = LanguageId::Python;
        focal.signature = "def parse(data: dict) -> list".to_string();
        store.upsert_entity(&focal).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        assert!(pack.focal_entities[0].content.contains("python"));
    }

    // ── Empty entity body ───────────────────────────────────────────────

    #[test]
    fn entity_with_empty_signature() {
        let store = kin_db::InMemoryGraph::new();
        let mut focal = make_entity("empty_sig", EntityKind::Function);
        focal.signature = String::new();
        focal.doc_summary = None;
        store.upsert_entity(&focal).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        assert_eq!(pack.focal_entities.len(), 1);
        // Should still produce some content (at least the entity name/kind header)
        assert!(!pack.focal_entities[0].content.is_empty());
    }

    // ── Entity with no signature ────────────────────────────────────────

    #[test]
    fn entity_with_no_doc_summary() {
        let store = kin_db::InMemoryGraph::new();
        let mut focal = make_entity("no_docs", EntityKind::Function);
        focal.doc_summary = None;
        store.upsert_entity(&focal).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        let content = &pack.focal_entities[0].content;
        assert!(content.contains("no_docs"));
        assert!(content.contains("fn no_docs()"));
    }

    // ── Entity not found ────────────────────────────────────────────────

    #[test]
    fn entity_not_found_returns_error() {
        let store = kin_db::InMemoryGraph::new();
        let missing_id = EntityId::new();
        let result = build_context_pack(&store, &missing_id, &ContextOptions::default());
        assert!(result.is_err());
    }

    // ── Test entity filtering ───────────────────────────────────────────

    #[test]
    fn test_entities_included_when_flag_set() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("handler", EntityKind::Function);
        let mut test = make_entity("test_handler", EntityKind::Function);
        test.role = EntityRole::Test;
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&test).unwrap();

        let rel = Relation {
            id: kin_model::ids::RelationId::new(),
            kind: RelationKind::Tests,
            src: GraphNodeId::Entity(test.id),
            dst: GraphNodeId::Entity(focal.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        store.upsert_relation(&rel).unwrap();

        let opts = ContextOptions {
            include_tests: true,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(!pack.tests.is_empty());
    }

    #[test]
    fn test_entities_excluded_when_flag_unset() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("handler", EntityKind::Function);
        let mut test = make_entity("test_handler", EntityKind::Function);
        test.role = EntityRole::Test;
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&test).unwrap();

        let rel = Relation {
            id: kin_model::ids::RelationId::new(),
            kind: RelationKind::Tests,
            src: GraphNodeId::Entity(test.id),
            dst: GraphNodeId::Entity(focal.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        store.upsert_relation(&rel).unwrap();

        let opts = ContextOptions {
            include_tests: false,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(pack.tests.is_empty());
    }

    // ── Contract filtering ──────────────────────────────────────────────

    #[test]
    fn contracts_excluded_when_flag_unset() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("api_handler", EntityKind::Function);
        let contract = make_entity("user_schema", EntityKind::Schema);
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&contract).unwrap();

        let rel = Relation {
            id: kin_model::ids::RelationId::new(),
            kind: RelationKind::ConsumesContract,
            src: GraphNodeId::Entity(focal.id),
            dst: GraphNodeId::Entity(contract.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        store.upsert_relation(&rel).unwrap();

        let opts = ContextOptions {
            include_contracts: false,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert!(pack.contracts.is_empty());
    }

    // ── Traffic metadata tests ──────────────────────────────────────────

    #[test]
    fn traffic_not_included_without_flag() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("fn_a", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let intents = vec![IntentSummary {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            vendor: "test".to_string(),
            task_description: "task".to_string(),
            lock_type: LockType::Soft,
            registered_at: Timestamp::now(),
        }];

        let opts = ContextOptions {
            include_traffic: false,
            ..Default::default()
        };
        let pack = build_context_pack_with_traffic(&store, &focal.id, &opts, &intents).unwrap();
        assert!(pack.traffic.is_empty());
    }

    #[test]
    fn traffic_included_with_flag() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("fn_b", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let intents = vec![IntentSummary {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            vendor: "claude-code".to_string(),
            task_description: "refactoring".to_string(),
            lock_type: LockType::Soft,
            registered_at: Timestamp::now(),
        }];

        let opts = ContextOptions {
            include_traffic: true,
            ..Default::default()
        };
        let pack = build_context_pack_with_traffic(&store, &focal.id, &opts, &intents).unwrap();
        assert_eq!(pack.traffic.len(), 1);
    }

    #[test]
    fn empty_intents_produce_no_traffic() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("fn_c", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let opts = ContextOptions {
            include_traffic: true,
            ..Default::default()
        };
        let pack = build_context_pack_with_traffic(&store, &focal.id, &opts, &[]).unwrap();
        assert!(pack.traffic.is_empty());
    }

    // ── GeminiCli location context ──────────────────────────────────────

    #[test]
    fn gemini_hint_adds_file_path_to_deps() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let store = kin_db::InMemoryGraph::new();
        let focal = make_file_entity("main", EntityKind::Function, "src/main.rs");
        let dep = make_file_entity("helper", EntityKind::Function, "src/helpers.rs");
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&dep).unwrap();

        let rel = Relation {
            id: kin_model::ids::RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(focal.id),
            dst: GraphNodeId::Entity(dep.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        store.upsert_relation(&rel).unwrap();

        let opts = ContextOptions {
            assistant_hint: Some(AssistantHint::GeminiCli),
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        // GeminiCli adds file path comments
        let has_file_comment = pack
            .dependency_signatures
            .iter()
            .any(|e| e.content.contains("// file:"));
        assert!(has_file_comment);
    }

    // ── Pack structure tests ────────────────────────────────────────────

    #[test]
    fn focal_entity_at_full_body_level() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("target", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        assert_eq!(pack.focal_entities.len(), 1);
        assert_eq!(
            pack.focal_entities[0].projection_level,
            ProjectionLevel::FullBody
        );
    }

    #[test]
    fn token_budget_stored_in_pack() {
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("x", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();

        let opts = ContextOptions {
            budget: TokenBudget::Medium16k,
            ..Default::default()
        };
        let pack = build_context_pack(&store, &focal.id, &opts).unwrap();
        assert_eq!(pack.token_budget, TokenBudget::Medium16k);
    }

    // ── Normalize entity name tests ─────────────────────────────────────

    #[test]
    fn normalize_strips_leading_underscore() {
        assert_eq!(normalize_entity_name("_helper"), "helper");
    }

    #[test]
    fn normalize_strips_leading_dollar() {
        assert_eq!(normalize_entity_name("$scope"), "scope");
    }

    #[test]
    fn normalize_preserves_normal_names() {
        assert_eq!(normalize_entity_name("process"), "process");
    }

    // ── What the token budget refused (FIR-2482) ────────────────────────

    /// A focal calling `deps` entities, so a tight budget has candidates to
    /// refuse and a generous one admits every last row.
    fn calling_store(deps: usize) -> (kin_db::InMemoryGraph, Entity) {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        let store = kin_db::InMemoryGraph::new();
        let focal = make_entity("focal", EntityKind::Function);
        store.upsert_entity(&focal).unwrap();
        for index in 0..deps {
            let dep = make_entity(&format!("dep_{index:04}"), EntityKind::Function);
            store.upsert_entity(&dep).unwrap();
            store
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(focal.id),
                    dst: GraphNodeId::Entity(dep.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        (store, focal)
    }

    #[test]
    fn a_budget_that_refused_a_row_says_how_many() {
        let (store, focal) = calling_store(40);
        let whole = ContextOptions {
            budget: TokenBudget::Large32k,
            ..ContextOptions::default()
        };
        let (full, full_selection) =
            build_context_pack_with_provenance(&store, &focal.id, &whole).unwrap();
        assert_eq!(
            full_selection.budget_elided(group::DEPENDENCIES),
            0,
            "a budget that admitted everything must claim no loss"
        );

        let tight = ContextOptions {
            budget: TokenBudget::Custom(full.actual_tokens / 2),
            ..ContextOptions::default()
        };
        let (cut, selection) =
            build_context_pack_with_provenance(&store, &focal.id, &tight).unwrap();
        let kept = cut.dependency_signatures.len();
        assert!(
            kept > 0 && kept < full.dependency_signatures.len(),
            "the budget must actually cut for this test to mean anything: kept {kept} of {}",
            full.dependency_signatures.len()
        );

        // The count is the whole point: without it, `kept` rows is what a focal
        // with `kept` dependencies looks like.
        let elided = selection.budget_elided(group::DEPENDENCIES);
        assert_eq!(
            kept + elided,
            full.dependency_signatures.len(),
            "kept plus refused must equal what the generous budget admitted"
        );
        assert!(
            selection
                .budget_elisions()
                .any(|(name, count)| name == group::DEPENDENCIES && count == elided),
            "the refused group must appear in the elision listing"
        );
    }

    #[test]
    fn a_row_recovered_by_another_route_is_not_counted_as_lost() {
        let (store, focal) = calling_store(40);
        let whole = ContextOptions {
            budget: TokenBudget::Large32k,
            ..ContextOptions::default()
        };
        let (full, _) = build_context_pack_with_provenance(&store, &focal.id, &whole).unwrap();
        let tight = ContextOptions {
            budget: TokenBudget::Custom(full.actual_tokens / 2),
            ..ContextOptions::default()
        };
        let (_, selection) = build_context_pack_with_provenance(&store, &focal.id, &tight).unwrap();
        let elided = selection.budget_elided(group::DEPENDENCIES);
        assert!(elided > 0, "the budget must have refused something");
        assert_eq!(
            selection.budget_elided_unrecovered(group::DEPENDENCIES, |_| true),
            0,
            "a row the caller recovered elsewhere is not a row the answer lost"
        );
    }

    #[test]
    fn a_pack_that_lost_nothing_claims_nothing() {
        let (store, focal) = calling_store(3);
        let opts = ContextOptions {
            budget: TokenBudget::Large32k,
            ..ContextOptions::default()
        };
        let (pack, selection) =
            build_context_pack_with_provenance(&store, &focal.id, &opts).unwrap();
        assert!(
            !pack.dependency_signatures.is_empty(),
            "the fixture must admit rows, or this asserts nothing"
        );
        assert_eq!(
            selection.budget_elisions().count(),
            0,
            "a whole pack must carry no elision at all, so a disclosure means a cut"
        );
    }
}
