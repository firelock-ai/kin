// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared entity ranking primitives used by CLI, MCP, and other surfaces.
//!
//! These functions provide a single source of truth for how entities are
//! ranked when disambiguating search results, selecting reference targets,
//! and ordering relation kinds.

use std::path::Path;

use kin_model::entity::{Entity, EntityKind, EntityRole, Visibility};
use kin_model::graph::GraphStore;
use kin_model::relation::{Relation, RelationKind};
use kin_model::{EntityId, GraphNodeId};

/// Rank declaration kinds for entity selection.
///
/// Higher values indicate more interesting entity kinds when multiple
/// entities match a query.
pub fn declaration_kind_rank(kind: &EntityKind) -> usize {
    match kind {
        EntityKind::Function
        | EntityKind::Method
        | EntityKind::Interface
        | EntityKind::TypeAlias => 3,
        EntityKind::Class | EntityKind::TraitDef | EntityKind::EnumDef => 2,
        EntityKind::Constant | EntityKind::StaticVar => 1,
        _ => 0,
    }
}

/// Rank relation kinds for display ordering.
///
/// Lower values appear first: imports before calls before references.
pub fn relation_kind_rank(kind: &RelationKind) -> usize {
    match kind {
        RelationKind::Imports => 0,
        RelationKind::Calls => 1,
        RelationKind::References => 2,
        _ => 3,
    }
}

/// The composite ranking key used to select the best entity match.
///
/// Compared via tuple ordering (higher = better):
/// 1. How the query meets the name ([`name_match_tier`]): the whole name, then
///    the member segment of an owner's member, then anything else
/// 2. Exported (public/internal)
/// 3. Declaration kind rank
/// 4. Direct call/import count (incoming)
/// 5. Total incoming reference count
/// 6. Has file origin
/// 7. Shorter name preferred (Reverse)
pub type EntityRankingKey = (
    u8,
    bool,
    usize,
    usize,
    usize,
    bool,
    std::cmp::Reverse<usize>,
);

/// Compute the ranking key for an entity given a query and its relations.
pub fn entity_ranking_key(
    entity: &Entity,
    query: &str,
    incoming_refs: usize,
    direct_signal: usize,
) -> EntityRankingKey {
    let exported = matches!(entity.visibility, Visibility::Public | Visibility::Internal);
    (
        name_match_tier(entity, query),
        exported,
        declaration_kind_rank(&entity.kind),
        direct_signal,
        incoming_refs,
        entity.file_origin.is_some(),
        std::cmp::Reverse(entity.name.len()),
    )
}

/// How closely `query` meets an entity's name, strongest first: `2` when it is
/// the whole name, `1` when it is the member name of an owner's member
/// ([`is_member_name_match`]), and `0` when it only occurs inside the name.
pub fn name_match_tier(entity: &Entity, query: &str) -> u8 {
    if entity.name == query {
        2
    } else if is_member_name_match(entity, query) {
        1
    } else {
        0
    }
}

/// The kinds a bare member name can reach: a method, a field, or an enum
/// variant.
///
/// This is the whole contract, and it is kind-qualified on purpose. Every
/// language adapter names these three by the type that declares them, the
/// method by its class, struct, trait, interface or receiver, the field by its
/// struct, the variant by its enum, so the segment after the owner is the
/// member's own declared name. No other kind qualifies, because for every other
/// kind a dotted name's prefix can be a path, a package or a namespace rather
/// than an owner, and its last segment is incidental: a file module named
/// `app.py` would answer to `py`, and a shallow-parsed constant named
/// `constant.Raspbian` to `Raspbian`. Those stay reachable by their whole name
/// or their id.
pub fn is_member_kind(kind: &EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Method | EntityKind::Field | EntityKind::EnumVariant
    )
}

/// Whether `query` is the bare member name of `entity`: an eligible member
/// kind ([`is_member_kind`]), an owner prefix, and a member segment exactly
/// `query`. `get` is the member name of the method `Scaffold.get` and of the
/// method `Router<S>::get`; it is not the member name of `get` itself, of
/// `get_db`, or of `ConfigAttribute.__get__`.
pub fn is_member_name_match(entity: &Entity, query: &str) -> bool {
    is_member_kind(&entity.kind)
        && qualified_owner_prefix(&entity.name).is_some()
        && bare_member_name(&entity.name) == query
}

/// The name a bare lookup matches `entity` by, and the one a listing publishes
/// as `member_name`: the member segment of an owner's member
/// ([`is_member_kind`] with an owner prefix), and the whole name of anything
/// else. A file module named `app.py` publishes `app.py`, not `py`.
pub fn lookup_member_name(entity: &Entity) -> &str {
    lookup_member_name_of(&entity.name, is_member_kind(&entity.kind))
}

/// [`lookup_member_name`] from a name and whether its kind is a member kind,
/// for a record that carries the two apart.
pub fn lookup_member_name_of(name: &str, member_kind: bool) -> &str {
    if member_kind && qualified_owner_prefix(name).is_some() {
        bare_member_name(name)
    } else {
        name
    }
}

/// [`is_member_kind`] for a kind carried as its `Debug` spelling, the way a
/// daemon search record carries it.
pub fn is_member_kind_named(kind: &str) -> bool {
    [
        EntityKind::Method,
        EntityKind::Field,
        EntityKind::EnumVariant,
    ]
    .iter()
    .any(|member| format!("{member:?}") == kind)
}

/// The owner of an owner's member, `Scaffold` for the method `Scaffold.get`,
/// and `None` for anything that is not one ([`lookup_member_name`]).
pub fn member_owner(entity: &Entity) -> Option<&str> {
    if is_member_kind(&entity.kind) {
        qualified_owner_prefix(&entity.name)
    } else {
        None
    }
}

/// Whether an entity is one a name may resolve to: anything the repository
/// holds a file for, and anything that is not an external reference target.
/// The same test [`select_best_entity`] applies.
fn addressable_by_name(entity: &Entity) -> bool {
    entity.file_origin.is_some() || entity.role != EntityRole::External
}

/// What a name reaches before anything ranks it, in the tiers every surface
/// that accepts a name applies.
#[derive(Debug, Clone, PartialEq)]
pub enum NameReach {
    /// Entities whose whole name is the query. This tier is never pooled with
    /// members: `Entity` means the struct named `Entity`, not the enum variant
    /// `GraphNodeId::Entity` beside it.
    Exact(Vec<Entity>),
    /// No entity's whole name is the query; these owners' members carry it as
    /// their member name.
    Members(Vec<Entity>),
    /// Neither tier reaches anything.
    Neither,
}

/// The one order every surface lists a name's candidates in: file, then name,
/// then id. A choice is never made from it, so it carries no ranking signal,
/// only a stable listing a caller can compare across surfaces.
pub fn sort_name_candidates(candidates: &mut Vec<Entity>) {
    candidates.sort_by(|left, right| {
        left.file_origin
            .as_ref()
            .map(|path| path.0.as_str())
            .cmp(&right.file_origin.as_ref().map(|path| path.0.as_str()))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates.dedup_by(|left, right| left.id == right.id);
}

/// [`NameReach`] over entities already in hand, such as a state replayed at a
/// historical ref. `entities` must include every entity the name could reach;
/// a whole state satisfies that.
pub fn reach_among(entities: impl IntoIterator<Item = Entity>, query: &str) -> NameReach {
    let mut exact = Vec::new();
    let mut members = Vec::new();
    for entity in entities {
        if !addressable_by_name(&entity) {
            continue;
        }
        if entity.name == query {
            exact.push(entity);
        } else if is_member_name_match(&entity, query) {
            members.push(entity);
        }
    }
    if !exact.is_empty() {
        sort_name_candidates(&mut exact);
        return NameReach::Exact(exact);
    }
    if !members.is_empty() {
        sort_name_candidates(&mut members);
        return NameReach::Members(members);
    }
    NameReach::Neither
}

/// [`NameReach`] over the store's own name index.
///
/// The whole name is asked for as itself, which the index answers exhaustively
/// because it is keyed by name. A member is asked for by the suffix its owner
/// separator leaves, `*.get` and `*::get`, which the index also answers whole.
/// The bare pattern alone would not be enough for members: the index answers it
/// with whole-name and token matches, falls back to substrings only when it has
/// neither, and drops a token match set over its cap, which on pallets/flask
/// hid `Request.blueprint` behind the two `Blueprint` classes.
///
/// A query carrying `*` is a glob, not a name, and reaches nothing here.
pub fn reach_by_name<G: GraphStore>(
    store: &G,
    query: &str,
) -> std::result::Result<NameReach, <G as GraphStore>::Error> {
    if query.is_empty() || query.contains('*') {
        return Ok(NameReach::Neither);
    }
    let mut found = store.query_entities(&kin_model::graph::EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    })?;
    if !found
        .iter()
        .any(|entity| entity.name == query && addressable_by_name(entity))
        && !query.contains('.')
        && !query.contains("::")
    {
        for pattern in [format!("*.{query}"), format!("*::{query}")] {
            found.extend(store.query_entities(&kin_model::graph::EntityFilter {
                name_pattern: Some(pattern),
                ..Default::default()
            })?);
        }
    }
    Ok(reach_among(found, query))
}

/// What a name resolves to for a surface that answers about one entity and
/// ranks when a name is ambiguous in the ways it already discloses.
#[derive(Debug, Clone)]
pub enum NameResolution {
    /// One entity answers: the best-ranked whole-name match (the exact tier
    /// always outranks everything else), the one owner's member the name
    /// reaches, or, for a name that is neither, the best-ranked name that
    /// contains it.
    One(Entity),
    /// No entity's whole name is the query, and several owners' members carry
    /// it as their member name, so the name does not say which one is meant and
    /// none was chosen. Listed in [`sort_name_candidates`] order.
    SharedMemberName(Vec<Entity>),
    /// Nothing the repository holds matches the name.
    Missing,
}

/// Resolve `query` for a surface that answers about exactly one entity.
///
/// The exact tier comes first and is never pooled with members. Members are a
/// fallback that runs only when no entity's whole name is the query: one
/// member answers, several are returned whole as
/// [`NameResolution::SharedMemberName`] for the surface to list, never ranked
/// down to one. Every other name goes to [`select_best_entity`], whose own tier
/// key keeps a whole-name match first; a surface that returns an editable body
/// uses [`resolve_name_strictly`] instead, which never ranks.
pub fn resolve_name<G: GraphStore>(
    store: &G,
    query: &str,
) -> std::result::Result<NameResolution, <G as GraphStore>::Error> {
    match reach_by_name(store, query)? {
        NameReach::Members(mut members) if members.len() == 1 => {
            Ok(NameResolution::One(members.remove(0)))
        }
        NameReach::Members(members) => Ok(NameResolution::SharedMemberName(members)),
        NameReach::Exact(_) | NameReach::Neither => Ok(match select_best_entity(store, query)? {
            Some(entity) => NameResolution::One(entity),
            None => NameResolution::Missing,
        }),
    }
}

/// Why a name answered with candidates instead of an entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateReason {
    /// Several entities have the name as their whole name.
    SameName,
    /// No entity has it as its whole name, and several owners' members have it
    /// as their member name.
    SharedMemberName,
    /// A qualified name that names nothing, whose last segment is the whole name
    /// of several entities.
    SameLeafName,
    /// Neither a whole name nor a member name; these entities' names contain it.
    PartialName,
}

impl CandidateReason {
    /// The value a structured answer carries under `resolution`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameName => "same_name",
            Self::SharedMemberName => "shared_member_name",
            Self::SameLeafName => "same_leaf_name",
            Self::PartialName => "partial_name",
        }
    }
}

/// What a name resolves to for a surface that returns an editable body or an
/// edit base, where a guess is a wrong edit rather than a wrong answer.
#[derive(Debug, Clone)]
pub enum StrictNameResolution {
    /// The one entity whose whole name is the query, or, when no entity has
    /// it as its whole name, the one owner's member that carries it.
    One(Entity),
    /// Anything else the name reaches, listed and never chosen from.
    Candidates(CandidateReason, Vec<Entity>),
    /// Nothing the repository holds matches the name.
    Missing,
}

/// Resolve `query` without ranking: one exact whole-name match, or one member
/// when there is no exact match, and otherwise every candidate.
///
/// A partial name never selects a body here. `get_d` reached the tutorial's
/// `get_db` through the ranked resolver and handed back its body and its edit
/// base with nothing saying a choice was made; through this one it lists
/// `get_db` as a candidate and answers about none.
pub fn resolve_name_strictly<G: GraphStore>(
    store: &G,
    query: &str,
) -> std::result::Result<StrictNameResolution, <G as GraphStore>::Error> {
    Ok(match reach_by_name(store, query)? {
        NameReach::Exact(mut exact) if exact.len() == 1 => {
            StrictNameResolution::One(exact.remove(0))
        }
        NameReach::Exact(exact) => {
            StrictNameResolution::Candidates(CandidateReason::SameName, exact)
        }
        NameReach::Members(mut members) if members.len() == 1 => {
            StrictNameResolution::One(members.remove(0))
        }
        NameReach::Members(members) => {
            StrictNameResolution::Candidates(CandidateReason::SharedMemberName, members)
        }
        NameReach::Neither => {
            if query.trim().is_empty() {
                return Ok(StrictNameResolution::Missing);
            }
            let mut partial: Vec<Entity> = store
                .query_entities(&kin_model::graph::EntityFilter {
                    name_pattern: Some(query.to_string()),
                    ..Default::default()
                })?
                .into_iter()
                .filter(addressable_by_name)
                .collect();
            if partial.is_empty() {
                StrictNameResolution::Missing
            } else {
                sort_name_candidates(&mut partial);
                StrictNameResolution::Candidates(CandidateReason::PartialName, partial)
            }
        }
    })
}

/// Select the best entity match for a query from a graph store.
///
/// Queries the store by name pattern, then ranks all matches using
/// [`entity_ranking_key`] to pick the single best result.
///
/// A candidate the repository holds no file for is never selected. Every caller
/// of this function wants a declaration it can open, and an external reference
/// target carries the imported symbol's name while standing for a definition
/// another repository owns, so selecting one turns a clean not-found into a
/// located answer that has no location. A repository that vendors its own copy
/// of a dependency keeps its [`EntityRole::External`] entities eligible, because
/// those carry real files.
pub fn select_best_entity<G: GraphStore>(
    store: &G,
    query: &str,
) -> std::result::Result<Option<Entity>, <G as GraphStore>::Error> {
    use kin_model::graph::EntityFilter;

    let matches = store.query_entities(&EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    })?;
    let matches: Vec<Entity> = matches
        .into_iter()
        .filter(|entity| entity.file_origin.is_some() || entity.role != EntityRole::External)
        .collect();
    if matches.is_empty() {
        return Ok(None);
    }

    let mut best: Option<(Entity, EntityRankingKey)> = None;

    for entity in matches {
        let relations = store.get_all_relations_for_entity(&entity.id)?;
        let incoming_refs = relations
            .iter()
            .filter(|rel| {
                rel.dst == kin_model::GraphNodeId::Entity(entity.id)
                    && matches!(
                        rel.kind,
                        RelationKind::Calls | RelationKind::Imports | RelationKind::References
                    )
            })
            .count();
        let direct_signal = relations
            .iter()
            .filter(|rel| {
                rel.dst == kin_model::GraphNodeId::Entity(entity.id)
                    && matches!(rel.kind, RelationKind::Calls | RelationKind::Imports)
            })
            .count();

        let score = entity_ranking_key(&entity, query, incoming_refs, direct_signal);
        if best
            .as_ref()
            .map(|(_, best_score)| score > *best_score)
            .unwrap_or(true)
        {
            best = Some((entity, score));
        }
    }

    Ok(best.map(|(entity, _)| entity))
}

/// The entity that structurally CONTAINS this one (class to method, enum to
/// variant), read from an already-fetched relation slice. `None` for an entity
/// nothing contains: free functions, and forwarding impls on reference or
/// generic owners (`&G::method`), whose qualified prefix is not a graph entity.
pub fn containing_owner_id(entity_id: &EntityId, relations: &[Relation]) -> Option<EntityId> {
    relations.iter().find_map(|rel| {
        if rel.kind == RelationKind::Contains && rel.dst == GraphNodeId::Entity(*entity_id) {
            match rel.src {
                GraphNodeId::Entity(owner) => Some(owner),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// The owner segment of a qualified entity name: `CodeEmbedder` for
/// `CodeEmbedder::embed_batch`, `constant` for `constant.Raspbian`, `None` for
/// a bare name. Both separators because both are in the graph (Rust/C++ store
/// `Type::method`, shallow-backed languages normalize to a dot); the LAST
/// separator wins so a mixed name splits where its own name starts.
pub fn qualified_owner_prefix(name: &str) -> Option<&str> {
    let dotted = name.rfind('.');
    let scoped = name.rfind("::");
    let split = match (dotted, scoped) {
        (Some(dot), Some(scope)) => Some(if scope > dot { scope } else { dot }),
        (Some(dot), None) => Some(dot),
        (None, Some(scope)) => Some(scope),
        (None, None) => None,
    };
    split
        .map(|idx| &name[..idx])
        .filter(|prefix| !prefix.is_empty())
}

/// The trailing, unqualified segment of a name: `embed_batch` for
/// `CodeEmbedder::embed_batch`, `Raspbian` for `constant.Raspbian`, the whole
/// name for one with no owner segment. The complement of
/// [`qualified_owner_prefix`]: it steps past whatever prefix that function
/// found, through whichever separator immediately follows it, so the two can
/// never disagree about where a name splits.
///
/// This is what several owner-qualified declarations "share" when a caller
/// addresses them by a bare name: `Flask.dispatch_request`,
/// `View.dispatch_request` and `MethodView.dispatch_request` disagree on
/// [`qualified_owner_prefix`] and agree here, on `dispatch_request`, which is
/// the fact `find_references` sections a bare-name answer on rather than a
/// substring or token overlap a name-pattern search would also match.
pub fn bare_member_name(name: &str) -> &str {
    match qualified_owner_prefix(name) {
        Some(prefix) => {
            let rest = &name[prefix.len()..];
            rest.strip_prefix("::")
                .or_else(|| rest.strip_prefix('.'))
                .unwrap_or(rest)
        }
        None => name,
    }
}

/// Relation count of one entity excluding temporal `CoChanges` edges, so the
/// number is a fact about code structure rather than commit history.
fn structural_relation_count<G: GraphStore>(
    store: &G,
    id: &EntityId,
) -> std::result::Result<usize, <G as GraphStore>::Error> {
    Ok(store
        .get_all_relations_for_entity(id)?
        .iter()
        .filter(|rel| rel.kind != RelationKind::CoChanges)
        .count())
}

/// Structural graph mass of the type an entity hangs off: the relation count
/// (excluding `CoChanges`) of its `Contains` parent when that edge exists, and
/// otherwise of the entity exactly named by its qualified owner prefix. `0`
/// only when neither resolves, which is what a blanket forwarding impl on a
/// reference or generic owner (`&G::method`) honestly reads as.
///
/// This is the canonical-definition signal for breaking pure exact-name ties.
/// When one symbol name is defined by several impls, the definition on the
/// primary type is the one an agent means, and the primary type is the one
/// that accretes graph mass: measured on the 26,633-entity gauntlet store,
/// `delete_work_item` is carried by `InMemoryGraph::` (owner mass 285),
/// `MockGraph::` (134), `EmptyStore::` (121), and a blanket `&G::` forwarding
/// impl (no owner, 0). Incoming references on the tied METHODS themselves
/// cannot break this tie: a shared test harness calls every impl, and on that
/// same store the mocks collect MORE method-level calls (3/3) than the
/// canonical definition (2), so the owner is the signal, not the method.
///
/// The name fallback is not a nicety. A method's `Contains` edge is
/// enrichment that a freshly built store can lack while the owner type itself
/// parsed fine: the same kin-db file measured owner mass 14 for
/// `CodeEmbedder::embed_batch` through its edge on the flagship store and 0 on
/// a minutes-old store missing the edge, which handed the tie to
/// `OpenAiCompatEmbedder::` (mass 5). A missing edge is a graph gap, not
/// evidence the definition is secondary, so the owner NAME answers when the
/// edge cannot.
pub fn owner_graph_mass<G: GraphStore>(
    store: &G,
    entity_id: &EntityId,
    entity_name: &str,
) -> std::result::Result<usize, <G as GraphStore>::Error> {
    let relations = store.get_all_relations_for_entity(entity_id)?;
    if let Some(owner) = containing_owner_id(entity_id, &relations) {
        return structural_relation_count(store, &owner);
    }
    let Some(prefix) = qualified_owner_prefix(entity_name) else {
        return Ok(0);
    };
    let candidates = store.query_entities(&kin_model::graph::EntityFilter {
        name_pattern: Some(prefix.to_string()),
        ..Default::default()
    })?;
    let mut best = 0;
    for candidate in candidates {
        if candidate.name == prefix && candidate.id != *entity_id {
            best = best.max(structural_relation_count(store, &candidate.id)?);
        }
    }
    Ok(best)
}

/// Rank relation kinds for trace operations.
///
/// Higher values indicate more significant relations:
/// Calls > Imports > References > UsesType. An annotation edge sits last on
/// purpose: naming a type in a signature moves no value, so when a scarce
/// fan-out slot is contested a bare value reference wins it.
pub fn trace_relation_rank(kind: RelationKind) -> usize {
    match kind {
        RelationKind::Calls => 3,
        RelationKind::Imports => 2,
        RelationKind::References => 1,
        RelationKind::UsesType => 0,
        _ => 0,
    }
}

/// Whether an edge of this kind states a TYPE dependency rather than a flow of
/// values.
///
/// [`RelationKind::UsesType`] is the model's own name for "type dependency in
/// signature/body", so it is what this reads. The distinction matters to a walk
/// rather than to a reference count: `find_references` on a class should list
/// the signature that names it, while a data-flow chain that hops through the
/// annotation has left the flow it was asked about.
pub fn trace_relation_is_annotation(kind: RelationKind) -> bool {
    matches!(kind, RelationKind::UsesType)
}

/// Why a trace walk reported a node as a leaf instead of expanding it.
///
/// Three of these are boundaries of what a data-flow answer means and say the
/// chain ends there. Two are shortfalls and say the walk stopped before the
/// chain did. [`TraceTerminal::truncates`] is the one place that distinction is
/// decided, because a response reporting the same flag for both is the defect
/// this enum grew to fix: a walk that stopped for lack of an edge read as a
/// walk that ran out of code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceTerminal {
    /// The repository defines nothing for this symbol, so there is no next hop
    /// to take. Measured on a converted `psf/requests`: `typing.Any` arrived as
    /// a file-less node with 44 referrers past the step budget, and walking it
    /// put `Response.json`, `create_cookie` and `super_len` in the data-flow
    /// chain of a TLS configuration function.
    ExternalReference,
    /// The edge into this node states a type, and the caller did not ask for
    /// type edges. Two entities that both annotate a parameter with the same
    /// class share nothing, so traversing the annotation makes every widely
    /// used type name a hub joining everything to everything.
    TypeAnnotation,
    /// The walk read this node's relations and the graph held no admissible
    /// edge of the walked classes, on a language whose deciding classes are
    /// observed present. This is the only terminal that asserts the chain ends
    /// here, and it earns that by resting on a coverage observation rather than
    /// on the empty read alone.
    Leaf,
    /// The walk never read this node's relations, because the requested depth
    /// or a work budget stopped it first. Whatever edges the node holds were
    /// not examined, so the branch below it is unknown rather than absent.
    BoundReached,
    /// The walk read this node's relations and found no admissible edge, on a
    /// language whose deciding coverage classes are absent or unmeasured. An
    /// empty read on such a graph cannot be told apart from a graph that could
    /// not have held the next hop in the first place.
    CoverageGap,
}

impl TraceTerminal {
    pub fn as_str(self) -> &'static str {
        match self {
            TraceTerminal::ExternalReference => "external_reference",
            TraceTerminal::TypeAnnotation => "type_annotation",
            TraceTerminal::Leaf => "leaf",
            TraceTerminal::BoundReached => "bound_reached",
            TraceTerminal::CoverageGap => "coverage_gap",
        }
    }

    /// Whether a response carrying this terminal received less chain than
    /// exists, or may have.
    ///
    /// The two boundary terminals are complete answers: a symbol this
    /// repository does not define has no next hop, and an annotation edge the
    /// caller declined to walk is a hop they asked not to take. `Leaf` is
    /// complete for the same reason and says so on evidence. The other two are
    /// not: one stopped at a bound the caller can raise, and one stopped on a
    /// graph that could not have answered. Reporting either as complete is what
    /// let two short chains read as whole ones.
    pub fn truncates(self) -> bool {
        match self {
            TraceTerminal::ExternalReference
            | TraceTerminal::TypeAnnotation
            | TraceTerminal::Leaf => false,
            TraceTerminal::BoundReached | TraceTerminal::CoverageGap => true,
        }
    }
}

/// The terminal a published wire name stands for, or `None` for a name this
/// build does not know.
///
/// Two payload builders read terminals back off a serialized chain, and a name
/// neither of them recognizes must not be guessed at: a response written by a
/// build this one has never seen is not evidence of a shortfall.
pub fn trace_terminal_named(name: &str) -> Option<TraceTerminal> {
    [
        TraceTerminal::ExternalReference,
        TraceTerminal::TypeAnnotation,
        TraceTerminal::Leaf,
        TraceTerminal::BoundReached,
        TraceTerminal::CoverageGap,
    ]
    .into_iter()
    .find(|terminal| terminal.as_str() == name)
}

/// What a walk's attempt to expand one node actually produced.
///
/// Recorded by the walk at the node, because none of it is recoverable from the
/// finished chain: a node with no children in the payload looks identical
/// whether its relations were read and held nothing, or were never read at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceExpansion {
    /// The node's relations were never read: the requested depth was already
    /// reached, or a work budget ended the walk before this node's turn.
    BoundStopped,
    /// The node's relations were read and held no admissible edge of the walked
    /// classes in the walked direction.
    NoEdges,
    /// The node's relations were read and held at least one admissible edge,
    /// whether or not the per-step cap kept it.
    HadEdges,
}

/// Classify a node the walk did not continue through.
///
/// `coverage_certain` is the answer's own edge-coverage observation for THIS
/// node's language, reduced to the one question a terminal rests on: were the
/// classes the verdict decides on observed present. It is passed in rather than
/// derived here so one observation governs both the per-hop terminal and the
/// response-level gate, which is the pairing that stopped agreeing when the
/// walk published no observation at all.
///
/// `None` means the node was expanded and has neighbors, so it is an ordinary
/// step rather than an end of any kind.
pub fn trace_walk_terminal(
    expansion: TraceExpansion,
    coverage_certain: bool,
) -> Option<TraceTerminal> {
    match expansion {
        TraceExpansion::BoundStopped => Some(TraceTerminal::BoundReached),
        TraceExpansion::NoEdges if coverage_certain => Some(TraceTerminal::Leaf),
        TraceExpansion::NoEdges => Some(TraceTerminal::CoverageGap),
        TraceExpansion::HadEdges => None,
    }
}

/// Whether a trace step is a leaf, and which boundary made it one.
///
/// `None` means the node may be expanded. External wins over annotation when
/// both apply, and it is unconditional: `include_type_edges` opens same-repo
/// type edges, and no parameter makes a symbol this repository does not define
/// walkable, because there is nothing on the other side of it to walk.
pub fn trace_step_terminal(
    entity: &Entity,
    relation_kind: RelationKind,
    include_type_edges: bool,
) -> Option<TraceTerminal> {
    if trace_entity_is_external(entity) {
        return Some(TraceTerminal::ExternalReference);
    }
    if trace_relation_is_annotation(relation_kind) && !include_type_edges {
        return Some(TraceTerminal::TypeAnnotation);
    }
    None
}

/// Extract the directory component of an entity's file origin.
pub fn entity_directory(entity: &Entity) -> Option<String> {
    entity
        .file_origin
        .as_ref()
        .and_then(|path| Path::new(path.0.as_str()).parent())
        .map(|dir| dir.to_string_lossy().into_owned())
}

/// Compute a composite score for trace callee selection.
///
/// Returns a tuple ordered by: relation rank, same directory,
/// declaration kind, has file origin, shorter name.
pub fn trace_callee_score(
    entity: &Entity,
    relation_kind: RelationKind,
    focal_dir: Option<&str>,
) -> (usize, bool, usize, bool, usize) {
    let same_dir = focal_dir
        .zip(entity_directory(entity).as_deref())
        .map(|(root, dir)| root == dir)
        .unwrap_or(false);
    (
        trace_relation_rank(relation_kind),
        same_dir,
        declaration_kind_rank(&entity.kind),
        entity.file_origin.is_some(),
        usize::MAX.saturating_sub(entity.name.len()),
    )
}

/// True when the graph holds this entity as a reference target it owns no
/// location for: an imported symbol another repository defines, a builtin, or an
/// import alias the extractor split off the definition.
///
/// Keyed on the file origin rather than on [`EntityRole::External`], because the
/// two disagree in both directions and only the file decides what a caller can
/// do with the record. A vendored dependency's entities are `External` by role
/// and carry real files, so they are addressable; the file-less placeholders
/// measured in a converted Python repository were `Module`-kinded with the
/// default `Source` role. A record with no file has no span, so no body, no
/// line, and nothing to open.
pub fn trace_entity_is_external(entity: &Entity) -> bool {
    entity.file_origin.is_none()
}

/// How much a role earns a scarce fan-out slot when a step has more candidates
/// than it may keep.
///
/// Test code is not noise, but a per-step cap is a choice between candidates,
/// and a caller asking what a function calls means its production callees before
/// the harness that exercises them. Measured on a converted `psf/requests`: the
/// six-wide caller cap on `HTTPAdapter.send` kept five `TestRequests` methods
/// and a test server while dropping `Session.send` and
/// `HTTPDigestAuth.handle_401`, the only two real callers, so the same graph
/// answered "who calls this" with five tests or two source functions depending
/// on which tool trimmed what.
fn trace_role_rank(role: &EntityRole) -> usize {
    match role {
        EntityRole::Source => 4,
        EntityRole::Vendored | EntityRole::External => 3,
        EntityRole::Generated => 2,
        EntityRole::Test => 1,
        EntityRole::Docs => 0,
    }
}

/// The comparable relevance key for one fan-out candidate. Higher is kept.
pub type TraceFanoutScore = (
    bool,
    usize,
    usize,
    bool,
    bool,
    bool,
    bool,
    usize,
    bool,
    u32,
    std::cmp::Reverse<usize>,
);

/// What the graph proved about the edge that reached one fan-out candidate.
///
/// Carried together because all three are properties of the EDGE rather than of
/// the candidate, and a scorer taking them as three loose booleans is a scorer
/// whose call sites can silently swap two of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TraceEdgeEvidence {
    /// The destination is proven rather than matched on a bare name. A
    /// `name_only` edge is exactly the class that made `Session.request` appear
    /// to call `RequestsCookieJar.update`, and `find_references` declines to
    /// certify it, so a walk must not spend a scarce fan-out slot on one while
    /// a proven call is waiting.
    pub proven: bool,
    /// The graph recorded a source site for the edge: a line in the caller
    /// where the call is written. A hop with no site cannot be opened and
    /// checked, which is what a data-flow answer is for.
    pub has_site: bool,
    /// Every call edge to this candidate is a `raise` target.
    pub raise_target: bool,
}

/// Relevance of one candidate against the other candidates of the SAME step, so
/// a per-step cap keeps the chain rather than whatever order the relation table
/// happened to return.
///
/// Compared as a tuple, most significant first:
/// 1. the graph holds a location for it (a file-less placeholder never takes a
///    slot from a symbol a caller can open)
/// 2. role rank (source over test; see [`trace_role_rank`])
/// 3. relation rank (Calls over Imports over References)
/// 4. the edge's destination is proven rather than guessed from a bare name
/// 5. the graph recorded the site where the call is written
/// 6. declared in the same FILE as the node being expanded
/// 7. declared in the same DIRECTORY as it
/// 8. declaration kind rank (functions and methods over constants)
/// 9. NOT a `raise` target (see below)
/// 10. the edge's own confidence
/// 11. shorter name, which only ever breaks a tie the ten signals above left
///
/// Proof and site sit directly under the relation kind, above locality, because
/// they are the two terms that say the hop is REAL. Everything below them is a
/// guess about which real hop the caller meant. Confidence carried some of this
/// at position 10, far too low to act: on a 714-commit slice of `cli/cli`,
/// `apiRun`'s fan-out held five `name_only` call edges (`Parse`,
/// `T.Errorf`, `Testing.Errorf`, `_testing.Errorf`, `RegexpWriter.Flush`) whose
/// destinations nothing at the call site proves, and only kind and locality
/// were keeping them out of the top slots. A same-file bare-name match would
/// have taken one.
///
/// The raise-target signal sits BELOW declaration kind, where it separates two
/// otherwise equal candidates and can never evict one in favour of a candidate
/// of a different kind. That position is measured, not assumed, and the
/// measurement is the point.
///
/// Ranking it second, above locality and kind, is the obvious reading of "a
/// throw site is not a hop" and it makes the tool's answer WORSE. At a fixed
/// `limit_per_step`, demoting a candidate promotes whatever ranked next, and on
/// a converted `psf/requests` what ranked next was `HTTPAdapter` itself,
/// `Response` and `RequestEncodingMixin._encode_params`. Those are hubs. Six
/// cheap terminal exception classes came out of `HTTPAdapter.send`'s twelve
/// depth-1 slots and six expensive ones went in, the walk grew from 129
/// discovered steps to its 200-step ceiling, and the hop that carries the
/// answer, `_urllib3_request_context` at depth 3, stopped arriving at the
/// default budget. Below kind it does not move at all: the walk stays at 129,
/// the hop comes back, and `SSLError` is still in the answer, still last.
///
/// `declaration_kind_rank` is what actually delivers "data flow above throw
/// sites" on real bytes, because exception classes are Classes and the callees
/// that carry a value are Functions and Methods. This signal orders throw sites
/// among their own kind, which is all a fan-out cap ever needed from it. It
/// demotes rather than filters either way, because "what does this throw" is a
/// real question and the edge is real evidence.
///
/// `parent_file` and `parent_dir` describe the node whose fan-out is being cut,
/// not the focal: locality is what makes a chain readable, and at depth 3 the
/// focal's directory says nothing about which of a distant node's callees
/// continue the path. On the measured trace this is the signal that decides:
/// `resolve_redirects` dropped `get_redirect_target` and `rebuild_method`, both
/// in its own file, in favour of `SupportsRead.read` and `HTTPAdapter.close`.
pub fn trace_fanout_score(
    entity: &Entity,
    relation_kind: RelationKind,
    parent_file: Option<&str>,
    parent_dir: Option<&str>,
    confidence: f32,
    evidence: TraceEdgeEvidence,
) -> TraceFanoutScore {
    let same_file = parent_file
        .zip(entity.file_origin.as_ref())
        .map(|(parent, file)| parent == file.0.as_str())
        .unwrap_or(false);
    let same_dir = parent_dir
        .zip(entity_directory(entity).as_deref())
        .map(|(parent, dir)| parent == dir)
        .unwrap_or(false);
    // Quantized because the key is compared with `Ord` and `f32` is not. Three
    // decimals keep every confidence the graph records distinguishable while
    // staying immune to the last-bit noise of a float that was multiplied out.
    let confidence = (confidence.clamp(0.0, 1.0) * 1000.0).round() as u32;
    (
        !trace_entity_is_external(entity),
        trace_role_rank(&entity.role),
        trace_relation_rank(relation_kind),
        evidence.proven,
        evidence.has_site,
        same_file,
        same_dir,
        declaration_kind_rank(&entity.kind),
        !evidence.raise_target,
        confidence,
        std::cmp::Reverse(entity.name.len()),
    )
}

/// Compute a composite score for trace constant selection.
pub fn trace_constant_score(entity: &Entity, focal_dir: Option<&str>) -> (bool, bool, usize) {
    let same_dir = focal_dir
        .zip(entity_directory(entity).as_deref())
        .map(|(root, dir)| root == dir)
        .unwrap_or(false);
    (
        same_dir,
        entity.file_origin.is_some(),
        usize::MAX.saturating_sub(entity.name.len()),
    )
}

/// Where one fan-out candidate sits relative to the node being expanded.
///
/// Three states, not two. A file-less candidate is neither in the node's file
/// nor in another one: the graph owns no location for it, it is a leaf with no
/// next hop, and reserving a cap slot for it would spend the reservation on a
/// step that continues nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutLocality {
    /// Defined in the expanded node's own file.
    SameFile,
    /// Defined in a different file this repository owns. This is the hop a
    /// data-flow question is about, and the one the cap used to discard first.
    OtherFile,
    /// The graph owns no file for this symbol: an import another repository
    /// defines, a builtin, or an alias split off its definition.
    Unlocated,
}

/// Which of a node's ranked neighbors a per-step fan-out cap keeps.
///
/// `locality` is one entry per candidate, in relevance order. The return is the
/// indices to keep, still in relevance order.
///
/// The rule is the ordinary top-N, with one floor under it: a cap may not spend
/// every slot inside the node's own file when the node has a located neighbor
/// outside it. A chain that never leaves the file it started in has not
/// answered a data-flow question, and the ranking cannot help here, because the
/// term that crowds the boundary out is a proximity term that no question is an
/// input to. The measured case is `Session.send` in `psf/requests`: fifteen
/// callees, eleven of them parser-certain same-file calls at confidence 1.0,
/// and a four-wide cap that therefore kept four `sessions.py` functions and
/// dropped every hop that leaves the module.
///
/// The reservation takes at most one slot and never takes it before the node's
/// own file has two, so a two-wide cap still keeps the two best neighbors it
/// has and nothing about a narrow walk changes. It is a floor, not a fix for
/// relevance: it guarantees the chain crosses the boundary when it can, and it
/// does not know which crossing the caller wanted. Naming a target is what
/// answers that.
pub fn fanout_cap_keeps(locality: &[FanoutLocality], limit: usize) -> Vec<usize> {
    if locality.len() <= limit {
        return (0..locality.len()).collect();
    }
    let mut kept: Vec<usize> = (0..limit).collect();
    if limit < 3 {
        return kept;
    }
    if kept
        .iter()
        .any(|&index| locality[index] == FanoutLocality::OtherFile)
    {
        return kept;
    }
    let Some(crossing) =
        (limit..locality.len()).find(|&index| locality[index] == FanoutLocality::OtherFile)
    else {
        return kept;
    };
    // The lowest-ranked kept slot, so the reservation costs the least relevant
    // neighbor rather than the best one, and the kept set stays in rank order.
    kept[limit - 1] = crossing;
    kept
}

/// One candidate for a file's anchor, as the ranking sees it: identity, kind,
/// name, and the structural graph mass measured for it.
///
/// Carrying a struct rather than an `Entity` keeps the ordering testable
/// without a graph: the caller does the graph IO, this crate decides the order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAnchorCandidate {
    pub id: EntityId,
    pub kind: EntityKind,
    pub name: String,
    /// Structural relation count for this entity, excluding `CoChanges`.
    pub mass: usize,
}

/// Whether a kind can be what a file is ABOUT.
///
/// Types and free functions can. Methods cannot: a method's anchor is the type
/// that contains it, and admitting methods lets one type's internals take every
/// anchor slot a file has, which is the failure this whole selection exists to
/// avoid. Constants, variants, macros and modules are excluded from the other
/// side: they are what a file holds, not what it is for.
pub fn is_file_anchor_kind(kind: EntityKind) -> bool {
    matches!(
        kind,
        EntityKind::Function
            | EntityKind::Class
            | EntityKind::Interface
            | EntityKind::TraitDef
            | EntityKind::EnumDef
    )
}

/// Type-shaped anchors are preferred over free functions when mass ties, and
/// when a probe budget has to choose which definitions to weigh at all. A file
/// that defines a type is usually named for it; a file of free functions has no
/// such head, so its functions are weighed on mass alone.
pub fn file_anchor_kind_rank(kind: EntityKind) -> u8 {
    match kind {
        EntityKind::Class | EntityKind::Interface | EntityKind::TraitDef | EntityKind::EnumDef => 1,
        _ => 0,
    }
}

/// The anchors of one file, most-depended-on first.
///
/// `locate` ranks FILES with every signal it has (lexical, vector, graph
/// resolve, multihop) and then projects ENTITIES only for the symbols a query
/// token happened to name. A file can therefore rank first for a question and
/// contribute nothing an agent can read: measured on 2026-09-02, VS Code's
/// `codeEditorWidget.ts` ranked second for "when I type a character in the
/// editor, how does it end up in the document" and the class `CodeEditorWidget`
/// appeared nowhere in the 122-row ranking, while six `*.editor` methods from
/// other files took the page on the word "editor".
///
/// This answers the question projection cannot: given a file the graph already
/// ranked, which of its definitions is the file about. Structural relation count
/// is the answer the graph already holds. A class the editor constructs from
/// forty places carries more edges than any of its own private methods, and an
/// entry point the scheduler calls carries more than its helpers. It is the same
/// measure [`owner_graph_mass`] uses to break exact-name ties, applied to a
/// different question.
///
/// Ordering: mass descending, then type over free function, then name, then id,
/// so the result is total and deterministic on a store with ties.
pub fn rank_file_anchors(
    mut candidates: Vec<FileAnchorCandidate>,
    limit: usize,
) -> Vec<FileAnchorCandidate> {
    if limit == 0 {
        return Vec::new();
    }
    candidates.retain(|candidate| is_file_anchor_kind(candidate.kind));
    candidates.sort_by(|a, b| {
        b.mass
            .cmp(&a.mass)
            .then_with(|| file_anchor_kind_rank(b.kind).cmp(&file_anchor_kind_rank(a.kind)))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
    });
    candidates.truncate(limit);
    candidates
}

/// Which of a file's definitions are worth a graph read, when the file has more
/// of them than the probe budget allows.
///
/// Anchor kinds only, types before free functions, then name for determinism.
/// The budget exists so one generated file with ten thousand definitions cannot
/// turn a ranked page into a graph walk; on the three stores this was measured
/// against, no file came close to the default.
pub fn file_anchor_probe_order(entities: &[Entity], probe_limit: usize) -> Vec<&Entity> {
    let mut probes: Vec<&Entity> = entities
        .iter()
        .filter(|entity| is_file_anchor_kind(entity.kind) && entity.role != EntityRole::Test)
        .collect();
    probes.sort_by(|a, b| {
        file_anchor_kind_rank(b.kind)
            .cmp(&file_anchor_kind_rank(a.kind))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
    });
    probes.truncate(probe_limit);
    probes
}

/// The anchors of one file, read from the graph: [`file_anchor_probe_order`]
/// chooses what to weigh, [`structural_relation_count`] weighs it, and
/// [`rank_file_anchors`] orders the result.
///
/// Graph-backed throughout: relations come from the store's own index, never
/// from a path walk or a file read.
pub fn file_anchor_entities<G: GraphStore>(
    store: &G,
    entities: &[Entity],
    limit: usize,
    probe_limit: usize,
) -> std::result::Result<Vec<FileAnchorCandidate>, <G as GraphStore>::Error> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    for entity in file_anchor_probe_order(entities, probe_limit) {
        candidates.push(FileAnchorCandidate {
            id: entity.id,
            kind: entity.kind,
            name: entity.name.clone(),
            mass: structural_relation_count(store, &entity.id)?,
        });
    }
    Ok(rank_file_anchors(candidates, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    use FanoutLocality::{OtherFile, SameFile, Unlocated};

    /// The measured shape: a node whose best neighbors are all in its own file,
    /// and the one hop that leaves the module ranked below every one of them.
    #[test]
    fn a_cap_may_not_spend_every_slot_inside_the_nodes_own_file() {
        let fanout = [SameFile, SameFile, SameFile, SameFile, OtherFile];
        assert_eq!(
            fanout_cap_keeps(&fanout, 4),
            vec![0, 1, 2, 4],
            "the reservation costs the lowest-ranked kept slot, not the best one"
        );
    }

    /// The floor is a floor, not extra breadth. It never takes a second slot,
    /// however many crossings are waiting.
    #[test]
    fn the_reservation_never_takes_more_than_one_slot() {
        let fanout = [
            SameFile, SameFile, SameFile, SameFile, OtherFile, OtherFile, OtherFile,
        ];
        assert_eq!(fanout_cap_keeps(&fanout, 4), vec![0, 1, 2, 4]);
    }

    /// A two-wide cap has room for the two best neighbors and nothing else, so
    /// it is left exactly as it was. This is the case `the_per_step_cap_keeps_\
    /// the_callees_that_continue_the_chain` pins on the walker.
    #[test]
    fn a_cap_too_narrow_to_afford_a_reservation_does_not_take_one() {
        let fanout = [SameFile, SameFile, OtherFile];
        assert_eq!(fanout_cap_keeps(&fanout, 2), vec![0, 1]);
        // Three is where it can afford one: two slots stay with the node's own
        // file, which is the promise the narrow case rests on.
        assert_eq!(fanout_cap_keeps(&fanout, 3), vec![0, 1, 2]);
    }

    /// A file-less symbol is a leaf with no next hop, so reserving a slot for
    /// one would spend the floor on a step that continues nothing.
    #[test]
    fn an_unlocated_candidate_never_takes_the_reserved_slot() {
        let fanout = [SameFile, SameFile, SameFile, SameFile, Unlocated];
        assert_eq!(
            fanout_cap_keeps(&fanout, 4),
            vec![0, 1, 2, 3],
            "nothing crosses a file boundary here, so nothing is reserved"
        );
    }

    /// A cap that already kept a crossing has nothing to fix, and must not
    /// reshuffle what relevance chose.
    ///
    /// The second crossing below the cap is the point of the fixture. Without
    /// it, a rule that reserved unconditionally would look identical here,
    /// because there would be nothing left to promote.
    #[test]
    fn a_cap_that_already_crosses_is_left_alone() {
        let fanout = [SameFile, OtherFile, SameFile, SameFile, OtherFile];
        assert_eq!(fanout_cap_keeps(&fanout, 4), vec![0, 1, 2, 3]);
    }

    /// And a fan-out inside the cap is untouched, so an unclipped walk is
    /// byte-identical to the one before this rule existed.
    #[test]
    fn a_fan_out_that_fits_is_kept_whole() {
        let fanout = [SameFile, OtherFile, Unlocated];
        assert_eq!(fanout_cap_keeps(&fanout, 5), vec![0, 1, 2]);
        assert_eq!(fanout_cap_keeps(&fanout, 3), vec![0, 1, 2]);
    }

    /// The measured shape, as a ranking: a file whose page was taken by one
    /// type's methods while the type itself never appeared. The anchor is the
    /// definition the rest of the repository depends on, not the one whose name
    /// a question happened to contain.
    #[test]
    fn a_files_anchor_is_the_definition_the_rest_of_the_repo_depends_on() {
        let candidate = |name: &str, kind: EntityKind, mass: usize| FileAnchorCandidate {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            mass,
        };
        let ranked = rank_file_anchors(
            vec![
                candidate("EditorModeContext", EntityKind::Class, 7),
                candidate("CodeEditorWidget", EntityKind::Class, 61),
                candidate("EditorDecorationsCollection", EntityKind::Class, 12),
            ],
            2,
        );
        assert_eq!(
            ranked.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["CodeEditorWidget", "EditorDecorationsCollection"],
            "mass orders the anchors, and the limit is a limit"
        );
    }

    /// A method's anchor is its owning type. Without this a widely-called
    /// method takes every slot its own file has, which is the failure the
    /// selection exists to avoid.
    ///
    /// The control is the free function beside it: dropping every candidate
    /// would pass the first assertion alone.
    #[test]
    fn a_method_is_never_a_files_anchor() {
        let candidate = |name: &str, kind: EntityKind, mass: usize| FileAnchorCandidate {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            mass,
        };
        let ranked = rank_file_anchors(
            vec![
                candidate("CodeEditorWidget.trigger", EntityKind::Method, 900),
                candidate("createTextModel", EntityKind::Function, 3),
            ],
            5,
        );
        assert_eq!(
            ranked.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["createTextModel"],
            "the method is dropped at any mass; the free function survives at any mass"
        );
        assert!(!is_file_anchor_kind(EntityKind::Method));
        assert!(is_file_anchor_kind(EntityKind::Function));
    }

    /// Kind is a tie-break, not an override. Both directions are pinned,
    /// because a rule that preferred types unconditionally would pass the
    /// first case and fail the second.
    #[test]
    fn a_type_wins_a_mass_tie_and_loses_a_mass_gap() {
        let candidate = |name: &str, kind: EntityKind, mass: usize| FileAnchorCandidate {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            mass,
        };
        let tied = rank_file_anchors(
            vec![
                candidate("search_path", EntityKind::Function, 40),
                candidate("Searcher", EntityKind::Class, 40),
            ],
            1,
        );
        assert_eq!(tied[0].name, "Searcher", "a type breaks a mass tie");

        let gapped = rank_file_anchors(
            vec![
                candidate("scheduleUpdateOnFiber", EntityKind::Function, 120),
                candidate("RootTag", EntityKind::EnumDef, 4),
            ],
            1,
        );
        assert_eq!(
            gapped[0].name, "scheduleUpdateOnFiber",
            "mass still decides when it differs, so a file of free functions has an anchor"
        );
    }

    /// A zero limit asks for nothing and gets nothing, without touching the
    /// candidates. The caller's kill switch runs through this path.
    #[test]
    fn a_zero_limit_returns_no_anchors() {
        let ranked = rank_file_anchors(
            vec![FileAnchorCandidate {
                id: EntityId::new(),
                kind: EntityKind::Class,
                name: "Walk".to_string(),
                mass: 99,
            }],
            0,
        );
        assert!(ranked.is_empty());
    }

    #[test]
    fn declaration_kind_rank_function_highest() {
        assert_eq!(declaration_kind_rank(&EntityKind::Function), 3);
        assert_eq!(declaration_kind_rank(&EntityKind::Method), 3);
    }

    #[test]
    fn declaration_kind_rank_class_middle() {
        assert_eq!(declaration_kind_rank(&EntityKind::Class), 2);
        assert_eq!(declaration_kind_rank(&EntityKind::TraitDef), 2);
    }

    #[test]
    fn declaration_kind_rank_constant_low() {
        assert_eq!(declaration_kind_rank(&EntityKind::Constant), 1);
        assert_eq!(declaration_kind_rank(&EntityKind::StaticVar), 1);
    }

    #[test]
    fn declaration_kind_rank_module_zero() {
        assert_eq!(declaration_kind_rank(&EntityKind::Module), 0);
    }

    #[test]
    fn relation_kind_rank_ordering() {
        assert!(
            relation_kind_rank(&RelationKind::Imports) < relation_kind_rank(&RelationKind::Calls)
        );
        assert!(
            relation_kind_rank(&RelationKind::Calls)
                < relation_kind_rank(&RelationKind::References)
        );
    }

    #[test]
    fn trace_relation_rank_ordering() {
        assert!(
            trace_relation_rank(RelationKind::Calls) > trace_relation_rank(RelationKind::Imports)
        );
        assert!(
            trace_relation_rank(RelationKind::Imports)
                > trace_relation_rank(RelationKind::References)
        );
        assert!(
            trace_relation_rank(RelationKind::References)
                > trace_relation_rank(RelationKind::UsesType),
            "naming a type in a signature moves no value, so a real reference wins a scarce slot"
        );
    }

    #[test]
    fn only_a_type_edge_is_an_annotation_edge() {
        assert!(trace_relation_is_annotation(RelationKind::UsesType));
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
            RelationKind::Instantiates,
        ] {
            assert!(
                !trace_relation_is_annotation(kind),
                "{kind:?} moves a value and must stay walkable"
            );
        }
    }

    #[test]
    fn an_external_target_is_terminal_whatever_edge_reached_it() {
        let external = fanout_entity("Any", None);
        for kind in [
            RelationKind::Calls,
            RelationKind::References,
            RelationKind::UsesType,
        ] {
            for include_type_edges in [false, true] {
                assert_eq!(
                    trace_step_terminal(&external, kind, include_type_edges),
                    Some(TraceTerminal::ExternalReference),
                    "no parameter makes a symbol this repository does not define walkable \
                     ({kind:?}, include_type_edges={include_type_edges})"
                );
            }
        }
    }

    #[test]
    fn a_repo_type_is_terminal_only_until_the_caller_asks_for_type_edges() {
        let located = fanout_entity("WikiLink", Some("src/links.py"));
        assert_eq!(
            trace_step_terminal(&located, RelationKind::UsesType, false),
            Some(TraceTerminal::TypeAnnotation)
        );
        assert_eq!(
            trace_step_terminal(&located, RelationKind::UsesType, true),
            None,
            "a field typed with a repo class is a real flow into that class"
        );
        assert_eq!(
            trace_step_terminal(&located, RelationKind::Calls, false),
            None,
            "an ordinary call is untouched by either boundary"
        );
    }

    #[test]
    fn an_unread_node_and_an_empty_read_are_different_terminals() {
        // The whole point: the same finished chain, three different reasons for
        // ending, and the classifier must not collapse them.
        assert_eq!(
            trace_walk_terminal(TraceExpansion::BoundStopped, true),
            Some(TraceTerminal::BoundReached),
            "a node whose relations were never read cannot be reported as a leaf"
        );
        assert_eq!(
            trace_walk_terminal(TraceExpansion::BoundStopped, false),
            Some(TraceTerminal::BoundReached),
            "coverage says nothing about a node the walk never examined"
        );
        assert_eq!(
            trace_walk_terminal(TraceExpansion::NoEdges, true),
            Some(TraceTerminal::Leaf)
        );
        assert_eq!(
            trace_walk_terminal(TraceExpansion::NoEdges, false),
            Some(TraceTerminal::CoverageGap),
            "an empty read on a graph that could not hold the hop is not a leaf"
        );
        for certain in [false, true] {
            assert_eq!(
                trace_walk_terminal(TraceExpansion::HadEdges, certain),
                None,
                "a node with neighbors is an ordinary step, not an end"
            );
        }
    }

    #[test]
    fn only_the_two_shortfall_terminals_truncate() {
        assert!(TraceTerminal::BoundReached.truncates());
        assert!(TraceTerminal::CoverageGap.truncates());
        for complete in [
            TraceTerminal::ExternalReference,
            TraceTerminal::TypeAnnotation,
            TraceTerminal::Leaf,
        ] {
            assert!(
                !complete.truncates(),
                "{} ends the chain and must not report a shortfall",
                complete.as_str()
            );
        }
    }

    #[test]
    fn every_terminal_has_its_own_wire_name() {
        let names: Vec<&str> = [
            TraceTerminal::ExternalReference,
            TraceTerminal::TypeAnnotation,
            TraceTerminal::Leaf,
            TraceTerminal::BoundReached,
            TraceTerminal::CoverageGap,
        ]
        .iter()
        .map(|terminal| terminal.as_str())
        .collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            names.len(),
            "two terminals sharing a wire name would be indistinguishable to a client: {names:?}"
        );
        assert!(names.contains(&"leaf"));
        assert!(names.contains(&"bound_reached"));
        assert!(names.contains(&"coverage_gap"));
    }

    fn relation(kind: RelationKind, src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: kin_model::RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn containing_owner_is_the_incoming_contains_source() {
        let method = EntityId::new();
        let owner = EntityId::new();
        let caller = EntityId::new();
        let rels = vec![
            // Incoming call noise must not read as ownership.
            relation(RelationKind::Calls, caller, method),
            relation(RelationKind::Contains, owner, method),
            // An OUTGOING Contains (this entity containing something else)
            // must not read as this entity's owner either.
            relation(RelationKind::Contains, method, caller),
        ];
        assert_eq!(containing_owner_id(&method, &rels), Some(owner));
    }

    #[test]
    fn entity_nothing_contains_has_no_owner() {
        let method = EntityId::new();
        let caller = EntityId::new();
        let rels = vec![relation(RelationKind::Calls, caller, method)];
        assert_eq!(containing_owner_id(&method, &rels), None);
        assert_eq!(containing_owner_id(&method, &[]), None);
    }

    fn fanout_entity(name: &str, file: Option<&str>) -> Entity {
        use kin_model::entity::{EntityMetadata, FingerprintAlgorithm, SemanticFingerprint};
        use kin_model::ids::{FilePathId, Hash256, LanguageId};
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: file.map(FilePathId::new),
            span: None,
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn score(entity: &Entity) -> TraceFanoutScore {
        scored(entity, false)
    }

    /// The evidence a parser-certain call carries: destination proven, site
    /// recorded, not a throw. The tests below vary one term at a time from it.
    fn proven_call() -> TraceEdgeEvidence {
        TraceEdgeEvidence {
            proven: true,
            has_site: true,
            raise_target: false,
        }
    }

    /// The same key with the raise-target signal set, so the tests below can
    /// compare a throw site against the hop it used to outrank.
    fn scored(entity: &Entity, raise_target: bool) -> TraceFanoutScore {
        trace_fanout_score(
            entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            TraceEdgeEvidence {
                raise_target,
                ..proven_call()
            },
        )
    }

    /// The five bare-name call edges in `apiRun`'s measured fan-out, in
    /// miniature: a guessed destination in the node's own file must not take a
    /// slot from a proven call one directory away.
    #[test]
    fn a_proven_call_outranks_a_bare_name_guess_that_sits_closer() {
        let guessed = fanout_entity("Errorf", Some("src/requests/sessions.py"));
        let proven = fanout_entity("httpRequest", Some("src/requests/adapters.py"));
        let guessed_score = trace_fanout_score(
            &guessed,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            0.4,
            TraceEdgeEvidence::default(),
        );
        let proven_score = trace_fanout_score(
            &proven,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            proven_call(),
        );
        assert!(
            proven_score > guessed_score,
            "a call the graph proved outranks one it guessed from a name, even in another file"
        );
    }

    /// A proven edge whose site the parser never recorded is still a hop a
    /// caller can follow, so the site term separates it from a proven hop that
    /// CAN be opened rather than sinking it to the bare-name tier.
    #[test]
    fn a_recorded_site_separates_two_proven_calls_and_nothing_else() {
        let entity = fanout_entity("httpRequest", Some("src/requests/adapters.py"));
        let sited = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            proven_call(),
        );
        let siteless = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            TraceEdgeEvidence {
                has_site: false,
                ..proven_call()
            },
        );
        let guessed = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            TraceEdgeEvidence::default(),
        );
        assert!(sited > siteless, "a hop with a site leads one without");
        assert!(siteless > guessed, "and both lead a bare-name guess");
    }

    #[test]
    fn a_raise_target_loses_to_an_equal_candidate_that_is_not_one() {
        // FIR-2642. The comparison this signal decides, and the only one it is
        // allowed to decide: two candidates alike in every other term, one of
        // them only ever thrown.
        let thrown = fanout_entity("SSLError", Some("src/requests/sessions.py"));
        let ordinary = fanout_entity("SSLError2", Some("src/requests/sessions.py"));
        assert!(
            scored(&ordinary, false) > scored(&thrown, true),
            "the candidate that is not a throw site wins"
        );
        assert!(
            scored(&thrown, false) > scored(&ordinary, false),
            "the fixture's premise: with neither marked, the shorter name wins, \
             so the signal is what reverses them rather than a tie"
        );
    }

    #[test]
    fn a_raise_target_never_outranks_a_hop_of_a_stronger_kind() {
        // And the term it must NOT override. Ranking a raise target below a
        // whole declaration kind was measured on a converted psf/requests and
        // cost the answer: it evicted six cheap exception classes from the
        // depth-1 cap and admitted six hubs, the walk grew from 129 steps to
        // its 200-step ceiling, and the hop at depth 3 stopped arriving.
        let mut hop = fanout_entity("build_pool_key", Some("src/requests/sessions.py"));
        hop.kind = EntityKind::Function;
        let mut thrown = fanout_entity("SSLError", Some("src/requests/sessions.py"));
        thrown.kind = EntityKind::Class;
        assert!(
            scored(&hop, false) > scored(&thrown, true),
            "a function the value travels through outranks a class that is \
             only thrown"
        );
        let mut other_class = fanout_entity("HTTPAdapter", Some("src/requests/sessions.py"));
        other_class.kind = EntityKind::Class;
        assert!(
            scored(&hop, false) > scored(&other_class, false),
            "and it outranks an ordinary class too, which is what stops the \
             raise signal from promoting a hub into a slot a throw site held"
        );
    }

    #[test]
    fn demoting_a_raise_target_orders_it_and_never_removes_it() {
        // The recall half, at the level the ordering is defined. Two throw
        // sites still compare against each other by every signal below, so a
        // step wide enough to hold them reports them in a stable order rather
        // than collapsing them.
        let first = fanout_entity("SSLError", Some("src/requests/sessions.py"));
        let second = fanout_entity("InvalidURL", Some("src/other/exceptions.py"));
        assert!(
            scored(&first, true) > scored(&second, true),
            "same-file still decides between two throw sites"
        );
    }

    #[test]
    fn a_located_callee_outranks_a_file_less_placeholder() {
        let admitted = fanout_entity("get_redirect_target", Some("src/requests/sessions.py"));
        let placeholder = fanout_entity("urljoin", None);
        assert!(trace_entity_is_external(&placeholder));
        assert!(!trace_entity_is_external(&admitted));
        assert!(score(&admitted) > score(&placeholder));
    }

    #[test]
    fn a_source_callee_outranks_a_test_one() {
        let source = fanout_entity("Session.send", Some("src/requests/sessions.py"));
        let mut test = fanout_entity("TestRequests.test_send", Some("tests/test_requests.py"));
        test.role = EntityRole::Test;
        assert!(score(&source) > score(&test));
    }

    #[test]
    fn a_callee_in_the_expanded_node_s_own_file_outranks_a_distant_one() {
        // The measured inversion: `resolve_redirects` kept `HTTPAdapter.close`
        // (adapters.py) and dropped `rebuild_method`, which sits beside it.
        let neighbour = fanout_entity("rebuild_method", Some("src/requests/sessions.py"));
        let distant = fanout_entity("HTTPAdapter.close", Some("src/requests/adapters.py"));
        assert!(score(&neighbour) > score(&distant));
    }

    #[test]
    fn a_call_edge_outranks_a_reference_edge_to_the_same_kind_of_callee() {
        let entity = fanout_entity("rebuild_proxies", Some("src/requests/sessions.py"));
        let called = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            proven_call(),
        );
        let referenced = trace_fanout_score(
            &entity,
            RelationKind::References,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            proven_call(),
        );
        assert!(called > referenced);
    }

    #[test]
    fn a_more_confident_edge_outranks_a_guessed_one() {
        let entity = fanout_entity("rebuild_auth", Some("src/requests/sessions.py"));
        let certain = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
            proven_call(),
        );
        let guessed = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            0.4,
            proven_call(),
        );
        assert!(certain > guessed);
    }

    /// A vendored dependency carries real files, so it is addressable and must
    /// not be scored as a placeholder the way a file-less import alias is.
    #[test]
    fn a_vendored_entity_with_a_file_is_not_external() {
        let mut vendored = fanout_entity("urllib3.connectionpool", Some("vendor/urllib3/pool.py"));
        vendored.role = EntityRole::External;
        assert!(!trace_entity_is_external(&vendored));
        let placeholder = fanout_entity("urllib3.connectionpool", None);
        assert!(score(&vendored) > score(&placeholder));
    }

    #[test]
    fn qualified_owner_prefix_splits_on_the_last_separator() {
        assert_eq!(
            qualified_owner_prefix("CodeEmbedder::embed_batch"),
            Some("CodeEmbedder")
        );
        assert_eq!(
            qualified_owner_prefix("constant.Raspbian"),
            Some("constant")
        );
        assert_eq!(qualified_owner_prefix("a::b::c"), Some("a::b"));
        assert_eq!(qualified_owner_prefix("&G::delete_work_item"), Some("&G"));
        // Bare names have no owner segment, and a leading separator yields no
        // usable prefix rather than an empty one.
        assert_eq!(qualified_owner_prefix("seal_change"), None);
        assert_eq!(qualified_owner_prefix("::rooted"), None);
        assert_eq!(qualified_owner_prefix(".hidden"), None);
    }

    #[test]
    fn bare_member_name_steps_past_the_same_separator_qualified_owner_prefix_found() {
        assert_eq!(bare_member_name("CodeEmbedder::embed_batch"), "embed_batch");
        assert_eq!(bare_member_name("constant.Raspbian"), "Raspbian");
        assert_eq!(bare_member_name("a::b::c"), "c");
        assert_eq!(bare_member_name("&G::delete_work_item"), "delete_work_item");
        // The three owner-qualified siblings `find_references` sections a
        // bare-name answer over: distinct full names, one shared bare one.
        assert_eq!(
            bare_member_name("Flask.dispatch_request"),
            "dispatch_request"
        );
        assert_eq!(
            bare_member_name("View.dispatch_request"),
            "dispatch_request"
        );
        assert_eq!(
            bare_member_name("MethodView.dispatch_request"),
            "dispatch_request"
        );
        // A bare name has nothing to step past, so it is its own answer --
        // including the two cases where `qualified_owner_prefix` recognizes no
        // usable prefix despite a separator being present.
        assert_eq!(bare_member_name("seal_change"), "seal_change");
        assert_eq!(bare_member_name("::rooted"), "::rooted");
        assert_eq!(bare_member_name(".hidden"), ".hidden");
    }

    fn member(name: &str, kind: EntityKind, file: &str) -> Entity {
        let mut entity = fanout_entity(name, Some(file));
        entity.kind = kind;
        entity
    }

    #[test]
    fn a_member_name_match_needs_a_member_kind_an_owner_and_the_whole_segment() {
        assert!(is_member_name_match(
            &member("Scaffold.get", EntityKind::Method, "a.py"),
            "get"
        ));
        assert!(is_member_name_match(
            &member("Router<S>::route", EntityKind::Method, "a.rs"),
            "route"
        ));
        assert!(is_member_name_match(
            &member("User.Name", EntityKind::Field, "a.go"),
            "Name"
        ));
        assert!(is_member_name_match(
            &member("GraphNodeId::Entity", EntityKind::EnumVariant, "a.rs"),
            "Entity"
        ));
        // The whole name is the exact tier, not the member tier.
        assert!(!is_member_name_match(
            &member("get", EntityKind::Function, "a.py"),
            "get"
        ));
        // A member segment that only contains the query is not its member name.
        assert!(!is_member_name_match(
            &member("ConfigAttribute.__get__", EntityKind::Method, "a.py"),
            "get"
        ));
        assert!(!is_member_name_match(
            &member("get_db", EntityKind::Function, "a.py"),
            "get"
        ));
        // An incidental last segment is not a member name: a file module, a
        // shallow constant and a dotted function are not owners' members.
        assert!(!is_member_name_match(
            &member("app.py", EntityKind::Module, "app.py"),
            "py"
        ));
        assert!(!is_member_name_match(
            &member("constant.Raspbian", EntityKind::Constant, "c.go"),
            "Raspbian"
        ));
        assert!(!is_member_name_match(
            &member("exports.render", EntityKind::Function, "a.js"),
            "render"
        ));
    }

    #[test]
    fn the_whole_name_outranks_the_member_segment_which_outranks_a_substring() {
        let exact = member("get", EntityKind::Function, "a.py");
        let method = member("Scaffold.get", EntityKind::Method, "a.py");
        let cousin = member("get_db", EntityKind::Function, "a.py");
        assert_eq!(name_match_tier(&exact, "get"), 2);
        assert_eq!(name_match_tier(&method, "get"), 1);
        assert_eq!(name_match_tier(&cousin, "get"), 0);

        // A lone member beats a substring cousin that is exported, a better
        // kind, and far more referenced: the pallets/flask shape where
        // `template_global` answered with `Blueprint.app_template_global`.
        let member_hit = member("App.template_global", EntityKind::Method, "app.py");
        let cousin_hit = member(
            "Blueprint.app_template_global",
            EntityKind::Method,
            "blueprints.py",
        );
        assert!(
            entity_ranking_key(&member_hit, "template_global", 0, 0)
                > entity_ranking_key(&cousin_hit, "template_global", 40, 40)
        );
    }

    #[test]
    fn an_exact_name_is_its_own_tier_and_is_never_pooled_with_members() {
        let exact = member("Entity", EntityKind::Class, "src/entity.rs");
        let variant = member(
            "GraphNodeId::Entity",
            EntityKind::EnumVariant,
            "src/graph.rs",
        );
        let method = member("Store::Entity", EntityKind::Method, "src/store.rs");
        assert_eq!(
            reach_among(
                vec![variant.clone(), exact.clone(), method.clone()],
                "Entity"
            ),
            NameReach::Exact(vec![exact])
        );
        // With no whole-name match the members answer, in listing order.
        match reach_among(vec![method.clone(), variant.clone()], "Entity") {
            NameReach::Members(members) => {
                let names: Vec<&str> = members.iter().map(|e| e.name.as_str()).collect();
                assert_eq!(names, vec!["GraphNodeId::Entity", "Store::Entity"]);
            }
            other => panic!("members must answer when nothing is named exactly: {other:?}"),
        }
    }

    #[test]
    fn exact_twins_stay_twins_and_a_partial_name_reaches_neither_tier() {
        let one = member("resolve", EntityKind::Function, "src/database.py");
        let two = member("resolve", EntityKind::Function, "src/link_graph.py");
        match reach_among(vec![two.clone(), one.clone()], "resolve") {
            NameReach::Exact(exact) => assert_eq!(exact.len(), 2),
            other => panic!("{other:?}"),
        }
        let cousin = member("get_db", EntityKind::Function, "examples/db.py");
        assert_eq!(reach_among(vec![cousin], "get_d"), NameReach::Neither);
        // A file-less external reference target is never reached.
        let mut external = member("Other.get", EntityKind::Method, "x.py");
        external.file_origin = None;
        external.role = EntityRole::External;
        assert_eq!(reach_among(vec![external], "get"), NameReach::Neither);
    }

    #[test]
    fn a_listing_publishes_member_names_only_for_members() {
        let method = member("Scaffold.get", EntityKind::Method, "a.py");
        assert_eq!(lookup_member_name(&method), "get");
        assert_eq!(member_owner(&method), Some("Scaffold"));
        let module = member("app.py", EntityKind::Module, "app.py");
        assert_eq!(lookup_member_name(&module), "app.py");
        assert_eq!(member_owner(&module), None);
        let free = member("get_db", EntityKind::Function, "db.py");
        assert_eq!(lookup_member_name(&free), "get_db");
        assert_eq!(member_owner(&free), None);
        assert!(is_member_kind_named("Method") && is_member_kind_named("EnumVariant"));
        assert!(!is_member_kind_named("Module") && !is_member_kind_named("method"));
        assert_eq!(lookup_member_name_of("Scaffold.get", true), "get");
        assert_eq!(lookup_member_name_of("app.py", false), "app.py");
    }

    #[test]
    fn candidate_reasons_have_stable_wire_names() {
        for (reason, wire) in [
            (CandidateReason::SameName, "same_name"),
            (CandidateReason::SharedMemberName, "shared_member_name"),
            (CandidateReason::SameLeafName, "same_leaf_name"),
            (CandidateReason::PartialName, "partial_name"),
        ] {
            assert_eq!(reason.as_str(), wire);
        }
    }
}
