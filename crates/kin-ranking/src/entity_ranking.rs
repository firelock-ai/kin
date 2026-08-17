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
/// 1. Exact name match
/// 2. Exported (public/internal)
/// 3. Declaration kind rank
/// 4. Direct call/import count (incoming)
/// 5. Total incoming reference count
/// 6. Has file origin
/// 7. Shorter name preferred (Reverse)
pub type EntityRankingKey = (
    bool,
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
        entity.name == query,
        exported,
        declaration_kind_rank(&entity.kind),
        direct_signal,
        incoming_refs,
        entity.file_origin.is_some(),
        std::cmp::Reverse(entity.name.len()),
    )
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
/// Higher values indicate more significant relations: Calls > Imports > References.
pub fn trace_relation_rank(kind: RelationKind) -> usize {
    match kind {
        RelationKind::Calls => 2,
        RelationKind::Imports => 1,
        RelationKind::References => 0,
        _ => 0,
    }
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
    usize,
    u32,
    std::cmp::Reverse<usize>,
);

/// Relevance of one candidate against the other candidates of the SAME step, so
/// a per-step cap keeps the chain rather than whatever order the relation table
/// happened to return.
///
/// Compared as a tuple, most significant first:
/// 1. the graph holds a location for it (a file-less placeholder never takes a
///    slot from a symbol a caller can open)
/// 2. role rank (source over test; see [`trace_role_rank`])
/// 3. relation rank (Calls over Imports over References)
/// 4. declared in the same FILE as the node being expanded
/// 5. declared in the same DIRECTORY as it
/// 6. declaration kind rank (functions and methods over constants)
/// 7. the edge's own confidence
/// 8. shorter name, which only ever breaks a tie the seven signals above left
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
        same_file,
        same_dir,
        declaration_kind_rank(&entity.kind),
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

#[cfg(test)]
mod tests {
    use super::*;

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
        trace_fanout_score(
            entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
        )
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
        );
        let referenced = trace_fanout_score(
            &entity,
            RelationKind::References,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            1.0,
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
        );
        let guessed = trace_fanout_score(
            &entity,
            RelationKind::Calls,
            Some("src/requests/sessions.py"),
            Some("src/requests"),
            0.4,
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
}
