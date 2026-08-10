// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Result};
use kin_model::{
    Entity, EntityFilter, EntityId, EntityRevision, GraphStore, Hash256, SemanticChangeId,
};

use super::repository_authority::{parse_git_object_id, parse_ref_name, ActiveRepositoryAuthority};

/// A reference did not resolve through repository-v6 authority.
#[derive(Debug)]
pub struct RefResolutionError {
    reference: String,
    reason: String,
}

impl std::fmt::Display for RefResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "cannot resolve ref '{}': {}",
            self.reference, self.reason
        )
    }
}

impl std::error::Error for RefResolutionError {}

fn ref_error(reference: impl Into<String>, reason: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(RefResolutionError {
        reference: reference.into(),
        reason: reason.into(),
    })
}

pub fn is_ref_resolution_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<RefResolutionError>().is_some())
}

pub(crate) fn parse_change_id(input: &str) -> Result<SemanticChangeId> {
    Ok(SemanticChangeId::from_hash(
        Hash256::from_hex(input).map_err(|error| anyhow!("invalid change hash: {error}"))?,
    ))
}

pub fn resolve_ref<G>(
    graph: &G,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    reference: Option<&str>,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let reference = reference.unwrap_or("HEAD");
    if reference.contains("@{") {
        return Err(ref_error(
            reference,
            "reflog/upstream '@{...}' syntax is not supported",
        ));
    }

    let (core, hops) = split_relative_hops(reference)?;
    let head = resolve_ref_core(graph, binding, reference, core)?;
    apply_parent_hops(graph, reference, head, &hops)
}

pub(crate) fn resolve_entity_query<G>(graph: &G, entity_query: &str) -> Result<Entity>
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
        .map_err(|error| anyhow!(error.to_string()))?;
    choose_entity_match(entities, entity_query).or_else(|primary| {
        // The store-side name_pattern filter and the local matcher do not agree
        // on every query shape, so a whole-graph sweep is the backstop. It must
        // still be narrowed to the query: handing choose_entity_match an
        // unfiltered graph makes it report the first five entities
        // alphabetically as "matches", which is how `kin history alwaysTrue`
        // came back with "Multiple entities match 'alwaysTrue': AND_THEN,
        // AND_WHEN, ANON_TEST_CASE, Approx". None of those contain the query.
        let narrowed = graph
            .list_all_entities()
            .map_err(|error| anyhow!(error.to_string()))?
            .into_iter()
            .filter(|entity| entity_matches_query(entity, entity_query))
            .collect::<Vec<_>>();
        if narrowed.is_empty() {
            // Nothing in the graph matches, so the first attempt's message is
            // the accurate one. Surfacing a second, wider failure here would
            // bury it.
            return Err(primary);
        }
        choose_entity_match(narrowed, entity_query)
    })
}

/// The entity a query names at `head`, together with its revision timeline.
///
/// Both come out of one replay of committed state, which is also why the two
/// are resolved together: the entity lookup already needs the state at `head`,
/// and resolving revisions separately would replay the same history twice.
pub(crate) fn resolve_entity_with_revisions_at<G>(
    graph: &G,
    entity_query: &str,
    head: &SemanticChangeId,
) -> Result<(Entity, Vec<EntityRevision>)>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut state = graph
        .resolve_graph_at(head)
        .map_err(|error| anyhow!(error.to_string()))?;
    let entities = state
        .entities
        .values()
        .filter(|entity| entity_matches_query(entity, entity_query))
        .cloned()
        .collect();
    let target = choose_entity_match(entities, entity_query)?;
    let revisions = state
        .entity_revisions
        .remove(&target.id)
        .unwrap_or_default();
    Ok((target, revisions))
}

/// Every revision of `entity_id` visible at `head`, oldest first.
///
/// `ChangeStore::get_entity_revisions_at` is not usable here. It replays only
/// the changes that mention this entity, yet validates every delta those
/// changes carry. A change that touches this entity while also modifying or
/// removing a second one is then checked against a state the second entity's
/// own history was filtered out of, so a sound repository answers with a
/// "stale old payload" conflict for an entity nobody asked about, and the
/// command fails before printing a single revision. Replaying the complete
/// first-parent state keeps every delta's precondition checkable, which is the
/// same reason the MCP entity handlers resolve through `resolve_graph_at`.
pub(crate) fn resolve_entity_revisions_at<G>(
    graph: &G,
    entity_id: &EntityId,
    head: &SemanticChangeId,
) -> Result<Vec<EntityRevision>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut state = graph
        .resolve_graph_at(head)
        .map_err(|error| anyhow!(error.to_string()))?;
    Ok(state.entity_revisions.remove(entity_id).unwrap_or_default())
}

#[derive(Debug, Clone, Copy)]
struct ParentHop(usize);

fn split_relative_hops(reference: &str) -> Result<(&str, Vec<ParentHop>)> {
    let mut hops = Vec::new();
    let mut rest = reference;
    while let Some(&last) = rest.as_bytes().last() {
        if last == b'^' || last == b'~' {
            hops.push(ParentHop(1));
            rest = &rest[..rest.len() - 1];
            continue;
        }
        if last.is_ascii_digit() {
            let digits_start = rest
                .rfind(|character: char| !character.is_ascii_digit())
                .map(|index| index + 1)
                .unwrap_or(0);
            if digits_start == 0 {
                break;
            }
            let marker = rest.as_bytes()[digits_start - 1];
            if marker != b'^' && marker != b'~' {
                break;
            }
            let count: usize = rest[digits_start..]
                .parse()
                .map_err(|_| ref_error(reference, "parent index is out of range"))?;
            if marker == b'^' {
                if count == 0 {
                    break;
                }
                hops.push(ParentHop(count));
            } else {
                hops.extend(std::iter::repeat_n(ParentHop(1), count));
            }
            rest = &rest[..digits_start - 1];
            continue;
        }
        break;
    }
    Ok((rest, hops))
}

fn apply_parent_hops<G>(
    graph: &G,
    original: &str,
    mut head: SemanticChangeId,
    hops: &[ParentHop],
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    for hop in hops {
        let change = graph
            .get_change(&head)
            .map_err(|error| anyhow!(error.to_string()))?
            .ok_or_else(|| ref_error(original, format!("change {head} not found in history")))?;
        head = *change.parents.get(hop.0 - 1).ok_or_else(|| {
            ref_error(
                original,
                format!(
                    "{head} has {} parent(s), no parent #{}",
                    change.parents.len(),
                    hop.0
                ),
            )
        })?;
    }
    Ok(head)
}

fn resolve_ref_core<G>(
    graph: &G,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    original: &str,
    core: &str,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if let Some(change_ref) = core
        .strip_prefix("kin:")
        .or_else(|| core.strip_prefix("change:"))
    {
        return resolve_semantic_change(graph, original, change_ref);
    }

    // A full semantic change id is unambiguous when that change is present.
    if core.len() == 64 {
        if let Ok(change_id) = parse_change_id(core) {
            if graph
                .get_change(&change_id)
                .map_err(|error| anyhow!(error.to_string()))?
                .is_some()
            {
                return Ok(change_id);
            }
        }
    }

    let authority = ActiveRepositoryAuthority::open(binding).map_err(|error| {
        ref_error(
            original,
            format!("this repository's authority could not be opened: {error:#}"),
        )
    })?;

    let resolved = if core == "HEAD" {
        authority
            .current_change_id()
            .map_err(|error| {
                ref_error(
                    original,
                    format!("this workspace's head could not be read: {error:#}"),
                )
            })?
            .ok_or_else(|| {
                ref_error(
                    original,
                    "this workspace has no commits yet, so HEAD names nothing; make one with \
                     `kin commit`",
                )
            })?
    } else if let Some(branch_name) = core.strip_prefix("branch:") {
        resolve_named_authority_ref(&authority, original, branch_name)?
    } else if let Some(git_oid) = core.strip_prefix("git:") {
        resolve_imported_git_ref(&authority, original, git_oid)?
    } else if matches!(core.len(), 40 | 64) && core.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        resolve_imported_git_ref(&authority, original, core)?
    } else if is_abbreviated_git_hex(core) {
        return Err(ref_error(
            original,
            format!(
                "Git commit prefix '{core}' cannot be resolved from exact alias authority; use a full object ID"
            ),
        ));
    } else {
        resolve_named_authority_ref(&authority, original, core)?
    };

    if graph
        .get_change(&resolved)
        .map_err(|error| anyhow!(error.to_string()))?
        .is_none()
    {
        return Err(ref_error(
            original,
            format!(
                "this repository's authority resolves to semantic change {resolved}, which the \
                 active graph projection does not hold; run `kin status`, then `kin health` if it \
                 repeats"
            ),
        ));
    }
    Ok(resolved)
}

fn resolve_named_authority_ref(
    authority: &ActiveRepositoryAuthority,
    original: &str,
    value: &str,
) -> Result<SemanticChangeId> {
    let name = parse_ref_name(value)
        .map_err(|error| ref_error(original, format!("invalid repository ref: {error:#}")))?;
    authority
        .resolve_named_ref(&name)
        .map_err(|error| ref_error(original, error.to_string()))
}

fn resolve_imported_git_ref(
    authority: &ActiveRepositoryAuthority,
    original: &str,
    value: &str,
) -> Result<SemanticChangeId> {
    let oid = parse_git_object_id(value)
        .map_err(|error| ref_error(original, format!("invalid Git object ID: {error:#}")))?;
    authority
        .resolve_git_oid(&oid)
        .map_err(|error| ref_error(original, error.to_string()))
}

fn resolve_semantic_change<G>(graph: &G, original: &str, value: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let change_id =
        parse_change_id(value).map_err(|error| ref_error(original, error.to_string()))?;
    if graph
        .get_change(&change_id)
        .map_err(|error| anyhow!(error.to_string()))?
        .is_some()
    {
        Ok(change_id)
    } else {
        Err(ref_error(
            original,
            format!("change {change_id} not found in graph authority"),
        ))
    }
}

fn is_abbreviated_git_hex(value: &str) -> bool {
    (4..40).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn choose_entity_match(mut entities: Vec<Entity>, entity_query: &str) -> Result<Entity> {
    if entities.is_empty() {
        bail!("No entity matching '{entity_query}' found.");
    }

    entities.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
    });
    if let Some(exact) = entities
        .iter()
        .find(|entity| entity.id.to_string() == entity_query || entity.name == entity_query)
    {
        return Ok(exact.clone());
    }
    if let Some(case_insensitive) = entities
        .iter()
        .find(|entity| entity.name.eq_ignore_ascii_case(entity_query))
    {
        return Ok(case_insensitive.clone());
    }
    match entities.as_slice() {
        [entity] => Ok(entity.clone()),
        many => {
            let preview = many
                .iter()
                .take(5)
                .map(|entity| entity.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!("Multiple entities match '{entity_query}': {preview}. Use a more exact name.")
        }
    }
}

fn entity_matches_query(entity: &Entity, entity_query: &str) -> bool {
    entity.id.to_string() == entity_query || name_matches_pattern(&entity.name, entity_query)
}

fn name_matches_pattern(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();
    if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name.contains(&pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use kin_db::LocalFileBackend;
    use kin_model::{AuthorId, ChangeOrigin, ChangeStore, SemanticChange, Timestamp};

    /// Build a change whose declared identity matches its immutable payload.
    ///
    /// Repository authority rejects a change whose id does not recompute from
    /// its own content, so the identity is derived rather than invented.
    fn change(parents: Vec<SemanticChangeId>) -> SemanticChange {
        let mut change = change_with_id(change_id(0), parents);
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn named_entity(name: &str) -> Entity {
        use kin_model::{
            EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
            Hash256, LanguageId, SemanticFingerprint, Visibility,
        };
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
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
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

    /// `resolve_entity_query` sweeps the whole graph when the store-side name
    /// filter comes back unusable. That sweep must still be narrowed to the
    /// query. It previously was not, so `choose_entity_match` received every
    /// entity in the repo and reported the first five alphabetically as
    /// "matches" — `kin history alwaysTrue` answered "Multiple entities match
    /// 'alwaysTrue': AND_THEN, AND_WHEN, ANON_TEST_CASE, Approx", none of which
    /// contain the query.
    #[test]
    fn whole_graph_fallback_stays_narrowed_to_the_query() {
        use kin_model::EntityStore;
        let graph = kin_db::InMemoryGraph::new();
        for name in [
            "AND_THEN",
            "AND_WHEN",
            "ANON_TEST_CASE",
            "Approx",
            "alwaysTrue",
            "alwaysFalse",
        ] {
            graph.upsert_entity(&named_entity(name)).unwrap();
        }

        let resolved = resolve_entity_query(&graph, "alwaysTrue")
            .expect("an exact name present in the graph must resolve");
        assert_eq!(resolved.name, "alwaysTrue");

        let err = resolve_entity_query(&graph, "definitely_not_here")
            .expect_err("a query matching nothing must fail");
        let message = err.to_string();
        assert!(
            !message.contains("AND_THEN") && !message.contains("Approx"),
            "an unmatched query must not list unrelated entities as matches, got: {message}"
        );
    }

    fn change_with_id(id: SemanticChangeId, parents: Vec<SemanticChangeId>) -> SemanticChange {
        SemanticChange {
            id,
            origin: ChangeOrigin::Native,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "test change".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        }
    }

    fn change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    /// One version of an entity. `marker` varies the fingerprint so two
    /// versions of the same entity are distinguishable revisions.
    fn entity_version(id: EntityId, name: &str, marker: u8) -> Entity {
        let mut entity = named_entity(name);
        entity.id = id;
        entity.fingerprint.ast_hash = Hash256::from_bytes([marker; 32]);
        entity.signature = format!("fn {name}(v{marker})");
        entity
    }

    fn change_with_deltas(
        parents: Vec<SemanticChangeId>,
        deltas: Vec<kin_model::EntityDelta>,
    ) -> SemanticChange {
        let mut change = change_with_id(change_id(0), parents);
        change.entity_deltas = deltas;
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        change
    }

    /// `kin history <entity>` and `kin blame <entity>` with no `--ref` resolve
    /// the entity from the live graph and its revisions from committed state at
    /// head, so this helper is the whole revision path for the default
    /// invocation. It must survive a change that touches the queried entity
    /// alongside a second one whose own introducing change does not mention the
    /// queried entity: deriving revisions from the entity-filtered change list
    /// validated that second entity against a state it was never added to, and
    /// answered a query about `alpha` with a stale-payload conflict naming
    /// `beta`.
    #[test]
    fn revisions_survive_a_change_that_also_removes_another_entity() {
        let graph = kin_db::InMemoryGraph::new();
        let alpha = kin_model::EntityId::new();
        let beta = kin_model::EntityId::new();
        let gamma = kin_model::EntityId::new();

        let add_alpha = change_with_deltas(
            Vec::new(),
            vec![kin_model::EntityDelta::Added {
                new: entity_version(alpha, "alpha", 1),
            }],
        );
        let add_beta = change_with_deltas(
            vec![add_alpha.id],
            vec![kin_model::EntityDelta::Added {
                new: entity_version(beta, "beta", 1),
            }],
        );
        let revise_alpha = change_with_deltas(
            vec![add_beta.id],
            vec![
                kin_model::EntityDelta::Modified {
                    old: entity_version(alpha, "alpha", 1),
                    new: entity_version(alpha, "alpha", 2),
                },
                kin_model::EntityDelta::Removed {
                    old: entity_version(beta, "beta", 1),
                },
                kin_model::EntityDelta::Added {
                    new: entity_version(gamma, "gamma", 1),
                },
            ],
        );
        for entry in [&add_alpha, &add_beta, &revise_alpha] {
            graph.create_change(entry).unwrap();
        }

        let revisions = resolve_entity_revisions_at(&graph, &alpha, &revise_alpha.id)
            .expect("a sound history must not report a conflict for an unqueried entity");

        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_alpha.id);
        assert_eq!(revisions[0].ended_by, Some(revise_alpha.id));
        assert_eq!(revisions[1].introduced_by, revise_alpha.id);
        assert_eq!(revisions[1].ended_by, None);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert!(
            !revisions
                .iter()
                .any(|revision| revision.introduced_by == add_beta.id),
            "a change that never touches alpha is not a revision of alpha"
        );
    }

    fn absent_binding(layout: &kin_core::KinLayout) -> kin_core::LocalRepositoryAuthorityBinding {
        kin_core::LocalRepositoryAuthorityBinding::from_parts(
            kin_model::RepositoryId::new("absent-ref-lookup").unwrap(),
            kin_model::WorkspaceId::new(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
    }

    #[test]
    fn explicit_semantic_change_and_parent_hops_need_no_file_or_git_fallback() {
        let graph = kin_db::InMemoryGraph::new();
        let parent_change = change(Vec::new());
        let head_change = change(vec![parent_change.id]);
        let parent = parent_change.id;
        let head = head_change.id;
        graph.create_change(&parent_change).unwrap();
        graph.create_change(&head_change).unwrap();
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
        let binding = absent_binding(&layout);

        assert_eq!(
            resolve_ref(&graph, &binding, Some(&format!("kin:{head}^"))).unwrap(),
            parent
        );
    }

    #[test]
    fn head_without_repository_authority_is_a_classified_failure() {
        let graph = kin_db::InMemoryGraph::new();
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
        let binding = absent_binding(&layout);
        let error = resolve_ref(&graph, &binding, None).unwrap_err();
        assert!(is_ref_resolution_error(&error));
        assert!(
            error.to_string().contains("this repository's authority"),
            "the layout version is not a noun the reader has: {error:#}"
        );
    }

    #[test]
    fn full_git_oid_is_not_converted_into_a_synthetic_change_id() {
        let graph = kin_db::InMemoryGraph::new();
        let directory = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(directory.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout)
            .expect("fixture must carry persisted empty repository authority");
        let error = resolve_ref(
            &graph,
            &binding,
            Some("1111111111111111111111111111111111111111"),
        )
        .unwrap_err();
        assert!(is_ref_resolution_error(&error));
        // The object ID must reach exact alias authority and be refused there.
        // Silently widening it into a semantic change id would invent history.
        assert!(
            error
                .to_string()
                .contains("was never imported into this repository"),
            "{error:#}"
        );
    }
}
