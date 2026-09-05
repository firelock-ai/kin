// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Result};
use kin_model::{Entity, EntityFilter, EntityId, EntityRevision, GraphStore, SemanticChangeId};

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

/// The graph cannot replay to a change the caller already resolved.
///
/// Distinct from `RefResolutionError`, which is a bad ref. Here the ref was
/// fine: it resolved to a real change that `kin log`, `kin diff` and
/// `kin git export` all hold. What failed is replaying the live graph to it.
///
/// It exists because the failure had no type. Both replay sites wrapped their
/// error with `anyhow!(error.to_string())`, which flattens a
/// `ModelError::ChangeNotFound` into a bare string, so the daemon's handler
/// could not classify it and fell through to a 500 carrying the RESOLVED change
/// id rather than the ref the user typed. That is why every ref form reported
/// the same id on the rc062j stranger run: they all resolve to the same tip and
/// the failure is downstream of resolution.
#[derive(Debug)]
pub struct GraphProjectionError {
    pub reference: String,
    pub resolved: String,
    pub reason: String,
}

impl std::fmt::Display for GraphProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "ref '{}' resolves to semantic change {}, which this daemon's live graph \
             projection does not hold, so its history cannot be replayed; durable history \
             is intact and `kin log` and `kin diff` still read it. Restart the repository \
             daemon with `kin daemon stop` and run the command again. Underlying cause: {}",
            self.reference, self.resolved, self.reason
        )
    }
}

impl std::error::Error for GraphProjectionError {}

/// Wrap a replay failure so it carries what the user asked for.
///
/// Unconditional at the replay sites rather than keyed on the inner cause,
/// because the bound on `GraphStore::Error` is `Display` only, so the concrete
/// type is not visible there. Matching the message text would be a string
/// comparison against another crate's wording. Every failure of a replay to an
/// ALREADY-RESOLVED head means one user-facing thing regardless of its cause,
/// which is what this says.
fn projection_error(
    reference: Option<&str>,
    resolved: &SemanticChangeId,
    reason: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(GraphProjectionError {
        reference: reference.unwrap_or("HEAD").to_string(),
        resolved: resolved.to_string(),
        reason: reason.to_string(),
    })
}

/// Split revisions into those that changed THIS entity and those that did not.
///
/// Returns `(own, withheld)`, oldest first, `own` always including the entity's
/// introduction.
///
/// THE one rule, so blame and history cannot drift into disagreeing about which
/// revisions are the entity's own. Two implementations of this would be two
/// answers to the same question, and the one nobody reads would be the wrong one.
///
/// Why the over-report exists, and why the fix belongs here rather than in the
/// minting: `reconciler.rs` stamps the whole FILE's blob hash into every
/// entity's `metadata.extra`, and commit compares the complete `Entity`, so
/// every entity in a touched file compares unequal and mints a revision. Span
/// shifts do it a second way. That behaviour is pinned deliberately by
/// `commit_publishes_an_entity_whose_provenance_moved_without_its_fingerprint`,
/// and the revisions it mints are real: they are what the file did. What was
/// wrong is reporting them as changes to an entity that did not change.
///
/// The discriminator is [`kin_core::workspace_semantics::entity_content_agrees`],
/// which is the fleet's ONE answer to "did this entity itself change" and is
/// what `kin conflicts`, `kin diff` and `kin log` now ask too. It is not
/// touched by the `metadata.extra` stamp or by a span shift, so an entity whose
/// own text did not move compares equal across a file-level revision.
pub(crate) fn split_own_revisions(
    revisions: &[EntityRevision],
) -> (Vec<EntityRevision>, Vec<EntityRevision>) {
    let mut own = Vec::new();
    let mut withheld = Vec::new();
    let mut last: Option<Entity> = None;
    for revision in revisions {
        match last.as_ref() {
            // The introduction is always the entity's own: there is nothing
            // before it for its text to be unchanged FROM.
            None => {
                own.push(revision.clone());
                last = Some(revision.entity.clone());
            }
            Some(previous)
                if kin_core::workspace_semantics::entity_content_agrees(
                    previous,
                    &revision.entity,
                ) =>
            {
                withheld.push(revision.clone())
            }
            Some(_) => {
                own.push(revision.clone());
                last = Some(revision.entity.clone());
            }
        }
    }
    (own, withheld)
}

/// The line naming what a trimmed listing did not show.
///
/// Named rather than silent. The withheld revisions are real, they are what the
/// file did, and a reader who cannot see that they exist has lost information
/// rather than been spared noise.
pub(crate) fn withheld_line(withheld: usize) -> Option<String> {
    if withheld == 0 {
        return None;
    }
    let plural = if withheld == 1 { "" } else { "s" };
    Some(format!(
        "{withheld} file-level revision{plural} did not change this entity; \
         --all-revisions lists them"
    ))
}

/// Whether an error is a live-graph replay miss, for a handler classifying it.
pub fn is_graph_projection_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<GraphProjectionError>().is_some())
}

pub fn is_ref_resolution_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<RefResolutionError>().is_some())
}

/// Resolve a ref for `kin blame --ref` and `kin history --ref`.
///
/// The grammar itself lives in [`super::ref_grammar`], which `kin diff` calls
/// too. Before FIR-3015 this function owned a second parser, and the two drifted
/// until `kin history` was printing change ids `kin diff` would not take back.
///
/// What stays here is what is particular to these two surfaces: they answer from
/// a graph projection the daemon holds, so a ref that resolves through authority
/// to a change the projection does not carry is a distinct condition with its
/// own remedy, and it is reported as one.
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
    // Deferred rather than opened here. An explicit `kin:<id>` or `change:<id>`
    // is graph-owned truth and resolves without repository authority at all;
    // opening it eagerly turned that into a hard requirement and broke
    // `explicit_semantic_change_and_parent_hops_need_no_file_or_git_fallback`,
    // which is pinning exactly the right thing.
    let authority = super::ref_grammar::Authority::deferred(binding);
    let resolved = super::ref_grammar::resolve(&authority, graph, reference)
        .map_err(|error| ref_error(reference, format!("{error:#}")))?;

    if graph
        .get_change(&resolved.change_id)
        .map_err(|error| anyhow!(error.to_string()))?
        .is_none()
    {
        return Err(ref_error(
            reference,
            format!(
                "this repository's authority resolves to semantic change {}, which the active \
                 graph projection does not hold; run `kin status`, then `kin doctor` if it repeats",
                resolved.change_id
            ),
        ));
    }
    Ok(resolved.change_id)
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
    reference: Option<&str>,
) -> Result<(Entity, Vec<EntityRevision>)>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut state = graph
        .resolve_graph_at(head)
        .map_err(|error| projection_error(reference, head, error))?;
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
    reference: Option<&str>,
) -> Result<Vec<EntityRevision>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut state = graph
        .resolve_graph_at(head)
        .map_err(|error| projection_error(reference, head, error))?;
    Ok(state.entity_revisions.remove(entity_id).unwrap_or_default())
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
    use kin_model::{AuthorId, ChangeOrigin, ChangeStore, Hash256, SemanticChange, Timestamp};

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

        let revisions = resolve_entity_revisions_at(&graph, &alpha, &revise_alpha.id, None)
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
