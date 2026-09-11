// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use kin_model::{Entity, EntityId, EntityRevision, GraphStore, SemanticChangeId};

use super::ref_grammar::AuthorityOpen;
use super::repository_authority::RequestRepositoryAuthority;
use crate::entity_identity::{EntityPointer, EntityResolution, IdentityQualifiers, PinSpelling};

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

/// A query that named no one entity, and the answer that says why.
///
/// Typed so the daemon answers it as the caller's news rather than as an
/// internal fault: the graph is sound, and the question needs a name the graph
/// holds or a pin that picks one entity out of several.
#[derive(Debug)]
pub struct EntityQueryRefusal {
    /// What the query reached and how to name one entity, ready to print.
    pub lines: Vec<String>,
    /// Whether the name reached nothing at all, rather than several entities or
    /// entities every pin excluded.
    pub absent: bool,
}

impl std::fmt::Display for EntityQueryRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.lines.join("\n"))
    }
}

impl std::error::Error for EntityQueryRefusal {}

/// The refusal inside an error, for a handler classifying it.
pub fn entity_query_refusal(error: &anyhow::Error) -> Option<&EntityQueryRefusal> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<EntityQueryRefusal>())
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

/// A ref resolved for blame or history, and what reaching authority cost.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedHead {
    pub(crate) change_id: SemanticChangeId,
    /// Set when an arm of the grammar had to reach repository authority.
    pub(crate) authority_open: Option<AuthorityOpen>,
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
    let authority = RequestRepositoryAuthority::pinned(binding.clone());
    resolve_ref_through(graph, &authority, reference).map(|head| head.change_id)
}

/// [`resolve_ref`] through whatever authority the caller has.
///
/// The daemon's blame and history routes pass the authority it keeps for the
/// current publication, so resolving `HEAD` costs a request nothing that grows
/// with the store. Each request used to open the whole repository authority
/// from disk for itself, decoding and re-verifying every persisted body to read
/// one workspace pointer.
pub(crate) fn resolve_ref_through<G>(
    graph: &G,
    authority: &RequestRepositoryAuthority,
    reference: Option<&str>,
) -> Result<ResolvedHead>
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
    let deferred = super::ref_grammar::Authority::deferred(authority);
    let resolved = super::ref_grammar::resolve(&deferred, graph, reference)
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
    Ok(ResolvedHead {
        change_id: resolved.change_id,
        authority_open: deferred.open_cost(),
    })
}

/// The line an answer ends with when resolving its ref opened the whole store
/// on the thread that built it, which is the one step whose cost follows the
/// size of the store rather than the question.
///
/// Silent otherwise. A daemon handing over the authority it already holds for
/// the current publication cost the answer nothing worth naming, and neither did
/// a selector the graph answered alone.
pub(crate) fn authority_open_line(open: Option<AuthorityOpen>) -> Option<String> {
    let open = open.filter(|open| open.opened_here)?;
    let seconds = open.waited.as_secs_f64();
    Some(if open.shared {
        format!(
            "Answered by: this repository's daemon, which opened repository authority for its \
             current publication to answer this ({seconds:.1} s, re-verifying every persisted \
             body); later reads at this publication reuse that open."
        )
    } else {
        format!(
            "Answered by: a repository-authority open made for this answer alone ({seconds:.1} \
             s, re-verifying every persisted body); the daemon serving this repository answers \
             from one open per publication instead."
        )
    })
}

/// The notes a blame or history answer ends with: the stale-span note when a
/// location it printed is marked, then the open line when resolving its ref
/// opened the store on this thread.
pub(crate) fn closing_notes(lines: &[String], open: Option<AuthorityOpen>) -> Vec<String> {
    crate::entity_identity::stale_span_note(lines)
        .into_iter()
        .chain(authority_open_line(open))
        .collect()
}

/// The first non-empty line of a commit message. Git calls this the subject and
/// renders exactly this in `--oneline`; the body belongs in a detail view, not
/// in a one-row-per-revision list. Blame and history both print it, from here,
/// so the two cannot disagree about what a change is called.
pub(crate) fn subject_line(message: &str) -> String {
    message
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no message)")
        .to_string()
}

/// ` @ path:line` for an answer's header, or nothing for an entity with no file.
pub(crate) fn pointer_suffix(pointer: &EntityPointer) -> String {
    if pointer.path.is_some() {
        format!(" @ {}", pointer.render())
    } else {
        String::new()
    }
}

/// The entity a blame or history answer is about, with what the answer prints
/// before its rows.
pub(crate) struct EntityTimeline {
    pub(crate) target: Entity,
    /// Every revision of `target` on the lineage reaching the head, oldest first.
    pub(crate) revisions: Vec<EntityRevision>,
    /// Where the entity starts, checked against the tree it was read from.
    pub(crate) pointer: EntityPointer,
    /// Every candidate and how to pin another, when the query reached several.
    pub(crate) choice: Vec<String>,
}

/// Resolve `entity_query` at `head` and read its revisions there.
///
/// Without `--ref` the entity comes from the live graph, through the resolver
/// every read command shares, so `kin blame` and `kin history` answer about the
/// entity `kin refs` and `kin impact` answer about for the same name and pins.
/// With `--ref` it comes from the state replayed at that ref, because a name can
/// have meant a different entity then, or one since removed. The same pins,
/// narrowing and ranking apply there, with dependents read from the replayed
/// relations and locations checked against the replayed tree.
pub(crate) fn resolve_entity_timeline<G>(
    graph: &G,
    entity_query: &str,
    head: &SemanticChangeId,
    reference: Option<&str>,
) -> Result<EntityTimeline>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if reference.is_none() {
        let resolution = crate::entity_identity::resolve_entity(
            graph,
            entity_query,
            &IdentityQualifiers::default(),
        )?;
        let locate = |entity: &Entity| crate::entity_identity::entity_location(graph, entity);
        let target = chosen_or_refused(&resolution, locate)?;
        let revisions = resolve_entity_revisions_at(graph, &target.id, head, None)?;
        return Ok(EntityTimeline {
            pointer: crate::entity_identity::entity_pointer(graph, &target),
            choice: crate::entity_identity::choice_note_by(
                &resolution,
                PinSpelling::FileKind,
                locate,
            ),
            target,
            revisions,
        });
    }

    let mut state = graph
        .resolve_graph_at(head)
        .map_err(|error| projection_error(reference, head, error))?;
    let depended_on: HashSet<EntityId> = state
        .relations
        .values()
        .filter_map(crate::entity_identity::depended_on_by)
        .collect();
    let resolution = crate::entity_identity::resolve_entity_among(
        state.entities.values(),
        entity_query,
        &IdentityQualifiers::default(),
        |entity| Ok(depended_on.contains(&entity.id)),
    )?;
    let tree = &state.tree;
    let locate =
        |entity: &Entity| crate::entity_identity::entity_pointer_in_tree(tree, entity).render();
    let target = chosen_or_refused(&resolution, locate)?;
    let pointer = crate::entity_identity::entity_pointer_in_tree(tree, &target);
    let choice = crate::entity_identity::choice_note_by(&resolution, PinSpelling::FileKind, locate);
    let revisions = state
        .entity_revisions
        .remove(&target.id)
        .unwrap_or_default();
    Ok(EntityTimeline {
        target,
        revisions,
        pointer,
        choice,
    })
}

/// The entity a resolution chose, or the refusal that says why it chose none.
///
/// A partial name reaching several entities and a pin excluding every entity a
/// name reaches are answered with the same lines `kin refs` and `kin impact`
/// print, so an answer never guesses and never calls an entity absent that the
/// graph holds.
fn chosen_or_refused(
    resolution: &EntityResolution,
    locate: impl Fn(&Entity) -> String + Copy,
) -> Result<Entity> {
    let refusal = if resolution.name_matches.is_empty() {
        EntityQueryRefusal {
            lines: vec![format!(
                "No entity matching '{}' found.",
                resolution.reference.name
            )],
            absent: true,
        }
    } else if resolution.pin_excluded_all() {
        EntityQueryRefusal {
            lines: crate::entity_identity::pin_miss_lines_by(resolution, locate),
            absent: false,
        }
    } else if resolution.needs_a_pin() {
        EntityQueryRefusal {
            lines: crate::entity_identity::pin_request_lines_by(resolution, locate),
            absent: false,
        }
    } else {
        return resolution.chosen().cloned().ok_or_else(|| {
            anyhow!(
                "resolving '{}' produced no candidate",
                resolution.reference.name
            )
        });
    };
    Err(anyhow::Error::new(refusal))
}

/// Every revision of `entity_id` on the lineage reaching `head`, oldest first.
///
/// kin-model's `ChangeStore::get_entity_revisions_at` reads the complete
/// first-parent history and applies only this entity's deltas, so every change
/// is read against the state its parent published, and a change that also
/// modifies or removes another entity is skipped for that entity rather than
/// checked against a state its history was filtered out of. The whole-graph
/// replay this used to run derived every entity and relation in the repository,
/// swept every live relation after every change and replayed the tree, to keep
/// one entity's list. The rows are the same, because a revision id is minted
/// from the entity id and the change that introduced it; the replay's cost grew
/// with the whole repository's history on every call.
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
    graph
        .get_entity_revisions_at(entity_id, head)
        .map_err(|error| projection_error(reference, head, error))
}

/// What an answer says when the entity it resolved has no revision on the line
/// of history it read.
///
/// Never a bare "No history recorded". The answer names the entity it looked
/// at, the ref, and which empty case this is, because each has a different next
/// step. A function with sixteen callers answered "No history recorded for this
/// entity." and nothing else, which reads like code that was never committed.
pub(crate) fn empty_history_lines(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    pointer: &EntityPointer,
    head: &SemanticChangeId,
    reference: Option<&str>,
) -> Result<Vec<String>> {
    let kind = kin_review::StableEntityIdentity::from_entity(target).kind;
    let line = reference.unwrap_or("HEAD");
    let mut lines = vec![format!(
        "  No history recorded for {kind} '{}'{} (entity {}) on the line of history reaching \
         {line}.",
        target.name,
        pointer_suffix(pointer),
        target.id
    )];
    if reference.is_some() {
        // A `--ref` entity comes from the state replayed at that ref, and the
        // replay mints a revision for every entity it adds, so an empty list
        // there is a gap in that replay rather than one of the cases below.
        lines.push(
            "  The state replayed at that ref holds this entity without the revision that added \
             it."
            .to_string(),
        );
        return Ok(lines);
    }
    let case = if graph.latest_revision_id_for(&target.id).is_some() {
        "  Changes in this store record this entity, but none is on the first-parent line \
         reaching HEAD, so its history is on another line of history, such as a branch or the \
         side of a merge."
            .to_string()
    } else if let Some(recorded) = committed_twin_on_line(graph, target, head)? {
        format!(
            "  Committed history on that line records {kind} '{}' in {} under entity {recorded}, \
             a different id from the one the live graph holds, so the two share no history. This \
             is a graph gap. `kin history {recorded} --ref HEAD` reads the committed one.",
            target.name,
            target
                .file_origin
                .as_ref()
                .map(|file| file.0.as_str())
                .unwrap_or("its file"),
        )
    } else {
        "  No change in this store records this entity id. That is how an entity admitted from \
         the working tree since the last commit looks, and `kin commit` records it."
            .to_string()
    };
    lines.push(case);
    Ok(lines)
}

/// The newest entity id that committed history on `head`'s first-parent line
/// records under `target`'s file, kind and name, other than `target`'s own.
///
/// Walked newest first, so the answer is the version that line holds at
/// `head`, and an id the walk has already seen removed is never reported as
/// held. Only an answer that is already empty pays for the walk.
fn committed_twin_on_line<G>(
    graph: &G,
    target: &Entity,
    head: &SemanticChangeId,
) -> Result<Option<EntityId>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let Some(file) = target.file_origin.as_ref() else {
        return Ok(None);
    };
    let mut removed = HashSet::new();
    let mut walked = HashSet::new();
    let mut current = Some(*head);
    while let Some(change_id) = current {
        if !walked.insert(change_id) {
            break;
        }
        let Some(change) = graph
            .get_change(&change_id)
            .map_err(|error| anyhow!(error.to_string()))?
        else {
            break;
        };
        for delta in change.entity_deltas.iter().rev() {
            let (entity, gone) = match delta {
                kin_model::EntityDelta::Added { new }
                | kin_model::EntityDelta::Modified { new, .. } => (new, false),
                kin_model::EntityDelta::Removed { old } => (old, true),
            };
            if entity.id == target.id
                || entity.name != target.name
                || entity.kind != target.kind
                || entity.file_origin.as_ref() != Some(file)
            {
                continue;
            }
            if gone {
                removed.insert(entity.id);
            } else if !removed.contains(&entity.id) {
                return Ok(Some(entity.id));
            }
        }
        current = change.parents.first().copied();
    }
    Ok(None)
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

    /// A name that reaches nothing is refused with its own name, never with a
    /// list of unrelated entities. The whole-graph sweep this module used to run
    /// handed its matcher an unfiltered graph, so `kin history alwaysTrue` once
    /// answered "Multiple entities match 'alwaysTrue': AND_THEN, AND_WHEN,
    /// ANON_TEST_CASE, Approx", none of which contain the query.
    #[test]
    fn a_query_that_reaches_nothing_is_refused_with_its_own_name() {
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
        let locate = |entity: &Entity| crate::entity_identity::entity_location(&graph, entity);
        let resolve = |query: &str| {
            crate::entity_identity::resolve_entity(&graph, query, &IdentityQualifiers::default())
                .unwrap()
        };

        let chosen = chosen_or_refused(&resolve("alwaysTrue"), locate)
            .expect("an exact name present in the graph must resolve");
        assert_eq!(chosen.name, "alwaysTrue");

        let error = chosen_or_refused(&resolve("definitely_not_here"), locate)
            .expect_err("a query matching nothing must be refused");
        let refusal =
            entity_query_refusal(&error).expect("the refusal must be typed for the daemon");
        assert!(refusal.absent, "nothing matched, so the entity is absent");
        let message = error.to_string();
        assert!(message.contains("definitely_not_here"), "{message}");
        assert!(
            !message.contains("AND_THEN") && !message.contains("Approx"),
            "an unmatched query must not list unrelated entities, got: {message}"
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

    /// The shared arm is handed the authority its server already holds and
    /// never opens the store on the resolving thread, the pinned arm opens for
    /// itself, and a graph-only selector reaches for neither.
    ///
    /// The per-thread open counter is the bound, because an open's cost is a
    /// property of the store rather than of the request: a timing assertion on
    /// a fixture this small would pass with every request reopening.
    #[test]
    fn a_shared_authority_is_handed_over_rather_than_reopened() {
        use crate::commands::repository_authority::{
            repository_authority_opens_on_this_thread, ActiveRepositoryAuthority,
            RequestRepositoryAuthority,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(directory.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout)
            .expect("fixture must carry persisted empty repository authority");
        let held = Arc::new(ActiveRepositoryAuthority::open(&binding).unwrap());
        let handed_over = Arc::new(AtomicUsize::new(0));
        let shared = RequestRepositoryAuthority::shared(binding.clone(), {
            let held = Arc::clone(&held);
            let handed_over = Arc::clone(&handed_over);
            Arc::new(move || {
                handed_over.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::clone(&held))
            })
        });
        let graph = kin_db::InMemoryGraph::new();

        // HEAD reads authority. This store has no commit, so HEAD names nothing
        // and the answer is a refusal; what reaching authority cost is the
        // property under test.
        let opens = repository_authority_opens_on_this_thread();
        let error = resolve_ref_through(&graph, &shared, None)
            .expect_err("an unborn workspace has no HEAD");
        assert!(is_ref_resolution_error(&error), "{error:#}");
        assert_eq!(
            handed_over.load(Ordering::SeqCst),
            1,
            "HEAD must ask the server for the authority it holds"
        );
        assert_eq!(
            repository_authority_opens_on_this_thread(),
            opens,
            "the shared arm must not open the store on this thread"
        );

        // An explicit change is graph-owned truth and reaches for nothing.
        let explicit = change(Vec::new());
        graph.create_change(&explicit).unwrap();
        let head = resolve_ref_through(&graph, &shared, Some(&format!("kin:{}", explicit.id)))
            .expect("an explicit change the graph holds resolves");
        assert_eq!(head.change_id, explicit.id);
        assert_eq!(head.authority_open, None);
        assert_eq!(
            handed_over.load(Ordering::SeqCst),
            1,
            "a graph-only selector must not ask for authority"
        );

        // The control: the pinned arm opens for itself, so the bound above is
        // one that could have moved.
        let _ = resolve_ref_through(&graph, &RequestRepositoryAuthority::pinned(binding), None);
        assert_eq!(
            repository_authority_opens_on_this_thread(),
            opens + 1,
            "the pinned arm opens the store once"
        );
    }

    /// An answer names an open only when its own thread paid for one, and says
    /// whether a daemon now holds it for the next read.
    #[test]
    fn an_answer_names_an_open_only_when_its_thread_paid_for_one() {
        let open = |opened_here, shared| {
            Some(AuthorityOpen {
                waited: std::time::Duration::from_millis(58_200),
                opened_here,
                shared,
            })
        };
        assert_eq!(authority_open_line(None), None);
        assert_eq!(
            authority_open_line(open(false, true)),
            None,
            "an authority handed over costs the answer nothing worth naming"
        );
        let daemon = authority_open_line(open(true, true)).unwrap();
        assert!(
            daemon.contains("58.2 s") && daemon.contains("later reads at this publication reuse"),
            "{daemon}"
        );
        let alone = authority_open_line(open(true, false)).unwrap();
        assert!(
            alone.contains("58.2 s") && alone.contains("for this answer alone"),
            "{alone}"
        );
    }

    /// An empty history says which empty case it is. An entity recorded only
    /// off HEAD's first-parent line, one committed history holds under another
    /// id, and one no change records at all each get their own answer, and none
    /// of them is the bare line.
    #[test]
    fn an_empty_history_says_which_empty_case_it_is() {
        use kin_model::EntityStore;
        let graph = kin_db::InMemoryGraph::new();
        let side = named_entity("side_helper");
        let fresh = named_entity("fresh_helper");
        let committed = named_entity("gapped");
        let mut regapped = committed.clone();
        regapped.id = EntityId::new();

        let root = change_with_deltas(Vec::new(), Vec::new());
        let on_side = change_with_deltas(
            vec![root.id],
            vec![kin_model::EntityDelta::Added { new: side.clone() }],
        );
        let head = change_with_deltas(
            vec![root.id],
            vec![kin_model::EntityDelta::Added {
                new: committed.clone(),
            }],
        );
        for entry in [&root, &on_side, &head] {
            graph.create_change(entry).unwrap();
        }
        for entity in [&side, &fresh, &regapped] {
            graph.upsert_entity(entity).unwrap();
        }
        let answer = |entity: &Entity| {
            let pointer = crate::entity_identity::entity_pointer(&graph, entity);
            empty_history_lines(&graph, entity, &pointer, &head.id, None)
                .unwrap()
                .join("\n")
        };

        let elsewhere = answer(&side);
        assert!(
            elsewhere.contains(&side.id.to_string()) && elsewhere.contains("reaching HEAD"),
            "the answer names the entity and the ref it read: {elsewhere}"
        );
        assert!(
            elsewhere.contains("none is on the first-parent line"),
            "an entity recorded only off HEAD's line must say so: {elsewhere}"
        );

        let gap = answer(&regapped);
        assert!(
            gap.contains(&format!("kin history {} --ref HEAD", committed.id)),
            "a graph gap names the id committed history holds: {gap}"
        );

        let unrecorded = answer(&fresh);
        assert!(
            unrecorded.contains("No change in this store records this entity id"),
            "an entity no change records must say so: {unrecorded}"
        );
        for text in [&elsewhere, &gap, &unrecorded] {
            assert!(
                !text.contains("No history recorded for this entity."),
                "never the bare line: {text}"
            );
        }
    }
}
