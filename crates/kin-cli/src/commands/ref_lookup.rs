// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Context, Result};
use kin_model::{BranchName, ChangeStore, Entity, EntityFilter, GraphStore};
use kin_model::{Hash256, SemanticChangeId};

/// A reference did not resolve to a semantic change — unknown ref syntax, a
/// ref that legitimately does not exist, or a relative-ref hop (`^N`/`~N`)
/// that runs past the start of history.
///
/// Distinguished from other failure modes (graph/backend faults) so callers
/// can report it as a client-input error (e.g. HTTP 400) rather than an
/// internal server error, without matching on message text.
#[derive(Debug)]
pub struct RefResolutionError {
    reference: String,
    reason: String,
}

impl std::fmt::Display for RefResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
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

/// True when `err` is, or wraps via added context, a [`RefResolutionError`].
/// Lets callers outside this crate classify a failure as a client-input
/// problem (bad ref) without depending on `anyhow` themselves or matching on
/// message text — they only need to name the error type, which they can
/// reach through their existing dependency on this crate.
pub fn is_ref_resolution_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<RefResolutionError>().is_some())
}

pub(crate) fn parse_change_id(input: &str) -> Result<SemanticChangeId> {
    Ok(SemanticChangeId::from_hash(
        Hash256::from_hex(input).map_err(|err| anyhow!("invalid change hash: {}", err))?,
    ))
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedRef {
    pub head: SemanticChangeId,
    /// Whether resolving this ref lazily imported Git ancestry into the graph.
    /// Derived from `hydrated_changes > 0`; kept for callers that only need
    /// the yes/no signal.
    pub hydrated_git_history: bool,
    /// Count of historical changes hydration actually inserted into the
    /// graph (0 when the ref was already present and no import ran). Distinct
    /// from `hydrated_git_history`: a caller reporting on hydration should
    /// show this count rather than collapse it to a boolean.
    pub hydrated_changes: usize,
}

/// A ref-resolution attempt separated from the mutation owner's publication
/// boundary.
///
/// Hydrating a Git ref can successfully insert its ancestry and then fail
/// while applying a trailing relative hop (for example `<oid>^2` on a
/// single-parent commit). Keeping that final resolution error beside the real
/// insertion count lets daemon owners persist or retain the graph growth
/// before surfacing the caller's invalid ref.
#[derive(Debug)]
pub struct PreparedRefResolution {
    resolution: Result<SemanticChangeId>,
    pub hydrated_changes: usize,
}

impl PreparedRefResolution {
    pub fn into_result(self) -> Result<ResolvedRef> {
        let head = self.resolution?;
        Ok(ResolvedRef {
            head,
            hydrated_git_history: self.hydrated_changes > 0,
            hydrated_changes: self.hydrated_changes,
        })
    }
}

pub fn resolve_ref<G>(
    graph: &G,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    match reference {
        Some(reference) => resolve_explicit_ref(graph, layout, reference),
        None => {
            let current = kin_core::read_current_branch(layout)?;
            let branch = graph
                .get_branch(&current)
                .map_err(|err| anyhow!(err.to_string()))?
                .ok_or_else(|| anyhow!("branch '{}' not found", current))?;
            Ok(branch.head)
        }
    }
}

/// How much semantic work a lazy Git-ref hydration performs on the ancestry it
/// imports. Both depths import the same commits and the same artifact deltas;
/// they differ only in whether the per-commit semantic replay runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HydrationDepth {
    /// Replay per-commit entity and relation deltas across the whole imported
    /// ancestry.
    ///
    /// Required by every caller that reads semantic truth *at* the ref rather
    /// than a tree state derived from it: `history` and `blame` resolve the
    /// target entity through `resolve_graph_at`, which replays exactly these
    /// deltas, and `review` diffs them between two refs.
    Semantic,
    /// Import artifact deltas only, skipping the per-commit semantic replay.
    ///
    /// Retrieval does not read those deltas. `kin_core::build_graph_at_ref*`
    /// takes the ref's file tree from the replayed *artifact* deltas (or from
    /// the Git tree directly) and rebuilds the scoped entity set by re-parsing
    /// that tree through `IndexPipeline`, so scope-for-retrieval and
    /// `locate --ref` get the same answer either way. Co-change mining also
    /// reads artifact deltas only.
    ///
    /// The replay it skips re-parses and re-links every ancestor commit — the
    /// "Hydrating History: [n/26747]" pass, minutes of work on a deep
    /// base_commit — which is pure cost on these two paths.
    ArtifactOnly,
}

pub fn resolve_ref_importing_git_if_needed(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> Result<SemanticChangeId> {
    Ok(
        prepare_ref_importing_git_if_needed(graph, layout, reference, HydrationDepth::Semantic)
            .into_result()?
            .head,
    )
}

pub fn resolve_ref_importing_git_if_needed_for_locate(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> Result<SemanticChangeId> {
    Ok(
        prepare_ref_importing_git_if_needed(graph, layout, reference, HydrationDepth::ArtifactOnly)
            .into_result()?
            .head,
    )
}

pub fn resolve_ref_importing_git_if_needed_with_report(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> Result<ResolvedRef> {
    prepare_ref_importing_git_if_needed(graph, layout, reference, HydrationDepth::Semantic)
        .into_result()
}

pub fn resolve_ref_importing_git_if_needed_for_locate_with_report(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> Result<ResolvedRef> {
    prepare_ref_importing_git_if_needed(graph, layout, reference, HydrationDepth::ArtifactOnly)
        .into_result()
}

pub fn prepare_ref_importing_git_if_needed_with_report(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> PreparedRefResolution {
    prepare_ref_importing_git_if_needed(graph, layout, reference, HydrationDepth::Semantic)
}

fn prepare_ref_importing_git_if_needed(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
    depth: HydrationDepth,
) -> PreparedRefResolution {
    match resolve_ref(graph, layout, reference) {
        Ok(head) => PreparedRefResolution {
            resolution: Ok(head),
            hydrated_changes: 0,
        },
        Err(original_err) => {
            let Some(reference) = reference else {
                return PreparedRefResolution {
                    resolution: Err(original_err),
                    hydrated_changes: 0,
                };
            };
            let Some(git_oid) = extract_git_ref(reference) else {
                return PreparedRefResolution {
                    resolution: Err(original_err),
                    hydrated_changes: 0,
                };
            };
            match hydrate_imported_git_ref(graph, layout, git_oid, depth) {
                Ok(hydrated_changes) => PreparedRefResolution {
                    // Preserve a relative-hop error until the graph owner has
                    // acknowledged the successful ancestry insertion.
                    resolution: resolve_ref(graph, layout, Some(reference)),
                    hydrated_changes,
                },
                Err(error) => PreparedRefResolution {
                    resolution: Err(error),
                    hydrated_changes: 0,
                },
            }
        }
    }
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
        .map_err(|err| anyhow!(err.to_string()))?;
    choose_entity_match(entities, entity_query).or_else(|_| {
        let all = graph
            .list_all_entities()
            .map_err(|err| anyhow!(err.to_string()))?;
        choose_entity_match(all, entity_query)
    })
}

pub(crate) fn resolve_entity_query_at_ref<G>(
    graph: &G,
    entity_query: &str,
    head: &SemanticChangeId,
) -> Result<Entity>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let state = graph
        .resolve_graph_at(head)
        .map_err(|err| anyhow!(err.to_string()))?;
    let entities = state
        .entities
        .into_values()
        .filter(|entity| entity_matches_query(entity, entity_query))
        .collect();
    choose_entity_match(entities, entity_query)
}

/// One relative-ref hop applied after a base ref resolves: select the Nth
/// parent (1-indexed) of the commit reached so far.
#[derive(Debug, Clone, Copy)]
struct ParentHop(usize);

/// Split trailing `^`, `^N`, `~`, `~N` operators off the end of `reference`,
/// returning the remaining base-ref text and the hops to apply, in
/// application order (closest to the base first). Mirrors git's own suffix
/// grammar (see `git-rev-parse(1)`, "Specifying Revisions"): bare `^`/`~` is
/// one first-parent hop, `~N` desugars to N repeated first-parent hops, and
/// `^N` selects the Nth parent directly (relevant only at merge commits,
/// where parent order matters). Branch/tag names cannot themselves contain
/// `^` or `~` under Git's own ref-name rules, so peeling trailing operators
/// never misreads a legitimate name.
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
                .rfind(|c: char| !c.is_ascii_digit())
                .map(|i| i + 1)
                .unwrap_or(0);
            if digits_start == 0 {
                // The whole remaining string is digits (e.g. a bare numeric
                // ref) — not a `^N`/`~N` suffix, stop peeling.
                break;
            }
            let marker = rest.as_bytes()[digits_start - 1];
            if marker != b'^' && marker != b'~' {
                break;
            }
            let n: usize = rest[digits_start..]
                .parse()
                .map_err(|_| ref_error(reference, "parent index is out of range"))?;
            if marker == b'^' {
                if n == 0 {
                    // `^0` names the commit itself, not a parent hop — stop
                    // peeling and let core resolution handle (or reject) it.
                    break;
                }
                hops.push(ParentHop(n));
            } else {
                hops.extend(std::iter::repeat_n(ParentHop(1), n));
            }
            rest = &rest[..digits_start - 1];
            continue;
        }
        break;
    }
    Ok((rest, hops))
}

/// Walk `hops` from `head`, following recorded parents in the graph.
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
            .map_err(|err| anyhow!(err.to_string()))?
            .ok_or_else(|| ref_error(original, format!("change {} not found in history", head)))?;
        head = *change.parents.get(hop.0 - 1).ok_or_else(|| {
            ref_error(
                original,
                format!(
                    "{} has {} parent(s), no parent #{}",
                    head,
                    change.parents.len(),
                    hop.0
                ),
            )
        })?;
    }
    Ok(head)
}

fn resolve_explicit_ref<G>(
    graph: &G,
    layout: &kin_core::KinLayout,
    reference: &str,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if reference.contains("@{") {
        return Err(ref_error(
            reference,
            "reflog/upstream '@{...}' ref syntax is not supported",
        ));
    }

    let (core, hops) = split_relative_hops(reference)?;
    let head = resolve_ref_core(graph, layout, reference, core)?;
    apply_parent_hops(graph, reference, head, &hops)
}

/// Resolve the non-relative "core" of a reference: exactly `HEAD`, a
/// `branch:`/`git:`/`kin:`/`change:`-prefixed form, a bare branch name, a
/// 40-character Git commit hash, or a Kin change id. `original` is the full,
/// pre-peel reference text the caller supplied, threaded through only so
/// error messages point at what was actually typed.
fn resolve_ref_core<G>(
    graph: &G,
    layout: &kin_core::KinLayout,
    original: &str,
    core: &str,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if core == "HEAD" {
        let current = kin_core::read_current_branch(layout)?;
        let branch = graph
            .get_branch(&current)
            .map_err(|err| anyhow!(err.to_string()))?
            .ok_or_else(|| ref_error(original, format!("branch '{}' not found", current)))?;
        return Ok(branch.head);
    }

    if let Some(branch_name) = core.strip_prefix("branch:") {
        return resolve_branch_head(graph, original, branch_name);
    }

    if let Some(git_oid) = core.strip_prefix("git:") {
        return resolve_imported_git_ref(graph, original, git_oid);
    }

    if let Some(change_ref) = core
        .strip_prefix("kin:")
        .or_else(|| core.strip_prefix("change:"))
    {
        return resolve_semantic_change(graph, original, change_ref);
    }

    if let Some(branch) = graph
        .get_branch(&BranchName::new(core))
        .map_err(|err| anyhow!(err.to_string()))?
    {
        return Ok(branch.head);
    }

    if core.len() == 40 {
        if let Ok(imported_change_id) = resolve_imported_git_ref(graph, original, core) {
            return Ok(imported_change_id);
        }
    }

    if is_abbreviated_git_hex(core) {
        match kin_git::expand_git_commit_prefix(layout.working_dir(), core) {
            kin_git::GitOidPrefixExpansion::Commit(full_oid) => {
                if let Ok(imported_change_id) = resolve_imported_git_ref(graph, original, &full_oid)
                {
                    return Ok(imported_change_id);
                }
                return Err(ref_error(
                    original,
                    format!(
                        "git commit '{}' (full id {}) is not imported into this repository's history; use the full 40-character id to hydrate it",
                        core, full_oid
                    ),
                ));
            }
            kin_git::GitOidPrefixExpansion::Ambiguous => {
                return Err(ref_error(
                    original,
                    format!(
                        "git commit prefix '{}' is ambiguous; use more characters or the full 40-character id",
                        core
                    ),
                ));
            }
            kin_git::GitOidPrefixExpansion::NotFound => {}
        }
    }

    if parse_change_id(core).is_ok() {
        return resolve_semantic_change(graph, original, core);
    }

    Err(ref_error(original, format!("unknown ref '{}'", core)))
}

/// True for a plausible abbreviated Git commit hash: 4–39 hex characters.
/// Full 40-character ids resolve through the exact-id path instead, and
/// anything shorter than Git's 4-character minimum never expands.
fn is_abbreviated_git_hex(core: &str) -> bool {
    (4..40).contains(&core.len()) && core.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolve_branch_head<G>(graph: &G, original: &str, branch_name: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if let Some(branch) = graph
        .get_branch(&BranchName::new(branch_name))
        .map_err(|err| anyhow!(err.to_string()))?
    {
        return Ok(branch.head);
    }

    Err(ref_error(
        original,
        format!("branch '{}' not found", branch_name),
    ))
}

fn resolve_imported_git_ref<G>(graph: &G, original: &str, git_oid: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let imported_change_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid)?;
    if graph
        .get_change(&imported_change_id)
        .map_err(|err| anyhow!(err.to_string()))?
        .is_some()
    {
        Ok(imported_change_id)
    } else {
        Err(ref_error(
            original,
            format!("imported Git commit '{}' not found", git_oid),
        ))
    }
}

/// Extract the bare Git commit oid a reference names, if any, peeling any
/// trailing `^`/`~N` relative-ref hops first so a not-yet-imported commit
/// referenced as e.g. `<oid>~2` is still recognized as needing hydration for
/// its `<oid>` core. Returns a slice of `reference`, so hydrating the
/// returned oid and then re-resolving the original (unpeeled) string
/// resolves the hop against the now-present history.
pub fn extract_git_ref(reference: &str) -> Option<&str> {
    if reference.contains("@{") {
        return None;
    }
    let (core, _hops) = split_relative_hops(reference).ok()?;
    if let Some(git_oid) = core.strip_prefix("git:") {
        return Some(git_oid);
    }
    if core.len() == 40 {
        return Some(core);
    }
    None
}

/// Returns true when resolving `reference` would import a full Git ancestry that
/// is not yet present in `graph`. Callers use this to decide whether a request
/// must take a serialized hydration gate before resolving: already-imported or
/// non-Git refs stay on the lock-free fast path. Conservative on lookup error —
/// an unresolved presence check reports `true` so a real import is never left
/// unserialized.
pub fn git_ref_requires_hydration(graph: &kin_db::InMemoryGraph, reference: &str) -> bool {
    let Some(git_oid) = extract_git_ref(reference) else {
        return false;
    };
    let Ok(imported_change_id) = kin_git::semantic_change_id_from_git_oid_hex(git_oid) else {
        return false;
    };
    !matches!(graph.get_change(&imported_change_id), Ok(Some(_)))
}

/// Lazily import the Git ancestry of `git_oid` into `graph`, returning the
/// count of changes actually inserted (0 when the ref was already present and
/// no import ran). Callers report this count directly rather than collapsing
/// it to a boolean, so a cold multi-thousand-change import is never described
/// the same way as a no-op.
///
/// `depth` selects whether the imported ancestry also gets its per-commit
/// semantic replay; see [`HydrationDepth`] for which callers need it.
fn hydrate_imported_git_ref(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    git_oid: &str,
    depth: HydrationDepth,
) -> Result<usize> {
    match depth {
        HydrationDepth::Semantic => {
            hydrate_imported_git_ref_with(graph, layout, git_oid, replay_imported_semantics)
        }
        HydrationDepth::ArtifactOnly => {
            hydrate_imported_git_ref_with(graph, layout, git_oid, skip_imported_semantics)
        }
    }
}

/// [`HydrationDepth::Semantic`] replay: reconstruct per-commit entity and
/// relation deltas across the imported ancestry, resuming from and writing
/// hydration checkpoints.
fn replay_imported_semantics(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    kin_root: &std::path::Path,
) -> Result<()> {
    crate::commands::init::enrich_imported_changes_with_semantics_checkpointed(
        imported,
        blob_store,
        kin_root,
        kin_core::build_genesis_change().id,
    )
    .map(|_| ())
}

/// [`HydrationDepth::ArtifactOnly`] replay: none. The imported changes keep the
/// artifact deltas the Git import produced, which is what the ref view and
/// co-change mining read.
fn skip_imported_semantics(
    _imported: &mut [kin_git::ImportedChange],
    _blob_store: &kin_blobs::BlobStore,
    _kin_root: &std::path::Path,
) -> Result<()> {
    Ok(())
}

/// Reject an imported window before any of it is written to the graph unless
/// every change lands on an already-known parent.
///
/// A change is admitted when each of its parents is the import's boundary root
/// (canonical genesis), a change already present in `graph`, or a change
/// admitted earlier in this same pass. Because admission is evaluated in the
/// order kin-git emits — a parent-first Kahn traversal — that single rule
/// rejects a parentless change, a parent outside the imported window, and a
/// parent cycle alike: no member of a cycle can ever be admitted first.
///
/// This guards the graph write itself, so it holds for every hydration depth.
/// The semantic replay performs its own richer validation before it mutates
/// deltas; this check is what keeps an artifact-only import, which runs no
/// replay, from inserting an ancestry the graph cannot resolve.
fn admit_imported_changes_for_insert(
    graph: &kin_db::InMemoryGraph,
    imported: &[kin_git::ImportedChange],
    boundary_root: SemanticChangeId,
) -> Result<()> {
    let mut admitted = std::collections::HashSet::with_capacity(imported.len());
    for imported_change in imported {
        let change = &imported_change.change;
        if change.parents.is_empty() {
            bail!(
                "imported change {} has no parent; Git roots must reference canonical genesis {}",
                change.id,
                boundary_root
            );
        }
        for parent in &change.parents {
            if *parent == boundary_root
                || admitted.contains(parent)
                || graph.get_change(parent)?.is_some()
            {
                continue;
            }
            bail!(
                "imported change {} names parent {} that is neither canonical genesis {}, already in the graph, nor an earlier change in the imported window",
                change.id,
                parent,
                boundary_root
            );
        }
        admitted.insert(change.id);
    }
    Ok(())
}

fn hydrate_imported_git_ref_with<F>(
    graph: &kin_db::InMemoryGraph,
    layout: &kin_core::KinLayout,
    git_oid: &str,
    enrich_semantics: F,
) -> Result<usize>
where
    F: FnOnce(
        &mut [kin_git::ImportedChange],
        &kin_blobs::BlobStore,
        &std::path::Path,
    ) -> Result<()>,
{
    let imported_change_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid)?;
    if graph.get_change(&imported_change_id)?.is_some() {
        return Ok(0);
    }

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .context("open blob store for imported Git ref hydration")?;
    let genesis_id = kin_core::build_genesis_change().id;
    let mut imported = kin_git::import_git_history_to_commit_with_blobs(
        layout.working_dir(),
        git_oid,
        genesis_id,
        Some(&blob_store),
    )
    .with_context(|| format!("hydrate imported Git commit '{}'", git_oid))?;

    enrich_semantics(&mut imported, &blob_store, layout.root()).with_context(|| {
        format!(
            "semantically hydrate imported Git history for ref '{}'",
            git_oid
        )
    })?;

    admit_imported_changes_for_insert(graph, &imported, genesis_id)?;

    let mut inserted = 0usize;
    for imported_change in &imported {
        if graph.get_change(&imported_change.change.id)?.is_none() {
            graph.create_change(&imported_change.change)?;
            inserted += 1;
        }
    }

    if graph.get_change(&imported_change_id)?.is_none() {
        return Err(ref_error(
            git_oid,
            "imported Git commit not found after hydration",
        ));
    }

    Ok(inserted)
}

fn resolve_semantic_change<G>(
    graph: &G,
    original: &str,
    change_ref: &str,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let change_id = parse_change_id(change_ref)?;
    if graph
        .get_change(&change_id)
        .map_err(|err| anyhow!(err.to_string()))?
        .is_some()
    {
        Ok(change_id)
    } else {
        Err(ref_error(
            original,
            format!("change {} not found", change_id),
        ))
    }
}

fn choose_entity_match(mut entities: Vec<Entity>, entity_query: &str) -> Result<Entity> {
    if entities.is_empty() {
        bail!("No entity matching '{}' found.", entity_query);
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
            bail!(
                "Multiple entities match '{}': {}. Use a more exact name.",
                entity_query,
                preview
            );
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
    use kin_db::InMemoryGraph;
    use kin_model::{AuthorId, Branch, ChangeStore, SemanticChange, Timestamp};

    fn git_ok(cwd: &std::path::Path, args: &[&str]) -> Option<String> {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn checkpoint_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        fn walk(path: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, files);
                } else if path.is_file() {
                    files.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(root, &mut files);
        files.sort();
        files
    }

    fn temp_layout() -> kin_core::KinLayout {
        let temp = tempfile::tempdir().unwrap();
        let kin_dir = temp.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        // Keep the tempdir alive by leaking it for the test process lifetime.
        let leaked = temp.keep();
        kin_core::KinLayout::new(leaked.join(".kin"))
    }

    #[test]
    fn lazy_git_ref_hydration_resumes_checkpoint_and_refuses_corruption_before_insert() {
        let repo = tempfile::tempdir().unwrap();
        if git_ok(repo.path(), &["init", "-q"]).is_none() {
            return;
        }
        assert!(git_ok(repo.path(), &["config", "user.email", "test@kin.dev"]).is_some());
        assert!(git_ok(repo.path(), &["config", "user.name", "Kin Test"]).is_some());
        std::fs::write(
            repo.path().join("main.py"),
            "def answer():\n    return 42\n",
        )
        .unwrap();
        assert!(git_ok(repo.path(), &["add", "main.py"]).is_some());
        assert!(git_ok(repo.path(), &["commit", "-q", "-m", "initial"]).is_some());
        let git_oid = git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap();
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(&git_oid).unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;

        let first_resumed = std::cell::Cell::new(usize::MAX);
        let first_graph = InMemoryGraph::new();
        let first_inserted = hydrate_imported_git_ref_with(
            &first_graph,
            &layout,
            &git_oid,
            |imported, blob_store, kin_root| {
                let stats =
                    crate::commands::init::enrich_imported_changes_with_semantics_test_checkpoint(
                        imported,
                        blob_store,
                        kin_root,
                        "lazy-ref-clean-sha",
                        kin_core::build_genesis_change().id,
                    )?;
                first_resumed.set(stats.resumed_from());
                Ok(())
            },
        )
        .unwrap();
        assert!(first_inserted > 0);
        assert_eq!(first_resumed.get(), 0);
        assert!(first_graph.get_change(&imported_id).unwrap().is_some());

        let second_resumed = std::cell::Cell::new(0usize);
        let second_graph = InMemoryGraph::new();
        hydrate_imported_git_ref_with(
            &second_graph,
            &layout,
            &git_oid,
            |imported, blob_store, kin_root| {
                let stats =
                    crate::commands::init::enrich_imported_changes_with_semantics_test_checkpoint(
                        imported,
                        blob_store,
                        kin_root,
                        "lazy-ref-clean-sha",
                        kin_core::build_genesis_change().id,
                    )?;
                second_resumed.set(stats.resumed_from());
                Ok(())
            },
        )
        .unwrap();
        assert!(second_resumed.get() > 0, "lazy ref path did not resume");
        assert!(second_graph.get_change(&imported_id).unwrap().is_some());

        let checkpoint_root = layout.root().join("checkpoints/history-hydration");
        let files = checkpoint_files(&checkpoint_root);
        for component in ["/segments/", "/parser-frontiers/", "/linker-frontiers/"] {
            assert!(
                files
                    .iter()
                    .any(|path| path.to_string_lossy().contains(component)),
                "lazy ref checkpoint did not persist {component}"
            );
        }
        let manifest = files
            .into_iter()
            .find(|path| path.to_string_lossy().ends_with(".manifest.json"))
            .unwrap();
        std::fs::write(&manifest, b"corrupt").unwrap();

        let refused_graph = InMemoryGraph::new();
        let error = hydrate_imported_git_ref_with(
            &refused_graph,
            &layout,
            &git_oid,
            |imported, blob_store, kin_root| {
                crate::commands::init::enrich_imported_changes_with_semantics_test_checkpoint(
                    imported,
                    blob_store,
                    kin_root,
                    "lazy-ref-clean-sha",
                    kin_core::build_genesis_change().id,
                )
                .map(|_| ())
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("semantically hydrate"),
            "lazy ref error lost its semantic hydration context: {error:#}"
        );
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("REFUSED hydration checkpoint")),
            "lazy ref corruption did not fail through the checkpoint wrapper: {error:#}"
        );
        assert!(refused_graph.get_change(&imported_id).unwrap().is_none());
    }

    #[test]
    fn lazy_git_ref_dangling_parent_refuses_before_store_or_graph_write() {
        let repo = tempfile::tempdir().unwrap();
        if git_ok(repo.path(), &["init", "-q"]).is_none() {
            return;
        }
        assert!(git_ok(repo.path(), &["config", "user.email", "test@kin.dev"]).is_some());
        assert!(git_ok(repo.path(), &["config", "user.name", "Kin Test"]).is_some());
        std::fs::write(
            repo.path().join("main.py"),
            "def answer():\n    return 42\n",
        )
        .unwrap();
        assert!(git_ok(repo.path(), &["add", "main.py"]).is_some());
        assert!(git_ok(repo.path(), &["commit", "-q", "-m", "initial"]).is_some());
        let git_oid = git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap();
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(&git_oid).unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let graph = InMemoryGraph::new();
        let dangling = SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0xee; 32]));

        let error = hydrate_imported_git_ref_with(
            &graph,
            &layout,
            &git_oid,
            |imported, blob_store, kin_root| {
                imported[0].change.parents = vec![dangling];
                crate::commands::init::enrich_imported_changes_with_semantics_test_checkpoint(
                    imported,
                    blob_store,
                    kin_root,
                    "lazy-ref-clean-sha",
                    kin_core::build_genesis_change().id,
                )
                .map(|_| ())
            },
        )
        .unwrap_err();
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("dangling parent")),
            "lazy ref lost dangling-parent cause: {error:#}"
        );
        assert!(graph.get_change(&imported_id).unwrap().is_none());
        assert!(
            !layout.root().join("checkpoints/history-hydration").exists(),
            "lazy parent preflight must precede checkpoint-store creation"
        );
    }

    /// A one-commit Git repo with a real source file, initialized for Kin, plus
    /// an empty graph and the commit's oid. Returns `None` when Git is
    /// unavailable so these tests skip the same way the others do.
    fn single_commit_repo_for_hydration() -> Option<(InMemoryGraph, kin_core::KinLayout, String)> {
        let repo = tempfile::tempdir().unwrap();
        if git_ok(repo.path(), &["init", "-q"]).is_none() {
            return None;
        }
        assert!(git_ok(repo.path(), &["config", "user.email", "test@kin.dev"]).is_some());
        assert!(git_ok(repo.path(), &["config", "user.name", "Kin Test"]).is_some());
        std::fs::write(
            repo.path().join("lib.rs"),
            "pub fn answer() -> i32 {\n    42\n}\n",
        )
        .unwrap();
        assert!(git_ok(repo.path(), &["add", "lib.rs"]).is_some());
        assert!(git_ok(repo.path(), &["commit", "-q", "-m", "initial"]).is_some());
        let git_oid = git_ok(repo.path(), &["rev-parse", "HEAD"]).unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        // Keep the repo alive for the test process lifetime; the layout and the
        // blob store both keep reading from it after this function returns.
        let _kept = repo.keep();
        Some((InMemoryGraph::new(), layout, git_oid))
    }

    fn hydrated_tip_change(graph: &InMemoryGraph, git_oid: &str) -> kin_model::SemanticChange {
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid).unwrap();
        graph
            .get_change(&imported_id)
            .unwrap()
            .expect("hydration must insert the requested commit")
    }

    /// The perf contract: an artifact-only hydration imports the same commits
    /// and the same artifact deltas but runs no per-commit semantic replay, so
    /// it writes no entity deltas and never opens a hydration checkpoint store.
    /// The semantic hydration does replay.
    #[test]
    fn artifact_only_hydration_skips_the_semantic_replay_that_full_hydration_runs() {
        let Some((semantic_graph, semantic_layout, semantic_oid)) =
            single_commit_repo_for_hydration()
        else {
            return;
        };
        let Some((artifact_graph, artifact_layout, artifact_oid)) =
            single_commit_repo_for_hydration()
        else {
            return;
        };

        let semantic_inserted = hydrate_imported_git_ref(
            &semantic_graph,
            &semantic_layout,
            &semantic_oid,
            HydrationDepth::Semantic,
        )
        .unwrap();
        let artifact_inserted = hydrate_imported_git_ref(
            &artifact_graph,
            &artifact_layout,
            &artifact_oid,
            HydrationDepth::ArtifactOnly,
        )
        .unwrap();

        assert!(semantic_inserted > 0);
        assert_eq!(
            artifact_inserted, semantic_inserted,
            "both depths must import the same ancestry; only the replay differs"
        );

        let semantic_change = hydrated_tip_change(&semantic_graph, &semantic_oid);
        let artifact_change = hydrated_tip_change(&artifact_graph, &artifact_oid);

        assert!(
            !semantic_change.entity_deltas.is_empty(),
            "semantic hydration must replay per-commit entity deltas"
        );
        assert!(
            artifact_change.entity_deltas.is_empty(),
            "artifact-only hydration must not run the per-commit semantic replay"
        );
        assert!(
            !artifact_change.artifact_deltas.is_empty(),
            "artifact-only hydration must still import artifact deltas: the ref view and co-change mining read them"
        );
        assert!(
            !artifact_layout
                .root()
                .join("checkpoints/history-hydration")
                .exists(),
            "artifact-only hydration must not open a hydration checkpoint store"
        );
    }

    /// The regression this guards: the four public entry points must stay
    /// distinct. `_for_locate*` resolves at artifact-only depth for scope and
    /// `locate --ref`; the plain variants stay semantic for `history`, `blame`,
    /// and `review`, which read the deltas the replay produces.
    #[test]
    fn locate_entry_points_resolve_at_artifact_only_depth_and_others_stay_semantic() {
        let Some((locate_graph, locate_layout, locate_oid)) = single_commit_repo_for_hydration()
        else {
            return;
        };
        let Some((locate_report_graph, locate_report_layout, locate_report_oid)) =
            single_commit_repo_for_hydration()
        else {
            return;
        };
        let Some((standard_graph, standard_layout, standard_oid)) =
            single_commit_repo_for_hydration()
        else {
            return;
        };
        let Some((prepared_graph, prepared_layout, prepared_oid)) =
            single_commit_repo_for_hydration()
        else {
            return;
        };

        resolve_ref_importing_git_if_needed_for_locate(
            &locate_graph,
            &locate_layout,
            Some(&locate_oid),
        )
        .unwrap();
        let locate_report = resolve_ref_importing_git_if_needed_for_locate_with_report(
            &locate_report_graph,
            &locate_report_layout,
            Some(&locate_report_oid),
        )
        .unwrap();
        let standard_report = resolve_ref_importing_git_if_needed_with_report(
            &standard_graph,
            &standard_layout,
            Some(&standard_oid),
        )
        .unwrap();
        let prepared = prepare_ref_importing_git_if_needed_with_report(
            &prepared_graph,
            &prepared_layout,
            Some(&prepared_oid),
        );

        assert!(locate_report.hydrated_changes > 0);
        assert!(standard_report.hydrated_changes > 0);
        assert!(prepared.hydrated_changes > 0);
        prepared.into_result().unwrap();

        for (graph, oid, label) in [
            (&locate_graph, &locate_oid, "resolve_..._for_locate"),
            (
                &locate_report_graph,
                &locate_report_oid,
                "resolve_..._for_locate_with_report",
            ),
        ] {
            assert!(
                hydrated_tip_change(graph, oid).entity_deltas.is_empty(),
                "{label} must hydrate at artifact-only depth; otherwise it runs the deep per-commit replay whose deltas scope and locate --ref never read"
            );
        }

        for (graph, oid, label) in [
            (&standard_graph, &standard_oid, "resolve_..._with_report"),
            (&prepared_graph, &prepared_oid, "prepare_..._with_report"),
        ] {
            assert!(
                !hydrated_tip_change(graph, oid).entity_deltas.is_empty(),
                "{label} must keep full semantic hydration; history, blame, and review read these deltas"
            );
        }
    }

    /// Graph-integrity parity: the artifact-only path runs no semantic replay,
    /// so the replay's own preflight cannot be what protects it. A corrupt
    /// imported window must still be refused before anything is written.
    #[test]
    fn artifact_only_hydration_still_refuses_a_dangling_parent_before_graph_write() {
        let Some((graph, layout, git_oid)) = single_commit_repo_for_hydration() else {
            return;
        };
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(&git_oid).unwrap();
        let dangling = SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([0xee; 32]));

        let error = hydrate_imported_git_ref_with(
            &graph,
            &layout,
            &git_oid,
            |imported, blob_store, kin_root| {
                imported[0].change.parents = vec![dangling];
                skip_imported_semantics(imported, blob_store, kin_root)
            },
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("names parent"),
            "artifact-only hydration lost its parent-admission guard: {error:#}"
        );
        assert!(
            graph.get_change(&imported_id).unwrap().is_none(),
            "a refused imported window must leave the graph untouched"
        );
    }

    #[test]
    fn resolve_ref_accepts_imported_git_commit_sha() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let git_oid = "1111111111111111111111111111111111111111";
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid).unwrap();
        graph
            .create_change(&SemanticChange {
                id: imported_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "imported git commit".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(git_oid)).unwrap();
        assert_eq!(resolved, imported_id);
    }

    #[test]
    fn resolve_ref_accepts_prefixed_git_commit_sha() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let git_oid = "1111111111111111111111111111111111111111";
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid).unwrap();
        graph
            .create_change(&SemanticChange {
                id: imported_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "imported git commit".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(&format!("git:{git_oid}"))).unwrap();
        assert_eq!(resolved, imported_id);
    }

    #[test]
    fn resolve_ref_accepts_prefixed_change_id() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "kin change".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&change).unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(&format!("kin:{}", change.id))).unwrap();
        assert_eq!(resolved, change.id);
    }

    #[test]
    fn resolve_ref_accepts_prefixed_branch_name() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x52; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "branch tip".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&change).unwrap();
        let branch = Branch {
            name: BranchName::new("feature/history"),
            head: change.id,
        };
        graph.create_branch(&branch).unwrap();

        let resolved = resolve_ref(&graph, &layout, Some("branch:feature/history")).unwrap();
        assert_eq!(resolved, branch.head);
    }

    fn make_change(id: SemanticChangeId, parents: Vec<SemanticChangeId>) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "test change".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    /// A layout with `main` checked out as the current branch, backed by a
    /// native chain `grandparent <- parent <- head`, where `head` is a merge
    /// of `parent` and `other_parent` (so `^2`-style parent selection has
    /// something real to select).
    fn temp_layout_on_main(graph: &InMemoryGraph) -> (kin_core::KinLayout, [SemanticChangeId; 4]) {
        let layout = temp_layout();
        kin_core::write_current_branch(&layout, &BranchName::new("main")).unwrap();

        let grandparent = change_id(0x01);
        let parent = change_id(0x02);
        let other_parent = change_id(0x03);
        let head = change_id(0x04);

        graph
            .create_change(&make_change(grandparent, vec![]))
            .unwrap();
        graph
            .create_change(&make_change(parent, vec![grandparent]))
            .unwrap();
        graph
            .create_change(&make_change(other_parent, vec![]))
            .unwrap();
        graph
            .create_change(&make_change(head, vec![parent, other_parent]))
            .unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head,
            })
            .unwrap();

        (layout, [grandparent, parent, other_parent, head])
    }

    // ── Caret/tilde/relative-ref peeling ──

    #[test]
    fn resolve_ref_head_caret_matches_head_tilde_one() {
        let graph = InMemoryGraph::new();
        let (layout, [_grandparent, parent, _other_parent, _head]) = temp_layout_on_main(&graph);

        let caret = resolve_ref(&graph, &layout, Some("HEAD^")).unwrap();
        let tilde = resolve_ref(&graph, &layout, Some("HEAD~1")).unwrap();
        assert_eq!(caret, parent, "HEAD^ must select the first parent");
        assert_eq!(caret, tilde, "HEAD^ and HEAD~1 must agree");
    }

    #[test]
    fn resolve_ref_caret_n_selects_that_parent_by_position() {
        let graph = InMemoryGraph::new();
        let (layout, [_grandparent, parent, other_parent, _head]) = temp_layout_on_main(&graph);

        let first = resolve_ref(&graph, &layout, Some("HEAD^1")).unwrap();
        let second = resolve_ref(&graph, &layout, Some("HEAD^2")).unwrap();
        assert_eq!(
            first, parent,
            "HEAD^1 must select the first recorded parent"
        );
        assert_eq!(
            second, other_parent,
            "HEAD^2 must select the second recorded parent (the merged-in side)"
        );
    }

    #[test]
    fn resolve_ref_chained_hops_walk_in_order() {
        let graph = InMemoryGraph::new();
        let (layout, [grandparent, _parent, _other_parent, _head]) = temp_layout_on_main(&graph);

        let resolved = resolve_ref(&graph, &layout, Some("HEAD^1~1")).unwrap();
        assert_eq!(
            resolved, grandparent,
            "HEAD^1~1 is first-parent then first-parent again"
        );

        let resolved_bare = resolve_ref(&graph, &layout, Some("HEAD^^")).unwrap();
        assert_eq!(
            resolved_bare, grandparent,
            "HEAD^^ is two first-parent hops, same as HEAD^1~1 here"
        );
    }

    #[test]
    fn resolve_ref_tilde_n_desugars_to_n_first_parent_hops() {
        let graph = InMemoryGraph::new();
        let (layout, [grandparent, _parent, _other_parent, _head]) = temp_layout_on_main(&graph);

        let resolved = resolve_ref(&graph, &layout, Some("HEAD~2")).unwrap();
        assert_eq!(resolved, grandparent);
    }

    #[test]
    fn resolve_ref_hop_past_history_start_fails_cleanly_not_opaque() {
        let graph = InMemoryGraph::new();
        let (layout, _ids) = temp_layout_on_main(&graph);

        let err = resolve_ref(&graph, &layout, Some("HEAD~50")).unwrap_err();
        assert!(
            is_ref_resolution_error(&err),
            "a hop past the start of history must be a RefResolutionError, not an opaque error: {err:#}"
        );
    }

    #[test]
    fn resolve_ref_rejects_reflog_upstream_syntax_cleanly() {
        let graph = InMemoryGraph::new();
        let (layout, _ids) = temp_layout_on_main(&graph);

        let err = resolve_ref(&graph, &layout, Some("HEAD@{upstream}")).unwrap_err();
        assert!(
            is_ref_resolution_error(&err),
            "unsupported '@{{...}}' syntax must fail as a clean ref-resolution error, not panic or 500: {err:#}"
        );
    }

    #[test]
    fn resolve_ref_unknown_ref_is_classified_as_ref_resolution_error() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();

        let err = resolve_ref(&graph, &layout, Some("this-branch-does-not-exist")).unwrap_err();
        assert!(
            is_ref_resolution_error(&err),
            "an unknown ref must be classified as a client-input error: {err:#}"
        );
    }

    #[test]
    fn resolve_ref_caret_applies_after_any_core_form_not_just_head() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let git_oid = "2222222222222222222222222222222222222222";
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid).unwrap();
        let parent_id = change_id(0x09);
        graph
            .create_change(&make_change(parent_id, vec![]))
            .unwrap();
        graph
            .create_change(&make_change(imported_id, vec![parent_id]))
            .unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(&format!("{git_oid}^"))).unwrap();
        assert_eq!(
            resolved, parent_id,
            "relative hops must apply after any resolved core ref, not just HEAD"
        );
    }

    #[test]
    fn split_relative_hops_parses_caret_and_tilde_chains() {
        let (core, hops) = split_relative_hops("HEAD").unwrap();
        assert_eq!(core, "HEAD");
        assert!(hops.is_empty());

        let (core, hops) = split_relative_hops("HEAD^").unwrap();
        assert_eq!(core, "HEAD");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].0, 1);

        let (core, hops) = split_relative_hops("HEAD^2").unwrap();
        assert_eq!(core, "HEAD");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].0, 2);

        let (core, hops) = split_relative_hops("HEAD~3").unwrap();
        assert_eq!(core, "HEAD");
        assert_eq!(hops.len(), 3);
        assert!(hops.iter().all(|h| h.0 == 1));

        let (core, hops) = split_relative_hops("HEAD~2^").unwrap();
        assert_eq!(core, "HEAD");
        assert_eq!(hops.len(), 3);
        assert!(hops.iter().all(|h| h.0 == 1));
    }

    #[test]
    fn extract_git_ref_recognizes_hop_suffixed_sha() {
        let sha = "3333333333333333333333333333333333333333";
        assert_eq!(extract_git_ref(&format!("{sha}~2")), Some(sha));
        assert_eq!(extract_git_ref(&format!("git:{sha}^")), Some(sha));
        assert_eq!(extract_git_ref("HEAD^"), None);
        assert_eq!(extract_git_ref("HEAD@{upstream}"), None);
    }
}
