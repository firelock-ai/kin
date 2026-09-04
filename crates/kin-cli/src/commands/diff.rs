// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-v6 diffs.
//!
//! Diff reads one immutable repository authority lease and compares two
//! graph-owned endpoint states. Exact artifact membership is primary; semantic
//! entity and relation changes are additive enrichment. Git, checkout files,
//! legacy graph snapshots, and daemon-local overlays never answer this command.

use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, bail, Context, Result};
use kin_model::{
    compute_resolved_tree_hash, ChangeStore, Entity, EntityDelta, EntityId, Hash256, RefName,
    RefTarget, Relation, RelationDelta, RelationId, RepositoryId, ResolvedTree, RootBundle,
    SemanticChangeId, TreeDelta, TreeEntry, WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;

pub const DIFF_SCHEMA: &str = "kin.diff.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffRequest {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub head: Option<String>,
    #[serde(default)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<DiffReport>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffEndpointSource {
    Empty,
    Workspace,
    Head,
    Ref,
    Change,
    GitObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffEndpoint {
    pub source: DiffEndpointSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<RefName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<RefTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<SemanticChangeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_head: Option<WorkspaceHead>,
    pub tree_hash: Hash256,
    pub artifact_count: usize,
    pub entity_count: usize,
    pub relation_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffSummary {
    pub artifacts_added: usize,
    pub artifacts_updated: usize,
    pub artifacts_removed: usize,
    pub entities_added: usize,
    pub entities_modified: usize,
    pub entities_removed: usize,
    /// Entities that appear in a changed artifact on both endpoints while their
    /// own content is identical.
    ///
    /// Counted rather than silently dropped, and `#[serde(default)]` because
    /// this crosses the daemon wire and an older peer sends none.
    #[serde(default)]
    pub entities_unchanged: usize,
    pub relations_added: usize,
    pub relations_modified: usize,
    pub relations_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    pub workspace_id: WorkspaceId,
    pub base: DiffEndpoint,
    pub head: DiffEndpoint,
    pub summary: DiffSummary,
    /// Complete exact artifact transitions. `RepoPath` serializes as byte hex,
    /// and `TreeEntry` preserves blob identity, executable mode, symlink body,
    /// or gitlink target.
    pub artifact_deltas: Vec<TreeDelta>,
    /// Semantic enrichment is additive. Repositories with no supported parser
    /// still receive the complete `artifact_deltas` report.
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    /// Where a workspace endpoint's semantics came from, absent when neither
    /// endpoint is the workspace. `#[serde(default)]` because this crosses the
    /// daemon wire and an older peer sends none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_basis: Option<WorkspaceSemanticBasis>,
    /// What actually changed inside each artifact, read from graph-owned CAS.
    ///
    /// A PARALLEL array keyed by `artifact_id` rather than a field on
    /// `TreeDelta`, because `TreeDelta` is a kin-model type carrying
    /// `deny_unknown_fields` and kin consumes it from the registry. Nesting the
    /// content would be a cross-repo change; joining on the id is not, and the
    /// content is at the artifact level either way, which is the property that
    /// matters: a changed file with no entities still carries its content.
    ///
    /// `#[serde(default)]` because this crosses the daemon wire and an older
    /// peer sends none, the same reason `semantic_basis` above carries it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_content: Vec<ArtifactContent>,
}

/// The content transition for one artifact, rendered from two CAS bodies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactContent {
    pub artifact_id: kin_model::ArtifactId,
    pub path: String,
    /// Blob identity on each side. Absent on an add or a delete respectively,
    /// and both are already carried by the artifact delta this joins to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_hash: Option<Hash256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_hash: Option<Hash256>,
    /// Unified hunks, from the same renderer the text surface uses, so the two
    /// surfaces cannot disagree about what changed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hunks: Vec<String>,
    /// Full bodies, only under `--full-bodies`. Off by default so a large tree
    /// does not double its payload to say what a hunk already said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_text: Option<String>,
    /// Why content is absent, when it is. Named rather than empty, because a
    /// missing hunk list and a refused one read identically otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted: Option<String>,
}

struct EndpointState {
    report: DiffEndpoint,
    tree: ResolvedTree,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
}

impl EndpointState {
    fn empty(source: DiffEndpointSource, requested: Option<String>) -> Result<Self> {
        let tree = ResolvedTree::default();
        let tree_hash =
            compute_resolved_tree_hash(&tree).context("hash empty repository-v6 tree")?;
        Ok(Self {
            report: DiffEndpoint {
                source,
                requested,
                ref_name: None,
                target: None,
                change_id: None,
                workspace_generation: None,
                workspace_head: None,
                tree_hash,
                artifact_count: 0,
                entity_count: 0,
                relation_count: 0,
            },
            tree,
            entities: HashMap::new(),
            relations: HashMap::new(),
        })
    }
}

/// The exact entity sets the report's two endpoints resolved to.
///
/// A caller that classifies the endpoints themselves must read the same
/// immutable states the deltas were derived from rather than resolving the
/// endpoints a second time.
pub struct DiffEndpointEntities {
    pub base: HashMap<EntityId, Entity>,
    pub head: HashMap<EntityId, Entity>,
}

/// Where a workspace endpoint's entities and relations came from.
///
/// A CHANGE endpoint DERIVES its semantics: `state_at_change` replays the change
/// DAG through `resolve_graph_at`. The WORKSPACE endpoint alone did not derive.
/// It read its base change plus the workspace semantic overlay, and nothing ever
/// writes an entity delta into that overlay, so `Entities: +0 ~0 -0` on a
/// HEAD-to-WORKSPACE diff could not move for any edit whatsoever. That asymmetry
/// was the defect (FIR-2961).
///
/// Storing the entities in the overlay was the other candidate and was rejected
/// on the thesis: authority publishes the tree BEFORE the graph derives them, so
/// at publication there is nothing to publish, and writing them later puts a
/// reproducible derivation inside authority, which is what
/// `language_server_enrichment_delta` refuses in as many words. Entities are
/// derived from the tree; a read derives them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum WorkspaceSemanticBasis {
    /// Derived from the live graph, which held the named tree when it was read.
    Derived {
        /// The tree the live graph held. Named because a reconcile can land
        /// between the authority lease read and the derivation, and an answer
        /// derived from a NEWER graph than the tree it describes is a different
        /// answer that must not present as this one.
        graph_tree_hash: Hash256,
        /// Whether that tree is the admitted workspace tree this diff is about.
        matches_admitted_tree: bool,
        /// Artifact paths whose entities were re-derived. Only a changed artifact
        /// can move an entity, so this is the tree delta's own path set.
        derived_paths: usize,
    },
    /// No live graph was available, so the entity and relation counts are the
    /// admitted overlay's and cannot move. Reported rather than printed as a
    /// zero, which is the zero-file-search rule applied to a read: when the
    /// graph cannot answer, report the gap.
    AdmittedOverlayOnly,
}

pub fn inspect(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: Option<&str>,
    head: Option<&str>,
    live: Option<&kin_db::InMemoryGraph>,
) -> Result<DiffReport> {
    inspect_with_endpoint_entities(binding, base, head, live).map(|(report, _)| report)
}

pub fn inspect_with_endpoint_entities(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: Option<&str>,
    head: Option<&str>,
    live: Option<&kin_db::InMemoryGraph>,
) -> Result<(DiffReport, DiffEndpointEntities)> {
    let authority = ActiveRepositoryAuthority::open(binding)?;
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow!(
                "repository {} has no workspace {} in its authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    workspace
        .validate()
        .context("active repository-v6 workspace is invalid")?;

    // Build the immutable history resolver from the exact snapshot carried by
    // this lease. The authority envelope is excluded from the query graph; it
    // remains owned by `lease` and cannot be confused with graph content.
    let mut history_snapshot = lease.snapshot().clone();
    history_snapshot.repository_authority = None;
    let expected_root_hash = kin_db::compute_graph_root_hash(&history_snapshot);
    let history = kin_db::InMemoryGraph::from_snapshot_without_text_index_with_root_hash(
        history_snapshot,
        expected_root_hash,
    )
    .context("open immutable repository-v6 history for diff")?;

    // Git-compatible default: HEAD is the committed workspace base and the
    // implicit right side is Kin's exact graph-owned workspace tree.
    let base_state = resolve_endpoint(
        &lease,
        workspace,
        &history,
        base.unwrap_or("HEAD"),
        base.is_some(),
    )
    .context("resolve diff base")?;
    let head_state = resolve_endpoint(
        &lease,
        workspace,
        &history,
        head.unwrap_or("WORKSPACE"),
        head.is_some(),
    )
    .context("resolve diff head")?;

    let artifact_deltas = diff_trees(&base_state.tree, &head_state.tree);
    // Derived here rather than in the endpoint arm, and the order is the whole
    // reason: only a CHANGED artifact can move an entity, and which artifacts
    // changed is not known until both endpoints have resolved. Deriving in the
    // arm would mean one query per file in the tree instead of one per file that
    // moved.
    let mut base_state = base_state;
    let mut head_state = head_state;
    let semantic_basis = derive_workspace_semantics(
        live,
        workspace.tree_hash,
        &artifact_deltas,
        &mut base_state,
        &mut head_state,
    );
    let (entity_deltas, entities_unchanged) =
        diff_entities(&base_state.entities, &head_state.entities);
    let relation_deltas = diff_relations(&base_state.relations, &head_state.relations);
    let summary = summarize(
        &artifact_deltas,
        &entity_deltas,
        &relation_deltas,
        entities_unchanged,
    );

    let report = DiffReport {
        artifact_content: Vec::new(),
        schema: DIFF_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: lease.roots().generation,
        roots: lease.roots().clone(),
        workspace_id: authority.workspace_id,
        base: base_state.report,
        head: head_state.report,
        summary,
        artifact_deltas,
        entity_deltas,
        relation_deltas,
        semantic_basis,
    };
    Ok((
        report,
        DiffEndpointEntities {
            base: base_state.entities,
            head: head_state.entities,
        },
    ))
}

/// Re-derive a workspace endpoint's semantics for the artifacts that moved.
///
/// The base map is kept and only the CHANGED files are replaced in it. That is
/// not an optimisation, it is the correctness condition: `diff_entities` diffs
/// whole maps, so a partially populated endpoint would report every unchanged
/// file's entities as REMOVED. Overlaying onto the admitted map is what keeps the
/// answer about the edit.
///
/// One `query_entities` per moved path, filtered by file, which is the idiom
/// `trace.rs` already uses. Deliberately NOT `to_snapshot`: that deep-clones
/// every sub-store including the change DAG, and the commit path's own comment
/// records it staying resident through the resident-set peak of a one-file commit
/// on a 1.0 GB store. A diff must not pay that.
///
/// Returns `None` when neither endpoint is the workspace, because then both sides
/// are history and the entity delta is already computed and already means what it
/// says.
fn derive_workspace_semantics(
    live: Option<&kin_db::InMemoryGraph>,
    admitted_tree_hash: Hash256,
    artifact_deltas: &[kin_model::TreeDelta],
    base_state: &mut EndpointState,
    head_state: &mut EndpointState,
) -> Option<WorkspaceSemanticBasis> {
    let base_is_workspace = matches!(base_state.report.source, DiffEndpointSource::Workspace);
    let head_is_workspace = matches!(head_state.report.source, DiffEndpointSource::Workspace);
    if !base_is_workspace && !head_is_workspace {
        return None;
    }
    let Some(graph) = live else {
        return Some(WorkspaceSemanticBasis::AdmittedOverlayOnly);
    };

    // The tree the live graph actually holds. A reconcile can land between the
    // authority lease read and this query, and an answer derived from a newer
    // graph than the tree it describes is a different answer, so it is named
    // rather than assumed.
    let graph_tree = graph.resolved_tree();
    let graph_tree_hash = match kin_model::compute_resolved_tree_hash(&graph_tree) {
        Ok(hash) => hash,
        // A tree that will not hash is not a basis. Fall back to the admitted
        // overlay and say so, rather than deriving from something unnameable.
        Err(_) => return Some(WorkspaceSemanticBasis::AdmittedOverlayOnly),
    };
    drop(graph_tree);

    let mut paths: Vec<kin_model::RepoPath> = Vec::new();
    for delta in artifact_deltas {
        for located in [delta.old_state(), delta.new_state()].into_iter().flatten() {
            if !paths.contains(&located.path) {
                paths.push(located.path.clone());
            }
        }
    }

    let mut derived_paths = 0usize;
    for path in &paths {
        // A non-UTF-8 path cannot be handed to a file-path filter. It is skipped
        // rather than guessed at, and the count below reports how many paths were
        // actually re-derived so a reader can see the difference.
        let Some(text) = path.as_utf8() else { continue };
        let filter = kin_model::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(text)),
            ..Default::default()
        };
        // `query_entities` is an `EntityStore` method, not an inherent one and not
        // `GraphStore`'''s, which is what the compiler had to tell me. Imported at
        // the call rather than at the module head so a reader sees which surface
        // this read comes from.
        use kin_model::EntityStore as _;
        let Ok(found) = graph.query_entities(&filter) else {
            continue;
        };
        for state in [
            (base_is_workspace, &mut *base_state),
            (head_is_workspace, &mut *head_state),
        ]
        .into_iter()
        .filter_map(|(is_workspace, state)| is_workspace.then_some(state))
        {
            // Retire this file's admitted entities, then insert what the graph
            // holds. Replacing rather than merging, because an entity the edit
            // DELETED must leave the map or the delta under-reports.
            state.entities.retain(|_, entity| {
                entity
                    .file_origin
                    .as_ref()
                    .map(|origin| origin.0 != text)
                    .unwrap_or(true)
            });
            for entity in &found {
                state.entities.insert(entity.id, entity.clone());
            }
        }
        derived_paths += 1;
    }

    Some(WorkspaceSemanticBasis::Derived {
        graph_tree_hash,
        matches_admitted_tree: graph_tree_hash == admitted_tree_hash,
        derived_paths,
    })
}

/// The state one endpoint selector names.
///
/// `WORKSPACE` is answered here and everything else is handed to
/// [`super::ref_grammar`], the one grammar `kin blame --ref` and
/// `kin history --ref` also speak. FIR-3015: this function used to carry a
/// second parser, which knew `@`, `ref:` and `ref-hex:` and did not know
/// `HEAD~N`, `kin:`, `branch:` or a short change id, so `kin diff` refused
/// three forms in a row that its own sibling commands had just printed or
/// accepted.
///
/// `WORKSPACE` stays local because it is not a point in history. It names the
/// uncommitted working tree, there is no change id behind it, and it carries an
/// entity and relation snapshot the history arms have to derive.
fn resolve_endpoint(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    workspace: &kin_model::WorkspaceState,
    history: &kin_db::InMemoryGraph,
    selector: &str,
    requested_explicitly: bool,
) -> Result<EndpointState> {
    let requested = requested_explicitly.then(|| selector.to_string());
    match selector {
        "WORKSPACE" | "workspace" => {
            let snapshot = lease
                .workspace_graph_snapshot(&workspace.workspace_id)
                .context("materialize exact workspace graph for diff")?
                .ok_or_else(|| {
                    anyhow!(
                        "workspace {} disappeared from the active authority lease",
                        workspace.workspace_id
                    )
                })?;
            let change_id = workspace
                .base_target
                .as_ref()
                .map(|target| lease.resolve_target_change_id(target))
                .transpose()
                .context("resolve workspace semantic base for diff")?;
            let report = DiffEndpoint {
                source: DiffEndpointSource::Workspace,
                requested,
                ref_name: match &workspace.head {
                    WorkspaceHead::Symbolic { target } => Some(target.clone()),
                    WorkspaceHead::Detached { .. } => None,
                },
                target: workspace.base_target.clone(),
                change_id,
                workspace_generation: Some(workspace.generation),
                workspace_head: Some(workspace.head.clone()),
                tree_hash: workspace.tree_hash,
                artifact_count: workspace.tree.artifacts().len(),
                entity_count: snapshot.entities.len(),
                relation_count: snapshot.relations.len(),
            };
            return Ok(EndpointState {
                report,
                tree: workspace.tree.clone(),
                entities: snapshot.entities,
                relations: snapshot.relations,
            });
        }
        // A repository with no commits yet has an empty base rather than a
        // missing one, so `kin diff` against a fresh HEAD shows the whole
        // workspace as added. The shared resolver refuses an unborn HEAD, which
        // is right for blame and wrong here, so the case is answered before it.
        "HEAD" | "@" if workspace.base_target.is_none() => {
            return EndpointState::empty(DiffEndpointSource::Head, requested);
        }
        _ => {}
    }

    let authority = super::ref_grammar::Authority::held(lease, &workspace.workspace_id);
    let resolved = super::ref_grammar::resolve(&authority, history, selector)?;
    let source = match resolved.kind {
        super::ref_grammar::SelectorKind::Head => DiffEndpointSource::Head,
        super::ref_grammar::SelectorKind::Ref => DiffEndpointSource::Ref,
        super::ref_grammar::SelectorKind::Change => DiffEndpointSource::Change,
        super::ref_grammar::SelectorKind::GitObject => DiffEndpointSource::GitObject,
    };
    // HEAD reports the ref the workspace is standing on, which the resolver does
    // not know: it answers about history and this is a property of the workspace.
    let ref_name = match resolved.kind {
        super::ref_grammar::SelectorKind::Head => match &workspace.head {
            WorkspaceHead::Symbolic { target } => Some(target.clone()),
            WorkspaceHead::Detached { .. } => None,
        },
        _ => resolved.ref_name.clone(),
    };
    state_at_change(
        history,
        DiffEndpoint {
            source,
            requested,
            ref_name,
            target: resolved.target.clone(),
            change_id: Some(resolved.change_id),
            workspace_generation: None,
            workspace_head: None,
            tree_hash: Hash256::from_bytes([0; 32]),
            artifact_count: 0,
            entity_count: 0,
            relation_count: 0,
        },
        resolved.change_id,
    )
}

fn state_at_change(
    history: &kin_db::InMemoryGraph,
    mut report: DiffEndpoint,
    change_id: SemanticChangeId,
) -> Result<EndpointState> {
    require_change(history, change_id)?;
    let resolved = history
        .resolve_graph_at(&change_id)
        .with_context(|| format!("resolve immutable repository state at {change_id}"))?;
    report.tree_hash =
        compute_resolved_tree_hash(&resolved.tree).context("hash resolved diff endpoint tree")?;
    report.artifact_count = resolved.tree.artifacts().len();
    report.entity_count = resolved.entities.len();
    report.relation_count = resolved.relations.len();
    Ok(EndpointState {
        report,
        tree: resolved.tree,
        entities: resolved.entities,
        relations: resolved.relations,
    })
}

fn require_change(history: &kin_db::InMemoryGraph, change_id: SemanticChangeId) -> Result<()> {
    if history
        .get_change(&change_id)
        .with_context(|| format!("read immutable semantic change {change_id}"))?
        .is_none()
    {
        bail!(
            "semantic change '{change_id}' is not in this repository's authority, so there is \
             nothing to diff it against; run `kin log` to see the changes kin holds"
        );
    }
    Ok(())
}

fn diff_trees(base: &ResolvedTree, head: &ResolvedTree) -> Vec<TreeDelta> {
    let ids = base
        .artifacts()
        .map(|artifact| artifact.artifact_id)
        .chain(head.artifacts().map(|artifact| artifact.artifact_id))
        .collect::<BTreeSet<_>>();
    ids.into_iter()
        .filter_map(
            |artifact_id| match (base.get(&artifact_id), head.get(&artifact_id)) {
                (None, Some(new)) => Some(TreeDelta::Added {
                    artifact_id,
                    new: new.located_entry(),
                }),
                (Some(old), Some(new)) if old != new => Some(TreeDelta::Updated {
                    artifact_id,
                    old: old.located_entry(),
                    new: new.located_entry(),
                }),
                (Some(old), None) => Some(TreeDelta::Removed {
                    artifact_id,
                    old: old.located_entry(),
                }),
                (Some(_), Some(_)) | (None, None) => None,
            },
        )
        .collect()
}

/// The entity transitions between two graph states, and how many file-level
/// ones were withheld.
///
/// A `Modified` delta is reported when the entity's own CONTENT moved, asked
/// through [`kin_core::workspace_semantics::entity_content_agrees`], which is
/// the same question `kin conflicts`, `kin log`, `kin blame` and `kin history`
/// ask. Comparing the whole `Entity` here is what made `kin diff` answer a
/// two-function commit with `Entities: +1 ~11 -0` and list nine functions the
/// author never touched: `reconciler` stamps the whole FILE's blob hash into
/// every entity's `metadata.extra`, and editing one function moves the byte
/// span of every entity below it, so every entity in a changed file compares
/// unequal.
///
/// The withheld count is returned rather than dropped. Those revisions are
/// real, they are what the file did, and a reader who cannot see that they
/// exist has lost information rather than been spared noise. That is the
/// contract `kin blame` already holds its own listing to.
fn diff_entities(
    base: &HashMap<EntityId, Entity>,
    head: &HashMap<EntityId, Entity>,
) -> (Vec<EntityDelta>, usize) {
    let mut deltas = Vec::new();
    let mut withheld = 0usize;
    for entity_id in base
        .keys()
        .copied()
        .chain(head.keys().copied())
        .collect::<BTreeSet<_>>()
    {
        match (base.get(&entity_id), head.get(&entity_id)) {
            (None, Some(new)) => deltas.push(EntityDelta::Added { new: new.clone() }),
            (Some(old), Some(new)) if old != new => {
                if kin_core::workspace_semantics::entity_content_agrees(old, new) {
                    withheld += 1;
                } else {
                    deltas.push(EntityDelta::Modified {
                        old: old.clone(),
                        new: new.clone(),
                    });
                }
            }
            (Some(old), None) => deltas.push(EntityDelta::Removed { old: old.clone() }),
            (Some(_), Some(_)) | (None, None) => {}
        }
    }
    (deltas, withheld)
}

fn diff_relations(
    base: &HashMap<RelationId, Relation>,
    head: &HashMap<RelationId, Relation>,
) -> Vec<RelationDelta> {
    base.keys()
        .copied()
        .chain(head.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(
            |relation_id| match (base.get(&relation_id), head.get(&relation_id)) {
                (None, Some(new)) => Some(RelationDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(RelationDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(RelationDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            },
        )
        .collect()
}

fn summarize(
    artifacts: &[TreeDelta],
    entities: &[EntityDelta],
    relations: &[RelationDelta],
    entities_unchanged: usize,
) -> DiffSummary {
    let mut summary = DiffSummary {
        entities_unchanged,
        ..DiffSummary::default()
    };
    for delta in artifacts {
        match delta {
            TreeDelta::Added { .. } => summary.artifacts_added += 1,
            TreeDelta::Updated { .. } => summary.artifacts_updated += 1,
            TreeDelta::Removed { .. } => summary.artifacts_removed += 1,
        }
    }
    for delta in entities {
        match delta {
            EntityDelta::Added { .. } => summary.entities_added += 1,
            EntityDelta::Modified { .. } => summary.entities_modified += 1,
            EntityDelta::Removed { .. } => summary.entities_removed += 1,
        }
    }
    for delta in relations {
        match delta {
            RelationDelta::Added { .. } => summary.relations_added += 1,
            RelationDelta::Modified { .. } => summary.relations_modified += 1,
            RelationDelta::Removed { .. } => summary.relations_removed += 1,
        }
    }
    summary
}

pub async fn run(
    base: Option<String>,
    head: Option<String>,
    json: bool,
    full_bodies: bool,
) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let workspace_endpoint =
        endpoint_is_workspace(base.as_deref()) || endpoint_is_workspace(head.as_deref());

    // ADMIT FIRST, before anything reads, including before the daemon route
    // below. The order is the whole point and I got it wrong once: routing to the
    // daemon ahead of the admission answered from a graph that had not seen the
    // edit, and the resident-set measurement caught it printing
    // `Artifacts: +0 ~0 -0` over a file written a moment earlier, which is the
    // very defect kin#1258 landed to fix.
    //
    // Admission is what makes the answer about the working copy; the daemon route
    // is what makes its entity half real. Both are needed and this one is first.
    //
    // Only when a workspace endpoint is involved. A diff between two changes is
    // history, and walking the tree to answer it would be a cost with nothing
    // behind it. Reading the working copy to ADMIT it is ingestion at an explicit
    // input boundary, not answering from files.
    let pass = if workspace_endpoint {
        Some(crate::commands::status::admit_before_reading(&layout).await)
    } else {
        None
    };

    // A workspace endpoint's entities are DERIVED, and the daemon's graph is the
    // only place they exist, so a workspace diff asks the daemon once the
    // admission above has landed.
    //
    // Never fatal. If the daemon is absent or refuses, this falls through to the
    // local answer, which names its own gap rather than printing a zero that
    // reads like an answer.
    if !json && workspace_endpoint {
        if let Some(response) = daemon_diff(&layout, &base, &head).await {
            for line in response.lines {
                println!("{line}");
            }
            if let Some(report) = response.report.as_ref() {
                // Content on the daemon route too, and by the SAME renderer.
                //
                // The daemon renders its own header lines and this appends after
                // them, so its output stays byte-identical and the wire payload
                // is unchanged. The report it already returns carries both blob
                // hashes, so the CLI opens its own binding and reads CAS here.
                // Two renderings of a content diff would drift, and the one
                // nobody runs would be the one that drifts.
                for line in content_lines_for(&layout, report, full_bodies) {
                    println!("{line}");
                }
                if let Some(line) = semantic_scope_line(report.semantic_basis.as_ref()) {
                    println!("{line}");
                }
            }
            if let Some(crate::commands::status::StatusAdmission::Skipped(why)) = pass.as_ref() {
                println!(
                    "Admission scope: this diff was not measured against the working copy: {why}"
                );
            }
            println!("{}", admitted_scope_line(&layout));
            return Ok(());
        }
    }
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    // No live graph on this path: the CLI opens durable authority in-process and
    // the entities a workspace endpoint needs live in the daemon's graph. So this
    // derives nothing and the basis says so by name, which is the zero
    // file-search rule applied to a read: when the graph cannot answer, report
    // the gap rather than a zero that reads like an answer.
    let mut report = inspect(&binding, base.as_deref(), head.as_deref(), None)?;
    if let Ok(authority) =
        crate::commands::repository_authority::ActiveRepositoryAuthority::open(&binding)
    {
        report.artifact_content =
            collect_artifact_content(&authority, &report.artifact_deltas, full_bodies);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_lines(&report) {
            println!("{line}");
        }
        for row in &report.artifact_content {
            for line in render_content_lines(row) {
                println!("{line}");
            }
        }
        if let Some(line) = semantic_scope_line(report.semantic_basis.as_ref()) {
            println!("{line}");
        }
        if let Some(crate::commands::status::StatusAdmission::Skipped(why)) = pass.as_ref() {
            println!("Admission scope: this diff was not measured against the working copy: {why}");
        }
        println!("{}", admitted_scope_line(&layout));
    }
    Ok(())
}

/// Content lines for a report the daemon rendered, read from this CLI's own CAS.
///
/// Best effort by design: a diff that refused because the binding would not open
/// would be a regression against the command as it shipped, so a failure here
/// yields no lines rather than an error, exactly as `daemon_diff` itself does.
fn content_lines_for(
    layout: &kin_core::KinLayout,
    report: &DiffReport,
    full_bodies: bool,
) -> Vec<String> {
    let Ok(binding) = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout) else {
        return Vec::new();
    };
    let Ok(authority) =
        crate::commands::repository_authority::ActiveRepositoryAuthority::open(&binding)
    else {
        return Vec::new();
    };
    collect_artifact_content(&authority, &report.artifact_deltas, full_bodies)
        .iter()
        .flat_map(render_content_lines)
        .collect()
}

/// Ask the daemon for a diff, or `None` when it cannot answer.
///
/// Deliberately swallows every failure into `None`. This is a best-effort upgrade
/// of one answer, not a dependency: a `kin diff` that refused because no daemon
/// was running would be a regression against the command as it shipped, and the
/// local path it falls back to states its own gap.
async fn daemon_diff(
    layout: &kin_core::KinLayout,
    base: &Option<String>,
    head: &Option<String>,
) -> Option<DiffResponse> {
    let base_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout).await?;
    let client =
        crate::daemon_client::DaemonClient::from_base_url_for_layout(base_url, layout).ok()?;
    let request = DiffRequest {
        base: base.clone(),
        head: head.clone(),
        // The daemon renders its own lines and this path only takes the text
        // path, so it never asks for the JSON shape.
        json: false,
    };
    client.diff(&request).await.ok()
}

/// Whether a requested endpoint spelling names the workspace.
///
/// `None` is the workspace on the head side and HEAD on the base side, and the
/// defaults are applied inside `inspect`, so this asks about the SPELLING a
/// caller used and errs toward admitting: a bare `kin diff` is the everyday
/// call and its head endpoint is the workspace.
fn endpoint_is_workspace(requested: Option<&str>) -> bool {
    matches!(requested, None | Some("WORKSPACE") | Some("workspace"))
}

/// What the ENTITY count above cannot show on a workspace endpoint.
///
/// Narrower than it first shipped, and the narrowing matters. A workspace
/// endpoint's semantic side is its base change's entities and relations plus the
/// workspace semantic overlay. Nothing ever writes an ENTITY delta into that
/// overlay: the admission seam publishes
/// `semantic_delta: WorkspaceSemanticDelta::default()` unconditionally, and the
/// enrichment writer computes its delta with the authority entities as BOTH the
/// base and the desired side (`kin-daemon/src/state.rs`), so an entity delta is
/// structurally impossible from either. RELATION deltas do reach it, from that
/// same enrichment writer, whose relation arguments are not the same value twice.
///
/// So `Entities: +0 ~0 -0` beside a moving `Relations` line is not a
/// contradiction, and saying so is the point. Two independent runs read the pair
/// as an answer and went looking for a broken semantic layer: one over a
/// rewritten function body against a fully settled graph (`kin graph status`: 78
/// of 78 embeddings indexed, 8 of 8 files at 100% coverage), and one over an
/// appended top-level function that read `Artifacts: +0 ~1 -0`,
/// `Relations: +0 ~9 -0`, `Entities: +0 ~0 -0`, unchanged twenty seconds later at
/// the same authority generation, while `kin status` already counted the entity
/// and the commit that followed recorded ten of them (FIR-2961).
///
/// Silent on a diff between two changes, where the entity delta is computed and
/// means what it says.
fn semantic_scope_line(basis: Option<&WorkspaceSemanticBasis>) -> Option<String> {
    // Derived answers name their own basis instead of the old blanket
    // disclaimer, because the count CAN move now and a line saying it cannot
    // would be the new wrong sentence.
    match basis {
        Some(WorkspaceSemanticBasis::Derived {
            graph_tree_hash,
            matches_admitted_tree,
            derived_paths,
        }) => {
            let qualifier = if *matches_admitted_tree {
                String::new()
            } else {
                format!(
                    ", but that graph holds tree {graph_tree_hash} rather than the admitted \
                     workspace tree, so a reconcile landed between the two reads and this \
                     describes the newer one"
                )
            };
            return Some(format!(
                "Semantic scope: entities and relations for the {derived_paths} moved path(s) \
                 were derived from the live graph{qualifier}."
            ));
        }
        Some(WorkspaceSemanticBasis::AdmittedOverlayOnly) => {
            return Some(
                "Semantic scope: no live graph was reachable, so the entity and relation counts \
                 above are the admitted overlay's and cannot move for work in the working copy. \
                 That is a gap in this answer, not a statement that nothing changed; start the \
                 daemon, or commit and diff change to change."
                    .to_string(),
            );
        }
        None => {}
    }
    None
}

/// What this diff does not cover, and when the graph last caught up.
///
/// Both endpoints are admitted authority, so a file the working copy holds and
/// no admission has taken contributes nothing to either side and the summary
/// reads `+0 ~0 -0`. That answer is exactly right about authority and reads as
/// "nothing changed" to anyone who just wrote a file, which is how a session
/// concluded the graph could not see its own new module (FIR-2499). Naming the
/// scope beside the counts is what tells those two apart.
///
/// The clock comes from the durable last-admission marker rather than from a
/// daemon, because this command talks to none. That bounds what it can say: it
/// reports WHEN the graph last caught up, never HOW MANY host paths are
/// outstanding, which needs the daemon's own reconcile reading.
fn admitted_scope_line(layout: &kin_core::KinLayout) -> String {
    let scope = "Admitted scope: both endpoints are admitted repository authority, so host \
                 content no admission has taken appears on neither side";
    match kin_core::last_admission::read(layout) {
        kin_core::last_admission::LastAdmissionRead::Recorded(recorded) => format!(
            "{scope}; graph truth was last admitted at {} over {} artifact(s).",
            recorded.at.to_rfc3339(),
            recorded.tracked_artifacts
        ),
        kin_core::last_admission::LastAdmissionRead::Absent => format!(
            "{scope}; this store records no complete admission, so how far it is behind is \
             unknown. `kin admit` takes what the working copy holds."
        ),
        kin_core::last_admission::LastAdmissionRead::Unreadable(reason) => format!(
            "{scope}; the last-admission marker will not parse ({reason}), so how far this store \
             is behind is unknown. `kin admit` takes what the working copy holds."
        ),
    }
}

pub fn build_diff_response(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    request: &DiffRequest,
    live: Option<&kin_db::InMemoryGraph>,
) -> Result<DiffResponse> {
    let report = inspect(
        binding,
        request.base.as_deref(),
        request.head.as_deref(),
        live,
    )?;
    Ok(DiffResponse {
        lines: render_lines(&report),
        report: Some(report),
    })
}

/// The line naming what the entity counts did not show.
///
/// Named rather than silent. The withheld revisions are real, they are what the
/// file did, and a reader who cannot see that they exist has lost information
/// rather than been spared noise.
///
/// Half of `kin blame`'s contract, not all of it. Blame names its withheld
/// count AND takes `--all-revisions` to list them; `kin diff` names the count
/// and has no flag that shows them yet. Saying so here rather than claiming the
/// whole contract, because the flag is the follow-up and a comment that claims
/// it is the reason nobody writes it.
fn unchanged_entities_line(unchanged: usize) -> Option<String> {
    if unchanged == 0 {
        return None;
    }
    let plural = if unchanged == 1 { "y" } else { "ies" };
    Some(format!(
        "{unchanged} entit{plural} moved with a changed artifact without changing; \
         they are not counted above"
    ))
}

fn render_lines(report: &DiffReport) -> Vec<String> {
    let mut lines = vec![
        "Kin repository-v6 diff".to_string(),
        format!("Authority generation: {}", report.authority_generation),
        format!("Base: {}", render_endpoint(&report.base)),
        format!("Head: {}", render_endpoint(&report.head)),
        format!(
            "Artifacts: +{} ~{} -{}",
            report.summary.artifacts_added,
            report.summary.artifacts_updated,
            report.summary.artifacts_removed
        ),
        format!(
            "Entities: +{} ~{} -{}",
            report.summary.entities_added,
            report.summary.entities_modified,
            report.summary.entities_removed
        ),
        format!(
            "Relations: +{} ~{} -{}",
            report.summary.relations_added,
            report.summary.relations_modified,
            report.summary.relations_removed
        ),
    ];
    if let Some(line) = unchanged_entities_line(report.summary.entities_unchanged) {
        lines.push(line);
    }
    for delta in &report.artifact_deltas {
        lines.push(render_tree_delta(delta));
    }
    for delta in &report.entity_deltas {
        lines.push(match delta {
            EntityDelta::Added { new } => format!("E+ {} {}", new.id, new.name),
            EntityDelta::Modified { old, new } => {
                format!("E~ {} {} -> {}", new.id, old.name, new.name)
            }
            EntityDelta::Removed { old } => format!("E- {} {}", old.id, old.name),
        });
    }
    for delta in &report.relation_deltas {
        lines.push(match delta {
            RelationDelta::Added { new } => format!("R+ {} {:?}", new.id, new.kind),
            RelationDelta::Modified { old, new } => {
                format!("R~ {} {:?} -> {:?}", new.id, old.kind, new.kind)
            }
            RelationDelta::Removed { old } => format!("R- {} {:?}", old.id, old.kind),
        });
    }
    lines
}

fn render_endpoint(endpoint: &DiffEndpoint) -> String {
    match endpoint.source {
        DiffEndpointSource::Empty => "empty tree".to_string(),
        DiffEndpointSource::Workspace => format!(
            "workspace generation {} ({})",
            endpoint.workspace_generation.unwrap_or_default(),
            endpoint.tree_hash
        ),
        DiffEndpointSource::Head => format!(
            "HEAD {} ({})",
            endpoint
                .change_id
                .map(|change| change.to_string())
                .unwrap_or_else(|| "unborn".to_string()),
            endpoint.tree_hash
        ),
        DiffEndpointSource::Ref => format!(
            "{} {} ({})",
            endpoint
                .ref_name
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<unknown ref>".to_string()),
            endpoint
                .change_id
                .map(|change| change.to_string())
                .unwrap_or_else(|| "<unborn>".to_string()),
            endpoint.tree_hash
        ),
        DiffEndpointSource::Change | DiffEndpointSource::GitObject => format!(
            "{} ({})",
            endpoint
                .requested
                .as_deref()
                .unwrap_or("<implicit endpoint>"),
            endpoint.tree_hash
        ),
    }
}

/// The one content cap, borrowed from the hosted semantic surface rather than
/// invented. `kin_db::MAX_SOURCE_BLOB_BYTES` is 1 GiB, which is a storage bound
/// and not a display one.
const CONTENT_MAX_BYTES: u64 = kin_mcp::handlers::HOSTED_SEMANTIC_SOURCE_BLOB_MAX_BYTES;

/// Read one side's body out of graph-owned CAS, or say why not.
///
/// Never touches the working copy. The digest comes from the artifact delta the
/// caller already holds, and `load_source_blob` reads repository-owned CAS
/// through KinDB, which re-verifies the digest at the manager boundary. So the
/// Zero File-Search Authority Rule holds by construction here rather than by
/// argument: there is no filesystem path in this function to get wrong.
fn load_side(
    authority: &crate::commands::repository_authority::ActiveRepositoryAuthority,
    digest: Option<Hash256>,
) -> Result<Option<String>, String> {
    let Some(digest) = digest else {
        return Ok(None);
    };
    let bytes = authority
        .load_source_blob(digest)
        .map_err(|error| format!("blob {digest} could not be read: {error}"))?;
    if bytes.len() as u64 > CONTENT_MAX_BYTES {
        return Err(format!(
            "content omitted: {} bytes over the {} byte cap",
            bytes.len() as u64 - CONTENT_MAX_BYTES,
            CONTENT_MAX_BYTES
        ));
    }
    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(text)),
        Err(error) => Err(format!(
            "content omitted: not valid UTF-8 ({} bytes)",
            error.into_bytes().len()
        )),
    }
}

/// Render two bodies as unified hunks.
///
/// `pub(crate)` because `kin conflicts` renders each conflict side's
/// re-materialized body with THIS function rather than a second one. One
/// renderer for diff and conflicts is what keeps the two surfaces from drifting,
/// and a conflict body rendered differently from a diff body is a difference a
/// reader would have to learn rather than read.
///
/// THE one renderer. The JSON hunks and the text surface both come from here, so
/// the two cannot drift into disagreeing about what changed, which is the whole
/// reason this is a function and not two call sites.
pub(crate) fn render_hunks(old: Option<&str>, new: Option<&str>) -> Vec<String> {
    let old = old.unwrap_or("");
    let new = new.unwrap_or("");
    if old == new {
        return Vec::new();
    }
    // `unified_diff` and `iter_hunks` are the DEFAULT-feature path. The inline
    // API next to them requires similar's `inline` feature, which is not on by
    // default, and reaching for it is what failed this file's first compile.
    let diff = similar::TextDiff::from_lines(old, new);
    let mut unified = diff.unified_diff();
    unified.context_radius(3);
    let mut out = Vec::new();
    for hunk in unified.iter_hunks() {
        let mut text = format!("{}\n", hunk.header());
        for change in hunk.iter_changes() {
            let sign = match change.tag() {
                similar::ChangeTag::Delete => '-',
                similar::ChangeTag::Insert => '+',
                similar::ChangeTag::Equal => ' ',
            };
            text.push(sign);
            text.push_str(change.value());
            if change.missing_newline() {
                text.push('\n');
            }
        }
        out.push(text);
    }
    out
}

/// Build the content rows for a report's artifact deltas.
fn collect_artifact_content(
    authority: &crate::commands::repository_authority::ActiveRepositoryAuthority,
    deltas: &[TreeDelta],
    full_bodies: bool,
) -> Vec<ArtifactContent> {
    let mut rows = Vec::new();
    for delta in deltas {
        let (artifact_id, path, old_hash, new_hash) = match delta {
            TreeDelta::Added { artifact_id, new } => (
                artifact_id.clone(),
                new.path.to_string(),
                None,
                new.entry.blob_identity(),
            ),
            TreeDelta::Removed { artifact_id, old } => (
                artifact_id.clone(),
                old.path.to_string(),
                old.entry.blob_identity(),
                None,
            ),
            TreeDelta::Updated {
                artifact_id,
                old,
                new,
            } => (
                artifact_id.clone(),
                new.path.to_string(),
                old.entry.blob_identity(),
                new.entry.blob_identity(),
            ),
        };
        // A mode-only or move-only change moves no bytes, and a row saying so
        // is noise. An identical pair is the same case reached differently.
        if old_hash.is_some() && old_hash == new_hash {
            continue;
        }
        let mut row = ArtifactContent {
            artifact_id,
            path,
            old_hash,
            new_hash,
            hunks: Vec::new(),
            old_text: None,
            new_text: None,
            omitted: None,
        };
        let old_text = match load_side(authority, old_hash) {
            Ok(text) => text,
            Err(why) => {
                row.omitted = Some(why);
                rows.push(row);
                continue;
            }
        };
        let new_text = match load_side(authority, new_hash) {
            Ok(text) => text,
            Err(why) => {
                row.omitted = Some(why);
                rows.push(row);
                continue;
            }
        };
        row.hunks = render_hunks(old_text.as_deref(), new_text.as_deref());
        if full_bodies {
            row.old_text = old_text;
            row.new_text = new_text;
        }
        rows.push(row);
    }
    rows
}

/// The text rendering of one content row, from the same hunks the JSON carries.
fn render_content_lines(row: &ArtifactContent) -> Vec<String> {
    if let Some(why) = row.omitted.as_deref() {
        return vec![format!("   {} {}", row.path, why)];
    }
    let mut lines = Vec::new();
    for hunk in &row.hunks {
        for line in hunk.lines() {
            lines.push(format!("   {line}"));
        }
    }
    lines
}

fn render_tree_delta(delta: &TreeDelta) -> String {
    match delta {
        TreeDelta::Added { artifact_id, new } => format!(
            "A  {} [{}] {}",
            new.path,
            artifact_id.0,
            render_tree_entry(new.entry)
        ),
        TreeDelta::Updated {
            artifact_id,
            old,
            new,
        } => format!(
            "M  {} -> {} [{}] {} -> {}",
            old.path,
            new.path,
            artifact_id.0,
            render_tree_entry(old.entry),
            render_tree_entry(new.entry)
        ),
        TreeDelta::Removed { artifact_id, old } => format!(
            "D  {} [{}] {}",
            old.path,
            artifact_id.0,
            render_tree_entry(old.entry)
        ),
    }
}

fn render_tree_entry(entry: TreeEntry) -> String {
    match entry {
        TreeEntry::Blob { hash, executable } => format!(
            "blob {hash} mode={}",
            if executable { "100755" } else { "100644" }
        ),
        TreeEntry::Symlink { target_blob } => format!("symlink {target_blob} mode=120000"),
        TreeEntry::Gitlink { target } => format!("gitlink {target} mode=160000"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        relation::GraphNodeId, ArtifactId, EntityKind, EntityMetadata, EntityRole, FilePathId,
        FingerprintAlgorithm, LanguageId, RelationKind, RelationOrigin, RepoPath, ResolvedArtifact,
        SemanticFingerprint, Visibility,
    };

    fn entity(id: EntityId, name: &str) -> Entity {
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([4; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Private,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// `entity`, plus the file-level noise a real reconcile stamps on every
    /// entity in a touched file whether or not that entity moved: the whole
    /// FILE's blob hash in `metadata.extra`, and the byte span everything below
    /// an edit shifts to.
    fn entity_stamped(id: EntityId, name: &str, body: u8, stamp: u8) -> Entity {
        let mut built = entity(id, name);
        built.fingerprint.ast_hash = Hash256::from_bytes([body; 32]);
        built.fingerprint.behavior_hash = Hash256::from_bytes([body; 32]);
        built.fingerprint.equivalence_hash = Hash256::from_bytes([body; 32]);
        built.metadata.extra.insert(
            "artifact_blob".to_string(),
            serde_json::Value::String(format!("{stamp:02x}")),
        );
        built.span = Some(kin_model::SourceSpan {
            file: FilePathId::new("ledger/reporting.py"),
            start_byte: usize::from(stamp) * 100,
            end_byte: usize::from(stamp) * 100 + 40,
            start_line: u32::from(stamp),
            start_col: 0,
            end_line: u32::from(stamp) + 3,
            end_col: 0,
        });
        built
    }

    /// The vcs stranger run's `kin diff` finding, rebuilt.
    ///
    /// A commit that edited two function bodies reported
    /// `Entities: +1 ~11 -0` and listed nine functions the author never
    /// touched, because `diff_entities` compared the whole `Entity` and every
    /// entity in a changed file carries that file's blob hash and a shifted
    /// span. Twelve entities live in the two changed files, one is new, and
    /// exactly one of the survivors was edited.
    ///
    /// Breaking it: put `old != new` back in place of the content comparison in
    /// `diff_entities` and this reports eleven modified.
    #[test]
    fn a_two_function_commit_reports_the_functions_it_changed() {
        let ids: Vec<EntityId> = (0..12).map(|_| EntityId::new()).collect();
        let added = EntityId::new();
        let mut base = HashMap::new();
        let mut head = HashMap::new();
        for (index, id) in ids.iter().enumerate() {
            let name = format!("entity_{index}");
            base.insert(*id, entity_stamped(*id, &name, 1, 0x10));
            // Only the first survivor's own body moved. Every other entity
            // moved only with its file.
            let body = if index == 0 { 2 } else { 1 };
            head.insert(*id, entity_stamped(*id, &name, body, 0x30));
        }
        head.insert(added, entity_stamped(added, "format_currency", 9, 0x30));

        let (deltas, unchanged) = diff_entities(&base, &head);
        let summary = summarize(&[], &deltas, &[], unchanged);
        assert_eq!(summary.entities_added, 1, "{deltas:#?}");
        assert_eq!(
            summary.entities_modified, 1,
            "one function body moved, not eleven: {deltas:#?}"
        );
        assert_eq!(summary.entities_removed, 0);
        assert_eq!(
            summary.entities_unchanged, 11,
            "the eleven that moved with their file are counted, not dropped"
        );

        // Counted is not enough. A reader has to be able to SEE that they
        // exist, which is the contract `kin blame` already holds itself to.
        let line =
            unchanged_entities_line(summary.entities_unchanged).expect("a withheld count says so");
        assert!(line.contains("11"), "{line}");
    }

    /// The control for the test above. A diff that elides nothing must say
    /// nothing about eliding, or every diff reads as trimmed.
    #[test]
    fn a_diff_that_withholds_nothing_says_nothing_about_withholding() {
        let id = EntityId::new();
        let base = HashMap::from([(id, entity_stamped(id, "format_totals", 1, 0x10))]);
        let head = HashMap::from([(id, entity_stamped(id, "format_totals", 2, 0x30))]);
        let (deltas, unchanged) = diff_entities(&base, &head);
        assert_eq!(deltas.len(), 1, "a real body change is still reported");
        assert_eq!(unchanged, 0);
        assert!(unchanged_entities_line(unchanged).is_none());
    }

    fn entity_in(id: EntityId, name: &str, file: &str) -> Entity {
        let mut built = entity(id, name);
        built.file_origin = Some(FilePathId::new(file));
        built
    }

    fn endpoint(source: DiffEndpointSource, entities: HashMap<EntityId, Entity>) -> EndpointState {
        EndpointState {
            report: DiffEndpoint {
                source,
                requested: None,
                ref_name: None,
                target: None,
                change_id: None,
                workspace_generation: None,
                workspace_head: None,
                tree_hash: Hash256::from_bytes([9; 32]),
                artifact_count: 0,
                entity_count: entities.len(),
                relation_count: 0,
            },
            tree: kin_model::ResolvedTree::default(),
            entities,
            relations: HashMap::new(),
        }
    }

    fn updated_delta(path: &str) -> kin_model::TreeDelta {
        let entry = kin_model::LocatedEntry {
            path: RepoPath::from_utf8(path).unwrap(),
            entry: kin_model::TreeEntry::Blob {
                hash: Hash256::from_bytes([7; 32]),
                executable: false,
            },
        };
        kin_model::TreeDelta::Updated {
            artifact_id: ArtifactId::new(),
            old: entry.clone(),
            new: entry,
        }
    }

    /// The correctness condition, and it is the one I nearly got wrong.
    /// `diff_entities` diffs whole maps, so an endpoint populated ONLY from the
    /// moved paths would report every untouched file's entities as REMOVED. The
    /// base map is kept and only the moved file is replaced in it.
    #[test]
    fn derivation_replaces_the_moved_path_and_leaves_the_rest_of_the_map_alone() {
        let moved_old = EntityId::new();
        let moved_new = EntityId::new();
        let untouched = EntityId::new();

        let graph = kin_db::InMemoryGraph::new();
        graph
            .batch_upsert_entities(&[entity_in(moved_new, "after", "src/moved.rs")])
            .unwrap();

        let admitted = HashMap::from([
            (moved_old, entity_in(moved_old, "before", "src/moved.rs")),
            (untouched, entity_in(untouched, "elsewhere", "src/other.rs")),
        ]);
        let mut base = endpoint(DiffEndpointSource::Head, admitted.clone());
        let mut head = endpoint(DiffEndpointSource::Workspace, admitted);

        let basis = derive_workspace_semantics(
            Some(&graph),
            Hash256::from_bytes([9; 32]),
            &[updated_delta("src/moved.rs")],
            &mut base,
            &mut head,
        );

        // The head is the workspace, so it derives.
        assert!(
            head.entities.contains_key(&moved_new),
            "the moved path's entities must come from the live graph"
        );
        assert!(
            !head.entities.contains_key(&moved_old),
            "an entity the edit removed has to leave the map, or the delta under-reports"
        );
        assert!(
            head.entities.contains_key(&untouched),
            "an untouched file's entities must survive, or every one of them reads as REMOVED"
        );
        // The base is HEAD, so it must be untouched by the derivation.
        assert!(
            base.entities.contains_key(&moved_old) && !base.entities.contains_key(&moved_new),
            "a non-workspace endpoint must not be re-derived"
        );

        // And the delta says what happened, which is the whole point.
        let (deltas, _) = diff_entities(&base.entities, &head.entities);
        assert_eq!(deltas.len(), 2, "one added, one removed: {deltas:?}");

        match basis {
            Some(WorkspaceSemanticBasis::Derived {
                matches_admitted_tree,
                derived_paths,
                ..
            }) => {
                assert_eq!(derived_paths, 1);
                let _ = matches_admitted_tree;
            }
            other => panic!("expected a derived basis, got {other:?}"),
        }
    }

    /// The gap, by name. This is the zero-file-search rule applied to a read:
    /// when the graph cannot answer, report the gap rather than a zero that reads
    /// like an answer.
    #[test]
    fn no_live_graph_reports_the_gap_rather_than_a_zero() {
        let mut base = endpoint(DiffEndpointSource::Head, HashMap::new());
        let mut head = endpoint(DiffEndpointSource::Workspace, HashMap::new());
        let basis = derive_workspace_semantics(
            None,
            Hash256::from_bytes([9; 32]),
            &[updated_delta("src/moved.rs")],
            &mut base,
            &mut head,
        );
        assert_eq!(basis, Some(WorkspaceSemanticBasis::AdmittedOverlayOnly));

        let line = semantic_scope_line(basis.as_ref()).expect("a workspace diff states its scope");
        assert!(line.contains("no live graph was reachable"), "{line}");
        assert!(
            line.contains("not a statement that nothing changed"),
            "the gap has to say what it is NOT, or a reader takes it for an answer: {line}"
        );
    }

    /// The control. A change-to-change diff is history on both sides, where the
    /// entity delta is already computed and already means what it says, so
    /// nothing is derived and nothing is disclosed. Without this, a derivation
    /// that fired on every diff would pass every assertion above.
    #[test]
    fn a_change_to_change_diff_derives_nothing_and_says_nothing() {
        let graph = kin_db::InMemoryGraph::new();
        let mut base = endpoint(DiffEndpointSource::Change, HashMap::new());
        let mut head = endpoint(DiffEndpointSource::Change, HashMap::new());
        let basis = derive_workspace_semantics(
            Some(&graph),
            Hash256::from_bytes([9; 32]),
            &[updated_delta("src/moved.rs")],
            &mut base,
            &mut head,
        );
        assert_eq!(basis, None, "history needs no derivation");

        assert!(
            semantic_scope_line(None).is_none(),
            "a change-to-change diff must not carry a workspace scope note"
        );
    }

    /// A reconcile can land between the authority lease read and the derivation,
    /// and an answer derived from a NEWER graph than the tree it describes is a
    /// different answer. So the basis names the graph's own tree and the text
    /// says when it disagrees.
    #[test]
    fn a_graph_holding_another_tree_names_the_mismatch() {
        let graph = kin_db::InMemoryGraph::new();
        let mut base = endpoint(DiffEndpointSource::Head, HashMap::new());
        let mut head = endpoint(DiffEndpointSource::Workspace, HashMap::new());
        // The workspace's admitted tree is deliberately not the empty tree the
        // fresh graph holds.
        let basis = derive_workspace_semantics(
            Some(&graph),
            Hash256::from_bytes([0xAB; 32]),
            &[],
            &mut base,
            &mut head,
        );
        let Some(WorkspaceSemanticBasis::Derived {
            matches_admitted_tree,
            ..
        }) = basis
        else {
            panic!("expected a derived basis, got {basis:?}");
        };
        assert!(
            !matches_admitted_tree,
            "a graph holding a different tree must not claim to match"
        );

        let line = semantic_scope_line(basis.as_ref()).expect("a workspace diff states its scope");
        assert!(line.contains("rather than the admitted"), "{line}");

        // The control: when it DOES match, the line must not carry the warning,
        // or the caveat is boilerplate rather than a signal.
        let matching = WorkspaceSemanticBasis::Derived {
            graph_tree_hash: Hash256::from_bytes([0xAB; 32]),
            matches_admitted_tree: true,
            derived_paths: 3,
        };
        let clean = semantic_scope_line(Some(&matching)).expect("still states its scope");
        assert!(!clean.contains("rather than the admitted"), "{clean}");
        assert!(clean.contains("3 moved path(s)"), "{clean}");
    }

    #[test]
    fn semantic_enrichment_is_complete_and_independent_of_artifact_support() {
        let retained_id = EntityId::new();
        let removed_id = EntityId::new();
        let added_id = EntityId::new();
        let old_retained = entity(retained_id, "before");
        let new_retained = entity(retained_id, "after");
        let removed = entity(removed_id, "removed");
        let added = entity(added_id, "added");
        let base_entities = HashMap::from([
            (retained_id, old_retained.clone()),
            (removed_id, removed.clone()),
        ]);
        let head_entities = HashMap::from([
            (retained_id, new_retained.clone()),
            (added_id, added.clone()),
        ]);

        let relation_id = RelationId::new();
        let relation = Relation {
            id: relation_id,
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(retained_id),
            dst: GraphNodeId::Entity(added_id),
            confidence: 1.0,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let base_relations = HashMap::new();
        let head_relations = HashMap::from([(relation_id, relation.clone())]);

        let (entity_deltas, _) = diff_entities(&base_entities, &head_entities);
        let relation_deltas = diff_relations(&base_relations, &head_relations);
        assert_eq!(entity_deltas.len(), 3);
        assert!(entity_deltas.iter().any(|delta| {
            matches!(
                delta,
                EntityDelta::Modified { old, new }
                    if old == &old_retained && new == &new_retained
            )
        }));
        assert!(entity_deltas
            .iter()
            .any(|delta| matches!(delta, EntityDelta::Removed { old } if old == &removed)));
        assert!(entity_deltas
            .iter()
            .any(|delta| matches!(delta, EntityDelta::Added { new } if new == &added)));
        assert_eq!(
            relation_deltas,
            vec![RelationDelta::Added { new: relation }]
        );
    }

    #[test]
    fn exact_tree_diff_preserves_ill_formed_utf8_paths_and_mode_only_updates() {
        let renamed_id = ArtifactId::new();
        let executable_id = ArtifactId::new();
        let body = Hash256::from_bytes([0x41; 32]);
        let executable_body = Hash256::from_bytes([0x42; 32]);
        let base = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                renamed_id,
                RepoPath::from_bytes(b"raw-\xff.dat".to_vec()).unwrap(),
                TreeEntry::blob(body, false),
            ),
            ResolvedArtifact::new(
                executable_id,
                RepoPath::from_utf8("tool").unwrap(),
                TreeEntry::blob(executable_body, true),
            ),
        ])
        .unwrap();
        let head = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                renamed_id,
                RepoPath::from_bytes(b"renamed-\xfe.dat".to_vec()).unwrap(),
                TreeEntry::blob(body, false),
            ),
            ResolvedArtifact::new(
                executable_id,
                RepoPath::from_utf8("tool").unwrap(),
                TreeEntry::blob(executable_body, false),
            ),
        ])
        .unwrap();

        let deltas = diff_trees(&base, &head);
        assert_eq!(deltas.len(), 2);
        assert!(deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Updated { artifact_id, old, new }
                    if *artifact_id == renamed_id
                        && old.path.as_bytes() == b"raw-\xff.dat"
                        && new.path.as_bytes() == b"renamed-\xfe.dat"
                        && old.entry == new.entry
            )
        }));
        assert!(deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Updated { artifact_id, old, new }
                    if *artifact_id == executable_id
                        && old.entry == TreeEntry::blob(executable_body, true)
                        && new.entry == TreeEntry::blob(executable_body, false)
            )
        }));
    }
}
