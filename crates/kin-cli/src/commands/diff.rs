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
    compute_resolved_tree_hash, ChangeStore, Entity, EntityDelta, EntityId, GitObjectId, Hash256,
    RefName, RefTarget, Relation, RelationDelta, RelationId, RepositoryId, ResolvedTree,
    RootBundle, SemanticChangeId, TreeDelta, TreeEntry, WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::{parse_git_object_id, parse_ref_name, ActiveRepositoryAuthority};

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

pub fn inspect(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: Option<&str>,
    head: Option<&str>,
) -> Result<DiffReport> {
    inspect_with_endpoint_entities(binding, base, head).map(|(report, _)| report)
}

pub fn inspect_with_endpoint_entities(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    base: Option<&str>,
    head: Option<&str>,
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
    let entity_deltas = diff_entities(&base_state.entities, &head_state.entities);
    let relation_deltas = diff_relations(&base_state.relations, &head_state.relations);
    let summary = summarize(&artifact_deltas, &entity_deltas, &relation_deltas);

    let report = DiffReport {
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
    };
    Ok((
        report,
        DiffEndpointEntities {
            base: base_state.entities,
            head: head_state.entities,
        },
    ))
}

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
        "HEAD" | "@" => {
            let Some(target) = workspace.base_target.clone() else {
                return EndpointState::empty(DiffEndpointSource::Head, requested);
            };
            let change_id = lease
                .resolve_target_change_id(&target)
                .context("resolve repository-v6 HEAD target")?;
            return state_at_change(
                history,
                DiffEndpoint {
                    source: DiffEndpointSource::Head,
                    requested,
                    ref_name: match &workspace.head {
                        WorkspaceHead::Symbolic { target } => Some(target.clone()),
                        WorkspaceHead::Detached { .. } => None,
                    },
                    target: Some(target),
                    change_id: Some(change_id),
                    workspace_generation: None,
                    workspace_head: None,
                    tree_hash: Hash256::from_bytes([0; 32]),
                    artifact_count: 0,
                    entity_count: 0,
                    relation_count: 0,
                },
                change_id,
            );
        }
        _ => {}
    }

    if let Some(hex_name) = selector.strip_prefix("ref-hex:") {
        if hex_name.is_empty()
            || hex_name != hex_name.to_ascii_lowercase()
            || !hex_name.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("ref-hex selector must use non-empty canonical lowercase hexadecimal bytes");
        }
        let bytes = hex::decode(hex_name).context("decode ref-hex selector")?;
        let name = RefName::from_bytes(bytes)
            .map_err(|error| anyhow!("invalid ref-hex selector: {error}"))?;
        return state_at_ref(lease, history, name, requested);
    }

    if let Some(value) = selector.strip_prefix("ref:") {
        return state_at_ref(lease, history, parse_ref_name(value)?, requested);
    }
    if let Some(value) = selector.strip_prefix("change:") {
        let change_id = parse_change_id(value)?;
        require_change(history, change_id)?;
        return state_at_change(
            history,
            endpoint_descriptor(DiffEndpointSource::Change, requested, Some(change_id)),
            change_id,
        );
    }
    if let Some(value) = selector.strip_prefix("git:") {
        return state_at_git_object(lease, history, parse_git_object_id(value)?, requested);
    }

    // Bare values prefer exact refs, matching Git's ordinary branch UX while
    // avoiding revision-string heuristics. A 64-hex branch remains a branch if
    // it exists; otherwise it may identify a Kin change or Git SHA-256 object.
    if let Ok(name) = parse_ref_name(selector) {
        if lease.resolve_ref_target(&name)?.is_some() {
            return state_at_ref(lease, history, name, requested);
        }
    }
    if selector.len() == 64 && selector.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        if let Ok(change_id) = parse_change_id(selector) {
            if history.get_change(&change_id)?.is_some() {
                return state_at_change(
                    history,
                    endpoint_descriptor(DiffEndpointSource::Change, requested, Some(change_id)),
                    change_id,
                );
            }
        }
    }
    if matches!(selector.len(), 40 | 64) && selector.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return state_at_git_object(lease, history, parse_git_object_id(selector)?, requested);
    }

    bail!(
        "diff endpoint '{selector}' is not an authority ref, semantic change, Git object, HEAD, \
         or WORKSPACE"
    )
}

fn state_at_ref(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    history: &kin_db::InMemoryGraph,
    name: RefName,
    requested: Option<String>,
) -> Result<EndpointState> {
    let target = lease
        .resolve_ref_target(&name)
        .with_context(|| format!("resolve repository ref '{name}'"))?
        .ok_or_else(|| anyhow!("repository ref '{name}' was not found"))?;
    let change_id = lease
        .resolve_target_change_id(&target)
        .with_context(|| format!("resolve repository ref '{name}' semantic target"))?;
    state_at_change(
        history,
        DiffEndpoint {
            source: DiffEndpointSource::Ref,
            requested,
            ref_name: Some(name),
            target: Some(target),
            change_id: Some(change_id),
            workspace_generation: None,
            workspace_head: None,
            tree_hash: Hash256::from_bytes([0; 32]),
            artifact_count: 0,
            entity_count: 0,
            relation_count: 0,
        },
        change_id,
    )
}

fn state_at_git_object(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    history: &kin_db::InMemoryGraph,
    oid: GitObjectId,
    requested: Option<String>,
) -> Result<EndpointState> {
    let target = lease
        .metadata()
        .external_objects
        .iter()
        .find(|record| record.object.oid == oid)
        .map(|record| RefTarget::external_object(record.object))
        .or_else(|| {
            lease
                .metadata()
                .aliases
                .iter()
                .find(|alias| alias.oid == oid)
                .map(|alias| RefTarget::change(alias.change_id))
        })
        .ok_or_else(|| {
            anyhow!(
                "Git object '{oid}' was never imported into this repository, so there is nothing \
                 to diff it against; import it with `kin init` in the source checkout, or name a \
                 ref kin already holds"
            )
        })?;
    let change_id = lease
        .resolve_target_change_id(&target)
        .with_context(|| format!("resolve Git object '{oid}' semantic target"))?;
    state_at_change(
        history,
        DiffEndpoint {
            source: DiffEndpointSource::GitObject,
            requested,
            ref_name: None,
            target: Some(target),
            change_id: Some(change_id),
            workspace_generation: None,
            workspace_head: None,
            tree_hash: Hash256::from_bytes([0; 32]),
            artifact_count: 0,
            entity_count: 0,
            relation_count: 0,
        },
        change_id,
    )
}

fn endpoint_descriptor(
    source: DiffEndpointSource,
    requested: Option<String>,
    change_id: Option<SemanticChangeId>,
) -> DiffEndpoint {
    DiffEndpoint {
        source,
        requested,
        ref_name: None,
        target: change_id.map(RefTarget::change),
        change_id,
        workspace_generation: None,
        workspace_head: None,
        tree_hash: Hash256::from_bytes([0; 32]),
        artifact_count: 0,
        entity_count: 0,
        relation_count: 0,
    }
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

fn parse_change_id(value: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(value)
        .map_err(|error| anyhow!("invalid semantic change ID '{value}': {error}"))?;
    Ok(SemanticChangeId::from_hash(hash))
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

fn diff_entities(
    base: &HashMap<EntityId, Entity>,
    head: &HashMap<EntityId, Entity>,
) -> Vec<EntityDelta> {
    base.keys()
        .copied()
        .chain(head.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(
            |entity_id| match (base.get(&entity_id), head.get(&entity_id)) {
                (None, Some(new)) => Some(EntityDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(EntityDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(EntityDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            },
        )
        .collect()
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
) -> DiffSummary {
    let mut summary = DiffSummary::default();
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

pub async fn run(base: Option<String>, head: Option<String>, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    // Admit, THEN diff, for the same reason `kin status` does and by the same
    // founder-owned decision relayed 2026-08-30. A diff whose WORKSPACE endpoint
    // is the graph as it was before your edit reports `+0 ~0 -0` over a file you
    // just wrote, which is the answer that sent a stranger looking for a lost
    // module (FIR-2499) and told another that a rewritten function body had not
    // changed (FIR-2961). Reading the working copy to ADMIT it is ingestion at
    // an explicit input boundary, not answering from files.
    //
    // Only when a workspace endpoint is actually involved. A diff between two
    // changes is history, and walking the tree to answer it would be a cost with
    // nothing behind it.
    let pass = if endpoint_is_workspace(base.as_deref()) || endpoint_is_workspace(head.as_deref()) {
        Some(crate::commands::status::admit_before_reading(&layout).await)
    } else {
        None
    };
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let report = inspect(&binding, base.as_deref(), head.as_deref())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_lines(&report) {
            println!("{line}");
        }
        if let Some(line) = semantic_scope_line(&report) {
            println!("{line}");
        }
        if let Some(crate::commands::status::StatusAdmission::Skipped(why)) = pass.as_ref() {
            println!("Admission scope: this diff was not measured against the working copy: {why}");
        }
        println!("{}", admitted_scope_line(&layout));
    }
    Ok(())
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

/// What the entity and relation counts above cannot show on a workspace endpoint.
///
/// A workspace endpoint's semantic side is its base change's entities and
/// relations plus the workspace semantic overlay, and no writer in the daemon
/// ever puts an entity delta into that overlay. The admission seam publishes
/// with `semantic_delta: WorkspaceSemanticDelta::default()`, unconditionally,
/// and the one other overlay writer computes its delta with the authority
/// entities as BOTH the base and the desired side, so it cannot emit an entity
/// delta either. `Entities: +0 ~0 -0` on a HEAD-to-WORKSPACE diff is therefore
/// structural rather than an answer about the edit.
///
/// A stranger read the pair as an answer, checked it against a fully settled
/// graph (`kin graph status`: 78 of 78 embeddings indexed, 8 of 8 files at 100%
/// coverage), and concluded the semantic layer had silently skipped a rewrite of
/// a function body (FIR-2961). Naming the scope beside the counts is what tells a
/// real zero apart from one nothing could have moved.
///
/// Silent on a diff between two changes, where the entity delta is computed and
/// means what it says.
fn semantic_scope_line(report: &DiffReport) -> Option<String> {
    let base_is_workspace = matches!(report.base.source, DiffEndpointSource::Workspace);
    let head_is_workspace = matches!(report.head.source, DiffEndpointSource::Workspace);
    if !base_is_workspace && !head_is_workspace {
        return None;
    }
    let side = if base_is_workspace && head_is_workspace {
        "Both endpoints are"
    } else if head_is_workspace {
        "The head endpoint is"
    } else {
        "The base endpoint is"
    };
    Some(format!(
        "Semantic scope: {side} the workspace, whose entities and relations are its base \
         change's plus a workspace semantic overlay that no admission writes entity or relation \
         deltas into. So semantic movement made in the working copy since its base change \
         appears in neither count above, whatever the artifact rows show; commit it and diff \
         change to change to see it."
    ))
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
) -> Result<DiffResponse> {
    let report = inspect(binding, request.base.as_deref(), request.head.as_deref())?;
    Ok(DiffResponse {
        lines: render_lines(&report),
        report: Some(report),
    })
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

        let entity_deltas = diff_entities(&base_entities, &head_entities);
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
