// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconstructive commit-delta computation for `command_commit`.
//!
//! Computes entity, relation, and exact tree deltas by diffing current graph
//! state against the last-committed change-DAG node.  This approach is
//! robust regardless of when the reconcile loop drained the working-copy
//! overlay — the overlay is never consulted here.
//!
//! ## Algorithm
//!
//! 1. Resolve the exact repository-authority parent state.
//! 2. Take one coherent snapshot of the live admitted graph workspace.
//! 3. Diff current vs committed to produce typed `EntityDelta`,
//!    `RelationDelta`, and `TreeDelta` slices.
//!
//! Because `apply_overlay_to_graph` folds reconcile mutations into the
//! primary graph before clearing the overlay, `graph.list_all_entities()`
//! already reflects the current working state — diffing against the DAG
//! baseline captures exactly what changed since the last commit.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_model::{
    graph::ResolvedGraphState, ArtifactId, ChangeStore, Entity, EntityDelta, EntityId, EntityStore,
    GraphNodeId, Hash256, Relation, RelationDelta, RelationId, RepoPath, ResolvedTree,
    SemanticChangeId, TransactionDelta, TreeDelta, TreeEntry,
};
use sha2::{Digest, Sha256};

use crate::error::{DaemonError, Result};

/// The three delta slices that constitute a semantic commit.
#[derive(Debug)]
pub struct CommitDeltas {
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    pub tree_deltas: Vec<TreeDelta>,
    /// Exact graph-owned tree that the change must resolve to.
    pub expected_tree: ResolvedTree,
}

/// Compute commit deltas by diffing current graph state against the
/// last-committed change-DAG node (`branch_head`).
///
/// Returns empty delta slices when nothing has changed since the last commit,
/// and non-empty slices when entities, relations, or files have been modified.
pub fn compute_deltas_vs_last_commit(
    graph: &InMemoryGraph,
    branch_head: &SemanticChangeId,
) -> Result<CommitDeltas> {
    let committed = graph
        .resolve_graph_at(branch_head)
        .map_err(DaemonError::Graph)?;
    compute_deltas_from_resolved_state(graph, &committed)
}

/// Resolve the graph at one change out of persisted authority, without
/// building a graph to throw away.
///
/// The commit planner needs the parent's entities, relations and tree so it can
/// diff the live graph against them. It used to get them by cloning the
/// authority snapshot, constructing a whole `InMemoryGraph` from it, calling
/// `resolve_graph_at` once, and dropping the graph. Constructing it was not
/// free. `from_snapshot` rebuilds a lexical index over every entity, which
/// nothing here searches, and an authority snapshot always arrives with
/// `entity_revisions` cleared (kin-db clears them on purpose, because a
/// repository with multiple refs has no single revision view), which selects
/// the branch that derives entity revisions across the entire history. Neither
/// result reaches the delta this returns.
///
/// Measured on one repository at two history depths, six files and twenty-five
/// entities either way: at 5 changes the commit took 0.43 s and 52.2 MiB of
/// daemon resident set, and at 2000 changes the same edit produced the same 6
/// entities and 143 relations while taking 7.57 s and 166.2 MiB. The 1995 extra
/// changes changed no output.
///
/// Two arms, in cost order, and the second is not a degraded mode. The
/// materialized section is authority's own memo of this exact resolution and is
/// refreshed at the change that becomes the next commit's parent, by
/// `refresh_workspace_base_graph_section` after every native commit and by
/// `kin init`. When it answers, nothing decodes the change map at all. When it
/// does not, folding the history is always available beside it and is always
/// correct; a refusal can only ever cost time. Amend is the recurring miss and
/// misses correctly, because it resolves at the amended change's own parent
/// rather than at the workspace base the section names.
///
/// Public so the heap-ceiling guard can measure both arms against the
/// graph-building path in the same process, which is the only way its ceiling is
/// evidence rather than an arbitrary constant.
pub fn resolve_authority_baseline<'a>(
    authority_snapshot: &'a GraphSnapshot,
    parent: &SemanticChangeId,
) -> Result<Cow<'a, ResolvedGraphState>> {
    match baseline_from_materialized_section(authority_snapshot, parent) {
        Ok(state) => Ok(Cow::Borrowed(state)),
        Err(refusal) => {
            tracing::debug!(
                %parent,
                %refusal,
                "the materialized graph section did not answer for this commit's parent, so the \
                 baseline folds from history instead"
            );
            baseline_from_history(authority_snapshot, parent).map(Cow::Owned)
        }
    }
}

/// Authority's own memo of `resolve_graph_at` at exactly this change.
///
/// Deliberately no re-derivation to check the memo. Recomputing the resolution
/// to decide whether to trust a memo of the resolution would pay the whole cost
/// this avoids and conclude what the change id already proves: a change id
/// hashes every immutable field including `parents`, so naming the change names
/// its complete ancestry and therefore the graph. This mirrors kin-db's own
/// provider for the same section rather than inventing a second policy.
fn baseline_from_materialized_section<'a>(
    authority_snapshot: &'a GraphSnapshot,
    parent: &SemanticChangeId,
) -> std::result::Result<&'a ResolvedGraphState, kin_db::MaterializedGraphRefusal> {
    let section = authority_snapshot
        .materialized_graph
        .as_ref()
        .ok_or(kin_db::MaterializedGraphRefusal::Absent)?;
    section.validate_for(parent)?;
    Ok(&section.state)
}

/// Fold the parent out of persisted history, borrowing the change map.
///
/// `resolve_graph_at` reaches its store through `get_change` and nothing else
/// (`kin_model::graph::collect_changes_first_parent`), so the graph this used to
/// construct served one lookup loop. Borrowing does still decode the change map,
/// because `ChangeMap` derefs through `force()`; what it drops is the throwaway
/// graph, its lexical index, and the whole-history entity-revision derivation.
fn baseline_from_history(
    authority_snapshot: &GraphSnapshot,
    parent: &SemanticChangeId,
) -> Result<ResolvedGraphState> {
    crate::state::HostedAuthorityHistory {
        changes: &authority_snapshot.changes,
    }
    .resolve_graph_at(parent)
    .map_err(DaemonError::Graph)
}

/// Diff the live admitted graph against one repository-v6 authority lease.
///
/// The baseline comes exclusively from the persisted semantic history. The
/// live side is the already-admitted graph workspace; no checkout is read and
/// no artifact identity is inferred here. `None` is an unborn repository and
/// therefore has an exact empty baseline.
pub fn compute_deltas_vs_repository_authority(
    graph: &InMemoryGraph,
    authority_snapshot: &GraphSnapshot,
    parent: Option<&SemanticChangeId>,
) -> Result<CommitDeltas> {
    let committed = match parent {
        Some(parent) => resolve_authority_baseline(authority_snapshot, parent)?,
        None => Cow::Owned(ResolvedGraphState {
            entities: Default::default(),
            relations: Default::default(),
            entity_revisions: Default::default(),
            tree: ResolvedTree::default(),
            entity_tombstones: Default::default(),
            relation_tombstones: Default::default(),
            external_references: HashMap::new(),
        }),
    };
    compute_deltas_from_resolved_state(graph, &committed)
}

/// Build the complete derived-graph transition for one selected-path checkout.
///
/// Exact tree membership comes from the repository checkout plan. Semantic
/// entities and every relation touching a selected entity or artifact are
/// spliced from the immutable target change. Unsupported/config/binary members
/// naturally carry only tree deltas. This makes a missing semantic parser an
/// honest absence of enrichment rather than permission to leave stale entities
/// attached to replaced bytes.
pub fn compute_selected_checkout_delta(
    graph: &InMemoryGraph,
    selected: &RepoPath,
    target: &ResolvedGraphState,
    expected_previous_tree: &ResolvedTree,
    desired_tree: &ResolvedTree,
) -> Result<TransactionDelta> {
    let current = graph.to_snapshot();
    if current.resolved_tree != *expected_previous_tree && current.resolved_tree != *desired_tree {
        return Err(DaemonError::IncompatibleRepo(format!(
            "daemon query tree matches neither checkout base nor desired authority for {selected}"
        )));
    }

    let current_selected_entities = selected_entity_ids(current.entities.values(), selected)?;
    let target_selected_entities = selected_entity_ids(target.entities.values(), selected)?;
    let current_selected_artifacts = selected_artifact_ids(&current.resolved_tree, selected);
    let target_selected_artifacts = selected_artifact_ids(&target.tree, selected);

    let mut desired_entities = current.entities.clone();
    for entity_id in &current_selected_entities {
        desired_entities.remove(entity_id);
    }
    let mut occupied_entity_ids = desired_entities.keys().copied().collect::<HashSet<_>>();
    let mut entity_remap = HashMap::new();
    let mut ordered_target_entities = target_selected_entities.iter().copied().collect::<Vec<_>>();
    ordered_target_entities.sort_unstable();
    for entity_id in &ordered_target_entities {
        let entity = target
            .entities
            .get(entity_id)
            .expect("selected entity IDs come from target entity map");
        let desired_id = if occupied_entity_ids.contains(entity_id) {
            collision_copy_entity_id(entity, &occupied_entity_ids)
        } else {
            *entity_id
        };
        occupied_entity_ids.insert(desired_id);
        entity_remap.insert(*entity_id, desired_id);
    }
    for entity_id in &ordered_target_entities {
        let mut entity = target
            .entities
            .get(entity_id)
            .expect("selected entity IDs come from target entity map")
            .clone();
        entity.id = *entity_remap
            .get(entity_id)
            .expect("every selected target entity has a remap");
        entity.lineage_parent = remap_retained_entity_reference(
            entity.lineage_parent,
            &entity_remap,
            &occupied_entity_ids,
        );
        entity.superseded_by = remap_retained_entity_reference(
            entity.superseded_by,
            &entity_remap,
            &occupied_entity_ids,
        );
        desired_entities.insert(entity.id, entity);
    }

    let artifact_remap = selected_artifact_remap(&target.tree, desired_tree, selected)?;
    let mut desired_relations = current.relations.clone();
    desired_relations.retain(|_, relation| {
        !relation_touches_selected(
            relation,
            &current_selected_entities,
            &current_selected_artifacts,
        )
    });

    let mut occupied_relation_ids = desired_relations.keys().copied().collect::<HashSet<_>>();
    let mut target_relations = target
        .relations
        .values()
        .filter(|relation| {
            relation_touches_selected(
                relation,
                &target_selected_entities,
                &target_selected_artifacts,
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    target_relations.sort_by_key(|relation| relation.id);
    for mut relation in target_relations {
        let original_id = relation.id;
        let original_src = relation.src;
        let original_dst = relation.dst;
        relation.src = remap_checkout_node(relation.src, &entity_remap, &artifact_remap);
        relation.dst = remap_checkout_node(relation.dst, &entity_remap, &artifact_remap);
        if !checkout_node_exists(relation.src, &desired_entities, desired_tree, &current)
            || !checkout_node_exists(relation.dst, &desired_entities, desired_tree, &current)
        {
            // A selected historical edge may point outside the selected
            // subtree to a node that is absent from the current mixed graph.
            // Omitting that stale edge is truthful; inventing or resurrecting
            // the unselected endpoint is not.
            continue;
        }
        if relation.src != original_src || relation.dst != original_dst {
            relation.id =
                collision_copy_relation_id(&relation, original_id, &occupied_relation_ids);
        } else if desired_relations
            .get(&relation.id)
            .is_some_and(|retained| retained != &relation)
        {
            relation.id =
                collision_copy_relation_id(&relation, original_id, &occupied_relation_ids);
        }
        if let Some(retained) = desired_relations.get(&relation.id) {
            if retained != &relation {
                return Err(DaemonError::IncompatibleRepo(format!(
                    "checkout of {selected} would reuse relation identity {} across the selection boundary",
                    relation.id
                )));
            }
        } else {
            occupied_relation_ids.insert(relation.id);
            desired_relations.insert(relation.id, relation);
        }
    }

    let semantic_delta = kin_core::diff_workspace_semantics(
        &current.entities,
        &current.relations,
        &desired_entities,
        &desired_relations,
    )?;
    let delta = TransactionDelta {
        entity_deltas: semantic_delta.entity_deltas().to_vec(),
        relation_deltas: semantic_delta.relation_deltas().to_vec(),
        tree_deltas: kin_core::exact_tree_correction(&current.resolved_tree, desired_tree)?,
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };

    let preflight = InMemoryGraph::from_snapshot(current).map_err(DaemonError::Graph)?;
    preflight
        .apply_transaction_delta(&delta)
        .map_err(DaemonError::Graph)?;
    if preflight.resolved_tree() != *desired_tree {
        return Err(DaemonError::IncompatibleRepo(format!(
            "checkout preflight for {selected} did not resolve to exact desired tree"
        )));
    }
    Ok(delta)
}

fn selected_entity_ids<'a>(
    entities: impl Iterator<Item = &'a Entity>,
    selected: &RepoPath,
) -> Result<HashSet<EntityId>> {
    let mut selected_ids = HashSet::new();
    for entity in entities {
        let Some(file_origin) = &entity.file_origin else {
            continue;
        };
        let path = RepoPath::from_utf8(file_origin.0.clone()).map_err(|error| {
            DaemonError::IncompatibleRepo(format!(
                "entity {} has invalid repository file origin '{}': {error}",
                entity.id, file_origin
            ))
        })?;
        if checkout_path_contains(selected, &path) {
            selected_ids.insert(entity.id);
        }
    }
    Ok(selected_ids)
}

fn selected_artifact_ids(tree: &ResolvedTree, selected: &RepoPath) -> HashSet<ArtifactId> {
    tree.artifacts_by_path()
        .filter(|artifact| checkout_path_contains(selected, &artifact.path))
        .map(|artifact| artifact.artifact_id)
        .collect()
}

fn selected_artifact_remap(
    target: &ResolvedTree,
    desired: &ResolvedTree,
    selected: &RepoPath,
) -> Result<HashMap<ArtifactId, ArtifactId>> {
    let mut remap = HashMap::new();
    for artifact in target
        .artifacts_by_path()
        .filter(|artifact| checkout_path_contains(selected, &artifact.path))
    {
        let desired_artifact = desired.artifact_at_path(&artifact.path).ok_or_else(|| {
            DaemonError::IncompatibleRepo(format!(
                "desired checkout tree lost selected target artifact {}",
                artifact.path
            ))
        })?;
        if desired_artifact.entry != artifact.entry {
            return Err(DaemonError::IncompatibleRepo(format!(
                "desired checkout entry at {} differs from target history",
                artifact.path
            )));
        }
        remap.insert(artifact.artifact_id, desired_artifact.artifact_id);
    }
    Ok(remap)
}

fn relation_touches_selected(
    relation: &Relation,
    entities: &HashSet<EntityId>,
    artifacts: &HashSet<ArtifactId>,
) -> bool {
    [relation.src, relation.dst]
        .into_iter()
        .any(|node| match node {
            GraphNodeId::Entity(entity_id) => entities.contains(&entity_id),
            GraphNodeId::Artifact(artifact_id) => artifacts.contains(&artifact_id),
            _ => false,
        })
}

fn remap_checkout_node(
    node: GraphNodeId,
    entity_remap: &HashMap<EntityId, EntityId>,
    artifact_remap: &HashMap<ArtifactId, ArtifactId>,
) -> GraphNodeId {
    match node {
        GraphNodeId::Entity(entity_id) => entity_remap
            .get(&entity_id)
            .copied()
            .map(GraphNodeId::Entity)
            .unwrap_or(node),
        GraphNodeId::Artifact(artifact_id) => artifact_remap
            .get(&artifact_id)
            .copied()
            .map(GraphNodeId::Artifact)
            .unwrap_or(node),
        _ => node,
    }
}

fn remap_retained_entity_reference(
    reference: Option<EntityId>,
    remap: &HashMap<EntityId, EntityId>,
    occupied: &HashSet<EntityId>,
) -> Option<EntityId> {
    reference.and_then(|entity_id| {
        remap
            .get(&entity_id)
            .copied()
            .or_else(|| occupied.contains(&entity_id).then_some(entity_id))
    })
}

fn collision_copy_entity_id(entity: &Entity, occupied: &HashSet<EntityId>) -> EntityId {
    for counter in 0_u64.. {
        let mut hasher = Sha256::new();
        hasher.update(b"kin.checkout-collision-copy-entity.v1\0");
        hasher.update(entity.id.0.as_bytes());
        if let Some(path) = &entity.file_origin {
            hasher.update(path.0.as_bytes());
        }
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let candidate = EntityId(uuid::Uuid::from_bytes(bytes));
        if !occupied.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("u64 entity remap namespace exhausted")
}

fn collision_copy_relation_id(
    relation: &Relation,
    original_id: RelationId,
    occupied: &HashSet<RelationId>,
) -> RelationId {
    for counter in 0_u64.. {
        let mut hasher = Sha256::new();
        hasher.update(b"kin.checkout-collision-copy-relation.v1\0");
        hasher.update(original_id.0.as_bytes());
        hasher.update(relation.src.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(relation.dst.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(format!("{:?}", relation.kind).as_bytes());
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let candidate = RelationId::from_bytes(bytes);
        if !occupied.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("u64 relation remap namespace exhausted")
}

fn checkout_node_exists(
    node: GraphNodeId,
    desired_entities: &HashMap<EntityId, Entity>,
    desired_tree: &ResolvedTree,
    current: &GraphSnapshot,
) -> bool {
    match node {
        GraphNodeId::Entity(entity_id) => desired_entities.contains_key(&entity_id),
        GraphNodeId::Artifact(artifact_id) => desired_tree.get(&artifact_id).is_some(),
        GraphNodeId::Test(test_id) => current.test_cases.contains_key(&test_id),
        GraphNodeId::Contract(contract_id) => current.contracts.contains_key(&contract_id),
        GraphNodeId::Work(work_id) => current.work_items.contains_key(&work_id),
        GraphNodeId::VerificationRun(run_id) => current.verification_runs.contains_key(&run_id),
        // External references are not scoped by a path selection, and this
        // delta adds none, so the desired set equals the current one. An edge
        // to a reference the graph does not hold is dropped exactly like any
        // other absent endpoint rather than inventing the reference.
        GraphNodeId::ExternalReference(reference_id) => {
            current.external_references.contains_key(&reference_id)
        }
    }
}

fn checkout_path_contains(selected: &RepoPath, path: &RepoPath) -> bool {
    path == selected
        || path
            .as_bytes()
            .strip_prefix(selected.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn compute_deltas_from_resolved_state(
    graph: &InMemoryGraph,
    committed: &ResolvedGraphState,
) -> Result<CommitDeltas> {
    // One coherent live snapshot keeps entity, relation, and exact-tree deltas
    // on the same graph generation.
    let current = graph.to_snapshot();

    let mut entity_deltas = Vec::new();
    for entity in current.entities.values() {
        match committed.entities.get(&entity.id) {
            None => {
                entity_deltas.push(EntityDelta::Added {
                    new: entity.clone(),
                });
            }
            // Compare the complete payload, not only the AST/signature/behavior
            // fingerprint. An entity whose body is unchanged but whose span or
            // blob provenance advanced is still a different value, and the
            // workspace semantic overlay is derived by whole-value difference
            // against the change this delta publishes. Recording only
            // fingerprint changes therefore leaves the published base holding a
            // superseded payload, which strands that difference in the overlay:
            // the workspace reports dirty forever, the next switch or merge
            // refuses it, and a further commit publishes an empty change
            // because the fingerprint still has not moved. Publishing the exact
            // payload is also what keeps history able to reproduce the spans
            // and source provenance the entity actually had at that change.
            Some(committed) if committed != entity => {
                entity_deltas.push(EntityDelta::Modified {
                    old: committed.clone(),
                    new: entity.clone(),
                });
            }
            _ => {}
        }
    }
    for (entity_id, entity) in &committed.entities {
        if !current.entities.contains_key(entity_id) {
            entity_deltas.push(EntityDelta::Removed {
                old: entity.clone(),
            });
        }
    }
    entity_deltas.sort_by_key(EntityDelta::target_id);

    let mut relation_deltas = Vec::new();
    for relation in current.relations.values() {
        match committed.relations.get(&relation.id) {
            None => relation_deltas.push(RelationDelta::Added {
                new: relation.clone(),
            }),
            Some(old) if old != relation => {
                relation_deltas.push(RelationDelta::Modified {
                    old: old.clone(),
                    new: relation.clone(),
                });
            }
            _ => {}
        }
    }
    for (relation_id, relation) in &committed.relations {
        if !current.relations.contains_key(relation_id) {
            relation_deltas.push(RelationDelta::Removed {
                old: relation.clone(),
            });
        }
    }
    relation_deltas.sort_by_key(RelationDelta::target_id);

    let expected_tree = current.resolved_tree;
    let tree_deltas = kin_core::exact_tree_correction(&committed.tree, &expected_tree)?;

    Ok(CommitDeltas {
        entity_deltas,
        relation_deltas,
        tree_deltas,
        expected_tree,
    })
}

/// One host observation carried together with the scanner's completion proof.
///
/// [`kin_index::CompleteScanToken`] can only be minted by a repository walk in
/// which every directory read, metadata lookup, file read, and symbolic-link
/// read succeeded. Carrying it in the observation keeps the proof attached
/// through planning and into publication, so a partial walk or a fabricated
/// path map cannot reach repository authority.
///
/// The observed entry set stays mutable because the daemon narrows it to the
/// paths one ambient notification batch actually named. Narrowing what may
/// move never weakens the proof that the walk itself was complete.
pub(crate) struct CompleteWorkspaceObservation {
    entries: BTreeMap<RepoPath, TreeEntry>,
    completion: kin_index::CompleteScanToken,
}

impl CompleteWorkspaceObservation {
    pub(crate) fn insert(&mut self, path: RepoPath, entry: TreeEntry) {
        self.entries.insert(path, entry);
    }

    pub(crate) fn retain(&mut self, keep: impl FnMut(&RepoPath, &mut TreeEntry) -> bool) {
        self.entries.retain(keep);
    }

    pub(crate) fn entries(&self) -> &BTreeMap<RepoPath, TreeEntry> {
        &self.entries
    }

    pub(crate) const fn completion(&self) -> kin_index::CompleteScanToken {
        self.completion
    }
}

/// Turn one complete host scan into exact graph entries.
///
/// Graph-only entries (currently Gitlinks) are copied from the parent tree:
/// their host checkout is neither membership evidence nor an identity source.
///
/// So are the tracked paths the walk declined to observe because ignore rules
/// cover them. The walk holds no evidence about those paths, and an observation
/// that omitted them would plan their removal, which would turn a rule into a
/// silent deletion on the first pass that stopped reading them. Retiring an
/// ignored member is an announced retraction the caller performs against graph
/// truth, never something an unobserved path infers on its own.
pub(crate) fn observed_tree_from_complete_scan(
    blobs: &kin_blobs::BlobStore,
    scan: &kin_index::CompleteRepositoryScan,
    previous: &ResolvedTree,
) -> Result<CompleteWorkspaceObservation> {
    let mut observed = previous
        .artifacts_by_path()
        .filter(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
        .map(|artifact| (artifact.path.clone(), artifact.entry))
        .collect::<BTreeMap<_, _>>();
    for path in scan.unverified_ignored_paths() {
        if let Some(artifact) = previous.artifact_at_path(path) {
            observed.insert(artifact.path.clone(), artifact.entry);
        }
    }

    for scanned in scan.entries() {
        let entry = match scanned.kind {
            kin_index::ScannedEntryKind::Regular { executable } => {
                TreeEntry::blob(Hash256::from_bytes(scanned.content_hash), executable)
            }
            kin_index::ScannedEntryKind::Symlink => {
                TreeEntry::symlink(Hash256::from_bytes(scanned.content_hash))
            }
        };
        // Only an entry that differs from authority is read a second time.
        //
        // The walk has already opened, read, and hashed every leaf; reading each
        // one again here made the cost of observing a working copy proportional
        // to the whole working copy rather than to what moved in it, and the
        // reconcile loop pays this on every tick. When the scanned identity
        // matches the entry authority already carries at that path, the bytes
        // behind it are by definition already a blob this store resolves, so the
        // second read would re-derive a digest nothing is waiting for and rewrite
        // a blob that is already there.
        //
        // The re-read is kept where it can still catch something. An entry that
        // does differ is about to cross the compare-and-swap, so its bytes are
        // read and their digest is checked against the walk's, which is what
        // catches a file rewritten between the walk and the publication and
        // refuses the whole observation rather than admitting a hash for content
        // the store never held.
        if previous
            .artifact_at_path(&scanned.repo_path)
            .map(|artifact| artifact.entry)
            != Some(entry)
        {
            let content = read_scanned_entry(scanned)?;
            let blob_digest = blobs.write(&content).map_err(DaemonError::from)?;
            if blob_digest.0 != scanned.content_hash {
                return Err(DaemonError::Io(std::io::Error::other(format!(
                    "repository entry changed after complete scan: {}",
                    scanned.repo_path
                ))));
            }
        }
        observed.insert(scanned.repo_path.clone(), entry);
    }

    Ok(CompleteWorkspaceObservation {
        entries: observed,
        completion: scan.completion(),
    })
}

fn read_scanned_entry(scanned: &kin_index::ScannedRepositoryEntry) -> Result<Vec<u8>> {
    kin_index::read_verified_scanned_entry(scanned).map_err(DaemonError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactId, EntityStore, FilePathId, LocatedEntry};

    use std::sync::Arc;

    use kin_blobs::BlobStore;
    use kin_model::{
        AuthorId, EntityKind, EntityMetadata, FingerprintAlgorithm, LanguageId, RelationKind,
        RelationOrigin, ResolvedArtifact, SemanticFingerprint, Timestamp, Visibility,
    };

    #[test]
    fn exact_tree_scan_fails_loud_when_root_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        assert!(kin_index::scan_repository(
            &missing,
            &kin_index::RepositoryIgnore::default(),
            std::iter::empty()
        )
        .is_err());
    }

    fn resolved_tree(artifacts: Vec<(ArtifactId, RepoPath, TreeEntry)>) -> ResolvedTree {
        ResolvedTree::from_artifacts(
            artifacts
                .into_iter()
                .map(|(artifact_id, path, entry)| ResolvedArtifact::new(artifact_id, path, entry)),
        )
        .unwrap()
    }

    #[test]
    fn exact_tree_planner_preserves_artifact_identity_across_a_unique_move() {
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false);
        let old_path = RepoPath::from_utf8("src/old.rs").unwrap();
        let new_path = RepoPath::from_utf8("src/new.rs").unwrap();
        let previous = resolved_tree(vec![(artifact_id, old_path.clone(), entry)]);

        let deltas = kin_core::plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([(new_path.clone(), entry)]),
        )
        .unwrap();

        assert_eq!(
            deltas,
            vec![TreeDelta::Updated {
                artifact_id,
                old: LocatedEntry::new(old_path, entry),
                new: LocatedEntry::new(new_path.clone(), entry),
            }]
        );
        let next = previous.apply(&deltas).unwrap();
        assert_eq!(next.get(&artifact_id).unwrap().path, new_path);
    }

    #[test]
    fn exact_tree_planner_handles_move_plus_path_reuse_atomically() {
        let moved_id = ArtifactId::new();
        let moved_entry = TreeEntry::blob(Hash256::from_bytes([0x22; 32]), false);
        let replacement_entry = TreeEntry::blob(Hash256::from_bytes([0x33; 32]), true);
        let reused_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let destination = RepoPath::from_utf8("deploy/compose.yaml").unwrap();
        let previous = resolved_tree(vec![(moved_id, reused_path.clone(), moved_entry)]);

        let deltas = kin_core::plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([
                (reused_path.clone(), replacement_entry),
                (destination.clone(), moved_entry),
            ]),
        )
        .unwrap();
        let next = previous.apply(&deltas).unwrap();

        assert_eq!(next.get(&moved_id).unwrap().path, destination);
        let replacement = next.artifact_at_path(&reused_path).unwrap();
        assert_ne!(replacement.artifact_id, moved_id);
        assert_eq!(replacement.entry, replacement_entry);
    }

    #[test]
    fn exact_tree_planner_supports_swaps_and_non_utf8_paths() {
        let left_id = ArtifactId::new();
        let right_id = ArtifactId::new();
        let left_entry = TreeEntry::blob(Hash256::from_bytes([0x44; 32]), false);
        let right_entry = TreeEntry::symlink(Hash256::from_bytes([0x55; 32]));
        let left_path = RepoPath::from_bytes(b"left-\xff".to_vec()).unwrap();
        let right_path = RepoPath::from_utf8("right-link").unwrap();
        let previous = resolved_tree(vec![
            (left_id, left_path.clone(), left_entry),
            (right_id, right_path.clone(), right_entry),
        ]);

        let deltas = kin_core::plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([
                (left_path.clone(), right_entry),
                (right_path.clone(), left_entry),
            ]),
        )
        .unwrap();
        let next = previous.apply(&deltas).unwrap();

        assert_eq!(next.get(&left_id).unwrap().path, right_path);
        assert_eq!(next.get(&right_id).unwrap().path, left_path);
    }

    #[test]
    fn exact_tree_planner_fails_closed_on_duplicate_move_candidates() {
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x66; 32]), false);
        let previous = resolved_tree(vec![(
            artifact_id,
            RepoPath::from_utf8("old").unwrap(),
            entry,
        )]);
        let observed = BTreeMap::from([
            (RepoPath::from_utf8("copy-a").unwrap(), entry),
            (RepoPath::from_utf8("copy-b").unwrap(), entry),
        ]);

        let error = kin_core::plan_observed_tree_deltas(&previous, observed)
            .expect_err("ambiguous move identity must never be guessed");
        assert!(error.to_string().contains("ambiguous repository identity"));
    }

    fn make_entity(name: &str, file_path: &str, ast_hash: [u8; 32]) -> kin_model::entity::Entity {
        make_entity_with_id(EntityId::new(), name, file_path, LanguageId::Rust, ast_hash)
    }

    fn make_entity_with_id(
        id: EntityId,
        name: &str,
        file_path: &str,
        language: LanguageId,
        ast_hash: [u8; 32],
    ) -> kin_model::entity::Entity {
        kin_model::entity::Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes(ast_hash),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file_path)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn relation(
        id: RelationId,
        src: GraphNodeId,
        dst: GraphNodeId,
        kind: RelationKind,
    ) -> Relation {
        Relation {
            id,
            kind,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn selected_checkout_remaps_entity_artifact_and_relation_collisions() {
        let selected = RepoPath::from_utf8("selected").unwrap();
        let shared_entity_id = EntityId::new();
        let current_selected_id = EntityId::new();
        let python_id = EntityId::new();
        let shared_artifact_id = ArtifactId::new();
        let current_selected_artifact_id = ArtifactId::new();
        let python_artifact_id = ArtifactId::new();
        let remapped_artifact_id = ArtifactId::new();
        let relation_id = RelationId::new();
        let retained = make_entity_with_id(
            shared_entity_id,
            "retained",
            "outside.rs",
            LanguageId::Rust,
            [0x11; 32],
        );
        let current_selected = make_entity_with_id(
            current_selected_id,
            "old",
            "selected/old.rs",
            LanguageId::Rust,
            [0x12; 32],
        );
        let target_rust = make_entity_with_id(
            shared_entity_id,
            "replacement",
            "selected/new.rs",
            LanguageId::Rust,
            [0x13; 32],
        );
        let target_python = make_entity_with_id(
            python_id,
            "helper",
            "selected/tool.py",
            LanguageId::Python,
            [0x14; 32],
        );
        let retained_relation = relation(
            relation_id,
            GraphNodeId::Entity(shared_entity_id),
            GraphNodeId::Entity(shared_entity_id),
            RelationKind::DependsOn,
        );
        let target_relation = relation(
            relation_id,
            GraphNodeId::Entity(shared_entity_id),
            GraphNodeId::Entity(python_id),
            RelationKind::Calls,
        );
        let outside_entry = TreeEntry::blob(Hash256::from_bytes([0x21; 32]), false);
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x22; 32]), false);
        let rust_entry = TreeEntry::blob(Hash256::from_bytes([0x23; 32]), false);
        let python_entry = TreeEntry::blob(Hash256::from_bytes([0x24; 32]), false);
        let current_tree = resolved_tree(vec![
            (
                shared_artifact_id,
                RepoPath::from_utf8("outside.rs").unwrap(),
                outside_entry,
            ),
            (
                current_selected_artifact_id,
                RepoPath::from_utf8("selected/old.rs").unwrap(),
                old_entry,
            ),
        ]);
        let target_tree = resolved_tree(vec![
            (
                shared_artifact_id,
                RepoPath::from_utf8("selected/new.rs").unwrap(),
                rust_entry,
            ),
            (
                python_artifact_id,
                RepoPath::from_utf8("selected/tool.py").unwrap(),
                python_entry,
            ),
        ]);
        let desired_tree = resolved_tree(vec![
            (
                shared_artifact_id,
                RepoPath::from_utf8("outside.rs").unwrap(),
                outside_entry,
            ),
            (
                remapped_artifact_id,
                RepoPath::from_utf8("selected/new.rs").unwrap(),
                rust_entry,
            ),
            (
                python_artifact_id,
                RepoPath::from_utf8("selected/tool.py").unwrap(),
                python_entry,
            ),
        ]);
        let graph = InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![
                    EntityDelta::Added {
                        new: retained.clone(),
                    },
                    EntityDelta::Added {
                        new: current_selected,
                    },
                ],
                relation_deltas: vec![RelationDelta::Added {
                    new: retained_relation.clone(),
                }],
                tree_deltas: kin_core::exact_tree_correction(
                    &ResolvedTree::default(),
                    &current_tree,
                )
                .unwrap(),
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        let target = ResolvedGraphState {
            entities: HashMap::from([
                (target_rust.id, target_rust),
                (target_python.id, target_python.clone()),
            ]),
            relations: HashMap::from([(target_relation.id, target_relation)]),
            entity_revisions: Default::default(),
            tree: target_tree,
            entity_tombstones: Default::default(),
            relation_tombstones: Default::default(),
            external_references: HashMap::new(),
        };

        let delta = compute_selected_checkout_delta(
            &graph,
            &selected,
            &target,
            &current_tree,
            &desired_tree,
        )
        .unwrap();
        graph.apply_transaction_delta(&delta).unwrap();
        let installed = graph.to_snapshot();
        assert_eq!(installed.resolved_tree, desired_tree);
        assert_eq!(
            installed.entities.get(&shared_entity_id),
            Some(&retained),
            "the retained entity keeps its original identity"
        );
        let copied = installed
            .entities
            .values()
            .find(|entity| entity.name == "replacement")
            .unwrap();
        assert_ne!(copied.id, shared_entity_id);
        assert_eq!(installed.entities.get(&python_id), Some(&target_python));
        assert_eq!(
            installed.relations.get(&relation_id),
            Some(&retained_relation),
            "the retained edge keeps its original identity"
        );
        let copied_relation = installed
            .relations
            .values()
            .find(|candidate| candidate.kind == RelationKind::Calls)
            .unwrap();
        assert_ne!(copied_relation.id, relation_id);
        assert_eq!(copied_relation.src, GraphNodeId::Entity(copied.id));
        assert_eq!(copied_relation.dst, GraphNodeId::Entity(python_id));
    }

    #[test]
    fn selected_checkout_omits_stale_cross_boundary_relation_without_losing_semantics() {
        let selected = RepoPath::from_utf8("src").unwrap();
        let selected_id = EntityId::new();
        let absent_outside_id = EntityId::new();
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let tree = resolved_tree(vec![(
            artifact_id,
            RepoPath::from_utf8("src/lib.rs").unwrap(),
            entry,
        )]);
        let target_entity = make_entity_with_id(
            selected_id,
            "selected",
            "src/lib.rs",
            LanguageId::Rust,
            [0x32; 32],
        );
        let stale = relation(
            RelationId::new(),
            GraphNodeId::Entity(selected_id),
            GraphNodeId::Entity(absent_outside_id),
            RelationKind::Calls,
        );
        let graph = InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: kin_core::exact_tree_correction(&ResolvedTree::default(), &tree)
                    .unwrap(),
                ..TransactionDelta::default()
            })
            .unwrap();
        let target = ResolvedGraphState {
            entities: HashMap::from([(selected_id, target_entity.clone())]),
            relations: HashMap::from([(stale.id, stale)]),
            entity_revisions: Default::default(),
            tree: tree.clone(),
            entity_tombstones: Default::default(),
            relation_tombstones: Default::default(),
            external_references: HashMap::new(),
        };

        let delta =
            compute_selected_checkout_delta(&graph, &selected, &target, &tree, &tree).unwrap();
        assert!(delta.tree_deltas.is_empty());
        assert_eq!(delta.entity_deltas.len(), 1);
        assert!(delta.relation_deltas.is_empty());
        graph.apply_transaction_delta(&delta).unwrap();
        assert_eq!(graph.get_entity(&selected_id).unwrap(), Some(target_entity));
        assert!(graph.to_snapshot().relations.is_empty());
    }

    /// A per-path checkout retires the edges into every entity it discards, in
    /// the same delta that discards them.
    ///
    /// The class this locks: an edit adds an entity, background enrichment mints
    /// an edge into it from a file outside the selection, and the checkout drops
    /// the entity. An edge left pointing at it is an orphan, and kin-db then
    /// refuses every later transaction and every later snapshot naming an entity
    /// `kin graph inspect` reports as not found. A stranger driving the v0.7.0
    /// release reached that state and had commit, `kin stash push` and
    /// `kin branch switch` all refuse at once.
    ///
    /// The `apply_transaction_delta` at the end is the positive control: it is
    /// the same admission check the daemon runs, so a delta that stranded the
    /// edge fails here rather than passing quietly.
    #[test]
    fn selected_checkout_retires_the_edges_into_every_entity_it_discards() {
        let selected = RepoPath::from_utf8("src").unwrap();
        let discarded_id = EntityId::new();
        let outside_id = EntityId::new();
        let selected_artifact = ArtifactId::new();
        let outside_artifact = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x41; 32]), false);
        let tree = resolved_tree(vec![
            (
                selected_artifact,
                RepoPath::from_utf8("src/lib.rs").unwrap(),
                entry.clone(),
            ),
            (
                outside_artifact,
                RepoPath::from_utf8("other/mod.rs").unwrap(),
                entry,
            ),
        ]);
        let discarded = make_entity_with_id(
            discarded_id,
            "grand_total",
            "src/lib.rs",
            LanguageId::Rust,
            [0x42; 32],
        );
        let outside = make_entity_with_id(
            outside_id,
            "format_report",
            "other/mod.rs",
            LanguageId::Rust,
            [0x43; 32],
        );
        // Enrichment derived this after the edit, from a file the checkout does
        // not touch into one it does.
        let inbound = relation(
            RelationId::new(),
            GraphNodeId::Entity(outside_id),
            GraphNodeId::Entity(discarded_id),
            RelationKind::UsesType,
        );

        let graph = InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: kin_core::exact_tree_correction(&ResolvedTree::default(), &tree)
                    .unwrap(),
                entity_deltas: vec![
                    kin_model::EntityDelta::Added {
                        new: discarded.clone(),
                    },
                    kin_model::EntityDelta::Added {
                        new: outside.clone(),
                    },
                ],
                relation_deltas: vec![kin_model::RelationDelta::Added {
                    new: inbound.clone(),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        // The change being restored predates the edit, so it never held the
        // entity or the edge into it.
        let target = ResolvedGraphState {
            entities: HashMap::from([(outside_id, outside.clone())]),
            relations: HashMap::new(),
            entity_revisions: Default::default(),
            tree: tree.clone(),
            entity_tombstones: Default::default(),
            relation_tombstones: Default::default(),
            external_references: HashMap::new(),
        };

        let delta =
            compute_selected_checkout_delta(&graph, &selected, &target, &tree, &tree).unwrap();
        assert!(delta.tree_deltas.is_empty());
        assert_eq!(
            delta.entity_deltas,
            vec![kin_model::EntityDelta::Removed { old: discarded }],
            "the checkout discards the entity the edit introduced"
        );
        assert_eq!(
            delta.relation_deltas,
            vec![kin_model::RelationDelta::Removed {
                old: inbound.clone()
            }],
            "and retires the edge into it in the same delta"
        );

        graph.apply_transaction_delta(&delta).unwrap();
        let after = graph.to_snapshot();
        assert!(!after.entities.contains_key(&discarded_id));
        assert!(after.relations.is_empty());
        assert!(
            after.entities.contains_key(&outside_id),
            "the entity outside the selection is untouched"
        );
    }

    /// A path selection does not scope the external-reference domain, so a
    /// spliced edge to an external endpoint survives exactly when the graph
    /// already holds that reference. The absent case must drop the edge rather
    /// than fabricate the endpoint, because the resulting delta is applied
    /// against a graph that rejects a relation to a reference it does not hold.
    #[test]
    fn selected_checkout_keeps_external_reference_edges_only_when_the_reference_exists() {
        fn checkout_delta_for_external_edge(
            reference: &kin_model::ExternalReference,
            present_in_graph: bool,
        ) -> TransactionDelta {
            let selected = RepoPath::from_utf8("src").unwrap();
            let selected_id = EntityId::new();
            let artifact_id = ArtifactId::new();
            let entry = TreeEntry::blob(Hash256::from_bytes([0x41; 32]), false);
            let tree = resolved_tree(vec![(
                artifact_id,
                RepoPath::from_utf8("src/lib.rs").unwrap(),
                entry,
            )]);
            let target_entity = make_entity_with_id(
                selected_id,
                "selected",
                "src/lib.rs",
                LanguageId::Rust,
                [0x42; 32],
            );
            let edge = relation(
                RelationId::new(),
                GraphNodeId::Entity(selected_id),
                GraphNodeId::ExternalReference(reference.id),
                RelationKind::Calls,
            );
            let graph = InMemoryGraph::new();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: kin_core::exact_tree_correction(&ResolvedTree::default(), &tree)
                        .unwrap(),
                    external_reference_deltas: if present_in_graph {
                        vec![kin_model::ExternalReferenceDelta::Added {
                            new: reference.clone(),
                        }]
                    } else {
                        Vec::new()
                    },
                    ..TransactionDelta::default()
                })
                .unwrap();
            let target = ResolvedGraphState {
                entities: HashMap::from([(selected_id, target_entity)]),
                relations: HashMap::from([(edge.id, edge)]),
                entity_revisions: Default::default(),
                tree: tree.clone(),
                entity_tombstones: Default::default(),
                relation_tombstones: Default::default(),
                external_references: HashMap::from([(reference.id, reference.clone())]),
            };

            let delta =
                compute_selected_checkout_delta(&graph, &selected, &target, &tree, &tree).unwrap();
            graph
                .apply_transaction_delta(&delta)
                .expect("a checkout delta must apply to the graph it was computed against");
            delta
        }

        let reference = kin_model::ExternalReference::new_resolved(
            "kin.checkout-fixture-v1",
            "fixture-source",
            "fixture::symbol",
        )
        .unwrap();

        let absent = checkout_delta_for_external_edge(&reference, false);
        assert!(absent.relation_deltas.is_empty());
        assert!(absent.external_reference_deltas.is_empty());

        let present = checkout_delta_for_external_edge(&reference, true);
        assert_eq!(present.relation_deltas.len(), 1);
        assert!(present.external_reference_deltas.is_empty());
    }

    fn genesis_change() -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: kin_model::ChangeOrigin::Native,
            parents: vec![],
            author: AuthorId::new("test"),
            message: "test genesis".to_string(),
            timestamp: Timestamp::now(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            admission_policy_delta: None,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        change
    }

    /// Record a SemanticChange in the graph.
    fn record_commit(
        graph: &InMemoryGraph,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        tree_deltas: Vec<TreeDelta>,
        parent: &SemanticChangeId,
        _branch: &str,
    ) -> SemanticChangeId {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: kin_model::ChangeOrigin::Native,
            parents: vec![*parent],
            author: AuthorId::new("test".to_string()),
            message: "test commit".to_string(),
            timestamp: Timestamp::now(),
            entity_deltas,
            relation_deltas,
            tree_deltas,
            admission_policy_delta: None,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        let change_id = change.id;
        graph.create_change(&change).expect("create_change");
        let desired = graph
            .resolve_tree_at(&change_id)
            .expect("resolve committed tree");
        let correction = kin_core::exact_tree_correction(&graph.resolved_tree(), &desired)
            .expect("align live tree with committed test head");
        graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: correction,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .expect("publish committed tree as live test authority");
        change_id
    }

    /// Simulate the serialized exact-tree admission that production performs
    /// before commit-delta construction.
    fn admit_working_tree(
        graph: &InMemoryGraph,
        blobs: &BlobStore,
        layout: &kin_core::KinLayout,
    ) -> Result<()> {
        let previous = graph.resolved_tree();
        let tracked_paths = previous
            .artifacts_by_path()
            .map(|artifact| artifact.path.clone())
            .collect::<Vec<_>>();
        let mut graph_only_paths = Vec::new();
        for artifact in previous.artifacts_by_path() {
            if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
                != kin_core::SourceProjectionDisposition::Materialized
            {
                graph_only_paths.push(artifact.path.clone());
            }
        }
        let source = layout.working_dir();
        let ignore =
            kin_index::RepositoryIgnore::load(&source).map_err(kin_index::IndexError::from)?;
        let scan = kin_index::scan_repository_preserving_graph_only(
            &source,
            &ignore,
            None,
            tracked_paths.iter(),
            graph_only_paths.iter(),
        )
        .map_err(kin_index::IndexError::from)?;
        let observed = observed_tree_from_complete_scan(blobs, &scan, &previous)?;
        let tree_deltas =
            kin_core::plan_observed_tree_deltas(&previous, observed.entries().clone())?;
        graph.apply_transaction_delta(&kin_model::TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        })?;
        Ok(())
    }

    // ── Entity delta tests ───────────────────────────────────────────────

    /// Adding a new entity to the graph (simulating reconcile applying an
    /// overlay) and then computing deltas against genesis should produce
    /// exactly one Added delta for that entity.
    #[test]
    fn entity_added_since_genesis_appears_in_deltas() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        // Simulate reconcile: entity upserted into primary graph (overlay cleared).
        let entity = make_entity("my_fn", "src/lib.rs", [1; 32]);
        graph.upsert_entity(&entity).unwrap();

        // No files on disk; tree deltas will be empty.
        let deltas = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();

        assert_eq!(
            deltas.entity_deltas.len(),
            1,
            "expected one entity Added delta"
        );
        assert!(
            matches!(
                &deltas.entity_deltas[0],
                EntityDelta::Added { new } if new.id == entity.id
            ),
            "delta must be Added for the new entity"
        );
        assert!(deltas.relation_deltas.is_empty());
    }

    /// After a commit that records the current entity, computing deltas
    /// against the new head produces zero entity deltas (idempotent).
    #[test]
    fn no_deltas_after_commit_records_current_entity() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let entity = make_entity("stable_fn", "src/lib.rs", [42; 32]);
        graph.upsert_entity(&entity).unwrap();

        // Record a commit that contains this entity.
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Now compute deltas against the new head: entity is committed, nothing changed.
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert!(
            deltas.entity_deltas.is_empty(),
            "no entity changes since the commit — deltas must be empty"
        );
        assert!(deltas.tree_deltas.is_empty());
    }

    /// A fingerprint change on an existing committed entity produces a Modified
    /// delta with the correct old (from DAG) and new (from graph) entity.
    #[test]
    fn modified_entity_fingerprint_produces_modified_delta() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        // Commit the entity with hash [1;32].
        let old_entity = make_entity("changing_fn", "src/lib.rs", [1; 32]);
        graph.upsert_entity(&old_entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: old_entity.clone(),
            }],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Simulate reconcile applying a changed version (hash [2;32]) to graph.
        let mut new_entity = old_entity.clone();
        new_entity.fingerprint.ast_hash = Hash256::from_bytes([2; 32]);
        graph.upsert_entity(&new_entity).unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert_eq!(deltas.entity_deltas.len(), 1);
        match &deltas.entity_deltas[0] {
            EntityDelta::Modified { old, new } => {
                assert_eq!(old.fingerprint.ast_hash, Hash256::from_bytes([1; 32]));
                assert_eq!(new.fingerprint.ast_hash, Hash256::from_bytes([2; 32]));
            }
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    /// Removing an entity from the graph after it was committed produces a Removed delta.
    #[test]
    fn removed_entity_produces_removed_delta() {
        let graph = Arc::new(kin_db::InMemoryGraph::new());

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let entity = make_entity("doomed_fn", "src/lib.rs", [7; 32]);
        graph.upsert_entity(&entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![],
            &genesis.id,
            "main",
        );

        // Simulate reconcile removing the entity from the primary graph.
        graph.remove_entity(&entity.id).unwrap();

        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert_eq!(deltas.entity_deltas.len(), 1);
        assert!(
            matches!(
                &deltas.entity_deltas[0],
                EntityDelta::Removed { old } if old.id == entity.id
            ),
            "expected Removed delta for the deleted entity"
        );
    }

    // ── Exact tree delta tests ───────────────────────────────────────────

    /// A new file on disk that was not in the last commit appears as Added.
    #[test]
    fn new_file_on_disk_appears_as_added_tree_delta() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        // Write a file to the working directory.
        let src_dir = layout.working_dir();
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        std::fs::write(src_dir.join("src/new.rs"), b"pub fn new_fn() {}\n").unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let live_tree = graph.resolved_tree();
        let live_artifact = live_tree
            .artifact_at_path(&RepoPath::from_utf8("src/new.rs").unwrap())
            .unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();

        assert_eq!(deltas.expected_tree, live_tree);
        assert!(
            !deltas.tree_deltas.is_empty(),
            "new file must produce a tree delta"
        );
        let added = deltas
            .tree_deltas
            .iter()
            .filter_map(|delta| match delta {
                TreeDelta::Added {
                    new:
                        LocatedEntry {
                            entry:
                                TreeEntry::Blob {
                                    executable: false, ..
                                },
                            ..
                        },
                    ..
                } => Some(()),
                _ => None,
            })
            .count();
        assert!(added >= 1, "at least one Added tree delta expected");
        assert!(deltas.tree_deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Added { artifact_id, new }
                    if *artifact_id == live_artifact.artifact_id
                        && new.path == live_artifact.path
            )
        }));
        assert_eq!(
            graph
                .resolve_tree_at(&genesis.id)
                .unwrap()
                .apply(&deltas.tree_deltas)
                .unwrap(),
            live_tree
        );
    }

    /// The walk declines to observe a tracked path its rules cover, so the
    /// observation carries that path's existing truth forward unchanged.
    /// Reading "unobserved" as "absent" would delete graph-owned identity by
    /// inference, and it would do it on the exact pass that stopped reading the
    /// path. Retiring an ignored member stays an announced retraction.
    #[test]
    fn an_unverified_ignored_path_keeps_its_previous_tree_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let working = layout.working_dir();
        std::fs::create_dir_all(working.join("vm")).unwrap();
        std::fs::write(working.join(".kinignore"), b"vm\n").unwrap();
        std::fs::write(working.join("kept.rs"), b"pub fn kept() {}").unwrap();
        // Admitted before the rule existed, and rewritten on the host since.
        std::fs::write(working.join("vm/disk.img"), b"rewritten since").unwrap();
        let admitted_bytes = b"admitted before the rule existed";
        let admitted_hash = Hash256::from_bytes(blobs.write(admitted_bytes).unwrap().0);
        let ignored = RepoPath::from_utf8("vm/disk.img").unwrap();
        let previous = resolved_tree(vec![(
            ArtifactId::new(),
            ignored.clone(),
            TreeEntry::blob(admitted_hash, false),
        )]);

        let ignore = kin_index::RepositoryIgnore::load(&working).unwrap();
        let scan = kin_index::scan_repository(
            &working,
            &ignore,
            previous.artifacts_by_path().map(|artifact| &artifact.path),
        )
        .unwrap();
        assert_eq!(
            scan.unverified_ignored_paths().collect::<Vec<_>>(),
            [&ignored]
        );

        let observed = observed_tree_from_complete_scan(&blobs, &scan, &previous).unwrap();
        assert_eq!(
            observed.entries().get(&ignored),
            Some(&TreeEntry::blob(admitted_hash, false)),
            "an unobserved ignored path keeps the exact entry graph truth holds"
        );

        let deltas =
            kin_core::plan_observed_tree_deltas(&previous, observed.entries().clone()).unwrap();
        assert!(
            !deltas
                .iter()
                .any(|delta| matches!(delta, TreeDelta::Removed { .. })),
            "declining to read a path must not plan its removal: {deltas:?}"
        );
        assert!(deltas.iter().any(|delta| matches!(
            delta,
            TreeDelta::Added { new, .. } if new.path == RepoPath::from_utf8("kept.rs").unwrap()
        )));

        // Falsification: the same fixture removes a tracked path the rules do
        // not cover, so the absence of a Removed delta above is the ignore rule
        // and not a planner that never removes anything. Every host file is
        // already tracked here, because an unmatched removal beside an
        // unmatched addition is refused as a possible move.
        let gone = RepoPath::from_utf8("gone.rs").unwrap();
        let previous_with_gone = resolved_tree(vec![
            (
                ArtifactId::new(),
                ignored.clone(),
                TreeEntry::blob(admitted_hash, false),
            ),
            (
                ArtifactId::new(),
                RepoPath::from_utf8(".kinignore").unwrap(),
                TreeEntry::blob(Hash256::from_bytes(blobs.write(b"vm\n").unwrap().0), false),
            ),
            (
                ArtifactId::new(),
                RepoPath::from_utf8("kept.rs").unwrap(),
                TreeEntry::blob(
                    Hash256::from_bytes(blobs.write(b"pub fn kept() {}").unwrap().0),
                    false,
                ),
            ),
            (
                ArtifactId::new(),
                gone.clone(),
                TreeEntry::blob(admitted_hash, false),
            ),
        ]);
        let scan = kin_index::scan_repository(
            &working,
            &ignore,
            previous_with_gone
                .artifacts_by_path()
                .map(|artifact| &artifact.path),
        )
        .unwrap();
        let observed =
            observed_tree_from_complete_scan(&blobs, &scan, &previous_with_gone).unwrap();
        let deltas =
            kin_core::plan_observed_tree_deltas(&previous_with_gone, observed.entries().clone())
                .unwrap();
        assert!(deltas.iter().any(|delta| matches!(
            delta,
            TreeDelta::Removed { old, .. } if old.path == gone
        )));
    }

    /// An entry the walk found identical to authority is observed from the
    /// walk's own proof, with no second read of the host.
    ///
    /// Asserted by deleting the file between the scan and the observation. The
    /// walk already opened, read, and hashed it, and authority already holds a
    /// blob for those exact bytes, so nothing is left to read and this succeeds;
    /// the earlier code read every leaf a second time and fails here.
    ///
    /// This is the whole-store phase that used to sit inside the per-event path.
    /// The reconcile loop runs this on every tick, so a working copy of twenty
    /// thousand files paid two complete reads of itself to observe that one file
    /// had moved. What it costs now is proportional to what moved.
    #[test]
    fn an_unchanged_entry_is_observed_without_a_second_host_read() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let working = layout.working_dir();

        let bytes = b"pub fn unchanged() {}\n";
        std::fs::write(working.join("unchanged.rs"), bytes).unwrap();
        let hash = Hash256::from_bytes(blobs.write(bytes).unwrap().0);
        let path = RepoPath::from_utf8("unchanged.rs").unwrap();
        let previous = resolved_tree(vec![(
            ArtifactId::new(),
            path.clone(),
            TreeEntry::blob(hash, false),
        )]);

        let ignore = kin_index::RepositoryIgnore::load(&working).unwrap();
        let scan = kin_index::scan_repository(
            &working,
            &ignore,
            previous.artifacts_by_path().map(|artifact| &artifact.path),
        )
        .unwrap();

        std::fs::remove_file(working.join("unchanged.rs")).unwrap();

        let observed = observed_tree_from_complete_scan(&blobs, &scan, &previous).unwrap();
        assert_eq!(
            observed.entries().get(&path),
            Some(&TreeEntry::blob(hash, false)),
            "an unchanged entry is carried by the walk's hash, not by reading it again"
        );
        let deltas =
            kin_core::plan_observed_tree_deltas(&previous, observed.entries().clone()).unwrap();
        assert!(
            deltas.is_empty(),
            "an unchanged working copy plans no transition: {deltas:?}"
        );
    }

    /// Falsification: an entry that differs from authority is still read, and
    /// its bytes are still checked against the digest the walk recorded.
    ///
    /// Without this the saving above would be a hole rather than an economy: a
    /// file rewritten between the walk and the publication would reach authority
    /// as a hash for content the store never held.
    #[test]
    fn a_changed_entry_is_still_read_and_checked_against_the_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let working = layout.working_dir();

        std::fs::write(working.join("changed.rs"), b"pub fn before() {}\n").unwrap();
        let stale = Hash256::from_bytes(blobs.write(b"pub fn stale() {}\n").unwrap().0);
        let path = RepoPath::from_utf8("changed.rs").unwrap();
        let previous = resolved_tree(vec![(
            ArtifactId::new(),
            path.clone(),
            TreeEntry::blob(stale, false),
        )]);

        let ignore = kin_index::RepositoryIgnore::load(&working).unwrap();
        let scan = kin_index::scan_repository(
            &working,
            &ignore,
            previous.artifacts_by_path().map(|artifact| &artifact.path),
        )
        .unwrap();

        // Rewritten after the walk hashed it, which is the race the check exists
        // for. The observation must refuse rather than publish the stale digest.
        std::fs::write(working.join("changed.rs"), b"pub fn after() {}\n").unwrap();

        let Err(error) = observed_tree_from_complete_scan(&blobs, &scan, &previous) else {
            panic!("a changed entry must still be read and refused when it moved mid-pass");
        };
        let error = error.to_string();
        assert!(
            error.contains("changed.rs") || error.contains("changed after"),
            "{error}"
        );
    }

    /// A file whose content changed since the last commit appears as Modified.
    #[test]
    fn changed_file_appears_as_modified_tree_delta() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        // Simulate a prior commit that recorded the file with old content.
        let src_dir = layout.working_dir();
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        let old_content = b"pub fn old() {}\n";
        std::fs::write(src_dir.join("src/lib.rs"), old_content).unwrap();
        let old_digest = blobs.write(old_content).unwrap();
        let old_hash = Hash256::from_bytes(old_digest.0);
        let path = RepoPath::from_utf8("src/lib.rs").unwrap();
        let artifact_id = ArtifactId::new();

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path.clone(), TreeEntry::blob(old_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // Change the file on disk.
        std::fs::write(src_dir.join("src/lib.rs"), b"pub fn new() {}\n").unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        let (old_entry, new_entry) = deltas
            .tree_deltas
            .iter()
            .find_map(|delta| match delta {
                TreeDelta::Updated {
                    artifact_id: delta_artifact_id,
                    old,
                    new,
                } if *delta_artifact_id == artifact_id && new.path == path => {
                    Some((&old.entry, &new.entry))
                }
                _ => None,
            })
            .expect("changed file must produce an Updated tree delta");
        assert_eq!(*old_entry, TreeEntry::blob(old_hash, false));
        assert_ne!(new_entry.blob_identity(), Some(old_hash));
        assert!(matches!(
            new_entry,
            TreeEntry::Blob {
                executable: false,
                ..
            }
        ));
    }

    #[test]
    fn commit_preserves_live_identity_after_admitted_move_then_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let source = layout.working_dir();
        std::fs::create_dir_all(source.join("src")).unwrap();
        let old_path = RepoPath::from_utf8("src/old.rs").unwrap();
        let new_path = RepoPath::from_utf8("src/new.rs").unwrap();
        let old_bytes = b"pub fn value() -> u8 { 1 }\n";
        let old_hash = Hash256::from_bytes(blobs.write(old_bytes).unwrap().0);
        let artifact_id = ArtifactId::new();
        std::fs::write(source.join("src/old.rs"), old_bytes).unwrap();
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(old_path.clone(), TreeEntry::blob(old_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        std::fs::rename(source.join("src/old.rs"), source.join("src/new.rs")).unwrap();
        admit_working_tree(&graph, &blobs, &layout).unwrap();
        assert_eq!(
            graph
                .resolved_tree()
                .artifact_at_path(&new_path)
                .unwrap()
                .artifact_id,
            artifact_id
        );

        std::fs::write(source.join("src/new.rs"), b"pub fn value() -> u8 { 2 }\n").unwrap();
        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let live_tree = graph.resolved_tree();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        assert_eq!(deltas.expected_tree, live_tree);
        assert_eq!(deltas.tree_deltas.len(), 1);
        assert!(matches!(
            &deltas.tree_deltas[0],
            TreeDelta::Updated {
                artifact_id: id,
                old,
                new,
            } if *id == artifact_id && old.path == old_path && new.path == new_path
        ));
        assert_eq!(
            graph
                .resolve_tree_at(&head)
                .unwrap()
                .apply(&deltas.tree_deltas)
                .unwrap(),
            live_tree
        );
    }

    /// A file that was committed but no longer exists on disk appears as Removed.
    #[test]
    fn deleted_file_appears_as_removed_tree_delta() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let content = b"pub fn gone() {}\n";
        let digest = blobs.write(content).unwrap();
        let committed_hash = Hash256::from_bytes(digest.0);
        let path = RepoPath::from_utf8("src/deleted.rs").unwrap();
        let artifact_id = ArtifactId::new();

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path.clone(), TreeEntry::blob(committed_hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // File is NOT present on disk — simulate deletion.
        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();

        let old_entry = deltas
            .tree_deltas
            .iter()
            .find_map(|delta| match delta {
                TreeDelta::Removed {
                    artifact_id: delta_artifact_id,
                    old,
                } if *delta_artifact_id == artifact_id && old.path == path => Some(&old.entry),
                _ => None,
            })
            .expect("deleted file must produce a Removed tree delta");
        assert_eq!(*old_entry, TreeEntry::blob(committed_hash, false));
    }

    #[cfg(unix)]
    #[test]
    fn tree_deltas_preserve_modes_symlinks_and_mode_only_changes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let source = layout.working_dir();
        std::fs::create_dir_all(source.join("bin")).unwrap();
        let regular = source.join("plain.txt");
        let executable = source.join("bin/run");
        std::fs::write(&regular, b"plain\n").unwrap();
        std::fs::write(&executable, b"#!/bin/sh\n").unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        symlink("plain.txt", source.join("current")).unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let initial = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();
        let entries: std::collections::BTreeMap<_, _> = initial
            .tree_deltas
            .iter()
            .filter_map(|delta| match delta {
                TreeDelta::Added { new, .. } => {
                    Some((new.path.as_utf8().expect("UTF-8 fixture path"), new.entry))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            entries.get("plain.txt"),
            Some(&TreeEntry::blob(
                Hash256::from_bytes(blobs.write(b"plain\n").unwrap().0),
                false
            ))
        );
        assert!(matches!(
            entries.get("bin/run"),
            Some(TreeEntry::Blob {
                executable: true,
                ..
            })
        ));
        assert!(matches!(
            entries.get("current"),
            Some(TreeEntry::Symlink { .. })
        ));
        let link = initial
            .tree_deltas
            .iter()
            .find_map(|delta| match delta {
                TreeDelta::Added { new, .. } if new.path.as_utf8() == Some("current") => {
                    Some(new.entry)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            blobs
                .read(&kin_blobs::Hash256(
                    link.blob_identity().expect("symlink blob").0
                ))
                .unwrap(),
            b"plain.txt"
        );

        let head = record_commit(
            &graph,
            vec![],
            vec![],
            initial.tree_deltas,
            &genesis.id,
            "main",
        );
        let plain_hash = blobs.write(b"plain\n").unwrap();
        let mut permissions = std::fs::metadata(&regular).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&regular, permissions).unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let mode_only = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert_eq!(mode_only.tree_deltas.len(), 1);
        let TreeDelta::Updated {
            artifact_id: _,
            old,
            new,
        } = &mode_only.tree_deltas[0]
        else {
            panic!("mode-only change must be Updated");
        };
        assert_eq!(old.path.as_utf8(), Some("plain.txt"));
        assert_eq!(new.path, old.path);
        assert_eq!(
            old.entry,
            TreeEntry::blob(Hash256::from_bytes(plain_hash.0), false)
        );
        assert_eq!(
            new.entry,
            TreeEntry::blob(Hash256::from_bytes(plain_hash.0), true)
        );
    }

    #[test]
    fn commit_admits_mixed_codebase_membership_independent_of_language_support() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let source = layout.working_dir();
        // Parser support, vendoring, opaque bytes, and generated-but-committed
        // artifacts never decide membership.
        let expected: &[(&str, &[u8])] = &[
            ("Dockerfile", b"FROM scratch"),
            ("compose.yaml", b"services: {}"),
            ("Cargo.lock", b"version = 4"),
            ("src/main.rs", b"fn main() {}"),
            ("web/app.ts", b"export const app = true"),
            ("tools/job.py", b"print('job')"),
            ("unsupported/program.xyzzy", b"opaque source"),
            ("assets/logo.bin", b"\x00\xff\x10"),
            ("vendor/lib/source.c", b"int vendored(void) { return 1; }"),
            ("generated/schema.pb", b"\x01\x02generated"),
        ];
        // Build output a compiler reproduces is excluded by the built-in
        // defaults, so it never reaches repository truth.
        let derived: &[(&str, &[u8])] = &[
            ("node_modules/pkg/index.js", b"export default 1"),
            ("target/debug/build.log", b"built"),
        ];
        for (relative, bytes) in expected.iter().chain(derived) {
            let path = source.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &genesis.id).unwrap();
        let admitted = deltas
            .tree_deltas
            .iter()
            .filter_map(|delta| match delta {
                TreeDelta::Added { new, .. } => new.path.as_utf8(),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        for (relative, _) in expected {
            assert!(
                admitted.contains(*relative),
                "missing exact member {relative}"
            );
        }
        for (relative, _) in derived {
            assert!(
                !admitted.contains(*relative),
                "derived output admitted: {relative}"
            );
        }
    }

    #[test]
    fn commit_preserves_gitlink_without_expanding_materialized_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();
        let gitlink = TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x61; 20]));
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(RepoPath::from_utf8("submodule").unwrap(), gitlink),
            }],
            &genesis.id,
            "main",
        );
        let checkout_file = layout.working_dir().join("submodule/src/lib.rs");
        std::fs::create_dir_all(checkout_file.parent().unwrap()).unwrap();
        std::fs::write(checkout_file, b"materialized checkout").unwrap();

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert!(
            deltas.tree_deltas.is_empty(),
            "host checkout cannot update, remove, or expand graph-owned Gitlink truth"
        );
    }

    /// A rule covers what commit reads, not only what commit admits. A tracked
    /// path the rules cover keeps the truth the graph already holds for it and
    /// the host copy stops being read, so its bytes can change all they like
    /// without moving repository truth or failing the walk around it.
    #[test]
    fn commit_ignore_withholds_covered_paths_and_carries_their_truth_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let source = layout.working_dir();
        std::fs::create_dir_all(source.join("target")).unwrap();
        std::fs::create_dir_all(source.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::write(source.join(".kinignore"), b"target/\nnode_modules/\n.env\n").unwrap();
        std::fs::write(source.join("target/retained.bin"), b"new tracked bytes").unwrap();
        std::fs::write(source.join("target/untracked.bin"), b"build output").unwrap();
        std::fs::write(source.join("node_modules/pkg/index.js"), b"generated").unwrap();
        std::fs::write(source.join(".env"), b"SECRET=never-admit").unwrap();
        std::fs::write(source.join("src/lib.rs"), b"new admitted bytes").unwrap();

        let old_hash = Hash256::from_bytes(blobs.write(b"old tracked bytes").unwrap().0);
        let retained = RepoPath::from_utf8("target/retained.bin").unwrap();
        let admitted = RepoPath::from_utf8("src/lib.rs").unwrap();
        let artifact_id = ArtifactId::new();
        let admitted_id = ArtifactId::new();
        let head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![
                TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(retained.clone(), TreeEntry::blob(old_hash, false)),
                },
                TreeDelta::Added {
                    artifact_id: admitted_id,
                    new: LocatedEntry::new(admitted.clone(), TreeEntry::blob(old_hash, false)),
                },
            ],
            &genesis.id,
            "main",
        );

        admit_working_tree(&graph, &blobs, &layout).unwrap();
        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert!(
            !deltas.tree_deltas.iter().any(|delta| delta
                .new_state()
                .is_some_and(|new| new.path == retained)
                || delta.old_state().is_some_and(|old| old.path == retained)),
            "a covered path's host bytes must not move repository truth: {:?}",
            deltas.tree_deltas
        );
        // Falsification: the same commit still follows an admitted file whose
        // bytes changed, so the silence above belongs to the rule.
        assert!(deltas.tree_deltas.iter().any(|delta| {
            matches!(
                delta,
                TreeDelta::Updated {
                    artifact_id: id,
                    new,
                    ..
                } if *id == admitted_id && new.path == admitted
            )
        }));
        for ignored in [".env", "target/untracked.bin", "node_modules/pkg/index.js"] {
            assert!(
                !deltas.tree_deltas.iter().any(|delta| {
                    delta
                        .new_state()
                        .is_some_and(|entry| entry.path.as_utf8() == Some(ignored))
                }),
                "untracked ignored path entered commit truth: {ignored}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn tracked_special_entry_blocks_commit_before_missing_paths_become_removals() {
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let missing = RepoPath::from_utf8("missing.txt").unwrap();
        let special = RepoPath::from_utf8("tracked.sock").unwrap();
        let old_hash = Hash256::from_bytes(blobs.write(b"old").unwrap().0);
        let _head = record_commit(
            &graph,
            vec![],
            vec![],
            vec![
                TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(missing, TreeEntry::blob(old_hash, false)),
                },
                TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(special, TreeEntry::blob(old_hash, false)),
                },
            ],
            &genesis.id,
            "main",
        );
        let _listener = UnixListener::bind(layout.working_dir().join("tracked.sock")).unwrap();

        let error = admit_working_tree(&graph, &blobs, &layout)
            .expect_err("an incomplete exact scan cannot authorize any inferred removal");
        assert!(error.to_string().contains("tracked path changed"));
    }

    // ── End-to-end: zero deltas after recording current state ─────────────

    /// After recording all current entities + files in a commit, a second
    /// compute produces zero deltas across all three slices.  This is the
    /// non-zero → zero correctness gate — ensures the production path will
    /// emit empty deltas for a clean second commit.
    #[test]
    fn second_commit_with_no_changes_produces_zero_deltas() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        // Write a file and add an entity.
        let src_dir = layout.working_dir();
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        let content = b"pub fn stable() {}\n";
        std::fs::write(src_dir.join("src/lib.rs"), content).unwrap();
        let digest = blobs.write(content).unwrap();
        let hash = Hash256::from_bytes(digest.0);
        let path = RepoPath::from_utf8("src/lib.rs").unwrap();

        let entity = make_entity("stable", "src/lib.rs", [99; 32]);
        graph.upsert_entity(&entity).unwrap();

        // First commit: record the current state.
        let head1 = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // Second compute: nothing changed → all deltas empty.
        let deltas = compute_deltas_vs_last_commit(&graph, &head1).unwrap();

        assert!(
            deltas.entity_deltas.is_empty(),
            "no entity changes: expected 0, got {}",
            deltas.entity_deltas.len()
        );
        assert!(
            deltas.tree_deltas.is_empty(),
            "no file changes: expected 0, got {}",
            deltas.tree_deltas.len()
        );
        assert!(
            deltas.relation_deltas.is_empty(),
            "no relation changes: expected 0, got {}",
            deltas.relation_deltas.len()
        );
    }

    /// An entity whose body did not change but whose source provenance moved
    /// must still be published.
    ///
    /// The workspace semantic overlay is derived by whole-value difference
    /// against the change a commit publishes. Recording only fingerprint
    /// changes leaves the published base holding a superseded payload, so the
    /// difference is stranded in the overlay: the workspace reports dirty
    /// permanently, the next switch or merge refuses it, and a further commit
    /// publishes an empty change because the fingerprint still has not moved.
    #[test]
    fn commit_publishes_an_entity_whose_provenance_moved_without_its_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let init = kin_core::init(tmp.path()).unwrap();
        let layout = init.layout;
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();

        let genesis = genesis_change();
        graph.create_change(&genesis).unwrap();

        let src_dir = layout.working_dir();
        std::fs::create_dir_all(src_dir.join("src")).unwrap();
        let content = b"pub fn stable() {}\n";
        std::fs::write(src_dir.join("src/lib.rs"), content).unwrap();
        let digest = blobs.write(content).unwrap();
        let hash = Hash256::from_bytes(digest.0);
        let path = RepoPath::from_utf8("src/lib.rs").unwrap();

        let entity = make_entity("stable", "src/lib.rs", [99; 32]);
        graph.upsert_entity(&entity).unwrap();
        let head = record_commit(
            &graph,
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            vec![],
            vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
            }],
            &genesis.id,
            "main",
        );

        // Same identity, same body, same fingerprint. Only the blob provenance
        // the reconciler stamps has advanced, exactly as it does when an edit
        // elsewhere in the file rewrites the artifact this entity came from.
        let mut reprovenanced = entity.clone();
        reprovenanced
            .metadata
            .extra
            .insert("blob_hash".into(), "advanced-source-blob".into());
        graph.upsert_entity(&reprovenanced).unwrap();
        assert_eq!(
            entity.fingerprint, reprovenanced.fingerprint,
            "the fixture must move provenance without moving the semantic fingerprint"
        );
        assert_ne!(
            entity, reprovenanced,
            "the fixture must still be a different entity payload"
        );

        let deltas = compute_deltas_vs_last_commit(&graph, &head).unwrap();
        assert_eq!(
            deltas.entity_deltas,
            vec![EntityDelta::Modified {
                old: entity,
                new: reprovenanced,
            }],
            "a moved payload must reach the published change, not the workspace overlay"
        );
    }

    // ── The commit baseline: which arm answered, and do they agree ──
    //
    // `resolve_authority_baseline` has two arms and they must return the same
    // graph. These fixtures make WHICH arm answered observable, because an
    // equality assertion alone cannot tell a section hit from a fallback that
    // happened to agree. The section here is given a state history cannot
    // reproduce, purely so the test can read the answer's provenance off its
    // content; a real section is authority's own memo of the same fold.

    fn baseline_entity(name: &str) -> Entity {
        Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn baseline_change(
        parent: Option<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
    ) -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: kin_model::ChangeOrigin::Native,
            parents: parent.into_iter().collect(),
            timestamp: Timestamp::from(
                chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("relchurn"),
            message: "baseline fixture".to_string(),
            entity_deltas,
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    /// A snapshot shaped like the one a commit holds: several linear changes
    /// carrying entity deltas, and `entity_revisions` cleared, which is what
    /// repository authority always does to them.
    fn authority_like_snapshot(depth: usize) -> (GraphSnapshot, SemanticChangeId) {
        let graph = InMemoryGraph::new();
        let mut head = None;
        let mut carried: Option<Entity> = None;
        for index in 0..depth {
            let deltas = match carried.take() {
                None => {
                    let entity = baseline_entity(&format!("seed_{index}"));
                    carried = Some(entity.clone());
                    vec![EntityDelta::Added { new: entity }]
                }
                Some(previous) => {
                    let mut next = previous.clone();
                    next.signature = format!("fn seed_{index}()");
                    carried = Some(next.clone());
                    vec![EntityDelta::Modified {
                        old: previous,
                        new: next,
                    }]
                }
            };
            let change = baseline_change(head, deltas);
            graph.create_change(&change).unwrap();
            head = Some(change.id);
        }
        if let Some(entity) = carried {
            graph.upsert_entity(&entity).unwrap();
        }
        let mut snapshot = graph.to_snapshot();
        snapshot.repository_authority = None;
        snapshot.entity_revisions.clear();
        (snapshot, head.expect("depth is at least one change"))
    }

    /// The pre-change baseline path, kept here as the reference the two arms
    /// are measured against rather than as production code.
    fn baseline_by_building_a_graph(
        snapshot: &GraphSnapshot,
        head: &SemanticChangeId,
    ) -> ResolvedGraphState {
        let mut owned = snapshot.clone();
        owned.repository_authority = None;
        InMemoryGraph::from_snapshot(owned)
            .unwrap()
            .resolve_graph_at(head)
            .unwrap()
    }

    fn marked_section(
        resolved_at: SemanticChangeId,
        mut state: ResolvedGraphState,
    ) -> kin_db::MaterializedGraphSection {
        let marker = baseline_entity("only_a_section_can_answer_with_this");
        state.entities.insert(marker.id, marker);
        kin_db::MaterializedGraphSection {
            schema_version: kin_db::MATERIALIZED_GRAPH_SCHEMA_VERSION,
            resolved_at,
            state,
        }
    }

    #[test]
    fn folding_history_returns_what_building_a_graph_returned() {
        let (snapshot, head) = authority_like_snapshot(6);
        let expected = baseline_by_building_a_graph(&snapshot, &head);

        let folded = baseline_from_history(&snapshot, &head).unwrap();

        assert_eq!(folded.entities, expected.entities);
        assert_eq!(folded.relations, expected.relations);
        assert_eq!(folded.tree, expected.tree);
        // The reference is not vacuous: this fixture resolves real entities.
        assert!(
            !expected.entities.is_empty(),
            "a fixture that resolves to nothing would let any implementation pass"
        );
    }

    #[test]
    fn a_section_at_the_parent_answers_without_folding_history() {
        let (mut snapshot, head) = authority_like_snapshot(6);
        let folded = baseline_from_history(&snapshot, &head).unwrap();
        snapshot.materialized_graph = Some(Arc::new(marked_section(head, folded.clone())));

        let resolved = resolve_authority_baseline(&snapshot, &head).unwrap();

        assert_eq!(
            resolved.entities.len(),
            folded.entities.len() + 1,
            "the section arm must have answered; a fallback would have dropped its marker"
        );
    }

    #[test]
    fn a_section_at_another_change_falls_back_and_still_answers() {
        let (mut snapshot, head) = authority_like_snapshot(6);
        let folded = baseline_from_history(&snapshot, &head).unwrap();
        let stale = SemanticChangeId::from_hash(Hash256::from_bytes([0x5a; 32]));
        assert_ne!(stale, head, "the stale target must not be the parent");
        snapshot.materialized_graph = Some(Arc::new(marked_section(stale, folded.clone())));

        let resolved = resolve_authority_baseline(&snapshot, &head).unwrap();

        assert_eq!(
            resolved.entities, folded.entities,
            "a section naming another change must be refused, not trusted"
        );
        assert_eq!(
            resolved.entities.len(),
            folded.entities.len(),
            "the marker proves the refused section did not answer"
        );
    }
}
