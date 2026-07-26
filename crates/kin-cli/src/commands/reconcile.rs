// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconcile an isolated session workspace into graph-owned repository truth.
//!
//! The filesystem is consulted only as an explicit, complete session-ingress
//! observation. The recorded graph head supplies the base, the live graph
//! supplies the current state, and one identity-bearing transaction publishes
//! exact tree plus semantic changes. The working directory is only a projection.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kin_index::{FileClassification, FileClassifier, FileEvent};
use kin_model::{
    ChangeStore, Entity, EntityDelta, EntityFilter, EntityId, EntityStore, FilePathId, GraphNodeId,
    GraphOverlay, Relation, RelationDelta, RelationId, RepoPath, ResolvedArtifact, ResolvedTree,
    TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::{ReconcileOutcome, Reconciler};
use serde::{Deserialize, Serialize};

/// `kin reconcile [session-id] [--cleanup]` — admit a session workspace into the graph.
pub async fn run(session_id: Option<String>, cleanup: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let session_dir = resolve_session_dir(&layout, session_id)?;
    let summary = reconcile_session_dir(&layout, &session_dir).await?;

    if summary.change_count == 0 {
        println!("No changes detected.");
        return Ok(());
    }

    println!("\nDetected changes:");
    for change in &summary.changes {
        println!("  {} {}", change.0, change.1);
    }
    println!(
        "\nReconciliation complete: {} files semantically indexed, {} entities upserted, {} entities removed.",
        summary.files_indexed, summary.total_upserted, summary.total_removed
    );

    if cleanup {
        std::fs::remove_dir_all(&session_dir).map_err(|error| {
            anyhow::anyhow!(
                "reconciled successfully, but failed to clean up {}: {}",
                session_dir.display(),
                error
            )
        })?;
        println!("Cleaned up session workspace: {}", session_dir.display());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileSummary {
    pub changes: Vec<(String, String)>,
    pub change_count: usize,
    pub files_indexed: usize,
    pub total_upserted: usize,
    pub total_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileRequest {
    pub session_dir: PathBuf,
}

pub async fn reconcile_session_dir(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    #[cfg(test)]
    {
        let snapshot = crate::backend::open_kindb_snapshot(layout)
            .map_err(|error| anyhow::anyhow!("failed to open graph store: {error}"))?;
        reconcile_session_dir_with_snapshot(layout, session_dir, snapshot)
    }

    #[cfg(not(test))]
    {
        let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for reconcile"))?;
        let client =
            crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, layout)?;
        client
            .reconcile(&ReconcileRequest {
                session_dir: session_dir.to_path_buf(),
            })
            .await
            .map_err(|error| anyhow::anyhow!("daemon reconcile failed: {error}"))
    }
}

/// Reconcile through an endpoint and bearer token already verified for the
/// session repository. No ambient daemon/session authority is consulted.
pub(crate) async fn reconcile_session_dir_with_binding(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    #[cfg(test)]
    {
        let snapshot = crate::backend::open_kindb_snapshot(binding.layout())
            .map_err(|error| anyhow::anyhow!("failed to open graph store: {error}"))?;
        reconcile_session_dir_with_snapshot(binding.layout(), session_dir, snapshot)
    }

    #[cfg(not(test))]
    {
        binding
            .client(None)?
            .reconcile(&ReconcileRequest {
                session_dir: session_dir.to_path_buf(),
            })
            .await
            .map_err(|error| anyhow::anyhow!("daemon reconcile failed: {error}"))
    }
}

#[cfg(test)]
fn reconcile_session_dir_sync(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    let snapshot = crate::backend::open_kindb_snapshot(layout)
        .map_err(|error| anyhow::anyhow!("failed to open graph store: {error}"))?;
    reconcile_session_dir_with_snapshot(layout, session_dir, snapshot)
}

#[cfg(test)]
fn reconcile_session_dir_with_snapshot(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    snapshot: kin_db::SnapshotManager,
) -> Result<ReconcileSummary> {
    let graph = snapshot.graph();
    execute_reconcile_session_dir_with_persist(layout, graph.as_ref(), session_dir, || {
        snapshot
            .save()
            .map_err(|error| {
                anyhow::anyhow!("failed to persist reconciled graph snapshot: {error}")
            })
            .map(|_| ())
    })
}

pub fn execute_reconcile_session_dir(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    execute_reconcile_session_dir_with_persist(layout, graph, session_dir, || Ok(()))
}

pub fn execute_reconcile_session_dir_scoped(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    execute_reconcile_session_dir_inner(layout, graph, session_dir, || Ok(()), false)
}

pub fn execute_reconcile_session_dir_with_persist<F>(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    persist: F,
) -> Result<ReconcileSummary>
where
    F: FnOnce() -> Result<()>,
{
    execute_reconcile_session_dir_inner(layout, graph, session_dir, persist, true)
}

fn execute_reconcile_session_dir_inner<F>(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    persist: F,
    project_source: bool,
) -> Result<ReconcileSummary>
where
    F: FnOnce() -> Result<()>,
{
    ensure_session_dir_exists(session_dir)?;
    let base = super::session_base::load_base(session_dir)?;
    let base_tree = graph
        .resolve_tree_at(&base.base_head)
        .with_context(|| format!("resolve session base graph head {}", base.base_head))?;
    let mut observation = super::session_base::snapshot_dir(session_dir)?;

    // A Gitlink has no ordinary host-file materialization. Preserve it unless a
    // future explicit identity-bearing session command says otherwise.
    for artifact in base_tree.artifacts() {
        if matches!(artifact.entry, TreeEntry::Gitlink { .. })
            && !observation.contains_key(&artifact.path)
        {
            observation.insert(artifact.path.clone(), artifact.entry);
        }
    }

    let session_deltas = kin_core::plan_observed_tree_deltas(&base_tree, observation)
        .context("plan exact session observation")?;
    if session_deltas.is_empty() {
        return Ok(empty_summary());
    }

    let current_tree = graph.resolved_tree();
    let rebased = rebase_session_deltas(&current_tree, &session_deltas).with_context(|| {
        format!(
            "session reconcile conflict for {} (base graph head {}); graph truth was not changed",
            session_dir.display(),
            base.base_head
        )
    })?;
    if rebased.deltas.is_empty() {
        return Ok(empty_summary());
    }

    let blob_store =
        kin_blobs::BlobStore::new(layout.objects_dir()).context("open Kin object store")?;
    let prepared = prepare_target_entries(session_dir, &rebased.deltas, &blob_store)?;
    let semantic = prepare_semantic_transaction(
        graph,
        session_dir,
        &current_tree,
        &rebased.target,
        &rebased.deltas,
        &prepared,
        &blob_store,
    )?;
    let transaction = TransactionDelta {
        entity_deltas: semantic.entity_deltas,
        relation_deltas: semantic.relation_deltas,
        tree_deltas: rebased.deltas.clone(),
    };
    let inverse = inverse_transaction(graph, &transaction)?;
    let projection = projection_trees(&current_tree, &rebased.target, &rebased.deltas)?;
    let source = kin_core::source_dir(layout);

    if project_source {
        kin_projection::transition_resolved_tree(
            &source,
            &projection.previous,
            &projection.target,
            &blob_store,
        )
        .context("stage and publish reconciled working-copy projection")?;
    }

    if let Err(graph_error) = graph.apply_transaction_delta(&transaction) {
        let rollback = project_source.then(|| {
            kin_projection::transition_resolved_tree(
                &source,
                &projection.target,
                &projection.previous,
                &blob_store,
            )
        });
        return Err(command_failure(
            "exact reconcile graph transaction failed after projection",
            graph_error,
            rollback,
        ));
    }

    if let Err(persist_error) = persist() {
        let graph_rollback = graph.apply_transaction_delta(&inverse);
        let projection_rollback = project_source.then(|| {
            kin_projection::transition_resolved_tree(
                &source,
                &projection.target,
                &projection.previous,
                &blob_store,
            )
        });
        let graph_status = graph_rollback
            .map(|_| "graph rollback succeeded".to_string())
            .unwrap_or_else(|error| format!("graph rollback failed: {error}"));
        let projection_status = projection_rollback
            .map(|result| {
                result
                    .map(|_| "projection rollback succeeded".to_string())
                    .unwrap_or_else(|error| format!("projection rollback failed: {error}"))
            })
            .unwrap_or_else(|| "projection was not requested".to_string());
        anyhow::bail!("{persist_error}; {graph_status}; {projection_status}");
    }

    let changes = summarize_tree_deltas(&rebased.deltas);
    Ok(ReconcileSummary {
        change_count: changes.len(),
        changes,
        files_indexed: semantic.files_indexed,
        total_upserted: semantic.total_upserted,
        total_removed: semantic.total_removed,
    })
}

fn empty_summary() -> ReconcileSummary {
    ReconcileSummary {
        changes: Vec::new(),
        change_count: 0,
        files_indexed: 0,
        total_upserted: 0,
        total_removed: 0,
    }
}

struct RebasedTree {
    deltas: Vec<TreeDelta>,
    target: ResolvedTree,
}

/// Rebase the workspace's identity-bearing base transition onto current graph
/// truth. Identity preconditions detect concurrent edits; `ResolvedTree::apply`
/// validates all path swaps, cycles, and path reuse against one parent.
fn rebase_session_deltas(current: &ResolvedTree, session: &[TreeDelta]) -> Result<RebasedTree> {
    let mut rebased = Vec::new();
    let mut conflicts = Vec::new();

    for delta in session {
        match delta {
            TreeDelta::Added { artifact_id, new } => match current.get(artifact_id) {
                Some(existing) if existing.located_entry() == *new => {}
                Some(existing) => conflicts.push(format!(
                    "new session artifact {artifact_id:?} conflicts with current {}",
                    existing.path
                )),
                None => {
                    if current
                        .artifact_at_path(&new.path)
                        .is_some_and(|existing| existing.entry == new.entry)
                    {
                        // Both sides independently added the same exact bytes at
                        // the same path. Keep the already-published identity.
                        continue;
                    }
                    rebased.push(delta.clone());
                }
            },
            TreeDelta::Updated {
                artifact_id,
                old,
                new,
            } => match current.get(artifact_id) {
                Some(existing) if existing.located_entry() == *old => rebased.push(delta.clone()),
                Some(existing) if existing.located_entry() == *new => {}
                Some(existing) => conflicts.push(format!(
                    "artifact {artifact_id:?} changed concurrently (base {}, session {}, current {})",
                    old.path, new.path, existing.path
                )),
                None => conflicts.push(format!(
                    "artifact {artifact_id:?} at {} was removed while the session changed it",
                    old.path
                )),
            },
            TreeDelta::Removed { artifact_id, old } => match current.get(artifact_id) {
                Some(existing) if existing.located_entry() == *old => rebased.push(delta.clone()),
                None => {}
                Some(existing) => conflicts.push(format!(
                    "artifact {artifact_id:?} changed concurrently from {} to {} while the session removed it",
                    old.path, existing.path
                )),
            },
        }
    }

    if !conflicts.is_empty() {
        anyhow::bail!(conflicts.join("\n  "));
    }
    let target = current.apply(&rebased).map_err(|error| {
        anyhow::anyhow!(
            "session changes collide with current graph paths; no state was changed: {error}"
        )
    })?;
    Ok(RebasedTree {
        deltas: rebased,
        target,
    })
}

#[derive(Default)]
struct PreparedEntries {
    by_path: BTreeMap<RepoPath, Vec<u8>>,
}

fn prepare_target_entries(
    session_dir: &Path,
    deltas: &[TreeDelta],
    blobs: &kin_blobs::BlobStore,
) -> Result<PreparedEntries> {
    let mut prepared = PreparedEntries::default();
    for located in deltas.iter().filter_map(TreeDelta::new_state) {
        let Some(expected_hash) = located.entry.blob_identity() else {
            anyhow::bail!(
                "session reconcile cannot materialize Gitlink at {}; use an explicit graph-native Gitlink command",
                located.path
            );
        };
        let relative = repo_path_to_relative(&located.path)?;
        let host = session_dir.join(&relative);
        let (actual_entry, content) =
            super::session_base::read_disk_entry(&host)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "session entry disappeared during reconcile: {}",
                    located.path
                )
            })?;
        anyhow::ensure!(
            actual_entry == located.entry,
            "session entry changed after complete observation: {}",
            located.path
        );
        let stored = blobs
            .write(&content)
            .with_context(|| format!("store exact session blob for {}", located.path))?;
        anyhow::ensure!(
            stored.0 == expected_hash.0,
            "object-store identity mismatch while admitting {}",
            located.path
        );
        prepared.by_path.insert(located.path.clone(), content);
    }
    Ok(prepared)
}

struct SemanticPreparation {
    entity_deltas: Vec<EntityDelta>,
    relation_deltas: Vec<RelationDelta>,
    files_indexed: usize,
    total_upserted: usize,
    total_removed: usize,
}

fn prepare_semantic_transaction(
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    current: &ResolvedTree,
    target: &ResolvedTree,
    tree_deltas: &[TreeDelta],
    prepared: &PreparedEntries,
    blobs: &kin_blobs::BlobStore,
) -> Result<SemanticPreparation> {
    let before = semantic_snapshot(graph)?;
    let mut overlay = GraphOverlay::default();
    let mut reconciler = Reconciler::new(session_dir.to_path_buf());
    reconciler.seed_lkg_from_graph(graph);
    let mut affected_paths = BTreeSet::new();
    for delta in tree_deltas {
        affected_paths.extend(delta.old_state().map(|entry| entry.path.clone()));
        affected_paths.extend(delta.new_state().map(|entry| entry.path.clone()));
    }

    let mut files_indexed = 0usize;
    let mut total_upserted = 0usize;
    let mut total_removed = 0usize;
    for path in affected_paths {
        let utf8 = path.as_utf8();
        let target_artifact = target.artifact_at_path(&path);
        let target_content = prepared.by_path.get(&path);
        let entity_source = match (utf8, target_artifact, target_content) {
            (Some(path), Some(artifact), Some(content))
                if !matches!(artifact.entry, TreeEntry::Symlink { .. }) =>
            {
                matches!(
                    FileClassifier::classify_with_content(Path::new(path), content),
                    FileClassification::EntitySource
                )
            }
            _ => false,
        };

        if entity_source {
            let path_text = utf8.expect("entity source path was UTF-8");
            let event = FileEvent::Changed(session_dir.join(path_text));
            match reconciler.reconcile_file_change(&event, blobs, graph, &mut overlay) {
                Ok(ReconcileOutcome::Updated {
                    added,
                    modified,
                    removed,
                    ..
                }) => {
                    files_indexed += 1;
                    total_upserted += added.len() + modified.len();
                    total_removed += removed.len();
                }
                Ok(ReconcileOutcome::BrokenAst { file_id, .. }) => {
                    eprintln!(
                        "  Note: {file_id} has incomplete syntax; exact bytes were admitted and semantic LKG was retained"
                    );
                }
                Ok(ReconcileOutcome::Conflict(conflict)) => {
                    eprintln!(
                        "  Note: {} has a semantic conflict ({:?}); exact bytes remain authoritative",
                        path, conflict.kind
                    );
                }
                Ok(ReconcileOutcome::FileRemoved { .. }) => {
                    eprintln!(
                        "  Note: semantic enrichment observed {} as removed; exact admission remains authoritative",
                        path
                    );
                }
                Err(error) => {
                    eprintln!(
                        "  Note: {} could not be semantically enriched ({}); exact repository truth remains authoritative",
                        path, error
                    );
                }
            }
        } else if let Some(path_text) = utf8 {
            let file_id = FilePathId::new(path_text.to_string());
            let entities = graph.query_entities(&EntityFilter {
                file_path: Some(file_id),
                ..Default::default()
            })?;
            total_removed += entities.len();
            overlay
                .entity_removes
                .extend(entities.into_iter().map(|entity| entity.id));
        }
    }

    // If an artifact moved away from a UTF-8 path that is not otherwise in the
    // target affected set, the loop above already removes its semantic facets.
    // `current` is intentionally retained in this signature as an assertion
    // that semantic preparation was based on the same exact parent.
    debug_assert!(tree_deltas
        .iter()
        .all(|delta| delta.old_state().is_none_or(|old| current
            .get(&delta.artifact_id())
            .is_some_and(|artifact| artifact.located_entry() == *old))));

    let (entity_deltas, relation_deltas) = overlay_transaction(&before, overlay);
    Ok(SemanticPreparation {
        entity_deltas,
        relation_deltas,
        files_indexed,
        total_upserted,
        total_removed,
    })
}

struct SemanticSnapshot {
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
}

fn semantic_snapshot(graph: &kin_db::InMemoryGraph) -> Result<SemanticSnapshot> {
    let entities = graph
        .list_all_entities()?
        .into_iter()
        .map(|entity| (entity.id, entity))
        .collect::<HashMap<_, _>>();
    let mut relations = HashMap::new();
    for entity_id in entities.keys() {
        for relation in graph.get_all_relations_for_entity(entity_id)? {
            relations.insert(relation.id, relation);
        }
    }
    Ok(SemanticSnapshot {
        entities,
        relations,
    })
}

fn overlay_transaction(
    before: &SemanticSnapshot,
    overlay: GraphOverlay,
) -> (Vec<EntityDelta>, Vec<RelationDelta>) {
    let removed_entities = overlay.entity_removes.into_iter().collect::<HashSet<_>>();
    let mut updates = overlay.entity_adds;
    updates.extend(overlay.entity_mods);
    let mut entity_deltas = updates
        .into_iter()
        .filter(|(id, _)| !removed_entities.contains(id))
        .map(|(id, new)| match before.entities.get(&id) {
            Some(old) => EntityDelta::Modified {
                old: old.clone(),
                new,
            },
            None => EntityDelta::Added(new),
        })
        .collect::<Vec<_>>();
    entity_deltas.extend(
        removed_entities
            .into_iter()
            .filter(|id| before.entities.contains_key(id))
            .map(EntityDelta::Removed),
    );

    let removed_relations = overlay.relation_removes.into_iter().collect::<HashSet<_>>();
    let mut relation_deltas = overlay
        .relation_adds
        .into_iter()
        .filter(|(id, _)| !removed_relations.contains(id))
        .map(|(_, relation)| RelationDelta::Added(relation))
        .collect::<Vec<_>>();
    relation_deltas.extend(
        removed_relations
            .into_iter()
            .filter(|id| before.relations.contains_key(id))
            .map(RelationDelta::Removed),
    );
    (entity_deltas, relation_deltas)
}

fn inverse_transaction(
    graph: &kin_db::InMemoryGraph,
    transaction: &TransactionDelta,
) -> Result<TransactionDelta> {
    let before = semantic_snapshot(graph)?;
    let mut entity_deltas = Vec::new();
    let mut relation_restore = HashMap::new();
    let mut relation_remove = HashSet::new();

    for delta in transaction.entity_deltas.iter().rev() {
        match delta {
            EntityDelta::Added(entity) => entity_deltas.push(EntityDelta::Removed(entity.id)),
            EntityDelta::Modified { old, new } => entity_deltas.push(EntityDelta::Modified {
                old: new.clone(),
                new: old.clone(),
            }),
            EntityDelta::Removed(id) => {
                if let Some(entity) = before.entities.get(id) {
                    entity_deltas.push(EntityDelta::Added(entity.clone()));
                }
                for relation in before
                    .relations
                    .values()
                    .filter(|relation| relation_mentions_entity(relation, *id))
                {
                    relation_restore.insert(relation.id, relation.clone());
                }
            }
        }
    }
    for delta in transaction.relation_deltas.iter().rev() {
        match delta {
            RelationDelta::Added(relation) => {
                if let Some(old) = before.relations.get(&relation.id) {
                    relation_restore.insert(old.id, old.clone());
                } else {
                    relation_remove.insert(relation.id);
                }
            }
            RelationDelta::Removed(id) => {
                if let Some(old) = before.relations.get(id) {
                    relation_restore.insert(*id, old.clone());
                }
            }
        }
    }
    for id in relation_restore.keys() {
        relation_remove.remove(id);
    }
    let mut relation_deltas = relation_remove
        .into_iter()
        .map(RelationDelta::Removed)
        .collect::<Vec<_>>();
    relation_deltas.extend(relation_restore.into_values().map(RelationDelta::Added));
    let tree_deltas = transaction
        .tree_deltas
        .iter()
        .rev()
        .map(|delta| match delta {
            TreeDelta::Added { artifact_id, new } => TreeDelta::Removed {
                artifact_id: *artifact_id,
                old: new.clone(),
            },
            TreeDelta::Updated {
                artifact_id,
                old,
                new,
            } => TreeDelta::Updated {
                artifact_id: *artifact_id,
                old: new.clone(),
                new: old.clone(),
            },
            TreeDelta::Removed { artifact_id, old } => TreeDelta::Added {
                artifact_id: *artifact_id,
                new: old.clone(),
            },
        })
        .collect();
    Ok(TransactionDelta {
        entity_deltas,
        relation_deltas,
        tree_deltas,
    })
}

fn relation_mentions_entity(relation: &Relation, id: EntityId) -> bool {
    relation.src == GraphNodeId::Entity(id) || relation.dst == GraphNodeId::Entity(id)
}

struct ProjectionTrees {
    previous: ResolvedTree,
    target: ResolvedTree,
}

fn projection_trees(
    current: &ResolvedTree,
    target: &ResolvedTree,
    deltas: &[TreeDelta],
) -> Result<ProjectionTrees> {
    let ids = deltas
        .iter()
        .map(TreeDelta::artifact_id)
        .collect::<BTreeSet<_>>();
    let previous = ResolvedTree::from_artifacts(
        ids.iter()
            .filter_map(|id| current.get(id).cloned())
            .collect::<Vec<ResolvedArtifact>>(),
    )
    .context("build reconcile projection parent")?;
    let target = ResolvedTree::from_artifacts(
        ids.iter()
            .filter_map(|id| target.get(id).cloned())
            .collect::<Vec<ResolvedArtifact>>(),
    )
    .context("build reconcile projection target")?;
    Ok(ProjectionTrees { previous, target })
}

fn command_failure<E: std::fmt::Display>(
    context: &str,
    error: E,
    rollback: Option<Result<kin_projection::TreeProjectionReport, kin_projection::ProjectionError>>,
) -> anyhow::Error {
    let rollback = rollback
        .map(|result| {
            result
                .map(|_| "projection rollback succeeded".to_string())
                .unwrap_or_else(|error| format!("projection rollback failed: {error}"))
        })
        .unwrap_or_else(|| "projection was not requested".to_string());
    anyhow::anyhow!("{context}: {error}; {rollback}")
}

fn summarize_tree_deltas(deltas: &[TreeDelta]) -> Vec<(String, String)> {
    deltas
        .iter()
        .map(|delta| match delta {
            TreeDelta::Added { new, .. } => ("added".to_string(), new.path.to_string()),
            TreeDelta::Updated { old, new, .. } if old.path == new.path => {
                ("modified".to_string(), new.path.to_string())
            }
            TreeDelta::Updated { old, new, .. } => {
                ("moved".to_string(), format!("{} -> {}", old.path, new.path))
            }
            TreeDelta::Removed { old, .. } => ("deleted".to_string(), old.path.to_string()),
        })
        .collect()
}

fn repo_path_to_relative(path: &RepoPath) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(OsStr::from_bytes(path.as_bytes())))
    }
    #[cfg(not(unix))]
    {
        path.as_utf8().map(PathBuf::from).ok_or_else(|| {
            anyhow::anyhow!("repository path is not representable on this host: {path}")
        })
    }
}

fn ensure_session_dir_exists(session_dir: &Path) -> Result<()> {
    if session_dir.exists() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "session workspace not found: {}",
        session_dir.display()
    ))
}

/// Find the session directory, either by explicit ID or the most recent.
fn resolve_session_dir(
    layout: &kin_core::KinLayout,
    session_id: Option<String>,
) -> Result<PathBuf> {
    let runs_dir = layout.root().join("runs");
    if let Some(id) = session_id {
        let with_prefix = runs_dir.join(format!("session-{id}"));
        if with_prefix.exists() {
            return Ok(with_prefix);
        }
        let bare = runs_dir.join(&id);
        if bare.exists() {
            return Ok(bare);
        }
        anyhow::bail!("session '{id}' not found in {}", runs_dir.display());
    }
    if !runs_dir.exists() {
        anyhow::bail!("no session workspaces found");
    }
    let mut sessions = std::fs::read_dir(&runs_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("session-"))
        .collect::<Vec<_>>();
    if sessions.is_empty() {
        anyhow::bail!("no session workspaces found");
    }
    sessions.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });
    Ok(sessions.last().expect("sessions is non-empty").path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactId, Hash256, LocatedEntry, ResolvedArtifact};
    use tempfile::tempdir;

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn entry(byte: u8, executable: bool) -> TreeEntry {
        TreeEntry::blob(Hash256::from_bytes([byte; 32]), executable)
    }

    fn tree(entries: Vec<(ArtifactId, &str, TreeEntry)>) -> ResolvedTree {
        ResolvedTree::from_artifacts(
            entries
                .into_iter()
                .map(|(id, path_value, entry)| ResolvedArtifact::new(id, path(path_value), entry)),
        )
        .unwrap()
    }

    #[test]
    fn rebase_preserves_disjoint_current_graph_changes() {
        let edited_id = ArtifactId::new();
        let concurrent_id = ArtifactId::new();
        let old = entry(1, false);
        let updated = entry(2, false);
        let concurrent = entry(3, false);
        let base = tree(vec![(edited_id, "src/lib.rs", old)]);
        let session = base
            .apply(&[TreeDelta::Updated {
                artifact_id: edited_id,
                old: LocatedEntry::new(path("src/lib.rs"), old),
                new: LocatedEntry::new(path("src/lib.rs"), updated),
            }])
            .unwrap();
        let session_deltas = kin_core::exact_tree_correction(&base, &session).unwrap();
        let current = tree(vec![
            (edited_id, "src/lib.rs", old),
            (concurrent_id, "compose.yaml", concurrent),
        ]);

        let rebased = rebase_session_deltas(&current, &session_deltas).unwrap();
        assert_eq!(
            rebased.target.get(&concurrent_id).unwrap().entry,
            concurrent
        );
        assert_eq!(rebased.target.get(&edited_id).unwrap().entry, updated);
    }

    #[test]
    fn rebase_fails_before_mutation_on_same_identity_conflict() {
        let id = ArtifactId::new();
        let old = entry(1, false);
        let session_new = entry(2, false);
        let current_new = entry(3, false);
        let current = tree(vec![(id, "src/lib.rs", current_new)]);
        let error = rebase_session_deltas(
            &current,
            &[TreeDelta::Updated {
                artifact_id: id,
                old: LocatedEntry::new(path("src/lib.rs"), old),
                new: LocatedEntry::new(path("src/lib.rs"), session_new),
            }],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("changed concurrently"));
        assert_eq!(current.get(&id).unwrap().entry, current_new);
    }

    #[test]
    fn rebase_applies_identity_move_and_path_reuse_atomically() {
        let moved_id = ArtifactId::new();
        let replacement_id = ArtifactId::new();
        let moved = entry(1, false);
        let replacement = entry(2, true);
        let current = tree(vec![(moved_id, "compose.yaml", moved)]);
        let deltas = vec![
            TreeDelta::Updated {
                artifact_id: moved_id,
                old: LocatedEntry::new(path("compose.yaml"), moved),
                new: LocatedEntry::new(path("deploy/compose.yaml"), moved),
            },
            TreeDelta::Added {
                artifact_id: replacement_id,
                new: LocatedEntry::new(path("compose.yaml"), replacement),
            },
        ];
        let rebased = rebase_session_deltas(&current, &deltas).unwrap();
        assert_eq!(
            rebased
                .target
                .artifact_at_path(&path("deploy/compose.yaml"))
                .unwrap()
                .artifact_id,
            moved_id
        );
        assert_eq!(
            rebased
                .target
                .artifact_at_path(&path("compose.yaml"))
                .unwrap()
                .artifact_id,
            replacement_id
        );
    }

    fn genesis_head(
        layout: &kin_core::KinLayout,
        graph: &kin_db::InMemoryGraph,
    ) -> kin_model::SemanticChangeId {
        let branch = kin_core::read_current_branch(layout).unwrap();
        graph.get_branch(&branch).unwrap().unwrap().head
    }

    #[test]
    fn reconcile_admits_compose_binary_and_unsupported_extension_exactly() {
        let repository = tempdir().unwrap();
        let layout = kin_core::init(repository.path()).unwrap().layout;
        let snapshot = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snapshot.graph();
        let session = layout.root().join("runs/session-heterogeneous");
        std::fs::create_dir_all(session.join("assets")).unwrap();
        std::fs::write(session.join("compose.yaml"), b"services:\n  app: {}\n").unwrap();
        std::fs::write(session.join("assets/model.bin"), [0, 1, 2, 255]).unwrap();
        std::fs::write(
            session.join("README.unsupported"),
            b"still repository truth\n",
        )
        .unwrap();
        super::super::session_base::record_materialized_base(
            &session,
            genesis_head(&layout, graph.as_ref()),
        )
        .unwrap();

        let summary = reconcile_session_dir_sync(&layout, &session).unwrap();
        assert_eq!(summary.change_count, 3);
        let reopened = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let exact = reopened.graph().resolved_tree();
        for expected in ["compose.yaml", "assets/model.bin", "README.unsupported"] {
            assert!(
                exact.artifact_at_path(&path(expected)).is_some(),
                "{expected} missing from exact graph tree"
            );
            assert!(repository.path().join(expected).exists());
        }
    }

    #[test]
    fn persist_failure_reverses_exact_graph_and_projection() {
        let repository = tempdir().unwrap();
        let layout = kin_core::init(repository.path()).unwrap().layout;
        let snapshot = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snapshot.graph();
        let session = layout.root().join("runs/session-rollback");
        std::fs::create_dir_all(&session).unwrap();
        std::fs::write(session.join("compose.yaml"), b"services: {}\n").unwrap();
        super::super::session_base::record_materialized_base(
            &session,
            genesis_head(&layout, graph.as_ref()),
        )
        .unwrap();

        let error =
            execute_reconcile_session_dir_with_persist(&layout, graph.as_ref(), &session, || {
                anyhow::bail!("injected snapshot failure")
            })
            .unwrap_err()
            .to_string();
        assert!(error.contains("injected snapshot failure"));
        assert!(graph.resolved_tree().is_empty());
        assert!(!repository.path().join("compose.yaml").exists());
    }
}
