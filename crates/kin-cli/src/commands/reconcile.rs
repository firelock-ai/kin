// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use anyhow::Result;
use kin_index::{FileClassification, FileClassifier, FileEvent, IndexPipeline, IndexedAny};
use kin_model::{
    EntityFilter, EntityStore, FilePathId, GraphOverlay, ShallowTrackedFile, TreeEntry,
    TreeEntryKind,
};
use kin_reconcile::{apply_overlay_to_graph, ReconcileOutcome, Reconciler};
use serde::{Deserialize, Serialize};

/// `kin reconcile [session-id] [--cleanup]` — Detect changes in a session workspace and update the graph.
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
        "\nReconciliation complete: {} files indexed, {} entities upserted, {} entities removed.",
        summary.files_indexed, summary.total_upserted, summary.total_removed
    );

    if cleanup {
        std::fs::remove_dir_all(&session_dir).map_err(|e| {
            anyhow::anyhow!(
                "reconciled successfully, but failed to clean up {}: {}",
                session_dir.display(),
                e
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
        let snap = crate::backend::open_kindb_snapshot(layout)
            .map_err(|e| anyhow::anyhow!("failed to open graph store: {}", e))?;
        reconcile_session_dir_with_snapshot(layout, session_dir, snap)
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
            .map_err(|e| anyhow::anyhow!("daemon reconcile failed: {}", e))
    }
}

/// Reconcile through the endpoint and bearer token already verified for the
/// session's repository. This path deliberately carries no ambient
/// `KIN_DAEMON_URL` or `KIN_SESSION_ID` authority.
pub(crate) async fn reconcile_session_dir_with_binding(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    #[cfg(test)]
    {
        let snap = crate::backend::open_kindb_snapshot(binding.layout())
            .map_err(|e| anyhow::anyhow!("failed to open graph store: {}", e))?;
        reconcile_session_dir_with_snapshot(binding.layout(), session_dir, snap)
    }

    #[cfg(not(test))]
    {
        binding
            .client(None)?
            .reconcile(&ReconcileRequest {
                session_dir: session_dir.to_path_buf(),
            })
            .await
            .map_err(|e| anyhow::anyhow!("daemon reconcile failed: {}", e))
    }
}

/// Test-only sync variant that opens the snapshot directly (no daemon).
#[cfg(test)]
fn reconcile_session_dir_sync(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
) -> Result<ReconcileSummary> {
    let snap = crate::backend::open_kindb_snapshot(layout)
        .map_err(|e| anyhow::anyhow!("failed to open graph store: {}", e))?;
    reconcile_session_dir_with_snapshot(layout, session_dir, snap)
}

#[cfg(test)]
fn reconcile_session_dir_with_snapshot(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    snap: kin_db::SnapshotManager,
) -> Result<ReconcileSummary> {
    let graph = snap.graph();
    execute_reconcile_session_dir_with_persist(layout, graph.as_ref(), session_dir, || {
        snap.save()
            .map_err(|e| anyhow::anyhow!("failed to persist reconciled graph snapshot: {}", e))
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
    let source = kin_core::source_dir(layout);
    ensure_session_dir_exists(session_dir)?;

    println!("Reconciling session workspace: {}", session_dir.display());
    if project_source {
        println!("Projecting graph authority to: {}", source.display());
    }

    let changes = plan_reconcile_changes(session_dir, &source)?;
    if changes.is_empty() {
        return Ok(ReconcileSummary {
            changes: Vec::new(),
            change_count: 0,
            files_indexed: 0,
            total_upserted: 0,
            total_removed: 0,
        });
    }

    let prepared = changes
        .iter()
        .map(|change| prepare_change(session_dir, &source, change))
        .collect::<Result<Vec<_>>>()?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|error| anyhow::anyhow!("failed to open blob store: {}", error))?;
    let pipeline = IndexPipeline::new();
    let mut reconciler = Reconciler::new(session_dir.to_path_buf());
    reconciler.seed_lkg_from_graph(graph);
    let mut overlay = GraphOverlay::default();
    let mut total_upserted = 0usize;
    let mut total_removed = 0usize;
    let mut files_indexed = 0usize;

    for change in &prepared {
        match &change.after {
            Some(after) => {
                let written_hash = blob_store.write(&after.content).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to persist graph blob for {}: {}",
                        change.file_id,
                        error
                    )
                })?;
                if written_hash.0 != *after.entry.blob_hash.as_bytes() {
                    anyhow::bail!(
                        "session entry hash changed during admission for {}",
                        change.file_id
                    );
                }
                if after.entry.kind == TreeEntryKind::Symlink {
                    total_removed += clear_all_enrichment(graph, &change.file_id)?;
                } else {
                    match FileClassifier::classify_with_content(
                        Path::new(&change.file_id.0),
                        &after.content,
                    ) {
                        FileClassification::EntitySource => {
                            clear_non_entity_enrichment(graph, &change.file_id)?;
                            let event = FileEvent::Changed(session_dir.join(&change.relative_path));
                            match reconciler.reconcile_file_change(
                                &event,
                                &blob_store,
                                graph,
                                &mut overlay,
                            ) {
                                Ok(ReconcileOutcome::Updated {
                                    added,
                                    modified,
                                    removed,
                                    file_id,
                                    ..
                                }) => {
                                    total_upserted += added.len() + modified.len();
                                    total_removed += removed.len();
                                    files_indexed += 1;
                                    if let Some(layout) =
                                        reconciler.projection().get_layout(&file_id)
                                    {
                                        graph.upsert_file_layout(layout)?;
                                    }
                                }
                                Ok(ReconcileOutcome::BrokenAst { file_id, .. }) => {
                                    eprintln!(
                                        "  Note: {} has incomplete syntax; exact bytes were admitted and semantic LKG was retained",
                                        file_id
                                    );
                                }
                                Ok(ReconcileOutcome::Conflict(conflict)) => {
                                    eprintln!(
                                        "  Note: {} has a semantic conflict ({:?}); exact bytes were admitted and semantic LKG was retained",
                                        change.file_id, conflict.kind
                                    );
                                }
                                Ok(ReconcileOutcome::FileRemoved { .. }) => {
                                    eprintln!(
                                        "  Note: {} disappeared from semantic enrichment; exact admission will revalidate it",
                                        change.file_id
                                    );
                                }
                                Err(error) => {
                                    eprintln!(
                                        "  Note: {} could not be semantically enriched ({}); exact repository truth was still admitted",
                                        change.file_id, error
                                    );
                                }
                            }
                        }
                        _ => {
                            let indexed = pipeline
                                .index_any_content(&change.file_id, &after.content, written_hash)
                                .map_err(|error| {
                                    anyhow::anyhow!(
                                        "failed to enrich exact repository entry {}: {}",
                                        change.file_id,
                                        error
                                    )
                                })?;
                            total_removed += clear_all_enrichment(graph, &change.file_id)?;
                            persist_non_entity_enrichment(graph, indexed)?;
                            files_indexed += 1;
                        }
                    }
                }

                let current =
                    super::session_base::read_disk_entry(&session_dir.join(&change.relative_path))?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "session entry disappeared during reconcile: {}",
                                change.relative_path.display()
                            )
                        })?;
                if current.0 != after.entry {
                    anyhow::bail!(
                        "session entry changed during reconcile: {}",
                        change.relative_path.display()
                    );
                }
                // Enrichment deletion may remove the last facet-backed artifact
                // index entry. Exact tree authority always retains identity.
                graph.ensure_artifact_id(&change.file_id);
                graph.set_working_tree_entry(&change.file_id.0, after.entry);
            }
            None => {
                total_removed += clear_all_enrichment(graph, &change.file_id)?;
                graph.remove_working_tree_entry(&change.file_id.0);
            }
        }
    }

    apply_overlay_to_graph(graph, &mut overlay)
        .map_err(|error| anyhow::anyhow!("failed to apply reconciled overlay: {}", error))?;
    persist()?;

    if project_source {
        let previous_entries: Vec<_> = prepared
            .iter()
            .filter_map(|change| {
                change
                    .before
                    .as_ref()
                    .map(|entry| (&change.file_id, entry.entry.kind, entry.content.as_slice()))
            })
            .collect();
        let target_entries: Vec<_> = prepared
            .iter()
            .filter_map(|change| {
                change
                    .after
                    .as_ref()
                    .map(|entry| (&change.file_id, entry.entry.kind, entry.content.as_slice()))
            })
            .collect();
        kin_core::reconcile_source_tree(
            &source,
            previous_entries,
            target_entries,
            kin_core::should_preserve_checkout_path,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "graph authority was persisted, but its filesystem projection failed: {}",
                error
            )
        })?;
    }

    let change_summaries = changes
        .iter()
        .map(|change| {
            (
                match change.kind {
                    ChangeKind::Modified => "modified",
                    ChangeKind::Added => "added",
                    ChangeKind::Deleted => "deleted",
                }
                .to_string(),
                change.relative_path.display().to_string(),
            )
        })
        .collect();
    Ok(ReconcileSummary {
        changes: change_summaries,
        change_count: changes.len(),
        files_indexed,
        total_upserted,
        total_removed,
    })
}

#[derive(Debug)]
struct PreparedTreeEntry {
    entry: TreeEntry,
    content: Vec<u8>,
}

#[derive(Debug)]
struct PreparedChange {
    relative_path: PathBuf,
    file_id: FilePathId,
    before: Option<PreparedTreeEntry>,
    after: Option<PreparedTreeEntry>,
}

fn prepare_change(
    session_dir: &Path,
    source: &Path,
    change: &FileChange,
) -> Result<PreparedChange> {
    let session_path = session_dir.join(&change.relative_path);
    let source_path = source.join(&change.relative_path);
    let after = super::session_base::read_disk_entry(&session_path)?
        .map(|(entry, content)| PreparedTreeEntry { entry, content });
    let before = super::session_base::read_disk_entry(&source_path)?
        .map(|(entry, content)| PreparedTreeEntry { entry, content });

    if after.as_ref().map(|entry| entry.entry) != change.workspace_entry {
        anyhow::bail!(
            "session entry changed after reconcile planning: {}",
            change.relative_path.display()
        );
    }
    if before.as_ref().map(|entry| entry.entry) != change.source_entry {
        anyhow::bail!(
            "source entry changed after reconcile planning: {}",
            change.relative_path.display()
        );
    }
    let file_id = FilePathId::new(
        change
            .relative_path
            .to_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "session path is not valid UTF-8: {}",
                    change.relative_path.display()
                )
            })?
            .replace(std::path::MAIN_SEPARATOR, "/"),
    );
    if let Some(after) = &after {
        kin_core::validate_source_entry(&file_id, after.entry.kind, &after.content)?;
    }
    Ok(PreparedChange {
        relative_path: change.relative_path.clone(),
        file_id,
        before,
        after,
    })
}

fn clear_non_entity_enrichment(graph: &kin_db::InMemoryGraph, file_id: &FilePathId) -> Result<()> {
    graph.delete_shallow_file(file_id)?;
    graph.delete_structured_artifact(file_id)?;
    graph.delete_opaque_artifact(file_id)?;
    Ok(())
}

fn clear_all_enrichment(graph: &kin_db::InMemoryGraph, file_id: &FilePathId) -> Result<usize> {
    let entities = graph.query_entities(&EntityFilter {
        file_path: Some(file_id.clone()),
        ..Default::default()
    })?;
    let entity_ids: Vec<_> = entities.into_iter().map(|entity| entity.id).collect();
    graph.remove_entities_batch(&entity_ids)?;
    graph.delete_file_layout(file_id)?;
    clear_non_entity_enrichment(graph, file_id)?;
    Ok(entity_ids.len())
}

fn persist_non_entity_enrichment(graph: &kin_db::InMemoryGraph, indexed: IndexedAny) -> Result<()> {
    match indexed {
        IndexedAny::EntitySource(_) => {
            anyhow::bail!("entity source reached non-entity session enrichment path")
        }
        IndexedAny::StructuredArtifact(artifact) => graph.upsert_structured_artifact(&artifact)?,
        IndexedAny::OpaqueArtifact(artifact) => graph.upsert_opaque_artifact(&artifact)?,
        IndexedAny::ShallowSyntax(shallow) => {
            let shallow = ShallowTrackedFile {
                file_id: shallow.file_id,
                language_hint: shallow.language_hint.unwrap_or_default(),
                declaration_count: shallow.declarations.len(),
                import_count: shallow.imports.len(),
                syntax_hash: shallow.fingerprint.syntax_hash,
                signature_hash: shallow.fingerprint.signature_hash,
                declaration_names: shallow
                    .declarations
                    .into_iter()
                    .map(|declaration| declaration.name)
                    .collect(),
                import_paths: shallow
                    .imports
                    .into_iter()
                    .map(|import| import.raw_path)
                    .collect(),
            };
            graph.upsert_shallow_file(&shallow)?;
        }
    }
    Ok(())
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

#[derive(Debug)]
struct FileChange {
    relative_path: PathBuf,
    kind: ChangeKind,
    workspace_entry: Option<TreeEntry>,
    source_entry: Option<TreeEntry>,
}

#[derive(Debug, Clone, Copy)]
enum ChangeKind {
    Modified,
    Added,
    Deleted,
}

/// Find the session directory, either by explicit ID or the most recent.
fn resolve_session_dir(
    layout: &kin_core::KinLayout,
    session_id: Option<String>,
) -> Result<PathBuf> {
    let runs_dir = layout.root().join("runs");

    if let Some(id) = session_id {
        // Try both with and without "session-" prefix
        let with_prefix = runs_dir.join(format!("session-{}", id));
        if with_prefix.exists() {
            return Ok(with_prefix);
        }
        let bare = runs_dir.join(&id);
        if bare.exists() {
            return Ok(bare);
        }
        return Err(anyhow::anyhow!(
            "session '{}' not found in {}",
            id,
            runs_dir.display()
        ));
    }

    // Find most recent session directory
    if !runs_dir.exists() {
        return Err(anyhow::anyhow!("no session workspaces found"));
    }

    let mut sessions: Vec<_> = std::fs::read_dir(&runs_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("session-"))
        .collect();

    if sessions.is_empty() {
        return Err(anyhow::anyhow!("no session workspaces found"));
    }

    // Sort by modification time (most recent last)
    sessions.sort_by_key(|e| {
        e.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    Ok(sessions.last().unwrap().path())
}

/// Compute the change-set to apply when reconciling a session workspace.
///
/// Reconcile replays only the workspace's own edits — the delta between the
/// base state captured when the workspace was materialized and the workspace's
/// current contents — instead of force-syncing the entire tree. Files the
/// workspace never touched are left untouched even when the source has advanced
/// past the base, so a workspace reconciled late never reverts intervening
/// source truth. When the workspace and the source both changed the same file,
/// the edits are merged when they agree and reported as a conflict when they do
/// not; the source is never silently overwritten with older content.
fn plan_reconcile_changes(session_dir: &Path, source: &Path) -> Result<Vec<FileChange>> {
    let base = super::session_base::load_base(session_dir)?;
    plan_from_base(session_dir, source, &base)
}

/// Change-set plan for a workspace with a recorded base: a file-level three-way
/// merge of base -> workspace against base -> source.
fn plan_from_base(
    session_dir: &Path,
    source: &Path,
    base: &super::session_base::SessionBase,
) -> Result<Vec<FileChange>> {
    let workspace_state = super::session_base::snapshot_dir(session_dir)?;
    let source_state = super::session_base::snapshot_dir(source)?;
    let base_state = &base.tree;

    let mut candidate_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    candidate_paths.extend(base_state.keys().cloned());
    candidate_paths.extend(workspace_state.keys().cloned());

    let mut changes = Vec::new();
    let mut conflicts = Vec::new();

    for path in candidate_paths {
        let base_entry = base_state.get(&path);
        let workspace_entry = workspace_state.get(&path);
        if base_entry == workspace_entry {
            // The workspace never changed this path; leave it untouched even if
            // the source advanced it. This is the change-set guarantee.
            continue;
        }

        let source_entry = source_state.get(&path);
        if source_entry != base_entry {
            // Both the workspace and the source moved this path off the base.
            if workspace_entry == source_entry {
                // They converged to identical content — nothing to apply.
                continue;
            }
            conflicts.push(describe_reconcile_conflict(
                &path,
                base_entry,
                workspace_entry,
                source_entry,
            ));
            continue;
        }

        // Disjoint edit: the source is still at the base here, so the
        // workspace's own change applies cleanly.
        let kind = match (base_entry.is_some(), workspace_entry.is_some()) {
            (false, true) => ChangeKind::Added,
            (true, true) => ChangeKind::Modified,
            (true, false) => ChangeKind::Deleted,
            // Unreachable: base_hash != workspace_hash is guaranteed above.
            (false, false) => continue,
        };
        changes.push(FileChange {
            relative_path: PathBuf::from(path),
            kind,
            workspace_entry: workspace_entry.copied(),
            source_entry: source_entry.copied(),
        });
    }

    if !conflicts.is_empty() {
        let base_head = &base.base_head;
        anyhow::bail!(
            "session reconcile conflict for {}: {} file(s) changed both in the session workspace \
             and in the source since it was materialized (base graph head {base_head}). Kin will \
             not overwrite newer source truth. Resolve the workspace by hand or discard it. \
             Conflicting files:\n  {}",
            session_dir.display(),
            conflicts.len(),
            conflicts.join("\n  "),
        );
    }

    Ok(changes)
}

/// Human-readable description of how a file diverged in both the workspace and
/// the source, for conflict reporting.
fn describe_reconcile_conflict(
    path: &str,
    base: Option<&TreeEntry>,
    workspace: Option<&TreeEntry>,
    source: Option<&TreeEntry>,
) -> String {
    let workspace_action = match (base.is_some(), workspace.is_some()) {
        (false, true) => "added in session",
        (true, true) => "modified in session",
        (true, false) => "deleted in session",
        (false, false) => "unchanged in session",
    };
    let source_action = match (base.is_some(), source.is_some()) {
        (false, true) => "added in source",
        (true, true) => "modified in source",
        (true, false) => "deleted in source",
        (false, false) => "unchanged in source",
    };
    format!("{path} ({workspace_action}; {source_action})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Record a base manifest for a hand-built session workspace, modeling the
    /// base a real materialization captures: a snapshot of the source tree at
    /// the moment the workspace was materialized. With the source unchanged
    /// afterward, the change-set plan reduces to the workspace's own edits.
    fn record_base_from_source(layout: &kin_core::KinLayout, session_dir: &Path) {
        let tree =
            crate::commands::session_base::snapshot_dir(&kin_core::source_dir(layout)).unwrap();
        crate::commands::session_base::write_base(
            session_dir,
            &crate::commands::session_base::SessionBase {
                base_head: kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes(
                    [0x42; 32],
                )),
                tree,
            },
        )
        .unwrap();
    }

    #[test]
    fn reconcile_session_dir_persists_snapshot_backed_changes() {
        let repo = tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-persist");

        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(
            session_dir.join("src/lib.rs"),
            "pub fn persisted_reconcile() -> &'static str { \"ok\" }\n",
        )
        .unwrap();
        record_base_from_source(&layout, &session_dir);

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();
        assert_eq!(summary.files_indexed, 1);
        assert!(summary.total_upserted > 0);

        let reopened = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = reopened.graph();
        assert!(graph.entity_count() > 0);
    }

    #[test]
    fn reconcile_session_dir_admits_broken_source_and_retains_semantic_lkg() {
        let repo = tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-broken-source");
        let source_file = repo.path().join("src/lib.rs");
        let original = "pub fn stable_source() -> &'static str { \"ok\" }\n";

        fs::create_dir_all(source_file.parent().unwrap()).unwrap();
        fs::write(&source_file, original).unwrap();
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/lib.rs"), "pub fn stable_source( {\n").unwrap();
        record_base_from_source(&layout, &session_dir);

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();
        assert_eq!(summary.change_count, 1);
        assert_eq!(
            fs::read_to_string(&source_file).unwrap(),
            "pub fn stable_source( {\n"
        );

        let reopened = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let entry = reopened
            .graph()
            .get_working_tree_entry("src/lib.rs")
            .expect("broken source remains exact repository truth");
        assert_eq!(
            entry.blob_hash,
            kin_blobs::digest(b"pub fn stable_source( {\n")
        );
    }

    #[test]
    fn reconcile_session_dir_restores_source_tree_when_snapshot_persist_fails() {
        let repo = tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-save-fail");
        let source_file = repo.path().join("src/lib.rs");
        let original = "pub fn persisted_before_failure() -> &'static str { \"before\" }\n";
        let updated = "pub fn persisted_before_failure() -> &'static str { \"after\" }\n";

        fs::create_dir_all(source_file.parent().unwrap()).unwrap();
        fs::write(&source_file, original).unwrap();
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/lib.rs"), updated).unwrap();
        record_base_from_source(&layout, &session_dir);

        // Block the next immutable snapshot base's atomic-write tmp path. The
        // canonical graph.kndb file is now only a compatibility projection, so
        // blocking its tmp would happen after committed authority and would no
        // longer make persistence fail.
        let snapshot_path = crate::backend::kindb_snapshot_path(&layout);
        let generation = kin_db::SnapshotManager::open_read_only(&snapshot_path)
            .unwrap()
            .generation();
        let mut versions_name = snapshot_path.into_os_string();
        versions_name.push(".snapshots");
        let versioned_path =
            std::path::PathBuf::from(versions_name).join(format!("{:020}.kndb", generation + 1));
        let mut blocked_tmp_name = versioned_path.into_os_string();
        blocked_tmp_name.push(".tmp");
        let blocked_tmp_path = std::path::PathBuf::from(blocked_tmp_name);
        fs::create_dir_all(&blocked_tmp_path).unwrap();

        let err = reconcile_session_dir_sync(&layout, &session_dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to persist reconciled graph snapshot"));
        assert_eq!(fs::read_to_string(&source_file).unwrap(), original);
    }

    // --- change-set reconcile tests ---

    const A_V1: &str = "pub fn a() -> u8 { 1 }\n";
    const A_V2: &str = "pub fn a() -> u8 { 2 }\n";
    const A_V3: &str = "pub fn a() -> u8 { 3 }\n";

    /// Fast path: with the source still at the base, the workspace's own edit
    /// applies exactly as before — behavior is unchanged for the common case.
    #[test]
    fn change_set_fast_path_applies_workspace_edit() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();

        let session_dir = layout.root().join("runs/session-fast-path");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V2).unwrap();
        record_base_from_source(&layout, &session_dir);

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();

        assert_eq!(summary.change_count, 1);
        assert!(summary
            .changes
            .contains(&("modified".into(), "src/a.rs".into())));
        assert_eq!(fs::read_to_string(source.join("src/a.rs")).unwrap(), A_V2);
    }

    /// Regression for the session-workspace data-loss edge: a file created in
    /// the source after the workspace was materialized must survive a late
    /// reconcile, never be deleted as "absent from the workspace".
    #[test]
    fn change_set_preserves_source_file_added_after_materialization() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        // Base state: the source has only a.rs.
        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();

        // Materialize + edit a.rs in the workspace.
        let session_dir = layout.root().join("runs/session-late-add");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V2).unwrap();
        record_base_from_source(&layout, &session_dir);

        // The source advances after materialization: a new file appears.
        let new_source_file = "pub fn b() -> u8 { 9 }\n";
        fs::write(source.join("src/b.rs"), new_source_file).unwrap();

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();

        // The workspace's own edit is applied...
        assert_eq!(fs::read_to_string(source.join("src/a.rs")).unwrap(), A_V2);
        // ...and the intervening source file is preserved, not reverted.
        assert!(
            source.join("src/b.rs").exists(),
            "reconcile must not delete source files created after materialization"
        );
        assert_eq!(
            fs::read_to_string(source.join("src/b.rs")).unwrap(),
            new_source_file
        );
        assert_eq!(summary.change_count, 1);
        assert!(!summary.changes.iter().any(|(_, path)| path == "src/b.rs"));
    }

    /// A source file modified after materialization but never touched by the
    /// workspace must keep the newer source content, not be reverted to base.
    #[test]
    fn change_set_preserves_unrelated_source_edit() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();
        fs::write(source.join("src/c.rs"), "pub fn c() -> u8 { 1 }\n").unwrap();

        // Workspace edits a.rs, leaves c.rs at the base content.
        let session_dir = layout.root().join("runs/session-unrelated");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V2).unwrap();
        fs::write(session_dir.join("src/c.rs"), "pub fn c() -> u8 { 1 }\n").unwrap();
        record_base_from_source(&layout, &session_dir);

        // The source advances c.rs after materialization.
        let advanced_c = "pub fn c() -> u8 { 2 }\n";
        fs::write(source.join("src/c.rs"), advanced_c).unwrap();

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();

        assert_eq!(fs::read_to_string(source.join("src/a.rs")).unwrap(), A_V2);
        assert_eq!(
            fs::read_to_string(source.join("src/c.rs")).unwrap(),
            advanced_c,
            "reconcile must not revert a source edit the workspace never touched"
        );
        assert_eq!(summary.change_count, 1);
    }

    /// When the workspace and the source both change the same file to different
    /// content, reconcile fails loud and leaves the newer source truth intact.
    #[test]
    fn change_set_conflicting_edit_fails_loud() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();

        let session_dir = layout.root().join("runs/session-conflict");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V2).unwrap();
        record_base_from_source(&layout, &session_dir);

        // The source moves the same file to a third state.
        fs::write(source.join("src/a.rs"), A_V3).unwrap();

        let err = reconcile_session_dir_sync(&layout, &session_dir)
            .unwrap_err()
            .to_string();

        assert!(err.contains("conflict"), "unexpected error: {err}");
        assert!(err.contains("src/a.rs"), "unexpected error: {err}");
        // Newer source truth is untouched, and the workspace is preserved.
        assert_eq!(fs::read_to_string(source.join("src/a.rs")).unwrap(), A_V3);
        assert_eq!(
            fs::read_to_string(session_dir.join("src/a.rs")).unwrap(),
            A_V2
        );
    }

    /// If the workspace and source converged to identical content, there is no
    /// conflict and nothing to apply.
    #[test]
    fn change_set_converged_edit_is_noop() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();

        let session_dir = layout.root().join("runs/session-converged");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V2).unwrap();
        record_base_from_source(&layout, &session_dir);

        // The source independently reaches the same content as the workspace.
        fs::write(source.join("src/a.rs"), A_V2).unwrap();

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();
        assert_eq!(summary.change_count, 0);
        assert_eq!(fs::read_to_string(source.join("src/a.rs")).unwrap(), A_V2);
    }

    // --- resolve_session_dir tests ---
    // layout.root() = .kin, so runs dir = .kin/runs/

    #[test]
    fn resolve_session_dir_finds_with_prefix() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let kin_dir = root.join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        fs::create_dir_all(kin_dir.join("runs").join("session-abc123")).unwrap();

        let layout = kin_core::KinLayout::discover(root).unwrap();
        let result = resolve_session_dir(&layout, Some("abc123".into())).unwrap();
        assert!(result.ends_with("session-abc123"));
    }

    #[test]
    fn resolve_session_dir_finds_bare_name() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let kin_dir = root.join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        fs::create_dir_all(kin_dir.join("runs").join("my-session")).unwrap();

        let layout = kin_core::KinLayout::discover(root).unwrap();
        let result = resolve_session_dir(&layout, Some("my-session".into())).unwrap();
        assert!(result.ends_with("my-session"));
    }

    #[test]
    fn resolve_session_dir_errors_on_missing() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let kin_dir = root.join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        fs::create_dir_all(kin_dir.join("runs")).unwrap();

        let layout = kin_core::KinLayout::discover(root).unwrap();
        let result = resolve_session_dir(&layout, Some("nonexistent".into()));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_session_dir_picks_most_recent() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let kin_dir = root.join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        fs::create_dir_all(kin_dir.join("runs").join("session-old")).unwrap();

        // Small delay so modification times differ
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::create_dir_all(kin_dir.join("runs").join("session-new")).unwrap();

        let layout = kin_core::KinLayout::discover(root).unwrap();
        let result = resolve_session_dir(&layout, None).unwrap();
        assert!(result.ends_with("session-new"));
    }
}
