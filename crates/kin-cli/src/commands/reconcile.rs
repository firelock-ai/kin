// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use kin_index::{FileClassification, FileClassifier, FileEvent};
use kin_model::GraphOverlay;
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
    let source = kin_core::source_dir(layout);

    ensure_session_dir_exists(session_dir)?;

    println!(
        "Reconciling session workspace (scoped): {}",
        session_dir.display()
    );
    println!("Against source: {}", source.display());

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

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let mut reconciler = Reconciler::new(session_dir.to_path_buf());
    let mut overlay = GraphOverlay::default();
    let mut total_upserted = 0usize;
    let mut total_removed = 0usize;
    let mut files_indexed = 0usize;
    let change_summaries: Vec<(String, String)> = changes
        .iter()
        .map(|change| {
            let label = match change.kind {
                ChangeKind::Modified => "modified",
                ChangeKind::Added => "added",
                ChangeKind::Deleted => "deleted",
            };
            (
                label.to_string(),
                change.relative_path.display().to_string(),
            )
        })
        .collect();

    for change in &changes {
        let session_file = session_dir.join(&change.relative_path);
        // Scoped reconcile is a batch operation: it diffs the session worktree
        // against the base source and re-indexes every changed file. Individual
        // file failures (broken AST, unsupported extension, semantic conflict)
        // should be silently handled — retain LKG state or skip — rather than
        // aborting the entire reconcile. The strict guard is only meaningful for
        // the interactive daemon file-watcher loop where a developer needs to
        // know about corrupted edits immediately.
        let strict_semantic_guard = false;

        match change.kind {
            ChangeKind::Modified | ChangeKind::Added => {
                let event = FileEvent::Changed(session_file.clone());
                match reconciler.reconcile_file_change(&event, &blob_store, graph, &mut overlay) {
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

                        use kin_model::EntityStore;
                        if let Some(layout) = reconciler.projection().get_layout(&file_id) {
                            graph.upsert_file_layout(layout)?;
                        }
                        if let Some(content) = reconciler.projection().get_content(&file_id) {
                            let hash = kin_blobs::digest_bytes(content);
                            graph.set_file_hash(&file_id.0, hash);
                        }
                    }
                    Ok(ReconcileOutcome::BrokenAst { file_id, .. }) if strict_semantic_guard => {
                        anyhow::bail!(
                            "reconcile aborted for {}: broken AST retained LKG state for {}",
                            change.relative_path.display(),
                            file_id
                        );
                    }
                    Ok(ReconcileOutcome::BrokenAst { file_id, .. }) => {
                        eprintln!("  Note: {} has broken AST, retaining LKG state", file_id);
                    }
                    Ok(ReconcileOutcome::Conflict(conflict)) if strict_semantic_guard => {
                        anyhow::bail!(
                            "reconcile aborted for {}: semantic conflict ({:?})",
                            change.relative_path.display(),
                            conflict.kind
                        );
                    }
                    Ok(ReconcileOutcome::Conflict(conflict)) => {
                        eprintln!(
                            "  Note: {} produced a conflict ({:?})",
                            change.relative_path.display(),
                            conflict.kind
                        );
                    }
                    Ok(ReconcileOutcome::FileRemoved { .. }) if strict_semantic_guard => {
                        anyhow::bail!(
                            "reconcile aborted for {}: unexpected file removal outcome",
                            change.relative_path.display()
                        );
                    }
                    Ok(ReconcileOutcome::FileRemoved { .. }) => {
                        // Shouldn't happen for a Changed event, but handle gracefully.
                    }
                    Err(e) if strict_semantic_guard => {
                        anyhow::bail!(
                            "reconcile aborted for {}: {}",
                            change.relative_path.display(),
                            e
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "  Note: {} not indexable ({})",
                            change.relative_path.display(),
                            e
                        );
                    }
                }
            }
            ChangeKind::Deleted => {
                let event = FileEvent::Removed(session_file.clone());
                match reconciler.reconcile_file_change(&event, &blob_store, graph, &mut overlay) {
                    Ok(ReconcileOutcome::FileRemoved {
                        removed, file_id, ..
                    }) => {
                        total_removed += removed.len();
                        use kin_model::EntityStore;
                        graph.delete_file_layout(&file_id)?;
                        graph.remove_entities_for_file(&file_id.0);
                    }
                    Ok(_) if strict_semantic_guard => {
                        anyhow::bail!(
                            "reconcile aborted for {}: unexpected remove outcome",
                            change.relative_path.display()
                        );
                    }
                    Ok(_) => {}
                    Err(e) if strict_semantic_guard => {
                        anyhow::bail!(
                            "reconcile aborted for {}: {}",
                            change.relative_path.display(),
                            e
                        );
                    }
                    Err(_) => {}
                }
            }
        }
    }

    apply_overlay_to_graph(graph, &mut overlay)
        .map_err(|e| anyhow::anyhow!("failed to apply reconciled overlay: {}", e))?;

    Ok(ReconcileSummary {
        changes: change_summaries,
        change_count: changes.len(),
        files_indexed,
        total_upserted,
        total_removed,
    })
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
    let source = kin_core::source_dir(layout);

    ensure_session_dir_exists(session_dir)?;

    println!("Reconciling session workspace: {}", session_dir.display());
    println!("Against source: {}", source.display());

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

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    // Parse and validate against the session workspace first; only copy back to
    // the materialized source tree after semantic reconcile accepts the change.
    let mut reconciler = Reconciler::new(session_dir.to_path_buf());
    let mut overlay = GraphOverlay::default();
    let mut total_upserted = 0usize;
    let mut total_removed = 0usize;
    let mut files_indexed = 0usize;
    let change_summaries: Vec<(String, String)> = changes
        .iter()
        .map(|change| {
            let label = match change.kind {
                ChangeKind::Modified => "modified",
                ChangeKind::Added => "added",
                ChangeKind::Deleted => "deleted",
            };
            (
                label.to_string(),
                change.relative_path.display().to_string(),
            )
        })
        .collect();
    let backups = capture_source_backups(&source, &changes)?;
    let result = (|| -> Result<ReconcileSummary> {
        for change in &changes {
            let session_file = session_dir.join(&change.relative_path);
            let source_file = source.join(&change.relative_path);
            let strict_semantic_guard = requires_strict_reconcile_guard(&change.relative_path);

            match change.kind {
                ChangeKind::Modified | ChangeKind::Added => {
                    let event = FileEvent::Changed(session_file.clone());
                    match reconciler.reconcile_file_change(&event, &blob_store, graph, &mut overlay)
                    {
                        Ok(ReconcileOutcome::Updated {
                            added,
                            modified,
                            removed,
                            ..
                        }) => {
                            total_upserted += added.len() + modified.len();
                            total_removed += removed.len();
                            files_indexed += 1;
                        }
                        Ok(ReconcileOutcome::BrokenAst { file_id, .. })
                            if strict_semantic_guard =>
                        {
                            anyhow::bail!(
                                "reconcile aborted for {}: broken AST retained LKG state for {}",
                                change.relative_path.display(),
                                file_id
                            );
                        }
                        Ok(ReconcileOutcome::BrokenAst { file_id, .. }) => {
                            eprintln!("  Note: {} has broken AST, retaining LKG state", file_id);
                        }
                        Ok(ReconcileOutcome::Conflict(conflict)) if strict_semantic_guard => {
                            anyhow::bail!(
                                "reconcile aborted for {}: semantic conflict ({:?})",
                                change.relative_path.display(),
                                conflict.kind
                            );
                        }
                        Ok(ReconcileOutcome::Conflict(conflict)) => {
                            eprintln!(
                                "  Note: {} produced a conflict ({:?})",
                                change.relative_path.display(),
                                conflict.kind
                            );
                        }
                        Ok(ReconcileOutcome::FileRemoved { .. }) if strict_semantic_guard => {
                            anyhow::bail!(
                                "reconcile aborted for {}: unexpected file removal outcome",
                                change.relative_path.display()
                            );
                        }
                        Ok(ReconcileOutcome::FileRemoved { .. }) => {
                            // Shouldn't happen for a Changed event, but handle gracefully.
                        }
                        Err(e) if strict_semantic_guard => {
                            anyhow::bail!(
                                "reconcile aborted for {}: {}",
                                change.relative_path.display(),
                                e
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "  Note: {} not indexable ({})",
                                change.relative_path.display(),
                                e
                            );
                        }
                    }

                    if let Some(parent) = source_file.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }
                    std::fs::copy(&session_file, &source_file).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to copy {} -> {}: {}",
                            session_file.display(),
                            source_file.display(),
                            e
                        )
                    })?;
                }
                ChangeKind::Deleted => {
                    let event = FileEvent::Removed(session_file.clone());
                    match reconciler.reconcile_file_change(&event, &blob_store, graph, &mut overlay)
                    {
                        Ok(ReconcileOutcome::FileRemoved {
                            removed, file_id, ..
                        }) => {
                            total_removed += removed.len();
                            use kin_model::EntityStore;
                            graph.delete_file_layout(&file_id)?;
                            graph.remove_entities_for_file(&file_id.0);
                            graph.delete_structured_artifact(&file_id)?;
                            graph.delete_opaque_artifact(&file_id)?;
                        }
                        Ok(_) if strict_semantic_guard => {
                            anyhow::bail!(
                                "reconcile aborted for {}: unexpected remove outcome",
                                change.relative_path.display()
                            );
                        }
                        Ok(_) => {}
                        Err(e) if strict_semantic_guard => {
                            anyhow::bail!(
                                "reconcile aborted for {}: {}",
                                change.relative_path.display(),
                                e
                            );
                        }
                        Err(_) => {}
                    }

                    if source_file.exists() {
                        std::fs::remove_file(&source_file).ok();
                    }
                }
            }
        }

        apply_overlay_to_graph(graph, &mut overlay)
            .map_err(|e| anyhow::anyhow!("failed to apply reconciled overlay: {}", e))?;
        persist()?;

        Ok(ReconcileSummary {
            changes: change_summaries,
            change_count: changes.len(),
            files_indexed,
            total_upserted,
            total_removed,
        })
    })();

    match result {
        Ok(summary) => Ok(summary),
        Err(err) => {
            restore_source_backups(&source, &backups).map_err(|restore_err| {
                anyhow::anyhow!(
                    "{}; additionally failed to restore source tree: {}",
                    err,
                    restore_err
                )
            })?;
            Err(err)
        }
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

#[derive(Debug)]
struct FileChange {
    relative_path: PathBuf,
    kind: ChangeKind,
}

#[derive(Debug)]
enum ChangeKind {
    Modified,
    Added,
    Deleted,
}

#[derive(Debug)]
struct SourceBackup {
    relative_path: PathBuf,
    original: OriginalSourceState,
}

#[derive(Debug)]
enum OriginalSourceState {
    Missing,
    File(Vec<u8>),
}

fn capture_source_backups(source: &Path, changes: &[FileChange]) -> Result<Vec<SourceBackup>> {
    changes
        .iter()
        .map(|change| {
            let path = source.join(&change.relative_path);
            let original = if path.exists() {
                OriginalSourceState::File(std::fs::read(&path).map_err(|e| {
                    anyhow::anyhow!("failed to read {} before reconcile: {}", path.display(), e)
                })?)
            } else {
                OriginalSourceState::Missing
            };
            Ok(SourceBackup {
                relative_path: change.relative_path.clone(),
                original,
            })
        })
        .collect()
}

fn restore_source_backups(source: &Path, backups: &[SourceBackup]) -> Result<()> {
    for backup in backups.iter().rev() {
        let path = source.join(&backup.relative_path);
        match &backup.original {
            OriginalSourceState::Missing => {
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|e| {
                        anyhow::anyhow!("failed to remove restored file {}: {}", path.display(), e)
                    })?;
                }
                prune_empty_parent_dirs(source, path.parent());
            }
            OriginalSourceState::File(bytes) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to recreate parent directory {}: {}",
                            parent.display(),
                            e
                        )
                    })?;
                }
                std::fs::write(&path, bytes)
                    .map_err(|e| anyhow::anyhow!("failed to restore {}: {}", path.display(), e))?;
            }
        }
    }
    Ok(())
}

fn prune_empty_parent_dirs(root: &Path, mut current: Option<&Path>) {
    while let Some(dir) = current {
        if dir == root {
            break;
        }

        match std::fs::remove_dir(dir) {
            Ok(()) => current = dir.parent(),
            Err(_) => break,
        }
    }
}

fn requires_strict_reconcile_guard(relative_path: &Path) -> bool {
    // Only enforce the strict semantic guard for files that have a real
    // tree-sitter indexing path (EntitySource, ShallowSyntax). Structured
    // artifacts (Cargo.toml, pyproject.toml, Dockerfile, …) and opaque blobs
    // are tracked but do not go through entity extraction, so an "unsupported
    // file" error from the reconciler is expected and must not abort.
    matches!(
        FileClassifier::classify(relative_path),
        FileClassification::EntitySource | FileClassification::ShallowSyntax { .. }
    )
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
    match super::session_base::load_base(session_dir)? {
        Some(base) => plan_from_base(session_dir, source, &base),
        None => plan_without_base(session_dir, source),
    }
}

/// Change-set plan for a workspace with a recorded base: a file-level three-way
/// merge of base -> workspace against base -> source.
fn plan_from_base(
    session_dir: &Path,
    source: &Path,
    base: &super::session_base::SessionBase,
) -> Result<Vec<FileChange>> {
    let workspace_state = super::session_base::hash_dir(session_dir)?;
    let source_state = super::session_base::hash_dir(source)?;
    let base_state = &base.files;

    let mut candidate_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    candidate_paths.extend(base_state.keys().cloned());
    candidate_paths.extend(workspace_state.keys().cloned());

    let mut changes = Vec::new();
    let mut conflicts = Vec::new();

    for path in candidate_paths {
        let base_hash = base_state.get(&path);
        let workspace_hash = workspace_state.get(&path);
        if base_hash == workspace_hash {
            // The workspace never changed this path; leave it untouched even if
            // the source advanced it. This is the change-set guarantee.
            continue;
        }

        let source_hash = source_state.get(&path);
        if source_hash != base_hash {
            // Both the workspace and the source moved this path off the base.
            if workspace_hash == source_hash {
                // They converged to identical content — nothing to apply.
                continue;
            }
            conflicts.push(describe_reconcile_conflict(
                &path,
                base_hash,
                workspace_hash,
                source_hash,
            ));
            continue;
        }

        // Disjoint edit: the source is still at the base here, so the
        // workspace's own change applies cleanly.
        let kind = match (base_hash.is_some(), workspace_hash.is_some()) {
            (false, true) => ChangeKind::Added,
            (true, true) => ChangeKind::Modified,
            (true, false) => ChangeKind::Deleted,
            // Unreachable: base_hash != workspace_hash is guaranteed above.
            (false, false) => continue,
        };
        changes.push(FileChange {
            relative_path: PathBuf::from(path),
            kind,
        });
    }

    if !conflicts.is_empty() {
        let base_head = base.base_head.as_deref().unwrap_or("unknown");
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
    base: Option<&String>,
    workspace: Option<&String>,
    source: Option<&String>,
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

/// Change-set plan for a legacy workspace with no recorded base.
///
/// Without a base the workspace's own edits cannot be separated from source
/// changes made since it was materialized. Additions are the one provably safe
/// class — the path does not exist in the source tree, so writing it cannot
/// overwrite or remove source truth — and they apply. Modifications and
/// deletions of source-existing paths could revert newer source truth, so any
/// of those fails loud and asks the operator to rematerialize.
fn plan_without_base(session_dir: &Path, source: &Path) -> Result<Vec<FileChange>> {
    let changes = diff_directories(session_dir, source)?;
    let dangerous: Vec<String> = changes
        .iter()
        .filter(|change| !matches!(change.kind, ChangeKind::Added))
        .map(|change| {
            let action = match change.kind {
                ChangeKind::Modified => "modified in session",
                ChangeKind::Deleted => "missing from session",
                ChangeKind::Added => unreachable!("filtered above"),
            };
            format!("{} ({action})", change.relative_path.display())
        })
        .collect();
    if dangerous.is_empty() {
        return Ok(changes);
    }
    anyhow::bail!(
        "session workspace {} has no recorded base version, so its edits to {} existing source \
         path(s) cannot be separated from source changes made since it was materialized; \
         reconciling could revert newer source truth. Re-run the work in a fresh session \
         (kin exec/shell/with) or discard this workspace (rm -rf {}). Affected:\n  {}",
        session_dir.display(),
        dangerous.len(),
        session_dir.display(),
        dangerous.join("\n  "),
    )
}

/// Compare two directories and find differences.
fn diff_directories(session: &Path, source: &Path) -> Result<Vec<FileChange>> {
    let mut changes = Vec::new();

    let session_files = collect_relative_files(session)?;
    let source_files = collect_relative_files(source)?;

    let session_set: HashSet<_> = session_files.iter().collect();
    let source_set: HashSet<_> = source_files.iter().collect();

    // Modified or added: files in session that differ from source
    for rel_path in &session_files {
        let session_file = session.join(rel_path);
        let source_file = source.join(rel_path);

        if !source_set.contains(rel_path) {
            changes.push(FileChange {
                relative_path: rel_path.clone(),
                kind: ChangeKind::Added,
            });
        } else if files_differ(&session_file, &source_file) {
            changes.push(FileChange {
                relative_path: rel_path.clone(),
                kind: ChangeKind::Modified,
            });
        }
    }

    // Deleted: files in source that don't exist in session
    for rel_path in &source_files {
        if !session_set.contains(rel_path) {
            changes.push(FileChange {
                relative_path: rel_path.clone(),
                kind: ChangeKind::Deleted,
            });
        }
    }

    Ok(changes)
}

/// Collect all file paths relative to root, skipping hidden dirs and common large dirs.
pub(crate) fn collect_relative_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_recursive(root, root, &mut files)?;
    Ok(files)
}

fn collect_recursive(dir: &Path, root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if dir == root && name_str == super::session_process::SESSION_CONTEXT_FILE {
            continue;
        }
        if kin_index::should_skip_dir(&name_str) {
            continue;
        }

        let path = entry.path();
        if path.is_dir() {
            collect_recursive(&path, root, files)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                files.push(rel.to_path_buf());
            }
        }
    }

    Ok(())
}

/// Compare two files for content differences (by size first, then bytes).
fn files_differ(a: &Path, b: &Path) -> bool {
    let meta_a = match std::fs::metadata(a) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let meta_b = match std::fs::metadata(b) {
        Ok(m) => m,
        Err(_) => return true,
    };

    if meta_a.len() != meta_b.len() {
        return true;
    }

    // Same size — compare content
    let content_a = std::fs::read(a).unwrap_or_default();
    let content_b = std::fs::read(b).unwrap_or_default();
    content_a != content_b
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
        let files = crate::commands::session_base::hash_dir(&kin_core::source_dir(layout)).unwrap();
        crate::commands::session_base::write_base(
            session_dir,
            &crate::commands::session_base::SessionBase {
                base_head: None,
                files,
            },
        )
        .unwrap();
    }

    // --- files_differ tests ---

    #[test]
    fn files_differ_identical_content() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::write(dir.path().join("b.txt"), "hello").unwrap();
        assert!(!files_differ(
            &dir.path().join("a.txt"),
            &dir.path().join("b.txt")
        ));
    }

    #[test]
    fn files_differ_different_content() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::write(dir.path().join("b.txt"), "world").unwrap();
        assert!(files_differ(
            &dir.path().join("a.txt"),
            &dir.path().join("b.txt")
        ));
    }

    #[test]
    fn files_differ_different_sizes() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "short").unwrap();
        fs::write(dir.path().join("b.txt"), "much longer content").unwrap();
        assert!(files_differ(
            &dir.path().join("a.txt"),
            &dir.path().join("b.txt")
        ));
    }

    #[test]
    fn files_differ_missing_file_returns_true() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        assert!(files_differ(
            &dir.path().join("a.txt"),
            &dir.path().join("nonexistent.txt")
        ));
        assert!(files_differ(
            &dir.path().join("nonexistent.txt"),
            &dir.path().join("a.txt")
        ));
    }

    #[test]
    fn files_differ_empty_files_are_equal() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "").unwrap();
        fs::write(dir.path().join("b.txt"), "").unwrap();
        assert!(!files_differ(
            &dir.path().join("a.txt"),
            &dir.path().join("b.txt")
        ));
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
    fn reconcile_session_dir_restores_source_tree_when_semantic_reconcile_fails() {
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

        let err = reconcile_session_dir_sync(&layout, &session_dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("broken AST"));
        assert_eq!(fs::read_to_string(&source_file).unwrap(), original);
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

    /// A legacy workspace with no recorded base refuses to reconcile when its
    /// contents differ from the source, rather than risk reverting source truth.
    #[test]
    fn change_set_without_base_refuses_when_workspace_differs() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();

        // Hand-built session with no base manifest (legacy workspace).
        let session_dir = layout.root().join("runs/session-legacy-diff");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V2).unwrap();

        let err = reconcile_session_dir_sync(&layout, &session_dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no recorded base"), "unexpected error: {err}");
        // The source is untouched — reconcile refused before applying anything.
        assert_eq!(fs::read_to_string(source.join("src/a.rs")).unwrap(), A_V1);
    }

    /// A legacy workspace already identical to the source is a provable no-op
    /// and is allowed.
    #[test]
    fn change_set_without_base_allows_identical_noop() {
        let repo = tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let source = kin_core::source_dir(&layout);

        fs::create_dir_all(source.join("src")).unwrap();
        fs::write(source.join("src/a.rs"), A_V1).unwrap();

        let session_dir = layout.root().join("runs/session-legacy-noop");
        fs::create_dir_all(session_dir.join("src")).unwrap();
        fs::write(session_dir.join("src/a.rs"), A_V1).unwrap();

        let summary = reconcile_session_dir_sync(&layout, &session_dir).unwrap();
        assert_eq!(summary.change_count, 0);
    }

    // --- collect_relative_files tests ---

    #[test]
    fn collect_relative_files_basic() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src").join("main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("README.md"), "readme").unwrap();

        let mut files = collect_relative_files(root).unwrap();
        files.sort();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0], PathBuf::from("README.md"));
        assert_eq!(files[1], PathBuf::from("src/main.rs"));
    }

    #[test]
    fn collect_relative_files_skips_hidden_dirs_but_preserves_dotfiles() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join(".git")).unwrap();
        fs::write(root.join(".git").join("config"), "git config").unwrap();
        fs::write(root.join(".hidden_file"), "hidden").unwrap();
        fs::write(root.join("visible.txt"), "visible").unwrap();

        let mut files = collect_relative_files(root).unwrap();
        files.sort();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0], PathBuf::from(".hidden_file"));
        assert_eq!(files[1], PathBuf::from("visible.txt"));
    }

    #[test]
    fn collect_relative_files_skips_known_dirs() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("pkg.json"), "{}").unwrap();
        fs::create_dir(root.join("target")).unwrap();
        fs::write(root.join("target").join("debug"), "binary").unwrap();
        fs::write(root.join("src.rs"), "code").unwrap();

        let files = collect_relative_files(root).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0], PathBuf::from("src.rs"));
    }

    #[test]
    fn collect_relative_files_skips_session_context_at_workspace_root() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join(super::super::session_process::SESSION_CONTEXT_FILE),
            r#"{"session_id":"private-runtime-state"}"#,
        )
        .unwrap();
        fs::write(root.join("compose.yaml"), "services: {}\n").unwrap();

        let files = collect_relative_files(root).unwrap();

        assert_eq!(files, vec![PathBuf::from("compose.yaml")]);
    }

    // --- diff_directories tests ---

    #[test]
    fn diff_detects_added_file() {
        let dir = tempdir().unwrap();
        let session = dir.path().join("session");
        let source = dir.path().join("source");
        fs::create_dir(&session).unwrap();
        fs::create_dir(&source).unwrap();

        // File only in session = added
        fs::write(session.join("new_file.rs"), "new code").unwrap();

        let changes = diff_directories(&session, &source).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].relative_path, PathBuf::from("new_file.rs"));
        assert!(matches!(changes[0].kind, ChangeKind::Added));
    }

    #[test]
    fn diff_detects_deleted_file() {
        let dir = tempdir().unwrap();
        let session = dir.path().join("session");
        let source = dir.path().join("source");
        fs::create_dir(&session).unwrap();
        fs::create_dir(&source).unwrap();

        // File only in source = deleted
        fs::write(source.join("old_file.rs"), "old code").unwrap();

        let changes = diff_directories(&session, &source).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].relative_path, PathBuf::from("old_file.rs"));
        assert!(matches!(changes[0].kind, ChangeKind::Deleted));
    }

    #[test]
    fn diff_detects_modified_file() {
        let dir = tempdir().unwrap();
        let session = dir.path().join("session");
        let source = dir.path().join("source");
        fs::create_dir(&session).unwrap();
        fs::create_dir(&source).unwrap();

        // Same filename, different content = modified
        fs::write(session.join("lib.rs"), "fn new_impl() {}").unwrap();
        fs::write(source.join("lib.rs"), "fn old_impl() {}").unwrap();

        let changes = diff_directories(&session, &source).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].relative_path, PathBuf::from("lib.rs"));
        assert!(matches!(changes[0].kind, ChangeKind::Modified));
    }

    #[test]
    fn diff_no_changes_when_identical() {
        let dir = tempdir().unwrap();
        let session = dir.path().join("session");
        let source = dir.path().join("source");
        fs::create_dir(&session).unwrap();
        fs::create_dir(&source).unwrap();

        fs::write(session.join("same.txt"), "identical").unwrap();
        fs::write(source.join("same.txt"), "identical").unwrap();

        let changes = diff_directories(&session, &source).unwrap();
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_detects_mixed_changes() {
        let dir = tempdir().unwrap();
        let session = dir.path().join("session");
        let source = dir.path().join("source");
        fs::create_dir(&session).unwrap();
        fs::create_dir(&source).unwrap();

        // Added
        fs::write(session.join("new.rs"), "new").unwrap();
        // Modified
        fs::write(session.join("changed.rs"), "v2").unwrap();
        fs::write(source.join("changed.rs"), "v1").unwrap();
        // Deleted
        fs::write(source.join("removed.rs"), "old").unwrap();
        // Unchanged
        fs::write(session.join("same.rs"), "same").unwrap();
        fs::write(source.join("same.rs"), "same").unwrap();

        let changes = diff_directories(&session, &source).unwrap();

        assert_eq!(changes.len(), 3);

        let added = changes.iter().find(|c| matches!(c.kind, ChangeKind::Added));
        let modified = changes
            .iter()
            .find(|c| matches!(c.kind, ChangeKind::Modified));
        let deleted = changes
            .iter()
            .find(|c| matches!(c.kind, ChangeKind::Deleted));

        assert!(added.is_some());
        assert_eq!(added.unwrap().relative_path, PathBuf::from("new.rs"));
        assert!(modified.is_some());
        assert_eq!(modified.unwrap().relative_path, PathBuf::from("changed.rs"));
        assert!(deleted.is_some());
        assert_eq!(deleted.unwrap().relative_path, PathBuf::from("removed.rs"));
    }

    #[test]
    fn diff_handles_nested_directories() {
        let dir = tempdir().unwrap();
        let session = dir.path().join("session");
        let source = dir.path().join("source");
        fs::create_dir_all(session.join("src").join("util")).unwrap();
        fs::create_dir_all(source.join("src").join("util")).unwrap();

        fs::write(session.join("src").join("util").join("helper.rs"), "new").unwrap();
        fs::write(source.join("src").join("util").join("helper.rs"), "old").unwrap();

        // Added in a nested dir
        fs::write(session.join("src").join("new_mod.rs"), "mod new_mod;").unwrap();

        let changes = diff_directories(&session, &source).unwrap();

        assert_eq!(changes.len(), 2);

        let modified = changes
            .iter()
            .find(|c| matches!(c.kind, ChangeKind::Modified));
        assert!(modified.is_some());
        assert_eq!(
            modified.unwrap().relative_path,
            PathBuf::from("src/util/helper.rs")
        );

        let added = changes.iter().find(|c| matches!(c.kind, ChangeKind::Added));
        assert!(added.is_some());
        assert_eq!(
            added.unwrap().relative_path,
            PathBuf::from("src/new_mod.rs")
        );
    }

    // --- resolve_session_dir tests ---

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
