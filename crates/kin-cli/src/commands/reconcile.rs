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
        return reconcile_session_dir_with_snapshot(layout, session_dir, snap);
    }

    #[cfg(not(test))]
    {
        let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for reconcile"))?;
        let client = crate::daemon_client::DaemonClient::from_base_url(daemon_url)?;
        client
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

    let changes = diff_directories(session_dir, &source)?;

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
                        Ok(ReconcileOutcome::FileRemoved { removed, .. }) => {
                            total_removed += removed.len();
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
    !matches!(
        FileClassifier::classify(relative_path),
        FileClassification::OpaqueArtifact { .. }
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
fn collect_relative_files(root: &Path) -> Result<Vec<PathBuf>> {
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

        let blocked_tmp_path = crate::backend::kindb_snapshot_path(&layout).with_extension("tmp");
        fs::create_dir_all(&blocked_tmp_path).unwrap();

        let err = reconcile_session_dir_sync(&layout, &session_dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to persist reconciled graph snapshot"));
        assert_eq!(fs::read_to_string(&source_file).unwrap(), original);
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
