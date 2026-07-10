// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use kin_index::{FileEvent, FileWatcher};
use kin_reconcile::apply_overlay_to_graph;
use tracing::{debug, error, info, warn};

use crate::error::{DaemonError, Result};
use crate::state::{
    ChangeType, DaemonEvent, DaemonState, LspEnrichmentRequest, ProjectionChangedSet, RECON_IDLE,
    RECON_PROCESSING,
};

/// Configuration for the reconciliation loop.
#[derive(Debug, Clone)]
pub struct LoopConfig {
    /// How often to drain the file watcher (milliseconds).
    pub poll_interval_ms: u64,
    /// Maximum events to process per tick.
    pub batch_size: usize,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 100,
            batch_size: 64,
        }
    }
}

/// Run the reconciliation loop until the cancellation token fires.
///
/// This is the main loop of the daemon. It:
/// 1. Watches the working directory for file changes (via `notify`)
/// 2. Drains batches of events
/// 3. For each event, runs the reconciler (file -> overlay)
/// 4. Projects overlay mutations back to files (overlay -> file)
///
fn is_bare_repository(dir: &std::path::Path) -> bool {
    dir.join("config").is_file()
        && dir.join("objects").is_dir()
        && dir.join("refs").is_dir()
        && !dir.join(".git").exists()
}

/// Run the reconciliation loop until the cancellation token fires.
///
/// This is the main loop of the daemon. It:
/// 1. Watches the working directory for file changes (via `notify`)
/// 2. Drains batches of events
/// 3. For each event, runs the reconciler (file -> overlay)
/// 4. Projects overlay mutations back to files (overlay -> file)
///
/// The loop runs on a tokio task and shares state through `DaemonState`.
pub async fn run_loop(
    state: Arc<DaemonState>,
    config: LoopConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let working_dir = state.layout.working_dir();
    if is_bare_repository(working_dir) {
        info!(working_dir = %working_dir.display(), "working directory is a bare Git repository; reconciliation loop disabled");
        let mut cancel = cancel;
        tokio::select! {
            _ = cancel.changed() => {}
        }
        return Ok(());
    }

    let extensions = kin_index::watcher::supported_extensions();
    let watcher = FileWatcher::new(working_dir, extensions).map_err(DaemonError::from)?;

    info!(
        poll_ms = config.poll_interval_ms,
        batch = config.batch_size,
        "reconciliation loop started"
    );

    if let Err(e) = sync_filesystem_with_graph(&state).await {
        error!(error = %e, "initial filesystem sync failed");
    }

    let interval = Duration::from_millis(config.poll_interval_ms);
    let mut cancel = cancel;
    // Track the effective batch size for backpressure catch-up.
    let base_batch_size = config.batch_size.max(1);
    if config.batch_size == 0 {
        warn!("reconciliation batch_size=0 is invalid; clamping to 1");
    }

    // RACE CONDITION HARDENING: Retry queue for files that were modified
    // during reconciliation. When a FileModifiedDuringReconcile error
    // occurs, the file watcher may have already drained the event for the
    // new content in the current batch. Without re-queuing, the file would
    // remain stale in the graph until the next external write. This queue
    // injects synthetic Changed events at the start of the next tick.
    let mut retry_queue: Vec<PathBuf> = Vec::new();

    // The watcher API drains its whole channel at once, while this loop deliberately
    // processes only a bounded batch per tick. Keep the unprocessed tail here so a burst
    // larger than `batch_size` is deferred instead of silently discarded.
    let mut pending_events: VecDeque<FileEvent> = VecDeque::new();
    let mut backlog_warning_active = false;

    loop {
        // Check for shutdown signal.
        if *cancel.borrow() {
            state
                .reconciliation_status
                .store(RECON_IDLE, Ordering::Relaxed);
            info!("reconciliation loop shutting down");
            break;
        }

        // Sweep expired intents so stale leases don't block work.
        if let Ok(reaped) = state.coordinator.sweep_expired_intents() {
            if reaped > 0 {
                debug!(reaped, "swept expired intents");
            }
        }

        // Collect retries first and real watcher notifications second. Dedup once per tick,
        // only when something new arrived; a real remove/recreate therefore supersedes a
        // synthetic Changed retry without repeatedly rebuilding an unchanged backlog.
        let mut incoming_events = Vec::new();
        if !retry_queue.is_empty() {
            debug!(
                count = retry_queue.len(),
                "injecting retry events from previous tick"
            );
            incoming_events.extend(retry_queue.drain(..).map(FileEvent::Changed));
        }
        incoming_events.extend(watcher.drain());
        enqueue_file_events(&mut pending_events, incoming_events);

        if pending_events.is_empty() {
            // No events — sleep briefly then check again.
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.changed() => {
                    state.reconciliation_status.store(RECON_IDLE, Ordering::Relaxed);
                    info!("reconciliation loop shutting down");
                    break;
                }
            }
            continue;
        }

        state
            .reconciliation_status
            .store(RECON_PROCESSING, Ordering::Relaxed);

        // Backpressure stays bounded. A large burst remains in `pending_events` and is
        // consumed over multiple iterations; processing the entire queue under the write
        // locks would starve API tasks and delay cancellation.
        let event_count = pending_events.len();
        if event_count > base_batch_size.saturating_mul(4) {
            if !backlog_warning_active {
                warn!(
                    pending = event_count,
                    base_batch = base_batch_size,
                    "event queue backpressure — retaining bounded batches for fair catch-up"
                );
                backlog_warning_active = true;
            }
        } else {
            backlog_warning_active = false;
        }

        // Process only the configured prefix. `take_file_event_batch` removes that prefix
        // and leaves every later event in `pending_events` for the next loop iteration.
        let batch = take_file_event_batch(&mut pending_events, base_batch_size);
        debug!(count = batch.len(), "processing file events (after dedup)");

        // Acquire write locks for reconciliation.
        let mut reconciler = state.reconciler.write().await;
        let mut working_copy = state.working_copy.write().await;
        let mut graph_changed = false;
        let mut projection_changed = ProjectionChangedSet::default();

        let mut lsp_changed: Vec<(PathBuf, Vec<kin_model::EntityId>)> = Vec::new();

        for event in &batch {
            match reconciler.reconcile_file_change(
                event,
                &state.blobs,
                state.graph.as_ref(),
                &mut working_copy.uncommitted_mutations,
            ) {
                Ok(outcome) => {
                    debug!(?outcome, "reconcile outcome");

                    use kin_reconcile::ReconcileOutcome;
                    let should_apply = matches!(
                        &outcome,
                        ReconcileOutcome::Updated { .. } | ReconcileOutcome::FileRemoved { .. }
                    );
                    if should_apply {
                        if let Err(e) = apply_overlay_to_graph(
                            state.graph.as_ref(),
                            &mut working_copy.uncommitted_mutations,
                        ) {
                            warn!(error = %e, "failed to apply reconciled mutations into primary graph");
                            continue;
                        }
                        if let Err(e) =
                            state.persist_projection_truth_from_reconcile(&reconciler, &outcome)
                        {
                            warn!(error = %e, "failed to persist projection truth after reconcile");
                        }
                        projection_changed.record_reconcile_outcome(&outcome);
                        graph_changed = true;
                    }

                    if let ReconcileOutcome::Updated {
                        added,
                        modified,
                        removed,
                        ..
                    } = &outcome
                    {
                        let file_path = match event {
                            FileEvent::Changed(p) | FileEvent::Removed(p) => {
                                p.to_string_lossy().to_string()
                            }
                        };
                        for id in added {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Created,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        for id in modified {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Modified,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }
                        state.bump_version();

                        // Collect entity IDs for LSP enrichment.
                        let mut changed_ids: Vec<kin_model::EntityId> = Vec::new();
                        changed_ids.extend(added.iter().copied());
                        changed_ids.extend(modified.iter().copied());
                        debug!(
                            added = added.len(),
                            modified = modified.len(),
                            removed = removed.len(),
                            total_for_lsp = changed_ids.len(),
                            "reconcile entity counts for LSP enrichment"
                        );
                        if !changed_ids.is_empty() {
                            let path = match event {
                                FileEvent::Changed(p) | FileEvent::Removed(p) => p.clone(),
                            };
                            lsp_changed.push((path, changed_ids));
                        }
                    } else if let ReconcileOutcome::FileRemoved {
                        removed, file_id, ..
                    } = &outcome
                    {
                        let file_path = match event {
                            FileEvent::Changed(p) | FileEvent::Removed(p) => {
                                p.to_string_lossy().to_string()
                            }
                        };
                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_path.clone()),
                                // FS-reconcile loop: a raw filesystem change has
                                // no owning agent, so attribution is honestly None.
                                session_id: None,
                            });
                        }

                        use kin_model::EntityStore;
                        let _ = state.graph.delete_file_layout(file_id);
                        state.graph.remove_entities_for_file(&file_id.0);
                        let _ = state.graph.delete_structured_artifact(file_id);
                        let _ = state.graph.delete_opaque_artifact(file_id);

                        state.bump_version();
                    }
                }
                Err(e) => {
                    // FileModifiedDuringReconcile is an expected race — the file
                    // changed while we were processing it. Re-queue the file so
                    // it's reconciled on the next tick even if the watcher already
                    // drained the event for the new content in this batch.
                    if matches!(
                        e,
                        kin_reconcile::ReconcileError::FileModifiedDuringReconcile { .. }
                    ) {
                        debug!(error = %e, "file changed during reconcile, queued for retry");
                        let retry_path = match &event {
                            FileEvent::Changed(path) | FileEvent::Removed(path) => path.clone(),
                        };
                        retry_queue.push(retry_path);
                    } else {
                        warn!(error = %e, "reconciliation error for event, skipping");
                    }
                }
            }
        }

        // Drop write locks before rebuilding projection (it takes its own locks).
        drop(working_copy);
        drop(reconciler);

        // Queue only changed entities for LSP enrichment.
        for (path, entity_ids) in lsp_changed {
            state.queue_lsp_enrichment(LspEnrichmentRequest {
                file_path: path,
                changed_entity_ids: entity_ids,
            });
        }

        // Refresh projection cache so VFS reads serve fresh content.
        // Persistence is handled by the background save task — the reconcile
        // loop just marks the graph dirty and refreshes touched projection rows.
        if graph_changed {
            state.mark_dirty();
            let projection_result = if projection_changed.is_empty() {
                state.rebuild_projection().await
            } else {
                state.refresh_projection(&projection_changed).await
            };
            if let Err(e) = projection_result {
                error!(error = %e, "failed to refresh projection after reconciliation");
            }
        }

        let backlog_remains = !pending_events.is_empty() || !retry_queue.is_empty();
        if !backlog_remains {
            state
                .reconciliation_status
                .store(RECON_IDLE, Ordering::Relaxed);
        }

        // Mark initialized after the first successful reconciliation cycle.
        if !state.is_initialized.load(Ordering::Relaxed) {
            state.is_initialized.store(true, Ordering::Relaxed);
            info!("daemon initialized after first reconciliation cycle");
        }

        // A retained backlog should catch up promptly, but yield between batches so the
        // daemon's other Tokio tasks and the cancellation sender are never starved.
        if backlog_remains {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

/// Deduplicate file events, keeping only the last event per path.
///
/// When multiple events arrive for the same file in a single batch (e.g.,
/// rapid saves, multi-file refactors), only the last event matters because
/// the reconciler will read the file at its current state. A `Removed` event
/// supersedes any prior `Changed` events, and a `Changed` event after a
/// `Removed` means the file was recreated.
///
/// Preserves the relative order of the last event per unique path.
fn dedup_file_events(events: Vec<FileEvent>) -> Vec<FileEvent> {
    // Track the last event per path, preserving insertion order via index.
    let mut last_event: HashMap<PathBuf, (usize, FileEvent)> = HashMap::new();
    for (idx, event) in events.into_iter().enumerate() {
        let path = match &event {
            FileEvent::Changed(p) | FileEvent::Removed(p) => p.clone(),
        };
        last_event.insert(path, (idx, event));
    }

    // Sort by original index to preserve temporal order.
    let mut deduped: Vec<(usize, FileEvent)> = last_event.into_values().collect();
    deduped.sort_by_key(|(idx, _)| *idx);
    deduped.into_iter().map(|(_, event)| event).collect()
}

/// Append events to the retained watcher backlog and keep only the last event per path.
///
/// Deduplicating the whole backlog, rather than just the next processing batch, also handles a
/// path whose superseding event arrives after an earlier event was deferred to the next tick.
fn enqueue_file_events(
    pending: &mut VecDeque<FileEvent>,
    events: impl IntoIterator<Item = FileEvent>,
) {
    let incoming = events.into_iter().collect::<Vec<_>>();
    if incoming.is_empty() {
        return;
    }

    let mut combined = Vec::with_capacity(pending.len() + incoming.len());
    combined.extend(pending.drain(..));
    combined.extend(incoming);
    pending.extend(dedup_file_events(combined));
}

/// Remove at most `batch_size` events from the front of the retained backlog.
fn take_file_event_batch(pending: &mut VecDeque<FileEvent>, batch_size: usize) -> Vec<FileEvent> {
    let count = batch_size.max(1).min(pending.len());
    (0..count).filter_map(|_| pending.pop_front()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn dedup_keeps_last_event_per_path() {
        let events = vec![
            FileEvent::Changed(PathBuf::from("/a.rs")),
            FileEvent::Changed(PathBuf::from("/b.rs")),
            FileEvent::Changed(PathBuf::from("/a.rs")), // supersedes first /a.rs
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 2);
        // /b.rs comes first (index 1), /a.rs second (index 2)
        assert!(matches!(&deduped[0], FileEvent::Changed(p) if p == &PathBuf::from("/b.rs")));
        assert!(matches!(&deduped[1], FileEvent::Changed(p) if p == &PathBuf::from("/a.rs")));
    }

    #[test]
    fn dedup_removed_supersedes_changed() {
        let events = vec![
            FileEvent::Changed(PathBuf::from("/a.rs")),
            FileEvent::Removed(PathBuf::from("/a.rs")), // supersedes Changed
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 1);
        assert!(matches!(&deduped[0], FileEvent::Removed(p) if p == &PathBuf::from("/a.rs")));
    }

    #[test]
    fn dedup_changed_after_removed_means_recreated() {
        let events = vec![
            FileEvent::Removed(PathBuf::from("/a.rs")),
            FileEvent::Changed(PathBuf::from("/a.rs")), // file was recreated
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 1);
        assert!(matches!(&deduped[0], FileEvent::Changed(p) if p == &PathBuf::from("/a.rs")));
    }

    #[test]
    fn dedup_preserves_different_paths() {
        let events = vec![
            FileEvent::Changed(PathBuf::from("/a.rs")),
            FileEvent::Changed(PathBuf::from("/b.rs")),
            FileEvent::Removed(PathBuf::from("/c.rs")),
        ];
        let deduped = dedup_file_events(events);
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn dedup_empty_input() {
        let deduped = dedup_file_events(vec![]);
        assert!(deduped.is_empty());
    }

    #[test]
    fn retained_backlog_processes_every_event_across_bounded_batches() {
        let mut pending = VecDeque::new();
        let events = (0..6)
            .map(|n| FileEvent::Changed(PathBuf::from(format!("/{n}.rs"))))
            .collect::<Vec<_>>();
        enqueue_file_events(&mut pending, events);

        let first = take_file_event_batch(&mut pending, 2);
        let second = take_file_event_batch(&mut pending, 2);
        let third = take_file_event_batch(&mut pending, 2);

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert_eq!(third.len(), 2);
        assert!(pending.is_empty());
        let ordered_paths = first
            .into_iter()
            .chain(second)
            .chain(third)
            .map(|event| match event {
                FileEvent::Changed(path) | FileEvent::Removed(path) => path,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ordered_paths,
            (0..6)
                .map(|n| PathBuf::from(format!("/{n}.rs")))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn retained_backlog_honors_default_batch_boundaries_and_large_bursts() {
        const BATCH: usize = 64;

        for total in [64usize, 65, 256, 257] {
            let mut pending = VecDeque::new();
            enqueue_file_events(
                &mut pending,
                (0..total).map(|n| FileEvent::Changed(PathBuf::from(format!("/{total}-{n}.rs")))),
            );

            let mut processed = Vec::new();
            while !pending.is_empty() {
                let batch = take_file_event_batch(&mut pending, BATCH);
                assert!(!batch.is_empty());
                assert!(batch.len() <= BATCH);
                processed.extend(batch);
            }

            assert_eq!(processed.len(), total);
            for (index, event) in processed.into_iter().enumerate() {
                let actual = match event {
                    FileEvent::Changed(path) | FileEvent::Removed(path) => path,
                };
                assert_eq!(actual, PathBuf::from(format!("/{total}-{index}.rs")));
            }
        }
    }

    #[test]
    fn retained_backlog_zero_batch_cannot_stall_forever() {
        let mut pending = VecDeque::from([FileEvent::Changed(PathBuf::from("/a.rs"))]);
        let batch = take_file_event_batch(&mut pending, 0);
        assert_eq!(batch.len(), 1);
        assert!(pending.is_empty());
    }

    #[test]
    fn retained_backlog_deduplicates_across_ticks_without_dropping_other_paths() {
        let mut pending = VecDeque::new();
        enqueue_file_events(
            &mut pending,
            [
                FileEvent::Changed(PathBuf::from("/a.rs")),
                FileEvent::Changed(PathBuf::from("/b.rs")),
                FileEvent::Changed(PathBuf::from("/c.rs")),
            ],
        );
        let first = take_file_event_batch(&mut pending, 1);
        assert!(matches!(&first[0], FileEvent::Changed(path) if path == &PathBuf::from("/a.rs")));

        enqueue_file_events(
            &mut pending,
            [
                FileEvent::Removed(PathBuf::from("/b.rs")),
                FileEvent::Changed(PathBuf::from("/d.rs")),
            ],
        );
        let rest = take_file_event_batch(&mut pending, 8);

        assert_eq!(rest.len(), 3);
        assert!(matches!(&rest[0], FileEvent::Changed(path) if path == &PathBuf::from("/c.rs")));
        assert!(matches!(&rest[1], FileEvent::Removed(path) if path == &PathBuf::from("/b.rs")));
        assert!(matches!(&rest[2], FileEvent::Changed(path) if path == &PathBuf::from("/d.rs")));
        assert!(pending.is_empty());
    }

    #[test]
    fn real_remove_supersedes_synthetic_changed_retry() {
        let path = PathBuf::from("/removed.rs");
        let mut pending = VecDeque::new();

        // Production enqueues synthetic retries first and real watcher events second.
        enqueue_file_events(&mut pending, [FileEvent::Changed(path.clone())]);
        enqueue_file_events(&mut pending, [FileEvent::Removed(path.clone())]);

        let batch = take_file_event_batch(&mut pending, 1);
        assert!(matches!(&batch[0], FileEvent::Removed(actual) if actual == &path));
        assert!(pending.is_empty());
    }

    #[test]
    fn mass_deletion_guard_blocks_drastic_removals_only() {
        assert!(should_block_mass_deletion(80, 100, false)); // 80% gone -> blocked
        assert!(should_block_mass_deletion(100, 100, false)); // total wipe -> blocked
        assert!(!should_block_mass_deletion(75, 100, false)); // 25 survive (25*4==100): boundary, allowed
        assert!(!should_block_mass_deletion(40, 100, false)); // moderate deletion -> allowed
        assert!(!should_block_mass_deletion(0, 100, false)); // nothing removed -> allowed
        assert!(!should_block_mass_deletion(10, 10, false)); // tiny repo (baseline < 16) -> allowed
        assert!(!should_block_mass_deletion(100, 100, true)); // operator override -> allowed
    }
}

/// Decide whether a filesystem-sync tick's bulk deletions should be WITHHELD as
/// a suspected mass-wipe. Returns true to block. Delegates the collapse
/// threshold to the shared `graph_collapse_is_wipe` predicate so the fs-sync
/// guard and the shutdown guard stay consistent (>75% gone, baseline ≥ 16). An
/// explicit operator override (`allow_override`) always permits the deletions.
fn should_block_mass_deletion(removed: u64, total_graph_files: u64, allow_override: bool) -> bool {
    if allow_override {
        return false;
    }
    let surviving = total_graph_files.saturating_sub(removed);
    crate::state::graph_collapse_is_wipe(surviving, total_graph_files)
}

#[tracing::instrument(skip(state))]
pub async fn sync_filesystem_with_graph(state: &DaemonState) -> Result<()> {
    let working_dir = state.layout.working_dir();
    if is_bare_repository(working_dir) {
        debug!(working_dir = %working_dir.display(), "working directory is a bare Git repository; skipping filesystem sync");
        return Ok(());
    }

    let extensions = kin_index::watcher::supported_extensions();

    // 1. Scan filesystem for all files recursively
    let mut files_on_disk = std::collections::HashMap::new();
    let mut stack = vec![working_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if path.is_dir() {
                if kin_index::should_skip_dir(&name_str) {
                    continue;
                }
                stack.push(path);
            } else if path.is_file() {
                let is_relevant = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| extensions.iter().any(|e| e == ext))
                    .unwrap_or(false);
                if is_relevant {
                    // Read file to compute content hash
                    if let Ok(content) = std::fs::read(&path) {
                        let hash = kin_blobs::digest_bytes(&content);
                        files_on_disk.insert(path, hash);
                    }
                }
            }
        }
    }

    // 2. Scan the graph for all indexed files
    let files_in_graph = state.graph.indexed_file_paths();

    let mut events = Vec::new();

    // 3. Find deleted files: files in graph that are NOT on disk.
    let mut removed_events = Vec::new();
    for file_path_str in &files_in_graph {
        let abs_path = working_dir.join(file_path_str);
        if !files_on_disk.contains_key(&abs_path) {
            removed_events.push(FileEvent::Removed(abs_path));
        }
    }

    // Mass-deletion anti-wipe guard: a transient empty/incomplete checkout (or a
    // mid-clone/unmount) makes this sync read every tracked file as "deleted",
    // which would wipe the graph on the next reconcile. Refuse a tick whose
    // deletions would collapse the file set past the SAME anti-wipe threshold the
    // shutdown guard uses (>75% gone, baseline ≥ 16) — kept consistent via the
    // shared `graph_collapse_is_wipe` predicate. Added/modified files still apply;
    // only the suspicious bulk removals are withheld. An operator can confirm a
    // genuine mass deletion with KIN_ALLOW_MASS_DELETION=1.
    let total_graph_files = files_in_graph.len() as u64;
    let allow_mass_deletion = std::env::var("KIN_ALLOW_MASS_DELETION")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false);
    if should_block_mass_deletion(
        removed_events.len() as u64,
        total_graph_files,
        allow_mass_deletion,
    ) {
        state.mass_deletion_blocked.store(true, Ordering::Relaxed);
        warn!(
            total_graph_files,
            removed_count = removed_events.len(),
            "refusing filesystem-sync deletions: they would wipe >75% of graph-known files (likely a transient empty/incomplete checkout). Set KIN_ALLOW_MASS_DELETION=1 to confirm an intentional mass deletion"
        );
    } else {
        state.mass_deletion_blocked.store(false, Ordering::Relaxed);
        events.extend(removed_events);
    }

    // 4. Find added/modified files: files on disk that are NOT in graph or have different hash
    for (path, disk_hash) in &files_on_disk {
        let rel_path = path
            .strip_prefix(working_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let in_graph = files_in_graph.iter().any(|p| p == &rel_path);
        let hash_matches = if in_graph {
            if let Some(graph_hash) = state.graph.get_file_hash(&rel_path) {
                graph_hash == *disk_hash
            } else {
                false
            }
        } else {
            false
        };

        if !in_graph || !hash_matches {
            events.push(FileEvent::Changed(path.clone()));
        }
    }

    if events.is_empty() {
        return Ok(());
    }

    info!(
        count = events.len(),
        "found outstanding filesystem changes to sync on daemon tick/startup"
    );

    // 5. Reconcile changes
    let mut reconciler = state.reconciler.write().await;
    let mut working_copy = state.working_copy.write().await;
    let mut graph_changed = false;
    let mut projection_changed = ProjectionChangedSet::default();

    for event in events {
        match reconciler.reconcile_file_change(
            &event,
            &state.blobs,
            state.graph.as_ref(),
            &mut working_copy.uncommitted_mutations,
        ) {
            Ok(outcome) => {
                use kin_reconcile::ReconcileOutcome;
                let should_apply = matches!(
                    &outcome,
                    ReconcileOutcome::Updated { .. } | ReconcileOutcome::FileRemoved { .. }
                );
                if should_apply {
                    if let Err(e) = apply_overlay_to_graph(
                        state.graph.as_ref(),
                        &mut working_copy.uncommitted_mutations,
                    ) {
                        warn!(error = %e, "failed to apply synced mutations into primary graph");
                        continue;
                    }
                    if let Err(e) =
                        state.persist_projection_truth_from_reconcile(&reconciler, &outcome)
                    {
                        warn!(error = %e, "failed to persist projection truth after sync");
                    }
                    projection_changed.record_reconcile_outcome(&outcome);

                    // Call the cleanup if it's a FileRemoved outcome!
                    if let ReconcileOutcome::FileRemoved {
                        removed, file_id, ..
                    } = &outcome
                    {
                        use kin_model::EntityStore;
                        let _ = state.graph.delete_file_layout(file_id);
                        state.graph.remove_entities_for_file(&file_id.0);
                        let _ = state.graph.delete_structured_artifact(file_id);
                        let _ = state.graph.delete_opaque_artifact(file_id);

                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_id.0.clone()),
                                // FS-reconcile loop: anonymous, no owning session.
                                session_id: None,
                            });
                        }
                    }

                    graph_changed = true;
                }
            }
            Err(e) => {
                warn!(error = %e, "sync reconciliation error for event, skipping");
            }
        }
    }

    drop(working_copy);
    drop(reconciler);

    if graph_changed {
        state.mark_dirty();
        state.bump_version();
        let projection_result = if projection_changed.is_empty() {
            state.rebuild_projection().await
        } else {
            state.refresh_projection(&projection_changed).await
        };
        if let Err(e) = projection_result {
            error!(error = %e, "failed to refresh projection after sync");
        }
    }

    Ok(())
}
