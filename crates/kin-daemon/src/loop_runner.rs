// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use kin_index::{FileEvent, FileWatcher};
use tracing::{debug, error, info, warn};

use crate::error::{DaemonError, Result};
use crate::state::{ChangeType, DaemonEvent, DaemonState, RECON_IDLE, RECON_PROCESSING};

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
/// The loop runs on a tokio task and shares state through `DaemonState`.
pub async fn run_loop(
    state: Arc<DaemonState>,
    config: LoopConfig,
    cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let extensions = kin_index::watcher::supported_extensions();
    let watcher =
        FileWatcher::new(state.layout.working_dir(), extensions).map_err(DaemonError::from)?;

    info!(
        poll_ms = config.poll_interval_ms,
        batch = config.batch_size,
        "reconciliation loop started"
    );

    let interval = Duration::from_millis(config.poll_interval_ms);
    let mut cancel = cancel;
    // Track the effective batch size for backpressure catch-up.
    let base_batch_size = config.batch_size;

    // RACE CONDITION HARDENING: Retry queue for files that were modified
    // during reconciliation. When a FileModifiedDuringReconcile error
    // occurs, the file watcher may have already drained the event for the
    // new content in the current batch. Without re-queuing, the file would
    // remain stale in the graph until the next external write. This queue
    // injects synthetic Changed events at the start of the next tick.
    let mut retry_queue: Vec<PathBuf> = Vec::new();

    loop {
        // Check for shutdown signal.
        if *cancel.borrow() {
            info!("reconciliation loop shutting down");
            break;
        }

        // Drain pending file events.
        let mut events = watcher.drain();

        // Inject retries from the previous tick's FileModifiedDuringReconcile errors.
        if !retry_queue.is_empty() {
            debug!(
                count = retry_queue.len(),
                "injecting retry events from previous tick"
            );
            let retries: Vec<FileEvent> = retry_queue.drain(..).map(FileEvent::Changed).collect();
            events.extend(retries);
        }

        if events.is_empty() {
            // No events — sleep briefly then check again.
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = cancel.changed() => {
                    info!("reconciliation loop shutting down");
                    break;
                }
            }
            continue;
        }

        state
            .reconciliation_status
            .store(RECON_PROCESSING, Ordering::Relaxed);

        // Backpressure: if event count exceeds batch_size * 4, increase
        // the effective batch size temporarily for catch-up.
        let event_count = events.len();
        let effective_batch_size = if event_count > base_batch_size * 4 {
            warn!(
                pending = event_count,
                base_batch = base_batch_size,
                "event queue backpressure — increasing batch size for catch-up"
            );
            event_count // process all pending events to catch up
        } else {
            base_batch_size
        };

        // Process events in batches.
        let batch: Vec<FileEvent> = events.into_iter().take(effective_batch_size).collect();

        // RACE CONDITION HARDENING: Deduplicate events per file path.
        //
        // Rapid concurrent writes (e.g., save-all, multi-file refactor, or
        // an editor writing a temp file then renaming) can produce multiple
        // events for the same file in a single batch. Processing them all
        // wastes work and can cause inconsistencies: the first event may
        // reconcile against stale content while the second sees the final
        // state. By keeping only the last event per path, we reconcile
        // exactly once per file per tick, using the most recent state.
        let batch = dedup_file_events(batch);
        debug!(count = batch.len(), "processing file events (after dedup)");

        // Acquire write locks for reconciliation.
        let mut reconciler = state.reconciler.write().await;
        let mut working_copy = state.working_copy.write().await;

        for event in &batch {
            match reconciler.reconcile_file_change(
                event,
                &state.blobs,
                state.graph.as_ref(),
                &mut working_copy.uncommitted_mutations,
            ) {
                Ok(outcome) => {
                    debug!(?outcome, "reconcile outcome");

                    // Emit SSE events for entities affected by the file change.
                    use kin_reconcile::ReconcileOutcome;
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
                            });
                        }
                        for id in modified {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Modified,
                                file_path: Some(file_path.clone()),
                            });
                        }
                        for id in removed {
                            state.emit_event(DaemonEvent::EntityChanged {
                                entity_id: *id,
                                change_type: ChangeType::Deleted,
                                file_path: Some(file_path.clone()),
                            });
                        }
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

        // Project overlay mutations back to files.
        match reconciler.project_overlay_to_files(&working_copy.uncommitted_mutations) {
            Ok((modified, warnings)) => {
                if !modified.is_empty() {
                    info!(files = modified.len(), "projected overlay changes");
                }
                if !warnings.is_empty() {
                    warn!(
                        count = warnings.len(),
                        "collision warnings during projection"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "overlay projection failed");
            }
        }

        // Drop write locks before rebuilding projection (it takes its own locks).
        drop(working_copy);
        drop(reconciler);

        // Rebuild projection cache so VFS reads serve fresh content.
        if let Err(e) = state.rebuild_projection().await {
            error!(error = %e, "failed to rebuild projection after reconciliation");
        }

        state
            .reconciliation_status
            .store(RECON_IDLE, Ordering::Relaxed);

        // Mark initialized after the first successful reconciliation cycle.
        if !state.is_initialized.load(Ordering::Relaxed) {
            state.is_initialized.store(true, Ordering::Relaxed);
            info!("daemon initialized after first reconciliation cycle");
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
}
