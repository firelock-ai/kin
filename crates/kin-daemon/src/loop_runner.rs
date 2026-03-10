use std::sync::Arc;
use std::time::Duration;

use kin_index::{FileWatcher, FileEvent};
use tracing::{debug, error, info, warn};

use crate::error::{DaemonError, Result};
use crate::state::DaemonState;

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
    let watcher = FileWatcher::new(state.layout.working_dir(), extensions)
        .map_err(|e| DaemonError::Index(e.to_string()))?;

    info!(
        poll_ms = config.poll_interval_ms,
        batch = config.batch_size,
        "reconciliation loop started"
    );

    let interval = Duration::from_millis(config.poll_interval_ms);
    let mut cancel = cancel;

    loop {
        // Check for shutdown signal.
        if *cancel.borrow() {
            info!("reconciliation loop shutting down");
            break;
        }

        // Drain pending file events.
        let events = watcher.drain();

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

        // Process events in batches.
        let batch: Vec<FileEvent> = events.into_iter().take(config.batch_size).collect();
        debug!(count = batch.len(), "processing file events");

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
                }
                Err(e) => {
                    warn!(error = %e, "reconciliation error for event, skipping");
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
                    warn!(count = warnings.len(), "collision warnings during projection");
                }
            }
            Err(e) => {
                error!(error = %e, "overlay projection failed");
            }
        }
    }

    Ok(())
}
