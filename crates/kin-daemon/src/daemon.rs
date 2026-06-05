// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::api;
use crate::error::{DaemonError, Result};
use crate::loop_runner::{self, LoopConfig};
use crate::state::{DaemonState, RECON_IDLE};

/// Configuration for the daemon process.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Port for the HTTP API server.
    pub api_port: u16,
    /// Reconciliation loop configuration.
    pub loop_config: LoopConfig,
    /// Interval for the orphan session sweeper (default 30s).
    pub sweep_interval: Duration,
    /// Interval for the background embedding worker (default 5s).
    pub embed_interval: Duration,
    /// Batch size for embedding inference (entities per pass).
    pub embed_batch_size: usize,
    /// Whether to enable LSP enrichment (auto-detected if not set).
    pub lsp_enabled: bool,
    /// Optional idle timeout. Intended for CLI-autostarted daemons so command
    /// bursts can reuse warm state without leaving background processes alive
    /// indefinitely.
    pub idle_timeout: Option<Duration>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            api_port: 4219,
            loop_config: LoopConfig::default(),
            sweep_interval: Duration::from_secs(30),
            embed_interval: Duration::from_secs(5),
            embed_batch_size: 160,
            lsp_enabled: true,
            idle_timeout: None,
        }
    }
}

fn idle_check_interval(idle_timeout: Duration) -> Duration {
    let millis = (idle_timeout.as_millis() / 4).clamp(100, 5_000) as u64;
    Duration::from_millis(millis)
}

fn endpoint_files_missing(state: &DaemonState) -> bool {
    let root = state.layout.root();
    !root.join("daemon.pid").exists() || !root.join("daemon.port").exists()
}

fn control_plane_missing(state: &DaemonState) -> bool {
    !state.layout.root().exists()
}

fn ready_for_idle_shutdown(state: &DaemonState, idle_timeout: Duration) -> bool {
    if state.active_request_count() > 0 {
        return false;
    }
    if endpoint_files_missing(state) {
        return state.idle_duration() >= idle_timeout;
    }
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return false;
    }
    if state
        .reconciliation_status
        .load(std::sync::atomic::Ordering::Relaxed)
        != RECON_IDLE
    {
        return false;
    }
    if state.event_tx.receiver_count() > 0 {
        return false;
    }
    if state.has_external_sessions() {
        return false;
    }
    state.idle_duration() >= idle_timeout
}

async fn save_snapshot_blocking(state: Arc<DaemonState>) -> Result<()> {
    tokio::task::spawn_blocking(move || state.save_snapshot())
        .await
        .map_err(|error| DaemonError::Io(std::io::Error::other(error.to_string())))?
}

/// How often the watched-PID watchdog checks whether the watched process is
/// still alive.
const WATCH_PID_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Is the process with this PID still alive?
///
/// Sends signal 0 — this delivers no signal and only checks for existence. A
/// return of 0 means the process exists. A non-zero return with `ESRCH` (no
/// such process) means it is gone; any other error (e.g. `EPERM`, the process
/// exists but is owned by another user) is treated as still alive so the
/// watchdog never shuts down on a process that is merely out of reach.
#[cfg(unix)]
fn watched_process_is_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    !matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    )
}

#[cfg(not(unix))]
fn watched_process_is_alive(_pid: i32) -> bool {
    true
}

async fn run_idle_monitor(
    state: Arc<DaemonState>,
    idle_timeout: Option<Duration>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let Some(idle_timeout) = idle_timeout else {
        let _ = cancel_rx.changed().await;
        return;
    };
    let check_interval = idle_check_interval(idle_timeout);
    // Start the idle window from when monitoring begins, not from process
    // construction. `last_activity_ms` is seeded to 0, so without this the
    // idle clock counts from `started_at` — which includes snapshot load and
    // projection rebuild — and a short timeout can fire before the daemon has
    // ever served a request, racing clients that haven't connected yet.
    state.touch_activity();
    info!(
        idle_timeout_s = idle_timeout.as_secs_f64(),
        "daemon idle shutdown enabled"
    );

    loop {
        tokio::select! {
            _ = tokio::time::sleep(check_interval) => {}
            _ = cancel_rx.changed() => return,
        }

        if *cancel_rx.borrow() {
            return;
        }
        if ready_for_idle_shutdown(&state, idle_timeout) {
            if state.is_dirty() {
                if control_plane_missing(&state) {
                    warn!(
                        root = %state.layout.root().display(),
                        "skipping dirty graph flush before idle shutdown because Kin control directory is gone"
                    );
                } else {
                    info!("flushing dirty graph before idle shutdown");
                    if let Err(error) = save_snapshot_blocking(Arc::clone(&state)).await {
                        if control_plane_missing(&state) {
                            warn!(
                                error = %error,
                                root = %state.layout.root().display(),
                                "skipping dirty graph flush after Kin control directory disappeared"
                            );
                        } else {
                            warn!(error = %error, "idle shutdown delayed because snapshot flush failed");
                            continue;
                        }
                    } else {
                        state.mark_clean();
                    }
                }
            }
            info!(
                idle_ms = state.idle_duration().as_millis(),
                "daemon idle timeout reached, shutting down"
            );
            let _ = cancel_tx.send(true);
            return;
        }
    }
}

/// Enrich a single entity with all available LSP relation types (calls, overrides,
/// uses-type, references). Each query is capped at 5 seconds. Returns the total
/// number of relations upserted into the graph.
async fn enrich_single_entity(
    server: &kin_lsp::lifecycle::LspServer,
    entity_ref: &kin_lsp::EntityRef,
    index: &kin_lsp::EntityIndex,
    root: &std::path::Path,
    graph: &kin_db::InMemoryGraph,
) -> usize {
    use kin_model::EntityStore;
    let timeout = std::time::Duration::from_secs(5);
    let mut count = 0;

    // Calls
    match tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_calls(server, entity_ref, index, root),
    )
    .await
    {
        Ok(Ok(relations)) => {
            for r in &relations {
                let _ = graph.upsert_relation(r);
            }
            count += relations.len();
        }
        Ok(Err(e)) => {
            debug!(entity = %entity_ref.name, error = %e, "LSP calls enrichment failed");
        }
        Err(_) => {
            debug!(entity = %entity_ref.name, "LSP calls enrichment timed out");
        }
    }

    // Overrides
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_overrides(server, entity_ref, index, root),
    )
    .await
    {
        for r in &relations {
            let _ = graph.upsert_relation(r);
        }
        count += relations.len();
    }

    // UsesType
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_uses_type(server, entity_ref, index, root),
    )
    .await
    {
        for r in &relations {
            let _ = graph.upsert_relation(r);
        }
        count += relations.len();
    }

    // References
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_references(server, entity_ref, index, root),
    )
    .await
    {
        for r in &relations {
            let _ = graph.upsert_relation(r);
        }
        count += relations.len();
    }

    count
}

/// Run the kin daemon. This is the main entry point.
///
/// Starts:
/// 1. The reconciliation loop (file watcher + reconciler)
/// 2. The HTTP API server (for CLI, MCP, and UI)
/// 3. The orphan session sweeper (Phase 7)
///
/// All run concurrently. Any shutting down causes the others to stop.
pub async fn run(mut state: DaemonState, config: DaemonConfig) -> Result<()> {
    // Set up LSP enrichment channel before wrapping state in Arc.
    let lsp_rx = if config.lsp_enabled {
        let discovered = kin_lsp::discovery::discover_servers();
        if !discovered.is_empty() {
            info!(
                count = discovered.len(),
                languages = ?discovered.iter().map(|s| format!("{}", s.language)).collect::<Vec<_>>(),
                "LSP servers available for enrichment"
            );
            let (tx, rx) = tokio::sync::mpsc::channel::<crate::state::LspEnrichmentMessage>(256);
            state.lsp_enrichment_tx = Some(tx);
            Some(rx)
        } else {
            info!("no LSP servers found — enrichment disabled");
            None
        }
    } else {
        None
    };

    let state = Arc::new(state);

    // Write PID and port files so CLI processes can discover and auto-connect.
    // Each repo gets its own daemon on its own port — the port file enables
    // per-repo isolation (critical for benchmark worktrees).
    crate::lifecycle::write_pid_file(state.layout.root());
    crate::lifecycle::write_port_file(state.layout.root(), config.api_port);

    // Shutdown signal: when set to true, all loops exit.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    info!(port = config.api_port, "starting kin daemon");

    let idle_state = Arc::clone(&state);
    let idle_timeout = config.idle_timeout;
    let idle_cancel_tx = cancel_tx.clone();
    let idle_cancel = cancel_rx.clone();
    let idle_handle = tokio::spawn(async move {
        run_idle_monitor(idle_state, idle_timeout, idle_cancel_tx, idle_cancel).await
    });

    // Opt-in watched-PID watchdog. A harness (e.g. the benchmark driver) sets
    // KIN_DAEMON_WATCH_PID to its own PID; if that process dies — leaving this
    // daemon orphaned and potentially busy-spinning on a shared repo — the
    // daemon shuts itself down gracefully via the same cancel channel the idle
    // path uses. Unset/empty/<= 1 disables it entirely, so normal persistent
    // daemons (which legitimately outlive and reparent away from their launcher)
    // are completely unaffected.
    if let Some(watch_pid) = std::env::var("KIN_DAEMON_WATCH_PID")
        .ok()
        .and_then(|raw| raw.trim().parse::<i32>().ok())
        .filter(|pid| *pid > 1)
    {
        info!(watch_pid, "daemon watched-PID shutdown enabled");
        let watch_cancel_tx = cancel_tx.clone();
        let mut watch_cancel_rx = cancel_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(WATCH_PID_CHECK_INTERVAL) => {}
                    _ = watch_cancel_rx.changed() => return,
                }
                if *watch_cancel_rx.borrow() {
                    return;
                }
                if !watched_process_is_alive(watch_pid) {
                    warn!(
                        watch_pid,
                        "watched process is gone — shutting down orphaned daemon"
                    );
                    let _ = watch_cancel_tx.send(true);
                    return;
                }
            }
        });
    }

    // Spawn the reconciliation loop.
    let loop_state = Arc::clone(&state);
    let loop_config = config.loop_config.clone();
    let loop_cancel = cancel_rx.clone();
    let loop_handle =
        tokio::spawn(
            async move { loop_runner::run_loop(loop_state, loop_config, loop_cancel).await },
        );

    // Spawn the API server.
    let api_state = Arc::clone(&state);
    let api_port = config.api_port;
    let api_cancel = cancel_rx.clone();
    let api_handle =
        tokio::spawn(
            async move { api::serve_with_shutdown(api_state, api_port, api_cancel).await },
        );

    // Register this repo-scoped graph daemon with the lightweight central
    // supervisor when one is available. The supervisor owns process/routing
    // metadata only; this daemon remains graph-authoritative for its repo.
    let supervisor_state = Arc::clone(&state);
    let supervisor_port = config.api_port;
    let supervisor_cancel = cancel_rx.clone();
    let supervisor_handle = tokio::spawn(async move {
        crate::supervisor::repo_daemon_registration_loop(
            supervisor_state,
            supervisor_port,
            supervisor_cancel,
        )
        .await
    });

    // Startup watchdog: monitor initialization and warn if it takes too long.
    let watchdog_state = Arc::clone(&state);
    let mut watchdog_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        let init_timeout = Duration::from_secs(120);
        let check = Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(check) => {}
                _ = watchdog_cancel.changed() => return,
            }
            if watchdog_state
                .is_initialized
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                info!(
                    elapsed_ms = start.elapsed().as_millis(),
                    "daemon initialization complete"
                );
                return;
            }
            let elapsed = start.elapsed();
            if elapsed >= init_timeout {
                error!(
                    elapsed_s = elapsed.as_secs(),
                    "daemon initialization timed out — first reconciliation did not complete within 120s; check snapshot or repo state"
                );
                return;
            }
            info!(
                elapsed_s = elapsed.as_secs(),
                "daemon still initializing (waiting for first reconciliation)"
            );
        }
    });

    // Spawn projection rebuild in background — VFS needs it but locate doesn't.
    // The reconcile loop and API server can start immediately.
    let projection_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(error) = projection_state.rebuild_projection().await {
            tracing::error!(error = %error, "failed to rebuild projection state on startup");
        } else {
            tracing::info!("projection state rebuilt in background");
        }
    });

    // Spawn the orphan session sweeper (Phase 7).
    let sweep_state = Arc::clone(&state);
    let sweep_interval = config.sweep_interval;
    let mut sweep_cancel = cancel_rx.clone();
    let sweep_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(sweep_interval) => {}
                _ = sweep_cancel.changed() => {
                    info!("session sweeper shutting down");
                    break;
                }
            }
            if *sweep_cancel.borrow() {
                break;
            }
            match sweep_state.coordinator.sweep_stale_sessions() {
                Ok(_) => {}
                Err(e) => {
                    error!(error = %e, "session sweeper error");
                }
            }
        }
    });

    // Spawn the background persistence task.
    // Instead of blocking the reconcile loop with synchronous save_graph(),
    // this task periodically flushes dirty state to disk:
    //   - Idle flush: 2s after the last mutation with no new mutations
    //   - Periodic flush: every 30s regardless of activity
    //   - Shutdown flush: handled separately in the graceful shutdown path
    let persist_state = Arc::clone(&state);
    let mut persist_cancel = cancel_rx.clone();
    let persist_handle = tokio::spawn(async move {
        let idle_flush = Duration::from_secs(2);
        let periodic_flush = Duration::from_secs(30);
        let base_interval = Duration::from_millis(500);
        let max_backoff = Duration::from_secs(30);
        const UNHEALTHY_THRESHOLD: u32 = 5;

        let mut consecutive_failures: u32 = 0;
        let mut current_interval = base_interval;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(current_interval) => {}
                _ = persist_cancel.changed() => {
                    if persist_state.is_dirty() {
                        info!("final persistence flush on shutdown");
                        if let Err(e) = save_snapshot_blocking(Arc::clone(&persist_state)).await {
                            error!(error = %e, "shutdown save failed");
                        } else {
                            persist_state.mark_clean();
                        }
                    }
                    break;
                }
            }
            if *persist_cancel.borrow() {
                break;
            }

            if !persist_state.is_dirty() {
                continue;
            }

            let since_save = persist_state.time_since_save();

            let should_flush = since_save >= periodic_flush || since_save >= idle_flush;

            if should_flush {
                let start = std::time::Instant::now();
                match save_snapshot_blocking(Arc::clone(&persist_state)).await {
                    Ok(()) => {
                        persist_state.mark_clean();
                        if consecutive_failures > 0 {
                            info!(
                                prior_failures = consecutive_failures,
                                "persistence recovered"
                            );
                        }
                        consecutive_failures = 0;
                        current_interval = base_interval;
                        info!(
                            elapsed_ms = start.elapsed().as_millis(),
                            "background persistence flush complete"
                        );
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        let backoff_secs =
                            (1u64 << consecutive_failures.min(5)).min(max_backoff.as_secs());
                        current_interval = Duration::from_secs(backoff_secs);
                        if consecutive_failures >= UNHEALTHY_THRESHOLD {
                            error!(
                                error = %e,
                                consecutive_failures,
                                next_retry_s = backoff_secs,
                                "daemon persistence unhealthy — check disk space and permissions"
                            );
                        } else {
                            tracing::warn!(
                                error = %e,
                                consecutive_failures,
                                next_retry_s = backoff_secs,
                                "background persistence flush failed, backing off"
                            );
                        }
                    }
                }
            }
        }
    });

    // Spawn the background embedding worker.
    // Periodically drains the embedding queue, generating vector embeddings
    // for newly added/modified entities. Non-blocking to the reconcile loop.
    let embed_state = Arc::clone(&state);
    let embed_interval = config.embed_interval;
    let embed_batch_size = config.embed_batch_size;
    let mut embed_cancel = cancel_rx.clone();
    let embed_handle = tokio::spawn(async move {
        // Wait for the daemon to finish its first reconciliation cycle
        // before starting embedding work — no point embedding an empty graph.
        while !embed_state
            .is_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                _ = embed_cancel.changed() => return,
            }
        }
        info!("embedding worker started");
        let mut consecutive_panics: u32 = 0;
        const MAX_CONSECUTIVE_PANICS: u32 = 3;
        'wake: loop {
            tokio::select! {
                _ = tokio::time::sleep(embed_interval) => {}
                _ = embed_cancel.changed() => {
                    info!("embedding worker shutting down");
                    break;
                }
            }
            if *embed_cancel.borrow() {
                break;
            }

            // Drain the pending backlog continuously within this wake rather than
            // one batch per `embed_interval`. A fresh central-graph embed (or an
            // explicit `kin embed --rebuild`) enqueues thousands of entities;
            // trickling a single batch per interval would cap throughput at
            // `embed_batch_size / embed_interval` (e.g. 160 / 5s ≈ 32 ent/s) no
            // matter how fast the GPU runs. We yield between batches so locate,
            // persistence, and cancellation stay responsive, then fall back to the
            // idle sleep once the queue is empty. Incremental trickle (a handful of
            // newly-reconciled entities) drains in a single pass and is unchanged.
            loop {
                if *embed_cancel.borrow() {
                    break 'wake;
                }
                let pending = embed_state.graph.pending_embeddings();
                if pending == 0 {
                    break;
                }
                let batch = embed_batch_size;
                let state_for_embed = Arc::clone(&embed_state);
                match tokio::task::spawn_blocking(move || {
                    let _guard = state_for_embed.embedding_work.lock().map_err(|_| {
                        kin_db::KinDbError::ConcurrentAccessError(
                            "embedding work lock poisoned".to_string(),
                        )
                    })?;
                    state_for_embed.graph.process_embedding_queue(batch)
                })
                .await
                {
                    Ok(Ok(count)) if count > 0 => {
                        consecutive_panics = 0;
                        info!(
                            count,
                            remaining = pending.saturating_sub(count),
                            "embedded entities"
                        );
                        // Persist the vector index under the shared persist lock so
                        // this kvec write can never interleave with a snapshot save
                        // running in the persistence loop or idle-shutdown flush.
                        // Run inside spawn_blocking so the std persist Mutex is held
                        // only across the synchronous write, never across an await.
                        let state_for_persist = Arc::clone(&embed_state);
                        let persist_result = tokio::task::spawn_blocking(move || {
                            let _persist_guard =
                                state_for_persist.persist_lock.lock().map_err(|_| {
                                    kin_db::KinDbError::ConcurrentAccessError(
                                        "persist lock poisoned".to_string(),
                                    )
                                })?;
                            kin_db::SnapshotManager::save_vector_index_for_graph(
                                state_for_persist.layout.kindb_snapshot_path(),
                                state_for_persist.graph.as_ref(),
                            )
                        })
                        .await;
                        match persist_result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                error!(error = %e, "failed to persist vector index");
                            }
                            Err(e) => {
                                error!(error = %e, "vector index persist task panicked");
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        // Queue drained out from under us (e.g. an explicit
                        // `/embed` request raced ahead). Stop draining and return
                        // to the idle sleep.
                        consecutive_panics = 0;
                        break;
                    }
                    Ok(Err(e)) => {
                        error!(error = %e, "embedding worker error");
                        break;
                    }
                    Err(e) => {
                        consecutive_panics += 1;
                        if consecutive_panics >= MAX_CONSECUTIVE_PANICS {
                            error!(
                                error = %e,
                                consecutive_panics,
                                "embedding worker permanently failed — vector index will not update until daemon restart"
                            );
                            break 'wake;
                        }
                        error!(
                            error = %e,
                            consecutive_panics,
                            "embedding task panicked, respawning after 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                }

                // Cooperative yield: let locate, persistence, and other daemon
                // tasks interleave between embedding batches during a long drain.
                tokio::task::yield_now().await;
            }
        }
    });

    // Spawn the LSP enrichment worker (channel was set up before Arc::new).
    if let Some(mut lsp_rx) = lsp_rx {
        let mut lsp_cancel = cancel_rx.clone();
        let lsp_state = Arc::clone(&state);
        // Canonicalize to resolve symlinks (macOS /tmp → /private/tmp).
        // RA needs rootUri and file URIs to match.
        let lsp_root = state
            .layout
            .working_dir()
            .canonicalize()
            .unwrap_or_else(|_| state.layout.working_dir().to_path_buf());
        let _lsp_handle = tokio::spawn(async move {
            info!("LSP enrichment worker started");

            // Lazily start LSP servers on first use per language.
            let mut servers: std::collections::HashMap<
                kin_model::LanguageId,
                kin_lsp::lifecycle::LspServer,
            > = std::collections::HashMap::new();
            // Buffer for requests that arrive during server startup.
            let mut pending_buffer: Vec<crate::state::LspEnrichmentRequest> = Vec::new();
            // Track which languages have had their first didOpen processed.
            let mut first_open_done: std::collections::HashSet<kin_model::LanguageId> =
                std::collections::HashSet::new();

            loop {
                use crate::state::LspEnrichmentMessage;

                // Process buffered requests first (always incremental), then wait for new messages.
                let message = if let Some(buffered) = pending_buffer.pop() {
                    LspEnrichmentMessage::Incremental(buffered)
                } else {
                    tokio::select! {
                        Some(msg) = lsp_rx.recv() => msg,
                        _ = lsp_cancel.changed() => {
                            for (lang, server) in servers {
                                info!(language = %lang, "shutting down LSP server");
                                let _ = server.shutdown().await;
                            }
                            info!("LSP enrichment worker shutting down");
                            break;
                        }
                    }
                };

                match message {
                    LspEnrichmentMessage::Incremental(request) => {
                        // Canonicalize to match the rootUri sent to RA.
                        let path = request
                            .file_path
                            .canonicalize()
                            .unwrap_or_else(|_| request.file_path.clone());
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        let language = match ext {
                            "rs" => Some(kin_model::LanguageId::Rust),
                            "py" | "pyi" => Some(kin_model::LanguageId::Python),
                            "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                            "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                            "go" => Some(kin_model::LanguageId::Go),
                            "java" => Some(kin_model::LanguageId::Java),
                            "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => {
                                Some(kin_model::LanguageId::C)
                            }
                            _ => None,
                        };

                        let Some(lang) = language else {
                            continue;
                        };

                        // Lazily start LSP server for this language.
                        if !servers.contains_key(&lang) {
                            use kin_lsp::adapters::LspAdapter;
                            let adapter = match lang {
                                kin_model::LanguageId::Rust => {
                                    let a = kin_lsp::adapters::rust_analyzer::RustAnalyzerAdapter;
                                    Some((
                                        a.server_command().to_string(),
                                        a.server_args(),
                                        a.initialization_options(&lsp_root),
                                    ))
                                }
                                kin_model::LanguageId::Python => {
                                    let a = kin_lsp::adapters::python::PyrightAdapter;
                                    Some((
                                        a.server_command().to_string(),
                                        a.server_args(),
                                        a.initialization_options(&lsp_root),
                                    ))
                                }
                                _ => None,
                            };

                            if let Some((cmd, args, init_opts)) = adapter {
                                let args_refs: Vec<&str> =
                                    args.iter().map(|s| s.as_str()).collect();
                                match kin_lsp::lifecycle::LspServer::start(
                                    &cmd, &args_refs, &lsp_root, init_opts,
                                )
                                .await
                                {
                                    Ok(server) => {
                                        info!(language = %lang, "LSP server started, waiting for indexing...");
                                        tokio::time::sleep(std::time::Duration::from_secs(25))
                                            .await;
                                        info!(language = %lang, "LSP server ready");
                                        servers.insert(lang, server);

                                        // Buffer the current request + drain any that arrived during startup.
                                        pending_buffer.push(request);
                                        while let Ok(queued) = lsp_rx.try_recv() {
                                            if let LspEnrichmentMessage::Incremental(req) = queued {
                                                pending_buffer.push(req);
                                            }
                                            // Sweep messages are not buffered — they'll be re-sent if needed.
                                        }
                                        info!(
                                            buffered = pending_buffer.len(),
                                            "replaying requests after server startup"
                                        );
                                        continue; // Re-enter loop to process from buffer
                                    }
                                    Err(e) => {
                                        debug!(language = %lang, error = %e, "failed to start LSP server");
                                        continue;
                                    }
                                }
                            }
                        }

                        // Build entity index from graph for matching LSP locations.
                        let Some(server) = servers.get(&lang) else {
                            continue;
                        };
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities
                            .iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                // Compute name position by finding name in signature.
                                // LSP needs cursor on name, not declaration start.
                                let name_col = e
                                    .signature
                                    .find(&e.name)
                                    .map(|offset| span.start_col as u32 + offset as u32)
                                    .unwrap_or(span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();
                        let index = kin_lsp::EntityIndex::new(entity_refs);

                        // Open the file in the LSP server so it can be queried.
                        let file_content = match std::fs::read_to_string(&path) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let file_uri = kin_lsp::protocol::path_to_uri(&path);
                        let lang_str = match lang {
                            kin_model::LanguageId::Rust => "rust",
                            kin_model::LanguageId::Python => "python",
                            kin_model::LanguageId::TypeScript => "typescript",
                            kin_model::LanguageId::JavaScript => "javascript",
                            kin_model::LanguageId::Go => "go",
                            kin_model::LanguageId::Java => "java",
                            kin_model::LanguageId::C | kin_model::LanguageId::Cpp => "c",
                            _ => "plaintext",
                        };
                        let _ = server
                            .client
                            .notify(
                                "textDocument/didOpen",
                                serde_json::json!({
                                    "textDocument": {
                                        "uri": file_uri,
                                        "languageId": lang_str,
                                        "version": 1,
                                        "text": file_content,
                                    }
                                }),
                            )
                            .await;

                        // On first file per language, wait for RA to process the didOpen.
                        // Subsequent files don't need this — RA is already indexed.
                        if first_open_done.insert(lang) {
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }

                        let rel_path = path
                            .strip_prefix(&lsp_root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .to_string();

                        // Cap: if too many entities changed, it's a full re-parse — skip
                        // this batch to avoid flooding the LSP server. Incremental changes
                        // (1-10 entities) get enriched; bulk changes wait for next edit.
                        const MAX_ENTITIES_PER_REQUEST: usize = 20;
                        if request.changed_entity_ids.len() > MAX_ENTITIES_PER_REQUEST {
                            debug!(
                                path = %rel_path,
                                count = request.changed_entity_ids.len(),
                                max = MAX_ENTITIES_PER_REQUEST,
                                "skipping LSP enrichment — too many changed entities (likely full re-parse)"
                            );
                            continue;
                        }

                        info!(
                            path = %rel_path,
                            entities = request.changed_entity_ids.len(),
                            "enriching changed entities via LSP"
                        );

                        // Only enrich the entities that actually changed.
                        let file_entities: Vec<kin_lsp::EntityRef> = request
                            .changed_entity_ids
                            .iter()
                            .filter_map(|id| {
                                let entity = entities.iter().find(|e| e.id == *id)?;
                                let fo = entity.file_origin.as_ref()?;
                                let span = entity.span.as_ref()?;
                                let name_col = entity
                                    .signature
                                    .find(&entity.name)
                                    .map(|offset| span.start_col as u32 + offset as u32)
                                    .unwrap_or(span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: entity.id,
                                    name: entity.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();

                        let mut total_relations = 0usize;
                        for entity_ref in &file_entities {
                            info!(entity = %entity_ref.name, "querying LSP for entity");
                            total_relations += enrich_single_entity(
                                server,
                                entity_ref,
                                &index,
                                &lsp_root,
                                &lsp_state.graph,
                            )
                            .await;
                        }

                        if total_relations > 0 {
                            info!(
                                path = %rel_path,
                                relations = total_relations,
                                "LSP enrichment added relations"
                            );
                            lsp_state.mark_dirty();
                        } else {
                            info!(
                                path = %rel_path,
                                entities_queried = file_entities.len(),
                                "LSP enrichment completed — no new relations found"
                            );
                        }
                    } // end Incremental

                    LspEnrichmentMessage::Sweep => {
                        info!("LSP cold sweep started — enriching all entities");

                        // Get all entities from the graph.
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };

                        // Group entities by file.
                        let mut by_file: std::collections::HashMap<
                            String,
                            Vec<&kin_model::Entity>,
                        > = std::collections::HashMap::new();
                        for entity in &entities {
                            if let Some(ref fo) = entity.file_origin {
                                by_file.entry(fo.0.clone()).or_default().push(entity);
                            }
                        }

                        let total_files = by_file.len();
                        let mut files_processed = 0usize;
                        let mut total_relations = 0usize;

                        // Build entity index for the whole graph (used for target matching).
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities
                            .iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                let name_col = e
                                    .signature
                                    .find(&e.name)
                                    .map(|offset| span.start_col as u32 + offset as u32)
                                    .unwrap_or(span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();
                        let index = kin_lsp::EntityIndex::new(entity_refs);

                        for (file_path, file_entities) in &by_file {
                            let abs_path = lsp_root.join(file_path);
                            if !abs_path.exists() {
                                continue;
                            }

                            // Determine language from file extension.
                            let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            let language = match ext {
                                "rs" => Some(kin_model::LanguageId::Rust),
                                "py" | "pyi" => Some(kin_model::LanguageId::Python),
                                "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                                "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                                "go" => Some(kin_model::LanguageId::Go),
                                "java" => Some(kin_model::LanguageId::Java),
                                "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => {
                                    Some(kin_model::LanguageId::C)
                                }
                                _ => None,
                            };
                            let Some(lang) = language else { continue };

                            // Lazily start LSP server for this language (same as incremental).
                            if !servers.contains_key(&lang) {
                                use kin_lsp::adapters::LspAdapter;
                                let adapter = match lang {
                                    kin_model::LanguageId::Rust => {
                                        let a =
                                            kin_lsp::adapters::rust_analyzer::RustAnalyzerAdapter;
                                        Some((
                                            a.server_command().to_string(),
                                            a.server_args(),
                                            a.initialization_options(&lsp_root),
                                        ))
                                    }
                                    kin_model::LanguageId::Python => {
                                        let a = kin_lsp::adapters::python::PyrightAdapter;
                                        Some((
                                            a.server_command().to_string(),
                                            a.server_args(),
                                            a.initialization_options(&lsp_root),
                                        ))
                                    }
                                    _ => None,
                                };

                                if let Some((cmd, args, init_opts)) = adapter {
                                    let args_refs: Vec<&str> =
                                        args.iter().map(|s| s.as_str()).collect();
                                    match kin_lsp::lifecycle::LspServer::start(
                                        &cmd, &args_refs, &lsp_root, init_opts,
                                    )
                                    .await
                                    {
                                        Ok(server) => {
                                            info!(language = %lang, "LSP server started for sweep, waiting for indexing...");
                                            tokio::time::sleep(std::time::Duration::from_secs(25))
                                                .await;
                                            info!(language = %lang, "LSP server ready");
                                            servers.insert(lang, server);
                                        }
                                        Err(e) => {
                                            debug!(language = %lang, error = %e, "failed to start LSP server for sweep");
                                            continue;
                                        }
                                    }
                                }
                            }

                            let Some(server) = servers.get(&lang) else {
                                continue;
                            };

                            // didOpen the file.
                            let file_content = match std::fs::read_to_string(&abs_path) {
                                Ok(c) => c,
                                Err(_) => continue,
                            };
                            let uri = kin_lsp::protocol::path_to_uri(&abs_path);
                            let lang_str = match lang {
                                kin_model::LanguageId::Rust => "rust",
                                kin_model::LanguageId::Python => "python",
                                kin_model::LanguageId::TypeScript => "typescript",
                                kin_model::LanguageId::JavaScript => "javascript",
                                kin_model::LanguageId::Go => "go",
                                kin_model::LanguageId::Java => "java",
                                kin_model::LanguageId::C | kin_model::LanguageId::Cpp => "c",
                                _ => "plaintext",
                            };
                            let _ = server.client.notify("textDocument/didOpen", serde_json::json!({
                            "textDocument": { "uri": uri, "languageId": lang_str, "version": 1, "text": file_content }
                        })).await;

                            // First file per language gets a processing delay.
                            if first_open_done.insert(lang) {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            }

                            // Enrich each entity in this file.
                            let file_entity_refs: Vec<kin_lsp::EntityRef> = file_entities
                                .iter()
                                .filter_map(|e| {
                                    let span = e.span.as_ref()?;
                                    let name_col = e
                                        .signature
                                        .find(&e.name)
                                        .map(|offset| span.start_col as u32 + offset as u32)
                                        .unwrap_or(span.start_col as u32);
                                    Some(kin_lsp::EntityRef {
                                        id: e.id,
                                        name: e.name.clone(),
                                        file_path: file_path.clone(),
                                        start_line: span.start_line as u32,
                                        start_col: span.start_col as u32,
                                        end_line: span.end_line as u32,
                                        name_line: span.start_line as u32,
                                        name_col,
                                    })
                                })
                                .collect();

                            // File-level enrichment: query definition at every identifier
                            // to capture ALL relationships (40-50x more than per-entity).
                            let file_result = kin_lsp::file_enrichment::enrich_file_definitions(
                                server,
                                &abs_path,
                                &file_content,
                                &index,
                                &lsp_root,
                            )
                            .await
                            .unwrap_or_default();

                            let mut file_relations = file_result.relations.len();
                            for rel in &file_result.relations {
                                let _ = lsp_state.graph.upsert_relation(rel);
                            }

                            // Also run per-entity call hierarchy for Calls relations
                            // (definition approach gives References, call hierarchy gives Calls).
                            for entity_ref in &file_entity_refs {
                                file_relations += enrich_single_entity(
                                    server,
                                    entity_ref,
                                    &index,
                                    &lsp_root,
                                    &lsp_state.graph,
                                )
                                .await;
                            }

                            // didClose to free LSP server memory.
                            let _ = server
                                .client
                                .notify(
                                    "textDocument/didClose",
                                    serde_json::json!({
                                        "textDocument": { "uri": uri }
                                    }),
                                )
                                .await;

                            files_processed += 1;
                            total_relations += file_relations;

                            if file_relations > 0 {
                                info!(
                                    file = %file_path,
                                    relations = file_relations,
                                    progress = format!("{}/{}", files_processed, total_files),
                                    "sweep enriched file"
                                );
                            }

                            // Check for shutdown between files.
                            if *lsp_cancel.borrow() {
                                break;
                            }
                        }

                        if total_relations > 0 {
                            lsp_state.mark_dirty();
                        }
                        info!(
                            files = files_processed,
                            total_files,
                            relations = total_relations,
                            "LSP cold sweep complete"
                        );
                    } // end Sweep
                } // end match
            }
        });
    }

    // Persistent daemons stay alive until SIGTERM/SIGINT, `kin eject`, or
    // `kin setup doctor`. CLI-autostarted daemons opt into idle shutdown via
    // KIN_DAEMON_IDLE_TIMEOUT_SECS.

    // Wait for either task to finish (or fail), or a shutdown signal.
    // When one exits, signal the others to shut down.
    //
    // SIGTERM handling is Unix-only (used in Docker containers).
    // On Windows we rely solely on ctrl_c() (Ctrl+C / CTRL_C_EVENT).
    let result = select_with_signals(
        loop_handle,
        api_handle,
        sweep_handle,
        embed_handle,
        idle_handle,
        persist_handle,
        supervisor_handle,
        cancel_tx,
    )
    .await;

    // Graceful shutdown: flush in-memory state to storage backend.
    // On spot instance preemption, GKE sends SIGTERM with a 30-second grace period.
    // This ensures overlays and uncommitted work are saved to GCS.
    if let Some(backend) = &state.storage_backend {
        info!("flushing state to storage backend before exit...");
        let repo_id = state
            .layout
            .root()
            .file_name()
            .and_then(|n: &std::ffi::OsStr| n.to_str())
            .unwrap_or("default");

        // Save global working copy overlay for recovery after preemption.
        let wc = state.working_copy.read().await;
        if !wc.uncommitted_mutations.entity_bodies.is_empty() {
            let overlay_bytes = serde_json::to_vec(&*wc).unwrap_or_default();
            if let Err(e) = backend.save_overlay(repo_id, "_working_copy", &overlay_bytes) {
                error!(error = %e, "failed to flush overlay on shutdown");
            } else {
                info!("overlay state flushed to storage backend");
            }
        }
        drop(wc);

        // Flush per-session overlays so agent work survives preemption.
        let sessions = state.session_overlays.read().await;
        for (session_id, overlay) in sessions.iter() {
            if overlay.entity_bodies.is_empty() {
                continue;
            }
            let overlay_bytes = serde_json::to_vec(overlay).unwrap_or_default();
            if let Err(e) = backend.save_overlay(repo_id, &session_id.to_string(), &overlay_bytes) {
                error!(session_id = %session_id, error = %e, "failed to flush session overlay");
            } else {
                info!(session_id = %session_id, "session overlay flushed");
            }
        }
        drop(sessions);
    }

    // Remove PID and port files after final flush work finishes, so a successor
    // daemon cannot start while this process is still draining persistent state.
    crate::lifecycle::remove_daemon_files_if_current_process(state.layout.root());

    result
}

#[cfg(unix)]
async fn select_with_signals(
    mut loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    mut api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    mut sweep_handle: tokio::task::JoinHandle<()>,
    mut embed_handle: tokio::task::JoinHandle<()>,
    mut idle_handle: tokio::task::JoinHandle<()>,
    persist_handle: tokio::task::JoinHandle<()>,
    supervisor_handle: tokio::task::JoinHandle<()>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(DaemonError::Io)?;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CompletedTask {
        Reconciliation,
        Api,
        Sweeper,
        Embedding,
        Idle,
        Signal,
    }

    let (completed, result) = tokio::select! {
        result = &mut loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Reconciliation, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        result = &mut api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Api, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        _ = &mut sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Sweeper, Ok(()))
        }
        _ = &mut embed_handle => {
            info!("embedding worker exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Embedding, Ok(()))
        }
        _ = &mut idle_handle => {
            info!("idle monitor exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Idle, Ok(()))
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
    };

    drain_handles(
        (completed != CompletedTask::Reconciliation).then_some(loop_handle),
        (completed != CompletedTask::Api).then_some(api_handle),
        (completed != CompletedTask::Sweeper).then_some(sweep_handle),
        (completed != CompletedTask::Embedding).then_some(embed_handle),
        (completed != CompletedTask::Idle).then_some(idle_handle),
        Some(persist_handle),
        Some(supervisor_handle),
    )
    .await;
    result
}

async fn drain_handles(
    loop_handle: Option<
        tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    >,
    api_handle: Option<tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>>,
    sweep_handle: Option<tokio::task::JoinHandle<()>>,
    embed_handle: Option<tokio::task::JoinHandle<()>>,
    idle_handle: Option<tokio::task::JoinHandle<()>>,
    persist_handle: Option<tokio::task::JoinHandle<()>>,
    supervisor_handle: Option<tokio::task::JoinHandle<()>>,
) {
    let drain_timeout = Duration::from_secs(10);
    info!("draining task handles before cleanup...");
    let mut drain_tasks = Vec::new();

    macro_rules! join_or_warn {
        ($name:expr, $handle:expr) => {
            if let Some(handle) = $handle {
                drain_tasks.push(tokio::spawn(async move {
                    match handle.await {
                        Ok(_) => info!(task = $name, "task drained"),
                        Err(e) => warn!(task = $name, error = %e, "task panicked during drain"),
                    }
                }));
            }
        };
    }

    join_or_warn!("reconciliation", loop_handle);
    join_or_warn!("api", api_handle);
    join_or_warn!("sweeper", sweep_handle);
    join_or_warn!("embedding", embed_handle);
    join_or_warn!("idle-monitor", idle_handle);
    join_or_warn!("persistence", persist_handle);
    join_or_warn!("supervisor-registration", supervisor_handle);

    if tokio::time::timeout(drain_timeout, async {
        for task in drain_tasks {
            let _ = task.await;
        }
    })
    .await
    .is_err()
    {
        warn!("one or more daemon tasks did not stop within 10s, proceeding");
    }
}

#[cfg(not(unix))]
async fn select_with_signals(
    mut loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    mut api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    mut sweep_handle: tokio::task::JoinHandle<()>,
    mut embed_handle: tokio::task::JoinHandle<()>,
    mut idle_handle: tokio::task::JoinHandle<()>,
    persist_handle: tokio::task::JoinHandle<()>,
    supervisor_handle: tokio::task::JoinHandle<()>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CompletedTask {
        Reconciliation,
        Api,
        Sweeper,
        Embedding,
        Idle,
        Signal,
    }

    let (completed, result) = tokio::select! {
        result = &mut loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Reconciliation, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        result = &mut api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Api, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        _ = &mut sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Sweeper, Ok(()))
        }
        _ = &mut embed_handle => {
            info!("embedding worker exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Embedding, Ok(()))
        }
        _ = &mut idle_handle => {
            info!("idle monitor exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Idle, Ok(()))
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
    };

    drain_handles(
        (completed != CompletedTask::Reconciliation).then_some(loop_handle),
        (completed != CompletedTask::Api).then_some(api_handle),
        (completed != CompletedTask::Sweeper).then_some(sweep_handle),
        (completed != CompletedTask::Embedding).then_some(embed_handle),
        (completed != CompletedTask::Idle).then_some(idle_handle),
        Some(persist_handle),
        Some(supervisor_handle),
    )
    .await;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::watched_process_is_alive;

    #[test]
    fn watched_process_liveness() {
        // The current process is obviously alive.
        assert!(watched_process_is_alive(std::process::id() as i32));

        // A child that has exited and been reaped no longer exists, so its PID
        // reads as gone (barring a near-instant PID recycle, which is not a
        // realistic risk inside this test window).
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id() as i32;
        child.wait().expect("reap child");
        assert!(!watched_process_is_alive(pid));
    }
}
