// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};

use crate::api;
use crate::error::{DaemonError, Result};
use crate::loop_runner::{self, LoopConfig};
use crate::state::DaemonState;

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
        }
    }
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
            let (tx, rx) = tokio::sync::mpsc::channel::<crate::state::LspEnrichmentRequest>(256);
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

    // Hydrate projection state before serving VFS reads so an already-indexed repo
    // doesn't start with an empty file-layout cache after daemon restart.
    if let Err(error) = state.rebuild_projection().await {
        error!(error = %error, "failed to rebuild projection state on startup");
    }

    // Shutdown signal: when set to true, all loops exit.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    info!(port = config.api_port, "starting kin daemon");

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
    let api_handle = tokio::spawn(async move { api::serve(api_state, api_port).await });

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
    let _persist_handle = tokio::spawn(async move {
        let idle_flush = Duration::from_secs(2);
        let periodic_flush = Duration::from_secs(30);
        let check_interval = Duration::from_millis(500);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {}
                _ = persist_cancel.changed() => {
                    // Final flush on shutdown.
                    if persist_state.is_dirty() {
                        info!("final persistence flush on shutdown");
                        if let Err(e) = persist_state.save_snapshot() {
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

            // Idle flush: graph is dirty and no mutation in last 2s.
            // Periodic flush: graph is dirty and >30s since last save.
            let should_flush = since_save >= periodic_flush || {
                // Check if mutations have settled (idle for 2s).
                // Use time_since_save as a proxy — if we haven't saved
                // in at least idle_flush time, the mutations have settled.
                since_save >= idle_flush
            };

            if should_flush {
                let start = std::time::Instant::now();
                match persist_state.save_snapshot() {
                    Ok(()) => {
                        persist_state.mark_clean();
                        info!(
                            elapsed_ms = start.elapsed().as_millis(),
                            "background persistence flush complete"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "background persistence flush failed");
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
        loop {
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
            let pending = embed_state.graph.pending_embeddings();
            if pending == 0 {
                continue;
            }
            // Run embedding inference on a blocking thread to avoid starving
            // the tokio runtime (BERT forward pass is CPU-intensive).
            let graph = Arc::clone(&embed_state.graph);
            let batch = embed_batch_size;
            match tokio::task::spawn_blocking(move || graph.process_embedding_queue(batch)).await {
                Ok(Ok(count)) if count > 0 => {
                    info!(
                        count,
                        remaining = pending.saturating_sub(count),
                        "embedded entities"
                    );
                    // Persist vector index after each batch so progress survives restarts.
                    let vi_path = embed_state.layout.kindb_vector_index_path();
                    if let Err(e) = embed_state.graph.save_vector_index(&vi_path) {
                        error!(error = %e, "failed to persist vector index");
                    }
                }
                Ok(Err(e)) => {
                    error!(error = %e, "embedding worker error");
                }
                Err(e) => {
                    error!(error = %e, "embedding task panicked");
                }
                _ => {}
            }
        }
    });

    // Spawn the LSP enrichment worker (channel was set up before Arc::new).
    if let Some(mut lsp_rx) = lsp_rx {
        let mut lsp_cancel = cancel_rx.clone();
        let lsp_state = Arc::clone(&state);
        let lsp_root = state.layout.working_dir().to_path_buf();
        let _lsp_handle = tokio::spawn(async move {
            info!("LSP enrichment worker started");

            // Lazily start LSP servers on first use per language.
            let mut servers: std::collections::HashMap<
                kin_model::LanguageId,
                kin_lsp::lifecycle::LspServer,
            > = std::collections::HashMap::new();

            loop {
                tokio::select! {
                    Some(request) = lsp_rx.recv() => {
                        let path = request.file_path.clone();
                        // Determine language from file extension.
                        let ext = path.extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        let language = match ext {
                            "rs" => Some(kin_model::LanguageId::Rust),
                            "py" | "pyi" => Some(kin_model::LanguageId::Python),
                            "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                            "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                            "go" => Some(kin_model::LanguageId::Go),
                            "java" => Some(kin_model::LanguageId::Java),
                            "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => Some(kin_model::LanguageId::C),
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
                                    Some((a.server_command().to_string(), a.server_args(), a.initialization_options(&lsp_root)))
                                }
                                kin_model::LanguageId::Python => {
                                    let a = kin_lsp::adapters::python::PyrightAdapter;
                                    Some((a.server_command().to_string(), a.server_args(), a.initialization_options(&lsp_root)))
                                }
                                _ => None, // Other adapters can be added as needed
                            };

                            if let Some((cmd, args, init_opts)) = adapter {
                                let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                                match kin_lsp::lifecycle::LspServer::start(
                                    &cmd, &args_refs, &lsp_root, init_opts,
                                ).await {
                                    Ok(server) => {
                                        info!(language = %lang, "LSP server started for enrichment, waiting for indexing...");
                                        // Give the server time to load project metadata.
                                        // rust-analyzer needs ~10-30s, pyright ~5-15s.
                                        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                                        info!(language = %lang, "LSP server ready");
                                        servers.insert(lang, server);
                                    }
                                    Err(e) => {
                                        debug!(language = %lang, error = %e, "failed to start LSP server");
                                        continue;
                                    }
                                }
                            }
                        }

                        // Build entity index from graph for matching LSP locations.
                        let Some(server) = servers.get(&lang) else { continue };
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities.iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
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
                        let _ = server.client.notify(
                            "textDocument/didOpen",
                            serde_json::json!({
                                "textDocument": {
                                    "uri": file_uri,
                                    "languageId": lang_str,
                                    "version": 1,
                                    "text": file_content,
                                }
                            }),
                        ).await;

                        let rel_path = path.strip_prefix(&lsp_root)
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
                        let file_entities: Vec<kin_lsp::EntityRef> = request.changed_entity_ids.iter()
                            .filter_map(|id| {
                                let entity = entities.iter().find(|e| e.id == *id)?;
                                let fo = entity.file_origin.as_ref()?;
                                let span = entity.span.as_ref()?;
                                Some(kin_lsp::EntityRef {
                                    id: entity.id,
                                    name: entity.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                })
                            })
                            .collect();

                        let mut total_relations = 0usize;
                        for entity_ref in &file_entities {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                kin_lsp::enrichment::enrich_entity_calls(
                                    server, entity_ref, &index, &lsp_root,
                                ),
                            ).await {
                                Ok(Ok(relations)) => {
                                    for rel in &relations {
                                        let _ = lsp_state.graph.upsert_relation(rel);
                                    }
                                    total_relations += relations.len();
                                }
                                Ok(Err(e)) => {
                                    debug!(entity = %entity_ref.name, error = %e, "LSP enrichment failed");
                                }
                                Err(_) => {
                                    debug!(entity = %entity_ref.name, "LSP enrichment timed out, skipping");
                                }
                            }
                        }

                        if total_relations > 0 {
                            info!(
                                path = %rel_path,
                                relations = total_relations,
                                "LSP enrichment added relations"
                            );
                            lsp_state.mark_dirty();
                        }
                    }
                    _ = lsp_cancel.changed() => {
                        // Shutdown all running LSP servers.
                        for (lang, server) in servers {
                            info!(language = %lang, "shutting down LSP server");
                            let _ = server.shutdown().await;
                        }
                        info!("LSP enrichment worker shutting down");
                        break;
                    }
                }
            }
        });
    }

    // The daemon stays alive as long as the repo exists. No idle shutdown.
    // Cleanup happens via: SIGTERM, `kin eject`, or `kin setup doctor`.

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
        cancel_tx,
    )
    .await;

    // Remove PID and port files on graceful shutdown.
    crate::lifecycle::remove_pid_file(state.layout.root());
    let _ = std::fs::remove_file(state.layout.root().join("daemon.port"));

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

    result
}

#[cfg(unix)]
async fn select_with_signals(
    loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    sweep_handle: tokio::task::JoinHandle<()>,
    embed_handle: tokio::task::JoinHandle<()>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(DaemonError::Io)?;

    tokio::select! {
        result = loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            }
        }
        result = api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            }
        }
        _ = sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            Ok(())
        }
        _ = embed_handle => {
            info!("embedding worker exited");
            let _ = cancel_tx.send(true);
            Ok(())
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down...");
            let _ = cancel_tx.send(true);
            Ok(())
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            Ok(())
        }
    }
}

#[cfg(not(unix))]
async fn select_with_signals(
    loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    sweep_handle: tokio::task::JoinHandle<()>,
    embed_handle: tokio::task::JoinHandle<()>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    tokio::select! {
        result = loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            }
        }
        result = api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            }
        }
        _ = sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            Ok(())
        }
        _ = embed_handle => {
            info!("embedding worker exited");
            let _ = cancel_tx.send(true);
            Ok(())
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            Ok(())
        }
    }
}
