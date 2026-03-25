// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use kin_model::session::{Intent, IntentScope, IntentSummary, LockType};
use kin_model::{
    BranchName, ContractId, EntityId, FilePathId, GraphStore, IntentId, SessionCapabilities,
    SessionId, SessionTransport,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use tracing::info;
use uuid::Uuid;

use crate::state::DaemonState;

/// Health check response.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub graph_entity_count: Option<usize>,
    pub graph_loaded: bool,
    pub reconciliation_status: String,
}

/// Readiness response.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub ready: bool,
}

/// Working copy status response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub base_change: String,
    pub entity_adds: usize,
    pub entity_mods: usize,
    pub entity_removes: usize,
    pub relation_adds: usize,
    pub relation_removes: usize,
}

/// JSON-friendly intent payload for CLI and adapter consumers.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntentResponse {
    pub intent_id: String,
    pub session_id: String,
    pub scopes: Vec<String>,
    pub lock_type: String,
    pub task_description: String,
    pub registered_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterIntentRequest {
    scope: String,
    lock_type: String,
    task_description: String,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterIntentResponse {
    intent_id: String,
    session_id: String,
    status: String,
    conflicts: Vec<IntentSummary>,
    downstream_warnings: Vec<IntentSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClearedIntentsResponse {
    cleared: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrafficResponse {
    active_intents: Vec<IntentSummary>,
    downstream_warnings: Vec<IntentSummary>,
    hard_blocks: usize,
    soft_locks: usize,
    downstream_count: usize,
}

/// Query parameters for VFS read endpoint.
#[derive(Debug, Deserialize)]
struct VfsReadParams {
    /// Optional session ID for session-scoped overlay (future).
    #[serde(default)]
    session_id: Option<String>,
}

/// Request body for VFS file-changed notification.
#[derive(Debug, Deserialize)]
struct FileChangedRequest {
    path: String,
    /// Optional byte range of the edit for incremental tree-sitter parse.
    /// When all three fields are present, the reconciler uses tree-sitter's
    /// incremental parse (<5ms) instead of a full re-parse (50-100ms).
    #[serde(default)]
    edit_start_byte: Option<usize>,
    #[serde(default)]
    edit_old_end_byte: Option<usize>,
    #[serde(default)]
    edit_new_end_byte: Option<usize>,
}

/// Build the axum router with all daemon API routes.
pub fn router(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/status", get(status))
        .route("/session", get(list_sessions))
        .route("/session/{session_id}", get(get_session))
        .route(
            "/session/{session_id}/intents",
            get(list_session_intents).delete(clear_session_intents),
        )
        .route("/intent", get(list_intents))
        .route("/intent/register", post(register_intent))
        .route("/intent/{intent_id}", delete(release_intent))
        .route("/traffic/{scope}", get(traffic))
        // VFS endpoints — serve file tree and blob content to kin-vfs-daemon
        .route("/vfs/version", get(vfs_version))
        .route("/vfs/tree", get(vfs_tree))
        .route("/vfs/stat/{*path}", get(vfs_stat))
        .route("/vfs/read/{*path}", get(vfs_read))
        .route("/vfs/readdir/{*path}", get(vfs_readdir))
        .route("/vfs/file-changed", post(vfs_file_changed))
        .route("/vfs/subscribe", get(vfs_subscribe))
        // Spine endpoints — cross-repo federation queries
        .route("/spine/health", get(spine_health))
        .route("/spine/repos", get(spine_repos))
        .route("/spine/resolve", get(spine_resolve))
        .route("/spine/impact", get(spine_impact))
        .route("/spine/xref", get(spine_xref))
        .with_state(state)
}

/// GET /health — liveness check with extended diagnostics.
async fn health(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let entity_count = state.graph.entity_count();
    let graph_loaded = entity_count > 0;

    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        graph_entity_count: Some(entity_count),
        graph_loaded,
        reconciliation_status: state.reconciliation_status_str().to_string(),
    })
}

/// GET /readiness — returns 200 when initialized, 503 otherwise.
/// An initialized daemon has either loaded a snapshot or completed at least
/// one reconciliation cycle. An empty but initialized workspace is ready.
async fn readiness(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let initialized = state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed);

    if initialized {
        (StatusCode::OK, Json(ReadinessResponse { ready: true }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessResponse { ready: false }),
        )
    }
}

/// GET /status — current working copy status.
async fn status(State(state): State<Arc<DaemonState>>) -> Result<impl IntoResponse, StatusCode> {
    let wc = state.working_copy.read().await;
    let overlay = &wc.uncommitted_mutations;

    Ok(Json(StatusResponse {
        base_change: wc.base_change.to_string(),
        entity_adds: overlay.entity_adds.len(),
        entity_mods: overlay.entity_mods.len(),
        entity_removes: overlay.entity_removes.len(),
        relation_adds: overlay.relation_adds.len(),
        relation_removes: overlay.relation_removes.len(),
    }))
}

/// GET /session — list all active sessions.
async fn list_sessions(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let sessions = state.coordinator.list_sessions().map_err(internal_error)?;
    Ok(Json(sessions))
}

/// GET /session/{session_id} — fetch a single active session.
async fn get_session(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    let session = state
        .coordinator
        .get_session(&session_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("session not found: {session_id}"),
            )
        })?;
    Ok(Json(session))
}

/// GET /session/{session_id}/intents — list intents owned by a session.
async fn list_session_intents(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    let intents = state
        .coordinator
        .list_intents(&session_id)
        .map_err(internal_error)?;
    Ok(Json(
        intents
            .into_iter()
            .map(IntentResponse::from)
            .collect::<Vec<_>>(),
    ))
}

/// DELETE /session/{session_id}/intents — clear all intents for a session.
async fn clear_session_intents(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    let intents = state
        .coordinator
        .list_intents(&session_id)
        .map_err(internal_error)?;

    for intent in &intents {
        state
            .coordinator
            .release_intent(&session_id, &intent.intent_id)
            .map_err(internal_error)?;
    }

    Ok(Json(ClearedIntentsResponse {
        cleared: intents.len(),
    }))
}

/// GET /intent — list all active intents.
async fn list_intents(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let intents = state.graph.list_all_intents().map_err(internal_error)?;
    Ok(Json(
        intents
            .into_iter()
            .map(IntentResponse::from)
            .collect::<Vec<_>>(),
    ))
}

/// POST /intent/register — register a new intent against the daemon-backed coordinator.
async fn register_intent(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<RegisterIntentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = parse_scope(&request.scope)?;
    let lock_type = parse_lock_type(&request.lock_type)?;
    let session_id = resolve_or_create_session(&state, request.session_id.as_deref())?;
    let result = state
        .coordinator
        .register_intent(
            &session_id,
            vec![scope],
            lock_type,
            &request.task_description,
            None,
        )
        .map_err(internal_error)?;

    let response = match result {
        crate::session_registry::IntentRegistrationResult::Registered {
            intent_id,
            downstream_warnings,
        } => RegisterIntentResponse {
            intent_id: intent_id.to_string(),
            session_id: session_id.to_string(),
            status: "registered".to_string(),
            conflicts: Vec::new(),
            downstream_warnings,
        },
        crate::session_registry::IntentRegistrationResult::Blocked {
            intent_id,
            conflicts,
        } => RegisterIntentResponse {
            intent_id: intent_id.to_string(),
            session_id: session_id.to_string(),
            status: "blocked".to_string(),
            conflicts,
            downstream_warnings: Vec::new(),
        },
    };

    Ok(Json(response))
}

/// DELETE /intent/{intent_id} — release an active intent.
async fn release_intent(
    Path(intent_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let intent_id = parse_intent_id(&intent_id)?;
    let intent = state
        .graph
        .get_intent(&intent_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("intent not found: {intent_id}"),
            )
        })?;

    state
        .coordinator
        .release_intent(&intent.session_id, &intent_id)
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /traffic/{scope} — summarize active locks and downstream warnings.
async fn traffic(
    Path(scope): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = parse_scope(&scope)?;
    let mut reports = state
        .coordinator
        .check_traffic(&[scope])
        .map_err(internal_error)?
        .reports;
    let report = reports.pop().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "traffic report missing for requested scope".to_string(),
        )
    })?;
    let hard_blocks = report
        .active_intents
        .iter()
        .filter(|intent| intent.lock_type == LockType::Hard)
        .count();
    let soft_locks = report.active_intents.len().saturating_sub(hard_blocks);
    let downstream_count = report.downstream_warnings.len();

    Ok(Json(TrafficResponse {
        active_intents: report.active_intents,
        downstream_warnings: report.downstream_warnings,
        hard_blocks,
        soft_locks,
        downstream_count,
    }))
}

// ---------------------------------------------------------------------------
// VFS endpoints — serve the committed file tree and blob content
// ---------------------------------------------------------------------------

/// Build the current file tree from the graph's "main" branch.
///
/// Uses `kin_core::build_file_tree` with the genesis change and the current
/// branch head. Falls back to an empty tree if no branch exists yet.
fn build_current_file_tree(
    state: &DaemonState,
) -> Result<HashMap<FilePathId, kin_model::Hash256>, (StatusCode, String)> {
    let genesis = kin_core::build_genesis_change();
    let genesis_id = genesis.id;

    // Try to find a branch head — prefer "main", fall back to the first branch.
    let head = state
        .graph
        .get_branch(&BranchName::new("main"))
        .map_err(internal_error)?
        .map(|b| b.head)
        .or_else(|| {
            state
                .graph
                .list_branches()
                .ok()
                .and_then(|branches| branches.into_iter().next().map(|b| b.head))
        });

    let head_id = match head {
        Some(id) => id,
        None => return Ok(HashMap::new()),
    };

    kin_core::build_file_tree(state.graph.as_ref(), &genesis_id, &head_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// GET /vfs/version — monotonic counter that increments on graph mutations.
async fn vfs_version(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    Json(json!({ "version": state.vfs_version.load(std::sync::atomic::Ordering::SeqCst) }))
}

/// GET /vfs/tree — full file tree as `{ files: { path: hex_hash, ... } }`.
///
/// Merges the committed tree with overlay additions and removals from the
/// working copy so the VFS sees uncommitted new/deleted files.
async fn vfs_tree(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut tree = build_current_file_tree(&state)?;

    // Merge overlay: add files for new entities, remove deleted entities' files.
    let wc = state.working_copy.read().await;
    let overlay = &wc.uncommitted_mutations;

    // Add files from newly-added entities that have a file_origin.
    for entity in overlay.entity_adds.values() {
        if let Some(ref file_id) = entity.file_origin {
            if !tree.contains_key(file_id) {
                // Placeholder hash — the VFS read path will project from overlay bodies.
                tree.insert(file_id.clone(), kin_model::Hash256::from_bytes([0; 32]));
            }
        }
    }

    // Remove files whose sole entities have been removed.
    // (Only remove if ALL entities for that file are in the remove set.)
    // For now, just mark removed entity files so the VFS can exclude them.
    // Full implementation requires cross-referencing layout regions.
    // Stub: no removals from tree yet — callers check overlay.entity_removes.

    drop(wc);

    let files: HashMap<String, String> = tree
        .into_iter()
        .map(|(path, hash)| (path.0, hash.to_string()))
        .collect();

    Ok(Json(json!({ "files": files })))
}

/// GET /vfs/stat/*path — return VirtualStat-like JSON for a file path.
async fn vfs_stat(
    Path(path): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tree = build_current_file_tree(&state)?;

    // Check if the path is a file.
    let file_id = FilePathId::new(&path);
    if let Some(hash) = tree.get(&file_id) {
        // Try to get the size from the blob store.
        let blob_hash = kin_blobs::Hash256(hash.0);
        let size = state
            .blobs
            .read(&blob_hash)
            .map(|data| data.len() as u64)
            .unwrap_or(0);

        return Ok(Json(json!({
            "is_file": true,
            "is_dir": false,
            "size": size,
            "content_hash": hash.to_string(),
            "mode": 0o644,
            "mtime": 0,
        })));
    }

    // Check if the path is a directory (any file starts with path/).
    let dir_prefix = if path.ends_with('/') {
        path.clone()
    } else {
        format!("{}/", path)
    };

    let is_dir = path.is_empty()
        || path == "."
        || tree.keys().any(|k| k.0.starts_with(&dir_prefix));

    if is_dir {
        return Ok(Json(json!({
            "is_file": false,
            "is_dir": true,
            "size": 0,
            "content_hash": null,
            "mode": 0o755,
            "mtime": 0,
        })));
    }

    Err((StatusCode::NOT_FOUND, format!("not found: {path}")))
}

/// GET /vfs/read/*path — return file content, with overlay projection if needed.
///
/// 1. Read blob content from committed tree
/// 2. Check if working copy overlay has entity mutations for this file
/// 3. If no overlap → return blob directly (zero overhead fast path)
/// 4. If overlap → project overlay mutations onto blob content
async fn vfs_read(
    Path(path): Path<String>,
    Query(params): Query<VfsReadParams>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tree = build_current_file_tree(&state)?;

    let file_id = FilePathId::new(&path);
    let hash = tree.get(&file_id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("file not found: {path}"))
    })?;

    let blob_hash = kin_blobs::Hash256(hash.0);
    let blob_data = state.blobs.read(&blob_hash).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("blob read error: {e}"),
        )
    })?;

    // Build merged overlay bodies: committed graph → global overlay → session overlay.
    // Session overlay takes priority over global overlay.
    let wc = state.working_copy.read().await;
    let mut merged_bodies = wc.uncommitted_mutations.entity_bodies.clone();

    // Merge session overlay on top of global overlay if session_id is provided.
    if let Some(ref session_id_str) = params.session_id {
        if let Ok(session_id) = parse_session_id(session_id_str) {
            let session_overlay = state.get_or_create_session_overlay(&session_id).await;
            // Session overlay bodies take priority over global overlay bodies.
            for (entity_id, body) in session_overlay.entity_bodies {
                merged_bodies.insert(entity_id, body);
            }
        }
    }

    if merged_bodies.is_empty() {
        drop(wc);
        return Ok(blob_data);
    }

    // Try to get the FileLayout for this file from projection state.
    let projection = state.projection.read().await;
    let layout = projection.get_layout(&file_id);

    if let Some(layout) = layout {
        match kin_projection::project_overlay_to_bytes(&blob_data, layout, &merged_bodies) {
            Ok(Some(projected)) => {
                drop(projection);
                drop(wc);
                return Ok(projected);
            }
            Ok(None) => {
                // No overlap — fast path.
            }
            Err(e) => {
                tracing::warn!(file = %file_id, error = %e, "projection failed, returning raw blob");
            }
        }
    }

    drop(projection);
    drop(wc);
    Ok(blob_data)
}

/// GET /vfs/readdir/*path — return directory listing derived from the file tree.
async fn vfs_readdir(
    Path(path): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tree = build_current_file_tree(&state)?;

    let prefix = if path.is_empty() || path == "." {
        String::new()
    } else if path.ends_with('/') {
        path.clone()
    } else {
        format!("{}/", path)
    };

    let mut entries: HashSet<String> = HashSet::new();
    let mut file_entries = Vec::new();

    for file_path in tree.keys() {
        let fp = &file_path.0;
        let rest = if prefix.is_empty() {
            fp.as_str()
        } else if let Some(r) = fp.strip_prefix(&prefix) {
            r
        } else {
            continue;
        };

        // Get the immediate child name.
        let child_name = if let Some(slash_pos) = rest.find('/') {
            &rest[..slash_pos]
        } else {
            rest
        };

        if child_name.is_empty() {
            continue;
        }

        if entries.insert(child_name.to_string()) {
            let is_dir = rest.contains('/');
            file_entries.push(json!({
                "name": child_name,
                "file_type": if is_dir { "directory" } else { "file" },
            }));
        }
    }

    if file_entries.is_empty() && !prefix.is_empty() {
        // Check if the path even exists as a directory.
        let any = tree.keys().any(|k| k.0.starts_with(&prefix));
        if !any {
            return Err((
                StatusCode::NOT_FOUND,
                format!("directory not found: {path}"),
            ));
        }
    }

    file_entries.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });

    Ok(Json(json!({ "entries": file_entries })))
}

/// POST /vfs/file-changed — notify the daemon that a file was modified on disk.
///
/// Triggers reconciliation for the specified path. Used by the VFS write-back
/// flow to inform the daemon that projected content has been written through.
async fn vfs_file_changed(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<FileChangedRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let file_path = std::path::PathBuf::from(&request.path);
    tracing::info!(path = %request.path, "VFS file-changed notification received");

    let event = kin_index::FileEvent::Changed(file_path);

    // Construct an EditHint when all three byte-range fields are present.
    let edit_hint = request
        .edit_start_byte
        .zip(request.edit_old_end_byte)
        .zip(request.edit_new_end_byte)
        .map(|((start, old_end), new_end)| kin_parser::EditHint {
            start_byte: start,
            old_end_byte: old_end,
            new_end_byte: new_end,
        });

    let mut reconciler = state.reconciler.write().await;
    let mut wc = state.working_copy.write().await;

    match reconciler.reconcile_file_change_with_hint(
        &event,
        &state.blobs,
        state.graph.as_ref(),
        &mut wc.uncommitted_mutations,
        edit_hint.as_ref(),
    ) {
        Ok(outcome) => {
            drop(wc);
            drop(reconciler);
            tracing::debug!(path = %request.path, ?outcome, "reconciled file change");

            // Emit SSE events for each entity affected by the file change.
            use crate::state::{ChangeType, DaemonEvent};
            use kin_reconcile::ReconcileOutcome;

            let (added_count, modified_count, removed_count) = match &outcome {
                ReconcileOutcome::Updated { added, modified, removed, .. } => {
                    for id in added {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: ChangeType::Created,
                            file_path: Some(request.path.clone()),
                        });
                    }
                    for id in modified {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: ChangeType::Modified,
                            file_path: Some(request.path.clone()),
                        });
                    }
                    for id in removed {
                        state.emit_event(DaemonEvent::EntityChanged {
                            entity_id: *id,
                            change_type: ChangeType::Deleted,
                            file_path: Some(request.path.clone()),
                        });
                    }
                    (added.len(), modified.len(), removed.len())
                }
                _ => (0, 0, 0),
            };

            // Bump version counter and rebuild projection so subsequent
            // VFS reads serve updated FileLayouts.
            if added_count + modified_count + removed_count > 0 {
                state.bump_version();
                if let Err(e) = state.rebuild_projection().await {
                    tracing::warn!(error = %e, "failed to rebuild projection after write-back");
                }
            }

            Ok(Json(json!({
                "status": "reconciled",
                "path": request.path,
                "added": added_count,
                "modified": modified_count,
                "removed": removed_count,
            })))
        }
        Err(e) => {
            drop(wc);
            drop(reconciler);
            tracing::warn!(path = %request.path, error = %e, "reconciliation failed");
            Ok(Json(json!({
                "status": "error",
                "path": request.path,
                "error": e.to_string(),
            })))
        }
    }
}

/// GET /vfs/subscribe — SSE stream for real-time invalidation events.
///
/// Subscribers receive DaemonEvent messages (EntityChanged, TreeChanged,
/// OverlayUpdated, GraphRootChanged) as they happen. The VFS daemon uses
/// these to invalidate its cache; the spine uses them to update its metadata index.
///
/// Protocol: Server-Sent Events (text/event-stream). Each event is a JSON
/// payload on a `data:` line. A heartbeat comment is sent every 30 seconds
/// to keep the connection alive through proxies/load balancers.
async fn vfs_subscribe(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let mut rx = state.event_tx.subscribe();

    let stream = async_stream::stream! {
        // Send initial connected event
        yield Ok::<_, std::convert::Infallible>(
            format!("data: {{\"type\":\"connected\",\"entity_count\":{}}}\n\n", state.graph.entity_count())
        );

        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(30));
        heartbeat.tick().await; // Skip first immediate tick

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Ok(daemon_event) => {
                            if let Ok(json) = serde_json::to_string(&daemon_event) {
                                yield Ok(format!("data: {json}\n\n"));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            // Subscriber fell behind — send a notification
                            yield Ok(format!("data: {{\"type\":\"lagged\",\"missed\":{n}}}\n\n"));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    yield Ok(": heartbeat\n\n".to_string());
                }
            }
        }
    };

    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONNECTION, "keep-alive"),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response();
    // Prevent nginx from buffering the SSE stream in GKE deployments.
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-accel-buffering"),
        axum::http::HeaderValue::from_static("no"),
    );
    response
}

// ---------------------------------------------------------------------------
// Spine endpoints — cross-repo federation queries
// ---------------------------------------------------------------------------

/// Query parameters for /spine/resolve.
#[derive(Debug, Deserialize)]
struct SpineResolveParams {
    name: String,
    #[serde(default)]
    kind: Option<String>,
}

/// Query parameters for /spine/impact.
#[derive(Debug, Deserialize)]
struct SpineImpactParams {
    repo: String,
    entity: String,
    #[serde(default = "default_depth")]
    depth: u32,
}

fn default_depth() -> u32 {
    3
}

/// Query parameters for /spine/xref.
#[derive(Debug, Deserialize)]
struct SpineXrefParams {
    repo: String,
    entity: String,
}

/// GET /spine/health — spine liveness check.
async fn spine_health(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine not activated".to_string(),
        )
    })?;

    Ok(Json(json!({
        "status": "ok",
        "repos": spine.repo_count(),
        "entities": spine.entity_count(),
        "cross_repo_edges": spine.edge_count(),
    })))
}

/// GET /spine/repos — list all registered repo IDs.
async fn spine_repos(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine not activated".to_string(),
        )
    })?;

    let repo_ids: Vec<String> = spine.registered_repo_ids().into_iter().collect();
    Ok(Json(json!({ "repos": repo_ids })))
}

/// GET /spine/resolve?name=X&kind=function — resolve an entity across repos.
async fn spine_resolve(
    Query(params): Query<SpineResolveParams>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine not activated".to_string(),
        )
    })?;

    let kind = params.kind.as_deref().and_then(parse_entity_kind);
    let results = spine.resolve(&params.name, kind, None);

    Ok(Json(json!({ "results": results })))
}

/// GET /spine/impact?repo=A&entity=X&depth=3 — federated impact analysis.
async fn spine_impact(
    Query(params): Query<SpineImpactParams>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine not activated".to_string(),
        )
    })?;

    let entity_id = parse_entity_id_hex(&params.entity)?;
    let impact =
        kin_spine::federated_impact(spine, &params.repo, &entity_id, params.depth);

    Ok(Json(impact))
}

/// GET /spine/xref?repo=A&entity=X — cross-repo edges for an entity.
async fn spine_xref(
    Query(params): Query<SpineXrefParams>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let spine = state.spine().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "spine not activated".to_string(),
        )
    })?;

    let entity_id = parse_entity_id_hex(&params.entity)?;
    let edges = spine.cross_repo_edges_for(&params.repo, &entity_id);

    Ok(Json(json!({ "edges": edges })))
}

/// Parse an entity kind string into an EntityKind enum value.
fn parse_entity_kind(kind: &str) -> Option<kin_model::EntityKind> {
    use kin_model::EntityKind;
    match kind.to_lowercase().as_str() {
        "function" | "fn" => Some(EntityKind::Function),
        "method" => Some(EntityKind::Method),
        "class" => Some(EntityKind::Class),
        "interface" => Some(EntityKind::Interface),
        "trait" | "traitdef" => Some(EntityKind::TraitDef),
        "type" | "typealias" => Some(EntityKind::TypeAlias),
        "module" | "mod" => Some(EntityKind::Module),
        "test" => Some(EntityKind::Test),
        "enum" | "enumdef" => Some(EntityKind::EnumDef),
        "const" | "constant" => Some(EntityKind::Constant),
        _ => None,
    }
}

/// Parse an entity ID from its UUID hex string representation.
fn parse_entity_id_hex(value: &str) -> Result<EntityId, (StatusCode, String)> {
    let uuid = Uuid::parse_str(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid entity UUID: {value}"),
        )
    })?;
    Ok(EntityId(uuid))
}

fn resolve_or_create_session(
    state: &DaemonState,
    session_id: Option<&str>,
) -> Result<SessionId, (StatusCode, String)> {
    if let Some(session_id) = session_id {
        let session_id = parse_session_id(session_id)?;
        let exists = state
            .coordinator
            .get_session(&session_id)
            .map_err(internal_error)?
            .is_some();
        if !exists {
            return Err((
                StatusCode::NOT_FOUND,
                format!("session not found: {session_id}"),
            ));
        }
        return Ok(session_id);
    }

    state
        .coordinator
        .register_session(
            "kin-cli",
            "daemon-intent",
            SessionTransport::Cli,
            None,
            state.layout.working_dir().to_path_buf(),
            SessionCapabilities::default(),
        )
        .map_err(internal_error)
}

fn parse_lock_type(lock_type: &str) -> Result<LockType, (StatusCode, String)> {
    match lock_type.trim().to_ascii_lowercase().as_str() {
        "hard" => Ok(LockType::Hard),
        "soft" => Ok(LockType::Soft),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("invalid lock type '{lock_type}': expected 'hard' or 'soft'"),
        )),
    }
}

fn parse_scope(scope: &str) -> Result<IntentScope, (StatusCode, String)> {
    if let Some(rest) = scope.strip_prefix("entity:") {
        return Ok(IntentScope::Entity(EntityId(parse_uuid(rest, "entity")?)));
    }
    if let Some(rest) = scope.strip_prefix("contract:") {
        return Ok(IntentScope::Contract(ContractId(parse_uuid(
            rest, "contract",
        )?)));
    }
    if let Some(rest) = scope.strip_prefix("file:") {
        return Ok(IntentScope::Artifact(FilePathId::new(rest)));
    }
    if let Ok(uuid) = Uuid::parse_str(scope) {
        return Ok(IntentScope::Entity(EntityId(uuid)));
    }
    Ok(IntentScope::Artifact(FilePathId::new(scope)))
}

fn parse_session_id(value: &str) -> Result<SessionId, (StatusCode, String)> {
    Ok(SessionId(parse_uuid(value, "session")?))
}

fn parse_intent_id(value: &str) -> Result<IntentId, (StatusCode, String)> {
    Ok(IntentId(parse_uuid(value, "intent")?))
}

fn parse_uuid(value: &str, kind: &str) -> Result<Uuid, (StatusCode, String)> {
    Uuid::parse_str(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {kind} UUID: {value}"),
        )
    })
}

fn format_scope(scope: &IntentScope) -> String {
    match scope {
        IntentScope::Entity(id) => format!("entity:{id}"),
        IntentScope::Contract(id) => format!("contract:{id}"),
        IntentScope::Artifact(id) => format!("file:{id}"),
    }
}

fn internal_error<E: std::fmt::Display>(error: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

impl From<Intent> for IntentResponse {
    fn from(intent: Intent) -> Self {
        Self {
            intent_id: intent.intent_id.to_string(),
            session_id: intent.session_id.to_string(),
            scopes: intent.scopes.iter().map(format_scope).collect(),
            lock_type: match intent.lock_type {
                LockType::Hard => "hard".to_string(),
                LockType::Soft => "soft".to_string(),
            },
            task_description: intent.task_description,
            registered_at: intent.registered_at.to_string(),
            expires_at: intent.expires_at.map(|timestamp| timestamp.to_string()),
        }
    }
}

/// Start the API server on the given port.
pub async fn serve(state: Arc<DaemonState>, port: u16) -> std::io::Result<()> {
    let app = router(state);
    let listener = bind_listener(port)?;

    info!(port, "daemon API server listening");

    axum::serve(listener, app).await
}

fn bind_listener(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;

    let listener: StdTcpListener = socket.into();
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use kin_model::{AgentSession, IntentScope};
    use tower::ServiceExt;

    fn test_state() -> Arc<DaemonState> {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("objects")).unwrap();
        std::fs::create_dir_all(kin_dir.join("working")).unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);
        Arc::new(DaemonState::open(layout).unwrap())
    }

    #[tokio::test]
    async fn health_returns_ok_with_extended_fields() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.status, "ok");
        assert!(json.uptime_seconds < 5);
        assert!(json.graph_entity_count.is_some());
    }

    #[tokio::test]
    async fn readiness_returns_503_when_empty() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/readiness").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Empty graph → not ready
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn sessions_and_intents_endpoints_return_live_state() {
        let state = test_state();
        let session_id = state
            .coordinator
            .register_session(
                "codex",
                "api-test",
                SessionTransport::Cli,
                None,
                state.layout.working_dir().to_path_buf(),
                SessionCapabilities::default(),
            )
            .unwrap();
        let entity_id = EntityId::new();
        state
            .coordinator
            .register_intent(
                &session_id,
                vec![IntentScope::Entity(entity_id)],
                LockType::Hard,
                "touch parser",
                None,
            )
            .unwrap();

        let app = router(state.clone());
        let sessions = app
            .clone()
            .oneshot(Request::get("/session").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions_body = axum::body::to_bytes(sessions.into_body(), 4096)
            .await
            .unwrap();
        let sessions_json: Vec<AgentSession> = serde_json::from_slice(&sessions_body).unwrap();
        assert_eq!(sessions_json.len(), 1);
        assert_eq!(sessions_json[0].session_id, session_id);

        let intents = app
            .oneshot(Request::get("/intent").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(intents.status(), StatusCode::OK);
        let intents_body = axum::body::to_bytes(intents.into_body(), 4096)
            .await
            .unwrap();
        let intents_json: Vec<IntentResponse> = serde_json::from_slice(&intents_body).unwrap();
        assert_eq!(intents_json.len(), 1);
        assert_eq!(intents_json[0].session_id, session_id.to_string());
        assert_eq!(intents_json[0].scopes, vec![format!("entity:{entity_id}")]);
    }

    #[tokio::test]
    async fn register_clear_and_traffic_endpoints_use_daemon_coordinator() {
        let state = test_state();
        let app = router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "file:src/lib.rs",
                            "lock_type": "hard",
                            "task_description": "edit lib"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let registered: RegisterIntentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(registered.status, "registered");
        assert!(!registered.session_id.is_empty());

        let traffic = app
            .clone()
            .oneshot(
                Request::get("/traffic/file%3Asrc%2Flib.rs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(traffic.status(), StatusCode::OK);
        let traffic_body = axum::body::to_bytes(traffic.into_body(), 4096)
            .await
            .unwrap();
        let traffic_json: TrafficResponse = serde_json::from_slice(&traffic_body).unwrap();
        assert_eq!(traffic_json.hard_blocks, 1);
        assert_eq!(traffic_json.soft_locks, 0);

        let clear = app
            .oneshot(
                Request::delete(format!("/session/{}/intents", registered.session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clear.status(), StatusCode::OK);
        let clear_body = axum::body::to_bytes(clear.into_body(), 4096).await.unwrap();
        let cleared: ClearedIntentsResponse = serde_json::from_slice(&clear_body).unwrap();
        assert_eq!(cleared.cleared, 1);
    }
}
